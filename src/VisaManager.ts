/**
 * The server, assembled.
 *
 * Transport-agnostic on purpose: every method takes plain values and returns
 * plain values, so the same object is driven by a ream route, by a test, or by
 * a host that is not ream at all. The HTTP binding lives in the provider.
 */

import {
	type AuthorizationRequest,
	type AuthorizeOptions,
	errorRedirect,
	issueAuthorizationCode,
	successRedirect,
	UnredirectableError,
	type ValidatedRequest,
	validateAuthorizationRequest,
} from "./authorize.js";
import {
	type ClientCredentials,
	readCredentials,
	redirectUriMatches,
} from "./clients.js";
import { hashSecret, randomToken } from "./crypto.js";
import { OAuthError, VisaError } from "./errors.js";
import { introspect, revoke, verifyAccessToken } from "./introspect.js";
import {
	type ClientRegistrationRequest,
	type ClientRegistrationResponse,
	type RegistrationOptions,
	registrationResponse,
	validateRegistration,
} from "./register.js";
import type { VisaStore } from "./store.js";
import { type TokenOptions, token } from "./token.js";
import type {
	AuthorizedApplication,
	Client,
	ClientAuthMethod,
	GrantType,
	IntrospectionResponse,
	TokenResponse,
} from "./types.js";

export interface VisaConfig extends AuthorizeOptions, TokenOptions {
	/** Where this server lives — `https://auth.example.com`. */
	issuer: string;
	store: VisaStore;
	/** Whether clients may register themselves, and on what terms (RFC 7591). */
	registration?: RegistrationOptions;
}

/** What `authorize()` decided. */
export type AuthorizationOutcome =
	/** Send the user here. */
	| { type: "redirect"; url: string }
	/** Ask first: this user has not agreed to these scopes for this client. */
	| { type: "consent"; request: ValidatedRequest }
	/**
	 * Show the user this error. It must NOT be redirected — the redirect URI
	 * is the thing that failed validation.
	 */
	| { type: "error"; error: OAuthError };

export class VisaManager {
	readonly #config: VisaConfig;

	constructor(config: VisaConfig) {
		// Validated here rather than at the first request: a server that boots
		// with a broken issuer answers every metadata fetch with something no
		// client can use, and says so nowhere.
		this.#config = { ...config, issuer: normalizeIssuer(config.issuer) };
	}

	get issuer(): string {
		return this.#config.issuer;
	}

	get store(): VisaStore {
		return this.#config.store;
	}

	/**
	 * Register a client and hand back its secret ONCE.
	 *
	 * The plaintext is never stored and cannot be recovered; a client that
	 * loses it gets a new one. That is not an inconvenience to work around —
	 * it is the reason a database dump is not a set of working credentials.
	 */
	async registerClient(input: {
		id: string;
		name: string;
		redirectUris: string[];
		grantTypes?: GrantType[];
		scopes?: string[];
		tokenEndpointAuthMethod?: ClientAuthMethod;
		trusted?: boolean;
	}): Promise<{ client: Client; secret?: string }> {
		// Refused at registration, not at the first authorization request: a
		// URI that cannot be parsed would otherwise throw out of
		// `successRedirect`, turning a client's mistake into a 500 on a path
		// an attacker can reach.
		assertRedirectUris(input.redirectUris);
		const method = input.tokenEndpointAuthMethod ?? "client_secret_basic";
		const secret = method === "none" ? undefined : randomToken();
		const client: Client = {
			id: input.id,
			name: input.name,
			redirectUris: input.redirectUris,
			grantTypes: input.grantTypes ?? ["authorization_code", "refresh_token"],
			scopes: input.scopes ?? [],
			tokenEndpointAuthMethod: method,
			...(input.trusted === undefined ? {} : { trusted: input.trusted }),
			...(secret === undefined ? {} : { secretHash: hashSecret(secret) }),
		};
		const store = this.#config.store;
		if (!("addClient" in store) || typeof store.addClient !== "function") {
			throw new VisaError(
				"E_VISA_STORE_READ_ONLY",
				"This store cannot register clients; create them where they live.",
				{
					hint: "MemoryStore.addClient exists; a database store registers rows.",
				},
			);
		}
		store.addClient(client);
		return secret === undefined ? { client } : { client, secret };
	}

	/**
	 * A client registering itself (RFC 7591).
	 *
	 * Refused unless the application turned registration on. What comes back is
	 * the 201 body, secret included — the one time it exists.
	 */
	async register(
		request: ClientRegistrationRequest,
		presentedToken?: string,
		now: Date = new Date(),
	): Promise<ClientRegistrationResponse> {
		const options = this.#config.registration ?? {};
		const metadata = validateRegistration(request, options, presentedToken);
		const { client, secret } = await this.registerClient({
			// The id is ours to choose: a client naming itself could claim one
			// that already exists and read another application's tokens.
			id: randomToken(),
			name: metadata.name,
			redirectUris: metadata.redirectUris,
			grantTypes: metadata.grantTypes,
			scopes: metadata.scopes,
			tokenEndpointAuthMethod: metadata.tokenEndpointAuthMethod,
		});
		return registrationResponse(client, now, secret, options);
	}

	/**
	 * Step one: check the request, and decide what happens to the user.
	 *
	 * `userId` is whoever is signed in — warden's business, not visa's. Pass
	 * `undefined` and the caller is told to authenticate first.
	 */
	async authorize(
		request: AuthorizationRequest,
		userId: string | undefined,
	): Promise<AuthorizationOutcome> {
		let validated: ValidatedRequest;
		try {
			validated = await validateAuthorizationRequest(
				request,
				this.#config.store,
				this.#config,
			);
		} catch (error) {
			if (error instanceof UnredirectableError) {
				return { type: "error", error: error.error };
			}
			if (error instanceof OAuthError) {
				// Redirectable: the URI was verified before this check ran.
				const uri = await this.#redirectUriFor(request);
				if (uri === null) return { type: "error", error };
				return {
					type: "redirect",
					url: errorRedirect(uri, error, request.state),
				};
			}
			throw error;
		}

		if (userId === undefined) {
			return { type: "consent", request: validated };
		}

		const consent = await this.#config.store.findConsent(
			userId,
			validated.client.id,
		);
		const covered =
			consent !== null &&
			validated.scopes.every((scope) => consent.scopes.includes(scope));
		const forced = request.prompt === "consent";
		if (validated.client.trusted !== true && (!covered || forced)) {
			return { type: "consent", request: validated };
		}

		return { type: "redirect", url: await this.grant(validated, userId) };
	}

	/**
	 * Step two: the user said yes. Record it and build the redirect.
	 *
	 * Split from `authorize` because the consent screen sits between them, and
	 * the answer to it is a POST the application owns.
	 */
	async grant(
		validated: ValidatedRequest,
		userId: string,
		now: Date = new Date(),
	): Promise<string> {
		await this.#config.store.saveConsent({
			userId,
			clientId: validated.client.id,
			scopes: validated.scopes,
			grantedAt: now,
		});
		const code = await issueAuthorizationCode(
			validated,
			userId,
			this.#config.store,
			this.#config,
			now,
		);
		return successRedirect(validated, code);
	}

	/** The user said no. */
	deny(validated: ValidatedRequest): string {
		return errorRedirect(
			validated.redirectUri,
			new OAuthError("access_denied", "The user refused the request."),
			validated.state,
		);
	}

	async token(
		body: Record<string, unknown>,
		credentials: ClientCredentials,
		now: Date = new Date(),
	): Promise<TokenResponse> {
		return token(body, credentials, this.#config.store, this.#config, now);
	}

	async introspect(
		body: Record<string, unknown>,
		credentials: ClientCredentials,
		now: Date = new Date(),
	): Promise<IntrospectionResponse> {
		return introspect(body, credentials, this.#config.store, now, this.issuer);
	}

	async revoke(
		body: Record<string, unknown>,
		credentials: ClientCredentials,
		now: Date = new Date(),
	): Promise<void> {
		return revoke(body, credentials, this.#config.store, now);
	}

	/**
	 * What a resource server calls on every request.
	 *
	 * `resource` is this server's own identifier (RFC 8707): given, a token
	 * minted for a different one is refused here rather than honoured.
	 */
	async verify(
		presented: string,
		now: Date = new Date(),
		resource?: string,
	): ReturnType<typeof verifyAccessToken> {
		return verifyAccessToken(presented, this.#config.store, now, resource);
	}

	/**
	 * Every application this user has authorised.
	 *
	 * What a "connected applications" screen renders. Includes an application
	 * whose tokens have all expired: "last used" matters most when nothing is
	 * live any more, and hiding it would tell someone an application never
	 * touched their data when it did.
	 */
	async listAuthorizations(
		userId: string,
		now: Date = new Date(),
	): Promise<AuthorizedApplication[]> {
		const store = this.#config.store;
		const consents = await store.listConsents(userId);
		const tokens = await store.listAccessTokens(userId);

		return Promise.all(
			consents.map(async (consent) => {
				const mine = tokens.filter(
					(token) => token.clientId === consent.clientId,
				);
				const client = await store.findClient(consent.clientId);
				const lastUsedAt = mine.reduce<Date | undefined>((latest, token) => {
					if (token.lastUsedAt === undefined) return latest;
					if (latest === undefined) return token.lastUsedAt;
					return token.lastUsedAt > latest ? token.lastUsedAt : latest;
				}, undefined);

				return {
					clientId: consent.clientId,
					// A client that has since been deleted still shows, under its id:
					// the grant is the user's and they must be able to end it.
					name: client?.name ?? consent.clientId,
					scopes: consent.scopes,
					grantedAt: consent.grantedAt,
					...(lastUsedAt === undefined ? {} : { lastUsedAt }),
					active: mine.some(
						(token) => token.revokedAt === undefined && token.expiresAt > now,
					),
				};
			}),
		);
	}

	/**
	 * End one application's access for one user.
	 *
	 * Tokens first, consent second, and deliberately in that order: someone
	 * revoking in a hurry wants the sessions dead, and a failure half-way
	 * through must not leave an application still holding live tokens with the
	 * grant already forgotten.
	 *
	 * Both kinds of token go — revoking only the refresh half would leave the
	 * access token it already bought alive for its full lifetime.
	 */
	async revokeAuthorization(
		userId: string,
		clientId: string,
		now: Date = new Date(),
	): Promise<void> {
		await this.#config.store.revokeAccessFor(userId, clientId, now);
		await this.#config.store.deleteConsent(userId, clientId);
	}

	/** Read credentials out of a request, both places the spec allows. */
	readCredentials(input: {
		authorization?: string;
		body: Record<string, unknown>;
	}): ClientCredentials {
		return readCredentials(input);
	}

	/**
	 * The redirect URI an error may travel to, or `null` when there is none to
	 * trust. Re-resolved rather than remembered: the validation that failed is
	 * the one that would have produced it.
	 */
	async #redirectUriFor(request: AuthorizationRequest): Promise<string | null> {
		if (request.client_id === undefined) return null;
		const client = await this.#config.store.findClient(request.client_id);
		if (client === null) return null;
		if (request.redirect_uri === undefined) {
			return client.redirectUris.length === 1
				? (client.redirectUris[0] ?? null)
				: null;
		}
		return redirectUriMatches(request.redirect_uri, client.redirectUris)
			? request.redirect_uri
			: null;
	}
}

/**
 * The issuer, checked and trimmed.
 *
 * A trailing slash is not cosmetic here: every endpoint is built by
 * concatenation, so `https://auth.test/` yields `https://auth.test//oauth/token`
 * — a URL some clients normalise and others do not.
 */
function normalizeIssuer(issuer: string): string {
	if (issuer === undefined || issuer === "") {
		throw new VisaError(
			"E_VISA_MISSING_ISSUER",
			"visa needs an issuer — the public URL this authorization server answers on.",
			{ hint: "Set `issuer` in config/visa.ts, e.g. https://auth.example.com" },
		);
	}
	let url: URL;
	try {
		url = new URL(issuer);
	} catch {
		throw new VisaError(
			"E_VISA_INVALID_ISSUER",
			`visa's issuer is not a URL: ${issuer}`,
			{ hint: "It is the public origin, e.g. https://auth.example.com" },
		);
	}
	if (url.protocol !== "https:" && url.hostname !== "localhost") {
		// Tokens travel to it. `http://` is for a laptop, and the exception is
		// named so nobody has to guess whether it applies in production.
		throw new VisaError(
			"E_VISA_INSECURE_ISSUER",
			`visa's issuer must be https (localhost excepted): ${issuer}`,
		);
	}
	if (url.hash !== "" || url.search !== "") {
		throw new VisaError(
			"E_VISA_INVALID_ISSUER",
			"visa's issuer must carry no query string and no fragment.",
		);
	}
	return issuer.replace(/\/+$/, "");
}

/**
 * Every redirect URI a client registers, checked once.
 *
 * A fragment is refused because the authorization response appends its own
 * query and a fragment would swallow it; a wildcard because this server
 * compares exactly and `*` would simply never match, silently.
 */
function assertRedirectUris(uris: readonly string[]): void {
	if (uris.length === 0) {
		throw new VisaError(
			"E_VISA_NO_REDIRECT_URI",
			"A client needs at least one redirect URI.",
		);
	}
	for (const uri of uris) {
		let url: URL;
		try {
			url = new URL(uri);
		} catch {
			throw new VisaError("E_VISA_INVALID_REDIRECT_URI", `Not a URL: ${uri}`, {
				hint: "Register the complete URI, scheme and path included.",
			});
		}
		if (url.hash !== "") {
			throw new VisaError(
				"E_VISA_INVALID_REDIRECT_URI",
				`A redirect URI must carry no fragment: ${uri}`,
			);
		}
		if (uri.includes("*")) {
			throw new VisaError(
				"E_VISA_INVALID_REDIRECT_URI",
				`Wildcards are not matched, so this would never accept anything: ${uri}`,
			);
		}
	}
}
