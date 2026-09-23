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
import type { VisaStore } from "./store.js";
import { type TokenOptions, token } from "./token.js";
import type {
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
		if (config.issuer === undefined || config.issuer === "") {
			throw new VisaError(
				"E_VISA_MISSING_ISSUER",
				"visa needs an issuer — the public URL this authorization server answers on.",
				{
					hint: "Set `issuer` in config/visa.ts, e.g. https://auth.example.com",
				},
			);
		}
		this.#config = config;
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
		return introspect(body, credentials, this.#config.store, now);
	}

	async revoke(
		body: Record<string, unknown>,
		credentials: ClientCredentials,
		now: Date = new Date(),
	): Promise<void> {
		return revoke(body, credentials, this.#config.store, now);
	}

	/** What a resource server calls on every request. */
	async verify(
		presented: string,
		now: Date = new Date(),
	): Promise<{ clientId: string; userId?: string; scopes: string[] } | null> {
		return verifyAccessToken(presented, this.#config.store, now);
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
