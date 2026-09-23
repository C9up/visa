/**
 * The authorization endpoint.
 *
 * It is the half a human sees, and the half where an error must NOT be
 * redirected: if the redirect URI is missing, unregistered or malformed, the
 * server tells the user and stops (§4.1.2.1). Bouncing the error to an
 * unverified URI is how an attacker learns that a client exists and gets a
 * page of their choosing loaded in the user's session.
 */

import {
	assertGrantAllowed,
	redirectUriMatches,
	resolveScopes,
} from "./clients.js";
import { hashSecret, randomToken } from "./crypto.js";
import { OAuthError } from "./errors.js";
import type { VisaStore } from "./store.js";
import type { AuthorizationCode, Client } from "./types.js";

/** The query as it arrived, untrusted. */
export interface AuthorizationRequest {
	response_type?: string;
	client_id?: string;
	redirect_uri?: string;
	scope?: string;
	state?: string;
	code_challenge?: string;
	code_challenge_method?: string;
	nonce?: string;
	/** A client may ask to always see the consent screen. */
	prompt?: string;
}

/** A request that passed every check, with the values it resolved to. */
export interface ValidatedRequest {
	client: Client;
	redirectUri: string;
	scopes: string[];
	state: string | undefined;
	codeChallenge: string;
	codeChallengeMethod: "S256" | "plain";
	nonce: string | undefined;
}

/**
 * A failure that cannot be redirected — the user must be told directly.
 *
 * Separate from `OAuthError` because the CALLER has to treat it differently:
 * render a page, never `Location:`.
 */
export class UnredirectableError extends Error {
	readonly error: OAuthError;
	constructor(error: OAuthError) {
		super(error.message);
		this.name = "UnredirectableError";
		this.error = error;
	}
}

export interface AuthorizeOptions {
	/** Lifetime of the code. Short on purpose — see `issueAuthorizationCode`. */
	codeTtlSeconds?: number;
	/**
	 * Accept `plain` as a code challenge method.
	 *
	 * NAMED DEVIATION — the spec allows `plain`; this refuses it by default.
	 * `plain` puts the verifier in the authorization request, so anything that
	 * can read that request (a log, a referrer, a proxy) can complete the
	 * exchange, which is precisely what PKCE exists to stop. Every client that
	 * can hash can use S256.
	 */
	allowPlainChallenge?: boolean;
}

/**
 * Check an authorization request. Throws `UnredirectableError` when the error
 * must not be bounced back, `OAuthError` when it may.
 */
export async function validateAuthorizationRequest(
	request: AuthorizationRequest,
	store: VisaStore,
	options: AuthorizeOptions = {},
): Promise<ValidatedRequest> {
	// Order matters: everything that decides WHERE an error may go has to be
	// settled before any error is produced.
	if (request.client_id === undefined || request.client_id === "") {
		throw new UnredirectableError(
			new OAuthError("invalid_request", "client_id is required."),
		);
	}
	const client = await store.findClient(request.client_id);
	if (client === null) {
		throw new UnredirectableError(
			new OAuthError("invalid_request", "Unknown client."),
		);
	}

	const redirectUri = resolveRedirectUri(request.redirect_uri, client);

	// From here the redirect URI is verified, so an error may travel back.
	if (request.response_type !== "code") {
		throw new OAuthError(
			request.response_type === undefined
				? "invalid_request"
				: "unsupported_response_type",
			// The implicit grant is gone in 2.1, and `token` is its response
			// type — saying so beats a blank refusal for whoever is porting.
			request.response_type === "token"
				? "The implicit grant is not supported; use response_type=code."
				: "Only response_type=code is supported.",
		);
	}

	assertGrantAllowed(client, "authorization_code");

	const { codeChallenge, codeChallengeMethod } = readChallenge(
		request,
		options,
	);
	const scopes = resolveScopes(request.scope, client);

	return {
		client,
		redirectUri,
		scopes,
		state: request.state,
		codeChallenge,
		codeChallengeMethod,
		nonce: request.nonce,
	};
}

/**
 * Which redirect URI this request lands on.
 *
 * Omitting it is allowed only when the client registered exactly one — with
 * two or more, "the first one" would be a choice the server makes on the
 * client's behalf, and the wrong choice sends the code elsewhere.
 */
function resolveRedirectUri(
	requested: string | undefined,
	client: Client,
): string {
	if (client.redirectUris.length === 0) {
		throw new UnredirectableError(
			new OAuthError("invalid_request", "This client has no redirect URI."),
		);
	}
	if (requested === undefined || requested === "") {
		const only = client.redirectUris[0];
		if (client.redirectUris.length > 1 || only === undefined) {
			throw new UnredirectableError(
				new OAuthError(
					"invalid_request",
					"redirect_uri is required when a client registers more than one.",
				),
			);
		}
		return only;
	}
	if (!redirectUriMatches(requested, client.redirectUris)) {
		throw new UnredirectableError(
			new OAuthError("invalid_request", "redirect_uri is not registered."),
		);
	}
	return requested;
}

function readChallenge(
	request: AuthorizationRequest,
	options: AuthorizeOptions,
): { codeChallenge: string; codeChallengeMethod: "S256" | "plain" } {
	const challenge = request.code_challenge;
	if (challenge === undefined || challenge === "") {
		// Mandatory in 2.1 for every client, confidential ones included.
		throw new OAuthError("invalid_request", "code_challenge is required.");
	}
	const method = request.code_challenge_method ?? "plain";
	if (method === "S256")
		return { codeChallenge: challenge, codeChallengeMethod: "S256" };
	if (method === "plain" && options.allowPlainChallenge === true) {
		return { codeChallenge: challenge, codeChallengeMethod: "plain" };
	}
	throw new OAuthError(
		"invalid_request",
		"code_challenge_method must be S256.",
	);
}

/**
 * Mint the code, once the user is known and has consented.
 *
 * Thirty seconds by default. A code is exchanged by a server the client
 * controls, milliseconds after the redirect — a long window buys the client
 * nothing and gives anything that can read a URL (a log, a referrer header, a
 * shoulder) time to use it.
 */
export async function issueAuthorizationCode(
	validated: ValidatedRequest,
	userId: string,
	store: VisaStore,
	options: AuthorizeOptions = {},
	now: Date = new Date(),
): Promise<string> {
	const code = randomToken();
	const ttl = options.codeTtlSeconds ?? 30;
	const record: AuthorizationCode = {
		codeHash: hashSecret(code),
		clientId: validated.client.id,
		userId,
		redirectUri: validated.redirectUri,
		scopes: validated.scopes,
		codeChallenge: validated.codeChallenge,
		codeChallengeMethod: validated.codeChallengeMethod,
		expiresAt: new Date(now.getTime() + ttl * 1000),
		...(validated.nonce === undefined ? {} : { nonce: validated.nonce }),
	};
	await store.saveAuthorizationCode(record);
	return code;
}

/** Build the redirect a successful authorization ends on. */
export function successRedirect(
	validated: ValidatedRequest,
	code: string,
): string {
	const url = new URL(validated.redirectUri);
	url.searchParams.set("code", code);
	// Returned verbatim when the client sent one, absent when it did not —
	// inventing a state would break the client's own CSRF check.
	if (validated.state !== undefined)
		url.searchParams.set("state", validated.state);
	return url.toString();
}

/** Build the redirect a refused or failed authorization ends on. */
export function errorRedirect(
	redirectUri: string,
	error: OAuthError,
	state?: string,
): string {
	const url = new URL(redirectUri);
	url.searchParams.set("error", error.code);
	if (error.description !== undefined) {
		url.searchParams.set("error_description", error.description);
	}
	if (state !== undefined) url.searchParams.set("state", state);
	return url.toString();
}
