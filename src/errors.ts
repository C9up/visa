/**
 * Two kinds of failure, and they are not interchangeable.
 *
 * A PROTOCOL error is part of the OAuth response: the spec names the string
 * (`invalid_grant`, `invalid_client`…), the client reads it, and leaking no
 * more than that string is deliberate — "which of the four checks failed" is
 * information an attacker uses to enumerate.
 *
 * A FRAMEWORK error is a mistake in the application: a store that does not
 * answer, a client registered without a redirect URI. Those carry a
 * `E_VISA_*` code and a message meant for a developer, never for a response
 * body.
 *
 * Both are `@c9up/flare` exceptions, one per code: a protocol error is an
 * `E_VISA_OAUTH_ERROR` whose `oauthCode` holds the protocol's string.
 */

import { createError, Exception } from "@c9up/flare";

/** Error codes the authorization endpoint may return (OAuth 2.1 §4.1.2.1). */
export type AuthorizationErrorCode =
	| "invalid_request"
	| "unauthorized_client"
	| "access_denied"
	| "unsupported_response_type"
	| "invalid_scope"
	/** RFC 8707 §2 — a resource this server will not issue for, or cannot parse. */
	| "invalid_target"
	| "server_error"
	| "temporarily_unavailable";

/** Error codes the token endpoint may return (OAuth 2.1 §4.1.4). */
export type TokenErrorCode =
	| "invalid_request"
	| "invalid_client"
	| "invalid_grant"
	| "unauthorized_client"
	| "unsupported_grant_type"
	| "invalid_scope"
	/** RFC 8707 §2. */
	| "invalid_target";

/** Error codes the registration endpoint may return (RFC 7591 §3.2.2). */
export type RegistrationErrorCode =
	| "invalid_redirect_uri"
	| "invalid_client_metadata"
	| "invalid_software_statement"
	| "unapproved_software_statement";

/**
 * Error codes an endpoint protected by a bearer token answers with (RFC 6750
 * §3.1) — the registration endpoint's initial access token among them (RFC
 * 7591 §3: "an error response appropriate to the OAuth 2.0 token type").
 */
export type BearerErrorCode = "invalid_token";

export type ProtocolErrorCode =
	| AuthorizationErrorCode
	| TokenErrorCode
	| RegistrationErrorCode
	| BearerErrorCode;

/**
 * A failure the client is told about, in the words the spec chose:
 * `oauthCode` is the protocol's string (`invalid_grant`, `invalid_client`…).
 *
 * `description` is optional and OPTIONAL on purpose: it goes on the wire, so
 * it says what the client can act on and never why a check failed internally.
 */
export class E_VISA_OAUTH_ERROR extends Exception {
	static override code = "E_VISA_OAUTH_ERROR";
	static override status = 400;

	/** The protocol's error code, the `error` member of the response. */
	readonly oauthCode: ProtocolErrorCode;
	readonly description: string | undefined;
	/**
	 * The `WWW-Authenticate` value a 401 carries, when the failure names one.
	 *
	 * A 401 has to say how to authenticate (RFC 9110 §15.5.2): `Basic` for a
	 * client credential, `Bearer` for a token (RFC 6750 §3).
	 */
	readonly challenge: string | undefined;

	/**
	 * `status` defaults to 401 for `invalid_client` and `invalid_token`, 400
	 * for everything else (§4.1.4, RFC 6750 §3.1).
	 */
	constructor(
		oauthCode: ProtocolErrorCode,
		description?: string,
		options: { status?: number; challenge?: string } = {},
	) {
		super(
			description === undefined ? oauthCode : `${oauthCode}: ${description}`,
			{
				status:
					options.status ??
					(oauthCode === "invalid_client" || oauthCode === "invalid_token"
						? 401
						: 400),
			},
		);
		this.oauthCode = oauthCode;
		this.description = description;
		this.challenge = options.challenge;
	}

	/** The body, exactly as §4.1.4 shapes it. */
	toResponse(): { error: ProtocolErrorCode; error_description?: string } {
		return this.description === undefined
			? { error: this.oauthCode }
			: { error: this.oauthCode, error_description: this.description };
	}
}

/**
 * An authorization failure that cannot be redirected: the client or its
 * redirect URI is unknown, so the user must be told directly. `error` is
 * the protocol error to show.
 *
 * Separate from `E_VISA_OAUTH_ERROR` because the CALLER has to treat it
 * differently: render a page, never `Location:`.
 */
export class E_VISA_UNREDIRECTABLE extends Exception {
	static override code = "E_VISA_UNREDIRECTABLE";
	static override status = 400;

	readonly error: E_VISA_OAUTH_ERROR;

	constructor(error: E_VISA_OAUTH_ERROR) {
		super(error.message, { status: error.status });
		this.error = error;
	}
}

/**
 * A token that does not carry the ability asked of it — what
 * `currentAccessToken.authorize()` throws.
 *
 * The upstream id `E_UNAUTHORIZED_ACCESS` verbatim rather than an
 * `E_VISA_*` code, so a handler that already maps it keeps working whichever
 * guard authenticated the request. 403, not 401: the request is
 * authenticated, the token is merely too narrow (RFC 6750 §3.1,
 * `insufficient_scope`).
 */
export const E_UNAUTHORIZED_ACCESS = createError<[ability: string]>(
	'Access denied: the token does not carry "%s"',
	"E_UNAUTHORIZED_ACCESS",
	403,
);

/** No `issuer` is configured. */
export class E_VISA_MISSING_ISSUER extends createError(
	"visa needs an issuer — the public URL this authorization server answers on.",
	"E_VISA_MISSING_ISSUER",
) {
	static override help =
		"Set `issuer` in config/visa.ts, e.g. https://auth.example.com";
}

/** The `issuer` is not a URL, or carries a query string or a fragment. */
export const E_VISA_INVALID_ISSUER = createError<[message: string]>(
	"%s",
	"E_VISA_INVALID_ISSUER",
);

/** The `issuer` is not https (localhost excepted). */
export const E_VISA_INSECURE_ISSUER = createError<[issuer: string]>(
	"visa's issuer must be https (localhost excepted): %s",
	"E_VISA_INSECURE_ISSUER",
);

/** `registration.initialAccessToken` is empty. */
export class E_VISA_INVALID_INITIAL_ACCESS_TOKEN extends createError(
	"registration.initialAccessToken is empty, which would accept an empty bearer token.",
	"E_VISA_INVALID_INITIAL_ACCESS_TOKEN",
) {
	static override help =
		"Set a long random value, or leave it out for open registration.";
}

/** Registration is on, and the store cannot save a client. */
export class E_VISA_STORE_READ_ONLY extends createError(
	"This store cannot register clients; create them where they live.",
	"E_VISA_STORE_READ_ONLY",
) {
	static override help =
		"Implement saveClient(client) on the store — MemoryStore and AtlasStore both do.";
}

/** A client registered without a redirect URI. */
export const E_VISA_NO_REDIRECT_URI = createError(
	"A client needs at least one redirect URI.",
	"E_VISA_NO_REDIRECT_URI",
);

/** A redirect URI that is not a complete URL, carries a fragment or a wildcard. */
export const E_VISA_INVALID_REDIRECT_URI = createError<[message: string]>(
	"%s",
	"E_VISA_INVALID_REDIRECT_URI",
);

/** `registration.secretTtlSeconds` is not a positive whole number of seconds. */
export class E_VISA_INVALID_SECRET_TTL extends createError<[ttl: unknown]>(
	"registration.secretTtlSeconds must be a positive whole number of seconds; received %s.",
	"E_VISA_INVALID_SECRET_TTL",
) {
	static override help = "Leave it out for a secret that never expires.";
}

/**
 * A lifetime (`accessTokenTtlSeconds`, `refreshTokenTtlSeconds`,
 * `codeTtlSeconds`, `consentTicketTtlSeconds` in the config, the guard's
 * `expiresInSeconds`) is not a positive whole number of seconds.
 */
export class E_VISA_INVALID_TTL extends createError<
	[option: string, ttl: unknown]
>(
	"%s must be a positive whole number of seconds; received %s.",
	"E_VISA_INVALID_TTL",
) {
	static override help = "Leave it out to keep the default lifetime.";
}

/** `VisaProvider` found no `config/visa.ts`. */
export const E_VISA_MISSING_CONFIG = createError(
	"[visa] no `config/visa.ts` — run `ream configure @c9up/visa`.",
	"E_VISA_MISSING_CONFIG",
);

/** `@c9up/visa/services/main` read before `VisaProvider` booted or `setVisa()`. */
export const E_VISA_NOT_BOOTED = createError(
	"[visa] accessed before initialization — register VisaProvider, or call setVisa() yourself.",
	"E_VISA_NOT_BOOTED",
);

/** `authenticate()` with credentials on the visa guard. */
export const E_VISA_CREDENTIALS_UNSUPPORTED = createError(
	"visa authenticates a bearer token, not credentials. Use verify() with the access token.",
	"E_VISA_CREDENTIALS_UNSUPPORTED",
);

/** The guard's `createToken()` ran without `tokenClientId`. */
export const E_VISA_NO_TOKEN_CLIENT = createError(
	"[visa] createToken needs `tokenClientId` — a token is always issued to a client. Name the first-party application in visaGuard({ tokenClientId }).",
	"E_VISA_NO_TOKEN_CLIENT",
);

/** A protected-resource identifier that is not an absolute URI, or carries a fragment. */
export const E_VISA_INVALID_RESOURCE = createError<[message: string]>(
	"%s",
	"E_VISA_INVALID_RESOURCE",
);

/** A `WWW-Authenticate` parameter that cannot be a quoted string. */
export const E_VISA_INVALID_CHALLENGE_PARAMETER = createError<
	[parameter: string]
>(
	"[visa] %s cannot go in a WWW-Authenticate header: it holds a quote, a backslash or a control character",
	"E_VISA_INVALID_CHALLENGE_PARAMETER",
);

/** The Atlas store read a column it cannot decode. */
export const E_VISA_CORRUPT_ROW = createError<[message: string]>(
	"%s",
	"E_VISA_CORRUPT_ROW",
);

/** The `@c9up/visa/testing` helper's authorization request was refused. */
export const E_VISA_TEST_AUTHORIZE_FAILED = createError<[message: string]>(
	"authorize failed: %s",
	"E_VISA_TEST_AUTHORIZE_FAILED",
);

/** An internal invariant broke: a bug in visa, to report. */
export const E_VISA_INTERNAL = createError<[message: string]>(
	"%s",
	"E_VISA_INTERNAL",
);
