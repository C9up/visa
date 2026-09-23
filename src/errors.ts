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
 */

/** Error codes the authorization endpoint may return (OAuth 2.1 §4.1.2.1). */
export type AuthorizationErrorCode =
	| "invalid_request"
	| "unauthorized_client"
	| "access_denied"
	| "unsupported_response_type"
	| "invalid_scope"
	| "server_error"
	| "temporarily_unavailable";

/** Error codes the token endpoint may return (OAuth 2.1 §4.1.4). */
export type TokenErrorCode =
	| "invalid_request"
	| "invalid_client"
	| "invalid_grant"
	| "unauthorized_client"
	| "unsupported_grant_type"
	| "invalid_scope";

export type ProtocolErrorCode = AuthorizationErrorCode | TokenErrorCode;

/**
 * A failure the client is told about, in the words the spec chose.
 *
 * `description` is optional and OPTIONAL on purpose: it goes on the wire, so
 * it says what the client can act on and never why a check failed internally.
 */
export class OAuthError extends Error {
	readonly code: ProtocolErrorCode;
	readonly description: string | undefined;
	/** 401 for `invalid_client`, 400 for everything else (§4.1.4). */
	readonly status: number;

	constructor(
		code: ProtocolErrorCode,
		description?: string,
		options: { status?: number } = {},
	) {
		super(description === undefined ? code : `${code}: ${description}`);
		this.name = "OAuthError";
		this.code = code;
		this.description = description;
		this.status = options.status ?? (code === "invalid_client" ? 401 : 400);
	}

	/** The body, exactly as §4.1.4 shapes it. */
	toResponse(): { error: ProtocolErrorCode; error_description?: string } {
		return this.description === undefined
			? { error: this.code }
			: { error: this.code, error_description: this.description };
	}
}

/** A mistake in the application, addressed to whoever wired it. */
export class VisaError extends Error {
	readonly code: string;
	readonly hint: string | undefined;

	constructor(code: string, message: string, options: { hint?: string } = {}) {
		super(message);
		this.name = "VisaError";
		this.code = code;
		this.hint = options.hint;
	}
}
