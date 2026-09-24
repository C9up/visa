/**
 * Clients that register themselves (RFC 7591).
 *
 * An MCP client such as claude.ai or ChatGPT has nobody to fill in a form for
 * it: it discovers this server, registers, and comes back with an id. Without
 * this the only way in is a human pasting credentials somewhere.
 *
 * OFF unless the application turns it on, and that is the important part. Open
 * registration means anyone who can reach the endpoint can create a client —
 * the RFC says a server SHOULD allow it for interoperability, and also says
 * the endpoint MAY be protected (§1.2, §3). The safe default here is the one
 * the RFC permits rather than the one it encourages, because an authorization
 * server that silently accepts registrations is a thing nobody asked for. Turn
 * it on deliberately, and with an initial access token if the deployment is
 * not meant to be open.
 *
 * A registered client gets exactly what this server allows: the grants,
 * scopes and auth methods in the configuration, never what the request asked
 * for. That is the difference between letting a client name itself and letting
 * it decide what it may do.
 */

import { OAuthError } from "./errors.js";
import type { Client, ClientAuthMethod, GrantType } from "./types.js";

/** The metadata a request may send (§2). Unknown members are ignored. */
export interface ClientRegistrationRequest {
	redirect_uris?: unknown;
	token_endpoint_auth_method?: unknown;
	grant_types?: unknown;
	response_types?: unknown;
	client_name?: unknown;
	client_uri?: unknown;
	logo_uri?: unknown;
	scope?: unknown;
	contacts?: unknown;
	tos_uri?: unknown;
	policy_uri?: unknown;
	software_id?: unknown;
	software_version?: unknown;
	software_statement?: unknown;
	/**
	 * Whatever else the client sent.
	 *
	 * §2 says a server ignores metadata it does not understand, and this is a
	 * parsed HTTP body — a client that sends `client_id` hoping to pick its own
	 * is a real thing, and it lands here rather than being a type error nobody
	 * sees at run time.
	 */
	[member: string]: unknown;
}

/** The 201 body (§3.2.1). */
export interface ClientRegistrationResponse {
	client_id: string;
	client_secret?: string;
	/** Seconds since the epoch. */
	client_id_issued_at: number;
	/** REQUIRED when a secret was issued. `0` means it does not expire. */
	client_secret_expires_at?: number;
	redirect_uris: string[];
	grant_types: GrantType[];
	token_endpoint_auth_method: ClientAuthMethod;
	client_name: string;
	scope?: string;
}

export interface RegistrationOptions {
	/** Nothing happens unless this is true. */
	enabled?: boolean;
	/**
	 * Require this bearer token on the registration request.
	 *
	 * Left out, the endpoint is open — which is what an MCP client that has
	 * never met you needs, and what a deployment on the public internet should
	 * think about before shipping.
	 */
	initialAccessToken?: string;
	/** What a self-registered client may ever ask for. Defaults to none. */
	scopes?: readonly string[];
	/** Which grants it may use. Defaults to the authorization code flow and refresh. */
	grantTypes?: readonly GrantType[];
	/** Seconds until an issued secret expires. Omitted means it does not (§3.2.1). */
	secretTtlSeconds?: number;
}

const DEFAULT_GRANTS: readonly GrantType[] = [
	"authorization_code",
	"refresh_token",
];

/**
 * Check a registration request and say what the client may be.
 *
 * Returns the client to store and the plaintext secret, if one was issued —
 * the caller persists the first and hands back the second, once.
 */
export function validateRegistration(
	request: ClientRegistrationRequest,
	options: RegistrationOptions,
	presentedToken?: string,
): {
	redirectUris: string[];
	grantTypes: GrantType[];
	scopes: string[];
	tokenEndpointAuthMethod: ClientAuthMethod;
	name: string;
} {
	if (options.enabled !== true) {
		throw new OAuthError(
			"invalid_client_metadata",
			"This server does not accept client registrations.",
		);
	}
	if (options.initialAccessToken !== undefined) {
		// Constant-time is not the point here: the token is compared once per
		// registration, and a registration endpoint is not a guessing oracle
		// worth the machinery. Absent or wrong reads the same to the caller.
		if (presentedToken !== options.initialAccessToken) {
			throw new OAuthError(
				"invalid_client_metadata",
				"Registration on this server needs an initial access token.",
			);
		}
	}

	const redirectUris = readStringList(request.redirect_uris);
	const grantTypes = resolveGrants(request.grant_types, options);

	// A client using the authorization code flow has somewhere to come back to,
	// and this is the last moment anyone checks.
	if (grantTypes.includes("authorization_code") && redirectUris.length === 0) {
		throw new OAuthError(
			"invalid_redirect_uri",
			"redirect_uris is required for the authorization_code grant.",
		);
	}
	for (const uri of redirectUris) assertRedirectUri(uri);

	const allowed = options.scopes ?? [];
	const requested = readScope(request.scope);
	const outside = requested.filter((scope) => !allowed.includes(scope));
	if (outside.length > 0) {
		throw new OAuthError(
			"invalid_client_metadata",
			`This server does not grant ${outside.join(", ")} to a self-registered client.`,
		);
	}

	return {
		redirectUris,
		grantTypes,
		// What was asked for, narrowed to what is allowed — never the allowed
		// set, or every client would be registered with everything.
		scopes: requested,
		tokenEndpointAuthMethod: readAuthMethod(request.token_endpoint_auth_method),
		name: readName(request.client_name),
	};
}

/** The 201 body for a client that was just created. */
export function registrationResponse(
	client: Client,
	issuedAt: Date,
	secret: string | undefined,
	options: RegistrationOptions,
): ClientRegistrationResponse {
	const seconds = Math.floor(issuedAt.getTime() / 1000);
	return {
		client_id: client.id,
		...(secret === undefined ? {} : { client_secret: secret }),
		client_id_issued_at: seconds,
		// REQUIRED when a secret was issued, and `0` is the spelling for "never"
		// — not an omission, which would mean the field was not answered.
		...(secret === undefined
			? {}
			: {
					client_secret_expires_at:
						options.secretTtlSeconds === undefined
							? 0
							: seconds + options.secretTtlSeconds,
				}),
		redirect_uris: client.redirectUris,
		grant_types: client.grantTypes,
		token_endpoint_auth_method: client.tokenEndpointAuthMethod,
		client_name: client.name,
		...(client.scopes.length === 0 ? {} : { scope: client.scopes.join(" ") }),
	};
}

function resolveGrants(
	value: unknown,
	options: RegistrationOptions,
): GrantType[] {
	const allowed = options.grantTypes ?? DEFAULT_GRANTS;
	const requested = readStringList(value);
	if (requested.length === 0) return [...allowed];
	const grants: GrantType[] = [];
	for (const grant of requested) {
		if (!isGrantType(grant) || !allowed.includes(grant)) {
			throw new OAuthError(
				"invalid_client_metadata",
				`This server does not allow the ${grant} grant to a self-registered client.`,
			);
		}
		if (!grants.includes(grant)) grants.push(grant);
	}
	return grants;
}

/**
 * A redirect URI a self-registered client may use.
 *
 * https, or http on a loopback address — a native app's callback. Anything
 * else is refused: an authorization code sent over plain http to a host
 * someone else controls is the code given away.
 */
function assertRedirectUri(value: string): void {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		throw new OAuthError(
			"invalid_redirect_uri",
			`${value} is not an absolute URI.`,
		);
	}
	if (url.hash !== "") {
		throw new OAuthError(
			"invalid_redirect_uri",
			`${value} must not carry a fragment.`,
		);
	}
	if (url.protocol === "https:") return;
	const loopback =
		url.hostname === "127.0.0.1" ||
		url.hostname === "[::1]" ||
		url.hostname === "localhost";
	if (url.protocol === "http:" && loopback) return;
	throw new OAuthError(
		"invalid_redirect_uri",
		`${value} must use https, or http on a loopback address.`,
	);
}

function readStringList(value: unknown): string[] {
	if (value === undefined || value === null) return [];
	if (!Array.isArray(value)) {
		throw new OAuthError(
			"invalid_client_metadata",
			"redirect_uris and grant_types must be arrays of strings.",
		);
	}
	return value.filter((entry): entry is string => typeof entry === "string");
}

function readScope(value: unknown): string[] {
	if (value === undefined || value === null) return [];
	if (typeof value !== "string") {
		throw new OAuthError(
			"invalid_client_metadata",
			"scope must be a space-separated string.",
		);
	}
	return value.split(/\s+/).filter((scope) => scope !== "");
}

function readAuthMethod(value: unknown): ClientAuthMethod {
	if (value === undefined || value === null) return "client_secret_basic";
	if (
		value === "client_secret_basic" ||
		value === "client_secret_post" ||
		value === "none"
	) {
		return value;
	}
	throw new OAuthError(
		"invalid_client_metadata",
		`token_endpoint_auth_method ${String(value)} is not supported.`,
	);
}

function readName(value: unknown): string {
	if (typeof value === "string" && value.trim() !== "") return value.trim();
	// A client with no name shows as one on a consent screen, which is worse
	// than a placeholder nobody mistakes for a brand.
	return "Unnamed client";
}

function isGrantType(value: string): value is GrantType {
	return (
		value === "authorization_code" ||
		value === "refresh_token" ||
		value === "client_credentials"
	);
}
