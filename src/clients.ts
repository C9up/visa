/**
 * Who is asking, and are they allowed to ask that.
 *
 * Three checks live here and each one closes a known attack: the redirect URI
 * comparison (an open redirect on the client's domain turns into a stolen
 * code), the client authentication (a leaked client_id is not a credential),
 * and the scope narrowing (a client must not be able to grant itself more
 * than it was registered for).
 */

import { secretMatches } from "./crypto.js";
import { OAuthError } from "./errors.js";
import type { Client, GrantType } from "./types.js";

/**
 * Does this redirect URI match one the client registered?
 *
 * EXACT string comparison, as OAuth 2.1 §2.3.1 requires — with the single
 * exception it names: a loopback redirect may differ in its port, because a
 * native app cannot know in advance which port the OS will hand it.
 *
 * No prefix matching, no wildcard, no "same origin is close enough": every
 * one of those has a published attack where the code lands on a URL the
 * attacker controls.
 */
export function redirectUriMatches(
	candidate: string,
	registered: readonly string[],
): boolean {
	if (registered.includes(candidate)) return true;

	let url: URL;
	try {
		url = new URL(candidate);
	} catch {
		return false;
	}
	if (!isLoopback(url.hostname)) return false;

	return registered.some((entry) => {
		let known: URL;
		try {
			known = new URL(entry);
		} catch {
			return false;
		}
		if (!isLoopback(known.hostname)) return false;
		// Everything but the port has to be identical.
		return (
			known.protocol === url.protocol &&
			known.hostname === url.hostname &&
			known.pathname === url.pathname &&
			known.search === url.search
		);
	});
}

function isLoopback(hostname: string): boolean {
	return hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

/** Credentials as they arrived, from either place the spec allows. */
export interface ClientCredentials {
	clientId?: string;
	clientSecret?: string;
	/** The raw `Authorization` header, if there was one. */
	authorization?: string;
}

/**
 * Read `client_id` / `client_secret` out of a request.
 *
 * A client MUST NOT use more than one authentication method in a single
 * request (§2.4): sending both Basic and body credentials is a sign of a
 * confused proxy or of an attempt to have one of them ignored, so it is
 * refused rather than resolved by precedence.
 */
export function readCredentials(input: {
	authorization?: string;
	body: Record<string, unknown>;
}): ClientCredentials {
	const basic = parseBasic(input.authorization);
	const bodyId = stringOrUndefined(input.body.client_id);
	const bodySecret = stringOrUndefined(input.body.client_secret);

	if (basic !== undefined && bodySecret !== undefined) {
		throw new OAuthError(
			"invalid_request",
			"More than one client authentication method was used.",
		);
	}
	if (basic !== undefined) {
		// A body client_id that disagrees with the header is not a mismatch to
		// resolve — it is two different claims about who is asking.
		if (bodyId !== undefined && bodyId !== basic.clientId) {
			throw new OAuthError(
				"invalid_request",
				"The client_id in the body does not match the one authenticated.",
			);
		}
		return basic;
	}
	return { clientId: bodyId, clientSecret: bodySecret };
}

function parseBasic(header?: string): ClientCredentials | undefined {
	if (header === undefined) return undefined;
	const [scheme, encoded] = header.split(" ");
	if (scheme?.toLowerCase() !== "basic" || encoded === undefined) {
		return undefined;
	}
	const decoded = Buffer.from(encoded, "base64").toString("utf8");
	const separator = decoded.indexOf(":");
	if (separator === -1) {
		throw new OAuthError("invalid_client", "Malformed Basic credentials.");
	}
	// RFC 6749 §2.3.1 form-encodes both halves before base64.
	return {
		clientId: decodeURIComponent(decoded.slice(0, separator)),
		clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
	};
}

function stringOrUndefined(value: unknown): string | undefined {
	return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * Authenticate a client for the token endpoint.
 *
 * Every failure answers `invalid_client` with no detail — "no such client",
 * "wrong secret" and "that client has no secret" are the same sentence to the
 * caller, because telling them apart is how a client list gets enumerated.
 */
export async function authenticateClient(
	credentials: ClientCredentials,
	load: (id: string) => Promise<Client | null>,
): Promise<Client> {
	if (credentials.clientId === undefined) {
		throw new OAuthError("invalid_client", "Client authentication failed.");
	}
	const client = await load(credentials.clientId);
	if (client === null) {
		throw new OAuthError("invalid_client", "Client authentication failed.");
	}

	if (client.tokenEndpointAuthMethod === "none") {
		// A public client authenticates by not authenticating. Accepting a
		// secret here would let one be registered as public and used as
		// confidential, which is a downgrade the client chooses.
		if (credentials.clientSecret !== undefined) {
			throw new OAuthError("invalid_client", "Client authentication failed.");
		}
		return client;
	}

	if (
		credentials.clientSecret === undefined ||
		client.secretHash === undefined ||
		!secretMatches(credentials.clientSecret, client.secretHash)
	) {
		throw new OAuthError("invalid_client", "Client authentication failed.");
	}
	return client;
}

/** Is this grant one the client was registered for? */
export function assertGrantAllowed(client: Client, grant: GrantType): void {
	if (client.grantTypes.includes(grant)) return;
	throw new OAuthError(
		"unauthorized_client",
		`This client may not use the ${grant} grant.`,
	);
}

/**
 * Narrow a requested scope against what the client may ever have.
 *
 * Absent, the request gets the client's registered set — never "everything".
 * A scope the client was not registered for is refused rather than dropped:
 * silently granting less than asked is how a client ends up believing it has
 * a permission it does not.
 */
export function resolveScopes(
	requested: string | undefined,
	client: Client,
): string[] {
	if (requested === undefined || requested.trim() === "") {
		return [...client.scopes];
	}
	const asked = requested.split(/\s+/).filter((scope) => scope !== "");
	const unknown = asked.filter((scope) => !client.scopes.includes(scope));
	if (unknown.length > 0) {
		throw new OAuthError(
			"invalid_scope",
			`Not registered for: ${unknown.join(" ")}`,
		);
	}
	return asked;
}
