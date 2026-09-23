/**
 * Revocation (RFC 7009) and introspection (RFC 7662).
 *
 * Both answer the same way to a token that is unknown, expired, revoked or
 * belongs to someone else — revocation with 200, introspection with
 * `{ active: false }`. That uniformity IS the security property: a different
 * answer per case turns either endpoint into an oracle for guessing tokens.
 */

import { authenticateClient, type ClientCredentials } from "./clients.js";
import { hashSecret } from "./crypto.js";
import { OAuthError } from "./errors.js";
import type { VisaStore } from "./store.js";
import type { IntrospectionResponse } from "./types.js";

/** `{ active: false }` — the only thing an inactive token ever reveals. */
const INACTIVE: IntrospectionResponse = { active: false };

export async function introspect(
	request: Record<string, unknown>,
	credentials: ClientCredentials,
	store: VisaStore,
	now: Date = new Date(),
): Promise<IntrospectionResponse> {
	// The CALLER authenticates — introspection tells you whether a credential
	// is live, which is exactly what an attacker wants to ask.
	const caller = await authenticateClient(credentials, (id) =>
		store.findClient(id),
	);
	const presented = asString(request.token);
	if (presented === undefined) {
		throw new OAuthError("invalid_request", "token is required.");
	}

	const hash = hashSecret(presented);
	const hint =
		asString(request.token_hint) ?? asString(request.token_type_hint);

	// The hint is an optimisation, never a filter: a wrong hint must still
	// find the token (RFC 7662 §2.1).
	const access =
		hint === "refresh_token" ? null : await store.findAccessToken(hash);
	if (access !== null) {
		if (access.revokedAt !== undefined || access.expiresAt <= now) {
			return INACTIVE;
		}
		// A client may only introspect its own tokens.
		if (access.clientId !== caller.id) return INACTIVE;
		return {
			active: true,
			scope: access.scopes.join(" "),
			client_id: access.clientId,
			token_type: "Bearer",
			exp: Math.floor(access.expiresAt.getTime() / 1000),
			...(access.userId === undefined ? {} : { sub: access.userId }),
		};
	}

	const refresh = await store.findRefreshToken(hash);
	if (refresh === null) return INACTIVE;
	if (
		refresh.revokedAt !== undefined ||
		refresh.consumedAt !== undefined ||
		refresh.expiresAt <= now ||
		refresh.clientId !== caller.id
	) {
		return INACTIVE;
	}
	return {
		active: true,
		scope: refresh.scopes.join(" "),
		client_id: refresh.clientId,
		exp: Math.floor(refresh.expiresAt.getTime() / 1000),
		...(refresh.userId === undefined ? {} : { sub: refresh.userId }),
	};
}

/**
 * Revoke a token. Answers nothing, always successfully (RFC 7009 §2.2).
 *
 * Revoking a REFRESH token takes its whole family with it, access tokens
 * included: "sign me out" has to mean the session is over, not that one of
 * its two credentials was retired.
 */
export async function revoke(
	request: Record<string, unknown>,
	credentials: ClientCredentials,
	store: VisaStore,
	now: Date = new Date(),
): Promise<void> {
	const caller = await authenticateClient(credentials, (id) =>
		store.findClient(id),
	);
	const presented = asString(request.token);
	if (presented === undefined) {
		throw new OAuthError("invalid_request", "token is required.");
	}
	const hash = hashSecret(presented);

	const refresh = await store.findRefreshToken(hash);
	if (refresh !== null) {
		// Someone else's token: nothing happens, and they are not told so.
		if (refresh.clientId !== caller.id) return;
		await store.revokeFamily(refresh.familyId, now);
		return;
	}

	const access = await store.findAccessToken(hash);
	if (access === null || access.clientId !== caller.id) return;
	await store.revokeAccessToken(hash, now);
}

/**
 * Is this bearer token good, and for what?
 *
 * What a resource server calls on every request — so it reads the store
 * directly instead of going through introspection's client authentication.
 */
export async function verifyAccessToken(
	presented: string,
	store: VisaStore,
	now: Date = new Date(),
): Promise<{ clientId: string; userId?: string; scopes: string[] } | null> {
	const token = await store.findAccessToken(hashSecret(presented));
	if (token === null) return null;
	if (token.revokedAt !== undefined || token.expiresAt <= now) return null;
	return {
		clientId: token.clientId,
		...(token.userId === undefined ? {} : { userId: token.userId }),
		scopes: token.scopes,
	};
}

function asString(value: unknown): string | undefined {
	return typeof value === "string" && value !== "" ? value : undefined;
}
