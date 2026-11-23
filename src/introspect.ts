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
import { E_VISA_OAUTH_ERROR } from "./errors.js";
import { audienceAllows } from "./resource.js";
import type { VisaStore } from "./store.js";
import type {
	AccessToken,
	Client,
	IntrospectionResponse,
	RefreshToken,
} from "./types.js";

/** `{ active: false }` — the only thing an inactive token ever reveals. */
const INACTIVE: IntrospectionResponse = { active: false };

/** Who may introspect a token other than the client it was issued to. */
export interface IntrospectionOptions {
	/**
	 * Client ids of the protected resources allowed to introspect any ACCESS
	 * token, whichever client it was issued to.
	 *
	 * RFC 7662 §2.1: "The protected resource calls the introspection endpoint",
	 * and §4 leaves to the server which callers it answers. Without a rule a
	 * resource server in another process has no way to check a token: `verify()`
	 * needs the store, and introspection only ever answered the client the token
	 * was issued to, which already knows it. Named here rather than inferred, so
	 * a client registering itself (RFC 7591) never gains it.
	 *
	 * Only a confidential client counts — a public one authenticates with
	 * nothing, so naming it would open introspection to anyone who knows its
	 * id. Refresh tokens stay with their own client: they are never sent to a
	 * resource server (RFC 6749 §1.5).
	 */
	resourceServers?: readonly string[];
}

export async function introspect(
	request: Record<string, unknown>,
	credentials: ClientCredentials,
	store: VisaStore,
	now: Date = new Date(),
	issuer?: string,
	options: IntrospectionOptions = {},
): Promise<IntrospectionResponse> {
	// The CALLER authenticates — introspection tells you whether a credential
	// is live, which is exactly what an attacker wants to ask.
	const caller = await authenticateClient(credentials, (id) =>
		store.findClient(id),
	);
	const presented = asString(request.token);
	if (presented === undefined) {
		throw new E_VISA_OAUTH_ERROR("invalid_request", "token is required.");
	}

	const hash = hashSecret(presented);
	const hint =
		asString(request.token_hint) ?? asString(request.token_type_hint);

	// The hint is an optimisation, never a filter: RFC 7662 §2.1 — "If the
	// server is unable to locate the token using the given hint, it MUST
	// extend its search across all of its supported token types". It only
	// decides which table is read first.
	if (hint === "refresh_token") {
		const refresh = await store.findRefreshToken(hash);
		if (refresh !== null)
			return describeRefresh(refresh, caller.id, now, issuer);
		const access = await store.findAccessToken(hash);
		if (access === null) return INACTIVE;
		return describeAccess(access, caller, now, issuer, options);
	}
	const access = await store.findAccessToken(hash);
	if (access !== null) {
		return describeAccess(access, caller, now, issuer, options);
	}
	const refresh = await store.findRefreshToken(hash);
	if (refresh === null) return INACTIVE;
	return describeRefresh(refresh, caller.id, now, issuer);
}

/**
 * Whether `caller` may learn about a token issued to `clientId`.
 *
 * The client the token was issued to, always; a protected resource named in
 * `resourceServers`, for access tokens only. Anyone else reads
 * `{ active: false }`, exactly as for a token that does not exist.
 */
function mayIntrospectAccess(
	caller: Client,
	clientId: string,
	options: IntrospectionOptions,
): boolean {
	if (caller.id === clientId) return true;
	return (
		caller.tokenEndpointAuthMethod !== "none" &&
		(options.resourceServers ?? []).includes(caller.id)
	);
}

function describeAccess(
	access: AccessToken,
	caller: Client,
	now: Date,
	issuer: string | undefined,
	options: IntrospectionOptions,
): IntrospectionResponse {
	if (access.revokedAt !== undefined || access.expiresAt <= now) {
		return INACTIVE;
	}
	if (!mayIntrospectAccess(caller, access.clientId, options)) return INACTIVE;
	return {
		active: true,
		...(issuer === undefined ? {} : { iss: issuer }),
		scope: access.scopes.join(" "),
		client_id: access.clientId,
		token_type: "Bearer",
		exp: Math.floor(access.expiresAt.getTime() / 1000),
		...(access.userId === undefined ? {} : { sub: access.userId }),
		// RFC 8707 §3 names introspection as where a resource server learns
		// what a token was minted for.
		...(access.audience === undefined ? {} : { aud: access.audience }),
	};
}

function describeRefresh(
	refresh: RefreshToken,
	callerId: string,
	now: Date,
	issuer: string | undefined,
): IntrospectionResponse {
	if (
		refresh.revokedAt !== undefined ||
		refresh.consumedAt !== undefined ||
		refresh.expiresAt <= now ||
		// A refresh token never travels to a resource server: only the client
		// it was issued to has any business asking about it.
		refresh.clientId !== callerId
	) {
		return INACTIVE;
	}
	return {
		active: true,
		...(issuer === undefined ? {} : { iss: issuer }),
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
		throw new E_VISA_OAUTH_ERROR("invalid_request", "token is required.");
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
	// Only the one read: a resource server that keeps nothing but tokens should
	// not have to implement eleven methods it never calls.
	store: Pick<VisaStore, "findAccessToken">,
	now: Date = new Date(),
	/**
	 * This resource's identifier (RFC 8707).
	 *
	 * Given, a token minted for a different resource is refused here rather
	 * than honoured — which is the entire point of binding one.
	 */
	resource?: string,
): Promise<{
	clientId: string;
	userId?: string;
	scopes: string[];
	expiresAt: Date;
	lastUsedAt?: Date;
	audience?: string[];
} | null> {
	const token = await store.findAccessToken(hashSecret(presented));
	if (token === null) return null;
	if (token.revokedAt !== undefined || token.expiresAt <= now) return null;
	// RFC 8707: a token bound to a resource is refused anywhere else. Unbound
	// tokens are accepted — that is every token issued before a client started
	// asking, and refusing them would break each one.
	if (!audienceAllows(token.audience, resource)) return null;
	return {
		clientId: token.clientId,
		...(token.userId === undefined ? {} : { userId: token.userId }),
		scopes: token.scopes,
		// Carried out so a caller can report the expiry it just checked, rather
		// than reading the store a second time to say the same thing.
		expiresAt: token.expiresAt,
		// The PREVIOUS use, before this one is recorded — which is what the
		// upstream guard shows on `currentAccessToken.lastUsedAt`.
		...(token.lastUsedAt === undefined ? {} : { lastUsedAt: token.lastUsedAt }),
		...(token.audience === undefined ? {} : { audience: token.audience }),
	};
}

function asString(value: unknown): string | undefined {
	return typeof value === "string" && value !== "" ? value : undefined;
}
