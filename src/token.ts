/**
 * The token endpoint — the three grants OAuth 2.1 keeps.
 *
 * `password` and `implicit` are gone from the spec and are not implemented
 * here under any option: both hand a credential to a party that should never
 * hold one, and an application that needs them needs a different design.
 */

import {
	assertGrantAllowed,
	authenticateClient,
	type ClientCredentials,
	resolveScopes,
} from "./clients.js";
import { hashMatches, hashSecret, randomToken, sha256 } from "./crypto.js";
import { OAuthError } from "./errors.js";
import type { VisaStore } from "./store.js";
import type { Client, GrantType, TokenResponse } from "./types.js";

export interface TokenOptions {
	accessTokenTtlSeconds?: number;
	refreshTokenTtlSeconds?: number;
	/** Hand out refresh tokens at all. */
	issueRefreshTokens?: boolean;
}

const DEFAULTS = {
	accessTokenTtlSeconds: 3600,
	refreshTokenTtlSeconds: 60 * 60 * 24 * 30,
	issueRefreshTokens: true,
};

/** The body of a token request, untrusted. */
export type TokenRequest = Record<string, unknown>;

export async function token(
	request: TokenRequest,
	credentials: ClientCredentials,
	store: VisaStore,
	options: TokenOptions = {},
	now: Date = new Date(),
): Promise<TokenResponse> {
	const grant = asString(request.grant_type);
	if (grant === undefined) {
		throw new OAuthError("invalid_request", "grant_type is required.");
	}
	// Authenticate BEFORE looking at the grant: an unknown grant from an
	// unauthenticated caller must not be distinguishable from an unknown grant
	// from a real client.
	const client = await authenticateClient(credentials, (id) =>
		store.findClient(id),
	);

	if (!isKnownGrant(grant)) {
		throw new OAuthError(
			"unsupported_grant_type",
			grant === "password" || grant === "implicit"
				? `The ${grant} grant was removed in OAuth 2.1.`
				: undefined,
		);
	}
	assertGrantAllowed(client, grant);

	if (grant === "authorization_code") {
		return exchangeCode(request, client, store, options, now);
	}
	if (grant === "refresh_token") {
		return exchangeRefresh(request, client, store, options, now);
	}
	return clientCredentials(request, client, store, options, now);
}

function isKnownGrant(grant: string): grant is GrantType {
	return (
		grant === "authorization_code" ||
		grant === "refresh_token" ||
		grant === "client_credentials"
	);
}

/**
 * The authorization code grant.
 *
 * Four things are verified, and each one has a published attack behind it:
 * the code belongs to THIS client (otherwise a malicious client redeems
 * another's code), the redirect URI is the one it was issued for (code
 * injection), the PKCE verifier hashes to the stored challenge (interception
 * on a native app), and the code has not been used (replay).
 */
async function exchangeCode(
	request: TokenRequest,
	client: Client,
	store: VisaStore,
	options: TokenOptions,
	now: Date,
): Promise<TokenResponse> {
	const code = asString(request.code);
	const verifier = asString(request.code_verifier);
	if (code === undefined) {
		throw new OAuthError("invalid_request", "code is required.");
	}
	if (verifier === undefined) {
		throw new OAuthError("invalid_request", "code_verifier is required.");
	}

	const record = await store.findAuthorizationCode(hashSecret(code));
	// One sentence for every failure below: "no such code", "expired",
	// "already used" and "wrong client" are indistinguishable to the caller.
	const invalid = new OAuthError("invalid_grant", "The code is not valid.");
	if (record === null || record.clientId !== client.id) throw invalid;
	if (record.expiresAt <= now) throw invalid;

	if (record.consumedAt !== undefined) {
		// A code coming back a second time means it leaked. Anything it already
		// bought has to go with it — the legitimate exchange has happened, so
		// the tokens in flight are the attacker's or a race.
		await store.revokeFamily(codeFamily(record.codeHash), now);
		throw invalid;
	}

	const redirectUri = asString(request.redirect_uri);
	// Required whenever it was in the authorization request, which this server
	// always records.
	if (redirectUri !== record.redirectUri) throw invalid;

	if (
		!verifierMatches(verifier, record.codeChallenge, record.codeChallengeMethod)
	) {
		throw invalid;
	}

	// The single-use gate. Atomic in the store, so two requests racing with the
	// same code cannot both pass.
	if (!(await store.consumeAuthorizationCode(record.codeHash, now))) {
		throw invalid;
	}

	return issue(
		{
			client,
			userId: record.userId,
			scopes: record.scopes,
			familyId: codeFamily(record.codeHash),
		},
		store,
		options,
		now,
	);
}

/**
 * The family a code's tokens belong to.
 *
 * Derived from the code rather than random, so the tokens minted from a code
 * can be revoked when that same code is replayed — at which point the code
 * record is all we have to go on.
 */
function codeFamily(codeHash: string): string {
	return sha256(`family:${codeHash}`);
}

/** PKCE verification (RFC 7636 §4.6). */
function verifierMatches(
	verifier: string,
	challenge: string,
	method: "S256" | "plain",
): boolean {
	const computed = method === "S256" ? sha256(verifier) : verifier;
	return hashMatches(computed, challenge);
}

/**
 * The refresh grant, with rotation.
 *
 * Every use mints a new refresh token and consumes the old one. A consumed
 * token coming back is a replay — the legitimate holder has already moved on
 * — and since there is no way to tell the thief from the victim, the whole
 * family is revoked and both are signed out (RFC 9700 §4.14.2).
 */
async function exchangeRefresh(
	request: TokenRequest,
	client: Client,
	store: VisaStore,
	options: TokenOptions,
	now: Date,
): Promise<TokenResponse> {
	const presented = asString(request.refresh_token);
	if (presented === undefined) {
		throw new OAuthError("invalid_request", "refresh_token is required.");
	}
	const record = await store.findRefreshToken(hashSecret(presented));
	const invalid = new OAuthError(
		"invalid_grant",
		"The refresh token is not valid.",
	);
	if (record === null || record.clientId !== client.id) throw invalid;
	if (record.revokedAt !== undefined) throw invalid;

	if (record.consumedAt !== undefined) {
		await store.revokeFamily(record.familyId, now);
		throw invalid;
	}
	if (record.expiresAt <= now) throw invalid;

	// A refresh MUST NOT widen what was consented to (§4.3.1); it may narrow.
	const requested = asString(request.scope);
	const scopes =
		requested === undefined ? record.scopes : narrow(requested, record.scopes);

	if (!(await store.consumeRefreshToken(record.tokenHash, now))) throw invalid;

	return issue(
		{
			client,
			...(record.userId === undefined ? {} : { userId: record.userId }),
			scopes,
			familyId: record.familyId,
		},
		store,
		options,
		now,
	);
}

function narrow(requested: string, granted: readonly string[]): string[] {
	const asked = requested.split(/\s+/).filter((scope) => scope !== "");
	const extra = asked.filter((scope) => !granted.includes(scope));
	if (extra.length > 0) {
		throw new OAuthError(
			"invalid_scope",
			`Not part of the original grant: ${extra.join(" ")}`,
		);
	}
	return asked;
}

/**
 * The client credentials grant — the client acting as itself.
 *
 * No user, so no refresh token: there is nothing to keep alive on someone's
 * behalf, and the client can always ask again with the credentials it holds
 * (§4.2.3).
 */
async function clientCredentials(
	request: TokenRequest,
	client: Client,
	store: VisaStore,
	options: TokenOptions,
	now: Date,
): Promise<TokenResponse> {
	if (client.tokenEndpointAuthMethod === "none") {
		// A public client has no secret, so "the client itself" is anyone who
		// read its id out of a browser.
		throw new OAuthError(
			"unauthorized_client",
			"A public client cannot use the client_credentials grant.",
		);
	}
	const scopes = resolveScopes(asString(request.scope), client);
	return issue(
		{ client, scopes },
		store,
		{ ...options, issueRefreshTokens: false },
		now,
	);
}

interface Issued {
	client: Client;
	userId?: string;
	scopes: string[];
	familyId?: string;
}

/** Mint the pair and store both, hashed. */
async function issue(
	grant: Issued,
	store: VisaStore,
	options: TokenOptions,
	now: Date,
): Promise<TokenResponse> {
	const accessTtl =
		options.accessTokenTtlSeconds ?? DEFAULTS.accessTokenTtlSeconds;
	const accessToken = randomToken();

	await store.saveAccessToken({
		tokenHash: hashSecret(accessToken),
		clientId: grant.client.id,
		...(grant.userId === undefined ? {} : { userId: grant.userId }),
		scopes: grant.scopes,
		expiresAt: new Date(now.getTime() + accessTtl * 1000),
		...(grant.familyId === undefined ? {} : { familyId: grant.familyId }),
	});

	const response: TokenResponse = {
		access_token: accessToken,
		token_type: "Bearer",
		expires_in: accessTtl,
		scope: grant.scopes.join(" "),
	};

	const wantsRefresh =
		(options.issueRefreshTokens ?? DEFAULTS.issueRefreshTokens) &&
		grant.familyId !== undefined &&
		grant.client.grantTypes.includes("refresh_token");
	if (!wantsRefresh || grant.familyId === undefined) return response;

	const refreshTtl =
		options.refreshTokenTtlSeconds ?? DEFAULTS.refreshTokenTtlSeconds;
	const refreshToken = randomToken();
	await store.saveRefreshToken({
		tokenHash: hashSecret(refreshToken),
		familyId: grant.familyId,
		clientId: grant.client.id,
		...(grant.userId === undefined ? {} : { userId: grant.userId }),
		scopes: grant.scopes,
		expiresAt: new Date(now.getTime() + refreshTtl * 1000),
	});
	response.refresh_token = refreshToken;
	return response;
}

function asString(value: unknown): string | undefined {
	return typeof value === "string" && value !== "" ? value : undefined;
}
