/**
 * Revocation and introspection.
 *
 * Both are oracles if they answer differently per case, so the property under
 * test is mostly SAMENESS: unknown, expired, revoked and someone else's all
 * look alike from the outside.
 */

import { describe, expect, it } from "vitest";
import { authorizeToCode, creds, harness, pkce, REDIRECT } from "./helpers.js";

async function pair(h: Awaited<ReturnType<typeof harness>>) {
	const { verifier, challenge } = pkce();
	const code = await authorizeToCode(h, { challenge, scope: "profile" });
	return h.visa.token(
		{
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
		},
		creds(h),
	);
}

describe("visa > introspection", () => {
	it("describes a live access token to the client that owns it", async () => {
		const h = await harness();
		const tokens = await pair(h);
		const result = await h.visa.introspect(
			{ token: tokens.access_token },
			creds(h),
		);
		expect(result).toMatchObject({
			active: true,
			client_id: h.client.id,
			sub: "user-1",
			scope: "profile",
			token_type: "Bearer",
		});
	});

	it("says only `active: false` for anything that is not", async () => {
		const h = await harness();
		const tokens = await pair(h);

		// Unknown.
		expect(await h.visa.introspect({ token: "invented" }, creds(h))).toEqual({
			active: false,
		});

		// Expired.
		const later = new Date(Date.now() + 3600_001);
		expect(
			await h.visa.introspect({ token: tokens.access_token }, creds(h), later),
		).toEqual({ active: false });

		// Someone else's — no hint that it exists.
		const { client, secret } = await h.visa.registerClient({
			id: "other",
			name: "Other",
			redirectUris: [REDIRECT],
		});
		const other = { ...h, client, secret: secret ?? "" };
		expect(
			await h.visa.introspect({ token: tokens.access_token }, creds(other)),
		).toEqual({ active: false });
	});

	it("finds a refresh token even when the hint says otherwise", async () => {
		// The hint is an optimisation, never a filter (RFC 7662 §2.1).
		const h = await harness();
		const tokens = await pair(h);
		const result = await h.visa.introspect(
			{ token: tokens.refresh_token, token_type_hint: "access_token" },
			creds(h),
		);
		expect(result.active).toBe(true);
	});

	it("requires the caller to authenticate", async () => {
		// Asking "is this credential live?" is what an attacker wants to do.
		const h = await harness();
		const tokens = await pair(h);
		await expect(
			h.visa.introspect(
				{ token: tokens.access_token },
				{ clientId: h.client.id },
			),
		).rejects.toMatchObject({ oauthCode: "invalid_client" });
	});

	it("finds an access token even when the hint says refresh_token", async () => {
		// RFC 7662 §2.1: a server that cannot locate the token with the hint
		// MUST extend its search to every token type. The refresh hint used to
		// skip the access table, and a live token was reported dead.
		const h = await harness();
		const tokens = await pair(h);
		const result = await h.visa.introspect(
			{ token: tokens.access_token, token_type_hint: "refresh_token" },
			creds(h),
		);
		expect(result).toMatchObject({
			active: true,
			client_id: h.client.id,
			token_type: "Bearer",
		});
	});

	it("describes a refresh token looked up with its own hint", async () => {
		const h = await harness();
		const tokens = await pair(h);
		const result = await h.visa.introspect(
			{ token: tokens.refresh_token, token_type_hint: "refresh_token" },
			creds(h),
		);
		expect(result).toMatchObject({ active: true, client_id: h.client.id });
	});
});

describe("visa > introspection by a resource server", () => {
	/** `app` gets the user's tokens; `api` is the protected resource. */
	async function withResourceServer(
		api: {
			id?: string;
			tokenEndpointAuthMethod?: "client_secret_basic" | "none";
		} = {},
		resourceServers: readonly string[] = ["api"],
	) {
		const h = await harness({}, { introspection: { resourceServers } });
		const tokens = await pair(h);
		const { client, secret } = await h.visa.registerClient({
			id: api.id ?? "api",
			name: "The API",
			redirectUris: [REDIRECT],
			grantTypes: ["client_credentials"],
			tokenEndpointAuthMethod:
				api.tokenEndpointAuthMethod ?? "client_secret_basic",
		});
		const resource = { ...h, client, secret: secret ?? "" };
		return { h, tokens, resource };
	}

	it("answers a named resource server about another client's access token", async () => {
		// RFC 7662 §2.1: "The protected resource calls the introspection
		// endpoint". Only the client the token was issued to used to get an
		// answer, and it already knows its own token.
		const { h, tokens, resource } = await withResourceServer();
		const result = await h.visa.introspect(
			{ token: tokens.access_token },
			creds(resource),
		);
		expect(result).toMatchObject({
			active: true,
			client_id: h.client.id,
			sub: "user-1",
			scope: "profile",
		});
	});

	it("still answers inactive to a client that is not named", async () => {
		const { h, tokens, resource } = await withResourceServer({}, ["other"]);
		expect(
			await h.visa.introspect({ token: tokens.access_token }, creds(resource)),
		).toEqual({ active: false });
	});

	it("never answers a public client, even a named one", async () => {
		// A public client authenticates with nothing: naming it would let
		// anyone who knows its id introspect every token.
		const { h, tokens, resource } = await withResourceServer({
			tokenEndpointAuthMethod: "none",
		});
		expect(
			await h.visa.introspect({ token: tokens.access_token }, creds(resource)),
		).toEqual({ active: false });
	});

	it("keeps refresh tokens to the client they were issued to", async () => {
		// A refresh token is never sent to a resource server (RFC 6749 §1.5).
		const { h, tokens, resource } = await withResourceServer();
		expect(
			await h.visa.introspect({ token: tokens.refresh_token }, creds(resource)),
		).toEqual({ active: false });
	});
});

describe("visa > revocation", () => {
	it("takes the whole family when a refresh token is revoked", async () => {
		// "Sign me out" has to mean the session is over, not that one of its
		// two credentials was retired.
		const h = await harness();
		const tokens = await pair(h);

		await h.visa.revoke({ token: tokens.refresh_token }, creds(h));

		expect(await h.visa.verify(tokens.access_token)).toBeNull();
		await expect(
			h.visa.token(
				{ grant_type: "refresh_token", refresh_token: tokens.refresh_token },
				creds(h),
			),
		).rejects.toMatchObject({ oauthCode: "invalid_grant" });
	});

	it("revokes an access token on its own without touching the refresh", async () => {
		const h = await harness();
		const tokens = await pair(h);
		await h.visa.revoke({ token: tokens.access_token }, creds(h));

		expect(await h.visa.verify(tokens.access_token)).toBeNull();
		// The session survives: the client can still refresh.
		const next = await h.visa.token(
			{ grant_type: "refresh_token", refresh_token: tokens.refresh_token },
			creds(h),
		);
		expect(next.access_token).toBeTypeOf("string");
	});

	it("succeeds silently on a token that is not the caller's, and on nonsense", async () => {
		// RFC 7009 §2.2: an invalid token is not an error, because saying so
		// turns the endpoint into a guessing game.
		const h = await harness();
		const tokens = await pair(h);
		const { client, secret } = await h.visa.registerClient({
			id: "other",
			name: "Other",
			redirectUris: [REDIRECT],
		});
		const other = { ...h, client, secret: secret ?? "" };

		await expect(
			h.visa.revoke({ token: "never-existed" }, creds(h)),
		).resolves.toBeUndefined();
		await expect(
			other.visa.revoke({ token: tokens.access_token }, creds(other)),
		).resolves.toBeUndefined();

		// And the token someone else tried to revoke is untouched.
		expect(await h.visa.verify(tokens.access_token)).not.toBeNull();
	});
});
