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
		).rejects.toMatchObject({ code: "invalid_client" });
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
		).rejects.toMatchObject({ code: "invalid_grant" });
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
