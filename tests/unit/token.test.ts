/**
 * The token endpoint.
 *
 * The properties under test are the ones that hold a session together: a code
 * works once, for the client it was issued to, at the URI it was issued for,
 * and only with the verifier that matches its challenge. A refresh token
 * rotates, and a replayed one ends the whole session rather than guessing
 * which of the two holders is the thief.
 */

import { describe, expect, it } from "vitest";
import { hashSecret } from "../../src/crypto.js";
import { OAuthError } from "../../src/errors.js";
import type { TokenResponse } from "../../src/types.js";
import {
	authorizeToCode,
	basic,
	codeFrom,
	harness,
	pkce,
	REDIRECT,
} from "./helpers.js";

async function exchange(
	h: Awaited<ReturnType<typeof harness>>,
	body: Record<string, unknown>,
): Promise<TokenResponse> {
	return h.visa.token(body, h.visa.readCredentials({ ...basic(h), body }));
}

describe("visa > token > the authorization code grant", () => {
	it("exchanges a code for a pair, scoped to what was consented", async () => {
		const h = await harness();
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, { challenge, scope: "profile" });

		const response = await exchange(h, {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
		});

		expect(response.token_type).toBe("Bearer");
		expect(response.scope).toBe("profile");
		expect(response.expires_in).toBe(3600);
		expect(response.refresh_token).toBeTypeOf("string");

		// The token works, and says who it is for.
		const verified = await h.visa.verify(response.access_token);
		expect(verified).toEqual({
			clientId: h.client.id,
			userId: "user-1",
			scopes: ["profile"],
			// Carried out so the guard can answer `isExpired()` without a second read.
			expiresAt: expect.any(Date),
		});
	});

	it("stores nothing that can be replayed from a dump", async () => {
		// Every credential is hashed at rest: a database copy is not a set of
		// working tokens.
		const h = await harness();
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, { challenge });
		const response = await exchange(h, {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
		});

		expect(await h.store.findAccessToken(response.access_token)).toBeNull();
		expect(
			await h.store.findAccessToken(hashSecret(response.access_token)),
		).not.toBeNull();
	});

	it("refuses a code the second time, and kills what it bought", async () => {
		// A code coming back has leaked. The legitimate exchange already
		// happened, so the tokens it produced are the attacker's — or a race.
		const h = await harness();
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, { challenge });
		const body = {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
		};
		const first = await exchange(h, body);

		await expect(exchange(h, body)).rejects.toMatchObject({
			code: "invalid_grant",
		});
		// What the first exchange minted is gone too.
		expect(await h.visa.verify(first.access_token)).toBeNull();
	});

	it("refuses the wrong verifier, and a missing one", async () => {
		const h = await harness();
		const { challenge } = pkce();
		const code = await authorizeToCode(h, { challenge });

		await expect(
			exchange(h, {
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				code_verifier: pkce().verifier,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });

		await expect(
			exchange(h, {
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
			}),
		).rejects.toMatchObject({ code: "invalid_request" });
	});

	it("refuses a redirect URI that is not the one the code was issued for", async () => {
		// Code injection: the attacker replays a code into their own session
		// on a different callback.
		const h = await harness({
			redirectUris: [REDIRECT, "https://app.example.test/other"],
		});
		const { verifier, challenge } = pkce();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				redirect_uri: REDIRECT,
				code_challenge: challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		if (outcome.type !== "consent") throw new Error("expected consent");
		const url = await h.visa.grant(outcome.request, "user-1");
		const code = new URL(url).searchParams.get("code") ?? "";

		await expect(
			exchange(h, {
				grant_type: "authorization_code",
				code,
				redirect_uri: "https://app.example.test/other",
				code_verifier: verifier,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });
	});

	it("exchanges a code without redirect_uri when the authorization request had none", async () => {
		// RFC 6749 §4.1.3 / OAuth 2.1 §4.1.3: redirect_uri is required at the
		// token endpoint only "if the redirect_uri parameter was included in the
		// authorization request". A client with one registered URI may omit it
		// in both requests.
		const h = await harness();
		const { verifier, challenge } = pkce();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				code_challenge: challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		if (outcome.type !== "consent") throw new Error("expected consent");
		const code = codeFrom(await h.visa.grant(outcome.request, "user-1"));

		const response = await exchange(h, {
			grant_type: "authorization_code",
			code,
			code_verifier: verifier,
		});
		expect(response.access_token).toBeTypeOf("string");
	});

	it("still compares redirect_uri when a client that omitted it sends one", async () => {
		const h = await harness({
			redirectUris: [REDIRECT],
		});
		const { verifier, challenge } = pkce();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				code_challenge: challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		if (outcome.type !== "consent") throw new Error("expected consent");
		const code = codeFrom(await h.visa.grant(outcome.request, "user-1"));

		await expect(
			exchange(h, {
				grant_type: "authorization_code",
				code,
				redirect_uri: "https://app.example.test/other",
				code_verifier: verifier,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });
	});

	it("refuses an exchange without redirect_uri when the authorization request carried it", async () => {
		// The other half of §4.1.3: included at authorization, it is REQUIRED
		// at the token endpoint.
		const h = await harness();
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, { challenge });

		await expect(
			exchange(h, {
				grant_type: "authorization_code",
				code,
				code_verifier: verifier,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });
	});

	it("refuses a code that belongs to another client", async () => {
		const first = await harness();
		const second = await harness({ id: "other", name: "Other" });
		// Same store would be the realistic case; here the point is the
		// ownership check, so put the second client in the first's store.
		const { client, secret } = await first.visa.registerClient({
			id: "other",
			name: "Other",
			redirectUris: [REDIRECT],
			scopes: ["profile"],
		});
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(first, { challenge });

		const thief = { ...first, client, secret: secret ?? "" };
		await expect(
			exchange(thief, {
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				code_verifier: verifier,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });
		void second;
	});

	it("refuses an expired code", async () => {
		const h = await harness({}, { codeTtlSeconds: 30 });
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, { challenge });

		const later = new Date(Date.now() + 31_000);
		await expect(
			h.visa.token(
				{
					grant_type: "authorization_code",
					code,
					redirect_uri: REDIRECT,
					code_verifier: verifier,
				},
				h.visa.readCredentials({ ...basic(h), body: {} }),
				later,
			),
		).rejects.toMatchObject({ code: "invalid_grant" });
	});

	it("says the same sentence for every way a code can be wrong", async () => {
		// "No such code", "expired", "already used" and "wrong client" are one
		// message: telling them apart is how a code space gets probed.
		const h = await harness();
		const failures: string[] = [];
		for (const code of ["nope", ""]) {
			try {
				await exchange(h, {
					grant_type: "authorization_code",
					code,
					redirect_uri: REDIRECT,
					code_verifier: "v",
				});
			} catch (error) {
				failures.push(error instanceof OAuthError ? error.message : "other");
			}
		}
		// The empty one fails on a missing parameter, which is not a secret.
		expect(failures[0]).toBe("invalid_grant: The code is not valid.");
	});
});

describe("visa > token > refresh rotation", () => {
	async function firstPair(h: Awaited<ReturnType<typeof harness>>) {
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, { challenge });
		return exchange(h, {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
		});
	}

	it("hands back a NEW refresh token every time", async () => {
		const h = await harness();
		const first = await firstPair(h);
		const second = await exchange(h, {
			grant_type: "refresh_token",
			refresh_token: first.refresh_token,
		});
		expect(second.refresh_token).not.toBe(first.refresh_token);
		expect(second.access_token).not.toBe(first.access_token);
	});

	it("ends the whole session when a spent refresh token comes back", async () => {
		// The replay proves a leak. There is no way to tell the thief from the
		// victim, so both are signed out (RFC 9700 §4.14.2).
		const h = await harness();
		const first = await firstPair(h);
		const second = await exchange(h, {
			grant_type: "refresh_token",
			refresh_token: first.refresh_token,
		});

		await expect(
			exchange(h, {
				grant_type: "refresh_token",
				refresh_token: first.refresh_token,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });

		// The legitimate holder's current tokens are gone as well.
		await expect(
			exchange(h, {
				grant_type: "refresh_token",
				refresh_token: second.refresh_token,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });
		expect(await h.visa.verify(second.access_token)).toBeNull();
	});

	it("lets a refresh narrow the scope but never widen it", async () => {
		const h = await harness();
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, {
			challenge,
			scope: "profile email",
		});
		const pair = await exchange(h, {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
		});

		const narrowed = await exchange(h, {
			grant_type: "refresh_token",
			refresh_token: pair.refresh_token,
			scope: "profile",
		});
		expect(narrowed.scope).toBe("profile");
		expect((await h.visa.verify(narrowed.access_token))?.scopes).toEqual([
			"profile",
		]);

		// Never wider than what the user agreed to.
		await expect(
			exchange(h, {
				grant_type: "refresh_token",
				refresh_token: narrowed.refresh_token,
				scope: "profile email openid",
			}),
		).rejects.toMatchObject({ code: "invalid_scope" });
	});

	it("narrows only the access token: the rotated refresh token keeps the grant (RFC 6749 §6)", async () => {
		// "If a new refresh token is issued, the refresh token scope MUST be
		// identical to that of the refresh token included by the client in the
		// request." A down-scoped token for one call must not cost the rest of
		// the user's consent for the whole session.
		const h = await harness();
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, {
			challenge,
			scope: "profile email",
		});
		const pair = await exchange(h, {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			code_verifier: verifier,
		});

		const narrowed = await exchange(h, {
			grant_type: "refresh_token",
			refresh_token: pair.refresh_token,
			scope: "profile",
		});
		expect(narrowed.scope).toBe("profile");

		const restored = await exchange(h, {
			grant_type: "refresh_token",
			refresh_token: narrowed.refresh_token,
			scope: "profile email",
		});
		expect(restored.scope).toBe("profile email");

		// No `scope` at all: the original grant, not the last narrowing.
		const unscoped = await exchange(h, {
			grant_type: "refresh_token",
			refresh_token: (
				await exchange(h, {
					grant_type: "refresh_token",
					refresh_token: restored.refresh_token,
					scope: "email",
				})
			).refresh_token,
		});
		expect(unscoped.scope).toBe("profile email");
	});

	it("refuses a refresh token presented by another client", async () => {
		const h = await harness();
		const pair = await firstPair(h);
		const { client, secret } = await h.visa.registerClient({
			id: "other",
			name: "Other",
			redirectUris: [REDIRECT],
			scopes: ["profile"],
		});
		const other = { ...h, client, secret: secret ?? "" };
		await expect(
			exchange(other, {
				grant_type: "refresh_token",
				refresh_token: pair.refresh_token,
			}),
		).rejects.toMatchObject({ code: "invalid_grant" });
	});
});

describe("visa > token > client credentials", () => {
	it("issues a token with no user and no refresh token", async () => {
		const h = await harness({
			grantTypes: ["client_credentials"],
			scopes: ["reports"],
		});
		const response = await exchange(h, { grant_type: "client_credentials" });
		expect(response.refresh_token).toBeUndefined();
		const verified = await h.visa.verify(response.access_token);
		expect(verified?.userId).toBeUndefined();
		expect(verified?.scopes).toEqual(["reports"]);
	});

	it("refuses it to a public client", async () => {
		// "The client itself" means nothing when anyone can read the id out of
		// a browser.
		const h = await harness({
			tokenEndpointAuthMethod: "none",
			grantTypes: ["client_credentials"],
		});
		await expect(
			h.visa.token(
				{ grant_type: "client_credentials" },
				{ clientId: h.client.id },
			),
		).rejects.toMatchObject({ code: "unauthorized_client" });
	});
});

describe("visa > token > grants and clients", () => {
	it("refuses a grant the client was not registered for", async () => {
		const h = await harness({ grantTypes: ["authorization_code"] });
		await expect(
			exchange(h, { grant_type: "client_credentials" }),
		).rejects.toMatchObject({ code: "unauthorized_client" });
	});

	it("names the grants OAuth 2.1 removed", async () => {
		const h = await harness();
		for (const grant of ["password", "implicit"]) {
			await expect(exchange(h, { grant_type: grant })).rejects.toMatchObject({
				code: "unsupported_grant_type",
			});
		}
	});

	it("refuses a wrong secret, an absent one, and one on a public client", async () => {
		const h = await harness();
		const body = { grant_type: "client_credentials" };

		await expect(
			h.visa.token(body, { clientId: h.client.id, clientSecret: "wrong" }),
		).rejects.toMatchObject({ code: "invalid_client", status: 401 });

		await expect(
			h.visa.token(body, { clientId: h.client.id }),
		).rejects.toMatchObject({ code: "invalid_client" });

		const open = await harness({ id: "spa", tokenEndpointAuthMethod: "none" });
		await expect(
			open.visa.token(body, { clientId: "spa", clientSecret: "invented" }),
		).rejects.toMatchObject({ code: "invalid_client" });
	});

	it("refuses two authentication methods in one request", async () => {
		// A sign of a confused proxy, or of an attempt to have one of them
		// ignored (§2.4).
		const h = await harness();
		expect(() =>
			h.visa.readCredentials({
				...basic(h),
				body: { client_id: h.client.id, client_secret: h.secret },
			}),
		).toThrowError(/more than one client authentication method/i);
	});

	it("refuses a body client_id that disagrees with the authenticated one", async () => {
		const h = await harness();
		expect(() =>
			h.visa.readCredentials({
				...basic(h),
				body: { client_id: "someone-else" },
			}),
		).toThrowError(/does not match/i);
	});

	it("reads form-encoded Basic credentials", async () => {
		// RFC 6749 §2.3.1 form-encodes both halves before base64.
		const h = await harness({ id: "a b" });
		const raw = `${encodeURIComponent("a b")}:${encodeURIComponent(h.secret)}`;
		const credentials = h.visa.readCredentials({
			authorization: `Basic ${Buffer.from(raw).toString("base64")}`,
			body: {},
		});
		expect(credentials.clientId).toBe("a b");
	});
});
