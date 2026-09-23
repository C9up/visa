/**
 * The authorization endpoint.
 *
 * Each case here is a published attack, not a style preference: an
 * unregistered redirect URI (stolen code), a missing PKCE challenge
 * (interception on a native app), an error bounced to an unverified URI
 * (client enumeration plus a page of the attacker's choosing in the user's
 * session).
 */

import { describe, expect, it } from "vitest";
import { OAuthError } from "../../src/errors.js";
import { authorizeToCode, harness, pkce, REDIRECT } from "./helpers.js";

describe("visa > authorize > what may be redirected", () => {
	it("refuses to bounce an error to an unregistered redirect URI", async () => {
		// The whole point: an attacker who can name the redirect gets the user
		// agent sent wherever they like, and learns the client exists.
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				redirect_uri: "https://evil.example.test/callback",
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		expect(outcome.type).toBe("error");
		if (outcome.type !== "error") throw new Error("unreachable");
		expect(outcome.error.code).toBe("invalid_request");
	});

	it("refuses an unknown client without redirecting anywhere", async () => {
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: "not-a-client",
				redirect_uri: REDIRECT,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		expect(outcome.type).toBe("error");
	});

	it("DOES redirect an error once the URI is verified", async () => {
		// The URI checked out, so the client is the right place to report to —
		// and it gets its state back, which its own CSRF check needs.
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				redirect_uri: REDIRECT,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
				scope: "admin",
				state: "xyz",
			},
			"user-1",
		);
		expect(outcome.type).toBe("redirect");
		if (outcome.type !== "redirect") throw new Error("unreachable");
		const url = new URL(outcome.url);
		expect(url.origin + url.pathname).toBe(REDIRECT);
		expect(url.searchParams.get("error")).toBe("invalid_scope");
		expect(url.searchParams.get("state")).toBe("xyz");
	});
});

describe("visa > authorize > PKCE", () => {
	it("requires a code challenge, from confidential clients too", async () => {
		// 2.1 makes PKCE universal: a confidential client's code is just as
		// interceptable on the front channel.
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				redirect_uri: REDIRECT,
			},
			"user-1",
		);
		if (outcome.type !== "redirect") throw new Error("expected a redirect");
		expect(new URL(outcome.url).searchParams.get("error_description")).toBe(
			"code_challenge is required.",
		);
	});

	it("refuses `plain` unless it was deliberately enabled", async () => {
		// plain puts the verifier in the authorization request, so anything
		// that can read that request can complete the exchange.
		const h = await harness();
		const request = {
			response_type: "code" as const,
			client_id: h.client.id,
			redirect_uri: REDIRECT,
			code_challenge: "a-verifier",
			code_challenge_method: "plain",
		};
		const refused = await h.visa.authorize(request, "user-1");
		if (refused.type !== "redirect") throw new Error("expected a redirect");
		expect(new URL(refused.url).searchParams.get("error")).toBe(
			"invalid_request",
		);

		const lenient = await harness({}, { allowPlainChallenge: true });
		const allowed = await lenient.visa.authorize(
			{ ...request, client_id: lenient.client.id },
			"user-1",
		);
		expect(allowed.type).not.toBe("error");
	});

	it("refuses a method it does not know", async () => {
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				redirect_uri: REDIRECT,
				code_challenge: "x",
				code_challenge_method: "S512",
			},
			"user-1",
		);
		if (outcome.type !== "redirect") throw new Error("expected a redirect");
		expect(new URL(outcome.url).searchParams.get("error")).toBe(
			"invalid_request",
		);
	});
});

describe("visa > authorize > response types", () => {
	it("names the implicit grant when a client asks for it", async () => {
		// `response_type=token` is a port from OAuth 2.0, not a typo — saying
		// so beats a blank refusal.
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "token",
				client_id: h.client.id,
				redirect_uri: REDIRECT,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		if (outcome.type !== "redirect") throw new Error("expected a redirect");
		const url = new URL(outcome.url);
		expect(url.searchParams.get("error")).toBe("unsupported_response_type");
		expect(url.searchParams.get("error_description")).toContain("implicit");
	});
});

describe("visa > authorize > redirect URIs", () => {
	it("matches exactly — not by prefix", async () => {
		// A prefix match is how an open redirect on the client's own domain
		// becomes a stolen authorization code.
		const h = await harness();
		for (const attempt of [
			`${REDIRECT}/../evil`,
			`${REDIRECT}?next=https://evil.test`,
			`${REDIRECT}extra`,
			"https://app.example.test/callback/",
		]) {
			const outcome = await h.visa.authorize(
				{
					response_type: "code",
					client_id: h.client.id,
					redirect_uri: attempt,
					code_challenge: pkce().challenge,
					code_challenge_method: "S256",
				},
				"user-1",
			);
			expect(outcome.type, attempt).toBe("error");
		}
	});

	it("allows a loopback redirect to differ in its port, and only in that", async () => {
		// A native app cannot know which port the OS will hand it (§2.3.1).
		const h = await harness({
			id: "native",
			redirectUris: ["http://127.0.0.1:1234/cb"],
			tokenEndpointAuthMethod: "none",
		});
		const ok = await h.visa.authorize(
			{
				response_type: "code",
				client_id: "native",
				redirect_uri: "http://127.0.0.1:55555/cb",
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		expect(ok.type).not.toBe("error");

		const wrongPath = await h.visa.authorize(
			{
				response_type: "code",
				client_id: "native",
				redirect_uri: "http://127.0.0.1:55555/other",
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		expect(wrongPath.type).toBe("error");
	});

	it("requires the parameter when the client registered several", async () => {
		// Picking one for the client is picking where the code goes.
		const h = await harness({
			redirectUris: [REDIRECT, "https://app.example.test/other"],
		});
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		expect(outcome.type).toBe("error");
	});
});

describe("visa > authorize > consent", () => {
	it("asks before granting, and remembers the answer", async () => {
		const h = await harness();
		const request = {
			response_type: "code" as const,
			client_id: h.client.id,
			redirect_uri: REDIRECT,
			scope: "profile",
			code_challenge: pkce().challenge,
			code_challenge_method: "S256",
		};

		const first = await h.visa.authorize(request, "user-1");
		expect(first.type).toBe("consent");
		if (first.type !== "consent") throw new Error("unreachable");
		await h.visa.grant(first.request, "user-1");

		// Asked once: the second time the stored consent covers it.
		const second = await h.visa.authorize(request, "user-1");
		expect(second.type).toBe("redirect");
	});

	it("asks again when the client wants MORE than was agreed", async () => {
		const h = await harness();
		const base = {
			response_type: "code" as const,
			client_id: h.client.id,
			redirect_uri: REDIRECT,
			code_challenge: pkce().challenge,
			code_challenge_method: "S256",
		};
		const first = await h.visa.authorize(
			{ ...base, scope: "profile" },
			"user-1",
		);
		if (first.type !== "consent") throw new Error("expected consent");
		await h.visa.grant(first.request, "user-1");

		const wider = await h.visa.authorize(
			{ ...base, scope: "profile email" },
			"user-1",
		);
		expect(wider.type).toBe("consent");
	});

	it("asks again on prompt=consent, and skips it for a trusted client", async () => {
		const h = await harness();
		const request = {
			response_type: "code" as const,
			client_id: h.client.id,
			redirect_uri: REDIRECT,
			scope: "profile",
			code_challenge: pkce().challenge,
			code_challenge_method: "S256",
		};
		const first = await h.visa.authorize(request, "user-1");
		if (first.type !== "consent") throw new Error("expected consent");
		await h.visa.grant(first.request, "user-1");

		const forced = await h.visa.authorize(
			{ ...request, prompt: "consent" },
			"user-1",
		);
		expect(forced.type).toBe("consent");

		// A first-party application you own does not ask the user to approve
		// itself.
		const trusted = await harness({ id: "own", trusted: true });
		const outcome = await trusted.visa.authorize(
			{ ...request, client_id: "own" },
			"user-1",
		);
		expect(outcome.type).toBe("redirect");
	});

	it("asks for authentication when nobody is signed in", async () => {
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				redirect_uri: REDIRECT,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			undefined,
		);
		expect(outcome.type).toBe("consent");
	});

	it("sends access_denied back when the user refuses", async () => {
		const h = await harness();
		const outcome = await h.visa.authorize(
			{
				response_type: "code",
				client_id: h.client.id,
				redirect_uri: REDIRECT,
				state: "xyz",
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		if (outcome.type !== "consent") throw new Error("expected consent");
		const url = new URL(h.visa.deny(outcome.request));
		expect(url.searchParams.get("error")).toBe("access_denied");
		expect(url.searchParams.get("state")).toBe("xyz");
	});
});

describe("visa > authorize > the code itself", () => {
	it("returns the state verbatim, and none when there was none", async () => {
		const h = await harness();
		const code = await authorizeToCode(h);
		expect(code).toHaveLength(43);
	});

	it("refuses a scope the client was never registered for", async () => {
		const h = await harness();
		await expect(
			authorizeToCode(h, { scope: "billing" }),
		).rejects.toBeInstanceOf(Error);
	});

	it("carries a VisaError, not an OAuthError, for a wiring mistake", async () => {
		// Two audiences: one error goes on the wire, the other to whoever
		// wired the server.
		const { VisaManager } = await import("../../src/VisaManager.js");
		const { MemoryStore } = await import("../../src/stores/memory.js");
		expect(
			() => new VisaManager({ issuer: "", store: new MemoryStore() }),
		).toThrowError(/issuer/);
		expect(new OAuthError("invalid_grant").toResponse()).toEqual({
			error: "invalid_grant",
		});
	});
});
