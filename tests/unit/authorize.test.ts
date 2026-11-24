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
import { errorRedirect } from "../../src/authorize.js";
import { E_VISA_OAUTH_ERROR } from "../../src/errors.js";
import { authorizeToCode, harness, ISSUER, pkce, REDIRECT } from "./helpers.js";

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
		expect(outcome.error.oauthCode).toBe("invalid_request");
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

/**
 * RFC 9207: every authorization response names the server that produced it,
 * so a client using several servers can tell a code injected from another
 * one (the mix-up attack, RFC 9700 §4.4).
 */
describe("visa > authorize > the issuer on the response (RFC 9207)", () => {
	const request = (h: Awaited<ReturnType<typeof harness>>) => ({
		response_type: "code",
		client_id: h.client.id,
		redirect_uri: REDIRECT,
		code_challenge: pkce().challenge,
		code_challenge_method: "S256",
		state: "xyz",
	});

	it("names the issuer on a success, a refusal and an error redirect", async () => {
		const h = await harness();
		const outcome = await h.visa.authorize(request(h), "user-1");
		if (outcome.type !== "consent") throw new Error("expected consent");

		const success = new URL(await h.visa.grant(outcome.request, "user-1"));
		const denied = new URL(h.visa.deny(outcome.request));
		const failed = await h.visa.authorize(
			{ ...request(h), scope: "admin" },
			"user-1",
		);
		if (failed.type !== "redirect") throw new Error("expected a redirect");
		const error = new URL(failed.url);

		for (const url of [success, denied, error]) {
			expect(url.searchParams.getAll("iss")).toEqual([ISSUER]);
			expect(url.searchParams.get("state")).toBe("xyz");
		}
		expect(success.searchParams.get("code")).not.toBeNull();
		expect(denied.searchParams.get("error")).toBe("access_denied");
		expect(error.searchParams.get("error")).toBe("invalid_scope");
	});

	it("names it on a remembered consent's silent redirect too", async () => {
		const h = await harness();
		const first = await h.visa.authorize(request(h), "user-1");
		if (first.type !== "consent") throw new Error("expected consent");
		await h.visa.grant(first.request, "user-1");

		const again = await h.visa.authorize(request(h), "user-1");
		if (again.type !== "redirect") throw new Error("expected a redirect");
		expect(new URL(again.url).searchParams.get("iss")).toBe(ISSUER);
	});

	it("sends the issuer as it is announced, trailing slash trimmed", async () => {
		const h = await harness({}, { issuer: `${ISSUER}/` });
		const outcome = await h.visa.authorize(request(h), "user-1");
		if (outcome.type !== "consent") throw new Error("expected consent");
		const url = new URL(h.visa.deny(outcome.request));
		expect(url.searchParams.get("iss")).toBe(ISSUER);
	});

	it("replaces an `iss` the registered redirect URI already carried", () => {
		const url = new URL(
			errorRedirect(
				"https://app.example.test/cb?iss=https://evil.example.test",
				new E_VISA_OAUTH_ERROR("access_denied"),
				{ issuer: ISSUER },
			),
		);
		expect(url.searchParams.getAll("iss")).toEqual([ISSUER]);
		expect(url.searchParams.has("state")).toBe(false);
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
			code_challenge: "a-verifier-of-the-length-rfc-7636-asks-for-0123",
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

	it("refuses a challenge that is not 43-128 unreserved characters (RFC 7636 §4.2)", async () => {
		// With `plain` the challenge IS the verifier: a one-character one is a
		// verifier anyone can guess, and the interception protection is gone.
		const lenient = await harness({}, { allowPlainChallenge: true });
		const malformed = [
			["plain", "a"],
			["plain", "a".repeat(42)],
			["plain", "a".repeat(129)],
			["S256", "a"],
			// `+`, `/` and `=` are base64, not base64url: outside the set.
			["S256", `${"a".repeat(42)}+`],
			["S256", `${"a".repeat(42)}=`],
			["plain", `${"a".repeat(42)} `],
		];
		for (const [method, challenge] of malformed) {
			const outcome = await lenient.visa.authorize(
				{
					response_type: "code",
					client_id: lenient.client.id,
					redirect_uri: REDIRECT,
					code_challenge: challenge,
					code_challenge_method: method,
				},
				"user-1",
			);
			if (outcome.type !== "redirect") {
				throw new Error(`expected a redirect for ${method} ${challenge}`);
			}
			expect(new URL(outcome.url).searchParams.get("error"), challenge).toBe(
				"invalid_request",
			);
		}
	});

	it("accepts a challenge at both ends of the length range", async () => {
		const lenient = await harness({}, { allowPlainChallenge: true });
		for (const challenge of ["A-._~".padEnd(43, "z"), "9".repeat(128)]) {
			const outcome = await lenient.visa.authorize(
				{
					response_type: "code",
					client_id: lenient.client.id,
					redirect_uri: REDIRECT,
					code_challenge: challenge,
					code_challenge_method: "plain",
				},
				"user-1",
			);
			expect(outcome.type, challenge).toBe("consent");
		}
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

	it("extends the port exception to the IPv6 loopback literal", async () => {
		// RFC 8252 §7.3: `http://[::1]:{port}/{path}` is the IPv6 form of the
		// same rule, any port at request time.
		const h = await harness({
			id: "native6",
			redirectUris: ["http://[::1]:1234/cb"],
			tokenEndpointAuthMethod: "none",
		});
		const ok = await h.visa.authorize(
			{
				response_type: "code",
				client_id: "native6",
				redirect_uri: "http://[::1]:40000/cb",
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-1",
		);
		expect(ok.type).not.toBe("error");
	});

	it("keeps `localhost` out of the port exception, matching it exactly", async () => {
		// RFC 8252 §8.3 / OAuth 2.1 §8.4.2 limit the exception to the IP
		// literals: `localhost` can resolve to a non-loopback address through
		// the hosts file or DNS, and then a "loopback" redirect on another port
		// sends the code to whoever listens there.
		const h = await harness({
			id: "native-localhost",
			redirectUris: ["http://localhost:1234/cb"],
			tokenEndpointAuthMethod: "none",
		});
		const request = {
			response_type: "code" as const,
			client_id: "native-localhost",
			code_challenge: pkce().challenge,
			code_challenge_method: "S256",
		};

		const otherPort = await h.visa.authorize(
			{ ...request, redirect_uri: "http://localhost:9999/cb" },
			"user-1",
		);
		expect(otherPort.type).toBe("error");

		const exact = await h.visa.authorize(
			{ ...request, redirect_uri: "http://localhost:1234/cb" },
			"user-1",
		);
		expect(exact.type).not.toBe("error");
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

/**
 * A remembered consent stands for "this user agreed to give THAT application
 * these scopes". For a public client whose code lands on the user's own
 * machine, nothing proves the next request comes from that application rather
 * than any other program presenting its client_id (RFC 8252 §8.6).
 */
describe("visa > authorize > consent for a client whose identity nothing proves", () => {
	async function consentThenReturn(
		redirectUris: string[],
		first: string,
		second: string,
		overrides: Partial<Parameters<typeof harness>[0]> = {},
	): Promise<{ firstType: string; secondType: string }> {
		const h = await harness({
			id: "desktop-app",
			redirectUris,
			tokenEndpointAuthMethod: "none",
			...overrides,
		});
		const request = (redirect: string) => ({
			response_type: "code",
			client_id: "desktop-app",
			redirect_uri: redirect,
			scope: "profile",
			code_challenge: pkce().challenge,
			code_challenge_method: "S256",
		});
		const day1 = await h.visa.authorize(request(first), "user-7");
		if (day1.type === "consent") await h.visa.grant(day1.request, "user-7");
		const day2 = await h.visa.authorize(request(second), "user-7");
		return { firstType: day1.type, secondType: day2.type };
	}

	it("asks again when a public loopback client comes back on another port", async () => {
		// The other port may be another program: it chose its own PKCE pair, so
		// a silent redirect would hand it the user's tokens.
		const outcome = await consentThenReturn(
			["http://127.0.0.1/callback"],
			"http://127.0.0.1:51000/callback",
			"http://127.0.0.1:6666/callback",
		);
		expect(outcome).toEqual({ firstType: "consent", secondType: "consent" });
	});

	it("asks again on the very same loopback port and on the IPv6 literal", async () => {
		// A fixed port is anyone's while the real application is not running.
		expect(
			await consentThenReturn(
				["http://127.0.0.1:51000/callback"],
				"http://127.0.0.1:51000/callback",
				"http://127.0.0.1:51000/callback",
			),
		).toEqual({ firstType: "consent", secondType: "consent" });
		expect(
			await consentThenReturn(
				["http://[::1]/callback"],
				"http://[::1]:51000/callback",
				"http://[::1]:6666/callback",
			),
		).toEqual({ firstType: "consent", secondType: "consent" });
	});

	it("asks again for http://localhost and for a private-use scheme", async () => {
		for (const uri of [
			"http://localhost:8080/callback",
			"https://localhost/callback",
			"https://dev.localhost/callback",
			"com.example.app:/oauth/callback",
		]) {
			expect(await consentThenReturn([uri], uri, uri)).toEqual({
				firstType: "consent",
				secondType: "consent",
			});
		}
	});

	it("asks even when such a client is marked trusted", async () => {
		const outcome = await consentThenReturn(
			["http://127.0.0.1/callback"],
			"http://127.0.0.1:51000/callback",
			"http://127.0.0.1:6666/callback",
			{ trusted: true },
		);
		expect(outcome).toEqual({ firstType: "consent", secondType: "consent" });
	});

	it("still remembers the consent of a public client on an https redirect", async () => {
		// The code lands on a host the client owns: that is proof enough.
		const outcome = await consentThenReturn(
			["https://spa.example.test/callback"],
			"https://spa.example.test/callback",
			"https://spa.example.test/callback",
		);
		expect(outcome).toEqual({ firstType: "consent", secondType: "redirect" });
	});

	it("still remembers the consent of a confidential client on a loopback redirect", async () => {
		// Its secret proves who redeems the code, wherever the code lands.
		const outcome = await consentThenReturn(
			["http://127.0.0.1/callback"],
			"http://127.0.0.1:51000/callback",
			"http://127.0.0.1:6666/callback",
			{ tokenEndpointAuthMethod: "client_secret_basic" },
		);
		expect(outcome).toEqual({ firstType: "consent", secondType: "redirect" });
	});

	it("gives another local program nothing it can redeem without the user", async () => {
		const h = await harness({
			id: "desktop-app",
			redirectUris: ["http://127.0.0.1/callback"],
			tokenEndpointAuthMethod: "none",
		});
		const real = await h.visa.authorize(
			{
				response_type: "code",
				client_id: "desktop-app",
				redirect_uri: "http://127.0.0.1:51000/callback",
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-7",
		);
		if (real.type !== "consent") throw new Error("expected consent");
		await h.visa.grant(real.request, "user-7");

		const rogue = await h.visa.authorize(
			{
				response_type: "code",
				client_id: "desktop-app",
				redirect_uri: "http://127.0.0.1:6666/callback",
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-7",
		);
		// The screen, not a code: the user sees the request and can refuse it.
		expect(rogue.type).toBe("consent");
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

	it("carries an E_VISA_* code, not an E_VISA_OAUTH_ERROR, for a wiring mistake", async () => {
		// Two audiences: one error goes on the wire, the other to whoever
		// wired the server.
		const { VisaManager } = await import("../../src/VisaManager.js");
		const { MemoryStore } = await import("../../src/stores/memory.js");
		expect(
			() => new VisaManager({ issuer: "", store: new MemoryStore() }),
		).toThrowError(/issuer/);
		expect(
			() => new VisaManager({ issuer: "", store: new MemoryStore() }),
		).toThrow(
			expect.objectContaining({
				code: "E_VISA_MISSING_ISSUER",
				help: "Set `issuer` in config/visa.ts, e.g. https://auth.example.com",
			}),
		);
		expect(new E_VISA_OAUTH_ERROR("invalid_grant").toResponse()).toEqual({
			error: "invalid_grant",
		});
	});
});

describe("visa > authorize > parameters a query parser repeated", () => {
	// `scope=a&scope=b` and `scope[]=a` reach `authorize()` as an array,
	// `scope[x]=1` as an object. RFC 6749 §3.1: "Request and response
	// parameters MUST NOT be included more than once." Each used to reach a
	// string method and throw a TypeError — a 500 any visitor could cause.
	const shapes: ReadonlyArray<[string, unknown]> = [
		["an array", ["a", "b"]],
		["an object", { x: "1" }],
	];

	function request(
		h: Awaited<ReturnType<typeof harness>>,
		override: Record<string, unknown>,
	): Record<string, unknown> {
		return {
			response_type: "code",
			client_id: h.client.id,
			redirect_uri: REDIRECT,
			code_challenge: pkce().challenge,
			code_challenge_method: "S256",
			state: "xyz",
			...override,
		};
	}

	for (const [shape, value] of shapes) {
		for (const key of [
			"response_type",
			"scope",
			"state",
			"code_challenge",
			"code_challenge_method",
			"nonce",
			"prompt",
		]) {
			it(`redirects invalid_request for ${key} as ${shape}`, async () => {
				const h = await harness();
				const outcome = await h.visa.authorize(
					request(h, { [key]: value }),
					"user-1",
				);
				expect(outcome.type, key).toBe("redirect");
				if (outcome.type !== "redirect") throw new Error("unreachable");
				const url = new URL(outcome.url);
				expect(url.searchParams.get("error"), key).toBe("invalid_request");
				// The state goes back only when it was one string — never a
				// repeated one flattened into `a,b`.
				expect(url.searchParams.get("state"), key).toBe(
					key === "state" ? null : "xyz",
				);
			});
		}

		for (const key of ["client_id", "redirect_uri"]) {
			it(`shows invalid_request, never redirected, for ${key} as ${shape}`, async () => {
				// These decide where an error may go: a repeated one is shown.
				const h = await harness();
				const outcome = await h.visa.authorize(
					request(h, { [key]: value }),
					"user-1",
				);
				expect(outcome.type, key).toBe("error");
				if (outcome.type !== "error") throw new Error("unreachable");
				expect(outcome.error.oauthCode, key).toBe("invalid_request");
			});
		}
	}

	it("still takes several resource indicators, and refuses an object", async () => {
		// RFC 8707 §2 is the one parameter allowed to repeat.
		const h = await harness();
		const several = await h.visa.authorize(
			request(h, {
				resource: ["https://api.example.test/a", "https://api.example.test/b"],
			}),
			"user-1",
		);
		expect(several.type).toBe("consent");
		if (several.type !== "consent") throw new Error("unreachable");
		expect(several.request.resources).toEqual([
			"https://api.example.test/a",
			"https://api.example.test/b",
		]);

		const object = await h.visa.authorize(
			request(h, { resource: { x: "https://api.example.test/a" } }),
			"user-1",
		);
		expect(object.type).toBe("redirect");
		if (object.type !== "redirect") throw new Error("unreachable");
		expect(new URL(object.url).searchParams.get("error")).toBe(
			"invalid_request",
		);
	});
});
