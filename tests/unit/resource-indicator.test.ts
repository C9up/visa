import { beforeEach, describe, expect, it } from "vitest";
import { issueAuthorizationCode } from "../../src/authorize.js";
import { hashSecret } from "../../src/crypto.js";
import { MemoryStore } from "../../src/stores/memory.js";
import { VisaManager } from "../../src/VisaManager.js";
import { pkce } from "./helpers.js";

/**
 * Which server a token is for (RFC 8707).
 *
 * A token with no stated audience is a token for everything: send it to the
 * wrong server, or let a compromised one replay it, and every resource that
 * trusts the same issuer accepts it. These tests are about the two halves that
 * make that stop — binding the token at the authorization endpoint, and
 * refusing it at the resource that was not named.
 */

const ISSUER = "https://auth.example";
const CALENDAR = "https://calendar.example/api";
const FILES = "https://files.example/api";
const REDIRECT = "https://app.example/cb";
// A real pair, built the way a client builds one.
const { verifier: VERIFIER, challenge: CHALLENGE } = pkce();

describe("visa > resource indicators", () => {
	let store: MemoryStore;

	function server(resourcesSupported?: string[]): VisaManager {
		return new VisaManager({
			issuer: ISSUER,
			store,
			...(resourcesSupported === undefined ? {} : { resourcesSupported }),
		});
	}

	beforeEach(() => {
		store = new MemoryStore([
			{
				id: "app",
				name: "App",
				redirectUris: [REDIRECT],
				grantTypes: [
					"authorization_code",
					"refresh_token",
					"client_credentials",
				],
				scopes: ["profile"],
				tokenEndpointAuthMethod: "none",
			},
		]);
	});

	async function authorized(
		visa: VisaManager,
		resource?: string | string[],
	): Promise<string> {
		const outcome = await visa.authorize(
			{
				response_type: "code",
				client_id: "app",
				redirect_uri: REDIRECT,
				scope: "profile",
				code_challenge: CHALLENGE,
				code_challenge_method: "S256",
				...(resource === undefined ? {} : { resource }),
			},
			"user-7",
		);
		if (outcome.type === "error") throw outcome.error;
		if (outcome.type !== "consent")
			throw new Error(`unexpected: ${outcome.type}`);
		return issueAuthorizationCode(outcome.request, "user-7", store);
	}

	async function exchange(
		visa: VisaManager,
		code: string,
		resource?: string | string[],
	) {
		return visa.token(
			{
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				code_verifier: VERIFIER,
				...(resource === undefined ? {} : { resource }),
			},
			{ clientId: "app" },
		);
	}

	it("binds the token to the resource the user was asked about", async () => {
		const visa = server();
		const code = await authorized(visa, CALENDAR);
		const tokens = await exchange(visa, code);

		const verified = await visa.verify(tokens.access_token);
		expect(verified?.audience).toEqual([CALENDAR]);
	});

	it("accepts the token at that resource and refuses it at another", async () => {
		// The whole point. A token that travelled is refused where it landed.
		const visa = server();
		const code = await authorized(visa, CALENDAR);
		const tokens = await exchange(visa, code);

		expect(
			await visa.verify(tokens.access_token, new Date(), CALENDAR),
		).not.toBeNull();
		expect(
			await visa.verify(tokens.access_token, new Date(), FILES),
		).toBeNull();
	});

	it("accepts an unbound token anywhere", async () => {
		// Every token issued before a client started asking is unbound, and
		// refusing them would break each one.
		const visa = server();
		const code = await authorized(visa);
		const tokens = await exchange(visa, code);

		expect(
			await visa.verify(tokens.access_token, new Date(), FILES),
		).not.toBeNull();
	});

	it("binds several resources at once", async () => {
		const visa = server();
		const code = await authorized(visa, [CALENDAR, FILES]);
		const tokens = await exchange(visa, code);

		const verified = await visa.verify(tokens.access_token);
		expect(verified?.audience).toEqual([CALENDAR, FILES]);
		expect(
			await visa.verify(tokens.access_token, new Date(), FILES),
		).not.toBeNull();
	});

	it("lets the exchange narrow the list, never widen it", async () => {
		const visa = server();
		const code = await authorized(visa, [CALENDAR, FILES]);
		const tokens = await exchange(visa, code, CALENDAR);

		expect((await visa.verify(tokens.access_token))?.audience).toEqual([
			CALENDAR,
		]);
	});

	it("refuses an exchange aiming outside what was authorized", async () => {
		const visa = server();
		const code = await authorized(visa, CALENDAR);

		await expect(exchange(visa, code, FILES)).rejects.toMatchObject({
			code: "invalid_target",
		});
	});

	it("refuses an exchange aiming anywhere when nothing was bound", async () => {
		// There is nothing to narrow FROM, so naming one here would mint a token
		// for an audience the user never saw.
		const visa = server();
		const code = await authorized(visa);

		await expect(exchange(visa, code, CALENDAR)).rejects.toMatchObject({
			code: "invalid_target",
		});
	});

	/** The error an authorization request came back with, off the redirect. */
	async function authorizationError(
		visa: VisaManager,
		resource: string,
	): Promise<string | null> {
		const outcome = await visa.authorize(
			{
				response_type: "code",
				client_id: "app",
				redirect_uri: REDIRECT,
				scope: "profile",
				code_challenge: CHALLENGE,
				code_challenge_method: "S256",
				resource,
			},
			"user-7",
		);
		if (outcome.type === "error") return outcome.error.code;
		if (outcome.type !== "redirect") return null;
		return new URL(outcome.url).searchParams.get("error");
	}

	it("refuses a resource this server does not issue for", async () => {
		// Back to the client as a redirect, not thrown: the redirect URI itself
		// passed validation, so that is where an error belongs.
		expect(await authorizationError(server([CALENDAR]), FILES)).toBe(
			"invalid_target",
		);
	});

	it("refuses a resource that is not an absolute URI, or carries a fragment", async () => {
		// §2. `invalid_target` for a malformed value too — the RFC names that
		// code for "cannot parse the provided value(s)".
		const visa = server();
		for (const bad of ["/api", "calendar.example", `${CALENDAR}#x`]) {
			expect(await authorizationError(visa, bad), bad).toBe("invalid_target");
		}
	});

	it("keeps the binding through a refresh, and lets it narrow", async () => {
		const visa = server();
		const code = await authorized(visa, [CALENDAR, FILES]);
		const first = await exchange(visa, code);
		expect(first.refresh_token).toBeTypeOf("string");

		const second = await visa.token(
			{
				grant_type: "refresh_token",
				refresh_token: first.refresh_token ?? "",
				resource: CALENDAR,
			},
			{ clientId: "app" },
		);

		expect((await visa.verify(second.access_token))?.audience).toEqual([
			CALENDAR,
		]);
	});

	it("binds a client-credentials token to what it asked for", async () => {
		// Nobody consented to a list here, so the request is the list — checked
		// against what this server issues for. A confidential client: a public
		// one may not use this grant at all.
		const visa = server([CALENDAR]);
		const secret = "s3cret";
		store.addClient({
			id: "machine",
			name: "Machine",
			secretHash: hashSecret(secret),
			redirectUris: [],
			grantTypes: ["client_credentials"],
			scopes: ["profile"],
			tokenEndpointAuthMethod: "client_secret_basic",
		});

		const tokens = await visa.token(
			{
				grant_type: "client_credentials",
				scope: "profile",
				resource: CALENDAR,
			},
			{
				clientId: "machine",
				clientSecret: secret,
				method: "client_secret_basic",
			},
		);

		expect((await visa.verify(tokens.access_token))?.audience).toEqual([
			CALENDAR,
		]);
		await expect(
			visa.token(
				{ grant_type: "client_credentials", scope: "profile", resource: FILES },
				{
					clientId: "machine",
					clientSecret: secret,
					method: "client_secret_basic",
				},
			),
		).rejects.toMatchObject({ code: "invalid_target" });
	});

	it("reports the audience on introspection", async () => {
		// §3 names introspection as where a resource server learns what a token
		// was minted for.
		const visa = server();
		const code = await authorized(visa, CALENDAR);
		const tokens = await exchange(visa, code);

		const body = await visa.introspect(
			{ token: tokens.access_token },
			{ clientId: "app" },
		);

		expect(body.active).toBe(true);
		expect(body.aud).toEqual([CALENDAR]);
	});
});
