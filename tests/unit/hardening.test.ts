/**
 * What an external audit found, pinned.
 *
 * Every case here is something that was accepted and should not have been, or
 * a failure that arrived as a 500 instead of as an OAuth error. The common
 * thread: a mistake an unauthenticated caller can make must produce a refusal,
 * never a crash and never a downgrade.
 */

import { describe, expect, it } from "vitest";
import { MemoryStore } from "../../src/stores/memory.js";
import { VisaManager } from "../../src/VisaManager.js";
import {
	authorizeToCode,
	creds,
	harness,
	ISSUER,
	pkce,
	REDIRECT,
} from "./helpers.js";

describe("visa > the registered authentication method is the only one", () => {
	it("refuses a Basic client that sends its secret in the body", async () => {
		// Accepting both makes the registered method decorative — and the body
		// is readable by anything that could not read the header.
		const h = await harness({ tokenEndpointAuthMethod: "client_secret_basic" });
		await expect(
			h.visa.token(
				{ grant_type: "client_credentials" },
				{ ...creds(h), method: "client_secret_post" },
			),
		).rejects.toMatchObject({ code: "invalid_client" });
	});

	it("refuses a POST client that sends Basic", async () => {
		const h = await harness({
			tokenEndpointAuthMethod: "client_secret_post",
			grantTypes: ["client_credentials"],
		});
		await expect(
			h.visa.token(
				{ grant_type: "client_credentials" },
				{ ...creds(h), method: "client_secret_basic" },
			),
		).rejects.toMatchObject({ code: "invalid_client" });
	});

	it("accepts the method it registered", async () => {
		const h = await harness({
			tokenEndpointAuthMethod: "client_secret_post",
			grantTypes: ["client_credentials"],
			scopes: ["reports"],
		});
		const body = { grant_type: "client_credentials" };
		const credentials = h.visa.readCredentials({
			body: { ...body, client_id: h.client.id, client_secret: h.secret },
		});
		await expect(h.visa.token(body, credentials)).resolves.toMatchObject({
			token_type: "Bearer",
		});
	});
});

describe("visa > malformed input is refused, not crashed on", () => {
	it("answers invalid_client to a Basic header with a broken escape", async () => {
		// `decodeURIComponent` throws URIError on `%zz`. Unhandled, that is an
		// unauthenticated caller choosing the endpoint's failure mode.
		const h = await harness();
		const header = `Basic ${Buffer.from("%zz:secret").toString("base64")}`;
		expect(() =>
			h.visa.readCredentials({ authorization: header, body: {} }),
		).toThrowError(/Malformed Basic credentials/);
	});

	it("answers invalid_client to Basic with no colon", async () => {
		const h = await harness();
		const header = `Basic ${Buffer.from("no-separator").toString("base64")}`;
		expect(() =>
			h.visa.readCredentials({ authorization: header, body: {} }),
		).toThrowError(/Malformed Basic credentials/);
	});
});

describe("visa > a client cannot be registered into a 500", () => {
	it("refuses a redirect URI that is not a URL", async () => {
		// It would parse fine here and throw out of `successRedirect` later,
		// turning a registration mistake into a crash on a reachable path.
		const h = await harness();
		await expect(
			h.visa.registerClient({
				id: "x",
				name: "X",
				redirectUris: ["not a url"],
			}),
		).rejects.toThrowError(/Not a URL/);
	});

	it("refuses a fragment and a wildcard", async () => {
		const h = await harness();
		await expect(
			h.visa.registerClient({
				id: "x",
				name: "X",
				redirectUris: ["https://app.test/cb#done"],
			}),
		).rejects.toThrowError(/no fragment/);
		await expect(
			h.visa.registerClient({
				id: "y",
				name: "Y",
				redirectUris: ["https://*.app.test/cb"],
			}),
		).rejects.toThrowError(/never accept anything/);
	});

	it("refuses a client with no redirect URI at all", async () => {
		const h = await harness();
		await expect(
			h.visa.registerClient({ id: "z", name: "Z", redirectUris: [] }),
		).rejects.toThrowError(/at least one redirect URI/);
	});
});

describe("visa > the issuer", () => {
	it("drops a trailing slash rather than building //oauth/token", () => {
		const visa = new VisaManager({
			issuer: "https://auth.test/",
			store: new MemoryStore(),
		});
		expect(visa.issuer).toBe("https://auth.test");
	});

	it("refuses one that is not a URL, or is plain http off localhost", () => {
		const store = new MemoryStore();
		expect(() => new VisaManager({ issuer: "auth.test", store })).toThrowError(
			/not a URL/,
		);
		expect(
			() => new VisaManager({ issuer: "http://auth.example.com", store }),
		).toThrowError(/must be https/);
		// A laptop is the named exception.
		expect(
			() => new VisaManager({ issuer: "http://localhost:3333", store }),
		).not.toThrow();
	});

	it("refuses a query string or a fragment on it", () => {
		const store = new MemoryStore();
		expect(
			() => new VisaManager({ issuer: "https://auth.test/?a=1", store }),
		).toThrowError(/no query string/);
	});

	it("names itself on introspection, since an opaque token cannot", async () => {
		const h = await harness();
		const { verifier, challenge } = pkce();
		const code = await authorizeToCode(h, { challenge });
		const tokens = await h.visa.token(
			{
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				code_verifier: verifier,
			},
			creds(h),
		);
		const result = await h.visa.introspect(
			{ token: tokens.access_token },
			creds(h),
		);
		expect(result.iss).toBe(ISSUER);
	});
});
