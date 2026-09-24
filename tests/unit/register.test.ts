import { beforeEach, describe, expect, it } from "vitest";
import { MemoryStore } from "../../src/stores/memory.js";
import { VisaManager } from "../../src/VisaManager.js";

/**
 * Clients that register themselves (RFC 7591).
 *
 * An MCP client has nobody to fill in a form for it. What it may become once
 * it has registered is this server's decision, not the request's — that is the
 * difference between letting a client name itself and letting it decide what
 * it may do.
 */

const ISSUER = "https://auth.example";
const CALLBACK = "https://client.example/callback";

describe("visa > dynamic client registration", () => {
	let store: MemoryStore;

	function server(
		registration?: Parameters<typeof makeConfig>[0],
	): VisaManager {
		return new VisaManager(makeConfig(registration));
	}

	function makeConfig(registration?: {
		enabled?: boolean;
		initialAccessToken?: string;
		scopes?: string[];
		grantTypes?: Array<
			"authorization_code" | "refresh_token" | "client_credentials"
		>;
		secretTtlSeconds?: number;
	}) {
		return {
			issuer: ISSUER,
			store,
			...(registration === undefined ? {} : { registration }),
		};
	}

	beforeEach(() => {
		store = new MemoryStore();
	});

	it("refuses to register anyone unless it was turned on", async () => {
		// The safe default the RFC permits, rather than the open one it
		// encourages: a server quietly accepting registrations is a thing
		// nobody asked for.
		await expect(
			server().register({ redirect_uris: [CALLBACK] }),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });

		await expect(
			server({ enabled: false }).register({ redirect_uris: [CALLBACK] }),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });
	});

	it("answers the fields §3.2.1 requires", async () => {
		const visa = server({ enabled: true });

		const created = await visa.register({
			redirect_uris: [CALLBACK],
			client_name: "My Example Client",
		});

		expect(created.client_id).toBeTypeOf("string");
		expect(created.client_secret).toBeTypeOf("string");
		expect(created.client_id_issued_at).toBeTypeOf("number");
		// `0` is the spelling for "does not expire" — not an omission, which
		// would mean the field was never answered.
		expect(created.client_secret_expires_at).toBe(0);
		expect(created.redirect_uris).toEqual([CALLBACK]);
		expect(created.client_name).toBe("My Example Client");
	});

	it("registers a client that can then be authenticated", async () => {
		const visa = server({ enabled: true });

		const created = await visa.register({ redirect_uris: [CALLBACK] });
		const client = await store.findClient(created.client_id);

		expect(client).not.toBeNull();
		expect(client?.redirectUris).toEqual([CALLBACK]);
		// The plaintext is answered once and stored hashed, like every other
		// credential here.
		expect(client?.secretHash).toBeTypeOf("string");
		expect(client?.secretHash).not.toBe(created.client_secret);
	});

	it("chooses the client id itself", async () => {
		// A client naming itself could claim an id that already exists and read
		// another application's tokens.
		const visa = server({ enabled: true });

		const created = await visa.register({
			redirect_uris: [CALLBACK],
			client_id: "i-would-like-this-one",
		});

		expect(created.client_id).not.toBe("i-would-like-this-one");
	});

	it("dates the secret when it expires", async () => {
		const visa = server({ enabled: true, secretTtlSeconds: 3600 });
		const now = new Date("2026-01-01T00:00:00Z");

		const created = await visa.register(
			{ redirect_uris: [CALLBACK] },
			undefined,
			now,
		);

		expect(created.client_secret_expires_at).toBe(
			Math.floor(now.getTime() / 1000) + 3600,
		);
	});

	it("takes an initial access token when one is required", async () => {
		const visa = server({ enabled: true, initialAccessToken: "letmein" });

		await expect(
			visa.register({ redirect_uris: [CALLBACK] }),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });
		await expect(
			visa.register({ redirect_uris: [CALLBACK] }, "wrong"),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });

		const created = await visa.register(
			{ redirect_uris: [CALLBACK] },
			"letmein",
		);
		expect(created.client_id).toBeTypeOf("string");
	});

	it("refuses a redirect URI that is not https or loopback http", async () => {
		const visa = server({ enabled: true });

		for (const uri of [
			"http://sketchy.example/callback",
			"not-a-uri",
			`${CALLBACK}#fragment`,
		]) {
			await expect(
				visa.register({ redirect_uris: [uri] }),
				uri,
			).rejects.toMatchObject({ code: "invalid_redirect_uri" });
		}
	});

	it("accepts loopback http, which is how a native app comes back", async () => {
		const visa = server({ enabled: true });

		const created = await visa.register({
			redirect_uris: ["http://127.0.0.1:8976/callback"],
		});

		expect(created.redirect_uris).toEqual(["http://127.0.0.1:8976/callback"]);
	});

	it("needs a redirect URI for the authorization code grant", async () => {
		const visa = server({ enabled: true });

		await expect(visa.register({})).rejects.toMatchObject({
			code: "invalid_redirect_uri",
		});
	});

	it("grants only the scopes this server allows a self-registered client", async () => {
		const visa = server({ enabled: true, scopes: ["profile"] });

		await expect(
			visa.register({ redirect_uris: [CALLBACK], scope: "profile admin" }),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });

		const created = await visa.register({
			redirect_uris: [CALLBACK],
			scope: "profile",
		});
		expect(created.scope).toBe("profile");
	});

	it("gives a client no scope when it asked for none", async () => {
		// What was asked for, narrowed — never the allowed set, or every client
		// would be registered with everything.
		const visa = server({ enabled: true, scopes: ["profile", "admin"] });

		const created = await visa.register({ redirect_uris: [CALLBACK] });

		expect(created.scope).toBeUndefined();
	});

	it("allows only the grants this server permits", async () => {
		const visa = server({ enabled: true });

		await expect(
			visa.register({
				redirect_uris: [CALLBACK],
				grant_types: ["client_credentials"],
			}),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });

		const created = await visa.register({ redirect_uris: [CALLBACK] });
		expect(created.grant_types).toEqual([
			"authorization_code",
			"refresh_token",
		]);
	});

	it("refuses an auth method it does not support", async () => {
		const visa = server({ enabled: true });

		await expect(
			visa.register({
				redirect_uris: [CALLBACK],
				token_endpoint_auth_method: "private_key_jwt",
			}),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });
	});

	it("issues no secret to a public client", async () => {
		const visa = server({ enabled: true });

		const created = await visa.register({
			redirect_uris: [CALLBACK],
			token_endpoint_auth_method: "none",
		});

		expect(created.client_secret).toBeUndefined();
		// §3.2.1 requires the expiry only when a secret was issued.
		expect(created.client_secret_expires_at).toBeUndefined();
	});

	it("names a client that did not name itself", async () => {
		// A blank name on a consent screen is worse than a placeholder nobody
		// mistakes for a brand.
		const visa = server({ enabled: true });

		const created = await visa.register({ redirect_uris: [CALLBACK] });

		expect(created.client_name).toBe("Unnamed client");
	});

	it("refuses metadata of the wrong shape", async () => {
		const visa = server({ enabled: true });

		await expect(
			visa.register({ redirect_uris: CALLBACK }),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });
		await expect(
			visa.register({ redirect_uris: [CALLBACK], scope: ["profile"] }),
		).rejects.toMatchObject({ code: "invalid_client_metadata" });
	});
});
