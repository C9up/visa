/**
 * The service accessor and the memory store.
 *
 * The accessor is a proxy held before the provider boots, and the shape of
 * that proxy has bitten this codebase before: a module namespace is probed for
 * `then` when it is imported, so a proxy that throws there crashes the import
 * itself rather than the call that was wrong.
 */

import { afterEach, describe, expect, it } from "vitest";
import visa, { clearVisa, getVisa, setVisa } from "../../src/services/main.js";
import type { VisaStore } from "../../src/store.js";
import { MemoryStore } from "../../src/stores/memory.js";
import { VisaManager } from "../../src/VisaManager.js";
import { ISSUER, REDIRECT } from "./helpers.js";

afterEach(() => {
	clearVisa();
});

describe("visa > services/main", () => {
	it("answers undefined for `then` and for symbols, booted or not", () => {
		// The import probe. Throwing here would fail the import, and the stack
		// would point at the module system rather than at the missing provider.
		expect((visa as unknown as { then?: unknown }).then).toBeUndefined();
		expect(
			(visa as unknown as Record<symbol, unknown>)[Symbol.iterator],
		).toBeUndefined();
	});

	it("names what to do when it is read before the provider booted", () => {
		expect(() => visa.issuer).toThrowError(/register VisaProvider/);
	});

	it("binds methods to the seated manager", async () => {
		const store = new MemoryStore();
		const manager = new VisaManager({ issuer: ISSUER, store });
		setVisa(manager);

		expect(getVisa()).toBe(manager);
		expect(visa.issuer).toBe(ISSUER);
		// Taken off the proxy and called loose: still bound, so `this` is the
		// manager and not the proxy.
		const register = visa.registerClient;
		const { client } = await register({
			id: "app",
			name: "App",
			redirectUris: [REDIRECT],
		});
		expect(await store.findClient("app")).toBe(client);
	});

	it("forgets the manager on clear", () => {
		setVisa(new VisaManager({ issuer: ISSUER, store: new MemoryStore() }));
		clearVisa();
		expect(getVisa()).toBeUndefined();
	});
});

describe("visa > MemoryStore", () => {
	it("answers null for what it does not hold", async () => {
		const store = new MemoryStore();
		expect(await store.findClient("ghost")).toBeNull();
		expect(await store.findAuthorizationCode("ghost")).toBeNull();
		expect(await store.findAccessToken("ghost")).toBeNull();
		expect(await store.findRefreshToken("ghost")).toBeNull();
		expect(await store.findConsent("user", "client")).toBeNull();
	});

	it("consumes a code exactly once", async () => {
		// The single-use guarantee the whole replay detection is built on.
		const store = new MemoryStore();
		const now = new Date();
		await store.saveAuthorizationCode({
			codeHash: "h",
			clientId: "app",
			userId: "user",
			redirectUri: REDIRECT,
			scopes: [],
			codeChallenge: "c",
			codeChallengeMethod: "S256",
			expiresAt: new Date(now.getTime() + 1000),
		});
		expect(await store.consumeAuthorizationCode("h", now)).toBe(true);
		expect(await store.consumeAuthorizationCode("h", now)).toBe(false);
		// And a code that never existed cannot be consumed either.
		expect(await store.consumeAuthorizationCode("ghost", now)).toBe(false);
	});

	it("revokes a family on both sides", async () => {
		// A leaked refresh token has usually already bought an access token;
		// leaving that one alive defeats the revocation.
		const store = new MemoryStore();
		const now = new Date();
		const later = new Date(now.getTime() + 1000);
		await store.saveRefreshToken({
			tokenHash: "r",
			familyId: "f",
			clientId: "app",
			scopes: [],
			expiresAt: later,
		});
		await store.saveAccessToken({
			tokenHash: "a",
			familyId: "f",
			clientId: "app",
			scopes: [],
			expiresAt: later,
		});
		await store.saveAccessToken({
			tokenHash: "other",
			familyId: "g",
			clientId: "app",
			scopes: [],
			expiresAt: later,
		});

		await store.revokeFamily("f", now);

		expect((await store.findRefreshToken("r"))?.revokedAt).toBe(now);
		expect((await store.findAccessToken("a"))?.revokedAt).toBe(now);
		// Another family is untouched.
		expect((await store.findAccessToken("other"))?.revokedAt).toBeUndefined();
	});

	it("keeps one consent per user and client", async () => {
		const store = new MemoryStore();
		const now = new Date();
		await store.saveConsent({
			userId: "u",
			clientId: "c",
			scopes: ["profile"],
			grantedAt: now,
		});
		await store.saveConsent({
			userId: "u",
			clientId: "c",
			scopes: ["profile", "email"],
			grantedAt: now,
		});
		expect((await store.findConsent("u", "c"))?.scopes).toEqual([
			"profile",
			"email",
		]);
		// Keyed by both: another client's consent is a different row.
		expect(await store.findConsent("u", "other")).toBeNull();
	});

	it("drops what has expired and keeps what has not", async () => {
		const store = new MemoryStore();
		const now = new Date();
		const past = new Date(now.getTime() - 1000);
		const future = new Date(now.getTime() + 60_000);
		await store.saveAccessToken({
			tokenHash: "stale",
			clientId: "app",
			scopes: [],
			expiresAt: past,
		});
		await store.saveAccessToken({
			tokenHash: "live",
			clientId: "app",
			scopes: [],
			expiresAt: future,
		});
		await store.saveRefreshToken({
			tokenHash: "stale-r",
			familyId: "f",
			clientId: "app",
			scopes: [],
			expiresAt: past,
		});
		await store.saveAuthorizationCode({
			codeHash: "stale-c",
			clientId: "app",
			userId: "u",
			redirectUri: REDIRECT,
			scopes: [],
			codeChallenge: "c",
			codeChallengeMethod: "S256",
			expiresAt: past,
		});

		await store.prune(now);

		expect(await store.findAccessToken("stale")).toBeNull();
		expect(await store.findRefreshToken("stale-r")).toBeNull();
		expect(await store.findAuthorizationCode("stale-c")).toBeNull();
		expect(await store.findAccessToken("live")).not.toBeNull();
	});

	it("takes clients at construction as well as afterwards", async () => {
		const store = new MemoryStore([
			{
				id: "seeded",
				name: "Seeded",
				redirectUris: [REDIRECT],
				grantTypes: ["authorization_code"],
				scopes: [],
				tokenEndpointAuthMethod: "none",
			},
		]);
		expect(await store.findClient("seeded")).not.toBeNull();
	});

	it("refuses to register a client in a store that cannot take one", async () => {
		// A database store creates rows where they live; the manager says so
		// instead of silently doing nothing.
		const base = new MemoryStore();
		// The contract without the convenience: what a database driver looks
		// like, written out rather than faked, so it type-checks as one.
		const readOnly: VisaStore = {
			findClient: (id) => base.findClient(id),
			saveAuthorizationCode: (code) => base.saveAuthorizationCode(code),
			findAuthorizationCode: (hash) => base.findAuthorizationCode(hash),
			consumeAuthorizationCode: (hash, at) =>
				base.consumeAuthorizationCode(hash, at),
			saveAccessToken: (token) => base.saveAccessToken(token),
			findAccessToken: (hash) => base.findAccessToken(hash),
			revokeAccessToken: (hash, at) => base.revokeAccessToken(hash, at),
			saveRefreshToken: (token) => base.saveRefreshToken(token),
			findRefreshToken: (hash) => base.findRefreshToken(hash),
			consumeRefreshToken: (hash, at) => base.consumeRefreshToken(hash, at),
			revokeFamily: (family, at) => base.revokeFamily(family, at),
			findConsent: (user, client) => base.findConsent(user, client),
			saveConsent: (consent) => base.saveConsent(consent),
		};
		const manager = new VisaManager({ issuer: ISSUER, store: readOnly });
		await expect(
			manager.registerClient({ id: "x", name: "X", redirectUris: [REDIRECT] }),
		).rejects.toThrowError(/cannot register clients/);
	});
});
