import { beforeEach, describe, expect, it } from "vitest";
import { hashSecret } from "../../src/crypto.js";
import { type GuardStore, type GuardUser, visaGuard } from "../../src/guard.js";
import { MemoryStore } from "../../src/stores/memory.js";

/**
 * The guard an application declares in `config/auth.ts` beside jwt and session.
 *
 * What it owes the application: the user behind the token, the token's scopes
 * where a route gate can read them, and a refusal the moment the account stops
 * being available — that last one is why the provider is asked on every
 * request rather than once when the token was minted.
 */

const HOUR = 3600_000;

describe("visa > the guard", () => {
	let memory: MemoryStore;
	let users: Map<string, GuardUser>;

	beforeEach(() => {
		memory = new MemoryStore();
		users = new Map([["user-7", { id: "user-7", roles: ["member"] }]]);
	});

	async function seedToken(
		overrides: {
			secret?: string;
			userId?: string;
			scopes?: string[];
			expiresAt?: Date;
			revokedAt?: Date;
			lastUsedAt?: Date;
		} = {},
	): Promise<string> {
		const secret = overrides.secret ?? "tok_abcdef";
		await memory.saveAccessToken({
			tokenHash: hashSecret(secret),
			clientId: "client-1",
			...(overrides.userId === undefined ? {} : { userId: overrides.userId }),
			scopes: overrides.scopes ?? ["contacts.read"],
			expiresAt: overrides.expiresAt ?? new Date(Date.now() + HOUR),
			...(overrides.revokedAt === undefined
				? {}
				: { revokedAt: overrides.revokedAt }),
			...(overrides.lastUsedAt === undefined
				? {}
				: { lastUsedAt: overrides.lastUsedAt }),
		});
		return secret;
	}

	const findUser = async (id: string): Promise<GuardUser | null> =>
		users.get(id) ?? null;

	function guard(store: GuardStore | (() => GuardStore) = memory) {
		return visaGuard({ store, findUser });
	}

	it("authenticates the user behind the token", async () => {
		const secret = await seedToken({ userId: "user-7" });

		const result = await guard().verify(secret);

		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe("user-7");
		expect(result.user?.roles).toEqual(["member"]);
	});

	it("refuses a token whose account is no longer available", async () => {
		// The whole point of asking the application's provider on every request:
		// the token is still valid, the account is not.
		const secret = await seedToken({ userId: "user-7" });
		users.delete("user-7");

		const result = await guard().verify(secret);

		expect(result.authenticated).toBe(false);
		expect(result.user).toBeUndefined();
	});

	it("refuses an unknown, expired or revoked token", async () => {
		const expired = await seedToken({
			secret: "tok_expired",
			userId: "user-7",
			expiresAt: new Date(Date.now() - HOUR),
		});
		const revoked = await seedToken({
			secret: "tok_revoked",
			userId: "user-7",
			revokedAt: new Date(),
		});

		for (const presented of ["tok_nope", expired, revoked]) {
			const result = await guard().verify(presented);
			expect(result.authenticated, presented).toBe(false);
		}
	});

	it("puts the token's scopes on the current access token", async () => {
		const secret = await seedToken({
			userId: "user-7",
			scopes: ["contacts.read", "contacts.write"],
		});

		const token = (await guard().verify(secret)).user?.currentAccessToken;

		expect(token?.abilities).toEqual(["contacts.read", "contacts.write"]);
		expect(token?.allows("contacts.read")).toBe(true);
		expect(token?.denies("invoices.read")).toBe(true);
		expect(token?.clientId).toBe("client-1");
		expect(token?.isExpired()).toBe(false);
	});

	it("treats a wildcard scope as every ability", async () => {
		// Upstream's rule, read off `@adonisjs/auth`: `includes(a) || includes('*')`.
		const secret = await seedToken({ userId: "user-7", scopes: ["*"] });

		const token = (await guard().verify(secret)).user?.currentAccessToken;

		expect(token?.allows("anything.at.all")).toBe(true);
	});

	it("throws E_UNAUTHORIZED_ACCESS from authorize()", async () => {
		const secret = await seedToken({
			userId: "user-7",
			scopes: ["contacts.read"],
		});

		const token = (await guard().verify(secret)).user?.currentAccessToken;

		expect(() => token?.authorize("contacts.read")).not.toThrow();
		let code: unknown;
		try {
			token?.authorize("contacts.write");
			expect.unreachable("authorize() should have thrown");
		} catch (error) {
			code = error instanceof Error ? Reflect.get(error, "code") : undefined;
		}
		expect(code).toBe("E_UNAUTHORIZED_ACCESS");
	});

	it("also surfaces the scopes on permissions, merged with the user's own", async () => {
		users.set("user-7", { id: "user-7", permissions: ["profile.read"] });
		const secret = await seedToken({
			userId: "user-7",
			scopes: ["contacts.read"],
		});

		const result = await guard().verify(secret);

		expect(new Set(result.user?.permissions)).toEqual(
			new Set(["profile.read", "contacts.read"]),
		);
		// The provider's object is the application's — a guard that mutated it
		// would leak one request's scopes into the next.
		expect(users.get("user-7")?.permissions).toEqual(["profile.read"]);
	});

	it("reports the PREVIOUS use and records this one", async () => {
		const yesterday = new Date(Date.now() - 24 * HOUR);
		const secret = await seedToken({ userId: "user-7", lastUsedAt: yesterday });

		const token = (await guard().verify(secret)).user?.currentAccessToken;
		expect(token?.lastUsedAt?.getTime()).toBe(yesterday.getTime());

		// …and the use just made is now what the store holds.
		const stored = await memory.findAccessToken(hashSecret(secret));
		expect(stored?.lastUsedAt?.getTime()).toBeGreaterThan(yesterday.getTime());
	});

	it("still authenticates against a store that records no use", async () => {
		const secret = await seedToken({ userId: "user-7" });
		const readOnly: GuardStore = {
			findAccessToken: (hash) => memory.findAccessToken(hash),
			saveAccessToken: (token) => memory.saveAccessToken(token),
			revokeAccessToken: (hash, at) => memory.revokeAccessToken(hash, at),
		};

		const result = await guard(readOnly).verify(secret);

		expect(result.authenticated).toBe(true);
		expect(result.user?.currentAccessToken?.lastUsedAt).toBeNull();
	});

	it("refuses a client-credentials token unless the app says who it is", async () => {
		// No user behind that grant. Guessing one would be worse than refusing.
		const secret = await seedToken({ scopes: ["reports.read"] });

		expect((await guard().verify(secret)).authenticated).toBe(false);

		const machine = visaGuard({
			store: memory,
			findUser,
			findClientSubject: async (clientId) => ({ id: `client:${clientId}` }),
		});
		const result = await machine.verify(secret);
		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe("client:client-1");
	});

	it("takes its store lazily, so config can be read before the provider boots", async () => {
		let built = false;
		const lazy = guard(() => {
			built = true;
			return memory;
		});
		expect(built, "the store must not be read while building the guard").toBe(
			false,
		);

		const secret = await seedToken({ userId: "user-7" });
		expect((await lazy.verify(secret)).authenticated).toBe(true);
		expect(built).toBe(true);
	});

	it("throws when asked to authenticate credentials", async () => {
		// Warden's own access-tokens guard throws here, and the distinction
		// matters: a bearer guard handed a password is a misconfigured app, not a
		// bad credential, and the two must not produce the same 401.
		await expect(guard().authenticate()).rejects.toThrow(/bearer token/i);
	});

	it("mints a token for a user, as upstream's guard does", async () => {
		const minting = visaGuard({
			store: memory,
			findUser,
			tokenClientId: "first-party",
		});

		const token = await minting.createToken("user-7", ["contacts.read"], {
			name: "CLI",
		});

		// The plaintext exists exactly once, on the way out.
		expect(token.value).toBeTypeOf("string");
		expect(token.toJSON().token).toBe(token.value);
		expect(token.name).toBe("CLI");
		expect(token.abilities).toEqual(["contacts.read"]);

		// …and it is an ordinary token: it authenticates, and it is stored hashed.
		const result = await minting.verify(token.value ?? "");
		expect(result.authenticated).toBe(true);
		expect(result.user?.id).toBe("user-7");
		expect(await memory.findAccessToken(token.value ?? "")).toBeNull();
	});

	it("refuses to mint a token with no client to issue it to", async () => {
		await expect(guard().createToken("user-7")).rejects.toThrow(
			/tokenClientId/,
		);
	});

	it("gives a minted token every ability by default", async () => {
		const minting = visaGuard({
			store: memory,
			findUser,
			tokenClientId: "first-party",
		});

		const token = await minting.createToken("user-7");

		expect(token.abilities).toEqual(["*"]);
		expect(token.allows("anything")).toBe(true);
	});

	it("revokes a token, once", async () => {
		const minting = visaGuard({
			store: memory,
			findUser,
			tokenClientId: "first-party",
		});
		const token = await minting.createToken("user-7");
		const presented = token.value ?? "";

		expect(await minting.invalidateToken(presented)).toBe(true);
		expect((await minting.verify(presented)).authenticated).toBe(false);
		// Already revoked, and a token nobody ever issued: neither is a thing to
		// revoke, and saying so is how a caller tells the two from a success.
		expect(await minting.invalidateToken(presented)).toBe(false);
		expect(await minting.invalidateToken("never-existed")).toBe(false);
	});

	it("tells a test client how to be a user", async () => {
		const minting = visaGuard({
			store: memory,
			findUser,
			tokenClientId: "first-party",
		});

		const response = await minting.authenticateAsClient("user-7", ["*"]);
		const header = response.headers?.authorization ?? "";

		expect(header.startsWith("Bearer ")).toBe(true);
		// The credential is real — a test authenticates the way the application
		// will, not against a token the store has never seen.
		const presented = header.slice("Bearer ".length);
		expect((await minting.verify(presented)).authenticated).toBe(true);
	});

	it("is named, so `auth.use()` can reach it", () => {
		expect(guard().name).toBe("visa");
		expect(visaGuard({ store: memory, findUser, name: "api" }).name).toBe(
			"api",
		);
	});
});
