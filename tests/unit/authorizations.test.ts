import { beforeEach, describe, expect, it } from "vitest";
import { hashSecret } from "../../src/crypto.js";
import { MemoryStore } from "../../src/stores/memory.js";
import { VisaManager } from "../../src/VisaManager.js";

/**
 * What a user sees on "connected applications", and what happens when they
 * press Revoke.
 *
 * The unit is the APPLICATION, not the token: a person authorised an
 * application once, and tokens come and go under that decision. Showing four
 * rows for four live tokens would be a lie about what revoking does.
 */

const ISSUER = "https://auth.example";
const HOUR = 3600_000;

describe("visa > a user's authorizations", () => {
	let store: MemoryStore;
	let visa: VisaManager;

	beforeEach(() => {
		store = new MemoryStore([
			{
				id: "billing",
				name: "Billing",
				redirectUris: ["https://billing.example/cb"],
				grantTypes: ["authorization_code"],
				scopes: ["profile", "invoices.read"],
				tokenEndpointAuthMethod: "none",
			},
			{
				id: "crm",
				name: "CRM",
				redirectUris: ["https://crm.example/cb"],
				grantTypes: ["authorization_code"],
				scopes: ["contacts.read"],
				tokenEndpointAuthMethod: "none",
			},
		]);
		visa = new VisaManager({ issuer: ISSUER, store });
	});

	async function grant(
		clientId: string,
		options: {
			userId?: string;
			scopes?: string[];
			grantedAt?: Date;
			tokens?: Array<{
				secret: string;
				expiresAt?: Date;
				lastUsedAt?: Date;
				revokedAt?: Date;
			}>;
		} = {},
	): Promise<void> {
		const userId = options.userId ?? "user-7";
		await store.saveConsent({
			userId,
			clientId,
			scopes: options.scopes ?? ["profile"],
			grantedAt: options.grantedAt ?? new Date(),
		});
		for (const token of options.tokens ?? []) {
			await store.saveAccessToken({
				tokenHash: hashSecret(token.secret),
				clientId,
				userId,
				scopes: options.scopes ?? ["profile"],
				expiresAt: token.expiresAt ?? new Date(Date.now() + HOUR),
				...(token.lastUsedAt === undefined
					? {}
					: { lastUsedAt: token.lastUsedAt }),
				...(token.revokedAt === undefined
					? {}
					: { revokedAt: token.revokedAt }),
			});
		}
	}

	it("lists one row per application, whatever its tokens", async () => {
		await grant("billing", {
			scopes: ["profile", "invoices.read"],
			tokens: [{ secret: "a" }, { secret: "b" }, { secret: "c" }],
		});

		const rows = await visa.listAuthorizations("user-7");

		expect(rows).toHaveLength(1);
		expect(rows[0]?.clientId).toBe("billing");
		expect(rows[0]?.name).toBe("Billing");
		// The consent, not what one token happens to carry.
		expect(rows[0]?.scopes).toEqual(["profile", "invoices.read"]);
		expect(rows[0]?.active).toBe(true);
	});

	it("shows the most recent use across an application's tokens", async () => {
		const older = new Date(Date.now() - 5 * HOUR);
		const newer = new Date(Date.now() - HOUR);
		await grant("billing", {
			tokens: [
				{ secret: "a", lastUsedAt: older },
				{ secret: "b", lastUsedAt: newer },
				{ secret: "c" },
			],
		});

		const [row] = await visa.listAuthorizations("user-7");

		expect(row?.lastUsedAt?.getTime()).toBe(newer.getTime());
	});

	it("keeps an application whose tokens have all expired, marked inactive", async () => {
		// "Last used" matters most when nothing is live any more. Hiding the row
		// would tell someone an application never touched their data when it did.
		const used = new Date(Date.now() - 48 * HOUR);
		await grant("billing", {
			tokens: [
				{
					secret: "a",
					expiresAt: new Date(Date.now() - 24 * HOUR),
					lastUsedAt: used,
				},
			],
		});

		const [row] = await visa.listAuthorizations("user-7");

		expect(row?.active).toBe(false);
		expect(row?.lastUsedAt?.getTime()).toBe(used.getTime());
	});

	it("marks an application inactive once its tokens are revoked", async () => {
		await grant("billing", {
			tokens: [{ secret: "a", revokedAt: new Date() }],
		});

		expect((await visa.listAuthorizations("user-7"))[0]?.active).toBe(false);
	});

	it("shows an application with no token yet", async () => {
		await grant("billing");

		const [row] = await visa.listAuthorizations("user-7");

		expect(row?.active).toBe(false);
		expect(row?.lastUsedAt).toBeUndefined();
	});

	it("still shows a grant whose client has been deleted", async () => {
		// The grant is the user's. They must be able to end it even if nobody
		// can say any more what the application was called.
		await store.saveConsent({
			userId: "user-7",
			clientId: "gone",
			scopes: ["profile"],
			grantedAt: new Date(),
		});

		const row = (await visa.listAuthorizations("user-7")).find(
			(entry) => entry.clientId === "gone",
		);

		expect(row?.name).toBe("gone");
	});

	it("shows nobody else's authorizations", async () => {
		await grant("billing", { userId: "user-7", tokens: [{ secret: "mine" }] });
		await grant("crm", { userId: "user-8", tokens: [{ secret: "theirs" }] });

		const rows = await visa.listAuthorizations("user-7");

		expect(rows.map((row) => row.clientId)).toEqual(["billing"]);
	});

	it("answers an empty list for a user who granted nothing", async () => {
		expect(await visa.listAuthorizations("stranger")).toEqual([]);
	});

	it("revokes every token of one application, and forgets the grant", async () => {
		await grant("billing", { tokens: [{ secret: "a" }, { secret: "b" }] });
		await grant("crm", {
			scopes: ["contacts.read"],
			tokens: [{ secret: "c" }],
		});

		await visa.revokeAuthorization("user-7", "billing");

		// Dead, both of them.
		expect(await visa.verify("a")).toBeNull();
		expect(await visa.verify("b")).toBeNull();
		// The grant is gone, so the user is asked again next time.
		expect(await store.findConsent("user-7", "billing")).toBeNull();
		// …and the other application is untouched.
		expect(await visa.verify("c")).not.toBeNull();
		expect(await store.findConsent("user-7", "crm")).not.toBeNull();
	});

	it("revokes the refresh tokens too", async () => {
		// Revoking only the access half would let the application mint a new one
		// a second later, which is not revocation at all.
		await grant("billing", { tokens: [{ secret: "a" }] });
		await store.saveRefreshToken({
			tokenHash: hashSecret("refresh"),
			familyId: "fam-1",
			clientId: "billing",
			userId: "user-7",
			scopes: ["profile"],
			expiresAt: new Date(Date.now() + 30 * HOUR),
		});

		await visa.revokeAuthorization("user-7", "billing");

		const refresh = await store.findRefreshToken(hashSecret("refresh"));
		expect(refresh?.revokedAt).toBeInstanceOf(Date);
	});

	it("revokes only that user's tokens for the application", async () => {
		await grant("billing", { userId: "user-7", tokens: [{ secret: "mine" }] });
		await grant("billing", {
			userId: "user-8",
			tokens: [{ secret: "theirs" }],
		});

		await visa.revokeAuthorization("user-7", "billing");

		expect(await visa.verify("mine")).toBeNull();
		expect(await visa.verify("theirs")).not.toBeNull();
	});

	it("is quiet about revoking what was never granted", async () => {
		// The end state is what was asked for: that application has no access.
		await expect(
			visa.revokeAuthorization("user-7", "never-authorized"),
		).resolves.toBeUndefined();
	});
});
