import { beforeEach, describe, expect, it } from "vitest";
import {
	type AtlasDb,
	type AtlasQuery,
	AtlasStore,
} from "../../src/stores/atlas.js";

/**
 * The store an application running atlas gets instead of writing twelve
 * methods, two of them atomic.
 *
 * Tested against a table engine that behaves like the query builder does —
 * WHERE narrows, `whereNull` means IS NULL, and an UPDATE answers how many
 * rows it touched. That last one is the whole of the single-use guarantee, so
 * it is what the racing tests below actually measure.
 */

type Row = Record<string, unknown>;

/** A tiny engine with the semantics the store relies on, and no others. */
class FakeDb implements AtlasDb {
	readonly tables = new Map<string, Row[]>();
	/** Every statement, so a test can assert one UPDATE rather than read-then-write. */
	readonly statements: string[] = [];

	rows(table: string): Row[] {
		let rows = this.tables.get(table);
		if (rows === undefined) {
			rows = [];
			this.tables.set(table, rows);
		}
		return rows;
	}

	from(table: string): AtlasQuery {
		return new FakeQuery(this, table);
	}

	table(table: string): AtlasQuery {
		return new FakeQuery(this, table);
	}
}

type Condition = (row: Row) => boolean;

class FakeQuery implements AtlasQuery {
	readonly #db: FakeDb;
	readonly #table: string;
	readonly #conditions: Condition[] = [];

	constructor(db: FakeDb, table: string) {
		this.#db = db;
		this.#table = table;
	}

	where(conditions: Row): AtlasQuery;
	where(column: string, operator: string, value: unknown): AtlasQuery;
	where(
		conditionsOrColumn: Row | string,
		operator?: string,
		value?: unknown,
	): AtlasQuery {
		if (typeof conditionsOrColumn === "string") {
			const column = conditionsOrColumn;
			this.#conditions.push((row) => compare(row[column], operator, value));
			return this;
		}
		for (const [column, expected] of Object.entries(conditionsOrColumn)) {
			this.#conditions.push((row) => row[column] === expected);
		}
		return this;
	}

	whereNull(column: string): AtlasQuery {
		this.#conditions.push(
			(row) => row[column] === null || row[column] === undefined,
		);
		return this;
	}

	orderBy(column: string, direction: "asc" | "desc" = "asc"): AtlasQuery {
		const rows = this.#matching();
		rows.sort((a, b) => {
			const left = String(a[column] ?? "");
			const right = String(b[column] ?? "");
			return direction === "asc"
				? left.localeCompare(right)
				: right.localeCompare(left);
		});
		return this;
	}

	#matching(): Row[] {
		return this.#db
			.rows(this.#table)
			.filter((row) => this.#conditions.every((condition) => condition(row)));
	}

	async first(): Promise<Row | null> {
		this.#db.statements.push(`select ${this.#table}`);
		return this.#matching()[0] ?? null;
	}

	async insert(data: Row): Promise<void> {
		this.#db.statements.push(`insert ${this.#table}`);
		this.#db.rows(this.#table).push({ ...data });
	}

	async update(data: Row): Promise<number> {
		this.#db.statements.push(`update ${this.#table}`);
		const rows = this.#matching();
		for (const row of rows) Object.assign(row, data);
		return rows.length;
	}

	async delete(): Promise<number> {
		this.#db.statements.push(`delete ${this.#table}`);
		const matching = new Set(this.#matching());
		const kept = this.#db.rows(this.#table).filter((row) => !matching.has(row));
		this.#db.tables.set(this.#table, kept);
		return matching.size;
	}
}

function compare(left: unknown, operator: string | undefined, right: unknown) {
	const a = left instanceof Date ? left.getTime() : Number(left);
	const b = right instanceof Date ? right.getTime() : Number(right);
	if (operator === "<") return a < b;
	if (operator === ">") return a > b;
	return left === right;
}

const HOUR = 3600_000;

describe("visa > the atlas store", () => {
	let db: FakeDb;
	let store: AtlasStore;

	beforeEach(() => {
		db = new FakeDb();
		store = new AtlasStore(db);
	});

	it("round-trips a client, lists and all", async () => {
		await store.saveClient({
			id: "app-1",
			name: "Billing",
			secretHash: "hash",
			redirectUris: ["https://app.example/cb"],
			grantTypes: ["authorization_code", "refresh_token"],
			scopes: ["profile", "contacts.read"],
			tokenEndpointAuthMethod: "client_secret_basic",
			trusted: true,
		});

		const client = await store.findClient("app-1");

		expect(client).toEqual({
			id: "app-1",
			name: "Billing",
			secretHash: "hash",
			redirectUris: ["https://app.example/cb"],
			grantTypes: ["authorization_code", "refresh_token"],
			scopes: ["profile", "contacts.read"],
			tokenEndpointAuthMethod: "client_secret_basic",
			trusted: true,
		});
	});

	it("answers null for a client it does not have", async () => {
		expect(await store.findClient("nope")).toBeNull();
	});

	it("leaves a public client without a secret and without trust", async () => {
		await store.saveClient({
			id: "spa",
			name: "SPA",
			redirectUris: ["https://spa.example/cb"],
			grantTypes: ["authorization_code"],
			scopes: [],
			tokenEndpointAuthMethod: "none",
		});

		const client = await store.findClient("spa");

		expect(client?.secretHash).toBeUndefined();
		expect(client?.trusted).toBeUndefined();
		expect(client?.tokenEndpointAuthMethod).toBe("none");
	});

	it("round-trips an authorization code", async () => {
		const expiresAt = new Date(Date.now() + 30_000);
		await store.saveAuthorizationCode({
			codeHash: "code-hash",
			clientId: "app-1",
			userId: "user-7",
			redirectUri: "https://app.example/cb",
			scopes: ["profile"],
			codeChallenge: "challenge",
			codeChallengeMethod: "S256",
			expiresAt,
			nonce: "n-1",
		});

		expect(await store.findAuthorizationCode("code-hash")).toEqual({
			codeHash: "code-hash",
			clientId: "app-1",
			userId: "user-7",
			redirectUri: "https://app.example/cb",
			scopes: ["profile"],
			codeChallenge: "challenge",
			codeChallengeMethod: "S256",
			expiresAt,
			nonce: "n-1",
		});
	});

	it("lets exactly one racing exchange consume a code", async () => {
		// The single-use guarantee. Both callers reach the database; only the one
		// whose UPDATE found the row still unconsumed may proceed.
		await store.saveAuthorizationCode({
			codeHash: "code-hash",
			clientId: "app-1",
			userId: "user-7",
			redirectUri: "https://app.example/cb",
			scopes: ["profile"],
			codeChallenge: "challenge",
			codeChallengeMethod: "S256",
			expiresAt: new Date(Date.now() + 30_000),
		});

		const [first, second] = await Promise.all([
			store.consumeAuthorizationCode("code-hash", new Date()),
			store.consumeAuthorizationCode("code-hash", new Date()),
		]);

		expect([first, second].filter(Boolean)).toHaveLength(1);
		// One statement each, and both of them an UPDATE: a read followed by a
		// write would let both through.
		expect(
			db.statements.filter((statement) =>
				statement.startsWith("update visa_authorization_codes"),
			),
		).toHaveLength(2);
		expect(
			db.statements.some((statement) =>
				statement.startsWith("select visa_authorization_codes"),
			),
		).toBe(false);
	});

	it("refuses to consume a code that was never there", async () => {
		expect(await store.consumeAuthorizationCode("ghost", new Date())).toBe(
			false,
		);
	});

	it("round-trips an access token, revokes it, and records its use", async () => {
		const expiresAt = new Date(Date.now() + HOUR);
		await store.saveAccessToken({
			tokenHash: "tok",
			clientId: "app-1",
			userId: "user-7",
			scopes: ["profile"],
			expiresAt,
			familyId: "fam-1",
		});

		expect(await store.findAccessToken("tok")).toEqual({
			tokenHash: "tok",
			clientId: "app-1",
			userId: "user-7",
			scopes: ["profile"],
			expiresAt,
			familyId: "fam-1",
		});

		const used = new Date();
		await store.touchAccessToken("tok", used);
		expect((await store.findAccessToken("tok"))?.lastUsedAt).toEqual(used);

		const at = new Date();
		await store.revokeAccessToken("tok", at);
		expect((await store.findAccessToken("tok"))?.revokedAt).toEqual(at);
	});

	it("keeps a client-credentials token without a user", async () => {
		await store.saveAccessToken({
			tokenHash: "machine",
			clientId: "app-1",
			scopes: ["reports.read"],
			expiresAt: new Date(Date.now() + HOUR),
		});

		const token = await store.findAccessToken("machine");

		expect(token?.userId).toBeUndefined();
		expect(token?.scopes).toEqual(["reports.read"]);
	});

	it("lets exactly one racing rotation consume a refresh token", async () => {
		await store.saveRefreshToken({
			tokenHash: "ref",
			familyId: "fam-1",
			clientId: "app-1",
			userId: "user-7",
			scopes: ["profile"],
			expiresAt: new Date(Date.now() + 30 * HOUR),
		});

		const [first, second] = await Promise.all([
			store.consumeRefreshToken("ref", new Date()),
			store.consumeRefreshToken("ref", new Date()),
		]);

		expect([first, second].filter(Boolean)).toHaveLength(1);
	});

	it("revokes a family on both sides", async () => {
		// Revoking only the refresh half would leave the access token it already
		// bought alive for its full lifetime.
		await store.saveRefreshToken({
			tokenHash: "ref",
			familyId: "fam-1",
			clientId: "app-1",
			userId: "user-7",
			scopes: ["profile"],
			expiresAt: new Date(Date.now() + 30 * HOUR),
		});
		await store.saveAccessToken({
			tokenHash: "tok",
			clientId: "app-1",
			userId: "user-7",
			scopes: ["profile"],
			expiresAt: new Date(Date.now() + HOUR),
			familyId: "fam-1",
		});
		await store.saveAccessToken({
			tokenHash: "other-family",
			clientId: "app-1",
			userId: "user-7",
			scopes: ["profile"],
			expiresAt: new Date(Date.now() + HOUR),
			familyId: "fam-2",
		});

		const at = new Date();
		await store.revokeFamily("fam-1", at);

		expect((await store.findRefreshToken("ref"))?.revokedAt).toEqual(at);
		expect((await store.findAccessToken("tok"))?.revokedAt).toEqual(at);
		// …and nothing outside the family.
		expect(
			(await store.findAccessToken("other-family"))?.revokedAt,
		).toBeUndefined();
	});

	it("replaces a consent instead of stacking two", async () => {
		const first = new Date(Date.now() - HOUR);
		await store.saveConsent({
			userId: "user-7",
			clientId: "app-1",
			scopes: ["profile"],
			grantedAt: first,
		});
		const second = new Date();
		await store.saveConsent({
			userId: "user-7",
			clientId: "app-1",
			scopes: ["profile", "contacts.read"],
			grantedAt: second,
		});

		expect(await store.findConsent("user-7", "app-1")).toEqual({
			userId: "user-7",
			clientId: "app-1",
			scopes: ["profile", "contacts.read"],
			grantedAt: second,
		});
		expect(db.rows("visa_consents")).toHaveLength(1);
	});

	it("prunes what has expired and keeps what has not", async () => {
		await store.saveAccessToken({
			tokenHash: "stale",
			clientId: "app-1",
			scopes: [],
			expiresAt: new Date(Date.now() - HOUR),
		});
		await store.saveAccessToken({
			tokenHash: "live",
			clientId: "app-1",
			scopes: [],
			expiresAt: new Date(Date.now() + HOUR),
		});

		await store.prune(new Date());

		expect(await store.findAccessToken("stale")).toBeNull();
		expect(await store.findAccessToken("live")).not.toBeNull();
	});

	it("writes into the tables it was given", async () => {
		const custom = new AtlasStore(db, { accessTokens: "oauth_tokens" });
		await custom.saveAccessToken({
			tokenHash: "tok",
			clientId: "app-1",
			scopes: [],
			expiresAt: new Date(Date.now() + HOUR),
		});

		expect(db.rows("oauth_tokens")).toHaveLength(1);
		expect(db.rows("visa_access_tokens")).toHaveLength(0);
	});

	it("refuses a scope column that is not a list", async () => {
		// A scope list that quietly empties is an authorisation bug, so a
		// malformed column fails loudly rather than reading as `[]`.
		db.rows("visa_access_tokens").push({
			token_hash: "broken",
			client_id: "app-1",
			user_id: null,
			scopes: "not json",
			expires_at: new Date(Date.now() + HOUR),
			revoked_at: null,
			last_used_at: null,
			family_id: null,
		});

		await expect(store.findAccessToken("broken")).rejects.toThrow();
	});
});
