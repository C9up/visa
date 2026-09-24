/**
 * The store an application running atlas gets for free.
 *
 * Twelve methods, two of them atomic, is not something every application
 * should write again — and the two that matter are exactly the ones a
 * hand-written store gets subtly wrong. This is that code, once.
 *
 * It takes atlas' `db` service rather than importing atlas: the structural
 * slice below is what the store calls and nothing more, so visa still installs
 * without a data layer and the package stays as standalone as every other one
 * here. Built on atlas' query builder rather than on SQL text, deliberately —
 * dialects are atlas' problem, and it already solves them.
 *
 * Every credential arrives HASHED, as the contract states, so what this writes
 * is what the rest of the package writes: a database copy is not a set of
 * working tokens.
 */

import type { VisaStore } from "../store.js";
import type {
	AccessToken,
	AuthorizationCode,
	Client,
	ClientAuthMethod,
	Consent,
	GrantType,
	RefreshToken,
} from "../types.js";

/** A row as atlas hands it back. */
type Row = Record<string, unknown>;

/** The comparisons atlas' builder accepts. */
type Operator = "=" | "!=" | ">" | ">=" | "<" | "<=";

/**
 * The slice of atlas' `DatabaseQueryBuilder` this store uses.
 *
 * Every read here fetches one row, so the slice asks for `first()` and not for
 * the builder's thenable form. Nothing is declared that nothing calls.
 */
export interface AtlasQuery {
	where(conditions: Row): AtlasQuery;
	where(column: string, operator: Operator, value: unknown): AtlasQuery;
	whereNull(column: string): AtlasQuery;
	orderBy(column: string, direction?: "asc" | "desc"): AtlasQuery;
	first(): Promise<Row | null>;
	/** Run the select and return every row — atlas' `exec()`. */
	exec(): Promise<Row[]>;
	insert(data: Row): PromiseLike<unknown>;
	/** Resolves to the number of rows affected, which is what the atomic paths read. */
	update(data: Row): PromiseLike<number | Row[]>;
	delete(): PromiseLike<number | Row[]>;
}

/** The slice of atlas' `db` service this store uses. */
export interface AtlasDb {
	from(table: string): AtlasQuery;
	table(table: string): AtlasQuery;
}

/** Where each kind of row lives. Override one to fit a schema you do not own. */
export interface AtlasStoreTables {
	clients?: string;
	authorizationCodes?: string;
	accessTokens?: string;
	refreshTokens?: string;
	consents?: string;
}

const DEFAULT_TABLES = {
	clients: "visa_clients",
	authorizationCodes: "visa_authorization_codes",
	accessTokens: "visa_access_tokens",
	refreshTokens: "visa_refresh_tokens",
	consents: "visa_consents",
} as const;

/**
 * A list of strings, stored as JSON text.
 *
 * Text and not a native array type: three dialects are supported and only one
 * of them has arrays. The round trip is explicit so a malformed value fails on
 * read rather than becoming `[]` — a scope list that quietly empties is an
 * authorisation bug, not a display one.
 */
function encodeList(values: readonly string[]): string {
	return JSON.stringify(values);
}

function decodeList(value: unknown, column: string): string[] {
	if (value === null || value === undefined) return [];
	if (Array.isArray(value)) {
		// A `json` column comes back parsed on some dialects and as text on others.
		return value.filter((entry): entry is string => typeof entry === "string");
	}
	if (typeof value !== "string") {
		throw new Error(`[visa] ${column} holds ${typeof value}, expected a list`);
	}
	const parsed: unknown = JSON.parse(value);
	if (!Array.isArray(parsed)) {
		throw new Error(`[visa] ${column} is not a JSON array: ${value}`);
	}
	return parsed.filter((entry): entry is string => typeof entry === "string");
}

/** A column that may be null, as a Date. */
function decodeDate(value: unknown): Date | undefined {
	if (value === null || value === undefined) return undefined;
	if (value instanceof Date) return value;
	if (typeof value === "number" || typeof value === "string") {
		const date = new Date(value);
		if (!Number.isNaN(date.getTime())) return date;
	}
	return undefined;
}

/** A column that must hold a date. */
function requireDate(value: unknown, column: string): Date {
	const date = decodeDate(value);
	if (date === undefined) {
		throw new Error(`[visa] ${column} is not a date: ${String(value)}`);
	}
	return date;
}

function requireString(value: unknown, column: string): string {
	if (typeof value !== "string") {
		throw new Error(`[visa] ${column} is not a string: ${String(value)}`);
	}
	return value;
}

function optionalString(value: unknown): string | undefined {
	return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * How many rows a write touched.
 *
 * `update()` answers a count, or the rows themselves when the caller asked for
 * them. Only the count is ever asked for here, and the other shape is read as
 * its length rather than assumed away.
 */
function affected(result: number | Row[]): number {
	return typeof result === "number" ? result : result.length;
}

export class AtlasStore implements VisaStore {
	readonly #db: AtlasDb;
	readonly #tables: Required<AtlasStoreTables>;

	constructor(db: AtlasDb, tables: AtlasStoreTables = {}) {
		this.#db = db;
		this.#tables = {
			clients: tables.clients ?? DEFAULT_TABLES.clients,
			authorizationCodes:
				tables.authorizationCodes ?? DEFAULT_TABLES.authorizationCodes,
			accessTokens: tables.accessTokens ?? DEFAULT_TABLES.accessTokens,
			refreshTokens: tables.refreshTokens ?? DEFAULT_TABLES.refreshTokens,
			consents: tables.consents ?? DEFAULT_TABLES.consents,
		};
	}

	async findClient(id: string): Promise<Client | null> {
		const row = await this.#db.from(this.#tables.clients).where({ id }).first();
		if (row === null) return null;
		const secretHash = optionalString(row.secret_hash);
		return {
			id: requireString(row.id, "id"),
			name: requireString(row.name, "name"),
			...(secretHash === undefined ? {} : { secretHash }),
			redirectUris: decodeList(row.redirect_uris, "redirect_uris"),
			grantTypes: decodeList(row.grant_types, "grant_types").filter(
				isGrantType,
			),
			scopes: decodeList(row.scopes, "scopes"),
			tokenEndpointAuthMethod: readAuthMethod(row.token_endpoint_auth_method),
			...(row.trusted === true || row.trusted === 1 ? { trusted: true } : {}),
		};
	}

	/** Persist a registered client. Not on the contract — what `registerClient` writes through. */
	async saveClient(client: Client): Promise<void> {
		await this.#db.table(this.#tables.clients).insert({
			id: client.id,
			name: client.name,
			secret_hash: client.secretHash ?? null,
			redirect_uris: encodeList(client.redirectUris),
			grant_types: encodeList(client.grantTypes),
			scopes: encodeList(client.scopes),
			token_endpoint_auth_method: client.tokenEndpointAuthMethod,
			trusted: client.trusted === true,
			created_at: new Date(),
		});
	}

	async saveAuthorizationCode(code: AuthorizationCode): Promise<void> {
		await this.#db.table(this.#tables.authorizationCodes).insert({
			code_hash: code.codeHash,
			client_id: code.clientId,
			user_id: code.userId,
			redirect_uri: code.redirectUri,
			scopes: encodeList(code.scopes),
			code_challenge: code.codeChallenge,
			code_challenge_method: code.codeChallengeMethod,
			expires_at: code.expiresAt,
			consumed_at: code.consumedAt ?? null,
			nonce: code.nonce ?? null,
			created_at: new Date(),
		});
	}

	async findAuthorizationCode(
		codeHash: string,
	): Promise<AuthorizationCode | null> {
		const row = await this.#db
			.from(this.#tables.authorizationCodes)
			.where({ code_hash: codeHash })
			.first();
		if (row === null) return null;
		const consumedAt = decodeDate(row.consumed_at);
		const nonce = optionalString(row.nonce);
		return {
			codeHash: requireString(row.code_hash, "code_hash"),
			clientId: requireString(row.client_id, "client_id"),
			userId: requireString(row.user_id, "user_id"),
			redirectUri: requireString(row.redirect_uri, "redirect_uri"),
			scopes: decodeList(row.scopes, "scopes"),
			codeChallenge: requireString(row.code_challenge, "code_challenge"),
			codeChallengeMethod:
				row.code_challenge_method === "plain" ? "plain" : "S256",
			expiresAt: requireDate(row.expires_at, "expires_at"),
			...(consumedAt === undefined ? {} : { consumedAt }),
			...(nonce === undefined ? {} : { nonce }),
		};
	}

	/**
	 * One UPDATE, guarded by `consumed_at IS NULL`.
	 *
	 * The single-use guarantee lives in that one statement: two requests racing
	 * with the same code both reach the database, and only the one that finds
	 * the row still unconsumed is allowed to write it. Reading and then writing
	 * would let both through.
	 */
	async consumeAuthorizationCode(codeHash: string, at: Date): Promise<boolean> {
		const result = await this.#db
			.from(this.#tables.authorizationCodes)
			.where({ code_hash: codeHash })
			.whereNull("consumed_at")
			.update({ consumed_at: at });
		return affected(result) === 1;
	}

	async saveAccessToken(token: AccessToken): Promise<void> {
		await this.#db.table(this.#tables.accessTokens).insert({
			token_hash: token.tokenHash,
			client_id: token.clientId,
			user_id: token.userId ?? null,
			scopes: encodeList(token.scopes),
			expires_at: token.expiresAt,
			revoked_at: token.revokedAt ?? null,
			last_used_at: token.lastUsedAt ?? null,
			family_id: token.familyId ?? null,
			created_at: new Date(),
		});
	}

	async findAccessToken(tokenHash: string): Promise<AccessToken | null> {
		const row = await this.#db
			.from(this.#tables.accessTokens)
			.where({ token_hash: tokenHash })
			.first();
		return row === null ? null : readAccessToken(row);
	}

	async revokeAccessToken(tokenHash: string, at: Date): Promise<void> {
		await this.#db
			.from(this.#tables.accessTokens)
			.where({ token_hash: tokenHash })
			.whereNull("revoked_at")
			.update({ revoked_at: at });
	}

	async touchAccessToken(tokenHash: string, at: Date): Promise<void> {
		await this.#db
			.from(this.#tables.accessTokens)
			.where({ token_hash: tokenHash })
			.update({ last_used_at: at });
	}

	async saveRefreshToken(token: RefreshToken): Promise<void> {
		await this.#db.table(this.#tables.refreshTokens).insert({
			token_hash: token.tokenHash,
			family_id: token.familyId,
			client_id: token.clientId,
			user_id: token.userId ?? null,
			scopes: encodeList(token.scopes),
			expires_at: token.expiresAt,
			consumed_at: token.consumedAt ?? null,
			revoked_at: token.revokedAt ?? null,
			created_at: new Date(),
		});
	}

	async findRefreshToken(tokenHash: string): Promise<RefreshToken | null> {
		const row = await this.#db
			.from(this.#tables.refreshTokens)
			.where({ token_hash: tokenHash })
			.first();
		if (row === null) return null;
		const userId = optionalString(row.user_id);
		const consumedAt = decodeDate(row.consumed_at);
		const revokedAt = decodeDate(row.revoked_at);
		return {
			tokenHash: requireString(row.token_hash, "token_hash"),
			familyId: requireString(row.family_id, "family_id"),
			clientId: requireString(row.client_id, "client_id"),
			...(userId === undefined ? {} : { userId }),
			scopes: decodeList(row.scopes, "scopes"),
			expiresAt: requireDate(row.expires_at, "expires_at"),
			...(consumedAt === undefined ? {} : { consumedAt }),
			...(revokedAt === undefined ? {} : { revokedAt }),
		};
	}

	/** Same one-statement guarantee as a code: rotation depends on it. */
	async consumeRefreshToken(tokenHash: string, at: Date): Promise<boolean> {
		const result = await this.#db
			.from(this.#tables.refreshTokens)
			.where({ token_hash: tokenHash })
			.whereNull("consumed_at")
			.update({ consumed_at: at });
		return affected(result) === 1;
	}

	/**
	 * End a family: the refresh tokens AND the access tokens they bought.
	 *
	 * Both, because revoking only the refresh half would leave an access token
	 * already minted alive for its full lifetime — which is most of what this
	 * revocation exists to prevent.
	 */
	async revokeFamily(familyId: string, at: Date): Promise<void> {
		await this.#db
			.from(this.#tables.refreshTokens)
			.where({ family_id: familyId })
			.whereNull("revoked_at")
			.update({ revoked_at: at });
		await this.#db
			.from(this.#tables.accessTokens)
			.where({ family_id: familyId })
			.whereNull("revoked_at")
			.update({ revoked_at: at });
	}

	async findConsent(userId: string, clientId: string): Promise<Consent | null> {
		const row = await this.#db
			.from(this.#tables.consents)
			.where({ user_id: userId, client_id: clientId })
			.first();
		if (row === null) return null;
		return {
			userId: requireString(row.user_id, "user_id"),
			clientId: requireString(row.client_id, "client_id"),
			scopes: decodeList(row.scopes, "scopes"),
			grantedAt: requireDate(row.granted_at, "granted_at"),
		};
	}

	/**
	 * Record a consent, replacing what was there.
	 *
	 * Delete then insert rather than an upsert: the dialects spell an upsert
	 * three different ways, and re-granting is not a hot path.
	 */
	async saveConsent(consent: Consent): Promise<void> {
		await this.#db
			.from(this.#tables.consents)
			.where({ user_id: consent.userId, client_id: consent.clientId })
			.delete();
		await this.#db.table(this.#tables.consents).insert({
			user_id: consent.userId,
			client_id: consent.clientId,
			scopes: encodeList(consent.scopes),
			granted_at: consent.grantedAt,
		});
	}

	async listConsents(userId: string): Promise<Consent[]> {
		const rows = await this.#db
			.from(this.#tables.consents)
			.where({ user_id: userId })
			.orderBy("granted_at", "desc")
			.exec();
		return rows.map((row) => ({
			userId: requireString(row.user_id, "user_id"),
			clientId: requireString(row.client_id, "client_id"),
			scopes: decodeList(row.scopes, "scopes"),
			grantedAt: requireDate(row.granted_at, "granted_at"),
		}));
	}

	/** Expired ones included — see the contract for why. */
	async listAccessTokens(userId: string): Promise<AccessToken[]> {
		const rows = await this.#db
			.from(this.#tables.accessTokens)
			.where({ user_id: userId })
			.orderBy("expires_at", "desc")
			.exec();
		return rows.map(readAccessToken);
	}

	async revokeAccessFor(
		userId: string,
		clientId: string,
		at: Date,
	): Promise<void> {
		for (const table of [
			this.#tables.accessTokens,
			this.#tables.refreshTokens,
		]) {
			await this.#db
				.from(table)
				.where({ user_id: userId, client_id: clientId })
				.whereNull("revoked_at")
				.update({ revoked_at: at });
		}
	}

	async deleteConsent(userId: string, clientId: string): Promise<void> {
		await this.#db
			.from(this.#tables.consents)
			.where({ user_id: userId, client_id: clientId })
			.delete();
	}

	/** Drop what has expired and can no longer be presented. */
	async prune(now: Date): Promise<void> {
		for (const table of [
			this.#tables.authorizationCodes,
			this.#tables.accessTokens,
			this.#tables.refreshTokens,
		]) {
			await this.#db.from(table).where("expires_at", "<", now).delete();
		}
	}
}

/** One access-token row, as the contract's shape. */
function readAccessToken(row: Row): AccessToken {
	const userId = optionalString(row.user_id);
	const revokedAt = decodeDate(row.revoked_at);
	const lastUsedAt = decodeDate(row.last_used_at);
	const familyId = optionalString(row.family_id);
	return {
		tokenHash: requireString(row.token_hash, "token_hash"),
		clientId: requireString(row.client_id, "client_id"),
		...(userId === undefined ? {} : { userId }),
		scopes: decodeList(row.scopes, "scopes"),
		expiresAt: requireDate(row.expires_at, "expires_at"),
		...(revokedAt === undefined ? {} : { revokedAt }),
		...(lastUsedAt === undefined ? {} : { lastUsedAt }),
		...(familyId === undefined ? {} : { familyId }),
	};
}

function isGrantType(value: string): value is GrantType {
	return (
		value === "authorization_code" ||
		value === "refresh_token" ||
		value === "client_credentials"
	);
}

function readAuthMethod(value: unknown): ClientAuthMethod {
	if (value === "client_secret_basic" || value === "client_secret_post") {
		return value;
	}
	// A row holding nothing usable is read as a public client, which is the
	// method that grants the least.
	return "none";
}
