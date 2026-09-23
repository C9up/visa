/**
 * The store that needs no database.
 *
 * For tests and for a single-process development server — never for
 * production, where a restart would sign every user out and a second instance
 * would not see the first one's tokens.
 *
 * It is also the reference implementation of the contract: the atomicity the
 * interface demands is trivially true here, in one event loop, which is
 * exactly why a driver on a real database has to say how it achieves it.
 */

import type { VisaStore } from "../store.js";
import type {
	AccessToken,
	AuthorizationCode,
	Client,
	Consent,
	RefreshToken,
} from "../types.js";

export class MemoryStore implements VisaStore {
	readonly #clients = new Map<string, Client>();
	readonly #codes = new Map<string, AuthorizationCode>();
	readonly #accessTokens = new Map<string, AccessToken>();
	readonly #refreshTokens = new Map<string, RefreshToken>();
	readonly #consents = new Map<string, Consent>();

	constructor(clients: readonly Client[] = []) {
		for (const client of clients) this.#clients.set(client.id, client);
	}

	/** Register a client. Returns it, so a caller can keep the reference. */
	addClient(client: Client): Client {
		this.#clients.set(client.id, client);
		return client;
	}

	async findClient(id: string): Promise<Client | null> {
		return this.#clients.get(id) ?? null;
	}

	async saveAuthorizationCode(code: AuthorizationCode): Promise<void> {
		this.#codes.set(code.codeHash, code);
	}

	async findAuthorizationCode(
		codeHash: string,
	): Promise<AuthorizationCode | null> {
		return this.#codes.get(codeHash) ?? null;
	}

	async consumeAuthorizationCode(codeHash: string, at: Date): Promise<boolean> {
		const code = this.#codes.get(codeHash);
		if (code === undefined || code.consumedAt !== undefined) return false;
		code.consumedAt = at;
		return true;
	}

	async saveAccessToken(token: AccessToken): Promise<void> {
		this.#accessTokens.set(token.tokenHash, token);
	}

	async findAccessToken(tokenHash: string): Promise<AccessToken | null> {
		return this.#accessTokens.get(tokenHash) ?? null;
	}

	async revokeAccessToken(tokenHash: string, at: Date): Promise<void> {
		const token = this.#accessTokens.get(tokenHash);
		if (token !== undefined) token.revokedAt = at;
	}

	async saveRefreshToken(token: RefreshToken): Promise<void> {
		this.#refreshTokens.set(token.tokenHash, token);
	}

	async findRefreshToken(tokenHash: string): Promise<RefreshToken | null> {
		return this.#refreshTokens.get(tokenHash) ?? null;
	}

	async consumeRefreshToken(tokenHash: string, at: Date): Promise<boolean> {
		const token = this.#refreshTokens.get(tokenHash);
		if (token === undefined || token.consumedAt !== undefined) return false;
		token.consumedAt = at;
		return true;
	}

	async revokeFamily(familyId: string, at: Date): Promise<void> {
		// Both kinds: a leaked refresh token has usually already bought an
		// access token, and leaving that one alive defeats the revocation.
		for (const token of this.#refreshTokens.values()) {
			if (token.familyId === familyId) token.revokedAt = at;
		}
		for (const token of this.#accessTokens.values()) {
			if (token.familyId === familyId) token.revokedAt = at;
		}
	}

	async findConsent(userId: string, clientId: string): Promise<Consent | null> {
		return this.#consents.get(`${userId}\u0000${clientId}`) ?? null;
	}

	async saveConsent(consent: Consent): Promise<void> {
		this.#consents.set(`${consent.userId}\u0000${consent.clientId}`, consent);
	}

	async prune(now: Date): Promise<void> {
		for (const [key, code] of this.#codes) {
			if (code.expiresAt <= now) this.#codes.delete(key);
		}
		for (const [key, token] of this.#accessTokens) {
			if (token.expiresAt <= now) this.#accessTokens.delete(key);
		}
		for (const [key, token] of this.#refreshTokens) {
			if (token.expiresAt <= now) this.#refreshTokens.delete(key);
		}
	}
}
