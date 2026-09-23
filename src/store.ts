/**
 * What the server needs from wherever its state lives.
 *
 * A contract rather than a table, the same way echo, eclipse and bay do it:
 * an application already running atlas gets a driver, one running on Redis or
 * on a schema it does not own writes twelve methods.
 *
 * Every method that takes a credential takes it HASHED. The plaintext never
 * reaches the store, so a database dump is not a set of working tokens.
 */

import type {
	AccessToken,
	AuthorizationCode,
	Client,
	Consent,
	RefreshToken,
} from "./types.js";

export interface VisaStore {
	findClient(id: string): Promise<Client | null>;

	saveAuthorizationCode(code: AuthorizationCode): Promise<void>;
	findAuthorizationCode(codeHash: string): Promise<AuthorizationCode | null>;
	/**
	 * Mark a code as used. MUST be atomic against a concurrent exchange: two
	 * requests racing with the same code must not both succeed, which is the
	 * whole of the single-use guarantee (§7.5.1).
	 *
	 * Answers `false` when it was already consumed.
	 */
	consumeAuthorizationCode(codeHash: string, at: Date): Promise<boolean>;

	saveAccessToken(token: AccessToken): Promise<void>;
	findAccessToken(tokenHash: string): Promise<AccessToken | null>;
	revokeAccessToken(tokenHash: string, at: Date): Promise<void>;

	saveRefreshToken(token: RefreshToken): Promise<void>;
	findRefreshToken(tokenHash: string): Promise<RefreshToken | null>;
	/** Same atomicity requirement as a code: rotation depends on it. */
	consumeRefreshToken(tokenHash: string, at: Date): Promise<boolean>;
	/**
	 * Revoke every token of a family, refresh and access alike.
	 *
	 * Called when a consumed refresh token comes back: that is a leak, and the
	 * only safe answer is to end the session it belongs to rather than guess
	 * which of the two holders is the thief.
	 */
	revokeFamily(familyId: string, at: Date): Promise<void>;

	findConsent(userId: string, clientId: string): Promise<Consent | null>;
	saveConsent(consent: Consent): Promise<void>;

	/** Drop what has expired. Optional: a store with a TTL does it itself. */
	prune?(now: Date): Promise<void>;
}
