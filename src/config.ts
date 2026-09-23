/**
 * `config/visa.ts` — the Adonis shape: a `defineConfig` that returns what the
 * provider reads out of the config store.
 */

import type { VisaStore } from "./store.js";

export interface VisaConfigInput {
	/**
	 * The public URL this server answers on — `https://auth.example.com`.
	 *
	 * It is the `iss` every token is bound to, so it is not cosmetic: a client
	 * that validates the issuer rejects tokens minted under a different one.
	 */
	issuer: string;
	/** Where clients, codes, tokens and consents live. */
	store: VisaStore;
	/** Seconds. Default 3600 — an hour is long enough to be useful, short
	 * enough that a leaked token is not a standing invitation. */
	accessTokenTtlSeconds?: number;
	/** Seconds. Default 30 days. */
	refreshTokenTtlSeconds?: number;
	/** Seconds. Default 30 — a code is exchanged in milliseconds. */
	codeTtlSeconds?: number;
	issueRefreshTokens?: boolean;
	/** See `AuthorizeOptions.allowPlainChallenge` — off, and stay off. */
	allowPlainChallenge?: boolean;
	/** Where the endpoints are mounted. Default `/oauth`. */
	prefix?: string;
}

export function defineConfig(config: VisaConfigInput): VisaConfigInput {
	return config;
}
