/**
 * `config/visa.ts` — the Adonis shape: a `defineConfig` that returns what the
 * provider reads out of the config store.
 */

import type { RegistrationOptions } from "./register.js";
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
	/**
	 * The resources this server issues tokens for (RFC 8707).
	 *
	 * Left out, any well-formed `resource` is accepted and carried. Named, an
	 * unknown one is refused with `invalid_target` — which is what stops a
	 * client asking for a token aimed at a server you do not run.
	 */
	resourcesSupported?: string[];
	/**
	 * Let clients register themselves (RFC 7591).
	 *
	 * OFF unless you say otherwise. An MCP client such as claude.ai has nobody
	 * to fill in a form for it, so it needs this; a server on the public
	 * internet with it open lets anyone create a client, so think about
	 * `initialAccessToken` before shipping one.
	 */
	registration?: RegistrationOptions;
	/**
	 * The protected resource this server issues tokens for (RFC 9728).
	 *
	 * Declare it and two things follow: the metadata document is served at
	 * `/.well-known/oauth-protected-resource`, and a refusal can name it. An
	 * MCP client walks from the 401 to that document to this server without
	 * anybody pasting a URL into a config file, which is the whole reason the
	 * RFC exists.
	 */
	protectedResource?: {
		/** The resource identifier — an absolute URI, no fragment. */
		resource: string;
		/** What a client may ask for. RECOMMENDED by §3.2. */
		scopesSupported?: string[];
		resourceName?: string;
		resourceDocumentation?: string;
	};
}

export function defineConfig(config: VisaConfigInput): VisaConfigInput {
	return config;
}
