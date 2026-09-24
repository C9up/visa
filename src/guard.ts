/**
 * `visaGuard()` — authenticating a request with an OAuth access token.
 *
 * Declared in `config/auth.ts` beside `jwtGuard` and `sessionGuard`, and it
 * behaves like the access-tokens guard upstream: the authenticated user carries
 * a `currentAccessToken` whose `abilities` are the token's scopes, with
 * `allows`, `denies`, `authorize`, `isExpired()` and `lastUsedAt` answering
 * exactly as they do there. `allows` treats `*` as every ability, which is the
 * upstream rule read off `@adonisjs/auth`'s build rather than recalled.
 *
 * Two things this fixes for every application at once. A route gate no longer
 * has to introspect the token itself — the scopes are on the guard's token. And
 * the user is fetched through the application's own provider on every request,
 * so an account disabled after the token was issued is refused here instead of
 * in each application that remembers to check.
 *
 * NO import of warden. A guard is structurally `{ name, authenticate, verify }`
 * and that is all warden asks for, so visa stays a package you can run without
 * it — the same rule every other package in this universe follows.
 */

import { hashSecret } from "./crypto.js";
import { verifyAccessToken } from "./introspect.js";
import type { VisaStore } from "./store.js";

/**
 * The user shape a guard hands back.
 *
 * `id` and the two optional arrays are what warden reads; everything else the
 * application's provider returns travels with it untouched.
 */
export interface GuardUser {
	id: string;
	roles?: string[];
	permissions?: string[];
	/** The token this request was authenticated with. Set by the guard. */
	currentAccessToken?: VisaAccessToken;
	[key: string]: unknown;
}

/**
 * What the guard needs from the store, and nothing more.
 *
 * A narrow slice rather than the whole contract: authenticating reads one row
 * and records one use, so that is what it asks for. A full {@link VisaStore}
 * satisfies it, and a resource server that keeps only tokens can implement two
 * methods instead of twelve.
 */
export type GuardStore = Pick<
	VisaStore,
	"findAccessToken" | "touchAccessToken"
>;

/** What a guard answers. Warden's `AuthResult`, declared here so visa owes it nothing. */
export interface GuardResult {
	authenticated: boolean;
	user?: GuardUser;
	error?: string;
}

/** What a test client sends to be this user. Warden's `AuthClientResponse`. */
export interface GuardClientResponse {
	headers?: Record<string, string>;
	session?: Record<string, unknown>;
}

/**
 * The token behind the current request.
 *
 * Upstream's `AccessToken`, minus what an opaque OAuth token has no equivalent
 * for: there is no `identifier`/`secret` pair to decode here, because visa
 * stores a hash and the plaintext never comes back.
 */
export class VisaAccessToken {
	/** The client the token was issued to — an OAuth token always has one. */
	readonly clientId: string;
	/** Absent for `client_credentials`: there is no user behind it. */
	readonly userId?: string;
	/** The token's scopes. Named `abilities` for the upstream surface. */
	readonly abilities: string[];
	/**
	 * A recognisable name, as upstream carries one.
	 *
	 * An OAuth token is not named by the user who holds it — it is named by the
	 * client it was issued to — so this is the client's name when the store
	 * knows it, and null otherwise.
	 */
	readonly name: string | null;
	readonly expiresAt: Date | null;
	readonly lastUsedAt: Date | null;

	constructor(attributes: {
		clientId: string;
		userId?: string;
		abilities: string[];
		name?: string | null;
		expiresAt?: Date | null;
		lastUsedAt?: Date | null;
	}) {
		this.clientId = attributes.clientId;
		if (attributes.userId !== undefined) this.userId = attributes.userId;
		this.abilities = [...attributes.abilities];
		this.name = attributes.name ?? null;
		this.expiresAt = attributes.expiresAt ?? null;
		this.lastUsedAt = attributes.lastUsedAt ?? null;
	}

	/** `*` means every ability — upstream's rule, read off its build. */
	allows(ability: string): boolean {
		return this.abilities.includes(ability) || this.abilities.includes("*");
	}

	denies(ability: string): boolean {
		return !this.allows(ability);
	}

	/**
	 * Throw unless the token carries `ability`.
	 *
	 * The upstream error id verbatim, so a handler that already maps
	 * `E_UNAUTHORIZED_ACCESS` keeps working.
	 */
	authorize(ability: string): void {
		if (this.allows(ability)) return;
		const error = new Error(
			`Access denied: the token does not carry "${ability}"`,
		) as Error & { code: string; status: number };
		error.code = "E_UNAUTHORIZED_ACCESS";
		error.status = 403;
		throw error;
	}

	/** A token with no expiry never expires. */
	isExpired(): boolean {
		if (this.expiresAt === null) return false;
		return this.expiresAt.getTime() <= Date.now();
	}

	/** Upstream's keys, plus the client an OAuth token always belongs to. */
	toJSON(): {
		type: "bearer";
		name: string | null;
		clientId: string;
		abilities: string[];
		lastUsedAt: Date | null;
		expiresAt: Date | null;
	} {
		return {
			type: "bearer",
			name: this.name,
			clientId: this.clientId,
			abilities: this.abilities,
			lastUsedAt: this.lastUsedAt,
			expiresAt: this.expiresAt,
		};
	}
}

export interface VisaGuardConfig {
	/**
	 * Where the tokens live. A function, so the guard can be built in
	 * `config/auth.ts` before the provider has seated the manager — config is
	 * read at boot, and the store exists a moment later.
	 */
	store: GuardStore | (() => GuardStore);
	/**
	 * The application's user provider — upstream's `tokensUserProvider({ model })`.
	 *
	 * Called on every authenticated request, deliberately: a token issued to an
	 * account that has since been disabled must stop working, and the only way
	 * to know is to ask. Answer `null` and the request is refused.
	 */
	findUser: (userId: string) => Promise<GuardUser | null>;
	/**
	 * What a `client_credentials` token authenticates as, when anything.
	 *
	 * There is no user behind that grant, so by default such a token does not
	 * authenticate a user at all and the guard refuses. An application that
	 * serves machine callers supplies this and gets a subject of its choosing.
	 */
	findClientSubject?: (clientId: string) => Promise<GuardUser | null>;
	/** Guard name, for `auth.use(name)`. Defaults to `visa`. */
	name?: string;
}

/**
 * A guard, in the shape warden's config expects.
 *
 * Shared per application, so it holds no per-request state — the same rule
 * warden states for its own strategies.
 */
export class VisaGuard {
	readonly name: string;
	readonly #config: VisaGuardConfig;

	constructor(config: VisaGuardConfig) {
		this.#config = config;
		this.name = config.name ?? "visa";
	}

	#store(): GuardStore {
		const store = this.#config.store;
		return typeof store === "function" ? store() : store;
	}

	/**
	 * There is no password flow here, and OAuth 2.1 removed the one there used
	 * to be. A token comes from the token endpoint.
	 *
	 * THROWS rather than answering "not authenticated", which is what warden's
	 * own access-tokens guard does: a bearer guard handed an email and a
	 * password is a misconfigured application, not a bad credential, and the two
	 * must not produce the same 401.
	 */
	async authenticate(): Promise<GuardResult> {
		throw new Error(
			"visa authenticates a bearer token, not credentials. Use verify() with the access token.",
		);
	}

	/**
	 * The header a test client sends to present `token`.
	 *
	 * NAMED DEVIATION — upstream takes the USER and mints a token for them.
	 * Here it takes the token, for the reason warden states for its own
	 * access-token guard: the credential is issued out of band. In OAuth that
	 * is not a detail, it is the point — a token exists because a client asked
	 * and a user consented, and a guard that could mint one for any user would
	 * be a second issuer with neither of those checks.
	 */
	authenticateAsClient(token: string): GuardClientResponse {
		return { headers: { authorization: `Bearer ${token}` } };
	}

	async verify(presented: string): Promise<GuardResult> {
		const store = this.#store();
		const now = new Date();
		const verified = await verifyAccessToken(presented, store, now);
		if (verified === null) {
			return { authenticated: false, error: "Invalid or expired access token" };
		}

		const subject =
			verified.userId === undefined
				? await this.#config.findClientSubject?.(verified.clientId)
				: await this.#config.findUser(verified.userId);

		if (subject === null || subject === undefined) {
			// The account is gone or disabled since the token was minted. Refusing
			// here is the point of asking on every request.
			return {
				authenticated: false,
				error:
					verified.userId === undefined
						? "This token authenticates no user"
						: "The account behind this token is no longer available",
			};
		}

		// The PREVIOUS use is what the token reports, and this one is recorded
		// after — the same order upstream reads its row in.
		await touch(store, presented, now);

		const token = new VisaAccessToken({
			clientId: verified.clientId,
			...(verified.userId === undefined ? {} : { userId: verified.userId }),
			abilities: verified.scopes,
			expiresAt: verified.expiresAt ?? null,
			lastUsedAt: verified.lastUsedAt ?? null,
		});

		// A copy: the provider's object is the application's, and a guard that
		// mutated it would leak one request's token into the next.
		const user: GuardUser = { ...subject, currentAccessToken: token };
		if (verified.scopes.length > 0) {
			// Scopes surface on `permissions` as well, the way warden's access-token
			// guard does it, so `ctx.auth.user.permissions` reads the same whichever
			// guard authenticated.
			//
			// They remain a SEPARATE axis from the route-level rights gate, exactly
			// as upstream: a token ability is checked with
			// `currentAccessToken.allows(...)`, and Bouncer does not consult it.
			user.permissions = [
				...new Set([...(subject.permissions ?? []), ...verified.scopes]),
			];
		}
		return { authenticated: true, user };
	}
}

/**
 * Record that the token was just used.
 *
 * Never fatal: a store with no `touchAccessToken` — the contract shipped
 * without one — still authenticates, it simply reports no last use.
 */
async function touch(
	store: GuardStore,
	presented: string,
	now: Date,
): Promise<void> {
	if (store.touchAccessToken === undefined) return;
	try {
		await store.touchAccessToken(hashSecret(presented), now);
	} catch {
		// Recording the use is bookkeeping; failing it must not refuse a request
		// whose token is valid.
	}
}

/** Build a visa guard from its config — `visaGuard({...})` in `config/auth.ts`. */
export function visaGuard(config: VisaGuardConfig): VisaGuard {
	return new VisaGuard(config);
}
