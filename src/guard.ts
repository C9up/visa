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

import { hashSecret, randomToken } from "./crypto.js";
import { verifyAccessToken } from "./introspect.js";
import { wwwAuthenticate } from "./protectedResource.js";
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
	| "findAccessToken"
	| "touchAccessToken"
	| "saveAccessToken"
	| "revokeAccessToken"
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
	/**
	 * The token itself, and only just after it was created.
	 *
	 * Upstream's `value`: the one moment the plaintext exists is when it is
	 * minted, because what is stored is a hash. A token read back from the
	 * store never has it, and that is not a gap — it is why a database copy is
	 * not a set of working tokens.
	 */
	readonly value?: string;

	constructor(attributes: {
		clientId: string;
		userId?: string;
		abilities: string[];
		name?: string | null;
		expiresAt?: Date | null;
		lastUsedAt?: Date | null;
		value?: string;
	}) {
		this.clientId = attributes.clientId;
		if (attributes.userId !== undefined) this.userId = attributes.userId;
		this.abilities = [...attributes.abilities];
		this.name = attributes.name ?? null;
		this.expiresAt = attributes.expiresAt ?? null;
		this.lastUsedAt = attributes.lastUsedAt ?? null;
		if (attributes.value !== undefined) this.value = attributes.value;
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
		token: string | undefined;
		clientId: string;
		abilities: string[];
		lastUsedAt: Date | null;
		expiresAt: Date | null;
	} {
		return {
			type: "bearer",
			name: this.name,
			// Present exactly once, on the token `createToken` just returned —
			// which is the only time a caller can hand it to anybody.
			token: this.value,
			clientId: this.clientId,
			abilities: this.abilities,
			lastUsedAt: this.lastUsedAt,
			expiresAt: this.expiresAt,
		};
	}
}

/** An hour, as the token endpoint uses by default. */
const DEFAULT_TTL = 3600;

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
	/**
	 * The client a token minted by {@link VisaGuard.createToken} belongs to.
	 *
	 * Upstream's guard needs no such thing because it has no clients. Here
	 * every token is issued TO somebody, and one with no client could not be
	 * introspected, revoked by its owner, or listed on a "connected
	 * applications" screen. Name the first-party application and a minted
	 * token is an ordinary token in every other respect.
	 */
	tokenClientId?: string;
	/** How long a minted token lasts — upstream's `expiresIn`, in seconds. */
	expiresInSeconds?: number;
	/**
	 * The protected resource this guard stands in front of (RFC 9728).
	 *
	 * Given, {@link VisaGuard.challenge} returns a `WWW-Authenticate` naming
	 * the metadata document, which is how an MCP client finds the
	 * authorization server without being told where it is.
	 */
	resource?: string;
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
	 * Mint a token for `user`, as upstream's guard does.
	 *
	 * The token is a real one: stored hashed, listed, introspectable,
	 * revocable. What it skips is the authorization code flow, so it is for a
	 * FIRST-PARTY client you own — `tokenClientId` — and nothing here should
	 * ever be handed a third-party client id.
	 */
	async createToken(
		user: { id: string } | string,
		abilities: string[] = ["*"],
		options: { name?: string; expiresInSeconds?: number } = {},
	): Promise<VisaAccessToken> {
		const clientId = this.#config.tokenClientId;
		if (clientId === undefined) {
			throw new Error(
				"[visa] createToken needs `tokenClientId` — a token is always issued to a client. Name the first-party application in visaGuard({ tokenClientId }).",
			);
		}
		const userId = typeof user === "string" ? user : user.id;
		const ttl =
			options.expiresInSeconds ?? this.#config.expiresInSeconds ?? DEFAULT_TTL;
		const secret = randomToken();
		const expiresAt = new Date(Date.now() + ttl * 1000);

		await this.#store().saveAccessToken({
			tokenHash: hashSecret(secret),
			clientId,
			userId,
			scopes: abilities,
			expiresAt,
		});

		return new VisaAccessToken({
			clientId,
			userId,
			abilities,
			name: options.name ?? null,
			expiresAt,
			// The one moment the plaintext exists.
			value: secret,
		});
	}

	/**
	 * Revoke a token — upstream's `invalidateToken`.
	 *
	 * NAMED DEVIATION — upstream's guard is built per request and invalidates
	 * the token it just authenticated with, so it takes no argument. A warden
	 * strategy is shared by the whole application and holds no per-request
	 * state, by warden's own rule, so the token to revoke is passed in. A
	 * sign-out handler has it: it is the bearer credential of the request.
	 *
	 * Answers whether the token was there to revoke.
	 */
	async invalidateToken(presented: string): Promise<boolean> {
		const store = this.#store();
		const hash = hashSecret(presented);
		const existing = await store.findAccessToken(hash);
		if (existing === null || existing.revokedAt !== undefined) return false;
		await store.revokeAccessToken(hash, new Date());
		return true;
	}

	/**
	 * What a test client sends to be `user` — upstream's signature.
	 *
	 * It mints a token, as upstream does, so a test authenticates the way the
	 * application will rather than against a credential the store has never
	 * seen.
	 */
	async authenticateAsClient(
		user: { id: string } | string,
		abilities: string[] = ["*"],
		options: { name?: string; expiresInSeconds?: number } = {},
	): Promise<GuardClientResponse> {
		const token = await this.createToken(user, abilities, options);
		return { headers: { authorization: `Bearer ${token.value}` } };
	}

	/**
	 * The `WWW-Authenticate` value a 401 from this guard should carry.
	 *
	 * Returned rather than set: a warden strategy answers whether a credential
	 * is good, and the response belongs to whoever refuses the request. An
	 * exception handler sets it — `response.header('www-authenticate',
	 * guard.challenge())` — and with it a client that has no token learns
	 * where to get one instead of hitting a dead end.
	 */
	challenge(
		options: { error?: string; scope?: readonly string[] } = {},
	): string {
		return wwwAuthenticate({
			...(this.#config.resource === undefined
				? {}
				: { resource: this.#config.resource }),
			...(options.error === undefined ? {} : { error: options.error }),
			...(options.scope === undefined ? {} : { scope: options.scope }),
		});
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
