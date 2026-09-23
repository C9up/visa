/**
 * What an authorization server stores, and what it hands back.
 *
 * Nothing here is an entity of a particular ORM: the store contract takes and
 * returns these shapes, so the same server runs on atlas, on Redis or on a
 * table someone else owns.
 */

/** How a client proves who it is at the token endpoint. */
export type ClientAuthMethod =
	/** A confidential client with a secret, sent as HTTP Basic (§2.4.1). */
	| "client_secret_basic"
	/** The same secret, in the form body. */
	| "client_secret_post"
	/** A public client — a SPA, a native app — which has no secret to keep. */
	| "none";

export type GrantType =
	| "authorization_code"
	| "refresh_token"
	| "client_credentials";

/**
 * A registered application.
 *
 * `redirectUris` is a list of COMPLETE uris, path included: OAuth 2.1 requires
 * an exact match, because a prefix match is how an open redirect on the
 * client's domain turns into a stolen authorization code.
 */
export interface Client {
	id: string;
	name: string;
	/** Hashed. The plaintext is shown once, at registration, and never stored. */
	secretHash?: string;
	redirectUris: string[];
	grantTypes: GrantType[];
	/** What this client may ever ask for; a request narrows it, never widens it. */
	scopes: string[];
	tokenEndpointAuthMethod: ClientAuthMethod;
	/** Skip the consent screen — for a first-party application you own. */
	trusted?: boolean;
}

/**
 * An authorization code: single use, short lived, bound to everything that
 * was true when it was issued.
 */
export interface AuthorizationCode {
	/** Hashed, like every other credential this package persists. */
	codeHash: string;
	clientId: string;
	userId: string;
	redirectUri: string;
	scopes: string[];
	codeChallenge: string;
	codeChallengeMethod: "S256" | "plain";
	expiresAt: Date;
	/** Set the moment it is exchanged, so a replay is detectable (§7.5.1). */
	consumedAt?: Date;
	/** Carried through to the id_token when OIDC lands. */
	nonce?: string;
}

export interface AccessToken {
	tokenHash: string;
	clientId: string;
	/** Absent for `client_credentials`: there is no user behind it. */
	userId?: string;
	scopes: string[];
	expiresAt: Date;
	revokedAt?: Date;
	/**
	 * The refresh family this token was minted in, when there is one.
	 *
	 * Without it, revoking a leaked family would leave the access token it
	 * already bought alive for its full lifetime — which is most of what the
	 * revocation exists to prevent.
	 */
	familyId?: string;
}

/**
 * A refresh token, and the family it belongs to.
 *
 * `familyId` is what makes replay detection possible: rotation issues a new
 * token in the same family, so presenting an old one proves a leak and the
 * whole family goes (RFC 9700 §4.14.2).
 */
export interface RefreshToken {
	tokenHash: string;
	familyId: string;
	clientId: string;
	userId?: string;
	scopes: string[];
	expiresAt: Date;
	consumedAt?: Date;
	revokedAt?: Date;
}

/** What a user agreed to give a client, so they are asked once. */
export interface Consent {
	userId: string;
	clientId: string;
	scopes: string[];
	grantedAt: Date;
}

/** The token endpoint's success body (§4.1.4). */
export interface TokenResponse {
	access_token: string;
	token_type: "Bearer";
	expires_in: number;
	refresh_token?: string;
	scope?: string;
}

/** The introspection body (RFC 7662 §2.2). */
export interface IntrospectionResponse {
	active: boolean;
	scope?: string;
	client_id?: string;
	username?: string;
	sub?: string;
	exp?: number;
	iat?: number;
	token_type?: "Bearer";
}
