/**
 * The authorization endpoint.
 *
 * It is the half a human sees, and the half where an error must NOT be
 * redirected: if the redirect URI is missing, unregistered or malformed, the
 * server tells the user and stops (§4.1.2.1). Bouncing the error to an
 * unverified URI is how an attacker learns that a client exists and gets a
 * page of their choosing loaded in the user's session.
 */

import {
	assertGrantAllowed,
	redirectUriMatches,
	resolveScopes,
} from "./clients.js";
import { hashSecret, randomToken } from "./crypto.js";
import { E_VISA_OAUTH_ERROR, E_VISA_UNREDIRECTABLE } from "./errors.js";
import { readResourceParameter, validateResources } from "./resource.js";
import type { VisaStore } from "./store.js";
import { assertTtlSeconds } from "./ttl.js";
import type { AuthorizationCode, Client } from "./types.js";

/** The query as it arrived, untrusted. */
export interface AuthorizationRequest {
	response_type?: string;
	client_id?: string;
	redirect_uri?: string;
	scope?: string;
	state?: string;
	code_challenge?: string;
	code_challenge_method?: string;
	nonce?: string;
	/** A client may ask to always see the consent screen. */
	prompt?: string;
	/**
	 * Which resource the token is for (RFC 8707). One, or several.
	 *
	 * A parser hands repeated parameters over as an array, so both shapes are
	 * accepted rather than one being silently the only one that works.
	 */
	resource?: string | string[];
}

/**
 * An authorization request as a query parser hands it over.
 *
 * Every field may hold anything: `scope=a&scope=b` and `scope[]=a` arrive as
 * an array, `scope[x]=1` as an object. {@link validateAuthorizationRequest}
 * narrows each one before it is used, so a repeated or bracketed parameter is
 * an `invalid_request` rather than a TypeError and a 500.
 */
export type UntrustedAuthorizationRequest = {
	readonly [K in keyof AuthorizationRequest]?: unknown;
};

/** A request that passed every check, with the values it resolved to. */
export interface ValidatedRequest {
	client: Client;
	redirectUri: string;
	/** Whether the request named `redirect_uri` itself (RFC 6749 §4.1.3). */
	redirectUriProvided: boolean;
	scopes: string[];
	state: string | undefined;
	codeChallenge: string;
	codeChallengeMethod: "S256" | "plain";
	nonce: string | undefined;
	/** The resources the token will be bound to (RFC 8707). Empty means unbound. */
	resources: string[];
}

export interface AuthorizeOptions {
	/** Lifetime of the code. Short on purpose — see `issueAuthorizationCode`. */
	codeTtlSeconds?: number;
	/**
	 * The resources this server will issue tokens for (RFC 8707).
	 *
	 * Left out, any well-formed resource is accepted and carried — which is
	 * useful while a deployment finds its names, and worth replacing with the
	 * list once it has: an unknown resource should be refused with
	 * `invalid_target` rather than minted for.
	 */
	resourcesSupported?: readonly string[];
	/**
	 * Accept `plain` as a code challenge method.
	 *
	 * NAMED DEVIATION — the spec allows `plain`; this refuses it by default.
	 * `plain` puts the verifier in the authorization request, so anything that
	 * can read that request (a log, a referrer, a proxy) can complete the
	 * exchange, which is precisely what PKCE exists to stop. Every client that
	 * can hash can use S256.
	 */
	allowPlainChallenge?: boolean;
}

/**
 * Check an authorization request. Throws `E_VISA_UNREDIRECTABLE` when the error
 * must not be bounced back, `E_VISA_OAUTH_ERROR` when it may.
 */
export async function validateAuthorizationRequest(
	request: UntrustedAuthorizationRequest,
	store: VisaStore,
	options: AuthorizeOptions = {},
): Promise<ValidatedRequest> {
	// Order matters: everything that decides WHERE an error may go has to be
	// settled before any error is produced. A repeated `client_id` or
	// `redirect_uri` is one of those, so it is shown, never redirected.
	const clientId = singleValue(request, "client_id", unredirectable);
	if (clientId === undefined || clientId === "") {
		throw new E_VISA_UNREDIRECTABLE(
			new E_VISA_OAUTH_ERROR("invalid_request", "client_id is required."),
		);
	}
	const requestedRedirectUri = singleValue(
		request,
		"redirect_uri",
		unredirectable,
	);
	const client = await store.findClient(clientId);
	if (client === null) {
		throw new E_VISA_UNREDIRECTABLE(
			new E_VISA_OAUTH_ERROR("invalid_request", "Unknown client."),
		);
	}

	const redirectUri = resolveRedirectUri(requestedRedirectUri, client);

	// From here the redirect URI is verified, so an error may travel back.
	const responseType = singleValue(request, "response_type", redirectable);
	const scope = singleValue(request, "scope", redirectable);
	const state = singleValue(request, "state", redirectable);
	const nonce = singleValue(request, "nonce", redirectable);
	singleValue(request, "prompt", redirectable);
	const challenge = singleValue(request, "code_challenge", redirectable);
	const challengeMethod = singleValue(
		request,
		"code_challenge_method",
		redirectable,
	);
	if (responseType !== "code") {
		throw new E_VISA_OAUTH_ERROR(
			responseType === undefined
				? "invalid_request"
				: "unsupported_response_type",
			// The implicit grant is gone in 2.1, and `token` is its response
			// type — saying so beats a blank refusal for whoever is porting.
			responseType === "token"
				? "The implicit grant is not supported; use response_type=code."
				: "Only response_type=code is supported.",
		);
	}

	assertGrantAllowed(client, "authorization_code");

	const { codeChallenge, codeChallengeMethod } = readChallenge(
		challenge,
		challengeMethod,
		options,
	);
	const scopes = resolveScopes(scope, client);
	const resources = validateResources(
		readResourceParameter(resourceValue(request.resource)),
		options.resourcesSupported,
	);

	return {
		client,
		redirectUri,
		redirectUriProvided:
			requestedRedirectUri !== undefined && requestedRedirectUri !== "",
		scopes,
		state,
		codeChallenge,
		codeChallengeMethod,
		nonce,
		resources,
	};
}

/** How a malformed parameter is refused: shown to the user, or redirected. */
type Refusal = (error: E_VISA_OAUTH_ERROR) => Error;

const unredirectable: Refusal = (error) => new E_VISA_UNREDIRECTABLE(error);
const redirectable: Refusal = (error) => error;

/**
 * One parameter, which must be a single string when present.
 *
 * RFC 6749 §3.1: "Request and response parameters MUST NOT be included more
 * than once." A parser hands a repeated parameter over as an array, and a
 * bracketed one (`scope[x]=1`) as an object; either is an `invalid_request`.
 */
function singleValue(
	request: UntrustedAuthorizationRequest,
	key: Exclude<keyof AuthorizationRequest, "resource">,
	refuse: Refusal,
): string | undefined {
	const value = request[key];
	if (value === undefined || typeof value === "string") return value;
	throw refuse(
		new E_VISA_OAUTH_ERROR(
			"invalid_request",
			`${key} must be given once, as a string.`,
		),
	);
}

/**
 * `resource` is the one parameter RFC 8707 §2 lets a request repeat — one or
 * several, each a string. Anything else (an object, a nested array, a number)
 * is not a resource indicator, and is refused rather than dropped: a token
 * left unbound because its `resource` was unreadable is a token for
 * everything.
 */
function resourceValue(value: unknown): string | string[] | undefined {
	if (value === undefined || typeof value === "string") return value;
	if (Array.isArray(value)) {
		const strings = value.filter(
			(entry): entry is string => typeof entry === "string",
		);
		if (strings.length === value.length) return strings;
	}
	throw new E_VISA_OAUTH_ERROR(
		"invalid_request",
		"resource must be one or several strings.",
	);
}

/**
 * Which redirect URI this request lands on.
 *
 * Omitting it is allowed only when the client registered exactly one — with
 * two or more, "the first one" would be a choice the server makes on the
 * client's behalf, and the wrong choice sends the code elsewhere.
 */
function resolveRedirectUri(
	requested: string | undefined,
	client: Client,
): string {
	if (client.redirectUris.length === 0) {
		throw new E_VISA_UNREDIRECTABLE(
			new E_VISA_OAUTH_ERROR(
				"invalid_request",
				"This client has no redirect URI.",
			),
		);
	}
	if (requested === undefined || requested === "") {
		const only = client.redirectUris[0];
		if (client.redirectUris.length > 1 || only === undefined) {
			throw new E_VISA_UNREDIRECTABLE(
				new E_VISA_OAUTH_ERROR(
					"invalid_request",
					"redirect_uri is required when a client registers more than one.",
				),
			);
		}
		return only;
	}
	if (!redirectUriMatches(requested, client.redirectUris)) {
		throw new E_VISA_UNREDIRECTABLE(
			new E_VISA_OAUTH_ERROR(
				"invalid_request",
				"redirect_uri is not registered.",
			),
		);
	}
	return requested;
}

/**
 * The one shape RFC 7636 allows for both a verifier (§4.1) and a challenge
 * (§4.2): 43 to 128 characters of the unreserved set.
 *
 * Checked on both sides, because with `plain` the challenge IS the verifier:
 * a short one is a verifier anyone can guess, and the interception protection
 * PKCE exists for is gone. An S256 challenge is 43 base64url characters, which
 * this admits.
 */
const PKCE_VALUE = /^[A-Za-z0-9._~-]{43,128}$/;

export function isPkceValue(value: string): boolean {
	return PKCE_VALUE.test(value);
}

function readChallenge(
	challenge: string | undefined,
	challengeMethod: string | undefined,
	options: AuthorizeOptions,
): { codeChallenge: string; codeChallengeMethod: "S256" | "plain" } {
	if (challenge === undefined || challenge === "") {
		// Mandatory in 2.1 for every client, confidential ones included.
		throw new E_VISA_OAUTH_ERROR(
			"invalid_request",
			"code_challenge is required.",
		);
	}
	if (!isPkceValue(challenge)) {
		throw new E_VISA_OAUTH_ERROR(
			"invalid_request",
			"code_challenge must be 43 to 128 unreserved characters (RFC 7636 §4.2).",
		);
	}
	const method = challengeMethod ?? "plain";
	if (method === "S256")
		return { codeChallenge: challenge, codeChallengeMethod: "S256" };
	if (method === "plain" && options.allowPlainChallenge === true) {
		return { codeChallenge: challenge, codeChallengeMethod: "plain" };
	}
	throw new E_VISA_OAUTH_ERROR(
		"invalid_request",
		"code_challenge_method must be S256.",
	);
}

/**
 * Mint the code, once the user is known and has consented.
 *
 * Thirty seconds by default. A code is exchanged by a server the client
 * controls, milliseconds after the redirect — a long window buys the client
 * nothing and gives anything that can read a URL (a log, a referrer header, a
 * shoulder) time to use it.
 */
export async function issueAuthorizationCode(
	validated: ValidatedRequest,
	userId: string,
	store: VisaStore,
	options: AuthorizeOptions = {},
	now: Date = new Date(),
): Promise<string> {
	// Checked here too: this function is exported, and `VisaManager`'s boot
	// check does not cover a caller that drives it directly.
	assertTtlSeconds("codeTtlSeconds", options.codeTtlSeconds);
	const code = randomToken();
	const ttl = options.codeTtlSeconds ?? 30;
	const record: AuthorizationCode = {
		codeHash: hashSecret(code),
		clientId: validated.client.id,
		userId,
		redirectUri: validated.redirectUri,
		...(validated.redirectUriProvided ? {} : { redirectUriOmitted: true }),
		scopes: validated.scopes,
		codeChallenge: validated.codeChallenge,
		codeChallengeMethod: validated.codeChallengeMethod,
		expiresAt: new Date(now.getTime() + ttl * 1000),
		...(validated.nonce === undefined ? {} : { nonce: validated.nonce }),
		...(validated.resources.length === 0
			? {}
			: { resources: validated.resources }),
	};
	await store.saveAuthorizationCode(record);
	return code;
}

/**
 * Build the redirect a successful authorization ends on.
 *
 * `issuer` travels as `iss` (RFC 9207 §2): a client that talks to several
 * authorization servers checks it against the one it sent the user to, which
 * is how it catches a code injected from another server (the mix-up attack,
 * RFC 9700 §4.4). Required, not optional: the metadata announces
 * `authorization_response_iss_parameter_supported`, and a client that reads
 * it rejects a response without `iss` (RFC 9207 §2.4).
 */
export function successRedirect(
	validated: ValidatedRequest,
	code: string,
	issuer: string,
): string {
	const url = new URL(validated.redirectUri);
	url.searchParams.set("code", code);
	// Returned verbatim when the client sent one, absent when it did not —
	// inventing a state would break the client's own CSRF check.
	if (validated.state !== undefined)
		url.searchParams.set("state", validated.state);
	url.searchParams.set("iss", issuer);
	return url.toString();
}

/**
 * Build the redirect a refused or failed authorization ends on.
 *
 * It carries `iss` as a success does — RFC 9207 §2 covers error responses
 * too. An options object rather than two trailing strings, so `state` and
 * `issuer` cannot be passed in each other's place.
 */
export function errorRedirect(
	redirectUri: string,
	error: E_VISA_OAUTH_ERROR,
	options: { issuer: string; state?: string | undefined },
): string {
	const url = new URL(redirectUri);
	url.searchParams.set("error", error.oauthCode);
	if (error.description !== undefined) {
		url.searchParams.set("error_description", error.description);
	}
	if (options.state !== undefined) url.searchParams.set("state", options.state);
	url.searchParams.set("iss", options.issuer);
	return url.toString();
}
