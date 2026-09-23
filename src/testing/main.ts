/**
 * Test helpers — `import { testVisa } from '@c9up/visa/testing'`.
 *
 * Not a fake of the server: the real one, on a memory store. An authorization
 * server whose test double is lenient teaches applications to ship the leniency
 * — a consent screen tested against a stub that always grants is a consent
 * screen nobody has ever seen refuse.
 *
 * What it removes is the setup, not the rules: a registered client, a PKCE
 * pair, and one call that walks authorize → consent → code → token.
 */

import { randomToken, sha256 } from "../crypto.js";
import { MemoryStore } from "../stores/memory.js";
import type { Client, GrantType, TokenResponse } from "../types.js";
import { type VisaConfig, VisaManager } from "../VisaManager.js";

export interface TestVisa {
	visa: VisaManager;
	store: MemoryStore;
	/** The client that was registered for you. */
	client: Client;
	/** Its secret, in the clear — it exists only in this process. */
	secret: string;
	/** Credentials shaped the way the endpoints take them. */
	credentials: { clientId: string; clientSecret?: string };
	/** A fresh PKCE pair. */
	pkce(): { verifier: string; challenge: string };
	/**
	 * Everything at once: authorize as `userId`, consent, exchange the code.
	 * What a test protecting a resource needs, without the four steps.
	 */
	tokensFor(userId: string, scope?: string): Promise<TokenResponse>;
}

export interface TestVisaOptions {
	issuer?: string;
	clientId?: string;
	redirectUri?: string;
	scopes?: string[];
	grantTypes?: GrantType[];
	/** A public client: no secret, and no client_credentials. */
	publicClient?: boolean;
	config?: Partial<Omit<VisaConfig, "issuer" | "store">>;
}

export async function testVisa(
	options: TestVisaOptions = {},
): Promise<TestVisa> {
	const redirectUri = options.redirectUri ?? "https://app.test/callback";
	const store = new MemoryStore();
	const visa = new VisaManager({
		issuer: options.issuer ?? "https://auth.test",
		store,
		...options.config,
	});
	const { client, secret } = await visa.registerClient({
		id: options.clientId ?? "test-client",
		name: "Test client",
		redirectUris: [redirectUri],
		scopes: options.scopes ?? ["profile", "email"],
		grantTypes: options.grantTypes ?? ["authorization_code", "refresh_token"],
		...(options.publicClient === true
			? { tokenEndpointAuthMethod: "none" as const }
			: {}),
	});

	const credentials =
		secret === undefined
			? { clientId: client.id }
			: { clientId: client.id, clientSecret: secret };

	return {
		visa,
		store,
		client,
		secret: secret ?? "",
		credentials,
		pkce() {
			const verifier = randomToken();
			return { verifier, challenge: sha256(verifier) };
		},
		async tokensFor(userId: string, scope?: string): Promise<TokenResponse> {
			const verifier = randomToken();
			const outcome = await visa.authorize(
				{
					response_type: "code",
					client_id: client.id,
					redirect_uri: redirectUri,
					code_challenge: sha256(verifier),
					code_challenge_method: "S256",
					...(scope === undefined ? {} : { scope }),
				},
				userId,
			);
			// The real path, consent screen included — a helper that skipped it
			// would let an application forget the screen and still pass.
			const url =
				outcome.type === "consent"
					? await visa.grant(outcome.request, userId)
					: outcome.type === "redirect"
						? outcome.url
						: (() => {
								throw new Error(`authorize failed: ${outcome.error.message}`);
							})();
			const code = new URL(url).searchParams.get("code");
			if (code === null) throw new Error(`no code in ${url}`);
			return visa.token(
				{
					grant_type: "authorization_code",
					code,
					redirect_uri: redirectUri,
					code_verifier: verifier,
				},
				credentials,
			);
		},
	};
}
