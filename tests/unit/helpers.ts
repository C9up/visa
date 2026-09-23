/**
 * Shared scaffolding. Not a `.test.ts`, so vitest does not run it as a suite.
 */

import { randomToken, sha256 } from "../../src/crypto.js";
import { MemoryStore } from "../../src/stores/memory.js";
import type { Client } from "../../src/types.js";
import { VisaManager } from "../../src/VisaManager.js";

export const ISSUER = "https://auth.example.test";
export const REDIRECT = "https://app.example.test/callback";

export interface Harness {
	visa: VisaManager;
	store: MemoryStore;
	client: Client;
	secret: string;
}

/** A confidential client, registered and ready to exchange codes. */
export async function harness(
	overrides: Partial<Parameters<VisaManager["registerClient"]>[0]> = {},
	config: Partial<ConstructorParameters<typeof VisaManager>[0]> = {},
): Promise<Harness> {
	const store = new MemoryStore();
	const visa = new VisaManager({ issuer: ISSUER, store, ...config });
	const { client, secret } = await visa.registerClient({
		id: "app",
		name: "The App",
		redirectUris: [REDIRECT],
		scopes: ["profile", "email"],
		grantTypes: ["authorization_code", "refresh_token"],
		...overrides,
	});
	return { visa, store, client, secret: secret ?? "" };
}

/** A PKCE pair, the way a real client builds one. */
export function pkce(): { verifier: string; challenge: string } {
	const verifier = randomToken();
	return { verifier, challenge: sha256(verifier) };
}

/** Walk the authorize → consent → code path and hand back the code. */
export async function authorizeToCode(
	h: Harness,
	options: { userId?: string; scope?: string; challenge?: string } = {},
): Promise<string> {
	const challenge = options.challenge ?? pkce().challenge;
	const outcome = await h.visa.authorize(
		{
			response_type: "code",
			client_id: h.client.id,
			redirect_uri: REDIRECT,
			code_challenge: challenge,
			code_challenge_method: "S256",
			state: "xyz",
			...(options.scope === undefined ? {} : { scope: options.scope }),
		},
		options.userId ?? "user-1",
	);
	if (outcome.type === "consent") {
		const url = await h.visa.grant(outcome.request, options.userId ?? "user-1");
		return codeFrom(url);
	}
	if (outcome.type !== "redirect") {
		throw new Error(`expected a redirect, got ${outcome.type}`);
	}
	return codeFrom(outcome.url);
}

export function codeFrom(url: string): string {
	const code = new URL(url).searchParams.get("code");
	if (code === null) throw new Error(`no code in ${url}`);
	return code;
}

/** Credentials the way a confidential client sends them. */
export function basic(h: Harness): { authorization: string } {
	const raw = `${encodeURIComponent(h.client.id)}:${encodeURIComponent(h.secret)}`;
	return { authorization: `Basic ${Buffer.from(raw).toString("base64")}` };
}

/**
 * The same credentials, already parsed.
 *
 * `basic()` is the header a client sends; this is what the endpoints take,
 * and the two are separate so a test can exercise the parsing on purpose.
 */
export function creds(h: Harness): {
	clientId: string;
	clientSecret?: string;
} {
	return h.secret === ""
		? { clientId: h.client.id }
		: { clientId: h.client.id, clientSecret: h.secret };
}
