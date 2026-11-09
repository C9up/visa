import { beforeEach, describe, expect, it } from "vitest";
import { MemoryStore } from "../../src/stores/memory.js";
import type { AuthorizationCode } from "../../src/types.js";
import { type ConsentTicket, VisaManager } from "../../src/VisaManager.js";
import { pkce } from "./helpers.js";

/**
 * The consent page and the POST that answers it.
 *
 * What is granted must be what the user was shown. Re-reading the request
 * from the POST lets anything that can shape that POST — another tab, a
 * cross-site form if CSRF slipped — change the client, the scopes or the
 * redirect behind the user's "yes". The ticket keeps the request server-side,
 * names the page it belongs to, and is bound to the user who was asked.
 */

const ISSUER = "https://auth.example";
const REDIRECT = "https://app.example/cb";

/** Counts codes, so a test can say none was minted. */
class CountingStore extends MemoryStore {
	codes = 0;
	override async saveAuthorizationCode(code: AuthorizationCode): Promise<void> {
		this.codes += 1;
		await super.saveAuthorizationCode(code);
	}
}

describe("visa > consent tickets", () => {
	let store: CountingStore;
	let visa: VisaManager;

	beforeEach(async () => {
		store = new CountingStore();
		visa = new VisaManager({ issuer: ISSUER, store });
		await visa.registerClient({
			id: "app",
			name: "App",
			redirectUris: [REDIRECT],
			scopes: ["profile", "email"],
		});
	});

	async function consentPage(
		userId = "user-7",
		scope: string | undefined = "profile",
	): Promise<ConsentTicket> {
		const outcome = await visa.authorize(
			{
				response_type: "code",
				client_id: "app",
				redirect_uri: REDIRECT,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
				state: "s-1",
				...(scope === undefined ? {} : { scope }),
			},
			userId,
		);
		if (outcome.type !== "consent") throw new Error(outcome.type);
		return visa.consentTicket(outcome.request, userId);
	}

	it("gives back the request the user was shown, and mints nothing", async () => {
		const ticket = await consentPage();

		const validated = await visa.redeemConsentTicket(
			ticket,
			ticket.id,
			"user-7",
		);

		expect(validated?.client.id).toBe("app");
		expect(validated?.scopes).toEqual(["profile"]);
		expect(validated?.state).toBe("s-1");
		expect(validated?.redirectUri).toBe(REDIRECT);
		// The code is `grant`'s to mint, once the user said yes — not a side
		// effect of reading the answer.
		expect(store.codes).toBe(0);
	});

	it("survives a session store's JSON round trip", async () => {
		const ticket = await consentPage();
		const stored: unknown = JSON.parse(JSON.stringify(ticket));

		const validated = await visa.redeemConsentTicket(
			stored,
			ticket.id,
			"user-7",
		);

		expect(validated?.scopes).toEqual(["profile"]);
	});

	it("is answered only by the user who was asked", async () => {
		const ticket = await consentPage("user-7");

		expect(
			await visa.redeemConsentTicket(ticket, ticket.id, "user-8"),
		).toBeNull();
	});

	it("refuses a form rendered for another consent page", async () => {
		// Two tabs: the session now holds the second page's ticket, and the
		// first page's form must not approve what the second one asks.
		const first = await consentPage("user-7", "profile");
		const second = await consentPage("user-7", "profile email");

		expect(
			await visa.redeemConsentTicket(second, first.id, "user-7"),
		).toBeNull();
		expect(
			await visa.redeemConsentTicket(second, undefined, "user-7"),
		).toBeNull();
	});

	it("refuses an answer that comes too late", async () => {
		const ticket = await consentPage();

		expect(
			await visa.redeemConsentTicket(
				ticket,
				ticket.id,
				"user-7",
				new Date(ticket.expiresAt),
			),
		).toBeNull();
	});

	it("refuses a ticket whose request no longer validates", async () => {
		const ticket = await consentPage();
		const tampered: ConsentTicket = {
			...ticket,
			request: { ...ticket.request, scope: "admin" },
		};
		const elsewhere: ConsentTicket = {
			...ticket,
			request: { ...ticket.request, redirect_uri: "https://evil.example/cb" },
		};

		expect(
			await visa.redeemConsentTicket(tampered, ticket.id, "user-7"),
		).toBeNull();
		expect(
			await visa.redeemConsentTicket(elsewhere, ticket.id, "user-7"),
		).toBeNull();
	});

	it("refuses to grant scopes the client gained after the page was shown", async () => {
		// A client registered with no scope: the page asked for nothing. If it
		// registers more meanwhile, an empty `scope` would resolve to them.
		await visa.registerClient({
			id: "bare",
			name: "Bare",
			redirectUris: [REDIRECT],
			scopes: [],
		});
		const outcome = await visa.authorize(
			{
				response_type: "code",
				client_id: "bare",
				redirect_uri: REDIRECT,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
			},
			"user-7",
		);
		if (outcome.type !== "consent") throw new Error(outcome.type);
		const ticket = visa.consentTicket(outcome.request, "user-7");
		await store.saveClient({
			id: "bare",
			name: "Bare",
			redirectUris: [REDIRECT],
			grantTypes: ["authorization_code", "refresh_token"],
			scopes: ["admin"],
			tokenEndpointAuthMethod: "none",
		});

		expect(
			await visa.redeemConsentTicket(ticket, ticket.id, "user-7"),
		).toBeNull();
	});

	it("refuses anything a session could hand back that is not a ticket", async () => {
		const ticket = await consentPage();
		for (const value of [
			undefined,
			null,
			"ticket",
			{ ...ticket, userId: 7 },
			{ ...ticket, expiresAt: "tomorrow" },
			{ ...ticket, request: { ...ticket.request, resource: "https://x" } },
			{ ...ticket, request: { ...ticket.request, scope: ["profile"] } },
		]) {
			expect(
				await visa.redeemConsentTicket(value, ticket.id, "user-7"),
			).toBeNull();
		}
	});

	it("carries the resources the user was asked about", async () => {
		const outcome = await visa.authorize(
			{
				response_type: "code",
				client_id: "app",
				redirect_uri: REDIRECT,
				code_challenge: pkce().challenge,
				code_challenge_method: "S256",
				scope: "profile",
				resource: ["https://calendar.example/api", "https://files.example/api"],
			},
			"user-7",
		);
		if (outcome.type !== "consent") throw new Error(outcome.type);
		const ticket = visa.consentTicket(outcome.request, "user-7");

		const validated = await visa.redeemConsentTicket(
			ticket,
			ticket.id,
			"user-7",
		);

		expect(validated?.resources).toEqual([
			"https://calendar.example/api",
			"https://files.example/api",
		]);
	});
});
