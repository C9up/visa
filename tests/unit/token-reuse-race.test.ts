/**
 * Reuse detection under concurrency, on every shipped store.
 *
 * RFC 9700 §4.14.2: when a refresh token is used by both the attacker and the
 * legitimate client, one of them presents an invalidated token and the server
 * ends the family. "One of them" includes the one that loses a race, not only
 * one that arrives strictly after — and the pair the winner minted has to die
 * with the family, whatever order the writes land in. RFC 6749 §4.1.2 asks
 * the same of a code used twice.
 */

import { describe, expect, it } from "vitest";
import { randomToken, sha256 } from "../../src/crypto.js";
import type { VisaStore } from "../../src/store.js";
import { AtlasStore } from "../../src/stores/atlas.js";
import { MemoryStore } from "../../src/stores/memory.js";
import type { AccessToken, TokenResponse } from "../../src/types.js";
import { VisaManager } from "../../src/VisaManager.js";
import { FakeDb } from "./fake-atlas.js";

type Point = "save" | "consume" | "consumed";

/**
 * Holds the next store call that reaches the armed point until released —
 * a store on a network, where another request runs during a round trip.
 */
class Gate {
	#armed: Point | undefined;
	#release: (() => void) | undefined;
	#reached: (() => void) | undefined;

	arm(point: Point): Promise<void> {
		this.#armed = point;
		return new Promise<void>((resolve) => {
			this.#reached = resolve;
		});
	}

	release(): void {
		this.#release?.();
	}

	async at(point: Point): Promise<void> {
		if (this.#armed !== point) return;
		this.#armed = undefined;
		const held = new Promise<void>((resolve) => {
			this.#release = resolve;
		});
		this.#reached?.();
		await held;
	}
}

class GatedMemoryStore extends MemoryStore {
	readonly gate = new Gate();

	override async saveAccessToken(token: AccessToken): Promise<void> {
		await this.gate.at("save");
		return super.saveAccessToken(token);
	}

	override async consumeRefreshToken(hash: string, at: Date): Promise<boolean> {
		await this.gate.at("consume");
		const ok = await super.consumeRefreshToken(hash, at);
		await this.gate.at("consumed");
		return ok;
	}

	override async consumeAuthorizationCode(
		hash: string,
		at: Date,
	): Promise<boolean> {
		const ok = await super.consumeAuthorizationCode(hash, at);
		await this.gate.at("consumed");
		return ok;
	}
}

class GatedAtlasStore extends AtlasStore {
	readonly gate = new Gate();

	constructor() {
		super(new FakeDb());
	}

	override async saveAccessToken(token: AccessToken): Promise<void> {
		await this.gate.at("save");
		return super.saveAccessToken(token);
	}

	override async consumeRefreshToken(hash: string, at: Date): Promise<boolean> {
		await this.gate.at("consume");
		const ok = await super.consumeRefreshToken(hash, at);
		await this.gate.at("consumed");
		return ok;
	}

	override async consumeAuthorizationCode(
		hash: string,
		at: Date,
	): Promise<boolean> {
		const ok = await super.consumeAuthorizationCode(hash, at);
		await this.gate.at("consumed");
		return ok;
	}
}

type GatedStore = VisaStore & { readonly gate: Gate };

const REDIRECT = "https://app.test/cb";

async function session(store: GatedStore) {
	const visa = new VisaManager({ issuer: "https://auth.test", store });
	const { client, secret } = await visa.registerClient({
		id: "app",
		name: "App",
		redirectUris: [REDIRECT],
		scopes: ["profile"],
	});
	const credentials = { clientId: client.id, clientSecret: secret ?? "" };
	const issueCode = async (): Promise<{ code: string; verifier: string }> => {
		const verifier = randomToken();
		const outcome = await visa.authorize(
			{
				response_type: "code",
				client_id: client.id,
				redirect_uri: REDIRECT,
				code_challenge: sha256(verifier),
				code_challenge_method: "S256",
			},
			"user-7",
		);
		const url =
			outcome.type === "consent"
				? await visa.grant(outcome.request, "user-7")
				: outcome.type === "redirect"
					? outcome.url
					: "";
		return { code: new URL(url).searchParams.get("code") ?? "", verifier };
	};
	const exchange = (code: string, verifier: string) =>
		visa.token(
			{
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				code_verifier: verifier,
			},
			credentials,
		);
	const refresh = (refreshToken: string | undefined) =>
		visa.token(
			{ grant_type: "refresh_token", refresh_token: refreshToken },
			credentials,
		);
	const { code, verifier } = await issueCode();
	const first = await exchange(code, verifier);
	return { visa, issueCode, exchange, refresh, first };
}

/** Nothing this pair can do any more: no API call, no rotation. */
async function expectDead(
	visa: VisaManager,
	refresh: (token: string | undefined) => Promise<TokenResponse>,
	pair: TokenResponse,
): Promise<void> {
	expect(await visa.verify(pair.access_token)).toBeNull();
	await expect(refresh(pair.refresh_token)).rejects.toMatchObject({
		oauthCode: "invalid_grant",
	});
}

const stores: Array<[string, () => GatedStore]> = [
	["MemoryStore", () => new GatedMemoryStore()],
	["AtlasStore", () => new GatedAtlasStore()],
];

for (const [name, make] of stores) {
	describe(`visa > token > reuse under concurrency (${name})`, () => {
		it("ends the family when one refresh token is presented twice at once", async () => {
			const s = await session(make());
			const stolen = s.first.refresh_token;

			const results = await Promise.allSettled([
				s.refresh(stolen),
				s.refresh(stolen),
			]);

			const won = results.flatMap((r) =>
				r.status === "fulfilled" ? [r.value] : [],
			);
			const lost = results.flatMap((r) =>
				r.status === "rejected" ? [r.reason] : [],
			);
			expect(won).toHaveLength(1);
			expect(lost).toEqual([
				expect.objectContaining({ oauthCode: "invalid_grant" }),
			]);
			// The loser was the breach signal: the winner's pair goes too.
			for (const pair of won) await expectDead(s.visa, s.refresh, pair);
			expect(await s.visa.verify(s.first.access_token)).toBeNull();
		});

		it("ends the family when a late loser's consume comes after the winner returned", async () => {
			const store = make();
			const s = await session(store);
			const stolen = s.first.refresh_token;

			// The thief is held on its first write; the victim rotates meanwhile.
			const held = store.gate.arm("save");
			const thief = s.refresh(stolen);
			await held;
			const victim = await s.refresh(stolen);
			store.gate.release();

			await expect(thief).rejects.toMatchObject({ oauthCode: "invalid_grant" });
			await expectDead(s.visa, s.refresh, victim);
		});

		it("revokes a rotation whose consume won before a replay was detected", async () => {
			const store = make();
			const s = await session(store);
			const stolen = s.first.refresh_token;

			// The thief has spent the token but not returned yet.
			const held = store.gate.arm("consumed");
			const thief = s.refresh(stolen);
			await held;
			await expect(s.refresh(stolen)).rejects.toMatchObject({
				oauthCode: "invalid_grant",
			});
			store.gate.release();

			// Its pair was saved before the consume, so the replay's revocation
			// reached it.
			await expectDead(s.visa, s.refresh, await thief);
		});

		it("stops a rotation when the user ends the authorization mid-flight", async () => {
			const store = make();
			const s = await session(store);

			// Read and saved, not yet consumed: the user disconnects the app.
			const held = store.gate.arm("consume");
			const rotation = s.refresh(s.first.refresh_token);
			await held;
			await s.visa.revokeAuthorization("user-7", "app");
			store.gate.release();

			await expect(rotation).rejects.toMatchObject({
				oauthCode: "invalid_grant",
			});
			// Including the pair the rotation saved before it was stopped.
			const tokens = await store.listAccessTokens("user-7");
			expect(tokens).toHaveLength(2);
			expect(tokens.every((token) => token.revokedAt !== undefined)).toBe(true);
		});

		it("refuses to consume a refresh token that was revoked", async () => {
			const store = make();
			const s = await session(store);
			await s.visa.revokeAuthorization("user-7", "app");

			expect(
				await store.consumeRefreshToken(
					sha256(s.first.refresh_token ?? ""),
					new Date(),
				),
			).toBe(false);
		});

		it("ends what a code bought when it is exchanged twice at once", async () => {
			const s = await session(make());
			const { code, verifier } = await s.issueCode();

			const results = await Promise.allSettled([
				s.exchange(code, verifier),
				s.exchange(code, verifier),
			]);

			const won = results.flatMap((r) =>
				r.status === "fulfilled" ? [r.value] : [],
			);
			expect(won).toHaveLength(1);
			expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
			for (const pair of won) await expectDead(s.visa, s.refresh, pair);
			// Another session of the same user is not touched.
			expect(await s.visa.verify(s.first.access_token)).not.toBeNull();
		});

		it("revokes an exchange whose consume won before the code came back", async () => {
			const store = make();
			const s = await session(store);
			const { code, verifier } = await s.issueCode();

			const held = store.gate.arm("consumed");
			const winner = s.exchange(code, verifier);
			await held;
			await expect(s.exchange(code, verifier)).rejects.toMatchObject({
				oauthCode: "invalid_grant",
			});
			store.gate.release();

			await expectDead(s.visa, s.refresh, await winner);
		});
	});
}
