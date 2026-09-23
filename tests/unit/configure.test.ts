/**
 * `ream configure @c9up/visa`, and the testing helper.
 *
 * The codemod is worth a test because its shape is a CONTRACT with ream's
 * `Codemods`, and a wrong method name there fails at `ream configure` time on
 * someone else's machine — the first time anyone runs it.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { configure } from "../../src/configure.js";
import { testVisa } from "../../src/testing/main.js";

/**
 * Read a stub the way `codemods.makeUsingStub` does.
 *
 * The real file, not a fixture: a test that stubbed this out would pass with
 * a stub that does not exist.
 */
function renderStub(
	stubsRoot: string,
	stubPath: string,
	state: Record<string, string | number | boolean>,
): { to: string; body: string } {
	const raw = readFileSync(resolve(stubsRoot, stubPath), "utf8");
	const [, front = "", body = ""] = raw.split(/^---\r?\n/m, 3);
	const declared = /^to:\s*(.+)$/m.exec(front)?.[1]?.trim() ?? "";
	const render = (text: string): string =>
		text.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (match, key: string) =>
			state[key] === undefined ? match : String(state[key]),
		);
	return { to: render(declared), body: render(body) };
}

function recorder() {
	const calls = {
		providers: [] as string[],
		env: [] as Record<string, string>[],
		files: [] as Array<{ path: string; content: string }>,
	};
	return {
		calls,
		codemods: {
			async addProvider(path: string) {
				calls.providers.push(path);
			},
			async addEnvVars(vars: Record<string, string>) {
				calls.env.push(vars);
			},
			async makeUsingStub(
				stubsRoot: string,
				stubPath: string,
				state: Record<string, string | number | boolean> = {},
			) {
				const { to, body } = renderStub(stubsRoot, stubPath, state);
				await this.writeFile(to, body);
				return { path: to, contents: body };
			},
			async writeFile(path: string, content: string) {
				calls.files.push({ path, content });
			},
		},
	};
}

describe("visa > configure", () => {
	it("registers the provider, declares the env var its config reads, writes the config", async () => {
		const { calls, codemods } = recorder();

		await configure(codemods);

		expect(calls.providers).toEqual(["@c9up/visa/provider"]);
		// The config below reads it; declaring one without the other leaves an
		// application asking the environment for something nothing put there.
		expect(calls.env[0]).toHaveProperty("VISA_ISSUER");
		const file = calls.files[0];
		expect(file?.path).toBe("config/visa.ts");
		expect(file?.content).toContain("defineConfig");
		expect(file?.content).toContain("env.get('VISA_ISSUER')");
	});

	it("says in the config itself that the store has to be replaced", async () => {
		// A memory store shipped to production loses every session on deploy.
		const { calls, codemods } = recorder();
		await configure(codemods);
		expect(calls.files[0]?.content).toContain("REPLACE THIS");
	});
});

describe("visa > testing helper", () => {
	it("hands back a working server and real tokens", async () => {
		const t = await testVisa();
		const tokens = await t.tokensFor("user-7", "profile");

		expect(tokens.scope).toBe("profile");
		const grant = await t.visa.verify(tokens.access_token);
		expect(grant).toEqual({
			clientId: t.client.id,
			userId: "user-7",
			scopes: ["profile"],
			expiresAt: expect.any(Date),
		});
	});

	it("is the real server, not a lenient stand-in", async () => {
		// A helper that granted whatever was asked would teach applications to
		// ship a consent screen nobody has seen refuse.
		const t = await testVisa({ scopes: ["profile"] });
		await expect(t.tokensFor("user-7", "billing")).rejects.toThrowError(
			/invalid_scope|Not registered/,
		);
	});

	it("builds a public client on request, with no secret", async () => {
		const t = await testVisa({ publicClient: true });
		expect(t.secret).toBe("");
		expect(t.credentials.clientSecret).toBeUndefined();
		const tokens = await t.tokensFor("user-7");
		expect(tokens.token_type).toBe("Bearer");
	});
});
