/**
 * The HTTP binding.
 *
 * What is under test is the part the spec is specific about and that is easy
 * to get subtly wrong: the status codes, the `WWW-Authenticate` on a 401, the
 * `no-store` on anything carrying a credential, and the fact that `/authorize`
 * is deliberately NOT mounted.
 */

import { describe, expect, it } from "vitest";
import { MemoryStore } from "../../src/stores/memory.js";
import { VisaManager } from "../../src/VisaManager.js";
import type { VisaAppContext } from "../../src/VisaProvider.js";
import VisaProvider from "../../src/VisaProvider.js";
import { ISSUER, REDIRECT } from "./helpers.js";

interface Recorded {
	status?: number;
	headers: Record<string, string>;
	body?: unknown;
}

function fakeContext(body: Record<string, unknown>, authorization?: string) {
	const recorded: Recorded = { headers: {} };
	const ctx = {
		request: {
			header: (name: string) =>
				name.toLowerCase() === "authorization" ? authorization : undefined,
			all: () => body,
		},
		response: {
			status(code: number) {
				recorded.status = code;
				return this;
			},
			header(name: string, value: string) {
				recorded.headers[name.toLowerCase()] = value;
				return this;
			},
			send(payload: unknown) {
				recorded.body = payload;
				return this;
			},
		},
	};
	return { ctx, recorded };
}

function buildApp(store: MemoryStore): {
	app: VisaAppContext;
	routes: Map<string, (ctx: unknown) => Promise<void>>;
} {
	const routes = new Map<string, (ctx: unknown) => Promise<void>>();
	const bindings = new Map<unknown, () => unknown>();
	const cache = new Map<unknown, unknown>();
	const router = {
		post(path: string, handler: (ctx: unknown) => Promise<void>) {
			routes.set(`POST ${path}`, handler);
		},
		get(path: string, handler: (ctx: unknown) => Promise<void>) {
			routes.set(`GET ${path}`, handler);
		},
	};
	cache.set("router", router);
	return {
		routes,
		app: {
			container: {
				singleton(token, factory) {
					bindings.set(token, factory as () => unknown);
				},
				async resolve<T>(token: unknown): Promise<T> {
					if (cache.has(token)) return cache.get(token) as T;
					const factory = bindings.get(token);
					if (!factory) throw new Error(`not registered: ${String(token)}`);
					const value = factory();
					cache.set(token, value);
					return value as T;
				},
				has: (token: unknown) => cache.has(token) || bindings.has(token),
			},
			config: {
				get<T>(key: string): T | undefined {
					return key === "visa" ? ({ issuer: ISSUER, store } as T) : undefined;
				},
			},
		},
	};
}

async function started(store: MemoryStore) {
	const { app, routes } = buildApp(store);
	const provider = new VisaProvider(app);
	provider.register();
	await provider.boot();
	await provider.start();
	const manager = await app.container.resolve<VisaManager>(VisaManager);
	return { routes, manager, provider };
}

describe("visa > provider", () => {
	it("mounts the machine endpoints and NOT /authorize", async () => {
		// /authorize needs a signed-in user and a consent screen, which belong
		// to the application. Guessing either is worse than not mounting it.
		const { routes } = await started(new MemoryStore());
		expect([...routes.keys()].sort()).toEqual([
			"GET /.well-known/oauth-authorization-server",
			"POST /oauth/introspect",
			"POST /oauth/revoke",
			"POST /oauth/token",
		]);
	});

	it("answers a bad client with 401 and says how to authenticate", async () => {
		const { routes } = await started(new MemoryStore());
		const handler = routes.get("POST /oauth/token");
		if (!handler) throw new Error("no token route");
		const { ctx, recorded } = fakeContext({
			grant_type: "client_credentials",
			client_id: "ghost",
			client_secret: "nope",
		});

		await handler(ctx);

		expect(recorded.status).toBe(401);
		expect(recorded.headers["www-authenticate"]).toBe('Basic realm="oauth"');
		expect(recorded.body).toEqual({
			error: "invalid_client",
			error_description: "Client authentication failed.",
		});
	});

	it("forbids caching anything that carries a credential", async () => {
		// RFC 6749 §5.1: a shared cache would hand a token to the next caller.
		const store = new MemoryStore();
		const { routes, manager } = await started(store);
		const { secret } = await manager.registerClient({
			id: "svc",
			name: "Service",
			redirectUris: [REDIRECT],
			scopes: ["reports"],
			grantTypes: ["client_credentials"],
		});
		const handler = routes.get("POST /oauth/token");
		if (!handler) throw new Error("no token route");
		const { ctx, recorded } = fakeContext({
			grant_type: "client_credentials",
			client_id: "svc",
			client_secret: secret,
		});

		await handler(ctx);

		expect(recorded.headers["cache-control"]).toBe("no-store");
		expect(recorded.body).toMatchObject({ token_type: "Bearer" });
	});

	it("publishes what a client needs to discover it", async () => {
		const { routes, manager } = await started(new MemoryStore());
		const handler = routes.get("GET /.well-known/oauth-authorization-server");
		if (!handler) throw new Error("no metadata route");
		const { ctx, recorded } = fakeContext({});

		await handler(ctx);

		expect(recorded.body).toMatchObject({
			issuer: manager.issuer,
			response_types_supported: ["code"],
			// S256 only: `plain` is off unless the application turned it on.
			code_challenge_methods_supported: ["S256"],
		});
	});

	it("refuses to boot without a config rather than inventing one", async () => {
		const { app } = buildApp(new MemoryStore());
		const blind: VisaAppContext = {
			container: app.container,
			config: { get: () => undefined },
		};
		const provider = new VisaProvider(blind);
		provider.register();
		await expect(provider.boot()).rejects.toThrow(/config\/visa\.ts/);
	});

	it("serves no endpoint on a host with no router", async () => {
		const { app } = buildApp(new MemoryStore());
		const headless: VisaAppContext = {
			container: {
				...app.container,
				has: (token: unknown) => token !== "router" && app.container.has(token),
			},
			config: app.config,
		};
		const provider = new VisaProvider(headless);
		provider.register();
		await provider.boot();
		await expect(provider.start()).resolves.toBeUndefined();
	});
});
