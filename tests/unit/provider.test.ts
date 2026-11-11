/**
 * The HTTP binding.
 *
 * What is under test is the part the spec is specific about and that is easy
 * to get subtly wrong: the status codes, the `WWW-Authenticate` on a 401, the
 * `no-store` on anything carrying a credential, and the fact that `/authorize`
 * is deliberately NOT mounted.
 */

import { HttpContext } from "@c9up/ream";
import BodyParserMiddleware from "@c9up/ream/bodyparser_middleware";
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

function fakeContext(
	body: unknown,
	authorization?: string,
	query: Record<string, unknown> = {},
) {
	const recorded: Recorded = { headers: {} };
	const ctx = {
		request: {
			header: (name: string) =>
				name.toLowerCase() === "authorization" ? authorization : undefined,
			body: () => body,
			qs: () => ({ ...query }),
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

/** A real framework context carrying one form-encoded POST to the token endpoint. */
function formContext(body: string): HttpContext {
	return new HttpContext(
		"visa-test",
		{
			method: "POST",
			path: "/oauth/token",
			query: "",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				"content-length": String(Buffer.byteLength(body, "utf8")),
			},
			body,
		},
		{},
		{ pattern: "/oauth/token", middleware: [] },
	);
}

function buildApp(
	store: MemoryStore,
	extra: Record<string, unknown> = {},
): {
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
					return key === "visa"
						? ({ issuer: ISSUER, store, ...extra } as T)
						: undefined;
				},
			},
		},
	};
}

async function started(
	store: MemoryStore,
	extra: Record<string, unknown> = {},
) {
	const { app, routes } = buildApp(store, extra);
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

	it("serves the protected resource metadata once one is declared", async () => {
		// RFC 9728. Without the declaration nothing is mounted: a document
		// announcing a resource nobody declared points clients at thin air.
		const { routes } = await started(new MemoryStore(), {
			protectedResource: {
				resource: "https://api.example/mcp",
				scopesSupported: ["profile"],
			},
		});

		// §3 puts the well-known segment between the host and the path, and a
		// client may ask for either form.
		expect(routes.has("GET /.well-known/oauth-protected-resource")).toBe(true);
		expect(routes.has("GET /.well-known/oauth-protected-resource/mcp")).toBe(
			true,
		);

		const handler = routes.get("GET /.well-known/oauth-protected-resource/mcp");
		if (!handler) throw new Error("no metadata route");
		const { ctx, recorded } = fakeContext({});
		await handler(ctx);

		expect(recorded.body).toEqual({
			resource: "https://api.example/mcp",
			// The issuer this server answers on — what the client goes to next.
			authorization_servers: [ISSUER],
			scopes_supported: ["profile"],
			bearer_methods_supported: ["header"],
		});
	});

	it("mounts registration only when it was turned on, and advertises it", async () => {
		const closed = await started(new MemoryStore());
		expect(closed.routes.has("POST /oauth/register")).toBe(false);

		const { routes } = await started(new MemoryStore(), {
			registration: { enabled: true },
		});
		expect(routes.has("POST /oauth/register")).toBe(true);

		// RFC 8414: a client discovers the endpoint rather than guessing it.
		const metadata = routes.get("GET /.well-known/oauth-authorization-server");
		if (!metadata) throw new Error("no metadata route");
		const { ctx, recorded } = fakeContext({});
		await metadata(ctx);
		expect(recorded.body).toMatchObject({
			registration_endpoint: `${ISSUER}/oauth/register`,
		});
	});

	it("mounts no resource metadata when none was declared", async () => {
		const { routes } = await started(new MemoryStore());
		expect(routes.has("GET /.well-known/oauth-protected-resource")).toBe(false);
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

	describe("parameters come from the body, never the URL", () => {
		// RFC 6749 §2.3.1: client credentials "MUST NOT be included in the
		// request URI". A URL is kept by access logs, proxies and traces where a
		// body is not.
		async function machineClient() {
			const store = new MemoryStore();
			const { routes, manager } = await started(store, {
				registration: { enabled: true },
			});
			const { secret } = await manager.registerClient({
				id: "svc",
				name: "Service",
				redirectUris: [REDIRECT],
				scopes: ["reports"],
				grantTypes: ["client_credentials"],
				tokenEndpointAuthMethod: "client_secret_post",
			});
			const credentials = {
				grant_type: "client_credentials",
				client_id: "svc",
				client_secret: secret ?? "",
			};
			return { routes, credentials };
		}

		function route(
			routes: Map<string, (ctx: unknown) => Promise<void>>,
			key: string,
		) {
			const handler = routes.get(key);
			if (!handler) throw new Error(`no route ${key}`);
			return handler;
		}

		it("issues a token for credentials in the body", async () => {
			const { routes, credentials } = await machineClient();
			const { ctx, recorded } = fakeContext(credentials);

			await route(routes, "POST /oauth/token")(ctx);

			expect(recorded.status).toBeUndefined();
			expect(recorded.body).toMatchObject({ token_type: "Bearer" });
		});

		it("reads a form body through the framework's body parser", async () => {
			// RFC 6749 §3.2: the token request is a POST with an
			// application/x-www-form-urlencoded body. The framework hands the
			// endpoint a parsed body only when its body parser ran, so this is
			// the setup the README documents, run with the real request and
			// middleware rather than a stub of either.
			const { routes, credentials } = await machineClient();
			const ctx = formContext(new URLSearchParams(credentials).toString());

			await new BodyParserMiddleware().handle(ctx, () =>
				route(routes, "POST /oauth/token")(ctx),
			);

			expect(ctx.response.getStatus()).toBe(200);
			expect(JSON.parse(ctx.response.getBody())).toMatchObject({
				token_type: "Bearer",
			});
		});

		it("finds no parameters when the body parser did not run", async () => {
			// The same request with the parser left out of the middleware stack:
			// the framework hands over no parameters, and the endpoint can only
			// answer that grant_type is missing. Hence the README's requirement.
			const { routes, credentials } = await machineClient();
			const ctx = formContext(new URLSearchParams(credentials).toString());

			await route(routes, "POST /oauth/token")(ctx);

			expect(ctx.response.getStatus()).toBe(400);
			expect(JSON.parse(ctx.response.getBody())).toMatchObject({
				error: "invalid_request",
			});
		});

		it("refuses the same credentials in the query string", async () => {
			const { routes, credentials } = await machineClient();
			const { ctx, recorded } = fakeContext(undefined, undefined, credentials);

			await route(routes, "POST /oauth/token")(ctx);

			expect(recorded.status).toBe(400);
			expect(recorded.body).toMatchObject({ error: "invalid_request" });
		});

		it("refuses a body that a query string would override", async () => {
			const { routes, credentials } = await machineClient();
			const { ctx, recorded } = fakeContext(credentials, undefined, {
				grant_type: "refresh_token",
			});

			await route(routes, "POST /oauth/token")(ctx);

			expect(recorded.status).toBe(400);
			expect(recorded.body).toMatchObject({ error: "invalid_request" });
		});

		it("refuses a query string on introspection, revocation and registration", async () => {
			const { routes, credentials } = await machineClient();
			for (const key of [
				"POST /oauth/introspect",
				"POST /oauth/revoke",
				"POST /oauth/register",
			]) {
				const { ctx, recorded } = fakeContext(
					key === "POST /oauth/register"
						? { redirect_uris: [REDIRECT] }
						: { token: "anything" },
					undefined,
					{ client_id: credentials.client_id },
				);

				await route(routes, key)(ctx);

				expect(recorded.status, key).toBe(400);
				expect(recorded.body, key).toMatchObject({ error: "invalid_request" });
			}
		});

		it("ignores a query parameter that is not an OAuth one", async () => {
			// A tracing or cache-busting parameter a proxy added carries no
			// credential: refusing it would break the request for nothing.
			const { routes, credentials } = await machineClient();
			const { ctx, recorded } = fakeContext(credentials, undefined, {
				trace: "abc",
				_: "1700000000",
			});

			await route(routes, "POST /oauth/token")(ctx);

			expect(recorded.status).toBeUndefined();
			expect(recorded.body).toMatchObject({ token_type: "Bearer" });
		});

		it("refuses every OAuth parameter in the query, on every endpoint", async () => {
			const { routes, credentials } = await machineClient();
			const parameters = [
				"client_id",
				"client_secret",
				"client_assertion",
				"client_assertion_type",
				"grant_type",
				"code",
				"code_verifier",
				"redirect_uri",
				"refresh_token",
				"scope",
				"resource",
				"token",
				"token_type_hint",
				"access_token",
				"username",
				"password",
			];
			for (const key of [
				"POST /oauth/token",
				"POST /oauth/introspect",
				"POST /oauth/revoke",
				"POST /oauth/register",
			]) {
				for (const parameter of parameters) {
					const { ctx, recorded } = fakeContext(
						key === "POST /oauth/register"
							? { redirect_uris: [REDIRECT] }
							: credentials,
						undefined,
						{ [parameter]: "x" },
					);

					await route(routes, key)(ctx);

					expect(recorded.status, `${key} ?${parameter}`).toBe(400);
					expect(recorded.body, `${key} ?${parameter}`).toMatchObject({
						error: "invalid_request",
					});
				}
			}
		});

		it("refuses client metadata in the query of a registration", async () => {
			const { routes } = await machineClient();
			for (const parameter of [
				"redirect_uris",
				"token_endpoint_auth_method",
				"grant_types",
				"response_types",
				"client_name",
				"client_uri",
				"logo_uri",
				"contacts",
				"tos_uri",
				"policy_uri",
				"jwks_uri",
				"jwks",
				"software_id",
				"software_version",
				"software_statement",
			]) {
				const { ctx, recorded } = fakeContext(
					{ redirect_uris: [REDIRECT] },
					undefined,
					{ [parameter]: "x" },
				);

				await route(routes, "POST /oauth/register")(ctx);

				expect(recorded.status, parameter).toBe(400);
				expect(recorded.body, parameter).toMatchObject({
					error: "invalid_request",
				});
			}

			const { ctx, recorded } = fakeContext(
				{ redirect_uris: [REDIRECT] },
				undefined,
				{ trace: "abc" },
			);
			await route(routes, "POST /oauth/register")(ctx);
			expect(recorded.status).toBe(201);
		});

		it("ignores registration metadata in the query of the token endpoint", async () => {
			// Registration metadata is only an OAuth parameter on /register: on
			// the token endpoint it means nothing and is ignored.
			const { routes, credentials } = await machineClient();
			const { ctx, recorded } = fakeContext(credentials, undefined, {
				client_name: "x",
			});

			await route(routes, "POST /oauth/token")(ctx);

			expect(recorded.body).toMatchObject({ token_type: "Bearer" });
		});

		it("refuses a body that is not an object", async () => {
			const { routes } = await machineClient();
			const { ctx, recorded } = fakeContext(["grant_type"]);

			await route(routes, "POST /oauth/token")(ctx);

			expect(recorded.status).toBe(400);
			expect(recorded.body).toMatchObject({ error: "invalid_request" });
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
			// Sends its secret in the body below, so that is what it registers.
			tokenEndpointAuthMethod: "client_secret_post",
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
