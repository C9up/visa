/**
 * Wires `config/visa.ts` into the container, and mounts the endpoints that
 * need no human.
 *
 * `/token`, `/revoke` and `/introspect` are machine-to-machine: the spec says
 * exactly what goes in and what comes out, so the provider owns them.
 *
 * `/authorize` is NOT mounted, and that is deliberate rather than unfinished.
 * It needs two things visa has no opinion about: who is signed in — warden's
 * business — and what a consent screen looks like, which is the application's.
 * A route that guessed either would be wrong in a way that is hard to notice:
 * a server that shows no consent screen grants silently, and one that assumes
 * a session shape signs the wrong user in. `visa.authorize()` gives you the
 * decision; the page around it is yours. The README shows the ten lines.
 *
 * Duck-typed throughout: visa must not import its host's HTTP types.
 */

import type { VisaConfigInput } from "./config.js";
import { OAuthError } from "./errors.js";
import { clearVisa, getVisa, setVisa } from "./services/main.js";
import { VisaManager } from "./VisaManager.js";

interface VisaContainer {
	singleton(token: unknown, factory: () => unknown): void;
	resolve<T = unknown>(token: unknown): Promise<T>;
	has(token: unknown): boolean;
}
interface VisaConfigStore {
	get<T = unknown>(key: string): T | undefined;
}
export interface VisaAppContext {
	container: VisaContainer;
	config: VisaConfigStore;
}

/** The slice of a request an OAuth endpoint reads. */
interface VisaHttpContext {
	request: {
		header(name: string): string | undefined;
		all(): Record<string, unknown>;
	};
	response: {
		status(code: number): unknown;
		header(name: string, value: string): unknown;
		send(body: unknown): unknown;
	};
}

/** The slice of a router visa mounts on. */
interface VisaRouter {
	post(path: string, handler: (ctx: VisaHttpContext) => Promise<void>): unknown;
	get(path: string, handler: (ctx: VisaHttpContext) => Promise<void>): unknown;
}

export default class VisaProvider {
	#owned: VisaManager | undefined;

	constructor(protected app: VisaAppContext) {}

	register(): void {
		this.app.container.singleton(VisaManager, () => {
			const config = this.app.config.get<VisaConfigInput>("visa");
			if (config === undefined) {
				throw new Error(
					"[visa] no `config/visa.ts` — run `ream configure @c9up/visa`.",
				);
			}
			const manager = new VisaManager(config);
			setVisa(manager);
			return manager;
		});
		this.app.container.singleton("visa", () =>
			this.app.container.resolve<VisaManager>(VisaManager),
		);
	}

	async boot(): Promise<void> {
		const manager = await this.app.container.resolve<VisaManager>(VisaManager);
		this.#owned = manager;
		setVisa(manager);
	}

	async start(): Promise<void> {
		if (!this.app.container.has("router")) return;
		const router = await this.app.container.resolve<VisaRouter>("router");
		const manager = await this.app.container.resolve<VisaManager>(VisaManager);
		const config = this.app.config.get<VisaConfigInput>("visa");
		const prefix = config?.prefix ?? "/oauth";

		router.post(`${prefix}/token`, async (ctx) => {
			await this.#answer(ctx, async () => {
				const body = ctx.request.all();
				const credentials = manager.readCredentials({
					body,
					...readAuthorization(ctx),
				});
				const tokens = await manager.token(body, credentials);
				// No store may keep a token response: it carries credentials
				// (RFC 6749 §5.1), and a shared cache would hand them to the
				// next caller.
				ctx.response.header("cache-control", "no-store");
				ctx.response.header("pragma", "no-cache");
				return tokens;
			});
		});

		router.post(`${prefix}/introspect`, async (ctx) => {
			await this.#answer(ctx, async () => {
				const body = ctx.request.all();
				const credentials = manager.readCredentials({
					body,
					...readAuthorization(ctx),
				});
				ctx.response.header("cache-control", "no-store");
				return manager.introspect(body, credentials);
			});
		});

		router.post(`${prefix}/revoke`, async (ctx) => {
			await this.#answer(ctx, async () => {
				const body = ctx.request.all();
				const credentials = manager.readCredentials({
					body,
					...readAuthorization(ctx),
				});
				await manager.revoke(body, credentials);
				// RFC 7009 §2.2: 200 with an empty body, whatever the token was.
				ctx.response.status(200);
				return null;
			});
		});

		// RFC 8414 — what a client fetches to discover the endpoints.
		router.get("/.well-known/oauth-authorization-server", async (ctx) => {
			ctx.response.header("content-type", "application/json");
			ctx.response.send({
				issuer: manager.issuer,
				authorization_endpoint: `${manager.issuer}${prefix}/authorize`,
				token_endpoint: `${manager.issuer}${prefix}/token`,
				introspection_endpoint: `${manager.issuer}${prefix}/introspect`,
				revocation_endpoint: `${manager.issuer}${prefix}/revoke`,
				response_types_supported: ["code"],
				grant_types_supported: [
					"authorization_code",
					"refresh_token",
					"client_credentials",
				],
				// S256 only unless the application turned `plain` back on.
				code_challenge_methods_supported:
					config?.allowPlainChallenge === true ? ["S256", "plain"] : ["S256"],
				token_endpoint_auth_methods_supported: [
					"client_secret_basic",
					"client_secret_post",
					"none",
				],
			});
		});
	}

	async shutdown(): Promise<void> {
		if (this.#owned !== undefined && getVisa() === this.#owned) clearVisa();
		this.#owned = undefined;
	}

	/**
	 * Run a handler and turn an `OAuthError` into the body the spec names.
	 *
	 * Anything else is rethrown: an unexpected failure is the application's
	 * exception handler's business, and dressing it as an OAuth error would
	 * tell a client its request was bad when the server broke.
	 */
	async #answer(
		ctx: VisaHttpContext,
		work: () => Promise<unknown>,
	): Promise<void> {
		try {
			const body = await work();
			if (body !== null) ctx.response.send(body);
			else ctx.response.send("");
		} catch (error) {
			if (!(error instanceof OAuthError)) throw error;
			ctx.response.status(error.status);
			if (error.code === "invalid_client") {
				// §5.2: a 401 has to say how to authenticate.
				ctx.response.header("www-authenticate", 'Basic realm="oauth"');
			}
			ctx.response.send(error.toResponse());
		}
	}
}

function readAuthorization(ctx: VisaHttpContext): { authorization?: string } {
	const header = ctx.request.header("authorization");
	return header === undefined ? {} : { authorization: header };
}
