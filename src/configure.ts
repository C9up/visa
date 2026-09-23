/**
 * `ream configure @c9up/visa` — wire the server in one command.
 *
 * The provider alone is not enough: it reads `config/visa.ts` and refuses to
 * boot without one, on purpose — an authorization server that invented its own
 * issuer would mint tokens nobody can validate.
 *
 * What it does NOT write is the store and the `/authorize` route. Both are
 * decisions rather than boilerplate, and a generated guess at either is wrong
 * in a way that only shows up in production: a memory store loses every
 * session on deploy, and a consent screen nobody wrote grants silently.
 */

interface Codemods {
	addProvider(importPath: string): Promise<void>;
	addEnvVars(vars: Record<string, string>): Promise<void>;
	writeFile(
		filePath: string,
		content: string,
		options?: { force?: boolean },
	): Promise<void>;
}

export async function configure(codemods: Codemods): Promise<void> {
	// The config below reads this, so it is declared here. Writing the file
	// without it leaves an application whose config asks the environment for
	// something nothing ever put there.
	await codemods.addEnvVars({
		VISA_ISSUER: "http://localhost:3333",
	});

	await codemods.addProvider("@c9up/visa/provider");
	await codemods.writeFile(
		"config/visa.ts",
		`import { defineConfig } from '@c9up/visa/config'
import { MemoryStore } from '@c9up/visa/stores/memory'
import env from '#start/env'

export default defineConfig({
  /**
   * The public URL this server answers on. It is the issuer every token is
   * bound to, so a client that validates it rejects anything minted elsewhere.
   */
  issuer: env.get('VISA_ISSUER'),

  /**
   * REPLACE THIS before deploying. MemoryStore keeps codes, tokens and
   * consents in one process: a restart signs every user out, and a second
   * instance sees none of the first one's tokens.
   */
  store: new MemoryStore(),

  // An hour is long enough to be useful, short enough that a leaked token is
  // not a standing invitation.
  accessTokenTtlSeconds: 3600,
})`,
	);
}
