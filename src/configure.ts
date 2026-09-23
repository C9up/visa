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

import { access, constants } from "node:fs/promises";
import { resolve } from "node:path";
import { stubsRoot } from "./stubs.js";

/**
 * The migration this package ships.
 *
 * A high, stable prefix rather than a timestamp: these five tables reference
 * nothing else, so running them last is fine, and a number nobody's own
 * migrations are likely to have taken means the file lands instead of silently
 * losing to a name that already exists.
 */
const MIGRATION_STUB = "database/migrations/9000_create_visa_tables.stub";

interface Codemods {
	addProvider(importPath: string): Promise<void>;
	addEnvVars(vars: Record<string, string>): Promise<void>;
	writeFile(
		filePath: string,
		content: string,
		options?: { force?: boolean },
	): Promise<void>;
	makeUsingStub(
		stubsRoot: string,
		stubPath: string,
		state?: Record<string, string | number | boolean>,
		options?: { force?: boolean },
	): Promise<{ path: string; contents: string }>;
}

export async function configure(codemods: Codemods): Promise<void> {
	// Fail fast BEFORE touching the project: a pruned tarball or an unreadable
	// stub must not leave an application with a provider registered, a config
	// written and no tables to put anything in.
	await access(resolve(stubsRoot, MIGRATION_STUB), constants.R_OK);

	// The config below reads this, so it is declared here. Writing the file
	// without it leaves an application whose config asks the environment for
	// something nothing ever put there.
	await codemods.addEnvVars({
		VISA_ISSUER: "http://localhost:3333",
	});

	await codemods.addProvider("@c9up/visa/provider");
	await codemods.makeUsingStub(stubsRoot, "config/visa.stub");
	// The tables the atlas store reads and writes. An application on another
	// data layer deletes the file and keeps its own store — which is why this
	// is a migration and not a schema the package owns.
	await codemods.makeUsingStub(stubsRoot, MIGRATION_STUB);
}
