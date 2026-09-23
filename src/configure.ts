/**
 * `ream configure @c9up/visa` — the Adonis codemod shape.
 *
 * It writes the config, registers the provider and stops there: the store and
 * the consent screen are decisions, not boilerplate, and a generated guess at
 * either would be wrong in a way that only shows up in production.
 */

interface Codemods {
	makeUsingStub(
		source: string,
		stub: string,
		data: Record<string, unknown>,
	): Promise<void>;
	registerProvider?(path: string): Promise<void>;
	defineEnvValidations?(input: {
		variables: Record<string, string>;
	}): Promise<void>;
}

interface ConfigureCommand {
	codemods: Codemods;
	logger?: { info(message: string): void };
}

export async function configure(command: ConfigureCommand): Promise<void> {
	const stubs = new URL("../stubs/", import.meta.url).pathname;
	await command.codemods.makeUsingStub(stubs, "config.stub", {});
	await command.codemods.registerProvider?.("@c9up/visa/provider");
	command.logger?.info(
		"visa is registered. Two things are yours: a store (MemoryStore is for tests) and the /authorize route with its consent screen — see the README.",
	);
}
