/**
 * Container service accessor — `import visa from '@c9up/visa/services/main'`.
 *
 * Populated by `VisaProvider.boot()`. Reading it before the provider booted
 * throws rather than answering with a half-built server: an authorization
 * server with no store would mint tokens nobody can verify.
 */

import type { VisaManager } from "../VisaManager.js";

let instance: VisaManager | undefined;

/** @internal Called by the provider once the manager exists. */
export function setVisa(manager: VisaManager): void {
	instance = manager;
}

/** @internal Read the seated manager, if there is one. */
export function getVisa(): VisaManager | undefined {
	return instance;
}

/**
 * @internal Forget the manager — the provider on shutdown, tests between cases.
 *
 * The caller checks ownership first (`getVisa() === mine`): two applications
 * share this module in one process, and the one shutting down must not clear a
 * manager the other has since seated.
 */
export function clearVisa(): void {
	instance = undefined;
}

function resolve(): VisaManager {
	if (!instance) {
		throw new Error(
			"[visa] accessed before initialization — register VisaProvider, or call setVisa() yourself.",
		);
	}
	return instance;
}

/**
 * A proxy so the import can be held before the provider boots.
 *
 * Symbols and `then` answer undefined: a module namespace is probed for `then`
 * when it is imported, and a proxy that threw there would crash the import.
 */
const visa = new Proxy({} as VisaManager, {
	get(_target, property) {
		if (typeof property === "symbol" || property === "then") return undefined;
		const value = Reflect.get(resolve(), property);
		return typeof value === "function" ? value.bind(resolve()) : value;
	},
}) as VisaManager;

export default visa;
