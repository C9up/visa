/**
 * Teach ream's `ContainerBindings` what `container.make(...)` returns for the
 * token visa binds.
 *
 * ream declares that interface open on purpose: it registers its own entries
 * and expects each package to contribute the ones it owns. Without this,
 * resolving by the string token answers `unknown` and every call site has to
 * assert a type it cannot prove — on the object that mints credentials, which
 * is the last place to be guessing.
 *
 * Loaded from the barrel and from the provider, so importing visa anywhere is
 * enough; nobody writes a `declare module` of their own.
 *
 * Type-only, and ream stays an OPTIONAL peer: nothing here reaches a runtime
 * import, and a `declare module` for a specifier that does not resolve is
 * simply inert.
 */

// Referenced so the augmentation below resolves the module it augments.
import type {} from "@c9up/ream/types";

import type { VisaManager } from "./VisaManager.js";

declare module "@c9up/ream/types" {
	interface ContainerBindings {
		/** The authorization server, bound by `VisaProvider`. */
		visa: VisaManager;
	}
}
