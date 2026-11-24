/**
 * The one rule every lifetime in this package follows.
 *
 * A positive whole number of seconds, refused otherwise rather than rounded:
 * an expiry computed from `NaN` or `Infinity` is a date every
 * `expiresAt <= now` check reads as "not expired", so a code, a token or a
 * consent ticket issued under it would never expire.
 */

import { E_VISA_INVALID_TTL } from "./errors.js";

/** `undefined` passes: the caller's default applies. */
export function assertTtlSeconds(
	option: string,
	ttl: number | undefined,
): void {
	if (ttl === undefined) return;
	if (!Number.isInteger(ttl) || ttl <= 0) {
		throw new E_VISA_INVALID_TTL([option, ttl]);
	}
}
