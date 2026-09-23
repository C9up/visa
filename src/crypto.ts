/**
 * Every secret in this package goes through here.
 *
 * `node:crypto` only — a dependency in the path that mints and compares
 * credentials is a dependency that can replace them.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * 256 bits of randomness, base64url.
 *
 * The length is not a preference: a token is guessed offline, so its entropy
 * is the only thing standing between an attacker and someone's session.
 */
export function randomToken(bytes = 32): string {
	return randomBytes(bytes).toString("base64url");
}

/** SHA-256, base64url — the shape PKCE's `S256` needs (RFC 7636 §4.2). */
export function sha256(value: string): string {
	return createHash("sha256").update(value).digest("base64url");
}

/**
 * What goes in the store for a token or a client secret.
 *
 * SHA-256 with no salt and no stretching, DELIBERATELY: these are values this
 * package generated with 256 bits of entropy, so there is no dictionary to run
 * and nothing for a slow hash to buy. Stretching here would only make every
 * token lookup expensive — and a token lookup happens on every single request.
 * A USER password is the opposite case and belongs in sigil.
 */
export function hashSecret(secret: string): string {
	return sha256(secret);
}

/**
 * Compare in constant time.
 *
 * A `===` on a secret leaks its prefix through timing, one byte at a time,
 * which is enough to reconstruct it remotely given patience.
 */
export function secretMatches(candidate: string, stored: string): boolean {
	const a = Buffer.from(hashSecret(candidate));
	const b = Buffer.from(stored);
	// Different lengths cannot be compared in constant time by
	// `timingSafeEqual`, and a length mismatch is not a secret anyway.
	if (a.length !== b.length) return false;
	return timingSafeEqual(a, b);
}

/** The same comparison for two already-hashed values. */
export function hashMatches(a: string, b: string): boolean {
	const left = Buffer.from(a);
	const right = Buffer.from(b);
	if (left.length !== right.length) return false;
	return timingSafeEqual(left, right);
}
