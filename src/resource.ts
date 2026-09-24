/**
 * Which resource a token is for (RFC 8707).
 *
 * A token with no stated audience is a token for everything. Send it to the
 * wrong server — or let a compromised one replay it — and every other resource
 * that trusts the same issuer accepts it. The `resource` parameter is how a
 * client says "this one is for the calendar API", and how the calendar API
 * refuses one minted for somebody else.
 *
 * Read off the RFC rather than recalled: the value MUST be an absolute URI
 * without a fragment (§2), it MAY repeat, and a resource the server does not
 * accept is refused with `invalid_target` (§2) — not `invalid_request`, which
 * would tell a client its request was malformed when it was merely aimed
 * somewhere it may not go.
 */

import { OAuthError } from "./errors.js";

/**
 * Normalise however the parameter arrived into a list.
 *
 * A form body gives one value or several under the same name, and a query
 * string the same; both are `resource=` repeated, which parsers hand over
 * either way.
 */
export function readResourceParameter(value: unknown): string[] {
	if (value === undefined || value === null) return [];
	if (Array.isArray(value)) {
		return value.filter((entry): entry is string => typeof entry === "string");
	}
	return typeof value === "string" && value !== "" ? [value] : [];
}

/**
 * Check each one, and refuse the request if any is unusable.
 *
 * `invalid_target` for every rejection here, including a malformed URI: §2
 * names that code for "cannot parse the provided value(s)" as well as for a
 * resource the server will not issue for.
 */
export function validateResources(
	requested: readonly string[],
	accepted?: readonly string[],
): string[] {
	const resources: string[] = [];
	for (const value of requested) {
		let url: URL;
		try {
			url = new URL(value);
		} catch {
			throw new OAuthError(
				"invalid_target",
				`resource must be an absolute URI: ${value}`,
			);
		}
		if (url.hash !== "") {
			throw new OAuthError(
				"invalid_target",
				`resource must not carry a fragment: ${value}`,
			);
		}
		// §2 SHOULD NOT include a query, and recognises that some cases need
		// one — so it travels rather than being refused or stripped. Stripping
		// would hand back a token for a resource nobody asked for.
		if (accepted !== undefined && !accepted.includes(value)) {
			throw new OAuthError(
				"invalid_target",
				`this server does not issue tokens for ${value}`,
			);
		}
		if (!resources.includes(value)) resources.push(value);
	}
	return resources;
}

/**
 * What a token request may narrow to.
 *
 * A refresh or an exchange may ask for fewer resources than were authorised,
 * never for more — the same rule scopes follow, and for the same reason: the
 * user agreed to a set, and a later request must not widen it.
 */
export function narrowResources(
	requested: readonly string[],
	granted: readonly string[],
): string[] {
	if (requested.length === 0) return [...granted];
	if (granted.length === 0) {
		// Nothing was bound at authorization time, so there is nothing to narrow
		// FROM. Letting the request name one here would mint a token for an
		// audience the user never saw.
		throw new OAuthError(
			"invalid_target",
			"this grant is not bound to any resource",
		);
	}
	const outside = requested.filter((value) => !granted.includes(value));
	if (outside.length > 0) {
		throw new OAuthError(
			"invalid_target",
			`this grant does not cover ${outside.join(", ")}`,
		);
	}
	return [...requested];
}

/**
 * Is this token for me?
 *
 * What a resource server asks. A token bound to nothing is accepted — that is
 * every token issued before a client started sending `resource`, and refusing
 * them would break each one. A token bound to SOMETHING must name this
 * resource, or it was minted for another server and arriving here means it
 * travelled.
 */
export function audienceAllows(
	audience: readonly string[] | undefined,
	resource: string | undefined,
): boolean {
	if (audience === undefined || audience.length === 0) return true;
	if (resource === undefined) return true;
	return audience.includes(resource);
}
