/**
 * What a protected resource says when it refuses, so a client can find its way
 * in on its own (RFC 9728).
 *
 * Without this, a 401 is a dead end: the caller knows it needs a token and has
 * no way to learn where tokens come from. With it, the refusal names a
 * metadata document, the document names the authorization server, and an MCP
 * client walks from one to the other unattended. That is the whole point — it
 * is the difference between an agent that can connect and one that needs
 * somebody to paste a URL into a config file.
 *
 * Nothing here is visa-specific: a resource server is free to be a different
 * process from the authorization server, which is why the metadata takes the
 * issuer as a value rather than reading one.
 */

/** The metadata document, §3.2. Only `resource` is required. */
export interface ProtectedResourceMetadata {
	resource: string;
	authorization_servers?: string[];
	scopes_supported?: string[];
	bearer_methods_supported?: string[];
	resource_name?: string;
	resource_documentation?: string;
	jwks_uri?: string;
}

export interface ProtectedResourceOptions {
	/** This resource's identifier — an absolute URI, no fragment. */
	resource: string;
	/** The authorization servers that issue tokens for it. */
	authorizationServers?: readonly string[];
	/** What a client may ask for here. RECOMMENDED by §3.2. */
	scopesSupported?: readonly string[];
	/** Where the token may travel. Defaults to the header, which is all visa reads. */
	bearerMethodsSupported?: readonly string[];
	resourceName?: string;
	resourceDocumentation?: string;
}

/** The path the document is served at, §3. */
export const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";

/**
 * The well-known URL for a resource identifier.
 *
 * §3 inserts the well-known segment BETWEEN the host and the path, so a
 * resource at `https://api.example/mcp` publishes at
 * `https://api.example/.well-known/oauth-protected-resource/mcp` — not at the
 * resource's own path with the segment appended, which is the easy mistake and
 * the one that leaves a client fetching 404s.
 */
export function protectedResourceMetadataUrl(resource: string): string {
	const url = new URL(resource);
	const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
	url.pathname = `${PROTECTED_RESOURCE_PATH}${path}`;
	url.search = "";
	url.hash = "";
	return url.href;
}

/** Build the document a client fetches after a 401. */
export function protectedResourceMetadata(
	options: ProtectedResourceOptions,
): ProtectedResourceMetadata {
	assertResourceIdentifier(options.resource);
	return {
		resource: options.resource,
		...(options.authorizationServers === undefined
			? {}
			: { authorization_servers: [...options.authorizationServers] }),
		...(options.scopesSupported === undefined
			? {}
			: { scopes_supported: [...options.scopesSupported] }),
		bearer_methods_supported: [
			...(options.bearerMethodsSupported ?? ["header"]),
		],
		...(options.resourceName === undefined
			? {}
			: { resource_name: options.resourceName }),
		...(options.resourceDocumentation === undefined
			? {}
			: { resource_documentation: options.resourceDocumentation }),
	};
}

export interface ChallengeOptions {
	/** Where the metadata lives. Derived from the resource when omitted. */
	resourceMetadata?: string;
	/** This resource's identifier, used to derive the metadata URL. */
	resource?: string;
	/** `invalid_token`, `insufficient_scope` — RFC 6750 §3.1. */
	error?: string;
	errorDescription?: string;
	/** What the caller would have needed, with `insufficient_scope`. */
	scope?: readonly string[];
}

/**
 * The `WWW-Authenticate` value for a 401, §5.1.
 *
 * Quoted values are checked rather than escaped: the header is a
 * comma-separated list of quoted strings, and a value carrying a quote or a
 * control character cannot be represented in it at all. A caller that built
 * one from user input should hear about it here, not ship a header a client
 * parses into something else.
 */
export function wwwAuthenticate(options: ChallengeOptions = {}): string {
	const metadataUrl =
		options.resourceMetadata ??
		(options.resource === undefined
			? undefined
			: protectedResourceMetadataUrl(options.resource));

	const parameters: Array<[string, string]> = [];
	if (options.error !== undefined) parameters.push(["error", options.error]);
	if (options.errorDescription !== undefined) {
		parameters.push(["error_description", options.errorDescription]);
	}
	if (options.scope !== undefined && options.scope.length > 0) {
		parameters.push(["scope", options.scope.join(" ")]);
	}
	if (metadataUrl !== undefined) {
		parameters.push(["resource_metadata", metadataUrl]);
	}

	if (parameters.length === 0) return "Bearer";
	const rendered = parameters
		.map(([key, value]) => `${key}="${quotable(value, key)}"`)
		.join(", ");
	return `Bearer ${rendered}`;
}

function quotable(value: string, parameter: string): string {
	// A quoted-string holds neither a bare quote nor a control character, and
	// neither can be escaped into one usefully — a client would read the header
	// as a different set of parameters.
	for (const character of value) {
		const code = character.codePointAt(0) ?? 0;
		if (
			character === '"' ||
			character === "\\" ||
			code < 0x20 ||
			code === 0x7f
		) {
			throw new Error(
				`[visa] ${parameter} cannot go in a WWW-Authenticate header: it holds a quote, a backslash or a control character`,
			);
		}
	}
	return value;
}

/**
 * A resource identifier is an absolute URI with no fragment (RFC 8707 §2).
 *
 * Checked where the metadata is built, because a resource that publishes an
 * identifier its own tokens will not match is broken in a way only visible at
 * the moment a client is refused.
 */
export function assertResourceIdentifier(resource: string): void {
	let url: URL;
	try {
		url = new URL(resource);
	} catch {
		throw new Error(`[visa] resource must be an absolute URI: ${resource}`);
	}
	if (url.hash !== "") {
		throw new Error(`[visa] resource must not carry a fragment: ${resource}`);
	}
}
