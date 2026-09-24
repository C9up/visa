import { describe, expect, it } from "vitest";
import { visaGuard } from "../../src/guard.js";
import {
	PROTECTED_RESOURCE_PATH,
	protectedResourceMetadata,
	protectedResourceMetadataUrl,
	wwwAuthenticate,
} from "../../src/protectedResource.js";
import { MemoryStore } from "../../src/stores/memory.js";

/**
 * How a client with no token finds its way in (RFC 9728).
 *
 * Without this a 401 is a dead end: the caller learns it needs a token and
 * nothing about where tokens come from. With it, the refusal names a document,
 * the document names the authorization server, and an MCP client walks the
 * chain unattended.
 */

describe("visa > protected resource metadata", () => {
	it("puts the well-known segment between the host and the path", () => {
		// §3. The easy mistake is appending to the resource's own path, which
		// leaves a client fetching 404s.
		expect(protectedResourceMetadataUrl("https://api.example/mcp")).toBe(
			"https://api.example/.well-known/oauth-protected-resource/mcp",
		);
		expect(protectedResourceMetadataUrl("https://api.example")).toBe(
			`https://api.example${PROTECTED_RESOURCE_PATH}`,
		);
		expect(protectedResourceMetadataUrl("https://api.example/")).toBe(
			`https://api.example${PROTECTED_RESOURCE_PATH}`,
		);
	});

	it("drops a query and a fragment from the metadata URL", () => {
		expect(protectedResourceMetadataUrl("https://api.example/mcp?x=1")).toBe(
			"https://api.example/.well-known/oauth-protected-resource/mcp",
		);
	});

	it("builds the document §3.2 describes", () => {
		expect(
			protectedResourceMetadata({
				resource: "https://api.example/mcp",
				authorizationServers: ["https://auth.example"],
				scopesSupported: ["profile", "contacts.read"],
				resourceName: "Example MCP",
			}),
		).toEqual({
			resource: "https://api.example/mcp",
			authorization_servers: ["https://auth.example"],
			scopes_supported: ["profile", "contacts.read"],
			bearer_methods_supported: ["header"],
			resource_name: "Example MCP",
		});
	});

	it("says the token goes in the header unless told otherwise", () => {
		// It is all visa reads, so announcing more would be a promise the
		// resource server does not keep.
		const document = protectedResourceMetadata({
			resource: "https://api.example",
		});
		expect(document.bearer_methods_supported).toEqual(["header"]);
	});

	it("refuses a resource identifier that is not an absolute URI", () => {
		expect(() => protectedResourceMetadata({ resource: "/mcp" })).toThrow(
			/absolute URI/,
		);
	});

	it("refuses a resource identifier carrying a fragment", () => {
		// RFC 8707 §2.
		expect(() =>
			protectedResourceMetadata({ resource: "https://api.example/mcp#x" }),
		).toThrow(/fragment/);
	});
});

describe("visa > the WWW-Authenticate challenge", () => {
	it("names the metadata document, §5.1", () => {
		expect(wwwAuthenticate({ resource: "https://api.example/mcp" })).toBe(
			'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/mcp"',
		);
	});

	it("takes an explicit metadata URL over deriving one", () => {
		expect(
			wwwAuthenticate({ resourceMetadata: "https://elsewhere.example/doc" }),
		).toBe('Bearer resource_metadata="https://elsewhere.example/doc"');
	});

	it("carries the error and the scope a caller lacked", () => {
		expect(
			wwwAuthenticate({
				resource: "https://api.example",
				error: "insufficient_scope",
				scope: ["contacts.read", "contacts.write"],
			}),
		).toBe(
			'Bearer error="insufficient_scope", scope="contacts.read contacts.write", ' +
				'resource_metadata="https://api.example/.well-known/oauth-protected-resource"',
		);
	});

	it("is a bare Bearer when there is nothing to say", () => {
		expect(wwwAuthenticate()).toBe("Bearer");
	});

	it("refuses a value that cannot live in a quoted string", () => {
		// A quote or a control character cannot be escaped into one usefully — a
		// client would read the header as a different set of parameters.
		expect(() =>
			wwwAuthenticate({ error: 'inval"id', resource: "https://api.example" }),
		).toThrow(/WWW-Authenticate/);
		expect(() => wwwAuthenticate({ errorDescription: "line\nbreak" })).toThrow(
			/WWW-Authenticate/,
		);
	});
});

describe("visa > the guard's challenge", () => {
	const guard = (resource?: string) =>
		visaGuard({
			store: new MemoryStore(),
			findUser: async () => null,
			...(resource === undefined ? {} : { resource }),
		});

	it("names the resource it stands in front of", () => {
		expect(guard("https://api.example/mcp").challenge()).toBe(
			'Bearer resource_metadata="https://api.example/.well-known/oauth-protected-resource/mcp"',
		);
	});

	it("carries what the caller was missing", () => {
		expect(
			guard("https://api.example").challenge({
				error: "insufficient_scope",
				scope: ["contacts.read"],
			}),
		).toContain('error="insufficient_scope"');
	});

	it("is a bare Bearer when no resource was declared", () => {
		// Nothing to point at, so nothing is claimed.
		expect(guard().challenge()).toBe("Bearer");
	});
});
