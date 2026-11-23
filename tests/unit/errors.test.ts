import { Exception } from "@c9up/flare";
import { describe, expect, it } from "vitest";
import { errors } from "../../src/index.js";

describe("visa > errors", () => {
	it("are exported as one namespace of flare exceptions", () => {
		const error = new errors.E_VISA_OAUTH_ERROR("invalid_client", "Unknown.");
		expect(error).toBeInstanceOf(Exception);
		expect(error).toMatchObject({
			code: "E_VISA_OAUTH_ERROR",
			oauthCode: "invalid_client",
			status: 401,
			message: "invalid_client: Unknown.",
		});
		expect(error.toResponse()).toEqual({
			error: "invalid_client",
			error_description: "Unknown.",
		});
		expect(new errors.E_VISA_OAUTH_ERROR("invalid_grant").status).toBe(400);
		expect(new errors.E_VISA_NOT_BOOTED()).toMatchObject({
			code: "E_VISA_NOT_BOOTED",
			status: 500,
		});
	});

	it("keeps an unredirectable failure's protocol error and status", () => {
		const inner = new errors.E_VISA_OAUTH_ERROR("invalid_request", "No.");
		const error = new errors.E_VISA_UNREDIRECTABLE(inner);
		expect(error).toMatchObject({
			code: "E_VISA_UNREDIRECTABLE",
			status: 400,
			error: inner,
		});
	});
});
