/**
 * Visa — an OAuth 2.1 authorization server.
 *
 * It issues tokens to OTHER applications on a user's behalf. Knowing who that
 * user is stays warden's job; visa never authenticates anyone, it only asks
 * the application who is signed in.
 *
 * Nothing here depends on a transport or on a database: the manager takes
 * values and returns values, the store is a contract. The HTTP endpoints are
 * in the provider.
 */

import "./augmentations.js";

export {
	type AuthorizationRequest,
	type AuthorizeOptions,
	errorRedirect,
	issueAuthorizationCode,
	successRedirect,
	UnredirectableError,
	type ValidatedRequest,
	validateAuthorizationRequest,
} from "./authorize.js";
export {
	assertGrantAllowed,
	authenticateClient,
	type ClientCredentials,
	readCredentials,
	redirectUriMatches,
	resolveScopes,
} from "./clients.js";
export { defineConfig, type VisaConfigInput } from "./config.js";
export { hashSecret, randomToken, secretMatches, sha256 } from "./crypto.js";
export {
	type AuthorizationErrorCode,
	OAuthError,
	type ProtocolErrorCode,
	type TokenErrorCode,
	VisaError,
} from "./errors.js";
export {
	type GuardClientResponse,
	type GuardResult,
	type GuardStore,
	type GuardUser,
	VisaAccessToken,
	VisaGuard,
	type VisaGuardConfig,
	visaGuard,
} from "./guard.js";
export { introspect, revoke, verifyAccessToken } from "./introspect.js";
export {
	assertResourceIdentifier,
	type ChallengeOptions,
	PROTECTED_RESOURCE_PATH,
	type ProtectedResourceMetadata,
	type ProtectedResourceOptions,
	protectedResourceMetadata,
	protectedResourceMetadataUrl,
	wwwAuthenticate,
} from "./protectedResource.js";
export {
	audienceAllows,
	narrowResources,
	readResourceParameter,
	validateResources,
} from "./resource.js";
export {
	clearVisa,
	default as visa,
	getVisa,
	setVisa,
} from "./services/main.js";
export type { VisaStore } from "./store.js";
export {
	type AtlasDb,
	type AtlasQuery,
	AtlasStore,
	type AtlasStoreTables,
} from "./stores/atlas.js";
export { MemoryStore } from "./stores/memory.js";
export { type TokenOptions, type TokenRequest, token } from "./token.js";
export type {
	AccessToken,
	AuthorizationCode,
	AuthorizedApplication,
	Client,
	ClientAuthMethod,
	Consent,
	GrantType,
	IntrospectionResponse,
	RefreshToken,
	TokenResponse,
} from "./types.js";
export {
	type AuthorizationOutcome,
	type VisaConfig,
	VisaManager,
} from "./VisaManager.js";
