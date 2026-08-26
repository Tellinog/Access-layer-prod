import { PERMISSION_KEY_REGEX, TOOL_SLUG_REGEX } from "../validation.js";
import type {
  LegacyEntitlementSnapshot,
  OAuthClientRegistration,
  OAuthClientResourceScopeAllowance,
  OAuthRegistrationBundle,
  OAuthResourceRegistration
} from "./types.js";

export const OAUTH_CLIENT_ID_REGEX = /^[a-z][a-z0-9._-]{2,127}$/;
export const OAUTH_SCOPE_REGEX = /^[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}$/;
const OAUTH_RESOURCE_ID_REGEX = /^https:\/\/[^*#\s]+$/;
const OAUTH_REDIRECT_SCHEMA_REGEX = /^(https:\/\/|http:\/\/localhost(?::[0-9]{1,5})?\/)[^*#]*$/;

export class OAuthRegistrationValidationError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`OAuth registration rejected (${issues.length} validation issue${issues.length === 1 ? "" : "s"})`);
    this.name = "OAuthRegistrationValidationError";
    this.issues = [...new Set(issues)].sort();
  }
}

function duplicates(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated];
}

function isHttpsUri(value: string): boolean {
  if (!OAUTH_RESOURCE_ID_REGEX.test(value)) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !parsed.username && !parsed.password && !parsed.hash;
  } catch {
    return false;
  }
}

export function isCanonicalOAuthScope(scope: string): boolean {
  return OAUTH_SCOPE_REGEX.test(scope);
}

export function isExactOAuthRedirectUri(redirectUri: string): boolean {
  if (!OAUTH_REDIRECT_SCHEMA_REGEX.test(redirectUri)) return false;
  try {
    const parsed = new URL(redirectUri);
    if (parsed.username || parsed.password || parsed.hash || redirectUri.includes("*")) return false;
    if (parsed.protocol === "https:") return true;
    return parsed.protocol === "http:" && parsed.hostname === "localhost";
  } catch {
    return false;
  }
}

export function validateOAuthClientRegistration(client: OAuthClientRegistration): string[] {
  const issues: string[] = [];
  if (!OAUTH_CLIENT_ID_REGEX.test(client.clientId)) issues.push("client_id_invalid");
  if (client.clientName.trim() === "") issues.push("client_name_required");
  if (client.ownerTeam.trim() === "") issues.push("owner_team_required");
  if (!["draft", "active", "disabled"].includes(client.status)) issues.push("client_status_invalid");
  if (!["confidential", "public"].includes(client.clientType)) issues.push("client_type_invalid");
  if (client.clientType === "confidential" && client.tokenEndpointAuthMethod !== "client_secret_basic") {
    issues.push("confidential_client_auth_method_invalid");
  }
  if (client.clientType === "public" && client.tokenEndpointAuthMethod !== "none") {
    issues.push("public_client_auth_method_invalid");
  }
  if (client.grantTypes.length === 0 || !client.grantTypes.includes("authorization_code")) {
    issues.push("authorization_code_grant_required");
  }
  if (client.grantTypes.some((grant) => !["authorization_code", "refresh_token"].includes(grant))) {
    issues.push("grant_type_invalid");
  }
  if (duplicates(client.grantTypes).length > 0) issues.push("grant_type_duplicate");
  if (client.redirectUris.length === 0) issues.push("redirect_uri_required");
  if (duplicates(client.redirectUris).length > 0) issues.push("redirect_uri_duplicate");
  if (client.redirectUris.some((uri) => !isExactOAuthRedirectUri(uri))) issues.push("redirect_uri_invalid");
  if (client.allowedResources.length === 0) issues.push("allowed_resource_required");
  if (duplicates(client.allowedResources).length > 0) issues.push("allowed_resource_duplicate");
  if (client.allowedResources.some((resource) => !isHttpsUri(resource))) issues.push("allowed_resource_invalid");
  if (client.allowedScopes.length === 0) issues.push("allowed_scope_required");
  if (duplicates(client.allowedScopes).length > 0) issues.push("allowed_scope_duplicate");
  if (client.allowedScopes.some((scope) => !isCanonicalOAuthScope(scope))) issues.push("allowed_scope_invalid");
  return [...new Set(issues)].sort();
}

export function validateOAuthResourceRegistration(
  resource: OAuthResourceRegistration,
  legacyEntitlement: LegacyEntitlementSnapshot
): string[] {
  const issues: string[] = [];
  if (!isHttpsUri(resource.resourceId)) issues.push("resource_id_invalid");
  if (!isHttpsUri(resource.protectedResourceMetadataUrl)) issues.push("protected_resource_metadata_url_invalid");
  if (resource.displayName.trim() === "") issues.push("resource_display_name_required");
  if (resource.ownerTeam.trim() === "") issues.push("resource_owner_team_required");
  if (!["draft", "active", "disabled"].includes(resource.status)) issues.push("resource_status_invalid");
  if (resource.audiencePolicy !== "exact_single_resource") issues.push("audience_policy_invalid");
  if (resource.entitlementBinding.type !== "legacy_tool") issues.push("entitlement_binding_type_invalid");
  if (!TOOL_SLUG_REGEX.test(resource.entitlementBinding.legacyToolSlug)) issues.push("legacy_tool_slug_invalid");
  if (!TOOL_SLUG_REGEX.test(legacyEntitlement.legacyToolSlug)) issues.push("resolved_legacy_tool_slug_invalid");
  if (resource.entitlementBinding.legacyToolSlug !== legacyEntitlement.legacyToolSlug) {
    issues.push("legacy_tool_binding_mismatch");
  }
  if (!legacyEntitlement.legacyToolId) issues.push("legacy_tool_id_required");
  if (resource.scopes.length === 0) issues.push("resource_scope_required");
  if (duplicates(resource.scopes).length > 0) issues.push("resource_scope_duplicate");
  if (resource.scopes.some((scope) => !isCanonicalOAuthScope(scope))) issues.push("resource_scope_invalid");

  const mappedScopes = resource.scopeEntitlementMappings.map((mapping) => mapping.scope);
  if (duplicates(mappedScopes).length > 0) issues.push("scope_mapping_duplicate");
  const declared = new Set(resource.scopes);
  const mapped = new Set(mappedScopes);
  if (resource.scopes.some((scope) => !mapped.has(scope))) issues.push("scope_mapping_missing");
  if (mappedScopes.some((scope) => !declared.has(scope))) issues.push("scope_mapping_extra");
  if (resource.scopeEntitlementMappings.length !== resource.scopes.length) issues.push("scope_mapping_coverage_invalid");

  const registeredPermissions = new Set(legacyEntitlement.registeredPermissionKeys);
  if (legacyEntitlement.registeredPermissionKeys.some((permission) => !PERMISSION_KEY_REGEX.test(permission))) {
    issues.push("registered_legacy_permission_invalid");
  }
  for (const mapping of resource.scopeEntitlementMappings) {
    if (!isCanonicalOAuthScope(mapping.scope)) issues.push("scope_mapping_scope_invalid");
    if (!PERMISSION_KEY_REGEX.test(mapping.legacyPermissionKey)) issues.push("mapped_legacy_permission_invalid");
    if (!registeredPermissions.has(mapping.legacyPermissionKey)) issues.push("mapped_legacy_permission_not_registered");
  }
  return [...new Set(issues)].sort();
}

export function validateOAuthClientResourceScopeAllowances(
  client: OAuthClientRegistration,
  resources: readonly OAuthResourceRegistration[],
  allowances: readonly OAuthClientResourceScopeAllowance[]
): string[] {
  const issues: string[] = [];
  const resourceById = new Map(resources.map((resource) => [resource.resourceId, resource]));
  const allowanceKeys = allowances.map((allowance) => `${allowance.resourceId}\u0000${allowance.scope}`);
  if (duplicates(allowanceKeys).length > 0) issues.push("client_resource_scope_allowance_duplicate");

  for (const allowance of allowances) {
    if (!client.allowedResources.includes(allowance.resourceId)) issues.push("allowance_resource_not_client_allowed");
    if (!client.allowedScopes.includes(allowance.scope)) issues.push("allowance_scope_not_client_allowed");
    const resource = resourceById.get(allowance.resourceId);
    if (!resource) {
      issues.push("allowance_resource_not_registered");
    } else if (!resource.scopes.includes(allowance.scope)) {
      issues.push("allowance_scope_not_registered_for_resource");
    }
  }

  for (const resourceId of client.allowedResources) {
    if (!resourceById.has(resourceId)) issues.push("client_allowed_resource_not_registered");
    if (!allowances.some((allowance) => allowance.resourceId === resourceId)) {
      issues.push("client_allowed_resource_without_explicit_scope_allowance");
    }
  }
  for (const scope of client.allowedScopes) {
    if (!allowances.some((allowance) => allowance.scope === scope)) {
      issues.push("client_allowed_scope_without_explicit_resource_allowance");
    }
  }
  return [...new Set(issues)].sort();
}

export function isExplicitlyAllowedClientResourceScope(
  allowances: readonly OAuthClientResourceScopeAllowance[],
  resourceId: string,
  scope: string
): boolean {
  return allowances.some((allowance) => allowance.resourceId === resourceId && allowance.scope === scope);
}

export function assertValidOAuthRegistrationBundle(bundle: OAuthRegistrationBundle): void {
  const resourceIds = bundle.resources.map(({ registration }) => registration.resourceId);
  const issues = [
    ...validateOAuthClientRegistration(bundle.client),
    ...(duplicates(resourceIds).length > 0 ? ["resource_registration_duplicate"] : []),
    ...bundle.resources.flatMap(({ registration, legacyEntitlement }) =>
      validateOAuthResourceRegistration(registration, legacyEntitlement)
    ),
    ...validateOAuthClientResourceScopeAllowances(
      bundle.client,
      bundle.resources.map(({ registration }) => registration),
      bundle.allowances
    )
  ];
  if (issues.length > 0) throw new OAuthRegistrationValidationError(issues);
}
