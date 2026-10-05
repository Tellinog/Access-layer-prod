import { generateKeyPair, randomBytes } from "node:crypto";
import { open, realpath, stat, unlink } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { exportJWK } from "jose";
import type { Config } from "../types.js";
import { hashOAuthCredentialSecret, randomToken } from "../security.js";
import type {
  OAuthAdminAuditContext,
  OAuthAdminAllowanceState,
  OAuthAdminBulkGrantInput,
  OAuthAdminBulkScopesInput,
  OAuthAdminClientInput,
  OAuthAdminNativeGrantInput,
  OAuthAdminResourceInput,
  OAuthAdminScopeInput
} from "./admin-types.js";
import { OAuthAdminRepository, OAuthAdminRepositoryError } from "./admin-repository.js";
import { canonicalOAuthPublicFingerprint } from "./signing.js";
import {
  isCanonicalOAuthScope,
  isExactOAuthRedirectUri,
  isExactOAuthHttpsUri,
  OAUTH_RS256_MIN_MODULUS_BITS,
  validateOAuthClientRegistration,
  validateOAuthClientResourceScopeAllowances,
  validateOAuthResourceRegistration
} from "./validation.js";

export class OAuthAdminValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super("OAuth administration request rejected");
    this.name = "OAuthAdminValidationError";
  }
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertNoIssues(issues: string[]): void {
  const unique = [...new Set(issues)].sort();
  if (unique.length > 0) throw new OAuthAdminValidationError(unique);
}

function requireCredentialPepper(config: Config): string {
  const pepper = config.oauthCredentialSecretPepper;
  if (!pepper || pepper === config.toolClientSecretPepper) {
    throw new OAuthAdminValidationError(["oauth_credential_pepper_unavailable"]);
  }
  return pepper;
}

function isInsideRoot(root: string, candidate: string): boolean {
  const fromRoot = relative(root, candidate);
  return fromRoot === "" || (!fromRoot.startsWith(`..${sep}`) && fromRoot !== ".." && !isAbsolute(fromRoot));
}

async function generateRsaKeyPair(): Promise<{ publicKey: import("node:crypto").KeyObject; privateKey: import("node:crypto").KeyObject }> {
  return new Promise((resolve, reject) => {
    generateKeyPair("rsa", {
      modulusLength: OAUTH_RS256_MIN_MODULUS_BITS,
      publicExponent: 0x10001
    }, (error, publicKey, privateKey) => {
      if (error) reject(error);
      else resolve({ publicKey, privateKey });
    });
  });
}

export class OAuthAdminService {
  constructor(private readonly input: {
    config: Config;
    repository: OAuthAdminRepository;
    now?: () => Date;
  }) {}

  private now(): Date {
    return this.input.now?.() ?? new Date();
  }

  snapshot() {
    return this.input.repository.snapshot();
  }

  async createScope(input: OAuthAdminScopeInput, ctx: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(isCanonicalOAuthScope(input.scope) ? [] : ["scope_invalid"]),
      ...(input.description.trim() ? [] : ["scope_description_required"])
    ]);
    return this.input.repository.createScope({ scope: input.scope, description: input.description.trim() }, ctx);
  }

  async updateScope(id: string, input: { description?: string; status?: "active" | "disabled" }, ctx: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(!id ? ["scope_id_required"] : []),
      ...(input.description !== undefined && !input.description.trim() ? ["scope_description_required"] : []),
      ...(input.status !== undefined && !["active", "disabled"].includes(input.status) ? ["scope_status_invalid"] : []),
      ...(input.description === undefined && input.status === undefined ? ["scope_update_required"] : [])
    ]);
    return this.input.repository.updateScope(id, input, ctx);
  }

  bulkScopes(input: OAuthAdminBulkScopesInput, commit: boolean, ctx?: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(input.mode !== "create_missing" ? ["bulk_scope_mode_invalid"] : []),
      ...(input.rows.length < 1 || input.rows.length > 200 ? ["bulk_scope_batch_size_invalid"] : []),
      ...(input.rows.some((row) => row.scope.length > 200 || row.description.length > 2000 ||
        !Number.isInteger(row.row) || row.row < 1 || row.row > 100000) ? ["bulk_scope_row_invalid"] : [])
    ]);
    return this.input.repository.bulkScopes({ ...input, rows: input.rows.map((row) => ({ ...row, description: row.description.trim() })) }, commit, ctx);
  }

  bulkScopeStatus(scopes: string[], status: "active" | "disabled", commit: boolean, ctx?: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(scopes.length < 1 || scopes.length > 200 ? ["bulk_scope_batch_size_invalid"] : []),
      ...(new Set(scopes).size !== scopes.length ? ["bulk_scope_duplicate"] : []),
      ...(scopes.some((scope) => !isCanonicalOAuthScope(scope)) ? ["scope_invalid"] : []),
      ...(!["active", "disabled"].includes(status) ? ["scope_status_invalid"] : [])
    ]);
    return this.input.repository.bulkScopeStatus(scopes, status, commit, ctx);
  }

  bulkNativeResourceScopes(resourceId: string, operations: Array<{ scope: string; action: "activate" | "disable" }>,
    commit: boolean, ctx?: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(!UUID_REGEX.test(resourceId) ? ["resource_id_invalid"] : []),
      ...(operations.length < 1 || operations.length > 200 ? ["resource_scope_batch_size_invalid"] : []),
      ...(new Set(operations.map((row) => row.scope)).size !== operations.length ? ["resource_scope_duplicate"] : []),
      ...(operations.some((row) => !isCanonicalOAuthScope(row.scope) || !["activate", "disable"].includes(row.action))
        ? ["resource_scope_operation_invalid"] : [])
    ]);
    return this.input.repository.bulkNativeResourceScopes(resourceId, operations, commit, ctx);
  }

  async createResource(input: OAuthAdminResourceInput, ctx: OAuthAdminAuditContext) {
    if (input.entitlementMode === "native") {
      assertNoIssues([
        ...(!isExactOAuthHttpsUri(input.resourceId) ? ["resource_id_invalid"] : []),
        ...(!isExactOAuthHttpsUri(input.protectedResourceMetadataUrl) ? ["protected_resource_metadata_url_invalid"] : []),
        ...(!input.displayName.trim() ? ["resource_display_name_required"] : []),
        ...(!input.ownerTeam.trim() ? ["resource_owner_team_required"] : []),
        ...(!["draft", "active", "disabled"].includes(input.status) ? ["resource_status_invalid"] : []),
        ...(input.scopes.length === 0 ? ["resource_scope_required"] : []),
        ...(new Set(input.scopes).size !== input.scopes.length ? ["resource_scope_duplicate"] : []),
        ...(input.scopes.some((scope) => !isCanonicalOAuthScope(scope)) ? ["resource_scope_invalid"] : [])
      ]);
      const found = await this.input.repository.findScopes(input.scopes);
      assertNoIssues(found.length !== input.scopes.length || found.some((scope) => scope.status !== "active")
        ? ["scope_not_found_or_disabled"] : []);
    } else {
      const entitlement = await this.input.repository.resolveLegacyEntitlement(input.legacyToolSlug);
      const scopes = await this.input.repository.findScopes(input.scopeMappings.map((mapping) => mapping.scope));
      const registration = {
        resourceId: input.resourceId,
        displayName: input.displayName,
        status: input.status,
        ownerTeam: input.ownerTeam,
        ownerContact: input.ownerContact,
        scopes: input.scopeMappings.map((mapping) => mapping.scope),
        scopeEntitlementMappings: input.scopeMappings,
        audiencePolicy: "exact_single_resource" as const,
        protectedResourceMetadataUrl: input.protectedResourceMetadataUrl,
        entitlementBinding: { type: "legacy_tool" as const, legacyToolSlug: input.legacyToolSlug }
      };
      const issues = entitlement === null
        ? ["legacy_tool_not_found"]
        : validateOAuthResourceRegistration(registration, {
          legacyToolId: entitlement.legacy_tool_id,
          legacyToolSlug: entitlement.legacy_tool_slug,
          registeredPermissionKeys: entitlement.registered_permission_keys
        });
      if (scopes.length !== input.scopeMappings.length || scopes.some((scope) => scope.status !== "active")) {
        issues.push("scope_not_found_or_disabled");
      }
      assertNoIssues(issues);
    }

    const pepper = requireCredentialPepper(this.input.config);
    const credentialId = `orc_${randomBytes(18).toString("hex")}`;
    const secret = randomToken("ors_", 32);
    const secretHash = await hashOAuthCredentialSecret(secret, pepper);
    const resource = await this.input.repository.createResource(input, { id: credentialId, secretHash }, ctx);
    return { resource, resource_credential_id: credentialId, resource_credential_secret: secret };
  }

  legacyTools() { return this.input.repository.listLegacyTools(); }

  searchUsers(query: string) {
    assertNoIssues(query.trim().length < 2 || query.length > 100 ? ["user_search_invalid"] : []);
    return this.input.repository.searchUsers(query.trim());
  }

  listNativeGrants(resourceId: string, filters: { query: string; scope: string; status: string; effective: string; offset: number } =
    { query: "", scope: "", status: "", effective: "", offset: 0 }) {
    assertNoIssues([
      ...(!UUID_REGEX.test(resourceId) ? ["resource_id_invalid"] : []),
      ...(filters.query.length > 100 || filters.scope.length > 200 ? ["grant_filter_invalid"] : []),
      ...(filters.status && !["active", "expired", "revoked", "pending_user_link"].includes(filters.status)
        ? ["grant_status_filter_invalid"] : []),
      ...(filters.effective && !["true", "false"].includes(filters.effective) ? ["grant_effective_filter_invalid"] : []),
      ...(!Number.isInteger(filters.offset) || filters.offset < 0 || filters.offset > 10000 ? ["grant_offset_invalid"] : [])
    ]);
    return this.input.repository.listNativeGrants(resourceId, filters);
  }

  createNativeGrants(input: OAuthAdminNativeGrantInput, ctx: OAuthAdminAuditContext) {
    const validFrom = input.validFrom ?? this.now();
    assertNoIssues([
      ...(!UUID_REGEX.test(input.resourceId) ? ["resource_id_invalid"] : []),
      ...(!UUID_REGEX.test(input.userId) ? ["user_id_invalid"] : []),
      ...(input.scopes.length === 0 || input.scopes.length > 50 ? ["grant_scopes_invalid"] : []),
      ...(new Set(input.scopes).size !== input.scopes.length ? ["grant_scope_duplicate"] : []),
      ...(input.scopes.some((scope) => !isCanonicalOAuthScope(scope)) ? ["grant_scope_invalid"] : []),
      ...(input.validUntil && input.validUntil <= validFrom ? ["grant_validity_invalid"] : [])
    ]);
    return this.input.repository.createNativeGrants({ ...input, validFrom }, this.now(), ctx);
  }

  revokeNativeGrant(id: string, ctx: OAuthAdminAuditContext) {
    assertNoIssues(!UUID_REGEX.test(id) ? ["native_grant_not_found"] : []);
    return this.input.repository.revokeNativeGrant(id, ctx);
  }

  bulkNativeGrants(input: OAuthAdminBulkGrantInput, commit: boolean, ctx?: OAuthAdminAuditContext) {
    const matrix = (input.userIds.length + input.emails.length) * input.scopes.length;
    assertNoIssues([
      ...(!UUID_REGEX.test(input.resourceId) ? ["resource_id_invalid"] : []),
      ...(matrix < 1 || matrix > 1000 || input.userIds.length + input.emails.length > 100 || input.scopes.length > 50
        ? ["bulk_grant_batch_size_invalid"] : []),
      ...(input.userIds.some((id) => !UUID_REGEX.test(id)) ? ["user_id_invalid"] : []),
      ...(input.emails.some((email) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)
        ? ["grant_email_invalid"] : []),
      ...(input.scopes.some((scope) => !isCanonicalOAuthScope(scope)) ? ["grant_scope_invalid"] : []),
      ...(new Set(input.scopes).size !== input.scopes.length ? ["grant_scope_duplicate"] : []),
      ...(new Set(input.userIds).size !== input.userIds.length ? ["grant_user_duplicate"] : []),
      ...(new Set(input.emails.map((email) => email.toLowerCase())).size !== input.emails.length ? ["grant_email_duplicate"] : []),
      ...(input.validUntil && input.validUntil <= (input.validFrom ?? this.now()) ? ["grant_validity_invalid"] : [])
    ]);
    return this.input.repository.bulkNativeGrants({ ...input, emails: input.emails.map((email) => email.toLowerCase()) }, commit, ctx);
  }

  bulkRevokeNativeGrants(ids: string[], commit: boolean, ctx?: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(ids.length < 1 || ids.length > 200 ? ["bulk_revoke_batch_size_invalid"] : []),
      ...(ids.some((id) => !UUID_REGEX.test(id)) ? ["native_grant_id_invalid"] : []),
      ...(new Set(ids).size !== ids.length ? ["native_grant_duplicate"] : [])
    ]);
    return this.input.repository.bulkRevokeNativeGrants(ids, commit, ctx);
  }

  async createClient(input: OAuthAdminClientInput, ctx: OAuthAdminAuditContext) {
    const allowedResources = [...new Set(input.allowances.map((item) => item.resourceId))];
    const allowedScopes = [...new Set(input.allowances.map((item) => item.scope))];
    const registration = {
      clientId: input.clientId,
      clientName: input.clientName,
      clientType: "confidential" as const,
      status: input.status,
      grantTypes: input.grantTypes,
      redirectUris: input.redirectUris,
      tokenEndpointAuthMethod: "client_secret_basic" as const,
      credentialLifecycle: { secretPresent: true, rotatedAt: null, expiresAt: null },
      allowedResources,
      allowedScopes,
      ownerTeam: input.ownerTeam,
      ownerContact: input.ownerContact
    };
    const resourceRegistrations = allowedResources.map((resourceId) => ({
      resourceId,
      displayName: resourceId,
      status: "active" as const,
      ownerTeam: "validation",
      ownerContact: null,
      scopes: input.allowances.filter((item) => item.resourceId === resourceId).map((item) => item.scope),
      scopeEntitlementMappings: [],
      audiencePolicy: "exact_single_resource" as const,
      protectedResourceMetadataUrl: resourceId,
      entitlementBinding: { type: "legacy_tool" as const, legacyToolSlug: "validation-tool" }
    }));
    assertNoIssues([
      ...validateOAuthClientRegistration(registration),
      ...validateOAuthClientResourceScopeAllowances(registration, resourceRegistrations, input.allowances)
    ]);
    const secret = randomToken("ocs_", 32);
    const secretHash = await hashOAuthCredentialSecret(secret, requireCredentialPepper(this.input.config));
    const client = await this.input.repository.createClient(input, secretHash, ctx);
    return { client, client_secret: secret };
  }

  updateRegistrationStatus(kind: "client" | "resource", id: string, status: "draft" | "active" | "disabled", ctx: OAuthAdminAuditContext) {
    if (!id || !["draft", "active", "disabled"].includes(status)) {
      throw new OAuthAdminValidationError(["registration_status_invalid"]);
    }
    return this.input.repository.updateRegistrationStatus(kind, id, status, ctx);
  }

  replaceRedirectUris(clientId: string, redirectUris: string[], ctx: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(redirectUris.length === 0 ? ["redirect_uri_required"] : []),
      ...(new Set(redirectUris).size !== redirectUris.length ? ["redirect_uri_duplicate"] : []),
      ...(redirectUris.some((uri) => !isExactOAuthRedirectUri(uri)) ? ["redirect_uri_invalid"] : [])
    ]);
    return this.input.repository.replaceRedirectUris(clientId, redirectUris, ctx);
  }

  previewCommitRedirectUris(clientId: string, redirectUris: string[], expectedCurrent: string[] | null,
    commit: boolean, ctx?: OAuthAdminAuditContext) {
    assertNoIssues([
      ...(!UUID_REGEX.test(clientId) ? ["client_id_invalid"] : []),
      ...(redirectUris.length < 1 || redirectUris.length > 100 ? ["redirect_uri_count_invalid"] : []),
      ...(new Set(redirectUris).size !== redirectUris.length ? ["redirect_uri_duplicate"] : []),
      ...(redirectUris.some((uri) => !isExactOAuthRedirectUri(uri)) ? ["redirect_uri_invalid"] : []),
      ...(commit && !expectedCurrent ? ["redirect_preview_required"] : []),
      ...(expectedCurrent && expectedCurrent.length > 100 ? ["redirect_current_set_too_large"] : [])
    ]);
    return this.input.repository.previewCommitRedirectUris(clientId, redirectUris, expectedCurrent, commit, ctx);
  }

  replaceAllowances(clientId: string, allowances: OAuthAdminClientInput["allowances"], ctx: OAuthAdminAuditContext) {
    const keys = allowances.map((item) => `${item.resourceId}\u0000${item.scope}`);
    assertNoIssues([
      ...(allowances.length === 0 ? ["allowance_required"] : []),
      ...(new Set(keys).size !== keys.length ? ["allowance_duplicate"] : []),
      ...(allowances.some((item) => !isExactOAuthHttpsUri(item.resourceId)) ? ["allowance_resource_invalid"] : []),
      ...(allowances.some((item) => !isCanonicalOAuthScope(item.scope)) ? ["allowance_scope_invalid"] : [])
    ]);
    return this.input.repository.replaceAllowances(clientId, allowances, ctx);
  }

  previewCommitAllowances(clientId: string, allowances: OAuthAdminClientInput["allowances"],
    expectedCurrent: OAuthAdminAllowanceState[] | null, commit: boolean, ctx?: OAuthAdminAuditContext) {
    const keys = allowances.map((item) => `${item.resourceId}\u0000${item.scope}`);
    assertNoIssues([
      ...(!UUID_REGEX.test(clientId) ? ["client_id_invalid"] : []),
      ...(allowances.length > 200 ? ["allowance_batch_size_invalid"] : []),
      ...(new Set(keys).size !== keys.length ? ["allowance_duplicate"] : []),
      ...(allowances.some((item) => !isExactOAuthHttpsUri(item.resourceId) || !isCanonicalOAuthScope(item.scope))
        ? ["allowance_invalid"] : []),
      ...(commit && !expectedCurrent ? ["allowance_preview_required"] : []),
      ...(expectedCurrent && expectedCurrent.length > 200 ? ["allowance_current_set_too_large"] : []),
      ...(expectedCurrent?.some((item) => !["active", "disabled"].includes(item.status)) ? ["allowance_current_status_invalid"] : [])
    ]);
    return this.input.repository.previewCommitAllowances(clientId, allowances, expectedCurrent, commit, ctx);
  }

  setResourceScope(resourceId: string, scopeId: string, input: { legacyPermissionKey: string | null; status: "active" | "disabled" }, ctx: OAuthAdminAuditContext) {
    if (!resourceId || !scopeId || !["active", "disabled"].includes(input.status)) {
      throw new OAuthAdminValidationError(["resource_scope_update_invalid"]);
    }
    return this.input.repository.setResourceScope(resourceId, scopeId, input, ctx);
  }

  setEntitlementBinding(resourceId: string, legacyToolSlug: string, status: "active" | "disabled", ctx: OAuthAdminAuditContext) {
    if (!resourceId || !legacyToolSlug || !["active", "disabled"].includes(status)) {
      throw new OAuthAdminValidationError(["entitlement_binding_update_invalid"]);
    }
    return this.input.repository.setEntitlementBinding(resourceId, legacyToolSlug, status, ctx);
  }

  async rotateCredential(kind: "client" | "resource", ownerId: string, ctx: OAuthAdminAuditContext) {
    const prefix = kind === "client" ? "ocs_" : "ors_";
    const secret = randomToken(prefix, 32);
    const secretHash = await hashOAuthCredentialSecret(secret, requireCredentialPepper(this.input.config));
    const credentialId = kind === "resource" ? `orc_${randomBytes(18).toString("hex")}` : undefined;
    const credential = await this.input.repository.rotateCredential(kind, ownerId, { id: credentialId, secretHash }, ctx);
    return kind === "client"
      ? { credential, client_secret: secret }
      : { credential, resource_credential_id: credentialId, resource_credential_secret: secret };
  }

  retireCredential(kind: "client" | "resource", credentialId: string, ctx: OAuthAdminAuditContext) {
    return this.input.repository.retireCredential(kind, credentialId, ctx);
  }

  async generateSigningKey(ctx: OAuthAdminAuditContext) {
    const configuredRoot = this.input.config.oauthSigningKeyRoot;
    if (!configuredRoot || !isAbsolute(configuredRoot)) {
      throw new OAuthAdminValidationError(["oauth_signing_key_root_unavailable"]);
    }
    let canonicalRoot: string;
    try {
      canonicalRoot = await realpath(configuredRoot);
      const rootStat = await stat(canonicalRoot);
      if (!rootStat.isDirectory()) throw new Error("not-directory");
    } catch {
      throw new OAuthAdminValidationError(["oauth_signing_key_root_unavailable"]);
    }
    const suffix = randomBytes(12).toString("hex");
    const kid = `oauth-${suffix}`;
    const privatePath = join(canonicalRoot, `${kid}.pem`);
    if (!isInsideRoot(canonicalRoot, privatePath)) {
      throw new OAuthAdminValidationError(["oauth_signing_key_path_invalid"]);
    }
    const { publicKey, privateKey } = await generateRsaKeyPair();
    const exported = await exportJWK(publicKey);
    const publicJwk: Record<string, unknown> = { ...exported, kid, alg: "RS256", use: "sig" };
    const fingerprint = canonicalOAuthPublicFingerprint(publicJwk);
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
    const file = await open(privatePath, "wx", 0o600);
    try {
      await file.writeFile(privatePem, { encoding: "utf8" });
      await file.sync();
      await file.close();
      return await this.input.repository.insertSigningKey({
        kid, publicJwk, fingerprint, protectedReference: pathToFileURL(privatePath).href
      }, ctx);
    } catch (error) {
      await file.close().catch(() => undefined);
      await unlink(privatePath).catch(() => undefined);
      throw error;
    }
  }

  publishSigningKey(id: string, ctx: OAuthAdminAuditContext) {
    return this.input.repository.publishSigningKey(id, this.now(), ctx);
  }

  activateSigningKey(id: string, ctx: OAuthAdminAuditContext) {
    return this.input.repository.activateSigningKey(id, this.now(), ctx);
  }

  retireSigningKey(id: string, ctx: OAuthAdminAuditContext) {
    return this.input.repository.retireSigningKey(id, this.now(), ctx);
  }

  disableSigningKey(id: string, ctx: OAuthAdminAuditContext) {
    return this.input.repository.disableSigningKey(id, ctx);
  }
}

export function isOAuthAdminKnownError(error: unknown): error is OAuthAdminValidationError | OAuthAdminRepositoryError {
  return error instanceof OAuthAdminValidationError || error instanceof OAuthAdminRepositoryError;
}
