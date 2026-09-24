import { generateKeyPair, randomBytes } from "node:crypto";
import { open, realpath, stat, unlink } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { exportJWK } from "jose";
import type { Config } from "../types.js";
import { hashOAuthCredentialSecret, randomToken } from "../security.js";
import type {
  OAuthAdminAuditContext,
  OAuthAdminClientInput,
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

  async createResource(input: OAuthAdminResourceInput, ctx: OAuthAdminAuditContext) {
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

    const pepper = requireCredentialPepper(this.input.config);
    const credentialId = `orc_${randomBytes(18).toString("hex")}`;
    const secret = randomToken("ors_", 32);
    const secretHash = await hashOAuthCredentialSecret(secret, pepper);
    const resource = await this.input.repository.createResource(input, { id: credentialId, secretHash }, ctx);
    return { resource, resource_credential_id: credentialId, resource_credential_secret: secret };
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

  setResourceScope(resourceId: string, scopeId: string, input: { legacyPermissionKey: string; status: "active" | "disabled" }, ctx: OAuthAdminAuditContext) {
    if (!resourceId || !scopeId || !input.legacyPermissionKey || !["active", "disabled"].includes(input.status)) {
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
