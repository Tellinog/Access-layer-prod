import { readFileSync } from "node:fs";
import { config as loadDotenv } from "dotenv";
import type { Config } from "./types.js";
import { parseOAuthTransactionProtectionKey } from "./oauth/state-protection.js";
import { normalizeEmail, validateToolSlug } from "./validation.js";

loadDotenv();

function readRequired(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value.trim();
}

function readOptional(name: string, fallback?: string): string | undefined {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    return fallback;
  }
  return value.trim();
}

function readInt(name: string, fallback: number, min?: number, max?: number): number {
  const raw = readOptional(name);
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || (min !== undefined && value < min) || (max !== undefined && value > max)) {
    throw new Error(`Invalid integer environment variable ${name}`);
  }
  return value;
}

function readBoolean(name: string, fallback: boolean): boolean {
  const raw = readOptional(name);
  if (raw === undefined) {
    return fallback;
  }
  const normalized = raw.toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  throw new Error(`Invalid boolean environment variable ${name}`);
}


function normalizePublicBasePath(value: string | undefined): string {
  const raw = (value ?? "").trim();
  if (raw === "" || raw === "/") return "";
  if (!raw.startsWith("/")) {
    throw new Error("PUBLIC_BASE_PATH must start with / when set");
  }
  if (raw.includes("://") || raw.includes("?") || raw.includes("#") || raw.includes("\\")) {
    throw new Error("PUBLIC_BASE_PATH must be a URL path only");
  }
  const normalized = raw.replace(/\/+$/, "");
  if (normalized === "") return "";
  if (normalized.includes("//")) {
    throw new Error("PUBLIC_BASE_PATH must not contain empty path segments");
  }
  return normalized;
}

function readCsv(name: string, fallback = ""): string[] {
  const raw = readOptional(name, fallback) ?? "";
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

const hostedDomainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function isHostedDomain(value: string): boolean {
  if (value.includes("://") || value.includes("/") || value.includes(":")) {
    return false;
  }
  if (value === "localhost" || value.endsWith(".localhost")) {
    return false;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return false;
  }
  return hostedDomainPattern.test(value);
}

export function loadConfig(): Config {
  const appEnv = (readOptional("APP_ENV", "development") ?? "development") as Config["appEnv"];
  if (!["development", "staging", "production", "test"].includes(appEnv)) {
    throw new Error("APP_ENV must be development, staging, production or test");
  }

  const jwtPrivateKeyPem = readOptional("JWT_PRIVATE_KEY_PEM");
  const jwtPrivateKeyPemPath = readOptional("JWT_PRIVATE_KEY_PEM_PATH");
  if (!jwtPrivateKeyPem && !jwtPrivateKeyPemPath && appEnv !== "test") {
    throw new Error("JWT_PRIVATE_KEY_PEM_PATH or JWT_PRIVATE_KEY_PEM is required");
  }

  const oauthP0Enabled = readBoolean("OAUTH_P0_ENABLED", false);
  const oauthTransactionProtectionKeyValue = readOptional("OAUTH_TRANSACTION_PROTECTION_KEY");
  if (oauthP0Enabled && oauthTransactionProtectionKeyValue === undefined) {
    throw new Error("Missing required environment variable OAUTH_TRANSACTION_PROTECTION_KEY when OAUTH_P0_ENABLED=true");
  }
  const oauthTransactionProtectionKey = oauthTransactionProtectionKeyValue === undefined
    ? undefined
    : parseOAuthTransactionProtectionKey(oauthTransactionProtectionKeyValue);
  const oauthCredentialSecretPepper = readOptional("OAUTH_CREDENTIAL_SECRET_PEPPER");
  const oauthSigningKeyRoot = readOptional("OAUTH_SIGNING_KEY_ROOT");
  if (oauthP0Enabled && oauthCredentialSecretPepper === undefined) {
    throw new Error("Missing required environment variable OAUTH_CREDENTIAL_SECRET_PEPPER when OAUTH_P0_ENABLED=true");
  }
  if (oauthP0Enabled && oauthSigningKeyRoot === undefined) {
    throw new Error("Missing required environment variable OAUTH_SIGNING_KEY_ROOT when OAUTH_P0_ENABLED=true");
  }
  if (oauthCredentialSecretPepper !== undefined && oauthCredentialSecretPepper.length < 16) {
    throw new Error("OAUTH_CREDENTIAL_SECRET_PEPPER must be at least 16 characters when set");
  }

  const legacyMicrosoftEnabled = readBoolean("LEGACY_MICROSOFT_ENABLED", false);
  const microsoftTenantId = legacyMicrosoftEnabled ? readRequired("MICROSOFT_TENANT_ID").toLowerCase() : undefined;
  const microsoftClientId = legacyMicrosoftEnabled ? readRequired("MICROSOFT_CLIENT_ID").toLowerCase() : undefined;
  const microsoftClientSecret = legacyMicrosoftEnabled ? readRequired("MICROSOFT_CLIENT_SECRET") : undefined;
  const microsoftRedirectUri = legacyMicrosoftEnabled ? readRequired("MICROSOFT_REDIRECT_URI") : undefined;
  const microsoftOidcScope = readOptional("MICROSOFT_OIDC_SCOPE", "openid profile email") ?? "openid profile email";
  const microsoftAllowedEmailDomains = legacyMicrosoftEnabled
    ? readCsv("MICROSOFT_ALLOWED_EMAIL_DOMAINS").map((domain) => domain.toLowerCase())
    : [];
  const legacyMicrosoftToolSlugs = legacyMicrosoftEnabled
    ? readCsv("LEGACY_MICROSOFT_TOOL_SLUGS").map((slug) => slug.toLowerCase())
    : [];

  const config: Config = {
    appEnv,
    appBaseUrl: readRequired("APP_BASE_URL"),
    authIssuer: readRequired("AUTH_ISSUER"),
    publicBasePath: normalizePublicBasePath(readOptional("PUBLIC_BASE_PATH", "")),
    port: readInt("PORT", 8080, 1, 65535),
    logLevel: readOptional("LOG_LEVEL", "info") ?? "info",
    databaseUrl: readRequired("DATABASE_URL"),
    googleClientId: readRequired("GOOGLE_CLIENT_ID"),
    googleClientSecret: readRequired("GOOGLE_CLIENT_SECRET"),
    googleRedirectUri: readRequired("GOOGLE_REDIRECT_URI"),
    googleAllowedHd: readCsv("GOOGLE_ALLOWED_HD").map((hd) => hd.toLowerCase()),
    googleOidcScope: readOptional("GOOGLE_OIDC_SCOPE", "openid email profile") ?? "openid email profile",
    legacyMicrosoftEnabled,
    microsoftTenantId,
    microsoftClientId,
    microsoftClientSecret,
    microsoftRedirectUri,
    microsoftOidcScope,
    microsoftAllowedEmailDomains,
    legacyMicrosoftToolSlugs,
    jwtPrivateKeyPem: jwtPrivateKeyPem ?? (jwtPrivateKeyPemPath ? readFileSync(jwtPrivateKeyPemPath, "utf8") : undefined),
    jwtPrivateKeyPemPath,
    jwtPublicKeyId: readRequired("JWT_PUBLIC_KEY_ID"),
    accessTokenTtlSeconds: readInt("ACCESS_TOKEN_TTL_SECONDS", 900, 60, 3600),
    refreshTokenTtlSeconds: readInt("REFRESH_TOKEN_TTL_SECONDS", 28800, 300, 86400),
    oneTimeCodeTtlSeconds: readInt("ONE_TIME_CODE_TTL_SECONDS", 60, 15, 300),
    oauthP0Enabled,
    oauthTransactionProtectionKey,
    oauthCredentialSecretPepper,
    oauthSigningKeyRoot,
    sessionCookieName: readOptional("SESSION_COOKIE_NAME", "access_layer_admin_session") ?? "access_layer_admin_session",
    sessionSecret: readRequired("SESSION_SECRET"),
    toolClientSecretPepper: readRequired("TOOL_CLIENT_SECRET_PEPPER"),
    backupEncryptionKey: readOptional("BACKUP_ENCRYPTION_KEY"),
    corsAllowedOrigins: readCsv("CORS_ALLOWED_ORIGINS"),
    returnUrlAllowedSchemes: readCsv("RETURN_URL_ALLOWED_SCHEMES", "https,http"),
    adminBootstrapEmails: readCsv("ADMIN_BOOTSTRAP_EMAILS").map(normalizeEmail),
    logIpSalt: readRequired("LOG_IP_SALT"),
    auditLogRetentionDays: readInt("AUDIT_LOG_RETENTION_DAYS", 365, 30),
    auditLogRawIp: readBoolean("AUDIT_LOG_RAW_IP", false),
    accessRequestReopenAfterDays: readInt("ACCESS_REQUEST_REOPEN_AFTER_DAYS", 30, 0, 3650),
    enableRefreshTokens: readBoolean("ENABLE_REFRESH_TOKENS", true),
    siemExportEnabled: readBoolean("SIEM_EXPORT_ENABLED", false),
    siemExportEndpoint: readOptional("SIEM_EXPORT_ENDPOINT"),
    siemExportToken: readOptional("SIEM_EXPORT_TOKEN"),
    backupApiToken: readOptional("BACKUP_API_TOKEN"),
    trustProxyHops: readInt("TRUST_PROXY_HOPS", appEnv === "production" ? 1 : 0, 0, 5)
  };

  if (config.oauthCredentialSecretPepper !== undefined &&
      config.oauthCredentialSecretPepper === config.toolClientSecretPepper) {
    throw new Error("OAuth credential secret isolation is invalid");
  }

  if (config.googleAllowedHd.length === 0) {
    throw new Error("GOOGLE_ALLOWED_HD must include at least one hosted domain");
  }
  if (config.googleAllowedHd.some((hd) => !isHostedDomain(hd))) {
    throw new Error("GOOGLE_ALLOWED_HD may only include Workspace hosted domains, not URLs, IP addresses or localhost");
  }

  if (config.legacyMicrosoftEnabled) {
    const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    if (!config.microsoftTenantId || !guidPattern.test(config.microsoftTenantId)) {
      throw new Error("MICROSOFT_TENANT_ID must be a GUID");
    }
    if (!config.microsoftClientId || !guidPattern.test(config.microsoftClientId)) {
      throw new Error("MICROSOFT_CLIENT_ID must be a GUID");
    }
    if (!config.microsoftAllowedEmailDomains?.length) {
      throw new Error("MICROSOFT_ALLOWED_EMAIL_DOMAINS must include at least one hosted domain");
    }
    if (config.microsoftAllowedEmailDomains.some((domain) => !isHostedDomain(domain))) {
      throw new Error("MICROSOFT_ALLOWED_EMAIL_DOMAINS may only include hosted domains, not URLs, IP addresses or localhost");
    }
    if (!config.legacyMicrosoftToolSlugs?.length) {
      throw new Error("LEGACY_MICROSOFT_TOOL_SLUGS must include at least one tool slug");
    }
    if (config.legacyMicrosoftToolSlugs.some((slug) => !validateToolSlug(slug))) {
      throw new Error("LEGACY_MICROSOFT_TOOL_SLUGS may only include valid Access Layer tool slugs");
    }
    if (config.legacyMicrosoftToolSlugs.includes("access-admin")) {
      throw new Error("LEGACY_MICROSOFT_TOOL_SLUGS must not include access-admin");
    }
    const configuredMicrosoftScopes = new Set((config.microsoftOidcScope ?? "").split(/\s+/).filter(Boolean));
    for (const requiredScope of ["openid", "profile", "email"]) {
      if (!configuredMicrosoftScopes.has(requiredScope)) {
        throw new Error(`MICROSOFT_OIDC_SCOPE must include ${requiredScope}`);
      }
    }
  }

  for (const [name, value] of [
    ["APP_BASE_URL", config.appBaseUrl],
    ["AUTH_ISSUER", config.authIssuer],
    ["GOOGLE_REDIRECT_URI", config.googleRedirectUri]
  ] as const) {
    try {
      new URL(value);
    } catch {
      throw new Error(`${name} must be a valid URL`);
    }
  }

  if (config.legacyMicrosoftEnabled) {
    let microsoftRedirect: URL;
    try {
      microsoftRedirect = new URL(config.microsoftRedirectUri!);
    } catch {
      throw new Error("MICROSOFT_REDIRECT_URI must be a valid URL");
    }
    const appBase = new URL(config.appBaseUrl);
    const expectedPath = `${config.publicBasePath}/v1/auth/microsoft/callback`;
    if (microsoftRedirect.origin !== appBase.origin || microsoftRedirect.pathname !== expectedPath ||
        microsoftRedirect.search !== "" || microsoftRedirect.hash !== "" || microsoftRedirect.username || microsoftRedirect.password) {
      throw new Error("MICROSOFT_REDIRECT_URI must match the Access Layer public Microsoft callback exactly");
    }
  }

  if (config.publicBasePath) {
    const appPath = new URL(config.appBaseUrl).pathname.replace(/\/+$/, "");
    const issuerPath = new URL(config.authIssuer).pathname.replace(/\/+$/, "");
    const redirectPath = new URL(config.googleRedirectUri).pathname;
    if (appPath !== config.publicBasePath || issuerPath !== config.publicBasePath) {
      throw new Error("APP_BASE_URL and AUTH_ISSUER path must match PUBLIC_BASE_PATH");
    }
    if (!redirectPath.startsWith(`${config.publicBasePath}/`)) {
      throw new Error("GOOGLE_REDIRECT_URI path must be under PUBLIC_BASE_PATH");
    }
  }

  const requiredScopes = ["openid", "email", "profile"];
  const configuredScopes = new Set(config.googleOidcScope.split(/\s+/).filter(Boolean));
  for (const requiredScope of requiredScopes) {
    if (!configuredScopes.has(requiredScope)) {
      throw new Error(`GOOGLE_OIDC_SCOPE must include ${requiredScope}`);
    }
  }

  const allowedReturnSchemes = new Set(["https", "http"]);
  for (const scheme of config.returnUrlAllowedSchemes) {
    if (!allowedReturnSchemes.has(scheme)) {
      throw new Error("RETURN_URL_ALLOWED_SCHEMES may only include https and http");
    }
  }

  if (config.backupApiToken !== undefined && config.backupApiToken.length < 32) {
    throw new Error("BACKUP_API_TOKEN must be at least 32 characters when set");
  }

  if (config.backupEncryptionKey !== undefined && config.backupEncryptionKey.length < 32) {
    throw new Error("BACKUP_ENCRYPTION_KEY must be at least 32 characters when set");
  }

  if (config.appEnv === "production") {
    const mustBeHttps = [config.appBaseUrl, config.authIssuer, config.googleRedirectUri];
    if (mustBeHttps.some((value) => !value.startsWith("https://"))) {
      throw new Error("Production APP_BASE_URL, AUTH_ISSUER and GOOGLE_REDIRECT_URI must be HTTPS");
    }
    if (!config.backupEncryptionKey) {
      throw new Error("BACKUP_ENCRYPTION_KEY is required in production");
    }
    if (config.legacyMicrosoftEnabled && !config.microsoftRedirectUri?.startsWith("https://")) {
      throw new Error("Production MICROSOFT_REDIRECT_URI must be HTTPS");
    }
  }

  return config;
}
