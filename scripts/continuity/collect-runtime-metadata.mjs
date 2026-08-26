#!/usr/bin/env node
/** Emit source-derived, allowlisted runtime/config facts without secret values. */

import { statSync } from "node:fs";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const CONFIG_ENVIRONMENT_NAMES = Object.freeze([
  "ACCESS_REQUEST_REOPEN_AFTER_DAYS", "ACCESS_TOKEN_TTL_SECONDS", "ADMIN_BOOTSTRAP_EMAILS",
  "APP_BASE_URL", "APP_ENV", "AUDIT_LOG_RAW_IP", "AUDIT_LOG_RETENTION_DAYS", "AUTH_ISSUER",
  "BACKUP_API_TOKEN", "BACKUP_ENCRYPTION_KEY", "CORS_ALLOWED_ORIGINS", "DATABASE_URL",
  "ENABLE_REFRESH_TOKENS", "GOOGLE_ALLOWED_HD", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
  "GOOGLE_OIDC_SCOPE", "GOOGLE_REDIRECT_URI", "JWT_PRIVATE_KEY_PEM", "JWT_PRIVATE_KEY_PEM_PATH",
  "JWT_PUBLIC_KEY_ID", "LOG_IP_SALT", "LOG_LEVEL", "OAUTH_P0_ENABLED", "ONE_TIME_CODE_TTL_SECONDS", "PORT",
  "POSTGRES_DB", "POSTGRES_PASSWORD", "POSTGRES_USER", "PUBLIC_BASE_PATH",
  "REFRESH_TOKEN_TTL_SECONDS", "RETURN_URL_ALLOWED_SCHEMES", "RUN_MIGRATIONS_ON_START",
  "RUN_SEED_ON_START", "SEED_EXAMPLE_TOOLS", "SESSION_COOKIE_NAME", "SESSION_SECRET",
  "SIEM_EXPORT_ENABLED", "SIEM_EXPORT_ENDPOINT", "SIEM_EXPORT_TOKEN", "TOOL_CLIENT_SECRET_PEPPER",
  "TRUST_PROXY_HOPS",
]);

const REQUIRED_NON_EMPTY = new Set([
  "APP_ENV", "APP_BASE_URL", "AUTH_ISSUER", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
  "DATABASE_URL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI",
  "GOOGLE_ALLOWED_HD", "JWT_PUBLIC_KEY_ID", "SESSION_SECRET", "TOOL_CLIENT_SECRET_PEPPER",
  "BACKUP_ENCRYPTION_KEY", "CORS_ALLOWED_ORIGINS", "LOG_IP_SALT",
]);

export function environmentState(environment, name) {
  if (!Object.prototype.hasOwnProperty.call(environment, name)) return "ABSENT";
  const value = environment[name];
  return typeof value !== "string" || value.trim() === "" ? "PRESENT_EMPTY" : "PRESENT_NON_EMPTY";
}

function optional(environment, name, fallback) {
  const value = environment[name];
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function csv(environment, name, fallback = "") {
  return String(optional(environment, name, fallback) ?? "").split(",").map((value) => value.trim()).filter(Boolean);
}

function integer(environment, name, fallback, min, max, missing) {
  const text = optional(environment, name, String(fallback));
  const value = Number(text);
  if (!Number.isInteger(value) || value < min || value > max) {
    missing.push(`effective_non_secret_config.${name}`);
    return null;
  }
  return value;
}

function boolean(environment, name, fallback, missing) {
  const text = optional(environment, name, fallback ? "true" : "false").toLowerCase();
  if (["1", "true", "yes", "on"].includes(text)) return true;
  if (["0", "false", "no", "off"].includes(text)) return false;
  missing.push(`effective_non_secret_config.${name}`);
  return null;
}

function publicBasePath(environment, missing) {
  const raw = optional(environment, "PUBLIC_BASE_PATH", "").trim();
  if (raw === "" || raw === "/") return "";
  if (!raw.startsWith("/") || raw.includes("://") || raw.includes("?") || raw.includes("#") || raw.includes("\\")) {
    missing.push("effective_non_secret_config.PUBLIC_BASE_PATH");
    return null;
  }
  const normalized = raw.replace(/\/+$/, "");
  if (normalized.includes("//")) {
    missing.push("effective_non_secret_config.PUBLIC_BASE_PATH");
    return null;
  }
  return normalized;
}

function safeUrl(environment, name, missing, { allowQuery = false } = {}) {
  const raw = optional(environment, name, null);
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash || (!allowQuery && parsed.search)) {
      missing.push(`effective_non_secret_config.${name}`);
      return null;
    }
    return raw;
  } catch {
    missing.push(`effective_non_secret_config.${name}`);
    return null;
  }
}

function safeOrigins(environment, name, missing) {
  return csv(environment, name).flatMap((raw) => {
    try {
      const parsed = new URL(raw);
      if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.origin === "null") {
        missing.push(`effective_non_secret_config.${name}`);
        return [];
      }
      return [parsed.origin];
    } catch {
      missing.push(`effective_non_secret_config.${name}`);
      return [];
    }
  });
}

function safeConfiguredKeyPath(environment, missing) {
  const configured = optional(environment, "JWT_PRIVATE_KEY_PEM_PATH", null);
  if (!configured) return null;
  if (!configured.startsWith("/run/secrets/") || /[\r\n\0]/.test(configured)) {
    missing.push("jwt_signing_material.configured_file_path_under_/run/secrets");
    return null;
  }
  return configured;
}

function keyFileState(configuredPath) {
  if (!configuredPath) return "UNOBSERVED";
  try {
    const stat = statSync(configuredPath);
    if (!stat.isFile()) return "UNOBSERVED";
    return stat.size === 0 ? "PRESENT_EMPTY" : "PRESENT_NON_EMPTY";
  } catch (error) {
    return error && typeof error === "object" && "code" in error && error.code === "ENOENT" ? "ABSENT" : "UNOBSERVED";
  }
}

export function collectRuntimeMetadata(environment = process.env) {
  const missing = [];
  const states = Object.fromEntries(CONFIG_ENVIRONMENT_NAMES.map((name) => [name, environmentState(environment, name)]));
  for (const name of REQUIRED_NON_EMPTY) {
    if (states[name] !== "PRESENT_NON_EMPTY") missing.push(`environment_state.${name}=PRESENT_NON_EMPTY`);
  }
  const inlineKey = states.JWT_PRIVATE_KEY_PEM === "PRESENT_NON_EMPTY";
  const fileKey = states.JWT_PRIVATE_KEY_PEM_PATH === "PRESENT_NON_EMPTY";
  if (!inlineKey && !fileKey) missing.push("environment_state.JWT_PRIVATE_KEY_PEM_or_JWT_PRIVATE_KEY_PEM_PATH=PRESENT_NON_EMPTY");
  const sourceMode = inlineKey ? "inline_env" : fileKey ? "file_path" : "unknown";
  const configuredFilePath = safeConfiguredKeyPath(environment, missing);
  const fileState = sourceMode === "file_path" ? keyFileState(configuredFilePath) : "UNOBSERVED";
  if (sourceMode === "file_path" && fileState !== "PRESENT_NON_EMPTY") missing.push("jwt_signing_material.file_state=PRESENT_NON_EMPTY");

  const appEnv = optional(environment, "APP_ENV", "development");
  const appBaseUrl = safeUrl(environment, "APP_BASE_URL", missing);
  const authIssuer = safeUrl(environment, "AUTH_ISSUER", missing);
  const googleRedirectUri = safeUrl(environment, "GOOGLE_REDIRECT_URI", missing, { allowQuery: true });
  const siemExportEnabled = boolean(environment, "SIEM_EXPORT_ENABLED", false, missing);
  const siemExportEndpoint = safeUrl(environment, "SIEM_EXPORT_ENDPOINT", missing);
  if (siemExportEnabled === true && !siemExportEndpoint) missing.push("effective_non_secret_config.SIEM_EXPORT_ENDPOINT");
  if (siemExportEnabled === true && states.SIEM_EXPORT_TOKEN !== "PRESENT_NON_EMPTY") missing.push("environment_state.SIEM_EXPORT_TOKEN=PRESENT_NON_EMPTY");
  if (appEnv === "production" && states.BACKUP_ENCRYPTION_KEY === "PRESENT_NON_EMPTY" && String(environment.BACKUP_ENCRYPTION_KEY).length < 32) {
    missing.push("environment_state.BACKUP_ENCRYPTION_KEY=VALID_NON_EMPTY");
  }
  if (states.BACKUP_API_TOKEN === "PRESENT_NON_EMPTY" && String(environment.BACKUP_API_TOKEN).length < 32) {
    missing.push("environment_state.BACKUP_API_TOKEN=VALID_NON_EMPTY");
  }

  const effectiveConfig = {
    app_env: appEnv,
    public_base_path: publicBasePath(environment, missing),
    app_base_url: appBaseUrl,
    auth_issuer: authIssuer,
    port: integer(environment, "PORT", 8080, 1, 65535, missing),
    log_level: optional(environment, "LOG_LEVEL", "info"),
    postgres_user: optional(environment, "POSTGRES_USER", null),
    postgres_database: optional(environment, "POSTGRES_DB", null),
    google_client_id: optional(environment, "GOOGLE_CLIENT_ID", null),
    google_redirect_uri: googleRedirectUri,
    google_allowed_hd: csv(environment, "GOOGLE_ALLOWED_HD").map((value) => value.toLowerCase()),
    google_oidc_scope: String(optional(environment, "GOOGLE_OIDC_SCOPE", "openid email profile")).split(/\s+/).filter(Boolean),
    jwt_public_key_id: optional(environment, "JWT_PUBLIC_KEY_ID", null),
    access_token_ttl_seconds: integer(environment, "ACCESS_TOKEN_TTL_SECONDS", 900, 60, 3600, missing),
    refresh_token_ttl_seconds: integer(environment, "REFRESH_TOKEN_TTL_SECONDS", 28800, 300, 86400, missing),
    one_time_code_ttl_seconds: integer(environment, "ONE_TIME_CODE_TTL_SECONDS", 60, 15, 300, missing),
    enable_refresh_tokens: boolean(environment, "ENABLE_REFRESH_TOKENS", true, missing),
    oauth_p0_enabled: boolean(environment, "OAUTH_P0_ENABLED", false, missing),
    session_cookie_name: optional(environment, "SESSION_COOKIE_NAME", "access_layer_admin_session"),
    cors_allowed_origins: safeOrigins(environment, "CORS_ALLOWED_ORIGINS", missing),
    return_url_allowed_schemes: csv(environment, "RETURN_URL_ALLOWED_SCHEMES", "https,http"),
    trust_proxy_hops: integer(environment, "TRUST_PROXY_HOPS", appEnv === "production" ? 1 : 0, 0, 5, missing),
    audit_log_retention_days: integer(environment, "AUDIT_LOG_RETENTION_DAYS", 365, 30, Number.MAX_SAFE_INTEGER, missing),
    audit_log_raw_ip: boolean(environment, "AUDIT_LOG_RAW_IP", false, missing),
    access_request_reopen_after_days: integer(environment, "ACCESS_REQUEST_REOPEN_AFTER_DAYS", 30, 0, 3650, missing),
    run_migrations_on_start: boolean(environment, "RUN_MIGRATIONS_ON_START", true, missing),
    run_seed_on_start: boolean(environment, "RUN_SEED_ON_START", false, missing),
    seed_example_tools: boolean(environment, "SEED_EXAMPLE_TOOLS", false, missing),
    siem_export_enabled: siemExportEnabled,
    siem_export_endpoint: siemExportEndpoint,
    admin_bootstrap_email_count: csv(environment, "ADMIN_BOOTSTRAP_EMAILS").length,
  };
  if (!effectiveConfig.google_allowed_hd.length) missing.push("effective_non_secret_config.GOOGLE_ALLOWED_HD");
  if (!["openid", "email", "profile"].every((scope) => effectiveConfig.google_oidc_scope.includes(scope))) {
    missing.push("effective_non_secret_config.GOOGLE_OIDC_SCOPE_required_scopes");
  }

  const revision = ["SOURCE_COMMIT", "COOLIFY_GIT_COMMIT_SHA", "GIT_COMMIT"]
    .map((name) => environment[name]?.trim())
    .find((value) => value && /^[0-9a-f]{7,40}$/i.test(value)) ?? null;
  const digest = environment.IMAGE_DIGEST?.trim();
  const imageDigest = digest && /^sha256:[0-9a-f]{64}$/i.test(digest) ? digest.toLowerCase() : null;
  if (!revision && !imageDigest) missing.push("runtime.SOURCE_COMMIT_or_IMAGE_DIGEST");

  return {
    status: missing.length === 0 ? "OBSERVED" : "NOT_READY",
    observed_at: new Date().toISOString(),
    source_inventory: {
      derived_from: ["src/config.ts", "docker-compose.yaml", "docker/entrypoint.sh"],
      variables: CONFIG_ENVIRONMENT_NAMES,
    },
    runtime: {
      hostname: environment.HOSTNAME?.trim() || null,
      node_version: process.version,
      target_container_port: effectiveConfig.port,
      deployed_revision: revision,
      image_digest: imageDigest,
    },
    jwt_signing_material: {
      source_mode: sourceMode,
      configured_file_path: configuredFilePath,
      file_state: fileState,
    },
    environment_state: states,
    effective_non_secret_config: effectiveConfig,
    missing: [...new Set(missing)].sort(),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = collectRuntimeMetadata();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.status === "OBSERVED" ? 0 : 2;
}
