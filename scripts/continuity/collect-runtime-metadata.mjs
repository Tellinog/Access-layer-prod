#!/usr/bin/env node
/** Emit allowlisted runtime facts and environment-variable presence only. */

import process from "node:process";
import { pathToFileURL } from "node:url";

export const CONTINUITY_ENVIRONMENT_NAMES = Object.freeze([
  "APP_BASE_URL",
  "AUTH_ISSUER",
  "PUBLIC_BASE_PATH",
  "POSTGRES_USER",
  "POSTGRES_PASSWORD",
  "POSTGRES_DB",
  "DATABASE_URL",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_REDIRECT_URI",
  "JWT_PRIVATE_KEY_PEM_PATH",
  "JWT_PRIVATE_KEY_PEM",
  "JWT_PUBLIC_KEY_ID",
  "ACCESS_TOKEN_TTL_SECONDS",
  "REFRESH_TOKEN_TTL_SECONDS",
  "ONE_TIME_CODE_TTL_SECONDS",
  "ENABLE_REFRESH_TOKENS",
  "SESSION_COOKIE_NAME",
  "SESSION_SECRET",
  "TOOL_CLIENT_SECRET_PEPPER",
  "BACKUP_ENCRYPTION_KEY",
  "CORS_ALLOWED_ORIGINS",
  "LOG_IP_SALT",
  "SIEM_EXPORT_TOKEN",
  "BACKUP_API_TOKEN",
]);

function nonEmpty(environment, name) {
  return typeof environment[name] === "string" && environment[name].trim().length > 0;
}

function isDefined(environment, name) {
  return Object.prototype.hasOwnProperty.call(environment, name);
}

export function collectRuntimeMetadata(environment = process.env) {
  const environmentPresence = Object.fromEntries(
    CONTINUITY_ENVIRONMENT_NAMES.map((name) => [name, isDefined(environment, name)]),
  );
  const portText = nonEmpty(environment, "PORT") ? environment.PORT.trim() : "";
  const port = /^\d+$/.test(portText) ? Number(portText) : null;
  const revision = ["SOURCE_COMMIT", "COOLIFY_GIT_COMMIT_SHA", "GIT_COMMIT"]
    .map((name) => environment[name]?.trim())
    .find((value) => value && /^[0-9a-f]{7,40}$/i.test(value)) ?? null;
  const digest = environment.IMAGE_DIGEST?.trim();
  const validDigest = digest && /^sha256:[0-9a-f]{64}$/i.test(digest) ? digest.toLowerCase() : null;
  const missing = [];
  if (port === null) missing.push("PORT");
  if (!revision && !validDigest) missing.push("SOURCE_COMMIT_or_IMAGE_DIGEST");
  return {
    status: missing.length === 0 ? "OBSERVED" : "NOT_READY",
    observed_at: new Date().toISOString(),
    runtime: {
      hostname: environment.HOSTNAME?.trim() || null,
      node_version: process.version,
      target_container_port: port,
      deployed_revision: revision,
      image_digest: validDigest,
    },
    required_environment_presence: environmentPresence,
    missing,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = collectRuntimeMetadata();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.status === "OBSERVED" ? 0 : 2;
}
