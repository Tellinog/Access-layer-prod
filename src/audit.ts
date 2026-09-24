import { randomUUID } from "node:crypto";
import type { Repositories } from "./repositories.js";
import type { AuditEventInput } from "./types.js";

const FORBIDDEN_KEYS = new Set([
  "google_id_token",
  "id_token",
  "authorization_code",
  "code",
  "access_token",
  "refresh_token",
  "token",
  "cookie",
  "client_secret",
  "password",
  "secret"
]);

export class AuditLogger {
  constructor(private readonly repositories: Repositories) {}

  async write(input: AuditEventInput): Promise<void> {
    await this.repositories.writeAudit({
      ...input,
      event_id: randomUUID(),
      metadata: sanitizeMetadata(input.metadata ?? {})
    });
  }
}

export function sanitizeMetadata(metadata: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    const normalized = key.toLowerCase();
    if ([...FORBIDDEN_KEYS].some((forbidden) => normalized.includes(forbidden))) {
      continue;
    }
    sanitized[key] = sanitizeValue(value);
  }
  return sanitized;
}

function sanitizeValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value && typeof value === "object") {
    return sanitizeMetadata(value as Record<string, unknown>);
  }
  if (typeof value === "string" && looksTokenLike(value)) {
    return "[redacted]";
  }
  return value;
}

function looksTokenLike(value: string): boolean {
  if (value.length > 120) {
    return true;
  }
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    return true;
  }
  return /^(otc_|rt_|ocs_|ors_)[A-Za-z0-9_-]{20,}/.test(value);
}
