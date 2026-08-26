import type { OAuthSigningKeyPublicMetadata } from "./types.js";
import { isValidOAuthPublicJwk, validateOAuthSigningKeyLifecycle } from "./validation.js";

export interface OAuthJwks {
  keys: Record<string, unknown>[];
}

function isPublishableAt(key: OAuthSigningKeyPublicMetadata, now: Date): boolean {
  if (key.status === "published") {
    return key.publishedAt !== null && key.activatesAt !== null &&
      key.publishedAt.getTime() <= now.getTime() && now.getTime() < key.activatesAt.getTime();
  }
  return key.status === "active" && key.activatesAt !== null && key.activatesAt.getTime() <= now.getTime();
}

export function selectOAuthJwks(
  records: readonly OAuthSigningKeyPublicMetadata[],
  now: Date = new Date()
): OAuthJwks {
  if (!Number.isFinite(now.getTime())) return { keys: [] };

  const keys = records
    .filter((record) =>
      record.algorithm === "RS256" &&
      validateOAuthSigningKeyLifecycle(record).length === 0 &&
      isValidOAuthPublicJwk(record.publicJwk, record.kid) &&
      isPublishableAt(record, now)
    )
    .sort((left, right) => left.kid < right.kid ? -1 : left.kid > right.kid ? 1 : 0)
    .map((record) => ({
      kty: record.publicJwk.kty,
      kid: record.publicJwk.kid,
      alg: record.publicJwk.alg,
      use: record.publicJwk.use,
      n: record.publicJwk.n,
      e: record.publicJwk.e
    }));

  return { keys };
}
