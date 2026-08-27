import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ENVELOPE_VERSION = 1;
const ENVELOPE_ALGORITHM = "A256GCM";
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface OAuthProtectedStateEnvelope extends Record<string, unknown> {
  v: 1;
  alg: "A256GCM";
  iv: string;
  ciphertext: string;
  tag: string;
}

function decodeCanonicalBase64url(value: unknown, expectedBytes?: number): Buffer | null {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== value) return null;
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) return null;
  return decoded;
}

export function parseOAuthTransactionProtectionKey(value: string): Buffer {
  const key = decodeCanonicalBase64url(value, KEY_BYTES);
  if (key === null) {
    throw new Error(
      "OAUTH_TRANSACTION_PROTECTION_KEY must be canonical unpadded base64url for exactly 32 bytes"
    );
  }
  return key;
}

function aad(transactionId: string): Buffer {
  return Buffer.from(`oauth-transaction-state:v${ENVELOPE_VERSION}:${transactionId}`, "utf8");
}

export function protectOAuthDownstreamState(
  state: string,
  transactionId: string,
  key: Buffer
): OAuthProtectedStateEnvelope {
  if (key.length !== KEY_BYTES) throw new Error("Invalid OAuth transaction protection key");
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad(transactionId));
  const ciphertext = Buffer.concat([cipher.update(state, "utf8"), cipher.final()]);
  return {
    v: ENVELOPE_VERSION,
    alg: ENVELOPE_ALGORITHM,
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url")
  };
}

export function unprotectOAuthDownstreamState(
  envelope: unknown,
  transactionId: string,
  key: Buffer
): string {
  if (
    key.length !== KEY_BYTES ||
    envelope === null ||
    typeof envelope !== "object" ||
    Array.isArray(envelope)
  ) {
    throw new Error("Invalid protected OAuth state");
  }
  const record = envelope as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !== "alg,ciphertext,iv,tag,v" ||
    record.v !== ENVELOPE_VERSION ||
    record.alg !== ENVELOPE_ALGORITHM
  ) {
    throw new Error("Invalid protected OAuth state");
  }
  const iv = decodeCanonicalBase64url(record.iv, IV_BYTES);
  const tag = decodeCanonicalBase64url(record.tag, TAG_BYTES);
  const ciphertext = decodeCanonicalBase64url(record.ciphertext);
  if (iv === null || tag === null || ciphertext === null) {
    throw new Error("Invalid protected OAuth state");
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(aad(transactionId));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("Invalid protected OAuth state");
  }
}
