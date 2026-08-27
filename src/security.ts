import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);

export function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

export function randomToken(prefix = "", bytes = 32): string {
  return `${prefix}${randomBytes(bytes).toString("base64url")}`;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function hmacSha256(secret: string, value: string): string {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

export function hashOpaque(value: string, pepper: string): string {
  return hmacSha256(pepper, value);
}

export function hashRequestField(value: string | undefined, salt: string): string | null {
  if (!value) {
    return null;
  }
  return hmacSha256(salt, value);
}

export async function hashToolSecret(secret: string, pepper: string): Promise<string> {
  const salt = randomBytes(16).toString("base64url");
  const derived = (await scrypt(`${pepper}:${secret}`, salt, 32)) as Buffer;
  return `scrypt$v1$${salt}$${derived.toString("base64url")}`;
}

export async function verifyToolSecret(secret: string, pepper: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "scrypt" || parts[1] !== "v1") {
    return false;
  }
  const expected = Buffer.from(parts[3], "base64url");
  const actual = (await scrypt(`${pepper}:${secret}`, parts[2], expected.length)) as Buffer;
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export async function hashOAuthCredentialSecret(secret: string, pepper: string): Promise<string> {
  return hashToolSecret(secret, pepper);
}

export async function verifyOAuthCredentialSecret(secret: string, pepper: string, stored: string): Promise<boolean> {
  return verifyToolSecret(secret, pepper, stored);
}

export function constantTimeEqualString(a: string, b: string): boolean {
  const expected = Buffer.from(a);
  const actual = Buffer.from(b);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function signCookie(value: string, secret: string): string {
  return `${value}.${hmacSha256(secret, value)}`;
}

export function verifySignedCookie(cookieValue: string | undefined, secret: string): string | null {
  if (!cookieValue) {
    return null;
  }
  const separator = cookieValue.lastIndexOf(".");
  if (separator <= 0) {
    return null;
  }
  const value = cookieValue.slice(0, separator);
  const expected = Buffer.from(hmacSha256(secret, value));
  const actual = Buffer.from(cookieValue.slice(separator + 1));
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    return null;
  }
  return value;
}

function aesKeyFromSecret(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

export function encryptJsonPayload(payload: unknown, secret: string): Record<string, unknown> {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", aesKeyFromSecret(secret), iv);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    schema: "access-layer-encrypted-backup",
    version: 1,
    alg: "AES-256-GCM",
    iv: iv.toString("base64url"),
    tag: tag.toString("base64url"),
    ciphertext: ciphertext.toString("base64url")
  };
}

export function decryptJsonPayload(envelope: Record<string, unknown>, secret: string): Record<string, unknown> {
  if (
    envelope.schema !== "access-layer-encrypted-backup" ||
    envelope.version !== 1 ||
    envelope.alg !== "AES-256-GCM" ||
    typeof envelope.iv !== "string" ||
    typeof envelope.tag !== "string" ||
    typeof envelope.ciphertext !== "string"
  ) {
    throw new Error("Invalid encrypted payload");
  }
  const decipher = createDecipheriv("aes-256-gcm", aesKeyFromSecret(secret), Buffer.from(envelope.iv, "base64url"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
    decipher.final()
  ]);
  const parsed = JSON.parse(plaintext.toString("utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid decrypted payload");
  }
  return parsed as Record<string, unknown>;
}

export function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) {
    return {};
  }
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        if (index === -1) {
          return [part, ""];
        }
        return [decodeURIComponent(part.slice(0, index)), decodeURIComponent(part.slice(index + 1))];
      })
  );
}
