import { createHash, createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { lstat, readFile, realpath, stat } from "node:fs/promises";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeProtectedHeader, exportJWK, jwtVerify, SignJWT, type JWTPayload } from "jose";
import { randomToken } from "../security.js";
import type { OAuthSigningKeyPublicMetadata } from "./types.js";
import {
  isCanonicalOAuthScope,
  isValidOAuthPublicJwk,
  OAUTH_RS256_MIN_MODULUS_BITS,
  validateOAuthSigningKeyLifecycle
} from "./validation.js";

export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 900;
export const OAUTH_SIGNING_KEY_MAX_BYTES = 64 * 1024;
export const OAUTH_VERIFIER_CLOCK_SKEW_SECONDS = 60;

export interface OAuthSigningKeyRecord extends OAuthSigningKeyPublicMetadata {
  protectedPrivateKeyRef: string;
}

export interface OAuthAccessTokenClaims extends JWTPayload {
  iss: string;
  sub: string;
  aud: string;
  client_id: string;
  iat: number;
  exp: number;
  jti: string;
  scope: string;
  principal_type: "human";
  sid: string;
}

export class OAuthSigningUnavailableError extends Error {
  constructor() {
    super("OAuth signing is unavailable");
    this.name = "OAuthSigningUnavailableError";
  }
}

function failSigning(): never {
  throw new OAuthSigningUnavailableError();
}

export function canonicalOAuthPublicFingerprint(publicJwk: Record<string, unknown>): string {
  if (typeof publicJwk.e !== "string" || typeof publicJwk.n !== "string") return failSigning();
  const canonical = JSON.stringify({ e: publicJwk.e, kty: "RSA", n: publicJwk.n });
  return createHash("sha256").update(canonical).digest("hex");
}

function pathFromReference(reference: string): string {
  if (/%(?:2e|2f|5c)/i.test(reference) || /[\r\n\0]/.test(reference)) return failSigning();
  if (reference.startsWith("file:")) {
    try {
      const url = new URL(reference);
      if (url.protocol !== "file:" || url.hostname || url.search || url.hash) return failSigning();
      return fileURLToPath(url);
    } catch {
      return failSigning();
    }
  }
  if (!isAbsolute(reference)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(reference)) return failSigning();
    return failSigning();
  }
  return reference;
}

function isInsideRoot(root: string, candidate: string): boolean {
  const pathFromRoot = relative(root, candidate);
  return pathFromRoot === "" || (!pathFromRoot.startsWith(`..${sep}`) && pathFromRoot !== ".." && !isAbsolute(pathFromRoot));
}

async function resolveLegacyPath(legacyPath: string | undefined): Promise<string | null> {
  if (!legacyPath || !isAbsolute(legacyPath)) return null;
  try {
    return await realpath(legacyPath);
  } catch {
    return resolve(legacyPath);
  }
}

export async function loadOAuthPrivateSigningKey(input: {
  root: string | undefined;
  legacyPrivateKeyPath?: string;
  legacyPrivateKeyPem?: string;
  key: OAuthSigningKeyRecord;
}): Promise<KeyObject> {
  try {
    if (!input.root || !isAbsolute(input.root)) return failSigning();
    const configuredPath = pathFromReference(input.key.protectedPrivateKeyRef);
    const canonicalRoot = await realpath(input.root);
    const unresolvedCandidate = resolve(configuredPath);
    if (!isInsideRoot(canonicalRoot, unresolvedCandidate)) return failSigning();

    const candidateLstat = await lstat(unresolvedCandidate);
    if (!candidateLstat.isFile() && !candidateLstat.isSymbolicLink()) return failSigning();
    const canonicalCandidate = await realpath(unresolvedCandidate);
    if (!isInsideRoot(canonicalRoot, canonicalCandidate)) return failSigning();
    const candidateStat = await stat(canonicalCandidate);
    if (!candidateStat.isFile() || candidateStat.size === 0 || candidateStat.size > OAUTH_SIGNING_KEY_MAX_BYTES) {
      return failSigning();
    }

    const legacyPath = await resolveLegacyPath(input.legacyPrivateKeyPath);
    if (
      (legacyPath !== null && canonicalCandidate === legacyPath) ||
      /access-layer-jwt-private/i.test(basename(canonicalCandidate))
    ) return failSigning();

    const pem = await readFile(canonicalCandidate, "utf8");
    const privateKey = createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== "rsa") return failSigning();
    const modulusLength = privateKey.asymmetricKeyDetails?.modulusLength ?? 0;
    if (modulusLength < OAUTH_RS256_MIN_MODULUS_BITS) return failSigning();

    if (!isValidOAuthPublicJwk(input.key.publicJwk, input.key.kid)) return failSigning();
    const derived = await exportJWK(createPublicKey(privateKey));
    if (derived.kty !== "RSA" || derived.n !== input.key.publicJwk.n || derived.e !== input.key.publicJwk.e) {
      return failSigning();
    }
    const legacyPrivateKeyPem = input.legacyPrivateKeyPem ??
      (legacyPath === null ? undefined : await readFile(legacyPath, "utf8"));
    if (legacyPrivateKeyPem) {
      const legacyPrivateKey = createPrivateKey(legacyPrivateKeyPem);
      if (legacyPrivateKey.asymmetricKeyType !== "rsa") return failSigning();
      const legacyPublic = await exportJWK(createPublicKey(legacyPrivateKey));
      if (legacyPublic.kty === "RSA" && legacyPublic.n === derived.n && legacyPublic.e === derived.e) {
        return failSigning();
      }
    }
    if (canonicalOAuthPublicFingerprint(input.key.publicJwk) !== input.key.publicKeyFingerprintSha256) {
      return failSigning();
    }
    return privateKey;
  } catch (error) {
    if (error instanceof OAuthSigningUnavailableError) throw error;
    return failSigning();
  }
}

export function selectOAuthSigningKey(
  records: readonly OAuthSigningKeyRecord[],
  now: Date
): OAuthSigningKeyRecord {
  if (!Number.isFinite(now.getTime())) return failSigning();
  const signable = records.filter((record) =>
    record.algorithm === "RS256" &&
    record.status === "active" &&
    record.activatesAt !== null &&
    record.activatesAt.getTime() <= now.getTime() &&
    record.retireAfter === null &&
    validateOAuthSigningKeyLifecycle(record).length === 0 &&
    isValidOAuthPublicJwk(record.publicJwk, record.kid)
  );
  if (signable.length !== 1) return failSigning();
  return signable[0];
}

export class OAuthAccessTokenSigner {
  constructor(private readonly input: {
    issuer: string;
    signingKeyRoot?: string;
    legacyPrivateKeyPath?: string;
    legacyPrivateKeyPem?: string;
  }) {}

  async issue(input: {
    key: OAuthSigningKeyRecord;
    subject: string;
    audience: string;
    clientId: string;
    scopes: string[];
    sessionId: string;
    now: Date;
  }): Promise<{ token: string; claims: OAuthAccessTokenClaims; expiresAt: Date }> {
    if (
      !input.subject || !input.clientId || !input.sessionId ||
      input.scopes.length === 0 || new Set(input.scopes).size !== input.scopes.length ||
      input.scopes.some((scope) => !isCanonicalOAuthScope(scope))
    ) return failSigning();
    const privateKey = await loadOAuthPrivateSigningKey({
      root: this.input.signingKeyRoot,
      legacyPrivateKeyPath: this.input.legacyPrivateKeyPath,
      legacyPrivateKeyPem: this.input.legacyPrivateKeyPem,
      key: input.key
    });
    const issuedAt = Math.floor(input.now.getTime() / 1000);
    if (!Number.isFinite(issuedAt)) return failSigning();
    const expiresAtSeconds = issuedAt + OAUTH_ACCESS_TOKEN_TTL_SECONDS;
    const jti = randomToken("oauth_jti_", 18);
    const scope = input.scopes.join(" ");
    const token = await new SignJWT({
      client_id: input.clientId,
      scope,
      principal_type: "human",
      sid: input.sessionId
    })
      .setProtectedHeader({ alg: "RS256", kid: input.key.kid, typ: "at+jwt" })
      .setIssuer(this.input.issuer)
      .setSubject(input.subject)
      .setAudience(input.audience)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAtSeconds)
      .setJti(jti)
      .sign(privateKey);
    return {
      token,
      expiresAt: new Date(expiresAtSeconds * 1000),
      claims: {
        iss: this.input.issuer,
        sub: input.subject,
        aud: input.audience,
        client_id: input.clientId,
        iat: issuedAt,
        exp: expiresAtSeconds,
        jti,
        scope,
        principal_type: "human",
        sid: input.sessionId
      }
    };
  }
}

const FORBIDDEN_ACCESS_TOKEN_CLAIMS = ["email", "hd", "display_name", "picture_url", "role", "permissions"];

export async function verifyOAuthAccessToken(input: {
  token: string;
  issuer: string;
  audience: string;
  keys: readonly OAuthSigningKeyPublicMetadata[];
  now: Date;
}): Promise<OAuthAccessTokenClaims> {
  try {
    const header = decodeProtectedHeader(input.token);
    if (header.alg !== "RS256" || header.typ !== "at+jwt" || typeof header.kid !== "string" || !header.kid) {
      return failSigning();
    }
    const matching = input.keys.filter((key) =>
      key.kid === header.kid && key.algorithm === "RS256" && key.status === "active" &&
      key.activatesAt !== null && key.activatesAt.getTime() <= input.now.getTime() &&
      (key.retireAfter === null || key.retireAfter.getTime() > input.now.getTime()) &&
      validateOAuthSigningKeyLifecycle(key).length === 0 && isValidOAuthPublicJwk(key.publicJwk, key.kid)
    );
    if (matching.length !== 1) return failSigning();
    const publicKey = createPublicKey({ key: matching[0].publicJwk, format: "jwk" });
    const verified = await jwtVerify(input.token, publicKey, {
      algorithms: ["RS256"],
      typ: "at+jwt",
      issuer: input.issuer,
      audience: input.audience,
      clockTolerance: OAUTH_VERIFIER_CLOCK_SKEW_SECONDS,
      currentDate: input.now
    });
    const claims = verified.payload as Partial<OAuthAccessTokenClaims>;
    if (
      typeof claims.iss !== "string" || typeof claims.sub !== "string" || typeof claims.aud !== "string" ||
      typeof claims.client_id !== "string" || typeof claims.iat !== "number" || typeof claims.exp !== "number" ||
      !Number.isFinite(claims.iat) || !Number.isFinite(claims.exp) ||
      !Number.isInteger(claims.iat) || !Number.isInteger(claims.exp) ||
      claims.iat > Math.floor(input.now.getTime() / 1000) + OAUTH_VERIFIER_CLOCK_SKEW_SECONDS ||
      typeof claims.jti !== "string" || typeof claims.scope !== "string" || claims.principal_type !== "human" ||
      typeof claims.sid !== "string" || claims.exp - claims.iat !== OAUTH_ACCESS_TOKEN_TTL_SECONDS ||
      FORBIDDEN_ACCESS_TOKEN_CLAIMS.some((name) => Object.hasOwn(claims, name))
    ) return failSigning();
    const scopes = claims.scope.split(" ");
    if (scopes.length === 0 || new Set(scopes).size !== scopes.length || scopes.some((scope) => !isCanonicalOAuthScope(scope))) {
      return failSigning();
    }
    return claims as OAuthAccessTokenClaims;
  } catch (error) {
    if (error instanceof OAuthSigningUnavailableError) throw error;
    return failSigning();
  }
}
