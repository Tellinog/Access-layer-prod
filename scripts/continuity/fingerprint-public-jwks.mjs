#!/usr/bin/env node
/** Fetch a public JWKS and emit public key ids/fingerprints only. */

import { createHash } from "node:crypto";
import process from "node:process";
import { pathToFileURL } from "node:url";

const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

function canonicalPublicMembers(jwk) {
  if (jwk.kty === "RSA" && typeof jwk.e === "string" && typeof jwk.n === "string") {
    return { e: jwk.e, kty: "RSA", n: jwk.n };
  }
  if (jwk.kty === "EC" && typeof jwk.crv === "string" && typeof jwk.x === "string" && typeof jwk.y === "string") {
    return { crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y };
  }
  if (jwk.kty === "OKP" && typeof jwk.crv === "string" && typeof jwk.x === "string") {
    return { crv: jwk.crv, kty: "OKP", x: jwk.x };
  }
  throw new Error("unsupported or incomplete public JWK");
}

export function fingerprintPublicJwk(jwk) {
  if (!jwk || typeof jwk !== "object" || PRIVATE_JWK_MEMBERS.some((name) => name in jwk)) {
    throw new Error("private or symmetric JWK material is forbidden");
  }
  if (typeof jwk.kid !== "string" || jwk.kid.length === 0) throw new Error("public JWK kid is required");
  const canonical = JSON.stringify(canonicalPublicMembers(jwk));
  return {
    kid: jwk.kid,
    kty: jwk.kty,
    alg: typeof jwk.alg === "string" ? jwk.alg : null,
    use: typeof jwk.use === "string" ? jwk.use : null,
    fingerprint_sha256: createHash("sha256").update(canonical).digest("hex"),
  };
}

function validatedUrl(text) {
  const url = new URL(text);
  if (url.username || url.password || url.search || url.hash) throw new Error("JWKS URL must not contain credentials, query, or fragment");
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw new Error("JWKS URL must use HTTPS (HTTP is allowed only on loopback)");
  return url;
}

export async function fetchPublicJwks(urlText) {
  const url = validatedUrl(urlText);
  const response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`JWKS request failed with HTTP ${response.status}`);
  const body = await response.json();
  if (!body || !Array.isArray(body.keys) || body.keys.length === 0) throw new Error("JWKS has no keys");
  const keys = body.keys.map(fingerprintPublicJwk);
  if (new Set(keys.map((key) => key.kid)).size !== keys.length) throw new Error("JWKS contains duplicate kid values");
  return { status: "OBSERVED", observed_at: new Date().toISOString(), source_origin: url.origin, keys };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const index = process.argv.indexOf("--jwks-url");
  if (index < 0 || !process.argv[index + 1]) {
    process.stderr.write("Usage: node fingerprint-public-jwks.mjs --jwks-url https://host/v1/.well-known/jwks.json\n");
    process.exitCode = 1;
  } else {
    try {
      const report = await fetchPublicJwks(process.argv[index + 1]);
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    } catch (error) {
      // Error messages are authored by this script and never contain response bodies.
      process.stderr.write(`JWKS observation failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
      process.exitCode = 2;
    }
  }
}
