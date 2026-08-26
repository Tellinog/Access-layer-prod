import { Buffer } from "node:buffer";
import { generateKeyPairSync } from "node:crypto";

const { publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2_048,
  publicExponent: 0x10001
});
const generatedPublicJwk = publicKey.export({ format: "jwk" });

if (typeof generatedPublicJwk.n !== "string" || typeof generatedPublicJwk.e !== "string") {
  throw new Error("Synthetic RSA public JWK generation failed");
}

export const SYNTHETIC_RSA_2048_PUBLIC_NUMBERS = Object.freeze({
  n: generatedPublicJwk.n,
  e: generatedPublicJwk.e
});

export function withRedundantLeadingZero(value: string): string {
  return Buffer.concat([Buffer.from([0]), Buffer.from(value, "base64url")]).toString("base64url");
}
