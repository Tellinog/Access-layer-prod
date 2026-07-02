import { AppError } from "./errors.js";
import type { GoogleIdentity } from "./types.js";
import { isAllowedHostedDomain } from "./validation.js";

export interface GoogleTokenPayloadLike {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  hd?: string;
  name?: string;
  picture?: string;
  nonce?: unknown;
  iss?: string;
  aud?: string | string[];
  exp?: number;
}

export function validateGoogleTokenPayload(input: {
  payload: GoogleTokenPayloadLike | undefined;
  expectedAudience: string;
  allowedHostedDomains: string[];
  correlationId: string;
  nowSeconds?: number;
}): GoogleIdentity {
  const { payload, expectedAudience, allowedHostedDomains, correlationId } = input;
  if (!payload?.sub || !payload.email || !payload.iss || !payload.aud || !payload.exp) {
    throw new AppError("AUTH_INVALID_GOOGLE_TOKEN", correlationId);
  }

  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(expectedAudience)) {
    throw new AppError("AUTH_INVALID_GOOGLE_TOKEN", correlationId);
  }

  if (payload.iss !== "accounts.google.com" && payload.iss !== "https://accounts.google.com") {
    throw new AppError("AUTH_INVALID_GOOGLE_TOKEN", correlationId);
  }

  if (payload.exp <= (input.nowSeconds ?? Math.floor(Date.now() / 1000))) {
    throw new AppError("AUTH_INVALID_GOOGLE_TOKEN", correlationId);
  }

  if (payload.email_verified !== true) {
    throw new AppError("AUTH_EMAIL_NOT_VERIFIED", correlationId);
  }

  if (!isAllowedHostedDomain(payload.hd, allowedHostedDomains)) {
    throw new AppError("AUTH_EXTERNAL_DOMAIN", correlationId);
  }

  return {
    googleSub: payload.sub,
    email: payload.email,
    emailVerified: true,
    hd: payload.hd!,
    displayName: payload.name ?? null,
    pictureUrl: payload.picture ?? null,
    nonce: typeof payload.nonce === "string" ? payload.nonce : null,
    issuer: payload.iss,
    audience: expectedAudience,
    expiresAt: payload.exp
  };
}
