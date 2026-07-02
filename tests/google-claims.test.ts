import { describe, expect, it } from "vitest";
import { AppError } from "../src/errors.js";
import { validateGoogleTokenPayload, type GoogleTokenPayloadLike } from "../src/google-claims.js";

const basePayload: GoogleTokenPayloadLike = {
  sub: "110000000000000000000",
  email: "mario.rossi@unguess.io",
  email_verified: true,
  hd: "unguess.io",
  name: "Mario Rossi",
  picture: "https://example.test/photo.jpg",
  nonce: "nonce-value",
  iss: "https://accounts.google.com",
  aud: "client-id.apps.googleusercontent.com",
  exp: 2000
};

function validate(overrides: GoogleTokenPayloadLike = {}) {
  return validateGoogleTokenPayload({
    payload: { ...basePayload, ...overrides },
    expectedAudience: "client-id.apps.googleusercontent.com",
    allowedHostedDomains: ["unguess.io"],
    correlationId: "corr-test",
    nowSeconds: 1000
  });
}

function expectCode(fn: () => unknown, code: string) {
  expect(fn).toThrow(AppError);
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(AppError);
    expect((error as AppError).code).toBe(code);
  }
}

describe("Google token claim validation", () => {
  it("accepts a complete valid Workspace identity", () => {
    expect(validate()).toMatchObject({
      googleSub: basePayload.sub,
      email: basePayload.email,
      emailVerified: true,
      hd: "unguess.io",
      issuer: "https://accounts.google.com",
      audience: "client-id.apps.googleusercontent.com"
    });
  });

  it("allows the Nuoto Uno Stile di Vita hosted domain when configured", () => {
    const identity = validateGoogleTokenPayload({
      payload: { ...basePayload, email: "lorenzo@nuotounostiledivita.it", hd: "nuotounostiledivita.it" },
      expectedAudience: "client-id.apps.googleusercontent.com",
      allowedHostedDomains: ["unguess.io", "nuotounostiledivita.it"],
      correlationId: "corr-1",
      nowSeconds: 1000
    });

    expect(identity.hd).toBe("nuotounostiledivita.it");
    expect(identity.email).toBe("lorenzo@nuotounostiledivita.it");
  });

  it("denies missing or wrong hosted domain", () => {
    expectCode(() => validate({ hd: undefined }), "AUTH_EXTERNAL_DOMAIN");
    expectCode(() => validate({ hd: "gmail.com" }), "AUTH_EXTERNAL_DOMAIN");
  });

  it("denies unverified email", () => {
    expectCode(() => validate({ email_verified: false }), "AUTH_EMAIL_NOT_VERIFIED");
  });

  it("denies wrong audience, issuer and expiration", () => {
    expectCode(() => validate({ aud: "other-client.apps.googleusercontent.com" }), "AUTH_INVALID_GOOGLE_TOKEN");
    expectCode(() => validate({ iss: "https://evil.example" }), "AUTH_INVALID_GOOGLE_TOKEN");
    expectCode(() => validate({ exp: 999 }), "AUTH_INVALID_GOOGLE_TOKEN");
  });

  it("accepts audience arrays that contain the configured client id", () => {
    expect(validate({ aud: ["other", "client-id.apps.googleusercontent.com"] }).audience).toBe("client-id.apps.googleusercontent.com");
  });
});
