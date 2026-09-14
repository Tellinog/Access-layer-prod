import { describe, expect, it } from "vitest";
import { AppError } from "../src/errors.js";
import { MicrosoftEntraOidcClient, validateMicrosoftTokenPayload, type MicrosoftTokenPayloadLike } from "../src/microsoft.js";
import type { Config } from "../src/types.js";

const tenantId = "11111111-1111-4111-8111-111111111111";
const clientId = "33333333-3333-4333-8333-333333333333";
const now = 2_000_000_000;
const validPayload: MicrosoftTokenPayloadLike = {
  iss: `https://login.microsoftonline.com/${tenantId}/v2.0`,
  aud: clientId,
  exp: now + 600,
  tid: tenantId,
  oid: "22222222-2222-4222-8222-222222222222",
  nonce: "nonce-value",
  email: "Tester@Testbirds.com",
  preferred_username: "fallback@testbirds.com",
  name: "Testbirds Tester"
};

function validate(payload: MicrosoftTokenPayloadLike | undefined = validPayload) {
  return validateMicrosoftTokenPayload({
    payload,
    expectedTenantId: tenantId,
    expectedClientId: clientId,
    allowedEmailDomains: ["testbirds.com"],
    correlationId: "corr-microsoft-test",
    nowSeconds: now
  });
}

function expectInvalid(payload: MicrosoftTokenPayloadLike | undefined) {
  try {
    validateMicrosoftTokenPayload({
      payload,
      expectedTenantId: tenantId,
      expectedClientId: clientId,
      allowedEmailDomains: ["testbirds.com"],
      correlationId: "corr-microsoft-test",
      nowSeconds: now
    });
    throw new Error("expected validation failure");
  } catch (error) {
    expect(error).toBeInstanceOf(AppError);
    expect((error as AppError).code).toBe("AUTH_INVALID_MICROSOFT_TOKEN");
  }
}

const config = {
  legacyMicrosoftEnabled: true,
  microsoftTenantId: tenantId,
  microsoftClientId: clientId,
  microsoftClientSecret: "synthetic-client-secret",
  microsoftRedirectUri: "https://access-layer.example.test/v1/auth/microsoft/callback",
  microsoftOidcScope: "openid profile email",
  microsoftAllowedEmailDomains: ["testbirds.com"]
} as Config;

describe("legacy Microsoft Entra identity validation", () => {
  it("maps a verified tenant identity into the approved synthetic legacy identity", () => {
    expect(validate()).toEqual({
      googleSub: `msft:${tenantId}:22222222-2222-4222-8222-222222222222`,
      email: "tester@testbirds.com",
      emailVerified: true,
      hd: "testbirds.com",
      displayName: "Testbirds Tester",
      pictureUrl: null,
      nonce: "nonce-value",
      issuer: `https://login.microsoftonline.com/${tenantId}/v2.0`,
      audience: clientId,
      expiresAt: now + 600
    });
  });

  it("falls back to preferred_username only when it is a usable email", () => {
    const identity = validate({ ...validPayload, email: undefined, preferred_username: "Fallback@Testbirds.com" });
    expect(identity.email).toBe("fallback@testbirds.com");
  });

  it.each([
    ["missing payload", undefined],
    ["wrong issuer", { ...validPayload, iss: "https://login.microsoftonline.com/other/v2.0" }],
    ["wrong audience", { ...validPayload, aud: "other-client" }],
    ["expired token", { ...validPayload, exp: now }],
    ["wrong tenant", { ...validPayload, tid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }],
    ["missing oid", { ...validPayload, oid: undefined }],
    ["missing nonce", { ...validPayload, nonce: undefined }],
    ["missing usable email", { ...validPayload, email: undefined, preferred_username: "not-an-email" }],
    ["external email domain", { ...validPayload, email: "tester@external.example", preferred_username: undefined }]
  ] as const)("rejects %s", (_label, payload) => expectInvalid(payload));

  it("builds only tenant-specific authorization and token requests without Microsoft Graph", async () => {
    let fetchCalls = 0;
    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;
    const fetchMock: typeof fetch = async (requestUrl, requestInit) => {
      fetchCalls += 1;
      capturedUrl = String(requestUrl);
      capturedInit = requestInit;
      return new Response(JSON.stringify({ id_token: "synthetic-id-token" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    };
    const client = new MicrosoftEntraOidcClient(config, {
      fetch: fetchMock,
      verifyIdToken: async () => ({ ...validPayload, exp: Math.floor(Date.now() / 1000) + 600 })
    });
    const authorization = new URL(client.createAuthorizationUrl({
      state: "mst_synthetic-state",
      nonce: "nce_synthetic-nonce",
      loginHint: "tester@testbirds.com"
    }));
    expect(authorization.origin).toBe("https://login.microsoftonline.com");
    expect(authorization.pathname).toBe(`/${tenantId}/oauth2/v2.0/authorize`);
    expect(Object.fromEntries(authorization.searchParams)).toMatchObject({
      client_id: clientId,
      response_type: "code",
      response_mode: "query",
      scope: "openid profile email",
      state: "mst_synthetic-state",
      nonce: "nce_synthetic-nonce",
      prompt: "select_account",
      login_hint: "tester@testbirds.com"
    });

    const identity = await client.exchangeCodeForIdentity("synthetic-code", "corr-adapter");
    expect(identity.googleSub).toMatch(/^msft:/);
    expect(fetchCalls).toBe(1);
    expect(capturedUrl).toBe(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`);
    expect(capturedUrl).not.toContain("graph.microsoft.com");
    expect(String(capturedInit?.body)).toContain("grant_type=authorization_code");
  });

  it("returns only a safe callback error when token exchange fails", async () => {
    const client = new MicrosoftEntraOidcClient(config, {
      fetch: async () => new Response("sensitive-upstream-body", { status: 401 }),
      verifyIdToken: async () => validPayload
    });
    await expect(client.exchangeCodeForIdentity("sensitive-code", "corr-safe"))
      .rejects.toMatchObject({ code: "AUTH_MICROSOFT_CALLBACK_FAILED", correlationId: "corr-safe", details: {} });
  });
});
