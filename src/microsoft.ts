import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { AppError } from "./errors.js";
import type { Config, MicrosoftIdentity } from "./types.js";
import { normalizeEmail, validateEmail } from "./validation.js";

export interface MicrosoftOidcClient {
  createAuthorizationUrl(input: { state: string; nonce: string; loginHint?: string }): string;
  exchangeCodeForIdentity(code: string, correlationId: string): Promise<MicrosoftIdentity>;
}

export interface MicrosoftTokenPayloadLike extends JWTPayload {
  tid?: unknown;
  oid?: unknown;
  email?: unknown;
  preferred_username?: unknown;
  name?: unknown;
  nonce?: unknown;
}

interface MicrosoftClientOptions {
  fetch?: typeof fetch;
  verifyIdToken?: (idToken: string) => Promise<MicrosoftTokenPayloadLike>;
}

function requiredMicrosoftConfig(config: Config) {
  if (!config.microsoftTenantId || !config.microsoftClientId || !config.microsoftClientSecret ||
      !config.microsoftRedirectUri || !config.microsoftAllowedEmailDomains?.length) {
    throw new Error("Microsoft OIDC client requires enabled legacy Microsoft configuration");
  }
  return {
    tenantId: config.microsoftTenantId,
    clientId: config.microsoftClientId,
    clientSecret: config.microsoftClientSecret,
    redirectUri: config.microsoftRedirectUri,
    scope: config.microsoftOidcScope ?? "openid profile email",
    allowedEmailDomains: config.microsoftAllowedEmailDomains
  };
}

export function validateMicrosoftTokenPayload(input: {
  payload: MicrosoftTokenPayloadLike | undefined;
  expectedTenantId: string;
  expectedClientId: string;
  allowedEmailDomains: string[];
  correlationId: string;
  nowSeconds?: number;
}): MicrosoftIdentity {
  const { payload, correlationId } = input;
  const expectedTenantId = input.expectedTenantId.toLowerCase();
  const expectedIssuer = `https://login.microsoftonline.com/${expectedTenantId}/v2.0`;
  const audiences = typeof payload?.aud === "string" ? [payload.aud] : Array.isArray(payload?.aud) ? payload.aud : [];
  const tenantId = typeof payload?.tid === "string" ? payload.tid.trim().toLowerCase() : "";
  const objectId = typeof payload?.oid === "string" ? payload.oid.trim().toLowerCase() : "";
  const nonce = typeof payload?.nonce === "string" ? payload.nonce : "";
  const expiresAt = typeof payload?.exp === "number" ? payload.exp : 0;

  if (payload?.iss !== expectedIssuer || !audiences.includes(input.expectedClientId) ||
      expiresAt <= (input.nowSeconds ?? Math.floor(Date.now() / 1000)) || tenantId !== expectedTenantId ||
      objectId === "" || nonce === "") {
    throw new AppError("AUTH_INVALID_MICROSOFT_TOKEN", correlationId);
  }

  const rawEmail = [payload.email, payload.preferred_username]
    .find((value): value is string => typeof value === "string" && validateEmail(value.trim()));
  if (!rawEmail) {
    throw new AppError("AUTH_INVALID_MICROSOFT_TOKEN", correlationId);
  }
  const email = normalizeEmail(rawEmail);
  const emailDomain = email.slice(email.lastIndexOf("@") + 1);
  if (!input.allowedEmailDomains.includes(emailDomain)) {
    throw new AppError("AUTH_INVALID_MICROSOFT_TOKEN", correlationId);
  }

  return {
    googleSub: `msft:${tenantId}:${objectId}`,
    email,
    emailVerified: true,
    hd: emailDomain,
    displayName: typeof payload.name === "string" && payload.name.trim() !== "" ? payload.name : null,
    pictureUrl: null,
    nonce,
    issuer: expectedIssuer,
    audience: input.expectedClientId,
    expiresAt
  };
}

export class MicrosoftEntraOidcClient implements MicrosoftOidcClient {
  private readonly values: ReturnType<typeof requiredMicrosoftConfig>;
  private readonly fetchFn: typeof fetch;
  private readonly verifyIdToken: (idToken: string) => Promise<MicrosoftTokenPayloadLike>;

  constructor(config: Config, options: MicrosoftClientOptions = {}) {
    this.values = requiredMicrosoftConfig(config);
    this.fetchFn = options.fetch ?? fetch;
    if (options.verifyIdToken) {
      this.verifyIdToken = options.verifyIdToken;
    } else {
      const jwks = createRemoteJWKSet(
        new URL(`https://login.microsoftonline.com/${this.values.tenantId}/discovery/v2.0/keys`)
      );
      this.verifyIdToken = async (idToken) => {
        const verified = await jwtVerify(idToken, jwks, {
          algorithms: ["RS256"],
          issuer: `https://login.microsoftonline.com/${this.values.tenantId}/v2.0`,
          audience: this.values.clientId
        });
        return verified.payload;
      };
    }
  }

  createAuthorizationUrl(input: { state: string; nonce: string; loginHint?: string }): string {
    const url = new URL(`https://login.microsoftonline.com/${this.values.tenantId}/oauth2/v2.0/authorize`);
    url.search = new URLSearchParams({
      client_id: this.values.clientId,
      response_type: "code",
      redirect_uri: this.values.redirectUri,
      response_mode: "query",
      scope: this.values.scope,
      state: input.state,
      nonce: input.nonce,
      prompt: "select_account"
    }).toString();
    if (input.loginHint) {
      url.searchParams.set("login_hint", input.loginHint);
    }
    return url.toString();
  }

  async exchangeCodeForIdentity(code: string, correlationId: string): Promise<MicrosoftIdentity> {
    let idToken: string;
    try {
      const response = await this.fetchFn(
        `https://login.microsoftonline.com/${this.values.tenantId}/oauth2/v2.0/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
          body: new URLSearchParams({
            client_id: this.values.clientId,
            client_secret: this.values.clientSecret,
            grant_type: "authorization_code",
            code,
            redirect_uri: this.values.redirectUri,
            scope: this.values.scope
          }).toString()
        }
      );
      if (!response.ok) {
        throw new Error("Microsoft token endpoint rejected the request");
      }
      const body = await response.json() as { id_token?: unknown };
      if (typeof body.id_token !== "string" || body.id_token === "") {
        throw new Error("Microsoft token endpoint omitted the ID token");
      }
      idToken = body.id_token;
    } catch {
      throw new AppError("AUTH_MICROSOFT_CALLBACK_FAILED", correlationId);
    }

    let payload: MicrosoftTokenPayloadLike;
    try {
      payload = await this.verifyIdToken(idToken);
    } catch {
      throw new AppError("AUTH_INVALID_MICROSOFT_TOKEN", correlationId);
    }
    return validateMicrosoftTokenPayload({
      payload,
      expectedTenantId: this.values.tenantId,
      expectedClientId: this.values.clientId,
      allowedEmailDomains: this.values.allowedEmailDomains,
      correlationId
    });
  }
}
