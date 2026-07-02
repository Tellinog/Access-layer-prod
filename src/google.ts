import { OAuth2Client, type TokenPayload } from "google-auth-library";
import type { Config, GoogleIdentity } from "./types.js";
import { AppError } from "./errors.js";
import { validateGoogleTokenPayload } from "./google-claims.js";

export interface GoogleOidcClient {
  createAuthorizationUrl(input: { state: string; nonce: string; loginHint?: string }): string;
  exchangeCodeForIdentity(code: string, correlationId: string): Promise<GoogleIdentity>;
}

export class GoogleAuthLibraryOidcClient implements GoogleOidcClient {
  private readonly client: OAuth2Client;

  constructor(private readonly config: Config) {
    this.client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  }

  createAuthorizationUrl(input: { state: string; nonce: string; loginHint?: string }): string {
    return this.client.generateAuthUrl({
      scope: this.config.googleOidcScope,
      response_type: "code",
      state: input.state,
      nonce: input.nonce,
      prompt: "select_account",
      login_hint: input.loginHint
    } as Parameters<OAuth2Client["generateAuthUrl"]>[0]);
  }

  async exchangeCodeForIdentity(code: string, correlationId: string): Promise<GoogleIdentity> {
    let idToken: string | undefined;
    try {
      const response = await this.client.getToken(code);
      idToken = response.tokens.id_token ?? undefined;
    } catch {
      throw new AppError("AUTH_GOOGLE_CALLBACK_FAILED", correlationId);
    }

    if (!idToken) {
      throw new AppError("AUTH_INVALID_GOOGLE_TOKEN", correlationId);
    }

    let payload: TokenPayload | undefined;
    try {
      const ticket = await this.client.verifyIdToken({
        idToken,
        audience: this.config.googleClientId
      });
      payload = ticket.getPayload();
    } catch {
      throw new AppError("AUTH_INVALID_GOOGLE_TOKEN", correlationId);
    }

    return validateGoogleTokenPayload({
      payload,
      expectedAudience: this.config.googleClientId,
      allowedHostedDomains: this.config.googleAllowedHd,
      correlationId
    });
  }
}
