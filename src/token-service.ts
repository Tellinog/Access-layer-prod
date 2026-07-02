import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { exportJWK, jwtVerify, SignJWT, type JWTPayload } from "jose";
import type { AuthorizationGrant, Config, Session, Tool, User } from "./types.js";
import { randomToken } from "./security.js";

export interface AccessLayerClaims extends JWTPayload {
  sub: string;
  sid: string;
  tool_slug: string;
  email: string;
  hd: string;
  permissions: string[];
  role: string;
}

export class TokenService {
  private privateKey!: KeyObject;
  private publicKey!: KeyObject;
  private jwks!: { keys: Array<Record<string, unknown>> };

  constructor(private readonly config: Config) {}

  async init(): Promise<void> {
    if (this.config.jwtPrivateKeyPem) {
      this.privateKey = createPrivateKey(this.config.jwtPrivateKeyPem);
      this.publicKey = createPublicKey(this.privateKey);
    } else if (this.config.appEnv === "test") {
      const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
    } else {
      throw new Error("JWT private key is not configured");
    }

    const jwk = await exportJWK(this.publicKey);
    this.jwks = {
      keys: [
        {
          ...jwk,
          kid: this.config.jwtPublicKeyId,
          use: "sig",
          alg: "RS256"
        }
      ]
    };
  }

  getJwks(): { keys: Array<Record<string, unknown>> } {
    return this.jwks;
  }

  async issueAccessToken(input: { user: User; tool: Tool; grant: AuthorizationGrant; session: Session }): Promise<{
    token: string;
    expiresAt: Date;
    expiresIn: number;
    jti: string;
  }> {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = this.config.accessTokenTtlSeconds;
    const expiresAt = new Date((now + expiresIn) * 1000);
    const jti = randomToken("jti_", 18);
    const token = await new SignJWT({
      sid: input.session.id,
      tool_slug: input.tool.slug,
      email: input.user.email,
      hd: input.user.hd,
      permissions: input.grant.permissions,
      role: input.grant.role
    })
      .setProtectedHeader({ alg: "RS256", kid: this.config.jwtPublicKeyId, typ: "JWT" })
      .setIssuer(this.config.authIssuer)
      .setSubject(input.user.google_sub)
      .setAudience(input.tool.slug)
      .setIssuedAt(now)
      .setExpirationTime(now + expiresIn)
      .setJti(jti)
      .sign(this.privateKey);

    return { token, expiresAt, expiresIn, jti };
  }

  async verifyAccessToken(token: string, audience?: string): Promise<AccessLayerClaims> {
    const result = await jwtVerify(token, this.publicKey, {
      issuer: this.config.authIssuer,
      audience
    });
    return result.payload as AccessLayerClaims;
  }
}
