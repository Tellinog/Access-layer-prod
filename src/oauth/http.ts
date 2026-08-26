import type { FastifyInstance } from "fastify";
import type { Config } from "../types.js";
import type { OAuthFoundationRepository } from "./repository.js";
import { selectOAuthJwks } from "./jwks.js";
import { buildOAuthProtectedResourceMetadata } from "./metadata.js";

export const OAUTH_JWKS_CACHE_CONTROL = "public, max-age=300";
export const OAUTH_PROTECTED_RESOURCE_NAME = "Access Layer API target metadata (OAuth disabled)";

export function registerOAuthReadOnlyHttp(
  app: FastifyInstance,
  input: { config: Config; repository: OAuthFoundationRepository }
): void {
  if (!input.config.oauthP0Enabled) return;

  app.get("/oauth/jwks", { exposeHeadRoute: false }, async (_request, reply) => {
    try {
      const jwks = selectOAuthJwks(await input.repository.listSigningKeyPublicMetadata());
      if (jwks.keys.length === 0) {
        return reply
          .header("Cache-Control", "no-store")
          .status(503)
          .send({ error: "temporarily_unavailable" });
      }
      return reply.header("Cache-Control", OAUTH_JWKS_CACHE_CONTROL).send(jwks);
    } catch {
      return reply
        .header("Cache-Control", "no-store")
        .status(503)
        .send({ error: "temporarily_unavailable" });
    }
  });

  app.get("/.well-known/oauth-protected-resource/v1", { exposeHeadRoute: false }, async () =>
    buildOAuthProtectedResourceMetadata({
      resource: `${input.config.appBaseUrl.replace(/\/+$/, "")}/v1`,
      authorizationServer: input.config.authIssuer,
      scopesSupported: [],
      resourceName: OAUTH_PROTECTED_RESOURCE_NAME
    })
  );
}
