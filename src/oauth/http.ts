import type { FastifyInstance, FastifyReply } from "fastify";
import { randomUUID } from "node:crypto";
import type { AuditLogger } from "../audit.js";
import type { OAuthUpstreamGoogleClient } from "./google.js";
import type { OAuthAuthorizationFlowRepository } from "./flow-repository.js";
import type { Repositories } from "../repositories.js";
import { hashRequestField } from "../security.js";
import type { Config } from "../types.js";
import type { OAuthFoundationRepository } from "./repository.js";
import { selectOAuthJwks } from "./jwks.js";
import { buildOAuthProtectedResourceMetadata } from "./metadata.js";
import { OAuthAuthorizationService, type OAuthAuthorizationResult } from "./authorization.js";
import { OAUTH_CLIENT_ID_REGEX } from "./validation.js";

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

function sendAuthorizationResult(
  reply: FastifyReply,
  result: OAuthAuthorizationResult
) {
  reply.header("Cache-Control", "no-store");
  if (result.kind === "redirect") return reply.redirect(result.location);
  return reply.status(result.error === "temporarily_unavailable" ? 503 : 400).send({
    error: result.error,
    correlation_id: result.correlationId
  });
}

export function registerOAuthAuthorizationHttp(
  app: FastifyInstance,
  input: {
    config: Config;
    repository: OAuthFoundationRepository;
    flowRepository: OAuthAuthorizationFlowRepository;
    repositories: Repositories;
    audit: AuditLogger;
    google: OAuthUpstreamGoogleClient;
  }
): void {
  if (!input.config.oauthP0Enabled) return;
  const service = new OAuthAuthorizationService({
    config: input.config,
    foundation: input.repository,
    flow: input.flowRepository,
    legacy: input.repositories,
    audit: input.audit,
    google: input.google
  });
  const authorizeRateLimit = app.createRateLimit({
    max: 30,
    timeWindow: "1 minute",
    keyGenerator: (request) => {
      const query = request.query as Record<string, unknown>;
      const rawClientId = typeof query.client_id === "string" ? query.client_id : "";
      const clientId = OAUTH_CLIENT_ID_REGEX.test(rawClientId) ? rawClientId : "unknown-client";
      return `oauth-authorize:${hashRequestField(request.ip, input.config.logIpSalt) ?? "unknown-ip"}:${clientId}`;
    }
  });
  const callbackRateLimit = app.createRateLimit({
    max: 60,
    timeWindow: "1 minute",
    keyGenerator: (request) =>
      `oauth-google-callback:${hashRequestField(request.ip, input.config.logIpSalt) ?? "unknown-ip"}`
  });
  const routeOptions = { exposeHeadRoute: false, logLevel: "silent" as const };

  app.get("/oauth/authorize", {
    ...routeOptions,
    preHandler: async (request, reply) => {
      const result = await authorizeRateLimit(request);
      if (!result.isAllowed && (result.isExceeded || result.isBanned)) {
        return reply.header("Cache-Control", "no-store").status(429).send({ error: "temporarily_unavailable" });
      }
    }
  }, async (request, reply) => {
    const context = {
      correlationId: randomUUID(),
      requestIpHash: hashRequestField(request.ip, input.config.logIpSalt),
      userAgentHash: hashRequestField(request.headers["user-agent"], input.config.logIpSalt)
    };
    try {
      return sendAuthorizationResult(reply, await service.authorize(request.query as Record<string, unknown>, context));
    } catch {
      return sendAuthorizationResult(reply, {
        kind: "local_error",
        error: "server_error",
        correlationId: context.correlationId
      });
    }
  });

  app.get("/oauth/upstream/google/callback", {
    ...routeOptions,
    preHandler: async (request, reply) => {
      const result = await callbackRateLimit(request);
      if (!result.isAllowed && (result.isExceeded || result.isBanned)) {
        return reply.header("Cache-Control", "no-store").status(429).send({ error: "temporarily_unavailable" });
      }
    }
  }, async (request, reply) => {
    const context = {
      correlationId: randomUUID(),
      requestIpHash: hashRequestField(request.ip, input.config.logIpSalt),
      userAgentHash: hashRequestField(request.headers["user-agent"], input.config.logIpSalt)
    };
    try {
      return sendAuthorizationResult(reply, await service.callback(request.query as Record<string, unknown>, context));
    } catch {
      return sendAuthorizationResult(reply, {
        kind: "local_error",
        error: "server_error",
        correlationId: context.correlationId
      });
    }
  });
}
