import Fastify, {
  type FastifyReply,
  type FastifyInstance,
  type FastifyRequest,
  type RouteHandlerMethod
} from "fastify";
import { readFileSync } from "node:fs";
import rateLimit from "@fastify/rate-limit";
import type {
  AccessRequestStatus,
  Config,
  AdminActor,
  AuthorizationGrant,
  GrantStatus,
  Outcome,
  Tool,
  ToolClient,
  ToolStatus,
  User,
  UserStatus,
  LegacyIdentity,
  AuthRequest
} from "./types.js";
import { AuditLogger } from "./audit.js";
import { AppError, escapeHtml, safeErrorPage, sendJsonError, type ErrorCode } from "./errors.js";
import type { GoogleOidcClient } from "./google.js";
import type { MicrosoftOidcClient } from "./microsoft.js";
import { hasPermission, rolePermissions } from "./permissions.js";
import { Repositories } from "./repositories.js";
import {
  hashOpaque,
  hashRequestField,
  hashToolSecret,
  constantTimeEqualString,
  decryptJsonPayload,
  encryptJsonPayload,
  parseCookies,
  randomToken,
  sha256,
  signCookie,
  verifySignedCookie,
  verifyToolSecret
} from "./security.js";
import { TokenService } from "./token-service.js";
import {
  normalizeEmail,
  isAllowedPendingGrantEmail,
  validatePermissions,
  validateReturnUrlExact,
  validateState,
  validateToolSlug
} from "./validation.js";

const ADMIN_TOOL_SLUG = "access-admin";
const AUDIT_OUTCOMES = ["success", "denied", "error", "info"] as const;
const BACKUP_SCHEMA = "access-layer-backup";
const BACKUP_VERSION = 1;
const FAVICON_SVG = readFileSync(new URL("../assets/ui/favicon.svg", import.meta.url), "utf8");


function joinPublicPath(basePath: string, path = ""): string {
  const normalizedPath = path === "" ? "" : path.startsWith("/") ? path : `/${path}`;
  const joined = `${basePath}${normalizedPath}`;
  return joined === "" ? "/" : joined;
}

function apiPath(config: Config, path: string): string {
  return joinPublicPath(config.publicBasePath, path);
}

function adminUiPath(config: Config, path = ""): string {
  return config.publicBasePath ? joinPublicPath(config.publicBasePath, path) : joinPublicPath("/admin", path);
}

function adminCookiePath(config: Config): string {
  return config.publicBasePath || "/";
}

function adminRefreshCookieName(config: Config): string {
  return `${config.sessionCookieName}_refresh`;
}

function publicUrl(config: Config, path: string): string {
  return `${config.appBaseUrl.replace(/\/+$/, "")}${path}`;
}


export interface AppDependencies {
  config: Config;
  repositories: Repositories;
  audit: AuditLogger;
  google: GoogleOidcClient;
  microsoft?: MicrosoftOidcClient;
  tokenService: TokenService;
}

interface RequestContext {
  correlationId: string;
  requestIpHash: string | null;
  userAgentHash: string | null;
}

type BulkGrantAction = "upsert" | "revoke";
type BulkGrantResult = "ok" | "warning" | "error";
type BulkGrantOperation = "create" | "update" | "revoke" | "skip";

interface BulkGrantInputRow {
  row: number;
  email: string;
  tool_slug: string;
  role: string;
  permissions: string[];
  valid_until: string | null;
  action: BulkGrantAction | null;
  note: string | null;
}

interface BulkGrantPreviewRow extends BulkGrantInputRow {
  result: BulkGrantResult;
  reason: string | null;
  resolved_user: "known_user" | "pending_user_link" | null;
  status_after: GrantStatus | null;
  existing_grant_id?: string | null;
  operation?: BulkGrantOperation;
  tool_id?: string;
  user_id?: string | null;
}

interface BulkGrantSummary {
  total_rows: number;
  ok: number;
  warning: number;
  error: number;
  created?: number;
  updated?: number;
  revoked?: number;
  skipped?: number;
}

interface AuthenticatedToolClient {
  client: ToolClient;
  tool: Tool;
}

type AuthCallbackResult =
  | { error: AppError }
  | { tool: Tool; codeValue: string; toolState: string };

type RateLimitCheck = ReturnType<FastifyInstance["createRateLimit"]>;

export async function buildApp(deps: AppDependencies): Promise<FastifyInstance> {
  if (deps.config.legacyMicrosoftEnabled && !deps.microsoft) {
    throw new Error("Legacy Microsoft is enabled but no Microsoft OIDC client is configured");
  }
  const app = Fastify({
    logger: {
      level: deps.config.logLevel,
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "res.headers.set-cookie",
        "body.code",
        "body.token",
        "body.refresh_token",
        "body.client_secret",
        "access_token",
        "refresh_token"
      ]
    },
    trustProxy: deps.config.trustProxyHops === 0 ? false : deps.config.trustProxyHops
  });

  await app.register(rateLimit, {
    global: true,
    max: 240,
    timeWindow: "1 minute"
  });

  const authStartRateLimit = app.createRateLimit({
    max: 30,
    timeWindow: "1 minute",
    keyGenerator: (request) => {
      const query = request.query as { tool_slug?: string };
      return `auth-start:${hashRequestField(request.ip, deps.config.logIpSalt) ?? "unknown-ip"}:${query.tool_slug ?? "unknown-tool"}`;
    }
  });

  const tokenExchangeRateLimit = app.createRateLimit({
    max: 20,
    timeWindow: "1 minute",
    keyGenerator: (request) => {
      const body = request.body as { code?: string } | undefined;
      return `token-exchange:${readBasicClientId(request) ?? "unknown-client"}:${body?.code ? hashOpaque(body.code, deps.config.logIpSalt) : "missing-code"}`;
    }
  });

  const tokenRefreshRateLimit = app.createRateLimit({
    max: 60,
    timeWindow: "1 minute",
    keyGenerator: (request) => {
      const body = request.body as { refresh_token?: string } | undefined;
      return `token-refresh:${readBasicClientId(request) ?? "unknown-client"}:${body?.refresh_token ? hashOpaque(body.refresh_token, deps.config.logIpSalt) : "missing-refresh-token"}`;
    }
  });

  const introspectionRateLimit = app.createRateLimit({
    max: 120,
    timeWindow: "1 minute",
    keyGenerator: (request) => {
      const body = request.body as { token?: string } | undefined;
      return `token-introspect:${readBasicClientId(request) ?? "unknown-client"}:${body?.token ? hashOpaque(body.token, deps.config.logIpSalt) : "missing-token"}`;
    }
  });

  const adminWriteRateLimit = app.createRateLimit({
    max: 60,
    timeWindow: "1 minute",
    keyGenerator: (request) => `admin-write:${readAdminRateLimitKey(request, deps.config)}`
  });

  app.addHook("onRequest", async (request, reply) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    reply.header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'");
    const requestUrl = new URL(request.url, deps.config.appBaseUrl);
    const forbiddenQueryTokenKeys = ["token", "access_token", "refresh_token", "id_token"];
    if (forbiddenQueryTokenKeys.some((key) => requestUrl.searchParams.has(key))) {
      const correlationId = randomToken("corr_", 16);
      await deps.audit.write({
        event_type: "auth.denied.token_in_query",
        outcome: "denied",
        correlation_id: correlationId,
        reason_code: "TOKEN_IN_QUERY_REJECTED",
        request_ip_hash: hashRequestField(request.ip, deps.config.logIpSalt),
        user_agent_hash: hashRequestField(request.headers["user-agent"], deps.config.logIpSalt)
      });
      return sendJsonError(reply, new AppError("TOKEN_IN_QUERY_REJECTED", correlationId));
    }
    const origin = request.headers.origin;
    if (typeof origin === "string" && deps.config.corsAllowedOrigins.includes(origin)) {
      reply.header("Access-Control-Allow-Origin", origin);
      reply.header("Vary", "Origin");
      reply.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
      reply.header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
    }
    if (request.method === "OPTIONS") {
      return reply.status(204).send();
    }
  });

  app.setErrorHandler(async (error, request, reply) => {
    if (error instanceof AppError) {
      return sendJsonError(reply, error);
    }
    const correlationId = String(request.headers["x-correlation-id"] ?? randomToken("corr_", 16));
    const maybeStatusError = error as { statusCode?: unknown };
    const statusCode = typeof maybeStatusError.statusCode === "number" ? maybeStatusError.statusCode : 500;
    if (statusCode >= 400 && statusCode < 500) {
      request.log.warn({ err: error, correlation_id: correlationId }, "request rejected");
      return sendJsonError(reply, new AppError("VALIDATION_ERROR", correlationId));
    }
    request.log.error({ err: error, correlation_id: correlationId }, "request failed");
    return sendJsonError(reply, new AppError("INTERNAL_ERROR", correlationId));
  });

  const contextFor = (request: FastifyRequest, correlationId = randomToken("corr_", 16)): RequestContext => ({
    correlationId,
    requestIpHash: hashRequestField(request.ip, deps.config.logIpSalt),
    userAgentHash: hashRequestField(request.headers["user-agent"], deps.config.logIpSalt)
  });

  app.get("/", async (_request, reply) => reply.redirect(adminUiPath(deps.config)));

  const healthRouteOptions = { logLevel: "silent" as const };
  const healthHandler = async () => {
    let db = "ok";
    try {
      await deps.repositories.health();
    } catch {
      db = "error";
    }
    return { status: db === "ok" ? "ok" : "degraded", service: "access-layer-google-sso", db };
  };
  app.get("/health", healthRouteOptions, healthHandler);
  if (deps.config.publicBasePath) {
    app.get(apiPath(deps.config, "/health"), healthRouteOptions, healthHandler);
  }

  app.get(apiPath(deps.config, "/v1/.well-known/jwks.json"), async () => deps.tokenService.getJwks());

  app.get(apiPath(deps.config, "/v1/auth/start"), { preHandler: async (request, reply) => {
    if (!(await enforceRateLimit(authStartRateLimit, request, reply))) return reply;
  } }, async (request, reply) => {
    const ctx = contextFor(request);
    const query = request.query as Record<string, string | undefined>;
    const toolSlug = (query.tool_slug ?? "").toLowerCase();
    const returnUrl = query.return_url ?? "";
    const toolState = query.state ?? "";
    const loginHint = query.login_hint ? normalizeEmail(query.login_hint) : null;
    const toolSlugIsWellFormed = validateToolSlug(toolSlug);

    await deps.audit.write({
      event_type: "auth.requested",
      outcome: "info",
      correlation_id: ctx.correlationId,
      tool_slug: toolSlugIsWellFormed ? toolSlug : null,
      request_ip_hash: ctx.requestIpHash,
      user_agent_hash: ctx.userAgentHash
    });

    if (!toolSlugIsWellFormed) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_tool",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        reason_code: "AUTH_INVALID_TOOL",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_TOOL", ctx.correlationId));
    }

    if (!validateState(toolState)) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_state",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_slug: toolSlug,
        reason_code: "AUTH_INVALID_STATE",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_STATE", ctx.correlationId));
    }

    const tool = await deps.repositories.findToolBySlug(toolSlug);
    if (!tool) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_tool",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_slug: toolSlug,
        reason_code: "AUTH_INVALID_TOOL",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_TOOL", ctx.correlationId));
    }

    if (tool.status !== "active") {
      await deps.audit.write({
        event_type: "auth.denied.invalid_tool",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_id: tool.id,
        tool_slug: tool.slug,
        reason_code: "AUTH_TOOL_DISABLED",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(403).send(safeErrorPage("AUTH_TOOL_DISABLED", ctx.correlationId));
    }

    if (!validateReturnUrlExact(returnUrl, tool.allowed_return_urls, deps.config.returnUrlAllowedSchemes)) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_return_url",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_id: tool.id,
        tool_slug: tool.slug,
        reason_code: "AUTH_INVALID_RETURN_URL",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_RETURN_URL", ctx.correlationId));
    }

    const requestedProvider = query.provider;
    const microsoftAvailable = deps.config.legacyMicrosoftEnabled === true &&
      (deps.config.legacyMicrosoftToolSlugs ?? []).includes(tool.slug) && deps.microsoft !== undefined;
    if (requestedProvider !== undefined && requestedProvider !== "google" && requestedProvider !== "microsoft") {
      await deps.audit.write({
        event_type: "auth.denied.invalid_provider",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_id: tool.id,
        tool_slug: tool.slug,
        reason_code: "AUTH_INVALID_PROVIDER",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_PROVIDER", ctx.correlationId));
    }
    if (requestedProvider === undefined && microsoftAvailable) {
      return reply.header("Cache-Control", "no-store").header("Pragma", "no-cache")
        .type("text/html").status(200).send(providerChoicePage({
        config: deps.config,
        tool,
        returnUrl,
        toolState,
        loginHint
        }));
    }
    if (requestedProvider === "microsoft" && !microsoftAvailable) {
      await deps.audit.write({
        event_type: "auth.denied.microsoft_not_available",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_id: tool.id,
        tool_slug: tool.slug,
        reason_code: "AUTH_MICROSOFT_NOT_AVAILABLE",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(403).send(safeErrorPage("AUTH_MICROSOFT_NOT_AVAILABLE", ctx.correlationId));
    }

    const useMicrosoft = requestedProvider === "microsoft";
    const providerState = randomToken(useMicrosoft ? "mst_" : "gst_", 32);
    const nonce = randomToken("nce_", 32);
    await deps.repositories.createAuthRequest({
      stateHash: sha256(providerState),
      nonceHash: sha256(nonce),
      toolId: tool.id,
      toolSlug: tool.slug,
      returnUrl,
      toolState,
      toolStateHash: sha256(toolState),
      loginHint,
      correlationId: ctx.correlationId,
      requestIpHash: ctx.requestIpHash,
      userAgentHash: ctx.userAgentHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });

    const identityProvider = useMicrosoft ? deps.microsoft! : deps.google;
    return reply.redirect(identityProvider.createAuthorizationUrl({
      state: providerState,
      nonce,
      loginHint: loginHint ?? undefined
    }));
  });

  app.get(apiPath(deps.config, "/v1/auth/google/callback"), async (request, reply) => {
    const query = request.query as Record<string, string | undefined>;
    const state = query.state ?? "";
    const ctx = contextFor(request);
    if (!state.startsWith("gst_")) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_state",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        reason_code: "AUTH_INVALID_STATE",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_STATE", ctx.correlationId));
    }

    const authRequest = await deps.repositories.consumeAuthRequest(sha256(state));
    if (!authRequest) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_state",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        reason_code: "AUTH_INVALID_STATE",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_STATE", ctx.correlationId));
    }
    const flowCtx = contextFor(request, authRequest.correlation_id);
    await deps.audit.write({
      event_type: "google.callback.received",
      outcome: "info",
      correlation_id: authRequest.correlation_id,
      tool_id: authRequest.tool_id,
      tool_slug: authRequest.tool_slug,
      request_ip_hash: flowCtx.requestIpHash,
      user_agent_hash: flowCtx.userAgentHash
    });

    if (query.error) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_google_token",
        outcome: "denied",
        correlation_id: authRequest.correlation_id,
        tool_id: authRequest.tool_id,
        tool_slug: authRequest.tool_slug,
        request_ip_hash: flowCtx.requestIpHash,
        user_agent_hash: flowCtx.userAgentHash,
        reason_code: "AUTH_GOOGLE_CALLBACK_FAILED",
        metadata: { google_error: query.error }
      });
      return reply.type("text/html").status(401).send(safeErrorPage("AUTH_GOOGLE_CALLBACK_FAILED", authRequest.correlation_id));
    }

    try {
      const code = query.code;
      if (!code) {
        throw new AppError("AUTH_GOOGLE_CALLBACK_FAILED", authRequest.correlation_id);
      }
      const identity = await deps.google.exchangeCodeForIdentity(code, authRequest.correlation_id);
      if (!identity.nonce || sha256(identity.nonce) !== authRequest.nonce_hash) {
        throw new AppError("AUTH_INVALID_GOOGLE_TOKEN", authRequest.correlation_id);
      }

      const result = await completeLegacyIdentity(deps, authRequest, identity, flowCtx);

      if ("error" in result) {
        return reply
          .type("text/html")
          .status(statusForHtml(result.error.code))
          .send(safeErrorPage(result.error.code, result.error.correlationId));
      }
      const redirectUrl = new URL(authRequest.return_url);
      redirectUrl.searchParams.set("code", result.codeValue);
      redirectUrl.searchParams.set("state", result.toolState);
      return reply.redirect(redirectUrl.toString());
    } catch (error) {
      if (error instanceof AppError) {
        await auditCallbackErrorIfNeeded(deps.audit, authRequest, flowCtx, error);
        return reply.type("text/html").status(statusForHtml(error.code)).send(safeErrorPage(error.code, error.correlationId));
      }
      throw error;
    }
  });

  if (deps.config.legacyMicrosoftEnabled) {
    app.get(apiPath(deps.config, "/v1/auth/microsoft/callback"), { logLevel: "silent" }, async (request, reply) => {
      const query = request.query as Record<string, string | undefined>;
      const state = query.state ?? "";
      const ctx = contextFor(request);
      if (!state.startsWith("mst_")) {
        await deps.audit.write({
          event_type: "auth.denied.invalid_state",
          outcome: "denied",
          correlation_id: ctx.correlationId,
          reason_code: "AUTH_INVALID_STATE",
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
        return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_STATE", ctx.correlationId));
      }

      const authRequest = await deps.repositories.consumeAuthRequest(sha256(state));
      if (!authRequest) {
        await deps.audit.write({
          event_type: "auth.denied.invalid_state",
          outcome: "denied",
          correlation_id: ctx.correlationId,
          reason_code: "AUTH_INVALID_STATE",
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
        return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_STATE", ctx.correlationId));
      }
      const flowCtx = contextFor(request, authRequest.correlation_id);
      await deps.audit.write({
        event_type: "microsoft.callback.received",
        outcome: "info",
        correlation_id: authRequest.correlation_id,
        tool_id: authRequest.tool_id,
        tool_slug: authRequest.tool_slug,
        request_ip_hash: flowCtx.requestIpHash,
        user_agent_hash: flowCtx.userAgentHash
      });

      if (query.error) {
        await deps.audit.write({
          event_type: "auth.denied.invalid_microsoft_token",
          outcome: "denied",
          correlation_id: authRequest.correlation_id,
          tool_id: authRequest.tool_id,
          tool_slug: authRequest.tool_slug,
          request_ip_hash: flowCtx.requestIpHash,
          user_agent_hash: flowCtx.userAgentHash,
          reason_code: "AUTH_MICROSOFT_CALLBACK_FAILED"
        });
        return reply.type("text/html").status(401)
          .send(safeErrorPage("AUTH_MICROSOFT_CALLBACK_FAILED", authRequest.correlation_id));
      }

      try {
        const code = query.code;
        if (!code) {
          throw new AppError("AUTH_MICROSOFT_CALLBACK_FAILED", authRequest.correlation_id);
        }
        const identity = await deps.microsoft!.exchangeCodeForIdentity(code, authRequest.correlation_id);
        if (!identity.nonce || sha256(identity.nonce) !== authRequest.nonce_hash) {
          throw new AppError("AUTH_INVALID_MICROSOFT_TOKEN", authRequest.correlation_id);
        }
        const result = await completeLegacyIdentity(deps, authRequest, identity, flowCtx);
        if ("error" in result) {
          return reply.type("text/html").status(statusForHtml(result.error.code))
            .send(safeErrorPage(result.error.code, result.error.correlationId));
        }
        const redirectUrl = new URL(authRequest.return_url);
        redirectUrl.searchParams.set("code", result.codeValue);
        redirectUrl.searchParams.set("state", result.toolState);
        return reply.redirect(redirectUrl.toString());
      } catch (error) {
        if (error instanceof AppError) {
          await auditCallbackErrorIfNeeded(deps.audit, authRequest, flowCtx, error);
          return reply.type("text/html").status(statusForHtml(error.code))
            .send(safeErrorPage(error.code, error.correlationId));
        }
        throw error;
      }
    });
  }

  app.post(apiPath(deps.config, "/v1/auth/exchange"), { preHandler: async (request, reply) => {
    if (!(await enforceRateLimit(tokenExchangeRateLimit, request, reply))) return reply;
  } }, async (request, reply) => {
    const ctx = contextFor(request);
    const toolClient = await authenticateToolClient(request, deps, ctx);
    const body = request.body as { code?: string; redirect_uri?: string };
    if (!body?.code || !body.redirect_uri) {
      throw new AppError("VALIDATION_ERROR", ctx.correlationId);
    }
    const response = await exchangeOneTimeCode({
      deps,
      code: body.code,
      redirectUri: body.redirect_uri,
      tool: toolClient.tool,
      ctx,
      requestIpHash: ctx.requestIpHash,
      userAgentHash: ctx.userAgentHash
    });
    return reply.header("Cache-Control", "no-store").header("Pragma", "no-cache").send(response);
  });

  app.post(apiPath(deps.config, "/v1/auth/refresh"), { preHandler: async (request, reply) => {
    if (!(await enforceRateLimit(tokenRefreshRateLimit, request, reply))) return reply;
  } }, async (request, reply) => {
    const ctx = contextFor(request);
    const toolClient = await authenticateToolClient(request, deps, ctx, "token.refresh.denied");
    const body = request.body as { refresh_token?: string };
    if (!deps.config.enableRefreshTokens || !body?.refresh_token) {
      throw new AppError(body?.refresh_token ? "AUTH_REFRESH_TOKEN_INVALID" : "VALIDATION_ERROR", ctx.correlationId);
    }
    const response = await refreshAccessToken({
      deps,
      refreshToken: body.refresh_token,
      tool: toolClient.tool,
      ctx
    });
    return reply.header("Cache-Control", "no-store").header("Pragma", "no-cache").send(response);
  });

  app.post(apiPath(deps.config, "/v1/auth/introspect"), { preHandler: async (request, reply) => {
    if (!(await enforceRateLimit(introspectionRateLimit, request, reply))) return reply;
  } }, async (request) => {
    const ctx = contextFor(request);
    const toolClient = await authenticateToolClient(request, deps, ctx);
    const body = request.body as { token?: string };
    if (!body?.token) {
      throw new AppError("VALIDATION_ERROR", ctx.correlationId);
    }
    const result = await introspectToken(body.token, toolClient.tool, deps);
    await deps.audit.write({
      event_type: "token.introspected",
      outcome: "info",
      correlation_id: ctx.correlationId,
      tool_id: toolClient.tool.id,
      tool_slug: toolClient.tool.slug,
      request_ip_hash: ctx.requestIpHash,
      user_agent_hash: ctx.userAgentHash,
      metadata: { active: result.active, reason: result.active ? undefined : result.reason }
    });
    return result;
  });

  app.post(apiPath(deps.config, "/v1/auth/logout"), async (request, reply) => {
    const ctx = contextFor(request);
    const body = (request.body ?? {}) as { session_id?: string; refresh_token?: string };
    let revoked = 0;
    let tool: Tool | null = null;
    let actor: { userId?: string; googleSub?: string; email?: string; hd?: string; sessionId?: string } = {};

    if ((request.headers.authorization ?? "").startsWith("Basic ")) {
      const toolClient = await authenticateToolClient(request, deps, ctx, "session.revoke.denied");
      tool = toolClient.tool;
      if (body.session_id) {
        revoked += await deps.repositories.revokeSession(body.session_id, toolClient.tool.id);
      }
      if (body.refresh_token) {
        const refreshHash = hashOpaque(body.refresh_token, deps.config.toolClientSecretPepper);
        const refresh = await deps.repositories.findRefreshTokenByHash(refreshHash);
        const refreshSession = refresh ? await deps.repositories.findSessionById(refresh.session_id) : null;
        if (refreshSession?.tool_id === toolClient.tool.id) {
          revoked += await deps.repositories.revokeRefreshToken(refreshHash);
          revoked += await deps.repositories.revokeSession(refreshSession.id, toolClient.tool.id);
          actor.sessionId = refreshSession.id;
        }
      }
    } else {
      const token = readBearerOrAdminCookie(request, deps.config);
      if (!token) {
        await deps.audit.write({
          event_type: "session.revoke.denied",
          outcome: "denied",
          correlation_id: ctx.correlationId,
          reason_code: "AUTH_INVALID_STATE",
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
        throw new AppError("AUTH_INVALID_STATE", ctx.correlationId);
      }
      let claims;
      try {
        claims = await deps.tokenService.verifyAccessToken(token);
      } catch {
        await deps.audit.write({
          event_type: "session.revoke.denied",
          outcome: "denied",
          correlation_id: ctx.correlationId,
          reason_code: "AUTH_INVALID_STATE",
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
        throw new AppError("AUTH_INVALID_STATE", ctx.correlationId);
      }
      const user = await deps.repositories.findUserByGoogleSub(claims.sub);
      const session = await deps.repositories.findSessionById(claims.sid);
      if (!user || !session || user.status !== "active") {
        await deps.audit.write({
          event_type: "session.revoke.denied",
          outcome: "denied",
          correlation_id: ctx.correlationId,
          reason_code: "AUTH_INVALID_STATE",
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
        throw new AppError("AUTH_INVALID_STATE", ctx.correlationId);
      }
      tool = await deps.repositories.findToolById(session.tool_id);
      actor = {
        userId: user.id,
        googleSub: user.google_sub,
        email: user.email,
        hd: user.hd,
        sessionId: session.id
      };
      revoked += await deps.repositories.revokeSession(session.id);
      if (body.refresh_token) {
        revoked += await deps.repositories.revokeRefreshToken(hashOpaque(body.refresh_token, deps.config.toolClientSecretPepper));
      }
    }

    if (tool) {
      if (revoked > 0) {
        await deps.audit.write({
          event_type: "session.revoked",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId ?? null,
          actor_google_sub: actor.googleSub ?? null,
          actor_email: actor.email ?? null,
          actor_hd: actor.hd ?? null,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { revoked_count: revoked, session_id: actor.sessionId ?? body.session_id ?? null }
        });
      } else if (actor.sessionId || body.session_id || body.refresh_token) {
        await deps.audit.write({
          event_type: "session.revoke.denied",
          outcome: "denied",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId ?? null,
          actor_google_sub: actor.googleSub ?? null,
          actor_email: actor.email ?? null,
          actor_hd: actor.hd ?? null,
          reason_code: "TOKEN_INACTIVE",
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { session_id: actor.sessionId ?? body.session_id ?? null }
        });
      }
    }
    return reply.status(204).send();
  });

  app.get(apiPath(deps.config, "/v1/me"), async (request) => {
    const actor = await requireUserToken(request, deps);
    return actor;
  });

  registerAdminUi(app, deps, contextFor);
  registerAdminApi(app, deps, contextFor, adminWriteRateLimit);

  return app;
}

function providerChoicePage(input: {
  config: Config;
  tool: Tool;
  returnUrl: string;
  toolState: string;
  loginHint: string | null;
}): string {
  const providerUrl = (provider: "google" | "microsoft") => {
    const url = new URL(publicUrl(input.config, "/v1/auth/start"));
    url.search = new URLSearchParams({
      tool_slug: input.tool.slug,
      return_url: input.returnUrl,
      state: input.toolState,
      provider
    }).toString();
    if (input.loginHint) url.searchParams.set("login_hint", input.loginHint);
    return url.toString();
  };
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Choose how to continue</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f7f9; color: #18202a; }
    main { width: min(480px, calc(100vw - 32px)); border: 1px solid #d9e1e8; background: #fff; border-radius: 8px; padding: 28px; box-shadow: 0 8px 28px rgba(23, 36, 50, .08); }
    h1 { font-size: 1.35rem; margin: 0 0 8px; } p { line-height: 1.5; margin: 0 0 22px; }
    nav { display: grid; gap: 12px; }
    a { display: block; padding: 12px 16px; border: 1px solid #156b6b; border-radius: 6px; color: #0b5454; text-align: center; text-decoration: none; font-weight: 650; }
    a:hover, a:focus-visible { background: #e8f7f3; outline: 3px solid #9ee5d5; outline-offset: 2px; }
  </style>
</head>
<body>
  <main>
    <h1>Sign in to ${escapeHtml(input.tool.display_name)}</h1>
    <p>Choose your company account provider.</p>
    <nav aria-label="Sign-in provider">
      <a href="${escapeHtml(providerUrl("google"))}">Continue with Google</a>
      <a href="${escapeHtml(providerUrl("microsoft"))}">Continue with Microsoft</a>
    </nav>
  </main>
</body>
</html>`;
}

async function completeLegacyIdentity(
  deps: AppDependencies,
  authRequest: AuthRequest,
  identity: LegacyIdentity,
  flowCtx: RequestContext
): Promise<AuthCallbackResult> {
  return deps.repositories.db.transaction(async (tx) => {
    const txRepos = deps.repositories.withDb(tx);
    const txAudit = new AuditLogger(txRepos);
    const user = await txRepos.upsertUser({
      googleSub: identity.googleSub,
      email: identity.email,
      emailNormalized: normalizeEmail(identity.email),
      emailVerified: identity.emailVerified,
      hd: identity.hd,
      displayName: identity.displayName,
      pictureUrl: identity.pictureUrl
    });
    await txRepos.linkPendingEmailGrants(user);
    const tool = await txRepos.findToolById(authRequest.tool_id);
    if (!tool || tool.status !== "active") {
      await txAudit.write({
        event_type: "auth.denied.invalid_tool",
        outcome: "denied",
        correlation_id: authRequest.correlation_id,
        tool_id: authRequest.tool_id,
        tool_slug: authRequest.tool_slug,
        actor_user_id: user.id,
        actor_google_sub: user.google_sub,
        actor_email: user.email,
        actor_hd: user.hd,
        reason_code: "AUTH_TOOL_DISABLED",
        request_ip_hash: flowCtx.requestIpHash,
        user_agent_hash: flowCtx.userAgentHash
      });
      return { error: new AppError("AUTH_TOOL_DISABLED", authRequest.correlation_id) };
    }
    if (user.status !== "active") {
      await txAudit.write({
        event_type: "auth.denied.user_disabled",
        outcome: "denied",
        correlation_id: authRequest.correlation_id,
        tool_id: tool.id,
        tool_slug: tool.slug,
        actor_user_id: user.id,
        actor_google_sub: user.google_sub,
        actor_email: user.email,
        actor_hd: user.hd,
        reason_code: "AUTH_USER_DISABLED",
        request_ip_hash: flowCtx.requestIpHash,
        user_agent_hash: flowCtx.userAgentHash
      });
      return { error: new AppError("AUTH_USER_DISABLED", authRequest.correlation_id) };
    }

    const bootstrapGrant = await ensureBootstrapAdminGrant({
      config: deps.config,
      repos: txRepos,
      audit: txAudit,
      user,
      tool,
      ctx: flowCtx
    });
    const grant = bootstrapGrant ?? (await txRepos.findActiveGrant(tool.id, user.id, user.email_normalized));
    if (!grant) {
      await txAudit.write({
        event_type: "auth.denied.no_grant",
        outcome: "denied",
        correlation_id: authRequest.correlation_id,
        tool_id: tool.id,
        tool_slug: tool.slug,
        actor_user_id: user.id,
        actor_google_sub: user.google_sub,
        actor_email: user.email,
        actor_hd: user.hd,
        reason_code: "AUTH_NOT_AUTHORIZED_FOR_TOOL",
        request_ip_hash: flowCtx.requestIpHash,
        user_agent_hash: flowCtx.userAgentHash
      });
      const recentReviewed = await txRepos.findRecentReviewedAccessRequest(
        tool.id,
        user.email_normalized,
        deps.config.accessRequestReopenAfterDays
      );
      if (recentReviewed) {
        await txAudit.write({
          event_type: "access_request.reopen_suppressed",
          outcome: "info",
          correlation_id: authRequest.correlation_id,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: user.id,
          actor_google_sub: user.google_sub,
          actor_email: user.email,
          actor_hd: user.hd,
          request_ip_hash: flowCtx.requestIpHash,
          user_agent_hash: flowCtx.userAgentHash,
          metadata: {
            access_request_id: recentReviewed.id,
            previous_status: recentReviewed.status,
            reopen_after_days: deps.config.accessRequestReopenAfterDays
          }
        });
      } else {
        const accessRequest = await txRepos.upsertAccessRequest({
          tool,
          user,
          correlationId: authRequest.correlation_id,
          requestIpHash: flowCtx.requestIpHash,
          userAgentHash: flowCtx.userAgentHash
        });
        await txAudit.write({
          event_type: accessRequest.repeated ? "access_request.repeated" : "access_request.created",
          outcome: "info",
          correlation_id: authRequest.correlation_id,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: user.id,
          actor_google_sub: user.google_sub,
          actor_email: user.email,
          actor_hd: user.hd,
          request_ip_hash: flowCtx.requestIpHash,
          user_agent_hash: flowCtx.userAgentHash,
          metadata: { access_request_id: accessRequest.request.id, attempts_count: accessRequest.request.attempts_count }
        });
      }
      return { error: new AppError("AUTH_NOT_AUTHORIZED_FOR_TOOL", authRequest.correlation_id) };
    }

    const session = await txRepos.createSession({
      userId: user.id,
      toolId: tool.id,
      grantId: grant.id,
      expiresAt: new Date(Date.now() + deps.config.refreshTokenTtlSeconds * 1000)
    });
    const codeValue = randomToken("otc_", 32);
    await txRepos.createOneTimeCode({
      codeHash: hashOpaque(codeValue, deps.config.toolClientSecretPepper),
      userId: user.id,
      toolId: tool.id,
      grantId: grant.id,
      sessionId: session.id,
      returnUrl: authRequest.return_url,
      correlationId: authRequest.correlation_id,
      expiresAt: new Date(Date.now() + deps.config.oneTimeCodeTtlSeconds * 1000)
    });
    await txAudit.write({
      event_type: "auth.allowed",
      outcome: "success",
      correlation_id: authRequest.correlation_id,
      tool_id: tool.id,
      tool_slug: tool.slug,
      actor_user_id: user.id,
      actor_google_sub: user.google_sub,
      actor_email: user.email,
      actor_hd: user.hd,
      request_ip_hash: flowCtx.requestIpHash,
      user_agent_hash: flowCtx.userAgentHash,
      metadata: { session_id: session.id, grant_id: grant.id }
    });
    return { tool, codeValue, toolState: authRequest.tool_state };
  });
}

async function ensureBootstrapAdminGrant(input: {
  config: Config;
  repos: Repositories;
  audit: AuditLogger;
  user: User;
  tool: Tool;
  ctx: RequestContext;
}): Promise<AuthorizationGrant | null> {
  if (input.tool.slug !== ADMIN_TOOL_SLUG || !input.config.adminBootstrapEmails.includes(input.user.email_normalized)) {
    return null;
  }
  const existing = await input.repos.findActiveGrant(input.tool.id, input.user.id, input.user.email_normalized);
  if (existing) {
    return existing;
  }
  const grant = await input.repos.createGrant({
    toolId: input.tool.id,
    userId: input.user.id,
    emailNormalized: input.user.email_normalized,
    role: "platform_admin",
    permissions: rolePermissions("platform_admin"),
    status: "active"
  });
  await input.audit.write({
    event_type: "admin.grant.created",
    outcome: "success",
    correlation_id: input.ctx.correlationId,
    tool_id: input.tool.id,
    tool_slug: input.tool.slug,
    actor_user_id: input.user.id,
    actor_google_sub: input.user.google_sub,
    actor_email: input.user.email,
    actor_hd: input.user.hd,
    request_ip_hash: input.ctx.requestIpHash,
    user_agent_hash: input.ctx.userAgentHash,
    metadata: { bootstrap_admin: true, grant_id: grant.id }
  });
  return grant;
}

async function auditCallbackErrorIfNeeded(
  audit: AuditLogger,
  authRequest: { correlation_id: string; tool_id: string; tool_slug: string },
  ctx: RequestContext,
  error: AppError
): Promise<void> {
  const eventTypeByCode: Partial<Record<ErrorCode, string>> = {
    AUTH_INVALID_GOOGLE_TOKEN: "auth.denied.invalid_google_token",
    AUTH_EMAIL_NOT_VERIFIED: "auth.denied.email_not_verified",
    AUTH_EXTERNAL_DOMAIN: "auth.denied.external_domain",
    AUTH_GOOGLE_CALLBACK_FAILED: "auth.denied.invalid_google_token",
    AUTH_INVALID_MICROSOFT_TOKEN: "auth.denied.invalid_microsoft_token",
    AUTH_MICROSOFT_CALLBACK_FAILED: "auth.denied.invalid_microsoft_token"
  };
  const eventType = eventTypeByCode[error.code];
  if (!eventType) {
    return;
  }
  await audit.write({
    event_type: eventType,
    outcome: "denied",
    correlation_id: authRequest.correlation_id,
    tool_id: authRequest.tool_id,
    tool_slug: authRequest.tool_slug,
    reason_code: error.code,
    request_ip_hash: ctx.requestIpHash,
    user_agent_hash: ctx.userAgentHash
  });
}

function statusForHtml(code: ErrorCode): number {
  if (["AUTH_INVALID_GOOGLE_TOKEN", "AUTH_GOOGLE_CALLBACK_FAILED", "AUTH_INVALID_MICROSOFT_TOKEN", "AUTH_MICROSOFT_CALLBACK_FAILED"].includes(code)) return 401;
  if (code === "AUTH_INVALID_STATE" || code === "AUTH_INVALID_PROVIDER") return 400;
  if (code === "INTERNAL_ERROR") return 500;
  return 403;
}

async function authenticateToolClient(
  request: FastifyRequest,
  deps: AppDependencies,
  ctx: RequestContext,
  failureEventType = "token.exchange.denied"
): Promise<AuthenticatedToolClient> {
  const auth = request.headers.authorization ?? "";
  const [scheme, encoded] = auth.split(" ");
  if (scheme !== "Basic" || !encoded) {
    await deps.audit.write({
      event_type: failureEventType,
      outcome: "denied",
      correlation_id: ctx.correlationId,
      reason_code: "TOOL_AUTH_FAILED",
      request_ip_hash: ctx.requestIpHash,
      user_agent_hash: ctx.userAgentHash
    });
    throw new AppError("TOOL_AUTH_FAILED", ctx.correlationId);
  }
  let clientId = "";
  let clientSecret = "";
  let malformedBasicWasAudited = false;
  try {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator <= 0) {
      await deps.audit.write({
        event_type: failureEventType,
        outcome: "denied",
        correlation_id: ctx.correlationId,
        reason_code: "TOOL_AUTH_FAILED",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      malformedBasicWasAudited = true;
      throw new AppError("TOOL_AUTH_FAILED", ctx.correlationId);
    }
    clientId = decoded.slice(0, separator);
    clientSecret = decoded.slice(separator + 1);
  } catch {
    if (!malformedBasicWasAudited) {
      await deps.audit.write({
        event_type: failureEventType,
        outcome: "denied",
        correlation_id: ctx.correlationId,
        reason_code: "TOOL_AUTH_FAILED",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
    }
    throw new AppError("TOOL_AUTH_FAILED", ctx.correlationId);
  }
  const client = await deps.repositories.findToolClient(clientId);
  if (!client || client.status === "disabled") {
    await deps.audit.write({
      event_type: failureEventType,
      outcome: "denied",
      correlation_id: ctx.correlationId,
      reason_code: "TOOL_AUTH_FAILED",
      request_ip_hash: ctx.requestIpHash,
      user_agent_hash: ctx.userAgentHash
    });
    throw new AppError("TOOL_AUTH_FAILED", ctx.correlationId);
  }
  const tool = await deps.repositories.findToolById(client.tool_id);
  if (!tool || tool.status !== "active") {
    await deps.audit.write({
      event_type: failureEventType,
      outcome: "denied",
      correlation_id: ctx.correlationId,
      tool_id: client.tool_id,
      tool_slug: client.tool_slug,
      reason_code: "TOOL_AUTH_FAILED",
      request_ip_hash: ctx.requestIpHash,
      user_agent_hash: ctx.userAgentHash
    });
    throw new AppError("TOOL_AUTH_FAILED", ctx.correlationId);
  }
  if (!(await verifyToolSecret(clientSecret, deps.config.toolClientSecretPepper, client.client_secret_hash))) {
    await deps.audit.write({
      event_type: failureEventType,
      outcome: "denied",
      correlation_id: ctx.correlationId,
      tool_id: tool.id,
      tool_slug: tool.slug,
      reason_code: "TOOL_AUTH_FAILED",
      request_ip_hash: ctx.requestIpHash,
      user_agent_hash: ctx.userAgentHash
    });
    throw new AppError("TOOL_AUTH_FAILED", ctx.correlationId);
  }
  await deps.repositories.markToolClientUsed(client.client_id);
  return { client, tool };
}

async function exchangeOneTimeCode(input: {
  deps: AppDependencies;
  code: string;
  redirectUri: string;
  tool: Tool;
  ctx: RequestContext;
  requestIpHash: string | null;
  userAgentHash: string | null;
}) {
  const codeHash = hashOpaque(input.code, input.deps.config.toolClientSecretPepper);
  const consumed = await input.deps.repositories.db.transaction(async (tx) => {
    const repos = input.deps.repositories.withDb(tx);
    const code = await repos.consumeOneTimeCode(codeHash, input.tool.id, input.redirectUri);
    if (!code) return null;
    const user = await repos.findUserById(code.user_id);
    const tool = await repos.findToolById(code.tool_id);
    const grant = await repos.findGrantById(code.grant_id);
    const session = await repos.findSessionById(code.session_id);
    return { repos, code, user, tool, grant, session };
  });

  if (!consumed?.user || !consumed.tool || !consumed.grant || !consumed.session) {
    const existing = await input.deps.repositories.findOneTimeCodeByHash(codeHash);
    const reason = existing?.consumed_at ? "AUTH_CODE_ALREADY_USED" : "AUTH_CODE_EXPIRED";
    await input.deps.audit.write({
      event_type: "token.exchange.denied",
      outcome: "denied",
      correlation_id: input.ctx.correlationId,
      tool_id: input.tool.id,
      tool_slug: input.tool.slug,
      reason_code: reason,
      request_ip_hash: input.requestIpHash,
      user_agent_hash: input.userAgentHash
    });
    throw new AppError(reason, input.ctx.correlationId);
  }

  const { user, tool, grant, session, code } = consumed;
  if (
    tool.status !== "active" ||
    user.status !== "active" ||
    !isGrantCurrentlyUsable(grant) ||
    session.status !== "active" ||
    session.tool_id !== tool.id ||
    grant.tool_id !== tool.id
  ) {
    await input.deps.audit.write({
      event_type: "token.exchange.denied",
      outcome: "denied",
      correlation_id: code.correlation_id,
      tool_id: tool.id,
      tool_slug: tool.slug,
      actor_user_id: user.id,
      actor_google_sub: user.google_sub,
      actor_email: user.email,
      actor_hd: user.hd,
      reason_code: "AUTH_NOT_AUTHORIZED_FOR_TOOL",
      request_ip_hash: input.requestIpHash,
      user_agent_hash: input.userAgentHash
    });
    throw new AppError("AUTH_NOT_AUTHORIZED_FOR_TOOL", code.correlation_id);
  }

  const access = await input.deps.tokenService.issueAccessToken({ user, tool, grant, session });
  let refreshToken: string | undefined;
  if (input.deps.config.enableRefreshTokens) {
    refreshToken = randomToken("rt_", 32);
    await input.deps.repositories.createRefreshToken(
      hashOpaque(refreshToken, input.deps.config.toolClientSecretPepper),
      session.id,
      new Date(Date.now() + input.deps.config.refreshTokenTtlSeconds * 1000)
    );
  }
  await input.deps.audit.write({
    event_type: "token.exchanged",
    outcome: "success",
    correlation_id: code.correlation_id,
    tool_id: tool.id,
    tool_slug: tool.slug,
    actor_user_id: user.id,
    actor_google_sub: user.google_sub,
    actor_email: user.email,
    actor_hd: user.hd,
    request_ip_hash: input.requestIpHash,
    user_agent_hash: input.userAgentHash,
    metadata: { session_id: session.id, grant_id: grant.id, token_jti: access.jti }
  });

  return {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: access.expiresIn,
    refresh_token: refreshToken,
    session: {
      id: session.id,
      issued_at: session.issued_at,
      expires_at: session.expires_at
    },
    user: userResponse(user),
    tool: {
      slug: tool.slug,
      display_name: tool.display_name
    },
    grant: {
      role: grant.role,
      permissions: grant.permissions
    },
    correlation_id: code.correlation_id
  };
}

async function refreshAccessToken(input: {
  deps: AppDependencies;
  refreshToken: string;
  tool: Tool;
  ctx: RequestContext;
}) {
  const tokenHash = hashOpaque(input.refreshToken, input.deps.config.toolClientSecretPepper);
  const nextRefreshToken = randomToken("rt_", 32);
  const nextExpiresAt = new Date(Date.now() + input.deps.config.refreshTokenTtlSeconds * 1000);
  const refreshed = await input.deps.repositories.db.transaction(async (tx) => {
    const repos = input.deps.repositories.withDb(tx);
    const audit = new AuditLogger(repos);
    const consumed = await repos.consumeRefreshToken(tokenHash);
    if (!consumed) return null;

    const session = await repos.findSessionById(consumed.session_id);
    const user = session ? await repos.findUserById(session.user_id) : null;
    const grant = session ? await repos.findGrantById(session.grant_id) : null;
    const valid =
      Boolean(session && session.tool_id === input.tool.id && session.status === "active" && session.expires_at > new Date()) &&
      Boolean(user && user.status === "active") &&
      Boolean(grant && grant.tool_id === input.tool.id && isGrantCurrentlyUsable(grant)) &&
      input.tool.status === "active";

    if (!valid || !session || !user || !grant) {
      await audit.write({
        event_type: "token.refresh.denied",
        outcome: "denied",
        correlation_id: input.ctx.correlationId,
        tool_id: input.tool.id,
        tool_slug: input.tool.slug,
        actor_user_id: user?.id,
        actor_google_sub: user?.google_sub,
        actor_email: user?.email,
        actor_hd: user?.hd,
        reason_code: "AUTH_REFRESH_TOKEN_INVALID",
        request_ip_hash: input.ctx.requestIpHash,
        user_agent_hash: input.ctx.userAgentHash,
        metadata: { session_id: session?.id ?? consumed.session_id }
      });
      return { error: new AppError("AUTH_REFRESH_TOKEN_INVALID", input.ctx.correlationId) };
    }

    const extendedSession = await repos.extendSession(session.id, input.tool.id, nextExpiresAt);
    if (!extendedSession) {
      await audit.write({
        event_type: "token.refresh.denied",
        outcome: "denied",
        correlation_id: input.ctx.correlationId,
        tool_id: input.tool.id,
        tool_slug: input.tool.slug,
        actor_user_id: user.id,
        actor_google_sub: user.google_sub,
        actor_email: user.email,
        actor_hd: user.hd,
        reason_code: "AUTH_REFRESH_TOKEN_INVALID",
        request_ip_hash: input.ctx.requestIpHash,
        user_agent_hash: input.ctx.userAgentHash,
        metadata: { session_id: session.id }
      });
      return { error: new AppError("AUTH_REFRESH_TOKEN_INVALID", input.ctx.correlationId) };
    }

    await repos.createRefreshToken(
      hashOpaque(nextRefreshToken, input.deps.config.toolClientSecretPepper),
      extendedSession.id,
      nextExpiresAt
    );
    const access = await input.deps.tokenService.issueAccessToken({
      user,
      tool: input.tool,
      grant,
      session: extendedSession
    });
    await audit.write({
      event_type: "token.refreshed",
      outcome: "success",
      correlation_id: input.ctx.correlationId,
      tool_id: input.tool.id,
      tool_slug: input.tool.slug,
      actor_user_id: user.id,
      actor_google_sub: user.google_sub,
      actor_email: user.email,
      actor_hd: user.hd,
      request_ip_hash: input.ctx.requestIpHash,
      user_agent_hash: input.ctx.userAgentHash,
      metadata: { session_id: extendedSession.id, grant_id: grant.id, token_jti: access.jti }
    });

    return {
      access_token: access.token,
      token_type: "Bearer",
      expires_in: access.expiresIn,
      refresh_token: nextRefreshToken,
      session: {
        id: extendedSession.id,
        issued_at: extendedSession.issued_at,
        expires_at: extendedSession.expires_at
      },
      user: userResponse(user),
      tool: {
        slug: input.tool.slug,
        display_name: input.tool.display_name
      },
      grant: {
        role: grant.role,
        permissions: grant.permissions
      },
      correlation_id: input.ctx.correlationId
    };
  });

  if (!refreshed) {
    await input.deps.audit.write({
      event_type: "token.refresh.denied",
      outcome: "denied",
      correlation_id: input.ctx.correlationId,
      tool_id: input.tool.id,
      tool_slug: input.tool.slug,
      reason_code: "AUTH_REFRESH_TOKEN_INVALID",
      request_ip_hash: input.ctx.requestIpHash,
      user_agent_hash: input.ctx.userAgentHash
    });
    throw new AppError("AUTH_REFRESH_TOKEN_INVALID", input.ctx.correlationId);
  }
  if ("error" in refreshed) {
    throw refreshed.error;
  }
  return refreshed;
}

async function introspectToken(token: string, tool: Tool, deps: AppDependencies) {
  let claims;
  try {
    claims = await deps.tokenService.verifyAccessToken(token, tool.slug);
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    return { active: false, reason: message.includes("exp") ? "expired" : "invalid" };
  }
  const session = await deps.repositories.findSessionById(claims.sid);
  const user = await deps.repositories.findUserByGoogleSub(claims.sub);
  const grant = session ? await deps.repositories.findGrantById(session.grant_id) : null;
  const now = new Date();
  const active =
    Boolean(session && session.status === "active" && session.expires_at > now && session.tool_id === tool.id) &&
    Boolean(user && user.status === "active") &&
    Boolean(grant && grant.tool_id === tool.id && isGrantCurrentlyUsable(grant));
  if (!active || !session || !user || !grant) {
    return { active: false, reason: "revoked" };
  }
  return {
    active: true,
    issuer: claims.iss,
    audience: claims.aud,
    expires_at: new Date((claims.exp ?? 0) * 1000).toISOString(),
    session_id: session.id,
    user: {
      google_sub: user.google_sub,
      email: user.email,
      hd: user.hd
    },
    permissions: grant.permissions
  };
}

async function requireUserToken(request: FastifyRequest, deps: AppDependencies): Promise<Record<string, unknown>> {
  const correlationId = randomToken("corr_", 16);
  const token = readBearerOrAdminCookie(request, deps.config);
  if (!token) {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  let claims;
  try {
    claims = await deps.tokenService.verifyAccessToken(token);
  } catch {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  const user = await deps.repositories.findUserByGoogleSub(claims.sub);
  const session = await deps.repositories.findSessionById(claims.sid);
  const grant = session ? await deps.repositories.findGrantById(session.grant_id) : null;
  if (!user || !session || !grant || user.status !== "active" || session.status !== "active" || !isGrantCurrentlyUsable(grant)) {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  return {
    user: userResponse(user),
    tool_slug: claims.tool_slug,
    role: grant.role,
    permissions: grant.permissions,
    session_id: claims.sid
  };
}

function readBearerOrAdminCookie(request: FastifyRequest, config: Config): string | null {
  const auth = request.headers.authorization ?? "";
  if (auth.startsWith("Bearer ")) {
    return auth.slice("Bearer ".length);
  }
  const cookies = parseCookies(request.headers.cookie);
  const signed = cookies[config.sessionCookieName];
  return verifySignedCookie(signed, config.sessionSecret);
}

function readAdminRefreshCookie(request: FastifyRequest, config: Config): string | null {
  const cookies = parseCookies(request.headers.cookie);
  return verifySignedCookie(cookies[adminRefreshCookieName(config)], config.sessionSecret);
}

function adminAuthCookieHeaders(config: Config, accessToken: string, refreshToken: string): string[] {
  const common = {
    httpOnly: true,
    secure: config.appEnv === "production",
    path: adminCookiePath(config)
  };
  return [
    cookieHeader(config.sessionCookieName, signCookie(accessToken, config.sessionSecret), {
      ...common,
      maxAge: config.accessTokenTtlSeconds
    }),
    cookieHeader(adminRefreshCookieName(config), signCookie(refreshToken, config.sessionSecret), {
      ...common,
      maxAge: config.refreshTokenTtlSeconds
    })
  ];
}

function clearAdminAuthCookieHeaders(config: Config): string[] {
  const common = {
    maxAge: 0,
    httpOnly: true,
    secure: config.appEnv === "production",
    path: adminCookiePath(config)
  };
  return [
    cookieHeader(config.sessionCookieName, "", common),
    cookieHeader(adminRefreshCookieName(config), "", common)
  ];
}

async function enforceRateLimit(
  rateLimitCheck: RateLimitCheck,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<boolean> {
  const result = await rateLimitCheck(request);
  if (result.isAllowed) {
    return true;
  }
  if (!result.isExceeded && !result.isBanned) {
    return true;
  }
  sendJsonError(reply, new AppError("RATE_LIMITED", randomToken("corr_", 16)));
  return false;
}

function readBasicClientId(request: FastifyRequest): string | null {
  const auth = request.headers.authorization ?? "";
  const [scheme, encoded] = auth.split(" ");
  if (scheme !== "Basic" || !encoded) {
    return null;
  }
  try {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator <= 0) return null;
    return decoded.slice(0, separator);
  } catch {
    return null;
  }
}

function isAllowedAdminMutationOrigin(request: FastifyRequest, config: Config): boolean {
  const auth = request.headers.authorization ?? "";
  if (auth.startsWith("Bearer ")) {
    return true;
  }
  const origin = request.headers.origin;
  if (typeof origin !== "string") {
    return false;
  }
  return origin === new URL(config.appBaseUrl).origin;
}

function readAdminRateLimitKey(request: FastifyRequest, config: Config): string {
  const token = readBearerOrAdminCookie(request, config);
  if (token) {
    return `admin:${hashOpaque(token, config.logIpSalt)}`;
  }
  return `admin:${hashRequestField(request.ip, config.logIpSalt) ?? "unknown-ip"}`;
}

function hasValidBackupApiToken(request: FastifyRequest, config: Config): boolean {
  if (!config.backupApiToken) return false;
  const auth = request.headers.authorization ?? "";
  const [scheme, token] = auth.split(" ");
  return scheme === "Bearer" && typeof token === "string" && constantTimeEqualString(token, config.backupApiToken);
}

async function buildBackupPayload(repositories: Repositories, actor: AdminActor | null, authMode: "admin_session" | "api_token"): Promise<Record<string, unknown>> {
  const data = await repositories.exportBackup();
  return {
    schema: BACKUP_SCHEMA,
    version: BACKUP_VERSION,
    generated_at: new Date().toISOString(),
    generated_by: actor
      ? { type: authMode, user_id: actor.userId, email: actor.email }
      : { type: authMode },
    contents: {
      users: true,
      tools: true,
      tool_clients: true,
      tool_client_secret_material: "client_secret_hash_only",
      tool_permissions: true,
      authorization_grants: true,
      admin_tool_assignments: true,
      access_requests: true,
      sessions: false,
      refresh_tokens: false,
      auth_requests: false,
      one_time_codes: false,
      audit_logs: false
    },
    restore_requirements: [
      "Keep the same TOOL_CLIENT_SECRET_PEPPER if existing tool client secrets must continue to work after restore.",
      "Keep or restore JWT_PRIVATE_KEY_PEM/JWT_PRIVATE_KEY_PEM_PATH, JWT_PUBLIC_KEY_ID, SESSION_SECRET and Google OAuth env vars outside this backup.",
      "Run migrations before importing this backup. For a full disaster restore, import with replace_existing=true into the newly migrated database."
    ],
    data
  };
}

function validateBackupPayload(backup: Record<string, unknown>, correlationId: string, config: Config): Record<string, unknown> {
  let decoded = backup;
  if (backup.schema === "access-layer-encrypted-backup") {
    if (!config.backupEncryptionKey) {
      throw new AppError("VALIDATION_ERROR", correlationId);
    }
    try {
      decoded = decryptJsonPayload(backup, config.backupEncryptionKey);
    } catch {
      throw new AppError("VALIDATION_ERROR", correlationId);
    }
  }

  if (decoded.schema !== BACKUP_SCHEMA || decoded.version !== BACKUP_VERSION || typeof decoded.data !== "object" || decoded.data === null) {
    throw new AppError("VALIDATION_ERROR", correlationId);
  }
  const data = decoded.data as Record<string, unknown>;
  for (const section of [
    "users",
    "tools",
    "tool_clients",
    "tool_permissions",
    "authorization_grants",
    "admin_tool_assignments",
    "access_requests"
  ]) {
    if (!Array.isArray(data[section])) {
      throw new AppError("VALIDATION_ERROR", correlationId);
    }
  }
  return data;
}

async function requireAdminActor(
  request: FastifyRequest,
  deps: AppDependencies,
  required: string,
  assignedRequired?: string
): Promise<AdminActor> {
  const correlationId = randomToken("corr_", 16);
  const token = readBearerOrAdminCookie(request, deps.config);
  if (!token) {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  let claims;
  try {
    claims = await deps.tokenService.verifyAccessToken(token, ADMIN_TOOL_SLUG);
  } catch {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  const user = await deps.repositories.findUserByGoogleSub(claims.sub);
  const session = await deps.repositories.findSessionById(claims.sid);
  const grant = session ? await deps.repositories.findGrantById(session.grant_id) : null;
  if (!user || !session || !grant || user.status !== "active" || session.status !== "active" || !isGrantCurrentlyUsable(grant)) {
    throw new AppError("AUTH_INVALID_STATE", correlationId);
  }
  const assignedToolIds = await deps.repositories.listAssignedToolIds(user.id, user.email_normalized);
  const actor: AdminActor = {
    userId: user.id,
    googleSub: user.google_sub,
    email: user.email,
    hd: user.hd,
    role: grant.role,
    permissions: grant.permissions,
    assignedToolIds
  };
  const allowed =
    hasPermission(actor.permissions, required) ||
    (assignedRequired !== undefined && hasPermission(actor.permissions, assignedRequired) && assignedToolIds.length > 0);
  if (!allowed) {
    throw new AppError("ADMIN_FORBIDDEN", correlationId);
  }
  return actor;
}

function registerAdminUi(
  app: FastifyInstance,
  deps: AppDependencies,
  contextFor: (request: FastifyRequest, correlationId?: string) => RequestContext
): void {
  app.get(joinPublicPath(deps.config.publicBasePath, "/favicon.svg"), async (_request, reply) => {
    return reply
      .header("cache-control", "public, max-age=86400")
      .type("image/svg+xml; charset=utf-8")
      .send(FAVICON_SVG);
  });

  app.get(adminUiPath(deps.config, "/login"), async (request, reply) => {
    const state = randomToken("adm_", 24);
    const adminCallbackPath = deps.config.publicBasePath ? "/auth/callback" : "/admin/auth/callback";
    const callback = publicUrl(deps.config, adminCallbackPath);
    const url = new URL(publicUrl(deps.config, "/v1/auth/start"));
    url.searchParams.set("tool_slug", ADMIN_TOOL_SLUG);
    url.searchParams.set("return_url", callback);
    url.searchParams.set("state", state);
    reply.header(
      "Set-Cookie",
      cookieHeader("access_layer_admin_login_state", signCookie(state, deps.config.sessionSecret), {
        maxAge: 600,
        httpOnly: true,
        secure: deps.config.appEnv === "production",
        path: adminCookiePath(deps.config)
      })
    );
    return reply.redirect(url.toString());
  });

  app.get(adminUiPath(deps.config, "/auth/callback"), async (request, reply) => {
    const query = request.query as { code?: string; state?: string };
    const cookies = parseCookies(request.headers.cookie);
    const expectedState = verifySignedCookie(cookies.access_layer_admin_login_state, deps.config.sessionSecret);
    const ctx = contextFor(request);
    if (!query.code || !query.state || query.state !== expectedState) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_state",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_slug: ADMIN_TOOL_SLUG,
        reason_code: "AUTH_INVALID_STATE",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_STATE", ctx.correlationId));
    }
    const tool = await deps.repositories.findToolBySlug(ADMIN_TOOL_SLUG);
    if (!tool) {
      await deps.audit.write({
        event_type: "auth.denied.invalid_tool",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_slug: ADMIN_TOOL_SLUG,
        reason_code: "AUTH_INVALID_TOOL",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      return reply.type("text/html").status(400).send(safeErrorPage("AUTH_INVALID_TOOL", ctx.correlationId));
    }
    const result = await exchangeOneTimeCode({
      deps,
      code: query.code,
      redirectUri: publicUrl(deps.config, deps.config.publicBasePath ? "/auth/callback" : "/admin/auth/callback"),
      tool,
      ctx,
      requestIpHash: ctx.requestIpHash,
      userAgentHash: ctx.userAgentHash
    });
    const authCookies = result.refresh_token
      ? adminAuthCookieHeaders(deps.config, result.access_token, result.refresh_token)
      : [
          cookieHeader(deps.config.sessionCookieName, signCookie(result.access_token, deps.config.sessionSecret), {
            maxAge: deps.config.accessTokenTtlSeconds,
            httpOnly: true,
            secure: deps.config.appEnv === "production",
            path: adminCookiePath(deps.config)
          })
        ];
    reply.header("Set-Cookie", [
      ...authCookies,
      cookieHeader("access_layer_admin_login_state", "", {
        maxAge: 0,
        httpOnly: true,
        secure: deps.config.appEnv === "production",
        path: adminCookiePath(deps.config)
      })
    ]);
    return reply.redirect(adminUiPath(deps.config));
  });

  app.post(adminUiPath(deps.config, "/refresh"), async (request, reply) => {
    const ctx = contextFor(request);
    if (!isAllowedAdminMutationOrigin(request, deps.config)) {
      await deps.audit.write({
        event_type: "admin.csrf.denied",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        tool_slug: ADMIN_TOOL_SLUG,
        reason_code: "ADMIN_FORBIDDEN",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      throw new AppError("ADMIN_FORBIDDEN", ctx.correlationId);
    }
    const refreshToken = readAdminRefreshCookie(request, deps.config);
    const tool = await deps.repositories.findToolBySlug(ADMIN_TOOL_SLUG);
    if (!deps.config.enableRefreshTokens || !refreshToken || !tool || tool.status !== "active") {
      reply.header("Set-Cookie", clearAdminAuthCookieHeaders(deps.config));
      throw new AppError("AUTH_REFRESH_TOKEN_INVALID", ctx.correlationId);
    }
    try {
      const result = await refreshAccessToken({
        deps,
        refreshToken,
        tool,
        ctx
      });
      reply.header("Set-Cookie", adminAuthCookieHeaders(deps.config, result.access_token, result.refresh_token));
      return reply.header("Cache-Control", "no-store").header("Pragma", "no-cache").status(204).send();
    } catch (error) {
      reply.header("Set-Cookie", clearAdminAuthCookieHeaders(deps.config));
      throw error;
    }
  });

  app.post(adminUiPath(deps.config, "/logout"), async (request, reply) => {
    const ctx = contextFor(request);
    if (!isAllowedAdminMutationOrigin(request, deps.config)) {
      await deps.audit.write({
        event_type: "admin.csrf.denied",
        outcome: "denied",
        correlation_id: ctx.correlationId,
        reason_code: "ADMIN_FORBIDDEN",
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash
      });
      throw new AppError("ADMIN_FORBIDDEN", ctx.correlationId);
    }
    const refreshToken = readAdminRefreshCookie(request, deps.config);
    const token = readBearerOrAdminCookie(request, deps.config);
    if (token) {
      let claims: Awaited<ReturnType<TokenService["verifyAccessToken"]>> | null = null;
      try {
        claims = await deps.tokenService.verifyAccessToken(token, ADMIN_TOOL_SLUG);
      } catch {
        await deps.audit.write({
          event_type: "session.revoke.denied",
          outcome: "denied",
          correlation_id: ctx.correlationId,
          reason_code: "AUTH_INVALID_STATE",
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
      }
      if (claims) {
        const user = await deps.repositories.findUserByGoogleSub(claims.sub);
        const session = await deps.repositories.findSessionById(claims.sid);
        if (user && session) {
          const tool = await deps.repositories.findToolById(session.tool_id);
          const revoked = await deps.repositories.revokeSession(session.id);
          if (revoked > 0) {
            await deps.audit.write({
              event_type: "session.revoked",
              outcome: "success",
              correlation_id: ctx.correlationId,
              tool_id: tool?.id ?? session.tool_id,
              tool_slug: tool?.slug ?? ADMIN_TOOL_SLUG,
              actor_user_id: user.id,
              actor_google_sub: user.google_sub,
              actor_email: user.email,
              actor_hd: user.hd,
              request_ip_hash: ctx.requestIpHash,
              user_agent_hash: ctx.userAgentHash,
              metadata: { revoked_count: revoked, session_id: session.id, admin_ui: true }
            });
          } else {
            await deps.audit.write({
              event_type: "session.revoke.denied",
              outcome: "denied",
              correlation_id: ctx.correlationId,
              tool_id: tool?.id ?? session.tool_id,
              tool_slug: tool?.slug ?? ADMIN_TOOL_SLUG,
              actor_user_id: user.id,
              actor_google_sub: user.google_sub,
              actor_email: user.email,
              actor_hd: user.hd,
              reason_code: "TOKEN_INACTIVE",
              request_ip_hash: ctx.requestIpHash,
              user_agent_hash: ctx.userAgentHash,
              metadata: { session_id: session.id, admin_ui: true }
            });
          }
        } else {
          await deps.audit.write({
            event_type: "session.revoke.denied",
            outcome: "denied",
            correlation_id: ctx.correlationId,
            reason_code: "AUTH_INVALID_STATE",
            request_ip_hash: ctx.requestIpHash,
            user_agent_hash: ctx.userAgentHash
          });
        }
      }
    }
    if (refreshToken) {
      const refreshHash = hashOpaque(refreshToken, deps.config.toolClientSecretPepper);
      const refresh = await deps.repositories.findRefreshTokenByHash(refreshHash);
      const session = refresh ? await deps.repositories.findSessionById(refresh.session_id) : null;
      if (session) {
        await deps.repositories.revokeSession(session.id);
      }
      await deps.repositories.revokeRefreshToken(refreshHash);
    }
    reply.header("Set-Cookie", clearAdminAuthCookieHeaders(deps.config));
    return reply.status(204).send();
  });

  app.get(adminUiPath(deps.config), async (request, reply) => {
    const hasSession =
      (await hasRenderableAdminUiSession(request, deps)) ||
      (await refreshRenderableAdminUiSession(request, reply, deps, contextFor(request)));
    if (!hasSession) {
      return reply.redirect(adminUiPath(deps.config, "/login"));
    }
    return reply.type("text/html").send(adminHtml(deps.config));
  });
}

async function hasRenderableAdminUiSession(request: FastifyRequest, deps: AppDependencies): Promise<boolean> {
  const token = readBearerOrAdminCookie(request, deps.config);
  if (!token) return false;
  try {
    const claims = await deps.tokenService.verifyAccessToken(token, ADMIN_TOOL_SLUG);
    const user = await deps.repositories.findUserByGoogleSub(claims.sub);
    const session = await deps.repositories.findSessionById(claims.sid);
    const grant = session ? await deps.repositories.findGrantById(session.grant_id) : null;
    if (!user || !session || !grant || user.status !== "active" || session.status !== "active" || !isGrantCurrentlyUsable(grant)) {
      return false;
    }
    return hasRenderableAdminPermission(grant.permissions);
  } catch {
    return false;
  }
}

async function refreshRenderableAdminUiSession(
  request: FastifyRequest,
  reply: FastifyReply,
  deps: AppDependencies,
  ctx: RequestContext
): Promise<boolean> {
  if (!deps.config.enableRefreshTokens) return false;
  const refreshToken = readAdminRefreshCookie(request, deps.config);
  if (!refreshToken) return false;
  const tool = await deps.repositories.findToolBySlug(ADMIN_TOOL_SLUG);
  if (!tool || tool.status !== "active") return false;
  try {
    const result = await refreshAccessToken({ deps, refreshToken, tool, ctx });
    if (!hasRenderableAdminPermission(result.grant.permissions)) {
      reply.header("Set-Cookie", clearAdminAuthCookieHeaders(deps.config));
      return false;
    }
    reply.header("Set-Cookie", adminAuthCookieHeaders(deps.config, result.access_token, result.refresh_token));
    reply.header("Cache-Control", "no-store");
    return true;
  } catch {
    reply.header("Set-Cookie", clearAdminAuthCookieHeaders(deps.config));
    return false;
  }
}

function hasRenderableAdminPermission(permissions: string[]): boolean {
  return (
    hasPermission(permissions, "admin:tools:read") ||
    hasPermission(permissions, "admin:tools:read_assigned") ||
    hasPermission(permissions, "admin:users:read") ||
    hasPermission(permissions, "admin:grants:read") ||
    hasPermission(permissions, "admin:grants:read_assigned") ||
    hasPermission(permissions, "admin:access_requests:read") ||
    hasPermission(permissions, "admin:access_requests:read_assigned") ||
    hasPermission(permissions, "admin:audit:read") ||
    hasPermission(permissions, "admin:audit:read_assigned") ||
    hasPermission(permissions, "admin:backup:read")
  );
}

function registerAdminApi(
  app: FastifyInstance,
  deps: AppDependencies,
  contextFor: (request: FastifyRequest, correlationId?: string) => RequestContext,
  adminWriteRateLimit: RateLimitCheck
): void {
  const admin = (required: string, assigned?: string, handler?: RouteHandlerMethod): RouteHandlerMethod => {
    return async (request, reply) => {
      if (request.method !== "GET") {
        if (!isAllowedAdminMutationOrigin(request, deps.config)) {
          throw new AppError("ADMIN_FORBIDDEN", randomToken("corr_", 16));
        }
        const allowed = await enforceRateLimit(adminWriteRateLimit, request, reply);
        if (!allowed) return reply;
      }
      const actor = await requireAdminActor(request, deps, required, assigned);
      (request as FastifyRequest & { adminActor?: AdminActor }).adminActor = actor;
      return handler?.call(app, request, reply);
    };
  };

  app.get(
    apiPath(deps.config, "/v1/admin/tools"),
    admin("admin:tools:read", "admin:tools:read_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const query = request.query as { search?: string; status?: string; owner_email?: string };
      const status = parseToolStatus(query.status);
      if (status === null) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const tools = await deps.repositories.listTools({
        assignedToolIds: assigned,
        search: query.search,
        status,
        ownerEmail: query.owner_email ? normalizeEmail(query.owner_email) : undefined,
        limit: 200
      });
      const items = await Promise.all(
        tools.map(async (tool) => {
          const clientIds = await deps.repositories.listToolClientPublicIds(tool.id);
          return {
            ...tool,
            permission_keys: await deps.repositories.listToolPermissions(tool.id),
            client_ids: clientIds.map((client) => client.client_id)
          };
        })
      );
      return { items };
    })
  );

  app.post(
    apiPath(deps.config, "/v1/admin/tools"),
    admin("admin:tools:write", undefined, async (request, reply) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const body = request.body as {
        slug?: string;
        display_name?: string;
        description?: string | null;
        allowed_return_urls?: string[];
        owner_email?: string | null;
        permission_keys?: string[];
      };
      if (!body?.slug || !body.display_name || !Array.isArray(body.allowed_return_urls) || !validateToolSlug(body.slug)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      for (const url of body.allowed_return_urls) {
        if (!validateReturnUrlExact(url, [url], deps.config.returnUrlAllowedSchemes)) {
          throw new AppError("AUTH_INVALID_RETURN_URL", ctx.correlationId);
        }
      }
      if (body.permission_keys !== undefined && (!Array.isArray(body.permission_keys) || !validatePermissions(body.permission_keys))) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const result = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const permissionKeys = body.permission_keys ?? [];
        const tool = await repos.createTool({
          slug: body.slug!.toLowerCase(),
          displayName: body.display_name!,
          description: body.description,
          allowedReturnUrls: body.allowed_return_urls!,
          ownerEmail: body.owner_email ? normalizeEmail(body.owner_email) : null
        });
        await repos.replaceToolPermissions(tool.id, permissionKeys);
        const clientId = randomToken("tlc_", 18);
        const clientSecret = randomToken("tls_", 32);
        await repos.createToolClient(tool.id, clientId, await hashToolSecret(clientSecret, deps.config.toolClientSecretPepper));
        const audit = new AuditLogger(repos);
        await audit.write({
          event_type: "admin.tool.created",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
        return { tool: { ...tool, permission_keys: permissionKeys }, clientId, clientSecret };
      });
      return reply.status(201).send({
        tool: result.tool,
        tool_client_id: result.clientId,
        tool_client_secret: result.clientSecret
      });
    })
  );

  app.patch(
    apiPath(deps.config, "/v1/admin/tools/:tool_id"),
    admin("admin:tools:write", undefined, async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const params = request.params as { tool_id: string };
      const body = request.body as {
        display_name?: string;
        description?: string | null;
        status?: string;
        allowed_return_urls?: string[];
        owner_email?: string | null;
        permission_keys?: string[];
      };
      if (body.status && !["active", "disabled", "maintenance"].includes(body.status)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      if (body.allowed_return_urls) {
        for (const url of body.allowed_return_urls) {
          if (!validateReturnUrlExact(url, [url], deps.config.returnUrlAllowedSchemes)) {
            throw new AppError("AUTH_INVALID_RETURN_URL", ctx.correlationId);
          }
        }
      }
      if (body.permission_keys !== undefined && (!Array.isArray(body.permission_keys) || !validatePermissions(body.permission_keys))) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const updated = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const tool = await repos.updateTool(params.tool_id, {
          displayName: body.display_name,
          description: body.description,
          status: body.status,
          allowedReturnUrls: body.allowed_return_urls,
          ownerEmail: body.owner_email ? normalizeEmail(body.owner_email) : body.owner_email
        });
        if (!tool) throw new AppError("AUTH_INVALID_TOOL", ctx.correlationId);
        if (body.permission_keys !== undefined) await repos.replaceToolPermissions(tool.id, body.permission_keys);
        const permissionKeys = body.permission_keys ?? (await repos.listToolPermissions(tool.id));
        await new AuditLogger(repos).write({
          event_type: "admin.tool.updated",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash
        });
        return { ...tool, permission_keys: permissionKeys };
      });
      return { tool: updated };
    })
  );

  app.delete(
    apiPath(deps.config, "/v1/admin/tools/:tool_id"),
    admin("admin:tools:write", undefined, async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const params = request.params as { tool_id: string };
      const deleted = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const tool = await repos.findToolById(params.tool_id);
        if (!tool) throw new AppError("AUTH_INVALID_TOOL", ctx.correlationId);
        if (tool.slug === ADMIN_TOOL_SLUG) throw new AppError("ADMIN_FORBIDDEN", ctx.correlationId);
        await new AuditLogger(repos).write({
          event_type: "admin.tool.deleted",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { target_tool_id: tool.id }
        });
        const removed = await repos.deleteTool(tool.id);
        if (!removed) throw new AppError("AUTH_INVALID_TOOL", ctx.correlationId);
        return removed;
      });
      return { tool: deleted };
    })
  );

  app.post(
    apiPath(deps.config, "/v1/admin/tools/:tool_id/rotate-secret"),
    admin("admin:secrets:rotate", undefined, async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const params = request.params as { tool_id: string };
      const body = (request.body ?? {}) as { revoke_existing?: boolean };
      const clientId = randomToken("tlc_", 18);
      const clientSecret = randomToken("tls_", 32);
      await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const tool = await repos.findToolById(params.tool_id);
        if (!tool) throw new AppError("AUTH_INVALID_TOOL", ctx.correlationId);
        if (body.revoke_existing === true) {
          await repos.disableToolClients(tool.id);
        }
        await repos.createToolClient(tool.id, clientId, await hashToolSecret(clientSecret, deps.config.toolClientSecretPepper));
        await new AuditLogger(repos).write({
          event_type: "admin.tool.secret_rotated",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { revoked_existing_clients: body.revoke_existing === true }
        });
      });
      return { tool_client_id: clientId, tool_client_secret: clientSecret };
    })
  );

  app.get(
    apiPath(deps.config, "/v1/admin/backup/export"),
    async (request, reply) => {
      const ctx = contextFor(request);
      let actor: AdminActor | null = null;
      let authMode: "admin_session" | "api_token" = "api_token";
      if (!hasValidBackupApiToken(request, deps.config)) {
        actor = await requireAdminActor(request, deps, "admin:backup:read");
        authMode = "admin_session";
      }
      if (!deps.config.backupEncryptionKey) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const backup = await buildBackupPayload(deps.repositories, actor, authMode);
      const encryptedBackup = encryptJsonPayload(backup, deps.config.backupEncryptionKey);
      await deps.audit.write({
        event_type: "admin.backup.exported",
        outcome: "success",
        correlation_id: ctx.correlationId,
        actor_user_id: actor?.userId ?? null,
        actor_google_sub: actor?.googleSub ?? null,
        actor_email: actor?.email ?? null,
        actor_hd: actor?.hd ?? null,
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash,
        metadata: { auth_mode: authMode, version: BACKUP_VERSION }
      });
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Content-Disposition", `attachment; filename="access-layer-backup-${stamp}.json"`)
        .send(encryptedBackup);
    }
  );

  app.get(
    apiPath(deps.config, "/v1/admin/backup/secret-material"),
    admin("admin:backup:secrets", undefined, async (request, reply) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      await deps.audit.write({
        event_type: "admin.backup.secret_material_exported",
        outcome: "success",
        correlation_id: ctx.correlationId,
        actor_user_id: actor.userId,
        actor_google_sub: actor.googleSub,
        actor_email: actor.email,
        actor_hd: actor.hd,
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash,
        metadata: { restore_material_export: true, backup_key_present: Boolean(deps.config.backupEncryptionKey) }
      });
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      return reply
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Content-Disposition", `attachment; filename="access-layer-restore-secret-material-${stamp}.json"`)
        .send({
          exported_at: new Date().toISOString(),
          secret_material: {
            TOOL_CLIENT_SECRET_PEPPER: deps.config.toolClientSecretPepper,
            BACKUP_ENCRYPTION_KEY: deps.config.backupEncryptionKey ?? null
          },
          notes: [
            "Existing per-tool client secrets are not recoverable because only hashes are stored.",
            "New per-tool client secrets are shown only once during tool creation or rotation."
          ]
        });
    })
  );

  app.post(
    apiPath(deps.config, "/v1/admin/backup/import"),
    admin("admin:backup:write", undefined, async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const body = (request.body ?? {}) as { backup?: unknown; replace_existing?: boolean; confirm_replace?: boolean };
      const backup = (body.backup ?? body) as Record<string, unknown>;
      const replaceExisting = body.replace_existing === true;
      if (replaceExisting && body.confirm_replace !== true) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const data = validateBackupPayload(backup, ctx.correlationId, deps.config);
      const counts = await deps.repositories.importBackup(data, { replaceExisting });
      await deps.audit.write({
        event_type: "admin.backup.imported",
        outcome: "success",
        correlation_id: ctx.correlationId,
        actor_user_id: replaceExisting ? null : actor.userId,
        actor_google_sub: replaceExisting ? null : actor.googleSub,
        actor_email: actor.email,
        actor_hd: actor.hd,
        request_ip_hash: ctx.requestIpHash,
        user_agent_hash: ctx.userAgentHash,
        metadata: { replace_existing: replaceExisting, counts }
      });
      return { imported: true, replace_existing: replaceExisting, counts };
    })
  );

  app.get(
    apiPath(deps.config, "/v1/admin/users"),
    admin("admin:users:read", undefined, async (request) => {
      const ctx = contextFor(request);
      const query = request.query as { search?: string; status?: string };
      const status = parseUserStatus(query.status);
      if (status === null) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const users = await deps.repositories.listUsers({
        search: query.search,
        status,
        limit: 200
      });
      return { items: users.map(userResponse) };
    })
  );

  app.patch(
    apiPath(deps.config, "/v1/admin/users/:user_id"),
    admin("admin:users:write", undefined, async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const params = request.params as { user_id: string };
      const body = request.body as { status?: "active" | "suspended" | "disabled" };
      if (!body.status || !["active", "suspended", "disabled"].includes(body.status)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const result = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const user = await repos.updateUserStatus(params.user_id, body.status!);
        if (!user) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
        let revokedSessions = 0;
        if (body.status !== "active") {
          revokedSessions = await repos.revokeSessionsForUser(user.id);
        }
        await new AuditLogger(repos).write({
          event_type: "admin.user.status_changed",
          outcome: "success",
          correlation_id: ctx.correlationId,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { target_user_id: user.id, status: user.status, revoked_sessions: revokedSessions }
        });
        return { user, revokedSessions };
      });
      return { user: userResponse(result.user), revoked_sessions: result.revokedSessions };
    })
  );

  app.get(
    apiPath(deps.config, "/v1/admin/grants"),
    admin("admin:grants:read", "admin:grants:read_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const query = request.query as { tool_slug?: string; email?: string; status?: string };
      const status = parseGrantStatus(query.status);
      if (status === null) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const grants = await deps.repositories.listGrants({
        toolSlug: query.tool_slug,
        email: query.email ? normalizeEmail(query.email) : undefined,
        status,
        assignedToolIds: assigned,
        limit: 200
      });
      return { items: grants };
    })
  );

  app.get(
    apiPath(deps.config, "/v1/admin/grants/export"),
    admin("admin:grants:read", "admin:grants:read_assigned", async (request, reply) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const grants = await deps.repositories.listGrants({ assignedToolIds: assigned, limit: 10000 });
      const csv = toCsv(
        ["email", "tool_slug", "role", "permissions", "status", "valid_from", "valid_until", "grant_id", "user_id"],
        grants.map((grant) => ({
          email: String(grant.user_email ?? grant.email_normalized ?? ""),
          tool_slug: String(grant.tool_slug ?? ""),
          role: String(grant.role ?? ""),
          permissions: Array.isArray(grant.permissions) ? grant.permissions.join(";") : "",
          status: String(grant.status ?? ""),
          valid_from: formatCsvDate(grant.valid_from),
          valid_until: formatCsvDate(grant.valid_until),
          grant_id: String(grant.id ?? ""),
          user_id: String(grant.user_id ?? "")
        }))
      );
      return reply
        .header("content-disposition", "attachment; filename=access-layer-grants-export.csv")
        .type("text/csv; charset=utf-8")
        .send(csv);
    })
  );

  app.get(
    apiPath(deps.config, "/v1/admin/grants/bulk/template"),
    admin("admin:grants:read", "admin:grants:read_assigned", async (_request, reply) => {
      return reply
        .header("content-disposition", "attachment; filename=access-layer-grants-bulk-template.csv")
        .type("text/csv; charset=utf-8")
        .send(BULK_GRANT_TEMPLATE_CSV);
    })
  );

  app.get(
    apiPath(deps.config, "/v1/admin/tools/permissions/export"),
    admin("admin:tools:read", "admin:tools:read_assigned", async (request, reply) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const catalog = await deps.repositories.listToolPermissionCatalog({ assignedToolIds: assigned, limit: 10000 });
      const csv = toCsv(
        ["tool_slug", "tool_name", "tool_status", "permission_key", "permission_description"],
        catalog.map((row) => ({
          tool_slug: row.tool_slug,
          tool_name: row.tool_name,
          tool_status: row.tool_status,
          permission_key: row.permission_key,
          permission_description: row.permission_description ?? ""
        }))
      );
      return reply
        .header("content-disposition", "attachment; filename=access-layer-tool-permissions.csv")
        .type("text/csv; charset=utf-8")
        .send(csv);
    })
  );

  app.post(
    apiPath(deps.config, "/v1/admin/grants/bulk/preview"),
    admin("admin:grants:write", "admin:grants:write_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const parsed = parseBulkGrantRequest(request.body, ctx.correlationId);
      return previewBulkGrantImport(deps, actor, parsed);
    })
  );

  app.post(
    apiPath(deps.config, "/v1/admin/grants/bulk/commit"),
    admin("admin:grants:write", "admin:grants:write_assigned", async (request, reply) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const parsed = parseBulkGrantRequest(request.body, ctx.correlationId);
      const preview = await previewBulkGrantImport(deps, actor, parsed);
      if (preview.summary.error > 0) {
        return { committed: false, ...preview };
      }
      const committed = await commitBulkGrantImport(deps, actor, ctx, preview.rows);
      return reply.status(201).send({ committed: true, ...committed });
    })
  );

  app.post(
    apiPath(deps.config, "/v1/admin/grants"),
    admin("admin:grants:write", "admin:grants:write_assigned", async (request, reply) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const body = request.body as {
        tool_slug?: string;
        user_id?: string;
        email?: string;
        role?: string;
        permissions?: string[];
        valid_until?: string | null;
      };
      if (!body.tool_slug || !body.role || !Array.isArray(body.permissions) || !validatePermissions(body.permissions)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      if (!validateOptionalUtcDateTime(body.valid_until)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const grantRole = body.role;
      const grantPermissions = body.permissions;
      const tool = await deps.repositories.findToolBySlug(body.tool_slug);
      if (!tool) throw new AppError("AUTH_INVALID_TOOL", ctx.correlationId);
      if (actor.role === "tool_admin" && !actor.assignedToolIds.includes(tool.id)) {
        throw new AppError("ADMIN_FORBIDDEN", ctx.correlationId);
      }
      await assertKnownPermissions(deps.repositories, tool.id, grantPermissions, ctx.correlationId);
      const user = body.user_id
        ? await deps.repositories.findUserById(body.user_id)
        : body.email
          ? await deps.repositories.findUserByEmail(normalizeEmail(body.email))
          : null;
      const emailNormalized = user ? user.email_normalized : body.email ? normalizeEmail(body.email) : undefined;
      if (body.user_id && !user) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      if (!body.user_id && !emailNormalized) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      if (!user && emailNormalized && !isAllowedPendingGrantEmail(
        emailNormalized,
        deps.config.googleAllowedHd,
        deps.config.microsoftAllowedEmailDomains ?? []
      )) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const grant = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const created = await repos.createGrant({
          toolId: tool.id,
          userId: user?.id ?? null,
          emailNormalized,
          role: grantRole,
          permissions: grantPermissions,
          status: user ? "active" : "pending_user_link",
          validUntil: body.valid_until ?? null,
          createdByUserId: actor.userId
        });
        await new AuditLogger(repos).write({
          event_type: "admin.grant.created",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { grant_id: created.id, target_user_id: user?.id ?? null, target_email: emailNormalized }
        });
        return created;
      });
      return reply.status(201).send({
        grant_id: grant.id,
        status: grant.status,
        link_status: user ? "linked" : "pending_user_link",
        tool_slug: tool.slug,
        email: emailNormalized,
        role: grant.role,
        permissions: grant.permissions
      });
    })
  );

  app.patch(
    apiPath(deps.config, "/v1/admin/grants/:grant_id"),
    admin("admin:grants:write", "admin:grants:write_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const params = request.params as { grant_id: string };
      const body = request.body as { role?: string; permissions?: string[]; status?: string; valid_until?: string | null };
      if (body.permissions && !validatePermissions(body.permissions)) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      if (body.status && !["active", "revoked", "expired", "pending_user_link"].includes(body.status)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      if (!validateOptionalUtcDateTime(body.valid_until)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const result = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const current = await repos.findGrantById(params.grant_id);
        if (!current) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
        const tool = await repos.findToolById(current.tool_id);
        if (!tool) throw new AppError("AUTH_INVALID_TOOL", ctx.correlationId);
        if (actor.role === "tool_admin" && !actor.assignedToolIds.includes(tool.id)) {
          throw new AppError("ADMIN_FORBIDDEN", ctx.correlationId);
        }
        if (body.permissions) await assertKnownPermissions(repos, tool.id, body.permissions, ctx.correlationId);
        const updated = await repos.updateGrant(params.grant_id, {
          role: body.role,
          permissions: body.permissions,
          status: body.status,
          validUntil: body.valid_until,
          revokedByUserId: body.status === "revoked" ? actor.userId : null
        });
        if (!updated) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
        let revoked = 0;
        if (updated.status === "revoked") revoked = await repos.revokeSessionsForGrant(updated.id);
        await new AuditLogger(repos).write({
          event_type: updated.status === "revoked" ? "admin.grant.revoked" : "admin.grant.updated",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: tool.id,
          tool_slug: tool.slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { grant_id: updated.id, revoked_sessions: revoked }
        });
        return { grant: updated, revoked };
      });
      return { grant: result.grant, revoked_sessions: result.revoked };
    })
  );

  app.get(
    apiPath(deps.config, "/v1/admin/access-requests"),
    admin("admin:access_requests:read", "admin:access_requests:read_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const query = request.query as { status?: string; tool_slug?: string; email?: string };
      const status = parseAccessRequestStatus(query.status);
      if (status === null) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const items = await deps.repositories.listAccessRequests({
        status,
        toolSlug: query.tool_slug,
        email: query.email ? normalizeEmail(query.email) : undefined,
        assignedToolIds: assigned,
        limit: 200
      });
      return { items, pagination: { next_cursor: null } };
    })
  );

  app.post(
    apiPath(deps.config, "/v1/admin/access-requests/:request_id/approve"),
    admin("admin:access_requests:write", "admin:access_requests:write_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const params = request.params as { request_id: string };
      const body = request.body as { role?: string; permissions?: string[]; valid_until?: string | null; note?: string | null };
      if (!body.role || !Array.isArray(body.permissions) || !validatePermissions(body.permissions)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      if (!validateOptionalUtcDateTime(body.valid_until)) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const result = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const accessRequest = await repos.findAccessRequestById(params.request_id, assigned);
        if (!accessRequest) throw new AppError("ACCESS_REQUEST_NOT_FOUND", ctx.correlationId);
        if (accessRequest.status !== "pending") throw new AppError("ACCESS_REQUEST_NOT_PENDING", ctx.correlationId);
        await assertKnownPermissions(repos, accessRequest.tool_id, body.permissions!, ctx.correlationId);
        const grant = await repos.createGrant({
          toolId: accessRequest.tool_id,
          userId: accessRequest.user_id,
          emailNormalized: accessRequest.email_normalized,
          role: body.role!,
          permissions: body.permissions!,
          status: accessRequest.user_id ? "active" : "pending_user_link",
          validUntil: body.valid_until ?? null,
          createdByUserId: actor.userId
        });
        const reviewed = await repos.reviewAccessRequest({
          requestId: accessRequest.id,
          status: "approved",
          actorUserId: actor.userId,
          note: body.note,
          grantId: grant.id
        });
        if (!reviewed) throw new AppError("ACCESS_REQUEST_NOT_PENDING", ctx.correlationId);
        const audit = new AuditLogger(repos);
        await audit.write({
          event_type: "admin.grant.created",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: accessRequest.tool_id,
          tool_slug: accessRequest.tool_slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { grant_id: grant.id, access_request_id: accessRequest.id }
        });
        await audit.write({
          event_type: "admin.access_request.approved",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: accessRequest.tool_id,
          tool_slug: accessRequest.tool_slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { grant_id: grant.id, access_request_id: accessRequest.id }
        });
        return { request: reviewed, grant };
      });
      return { request_id: result.request.id, status: result.request.status, grant_id: result.grant.id };
    })
  );

  const decideAccessRequest = (status: "rejected" | "closed", eventType: string): RouteHandlerMethod =>
    admin("admin:access_requests:write", "admin:access_requests:write_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const params = request.params as { request_id: string };
      const body = (request.body ?? {}) as { note?: string | null };
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const reviewed = await deps.repositories.db.transaction(async (tx) => {
        const repos = deps.repositories.withDb(tx);
        const accessRequest = await repos.findAccessRequestById(params.request_id, assigned);
        if (!accessRequest) throw new AppError("ACCESS_REQUEST_NOT_FOUND", ctx.correlationId);
        if (accessRequest.status !== "pending") throw new AppError("ACCESS_REQUEST_NOT_PENDING", ctx.correlationId);
        const updated = await repos.reviewAccessRequest({
          requestId: accessRequest.id,
          status,
          actorUserId: actor.userId,
          note: body.note
        });
        if (!updated) throw new AppError("ACCESS_REQUEST_NOT_PENDING", ctx.correlationId);
        await new AuditLogger(repos).write({
          event_type: eventType,
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: accessRequest.tool_id,
          tool_slug: accessRequest.tool_slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: { access_request_id: accessRequest.id }
        });
        return updated;
      });
      return { request_id: reviewed.id, status: reviewed.status };
    });

  app.post(apiPath(deps.config, "/v1/admin/access-requests/:request_id/reject"), decideAccessRequest("rejected", "admin.access_request.rejected"));
  app.post(apiPath(deps.config, "/v1/admin/access-requests/:request_id/close"), decideAccessRequest("closed", "admin.access_request.closed"));

  app.get(
    apiPath(deps.config, "/v1/admin/audit-logs"),
    admin("admin:audit:read", "admin:audit:read_assigned", async (request) => {
      const actor = (request as FastifyRequest & { adminActor: AdminActor }).adminActor;
      const ctx = contextFor(request);
      const query = request.query as {
        tool_slug?: string;
        email?: string;
        google_sub?: string;
        outcome?: string;
        reason_code?: string;
        correlation_id?: string;
        date_from?: string;
        date_to?: string;
      };
      const outcome = parseAuditOutcome(query.outcome);
      if (
        outcome === null ||
        (query.tool_slug !== undefined && !validateToolSlug(query.tool_slug)) ||
        !validateOptionalUtcDateTime(query.date_from) ||
        !validateOptionalUtcDateTime(query.date_to)
      ) {
        throw new AppError("VALIDATION_ERROR", ctx.correlationId);
      }
      const assigned = actor.role === "tool_admin" ? actor.assignedToolIds : undefined;
      const items = await deps.repositories.listAuditLogs({
        toolSlug: query.tool_slug,
        email: query.email ? normalizeEmail(query.email) : undefined,
        googleSub: query.google_sub,
        outcome,
        reasonCode: query.reason_code,
        correlationId: query.correlation_id,
        dateFrom: query.date_from,
        dateTo: query.date_to,
        assignedToolIds: assigned,
        limit: 200
      });
      return { items };
    })
  );
}

const BULK_GRANT_TEMPLATE_CSV = toCsv(
  ["email", "tool_slug", "role", "permissions", "valid_until", "action", "note"],
  [
    {
      email: "mario.rossi@unguess.io",
      tool_slug: "petyr",
      role: "tool_user",
      permissions: "petyr:read:all",
      valid_until: "",
      action: "upsert",
      note: "Accesso Petyr"
    },
    {
      email: "anna.bianchi@unguess.io",
      tool_slug: "redash-ingestor",
      role: "tool_user",
      permissions: "redash:read:all",
      valid_until: "2026-12-31T23:59:59Z",
      action: "upsert",
      note: "Accesso temporaneo"
    },
    {
      email: "luca.verdi@unguess.io",
      tool_slug: "petyr",
      role: "tool_user",
      permissions: "",
      valid_until: "",
      action: "revoke",
      note: "Revoca accesso"
    }
  ]
);

function parseBulkGrantRequest(body: unknown, correlationId: string): { rows: BulkGrantInputRow[] } {
  if (!body || typeof body !== "object" || typeof (body as { content?: unknown }).content !== "string") {
    throw new AppError("VALIDATION_ERROR", correlationId, { expected: "JSON body with CSV content" });
  }
  const payload = body as { content: string; delimiter?: string };
  const delimiter = payload.delimiter === ";" || payload.delimiter === ","
    ? payload.delimiter
    : detectCsvDelimiter(payload.content);
  const table = parseCsv(payload.content, delimiter);
  if (table.length < 2) {
    throw new AppError("VALIDATION_ERROR", correlationId, { expected: "CSV header plus at least one data row" });
  }
  const headers = table[0].map((header) => normalizeCsvHeader(header));
  const requiredHeaders = ["email", "tool_slug", "role", "permissions", "valid_until", "action", "note"];
  const missingHeaders = requiredHeaders.filter((header) => !headers.includes(header));
  if (missingHeaders.length) {
    throw new AppError("VALIDATION_ERROR", correlationId, { missing_headers: missingHeaders });
  }
  const rowAt = (row: string[], header: string): string => row[headers.indexOf(header)]?.trim() ?? "";
  const rows = table
    .slice(1)
    .map((row, index) => ({ row, rowNumber: index + 2 }))
    .filter(({ row }) => row.some((cell) => cell.trim() !== ""))
    .map(({ row, rowNumber }) => {
      const actionValue = rowAt(row, "action").toLowerCase();
      return {
        row: rowNumber,
        email: normalizeEmail(rowAt(row, "email")),
        tool_slug: rowAt(row, "tool_slug"),
        role: rowAt(row, "role"),
        permissions: parsePermissionList(rowAt(row, "permissions")),
        valid_until: rowAt(row, "valid_until") || null,
        action: actionValue === "upsert" || actionValue === "revoke" ? actionValue : null,
        note: rowAt(row, "note") || null
      } satisfies BulkGrantInputRow;
    });
  if (!rows.length) {
    throw new AppError("VALIDATION_ERROR", correlationId, { expected: "at least one non-empty data row" });
  }
  return { rows };
}

async function previewBulkGrantImport(
  deps: AppDependencies,
  actor: AdminActor,
  input: { rows: BulkGrantInputRow[] }
): Promise<{ rows: BulkGrantPreviewRow[]; summary: BulkGrantSummary }> {
  const rows: BulkGrantPreviewRow[] = [];
  const acceptedUpsertTargets = new Set<string>();
  for (const row of input.rows) {
    const errors: string[] = [];
    let tool: Tool | null = null;
    let user: User | null = null;
    let existingGrantId: string | null = null;
    let operation: BulkGrantOperation | undefined;
    let resolvedUser: "known_user" | "pending_user_link" | null = null;
    let statusAfter: GrantStatus | null = null;

    if (!row.action) errors.push("INVALID_ACTION");
    const emailAllowed = row.email && isAllowedPendingGrantEmail(
      row.email,
      deps.config.googleAllowedHd,
      deps.config.microsoftAllowedEmailDomains ?? []
    );
    if (!emailAllowed) {
      errors.push("EMAIL_DOMAIN_NOT_ALLOWED");
    }
    if (!row.tool_slug || !validateToolSlug(row.tool_slug)) {
      errors.push("INVALID_TOOL_SLUG");
    } else {
      tool = await deps.repositories.findToolBySlug(row.tool_slug);
      if (!tool) {
        errors.push("UNKNOWN_TOOL");
      } else if (actor.role === "tool_admin" && !actor.assignedToolIds.includes(tool.id)) {
        errors.push("TOOL_NOT_ASSIGNED");
      }
    }
    if (!validateOptionalUtcDateTime(row.valid_until)) {
      errors.push("INVALID_VALID_UNTIL");
    }

    if (emailAllowed) {
      user = await deps.repositories.findUserByEmail(row.email);
      resolvedUser = user ? "known_user" : "pending_user_link";
    }

    if (row.action === "upsert") {
      if (!row.role) errors.push("ROLE_REQUIRED");
      if (!validatePermissions(row.permissions)) errors.push("INVALID_PERMISSIONS");
      if (tool && validatePermissions(row.permissions)) {
        const known = await deps.repositories.listToolPermissions(tool.id);
        const unknown = known.length === 0 && row.permissions.length > 0
          ? row.permissions
          : row.permissions.filter((permission) => !known.includes(permission));
        if (unknown.length) errors.push(`UNKNOWN_PERMISSIONS:${unknown.join("|")}`);
      }
      statusAfter = user ? "active" : "pending_user_link";
      if (tool && row.role && errors.length === 0) {
        const existing = await deps.repositories.findGrantForBulkTarget({
          toolId: tool.id,
          userId: user?.id ?? null,
          emailNormalized: row.email
        });
        existingGrantId = existing?.id ?? null;
        statusAfter = existing?.status ?? statusAfter;
        const targetKey = `${tool.id}\u0000${row.email}`;
        operation = existing || acceptedUpsertTargets.has(targetKey) ? "skip" : "create";
        acceptedUpsertTargets.add(targetKey);
      }
    } else if (row.action === "revoke") {
      statusAfter = "revoked";
      if (tool && errors.length === 0) {
        const targets = await deps.repositories.findGrantsForBulkRevoke({
          toolId: tool.id,
          userId: user?.id ?? null,
          emailNormalized: row.email,
          role: row.role || null
        });
        existingGrantId = targets[0]?.id ?? null;
        operation = targets.length ? "revoke" : "skip";
      }
    }

    const result: BulkGrantResult = errors.length ? "error" : operation === "skip" ? "warning" : "ok";
    const reason = errors.length
      ? errors.join("; ")
      : operation === "skip"
        ? row.action === "upsert"
          ? existingGrantId
            ? "EXISTING_GRANT_KEPT"
            : "EARLIER_BULK_ROW_WILL_CREATE_GRANT"
          : "NO_MATCHING_GRANT"
        : null;
    rows.push({
      ...row,
      result,
      reason,
      resolved_user: resolvedUser,
      status_after: statusAfter,
      existing_grant_id: existingGrantId,
      operation,
      tool_id: tool?.id,
      user_id: user?.id ?? null
    });
  }
  return { rows, summary: summarizeBulkRows(rows) };
}

async function commitBulkGrantImport(
  deps: AppDependencies,
  actor: AdminActor,
  ctx: RequestContext,
  previewRows: BulkGrantPreviewRow[]
): Promise<{ rows: BulkGrantPreviewRow[]; summary: BulkGrantSummary }> {
  const committedRows: BulkGrantPreviewRow[] = [];
  const summary: BulkGrantSummary = { total_rows: previewRows.length, ok: 0, warning: 0, error: 0, created: 0, updated: 0, revoked: 0, skipped: 0 };
  await deps.repositories.db.transaction(async (tx) => {
    const repos = deps.repositories.withDb(tx);
    const audit = new AuditLogger(repos);
    for (const row of previewRows) {
      if (row.result === "error" || !row.tool_id || !row.action) {
        summary.error += 1;
        committedRows.push(row);
        continue;
      }
      if (row.action === "upsert") {
        const status = row.user_id ? "active" : "pending_user_link";
        const existing = await repos.findGrantForBulkTarget({
          toolId: row.tool_id,
          userId: row.user_id ?? null,
          emailNormalized: row.email
        });
        if (existing) {
          summary.warning += 1;
          summary.skipped = (summary.skipped ?? 0) + 1;
          committedRows.push({
            ...row,
            result: "warning",
            reason: "EXISTING_GRANT_KEPT",
            existing_grant_id: existing.id,
            operation: "skip",
            status_after: existing.status
          });
          continue;
        }
        const grant = await repos.createGrant({
          toolId: row.tool_id,
          userId: row.user_id ?? null,
          emailNormalized: row.email,
          role: row.role,
          permissions: row.permissions,
          status,
          validUntil: row.valid_until,
          createdByUserId: actor.userId
        });
        if (!grant) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
        const operation: BulkGrantOperation = "create";
        summary.created = (summary.created ?? 0) + 1;
        summary.ok += 1;
        committedRows.push({
          ...row,
          result: "ok",
          reason: "GRANT_CREATED",
          existing_grant_id: grant.id,
          operation,
          status_after: grant.status
        });
        await audit.write({
          event_type: "admin.grant.created",
          outcome: "success",
          correlation_id: ctx.correlationId,
          tool_id: row.tool_id,
          tool_slug: row.tool_slug,
          actor_user_id: actor.userId,
          actor_google_sub: actor.googleSub,
          actor_email: actor.email,
          actor_hd: actor.hd,
          request_ip_hash: ctx.requestIpHash,
          user_agent_hash: ctx.userAgentHash,
          metadata: {
            grant_id: grant.id,
            target_user_id: row.user_id ?? null,
            target_email: row.email,
            row_number: row.row,
            bulk_import: true,
            note: row.note
          }
        });
      } else {
        const targets = await repos.findGrantsForBulkRevoke({
          toolId: row.tool_id,
          userId: row.user_id ?? null,
          emailNormalized: row.email,
          role: row.role || null
        });
        if (!targets.length) {
          summary.warning += 1;
          summary.skipped = (summary.skipped ?? 0) + 1;
          committedRows.push({ ...row, result: "warning", reason: "NO_MATCHING_GRANT", operation: "skip" });
          continue;
        }
        let revokedSessions = 0;
        for (const target of targets) {
          const updated = await repos.updateGrant(target.id, { status: "revoked", revokedByUserId: actor.userId });
          if (!updated) throw new AppError("VALIDATION_ERROR", ctx.correlationId);
          revokedSessions += await repos.revokeSessionsForGrant(updated.id);
          summary.revoked = (summary.revoked ?? 0) + 1;
          await audit.write({
            event_type: "admin.grant.revoked",
            outcome: "success",
            correlation_id: ctx.correlationId,
            tool_id: row.tool_id,
            tool_slug: row.tool_slug,
            actor_user_id: actor.userId,
            actor_google_sub: actor.googleSub,
            actor_email: actor.email,
            actor_hd: actor.hd,
            request_ip_hash: ctx.requestIpHash,
            user_agent_hash: ctx.userAgentHash,
            metadata: {
              grant_id: updated.id,
              target_user_id: updated.user_id,
              target_email: updated.email_normalized,
              row_number: row.row,
              revoked_sessions: revokedSessions,
              bulk_import: true,
              note: row.note
            }
          });
        }
        summary.ok += 1;
        committedRows.push({ ...row, result: "ok", reason: `GRANTS_REVOKED:${targets.length}; SESSIONS_REVOKED:${revokedSessions}`, operation: "revoke" });
      }
    }
    await audit.write({
      event_type: "admin.grant.bulk_import_committed",
      outcome: summary.error ? "error" : "success",
      correlation_id: ctx.correlationId,
      actor_user_id: actor.userId,
      actor_google_sub: actor.googleSub,
      actor_email: actor.email,
      actor_hd: actor.hd,
      request_ip_hash: ctx.requestIpHash,
      user_agent_hash: ctx.userAgentHash,
      metadata: { ...summary }
    });
  });
  return { rows: committedRows, summary };
}

function summarizeBulkRows(rows: BulkGrantPreviewRow[]): BulkGrantSummary {
  return rows.reduce<BulkGrantSummary>(
    (summary, row) => {
      summary[row.result] += 1;
      return summary;
    },
    { total_rows: rows.length, ok: 0, warning: 0, error: 0 }
  );
}

function parsePermissionList(value: string): string[] {
  return value
    .split(/[;,\n]/)
    .map((permission) => permission.trim())
    .filter(Boolean);
}

function normalizeCsvHeader(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function detectCsvDelimiter(content: string): "," | ";" {
  const requiredHeaders = ["email", "tool_slug", "role", "permissions", "valid_until", "action", "note"];
  const score = (delimiter: "," | ";"): number => {
    const header = parseCsv(content, delimiter).find((row) => row.some((cell) => cell.trim() !== "")) ?? [];
    return requiredHeaders.filter((requiredHeader) => header.map(normalizeCsvHeader).includes(requiredHeader)).length;
  };
  return score(";") > score(",") ? ";" : ",";
}

function parseCsv(content: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < content.length; i += 1) {
    const char = content[i];
    const next = content[i + 1];
    if (quoted) {
      if (char === '"' && next === '"') {
        field += '"';
        i += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"') {
      quoted = true;
    } else if (char === delimiter) {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (char !== "\r") {
      field += char;
    }
  }
  row.push(field);
  if (row.some((cell) => cell.trim() !== "") || rows.length === 0) rows.push(row);
  return rows;
}

function toCsv(headers: string[], rows: Array<Record<string, unknown>>): string {
  const lines = [headers.map(csvCell).join(",")];
  for (const row of rows) {
    lines.push(headers.map((header) => csvCell(row[header])).join(","));
  }
  return `${lines.join("\n")}\n`;
}

function csvCell(value: unknown): string {
  const raw = value === null || value === undefined ? "" : Array.isArray(value) ? value.join(";") : String(value);
  return /[",\n\r]/.test(raw) ? `"${raw.replace(/"/g, '""')}"` : raw;
}

function formatCsvDate(value: unknown): string {
  if (!value) return "";
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString();
}

async function assertKnownPermissions(
  repos: Repositories,
  toolId: string,
  permissions: string[],
  correlationId: string
): Promise<void> {
  const known = await repos.listToolPermissions(toolId);
  if (known.length === 0 && permissions.length > 0) {
    throw new AppError("VALIDATION_ERROR", correlationId, { unknown_permissions: permissions });
  }
  const unknown = permissions.filter((permission) => !known.includes(permission));
  if (unknown.length) {
    throw new AppError("VALIDATION_ERROR", correlationId, { unknown_permissions: unknown });
  }
}

function isGrantCurrentlyUsable(grant: AuthorizationGrant): boolean {
  const now = new Date();
  return (
    grant.status === "active" &&
    grant.valid_from <= now &&
    (grant.valid_until === null || grant.valid_until > now)
  );
}

function validateOptionalUtcDateTime(value: string | null | undefined): boolean {
  if (value === null || value === undefined) {
    return true;
  }
  if (!value.endsWith("Z")) {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime());
}

function parseUserStatus(value: string | undefined): UserStatus | null | undefined {
  if (value === undefined) return undefined;
  if (value === "active" || value === "suspended" || value === "disabled") return value;
  return null;
}

function parseToolStatus(value: string | undefined): ToolStatus | null | undefined {
  if (value === undefined) return undefined;
  if (value === "active" || value === "disabled" || value === "maintenance") return value;
  return null;
}

function parseGrantStatus(value: string | undefined): GrantStatus | null | undefined {
  if (value === undefined) return undefined;
  if (value === "active" || value === "revoked" || value === "expired" || value === "pending_user_link") return value;
  return null;
}

function parseAccessRequestStatus(value: string | undefined): AccessRequestStatus | null | undefined {
  if (value === undefined) return undefined;
  if (value === "pending" || value === "approved" || value === "rejected" || value === "closed" || value === "expired") {
    return value;
  }
  return null;
}

function parseAuditOutcome(value: string | undefined): Outcome | null | undefined {
  if (value === undefined) return undefined;
  return AUDIT_OUTCOMES.includes(value as Outcome) ? (value as Outcome) : null;
}

function userResponse(user: User): Record<string, unknown> {
  return {
    id: user.id,
    google_sub: user.google_sub,
    email: user.email,
    email_verified: user.email_verified,
    hd: user.hd,
    display_name: user.display_name,
    picture_url: user.picture_url,
    status: user.status
  };
}

function cookieHeader(
  name: string,
  value: string,
  options: { maxAge: number; httpOnly: boolean; secure: boolean; path?: string }
): string {
  const parts = [
    `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
    `Path=${options.path ?? "/"}`,
    "SameSite=Lax",
    `Max-Age=${options.maxAge}`
  ];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  return parts.join("; ");
}

function adminHtml(config: Config): string {
  const adminBasePath = adminUiPath(config);
  const apiBasePath = apiPath(config, "/v1");
  const faviconPath = joinPublicPath(config.publicBasePath, "/favicon.svg");
  return `<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="${faviconPath}" type="image/svg+xml">
  <title>Access Layer Admin</title>
  <style>
    :root {
      --bg: #ffffff;
      --bg-subtle: #f7f8fa;
      --bg-soft: #f9fafb;
      --card: #ffffff;
      --border: #e5e7eb;
      --border-strong: #d0d5dd;
      --text: #101828;
      --text-soft: #667085;
      --text-muted: #98a2b3;
      --primary: #004b63;
      --primary-dark: #003f56;
      --primary-soft: #e6f2f5;
      --accent: #74c69d;
      --accent-soft: #ecfdf3;
      --error: #ef4444;
      --warning: #f59e0b;
      --shadow: 0 8px 24px rgba(15, 23, 42, .06);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--text);
      background: var(--bg);
    }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; color: var(--text); background: var(--bg); font-size: 15px; line-height: 1.55; }
    .shell { min-height: 100vh; display: grid; grid-template-columns: 272px minmax(0, 1fr); background: linear-gradient(90deg, var(--primary-dark) 0 272px, var(--bg) 272px); }
    nav { position: sticky; top: 0; height: 100vh; background: var(--primary-dark); color: #ffffff; padding: 32px 20px; border-right: 1px solid rgba(255, 255, 255, .08); }
    nav h1 { position: relative; font-size: 1.12rem; line-height: 1.2; margin: 0 0 32px; font-weight: 800; letter-spacing: 0; }
    nav h1::after { content: ""; display: block; width: 40px; height: 3px; margin-top: 14px; border-radius: 999px; background: var(--accent); }
    nav button, nav a { width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 10px; text-align: left; border: 1px solid transparent; color: rgba(255, 255, 255, .78); background: transparent; padding: 12px 14px; border-radius: 14px; cursor: pointer; font: inherit; font-weight: 650; text-decoration: none; transition: background-color .22s ease-in-out, color .22s ease-in-out, border-color .22s ease-in-out; }
    nav a[hidden] { display: none; }
    nav button + button { margin-top: 4px; }
    nav button[aria-current="page"] { background: rgba(255, 255, 255, .1); color: #ffffff; border-color: rgba(116, 198, 157, .35); box-shadow: inset 3px 0 0 var(--accent); }
    nav button:hover, nav a:hover { background: rgba(255, 255, 255, .08); color: #ffffff; }
    main { min-width: 0; background: var(--bg); }
    header { min-height: 88px; display: flex; align-items: center; justify-content: space-between; gap: 24px; padding: 0 48px; border-bottom: 1px solid var(--border); background: rgba(255, 255, 255, .96); position: sticky; top: 0; z-index: 3; backdrop-filter: blur(10px); }
    header > span { display: flex; align-items: center; justify-content: flex-end; gap: 12px; color: var(--text-soft); font-size: .92rem; }
    #title { color: var(--text); font-size: 2rem; line-height: 1.22; font-weight: 800; letter-spacing: 0; }
    .badge { border: 1px solid var(--border); border-radius: 999px; padding: 4px 10px; font-size: .78rem; line-height: 1.2; color: var(--primary); background: var(--primary-soft); font-weight: 700; white-space: nowrap; }
    nav .badge { color: var(--primary-dark); background: var(--accent); border-color: transparent; padding: 2px 8px; }
    .content { width: 100%; margin: 0; padding: 32px 48px 64px; }
    .toolbar { display: flex; gap: 12px; align-items: end; margin: 0 0 24px; flex-wrap: wrap; }
    form.toolbar { background: var(--card); border: 1px solid var(--border); border-radius: 18px; padding: 20px; box-shadow: var(--shadow); }
    form.toolbar > label { flex: 1 1 220px; }
    .dashboard-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 0 0 24px; }
    .dashboard-kpis .badge { display: flex; min-height: 112px; align-items: flex-end; justify-content: flex-start; padding: 24px; border-radius: 18px; color: var(--text); background: var(--card); border: 1px solid var(--border); box-shadow: var(--shadow); font-size: 1rem; }
    .form-card { width: 100%; background: var(--card); border: 1px solid var(--border); border-radius: 18px; padding: 28px; max-width: none; box-shadow: var(--shadow); }
    .form-card + .form-card { margin-top: 24px; }
    .form-card h2 { margin: 0 0 8px; color: var(--text); font-size: 1.55rem; line-height: 1.25; font-weight: 750; letter-spacing: 0; }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px 24px; margin-top: 24px; }
    label, .form-grid label, .full-row { display: block; color: var(--text); font-size: .9rem; font-weight: 650; }
    .full-row { grid-column: 1 / -1; }
    .form-card input, .form-card select, .form-card textarea { width: 100%; margin-top: 8px; }
    .field-help { margin: 8px 0 0; color: var(--text-soft); font-size: .88rem; font-weight: 400; }
    .form-actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 24px; }
    .secret-box { display: block; width: 100%; margin-top: 8px; padding: 14px 16px; border: 1px solid var(--border); border-radius: 14px; background: var(--bg-soft); color: var(--text); word-break: break-all; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9rem; font-weight: 500; }
    input, select, textarea { border: 1px solid var(--border-strong); border-radius: 12px; padding: 11px 13px; font: inherit; color: var(--text); background: #fff; min-height: 44px; outline: none; transition: border-color .2s ease-in-out, box-shadow .2s ease-in-out, background-color .2s ease-in-out; }
    textarea { resize: vertical; }
    input::placeholder, textarea::placeholder { color: var(--text-muted); }
    input:focus, select:focus, textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 4px rgba(0, 75, 99, .12); }
    button.primary, button.secondary, button.danger-button { min-height: 44px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; border-radius: 999px; padding: 10px 18px; cursor: pointer; font: inherit; font-weight: 750; transition: background-color .22s ease-in-out, border-color .22s ease-in-out, color .22s ease-in-out, box-shadow .22s ease-in-out, transform .22s ease-in-out; }
    button.primary { background: var(--primary); color: #fff; border: 1px solid var(--primary); box-shadow: 0 8px 18px rgba(0, 75, 99, .16); }
    button.primary:hover { background: var(--primary-dark); border-color: var(--primary-dark); transform: translateY(-1px); }
    button.secondary { background: #fff; color: var(--primary); border: 1px solid var(--border-strong); }
    button.secondary:hover { background: var(--primary-soft); border-color: rgba(0, 75, 99, .28); }
    button.danger-button { background: #fff; color: var(--error); border: 1px solid #fecaca; }
    button.danger-button:hover { background: #fff5f5; border-color: #fca5a5; }
    button:disabled, input:disabled, select:disabled, textarea:disabled { opacity: .65; cursor: not-allowed; transform: none; box-shadow: none; }
    .table-card { overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 18px; box-shadow: var(--shadow); }
    table { width: 100%; border-collapse: separate; border-spacing: 0; background: transparent; min-width: 760px; }
    th, td { padding: 15px 18px; text-align: left; border-bottom: 1px solid #eaecf0; vertical-align: top; font-size: .92rem; }
    th { color: var(--text-soft); background: var(--bg-soft); font-size: .78rem; font-weight: 800; text-transform: uppercase; letter-spacing: .04em; }
    tbody tr { transition: background-color .18s ease-in-out; }
    tbody tr:hover { background: #fbfcfd; }
    tbody tr:last-child td { border-bottom: 0; }
    .pager { display: flex; gap: 12px; align-items: center; justify-content: flex-end; margin-top: 16px; color: var(--text-soft); font-size: .9rem; }
    .empty-state { border: 1px dashed var(--border-strong); background: var(--bg-soft); color: var(--text-soft); padding: 28px; border-radius: 18px; box-shadow: inset 0 0 0 1px rgba(255, 255, 255, .6); }
    .table-section { margin-top: 32px; }
    .table-section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin: 0 0 16px; }
    .table-section-head h2 { margin: 0; font-size: 1.25rem; line-height: 1.35; }
    .table-section-head p { margin: 4px 0 0; color: var(--text-soft); }
    .permission-picker { position: relative; display: block; width: 100%; margin-top: 8px; }
    .permission-field > span:first-child { display: block; color: var(--text); font-size: .9rem; font-weight: 650; }
    .permission-picker summary { min-height: 44px; display: flex; align-items: center; justify-content: space-between; gap: 12px; border: 1px solid var(--border-strong); border-radius: 12px; padding: 11px 13px; color: var(--text); background: #fff; cursor: pointer; font-weight: 500; list-style: none; }
    .permission-picker summary::-webkit-details-marker { display: none; }
    .permission-picker summary::after { content: "⌄"; color: var(--primary); font-size: 1.1rem; font-weight: 800; }
    .permission-picker[open] summary { border-color: var(--primary); box-shadow: 0 0 0 4px rgba(0, 75, 99, .12); }
    .permission-picker-panel { display: grid; gap: 8px; max-height: 260px; overflow: auto; margin-top: 8px; padding: 12px; border: 1px solid var(--border-strong); border-radius: 12px; background: var(--bg-soft); }
    .permission-option { display: flex !important; align-items: center; gap: 10px; min-height: 40px; padding: 8px 10px; border: 1px solid transparent; border-radius: 10px; background: #fff; font-weight: 500 !important; cursor: pointer; }
    .permission-option:hover { border-color: rgba(0, 75, 99, .28); background: var(--primary-soft); }
    .permission-option input { width: 18px !important; min-height: 18px !important; margin: 0 !important; accent-color: var(--primary); }
    .permission-picker-empty { margin: 0; color: var(--text-soft); font-weight: 400; }
    pre { white-space: pre-wrap; background: var(--bg-soft); border: 1px solid var(--border); padding: 18px; border-radius: 14px; color: var(--text); }
    dl { display: grid; grid-template-columns: minmax(140px, 220px) 1fr; gap: 10px 20px; margin: 0 0 24px; padding: 24px; background: var(--card); border: 1px solid var(--border); border-radius: 18px; box-shadow: var(--shadow); }
    dt { color: var(--text-soft); font-size: .78rem; font-weight: 800; text-transform: uppercase; letter-spacing: .04em; }
    dd { margin: 0; color: var(--text); font-weight: 600; overflow-wrap: anywhere; }
    .content > label { max-width: 520px; margin-bottom: 20px; }
    .status { font-size: .78rem; line-height: 1.2; padding: 5px 10px; border-radius: 999px; border: 1px solid rgba(0, 75, 99, .16); color: var(--primary); background: var(--primary-soft); display: inline-block; font-weight: 800; }
    .danger { color: var(--error); font-weight: 650; }
    .success { color: #13824f; font-weight: 650; }
    .warning { color: #9a5b00; background: #fffbeb; border: 1px solid #fde68a; border-radius: 14px; padding: 12px 14px; }
    @media (max-width: 960px) {
      .shell { grid-template-columns: 1fr; }
      nav { position: static; height: auto; display: flex; gap: 8px; overflow: auto; padding: 14px; }
      nav h1 { display: none; }
      nav button, nav a { width: auto; white-space: nowrap; }
      header { align-items: flex-start; height: auto; padding: 24px; flex-direction: column; position: static; }
      .content { padding: 24px; }
      .form-grid, .dashboard-kpis { grid-template-columns: 1fr; }
      dl { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <nav aria-label="Admin">
      <h1>Access Layer</h1>
      <button data-view="dashboard" aria-current="page">Dashboard</button>
      <button data-view="tools">Tools</button>
      <button data-view="users">Utenti</button>
      <button data-view="grants">Grant</button>
      <button data-view="requests">Richieste accesso <span id="request-badge" class="badge">0</span></button>
      <button data-view="audit">Audit log</button>
      <button data-view="backup">Backup</button>
      <button data-view="settings">Settings</button>
      <a id="oauth-admin-link" href="${escapeHtml(`${adminBasePath}/oauth`)}" hidden>OAuth P0</a>
    </nav>
    <main>
      <header>
        <strong id="title">Dashboard</strong>
        <span><span class="badge">${escapeHtml(config.appEnv)}</span> <span id="me">Caricamento sessione</span> <button class="secondary" id="auth-action">Logout</button></span>
      </header>
      <section class="content" id="content"></section>
    </main>
  </div>
  <script>
    const PAGE_SIZE = 25;
    const state = { view: 'dashboard', me: null, tools: [], toolCatalog: [], grants: [], pendingCount: 0, pages: {}, toolFilters: {}, userFilters: {}, grantFilters: {}, requestFilters: {}, auditFilters: {} };
    const content = document.getElementById('content');
    const title = document.getElementById('title');
    const me = document.getElementById('me');
    const authAction = document.getElementById('auth-action');
    const ADMIN_BASE_PATH = ${JSON.stringify(adminBasePath)};
    const API_BASE_PATH = ${JSON.stringify(apiBasePath)};
    const apiUrl = path => API_BASE_PATH + path;
    function setAuthAction(mode) {
      if (mode === 'logout') {
        authAction.textContent = 'Logout';
        authAction.onclick = async () => {
          authAction.disabled = true;
          try {
            const res = await fetch(ADMIN_BASE_PATH + '/logout', { method: 'POST', credentials: 'same-origin' });
            if (!res.ok && res.status !== 401) throw new Error('Logout non riuscito.');
          } catch (error) {
            authAction.disabled = false;
            content.innerHTML = '<p class="danger">' + esc(error.message) + '</p>';
            return;
          }
          state.me = null;
          location.href = ADMIN_BASE_PATH + '/login';
        };
        return;
      }
      authAction.disabled = false;
      authAction.textContent = 'Login';
      authAction.onclick = () => { location.href = ADMIN_BASE_PATH + '/login'; };
    }
    setAuthAction('logout');
    document.querySelectorAll('nav button[data-view]').forEach(btn => {
      btn.onclick = () => {
        state.view = btn.dataset.view;
        document.querySelectorAll('nav button[data-view]').forEach(b => b.removeAttribute('aria-current'));
        btn.setAttribute('aria-current', 'page');
        render();
      };
    });
    async function api(path, options = {}, refreshAttempted = false) {
      const headers = { ...(options.headers || {}) };
      if (options.body !== undefined && !Object.keys(headers).some(key => key.toLowerCase() === 'content-type')) {
        headers['content-type'] = 'application/json';
      }
      const res = await fetch(path, { credentials: 'same-origin', ...options, headers });
      if (res.status === 204) return null;
      let payload = null;
      try { payload = await res.json(); } catch {}
      const code = payload?.error?.code;
      const correlationId = payload?.error?.correlation_id;
      if (res.status === 401 || code === 'AUTH_INVALID_STATE') {
        if (!refreshAttempted) {
          try {
            const refreshed = await fetch(ADMIN_BASE_PATH + '/refresh', {
              method: 'POST',
              credentials: 'same-origin'
            });
            if (refreshed.ok) {
              return api(path, options, true);
            }
          } catch {}
        }
        handleExpiredAdminSession();
        const error = new Error('Sessione scaduta. Accedi di nuovo.');
        error.sessionExpired = true;
        error.code = code;
        error.correlationId = correlationId;
        throw error;
      }
      if (!res.ok) {
        const message = payload?.error?.message || 'Errore';
        const error = new Error(correlationId ? message + ' Codice: ' + correlationId : message);
        error.code = code;
        error.correlationId = correlationId;
        error.details = payload?.error?.details;
        throw error;
      }
      return payload;
    }
    function esc(v) { return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c])); }
    function table(rows, columns, options = {}) {
      const pageKey = options.pageKey || state.view;
      if (!rows.length) return '<p class="empty-state">Nessun dato.</p>';
      const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
      const currentPage = Math.min(state.pages[pageKey] || 0, totalPages - 1);
      state.pages[pageKey] = currentPage;
      const start = currentPage * PAGE_SIZE;
      const pageRows = rows.slice(start, start + PAGE_SIZE);
      return '<div class="table-card"><table><thead><tr>' + columns.map(c => '<th>' + esc(c.label) + '</th>').join('') + '</tr></thead><tbody>' +
        pageRows.map(row => '<tr>' + columns.map(c => '<td>' + (c.render ? c.render(row) : esc(row[c.key])) + '</td>').join('') + '</tr>').join('') +
        '</tbody></table></div>' +
        '<div class="pager" data-page-key="'+esc(pageKey)+'"><button class="secondary" data-page-prev="'+esc(pageKey)+'" '+(currentPage === 0 ? 'disabled' : '')+'>Precedente</button><span>Pagina '+(currentPage + 1)+' / '+totalPages+'</span><button class="secondary" data-page-next="'+esc(pageKey)+'" '+(currentPage >= totalPages - 1 ? 'disabled' : '')+'>Successiva</button></div>';
    }
    function bindPagination(pageKey, rerender) {
      content.querySelectorAll('[data-page-prev="'+pageKey+'"]').forEach(btn => btn.onclick = () => {
        state.pages[pageKey] = Math.max(0, (state.pages[pageKey] || 0) - 1);
        rerender();
      });
      content.querySelectorAll('[data-page-next="'+pageKey+'"]').forEach(btn => btn.onclick = () => {
        state.pages[pageKey] = (state.pages[pageKey] || 0) + 1;
        rerender();
      });
    }
    function queryString(params) {
      const query = new URLSearchParams();
      Object.entries(params || {}).forEach(([key, value]) => {
        if (value) query.set(key, value);
      });
      const encoded = query.toString();
      return encoded ? '?' + encoded : '';
    }
    function parseList(value) {
      return String(value || '').split(/[,\\n]/).map(s => s.trim()).filter(Boolean);
    }
    function valueOf(id) {
      return document.getElementById(id).value.trim();
    }
    function listValueOf(id) {
      return parseList(document.getElementById(id).value);
    }
    function selectedValues(id) {
      return Array.from(document.querySelectorAll('[data-permission-picker="'+id+'"]:checked')).map(input => input.value).filter(Boolean);
    }
    function hasAdminPermission(permission) {
      return Boolean(state.me && Array.isArray(state.me.permissions) && state.me.permissions.includes(permission));
    }
    async function loadToolCatalog() {
      const data = await api(apiUrl('/admin/tools'));
      state.toolCatalog = data.items || [];
      return state.toolCatalog;
    }
    function toolOptions(selectedSlug, includeEmpty = true) {
      const options = includeEmpty ? ['<option value="">Seleziona un tool</option>'] : [];
      state.toolCatalog.forEach(tool => {
        options.push('<option value="'+esc(tool.slug)+'"'+(tool.slug === selectedSlug ? ' selected' : '')+'>'+esc(tool.display_name)+' ('+esc(tool.slug)+')</option>');
      });
      return options.join('');
    }
    function permissionCheckboxes(id, toolSlug, selectedPermissions) {
      const tool = state.toolCatalog.find(item => item.slug === toolSlug);
      const selected = new Set(selectedPermissions || []);
      if (!tool || !(tool.permission_keys || []).length) {
        return '<p class="permission-picker-empty">Nessun permesso registrato: il grant sarà basato solo sul ruolo.</p>';
      }
      return tool.permission_keys.map(permission => '<label class="permission-option"><input type="checkbox" value="'+esc(permission)+'" data-permission-picker="'+esc(id)+'"'+(selected.has(permission) ? ' checked' : '')+'> <span>'+esc(permission)+'</span></label>').join('');
    }
    function permissionPickerSummary(toolSlug, selectedPermissions) {
      const tool = state.toolCatalog.find(item => item.slug === toolSlug);
      if (!tool || !(tool.permission_keys || []).length) return 'Nessun permesso disponibile (solo ruolo)';
      const count = (selectedPermissions || []).length;
      return count ? count + (count === 1 ? ' permesso selezionato' : ' permessi selezionati') : 'Seleziona i permessi';
    }
    function permissionPickerMarkup(id, toolSlug, selectedPermissions, describedBy) {
      return '<details class="permission-picker" id="'+esc(id)+'-picker" data-tool-slug="'+esc(toolSlug)+'"><summary aria-label="Permessi"'+(describedBy ? ' aria-describedby="'+esc(describedBy)+'"' : '')+'><span id="'+esc(id)+'-summary">'+esc(permissionPickerSummary(toolSlug, selectedPermissions))+'</span></summary><div class="permission-picker-panel">'+permissionCheckboxes(id, toolSlug, selectedPermissions)+'</div></details>';
    }
    function bindPermissionPicker(id, onChange) {
      document.querySelectorAll('[data-permission-picker="'+id+'"]').forEach(input => input.onchange = () => {
        const summary = document.getElementById(id + '-summary');
        const picker = document.getElementById(id + '-picker');
        if (summary) summary.textContent = permissionPickerSummary(picker ? picker.dataset.toolSlug : '', selectedValues(id));
        if (onChange) onChange();
      });
    }
    function syncPermissionPicker(toolSelectId, permissionPickerId, selectedPermissions = [], onChange) {
      const toolSlug = document.getElementById(toolSelectId).value;
      const picker = document.getElementById(permissionPickerId + '-picker');
      if (!picker) return;
      const summary = picker.querySelector('summary');
      picker.outerHTML = permissionPickerMarkup(permissionPickerId, toolSlug, selectedPermissions, summary ? summary.getAttribute('aria-describedby') : '');
      bindPermissionPicker(permissionPickerId, onChange);
    }
    function formError(id, error) {
      const target = document.getElementById(id);
      if (target) target.textContent = error ? error.message || String(error) : '';
    }
    function grantErrorMessage(error) {
      const unknown = error && error.details && error.details.unknown_permissions;
      return error.message + (Array.isArray(unknown) && unknown.length ? ' Permessi non registrati per il tool: ' + unknown.join(', ') + '.' : '');
    }
    function feedback(id, message, type = 'success') {
      const target = document.getElementById(id);
      if (!target) return;
      target.textContent = message || '';
      target.className = type === 'success' ? 'success' : 'danger';
    }
    function handleExpiredAdminSession() {
      state.me = null;
      me.textContent = 'Sessione scaduta';
      content.innerHTML = '<section class="form-card" role="alert"><h2>Sessione scaduta</h2><p>Sessione scaduta. Accedi di nuovo.</p></section>';
      window.setTimeout(() => { location.href = ADMIN_BASE_PATH + '/login'; }, 0);
    }
    function renderSecretResult(heading, clientId, secret, backLabel, backHandler) {
      title.textContent = heading;
      const envBlock = 'ACCESS_LAYER_CLIENT_ID=' + clientId + '\\nACCESS_LAYER_CLIENT_SECRET=' + secret;
      content.innerHTML = '<section class="form-card" role="status">' +
        '<h2>'+esc(heading)+'</h2>' +
        '<p class="field-help">Client ID e client secret generati per il tool. Client secret mostrato una sola volta: copia entrambi ora e conservali in modo sicuro.</p>' +
        '<label>Client ID<br><code class="secret-box" id="one-time-client-id">'+esc(clientId)+'</code></label>' +
        '<label>Client secret<br><code class="secret-box" id="one-time-secret">'+esc(secret)+'</code></label>' +
        '<label>Variabili env<br><code class="secret-box" id="one-time-env">'+esc(envBlock)+'</code></label>' +
        '<div class="form-actions"><button class="primary" id="copy-secret" type="button">Copia ID e secret</button><button class="secondary" id="secret-back" type="button">'+esc(backLabel)+'</button></div>' +
        '</section>';
      document.getElementById('copy-secret').onclick = async () => {
        if (navigator.clipboard) await navigator.clipboard.writeText(envBlock);
      };
      document.getElementById('secret-back').onclick = backHandler;
    }
    async function loadBase() {
      try {
        const current = await api(apiUrl('/me'));
        state.me = current;
        me.textContent = current.user.email;
        document.getElementById('oauth-admin-link').hidden = current.role !== 'platform_admin' || !hasAdminPermission('admin:oauth:read');
        setAuthAction('logout');
      } catch {
        document.getElementById('oauth-admin-link').hidden = true;
        me.textContent = 'Non autenticato';
        setAuthAction('login');
      }
      try {
        const requests = await api(apiUrl('/admin/access-requests?status=pending'));
        state.pendingCount = requests.items.length;
        document.getElementById('request-badge').textContent = state.pendingCount;
      } catch {}
    }
    async function render() {
      title.textContent = ({dashboard:'Dashboard', tools:'Tools', users:'Utenti', grants:'Grant', requests:'Richieste accesso', audit:'Audit log', backup:'Backup', settings:'Settings'})[state.view];
      content.innerHTML = '<p>Caricamento...</p>';
      try {
        if (state.view === 'dashboard') return renderDashboard();
        if (state.view === 'tools') return renderTools();
        if (state.view === 'users') return renderUsers();
        if (state.view === 'grants') return renderGrants();
        if (state.view === 'requests') return renderRequests();
        if (state.view === 'audit') return renderAudit();
        if (state.view === 'backup') return renderBackup();
        return renderSettings();
      } catch (error) {
        content.innerHTML = '<p class="danger">' + esc(error.message) + '</p>';
      }
    }
    async function renderDashboard() {
      const [tools, requests, logs] = await Promise.all([
        api(apiUrl('/admin/tools')),
        api(apiUrl('/admin/access-requests?status=pending')),
        api(apiUrl('/admin/audit-logs'))
      ]);
      content.innerHTML = '<div class="dashboard-kpis"><span class="badge">Tools ' + tools.items.length + '</span><span class="badge">Richieste pendenti ' + requests.items.length + '</span><span class="badge">Eventi recenti ' + logs.items.length + '</span></div>' +
        table(logs.items.slice(0, 10), [{key:'created_at', label:'Quando'}, {key:'event_type', label:'Evento'}, {key:'tool_slug', label:'Tool'}, {key:'outcome', label:'Esito'}, {key:'correlation_id', label:'Correlazione'}], {pageKey:'dashboard'});
      bindPagination('dashboard', renderDashboard);
    }
    async function renderTools() {
      const filters = state.toolFilters || {};
      const data = await api(apiUrl('/admin/tools') + queryString(filters));
      state.tools = data.items;
      const notice = state.toolNotice ? '<p class="success" role="status">' + esc(state.toolNotice) + '</p>' : '';
      state.toolNotice = '';
      content.innerHTML = notice + '<form class="toolbar" id="tool-filters">' +
        '<label>Cerca slug/nome<br><input id="tool-filter-search" name="search" value="'+esc(filters.search || '')+'"></label>' +
        '<label>Owner email<br><input id="tool-filter-owner" name="owner_email" value="'+esc(filters.owner_email || '')+'"></label>' +
        '<label>Stato<br><select id="tool-filter-status" name="status"><option value="">Tutti</option><option value="active">active</option><option value="disabled">disabled</option><option value="maintenance">maintenance</option></select></label>' +
        '<button class="primary" type="submit">Filtra</button><button class="secondary" id="tool-clear" type="button">Pulisci</button><button class="primary" id="create-tool" type="button">Nuovo tool</button></form>' +
        table(data.items, [{key:'slug', label:'Slug'}, {key:'display_name', label:'Nome'}, {key:'status', label:'Stato', render:r=>'<span class="status">'+esc(r.status)+'</span>'}, {key:'owner_email', label:'Owner'}, {key:'client_ids', label:'Client ID', render:r=>esc((r.client_ids||[]).join('\\n'))}, {key:'allowed_return_urls', label:'Return URL', render:r=>esc((r.allowed_return_urls||[]).join('\\n'))}, {key:'permission_keys', label:'Permessi', render:r=>esc((r.permission_keys||[]).join('\\n'))}, {key:'id', label:'Azioni', render:r=>'<button class="secondary" data-tool-detail="'+esc(r.id)+'">Dettaglio</button>'}], {pageKey:'tools'});
      bindPagination('tools', renderTools);
      document.getElementById('tool-filter-status').value = filters.status || '';
      document.getElementById('tool-filters').onsubmit = event => {
        event.preventDefault();
        state.toolFilters = {
          search: document.getElementById('tool-filter-search').value.trim(),
          owner_email: document.getElementById('tool-filter-owner').value.trim(),
          status: document.getElementById('tool-filter-status').value
        };
        state.pages.tools = 0;
        renderTools();
      };
      document.getElementById('tool-clear').onclick = () => {
        state.toolFilters = {};
        state.pages.tools = 0;
        renderTools();
      };
      document.getElementById('create-tool').onclick = () => renderToolCreateForm();
      content.querySelectorAll('[data-tool-detail]').forEach(btn => btn.onclick = () => {
        const tool = state.tools.find(item => item.id === btn.dataset.toolDetail);
        if (tool) renderToolDetail(tool);
      });
    }
    function renderToolCreateForm() {
      title.textContent = 'Nuovo tool';
      content.innerHTML = '<form class="form-card" id="tool-create-form">' +
        '<h2>Nuovo tool</h2>' +
        '<p class="field-help">Inserisci i dati del tool in un unico passaggio. Slug, nome e almeno una Return URL sono obbligatori.</p>' +
        '<div class="form-grid">' +
        '<label>Slug tool<br><input id="tool-create-slug" required autocomplete="off"></label>' +
        '<label>Nome visualizzato<br><input id="tool-create-name" required></label>' +
        '<label class="full-row">Descrizione opzionale<br><textarea id="tool-create-description" rows="3"></textarea></label>' +
        '<label>Owner email opzionale<br><input id="tool-create-owner" type="email"></label>' +
        '<label class="full-row">Return URL esatti<br><textarea id="tool-create-urls" rows="5" required placeholder="https://tool.example/callback"></textarea><span class="field-help">Uno per riga o separati da virgola.</span></label>' +
        '<label class="full-row">Permission keys<br><textarea id="tool-create-permissions" rows="4" placeholder="tool:read\\ntool:write"></textarea><span class="field-help">Una per riga o separate da virgola. Formato: segmenti gerarchici separati da due punti, es. tool:read o petyr:read:all. Solo minuscole, numeri e trattini.</span></label>' +
        '</div>' +
        '<p class="danger" id="tool-create-error" role="alert"></p>' +
        '<div class="form-actions"><button class="primary" type="submit">Salva tool</button><button class="secondary" id="tool-create-cancel" type="button">Annulla</button></div>' +
        '</form>';
      document.getElementById('tool-create-cancel').onclick = () => { state.view = 'tools'; render(); };
      document.getElementById('tool-create-form').onsubmit = async event => {
        event.preventDefault();
        formError('tool-create-error');
        const payload = {
          slug: valueOf('tool-create-slug'),
          display_name: valueOf('tool-create-name'),
          description: valueOf('tool-create-description') || null,
          owner_email: valueOf('tool-create-owner') || null,
          allowed_return_urls: listValueOf('tool-create-urls'),
          permission_keys: listValueOf('tool-create-permissions')
        };
        if (!payload.slug || !payload.display_name || !payload.allowed_return_urls.length) {
          formError('tool-create-error', 'Compila slug, nome e almeno una Return URL.');
          return;
        }
        try {
          const created = await api(apiUrl('/admin/tools'), { method:'POST', body: JSON.stringify(payload) });
          renderSecretResult('Tool salvato', created.tool_client_id, created.tool_client_secret, 'Torna ai tool', () => { state.view = 'tools'; render(); });
        } catch (error) {
          formError('tool-create-error', error);
        }
      };
    }
    async function renderToolDetail(tool, editMode = false, message = '', messageType = 'success') {
      title.textContent = 'Tool detail';
      const grantsData = await api(apiUrl('/admin/grants') + queryString({ tool_slug: tool.slug }));
      const grants = grantsData.items || [];
      const canViewAllUsers = hasAdminPermission('admin:users:read');
      let users = [];
      if (canViewAllUsers) {
        const usersData = await api(apiUrl('/admin/users'));
        users = usersData.items || [];
      }
      const now = Date.now();
      const visibleUsers = canViewAllUsers ? users : Array.from(new Map(grants.map(grant => {
        const user = {
          id: grant.user_id || grant.email_normalized || grant.user_email,
          email: grant.user_email || grant.email_normalized || '',
          display_name: '',
          status: grant.user_id ? 'active' : 'pending_user_link'
        };
        return [user.id, user];
      })).values());
      const accessRows = visibleUsers.map(user => {
        const userGrants = grants.filter(grant => grant.user_id === user.id || (!grant.user_id && grant.email_normalized === user.email_normalized));
        const authorized = tool.status === 'active' && user.status === 'active' && userGrants.some(grant => grant.status === 'active' && (!grant.valid_from || Date.parse(grant.valid_from) <= now) && (!grant.valid_until || Date.parse(grant.valid_until) > now));
        return {
          user,
          grants: userGrants,
          email: user.email,
          display_name: user.display_name || '',
          user_status: user.status,
          access: canViewAllUsers ? (authorized ? 'Autorizzato' : 'Non autorizzato') : 'Grant registrato',
          roles: userGrants.map(grant => grant.role).filter(Boolean).join(', ') || '—',
          permissions: [...new Set(userGrants.flatMap(grant => grant.permissions || []))].join(', ') || '—',
          grant_statuses: userGrants.map(grant => grant.status).filter(Boolean).join(', ') || '—'
        };
      });
      const disabled = editMode ? '' : ' disabled';
      content.innerHTML = '<div class="toolbar"><button class="secondary" id="back-tools">Tools</button>' +
        (editMode ? '<button class="primary" id="save-tool">Salva modifiche</button><button class="secondary" id="cancel-tool-edit">Annulla modifica</button>' : '<button class="primary" id="edit-tool">Modifica</button>') +
        '<button class="danger-button" id="delete-tool">Elimina</button><button class="secondary" id="rotate-tool">Ruota secret</button></div>' +
        '<p id="tool-detail-feedback" role="status"></p>' +
        '<div class="form-card"><div class="form-grid">' +
        '<label>Slug<br><input value="'+esc(tool.slug)+'" disabled></label>' +
        '<label>Nome<br><input id="tool-name" value="'+esc(tool.display_name)+'"'+disabled+'></label>' +
        '<label class="full-row">Descrizione<br><textarea id="tool-description" rows="3"'+disabled+'>'+esc(tool.description || '')+'</textarea></label>' +
        '<label>Stato<br><select id="tool-status"'+disabled+'><option value="active">active</option><option value="disabled">disabled</option><option value="maintenance">maintenance</option></select></label>' +
        '<label>Owner email<br><input id="tool-owner" value="'+esc(tool.owner_email || '')+'"'+disabled+'></label>' +
        '<label class="full-row">Client ID attivi<br><code class="secret-box">'+esc((tool.client_ids || []).join('\\n') || 'Nessun client attivo')+'</code></label>' +
        '<label class="full-row">Return URL<br><textarea id="tool-urls" rows="5"'+disabled+'>'+esc((tool.allowed_return_urls || []).join('\\n'))+'</textarea></label>' +
        '<label class="full-row">Permission keys<br><textarea id="tool-permissions" rows="5"'+disabled+'>'+esc((tool.permission_keys || []).join('\\n'))+'</textarea><span class="field-help">Una per riga o separate da virgola. Formato: segmenti gerarchici separati da due punti, es. tool:read o petyr:read:all. Solo minuscole, numeri e trattini.</span></label>' +
        '</div></div>' +
        '<section class="table-section" aria-labelledby="tool-access-heading"><div class="table-section-head"><div><h2 id="tool-access-heading">Utenti e autorizzazioni</h2><p>'+(canViewAllUsers ? 'Tutti gli utenti registrati su Access Layer; la colonna accesso considera stato utente, stato tool, grant e scadenza.' : 'Grant visibili per questo tool. La lista completa degli utenti è riservata ai platform admin.')+'</p></div><button class="primary" id="create-tool-grant">Concedi grant</button></div>' +
        table(accessRows, [
          {key:'email', label:'Utente'},
          {key:'display_name', label:'Nome'},
          {key:'user_status', label:'Stato utente'},
          {key:'access', label:'Accesso', render:row=>'<span class="status">'+esc(row.access)+'</span>'},
          {key:'roles', label:'Ruoli'},
          {key:'permissions', label:'Permessi'},
          {key:'grant_statuses', label:'Stato grant'},
          {key:'email', label:'Azioni', render:row=>row.grants.length ? '<button class="secondary" data-tool-user-grants="'+esc(row.user.id)+'">Gestisci grant</button>' : '<button class="primary" data-tool-user-grant="'+esc(row.user.id)+'">Concedi grant</button>'}
        ], {pageKey:'tool-access'}) +
        '</section>';
      bindPagination('tool-access', () => renderToolDetail(tool, editMode, message, messageType));
      document.getElementById('tool-status').value = tool.status;
      if (message) feedback('tool-detail-feedback', message, messageType);
      document.getElementById('back-tools').onclick = () => { state.view = 'tools'; render(); };
      const editButton = document.getElementById('edit-tool');
      if (editButton) editButton.onclick = () => renderToolDetail(tool, true);
      const cancelEditButton = document.getElementById('cancel-tool-edit');
      if (cancelEditButton) cancelEditButton.onclick = () => renderToolDetail(tool, false);
      const saveButton = document.getElementById('save-tool');
      if (saveButton) saveButton.onclick = async () => {
        feedback('tool-detail-feedback', '');
        saveButton.disabled = true;
        try {
          const result = await api(apiUrl('/admin/tools/') + tool.id, { method:'PATCH', body: JSON.stringify({
            display_name: document.getElementById('tool-name').value.trim(),
            description: document.getElementById('tool-description').value.trim() || null,
            status: document.getElementById('tool-status').value,
            owner_email: document.getElementById('tool-owner').value.trim() || null,
            allowed_return_urls: parseList(document.getElementById('tool-urls').value),
            permission_keys: parseList(document.getElementById('tool-permissions').value)
          }) });
          const updatedTool = { ...tool, ...result.tool };
          state.tools = state.tools.map(item => item.id === updatedTool.id ? updatedTool : item);
          renderToolDetail(updatedTool, false, 'Modifica salvata.', 'success');
        } catch (error) {
          if (!error.sessionExpired) {
            const hint = error.code === 'VALIDATION_ERROR' ? ' Verifica che slug, URL e permission keys siano validi. Le permission keys devono avere almeno due segmenti separati da due punti, es. tool:read o petyr:read:all.' : '';
            feedback('tool-detail-feedback', 'Salvataggio non riuscito: ' + (error.message || String(error)) + hint, 'danger');
          }
          saveButton.disabled = false;
        }
      };
      document.getElementById('delete-tool').onclick = async () => {
        feedback('tool-detail-feedback', '');
        if (!confirm('Confermi eliminazione del tool? Verranno rimossi credenziali, permission keys, grant, sessioni e richieste collegate. Gli audit storici restano consultabili.')) return;
        const deleteButton = document.getElementById('delete-tool');
        deleteButton.disabled = true;
        try {
          await api(apiUrl('/admin/tools/') + tool.id, { method:'DELETE' });
          state.toolNotice = 'Tool eliminato.';
          state.view = 'tools';
          render();
        } catch (error) {
          if (!error.sessionExpired) {
            feedback('tool-detail-feedback', 'Eliminazione non riuscita: ' + (error.message || String(error)), 'danger');
          }
          deleteButton.disabled = false;
        }
      };
      document.getElementById('rotate-tool').onclick = () => renderToolSecretRotationForm(tool);
      document.getElementById('create-tool-grant').onclick = () => renderGrantCreateForm({ toolSlug: tool.slug, back: () => renderToolDetail(tool) });
      content.querySelectorAll('[data-tool-user-grants]').forEach(button => button.onclick = () => {
        const row = accessRows.find(item => item.user.id === button.dataset.toolUserGrants);
        if (row) renderToolUserGrants(tool, row.user, row.grants);
      });
      content.querySelectorAll('[data-tool-user-grant]').forEach(button => button.onclick = () => {
        const row = accessRows.find(item => item.user.id === button.dataset.toolUserGrant);
        if (row) renderUserGrantCreateForm(row.user, { toolSlug: tool.slug, back: () => renderToolDetail(tool) });
      });
    }
    function renderToolUserGrants(tool, user, grants) {
      title.textContent = 'Grant utente';
      content.innerHTML = '<div class="toolbar"><button class="secondary" id="back-tool-access">'+esc(tool.display_name)+'</button><button class="primary" id="add-tool-user-grant">Aggiungi grant</button></div>' +
        '<dl><dt>Utente</dt><dd>'+esc(user.email || user.email_normalized || '')+'</dd><dt>Tool</dt><dd>'+esc(tool.display_name)+' ('+esc(tool.slug)+')</dd></dl>' +
        table(grants, [
          {key:'role', label:'Ruolo'},
          {key:'permissions', label:'Permessi', render:grant=>esc((grant.permissions || []).join(', ') || '—')},
          {key:'status', label:'Stato'},
          {key:'valid_until', label:'Scadenza'},
          {key:'id', label:'Azioni', render:grant=>'<button class="secondary" data-tool-grant-detail="'+esc(grant.id)+'">Dettaglio</button>'}
        ], {pageKey:'tool-user-grants'});
      bindPagination('tool-user-grants', () => renderToolUserGrants(tool, user, grants));
      document.getElementById('back-tool-access').onclick = () => renderToolDetail(tool);
      document.getElementById('add-tool-user-grant').onclick = () => renderUserGrantCreateForm(user, { toolSlug: tool.slug, back: () => renderToolDetail(tool) });
      content.querySelectorAll('[data-tool-grant-detail]').forEach(button => button.onclick = () => {
        const grant = grants.find(item => item.id === button.dataset.toolGrantDetail);
        if (grant) renderGrantDetail(grant, () => renderToolDetail(tool));
      });
    }
    function renderToolSecretRotationForm(tool) {
      title.textContent = 'Ruota secret tool';
      content.innerHTML = '<form class="form-card" id="tool-rotate-form">' +
        '<h2>Ruota secret per '+esc(tool.slug)+'</h2>' +
        '<p class="field-help">La rotazione genera un nuovo client secret mostrato una sola volta.</p>' +
        '<label><input id="tool-rotate-revoke" type="checkbox"> Revoca i client esistenti</label>' +
        '<p class="danger" id="tool-rotate-error" role="alert"></p>' +
        '<div class="form-actions"><button class="primary" type="submit">Ruota secret</button><button class="secondary" id="tool-rotate-cancel" type="button">Annulla</button></div>' +
        '</form>';
      document.getElementById('tool-rotate-cancel').onclick = () => renderToolDetail(tool);
      document.getElementById('tool-rotate-form').onsubmit = async event => {
        event.preventDefault();
        formError('tool-rotate-error');
        try {
          const rotated = await api(apiUrl('/admin/tools/') + tool.id + '/rotate-secret', { method:'POST', body: JSON.stringify({ revoke_existing: document.getElementById('tool-rotate-revoke').checked }) });
          renderSecretResult('Secret ruotato', rotated.tool_client_id, rotated.tool_client_secret, 'Torna al dettaglio tool', () => renderToolDetail(tool));
        } catch (error) {
          formError('tool-rotate-error', error);
        }
      };
    }
    async function renderUsers() {
      const filters = state.userFilters || {};
      const data = await api(apiUrl('/admin/users') + queryString(filters));
      content.innerHTML = '<form class="toolbar" id="user-filters">' +
        '<label>Cerca email/sub<br><input id="user-filter-search" name="search" value="'+esc(filters.search || '')+'"></label>' +
        '<label>Stato<br><select id="user-filter-status" name="status"><option value="">Tutti</option><option value="active">active</option><option value="suspended">suspended</option><option value="disabled">disabled</option></select></label>' +
        '<button class="primary" type="submit">Filtra</button><button class="secondary" id="user-clear" type="button">Pulisci</button></form>' +
        table(data.items, [{key:'email', label:'Email'}, {key:'google_sub', label:'Google sub'}, {key:'hd', label:'HD'}, {key:'status', label:'Stato'}, {key:'display_name', label:'Nome'}, {key:'id', label:'Azioni', render:r=>'<button class="secondary" data-user-detail="'+esc(r.id)+'">Dettaglio</button>'}], {pageKey:'users'});
      bindPagination('users', renderUsers);
      document.getElementById('user-filter-status').value = filters.status || '';
      document.getElementById('user-filters').onsubmit = event => {
        event.preventDefault();
        state.userFilters = {
          search: document.getElementById('user-filter-search').value.trim(),
          status: document.getElementById('user-filter-status').value
        };
        state.pages.users = 0;
        renderUsers();
      };
      document.getElementById('user-clear').onclick = () => {
        state.userFilters = {};
        state.pages.users = 0;
        renderUsers();
      };
      content.querySelectorAll('[data-user-detail]').forEach(btn => btn.onclick = () => {
        const user = data.items.find(item => item.id === btn.dataset.userDetail);
        if (user) renderUserDetail(user);
      });
    }
    async function renderUserDetail(user) {
      title.textContent = 'User detail';
      const [toolCatalog, grantsData] = await Promise.all([
        loadToolCatalog(),
        api(apiUrl('/admin/grants') + queryString({ email: user.email }))
      ]);
      state.toolCatalog = toolCatalog;
      const grants = grantsData.items || [];
      content.innerHTML = '<div class="toolbar"><button class="secondary" id="back-users">Utenti</button><button class="primary" id="save-user">Salva</button><button class="primary" id="create-user-grant">Aggiungi tool</button></div>' +
        '<dl><dt>Email</dt><dd>'+esc(user.email)+'</dd><dt>Google sub</dt><dd>'+esc(user.google_sub)+'</dd><dt>HD</dt><dd>'+esc(user.hd)+'</dd><dt>Nome</dt><dd>'+esc(user.display_name || '')+'</dd></dl>' +
        '<div class="form-card"><label>Stato<br><select id="user-status"><option value="active">active</option><option value="suspended">suspended</option><option value="disabled">disabled</option></select></label></div>' +
        '<section class="table-section" aria-labelledby="user-tools-heading"><div class="table-section-head"><div><h2 id="user-tools-heading">Tool e autorizzazioni</h2><p>Un grant per riga: qui puoi vedere e modificare tutti gli accessi dell’utente.</p></div></div>' +
        table(grants, [
          {key:'tool_display_name', label:'Tool', render:grant=>esc(grant.tool_display_name || grant.tool_slug)},
          {key:'role', label:'Ruolo'},
          {key:'permissions', label:'Permessi', render:grant=>esc((grant.permissions || []).join(', ') || '—')},
          {key:'status', label:'Stato'},
          {key:'valid_until', label:'Scadenza'},
          {key:'id', label:'Azioni', render:grant=>'<button class="secondary" data-user-grant-detail="'+esc(grant.id)+'">Gestisci grant</button>'}
        ], {pageKey:'user-grants'}) +
        '</section>';
      bindPagination('user-grants', () => renderUserDetail(user));
      document.getElementById('user-status').value = user.status;
      document.getElementById('back-users').onclick = () => { state.view = 'users'; render(); };
      document.getElementById('save-user').onclick = async () => {
        const nextStatus = document.getElementById('user-status').value;
        if (nextStatus !== 'active' && nextStatus !== user.status && !confirm("Confermi la revoca dell'accesso? Le sessioni attive potrebbero essere terminate.")) return;
        await api(apiUrl('/admin/users/') + user.id, { method:'PATCH', body: JSON.stringify({ status: nextStatus }) });
        state.view = 'users';
        render();
      };
      document.getElementById('create-user-grant').onclick = () => renderUserGrantCreateForm(user);
      content.querySelectorAll('[data-user-grant-detail]').forEach(button => button.onclick = () => {
        const grant = grants.find(item => item.id === button.dataset.userGrantDetail);
        if (grant) renderGrantDetail(grant, () => renderUserDetail(user));
      });
    }
    async function renderUserGrantCreateForm(user, options = {}) {
      title.textContent = 'Crea grant';
      await loadToolCatalog();
      const selectedToolSlug = options.toolSlug || '';
      content.innerHTML = '<form class="form-card" id="user-grant-create-form">' +
        '<h2>Crea grant per '+esc(user.email)+'</h2>' +
        '<p class="field-help">Scegli un tool e i relativi permessi registrati. I grant con permessi vuoti restano validi come grant basati sul solo ruolo.</p>' +
        '<div class="form-grid">' +
        '<label>Tool<br><select id="user-grant-tool" required>'+toolOptions(selectedToolSlug)+'</select></label>' +
        '<label>Ruolo<br><input id="user-grant-role" required value="tool_user"></label>' +
        '<div class="full-row permission-field"><span>Permessi</span>'+permissionPickerMarkup('user-grant-permissions', selectedToolSlug, [], 'user-grant-permissions-help')+'<span class="field-help" id="user-grant-permissions-help">Apri l’elenco e seleziona i permessi con le checkbox.</span></div>' +
        '<label>Scadenza opzionale ISO-8601 UTC<br><input id="user-grant-valid-until" placeholder="2026-12-31T23:59:59Z"></label>' +
        '</div>' +
        '<p class="danger" id="user-grant-create-error" role="alert"></p>' +
        '<div class="form-actions"><button class="primary" type="submit">Salva grant</button><button class="secondary" id="user-grant-create-cancel" type="button">Annulla</button></div>' +
        '</form>';
      document.getElementById('user-grant-create-cancel').onclick = () => {
        if (options.back) return options.back();
        return renderUserDetail(user);
      };
      bindPermissionPicker('user-grant-permissions');
      document.getElementById('user-grant-tool').onchange = () => syncPermissionPicker('user-grant-tool', 'user-grant-permissions');
      document.getElementById('user-grant-create-form').onsubmit = async event => {
        event.preventDefault();
        formError('user-grant-create-error');
        const payload = {
          tool_slug: valueOf('user-grant-tool'),
          user_id: user.id,
          role: valueOf('user-grant-role'),
          permissions: selectedValues('user-grant-permissions'),
          valid_until: valueOf('user-grant-valid-until') || null
        };
        if (!payload.tool_slug || !payload.role) {
          formError('user-grant-create-error', 'Seleziona tool e ruolo.');
          return;
        }
        try {
          await api(apiUrl('/admin/grants'), { method:'POST', body: JSON.stringify(payload) });
          if (options.back) {
            options.back();
          } else {
            renderUserDetail(user);
          }
        } catch (error) {
          formError('user-grant-create-error', grantErrorMessage(error));
        }
      };
    }
    async function renderGrants() {
      const filters = state.grantFilters || {};
      const [data, toolCatalog] = await Promise.all([
        api(apiUrl('/admin/grants') + queryString(filters)),
        loadToolCatalog()
      ]);
      state.toolCatalog = toolCatalog;
      state.grants = data.items;
      content.innerHTML = '<form class="toolbar" id="grant-filters">' +
        '<label>Tool<br><select id="grant-filter-tool" name="tool_slug">'+toolOptions(filters.tool_slug || '')+'</select></label>' +
        '<label>Email<br><input id="grant-filter-email" name="email" value="'+esc(filters.email || '')+'"></label>' +
        '<label>Stato<br><select id="grant-filter-status" name="status"><option value="">Tutti</option><option value="active">active</option><option value="revoked">revoked</option><option value="expired">expired</option><option value="pending_user_link">pending_user_link</option></select></label>' +
        '<button class="primary" type="submit">Filtra</button><button class="secondary" id="grant-clear" type="button">Pulisci</button><button class="primary" id="create-grant" type="button">Nuovo grant</button>' +
        '<button class="secondary" id="bulk-grants" type="button">Rilascia grant in blocco</button><button class="secondary" id="csv-grants" type="button">Importa CSV avanzato</button><button class="secondary" id="grant-template" type="button">Template CSV</button><button class="secondary" id="grant-export" type="button">Export grant</button><button class="secondary" id="permissions-export" type="button">Export permessi</button></form>' +
        table(data.items, [{key:'tool_slug', label:'Tool'}, {key:'user_email', label:'Utente'}, {key:'email_normalized', label:'Email pendente'}, {key:'role', label:'Ruolo'}, {key:'status', label:'Stato'}, {key:'permissions', label:'Permessi', render:r=>esc((r.permissions||[]).join(', '))}, {key:'valid_until', label:'Scadenza'}, {key:'id', label:'Azioni', render:r=>'<button class="secondary" data-grant-detail="'+esc(r.id)+'">Dettaglio</button>'}], {pageKey:'grants'});
      bindPagination('grants', renderGrants);
      document.getElementById('grant-filter-status').value = filters.status || '';
      document.getElementById('grant-filters').onsubmit = event => {
        event.preventDefault();
        state.grantFilters = {
          tool_slug: document.getElementById('grant-filter-tool').value.trim(),
          email: document.getElementById('grant-filter-email').value.trim(),
          status: document.getElementById('grant-filter-status').value
        };
        state.pages.grants = 0;
        renderGrants();
      };
      document.getElementById('grant-clear').onclick = () => {
        state.grantFilters = {};
        state.pages.grants = 0;
        renderGrants();
      };
      document.getElementById('create-grant').onclick = () => renderGrantCreateForm();
      document.getElementById('bulk-grants').onclick = () => renderGrantBulkForm();
      document.getElementById('csv-grants').onclick = () => renderGrantCsvImportForm();
      document.getElementById('grant-template').onclick = () => { location.href = apiUrl('/admin/grants/bulk/template'); };
      document.getElementById('grant-export').onclick = () => { location.href = apiUrl('/admin/grants/export'); };
      document.getElementById('permissions-export').onclick = () => { location.href = apiUrl('/admin/tools/permissions/export'); };
      content.querySelectorAll('[data-grant-detail]').forEach(btn => btn.onclick = () => {
        const grant = state.grants.find(item => item.id === btn.dataset.grantDetail);
        if (grant) renderGrantDetail(grant);
      });
    }
    async function renderGrantCreateForm(options = {}) {
      title.textContent = 'Nuovo grant';
      const filters = state.grantFilters || {};
      await loadToolCatalog();
      const selectedToolSlug = options.toolSlug || filters.tool_slug || '';
      content.innerHTML = '<form class="form-card" id="grant-create-form">' +
        '<h2>Nuovo grant</h2>' +
        '<p class="field-help">Crea un grant attivo per un utente noto o un grant pendente per email. Tool e permessi derivano dal catalogo registrato.</p>' +
        '<div class="form-grid">' +
        '<label>Tool<br><select id="grant-create-tool" required>'+toolOptions(selectedToolSlug)+'</select></label>' +
        '<label>Email utente<br><input id="grant-create-email" required type="email" value="'+esc(filters.email || '')+'"></label>' +
        '<label>Ruolo<br><input id="grant-create-role" required value="tool_user"></label>' +
        '<label>Scadenza opzionale ISO-8601 UTC<br><input id="grant-create-valid-until" placeholder="2026-12-31T23:59:59Z"></label>' +
        '<div class="full-row permission-field"><span>Permessi</span>'+permissionPickerMarkup('grant-create-permissions', selectedToolSlug, [], 'grant-create-permissions-help')+'<span class="field-help" id="grant-create-permissions-help">Apri l’elenco e seleziona i permessi con le checkbox.</span></div>' +
        '</div>' +
        '<p class="danger" id="grant-create-error" role="alert"></p>' +
        '<div class="form-actions"><button class="primary" type="submit">Salva grant</button><button class="secondary" id="grant-create-cancel" type="button">Annulla</button></div>' +
        '</form>';
      document.getElementById('grant-create-cancel').onclick = () => {
        if (options.back) return options.back();
        state.view = 'grants';
        return render();
      };
      bindPermissionPicker('grant-create-permissions');
      document.getElementById('grant-create-tool').onchange = () => syncPermissionPicker('grant-create-tool', 'grant-create-permissions');
      document.getElementById('grant-create-form').onsubmit = async event => {
        event.preventDefault();
        formError('grant-create-error');
        const payload = {
          tool_slug: valueOf('grant-create-tool'),
          email: valueOf('grant-create-email'),
          role: valueOf('grant-create-role'),
          permissions: selectedValues('grant-create-permissions'),
          valid_until: valueOf('grant-create-valid-until') || null
        };
        if (!payload.tool_slug || !payload.email || !payload.role) {
          formError('grant-create-error', 'Seleziona tool, email e ruolo.');
          return;
        }
        try {
          await api(apiUrl('/admin/grants'), { method:'POST', body: JSON.stringify(payload) });
          if (options.back) {
            options.back();
            return;
          }
          state.view = 'grants';
          state.grantFilters = { tool_slug: payload.tool_slug, email: payload.email };
          render();
        } catch (error) {
          formError('grant-create-error', grantErrorMessage(error));
        }
      };
    }
    async function renderGrantBulkForm() {
      title.textContent = 'Rilascia grant in blocco';
      await loadToolCatalog();
      content.innerHTML = '<form class="form-card" id="grant-bulk-form">' +
        '<h2>Rilascia grant in blocco</h2>' +
        '<p class="field-help">Inserisci un indirizzo email aziendale per riga, poi scegli tool e permessi. La preview resta obbligatoria: nessun grant viene scritto finché non confermi una preview senza errori. Se email e tool hanno già un grant attivo o pendente, il primo grant resta invariato.</p>' +
        '<div class="form-grid">' +
        '<label class="full-row">Email aziendali<br><textarea id="grant-bulk-emails" rows="12" required placeholder="mario.rossi@unguess.io\\nanna.bianchi@unguess.io"></textarea><span class="field-help">Una email per riga. Le email non ancora registrate diventano grant pendenti e si attivano al primo login verificato.</span></label>' +
        '<label>Tool<br><select id="grant-bulk-tool" required>'+toolOptions('')+'</select></label>' +
        '<label>Ruolo<br><input id="grant-bulk-role" required value="tool_user"></label>' +
        '<div class="full-row permission-field"><span>Permessi</span>'+permissionPickerMarkup('grant-bulk-permissions', '', [], 'grant-bulk-permissions-help')+'<span class="field-help" id="grant-bulk-permissions-help">Apri l’elenco e seleziona i permessi con le checkbox.</span></div>' +
        '<label>Scadenza opzionale ISO-8601 UTC<br><input id="grant-bulk-valid-until" placeholder="2026-12-31T23:59:59Z"></label>' +
        '</div>' +
        '<p class="danger" id="grant-bulk-error" role="alert"></p>' +
        '<div class="form-actions"><button class="secondary" id="grant-bulk-preview" type="button">Anteprima</button><button class="primary" id="grant-bulk-commit" type="button" disabled>Conferma rilascio</button><button class="secondary" id="grant-bulk-cancel" type="button">Annulla</button></div>' +
        '<div id="grant-bulk-result" aria-live="polite"></div>' +
        '</form>';
      let previewResult = null;
      const csvCell = value => {
        const raw = String(value || '');
        return /[",\\n\\r]/.test(raw) ? '"' + raw.replace(/"/g, '""') + '"' : raw;
      };
      const bulkPayload = () => {
        const emails = Array.from(new Set(valueOf('grant-bulk-emails').split(/\\r?\\n/).map(email => email.trim()).filter(Boolean)));
        const toolSlug = valueOf('grant-bulk-tool');
        const role = valueOf('grant-bulk-role');
        const permissions = selectedValues('grant-bulk-permissions').join(';');
        const validUntil = valueOf('grant-bulk-valid-until');
        if (!emails.length || !toolSlug || !role) return null;
        const headers = ['email', 'tool_slug', 'role', 'permissions', 'valid_until', 'action', 'note'];
        const rows = emails.map(email => [email, toolSlug, role, permissions, validUntil, 'upsert', '']);
        return { content: headers.join(',') + '\\n' + rows.map(row => row.map(csvCell).join(',')).join('\\n') + '\\n' };
      };
      const showBulkResult = result => {
        previewResult = result;
        const summary = result.summary || {};
        document.getElementById('grant-bulk-result').innerHTML = '<p class="'+(summary.error ? 'danger' : 'success')+'" role="status">Righe: '+esc(summary.total_rows || 0)+' · valide: '+esc(summary.ok || 0)+' · avvisi: '+esc(summary.warning || 0)+' · errori: '+esc(summary.error || 0)+'</p>' +
          table(result.rows || [], [
            {key:'row', label:'Riga'},
            {key:'email', label:'Email'},
            {key:'tool_slug', label:'Tool'},
            {key:'result', label:'Esito'},
            {key:'resolved_user', label:'Utente'},
            {key:'status_after', label:'Stato grant'},
            {key:'reason', label:'Dettaglio'}
          ], {pageKey:'grant-bulk-result'});
        bindPagination('grant-bulk-result', () => showBulkResult(result));
        document.getElementById('grant-bulk-commit').disabled = Boolean(summary.error);
      };
      const invalidatePreview = () => {
        previewResult = null;
        document.getElementById('grant-bulk-commit').disabled = true;
        document.getElementById('grant-bulk-result').innerHTML = '';
      };
      bindPermissionPicker('grant-bulk-permissions', invalidatePreview);
      document.getElementById('grant-bulk-cancel').onclick = () => { state.view = 'grants'; render(); };
      document.getElementById('grant-bulk-tool').onchange = () => {
        syncPermissionPicker('grant-bulk-tool', 'grant-bulk-permissions', [], invalidatePreview);
        invalidatePreview();
      };
      ['grant-bulk-emails', 'grant-bulk-role', 'grant-bulk-valid-until'].forEach(id => {
        document.getElementById(id).onchange = invalidatePreview;
        document.getElementById(id).oninput = invalidatePreview;
      });
      document.getElementById('grant-bulk-preview').onclick = async () => {
        formError('grant-bulk-error');
        const payload = bulkPayload();
        if (!payload) {
          formError('grant-bulk-error', 'Inserisci almeno una email e seleziona tool e ruolo.');
          return;
        }
        try { showBulkResult(await api(apiUrl('/admin/grants/bulk/preview'), { method:'POST', body: JSON.stringify(payload) })); }
        catch (error) { formError('grant-bulk-error', error); }
      };
      document.getElementById('grant-bulk-commit').onclick = async () => {
        formError('grant-bulk-error');
        const payload = bulkPayload();
        if (!payload || !previewResult) {
          formError('grant-bulk-error', 'Esegui prima l’anteprima del contenuto corrente.');
          return;
        }
        try {
          const result = await api(apiUrl('/admin/grants/bulk/commit'), { method:'POST', body: JSON.stringify(payload) });
          showBulkResult(result);
          state.pages.grants = 0;
        } catch (error) {
          formError('grant-bulk-error', error);
          if (error.details) showBulkResult(error.details);
        }
      };
    }
    function renderGrantCsvImportForm() {
      title.textContent = 'Importa CSV grant';
      content.innerHTML = '<form class="form-card" id="grant-csv-form">' +
        '<h2>Importa CSV avanzato</h2>' +
        '<p class="field-help">Per assegnazioni con tool, ruoli o azioni differenti sulla stessa importazione. Le colonne richieste sono email, tool_slug, role, permissions, valid_until, action, note. Sono accettati i separatori virgola e punto e virgola.</p>' +
        '<label class="full-row">CSV<br><textarea id="grant-csv-content" rows="12" placeholder="email,tool_slug,role,permissions,valid_until,action,note"></textarea></label>' +
        '<p class="danger" id="grant-csv-error" role="alert"></p>' +
        '<div class="form-actions"><button class="secondary" id="grant-csv-preview" type="button">Anteprima</button><button class="primary" id="grant-csv-commit" type="button">Commit import</button><button class="secondary" id="grant-csv-cancel" type="button">Annulla</button></div>' +
        '<pre id="grant-csv-result" aria-live="polite"></pre>' +
        '</form>';
      const bulkPayload = () => ({ content: document.getElementById('grant-csv-content').value });
      const showBulkResult = result => { document.getElementById('grant-csv-result').textContent = JSON.stringify(result, null, 2); };
      document.getElementById('grant-csv-cancel').onclick = () => { state.view = 'grants'; render(); };
      document.getElementById('grant-csv-preview').onclick = async () => {
        formError('grant-csv-error');
        try { showBulkResult(await api(apiUrl('/admin/grants/bulk/preview'), { method:'POST', body: JSON.stringify(bulkPayload()) })); }
        catch (error) { formError('grant-csv-error', error); }
      };
      document.getElementById('grant-csv-commit').onclick = async () => {
        formError('grant-csv-error');
        try {
          const result = await api(apiUrl('/admin/grants/bulk/commit'), { method:'POST', body: JSON.stringify(bulkPayload()) });
          showBulkResult(result);
          state.pages.grants = 0;
        } catch (error) {
          formError('grant-csv-error', error);
          if (error.details) showBulkResult(error.details);
        }
      };
    }
    async function renderGrantDetail(grant, back) {
      title.textContent = 'Grant detail';
      await loadToolCatalog();
      content.innerHTML = '<div class="toolbar"><button class="secondary" id="back-grants">Grant</button><button class="primary" id="save-grant">Salva</button><button class="secondary" id="revoke-grant">Revoca</button></div>' +
        '<dl><dt>Tool</dt><dd>'+esc(grant.tool_slug)+'</dd><dt>Utente</dt><dd>'+esc(grant.user_email || grant.email_normalized || '')+'</dd></dl>' +
        '<label>Ruolo<br><input id="grant-role" value="'+esc(grant.role)+'"></label><br><br>' +
        '<div class="permission-field"><span>Permessi</span>'+permissionPickerMarkup('grant-permissions', grant.tool_slug, grant.permissions || [], 'grant-permissions-help')+'<span class="field-help" id="grant-permissions-help">Apri l’elenco e seleziona i permessi con le checkbox.</span></div><br><br>' +
        '<label>Stato<br><select id="grant-status"><option value="active">active</option><option value="revoked">revoked</option><option value="expired">expired</option><option value="pending_user_link">pending_user_link</option></select></label><br><br>' +
        '<label>Scadenza<br><input id="grant-valid-until" placeholder="2026-12-31T23:59:59Z" value="'+esc(grant.valid_until || '')+'"></label>' +
        '<p class="danger" id="grant-detail-error" role="alert"></p>';
      document.getElementById('grant-status').value = grant.status;
      bindPermissionPicker('grant-permissions');
      document.getElementById('back-grants').onclick = () => {
        if (back) return back();
        state.view = 'grants';
        return render();
      };
      document.getElementById('save-grant').onclick = async () => {
        formError('grant-detail-error');
        try {
          await api(apiUrl('/admin/grants/') + grant.id, { method:'PATCH', body: JSON.stringify({
            role: document.getElementById('grant-role').value,
            permissions: selectedValues('grant-permissions'),
            status: document.getElementById('grant-status').value,
            valid_until: document.getElementById('grant-valid-until').value.trim() || null
          }) });
          if (back) return back();
          state.view = 'grants';
          render();
        } catch (error) {
          formError('grant-detail-error', grantErrorMessage(error));
        }
      };
      document.getElementById('revoke-grant').onclick = async () => {
        if (!confirm("Confermi la revoca dell'accesso? Le sessioni attive potrebbero essere terminate.")) return;
        await api(apiUrl('/admin/grants/') + grant.id, { method:'PATCH', body: JSON.stringify({ status: 'revoked' }) });
        if (back) return back();
        state.view = 'grants';
        render();
      };
    }
    async function renderRequests() {
      const filters = state.requestFilters || {};
      const [data, toolCatalog] = await Promise.all([
        api(apiUrl('/admin/access-requests') + queryString(filters)),
        loadToolCatalog()
      ]);
      state.toolCatalog = toolCatalog;
      content.innerHTML = '<form class="toolbar" id="request-filters">' +
        '<label>Stato<br><select id="request-filter-status" name="status"><option value="">Tutti</option><option value="pending">pending</option><option value="approved">approved</option><option value="rejected">rejected</option><option value="closed">closed</option><option value="expired">expired</option></select></label>' +
        '<label>Tool<br><select id="request-filter-tool" name="tool_slug">'+toolOptions(filters.tool_slug || '')+'</select></label>' +
        '<label>Email<br><input id="request-filter-email" name="email" value="'+esc(filters.email || '')+'"></label>' +
        '<button class="primary" type="submit">Filtra</button><button class="secondary" id="request-clear" type="button">Pulisci</button></form>' +
        table(data.items, [
        {key:'status', label:'Stato'}, {key:'tool_slug', label:'Tool'}, {key:'email', label:'Email'}, {key:'display_name', label:'Nome'},
        {key:'first_seen_at', label:'Primo tentativo'}, {key:'last_seen_at', label:'Ultimo tentativo'}, {key:'attempts_count', label:'Tentativi'}, {key:'last_correlation_id', label:'Correlazione'}, {key:'id', label:'Azioni', render:r => r.status === 'pending' ? '<button class="primary" data-approve="'+esc(r.id)+'">Approva</button> <button class="secondary" data-reject="'+esc(r.id)+'">Rifiuta</button> <button class="secondary" data-close="'+esc(r.id)+'">Chiudi</button>' : ''}
      ], {pageKey:'requests'});
      bindPagination('requests', renderRequests);
      document.getElementById('request-filter-status').value = filters.status || '';
      document.getElementById('request-filters').onsubmit = event => {
        event.preventDefault();
        state.requestFilters = {
          status: document.getElementById('request-filter-status').value,
          tool_slug: document.getElementById('request-filter-tool').value.trim(),
          email: document.getElementById('request-filter-email').value.trim()
        };
        state.pages.requests = 0;
        renderRequests();
      };
      document.getElementById('request-clear').onclick = () => {
        state.requestFilters = {};
        state.pages.requests = 0;
        renderRequests();
      };
      content.querySelectorAll('[data-approve]').forEach(btn => btn.onclick = () => {
        const request = data.items.find(item => item.id === btn.dataset.approve);
        if (request) renderAccessRequestApproveForm(request);
      });
      content.querySelectorAll('[data-reject]').forEach(btn => btn.onclick = () => {
        const request = data.items.find(item => item.id === btn.dataset.reject);
        if (request) renderAccessRequestDecisionForm(request, 'reject');
      });
      content.querySelectorAll('[data-close]').forEach(btn => btn.onclick = () => {
        const request = data.items.find(item => item.id === btn.dataset.close);
        if (request) renderAccessRequestDecisionForm(request, 'close');
      });
    }
    async function renderAccessRequestApproveForm(request) {
      title.textContent = 'Approva richiesta';
      await loadToolCatalog();
      content.innerHTML = '<form class="form-card" id="request-approve-form">' +
        '<h2>Approva richiesta accesso</h2>' +
        '<dl><dt>Tool</dt><dd>'+esc(request.tool_slug)+'</dd><dt>Email</dt><dd>'+esc(request.email)+'</dd><dt>Nome</dt><dd>'+esc(request.display_name || '')+'</dd></dl>' +
        '<div class="form-grid">' +
        '<label>Ruolo<br><input id="request-approve-role" required value="tool_user"></label>' +
        '<label>Scadenza opzionale ISO-8601 UTC<br><input id="request-approve-valid-until" placeholder="2026-12-31T23:59:59Z"></label>' +
        '<div class="full-row permission-field"><span>Permessi</span>'+permissionPickerMarkup('request-approve-permissions', request.tool_slug, [], 'request-approve-permissions-help')+'<span class="field-help" id="request-approve-permissions-help">Apri l’elenco e seleziona i permessi con le checkbox.</span></div>' +
        '<label class="full-row">Nota opzionale<br><textarea id="request-approve-note" rows="3"></textarea></label>' +
        '</div>' +
        '<p class="danger" id="request-approve-error" role="alert"></p>' +
        '<div class="form-actions"><button class="primary" type="submit">Approva e salva grant</button><button class="secondary" id="request-approve-cancel" type="button">Annulla</button></div>' +
        '</form>';
      bindPermissionPicker('request-approve-permissions');
      document.getElementById('request-approve-cancel').onclick = () => { state.view = 'requests'; render(); };
      document.getElementById('request-approve-form').onsubmit = async event => {
        event.preventDefault();
        formError('request-approve-error');
        const payload = {
          role: valueOf('request-approve-role'),
          permissions: selectedValues('request-approve-permissions'),
          valid_until: valueOf('request-approve-valid-until') || null,
          note: valueOf('request-approve-note') || null
        };
        if (!payload.role) {
          formError('request-approve-error', 'Compila il ruolo.');
          return;
        }
        try {
          await api(apiUrl('/admin/access-requests/') + request.id + '/approve', { method:'POST', body: JSON.stringify(payload) });
          loadBase();
          state.view = 'requests';
          render();
        } catch (error) {
          formError('request-approve-error', error);
        }
      };
    }
    function renderAccessRequestDecisionForm(request, action) {
      const isReject = action === 'reject';
      const heading = isReject ? 'Rifiuta richiesta accesso' : 'Chiudi richiesta accesso';
      const endpoint = isReject ? 'reject' : 'close';
      const buttonLabel = isReject ? 'Rifiuta richiesta' : 'Chiudi richiesta';
      title.textContent = heading;
      content.innerHTML = '<form class="form-card" id="request-decision-form">' +
        '<h2>'+esc(heading)+'</h2>' +
        '<dl><dt>Tool</dt><dd>'+esc(request.tool_slug)+'</dd><dt>Email</dt><dd>'+esc(request.email)+'</dd><dt>Nome</dt><dd>'+esc(request.display_name || '')+'</dd></dl>' +
        '<label>Nota opzionale<br><textarea id="request-decision-note" rows="4"></textarea></label>' +
        '<p class="danger" id="request-decision-error" role="alert"></p>' +
        '<div class="form-actions"><button class="primary" type="submit">'+esc(buttonLabel)+'</button><button class="secondary" id="request-decision-cancel" type="button">Annulla</button></div>' +
        '</form>';
      document.getElementById('request-decision-cancel').onclick = () => { state.view = 'requests'; render(); };
      document.getElementById('request-decision-form').onsubmit = async event => {
        event.preventDefault();
        formError('request-decision-error');
        try {
          await api(apiUrl('/admin/access-requests/') + request.id + '/' + endpoint, { method:'POST', body: JSON.stringify({ note: valueOf('request-decision-note') || null }) });
          loadBase();
          state.view = 'requests';
          render();
        } catch (error) {
          formError('request-decision-error', error);
        }
      };
    }
    async function renderAudit() {
      const filters = state.auditFilters || {};
      const data = await api(apiUrl('/admin/audit-logs') + queryString(filters));
      content.innerHTML = '<form class="toolbar" id="audit-filters">' +
        '<label>Da<br><input id="audit-date-from" name="date_from" placeholder="2026-06-16T00:00:00Z" value="'+esc(filters.date_from || '')+'"></label>' +
        '<label>A<br><input id="audit-date-to" name="date_to" placeholder="2026-06-16T23:59:59Z" value="'+esc(filters.date_to || '')+'"></label>' +
        '<label>Tool<br><input id="audit-tool-slug" name="tool_slug" value="'+esc(filters.tool_slug || '')+'"></label>' +
        '<label>Email<br><input id="audit-email" name="email" value="'+esc(filters.email || '')+'"></label>' +
        '<label>Google sub<br><input id="audit-google-sub" name="google_sub" value="'+esc(filters.google_sub || '')+'"></label>' +
        '<label>Esito<br><select id="audit-outcome" name="outcome"><option value="">Tutti</option><option value="success">success</option><option value="denied">denied</option><option value="error">error</option><option value="info">info</option></select></label>' +
        '<label>Reason<br><input id="audit-reason-code" name="reason_code" value="'+esc(filters.reason_code || '')+'"></label>' +
        '<label>Correlazione<br><input id="audit-correlation-id" name="correlation_id" value="'+esc(filters.correlation_id || '')+'"></label>' +
        '<button class="primary" type="submit">Filtra</button><button class="secondary" id="audit-clear" type="button">Pulisci</button></form>' +
        table(data.items, [{key:'created_at', label:'Quando'}, {key:'event_type', label:'Evento'}, {key:'tool_slug', label:'Tool'}, {key:'actor_email', label:'Attore'}, {key:'outcome', label:'Esito'}, {key:'reason_code', label:'Reason'}, {key:'correlation_id', label:'Correlazione', render:r=>'<button class="secondary" data-copy-correlation="'+esc(r.correlation_id)+'">'+esc(r.correlation_id)+'</button>'}], {pageKey:'audit'});
      bindPagination('audit', renderAudit);
      document.getElementById('audit-outcome').value = filters.outcome || '';
      document.getElementById('audit-filters').onsubmit = event => {
        event.preventDefault();
        state.auditFilters = {
          date_from: document.getElementById('audit-date-from').value.trim(),
          date_to: document.getElementById('audit-date-to').value.trim(),
          tool_slug: document.getElementById('audit-tool-slug').value.trim(),
          email: document.getElementById('audit-email').value.trim(),
          google_sub: document.getElementById('audit-google-sub').value.trim(),
          outcome: document.getElementById('audit-outcome').value,
          reason_code: document.getElementById('audit-reason-code').value.trim(),
          correlation_id: document.getElementById('audit-correlation-id').value.trim()
        };
        state.pages.audit = 0;
        renderAudit();
      };
      document.getElementById('audit-clear').onclick = () => {
        state.auditFilters = {};
        state.pages.audit = 0;
        renderAudit();
      };
      content.querySelectorAll('[data-copy-correlation]').forEach(btn => btn.onclick = async () => {
        const value = btn.dataset.copyCorrelation || '';
        if (navigator.clipboard) await navigator.clipboard.writeText(value);
        else btn.textContent = value;
      });
    }
    function downloadBlob(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }
    async function renderBackup() {
      content.innerHTML = '<section class="form-card">' +
        '<h2>Backup Access Layer</h2>' +
        '<p class="field-help">Scarica un backup JSON cifrato di utenti, tool, client ID, hash dei client secret, permessi, grant, assegnazioni admin e richieste accesso. Sessioni, token temporanei e audit log non vengono inclusi.</p>' +
        '<p class="warning">Per mantenere validi i client secret dopo un restore devi conservare anche lo stesso TOOL_CLIENT_SECRET_PEPPER e la BACKUP_ENCRYPTION_KEY fuori dal backup.</p>' +
        '<div class="form-actions"><button class="primary" id="backup-download" type="button">Scarica backup cifrato</button><button class="secondary" id="backup-secret-material" type="button">Scarica secret restore</button></div>' +
        '<p class="danger" id="backup-error" role="alert"></p>' +
        '</section>' +
        '<section class="form-card" style="margin-top:16px">' +
        '<h2>Import restore</h2>' +
        '<p class="field-help">Usa questa funzione su un database appena migrato o per ripristino controllato. Con replace_existing vengono eliminati dati operativi esistenti e ricaricati quelli del backup.</p>' +
        '<label>File backup JSON<br><input id="backup-file" type="file" accept="application/json,.json"></label><br><br>' +
        '<label><input id="backup-replace" type="checkbox"> Replace existing data</label><br>' +
        '<label><input id="backup-confirm" type="checkbox"> Confermo il restore distruttivo se replace_existing è attivo</label>' +
        '<div class="form-actions"><button class="secondary" id="backup-import" type="button">Importa backup</button></div>' +
        '<p id="backup-import-result" role="status"></p>' +
        '<p class="danger" id="backup-import-error" role="alert"></p>' +
        '</section>';
      document.getElementById('backup-download').onclick = async () => {
        formError('backup-error');
        try {
          const res = await fetch(apiUrl('/admin/backup/export'), { credentials: 'same-origin' });
          if (!res.ok) throw new Error((await res.json()).error?.message || 'Errore backup');
          const disposition = res.headers.get('content-disposition') || '';
          const match = disposition.match(/filename="?([^";]+)"?/i);
          const filename = match ? match[1] : 'access-layer-backup.json';
          downloadBlob(await res.blob(), filename);
        } catch (error) {
          formError('backup-error', error);
        }
      };
      document.getElementById('backup-secret-material').onclick = async () => {
        formError('backup-error');
        try {
          const res = await fetch(apiUrl('/admin/backup/secret-material'), { credentials: 'same-origin' });
          if (!res.ok) throw new Error((await res.json()).error?.message || 'Errore secret restore');
          downloadBlob(await res.blob(), 'access-layer-restore-secret-material.json');
        } catch (error) {
          formError('backup-error', error);
        }
      };
      document.getElementById('backup-import').onclick = async () => {
        formError('backup-import-error');
        document.getElementById('backup-import-result').textContent = '';
        const input = document.getElementById('backup-file');
        if (!input.files || !input.files[0]) {
          formError('backup-import-error', 'Seleziona un file JSON di backup.');
          return;
        }
        const replace = document.getElementById('backup-replace').checked;
        const confirmed = document.getElementById('backup-confirm').checked;
        if (replace && !confirmed) {
          formError('backup-import-error', 'Conferma il restore distruttivo prima di importare.');
          return;
        }
        if (!confirm('Confermi import/restore del backup selezionato?')) return;
        try {
          const backup = JSON.parse(await input.files[0].text());
          const result = await api(apiUrl('/admin/backup/import'), { method:'POST', body: JSON.stringify({ backup, replace_existing: replace, confirm_replace: confirmed }) });
          document.getElementById('backup-import-result').textContent = 'Import completato: ' + JSON.stringify(result.counts);
        } catch (error) {
          formError('backup-import-error', error);
        }
      };
    }
    function renderSettings() {
      content.innerHTML = '<dl>' +
        '<dt>Environment</dt><dd>${escapeHtml(config.appEnv)}</dd>' +
        '<dt>Base URL</dt><dd>${escapeHtml(config.appBaseUrl)}</dd>' +
        '<dt>Issuer</dt><dd>${escapeHtml(config.authIssuer)}</dd>' +
        '<dt>Public base path</dt><dd>${escapeHtml(config.publicBasePath || "/")}</dd>' +
        '<dt>JWKS</dt><dd>' + esc(API_BASE_PATH + '/.well-known/jwks.json') + '</dd>' +
        '<dt>OAuth callback</dt><dd>${escapeHtml(config.googleRedirectUri)}</dd>' +
        '<dt>Hosted domains</dt><dd>${escapeHtml(config.googleAllowedHd.join(", "))}</dd>' +
        '<dt>OIDC scope</dt><dd>${escapeHtml(config.googleOidcScope)}</dd>' +
        '<dt>Access token TTL</dt><dd>${config.accessTokenTtlSeconds} seconds</dd>' +
        '<dt>Refresh tokens</dt><dd>${config.enableRefreshTokens ? "enabled" : "disabled"}</dd>' +
        '<dt>CORS allowed origins</dt><dd>${escapeHtml(config.corsAllowedOrigins.length ? config.corsAllowedOrigins.join(", ") : "disabled")}</dd>' +
        '<dt>Access request reopen delay</dt><dd>${config.accessRequestReopenAfterDays} days</dd>' +
        '<dt>Backup API token</dt><dd>${config.backupApiToken ? "enabled" : "disabled"}</dd>' +
        '</dl>';
    }
    loadBase().then(render);
  </script>
</body>
</html>`;
}
