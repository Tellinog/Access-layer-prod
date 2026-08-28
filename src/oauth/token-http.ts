import { Buffer } from "node:buffer";
import { TextDecoder } from "node:util";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { hashOpaque } from "../security.js";
import type { Config } from "../types.js";
import {
  OAuthCoreError,
  type OAuthIntrospectionResult,
  type OAuthTokenLifecycleService,
  type OAuthTokenResponseMaterial
} from "./token-service.js";
import { buildOAuthAuthorizationServerMetadata } from "./metadata.js";
import { OAUTH_CLIENT_ID_REGEX } from "./validation.js";

export const OAUTH_FORM_BODY_LIMIT_BYTES = 16 * 1024;
export const OAUTH_DISCOVERY_CACHE_CONTROL = "public, max-age=300";
export const OAUTH_BASIC_CHALLENGE = 'Basic realm="oauth"';

type OAuthHttpErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "invalid_target"
  | "temporarily_unavailable";

type OAuthForm = Record<string, string>;
export type OAuthTokenHttpService = Pick<OAuthTokenLifecycleService,
  "exchangeAuthorizationCode" | "refresh" | "revoke" | "introspect">;

class OAuthHttpError extends Error {
  constructor(readonly code: OAuthHttpErrorCode) {
    super(code);
    this.name = "OAuthHttpError";
  }
}

function fail(code: OAuthHttpErrorCode): never {
  throw new OAuthHttpError(code);
}

function decodeFormComponent(value: string): string {
  if (/%(?![0-9a-f]{2})/i.test(value)) fail("invalid_request");
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    fail("invalid_request");
  }
}

export function parseOAuthForm(body: Buffer): OAuthForm {
  if (body.byteLength > OAUTH_FORM_BODY_LIMIT_BYTES) fail("invalid_request");
  let encoded: string;
  try {
    encoded = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    fail("invalid_request");
  }
  const parsed: OAuthForm = Object.create(null) as OAuthForm;
  if (encoded === "") return parsed;
  for (const pair of encoded.split("&")) {
    if (pair === "") fail("invalid_request");
    const separator = pair.indexOf("=");
    const rawName = separator === -1 ? pair : pair.slice(0, separator);
    const rawValue = separator === -1 ? "" : pair.slice(separator + 1);
    const name = decodeFormComponent(rawName);
    const value = decodeFormComponent(rawValue);
    if (name === "" || name.length > 128 || value.length > OAUTH_FORM_BODY_LIMIT_BYTES) fail("invalid_request");
    if (Object.hasOwn(parsed, name)) fail("invalid_request");
    parsed[name] = value;
  }
  return parsed;
}

export interface OAuthBasicCredentials {
  username: string;
  password: string;
}

export function parseOAuthBasicAuthorization(value: string | undefined): OAuthBasicCredentials | null {
  if (value === undefined) return null;
  const match = /^Basic ([A-Za-z0-9+/]*={0,2})$/i.exec(value);
  if (!match || match[1].length === 0 || match[1].length % 4 !== 0) fail("invalid_client");
  const decodedBytes = Buffer.from(match[1], "base64");
  if (decodedBytes.toString("base64") !== match[1]) fail("invalid_client");
  let decoded: string;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(decodedBytes);
  } catch {
    fail("invalid_client");
  }
  const separator = decoded.indexOf(":");
  if (separator < 1 || separator !== decoded.lastIndexOf(":")) fail("invalid_client");
  try {
    const username = decodeFormComponent(decoded.slice(0, separator));
    const password = decodeFormComponent(decoded.slice(separator + 1));
    if (username === "" || password === "") fail("invalid_client");
    return { username, password };
  } catch (error) {
    if (error instanceof OAuthHttpError) fail("invalid_client");
    throw error;
  }
}

function requireExactFields(form: OAuthForm, allowed: readonly string[], required: readonly string[]): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(form).some((name) => !allowedSet.has(name))) fail("invalid_request");
  if (required.some((name) => !Object.hasOwn(form, name) || form[name] === "")) fail("invalid_request");
}

function formFor(request: FastifyRequest): OAuthForm {
  if (!request.body || typeof request.body !== "object" || Array.isArray(request.body) || Buffer.isBuffer(request.body)) {
    fail("invalid_request");
  }
  return request.body as OAuthForm;
}

function authorizationFor(request: FastifyRequest): OAuthBasicCredentials | null {
  const header = request.headers.authorization;
  return parseOAuthBasicAuthorization(typeof header === "string" ? header : undefined);
}

function safeIdentifier(value: string | undefined): string {
  return value !== undefined && OAUTH_CLIENT_ID_REGEX.test(value) ? value : "unknown-id";
}

function rateMaterial(value: string | undefined, salt: string, missing: string): string {
  return value ? hashOpaque(value, salt) : missing;
}

function rateBasicUsername(request: FastifyRequest): string | undefined {
  try {
    return authorizationFor(request)?.username;
  } catch {
    return undefined;
  }
}

function statusFor(error: OAuthHttpErrorCode): number {
  if (error === "invalid_client") return 401;
  if (error === "temporarily_unavailable") return 503;
  return 400;
}

function sendOAuthError(reply: FastifyReply, error: OAuthHttpErrorCode) {
  reply.header("Cache-Control", "no-store");
  if (error === "invalid_client") reply.header("WWW-Authenticate", OAUTH_BASIC_CHALLENGE);
  return reply.status(statusFor(error)).send({ error });
}

function normalizedError(error: unknown): OAuthHttpErrorCode {
  if (error instanceof OAuthHttpError || error instanceof OAuthCoreError) return error.code;
  const statusCode = (error as { statusCode?: unknown } | null)?.statusCode;
  if (statusCode === 429) return "temporarily_unavailable";
  if (typeof statusCode === "number" && statusCode >= 400 && statusCode < 500) return "invalid_request";
  return "temporarily_unavailable";
}

function tokenWire(material: OAuthTokenResponseMaterial) {
  return {
    access_token: material.accessToken,
    token_type: material.tokenType,
    expires_in: material.expiresIn,
    refresh_token: material.refreshToken,
    scope: material.scope
  };
}

async function requireAllowed(
  check: ReturnType<FastifyInstance["createRateLimit"]>,
  request: FastifyRequest
): Promise<void> {
  const result = await check(request);
  if (!result.isAllowed && (result.isExceeded || result.isBanned)) fail("temporarily_unavailable");
}

export function registerOAuthTokenLifecycleHttp(
  app: FastifyInstance,
  input: { config: Config; service: OAuthTokenHttpService }
): void {
  if (!input.config.oauthP0Enabled) return;

  app.register(async (oauthApp) => {
    oauthApp.addContentTypeParser(
      "application/x-www-form-urlencoded",
      { parseAs: "buffer", bodyLimit: OAUTH_FORM_BODY_LIMIT_BYTES },
      (_request, body, done) => {
        try {
          done(null, parseOAuthForm(body as Buffer));
        } catch (error) {
          done(error as Error);
        }
      }
    );

    oauthApp.setErrorHandler((error, _request, reply) =>
      sendOAuthError(reply, normalizedError(error))
    );

    const codeExchangeRateLimit = oauthApp.createRateLimit({
      max: 20,
      timeWindow: "1 minute",
      keyGenerator: (request) => {
        const body = (request.body ?? {}) as OAuthForm;
        return `oauth-code-exchange:${safeIdentifier(body.client_id ?? rateBasicUsername(request))}:${rateMaterial(body.code, input.config.logIpSalt, "missing-code")}`;
      }
    });
    const refreshRateLimit = oauthApp.createRateLimit({
      max: 60,
      timeWindow: "1 minute",
      keyGenerator: (request) => {
        const body = (request.body ?? {}) as OAuthForm;
        return `oauth-refresh:${safeIdentifier(body.client_id ?? rateBasicUsername(request))}:${rateMaterial(body.refresh_token, input.config.logIpSalt, "missing-refresh")}`;
      }
    });
    const revocationRateLimit = oauthApp.createRateLimit({
      max: 60,
      timeWindow: "1 minute",
      keyGenerator: (request) => {
        const body = (request.body ?? {}) as OAuthForm;
        return `oauth-revoke:${safeIdentifier(rateBasicUsername(request) ?? body.client_id)}:${rateMaterial(body.token, input.config.logIpSalt, "missing-token")}`;
      }
    });
    const introspectionRateLimit = oauthApp.createRateLimit({
      max: 120,
      timeWindow: "1 minute",
      keyGenerator: (request) => {
        const body = (request.body ?? {}) as OAuthForm;
        return `oauth-introspect:${safeIdentifier(rateBasicUsername(request))}:${rateMaterial(body.token, input.config.logIpSalt, "missing-token")}`;
      }
    });

    oauthApp.post("/oauth/token", { logLevel: "silent" }, async (request, reply) => {
      try {
        const form = formFor(request);
        if (!Object.hasOwn(form, "grant_type") || form.grant_type === "") fail("invalid_request");
        const basic = authorizationFor(request);
        let material: OAuthTokenResponseMaterial;
        if (form.grant_type === "authorization_code") {
          requireExactFields(
            form,
            ["grant_type", "code", "redirect_uri", "client_id", "code_verifier", "resource"],
            ["code", "redirect_uri", "client_id", "code_verifier", "resource"]
          );
          await requireAllowed(codeExchangeRateLimit, request);
          if (basic && basic.username !== form.client_id) fail("invalid_client");
          material = await input.service.exchangeAuthorizationCode({
            code: form.code,
            clientId: form.client_id,
            clientSecret: basic?.password ?? null,
            redirectUri: form.redirect_uri,
            resource: form.resource,
            codeVerifier: form.code_verifier
          });
        } else if (form.grant_type === "refresh_token") {
          requireExactFields(
            form,
            ["grant_type", "refresh_token", "client_id", "resource", "scope"],
            ["refresh_token", "client_id", "resource"]
          );
          await requireAllowed(refreshRateLimit, request);
          if (basic && basic.username !== form.client_id) fail("invalid_client");
          material = await input.service.refresh({
            refreshToken: form.refresh_token,
            clientId: form.client_id,
            clientSecret: basic?.password ?? null,
            resource: form.resource,
            ...(Object.hasOwn(form, "scope") ? { scope: form.scope } : {})
          });
        } else {
          fail("unsupported_grant_type");
        }
        return reply
          .header("Cache-Control", "no-store")
          .header("Pragma", "no-cache")
          .send(tokenWire(material));
      } catch (error) {
        return sendOAuthError(reply, normalizedError(error));
      }
    });

    oauthApp.post("/oauth/revoke", { logLevel: "silent" }, async (request, reply) => {
      try {
        const form = formFor(request);
        requireExactFields(form, ["token", "token_type_hint", "client_id"], ["token"]);
        await requireAllowed(revocationRateLimit, request);
        const basic = authorizationFor(request);
        const clientId = basic?.username ?? form.client_id;
        if (!clientId) fail("invalid_client");
        if (basic && Object.hasOwn(form, "client_id") && form.client_id !== basic.username) fail("invalid_client");
        await input.service.revoke({
          token: form.token,
          clientId,
          clientSecret: basic?.password ?? null,
          ...(Object.hasOwn(form, "token_type_hint") ? { tokenTypeHint: form.token_type_hint } : {})
        });
        return reply.header("Cache-Control", "no-store").status(200).send();
      } catch (error) {
        return sendOAuthError(reply, normalizedError(error));
      }
    });

    oauthApp.post("/oauth/introspect", { logLevel: "silent" }, async (request, reply) => {
      try {
        const form = formFor(request);
        requireExactFields(form, ["token", "token_type_hint"], ["token"]);
        await requireAllowed(introspectionRateLimit, request);
        const basic = authorizationFor(request);
        if (!basic) fail("invalid_client");
        const result: OAuthIntrospectionResult = await input.service.introspect({
          token: form.token,
          credentialId: basic.username,
          credentialSecret: basic.password,
          ...(Object.hasOwn(form, "token_type_hint") ? { tokenTypeHint: form.token_type_hint } : {})
        });
        return reply.header("Cache-Control", "no-store").send(result);
      } catch (error) {
        return sendOAuthError(reply, normalizedError(error));
      }
    });
  });

  app.get("/.well-known/oauth-authorization-server", { exposeHeadRoute: false }, async (_request, reply) =>
    reply
      .header("Cache-Control", OAUTH_DISCOVERY_CACHE_CONTROL)
      .send(buildOAuthAuthorizationServerMetadata(input.config.authIssuer))
  );
}
