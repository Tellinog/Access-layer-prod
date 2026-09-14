import type { FastifyReply } from "fastify";

export type ErrorCode =
  | "AUTH_INVALID_TOOL"
  | "AUTH_TOOL_DISABLED"
  | "AUTH_INVALID_RETURN_URL"
  | "AUTH_INVALID_STATE"
  | "AUTH_GOOGLE_CALLBACK_FAILED"
  | "AUTH_INVALID_GOOGLE_TOKEN"
  | "AUTH_MICROSOFT_CALLBACK_FAILED"
  | "AUTH_INVALID_MICROSOFT_TOKEN"
  | "AUTH_INVALID_PROVIDER"
  | "AUTH_MICROSOFT_NOT_AVAILABLE"
  | "AUTH_EMAIL_NOT_VERIFIED"
  | "AUTH_EXTERNAL_DOMAIN"
  | "AUTH_USER_DISABLED"
  | "AUTH_NOT_AUTHORIZED_FOR_TOOL"
  | "AUTH_CODE_EXPIRED"
  | "AUTH_CODE_ALREADY_USED"
  | "AUTH_REFRESH_TOKEN_INVALID"
  | "TOOL_AUTH_FAILED"
  | "TOKEN_IN_QUERY_REJECTED"
  | "TOKEN_INACTIVE"
  | "ADMIN_FORBIDDEN"
  | "ACCESS_REQUEST_NOT_FOUND"
  | "ACCESS_REQUEST_NOT_PENDING"
  | "VALIDATION_ERROR"
  | "RATE_LIMITED"
  | "INTERNAL_ERROR";

export const httpStatusByCode: Record<ErrorCode, number> = {
  AUTH_INVALID_TOOL: 400,
  AUTH_TOOL_DISABLED: 403,
  AUTH_INVALID_RETURN_URL: 400,
  AUTH_INVALID_STATE: 400,
  AUTH_GOOGLE_CALLBACK_FAILED: 401,
  AUTH_INVALID_GOOGLE_TOKEN: 401,
  AUTH_MICROSOFT_CALLBACK_FAILED: 401,
  AUTH_INVALID_MICROSOFT_TOKEN: 401,
  AUTH_INVALID_PROVIDER: 400,
  AUTH_MICROSOFT_NOT_AVAILABLE: 403,
  AUTH_EMAIL_NOT_VERIFIED: 403,
  AUTH_EXTERNAL_DOMAIN: 403,
  AUTH_USER_DISABLED: 403,
  AUTH_NOT_AUTHORIZED_FOR_TOOL: 403,
  AUTH_CODE_EXPIRED: 400,
  AUTH_CODE_ALREADY_USED: 400,
  AUTH_REFRESH_TOKEN_INVALID: 401,
  TOOL_AUTH_FAILED: 401,
  TOKEN_IN_QUERY_REJECTED: 400,
  TOKEN_INACTIVE: 200,
  ADMIN_FORBIDDEN: 403,
  ACCESS_REQUEST_NOT_FOUND: 404,
  ACCESS_REQUEST_NOT_PENDING: 409,
  VALIDATION_ERROR: 400,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500
};

export const safeMessageByCode: Record<ErrorCode, string> = {
  AUTH_INVALID_TOOL: "Tool non riconosciuto. Contatta un amministratore.",
  AUTH_TOOL_DISABLED: "Il tool non e disponibile.",
  AUTH_INVALID_RETURN_URL: "Configurazione del tool non valida.",
  AUTH_INVALID_STATE: "Sessione di accesso non valida o scaduta. Riprova.",
  AUTH_GOOGLE_CALLBACK_FAILED: "Accesso Google non completato. Riprova.",
  AUTH_INVALID_GOOGLE_TOKEN: "Non e stato possibile verificare l'identita Google.",
  AUTH_MICROSOFT_CALLBACK_FAILED: "Accesso Microsoft non completato. Riprova.",
  AUTH_INVALID_MICROSOFT_TOKEN: "Non e stato possibile verificare l'identita Microsoft.",
  AUTH_INVALID_PROVIDER: "Provider di accesso non valido.",
  AUTH_MICROSOFT_NOT_AVAILABLE: "Accesso Microsoft non disponibile per questo tool.",
  AUTH_EMAIL_NOT_VERIFIED: "L'email Google non risulta verificata.",
  AUTH_EXTERNAL_DOMAIN: "Questo servizio e riservato agli account aziendali.",
  AUTH_USER_DISABLED: "Account non abilitato all'accesso.",
  AUTH_NOT_AUTHORIZED_FOR_TOOL:
    "Il tuo account aziendale e valido, ma non risulta autorizzato per questo tool. La richiesta e stata registrata per un amministratore.",
  AUTH_CODE_EXPIRED: "Sessione di accesso scaduta. Riprova.",
  AUTH_CODE_ALREADY_USED: "Sessione di accesso gia utilizzata. Riprova.",
  AUTH_REFRESH_TOKEN_INVALID: "Sessione non rinnovabile. Accedi di nuovo.",
  TOOL_AUTH_FAILED: "Configurazione del tool non valida.",
  TOKEN_IN_QUERY_REJECTED: "Token non ammesso nella query string.",
  TOKEN_INACTIVE: "Token non attivo.",
  ADMIN_FORBIDDEN: "Non hai permessi amministrativi sufficienti.",
  ACCESS_REQUEST_NOT_FOUND: "Richiesta di accesso non trovata.",
  ACCESS_REQUEST_NOT_PENDING: "Richiesta di accesso gia revisionata o non azionabile.",
  VALIDATION_ERROR: "Richiesta non valida.",
  RATE_LIMITED: "Troppe richieste. Riprova piu tardi.",
  INTERNAL_ERROR: "Errore interno. Comunica il codice di correlazione al supporto."
};

export class AppError extends Error {
  constructor(
    public readonly code: ErrorCode,
    public readonly correlationId: string,
    public readonly details: Record<string, unknown> = {}
  ) {
    super(code);
  }
}

export function sendJsonError(reply: FastifyReply, error: AppError): FastifyReply {
  return reply.status(httpStatusByCode[error.code]).send({
    error: {
      code: error.code,
      message: safeMessageByCode[error.code],
      correlation_id: error.correlationId,
      details: error.details
    }
  });
}

export function safeErrorPage(code: ErrorCode, correlationId: string): string {
  const message =
    code === "AUTH_NOT_AUTHORIZED_FOR_TOOL"
      ? `${safeMessageByCode[code]} Codice: ${correlationId}.`
      : `${safeMessageByCode[code]} Codice: ${correlationId}.`;
  return `<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Accesso non disponibile</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f7f9; color: #18202a; }
    main { width: min(560px, calc(100vw - 32px)); border: 1px solid #d9e1e8; background: #fff; border-radius: 8px; padding: 28px; box-shadow: 0 8px 28px rgba(23, 36, 50, .08); }
    h1 { font-size: 1.35rem; margin: 0 0 12px; }
    p { line-height: 1.5; margin: 0; }
    code { display: inline-block; margin-top: 16px; padding: 6px 8px; background: #eef3f7; border-radius: 4px; }
  </style>
</head>
<body>
  <main>
    <h1>Accesso non disponibile</h1>
    <p>${escapeHtml(message)}</p>
    <code>${escapeHtml(correlationId)}</code>
  </main>
</body>
</html>`;
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
