import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";

const accessLayerBaseUrl = requiredEnv("ACCESS_LAYER_BASE_URL", "http://localhost:8080");
const toolSlug = requiredEnv("ACCESS_LAYER_TOOL_SLUG", "crm");
const clientId = requiredEnv("ACCESS_LAYER_CLIENT_ID");
const clientSecret = requiredEnv("ACCESS_LAYER_CLIENT_SECRET");
const callbackUrl = requiredEnv("ACCESS_LAYER_CALLBACK_URL", "http://localhost:3000/auth/callback");
const port = Number(process.env.PORT ?? "3000");

const pendingStates = new Map();
const localSessions = new Map();

function requiredEnv(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(`Missing ${name}`);
  }
  return value;
}

function randomToken(prefix) {
  return `${prefix}${randomBytes(24).toString("base64url")}`;
}

function hash(value) {
  return createHash("sha256").update(value).digest("base64url");
}

function parseCookies(header) {
  return Object.fromEntries(
    String(header ?? "")
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        return index === -1
          ? [decodeURIComponent(part), ""]
          : [decodeURIComponent(part.slice(0, index)), decodeURIComponent(part.slice(index + 1))];
      })
  );
}

function html(res, status, body) {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "x-content-type-options": "nosniff"
  });
  res.end(`<!doctype html><html lang="it"><head><meta charset="utf-8"><title>Tool Harness</title></head><body>${body}</body></html>`);
}

function redirect(res, location, cookies = []) {
  const headers = { location };
  if (cookies.length) {
    headers["set-cookie"] = cookies;
  }
  res.writeHead(302, headers);
  res.end();
}

async function exchangeCode(code) {
  const response = await fetch(new URL("/v1/auth/exchange", accessLayerBaseUrl), {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      code,
      redirect_uri: callbackUrl
    })
  });
  if (!response.ok) {
    throw new Error(`Access Layer exchange failed with HTTP ${response.status}`);
  }
  return response.json();
}

async function logoutAccessLayer(sessionId) {
  await fetch(new URL("/v1/auth/logout", accessLayerBaseUrl), {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({ session_id: sessionId })
  });
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const cookies = parseCookies(req.headers.cookie);
    const localSession = cookies.tool_session ? localSessions.get(cookies.tool_session) : null;

    if (url.pathname === "/login") {
      const state = randomToken("state_");
      pendingStates.set(hash(state), { state, expiresAt: Date.now() + 5 * 60 * 1000 });
      const startUrl = new URL("/v1/auth/start", accessLayerBaseUrl);
      startUrl.searchParams.set("tool_slug", toolSlug);
      startUrl.searchParams.set("return_url", callbackUrl);
      startUrl.searchParams.set("state", state);
      return redirect(res, startUrl.toString());
    }

    if (url.pathname === "/auth/callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const pending = state ? pendingStates.get(hash(state)) : null;
      if (!code || !state || !pending || pending.expiresAt <= Date.now()) {
        return html(res, 400, "<h1>Sessione non valida</h1><p>Riprovare il login.</p>");
      }
      pendingStates.delete(hash(state));
      const exchanged = await exchangeCode(code);
      const sessionId = randomToken("sess_");
      localSessions.set(sessionId, {
        accessLayerSessionId: exchanged.session.id,
        googleSub: exchanged.user.google_sub,
        email: exchanged.user.email,
        permissions: exchanged.grant.permissions,
        correlationId: exchanged.correlation_id
      });
      return redirect(res, "/", [`tool_session=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; SameSite=Lax`]);
    }

    if (url.pathname === "/logout") {
      if (localSession) {
        await logoutAccessLayer(localSession.accessLayerSessionId);
        localSessions.delete(cookies.tool_session);
      }
      return redirect(res, "/", ["tool_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"]);
    }

    if (!localSession) {
      return html(res, 200, '<h1>Tool Harness</h1><p><a href="/login">Accedi con Google aziendale</a></p>');
    }

    return html(
      res,
      200,
      `<h1>Tool Harness</h1>
       <dl>
         <dt>Email</dt><dd>${escapeHtml(localSession.email)}</dd>
         <dt>Google sub</dt><dd>${escapeHtml(localSession.googleSub)}</dd>
         <dt>Permessi</dt><dd>${escapeHtml(localSession.permissions.join(", "))}</dd>
         <dt>Correlazione</dt><dd>${escapeHtml(localSession.correlationId)}</dd>
       </dl>
       <p><a href="/logout">Logout</a></p>`
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Tool harness error");
    html(res, 500, "<h1>Errore</h1><p>Errore del tool harness.</p>");
  }
});

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

server.listen(port, () => {
  console.log(`Tool harness listening on http://localhost:${port}`);
});
