import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";

const baseEnv: Record<string, string> = {
  APP_ENV: "test",
  APP_BASE_URL: "http://localhost:8080",
  AUTH_ISSUER: "http://localhost:8080",
  DATABASE_URL: "postgresql://test",
  GOOGLE_CLIENT_ID: "test-client.apps.googleusercontent.com",
  GOOGLE_CLIENT_SECRET: "test-client-secret",
  GOOGLE_REDIRECT_URI: "http://localhost:8080/v1/auth/google/callback",
  GOOGLE_ALLOWED_HD: "unguess.io",
  JWT_PRIVATE_KEY_PEM_PATH: "",
  JWT_PRIVATE_KEY_PEM: "",
  JWT_PUBLIC_KEY_ID: "test-key",
  SESSION_SECRET: "session-secret-value",
  TOOL_CLIENT_SECRET_PEPPER: "tool-secret-pepper-value",
  LOG_IP_SALT: "log-ip-salt-value"
};

beforeEach(() => {
  vi.unstubAllEnvs();
  for (const [key, value] of Object.entries(baseEnv)) {
    vi.stubEnv(key, value);
  }
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("loadConfig", () => {
  it("loads comma-separated Workspace hosted domains in normalized form", () => {
    vi.stubEnv("GOOGLE_ALLOWED_HD", "UNGUESS.IO,nuotounostiledivita.it");

    expect(loadConfig().googleAllowedHd).toEqual(["unguess.io", "nuotounostiledivita.it"]);
  });

  it("loads multiple bootstrap admin emails in normalized form", () => {
    vi.stubEnv("ADMIN_BOOTSTRAP_EMAILS", " Lorenzo.Prandi@UNGUESS.IO,lorenzo@nuotounostiledivita.it ");

    expect(loadConfig().adminBootstrapEmails).toEqual(["lorenzo.prandi@unguess.io", "lorenzo@nuotounostiledivita.it"]);
  });

  it.each(["localhost", "http://localhost:8080", "https://draftapps.it", "127.0.0.1", "::1"])(
    "rejects %s as a Google hosted domain",
    (value) => {
      vi.stubEnv("GOOGLE_ALLOWED_HD", value);

      expect(() => loadConfig()).toThrow("GOOGLE_ALLOWED_HD may only include Workspace hosted domains");
    }
  );

  it("fails closed when a required secret is missing", () => {
    vi.stubEnv("GOOGLE_CLIENT_SECRET", "");

    expect(() => loadConfig()).toThrow("Missing required environment variable GOOGLE_CLIENT_SECRET");
  });

  it("accepts the production root-domain deployment without a public base path", () => {
    vi.stubEnv("APP_ENV", "production");
    vi.stubEnv("PUBLIC_BASE_PATH", "");
    vi.stubEnv("APP_BASE_URL", "https://access-layer.unguess-internal.net");
    vi.stubEnv("AUTH_ISSUER", "https://access-layer.unguess-internal.net");
    vi.stubEnv("GOOGLE_REDIRECT_URI", "https://access-layer.unguess-internal.net/v1/auth/google/callback");
    vi.stubEnv("JWT_PRIVATE_KEY_PEM", "placeholder-production-private-key");
    vi.stubEnv("BACKUP_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef");

    const config = loadConfig();

    expect(config.publicBasePath).toBe("");
    expect(config.appBaseUrl).toBe("https://access-layer.unguess-internal.net");
    expect(config.googleRedirectUri).toBe("https://access-layer.unguess-internal.net/v1/auth/google/callback");
  });
});
