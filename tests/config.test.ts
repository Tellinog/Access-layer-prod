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
  LEGACY_MICROSOFT_ENABLED: "false",
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
  it("defaults the legacy Microsoft bridge off and requires no Microsoft configuration", () => {
    vi.stubEnv("LEGACY_MICROSOFT_ENABLED", undefined);
    for (const name of ["MICROSOFT_TENANT_ID", "MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "MICROSOFT_REDIRECT_URI", "MICROSOFT_ALLOWED_EMAIL_DOMAINS", "LEGACY_MICROSOFT_TOOL_SLUGS"]) {
      vi.stubEnv(name, undefined);
    }
    expect(loadConfig()).toMatchObject({
      legacyMicrosoftEnabled: false,
      microsoftTenantId: undefined,
      microsoftAllowedEmailDomains: [],
      legacyMicrosoftToolSlugs: []
    });
  });

  it("loads the complete temporary Microsoft bridge configuration only when enabled", () => {
    vi.stubEnv("LEGACY_MICROSOFT_ENABLED", "true");
    vi.stubEnv("MICROSOFT_TENANT_ID", "11111111-1111-4111-8111-111111111111");
    vi.stubEnv("MICROSOFT_CLIENT_ID", "33333333-3333-4333-8333-333333333333");
    vi.stubEnv("MICROSOFT_CLIENT_SECRET", "synthetic-secret");
    vi.stubEnv("MICROSOFT_REDIRECT_URI", "http://localhost:8080/v1/auth/microsoft/callback");
    vi.stubEnv("MICROSOFT_ALLOWED_EMAIL_DOMAINS", "Testbirds.com");
    vi.stubEnv("LEGACY_MICROSOFT_TOOL_SLUGS", "test-generator,sales-deck-agent");

    expect(loadConfig()).toMatchObject({
      legacyMicrosoftEnabled: true,
      microsoftTenantId: "11111111-1111-4111-8111-111111111111",
      microsoftClientId: "33333333-3333-4333-8333-333333333333",
      microsoftOidcScope: "openid profile email",
      microsoftAllowedEmailDomains: ["testbirds.com"],
      legacyMicrosoftToolSlugs: ["test-generator", "sales-deck-agent"]
    });
  });

  it.each([
    "MICROSOFT_TENANT_ID",
    "MICROSOFT_CLIENT_ID",
    "MICROSOFT_CLIENT_SECRET",
    "MICROSOFT_REDIRECT_URI",
    "MICROSOFT_ALLOWED_EMAIL_DOMAINS",
    "LEGACY_MICROSOFT_TOOL_SLUGS"
  ])("requires %s when the legacy Microsoft bridge is enabled", (name) => {
    vi.stubEnv("LEGACY_MICROSOFT_ENABLED", "true");
    vi.stubEnv("MICROSOFT_TENANT_ID", "11111111-1111-4111-8111-111111111111");
    vi.stubEnv("MICROSOFT_CLIENT_ID", "33333333-3333-4333-8333-333333333333");
    vi.stubEnv("MICROSOFT_CLIENT_SECRET", "synthetic-secret");
    vi.stubEnv("MICROSOFT_REDIRECT_URI", "http://localhost:8080/v1/auth/microsoft/callback");
    vi.stubEnv("MICROSOFT_ALLOWED_EMAIL_DOMAINS", "testbirds.com");
    vi.stubEnv("LEGACY_MICROSOFT_TOOL_SLUGS", "test-generator");
    vi.stubEnv(name, undefined);
    expect(() => loadConfig()).toThrow(name);
  });

  it("rejects unsafe Microsoft domains, slugs, scopes and callback topology", () => {
    vi.stubEnv("LEGACY_MICROSOFT_ENABLED", "true");
    vi.stubEnv("MICROSOFT_TENANT_ID", "11111111-1111-4111-8111-111111111111");
    vi.stubEnv("MICROSOFT_CLIENT_ID", "33333333-3333-4333-8333-333333333333");
    vi.stubEnv("MICROSOFT_CLIENT_SECRET", "synthetic-secret");
    vi.stubEnv("MICROSOFT_REDIRECT_URI", "http://localhost:8080/v1/auth/microsoft/callback");
    vi.stubEnv("MICROSOFT_ALLOWED_EMAIL_DOMAINS", "localhost");
    vi.stubEnv("LEGACY_MICROSOFT_TOOL_SLUGS", "test-generator");
    expect(() => loadConfig()).toThrow("MICROSOFT_ALLOWED_EMAIL_DOMAINS");

    vi.stubEnv("MICROSOFT_ALLOWED_EMAIL_DOMAINS", "testbirds.com");
    vi.stubEnv("LEGACY_MICROSOFT_TOOL_SLUGS", "access-admin");
    expect(() => loadConfig()).toThrow("must not include access-admin");

    vi.stubEnv("LEGACY_MICROSOFT_TOOL_SLUGS", "INVALID_SLUG");
    expect(() => loadConfig()).toThrow("valid Access Layer tool slugs");

    vi.stubEnv("LEGACY_MICROSOFT_TOOL_SLUGS", "test-generator");
    vi.stubEnv("MICROSOFT_OIDC_SCOPE", "openid email");
    expect(() => loadConfig()).toThrow("MICROSOFT_OIDC_SCOPE must include profile");

    vi.stubEnv("MICROSOFT_OIDC_SCOPE", "openid profile email");
    vi.stubEnv("MICROSOFT_REDIRECT_URI", "http://other.example/v1/auth/microsoft/callback");
    expect(() => loadConfig()).toThrow("public Microsoft callback exactly");
  });

  it("defaults the dark OAuth P0 foundation flag to false when the old environment omits it", () => {
    vi.stubEnv("OAUTH_P0_ENABLED", undefined);

    expect(loadConfig().oauthP0Enabled).toBe(false);
  });

  it("parses the OAuth P0 flag with the dedicated transaction protection key", () => {
    vi.stubEnv("OAUTH_P0_ENABLED", "true");
    vi.stubEnv("OAUTH_TRANSACTION_PROTECTION_KEY", Buffer.alloc(32, 7).toString("base64url"));
    vi.stubEnv("OAUTH_CREDENTIAL_SECRET_PEPPER", "oauth-only-secret-pepper");
    vi.stubEnv("OAUTH_SIGNING_KEY_ROOT", "C:\\oauth-keys");

    expect(loadConfig().oauthP0Enabled).toBe(true);
    expect(loadConfig().oauthTransactionProtectionKey).toEqual(Buffer.alloc(32, 7));
  });

  it("requires a dedicated canonical 32-byte transaction protection key only when OAuth is enabled", () => {
    vi.stubEnv("OAUTH_P0_ENABLED", "true");
    vi.stubEnv("OAUTH_TRANSACTION_PROTECTION_KEY", undefined);
    expect(() => loadConfig()).toThrow("OAUTH_TRANSACTION_PROTECTION_KEY");

    vi.stubEnv("OAUTH_TRANSACTION_PROTECTION_KEY", `${Buffer.alloc(32, 7).toString("base64url")}=`);
    expect(() => loadConfig()).toThrow("canonical unpadded base64url");

    vi.stubEnv("OAUTH_P0_ENABLED", "false");
    vi.stubEnv("OAUTH_TRANSACTION_PROTECTION_KEY", undefined);
    expect(loadConfig().oauthTransactionProtectionKey).toBeUndefined();
  });

  it("keeps lifecycle secrets optional while OAuth is false and requires them when the HTTP surface is enabled", () => {
    vi.stubEnv("OAUTH_CREDENTIAL_SECRET_PEPPER", undefined);
    vi.stubEnv("OAUTH_SIGNING_KEY_ROOT", undefined);
    expect(loadConfig()).toMatchObject({
      oauthCredentialSecretPepper: undefined,
      oauthSigningKeyRoot: undefined
    });

    vi.stubEnv("OAUTH_CREDENTIAL_SECRET_PEPPER", "oauth-only-secret-pepper");
    vi.stubEnv("OAUTH_SIGNING_KEY_ROOT", "C:\\oauth-keys");
    expect(loadConfig()).toMatchObject({
      oauthCredentialSecretPepper: "oauth-only-secret-pepper",
      oauthSigningKeyRoot: "C:\\oauth-keys"
    });

    vi.stubEnv("OAUTH_CREDENTIAL_SECRET_PEPPER", "too-short");
    expect(() => loadConfig()).toThrow("OAUTH_CREDENTIAL_SECRET_PEPPER");

    vi.stubEnv("OAUTH_P0_ENABLED", "true");
    vi.stubEnv("OAUTH_TRANSACTION_PROTECTION_KEY", Buffer.alloc(32, 7).toString("base64url"));
    vi.stubEnv("OAUTH_CREDENTIAL_SECRET_PEPPER", undefined);
    vi.stubEnv("OAUTH_SIGNING_KEY_ROOT", "C:\\oauth-keys");
    expect(() => loadConfig()).toThrow("OAUTH_CREDENTIAL_SECRET_PEPPER");

    vi.stubEnv("OAUTH_CREDENTIAL_SECRET_PEPPER", "oauth-only-secret-pepper");
    vi.stubEnv("OAUTH_SIGNING_KEY_ROOT", undefined);
    expect(() => loadConfig()).toThrow("OAUTH_SIGNING_KEY_ROOT");
  });

  it("rejects reuse of the legacy tool-client pepper without disclosing either value", () => {
    vi.stubEnv("OAUTH_CREDENTIAL_SECRET_PEPPER", baseEnv.TOOL_CLIENT_SECRET_PEPPER);
    expect(() => loadConfig()).toThrow("OAuth credential secret isolation is invalid");
    try {
      loadConfig();
    } catch (error) {
      expect(String(error)).not.toContain(baseEnv.TOOL_CLIENT_SECRET_PEPPER);
    }
  });

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
    expect(config.oauthP0Enabled).toBe(false);
  });
});
