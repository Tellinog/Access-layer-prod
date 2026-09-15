import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const secretSentinel = "continuity-secret-sentinel-never-print";
const personalSentinel = "operator-personal-address-never-print@example.test";

function completeEnvironment(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ACCESS_REQUEST_REOPEN_AFTER_DAYS: "30",
    ACCESS_TOKEN_TTL_SECONDS: "900",
    ADMIN_BOOTSTRAP_EMAILS: personalSentinel,
    APP_BASE_URL: "https://access-layer.example.test",
    APP_ENV: "production",
    AUDIT_LOG_RAW_IP: "false",
    AUDIT_LOG_RETENTION_DAYS: "365",
    AUTH_ISSUER: "https://access-layer.example.test",
    BACKUP_API_TOKEN: "",
    BACKUP_ENCRYPTION_KEY: `${secretSentinel}-${"x".repeat(32)}`,
    CORS_ALLOWED_ORIGINS: "https://access-layer.example.test",
    DATABASE_URL: `postgresql://access-layer:${secretSentinel}@postgres:5432/access-layer`,
    ENABLE_REFRESH_TOKENS: "true",
    GOOGLE_ALLOWED_HD: "example.test",
    GOOGLE_CLIENT_ID: "public-client-id.apps.googleusercontent.com",
    GOOGLE_CLIENT_SECRET: secretSentinel,
    GOOGLE_OIDC_SCOPE: "openid email profile",
    GOOGLE_REDIRECT_URI: "https://access-layer.example.test/v1/auth/google/callback",
    LEGACY_MICROSOFT_ENABLED: "false",
    JWT_PRIVATE_KEY_PEM: secretSentinel,
    JWT_PRIVATE_KEY_PEM_PATH: "",
    JWT_PUBLIC_KEY_ID: "public-kid",
    LOG_IP_SALT: secretSentinel,
    LOG_LEVEL: "info",
    ONE_TIME_CODE_TTL_SECONDS: "60",
    OAUTH_P0_ENABLED: "false",
    OAUTH_CREDENTIAL_SECRET_PEPPER: "",
    OAUTH_SIGNING_KEY_ROOT: "",
    PORT: "8080",
    POSTGRES_DB: "access_layer",
    POSTGRES_PASSWORD: secretSentinel,
    POSTGRES_USER: "access_layer",
    PUBLIC_BASE_PATH: "",
    REFRESH_TOKEN_TTL_SECONDS: "28800",
    RETURN_URL_ALLOWED_SCHEMES: "https",
    RUN_MIGRATIONS_ON_START: "true",
    RUN_SEED_ON_START: "true",
    SEED_EXAMPLE_TOOLS: "false",
    SESSION_COOKIE_NAME: "access_layer_admin_session",
    SESSION_SECRET: secretSentinel,
    SIEM_EXPORT_ENABLED: "false",
    SIEM_EXPORT_ENDPOINT: "",
    SIEM_EXPORT_TOKEN: "",
    TOOL_CLIENT_SECRET_PEPPER: secretSentinel,
    TRUST_PROXY_HOPS: "1",
    SOURCE_COMMIT: "a".repeat(40),
  };
}

function collect(environment = completeEnvironment()): { output: string; report: Record<string, unknown> } {
  const output = execFileSync(process.execPath, ["scripts/continuity/collect-runtime-metadata.mjs"], {
    cwd: process.cwd(), env: environment, encoding: "utf8",
  });
  return { output, report: JSON.parse(output) as Record<string, unknown> };
}

function sourceEnvironmentNames(): string[] {
  const names = new Set<string>();
  const config = readFileSync("src/config.ts", "utf8");
  for (const match of config.matchAll(/(?:readRequired|readOptional|readInt|readBoolean|readCsv)\("([A-Z][A-Z0-9_]*)"/g)) {
    names.add(match[1]);
  }
  for (const path of ["docker-compose.yaml", "docker/entrypoint.sh"]) {
    const source = readFileSync(path, "utf8");
    for (const match of source.matchAll(/\$\{([A-Z][A-Z0-9_]*)/g)) names.add(match[1]);
  }
  return [...names].sort();
}

function sha256Lf(path: string): string {
  const text = readFileSync(path, "utf8").replaceAll("\r\n", "\n");
  return createHash("sha256").update(text).digest("hex");
}

describe("production continuity helper safety", () => {
  it("emits state enums and safe effective config without secret or personal values", () => {
    const { output, report } = collect();
    const states = report.environment_state as Record<string, string>;
    const effective = report.effective_non_secret_config as Record<string, unknown>;
    expect(report.status).toBe("OBSERVED");
    expect(states.SESSION_SECRET).toBe("PRESENT_NON_EMPTY");
    expect(states.PUBLIC_BASE_PATH).toBe("PRESENT_EMPTY");
    expect(effective.public_base_path).toBe("");
    expect(effective.admin_bootstrap_email_count).toBe(1);
    expect(output).not.toContain(secretSentinel);
    expect(output).not.toContain(personalSentinel);
  });

  it("distinguishes an empty required secret and fails closed", () => {
    const environment = completeEnvironment();
    environment.SESSION_SECRET = "";
    const completed = spawnSync(process.execPath, ["scripts/continuity/collect-runtime-metadata.mjs"], {
      cwd: process.cwd(), env: environment, encoding: "utf8",
    });
    expect(completed.status).toBe(2);
    const report = JSON.parse(completed.stdout) as {
      environment_state: Record<string, string>;
      missing: string[];
    };
    expect(report.environment_state.SESSION_SECRET).toBe("PRESENT_EMPTY");
    expect(report.missing).toContain("environment_state.SESSION_SECRET=PRESENT_NON_EMPTY");
    expect(completed.stdout).not.toContain(secretSentinel);
  });

  it("tracks enabled Microsoft configuration without emitting its client secret", () => {
    const environment = completeEnvironment();
    environment.LEGACY_MICROSOFT_ENABLED = "true";
    environment.MICROSOFT_TENANT_ID = "11111111-1111-4111-8111-111111111111";
    environment.MICROSOFT_CLIENT_ID = "22222222-2222-4222-8222-222222222222";
    environment.MICROSOFT_CLIENT_SECRET = secretSentinel;
    environment.MICROSOFT_REDIRECT_URI = "https://access-layer.example.test/v1/auth/microsoft/callback";
    environment.MICROSOFT_OIDC_SCOPE = "openid profile email";
    environment.MICROSOFT_ALLOWED_EMAIL_DOMAINS = "testbirds.com";
    environment.LEGACY_MICROSOFT_TOOL_SLUGS = "test-generator";
    const { output, report } = collect(environment);
    const effective = report.effective_non_secret_config as Record<string, unknown>;
    expect(report.status).toBe("OBSERVED");
    expect(effective.legacy_microsoft_enabled).toBe(true);
    expect(effective.legacy_microsoft_tool_slugs).toEqual(["test-generator"]);
    expect(output).not.toContain(secretSentinel);
  });

  it("fails closed without emitting credentials embedded in nominally safe URLs", () => {
    const environment = completeEnvironment();
    environment.APP_BASE_URL = "https://operator:do-not-print@example.test";

    const completed = spawnSync(process.execPath, ["scripts/continuity/collect-runtime-metadata.mjs"], {
      cwd: process.cwd(), env: environment, encoding: "utf8",
    });
    const report = JSON.parse(completed.stdout) as Record<string, unknown>;
    const serialized = JSON.stringify(report);

    expect(completed.status).toBe(2);
    expect(report.status).toBe("NOT_READY");
    expect((report.effective_non_secret_config as Record<string, unknown>).app_base_url).toBeNull();
    expect(serialized).not.toContain("operator");
    expect(serialized).not.toContain("do-not-print");
  });

  it("tracks the complete environment surface derived from config, Compose, and entrypoint", () => {
    const { report } = collect();
    const inventory = report.source_inventory as { variables: string[] };
    expect([...inventory.variables].sort()).toEqual(sourceEnvironmentNames());
    expect(inventory.variables).toHaveLength(53);
  });

  it("pins the D-046 grant-domain configuration and the approved Compose continuity correction", () => {
    expect(sha256Lf("src/config.ts")).toBe("3b1652adef4eb1482722af9abf181647226e27ce05241dd093c760ba0dc6c75f");
    expect(sha256Lf("docker-compose.yaml")).toBe("7315710b8581c7e8dc3d6423df5ac11f8767fb29a8e12bdd571174f41a4a6359");
    expect(sha256Lf("docker/entrypoint.sh")).toBe("07d57fbdbb6bc09268b154c7d97afbfc5f8d5699b0378c747057393769ec6d76");
  });

  it("fingerprints a public JWK and rejects a private member", () => {
    const moduleUrl = new URL("../scripts/continuity/fingerprint-public-jwks.mjs", import.meta.url).href;
    const program = `
      import { fingerprintPublicJwk } from ${JSON.stringify(moduleUrl)};
      const key = { kty: "RSA", kid: "kid-1", e: "AQAB", n: "public-modulus" };
      const publicResult = fingerprintPublicJwk(key);
      let rejected = false;
      try { fingerprintPublicJwk({ ...key, d: "private" }); } catch { rejected = true; }
      process.stdout.write(JSON.stringify({ publicResult, rejected }));
    `;
    const output = execFileSync(process.execPath, ["--input-type=module", "--eval", program], { encoding: "utf8" });
    const report = JSON.parse(output) as { publicResult: { kid: string; fingerprint_sha256: string }; rejected: boolean };
    expect(report.publicResult.kid).toBe("kid-1");
    expect(report.publicResult.fingerprint_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(report.rejected).toBe(true);
  });

  it("keeps PostgreSQL failures from echoing driver messages or connection details", () => {
    const source = readFileSync("scripts/continuity/collect-postgres-metadata.mjs", "utf8");
    expect(source).not.toContain("error.message");
    expect(source).not.toContain("console.log(process.env");
    expect(source).toContain("BEGIN READ ONLY");
    expect(source).toContain("row_contents_collected: false");
  });
});
