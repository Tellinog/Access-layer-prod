import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("production continuity helper safety", () => {
  it("reports sensitive environment variables by presence without printing values", () => {
    const sentinel = "continuity-secret-sentinel-never-print";
    const names = [
      "APP_BASE_URL", "AUTH_ISSUER", "PUBLIC_BASE_PATH", "POSTGRES_USER",
      "POSTGRES_PASSWORD", "POSTGRES_DB", "DATABASE_URL", "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI", "JWT_PRIVATE_KEY_PEM_PATH",
      "JWT_PRIVATE_KEY_PEM", "JWT_PUBLIC_KEY_ID", "ACCESS_TOKEN_TTL_SECONDS",
      "REFRESH_TOKEN_TTL_SECONDS", "ONE_TIME_CODE_TTL_SECONDS", "ENABLE_REFRESH_TOKENS",
      "SESSION_COOKIE_NAME", "SESSION_SECRET", "TOOL_CLIENT_SECRET_PEPPER",
      "BACKUP_ENCRYPTION_KEY", "CORS_ALLOWED_ORIGINS", "LOG_IP_SALT",
      "SIEM_EXPORT_TOKEN", "BACKUP_API_TOKEN",
    ];
    const environment = {
      ...process.env,
      PORT: "8080",
      SOURCE_COMMIT: "a".repeat(40),
      ...Object.fromEntries(names.map((name) => [name, `${sentinel}-${name}`])),
      PUBLIC_BASE_PATH: "",
    };
    const output = execFileSync(
      process.execPath,
      ["scripts/continuity/collect-runtime-metadata.mjs"],
      { cwd: process.cwd(), env: environment, encoding: "utf8" },
    );
    const report = JSON.parse(output) as {
      status: string;
      required_environment_presence: Record<string, boolean>;
    };
    expect(report.status).toBe("OBSERVED");
    expect(Object.values(report.required_environment_presence).every(Boolean)).toBe(true);
    expect(output).not.toContain(sentinel);
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
