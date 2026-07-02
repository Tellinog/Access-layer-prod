import { describe, expect, it } from "vitest";
import { sanitizeMetadata } from "../src/audit.js";

describe("audit sanitization", () => {
  it("removes forbidden fields recursively", () => {
    const sanitized = sanitizeMetadata({
      access_token: "eyJabc.def.ghi",
      nested: {
        client_secret: "secret",
        safe: "value"
      },
      tool_slug: "crm"
    });
    expect(sanitized).toEqual({
      nested: { safe: "value" },
      tool_slug: "crm"
    });
  });

  it("redacts token-looking values even under allowed keys", () => {
    const sanitized = sanitizeMetadata({
      note: "eyJabc.def.ghi"
    });
    expect(sanitized.note).toBe("[redacted]");
  });
});
