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
      jwt_note: "eyJabc.def.ghi",
      generated_client_value: "ocs_abcdefghijklmnopqrstuvwxyz012345",
      generated_resource_value: "ors_abcdefghijklmnopqrstuvwxyz012345",
      public_resource_credential_id: "orc_0123456789abcdef"
    });
    expect(sanitized).toEqual({
      jwt_note: "[redacted]",
      generated_client_value: "[redacted]",
      generated_resource_value: "[redacted]",
      public_resource_credential_id: "orc_0123456789abcdef"
    });
  });
});
