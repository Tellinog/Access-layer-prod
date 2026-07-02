import { describe, expect, it } from "vitest";
import {
  decryptJsonPayload,
  encryptJsonPayload,
  hashOpaque,
  hashToolSecret,
  signCookie,
  verifySignedCookie,
  verifyToolSecret
} from "../src/security.js";

describe("security helpers", () => {
  it("hashes opaque values with a pepper", () => {
    expect(hashOpaque("otc_abc", "pepper")).toBe(hashOpaque("otc_abc", "pepper"));
    expect(hashOpaque("otc_abc", "pepper")).not.toBe(hashOpaque("otc_abc", "other"));
  });

  it("stores tool secrets as verifiable hashes", async () => {
    const stored = await hashToolSecret("secret-value", "pepper");
    expect(stored).not.toContain("secret-value");
    await expect(verifyToolSecret("secret-value", "pepper", stored)).resolves.toBe(true);
    await expect(verifyToolSecret("wrong", "pepper", stored)).resolves.toBe(false);
  });

  it("signs and verifies admin cookies", () => {
    const cookie = signCookie("jwt-value", "session-secret");
    expect(verifySignedCookie(cookie, "session-secret")).toBe("jwt-value");
    expect(verifySignedCookie(cookie.replace("jwt-value", "other"), "session-secret")).toBeNull();
  });

  it("encrypts and decrypts backup JSON payloads", () => {
    const secret = "backup-encryption-key-with-32-chars";
    const payload = { schema: "access-layer-backup", data: { users: [] } };
    const encrypted = encryptJsonPayload(payload, secret);
    expect(encrypted.schema).toBe("access-layer-encrypted-backup");
    expect(JSON.stringify(encrypted)).not.toContain("users");
    expect(decryptJsonPayload(encrypted, secret)).toEqual(payload);
    expect(() => decryptJsonPayload(encrypted, "wrong-backup-encryption-key-32chars")).toThrow();
  });
});
