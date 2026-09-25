import { describe, expect, it } from "vitest";
import {
  isAllowedPendingGrantEmail,
  normalizeEmail,
  validatePermissionKey,
  validateReturnUrlExact,
  validateToolSlug
} from "../src/validation.js";

describe("validation", () => {
  it("normalizes emails without using them as primary identity", () => {
    expect(normalizeEmail(" Mario.Rossi@UNGUESS.IO ")).toBe("mario.rossi@unguess.io");
  });

  it("allows pending grants only for well-formed company emails", () => {
    expect(isAllowedPendingGrantEmail("mario.rossi@unguess.io", ["unguess.io", "nuotounostiledivita.it"])).toBe(true);
    expect(isAllowedPendingGrantEmail("lorenzo@nuotounostiledivita.it", ["unguess.io", "nuotounostiledivita.it"])).toBe(true);
    expect(isAllowedPendingGrantEmail("tester@testbirds.com", ["unguess.io"], ["testbirds.com", "testbirds.de"])).toBe(true);
    expect(isAllowedPendingGrantEmail("tester@testbirds.de", ["unguess.io"], ["testbirds.com", "testbirds.de"])).toBe(true);
    expect(isAllowedPendingGrantEmail("mario.rossi@gmail.com", ["unguess.io", "nuotounostiledivita.it"])).toBe(false);
    expect(isAllowedPendingGrantEmail("not-an-email", ["unguess.io"])).toBe(false);
  });

  it("validates tool slugs", () => {
    expect(validateToolSlug("crm")).toBe(true);
    expect(validateToolSlug("intranet-admin")).toBe(true);
    expect(validateToolSlug("CRM")).toBe(false);
    expect(validateToolSlug("-crm")).toBe(false);
  });

  it("allows hierarchical documented permission key format", () => {
    expect(validatePermissionKey("crm:read")).toBe(true);
    expect(validatePermissionKey("crm:export-data")).toBe(true);
    expect(validatePermissionKey("petyr:read:all")).toBe(true);
    expect(validatePermissionKey("admin:tools:write")).toBe(true);
    expect(validatePermissionKey("admin:access_requests:read")).toBe(true);
    expect(validatePermissionKey("admin:access_requests:write")).toBe(true);
    expect(validatePermissionKey("admin:other_requests:read")).toBe(false);
    expect(validatePermissionKey("admin:access_requests:delete")).toBe(false);
    expect(validatePermissionKey("crm.read")).toBe(false);
    expect(validatePermissionKey("crm:read:")).toBe(false);
    expect(validatePermissionKey("crm::read")).toBe(false);
    expect(validatePermissionKey("CRM:read")).toBe(false);
  });

  it("requires exact return URL matches", () => {
    const allowed = ["https://crm.draftapps.it/auth/callback"];
    expect(validateReturnUrlExact("https://crm.draftapps.it/auth/callback", allowed, ["https", "http"])).toBe(true);
    expect(validateReturnUrlExact("https://crm.draftapps.it.evil.com/auth/callback", allowed, ["https", "http"])).toBe(false);
    expect(validateReturnUrlExact("https://crm.draftapps.it/auth/callback?next=https://evil.com", allowed, ["https", "http"])).toBe(false);
    expect(validateReturnUrlExact("javascript:alert(1)", allowed, ["https", "http"])).toBe(false);
  });

  it("allows http only for localhost-style development callbacks", () => {
    expect(validateReturnUrlExact("http://localhost:3000/auth/callback", ["http://localhost:3000/auth/callback"], ["https", "http"])).toBe(true);
    expect(validateReturnUrlExact("http://crm.draftapps.it/auth/callback", ["http://crm.draftapps.it/auth/callback"], ["https", "http"])).toBe(false);
  });
});
