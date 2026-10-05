import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { createContext, runInContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";
import type { Db } from "../src/db.js";
import { OAuthAdminRepository } from "../src/oauth/admin-repository.js";
import { OAuthAdminService } from "../src/oauth/admin-service.js";
import type { OAuthAdminAuditContext, OAuthAdminBulkScopesInput } from "../src/oauth/admin-types.js";
import type { Config } from "../src/types.js";

const ctx = { actor: { userId: randomUUID(), googleSub: "synthetic-admin", email: "admin@example.invalid", hd: "example.invalid" },
  correlationId: "synthetic-correlation", requestIpHash: null, userAgentHash: null } as OAuthAdminAuditContext;
const input = (count: number): OAuthAdminBulkScopesInput => ({ mode: "create_missing", updateDescriptions: false,
  reactivateDisabled: false, rows: Array.from({ length: count }, (_, i) => ({ row: i + 1,
    scope: `nancy-sim:area-${String(i + 1).padStart(3, "0")}:read`, description: `Read area ${i + 1}, including forms; drafts` })) });

function fakeScopeDb() {
  const state = new Map<string, { id: string; scope: string; description: string; status: string }>();
  const audit: unknown[][] = [];
  let failAt: string | null = null;
  const db: Db = {
    query: async (sql, params = []) => {
      if (sql.includes("SET TRANSACTION")) return { rows: [] } as never;
      if (sql.includes("SELECT id, scope, description, status FROM oauth_scopes")) {
        const names = params[0] as string[];
        return { rows: [...state.values()].filter((row) => names.includes(row.scope)) } as never;
      }
      if (sql.includes("INSERT INTO oauth_scopes")) {
        if (failAt === "mutation") throw new Error("synthetic mutation failure");
        const [scope, description] = params as string[];
        state.set(scope, { id: randomUUID(), scope, description, status: "active" });
        return { rows: [] } as never;
      }
      if (sql.includes("UPDATE oauth_scopes")) {
        const [id, description] = params as string[];
        const row = [...state.values()].find((item) => item.id === id)!;
        row.description = description;
        if (sql.includes("status = 'active'")) row.status = "active";
        return { rows: [] } as never;
      }
      if (sql.includes("INSERT INTO audit_logs")) {
        if (failAt === "audit") throw new Error("synthetic audit failure");
        audit.push(params);
        return { rows: [] } as never;
      }
      throw new Error(`Unexpected SQL: ${sql}`);
    },
    transaction: async (fn) => {
      const before = new Map([...state].map(([key, value]) => [key, { ...value }]));
      const auditLength = audit.length;
      try { return await fn(db); } catch (error) {
        state.clear(); for (const [key, value] of before) state.set(key, value);
        audit.length = auditLength;
        throw error;
      }
    },
    close: async () => undefined
  };
  return { db, state, audit, setFailure: (mode: string | null) => { failAt = mode; } };
}

describe("Phase 9A.4 bulk scope semantics", () => {
  it("previews 25 rows without writes, commits atomically, and repeats as skips", async () => {
    const fixture = fakeScopeDb(), repository = new OAuthAdminRepository(fixture.db), batch = input(25);
    const preview = await repository.bulkScopes(batch, false);
    expect(preview.summary).toMatchObject({ total: 25, create: 25, error: 0 });
    expect(fixture.state.size).toBe(0);
    expect(fixture.audit).toHaveLength(0);
    const committed = await repository.bulkScopes(batch, true, ctx);
    expect(committed).toMatchObject({ committed: 25 });
    expect(fixture.state.size).toBe(25);
    expect(fixture.audit).toHaveLength(26);
    const repeat = await repository.bulkScopes(batch, true, ctx);
    expect(repeat).toMatchObject({ committed: 0, summary: { skip: 25 } });
    expect(fixture.audit).toHaveLength(26);
  });

  it("requires explicit description update and reactivation, and flags duplicate/invalid rows", async () => {
    const fixture = fakeScopeDb(), repository = new OAuthAdminRepository(fixture.db), batch = input(1);
    await repository.bulkScopes(batch, true, ctx);
    const changed = { ...batch, rows: [{ ...batch.rows[0], description: "Changed" }] };
    expect((await repository.bulkScopes(changed, false)).rows[0]).toMatchObject({ operation: "skip", result: "warning" });
    expect(await repository.bulkScopes({ ...changed, updateDescriptions: true }, true, ctx)).toMatchObject({ committed: 1 });
    fixture.state.get(batch.rows[0].scope)!.status = "disabled";
    expect((await repository.bulkScopes(changed, false)).rows[0]).toMatchObject({ operation: "skip", reason: "disabled_requires_opt_in" });
    expect(await repository.bulkScopes({ ...changed, reactivateDisabled: true }, true, ctx)).toMatchObject({ committed: 1 });
    const duplicate = { ...batch, rows: [batch.rows[0], { ...batch.rows[0], row: 2 }] };
    expect((await repository.bulkScopes(duplicate, false)).summary.error).toBe(1);
    await expect(repository.bulkScopes(duplicate, true, ctx)).rejects.toMatchObject({ reason: "bulk_scope_validation_failed" });
    const invalid = { ...batch, rows: [{ row: 1, scope: "invalid:*", description: "" }] };
    expect((await repository.bulkScopes(invalid, false)).rows[0].operation).toBe("error");
  });

  it("rolls back mutations when a write or audit fails", async () => {
    for (const failure of ["mutation", "audit"]) {
      const fixture = fakeScopeDb(), repository = new OAuthAdminRepository(fixture.db);
      fixture.setFailure(failure);
      await expect(repository.bulkScopes(input(1), true, ctx)).rejects.toThrow();
      expect(fixture.state.size).toBe(0);
      expect(fixture.audit).toHaveLength(0);
    }
  });

  it("bounds 200 rows and the user-scope matrix at the service boundary", () => {
    const fixture = fakeScopeDb();
    const service = new OAuthAdminService({ config: {} as Config, repository: new OAuthAdminRepository(fixture.db) });
    expect(() => service.bulkScopes(input(201), false)).toThrowError(expect.objectContaining({ issues: ["bulk_scope_batch_size_invalid"] }));
    expect(() => service.bulkNativeGrants({ resourceId: randomUUID(), userIds: Array(101).fill(randomUUID()),
      emails: [], scopes: ["nancy-sim:area:read"], validFrom: null, validUntil: null }, false))
      .toThrowError(expect.objectContaining({ issues: expect.arrayContaining(["bulk_grant_batch_size_invalid"]) }));
  });
});

describe("Phase 9A.4 generated page contract", () => {
  const source = readFileSync(new URL("../src/oauth/admin-http.ts", import.meta.url), "utf8");
  const start = source.indexOf("return `<!doctype html>");
  const end = source.indexOf("</body></html>`;", start) + "</body></html>`".length;
  const html = new Function("endpoint", "legacyAdmin", "return " + source.slice(start + 7, end))(
    "/v1/admin/oauth", "/admin") as string;
  const inline = html.match(/<script>([\s\S]*?)<\/script>/)![1];
  const line = inline.split("\n").find((item) => item.startsWith("function parseScopePaste("))!;
  const parse = new Function(`${line}; return parseScopePaste;`)() as
    (text: string) => { rows: Array<{ row: number; scope: string; description: string }>; errors: Array<{ row: number }> };

  it("parses BOM, CRLF, blank lines, TAB and first-semicolon-only without comma splitting", () => {
    const parsed = parse("\uFEFFnancy-sim:forms:read ; Read forms, drafts; and history\r\n\r\n" +
      "nancy-sim:forms:write\tWrite forms; safely\r\n");
    expect(parsed.errors).toEqual([]);
    expect(parsed.rows).toEqual([
      { row: 1, scope: "nancy-sim:forms:read", description: "Read forms, drafts; and history" },
      { row: 3, scope: "nancy-sim:forms:write", description: "Write forms; safely" }
    ]);
    expect(parse("nancy-sim:forms:read\nmissing-description ; \n").errors).toEqual([{ row: 1, reason: "missing TAB or semicolon separator" },
      { row: 2, reason: "scope and description are required" }]);
  });

  it("exposes bulk, selectors, search and structured allowance controls", () => {
    for (const marker of ["Bulk scope catalogue", "bulk-scope-preview", "bulk-scope-commit", "Select all active",
      "scope-search", "client-picker", "allowance-picker", "bulk-grant-preview", "bulk-revoke-preview",
      "status-owner", "rotate-owner", "redirect-client", "bulk-resource-preview"]) expect(source).toContain(marker);
    expect(html).not.toMatch(/UUID<input/);
  });

  it("executes the generated controls, selects exact registered scopes and rejects an obsolete async preview", async () => {
    class Element {
      children: Element[] = [];
      style: Record<string, string> = {};
      dataset: Record<string, string> = {};
      textContent = ""; value = ""; type = ""; selected = false; checked = false; disabled = false;
      hidden = false; required = false; multiple = false; innerHTML = ""; className = ""; placeholder = "";
      onclick?: () => unknown; oninput?: (event: unknown) => unknown; onchange?: () => unknown;
      listeners: Record<string, Array<() => unknown>> = {};
      elements: Record<string, Element> = {};
      constructor(public tag = "div") {}
      get options() { return this.children.filter((item) => item.tag === "option"); }
      get selectedOptions() { return this.options.filter((item) => this.multiple ? item.selected : item.value === this.value); }
      appendChild(item: Element) { this.children.push(item); if (this.tag === "select" && !this.value) this.value = item.value; return item; }
      append(...items: Element[]) { items.forEach((item) => this.appendChild(item)); }
      replaceChildren(...items: Element[]) { this.children = []; if (this.tag === "select") this.value = ""; this.append(...items); }
      addEventListener(event: string, fn: () => unknown) { (this.listeners[event] ??= []).push(fn); }
      querySelector(selector: string): Element | null {
        if (selector === "input[type=search]") return this.children.find((item) => item.type === "search") ?? null;
        return null;
      }
      input() { for (const fn of this.listeners.input ?? []) fn(); this.oninput?.({ target: this }); }
    }
    const elements = new Map<string, Element>();
    for (const match of html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)) {
      const element = new Element(match[1]); element.disabled = /\bdisabled\b/.test(match[0]);
      element.multiple = /\bmultiple\b/.test(match[0]); elements.set(match[2], element);
    }
    for (const id of ["status-kind", "rotate-kind", "retire-kind"]) elements.get(id)!.value = "clients";
    elements.get("resource-mode")!.value = "native";
    elements.get("scope-target-status")!.value = "disabled";
    for (const form of ["redirect-form", "allowance-form"]) {
      elements.get(form)!.elements.redirects = new Element("textarea");
      elements.get(form)!.elements.allowances = new Element("textarea");
    }
    const resourceId = randomUUID(), clientId = randomUUID(), scopeId = randomUUID();
    const snapshot = { clients: [{ id: clientId, client_name: "Client", client_id: "synthetic-client", status: "active" }],
      resources: [{ id: resourceId, display_name: "Resource", resource_id: "https://synthetic.example.invalid/v1", status: "active", entitlement_mode: "native" }],
      scopes: [{ id: scopeId, scope: "synthetic:records:read", description: "Read", status: "active" },
        { id: randomUUID(), scope: "synthetic:other:read", description: "Unregistered", status: "active" }],
      resourceScopes: [{ oauth_resource_id: resourceId, oauth_scope_id: scopeId, scope: "synthetic:records:read", status: "active" }],
      allowances: [], redirectUris: [], entitlementBindings: [], clientCredentials: [], resourceCredentials: [], signingKeys: [] };
    let resolvePreview: ((value: unknown) => void) | undefined;
    const response = (data: unknown) => ({ ok: true, json: async () => data });
    const context = createContext({ document: {
      querySelector: (selector: string) => elements.get(selector.slice(1)),
      getElementById: (id: string) => elements.get(id), querySelectorAll: () => [],
      createElement: (tag: string) => new Element(tag), createTextNode: (text: string) => Object.assign(new Element("text"), { textContent: text })
    }, fetch: async (url: string, request: { method: string }) => {
      if (request.method === "POST") return new Promise((resolve) => { resolvePreview = resolve; });
      return response(url.endsWith("/legacy-tools") ? [] : url.includes("/native-grants?") ? [] : snapshot);
    }, URLSearchParams, setTimeout, clearTimeout, confirm: () => true });
    new Script(inline).runInContext(context);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(elements.get("result")!.textContent).toBe("");
    elements.get("client-select-all")!.onclick!();
    expect(Array.from(runInContext("[...clientChoice]", context))).toEqual(["synthetic:records:read"]);
    elements.get("bulk-scopes")!.value = "synthetic:new:read ; Read new";
    const pending = elements.get("bulk-scope-preview")!.onclick!() as Promise<unknown>;
    await new Promise((resolve) => setTimeout(resolve, 0));
    elements.get("bulk-scopes")!.value = "synthetic:edited:read ; Read edited";
    elements.get("bulk-scopes")!.input();
    resolvePreview!(response({ rows: [], summary: { error: 0 } }));
    await pending;
    expect(elements.get("bulk-scope-commit")!.disabled).toBe(true);
    expect(runInContext("bulkScopePreview", context)).toBeNull();
  });
});
