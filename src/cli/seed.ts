import { loadConfig } from "../config.js";
import { PostgresDb } from "../db.js";
import { Repositories } from "../repositories.js";
import { hashToolSecret, randomToken } from "../security.js";

const config = loadConfig();
const db = new PostgresDb(config.databaseUrl);
const repos = new Repositories(db);

const adminReturnUrls = [
  `${config.appBaseUrl.replace(/\/+$/, "")}${config.publicBasePath ? "/auth/callback" : "/admin/auth/callback"}`,
  config.publicBasePath ? `http://localhost:8080${config.publicBasePath}/auth/callback` : "http://localhost:8080/admin/auth/callback"
];

let accessAdmin = (await repos.findToolBySlug("access-admin")) ??
  (await repos.createTool({
    slug: "access-admin",
    displayName: "Access Layer Admin",
    description: "Admin UI for Access Layer itself",
    allowedReturnUrls: adminReturnUrls,
    ownerEmail: config.adminBootstrapEmails[0] ?? null
  }));

if (JSON.stringify(accessAdmin.allowed_return_urls) !== JSON.stringify(adminReturnUrls)) {
  accessAdmin = (await repos.updateTool(accessAdmin.id, { allowedReturnUrls: adminReturnUrls })) ?? accessAdmin;
}
await repos.replaceToolPermissions(accessAdmin.id, [
  "admin:tools:read",
  "admin:tools:write",
  "admin:users:read",
  "admin:users:write",
  "admin:grants:read",
  "admin:grants:write",
  "admin:access_requests:read",
  "admin:access_requests:write",
  "admin:audit:read",
  "admin:backup:read",
  "admin:backup:write",
  "admin:backup:secrets",
  "admin:secrets:rotate",
  "admin:oauth:read",
  "admin:oauth:write"
]);

if (["1", "true", "yes", "on"].includes((process.env.SEED_EXAMPLE_TOOLS ?? "").toLowerCase())) {
  const crm = (await repos.findToolBySlug("crm")) ??
    (await repos.createTool({
      slug: "crm",
      displayName: "CRM interno",
      description: "Example internal CRM tool",
      allowedReturnUrls: ["https://crm.draftapps.it/auth/callback", "http://localhost:3000/auth/callback"],
      ownerEmail: "crm-owner@unguess.io"
    }));
  await repos.replaceToolPermissions(crm.id, ["crm:read", "crm:write"]);

  const existingCrmClient = await db.query("SELECT id FROM tool_clients WHERE tool_id = $1 AND status = 'active' LIMIT 1", [crm.id]);
  if (!existingCrmClient.rowCount) {
    const crmClientId = randomToken("tlc_", 18);
    const crmClientSecret = randomToken("tls_", 32);
    await repos.createToolClient(crm.id, crmClientId, await hashToolSecret(crmClientSecret, config.toolClientSecretPepper));
    console.log(`CRM example tool client id: ${crmClientId}`);
    console.log("CRM example tool client secret was generated and stored hashed only. Rotate it through the Admin UI for a copyable value.");
  }
}

console.log("Seed complete.");
await db.close();
