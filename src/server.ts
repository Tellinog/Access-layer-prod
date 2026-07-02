import { AuditLogger } from "./audit.js";
import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { PostgresDb } from "./db.js";
import { GoogleAuthLibraryOidcClient } from "./google.js";
import { Repositories } from "./repositories.js";
import { TokenService } from "./token-service.js";

const config = loadConfig();
const db = new PostgresDb(config.databaseUrl);
const repositories = new Repositories(db);
const audit = new AuditLogger(repositories);
const tokenService = new TokenService(config);
await tokenService.init();

const app = await buildApp({
  config,
  repositories,
  audit,
  google: new GoogleAuthLibraryOidcClient(config),
  tokenService
});

const close = async () => {
  await app.close();
  await db.close();
};

process.on("SIGINT", () => {
  close().finally(() => process.exit(0));
});
process.on("SIGTERM", () => {
  close().finally(() => process.exit(0));
});

await app.listen({ port: config.port, host: "0.0.0.0" });
