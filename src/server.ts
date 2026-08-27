import { AuditLogger } from "./audit.js";
import { buildApplication } from "./application.js";
import { loadConfig } from "./config.js";
import { PostgresDb } from "./db.js";
import { GoogleAuthLibraryOidcClient } from "./google.js";
import { OAuthFoundationRepository } from "./oauth/repository.js";
import { OAuthAuthorizationFlowRepository } from "./oauth/flow-repository.js";
import { OAuthGoogleAuthLibraryOidcClient } from "./oauth/google.js";
import { Repositories } from "./repositories.js";
import { TokenService } from "./token-service.js";

const config = loadConfig();
const db = new PostgresDb(config.databaseUrl);
const repositories = new Repositories(db);
const audit = new AuditLogger(repositories);
const tokenService = new TokenService(config);
await tokenService.init();

const app = await buildApplication({
  config,
  repositories,
  oauthRepository: new OAuthFoundationRepository(db),
  oauthFlowRepository: new OAuthAuthorizationFlowRepository(db),
  oauthGoogle: new OAuthGoogleAuthLibraryOidcClient(config),
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
