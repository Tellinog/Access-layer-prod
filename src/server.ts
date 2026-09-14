import { AuditLogger } from "./audit.js";
import { buildApplication } from "./application.js";
import { loadConfig } from "./config.js";
import { PostgresDb } from "./db.js";
import { GoogleAuthLibraryOidcClient } from "./google.js";
import { MicrosoftEntraOidcClient } from "./microsoft.js";
import { OAuthFoundationRepository } from "./oauth/repository.js";
import { OAuthAuthorizationFlowRepository } from "./oauth/flow-repository.js";
import { OAuthGoogleAuthLibraryOidcClient } from "./oauth/google.js";
import { OAuthTokenRepository } from "./oauth/token-repository.js";
import { OAuthTokenLifecycleService } from "./oauth/token-service.js";
import { Repositories } from "./repositories.js";
import { TokenService } from "./token-service.js";

const config = loadConfig();
const db = new PostgresDb(config.databaseUrl);
const repositories = new Repositories(db);
const audit = new AuditLogger(repositories);
const tokenService = new TokenService(config);
await tokenService.init();
const oauthTokenRepository = new OAuthTokenRepository(db);

const app = await buildApplication({
  config,
  repositories,
  oauthRepository: new OAuthFoundationRepository(db),
  oauthFlowRepository: new OAuthAuthorizationFlowRepository(db),
  oauthGoogle: new OAuthGoogleAuthLibraryOidcClient(config),
  oauthTokenService: new OAuthTokenLifecycleService({
    config,
    repository: oauthTokenRepository
  }),
  audit,
  google: new GoogleAuthLibraryOidcClient(config),
  microsoft: config.legacyMicrosoftEnabled ? new MicrosoftEntraOidcClient(config) : undefined,
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
