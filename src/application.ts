import { buildApp, type AppDependencies } from "./app.js";
import { registerOAuthReadOnlyHttp } from "./oauth/http.js";
import type { OAuthFoundationRepository } from "./oauth/repository.js";

export interface ApplicationDependencies extends AppDependencies {
  oauthRepository: OAuthFoundationRepository;
}

export async function buildApplication(deps: ApplicationDependencies) {
  const app = await buildApp(deps);
  if (deps.config.oauthP0Enabled) {
    registerOAuthReadOnlyHttp(app, { config: deps.config, repository: deps.oauthRepository });
  }
  return app;
}
