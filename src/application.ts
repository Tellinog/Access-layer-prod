import { buildApp, type AppDependencies } from "./app.js";
import { registerOAuthAuthorizationHttp, registerOAuthReadOnlyHttp } from "./oauth/http.js";
import type { OAuthAuthorizationFlowRepository } from "./oauth/flow-repository.js";
import type { OAuthUpstreamGoogleClient } from "./oauth/google.js";
import type { OAuthFoundationRepository } from "./oauth/repository.js";

export interface ApplicationDependencies extends AppDependencies {
  oauthRepository: OAuthFoundationRepository;
  oauthFlowRepository: OAuthAuthorizationFlowRepository;
  oauthGoogle: OAuthUpstreamGoogleClient;
}

export async function buildApplication(deps: ApplicationDependencies) {
  const app = await buildApp(deps);
  if (deps.config.oauthP0Enabled) {
    registerOAuthReadOnlyHttp(app, { config: deps.config, repository: deps.oauthRepository });
    registerOAuthAuthorizationHttp(app, {
      config: deps.config,
      repository: deps.oauthRepository,
      flowRepository: deps.oauthFlowRepository,
      repositories: deps.repositories,
      audit: deps.audit,
      google: deps.oauthGoogle
    });
  }
  return app;
}
