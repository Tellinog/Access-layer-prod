import { buildApp, type AppDependencies } from "./app.js";
import { registerOAuthAuthorizationHttp, registerOAuthReadOnlyHttp } from "./oauth/http.js";
import type { OAuthAuthorizationFlowRepository } from "./oauth/flow-repository.js";
import type { OAuthUpstreamGoogleClient } from "./oauth/google.js";
import type { OAuthFoundationRepository } from "./oauth/repository.js";
import { registerOAuthTokenLifecycleHttp, type OAuthTokenHttpService } from "./oauth/token-http.js";
import { registerOAuthAdminHttp } from "./oauth/admin-http.js";
import type { OAuthAdminService } from "./oauth/admin-service.js";

export interface ApplicationDependencies extends AppDependencies {
  oauthRepository: OAuthFoundationRepository;
  oauthFlowRepository: OAuthAuthorizationFlowRepository;
  oauthGoogle: OAuthUpstreamGoogleClient;
  oauthTokenService: OAuthTokenHttpService;
  oauthAdminService?: OAuthAdminService;
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
    registerOAuthTokenLifecycleHttp(app, {
      config: deps.config,
      service: deps.oauthTokenService
    });
  }
  if (deps.oauthAdminService) {
    registerOAuthAdminHttp(app, {
      config: deps.config,
      repositories: deps.repositories,
      tokenService: deps.tokenService,
      service: deps.oauthAdminService
    });
  }
  return app;
}
