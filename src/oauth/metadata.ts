export interface OAuthAuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  revocation_endpoint: string;
  introspection_endpoint: string;
  response_types_supported: ["code"];
  grant_types_supported: ["authorization_code", "refresh_token"];
  code_challenge_methods_supported: ["S256"];
  token_endpoint_auth_methods_supported: ["client_secret_basic", "none"];
  revocation_endpoint_auth_methods_supported: ["client_secret_basic", "none"];
  introspection_endpoint_auth_methods_supported: ["client_secret_basic"];
  authorization_response_iss_parameter_supported: true;
}

export interface OAuthProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported: string[];
  bearer_methods_supported: ["header"];
  resource_name: string;
}

function withoutTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

export function buildOAuthAuthorizationServerMetadata(issuer: string): OAuthAuthorizationServerMetadata {
  const baseUrl = withoutTrailingSlash(issuer);
  return {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    jwks_uri: `${baseUrl}/oauth/jwks`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    introspection_endpoint: `${baseUrl}/oauth/introspect`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
    revocation_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
    introspection_endpoint_auth_methods_supported: ["client_secret_basic"],
    authorization_response_iss_parameter_supported: true
  };
}

export function buildOAuthProtectedResourceMetadata(input: {
  resource: string;
  authorizationServer: string;
  scopesSupported: readonly string[];
  resourceName: string;
}): OAuthProtectedResourceMetadata {
  return {
    resource: input.resource,
    authorization_servers: [withoutTrailingSlash(input.authorizationServer)],
    scopes_supported: [...input.scopesSupported],
    bearer_methods_supported: ["header"],
    resource_name: input.resourceName
  };
}
