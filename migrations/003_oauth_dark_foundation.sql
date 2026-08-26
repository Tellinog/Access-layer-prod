-- Step 3A OAuth vNext dark foundation.
-- Expand-only: this migration creates independent oauth_* registration metadata only.
-- It intentionally creates no protocol transaction, token, session, revocation, or seed data.

CREATE TABLE IF NOT EXISTS oauth_clients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id text NOT NULL UNIQUE,
  client_name text NOT NULL,
  client_type text NOT NULL,
  token_endpoint_auth_method text NOT NULL,
  grant_types text[] NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  owner_team text NOT NULL,
  owner_contact text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_clients_client_id_format CHECK (client_id ~ '^[a-z][a-z0-9._-]{2,127}$'),
  CONSTRAINT oauth_clients_client_name_nonempty CHECK (btrim(client_name) <> ''),
  CONSTRAINT oauth_clients_owner_team_nonempty CHECK (btrim(owner_team) <> ''),
  CONSTRAINT oauth_clients_type CHECK (client_type IN ('confidential', 'public')),
  CONSTRAINT oauth_clients_auth_method CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'none')),
  CONSTRAINT oauth_clients_type_auth_method CHECK (
    (client_type = 'confidential' AND token_endpoint_auth_method = 'client_secret_basic') OR
    (client_type = 'public' AND token_endpoint_auth_method = 'none')
  ),
  CONSTRAINT oauth_clients_grant_types CHECK (
    grant_types = ARRAY['authorization_code']::text[] OR
    grant_types = ARRAY['authorization_code', 'refresh_token']::text[] OR
    grant_types = ARRAY['refresh_token', 'authorization_code']::text[]
  ),
  CONSTRAINT oauth_clients_status CHECK (status IN ('draft', 'active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS oauth_client_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  secret_hash text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  expires_at timestamptz,
  retired_at timestamptz,
  rotation_parent_id uuid REFERENCES oauth_client_credentials(id) ON DELETE SET NULL,
  CONSTRAINT oauth_client_credentials_hash_only CHECK (
    length(secret_hash) BETWEEN 32 AND 1024 AND
    secret_hash !~ '[[:space:]]' AND
    secret_hash !~* 'BEGIN[[:space:]].*PRIVATE[[:space:]]KEY'
  ),
  CONSTRAINT oauth_client_credentials_status CHECK (status IN ('active', 'disabled', 'retired')),
  CONSTRAINT oauth_client_credentials_not_own_parent CHECK (rotation_parent_id IS NULL OR rotation_parent_id <> id),
  CONSTRAINT oauth_client_credentials_expiry_order CHECK (expires_at IS NULL OR expires_at > created_at),
  CONSTRAINT oauth_client_credentials_retired_order CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE TABLE IF NOT EXISTS oauth_client_redirect_uris (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_client_redirect_uris_exact_unique UNIQUE (oauth_client_id, redirect_uri),
  CONSTRAINT oauth_client_redirect_uris_no_wildcard CHECK (position('*' in redirect_uri) = 0),
  CONSTRAINT oauth_client_redirect_uris_no_fragment CHECK (position('#' in redirect_uri) = 0),
  CONSTRAINT oauth_client_redirect_uris_scheme CHECK (
    redirect_uri ~ '^https://[^[:space:]]+$' OR
    redirect_uri ~ '^http://localhost(:[0-9]{1,5})?/[^[:space:]]*$'
  )
);

CREATE TABLE IF NOT EXISTS oauth_resources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_id text NOT NULL UNIQUE,
  display_name text NOT NULL,
  status text NOT NULL DEFAULT 'draft',
  owner_team text NOT NULL,
  owner_contact text,
  audience_policy text NOT NULL DEFAULT 'exact_single_resource',
  protected_resource_metadata_url text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_resources_https_identity CHECK (
    resource_id ~ '^https://[^*#[:space:]]+$'
  ),
  CONSTRAINT oauth_resources_display_name_nonempty CHECK (btrim(display_name) <> ''),
  CONSTRAINT oauth_resources_owner_team_nonempty CHECK (btrim(owner_team) <> ''),
  CONSTRAINT oauth_resources_status CHECK (status IN ('draft', 'active', 'disabled')),
  CONSTRAINT oauth_resources_exact_audience CHECK (audience_policy = 'exact_single_resource'),
  CONSTRAINT oauth_resources_metadata_https CHECK (
    protected_resource_metadata_url ~ '^https://[^*#[:space:]]+$'
  )
);

CREATE TABLE IF NOT EXISTS oauth_resource_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE CASCADE,
  credential_id text NOT NULL UNIQUE,
  secret_hash text NOT NULL UNIQUE,
  authentication_method text NOT NULL DEFAULT 'client_secret_basic',
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  rotated_at timestamptz,
  expires_at timestamptz,
  retired_at timestamptz,
  rotation_parent_id uuid REFERENCES oauth_resource_credentials(id) ON DELETE SET NULL,
  CONSTRAINT oauth_resource_credentials_id_format CHECK (credential_id ~ '^[a-z][a-z0-9._-]{2,127}$'),
  CONSTRAINT oauth_resource_credentials_hash_only CHECK (
    length(secret_hash) BETWEEN 32 AND 1024 AND
    secret_hash !~ '[[:space:]]' AND
    secret_hash !~* 'BEGIN[[:space:]].*PRIVATE[[:space:]]KEY'
  ),
  CONSTRAINT oauth_resource_credentials_auth_method CHECK (authentication_method = 'client_secret_basic'),
  CONSTRAINT oauth_resource_credentials_status CHECK (status IN ('active', 'disabled', 'retired')),
  CONSTRAINT oauth_resource_credentials_not_own_parent CHECK (rotation_parent_id IS NULL OR rotation_parent_id <> id),
  CONSTRAINT oauth_resource_credentials_expiry_order CHECK (expires_at IS NULL OR expires_at > created_at),
  CONSTRAINT oauth_resource_credentials_retired_order CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE TABLE IF NOT EXISTS oauth_resource_entitlement_bindings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE CASCADE,
  binding_type text NOT NULL DEFAULT 'legacy_tool',
  legacy_tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  CONSTRAINT oauth_resource_entitlement_bindings_type CHECK (binding_type = 'legacy_tool'),
  CONSTRAINT oauth_resource_entitlement_bindings_status CHECK (status IN ('active', 'disabled')),
  CONSTRAINT oauth_resource_entitlement_bindings_disabled_state CHECK (
    (status = 'active' AND disabled_at IS NULL) OR
    (status = 'disabled' AND disabled_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_resource_one_active_legacy_binding
  ON oauth_resource_entitlement_bindings (oauth_resource_id)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS oauth_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scope text NOT NULL UNIQUE,
  description text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_scopes_canonical_three_segment CHECK (
    scope ~ '^[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}:[a-z][a-z0-9-]{1,62}$'
  ),
  CONSTRAINT oauth_scopes_description_nonempty CHECK (btrim(description) <> ''),
  CONSTRAINT oauth_scopes_status CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS oauth_resource_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE CASCADE,
  oauth_scope_id uuid NOT NULL REFERENCES oauth_scopes(id) ON DELETE RESTRICT,
  legacy_permission_key text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_resource_scopes_one_mapping UNIQUE (oauth_resource_id, oauth_scope_id),
  CONSTRAINT oauth_resource_scopes_legacy_permission_format CHECK (
    legacy_permission_key ~ '^[a-z0-9-]+(:[a-z0-9-]+)+$'
  ),
  CONSTRAINT oauth_resource_scopes_status CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS oauth_client_resource_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  oauth_resource_id uuid NOT NULL,
  oauth_scope_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_client_resource_scopes_explicit_unique UNIQUE (
    oauth_client_id,
    oauth_resource_id,
    oauth_scope_id
  ),
  CONSTRAINT oauth_client_resource_scopes_registered_mapping_fk FOREIGN KEY (
    oauth_resource_id,
    oauth_scope_id
  ) REFERENCES oauth_resource_scopes (oauth_resource_id, oauth_scope_id) ON DELETE CASCADE,
  CONSTRAINT oauth_client_resource_scopes_status CHECK (status IN ('active', 'disabled'))
);

CREATE TABLE IF NOT EXISTS oauth_signing_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key_namespace text NOT NULL DEFAULT 'oauth_p0',
  kid text NOT NULL UNIQUE,
  algorithm text NOT NULL DEFAULT 'RS256',
  public_jwk jsonb NOT NULL,
  public_key_fingerprint_sha256 text NOT NULL UNIQUE,
  protected_private_key_ref text NOT NULL,
  status text NOT NULL DEFAULT 'staged',
  published_at timestamptz,
  activates_at timestamptz,
  last_signed_at timestamptz,
  retire_after timestamptz,
  retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_signing_keys_namespace CHECK (key_namespace = 'oauth_p0'),
  CONSTRAINT oauth_signing_keys_kid_nonempty CHECK (btrim(kid) <> '' AND length(kid) <= 255),
  CONSTRAINT oauth_signing_keys_algorithm CHECK (algorithm = 'RS256'),
  CONSTRAINT oauth_signing_keys_public_jwk_shape CHECK (
    jsonb_typeof(public_jwk) = 'object' AND
    public_jwk ->> 'kty' = 'RSA' AND
    public_jwk ->> 'kid' = kid AND
    public_jwk ->> 'alg' = 'RS256' AND
    public_jwk ->> 'use' = 'sig' AND
    public_jwk ? 'n' AND
    public_jwk ? 'e' AND
    NOT (public_jwk ?| ARRAY['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'])
  ),
  CONSTRAINT oauth_signing_keys_public_fingerprint CHECK (
    public_key_fingerprint_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT oauth_signing_keys_reference_only CHECK (
    btrim(protected_private_key_ref) <> '' AND
    length(protected_private_key_ref) <= 2048 AND
    protected_private_key_ref !~ '[\r\n]' AND
    protected_private_key_ref !~* 'BEGIN[[:space:]].*PRIVATE[[:space:]]KEY' AND
    protected_private_key_ref !~ '^[[:space:]]*\{' AND
    (
      protected_private_key_ref ~ '^[a-z][a-z0-9+.-]{1,31}://[^[:space:]]+$' OR
      protected_private_key_ref ~ '^/run/secrets/[A-Za-z0-9._/-]+$'
    )
  ),
  CONSTRAINT oauth_signing_keys_not_legacy_reference CHECK (
    protected_private_key_ref !~* 'access-layer-jwt-private'
  ),
  CONSTRAINT oauth_signing_keys_status CHECK (status IN ('staged', 'published', 'active', 'retired', 'disabled')),
  CONSTRAINT oauth_signing_keys_activation_order CHECK (
    activates_at IS NULL OR published_at IS NULL OR activates_at >= published_at
  ),
  CONSTRAINT oauth_signing_keys_retirement_order CHECK (
    retire_after IS NULL OR last_signed_at IS NULL OR retire_after >= last_signed_at
  )
);

CREATE INDEX IF NOT EXISTS idx_oauth_client_credentials_client_status
  ON oauth_client_credentials (oauth_client_id, status);
CREATE INDEX IF NOT EXISTS idx_oauth_redirect_uris_client
  ON oauth_client_redirect_uris (oauth_client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_resource_credentials_resource_status
  ON oauth_resource_credentials (oauth_resource_id, status);
CREATE INDEX IF NOT EXISTS idx_oauth_resource_scopes_resource_status
  ON oauth_resource_scopes (oauth_resource_id, status);
CREATE INDEX IF NOT EXISTS idx_oauth_client_resource_scopes_client_status
  ON oauth_client_resource_scopes (oauth_client_id, status);
CREATE INDEX IF NOT EXISTS idx_oauth_signing_keys_status_lifecycle
  ON oauth_signing_keys (status, published_at, activates_at, retire_after);
