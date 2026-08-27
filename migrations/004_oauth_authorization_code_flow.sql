-- Step 3C OAuth vNext dark Authorization Code issuance storage.
-- Expand-only: no legacy table or row is altered by this migration.
-- Token exchange, OAuth sessions, refresh tokens and revocation remain out of scope.

CREATE TABLE IF NOT EXISTS oauth_authorization_transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE RESTRICT,
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE RESTRICT,
  redirect_uri text NOT NULL,
  requested_scopes text[] NOT NULL,
  code_challenge text NOT NULL,
  code_challenge_method text NOT NULL DEFAULT 'S256',
  protected_downstream_state jsonb,
  upstream_state_hash text NOT NULL UNIQUE,
  upstream_nonce_hash text NOT NULL,
  correlation_id text NOT NULL UNIQUE,
  status text NOT NULL DEFAULT 'pending',
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_authorization_transactions_redirect_nonempty CHECK (
    btrim(redirect_uri) <> '' AND position('*' in redirect_uri) = 0 AND position('#' in redirect_uri) = 0
  ),
  CONSTRAINT oauth_authorization_transactions_scopes_nonempty CHECK (
    cardinality(requested_scopes) > 0 AND array_position(requested_scopes, NULL) IS NULL
  ),
  CONSTRAINT oauth_authorization_transactions_pkce_s256 CHECK (
    code_challenge_method = 'S256' AND code_challenge ~ '^[A-Za-z0-9_-]{43}$'
  ),
  CONSTRAINT oauth_authorization_transactions_state_envelope_lifecycle CHECK (
    CASE
      WHEN status IN ('pending', 'claimed') THEN
        protected_downstream_state IS NOT NULL AND
        jsonb_typeof(protected_downstream_state) = 'object'
      WHEN status IN ('completed', 'denied', 'expired') THEN
        protected_downstream_state IS NULL
      ELSE false
    END
  ),
  CONSTRAINT oauth_authorization_transactions_hashes CHECK (
    upstream_state_hash ~ '^[A-Za-z0-9_-]{43}$' AND
    upstream_nonce_hash ~ '^[A-Za-z0-9_-]{43}$' AND
    upstream_state_hash <> upstream_nonce_hash
  ),
  CONSTRAINT oauth_authorization_transactions_correlation_nonempty CHECK (btrim(correlation_id) <> ''),
  CONSTRAINT oauth_authorization_transactions_expiry CHECK (expires_at = created_at + interval '600 seconds'),
  CONSTRAINT oauth_authorization_transactions_status CHECK (
    status IN ('pending', 'claimed', 'completed', 'denied', 'expired')
  ),
  CONSTRAINT oauth_authorization_transactions_lifecycle CHECK (
    (status = 'pending' AND claimed_at IS NULL AND completed_at IS NULL) OR
    (status = 'claimed' AND claimed_at IS NOT NULL AND completed_at IS NULL) OR
    (status IN ('completed', 'denied') AND claimed_at IS NOT NULL AND completed_at IS NOT NULL) OR
    (status = 'expired' AND completed_at IS NOT NULL)
  ),
  CONSTRAINT oauth_authorization_transactions_claim_order CHECK (
    claimed_at IS NULL OR claimed_at >= created_at
  ),
  CONSTRAINT oauth_authorization_transactions_completion_order CHECK (
    completed_at IS NULL OR completed_at >= created_at
  )
);

CREATE TABLE IF NOT EXISTS oauth_authorizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_authorization_transaction_id uuid NOT NULL UNIQUE
    REFERENCES oauth_authorization_transactions(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE RESTRICT,
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE RESTRICT,
  granted_scopes text[] NOT NULL,
  legacy_authorization_grant_id uuid NOT NULL REFERENCES authorization_grants(id) ON DELETE RESTRICT,
  correlation_id text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_authorizations_scopes_nonempty CHECK (
    cardinality(granted_scopes) > 0 AND array_position(granted_scopes, NULL) IS NULL
  ),
  CONSTRAINT oauth_authorizations_correlation_nonempty CHECK (btrim(correlation_id) <> ''),
  CONSTRAINT oauth_authorizations_status CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash text NOT NULL UNIQUE,
  oauth_authorization_transaction_id uuid NOT NULL UNIQUE
    REFERENCES oauth_authorization_transactions(id) ON DELETE RESTRICT,
  oauth_authorization_id uuid NOT NULL UNIQUE REFERENCES oauth_authorizations(id) ON DELETE RESTRICT,
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE RESTRICT,
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  redirect_uri text NOT NULL,
  granted_scopes text[] NOT NULL,
  code_challenge text NOT NULL,
  code_challenge_method text NOT NULL DEFAULT 'S256',
  correlation_id text NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CONSTRAINT oauth_authorization_codes_hash_sha256 CHECK (code_hash ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT oauth_authorization_codes_redirect_nonempty CHECK (btrim(redirect_uri) <> ''),
  CONSTRAINT oauth_authorization_codes_scopes_nonempty CHECK (
    cardinality(granted_scopes) > 0 AND array_position(granted_scopes, NULL) IS NULL
  ),
  CONSTRAINT oauth_authorization_codes_pkce_s256 CHECK (
    code_challenge_method = 'S256' AND code_challenge ~ '^[A-Za-z0-9_-]{43}$'
  ),
  CONSTRAINT oauth_authorization_codes_correlation_nonempty CHECK (btrim(correlation_id) <> ''),
  CONSTRAINT oauth_authorization_codes_fixed_ttl CHECK (expires_at = issued_at + interval '60 seconds'),
  CONSTRAINT oauth_authorization_codes_consumed_order CHECK (
    consumed_at IS NULL OR consumed_at >= issued_at
  )
);

CREATE INDEX IF NOT EXISTS idx_oauth_authorization_transactions_expiry_status
  ON oauth_authorization_transactions (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_authorizations_subject_status
  ON oauth_authorizations (user_id, status);
CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_expiry_consumed
  ON oauth_authorization_codes (expires_at, consumed_at);
