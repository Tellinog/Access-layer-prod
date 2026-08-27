-- Step 3D OAuth vNext token-lifecycle core storage.
-- Expand-only: creates independent oauth_* state and does not alter or write legacy rows.

CREATE TABLE IF NOT EXISTS oauth_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_authorization_id uuid NOT NULL UNIQUE REFERENCES oauth_authorizations(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE RESTRICT,
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'active',
  correlation_id text NOT NULL,
  issued_at timestamptz NOT NULL,
  last_activity_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revocation_reason text,
  CONSTRAINT oauth_sessions_status CHECK (status IN ('active', 'expired', 'revoked')),
  CONSTRAINT oauth_sessions_correlation_nonempty CHECK (btrim(correlation_id) <> ''),
  CONSTRAINT oauth_sessions_initial_idle_window CHECK (
    last_activity_at <> issued_at OR idle_expires_at = issued_at + interval '28800 seconds'
  ),
  CONSTRAINT oauth_sessions_activity_order CHECK (
    last_activity_at >= issued_at AND idle_expires_at = last_activity_at + interval '28800 seconds'
  ),
  CONSTRAINT oauth_sessions_revocation_lifecycle CHECK (
    (status = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL) OR
    (status IN ('expired', 'revoked') AND revoked_at IS NOT NULL AND COALESCE(btrim(revocation_reason), '') <> '')
  )
);

CREATE TABLE IF NOT EXISTS oauth_refresh_token_families (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_authorization_id uuid NOT NULL REFERENCES oauth_authorizations(id) ON DELETE RESTRICT,
  oauth_session_id uuid NOT NULL UNIQUE REFERENCES oauth_sessions(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  oauth_client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE RESTRICT,
  oauth_resource_id uuid NOT NULL REFERENCES oauth_resources(id) ON DELETE RESTRICT,
  scope_ceiling text[] NOT NULL,
  current_scopes text[] NOT NULL,
  current_generation integer NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'active',
  replay_detected_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text,
  created_at timestamptz NOT NULL,
  CONSTRAINT oauth_refresh_token_families_scopes_nonempty CHECK (
    cardinality(scope_ceiling) > 0 AND array_position(scope_ceiling, NULL) IS NULL AND
    cardinality(current_scopes) > 0 AND array_position(current_scopes, NULL) IS NULL AND
    current_scopes <@ scope_ceiling
  ),
  CONSTRAINT oauth_refresh_token_families_generation_nonnegative CHECK (current_generation >= 0),
  CONSTRAINT oauth_refresh_token_families_status CHECK (status IN ('active', 'expired', 'revoked')),
  CONSTRAINT oauth_refresh_token_families_replay_lifecycle CHECK (
    replay_detected_at IS NULL OR (status = 'revoked' AND revoked_at IS NOT NULL)
  ),
  CONSTRAINT oauth_refresh_token_families_revocation_lifecycle CHECK (
    (status = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL) OR
    (status IN ('expired', 'revoked') AND revoked_at IS NOT NULL AND COALESCE(btrim(revocation_reason), '') <> '')
  )
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_refresh_token_family_id uuid NOT NULL REFERENCES oauth_refresh_token_families(id) ON DELETE RESTRICT,
  token_hash text NOT NULL UNIQUE,
  generation integer NOT NULL,
  parent_refresh_token_id uuid,
  scopes text[] NOT NULL,
  status text NOT NULL DEFAULT 'current',
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  CONSTRAINT oauth_refresh_tokens_hash_sha256 CHECK (token_hash ~ '^[A-Za-z0-9_-]{43}$'),
  CONSTRAINT oauth_refresh_tokens_family_id_id_unique UNIQUE (oauth_refresh_token_family_id, id),
  CONSTRAINT oauth_refresh_tokens_family_generation UNIQUE (oauth_refresh_token_family_id, generation),
  CONSTRAINT oauth_refresh_tokens_parent_same_family FOREIGN KEY (
    oauth_refresh_token_family_id, parent_refresh_token_id
  ) REFERENCES oauth_refresh_tokens (oauth_refresh_token_family_id, id) ON DELETE RESTRICT,
  CONSTRAINT oauth_refresh_tokens_generation_lineage CHECK (
    (generation = 0 AND parent_refresh_token_id IS NULL) OR
    (generation > 0 AND parent_refresh_token_id IS NOT NULL)
  ),
  CONSTRAINT oauth_refresh_tokens_not_own_parent CHECK (
    parent_refresh_token_id IS NULL OR parent_refresh_token_id <> id
  ),
  CONSTRAINT oauth_refresh_tokens_scopes_nonempty CHECK (
    cardinality(scopes) > 0 AND array_position(scopes, NULL) IS NULL
  ),
  CONSTRAINT oauth_refresh_tokens_fixed_idle_window CHECK (
    expires_at = issued_at + interval '28800 seconds'
  ),
  CONSTRAINT oauth_refresh_tokens_status CHECK (status IN ('current', 'consumed', 'expired', 'revoked')),
  CONSTRAINT oauth_refresh_tokens_lifecycle CHECK (
    (status = 'current' AND consumed_at IS NULL AND revoked_at IS NULL) OR
    (status = 'consumed' AND consumed_at IS NOT NULL AND revoked_at IS NULL) OR
    (status IN ('expired', 'revoked') AND consumed_at IS NULL AND revoked_at IS NOT NULL)
  ),
  CONSTRAINT oauth_refresh_tokens_consumed_order CHECK (consumed_at IS NULL OR consumed_at >= issued_at),
  CONSTRAINT oauth_refresh_tokens_revoked_order CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_one_current_family_member
  ON oauth_refresh_tokens (oauth_refresh_token_family_id)
  WHERE status = 'current';

CREATE TABLE IF NOT EXISTS oauth_revocations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_type text NOT NULL,
  target_id text NOT NULL,
  oauth_client_id uuid REFERENCES oauth_clients(id) ON DELETE RESTRICT,
  oauth_resource_id uuid REFERENCES oauth_resources(id) ON DELETE RESTRICT,
  reason_code text NOT NULL,
  revoked_at timestamptz NOT NULL,
  expires_at timestamptz,
  CONSTRAINT oauth_revocations_idempotent_target UNIQUE (target_type, target_id),
  CONSTRAINT oauth_revocations_target_type CHECK (
    target_type IN ('access_token_jti', 'refresh_family', 'oauth_session', 'oauth_authorization')
  ),
  CONSTRAINT oauth_revocations_target_nonempty CHECK (btrim(target_id) <> ''),
  CONSTRAINT oauth_revocations_reason_nonempty CHECK (btrim(reason_code) <> ''),
  CONSTRAINT oauth_revocations_access_jti_expiry CHECK (
    (target_type = 'access_token_jti' AND expires_at IS NOT NULL AND expires_at > revoked_at) OR
    (target_type <> 'access_token_jti' AND expires_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_oauth_sessions_online_state
  ON oauth_sessions (status, idle_expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_families_online_state
  ON oauth_refresh_token_families (status, oauth_client_id, oauth_resource_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expiry_status
  ON oauth_refresh_tokens (expires_at, status);
CREATE INDEX IF NOT EXISTS idx_oauth_revocations_expiry
  ON oauth_revocations (expires_at)
  WHERE target_type = 'access_token_jti';
