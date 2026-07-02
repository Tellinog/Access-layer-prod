-- Access Layer Google SSO v1 baseline schema.
-- The schema intentionally stores opaque secrets, codes and refresh tokens as hashes only.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  google_sub text NOT NULL UNIQUE,
  email citext NOT NULL,
  email_normalized citext NOT NULL,
  email_verified boolean NOT NULL DEFAULT false,
  hd text NOT NULL,
  display_name text,
  picture_url text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'disabled')),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tools (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE,
  display_name text NOT NULL,
  description text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'maintenance')),
  allowed_return_urls jsonb NOT NULL DEFAULT '[]'::jsonb,
  owner_email citext,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tool_clients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  client_id text NOT NULL UNIQUE,
  client_secret_hash text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'rotating')),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS tool_permissions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  permission_key text NOT NULL,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tool_id, permission_key)
);

CREATE TABLE IF NOT EXISTS authorization_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  email_normalized citext,
  role text NOT NULL,
  permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'pending_user_link')),
  valid_from timestamptz NOT NULL DEFAULT now(),
  valid_until timestamptz,
  created_by_user_id uuid REFERENCES users(id),
  revoked_by_user_id uuid REFERENCES users(id),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (user_id IS NOT NULL OR email_normalized IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS admin_tool_assignments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  created_by_user_id uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, tool_id)
);

CREATE TABLE IF NOT EXISTS auth_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state_hash text NOT NULL UNIQUE,
  nonce_hash text NOT NULL,
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  tool_slug text NOT NULL,
  return_url text NOT NULL,
  tool_state text NOT NULL,
  tool_state_hash text NOT NULL,
  login_hint citext,
  correlation_id text NOT NULL,
  request_ip_hash text,
  user_agent_hash text,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  tool_slug text NOT NULL,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  google_sub text,
  email citext NOT NULL,
  email_normalized citext NOT NULL,
  hd text NOT NULL,
  display_name text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'closed', 'expired')),
  reason_code text NOT NULL DEFAULT 'AUTH_NOT_AUTHORIZED_FOR_TOOL',
  attempts_count integer NOT NULL DEFAULT 1 CHECK (attempts_count > 0),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  last_correlation_id text NOT NULL,
  request_ip_hash text,
  user_agent_hash text,
  reviewed_by_user_id uuid REFERENCES users(id),
  reviewed_at timestamptz,
  review_note text,
  grant_id uuid REFERENCES authorization_grants(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  grant_id uuid NOT NULL REFERENCES authorization_grants(id),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  last_seen_at timestamptz
);

CREATE TABLE IF NOT EXISTS one_time_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash text NOT NULL UNIQUE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_id uuid NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
  grant_id uuid NOT NULL REFERENCES authorization_grants(id),
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  return_url text NOT NULL,
  correlation_id text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text NOT NULL UNIQUE,
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id text NOT NULL UNIQUE,
  event_type text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'error', 'info')),
  correlation_id text NOT NULL,
  tool_id uuid REFERENCES tools(id),
  tool_slug text,
  actor_user_id uuid REFERENCES users(id),
  actor_google_sub text,
  actor_email citext,
  actor_hd text,
  request_ip_hash text,
  user_agent_hash text,
  reason_code text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_users_email_normalized ON users(email_normalized);
CREATE INDEX IF NOT EXISTS idx_tools_slug ON tools(slug);
CREATE INDEX IF NOT EXISTS idx_tool_clients_tool_status ON tool_clients(tool_id, status);
CREATE INDEX IF NOT EXISTS idx_tool_permissions_tool ON tool_permissions(tool_id);
CREATE INDEX IF NOT EXISTS idx_grants_tool_user ON authorization_grants(tool_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_grants_tool_email ON authorization_grants(tool_id, email_normalized, status);
CREATE INDEX IF NOT EXISTS idx_auth_requests_expires ON auth_requests(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_access_requests_pending_unique ON access_requests(tool_id, email_normalized) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_access_requests_status_last_seen ON access_requests(status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_requests_tool ON access_requests(tool_slug, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_requests_email ON access_requests(email_normalized, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_one_time_codes_expires ON one_time_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_tool ON sessions(user_id, tool_id, status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id, status);
CREATE INDEX IF NOT EXISTS idx_admin_tool_assignments_user ON admin_tool_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_logs(tool_slug, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor_email ON audit_logs(actor_email, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor_sub ON audit_logs(actor_google_sub, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_logs(outcome, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_logs(correlation_id);
