-- Phase 9A.1: additive, dark OAuth-native entitlement storage. No legacy rows are rewritten.
-- Existing resource and authorization rows acquire legacy_bridge defaults.

ALTER TABLE oauth_resources
  ADD COLUMN entitlement_mode text NOT NULL DEFAULT 'legacy_bridge',
  ADD CONSTRAINT oauth_resources_entitlement_mode CHECK (entitlement_mode IN ('legacy_bridge', 'native'));

-- Direct mode mutation is forbidden in 9A.1. A later privileged, audited
-- transition may preserve the resource_id/audience after reconciling live state.
CREATE FUNCTION oauth_resource_mode_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.entitlement_mode <> OLD.entitlement_mode THEN
    RAISE EXCEPTION 'OAuth resource entitlement mode is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_resource_mode_guard_trigger
  BEFORE UPDATE OF entitlement_mode ON oauth_resources
  FOR EACH ROW EXECUTE FUNCTION oauth_resource_mode_guard();

ALTER TABLE oauth_resource_scopes
  ALTER COLUMN legacy_permission_key DROP NOT NULL;

-- This check cannot be a row CHECK because the mode is owned by oauth_resources.
CREATE FUNCTION oauth_resource_scope_mode_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource_mode text;
BEGIN
  SELECT entitlement_mode INTO resource_mode FROM oauth_resources WHERE id = NEW.oauth_resource_id FOR SHARE;
  IF resource_mode = 'legacy_bridge' AND NEW.legacy_permission_key IS NULL THEN
    RAISE EXCEPTION 'Legacy bridge scope requires an explicit permission key';
  END IF;
  IF resource_mode = 'native' AND NEW.legacy_permission_key IS NOT NULL THEN
    RAISE EXCEPTION 'Native scope cannot have a legacy permission key';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_resource_scope_mode_guard_trigger
  BEFORE INSERT OR UPDATE OF oauth_resource_id, legacy_permission_key ON oauth_resource_scopes
  FOR EACH ROW EXECUTE FUNCTION oauth_resource_scope_mode_guard();

CREATE FUNCTION oauth_legacy_binding_mode_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource_mode text;
BEGIN
  SELECT entitlement_mode INTO resource_mode FROM oauth_resources WHERE id = NEW.oauth_resource_id FOR SHARE;
  IF resource_mode <> 'legacy_bridge' THEN
    RAISE EXCEPTION 'Legacy tool binding requires a legacy bridge resource';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_legacy_binding_mode_guard_trigger
  BEFORE INSERT OR UPDATE OF oauth_resource_id ON oauth_resource_entitlement_bindings
  FOR EACH ROW EXECUTE FUNCTION oauth_legacy_binding_mode_guard();

CREATE TABLE oauth_native_human_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_resource_id uuid NOT NULL,
  oauth_scope_id uuid NOT NULL,
  user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  email_normalized citext,
  status text NOT NULL DEFAULT 'pending_user_link',
  valid_from timestamptz NOT NULL DEFAULT now(),
  valid_until timestamptz,
  created_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  revoked_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_native_grants_registered_scope_fk FOREIGN KEY (oauth_resource_id, oauth_scope_id)
    REFERENCES oauth_resource_scopes(oauth_resource_id, oauth_scope_id) ON DELETE RESTRICT,
  CONSTRAINT oauth_native_grants_status CHECK (status IN ('active', 'pending_user_link', 'expired', 'revoked')),
  CONSTRAINT oauth_native_grants_target CHECK (
    (status = 'pending_user_link' AND user_id IS NULL AND email_normalized IS NOT NULL) OR
    (status = 'active' AND user_id IS NOT NULL) OR
    (status IN ('expired', 'revoked') AND (user_id IS NOT NULL OR email_normalized IS NOT NULL))
  ),
  CONSTRAINT oauth_native_grants_email_normalized CHECK (
    email_normalized IS NULL OR
    (email_normalized::text = lower(btrim(email_normalized::text)) AND
     email_normalized::text ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$')
  ),
  CONSTRAINT oauth_native_grants_validity CHECK (valid_until IS NULL OR valid_until > valid_from),
  CONSTRAINT oauth_native_grants_revocation CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= created_at AND revoked_by_user_id IS NOT NULL) OR
    (status <> 'revoked' AND revoked_at IS NULL AND revoked_by_user_id IS NULL)
  )
);

-- Partial unique indexes are deliberately stronger than time-window overlap checks:
-- an active row must be marked expired/revoked before replacement is inserted.
CREATE UNIQUE INDEX oauth_native_grants_one_active_linked
  ON oauth_native_human_grants (user_id, oauth_resource_id, oauth_scope_id)
  WHERE status = 'active';
CREATE UNIQUE INDEX oauth_native_grants_one_pending_email
  ON oauth_native_human_grants (email_normalized, oauth_resource_id, oauth_scope_id)
  WHERE status = 'pending_user_link';
CREATE INDEX oauth_native_grants_linked_lookup
  ON oauth_native_human_grants (user_id, oauth_resource_id, oauth_scope_id, status);

-- Native grant rows may only target native resources. This remains dark: no runtime
-- or Admin writer is added in this phase.
CREATE FUNCTION oauth_native_grant_mode_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource_mode text;
BEGIN
  SELECT entitlement_mode INTO resource_mode FROM oauth_resources WHERE id = NEW.oauth_resource_id FOR SHARE;
  IF resource_mode <> 'native' THEN
    RAISE EXCEPTION 'Native grant requires a native resource';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_native_grant_mode_guard_trigger
  BEFORE INSERT OR UPDATE OF oauth_resource_id ON oauth_native_human_grants
  FOR EACH ROW EXECUTE FUNCTION oauth_native_grant_mode_guard();

CREATE FUNCTION oauth_native_grant_lifecycle_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.oauth_resource_id <> OLD.oauth_resource_id OR NEW.oauth_scope_id <> OLD.oauth_scope_id THEN
    RAISE EXCEPTION 'Native grant resource and scope are immutable';
  END IF;
  IF OLD.user_id IS NOT NULL AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    RAISE EXCEPTION 'Linked native grant principal is immutable';
  END IF;
  IF OLD.status IN ('revoked', 'expired') AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION 'Terminal native grant cannot be reactivated';
  END IF;
  IF OLD.status = 'active' AND NEW.status = 'pending_user_link' THEN
    RAISE EXCEPTION 'Linked native grant cannot become pending';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_native_grant_lifecycle_guard_trigger
  BEFORE UPDATE ON oauth_native_human_grants
  FOR EACH ROW EXECUTE FUNCTION oauth_native_grant_lifecycle_guard();

ALTER TABLE oauth_authorizations
  ADD COLUMN entitlement_source text NOT NULL DEFAULT 'legacy_bridge',
  ALTER COLUMN legacy_authorization_grant_id DROP NOT NULL,
  ADD CONSTRAINT oauth_authorizations_entitlement_source CHECK (
    (entitlement_source = 'legacy_bridge' AND legacy_authorization_grant_id IS NOT NULL) OR
    (entitlement_source = 'native' AND legacy_authorization_grant_id IS NULL)
  );

-- Compare source to the resource mode once, at issuance. Historical
-- authorizations retain their recorded source after a future controlled mode
-- transition. This also makes old-binary default inserts fail closed on native
-- resources because they default to legacy_bridge.
CREATE FUNCTION oauth_authorization_source_mode_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource_mode text;
BEGIN
  SELECT entitlement_mode INTO resource_mode FROM oauth_resources WHERE id = NEW.oauth_resource_id FOR SHARE;
  IF resource_mode IS NULL OR NEW.entitlement_source <> resource_mode THEN
    RAISE EXCEPTION 'OAuth authorization source does not match resource entitlement mode';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_authorization_source_mode_guard_trigger
  BEFORE INSERT ON oauth_authorizations
  FOR EACH ROW EXECUTE FUNCTION oauth_authorization_source_mode_guard();

CREATE FUNCTION oauth_authorization_provenance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.entitlement_source IS DISTINCT FROM OLD.entitlement_source OR
     NEW.oauth_resource_id IS DISTINCT FROM OLD.oauth_resource_id OR
     NEW.user_id IS DISTINCT FROM OLD.user_id OR
     NEW.granted_scopes IS DISTINCT FROM OLD.granted_scopes THEN
    RAISE EXCEPTION 'OAuth authorization entitlement provenance is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_authorization_provenance_guard_trigger
  BEFORE UPDATE OF entitlement_source, oauth_resource_id, user_id, granted_scopes ON oauth_authorizations
  FOR EACH ROW EXECUTE FUNCTION oauth_authorization_provenance_guard();

-- Historical evidence of which native grant rows justified an authorization.
-- Current entitlement must still be re-evaluated on refresh/introspection.
CREATE TABLE oauth_authorization_native_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  oauth_authorization_id uuid NOT NULL REFERENCES oauth_authorizations(id) ON DELETE RESTRICT,
  oauth_native_human_grant_id uuid NOT NULL REFERENCES oauth_native_human_grants(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT oauth_authorization_native_grants_unique UNIQUE (oauth_authorization_id, oauth_native_human_grant_id)
);

CREATE FUNCTION oauth_authorization_native_grant_pair_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE authorization_row record;
DECLARE grant_row record;
BEGIN
  SELECT entitlement_source, user_id, oauth_resource_id, granted_scopes
    INTO authorization_row FROM oauth_authorizations
    WHERE id = NEW.oauth_authorization_id FOR SHARE;
  SELECT g.user_id, g.oauth_resource_id, s.scope
    INTO grant_row FROM oauth_native_human_grants g
    JOIN oauth_scopes s ON s.id = g.oauth_scope_id
    WHERE g.id = NEW.oauth_native_human_grant_id FOR SHARE OF g, s;
  IF authorization_row.entitlement_source IS DISTINCT FROM 'native' OR
     grant_row.user_id IS NULL OR
     grant_row.user_id IS DISTINCT FROM authorization_row.user_id OR
     grant_row.oauth_resource_id IS DISTINCT FROM authorization_row.oauth_resource_id OR
     NOT (grant_row.scope = ANY(authorization_row.granted_scopes)) THEN
    RAISE EXCEPTION 'Native grant provenance does not match authorization';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER oauth_authorization_native_grant_pair_guard_trigger
  BEFORE INSERT OR UPDATE OF oauth_authorization_id, oauth_native_human_grant_id
  ON oauth_authorization_native_grants
  FOR EACH ROW EXECUTE FUNCTION oauth_authorization_native_grant_pair_guard();

CREATE INDEX oauth_authorization_native_grants_grant_lookup
  ON oauth_authorization_native_grants (oauth_native_human_grant_id, oauth_authorization_id);
