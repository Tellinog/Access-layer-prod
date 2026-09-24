-- Reference data examples. Adjust to real company tools.

INSERT INTO tools (slug, display_name, description, allowed_return_urls, owner_email)
VALUES (
  'access-admin',
  'Access Layer Admin',
  'Admin UI for Access Layer itself',
  '["https://access-layer.unguess-internal.net/admin/auth/callback", "http://localhost:8080/access-control/auth/callback"]'::jsonb,
  'lorenzo.prandi@unguess.io'
)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:tools:read', 'Read tool configuration' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:grants:write', 'Create and revoke grants' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:audit:read', 'Read audit logs' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:backup:read', 'Export encrypted backups' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:backup:write', 'Import encrypted backups' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:backup:secrets', 'Export restore secret material' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:oauth:read', 'Read OAuth P0 administrative configuration' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'admin:oauth:write', 'Manage OAuth P0 registrations, credentials and signing keys' FROM tools WHERE slug = 'access-admin'
ON CONFLICT DO NOTHING;
