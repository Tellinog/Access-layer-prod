-- Local development example only. Do not run in production without changes.

INSERT INTO tools (slug, display_name, description, allowed_return_urls, owner_email)
VALUES (
  'crm',
  'CRM interno',
  'Example internal CRM tool',
  '["https://crm.draftapps.it/auth/callback", "http://localhost:3000/auth/callback"]'::jsonb,
  'crm-owner@unguess.io'
)
ON CONFLICT (slug) DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'crm:read', 'Read CRM data' FROM tools WHERE slug = 'crm'
ON CONFLICT DO NOTHING;

INSERT INTO tool_permissions (tool_id, permission_key, description)
SELECT id, 'crm:write', 'Write CRM data' FROM tools WHERE slug = 'crm'
ON CONFLICT DO NOTHING;

INSERT INTO authorization_grants (tool_id, email_normalized, role, permissions, status)
SELECT id, 'mario.rossi@unguess.io', 'tool_user', '["crm:read"]'::jsonb, 'pending_user_link'
FROM tools WHERE slug = 'crm'
ON CONFLICT DO NOTHING;
