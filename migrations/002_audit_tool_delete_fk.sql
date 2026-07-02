-- Preserve audit log rows when a tool registration is deleted.
-- The denormalized tool_slug remains available for historical search/readability.
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_tool_id_fkey;
ALTER TABLE audit_logs
  ADD CONSTRAINT audit_logs_tool_id_fkey
  FOREIGN KEY (tool_id) REFERENCES tools(id) ON DELETE SET NULL;
