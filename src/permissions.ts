export const PLATFORM_ADMIN_PERMISSIONS = [
  "admin:tools:read",
  "admin:tools:write",
  "admin:users:read",
  "admin:users:write",
  "admin:grants:read",
  "admin:grants:write",
  "admin:access_requests:read",
  "admin:access_requests:write",
  "admin:audit:read",
  "admin:backup:read",
  "admin:backup:write",
  "admin:backup:secrets",
  "admin:secrets:rotate"
];

export const TOOL_ADMIN_PERMISSIONS = [
  "admin:tools:read_assigned",
  "admin:grants:read_assigned",
  "admin:grants:write_assigned",
  "admin:access_requests:read_assigned",
  "admin:access_requests:write_assigned",
  "admin:audit:read_assigned"
];

export const AUDITOR_PERMISSIONS = [
  "admin:audit:read",
  "admin:tools:read",
  "admin:users:read",
  "admin:grants:read",
  "admin:access_requests:read"
];

export function rolePermissions(role: string): string[] {
  if (role === "platform_admin") return PLATFORM_ADMIN_PERMISSIONS;
  if (role === "tool_admin") return TOOL_ADMIN_PERMISSIONS;
  if (role === "auditor") return AUDITOR_PERMISSIONS;
  return [];
}

export function hasPermission(permissions: string[], required: string): boolean {
  return permissions.includes(required);
}

export function hasAnyPermission(permissions: string[], required: string[]): boolean {
  return required.some((permission) => permissions.includes(permission));
}
