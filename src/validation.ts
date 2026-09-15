export const TOOL_SLUG_REGEX = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/;
export const PERMISSION_KEY_REGEX = /^[a-z0-9-]+(?::[a-z0-9-]+)+$/;

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function validateEmail(email: string): boolean {
  return email.length <= 320 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isAllowedPendingGrantEmail(email: string, ...allowedDomainGroups: string[][]): boolean {
  if (!validateEmail(email)) {
    return false;
  }
  const domain = email.slice(email.lastIndexOf("@") + 1).toLowerCase();
  return allowedDomainGroups.some((allowedDomains) => allowedDomains.includes(domain));
}

export function validateToolSlug(slug: string): boolean {
  return TOOL_SLUG_REGEX.test(slug);
}

export function validatePermissionKey(permission: string): boolean {
  return PERMISSION_KEY_REGEX.test(permission);
}

export function validateState(state: string): boolean {
  return state.length >= 16 && state.length <= 512 && /^[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+$/.test(state);
}

export function validateReturnUrlExact(
  returnUrl: string,
  allowedReturnUrls: string[],
  allowedSchemes: string[]
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(returnUrl);
  } catch {
    return false;
  }

  if (parsed.username || parsed.password) {
    return false;
  }

  if (parsed.protocol === "http:") {
    const host = parsed.hostname.toLowerCase();
    const localOnly = host === "localhost" || host === "127.0.0.1" || host === "::1";
    if (!allowedSchemes.includes("http") || !localOnly) {
      return false;
    }
  } else if (parsed.protocol !== "https:" || !allowedSchemes.includes("https")) {
    return false;
  }

  return allowedReturnUrls.some((allowed) => {
    try {
      const allowedParsed = new URL(allowed);
      return parsed.href === allowedParsed.href;
    } catch {
      return false;
    }
  });
}

export function validatePermissions(permissions: string[]): boolean {
  return permissions.every(validatePermissionKey);
}

export function isAllowedHostedDomain(hd: string | undefined | null, allowedHd: string[]): boolean {
  if (!hd) {
    return false;
  }
  return allowedHd.includes(hd.toLowerCase());
}
