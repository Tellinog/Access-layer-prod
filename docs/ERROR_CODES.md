# ERROR_CODES.md

| Code | HTTP | Meaning |
|---|---:|---|
| `AUTH_INVALID_TOOL` | 400 | Tool slug not found or invalid |
| `AUTH_TOOL_DISABLED` | 403 | Tool exists but is not active |
| `AUTH_INVALID_RETURN_URL` | 400 | Return URL not allowed for tool |
| `AUTH_INVALID_STATE` | 400 | State missing, expired or mismatched |
| `AUTH_GOOGLE_CALLBACK_FAILED` | 401 | Google callback or code exchange failed |
| `AUTH_INVALID_GOOGLE_TOKEN` | 401 | ID token validation failed |
| `AUTH_EMAIL_NOT_VERIFIED` | 403 | Google email not verified |
| `AUTH_EXTERNAL_DOMAIN` | 403 | `hd` missing or not allowed |
| `AUTH_USER_DISABLED` | 403 | User disabled or suspended |
| `AUTH_NOT_AUTHORIZED_FOR_TOOL` | 403 | No active grant for tool |
| `AUTH_CODE_EXPIRED` | 400 | One-time code expired |
| `AUTH_CODE_ALREADY_USED` | 400 | One-time code already consumed |
| `TOOL_AUTH_FAILED` | 401 | Tool client authentication failed |
| `TOKEN_IN_QUERY_REJECTED` | 400 | Token-like credential was sent in query string |
| `TOKEN_INACTIVE` | 200 | Introspection token inactive |
| `ADMIN_FORBIDDEN` | 403 | Missing admin role |
| `ACCESS_REQUEST_NOT_FOUND` | 404 | Access request not found or not visible to admin |
| `ACCESS_REQUEST_NOT_PENDING` | 409 | Access request already reviewed or not actionable |
| `VALIDATION_ERROR` | 400 | Invalid request payload |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Unexpected error |
