# Legacy Compatibility Matrix

## D-045 temporary bridge addendum

| Surface | Temporary Microsoft behavior | Google/non-pilot guarantee |
|---|---|---|
| `/v1/auth/start` | Chooser only for slugs in `LEGACY_MICROSOFT_TOOL_SLUGS`; explicit `provider=microsoft` otherwise denied | Flag false or non-allowlisted/no-provider remains direct Google |
| Upstream state | Microsoft uses `mst_`; Google uses `gst_`; callback prefixes are mutually exclusive | Existing hash-only, single-use, expiring storage remains shared |
| Microsoft callback | Conditional `/v1/auth/microsoft/callback`; strict single-tenant validation | Google callback behavior and payload remain unchanged |
| Legacy identity | `google_sub=msft:<tid>:<oid>`, `hd=<validated-domain>` | Existing Google `sub` and `hd` remain untouched |
| Completion/token lifecycle | Same user, pending grant, grant, session, OTC, exchange, JWT, refresh, introspection, logout | No consumer, SDK, table, migration, TTL, cookie or payload change |
| Rollback | Set `LEGACY_MICROSOFT_ENABLED=false` and restart | Microsoft route/choice disappear; Google remains operational |

The frozen baseline file is not edited; `specs/legacy-microsoft-bridge.v1.yml` is the machine-readable exception.

This matrix freezes the repository-observed contract at commit `6e8221ade74591c23c3f9606f7d696ea2810d873`. The machine-readable source is `specs/legacy-contract-baseline.v1.json`.

| Surface | Frozen behavior | Step 1 evidence | Change |
|---|---|---|---|
| Public origin | `https://access-layer.unguess-internal.net` | production env/docs | None |
| Public API | current `/v1/*` route inventory | `src/app.ts`, baseline JSON | None |
| JWKS | RSA public key, `kid`, `use=sig`, `alg=RS256` | `src/token-service.ts` | None |
| Google callback | `/v1/auth/google/callback`, hashed state/nonce, one-time code redirect | `src/app.ts`, DB migration | None |
| Access JWT | RS256; issuer config; tool slug audience; Google sub subject; frozen custom claims | token service and goldens | None |
| Exchange | Basic-authenticated, single-use code; frozen response and no-cache headers | app and golden | None |
| Session | active/revoked/expired; server-side PostgreSQL record | app, repositories, migration | None |
| Refresh | optional, opaque hash-at-rest, single-use rotation, default 28,800 seconds | app, config, migration, golden | None |
| Logout | revokes the session and associated refresh tokens | app/repositories | None |
| Grant | role plus JSON permission array; unknown permission denied | permission spec and migration | None |
| Admin cookies | signed, HttpOnly, Secure in production, SameSite Lax, base-path scoped | app/config | None |
| Errors | stable JSON envelope and 22 code/status mappings; safe callback HTML | errors source and baseline JSON | None |
| Database | 11 tables and two existing migrations; audit tool FK uses `ON DELETE SET NULL` | migrations and baseline JSON | None |
| OpenAPI drift | secret-material runtime route absent from historical OpenAPI | app/OpenAPI comparison | Frozen and documented |
| Compose state | volume reference/declaration mismatch | `docker-compose.yaml` | Blocked; unchanged |

The baseline deliberately records actual behavior even where a current document is incomplete. It creates no new endpoint, permission, status, claim, field, TTL, cookie or table.
