# ANALYTICS.md

## Scope

This project does not track product analytics for user behavior. It tracks security and operational metrics derived from audit events.

## Metrics

| Metric | Source | Purpose |
|---|---|---|
| Login requests per tool | `auth.requested` | Capacity and adoption |
| Successful access per tool | `auth.allowed` | Usage visibility |
| Denied external domain | `auth.denied.external_domain` | Security monitoring |
| Denied no grant | `auth.denied.no_grant` | Access request demand |
| Invalid return URL attempts | `auth.denied.invalid_return_url` | Misconfiguration/attack detection |
| Token exchange failures | `token.exchange.denied` | Integration/security monitoring |
| Successful active-session renewals | `token.refreshed` | Session continuity and tool migration monitoring |
| Refresh failures | `token.refresh.denied` | Expiry, replay, integration and authorization monitoring |
| Admin grant changes | `admin.grant.*` | Change tracking |

Steps 3C–3E can derive dark/local authorization, exchange, refresh, replay, revocation and introspection metrics only when OAuth is explicitly enabled in an isolated environment. The protocol routes remain absent under the default-false production posture. D-047 registration/key-management audit events may exist while the protocol is disabled; metrics may count their action/outcome and stable public client/resource/scope/`kid` dimensions, never credentials, hashes, private references, tokens, codes, state, nonce, PKCE, email or subject.

## Dashboards

Recommended filters:

- time range;
- tool slug;
- outcome;
- reason code;
- actor email;
- IP hash;
- correlation ID.

## Data minimization

Analytics must not include tokens, secrets, raw cookies or business payloads from tools.

## Access request metrics

| Metric | Event/source | Purpose |
|---|---|---|
| Pending access requests per tool | `access_requests.status=pending` | Admin workload |
| New access requests | `access_request.created` | Demand signal |
| Repeated unauthorized attempts | `access_request.repeated` | User friction/spam signal |
| Approval rate | `admin.access_request.approved` / created | Access governance |
| Rejection rate | `admin.access_request.rejected` / created | Security/governance review |
