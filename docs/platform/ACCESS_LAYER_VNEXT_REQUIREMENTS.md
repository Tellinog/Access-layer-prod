# Access Layer vNext requirements

Status: platform target, not implemented by individual projects

## Functional requirements

| ID | Priority | Requirement |
|---|---|---|
| AS-FR-001 | P0 | Continue serving the frozen `access-layer-legacy-v1` contract. |
| AS-FR-002 | P0 | Expose OAuth authorization-server metadata and versioned OAuth endpoints. |
| AS-FR-003 | P0 | Support Authorization Code with mandatory PKCE `S256`. |
| AS-FR-004 | P0 | Support public and confidential clients. |
| AS-FR-005 | P0 | Register clients separately from resource servers. |
| AS-FR-006 | P0 | Issue one-resource, audience-bound access tokens. |
| AS-FR-007 | P0 | Compute scopes as the intersection of request, client allowance, resource support, entitlement and policy. |
| AS-FR-008 | P0 | Rotate refresh tokens and detect token-family replay. |
| AS-FR-009 | P0 | Provide protected revocation and introspection endpoints. |
| AS-FR-010 | P0 | Rotate signing keys without invalidating still-valid tokens. |
| AS-FR-011 | P0 | Pre-register first-party clients, resources and scopes through controlled administration. |
| AS-FR-012 | P1 | Support service principals and client credentials. |
| AS-FR-013 | P1 | Support OIDC discovery, ID tokens and UserInfo for standard web login. |
| AS-FR-014 | P1 | Support Client ID Metadata Documents for approved remote MCP clients. |
| AS-FR-015 | P1 | Support downscoped token exchange with subject/actor separation for Agent Gateway. |

## Security requirements

| ID | Priority | Requirement |
|---|---|---|
| AS-SEC-001 | P0 | Reject wildcard or partial redirect matching. |
| AS-SEC-002 | P0 | Reject implicit, password and PKCE `plain` flows. |
| AS-SEC-003 | P0 | Never place access, refresh or authorization tokens in query strings or logs. |
| AS-SEC-004 | P0 | Bind authorization codes to client, redirect URI, resource, scope, subject and PKCE challenge; consume atomically once. |
| AS-SEC-005 | P0 | Hash opaque codes and refresh tokens at rest. |
| AS-SEC-006 | P0 | Enforce issuer, audience, token type, expiry and algorithm allowlists. |
| AS-SEC-007 | P0 | Rate-limit and audit security-sensitive endpoints. |
| AS-SEC-008 | P0 | Protect metadata-document retrieval from SSRF, DNS rebinding and oversized/redirecting responses. |
| AS-SEC-009 | P1 | Keep client, subject and actor identities distinct in delegation. |
| AS-SEC-010 | P1 | Permit token exchange only for registered client-resource policies and only with downscoping. |

The frozen P0 contract is `../../specs/oauth-p0.v1.yml`; P0 human `sub` is Google `sub`, authorization responses include RFC 9207 `iss`, access tokens use `typ=at+jwt`, and OAuth signing keys are isolated from legacy keys.

## Compatibility requirements

| ID | Priority | Requirement |
|---|---|---|
| AS-COMP-001 | P0 | Deployment requires no change to any current consumer. |
| AS-COMP-002 | P0 | Active legacy sessions, refresh tokens, JWTs, callbacks, grants and client credentials survive upgrade. |
| AS-COMP-003 | P0 | Legacy endpoint paths, payloads, error envelopes and token claims remain unchanged. |
| AS-COMP-004 | P0 | New OAuth state is stored additively; no initial in-place reinterpretation of legacy protocol records. |
| AS-COMP-005 | P0 | OAuth/OIDC can be disabled independently and without data loss. |
| AS-COMP-006 | P0 | Database migrations support application rollback for the agreed release window. |
| AS-COMP-007 | P0 | Current consumer contract suites run in Access Layer CI. |
| AS-COMP-008 | P0 | Version N supports current legacy integrations and supported SDK versions N and N-1. |

## Non-functional requirements

| ID | Priority | Requirement |
|---|---|---|
| AS-NFR-001 | P0 | Run at least two stateless application replicas in production. |
| AS-NFR-002 | P0 | Store protocol state in transactional shared storage; do not depend on per-replica memory. |
| AS-NFR-003 | P0 | Provide liveness, readiness, dependency and synthetic checks. |
| AS-NFR-004 | P0 | Define stricter availability and recovery objectives than normal tools. |
| AS-NFR-005 | P0 | Correlate authorization, token and audit events without logging secret material. |
| AS-NFR-006 | P0 | Verify backup, restore and key-recovery runbooks. |
| AS-NFR-007 | P0 | Support zero-downtime signing-key rotation. |
| AS-NFR-008 | P0 | Provide operational dashboards and alerts for failures, replay, revocation, latency and key state. |

## Acceptance evidence

The platform team maintains protocol conformance tests, current-consumer end-to-end tests, threat model, security review, penetration-test findings, load results, backup/restore evidence and a signed production-readiness record.
