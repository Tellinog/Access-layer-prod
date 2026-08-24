# Changelog

## 2.1.0 — 2026-08-18

### Added

- Mandatory Coolify deployment contract for tools, platform services and infrastructure stacks.
- Explicit `project.kind` classification, including non-deployable `sdk_library` repositories.
- Local `deployment.registration.yaml` and central registry schemas.
- Domain, service, container-port, network, health, storage, backup and rollback declarations.
- Global collision checks for domains, Coolify resources and approved host ports.
- Documentation for the UNGUESS Platform SDK, central Observability Stack and Tool Observatory boundaries.
- `--registry` production conformance option and Coolify-aware bootstrap inputs.

### Changed

- Runtime projects are no longer deployment-platform neutral: Coolify is the required target.
- The ambiguous name "Platform Core" is replaced by **UNGUESS Platform SDK**.
- Container ports are explicitly reusable across resources; host ports are forbidden by default.
- Platform manifest schema is version 2.

### Compatibility

This release changes repository contracts and deployment documentation only. It does not alter Access Layer endpoints, sessions, grants, token semantics, product capabilities or deployed runtime behavior. Existing projects adopt the new deployment declarations additively.


## 2.0.0 — 2026-08-17

### Added

- Platform-level manifest and conformance tooling.
- Access Layer OAuth/OIDC target profile with legacy coexistence.
- Capability, API, MCP, monitoring and Tool Observatory contracts.
- English-first language requirements.
- AI Act readiness and AI governance evidence pack.
- UNGUESS Garden design tokens and accessible component demo.

### Changed

- Authentication, security, API, analytics and UI documents are no longer empty placeholders.
- The template remains application-stack neutral but now enforces shared platform contracts.

### Compatibility

The template explicitly preserves the currently deployed Access Layer `/v1/auth/*` protocol for existing tools. No forced migration is required.
