# Tool Observatory Contract

## Classification

Tool Observatory is a user-facing `tool`, not the technical telemetry
infrastructure. It has its own repository, Coolify resource, canonical domain,
Access Layer integration, API, database and Garden UI.

## Purpose

Provide a dedicated cross-tool catalogue and management view for technical
health, adoption, usage, outcomes, AI cost and compliance readiness.

## Data sources

- central deployment registry and project capability manifests;
- aggregated metrics and trace/log links from the UNGUESS Observability Stack;
- versioned product events submitted by tools;
- Access Layer entitlement/grant aggregates;
- synthetic monitoring results;
- release and ownership metadata.

Tool Observatory must not ingest unrestricted raw application logs, prompts or
business payloads by default.

## Required views

### Management

- active and returning users;
- active users versus users with grant;
- adoption by team and project;
- usage by capability and channel;
- outcome and failure rate;
- cost and work units where applicable;
- unused or underused capabilities.

### Technical

- availability and status transitions;
- p50/p95/p99 with sample counts;
- error/timeout/retry rate;
- dependency and queue latency;
- release comparison and error budget;
- links from an aggregate/event to the authorised technical backend view.

### Deployment catalogue

- owner and project kind;
- Coolify server/project/environment/resource;
- canonical route and internal target service/port;
- health endpoints;
- stateful/backup status;
- registry verification state;
- no display of secret environment variables.

### Audit/security

Identifiable drill-down is separately permissioned and not part of normal
management analytics.

## Interoperability

- OpenAPI for machine access;
- read-only MCP capabilities for approved management agents;
- CSV, JSON and Parquet exports;
- versioned event and export schemas;
- approved read-only iframe routes for UNGUESS Internal Network.

The iframe is a presentation channel, not the integration contract. Use exact
`frame-ancestors` allowlists and never put tokens in query strings.

## Independence

Tool Observatory is never called synchronously to authorise or complete another
tool's business request. It may ingest the Git deployment registry, but the
registry remains the declared deployment source of truth until an approved ADR
changes that model.
