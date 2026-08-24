# Observability

## Four distinct concerns

1. **Synthetic monitoring** — can the service and critical flow be reached?
2. **Technical observability** — where is latency or failure introduced?
3. **Product analytics** — who uses which capability, through which channel and with what outcome?
4. **Security audit** — who attempted or performed a protected operation and what policy decision was made?

They share identifiers but have different storage, cardinality, retention and
access controls.

## Three implementation layers

### Per-tool instrumentation

Every runtime project imports approved UNGUESS Platform SDK packages for:

- OpenTelemetry instrumentation;
- correlation and trace context;
- product-event envelopes;
- liveness/readiness helpers;
- bounded, non-blocking export.

This integration is implemented tool by tool because each tool owns its
capabilities and business events.

### UNGUESS Observability Stack

One central `infrastructure_stack` is deployed as its own Coolify resource. It
contains the OpenTelemetry Collector and the selected metrics, trace and log
backends. Projects send technical telemetry to its OTLP endpoint.

The stack is not duplicated for each tool. It is private by default and is not
the product analytics UI.

### Tool Observatory

Tool Observatory is a separate `tool` with its own Coolify deployment, domain,
Access Layer integration and application database. It combines:

- deployment/capability registry data;
- product events;
- synthetic results;
- aggregated technical signals and links to trace/log drill-down;
- Access Layer entitlement aggregates.

It does not replace the central Collector or raw technical telemetry stores.

## OpenTelemetry baseline

Instrument:

- inbound web/API/MCP requests;
- application-service calls;
- queue and job lifecycle;
- database and approved outbound dependencies;
- AI provider calls without content;
- event-export attempts.

Required resource attributes:

- `service.name` = project slug or declared component service name;
- `service.version` = release identifier;
- `deployment.environment.name`;
- owner/team where collector policy permits it.

Required dimensions remain low-cardinality:

- project;
- capability;
- invocation channel;
- outcome/status class;
- release;
- dependency/provider/model where approved.

## Trace propagation

Propagate W3C `traceparent` and `tracestate` across Agent Gateway, project
services and dependencies. Generate and return a safe correlation ID even when
no trace is sampled.

Never trust incoming trace fields as identity or authorization data.

## Health endpoints

- `/health/live`: process can serve requests; no deep dependency checks.
- `/health/ready`: required dependencies and migrations are ready; response is bounded and reveals no credentials.
- authenticated smoke capability: optional and registered centrally.

Coolify health checks target the internal container port. A public service must
listen on `0.0.0.0` so the proxy and health path can reach it as configured.

## Synthetic monitoring

Synthetic checks are declared in `project.platform.yaml`. Central monitoring
discovers them from the deployment/capability registry instead of hard-coding
every project endpoint.

Status views show availability, latency, p95 and sample count, degradation and
flapping. The existing Internal Network monitoring concepts are a reference
baseline, not the full product-usage system.

## Failure isolation

Telemetry exporters use bounded queues, batching and timeouts. Export failure
is logged at a controlled rate and must not fail the completed business
operation.

An Observability Stack outage may delay technical signals. A Tool Observatory
outage may delay analytics. Neither outage makes Nancy, Petyr, Goodman, Test
Generator or another source tool unavailable.
# Access Layer adoption status

The platform observability model below is a target standard, not current implementation. Current evidence is structured application logging, correlation IDs, database audit logs and `GET /health`. OpenTelemetry, OTLP, UNGUESS Platform SDK instrumentation, Tool Observatory registration and synthetic monitor deployment are not implemented in Step 1; see `../specs/telemetry.v1.yml`.
