# UNGUESS Observability Stack Contract

## Definition

The UNGUESS Observability Stack is one central `infrastructure_stack` deployed
as its own Coolify resource. It is not implemented separately inside every
tool.

Each tool is instrumented through the UNGUESS Platform SDK. The central stack
receives and stores the resulting technical telemetry.

```text
Tool instrumentation
  |- OpenTelemetry SDK
  |- correlation and trace context
  |- health endpoints
  `- non-blocking product-event emitter
             |
             v
UNGUESS Observability Stack
  |- OpenTelemetry Collector
  |- metrics backend
  |- trace backend
  `- log backend
             |
             v
Tool Observatory
  |- catalogue and management views
  |- aggregated health/performance
  |- product adoption and outcomes
  `- links to technical drill-down
```

## Separation of responsibilities

### Every tool

- creates low-cardinality technical telemetry;
- exposes liveness/readiness;
- emits versioned product events asynchronously;
- continues operating when telemetry export is unavailable.

### UNGUESS Observability Stack

- exposes the central OTLP endpoint;
- applies filtering, redaction, batching, sampling and routing;
- stores or forwards metrics, traces and logs;
- keeps operational backends private by default;
- is deployed and backed up independently from product tools.

### Tool Observatory

- owns the user-facing catalogue and management analytics;
- stores product-event and registry data;
- reads aggregated technical signals or links to technical backends;
- does not replace the OpenTelemetry Collector or raw telemetry stores;
- is not on the synchronous request path of other tools.

## Coolify topology

The stack is a separate multi-container Coolify resource. It may expose a
private OTLP endpoint to other resources through an approved shared network or
an authenticated HTTPS endpoint. Storage containers do not receive public
routes or host-port mappings by default.

The gateway Collector pattern gives projects one controlled OTLP endpoint and
centralises filtering and credentials. The final backend products and retention
periods remain platform decisions and must be recorded before production.

## Failure isolation

A collector or backend outage must not fail a completed business operation.
SDK exporters use bounded queues, timeouts and controlled retry. Tool
Observatory may show delayed or incomplete telemetry, but the source tool
remains available.

## Official implementation reference

- OpenTelemetry Collector gateway pattern: <https://opentelemetry.io/docs/collector/deploy/gateway/>
