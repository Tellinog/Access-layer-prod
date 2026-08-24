import { randomUUID } from "node:crypto";

import type { RequestContext } from "./request-context.js";

const FORBIDDEN = new Set([
  "email",
  "google_sub",
  "principal_id",
  "access_token",
  "refresh_token",
  "authorization_code",
  "client_secret",
  "cookie",
  "prompt",
  "raw_prompt",
  "raw_input",
  "raw_output",
  "document_content",
]);

export interface TelemetrySink {
  enqueue(event: Readonly<Record<string, unknown>>): Promise<void>;
}

export function emitCapabilityCompleted(
  sink: TelemetrySink,
  context: RequestContext,
  release: string,
  featureId: string,
  durationMs: number,
  actorPseudonym: string | null,
  dimensions: Readonly<Record<string, string | number | boolean | null>> = {},
): void {
  if (!context.capabilityId) throw new Error("TELEMETRY_CAPABILITY_REQUIRED");
  for (const key of Object.keys(dimensions)) {
    if (FORBIDDEN.has(key.toLowerCase())) {
      throw new Error("TELEMETRY_FORBIDDEN_DIMENSION");
    }
  }

  const event = {
    specversion: "1.0",
    id: `evt_${randomUUID()}`,
    type: "capability.completed",
    source: context.projectSlug,
    time: new Date().toISOString(),
    subject: context.capabilityId,
    datacontenttype: "application/json",
    data: {
      event_version: 1,
      project_slug: context.projectSlug,
      environment: context.environment,
      release,
      capability_id: context.capabilityId,
      feature_id: featureId,
      outcome: "success",
      reason_code: null,
      actor_type: context.principalType,
      actor_id: actorPseudonym,
      client_id: context.clientId,
      invocation_channel: context.invocationChannel,
      access_session_id: context.accessSessionId,
      authorization_grant_id: context.authorizationGrantId,
      correlation_id: context.correlationId,
      trace_id: context.traceId,
      duration_ms: durationMs,
      work_units: null,
      cost: null,
      dimensions,
    },
  } as const;

  // A production sink uses a bounded queue. Observatory failure never changes
  // the business response. Queue saturation must be counted locally.
  void sink.enqueue(event).catch(() => undefined);
}
