export interface HealthResponse {
  status: "ok" | "degraded" | "unavailable";
  service: string;
  release: string;
  timestamp: string;
}

export interface ReadinessDependency {
  name: string;
  required: boolean;
  ready: boolean;
}

export function liveness(service: string, release: string): HealthResponse {
  return {
    status: "ok",
    service,
    release,
    timestamp: new Date().toISOString(),
  };
}

export function readiness(
  service: string,
  release: string,
  dependencies: readonly ReadinessDependency[],
): HealthResponse {
  const requiredUnavailable = dependencies.some((item) => item.required && !item.ready);
  const optionalUnavailable = dependencies.some((item) => !item.required && !item.ready);
  return {
    status: requiredUnavailable ? "unavailable" : optionalUnavailable ? "degraded" : "ok",
    service,
    release,
    timestamp: new Date().toISOString(),
  };
}
