import type { RequestContext } from "./request-context.js";

export interface VerifiedContextAdapter {
  readonly profile: RequestContext["authProfile"];
  /** Detect only whether credentials for this profile are present. */
  hasCredentials(request: unknown): boolean;
  /** Validate present credentials. Invalid credentials must throw, not return null. */
  authenticate(request: unknown): Promise<RequestContext>;
}

/**
 * Select one explicit credential profile. This is coexistence, not fallback:
 * an invalid OAuth credential can never be rescued by a valid legacy cookie,
 * and a request carrying both profiles is rejected as ambiguous.
 */
export class DualAuthAdapter {
  constructor(
    private readonly legacy: VerifiedContextAdapter | null,
    private readonly oauth: VerifiedContextAdapter | null,
  ) {}

  async authenticate(request: unknown): Promise<RequestContext> {
    const candidates = [this.legacy, this.oauth].filter(
      (adapter): adapter is VerifiedContextAdapter => Boolean(adapter?.hasCredentials(request)),
    );

    if (candidates.length === 0) throw new Error("UNAUTHENTICATED");
    if (candidates.length > 1) throw new Error("AUTH_CREDENTIALS_AMBIGUOUS");

    const selected = candidates[0];
    const context = await selected.authenticate(request);
    if (context.authProfile !== selected.profile) throw new Error("AUTH_ADAPTER_PROFILE_MISMATCH");
    return context;
  }
}
