/** Explicit deployment policy. No automatic probe runs unless configured. */
export interface V4AutomaticLivenessPolicy {
  readonly intervalMS: bigint;
  readonly submissionMS: bigint;
  readonly responseMS: bigint;
  readonly missThreshold: number;
}

/** Elapsed time includes SDK/provider queuing, starting at local acceptance.
 * A successful authenticated PONG may precede the local provider callback. */
export interface V4LivenessResult {
  readonly submitted: boolean;
  readonly complete: boolean;
  readonly elapsedMS: bigint | null;
}
export type V4LivenessFailure = "canceled" | "timeout" | "closed" | "rekey_in_progress" |
  "resource_exhausted" | "time_unavailable" | "provider_failed" | "local_stall";
export class V4LivenessError extends Error {
  readonly result: V4LivenessResult;
  constructor(readonly code: V4LivenessFailure, result: V4LivenessResult) {
    super(code); this.name = "V4LivenessError";
    this.result = Object.freeze({ submitted: result.submitted, complete: result.complete, elapsedMS: result.elapsedMS });
  }
}
