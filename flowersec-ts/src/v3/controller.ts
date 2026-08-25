import type { ArtifactPathKindV3, CanonicalArtifactCandidateV3 } from "./artifact.js";
import { tlsPolicyDigestV3 } from "./artifact.js";
import {
  ConnectErrorV3,
  aggregateRetryDispositionsV3,
  type RetryDispositionV3,
  type TransportFailureV3,
} from "./security.js";

const WALL_CLOCK_RECHECK_MILLISECONDS = 1_000;

export type CandidateFailureV3 = Readonly<{
  candidate: CanonicalArtifactCandidateV3;
  failure: TransportFailureV3;
  disposition?: RetryDispositionV3;
}>;

export class ControllerCycleStateV3 {
  readonly #maximumAttempts: number;
  #attempts = 0;
  #consecutiveFailures = 0;
  #replacementUsed = false;
  readonly #blockedPinPolicies = new Map<string, Set<string>>();
  readonly #securityLockedEndpoints = new Set<string>();
  #securityPolicyTrigger = false;
  #opaquePolicyTrigger = false;

  constructor(maximumAttempts = 0) {
    if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 0) {
      throw new RangeError("maximumAttempts must be a non-negative safe integer");
    }
    this.#maximumAttempts = maximumAttempts;
  }

  beginAcquisition(): boolean {
    if (this.#maximumAttempts !== 0 && this.#attempts >= this.#maximumAttempts) return false;
    this.#attempts = saturatingControllerIncrementV3(this.#attempts);
    return true;
  }

  recordFailedAcquisitionOrLease(): number {
    this.#consecutiveFailures = Math.min(Number.MAX_SAFE_INTEGER, this.#consecutiveFailures + 1);
    return this.#consecutiveFailures;
  }

  claimReplacementQuota(): boolean {
    if (this.#replacementUsed) return false;
    this.#replacementUsed = true;
    return true;
  }

  blockPinPolicy(endpointKey: string, digest: string): void {
    const values = this.#blockedPinPolicies.get(endpointKey) ?? new Set<string>();
    values.add(digest);
    this.#blockedPinPolicies.set(endpointKey, values);
    this.#securityLockedEndpoints.add(endpointKey);
  }

  isBlocked(endpointKey: string, digest: string): boolean {
    return this.#blockedPinPolicies.get(endpointKey)?.has(digest) === true;
  }

  isSecurityLockedEndpoint(endpointKey: string): boolean {
    return this.#securityLockedEndpoints.has(endpointKey);
  }

  recordPolicyTrigger(opaque: boolean): void {
    if (opaque) this.#opaquePolicyTrigger = true;
    else this.#securityPolicyTrigger = true;
  }

  blockedPolicyTerminal(): ConnectErrorV3 {
    if (!this.#securityPolicyTrigger && !this.#opaquePolicyTrigger) {
      return new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
    }
    return new ConnectErrorV3(
      this.#securityPolicyTrigger ? "transport_security_failed" : "connection_failed",
      { kind: "terminal" },
    );
  }

  established(): void {
    this.#attempts = 0;
    this.#consecutiveFailures = 0;
    this.#replacementUsed = false;
    this.#blockedPinPolicies.clear();
    this.#securityLockedEndpoints.clear();
    this.#securityPolicyTrigger = false;
    this.#opaquePolicyTrigger = false;
  }

  snapshot() {
    return Object.freeze({
      attempts: this.#attempts,
      consecutiveFailures: this.#consecutiveFailures,
      replacementUsed: this.#replacementUsed,
    });
  }
}

export function saturatingControllerIncrementV3(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError("controller counter must be a non-negative safe integer");
  }
  return value === Number.MAX_SAFE_INTEGER ? value : value + 1;
}

export function endpointKeyV3(path: ArtifactPathKindV3, candidate: CanonicalArtifactCandidateV3): string {
  return `${candidate.carrier}\0${path}\0${candidate.normalized_url}`;
}

export function selectReplacementCandidatesV3(
  path: ArtifactPathKindV3,
  primary: readonly CanonicalArtifactCandidateV3[],
  replacement: readonly CanonicalArtifactCandidateV3[],
  triggerEndpointKeys: ReadonlySet<string>,
  failedEndpointKeys: ReadonlySet<string>,
  cycle: ControllerCycleStateV3,
): readonly CanonicalArtifactCandidateV3[] {
  const primaryByKey = new Map(primary.map((candidate) => [endpointKeyV3(path, candidate), candidate]));
  for (const key of triggerEndpointKeys) {
    const candidate = primaryByKey.get(key);
    if (candidate?.tls.mode === "pin") {
      cycle.blockPinPolicy(key, tlsPolicyDigestV3(candidate.tls).hashBase64URL);
    }
  }
  const eligible: CanonicalArtifactCandidateV3[] = [];
  let changedPin = false;
  for (const candidate of replacement) {
    const key = endpointKeyV3(path, candidate);
    const previous = primaryByKey.get(key);
    if (previous === undefined) {
      if (!blockedOrDowngraded(candidate, key, cycle)) eligible.push(candidate);
      continue;
    }
    if (triggerEndpointKeys.has(key)) {
      if (candidate.tls.mode !== "pin" || previous.tls.mode !== "pin") continue;
      const oldDigest = tlsPolicyDigestV3(previous.tls).hashBase64URL;
      const newDigest = tlsPolicyDigestV3(candidate.tls).hashBase64URL;
      if (oldDigest !== newDigest && !cycle.isBlocked(key, newDigest)) {
        changedPin = true;
        eligible.push(candidate);
      }
      continue;
    }
    if (!failedEndpointKeys.has(key) && !blockedOrDowngraded(candidate, key, cycle)) eligible.push(candidate);
  }
  return Object.freeze(changedPin ? eligible : []);
}

export function filterBlockedCandidatesV3(
  path: ArtifactPathKindV3,
  candidates: readonly CanonicalArtifactCandidateV3[],
  cycle: ControllerCycleStateV3,
): readonly CanonicalArtifactCandidateV3[] {
  return Object.freeze(candidates.filter((candidate) => !blockedOrDowngraded(
    candidate,
    endpointKeyV3(path, candidate),
    cycle,
  )));
}

export function aggregateCandidateFailuresV3(
  failures: readonly CandidateFailureV3[],
  policyRefreshExecutable: boolean,
): ConnectErrorV3 | "policy_refresh" {
  if (failures.some(({ failure }) => failure.code === "invalid_artifact")) {
    return new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  if (failures.some(({ failure }) => failure.code === "expired_artifact")) {
    return new ConnectErrorV3("expired_artifact", { kind: "retryable" });
  }
  const securityTriggers = failures.filter(({ failure, candidate }) =>
    isNativePolicyTriggerV3(candidate, failure));
  const opaqueTriggers = failures.filter(({ failure, candidate }) =>
    candidate.tls.mode === "pin" && failure.code === "connection_failed" &&
    failure.detail === "browser_pin_opaque");
  if (policyRefreshExecutable && (securityTriggers.length > 0 || opaqueTriggers.length > 0)) return "policy_refresh";
  if (securityTriggers.length > 0 || failures.some(({ failure }) => failure.code === "tls_failed")) {
    return new ConnectErrorV3("transport_security_failed", { kind: "terminal" });
  }
  if (opaqueTriggers.length > 0) return new ConnectErrorV3("connection_failed", { kind: "terminal" });
  if (failures.length > 0 && failures.every(({ failure }) => failure.code === "tls_unsupported")) {
    return new ConnectErrorV3("transport_security_unsupported", { kind: "terminal" });
  }
  const ordinary = failures.filter(({ failure }) => failure.code === "connection_failed");
  if (ordinary.length > 0) {
    return new ConnectErrorV3("connection_failed", aggregateRetryDispositionsV3(
      ordinary.map(({ disposition }) => disposition ?? { kind: "retryable" }),
    ));
  }
  return new ConnectErrorV3("connection_failed", { kind: "terminal" });
}

/** Records policy-refresh provenance at the A-result linearization point. */
export function blockPolicyRefreshTriggersV3(
  path: ArtifactPathKindV3,
  failures: readonly CandidateFailureV3[],
  cycle: ControllerCycleStateV3,
): ReadonlySet<string> {
  const triggerKeys = new Set<string>();
  for (const { candidate, failure } of failures) {
    if (!isPolicyTriggerV3(candidate, failure)) continue;
    cycle.recordPolicyTrigger(
      failure.code === "connection_failed" && failure.detail === "browser_pin_opaque",
    );
    const key = endpointKeyV3(path, candidate);
    triggerKeys.add(key);
    if (candidate.tls.mode === "pin") {
      cycle.blockPinPolicy(key, tlsPolicyDigestV3(candidate.tls).hashBase64URL);
    }
  }
  return triggerKeys;
}

function blockedOrDowngraded(
  candidate: CanonicalArtifactCandidateV3,
  endpointKey: string,
  cycle: ControllerCycleStateV3,
): boolean {
  if (cycle.isSecurityLockedEndpoint(endpointKey) && candidate.tls.mode === "ca") return true;
  if (candidate.tls.mode === "ca") return false;
  return cycle.isBlocked(endpointKey, tlsPolicyDigestV3(candidate.tls).hashBase64URL);
}

function isPolicyTriggerV3(
  candidate: CanonicalArtifactCandidateV3,
  failure: CandidateFailureV3["failure"],
): boolean {
  return isNativePolicyTriggerV3(candidate, failure) ||
    (candidate.tls.mode === "pin" && failure.code === "connection_failed" &&
      failure.detail === "browser_pin_opaque");
}

function isNativePolicyTriggerV3(
  candidate: CanonicalArtifactCandidateV3,
  failure: CandidateFailureV3["failure"],
): boolean {
  return candidate.tls.mode === "pin" && (
    failure.code === "tls_policy_expired" ||
    (failure.code === "tls_failed" &&
      (failure.detail === "pin_mismatch" || failure.detail === "unknown"))
  );
}

export type ControllerClockV3 = Readonly<{
  wallNowMilliseconds(): number;
  monotonicNowMilliseconds(): number;
  sleep(milliseconds: number, signal: AbortSignal): Promise<void>;
}>;

export class ControllerRetryWaitV3 {
  readonly #clock: ControllerClockV3;
  #waiting = false;
  #manual = false;
  #absoluteDeadline: number | undefined;
  #wake: (() => void) | undefined;

  constructor(clock: ControllerClockV3 = defaultControllerClockV3()) {
    this.#clock = clock;
  }

  retryNow(): boolean {
    if (!this.#waiting) return false;
    if (this.#absoluteDeadline !== undefined &&
        this.#clock.wallNowMilliseconds() < this.#absoluteDeadline) return false;
    this.#manual = true;
    this.#wake?.();
    return true;
  }

  async wait(
    disposition: RetryDispositionV3,
    consecutiveFailure: number,
    signal: AbortSignal,
  ): Promise<boolean> {
    const validated = validateControllerWaitDisposition(disposition);
    if (validated.kind === "terminal" || signal.aborted) return false;
    if (this.#waiting) throw new Error("Flowersec v3 retry wait is already active");
    const backoffDeadline = saturatingAddMilliseconds(
      this.#clock.monotonicNowMilliseconds(),
      controllerBackoffForWait(consecutiveFailure),
    );
    this.#waiting = true;
    this.#manual = false;
    this.#absoluteDeadline = validated.kind === "retry_after"
      ? validated.notBeforeUnixMilliseconds!
      : undefined;
    try {
      while (!signal.aborted) {
        const wallNow = this.#clock.wallNowMilliseconds();
        const monoNow = this.#clock.monotonicNowMilliseconds();
        const wallRemaining = this.#absoluteDeadline === undefined
          ? 0
          : saturatingDifferenceMilliseconds(this.#absoluteDeadline, wallNow);
        const monoRemaining = this.#manual ? 0 : saturatingDifferenceMilliseconds(backoffDeadline, monoNow);
        if (wallRemaining === 0 && monoRemaining === 0) return true;
        const delay = Math.max(1, Math.min(
          WALL_CLOCK_RECHECK_MILLISECONDS,
          ...(wallRemaining === 0 ? [] : [wallRemaining]),
          ...(monoRemaining === 0 ? [] : [monoRemaining]),
        ));
        await this.#sleepOrWake(delay, signal);
      }
      return false;
    } catch (error) {
      if (signal.aborted) return false;
      throw error;
    } finally {
      this.#waiting = false;
      this.#manual = false;
      this.#absoluteDeadline = undefined;
      this.#wake = undefined;
    }
  }

  async #sleepOrWake(milliseconds: number, signal: AbortSignal): Promise<void> {
    let wake!: () => void;
    const manual = new Promise<void>((resolve) => { wake = resolve; });
    this.#wake = wake;
    try {
      await Promise.race([this.#clock.sleep(milliseconds, signal), manual]);
    } finally {
      if (this.#wake === wake) this.#wake = undefined;
    }
  }
}

function saturatingAddMilliseconds(value: number, increment: number): number {
  if (!Number.isFinite(value) || !Number.isFinite(increment) || increment < 0) return Number.MAX_SAFE_INTEGER;
  if (value >= Number.MAX_SAFE_INTEGER - increment) return Number.MAX_SAFE_INTEGER;
  return value + increment;
}

function saturatingDifferenceMilliseconds(deadline: number, now: number): number {
  if (!Number.isFinite(deadline) || !Number.isFinite(now) || deadline <= now) return 0;
  const difference = deadline - now;
  return Number.isSafeInteger(difference) ? difference : Number.MAX_SAFE_INTEGER;
}

function validateControllerWaitDisposition(value: RetryDispositionV3): RetryDispositionV3 {
  if (value.kind === "terminal" || value.kind === "retryable") return value;
  if (value.kind !== "retry_after") {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  const deadline = value.notBeforeUnixMilliseconds ?? value.absoluteUnixMilliseconds;
  if (deadline === undefined || !Number.isSafeInteger(deadline) || deadline < 0 ||
      deadline > 253_402_300_799_999 || value.notBeforeUnixMilliseconds !== undefined &&
      value.absoluteUnixMilliseconds !== undefined &&
      value.notBeforeUnixMilliseconds !== value.absoluteUnixMilliseconds) {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  return Object.freeze({
    kind: "retry_after",
    notBeforeUnixMilliseconds: deadline,
    absoluteUnixMilliseconds: deadline,
  });
}

function controllerBackoffForWait(consecutiveFailure: number): number {
  if (!Number.isSafeInteger(consecutiveFailure) || consecutiveFailure < 1) {
    throw new RangeError("consecutive failure ordinal must be positive");
  }
  if (consecutiveFailure >= 8) return 30_000;
  return 250 * 2 ** (consecutiveFailure - 1);
}

function defaultControllerClockV3(): ControllerClockV3 {
  return Object.freeze({
    wallNowMilliseconds: Date.now,
    monotonicNowMilliseconds: () => Math.floor(performance.now()),
    sleep: async (milliseconds, signal) => await new Promise<void>((resolve, reject) => {
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }
      const timer = setTimeout(finish, milliseconds);
      const abort = () => {
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        reject(signal.reason);
      };
      function finish() {
        signal.removeEventListener("abort", abort);
        resolve();
      }
      signal.addEventListener("abort", abort, { once: true });
    }),
  });
}
