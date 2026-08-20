import {
  canonicalizeCandidatesV3,
  validateArtifactV3,
  type ArtifactV3,
  type CanonicalArtifactCandidateV3,
} from "./artifact.js";
import {
  artifactLeaseStateV3,
  claimArtifactLeaseV3,
  claimedArtifactV3,
  retireArtifactLeaseV3,
  type ArtifactLeaseV3,
  type ClaimedArtifactLeaseV3,
} from "./artifactLease.js";
import {
  ControllerCycleStateV3,
  ControllerRetryWaitV3,
  aggregateCandidateFailuresV3,
  blockPolicyRefreshTriggersV3,
  endpointKeyV3,
  filterBlockedCandidatesV3,
  selectReplacementCandidatesV3,
  type CandidateFailureV3,
  type ControllerClockV3,
} from "./controller.js";
import {
  ConnectErrorV3,
  validateRetryDispositionV3,
  type RetryDispositionV3,
} from "./security.js";
import {
  validateRuntimeCapabilityDescriptorV3,
  type RuntimeCapabilityDescriptorV3,
} from "./capability.js";

export type ArtifactSourceResultV3 =
  | Readonly<{ kind: "lease"; lease: ArtifactLeaseV3 }>
  | Readonly<{ kind: "failure"; code: string; disposition: RetryDispositionV3 }>;

const ARTIFACT_SOURCE_FAILURE_CODES_V3 = new Set([
  "artifact_invalid",
  "connection_failed",
  "expired_artifact",
]);

export type ArtifactSourceV3 = Readonly<{
  acquire(options: Readonly<{
    signal: AbortSignal;
    capability: RuntimeCapabilityDescriptorV3;
  }>): Promise<ArtifactSourceResultV3>;
}>;

export type ManagedSessionV3 = Readonly<{
  waitTermination(): Promise<Readonly<{ error: Error }>>;
  close(): Promise<void>;
}>;

export type LeaseAttemptContextV3 = Readonly<{
  kind: "primary" | "replacement";
  artifact: ArtifactV3;
  candidates: readonly CanonicalArtifactCandidateV3[];
  claim: ClaimedArtifactLeaseV3;
  signal: AbortSignal;
  capability: RuntimeCapabilityDescriptorV3;
  assertArtifactFresh(): void;
}>;

export type LeaseAttemptResultV3<Session extends ManagedSessionV3> =
  | Readonly<{ kind: "established"; session: Session }>
  | Readonly<{ kind: "candidate_failures"; failures: readonly CandidateFailureV3[] }>
  | Readonly<{ kind: "pre_spend_failure"; error: ConnectErrorV3 }>
  | Readonly<{ kind: "post_spend_failure"; error: ConnectErrorV3 }>;

export type LeaseConnectorV3<Session extends ManagedSessionV3> =
  (context: LeaseAttemptContextV3) => Promise<LeaseAttemptResultV3<Session>>;

export type ConnectionControllerStateV3 =
  | "idle"
  | "connecting"
  | "connected"
  | "waiting"
  | "failed"
  | "closed";

export type ConnectionControllerFailureV3 = Readonly<{
  phase: "artifact" | "connect" | "session";
  code: string;
}>;

export type ConnectionControllerSnapshotV3<Session extends ManagedSessionV3 = ManagedSessionV3> = Readonly<{
  state: ConnectionControllerStateV3;
  attempt: number;
  currentSession?: Session;
  failure?: ConnectionControllerFailureV3;
  retryDisposition?: RetryDispositionV3;
}>;

export type ConnectionControllerOptionsV3 = Readonly<{
  maximumAttempts?: number;
  clock?: ControllerClockV3;
  nowUnixSeconds?: () => number;
  capabilitySnapshot(): RuntimeCapabilityDescriptorV3;
  projectSessionFailure?: (error: Error) => ConnectErrorV3;
}>;

export class ConnectionControllerV3Error extends Error {
  constructor(
    readonly code: "failed" | "closed" | "canceled",
    readonly failure?: ConnectionControllerFailureV3,
    readonly retryDisposition?: RetryDispositionV3,
  ) {
    super(`Flowersec v3 connection controller stopped (code=${code})`);
    this.name = "ConnectionControllerError";
  }
}

export class ConnectionControllerV3<Session extends ManagedSessionV3 = ManagedSessionV3> {
  readonly #source: ArtifactSourceV3;
  readonly #connector: LeaseConnectorV3<Session>;
  readonly #maximumAttempts: number;
  readonly #nowUnixSeconds: () => number;
  readonly #retry: ControllerRetryWaitV3;
  readonly #capabilitySnapshot: () => RuntimeCapabilityDescriptorV3;
  readonly #projectSessionFailure: (error: Error) => ConnectErrorV3;
  readonly #lifetime = new AbortController();
  readonly #listeners = new Set<(snapshot: ConnectionControllerSnapshotV3<Session>) => void>();
  #cycle: ControllerCycleStateV3;
  #state: ConnectionControllerStateV3 = "idle";
  #session: Session | undefined;
  #failure: ConnectionControllerFailureV3 | undefined;
  #disposition: RetryDispositionV3 | undefined;
  #scheduler: Promise<void> | undefined;
  #closeOperation: Promise<void> | undefined;

  constructor(source: ArtifactSourceV3, connector: LeaseConnectorV3<Session>, options: ConnectionControllerOptionsV3) {
    if (source === null || typeof source !== "object" || typeof source.acquire !== "function") {
      throw new TypeError("Flowersec v3 artifact source must provide acquire()");
    }
    if (typeof connector !== "function") throw new TypeError("Flowersec v3 lease connector is required");
    const maximumAttempts = options.maximumAttempts ?? 0;
    if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 0) {
      throw new TypeError("maximumAttempts must be a non-negative safe integer");
    }
    this.#source = source;
    this.#connector = connector;
    this.#maximumAttempts = maximumAttempts;
    this.#cycle = new ControllerCycleStateV3(maximumAttempts);
    this.#nowUnixSeconds = options.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1_000));
    this.#retry = new ControllerRetryWaitV3(options.clock);
    if (typeof options.capabilitySnapshot !== "function") {
      throw new TypeError("Flowersec v3 capability snapshot factory is required");
    }
    this.#capabilitySnapshot = options.capabilitySnapshot;
    this.#projectSessionFailure = options.projectSessionFailure ?? (() =>
      new ConnectErrorV3("connection_failed", { kind: "terminal" }));
  }

  get state(): ConnectionControllerStateV3 { return this.#state; }
  get currentSession(): Session | undefined { return this.#state === "connected" ? this.#session : undefined; }
  get failure(): ConnectionControllerFailureV3 | undefined { return this.#failure; }

  start(): void {
    if (this.#state !== "idle") return;
    this.#scheduler = this.#run();
  }

  retryNow(): boolean {
    return this.#state === "waiting" && this.#retry.retryNow();
  }

  subscribe(listener: (snapshot: ConnectionControllerSnapshotV3<Session>) => void): () => void {
    if (typeof listener !== "function") throw new TypeError("connection listener must be a function");
    this.#listeners.add(listener);
    try {
      listener(this.#snapshot());
    } catch (error) {
      this.#listeners.delete(listener);
      throw error;
    }
    return () => { this.#listeners.delete(listener); };
  }

  async waitForSession(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<Session> {
    if (this.currentSession !== undefined) return this.currentSession;
    if (this.#state === "failed") {
      throw new ConnectionControllerV3Error("failed", this.#failure, this.#disposition);
    }
    if (this.#state === "closed") {
      throw new ConnectionControllerV3Error("closed", this.#failure, this.#disposition);
    }
    if (options.signal?.aborted === true) throw new ConnectionControllerV3Error("canceled");
    return await new Promise<Session>((resolve, reject) => {
      const finish = (session: Session | undefined, error?: ConnectionControllerV3Error) => {
        this.#listeners.delete(listener);
        options.signal?.removeEventListener("abort", canceled);
        session === undefined ? reject(error) : resolve(session);
      };
      const listener = (snapshot: ConnectionControllerSnapshotV3<Session>) => {
        if (snapshot.state === "connected" && snapshot.currentSession !== undefined) {
          finish(snapshot.currentSession);
        } else if (snapshot.state === "failed") {
          finish(undefined, new ConnectionControllerV3Error(
            "failed",
            snapshot.failure,
            snapshot.retryDisposition,
          ));
        } else if (snapshot.state === "closed") {
          finish(undefined, new ConnectionControllerV3Error(
            "closed",
            snapshot.failure,
            snapshot.retryDisposition,
          ));
        }
      };
      const canceled = () => finish(undefined, new ConnectionControllerV3Error("canceled"));
      this.#listeners.add(listener);
      options.signal?.addEventListener("abort", canceled, { once: true });
    });
  }

  close(): Promise<void> {
    if (this.#closeOperation !== undefined) return this.#closeOperation;
    const active = this.#session;
    this.#session = undefined;
    this.#disposition = undefined;
    this.#lifetime.abort(new ConnectionControllerV3Error("closed", this.#failure));
    this.#transition("closed");
    this.#closeOperation = Promise.allSettled([
      this.#scheduler ?? Promise.resolve(),
      active?.close() ?? Promise.resolve(),
    ]).then(() => undefined);
    return this.#closeOperation;
  }

  async #run(): Promise<void> {
    let next: "primary" | "replacement" = "primary";
    let pendingDisposition: RetryDispositionV3 | undefined;
    let replacementContext: Readonly<{
      artifact: ArtifactV3;
      candidates: readonly CanonicalArtifactCandidateV3[];
      failures: readonly CandidateFailureV3[];
      triggerKeys: ReadonlySet<string>;
      failedKeys: ReadonlySet<string>;
    }> | undefined;

    while (!this.#lifetime.signal.aborted) {
      if (pendingDisposition !== undefined) {
        this.#disposition = pendingDisposition;
        this.#transition("waiting");
        const continued = await this.#retry.wait(
          pendingDisposition,
          this.#cycle.snapshot().consecutiveFailures,
          this.#lifetime.signal,
        );
        if (!continued) return;
        pendingDisposition = undefined;
      }
      if (!this.#cycle.beginAcquisition()) {
        this.#forceTerminalDisposition();
        return;
      }
      this.#disposition = undefined;
      this.#transition("connecting");
      let capability: RuntimeCapabilityDescriptorV3;
      try {
        capability = this.#capabilitySnapshot();
        validateRuntimeCapabilityDescriptorV3(capability);
      } catch {
        this.#recordFailure("artifact", "artifact_invalid", { kind: "terminal" });
        return;
      }
      const acquisition = await this.#acquire(capability);
      if (this.#lifetime.signal.aborted) {
        if (acquisition.kind === "lease") await this.#claimAndRetire(acquisition.lease);
        return;
      }
      if (acquisition.kind === "failure") {
        const error = sourceFailure(acquisition);
        const ordinal = this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("artifact", error.code, error.disposition);
        if (error.disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
        pendingDisposition = error.disposition;
        void ordinal;
        continue;
      }

      let claim: ClaimedArtifactLeaseV3;
      try {
        claim = claimArtifactLeaseV3(acquisition.lease);
      } catch {
        this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("artifact", "artifact_invalid", { kind: "terminal" });
        return;
      }
      if (next === "replacement" && !this.#cycle.claimReplacementQuota()) {
        await retireArtifactLeaseV3(claim);
        this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("connect", replacementTerminal(replacementContext).code, { kind: "terminal" });
        return;
      }

      const artifact = claimedArtifactV3(claim);
      let allCandidates: readonly CanonicalArtifactCandidateV3[];
      try {
        validateArtifactV3(artifact);
        this.#assertArtifactFresh(artifact);
        allCandidates = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates).candidates;
      } catch {
        await retireArtifactLeaseV3(claim);
        this.#cycle.recordFailedAcquisitionOrLease();
        const expired = isExpired(artifact, this.#nowUnixSeconds);
        const error = new ConnectErrorV3(expired ? "expired_artifact" : "artifact_invalid", {
          kind: expired ? "retryable" : "terminal",
        });
        this.#recordFailure("artifact", error.code, error.disposition);
        if (error.disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
        next = "primary";
        replacementContext = undefined;
        pendingDisposition = error.disposition;
        continue;
      }

      const candidates = next === "replacement"
        ? selectReplacementCandidatesV3(
            artifact.path.kind,
            replacementContext?.candidates ?? [],
            allCandidates,
            replacementContext?.triggerKeys ?? new Set(),
            replacementContext?.failedKeys ?? new Set(),
            this.#cycle,
          )
        : filterBlockedCandidatesV3(artifact.path.kind, allCandidates, this.#cycle);
      if (candidates.length === 0) {
        await retireArtifactLeaseV3(claim);
        this.#cycle.recordFailedAcquisitionOrLease();
        const error = next === "replacement"
          ? replacementTerminal(replacementContext)
          : this.#cycle.blockedPolicyTerminal();
        this.#recordFailure("connect", error.code, error.disposition);
        return;
      }

      let result: LeaseAttemptResultV3<Session>;
      try {
        result = await this.#connector({
          kind: next,
          artifact,
          candidates,
          claim,
          signal: this.#lifetime.signal,
          capability,
          assertArtifactFresh: () => this.#assertArtifactFresh(artifact),
        });
      } catch {
        result = {
          kind: "post_spend_failure",
          error: new ConnectErrorV3("connection_failed", { kind: "terminal" }),
        };
      }
      if (this.#lifetime.signal.aborted) {
        if (result.kind === "established") {
          await result.session.close().catch(() => undefined);
        } else if (artifactLeaseStateV3(claim) === "claimed") {
          await retireArtifactLeaseV3(claim);
        }
        return;
      }

      if (result.kind === "established") {
        if (artifactLeaseStateV3(claim) !== "consumed") {
          if (artifactLeaseStateV3(claim) === "claimed") await retireArtifactLeaseV3(claim);
          this.#cycle.recordFailedAcquisitionOrLease();
          this.#recordFailure("connect", "artifact_invalid", { kind: "terminal" });
          await result.session.close().catch(() => undefined);
          return;
        }
        this.#cycle.established();
        this.#failure = undefined;
        this.#disposition = undefined;
        this.#session = result.session;
        this.#transition("connected");
        const termination = await this.#waitTermination(result.session);
        if (termination === undefined || this.#lifetime.signal.aborted) return;
        this.#session = undefined;
        await result.session.close().catch(() => undefined);
        this.#cycle = new ControllerCycleStateV3(this.#maximumAttempts);
        let sessionFailure: ConnectErrorV3;
        try {
          sessionFailure = this.#projectSessionFailure(termination.error);
          validateRetryDispositionV3(sessionFailure.disposition);
        } catch {
          sessionFailure = new ConnectErrorV3("connection_failed", { kind: "terminal" });
        }
        const disposition = sessionFailure.disposition;
        this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("session", sessionFailure.code, disposition);
        if (disposition.kind === "terminal") return;
        next = "primary";
        replacementContext = undefined;
        pendingDisposition = disposition;
        continue;
      }

      if (result.kind === "pre_spend_failure") {
        if (artifactLeaseStateV3(claim) !== "claimed") {
          this.#cycle.recordFailedAcquisitionOrLease();
          this.#recordFailure("connect", "artifact_invalid", { kind: "terminal" });
          return;
        }
        await retireArtifactLeaseV3(claim);
        this.#cycle.recordFailedAcquisitionOrLease();
        const replacementPreSpendFailure = next === "replacement" && result.error.code !== "expired_artifact";
        const disposition = replacementPreSpendFailure
          ? { kind: "terminal" as const }
          : result.error.disposition;
        this.#recordFailure("connect", result.error.code, disposition);
        if (disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
        next = "primary";
        replacementContext = undefined;
        pendingDisposition = result.error.disposition;
        continue;
      }

      if (result.kind === "post_spend_failure") {
        if (artifactLeaseStateV3(claim) !== "consumed") {
          if (artifactLeaseStateV3(claim) === "claimed") await retireArtifactLeaseV3(claim);
          result = {
            kind: "post_spend_failure",
            error: new ConnectErrorV3("artifact_invalid", { kind: "terminal" }),
          };
        }
        this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("connect", result.error.code, result.error.disposition);
        if (result.error.disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
        next = "primary";
        replacementContext = undefined;
        pendingDisposition = result.error.disposition;
        continue;
      }

      if (artifactLeaseStateV3(claim) !== "claimed") {
        this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("connect", "artifact_invalid", { kind: "terminal" });
        return;
      }
      await retireArtifactLeaseV3(claim);
      this.#cycle.recordFailedAcquisitionOrLease();
      if (isExpired(artifact, this.#nowUnixSeconds)) {
        const error = new ConnectErrorV3("expired_artifact", { kind: "retryable" });
        this.#recordFailure("connect", error.code, error.disposition);
        if (this.#attemptBudgetExhausted()) return;
        next = "primary";
        replacementContext = undefined;
        pendingDisposition = error.disposition;
        continue;
      }

      if (next === "replacement") {
        const error = replacementTerminal(replacementContext);
        this.#recordFailure("connect", error.code, error.disposition);
        return;
      }
      const refresh = aggregateCandidateFailuresV3(result.failures, !this.#cycle.snapshot().replacementUsed);
      if (refresh === "policy_refresh") {
        const triggerKeys = blockPolicyRefreshTriggersV3(artifact.path.kind, result.failures, this.#cycle);
        const failedKeys = new Set(result.failures.map(({ candidate }) => endpointKeyV3(artifact.path.kind, candidate)));
        replacementContext = { artifact, candidates: allCandidates, failures: result.failures, triggerKeys, failedKeys };
        next = "replacement";
        continue;
      }
      this.#recordFailure("connect", refresh.code, refresh.disposition);
      if (refresh.disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
      next = "primary";
      pendingDisposition = refresh.disposition;
    }
  }

  async #acquire(capability: RuntimeCapabilityDescriptorV3): Promise<ArtifactSourceResultV3> {
    try {
      const result = await this.#source.acquire({ signal: this.#lifetime.signal, capability });
      if (result === null || typeof result !== "object") return invalidSourceResult();
      if (result.kind === "lease") {
        if (result.lease === null || typeof result.lease !== "object") return invalidSourceResult();
        if (!hasExactOwnKeys(result, ["kind", "lease"])) {
          await this.#claimAndRetire(result.lease);
          return invalidSourceResult();
        }
        return { kind: "lease", lease: result.lease };
      }
      if (result.kind === "failure") {
        const mixedLease = deliveredLease(result);
        if (mixedLease !== undefined) {
          await this.#claimAndRetire(mixedLease);
        }
        if (!hasExactOwnKeys(result, ["kind", "code", "disposition"]) ||
            typeof result.code !== "string" || !ARTIFACT_SOURCE_FAILURE_CODES_V3.has(result.code)) {
          return invalidSourceResult();
        }
        return { kind: "failure", code: result.code, disposition: validateRetryDispositionV3(result.disposition) };
      }
      const invalidLease = deliveredLease(result);
      if (invalidLease !== undefined) await this.#claimAndRetire(invalidLease);
      return invalidSourceResult();
    } catch (error) {
      if (error instanceof ConnectErrorV3) {
        try {
          if (!ARTIFACT_SOURCE_FAILURE_CODES_V3.has(error.code)) return invalidSourceResult();
          return {
            kind: "failure",
            code: error.code,
            disposition: validateRetryDispositionV3(error.disposition),
          };
        } catch {
          return invalidSourceResult();
        }
      }
      return invalidSourceResult();
    }
  }

  async #claimAndRetire(lease: ArtifactLeaseV3): Promise<void> {
    try {
      await retireArtifactLeaseV3(claimArtifactLeaseV3(lease));
    } catch {
      // A duplicate or already-owned late lease is a source contract violation,
      // but close still remains terminal and does not start new work.
    }
  }

  #assertArtifactFresh(artifact: ArtifactV3): void {
    if (isExpired(artifact, this.#nowUnixSeconds)) {
      throw new ConnectErrorV3("expired_artifact", { kind: "retryable" });
    }
  }

  #attemptBudgetExhausted(): boolean {
    if (this.#maximumAttempts === 0 || this.#cycle.snapshot().attempts < this.#maximumAttempts) return false;
    this.#forceTerminalDisposition();
    return true;
  }

  #forceTerminalDisposition(): void {
    this.#disposition = { kind: "terminal" };
    this.#transition("failed");
  }

  #recordFailure(phase: ConnectionControllerFailureV3["phase"], code: string, disposition: RetryDispositionV3): void {
    this.#failure = Object.freeze({ phase, code });
    this.#disposition = disposition;
    if (disposition.kind === "terminal") this.#transition("failed");
  }

  async #waitTermination(session: Session): Promise<Readonly<{ error: Error }> | undefined> {
    try {
      return await raceAbort(session.waitTermination(), this.#lifetime.signal);
    } catch (error) {
      if (this.#lifetime.signal.aborted) return undefined;
      return { error: error instanceof Error ? error : new Error(String(error)) };
    }
  }

  #snapshot(): ConnectionControllerSnapshotV3<Session> {
    return Object.freeze({
      state: this.#state,
      attempt: this.#cycle.snapshot().attempts,
      ...(this.currentSession === undefined ? {} : { currentSession: this.currentSession }),
      ...(this.#failure === undefined ? {} : { failure: this.#failure }),
      ...(this.#disposition === undefined ? {} : { retryDisposition: this.#disposition }),
    });
  }

  #transition(state: ConnectionControllerStateV3): void {
    if (this.#state === "closed" && state !== "closed") return;
    this.#state = state;
    const snapshot = this.#snapshot();
    for (const listener of this.#listeners) {
      try { listener(snapshot); } catch { /* listener isolation */ }
    }
  }
}

export function createConnectionControllerV3<Session extends ManagedSessionV3>(
  source: ArtifactSourceV3,
  connector: LeaseConnectorV3<Session>,
  options: ConnectionControllerOptionsV3,
): ConnectionControllerV3<Session> {
  return new ConnectionControllerV3(source, connector, options);
}

function invalidSourceResult(): ArtifactSourceResultV3 {
  return Object.freeze({
    kind: "failure" as const,
    code: "artifact_invalid",
    disposition: Object.freeze({ kind: "terminal" as const }),
  });
}

function hasExactOwnKeys(value: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

function deliveredLease(value: object): ArtifactLeaseV3 | undefined {
  const lease = Reflect.get(value, "lease");
  return lease !== null && typeof lease === "object" ? lease as ArtifactLeaseV3 : undefined;
}

function sourceFailure(result: Extract<ArtifactSourceResultV3, { kind: "failure" }>): ConnectErrorV3 {
  const code = result.code === "expired_artifact" ? "expired_artifact" :
    result.code === "connection_failed" ? "connection_failed" : "artifact_invalid";
  return new ConnectErrorV3(code, validateRetryDispositionV3(result.disposition));
}

function replacementTerminal(context: Readonly<{ failures: readonly CandidateFailureV3[] }> | undefined): ConnectErrorV3 {
  if (context === undefined) return new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  const value = aggregateCandidateFailuresV3(context.failures, false);
  return value === "policy_refresh"
    ? new ConnectErrorV3("transport_security_failed", { kind: "terminal" })
    : value;
}

function isExpired(artifact: ArtifactV3, nowUnixSeconds: () => number): boolean {
  const now = nowUnixSeconds();
  if (!Number.isSafeInteger(now) || now < 0) return true;
  return now >= artifact.session.init_expire_at_unix_s;
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
