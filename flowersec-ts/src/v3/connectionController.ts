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
  TransportFailureV3,
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
  #connectedAttempt = 0;
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
    if (this.#state !== "idle" || this.#scheduler !== undefined) return;
    let resolveScheduler!: () => void;
    let rejectScheduler!: (reason?: unknown) => void;
    this.#scheduler = new Promise<void>((resolve, reject) => {
      resolveScheduler = resolve;
      rejectScheduler = reject;
    });
    void this.#run().then(resolveScheduler, rejectScheduler);
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
    let resolveClose!: () => void;
    const closeOperation = new Promise<void>((resolve) => { resolveClose = resolve; });
    this.#closeOperation = closeOperation;
    const active = this.#session;
    this.#session = undefined;
    this.#disposition = undefined;
    this.#lifetime.abort(new ConnectionControllerV3Error("closed", this.#failure));
    this.#transition("closed");
    void Promise.allSettled([
      this.#scheduler ?? Promise.resolve(),
      active?.close() ?? Promise.resolve(),
    ]).then(() => resolveClose());
    return closeOperation;
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
        const waitOperation = this.#retry.wait(
          pendingDisposition,
          this.#cycle.snapshot().consecutiveFailures,
          this.#lifetime.signal,
        );
        this.#transition("waiting");
        const continued = await waitOperation;
        if (!continued) return;
        pendingDisposition = undefined;
      }
      this.#disposition = undefined;
      this.#transition("connecting");
      if (this.#lifetime.signal.aborted) return;
      if (this.#maximumAttempts !== 0 && this.#cycle.snapshot().attempts >= this.#maximumAttempts) {
        this.#forceTerminalDisposition();
        return;
      }
      let capability: RuntimeCapabilityDescriptorV3;
      try {
        capability = this.#capabilitySnapshot();
        validateRuntimeCapabilityDescriptorV3(capability);
      } catch {
        this.#recordFailure("connect", "artifact_invalid", { kind: "terminal" });
        return;
      }
      if (!this.#cycle.beginAcquisition()) {
        this.#forceTerminalDisposition();
        return;
      }
      const acquisition = await this.#acquire();
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
        this.#recordFailure("connect", "artifact_invalid", { kind: "terminal" });
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
        allCandidates = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates).candidates;
      } catch {
        await retireArtifactLeaseV3(claim);
        this.#cycle.recordFailedAcquisitionOrLease();
        const error = new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
        this.#recordFailure("connect", error.code, error.disposition);
        return;
      }
      try {
        this.#assertArtifactFresh(artifact);
      } catch {
        await retireArtifactLeaseV3(claim);
        this.#cycle.recordFailedAcquisitionOrLease();
        const error = new ConnectErrorV3("expired_artifact", { kind: "retryable" });
        this.#recordFailure("connect", error.code, error.disposition);
        if (this.#attemptBudgetExhausted()) return;
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

      let rawResult: unknown;
      try {
        rawResult = await this.#connector({
          kind: next,
          artifact,
          candidates,
          claim,
          signal: this.#lifetime.signal,
          capability,
          assertArtifactFresh: () => this.#assertArtifactFresh(artifact),
        });
      } catch {
        rawResult = {
          kind: "post_spend_failure",
          error: new ConnectErrorV3("connection_failed", { kind: "terminal" }),
        };
      }
      let result = normalizeLeaseAttemptResultV3<Session>(rawResult, candidates, capability);
      if (result === undefined) {
        const malformedSession = sessionFromMalformedConnectorResultV3(rawResult);
        if (artifactLeaseStateV3(claim) === "claimed") await retireArtifactLeaseV3(claim);
        if (malformedSession !== undefined) await closeManagedSessionV3(malformedSession);
        if (this.#lifetime.signal.aborted) return;
        this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("connect", "artifact_invalid", { kind: "terminal" });
        return;
      }
      if (this.#lifetime.signal.aborted) {
        if (result.kind === "established") {
          if (artifactLeaseStateV3(claim) === "claimed") await retireArtifactLeaseV3(claim);
          await closeManagedSessionV3(result.session);
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
          await closeManagedSessionV3(result.session);
          return;
        }
        this.#connectedAttempt = this.#cycle.snapshot().attempts;
        this.#cycle.established();
        this.#failure = undefined;
        this.#disposition = undefined;
        this.#session = result.session;
        this.#transition("connected");
        const termination = await this.#waitTermination(result.session);
        if (termination === undefined || this.#lifetime.signal.aborted) return;
        this.#session = undefined;
        this.#connectedAttempt = 0;
        await closeManagedSessionV3(result.session);
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
        const error = next === "replacement" && result.error.code !== "expired_artifact"
          ? replacementTerminal(replacementContext)
          : result.error;
        const disposition = error.disposition;
        this.#recordFailure("connect", error.code, disposition);
        if (disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
        next = "primary";
        replacementContext = undefined;
        pendingDisposition = result.error.disposition;
        continue;
      }

      if (result.kind === "post_spend_failure") {
        let postSpendResult = result;
        if (artifactLeaseStateV3(claim) !== "consumed") {
          if (artifactLeaseStateV3(claim) === "claimed") await retireArtifactLeaseV3(claim);
          postSpendResult = {
            kind: "post_spend_failure",
            error: new ConnectErrorV3("artifact_invalid", { kind: "terminal" }),
          };
        }
        this.#cycle.recordFailedAcquisitionOrLease();
        this.#recordFailure("connect", postSpendResult.error.code, postSpendResult.error.disposition);
        if (postSpendResult.error.disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
        next = "primary";
        replacementContext = undefined;
        pendingDisposition = postSpendResult.error.disposition;
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
      const triggerKeys = blockPolicyRefreshTriggersV3(artifact.path.kind, result.failures, this.#cycle);
      const refresh = aggregateCandidateFailuresV3(result.failures, !this.#cycle.snapshot().replacementUsed);
      if (refresh === "policy_refresh") {
        const failedKeys = new Set(result.failures.map(({ candidate }) => endpointKeyV3(artifact.path.kind, candidate)));
        replacementContext = { artifact, candidates: allCandidates, failures: result.failures, triggerKeys, failedKeys };
        this.#rememberFailure("connect", replacementTerminal(replacementContext).code);
        next = "replacement";
        continue;
      }
      if (triggerKeys.size > 0 && refresh.code === "connection_failed") {
        const terminal = this.#cycle.blockedPolicyTerminal();
        this.#recordFailure("connect", terminal.code, terminal.disposition);
        return;
      }
      this.#recordFailure("connect", refresh.code, refresh.disposition);
      if (refresh.disposition.kind === "terminal" || this.#attemptBudgetExhausted()) return;
      next = "primary";
      pendingDisposition = refresh.disposition;
    }
  }

  async #acquire(): Promise<ArtifactSourceResultV3> {
    const acquisition = new SourceAcquisitionRaceV3(this.#source, this.#lifetime.signal);
    let deliveredLeaseSnapshot: ArtifactLeaseV3 | undefined;
    try {
      const result = await acquisition.value();
      await acquisition.settle();
      if (result === undefined) return invalidSourceResult();
      if (result === null || typeof result !== "object") return invalidSourceResult();
      const deliveredLease = Reflect.get(result, "lease");
      if (deliveredLease !== null && typeof deliveredLease === "object") {
        deliveredLeaseSnapshot = deliveredLease as ArtifactLeaseV3;
      }
      const kind = Reflect.get(result, "kind");
      const ownKeys = Reflect.ownKeys(result);
      if (kind === "lease") {
        if (deliveredLeaseSnapshot === undefined) return invalidSourceResult();
        if (!hasExactOwnKeyList(ownKeys, ["kind", "lease"])) {
          await this.#claimAndRetire(deliveredLeaseSnapshot);
          return invalidSourceResult();
        }
        return { kind: "lease", lease: deliveredLeaseSnapshot };
      }
      if (kind === "failure") {
        if (deliveredLeaseSnapshot !== undefined) await this.#claimAndRetire(deliveredLeaseSnapshot);
        const code = Reflect.get(result, "code");
        const disposition = Reflect.get(result, "disposition");
        if (!hasExactOwnKeyList(ownKeys, ["kind", "code", "disposition"]) ||
            typeof code !== "string" || !ARTIFACT_SOURCE_FAILURE_CODES_V3.has(code)) {
          return invalidSourceResult();
        }
        return { kind: "failure", code, disposition: validateRetryDispositionV3(disposition) };
      }
      if (deliveredLeaseSnapshot !== undefined) await this.#claimAndRetire(deliveredLeaseSnapshot);
      return invalidSourceResult();
    } catch (error) {
      await acquisition.settle();
      if (deliveredLeaseSnapshot !== undefined) await this.#claimAndRetire(deliveredLeaseSnapshot);
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
    this.#rememberFailure(phase, code);
    this.#disposition = disposition;
    if (disposition.kind === "terminal") this.#transition("failed");
  }

  #rememberFailure(phase: ConnectionControllerFailureV3["phase"], code: string): void {
    this.#failure = Object.freeze({ phase, code });
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
      attempt: this.#state === "connected" ? this.#connectedAttempt : this.#cycle.snapshot().attempts,
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

/** Serializes source delivery and controller cancellation at one ownership gate. */
class SourceAcquisitionRaceV3 {
  #state: "pending" | "delivered" | "canceled" = "pending";
  #cleanup = Promise.resolve();
  #sourcePromise: Promise<ArtifactSourceResultV3>;
  #settled: Promise<ArtifactSourceResultV3 | undefined>;
  #resolveSettled!: (result: ArtifactSourceResultV3 | undefined) => void;
  #rejectSettled!: (error: unknown) => void;
  readonly #signal: AbortSignal;
  readonly #abort: () => void;

  constructor(source: ArtifactSourceV3, signal: AbortSignal) {
    this.#signal = signal;
    this.#settled = new Promise((resolve, reject) => {
      this.#resolveSettled = resolve;
      this.#rejectSettled = reject;
    });
    try {
      // Invoke the source before returning so a synchronous close cannot abort
      // before the source has installed its own cancellation observer.
      this.#sourcePromise = Promise.resolve(source.acquire({ signal }));
    } catch (error) {
      this.#sourcePromise = Promise.reject(error);
    }
    this.#sourcePromise.then(
      (result) => this.#deliver(result),
      (error) => this.#deliverFailure(error),
    );
    this.#abort = () => this.#cancel();
    signal.addEventListener("abort", this.#abort, { once: true });
    if (signal.aborted) this.#cancel();
  }

  async value(): Promise<ArtifactSourceResultV3 | undefined> {
    return await this.#settled;
  }

  async settle(): Promise<void> {
    await this.#sourcePromise.catch(() => undefined);
    await this.#cleanup;
    this.#signal.removeEventListener("abort", this.#abort);
  }

  #cancel(): void {
    if (this.#state !== "pending") return;
    this.#state = "canceled";
    this.#resolveSettled(undefined);
  }

  #deliver(result: ArtifactSourceResultV3): void {
    if (this.#state === "pending") {
      this.#state = "delivered";
      this.#resolveSettled(result);
      return;
    }
    if (this.#state === "canceled") {
      this.#cleanup = this.#cleanup.then(() => this.#retireLateLease(result));
    }
  }

  #deliverFailure(error: unknown): void {
    if (this.#state === "pending") {
      this.#state = "delivered";
      this.#rejectSettled(error);
    }
  }

  async #retireLateLease(result: ArtifactSourceResultV3): Promise<void> {
    if (result === null || typeof result !== "object") return;
    try {
      const lease = deliveredLease(result);
      if (lease === undefined) return;
      await retireArtifactLeaseV3(claimArtifactLeaseV3(lease));
    } catch {
      // Late source cleanup is intentionally redacted at the public boundary.
    }
  }
}

function invalidSourceResult(): ArtifactSourceResultV3 {
  return Object.freeze({
    kind: "failure" as const,
    code: "artifact_invalid",
    disposition: Object.freeze({ kind: "terminal" as const }),
  });
}

const LEASE_ATTEMPT_RESULT_KINDS_V3 = new Set([
  "established",
  "candidate_failures",
  "pre_spend_failure",
  "post_spend_failure",
]);
const CONNECT_ERROR_CODES_V3 = new Set([
  "artifact_invalid",
  "expired_artifact",
  "transport_security_unsupported",
  "transport_security_failed",
  "connection_failed",
]);
const TRANSPORT_FAILURE_CODES_V3 = new Set([
  "invalid_artifact",
  "expired_artifact",
  "tls_unsupported",
  "tls_policy_expired",
  "tls_failed",
  "connection_failed",
]);
const TRANSPORT_FAILURE_DETAILS_V3 = new Set([
  "ca_untrusted",
  "pin_mismatch",
  "unknown",
  "browser_pin_opaque",
]);

/** Enforces the runtime adapter boundary before the controller consumes a result. */
function normalizeLeaseAttemptResultV3<Session extends ManagedSessionV3>(
  value: unknown,
  candidates: readonly CanonicalArtifactCandidateV3[],
  capability: RuntimeCapabilityDescriptorV3,
): LeaseAttemptResultV3<Session> | undefined {
  try {
    if (value === null || typeof value !== "object") return undefined;
    const kind = Reflect.get(value, "kind");
    if (typeof kind !== "string" || !LEASE_ATTEMPT_RESULT_KINDS_V3.has(kind)) return undefined;
    if (kind === "established") {
      if (!hasExactOwnKeys(value, ["kind", "session"])) return undefined;
      const session = Reflect.get(value, "session");
      if (!isManagedSessionV3(session)) return undefined;
      return Object.freeze({ kind: "established" as const, session: session as Session }) as LeaseAttemptResultV3<Session>;
    }
    if (kind === "candidate_failures") {
      if (!hasExactOwnKeys(value, ["kind", "failures"])) return undefined;
      const failures = Reflect.get(value, "failures");
      if (!Array.isArray(failures) || failures.length !== candidates.length) return undefined;
      const normalized = failures.map((failure) => normalizeCandidateFailureV3(failure, candidates, capability));
      if (normalized.some((failure) => failure === undefined)) return undefined;
      const seen = new Set(normalized.map((failure) => failure!.candidate));
      if (seen.size !== candidates.length) return undefined;
      return Object.freeze({
        kind,
        failures: Object.freeze(normalized as CandidateFailureV3[]),
      }) as LeaseAttemptResultV3<Session>;
    }
    if (!hasExactOwnKeys(value, ["kind", "error"])) return undefined;
    const error = Reflect.get(value, "error");
    if (!(error instanceof ConnectErrorV3) || !CONNECT_ERROR_CODES_V3.has(error.code)) return undefined;
    const normalizedError = new ConnectErrorV3(error.code, validateRetryDispositionV3(error.disposition));
    return Object.freeze({ kind, error: normalizedError }) as LeaseAttemptResultV3<Session>;
  } catch {
    return undefined;
  }
}

function isManagedSessionV3(value: unknown): value is ManagedSessionV3 {
  return value !== null && typeof value === "object" &&
    typeof Reflect.get(value, "waitTermination") === "function" &&
    typeof Reflect.get(value, "close") === "function";
}

function normalizeCandidateFailureV3(
  value: unknown,
  candidates: readonly CanonicalArtifactCandidateV3[],
  capability: RuntimeCapabilityDescriptorV3,
): CandidateFailureV3 | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const keys = Reflect.ownKeys(value);
  if (!hasExactOwnKeys(value, keys.includes("disposition")
    ? ["candidate", "failure", "disposition"]
    : ["candidate", "failure"])) return undefined;
  const candidate = Reflect.get(value, "candidate");
  const failure = Reflect.get(value, "failure");
  if (!candidates.includes(candidate)) return undefined;
  if (!(failure instanceof TransportFailureV3) || !TRANSPORT_FAILURE_CODES_V3.has(failure.code) ||
      !isValidTransportFailurePairV3(failure.code, failure.detail, candidate, capability)) return undefined;
  const disposition = Reflect.get(value, "disposition");
  const normalizedDisposition = disposition === undefined ? undefined : validateRetryDispositionV3(disposition);
  return Object.freeze({
    candidate: candidate as CanonicalArtifactCandidateV3,
    failure,
    ...(normalizedDisposition === undefined ? {} : { disposition: normalizedDisposition }),
  });
}

function isValidTransportFailurePairV3(
  code: TransportFailureV3["code"],
  detail: TransportFailureV3["detail"],
  candidate: CanonicalArtifactCandidateV3,
  capability: RuntimeCapabilityDescriptorV3,
): boolean {
  if (detail !== undefined && !TRANSPORT_FAILURE_DETAILS_V3.has(detail)) return false;
  if (code === "tls_failed") return detail === "ca_untrusted" || detail === "pin_mismatch" || detail === "unknown";
  if (code === "connection_failed") {
    if (detail === undefined) return true;
    return detail === "browser_pin_opaque" && candidate.carrier === "webtransport" &&
      candidate.tls.mode === "pin" && capability.language === "typescript" && capability.runtime === "browser" &&
      capability.tuples.some((tuple) => tuple.carrier === "webtransport" &&
        tuple.networkMode === "dial" && tuple.securityModes.includes("pin"));
  }
  return detail === undefined;
}

function sessionFromMalformedConnectorResultV3(value: unknown): ManagedSessionV3 | undefined {
  try {
    if (value === null || typeof value !== "object" || Reflect.get(value, "kind") !== "established") return undefined;
    const session = Reflect.get(value, "session");
    return isManagedSessionV3(session) ? session : undefined;
  } catch {
    return undefined;
  }
}

async function closeManagedSessionV3(session: ManagedSessionV3): Promise<void> {
  try {
    await Promise.resolve(session.close());
  } catch {
    // Adapter cleanup is best-effort after ownership has already become terminal.
  }
}

function hasExactOwnKeys(value: object, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return hasExactOwnKeyList(keys, expected);
}

function hasExactOwnKeyList(keys: readonly PropertyKey[], expected: readonly string[]): boolean {
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
  let expiry: unknown;
  try {
    if (artifact === null || typeof artifact !== "object") return false;
    const session = Reflect.get(artifact, "session");
    if (session === null || typeof session !== "object") return false;
    expiry = Reflect.get(session, "init_expire_at_unix_s");
  } catch {
    return false;
  }
  if (!Number.isSafeInteger(expiry) || (expiry as number) < 0) return false;
  const now = nowUnixSeconds();
  if (!Number.isSafeInteger(now) || now < 0) return true;
  return now >= (expiry as number);
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
