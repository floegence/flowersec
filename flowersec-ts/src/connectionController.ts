import type { ArtifactLease } from "./public/artifactLease.js";
import type { RetryDisposition, Session, SessionError, SessionErrorCode } from "./public/contract.js";
import type { ConnectErrorCode } from "./public/connectError.js";
import { ConnectError } from "./public/connectError.js";
import {
  retryDispositionForConnectError,
  retryDispositionForSessionError,
} from "./v2/retryDisposition.js";
import { SDK_DEFAULTS } from "./defaults.js";

const MAX_TIMER_DELAY_MS = 2_147_483_647;

export type { RetryDisposition } from "./public/contract.js";

export type ArtifactSourceResult =
  | Readonly<{ kind: "lease"; lease: ArtifactLease }>
  | Readonly<{ kind: "failure"; code: string; disposition: RetryDisposition }>;

export type ArtifactSource = Readonly<{
  acquire(options: Readonly<{ signal: AbortSignal }>): Promise<ArtifactSourceResult>;
}>;

export type ConnectionState =
  | "idle"
  | "connecting"
  | "connected"
  | "waiting"
  | "failed"
  | "closed";

export type ConnectionControllerFailure =
  | Readonly<{ phase: "artifact"; code: string }>
  | Readonly<{ phase: "connect"; code: ConnectErrorCode }>
  | Readonly<{ phase: "session"; code: SessionErrorCode }>;

export type ConnectionSnapshot = Readonly<{
  state: ConnectionState;
  attempt: number;
  currentSession?: Session;
  failure?: ConnectionControllerFailure;
  retryDisposition?: RetryDisposition;
}>;

export type ConnectionControllerOptions = Readonly<{
  maximumAttempts?: number;
}>;

export interface ConnectionController {
  readonly state: ConnectionState;
  readonly currentSession: Session | undefined;
  readonly failure: ConnectionControllerFailure | undefined;

  start(): void;
  retryNow(): boolean;
  waitForSession(options?: Readonly<{ signal?: AbortSignal }>): Promise<Session>;
  subscribe(listener: (snapshot: ConnectionSnapshot) => void): () => void;
  close(): Promise<void>;
}

export class ConnectionControllerError extends Error {
  constructor(
    readonly code: "failed" | "closed" | "canceled",
    readonly failure: ConnectionControllerFailure | undefined = undefined,
  ) {
    super(`Flowersec connection controller stopped (code=${code})`);
    this.name = "ConnectionControllerError";
  }
}

type ConnectOneShot = (lease: ArtifactLease, signal: AbortSignal) => Promise<Session>;

/** @internal Runtime facades supply the only runtime-specific operation: one one-shot connection attempt. */
export function createConnectionControllerV2(
  source: ArtifactSource,
  connectOneShot: ConnectOneShot,
  options: ConnectionControllerOptions = {},
): ConnectionController {
  return new ConnectionControllerV2Impl(source, connectOneShot, options);
}

class ConnectionControllerV2Impl implements ConnectionController {
  private controllerState: ConnectionState = "idle";
  private session: Session | undefined;
  private lastFailure: ConnectionControllerFailure | undefined;
  private currentRetryDisposition: RetryDisposition | undefined;
  private attempt = 0;
  private consecutiveFailures = 0;
  private resetAttemptOnRetry = false;
  private readonly lifetime = new AbortController();
  private readonly listeners = new Set<(snapshot: ConnectionSnapshot) => void>();
  private readonly issuedLeases = new WeakSet<object>();
  private readonly issuedSessions = new WeakSet<object>();
  private readonly maxAttempts: number | undefined;
  private scheduler: Promise<void> | undefined;
  private closeOperation: Promise<void> | undefined;
  private pendingConnectCleanup: Promise<void> | undefined;
  private pendingAcquisitionCleanup: Promise<void> | undefined;
  private waitingWake: (() => void) | undefined;
  private manualRetryRequested = false;
  private retryNotBefore = 0;

  constructor(
    private readonly source: ArtifactSource,
    private readonly connectOneShot: ConnectOneShot,
    options: ConnectionControllerOptions,
  ) {
    if (source === null || typeof source !== "object" || typeof source.acquire !== "function") {
      throw new TypeError("artifact source must provide acquire()");
    }
    if (typeof connectOneShot !== "function") throw new TypeError("one-shot connector is required");
    if (options.maximumAttempts !== undefined &&
      (!Number.isSafeInteger(options.maximumAttempts) || options.maximumAttempts < 1)) {
      throw new TypeError("maximumAttempts must be a positive safe integer");
    }
    this.maxAttempts = options.maximumAttempts;
  }

  get state(): ConnectionState { return this.controllerState; }
  get currentSession(): Session | undefined { return this.connectedSession(); }
  get failure(): ConnectionControllerFailure | undefined { return this.lastFailure; }

  start(): void {
    if (this.controllerState !== "idle") return;
    this.scheduler = this.run();
  }

  retryNow(): boolean {
    if (this.controllerState !== "waiting" || Date.now() < this.retryNotBefore) return false;
    this.manualRetryRequested = true;
    this.waitingWake?.();
    return true;
  }

  async waitForSession(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<Session> {
    const ready = this.connectedSession();
    if (ready !== undefined) return ready;
    if (this.controllerState === "failed") throw new ConnectionControllerError("failed", this.lastFailure);
    if (this.controllerState === "closed") throw new ConnectionControllerError("closed", this.lastFailure);
    if (options.signal?.aborted === true) throw new ConnectionControllerError("canceled");

    return await new Promise<Session>((resolve, reject) => {
      const finish = (result: Readonly<{ session?: Session; error?: ConnectionControllerError }>) => {
        this.listeners.delete(listener);
        options.signal?.removeEventListener("abort", canceled);
        if (result.session !== undefined) resolve(result.session);
        else reject(result.error ?? new ConnectionControllerError("failed", this.lastFailure));
      };
      const listener = (snapshot: ConnectionSnapshot) => {
        if (snapshot.state === "connected" && snapshot.currentSession !== undefined) {
          finish({ session: snapshot.currentSession });
        } else if (snapshot.state === "failed") {
          finish({ error: new ConnectionControllerError("failed", snapshot.failure) });
        } else if (snapshot.state === "closed") {
          finish({ error: new ConnectionControllerError("closed", snapshot.failure) });
        }
      };
      const canceled = () => finish({ error: new ConnectionControllerError("canceled") });
      this.listeners.add(listener);
      options.signal?.addEventListener("abort", canceled, { once: true });
    });
  }

  subscribe(listener: (snapshot: ConnectionSnapshot) => void): () => void {
    if (typeof listener !== "function") throw new TypeError("connection listener must be a function");
    this.listeners.add(listener);
    try {
      listener(this.snapshot());
    } catch (error) {
      this.listeners.delete(listener);
      throw error;
    }
    return () => { this.listeners.delete(listener); };
  }

  close(): Promise<void> {
    if (this.closeOperation !== undefined) return this.closeOperation;
    let resolveClose!: () => void;
    this.closeOperation = new Promise<void>((resolve) => {
      resolveClose = resolve;
    });
    const active = this.session;
    // A closed controller must never advertise a session that it has just retired.
    this.session = undefined;
    this.currentRetryDisposition = undefined;
    this.lifetime.abort(new ConnectionControllerError("closed", this.lastFailure));
    this.transition("closed");
    void this.finishClose(active).then(resolveClose);
    return this.closeOperation;
  }

  private async finishClose(active: Session | undefined): Promise<void> {
    this.waitingWake?.();
    const activeClose = active === undefined
      ? Promise.resolve()
      : active.close();
    await Promise.allSettled([this.scheduler ?? Promise.resolve(), activeClose]);
    const pendingCleanup = this.pendingConnectCleanup;
    const acquisitionCleanup = this.pendingAcquisitionCleanup;
    await Promise.allSettled([
      ...(pendingCleanup === undefined ? [] : [pendingCleanup]),
      ...(acquisitionCleanup === undefined ? [] : [acquisitionCleanup]),
    ]);
  }

  private async run(): Promise<void> {
    let disposition: RetryDisposition | undefined;
    while (!this.lifetime.signal.aborted) {
      if (disposition !== undefined) {
        const canContinue = await this.waitForRetry(disposition);
        if (!canContinue) return;
      }
      if (this.maxAttempts !== undefined && this.attempt >= this.maxAttempts) {
        this.currentRetryDisposition = Object.freeze({ kind: "terminal" });
        this.transition("failed");
        return;
      }

      this.currentRetryDisposition = undefined;
      this.attempt += 1;
      this.transition("connecting");
      const acquisition = await this.acquireLease();
      if (this.lifetime.signal.aborted) return;
      if (acquisition.kind === "failure") {
        this.lastFailure = Object.freeze({ phase: "artifact", code: acquisition.code });
        disposition = acquisition.disposition;
        this.currentRetryDisposition = disposition;
        if (disposition.kind === "terminal") {
          this.transition("failed");
          return;
        }
        this.consecutiveFailures += 1;
        continue;
      }

      let connected: Session;
      try {
        connected = await this.connect(acquisition.lease);
      } catch (error) {
        if (this.lifetime.signal.aborted) return;
        const failure = connectFailure(error);
        this.lastFailure = failure.failure;
        disposition = failure.disposition;
        this.currentRetryDisposition = disposition;
        if (disposition.kind === "terminal") {
          this.transition("failed");
          return;
        }
        this.consecutiveFailures += 1;
        continue;
      }
      if (this.lifetime.signal.aborted) {
        await connected.close().catch(() => undefined);
        return;
      }

      this.session = connected;
      this.lastFailure = undefined;
      this.currentRetryDisposition = undefined;
      this.consecutiveFailures = 0;
      disposition = undefined;
      this.transition("connected");
      const termination = await raceTermination(connected, this.lifetime.signal);
      if (termination === undefined || this.lifetime.signal.aborted) return;
      // A terminated session is no longer current while the replacement attempt waits.
      this.session = undefined;
      await connected.close().catch(() => undefined);
      if (this.lifetime.signal.aborted) return;
      const failure = sessionFailure(termination.error);
      this.lastFailure = failure.failure;
      disposition = failure.disposition;
      this.currentRetryDisposition = disposition;
      if (disposition.kind === "terminal") {
        this.transition("failed");
        return;
      }
      this.consecutiveFailures = 1;
      this.resetAttemptOnRetry = true;
    }
  }

  private async acquireLease(): Promise<ArtifactSourceResult> {
    let result: ArtifactSourceResult;
    let pending: Promise<ArtifactSourceResult>;
    try {
      pending = this.source.acquire({ signal: this.lifetime.signal });
    } catch {
      return terminalArtifactFailure("artifact_source_failed");
    }
    const cleanup = pending.then(() => undefined, () => undefined);
    this.pendingAcquisitionCleanup = cleanup;
    void cleanup.finally(() => {
      if (this.pendingAcquisitionCleanup === cleanup) this.pendingAcquisitionCleanup = undefined;
    }).catch(() => undefined);
    try {
      result = await raceAbort(pending, this.lifetime.signal);
    } catch {
      return terminalArtifactFailure("artifact_source_failed");
    }
    try {
      if (result === null || typeof result !== "object") return terminalArtifactFailure("artifact_source_failed");
      if (result.kind === "failure") {
        if (!validFailureCode(result.code) || !validDisposition(result.disposition)) {
          return terminalArtifactFailure("artifact_source_failed");
        }
        return Object.freeze({ kind: "failure", code: result.code, disposition: normalizeDisposition(result.disposition) });
      }
      if (result.kind !== "lease" || result.lease === null || typeof result.lease !== "object") {
        return terminalArtifactFailure("artifact_source_failed");
      }
      if (this.issuedLeases.has(result.lease)) return terminalArtifactFailure("reused_artifact_lease");
      this.issuedLeases.add(result.lease);
      return result;
    } catch {
      return terminalArtifactFailure("artifact_source_failed");
    }
  }

  private async connect(lease: ArtifactLease): Promise<Session> {
    const pending = this.connectOneShot(lease, this.lifetime.signal);
    try {
      const session = await raceAbort(pending, this.lifetime.signal);
      if (session === null || typeof session !== "object" ||
          typeof session.close !== "function" || typeof session.waitTermination !== "function") {
        throw new TypeError("one-shot connector returned an invalid session");
      }
      if (this.issuedSessions.has(session)) {
        await session.close().catch(() => undefined);
        throw new Error("one-shot connector reused a previous session");
      }
      this.issuedSessions.add(session);
      return session;
    } catch (error) {
      if (this.lifetime.signal.aborted) {
        const cleanup = pending.then(
          async (lateSession) => await lateSession.close(),
          () => undefined,
        );
        this.pendingConnectCleanup = cleanup;
        void cleanup.finally(() => {
          if (this.pendingConnectCleanup === cleanup) this.pendingConnectCleanup = undefined;
        }).catch(() => undefined);
      }
      throw error;
    }
  }

  private async waitForRetry(disposition: RetryDisposition): Promise<boolean> {
    if (this.maxAttempts !== undefined && !this.resetAttemptOnRetry && this.attempt >= this.maxAttempts) {
      this.currentRetryDisposition = Object.freeze({ kind: "terminal" });
      this.transition("failed");
      return false;
    }
    const now = Date.now();
    const backoffDeadline = now + retryDelay(this.consecutiveFailures);
    const hardDeadline = disposition.kind === "retry_after"
      ? disposition.notBeforeUnixMilliseconds
      : 0;
    this.retryNotBefore = hardDeadline;
    this.manualRetryRequested = false;
    this.transition("waiting");
    while (!this.lifetime.signal.aborted) {
      const deadline = this.manualRetryRequested
        ? hardDeadline
        : Math.max(backoffDeadline, hardDeadline);
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        this.waitingWake = undefined;
        this.retryNotBefore = 0;
        if (this.resetAttemptOnRetry) {
          this.attempt = 0;
          this.resetAttemptOnRetry = false;
        }
        return true;
      }
      await this.wait(Math.min(remaining, MAX_TIMER_DELAY_MS));
    }
    this.waitingWake = undefined;
    this.retryNotBefore = 0;
    return false;
  }

  private async wait(milliseconds: number): Promise<void> {
    await new Promise<void>((resolve) => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.lifetime.signal.removeEventListener("abort", finish);
        if (this.waitingWake === finish) this.waitingWake = undefined;
        resolve();
      };
      const timer = setTimeout(finish, milliseconds);
      this.waitingWake = finish;
      this.lifetime.signal.addEventListener("abort", finish, { once: true });
    });
  }

  private connectedSession(): Session | undefined {
    return this.controllerState === "connected" ? this.session : undefined;
  }

  private transition(state: ConnectionState): void {
    this.controllerState = state;
    const snapshot = this.snapshot();
    for (const listener of this.listeners) {
      try { listener(snapshot); } catch { /* Listener failures do not own controller lifecycle. */ }
    }
  }

  private snapshot(): ConnectionSnapshot {
    const currentSession = this.connectedSession();
    return Object.freeze({
      state: this.controllerState,
      attempt: this.attempt,
      ...(currentSession === undefined ? {} : { currentSession }),
      ...(this.lastFailure === undefined ? {} : { failure: this.lastFailure }),
      ...(this.currentRetryDisposition === undefined ? {} : { retryDisposition: this.currentRetryDisposition }),
    });
  }
}

function connectFailure(error: unknown): Readonly<{
  failure: ConnectionControllerFailure;
  disposition: RetryDisposition;
}> {
  if (!(error instanceof ConnectError)) {
    return Object.freeze({
      failure: Object.freeze({ phase: "connect", code: "connection_failed" }),
      disposition: Object.freeze({ kind: "terminal" }),
    });
  }
  const disposition = retryDispositionForConnectError(error);
  return Object.freeze({
    failure: Object.freeze({ phase: "connect", code: error.code }),
    disposition,
  });
}

function sessionFailure(error: SessionError): Readonly<{
  failure: ConnectionControllerFailure;
  disposition: RetryDisposition;
}> {
  const disposition = retryDispositionForSessionError(error);
  return Object.freeze({
    failure: Object.freeze({ phase: "session", code: error.code }),
    disposition,
  });
}

function terminalArtifactFailure(code: string): ArtifactSourceResult {
  return Object.freeze({
    kind: "failure",
    code,
    disposition: Object.freeze({ kind: "terminal" }),
  });
}

function validFailureCode(code: unknown): code is string {
  return typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code);
}

function validDisposition(value: unknown): value is RetryDisposition {
  if (value === null || typeof value !== "object" || !("kind" in value)) return false;
  const disposition = value as { kind?: unknown; notBeforeUnixMilliseconds?: unknown };
  if (disposition.kind === "terminal" || disposition.kind === "retryable") return true;
  return disposition.kind === "retry_after" &&
    typeof disposition.notBeforeUnixMilliseconds === "number" &&
    Number.isSafeInteger(disposition.notBeforeUnixMilliseconds) &&
    disposition.notBeforeUnixMilliseconds >= 0;
}

function normalizeDisposition(disposition: RetryDisposition): RetryDisposition {
  if (disposition.kind === "retry_after") {
    return Object.freeze({
      kind: "retry_after",
      notBeforeUnixMilliseconds: disposition.notBeforeUnixMilliseconds,
    });
  }
  return Object.freeze({ kind: disposition.kind });
}

function retryDelay(failures: number): number {
  const exponent = Math.max(0, Math.min(30, failures - 1));
  return Math.min(
    SDK_DEFAULTS.connectionController.maxDelayMs,
    SDK_DEFAULTS.connectionController.initialDelayMs *
      (SDK_DEFAULTS.connectionController.factor ** exponent),
  );
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

async function raceTermination(
  session: Session,
  signal: AbortSignal,
): Promise<Readonly<{ error: SessionError }> | undefined> {
  try {
    return await raceAbort(session.waitTermination(), signal);
  } catch {
    return undefined;
  }
}
