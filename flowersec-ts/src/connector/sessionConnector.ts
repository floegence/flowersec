import {
  buildFSB2RequestV2,
  encodeFSB2RequestV2,
  validateArtifactV2,
  type ArtifactV2,
  type CanonicalArtifactCandidateV2,
} from "../v2/artifact.js";
import { AdmissionSessionV2Error } from "../v2/admissionError.js";
import {
  establishSessionV2,
  SessionV2Error,
  type SessionConfigV2,
  type SessionDeadlineFactoryV2,
  type SessionProtocolRuntimeV2,
  type SessionV2 as InternalSessionV2,
} from "../v2/session.js";
import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import { unwrapArtifact } from "../v2/opaqueArtifact.js";
import {
  AbortError,
  ConnectError,
  TimeoutError,
  connectErrorDetailsInternal,
  createConnectErrorInternal,
  type FlowersecCandidateDiagnostic,
  type FlowersecErrorCode,
  type FlowersecPath,
  type FlowersecStage,
} from "../utils/errors.js";
import {
  validateRuntimeCapabilityDescriptorV2,
  type RuntimeCapabilityDescriptorV2,
} from "../v2/capability.js";
import { SDK_DEFAULTS } from "../defaults.js";
import { sessionConfigFromArtifactV2 } from "./sessionConfig.js";
import {
  commitClientAdmissionV2,
  CredentialCommitError,
  type ReadyAdmissionTransportV2,
} from "./admissionCommit.js";

export type SessionConnectorStateV2 =
  | "attempt"
  | "ready"
  | "winner"
  | "admitted"
  | "established"
  | "terminated";

export type ConnectorArtifactLeaseV2 = ArtifactLeaseV2;

export type CandidateAttemptV2 = Readonly<{
  candidate: CanonicalArtifactCandidateV2;
  ready(signal?: AbortSignal): Promise<ReadyAdmissionTransportV2>;
  abort(): void;
}>;

export type CandidateAttemptFactoryV2 = Readonly<{
  create(candidate: CanonicalArtifactCandidateV2, artifact: ArtifactV2): CandidateAttemptV2;
}>;

export function composeCandidateAttemptFactoryV2(
  factories: Readonly<Partial<Record<CanonicalArtifactCandidateV2["carrier"], CandidateAttemptFactoryV2>>>,
): CandidateAttemptFactoryV2 {
  return Object.freeze({
    create(candidate: CanonicalArtifactCandidateV2, artifact: ArtifactV2): CandidateAttemptV2 {
      const factory = factories[candidate.carrier];
      if (factory === undefined) throw new Error(`runtime does not implement ${candidate.carrier}`);
      return factory.create(candidate, artifact);
    },
  });
}

export type SessionConnectorOptionsV2 = Readonly<{
  signal?: AbortSignal;
  connectTimeoutMs?: number;
}>;

type SessionConnectorInternalOptionsV2 = Readonly<{
  runtime: SessionProtocolRuntimeV2;
  connectTimeoutMs?: number;
  deadlineFactory?: SessionDeadlineFactoryV2;
  loserCloseTimeoutMs?: number;
  now?: () => number;
  capability?: RuntimeCapabilityDescriptorV2;
}>;

export type SessionConnectResultV2 = Readonly<{
  candidate: CanonicalArtifactCandidateV2;
  session: InternalSessionV2;
}>;

export class SessionConnectorV2 {
  state: SessionConnectorStateV2 = "attempt";
  private claimed = false;
  private readonly artifact: ArtifactV2;
  constructor(
    private readonly lease: ConnectorArtifactLeaseV2,
    private readonly attemptFactory: CandidateAttemptFactoryV2,
    private readonly options: SessionConnectorInternalOptionsV2,
  ) {
    this.artifact = unwrapArtifact(lease.artifact);
  }

  async connect(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<SessionConnectResultV2> {
    const path = connectorPath(this.artifact);
    if (this.claimed) {
      throw connectorError(path, "validate", "invalid_input", new Error("Flowersec v2 artifact is already claimed"));
    }
    this.claimed = true;
    let stage: FlowersecStage = "validate";
    let deadline: ReturnType<typeof createConnectorDeadline> | undefined;
    let operation: ReturnType<typeof combineConnectorSignals> | undefined;
    const diagnostics: FlowersecCandidateDiagnostic[] = [];
    try {
      let loserCloseTimeoutMs: number;
      let connectTimeoutMs: number;
      try {
        loserCloseTimeoutMs = normalizeLoserCloseTimeout(this.options.loserCloseTimeoutMs);
        connectTimeoutMs = normalizeConnectTimeout(this.options.connectTimeoutMs);
      } catch (error) {
        throw connectorError(path, "validate", "invalid_option", error);
      }
      let canonical: ReturnType<typeof validateArtifactV2>;
      try {
        canonical = validateArtifactV2(this.artifact);
      } catch (error) {
        throw connectorError(path, "validate", "invalid_input", error);
      }
      let remaining: number;
      try {
        remaining = artifactRemainingMilliseconds(this.artifact, this.options.now);
      } catch (error) {
        throw connectorError(
          path,
          "validate",
          error instanceof ArtifactExpiredError ? "timeout" : "invalid_input",
          error,
        );
      }
      const capability = this.options.capability;
      if (capability === undefined) {
        throw connectorError(path, "validate", "invalid_option", new TypeError("runtime capability is required"));
      }
      try {
        validateRuntimeCapabilityDescriptorV2(capability);
      } catch (error) {
        throw connectorError(path, "validate", "invalid_option", error);
      }
      if (capability.language !== "typescript") {
        throw connectorError(
          path,
          "validate",
          "invalid_option",
          new TypeError("SessionV2 connector requires a TypeScript runtime capability descriptor"),
        );
      }
      const requiredRole = this.artifact.path.kind === "tunnel" && this.artifact.path.role === 2
        ? "server"
        : "client";
      const supported = new Set(capability.tuples
        .filter(({ networkMode, sessionRole, path }) =>
          networkMode === "dial" && sessionRole === requiredRole && path === this.artifact.path.kind)
        .map(({ carrier }) => carrier));
      const candidates = canonical.candidates.filter((candidate) => supported.has(candidate.carrier));
      if (candidates.length === 0) {
        throw connectorError(
          path,
          "validate",
          "unsupported_capability",
          new Error("no runtime-compatible Flowersec v2 candidate"),
        );
      }
      try {
        deadline = createConnectorDeadline(Math.min(
          connectTimeoutMs,
          this.artifact.session.establish_timeout_seconds * 1_000,
          remaining,
        ), this.options.deadlineFactory);
      } catch (error) {
        throw connectorError(path, "validate", "invalid_option", error);
      }
	      operation = combineConnectorSignals(options.signal, deadline.signal);
	      const operationSignal = operation.signal;
	      const cancellationSignal = options.signal;
	      const abortSources: ConnectorAbortSources = cancellationSignal === undefined
	        ? { timeoutSignal: deadline.signal }
	        : { cancellationSignal, timeoutSignal: deadline.signal };
      stage = "connect";
      throwIfAborted(operationSignal);
      if (this.attemptFactory == null) {
        throw connectorError(path, "validate", "invalid_option", new TypeError("candidate attempt factory is required"));
      }
      const attempts: CandidateAttemptV2[] = [];
      const createErrors: Error[] = [];
      for (const candidate of candidates) {
        try {
          const attempt = this.attemptFactory.create(candidate, this.artifact);
          if (attempt == null) throw new TypeError("candidate factory returned no attempt");
          attempts.push(attempt);
        } catch (error) {
          const failure = candidateFailure(candidate, "connect", "dial_failed", error);
          diagnostics.push(failure.diagnostic);
          createErrors.push(failure.error);
        }
      }
      if (attempts.length === 0) {
        throw connectorError(
          path,
          "connect",
          dominantDiagnosticCode(diagnostics, "dial_failed"),
          aggregateErrors("no Flowersec v2 candidate could be created", createErrors),
          diagnostics,
        );
      }
      const barrier = deferred<void>();
      const results = new ResultQueue();
      const attemptTasks = attempts.map(async (attempt) => {
          await barrier.promise;
          let result: ReadyResult;
          try {
            result = { attempt, ready: await attempt.ready(operationSignal) };
          } catch (error) {
            result = { attempt, error };
          }
          results.push(result);
          return result;
        });
      barrier.resolve();

      let winner: ReadyResult | undefined;
      const errors = [...createErrors];
      try {
        for (let remaining = attempts.length; remaining > 0;) {
          throwIfAborted(operationSignal);
          const result = await raceAbort(results.shift(), operationSignal);
          remaining--;
          if (result.ready !== undefined) {
            winner = result;
            break;
          }
          const failure = candidateFailure(result.attempt.candidate, "connect", "dial_failed", result.error);
          diagnostics.push(failure.diagnostic);
          errors.push(failure.error);
        }
      } catch (error) {
        const cleanupFailures = await closeCandidateLosers(
          attempts,
          attemptTasks,
          undefined,
          operationSignal,
          abortSources,
          loserCloseTimeoutMs,
        );
        diagnostics.push(...cleanupFailures.map(({ diagnostic }) => diagnostic));
        throw connectorError(
          path,
          "connect",
          contextualErrorCode(error, "dial_failed", options.signal, deadline.signal),
          aggregateErrors("candidate race failed", [asError(error), ...cleanupFailures.map(({ error }) => error)]),
          diagnostics,
        );
      }
      if (winner?.ready === undefined) {
        const cleanupFailures = await closeCandidateLosers(
          attempts,
          attemptTasks,
          undefined,
          operationSignal,
          abortSources,
          loserCloseTimeoutMs,
        );
        diagnostics.push(...cleanupFailures.map(({ diagnostic }) => diagnostic));
        const failureStage: FlowersecStage = cleanupFailures.length === 0 ? "connect" : "close";
        throw connectorError(
          path,
          failureStage,
          failureStage === "connect"
            ? dominantDiagnosticCode(diagnostics, "dial_failed")
            : dominantCandidateCode(cleanupFailures, "not_connected"),
          aggregateErrors(
            cleanupFailures.length === 0
              ? "no Flowersec v2 candidate became ready"
              : "no Flowersec v2 candidate became ready; candidate cleanup failed",
            [...errors, ...cleanupFailures.map(({ error }) => error)],
          ),
          diagnostics,
        );
      }
      this.state = "ready";
      const selected = { attempt: winner.attempt, ready: winner.ready } as const;
      this.state = "winner";
      stage = "close";
      const cleanupFailures = await closeCandidateLosers(
        attempts,
        attemptTasks,
        selected,
        operationSignal,
        abortSources,
        loserCloseTimeoutMs,
      );
      if (cleanupFailures.length !== 0) {
        const winnerClose = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => selected.ready.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.ready.abort,
        );
        if (winnerClose !== undefined) cleanupFailures.push(winnerClose);
        diagnostics.push(...cleanupFailures.map(({ diagnostic }) => diagnostic));
        throw connectorError(
          path,
          "close",
          dominantCandidateCode(cleanupFailures, "not_connected"),
          aggregateErrors("candidate cleanup failed", cleanupFailures.map(({ error }) => error)),
          diagnostics,
        );
      }
      stage = "validate";
      try {
        artifactRemainingMilliseconds(this.artifact, this.options.now);
      } catch (error) {
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => selected.ready.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.ready.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        throw connectorError(
          path,
          "validate",
          error instanceof ArtifactExpiredError ? "timeout" : "invalid_input",
          aggregateErrors("artifact validation failed after candidate selection", [
            asError(error),
            ...(closeFailure === undefined ? [] : [closeFailure.error]),
          ]),
          diagnostics,
        );
      }

      let rawFSB2: Uint8Array;
      let config: SessionConfigV2;
      try {
        rawFSB2 = encodeFSB2RequestV2(buildFSB2RequestV2(this.artifact, selected.attempt.candidate.id));
        config = sessionConfigFromArtifactV2(
          this.artifact,
          rawFSB2,
          this.options.runtime,
          this.options.deadlineFactory,
        );
      } catch (error) {
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => selected.ready.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.ready.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        throw connectorError(path, "validate", "invalid_input", aggregateErrors(
          "failed to prepare Flowersec v2 admission request",
          [asError(error), ...(closeFailure === undefined ? [] : [closeFailure.error])],
        ), diagnostics);
      }

      stage = "attach";
      try {
        throwIfAborted(operationSignal);
      } catch (error) {
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => selected.ready.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.ready.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        throw connectorError(
          path,
          "attach",
          contextualErrorCode(error, "attach_failed", options.signal, deadline.signal),
          aggregateErrors("connection canceled before durable spend", [
            asError(error),
            ...(closeFailure === undefined ? [] : [closeFailure.error]),
          ]),
          diagnostics,
        );
      }

      let session: InternalSessionV2 | undefined;
      stage = "attach";
      try {
        throwIfAborted(operationSignal);
        const committed = await commitClientAdmissionV2(
          selected.ready,
          this.lease,
          () => {
            artifactRemainingMilliseconds(this.artifact, this.options.now);
          },
          rawFSB2,
          config,
          operationSignal,
        );
        if (committed == null) throw new TypeError("candidate commit returned no carrier session");
        this.state = "admitted";
        session = await establishSessionV2(
          committed,
          config,
          operationSignal === undefined ? {} : { signal: operationSignal },
        );
        throwIfAborted(operationSignal);
      } catch (error) {
        const failureStage: FlowersecStage = error instanceof ArtifactExpiredError
          ? "validate"
          : error instanceof SessionV2Error || error instanceof CredentialCommitError
            ? "handshake"
            : "attach";
        const defaultCode: FlowersecErrorCode = error instanceof ArtifactExpiredError
          ? "timeout"
          : error instanceof CredentialCommitError
            ? "credential_commit_failed"
            : error instanceof SessionV2Error
              ? "handshake_failed"
              : "attach_failed";
        diagnostics.push(candidateFailure(
          selected.attempt.candidate,
          failureStage,
          defaultCode,
          error,
        ).diagnostic);
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => closeCommittedSession(session, selected.ready),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.ready.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        throw connectorError(
          path,
          failureStage,
          contextualErrorCode(error, defaultCode, options.signal, deadline.signal),
          aggregateErrors(
            error instanceof CredentialCommitError
              ? "durable credential spend failed"
              : error instanceof AdmissionSessionV2Error
              ? "Flowersec v2 admission failed"
              : failureStage === "handshake"
                ? "Flowersec v2 session handshake failed"
                : "Flowersec v2 candidate commit failed",
            [asError(error), ...(closeFailure === undefined ? [] : [closeFailure.error])],
          ),
          diagnostics,
        );
      }
      this.state = "established";
      void session.waitTermination().finally(() => {
        this.state = "terminated";
      });
      return { candidate: selected.attempt.candidate, session };
    } catch (error) {
      this.state = "terminated";
      throw normalizeConnectorError(error, path, stage, diagnostics, options.signal, deadline?.signal);
    } finally {
      operation?.cancel();
      deadline?.cancel();
    }
  }
}

async function closeCommittedSession(
  session: InternalSessionV2 | undefined,
  ready: ReadyAdmissionTransportV2,
): Promise<void> {
  const operations: Array<() => Promise<void>> = [() => ready.close()];
  if (session !== undefined && typeof session.close === "function") {
    operations.push(() => session.close());
  }
  const settled = await Promise.allSettled(operations.map(async (operation) => await operation()));
  const failures = settled.flatMap((result) => result.status === "rejected" ? [asError(result.reason)] : []);
  if (failures.length !== 0) throw aggregateErrors("committed session cleanup failed", failures);
}

async function closeCandidateLosers(
  attempts: readonly CandidateAttemptV2[],
  attemptTasks: readonly Promise<ReadyResult>[],
  winner: (ReadyResult & Readonly<{ ready: ReadyAdmissionTransportV2 }>) | undefined,
  operationSignal: AbortSignal,
  abortSources: ConnectorAbortSources,
  timeoutMs: number,
): Promise<CandidateFailure[]> {
  const deadline = new AbortController();
  const timeoutError = new TimeoutError("candidate cleanup timeout");
  const timer = setTimeout(() => deadline.abort(timeoutError), timeoutMs);
  const signal = combineConnectorSignals(operationSignal, deadline.signal);
  const failures: CandidateFailure[] = [];
  const loserSet = new Set(attempts.filter((attempt) => winner === undefined || attempt !== winner.attempt));
  try {
    for (const attempt of loserSet) {
      try {
        attempt.abort();
      } catch (error) {
        failures.push(candidateFailure(attempt.candidate, "close", "not_connected", error));
      }
    }
    let results: readonly ReadyResult[];
    try {
      results = await raceAbort(Promise.all(attemptTasks), signal.signal);
    } catch (error) {
      if (!signal.signal.aborted) throw error;
      const code = cleanupErrorCode(error, "not_connected", abortSources, deadline.signal);
      for (const attempt of loserSet) {
        failures.push(candidateFailure(attempt.candidate, "close", code, abortReason(signal.signal)));
      }
      return failures;
    }
    for (const result of results) {
      if (result.ready === undefined || !loserSet.has(result.attempt)) continue;
      const failure = await captureCandidateCleanupFailure(
        result.attempt.candidate,
        "close candidate loser",
        () => result.ready!.close(),
        timeoutMs,
        signal.signal,
        abortSources,
        result.ready.abort,
      );
      if (failure !== undefined) failures.push(failure);
    }
    return failures;
  } finally {
    clearTimeout(timer);
    signal.cancel();
  }
}

async function captureCandidateCleanupFailure(
  candidate: CanonicalArtifactCandidateV2,
  label: string,
  operation: () => Promise<void>,
  timeoutMs: number,
  operationSignal?: AbortSignal,
  abortSources: ConnectorAbortSources = {},
  abort?: () => void,
): Promise<CandidateFailure | undefined> {
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(new TimeoutError(`${label} timeout`)), timeoutMs);
  const signal = combineConnectorSignals(operationSignal, deadline.signal);
  try {
    let pending: Promise<void>;
    try {
      pending = Promise.resolve(operation());
    } catch (error) {
      return candidateFailure(candidate, "close", "not_connected", new Error(`${label}: ${asError(error).message}`));
    }
    void pending.catch(() => undefined);
    await raceAbort(pending, signal.signal);
    return undefined;
  } catch (error) {
    const code = cleanupErrorCode(error, "not_connected", abortSources, deadline.signal);
    const causes = [asError(error)];
    if (signal.signal.aborted && abort !== undefined) {
      try {
        abort();
      } catch (abortError) {
        causes.push(asError(abortError));
      }
    }
    return candidateFailure(
      candidate,
      "close",
      code,
      causes.length === 1
        ? new Error(`${label}: ${causes[0]!.message}`)
        : aggregateErrors(`${label} failed`, causes),
    );
  } finally {
    clearTimeout(timer);
    signal.cancel();
  }
}

function normalizeLoserCloseTimeout(value: number | undefined): number {
  const timeout = value ?? 1_000;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 60_000) {
    throw new RangeError("loserCloseTimeoutMs must be an integer from 1 to 60000");
  }
  return timeout;
}

function normalizeConnectTimeout(value: number | undefined): number {
  const timeout = value ?? SDK_DEFAULTS.transport.connectTimeoutMs;
  if (!Number.isSafeInteger(timeout) || timeout < 1) {
    throw new RangeError("connectTimeoutMs must be a positive safe integer");
  }
  return timeout;
}

function artifactRemainingMilliseconds(artifact: ArtifactV2, now?: () => number): number {
  const current = (now ?? Date.now)();
  if (!Number.isFinite(current)) throw new TypeError("session V2 clock returned a non-finite value");
  const remaining = artifact.session.init_expire_at_unix_s * 1_000 - current;
  if (remaining <= 0) throw new ArtifactExpiredError();
  return remaining;
}

class ArtifactExpiredError extends Error {
  constructor() {
    super("Flowersec v2 artifact initiation deadline expired");
    this.name = "ArtifactExpiredError";
  }
}

type ReadyResult = Readonly<{
  attempt: CandidateAttemptV2;
  ready?: ReadyAdmissionTransportV2;
  error?: unknown;
}>;

type CandidateFailure = Readonly<{
  diagnostic: FlowersecCandidateDiagnostic;
  error: Error;
}>;

type ConnectorAbortSources = Readonly<{
  cancellationSignal?: AbortSignal;
  timeoutSignal?: AbortSignal;
}>;

class ResultQueue {
  private readonly values: ReadyResult[] = [];
  private readonly waiters: Array<(value: ReadyResult) => void> = [];

  push(value: ReadyResult): void {
    const waiter = this.waiters.shift();
    if (waiter !== undefined) waiter(value);
    else this.values.push(value);
  }

  async shift(): Promise<ReadyResult> {
    const value = this.values.shift();
    if (value !== undefined) return value;
    return await new Promise<ReadyResult>((resolve) => this.waiters.push(resolve));
  }
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
}>;

function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  throwIfAborted(signal);
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(abortReason(signal));
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw abortReason(signal);
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("session V2 connect aborted");
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function connectorPath(artifact: ArtifactV2 | undefined): FlowersecPath {
  if (artifact?.path?.kind === "tunnel") return "tunnel";
  if (artifact?.path?.kind === "direct") return "direct";
  return "auto";
}

function connectorError(
  path: FlowersecPath,
  stage: FlowersecStage,
  code: FlowersecErrorCode,
  cause: unknown,
  diagnostics: readonly FlowersecCandidateDiagnostic[] = [],
): ConnectError {
  return createConnectErrorInternal({
    path,
    stage,
    code,
    cause,
    diagnostics,
  });
}

function normalizeConnectorError(
  error: unknown,
  path: FlowersecPath,
  stage: FlowersecStage,
  diagnostics: readonly FlowersecCandidateDiagnostic[],
  cancellationSignal?: AbortSignal,
  timeoutSignal?: AbortSignal,
): ConnectError {
  if (error instanceof ConnectError) {
    const details = connectErrorDetailsInternal(error);
    const merged = mergeDiagnostics(details.diagnostics, diagnostics);
    if (merged.length === details.diagnostics.length) return error;
    return createConnectErrorInternal({
      path,
      stage: details.stage,
      code: details.code,
      cause: details.cause ?? error,
      diagnostics: merged,
    });
  }
  return connectorError(
    path,
    stage,
    contextualErrorCode(error, defaultCodeForStage(stage), cancellationSignal, timeoutSignal),
    error,
    diagnostics,
  );
}

function defaultCodeForStage(stage: FlowersecStage): FlowersecErrorCode {
  switch (stage) {
    case "validate": return "invalid_input";
    case "connect": return "dial_failed";
    case "attach": return "attach_failed";
    case "handshake": return "handshake_failed";
    case "close": return "not_connected";
    case "secure": return "handshake_failed";
    case "yamux": return "mux_failed";
    case "rpc": return "rpc_failed";
  }
}

function contextualErrorCode(
  error: unknown,
  defaultCode: FlowersecErrorCode,
  cancellationSignal?: AbortSignal,
  timeoutSignal?: AbortSignal,
): FlowersecErrorCode {
  if (cancellationSignal?.aborted === true) return "canceled";
  if (timeoutSignal?.aborted === true) return "timeout";
  if (error instanceof TimeoutError || (error instanceof SessionV2Error && error.code === "timeout")) return "timeout";
  if (error instanceof AbortError ||
      (error instanceof SessionV2Error && error.code === "aborted") ||
      (error instanceof DOMException && error.name === "AbortError")) return "canceled";
  return defaultCode;
}

function cleanupErrorCode(
  error: unknown,
  defaultCode: FlowersecErrorCode,
  abortSources: ConnectorAbortSources,
  cleanupDeadline: AbortSignal,
): FlowersecErrorCode {
  return contextualErrorCode(
    error,
    defaultCode,
    abortSources.cancellationSignal,
    abortSources.timeoutSignal?.aborted === true ? abortSources.timeoutSignal : cleanupDeadline,
  );
}

function candidateFailure(
  candidate: CanonicalArtifactCandidateV2,
  stage: FlowersecStage,
  defaultCode: FlowersecErrorCode,
  error: unknown,
): CandidateFailure {
  const failure = asError(error);
  const code = contextualErrorCode(error, defaultCode);
  return {
    error: failure,
    diagnostic: {
      candidateId: candidate.id,
      carrier: candidate.carrier,
      stage,
      code,
      message: boundedCandidateDiagnosticMessage(failure.message),
    },
  };
}

function dominantCandidateCode(
  failures: readonly CandidateFailure[],
  defaultCode: FlowersecErrorCode,
): FlowersecErrorCode {
  if (failures.some(({ diagnostic }) => diagnostic.code === "canceled")) return "canceled";
  if (failures.some(({ diagnostic }) => diagnostic.code === "timeout")) return "timeout";
  if (failures.some(({ diagnostic }) => diagnostic.code === "not_connected")) return "not_connected";
  return defaultCode;
}

function dominantDiagnosticCode(
  diagnostics: readonly FlowersecCandidateDiagnostic[],
  defaultCode: FlowersecErrorCode,
): FlowersecErrorCode {
  if (diagnostics.some(({ code }) => code === "canceled")) return "canceled";
  if (diagnostics.some(({ code }) => code === "timeout")) return "timeout";
  return defaultCode;
}

const MAX_CANDIDATE_DIAGNOSTIC_MESSAGE_BYTES = 1_024;
const candidateDiagnosticEncoder = new TextEncoder();

function boundedCandidateDiagnosticMessage(message: string): string {
  if (candidateDiagnosticEncoder.encode(message).length <= MAX_CANDIDATE_DIAGNOSTIC_MESSAGE_BYTES) return message;
  let result = "";
  let bytes = 0;
  for (const character of message) {
    const characterBytes = candidateDiagnosticEncoder.encode(character).length;
    if (bytes + characterBytes > MAX_CANDIDATE_DIAGNOSTIC_MESSAGE_BYTES) break;
    result += character;
    bytes += characterBytes;
  }
  return result;
}

function mergeDiagnostics(
  left: readonly FlowersecCandidateDiagnostic[],
  right: readonly FlowersecCandidateDiagnostic[],
): FlowersecCandidateDiagnostic[] {
  const merged: FlowersecCandidateDiagnostic[] = [];
  const seen = new Set<string>();
  for (const diagnostic of [...left, ...right]) {
    const key = [
      diagnostic.candidateId,
      diagnostic.carrier,
      diagnostic.stage,
      diagnostic.code,
      diagnostic.message,
    ].join("\u0000");
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(diagnostic);
  }
  return merged;
}

function aggregateErrors(label: string, errors: readonly Error[]): Error {
  if (errors.length === 0) return new Error(label);
  return new AggregateError(errors, `${label}: ${errors.map(({ message }) => message).join("; ")}`);
}

function createConnectorDeadline(timeoutMs: number, factory?: SessionDeadlineFactoryV2): Readonly<{
  signal: AbortSignal;
  cancel(): void;
}> {
  if (factory !== undefined) {
    const handle = factory(timeoutMs, "establish");
    if (handle == null || !isAbortSignal(handle.signal) || typeof handle.cancel !== "function") {
      throw new TypeError("deadlineFactory returned an invalid establish deadline handle");
    }
    return handle;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new TimeoutError("session V2 establish deadline exceeded")), timeoutMs);
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

function isAbortSignal(value: unknown): value is AbortSignal {
  if (typeof value !== "object" || value === null) return false;
  const signal = value as Partial<AbortSignal>;
  return typeof signal.aborted === "boolean" &&
    typeof signal.addEventListener === "function" &&
    typeof signal.removeEventListener === "function";
}

function combineConnectorSignals(...signals: Array<AbortSignal | undefined>): Readonly<{
  signal: AbortSignal;
  cancel(): void;
}> {
  const controller = new AbortController();
  const cleanups: Array<() => void> = [];
  for (const signal of signals) {
    if (signal === undefined) continue;
    const abort = () => {
      if (!controller.signal.aborted) controller.abort(signal.reason instanceof Error ? signal.reason : new Error("session V2 connect aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
    cleanups.push(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  }
  return { signal: controller.signal, cancel: () => { for (const cleanup of cleanups.splice(0)) cleanup(); } };
}
