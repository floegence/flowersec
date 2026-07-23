import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import {
  admissionBindingV2,
  buildFSB2RequestV2,
  encodeFSB2RequestV2,
  validateArtifactV2,
  type ArtifactV2,
  type CanonicalArtifactCandidateV2,
} from "../v2/artifact.js";
import {
  AdmissionSessionV2Error,
  establishAdmittedNativeSessionV2,
  establishAdmittedWebSocketSessionV2,
} from "../v2/admittedSession.js";
import { base64urlDecode } from "../utils/base64url.js";
import {
  SessionV2Error,
  type SessionConfigV2,
  type SessionDeadlineFactoryV2,
  type SessionV2,
} from "../v2/session.js";
import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import { unwrapArtifact } from "../v2/opaqueArtifact.js";
import {
  AbortError,
  FlowersecError,
  TimeoutError,
  type FlowersecCandidateDiagnostic,
  type FlowersecErrorCode,
  type FlowersecPath,
  type FlowersecStage,
} from "../utils/errors.js";
import {
  detectBrowserRuntimeCapabilityV2,
  validateRuntimeCapabilityDescriptorV2,
  type RuntimeCapabilityDescriptorV2,
} from "../v2/capability.js";
import {
  createBrowserWebTransportCarrierInternalStage,
  type BrowserWebTransportCarrierInternalStage,
} from "./webTransportCarrierInternalStage.js";

export type BrowserConnectorStateV2 =
  | "validated"
  | "preconnecting"
  | "winner_selected"
  | "losers_closed"
  | "spent"
  | "established"
  | "terminated";

export type BrowserArtifactLeaseV2 = ArtifactLeaseV2;

export type BrowserPreparedCandidateV2 = Readonly<{
  candidate: CanonicalArtifactCandidateV2;
  commit(rawFSB2: Uint8Array, reasons: ReadonlySet<string>, config: SessionConfigV2, signal?: AbortSignal): Promise<SessionV2>;
  close(): Promise<void>;
  abort(): void;
}>;

export type BrowserCandidateAttemptV2 = Readonly<{
  candidate: CanonicalArtifactCandidateV2;
  ready(signal?: AbortSignal): Promise<BrowserPreparedCandidateV2>;
  abort(): void;
}>;

export type BrowserCandidateAttemptFactoryV2 = Readonly<{
  create(candidate: CanonicalArtifactCandidateV2, artifact: ArtifactV2): BrowserCandidateAttemptV2;
}>;

export type BrowserSessionConnectorV2Options = Readonly<{
  admissionReasons: ReadonlySet<string>;
  deadlineFactory?: SessionDeadlineFactoryV2;
  loserCloseTimeoutMs?: number;
  now?: () => number;
  capability?: RuntimeCapabilityDescriptorV2;
}>;

export type BrowserSessionConnectResultV2 = Readonly<{
  candidate: CanonicalArtifactCandidateV2;
  session: SessionV2;
}>;

export class BrowserSessionConnectorV2 {
  state: BrowserConnectorStateV2 = "validated";
  private claimed = false;
  private readonly artifact: ArtifactV2;
  constructor(
    private readonly lease: BrowserArtifactLeaseV2,
    private readonly options: BrowserSessionConnectorV2Options,
  ) {
    this.artifact = unwrapArtifact(lease.artifact);
  }

  async connect(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<BrowserSessionConnectResultV2> {
    const path = browserConnectorPath(this.artifact);
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
      try {
        loserCloseTimeoutMs = normalizeLoserCloseTimeout(this.options.loserCloseTimeoutMs);
      } catch (error) {
        throw connectorError(path, "validate", "invalid_option", error);
      }
      if (typeof this.lease?.commitSpend !== "function") {
        throw connectorError(path, "validate", "invalid_option", new TypeError("browser SessionV2 requires a durable artifact lease"));
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
          error instanceof BrowserArtifactExpiredError ? "timeout" : "invalid_input",
          error,
        );
      }
      const capability = this.options.capability ?? detectBrowserRuntimeCapabilityV2();
      try {
        validateRuntimeCapabilityDescriptorV2(capability);
      } catch (error) {
        throw connectorError(path, "validate", "invalid_option", error);
      }
      if (capability.language !== "typescript" || capability.runtime !== "browser") {
        throw connectorError(
          path,
          "validate",
          "invalid_option",
          new TypeError("browser SessionV2 requires a TypeScript browser capability descriptor"),
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
          "transport_policy_denied",
          new Error("no browser-compatible Flowersec v2 candidate"),
        );
      }
      try {
        deadline = createConnectorDeadline(Math.min(
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
      const attemptFactory = browserConnectorAttemptFactories.get(this) ?? new ProductionBrowserAttemptFactory();
      const attempts: BrowserCandidateAttemptV2[] = [];
      const createErrors: Error[] = [];
      for (const candidate of candidates) {
        try {
          const attempt = attemptFactory.create(candidate, this.artifact);
          if (attempt == null) throw new TypeError("browser candidate factory returned no attempt");
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
          aggregateErrors("no browser Flowersec v2 candidate could be created", createErrors),
          diagnostics,
        );
      }
      this.state = "preconnecting";
      const barrier = deferred<void>();
      const results = new ResultQueue();
      const attemptTasks = attempts.map(async (attempt) => {
          await barrier.promise;
          let result: ReadyResult;
          try {
            result = { attempt, prepared: await attempt.ready(operationSignal) };
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
          if (result.prepared !== undefined) {
            winner = result;
            break;
          }
          const failure = candidateFailure(result.attempt.candidate, "connect", "dial_failed", result.error);
          diagnostics.push(failure.diagnostic);
          errors.push(failure.error);
        }
      } catch (error) {
        const cleanupFailures = await closeBrowserCandidateLosers(
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
          aggregateErrors("browser candidate race failed", [asError(error), ...cleanupFailures.map(({ error }) => error)]),
          diagnostics,
        );
      }
      if (winner?.prepared === undefined) {
        const cleanupFailures = await closeBrowserCandidateLosers(
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
              ? "no browser Flowersec v2 candidate became ready"
              : "no browser Flowersec v2 candidate became ready; browser candidate cleanup failed",
            [...errors, ...cleanupFailures.map(({ error }) => error)],
          ),
          diagnostics,
        );
      }
      const selected = { attempt: winner.attempt, prepared: winner.prepared } as const;
      this.state = "winner_selected";
      stage = "close";
      const cleanupFailures = await closeBrowserCandidateLosers(
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
          () => selected.prepared.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.prepared.abort,
        );
        if (winnerClose !== undefined) cleanupFailures.push(winnerClose);
        diagnostics.push(...cleanupFailures.map(({ diagnostic }) => diagnostic));
        throw connectorError(
          path,
          "close",
          dominantCandidateCode(cleanupFailures, "not_connected"),
          aggregateErrors("browser candidate cleanup failed", cleanupFailures.map(({ error }) => error)),
          diagnostics,
        );
      }
      this.state = "losers_closed";

      stage = "validate";
      try {
        artifactRemainingMilliseconds(this.artifact, this.options.now);
      } catch (error) {
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => selected.prepared.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.prepared.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        throw connectorError(
          path,
          "validate",
          error instanceof BrowserArtifactExpiredError ? "timeout" : "invalid_input",
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
        config = sessionConfig(this.artifact, rawFSB2, this.options.deadlineFactory);
      } catch (error) {
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => selected.prepared.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.prepared.abort,
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
          () => selected.prepared.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.prepared.abort,
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

      stage = "handshake";
      try {
        await this.lease.commitSpend(operationSignal);
        this.state = "spent";
        throwIfAborted(operationSignal);
      } catch (error) {
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => selected.prepared.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.prepared.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        throw connectorError(
          path,
          "handshake",
          contextualErrorCode(error, "credential_commit_failed", options.signal, deadline.signal),
          aggregateErrors("durable credential spend failed", [
            asError(error),
            ...(closeFailure === undefined ? [] : [closeFailure.error]),
          ]),
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
          () => selected.prepared.close(),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.prepared.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        throw connectorError(
          path,
          "validate",
          error instanceof BrowserArtifactExpiredError ? "timeout" : "invalid_input",
          aggregateErrors("artifact validation failed after durable spend", [
            asError(error),
            ...(closeFailure === undefined ? [] : [closeFailure.error]),
          ]),
          diagnostics,
        );
      }
      let session: SessionV2 | undefined;
      stage = "attach";
      try {
        throwIfAborted(operationSignal);
        const committed = await selected.prepared.commit(
          rawFSB2,
          this.options.admissionReasons,
          config,
          operationSignal,
        );
        if (committed == null) throw new TypeError("browser candidate commit returned no session");
        session = committed;
        throwIfAborted(operationSignal);
      } catch (error) {
        const closeFailure = await captureCandidateCleanupFailure(
          selected.attempt.candidate,
          "close selected candidate",
          () => closeCommittedBrowserSession(session, selected.prepared),
          loserCloseTimeoutMs,
          operationSignal,
          abortSources,
          selected.prepared.abort,
        );
        if (closeFailure !== undefined) diagnostics.push(closeFailure.diagnostic);
        const failureStage: FlowersecStage = error instanceof SessionV2Error ? "handshake" : "attach";
        const fallbackCode: FlowersecErrorCode = error instanceof SessionV2Error ? "handshake_failed" : "attach_failed";
        throw connectorError(
          path,
          failureStage,
          contextualErrorCode(error, fallbackCode, options.signal, deadline.signal),
          aggregateErrors(
            error instanceof AdmissionSessionV2Error
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
      return { candidate: selected.attempt.candidate, session };
    } catch (error) {
      this.state = "terminated";
      throw normalizeConnectorError(error, path, stage, diagnostics, options.signal, deadline?.signal);
    } finally {
      try { operation?.cancel(); } catch { /* listener cleanup is best-effort */ }
      try { deadline?.cancel(); } catch { /* a deadline cancel callback cannot change the connection result */ }
    }
  }
}

const browserConnectorAttemptFactories = new WeakMap<
  BrowserSessionConnectorV2,
  BrowserCandidateAttemptFactoryV2
>();

export function createBrowserSessionConnectorV2InternalStage(
  lease: BrowserArtifactLeaseV2,
  options: BrowserSessionConnectorV2Options & Readonly<{
    attemptFactory: BrowserCandidateAttemptFactoryV2;
  }>,
): BrowserSessionConnectorV2 {
  const { attemptFactory, ...publicOptions } = options;
  const connector = new BrowserSessionConnectorV2(lease, publicOptions);
  browserConnectorAttemptFactories.set(connector, attemptFactory);
  return connector;
}

async function closeCommittedBrowserSession(
  session: SessionV2 | undefined,
  prepared: BrowserPreparedCandidateV2,
): Promise<void> {
  const operations: Array<() => Promise<void>> = [() => prepared.close()];
  if (session !== undefined && typeof session.close === "function") {
    operations.push(() => session.close());
  }
  const settled = await Promise.allSettled(operations.map(async (operation) => await operation()));
  const failures = settled.flatMap((result) => result.status === "rejected" ? [asError(result.reason)] : []);
  if (failures.length !== 0) throw aggregateErrors("committed session cleanup failed", failures);
}

async function closeBrowserCandidateLosers(
  attempts: readonly BrowserCandidateAttemptV2[],
  attemptTasks: readonly Promise<ReadyResult>[],
  winner: (ReadyResult & Readonly<{ prepared: BrowserPreparedCandidateV2 }>) | undefined,
  operationSignal: AbortSignal,
  abortSources: ConnectorAbortSources,
  timeoutMs: number,
): Promise<CandidateFailure[]> {
  const deadline = new AbortController();
  const timeoutError = new TimeoutError("browser candidate cleanup timeout");
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
      if (result.prepared === undefined || !loserSet.has(result.attempt)) continue;
      const failure = await captureCandidateCleanupFailure(
        result.attempt.candidate,
        "close browser candidate loser",
        () => result.prepared!.close(),
        timeoutMs,
        signal.signal,
        abortSources,
        result.prepared.abort,
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

function artifactRemainingMilliseconds(artifact: ArtifactV2, now?: () => number): number {
  const current = (now ?? Date.now)();
  if (!Number.isFinite(current)) throw new TypeError("browser SessionV2 clock returned a non-finite value");
  const remaining = artifact.session.init_expire_at_unix_s * 1_000 - current;
  if (remaining <= 0) throw new BrowserArtifactExpiredError();
  return remaining;
}

class BrowserArtifactExpiredError extends Error {
  constructor() {
    super("Flowersec v2 artifact initiation deadline expired");
    this.name = "BrowserArtifactExpiredError";
  }
}

export async function connectBrowserSessionV2(
  lease: BrowserArtifactLeaseV2,
  options: BrowserSessionConnectorV2Options & Readonly<{ signal?: AbortSignal }>,
): Promise<BrowserSessionConnectResultV2> {
  const connector = new BrowserSessionConnectorV2(lease, options);
  return await connector.connect(options.signal === undefined ? {} : { signal: options.signal });
}

type BrowserWebSocketLikeV2 = WebSocketLike & Readonly<{ protocol?: string }>;

class ProductionBrowserAttemptFactory implements BrowserCandidateAttemptFactoryV2 {
  create(candidate: CanonicalArtifactCandidateV2, artifact: ArtifactV2): BrowserCandidateAttemptV2 {
    if (candidate.carrier === "websocket") {
      return new BrowserWebSocketAttempt(candidate, artifact.path.kind);
    }
    if (candidate.carrier === "webtransport") {
      return new BrowserWebTransportAttempt(
        candidate,
        artifact.path.kind,
        artifact.session.max_inbound_streams + 2,
      );
    }
    throw new Error(`unsupported browser carrier ${candidate.carrier}`);
  }
}

class BrowserWebSocketAttempt implements BrowserCandidateAttemptV2 {
  private socket: BrowserWebSocketLikeV2 | undefined;
  private transport: WebSocketBinaryTransport | undefined;
  private aborted = false;
  private committed = false;

  constructor(
    readonly candidate: CanonicalArtifactCandidateV2,
    private readonly path: "direct" | "tunnel",
    private readonly factory = defaultWebSocketFactory,
  ) {}

  async ready(signal?: AbortSignal): Promise<BrowserPreparedCandidateV2> {
    if (this.aborted) throw new Error("WebSocket candidate aborted");
    const subprotocol = this.path === "direct" ? "flowersec.direct.v2" : "flowersec.tunnel.v2";
    const socket = this.factory(this.candidate.normalized_url, subprotocol);
    this.socket = socket;
    await waitForWebSocketOpen(socket, subprotocol, signal);
    if (this.aborted) throw new Error("WebSocket candidate aborted");
    const transport = new WebSocketBinaryTransport(socket);
    this.transport = transport;
    return {
      candidate: this.candidate,
      commit: async (rawFSB2, reasons, config, commitSignal) => {
        if (this.committed) throw new Error("WebSocket candidate already committed");
        this.committed = true;
        return await establishAdmittedWebSocketSessionV2(
          transport,
          rawFSB2,
          reasons,
          config,
          commitSignal === undefined ? {} : { signal: commitSignal },
        );
      },
      close: async () => transport.close(),
      abort: () => transport.close(),
    };
  }

  abort(): void {
    this.aborted = true;
    this.transport?.close();
    this.socket?.close();
  }
}

class BrowserWebTransportAttempt implements BrowserCandidateAttemptV2 {
  private carrier: BrowserWebTransportCarrierInternalStage | undefined;
  private readonly abortController = new AbortController();
  private committed = false;

  constructor(
    readonly candidate: CanonicalArtifactCandidateV2,
    private readonly path: "direct" | "tunnel",
    private readonly maxIncomingStreams: number,
  ) {}

  async ready(signal?: AbortSignal): Promise<BrowserPreparedCandidateV2> {
    const unlink = linkAbort(signal, this.abortController);
    try {
      const carrier = await createBrowserWebTransportCarrierInternalStage(this.candidate.normalized_url, {
        path: this.path,
        signal: this.abortController.signal,
        maxIncomingStreams: this.maxIncomingStreams,
      });
      this.carrier = carrier;
      return {
        candidate: this.candidate,
        commit: async (rawFSB2, reasons, config, commitSignal) => {
          if (this.committed) throw new Error("WebTransport candidate already committed");
          this.committed = true;
          return await establishAdmittedNativeSessionV2(
            carrier,
            rawFSB2,
            reasons,
            config,
            commitSignal === undefined ? {} : { signal: commitSignal },
          );
        },
        close: async () => await carrier.close(),
        abort: () => carrier.abort({ code: 6, reason: "browser candidate aborted" }),
      };
    } finally {
      unlink();
    }
  }

  abort(): void {
    this.abortController.abort();
    this.carrier?.abort({ code: 6, reason: "browser candidate aborted" });
  }
}

function sessionConfig(
  artifact: ArtifactV2,
  rawFSB2: Uint8Array,
  deadlineFactory?: SessionDeadlineFactoryV2,
): SessionConfigV2 {
  const localBinding = admissionBindingV2(rawFSB2);
  const tunnel = artifact.path.kind === "tunnel" ? artifact.path : undefined;
  return {
    role: tunnel?.role === 2 ? "server" : "client",
    path: artifact.path.kind,
    channelID: artifact.session.channel_id,
    sessionContractHash: base64urlDecode(artifact.session.contract_hash_b64u),
    suite: artifact.session.default_suite,
    psk: base64urlDecode(artifact.session.e2ee_psk_b64u),
    maxInboundStreams: artifact.session.max_inbound_streams,
    sessionContract: artifact.session,
    idleTimeoutMs: artifact.session.idle_timeout_seconds * 1_000,
    localAdmissionBinding: localBinding,
    peerAdmissionBinding: tunnel === undefined ? localBinding : new Uint8Array(32),
    localEndpointInstanceID: tunnel?.local_endpoint_instance_id ?? "",
    expectedPeerEndpointInstanceID: tunnel?.expected_peer_endpoint_instance_id ?? "",
    deadlines: {
      establishTimeoutMs: artifact.session.establish_timeout_seconds * 1_000,
      rekeyPrepareTimeoutMs: artifact.session.rekey_prepare_timeout_seconds * 1_000,
      rekeyCompletionTimeoutMs: artifact.session.rekey_completion_timeout_seconds * 1_000,
      ...(deadlineFactory === undefined ? {} : { factory: deadlineFactory }),
    },
  };
}

type ReadyResult = Readonly<{
  attempt: BrowserCandidateAttemptV2;
  prepared?: BrowserPreparedCandidateV2;
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

function defaultWebSocketFactory(url: string, subprotocol: string): BrowserWebSocketLikeV2 {
  const Constructor = (globalThis as unknown as { WebSocket?: new (url: string, protocols?: string | string[]) => BrowserWebSocketLikeV2 }).WebSocket;
  if (Constructor === undefined) throw new Error("WebSocket is unavailable in this browser runtime");
  return new Constructor(url, subprotocol);
}

async function waitForWebSocketOpen(socket: BrowserWebSocketLikeV2, expectedProtocol: string, signal?: AbortSignal): Promise<void> {
  if (socket.readyState === 1) {
    validateSubprotocol(socket, expectedProtocol);
    return;
  }
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      socket.removeEventListener("open", open);
      socket.removeEventListener("error", error);
      socket.removeEventListener("close", close);
      signal?.removeEventListener("abort", abort);
    };
    const finish = (failure?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      failure === undefined ? resolve() : reject(failure);
    };
    const open = () => {
      try { validateSubprotocol(socket, expectedProtocol); finish(); }
      catch (cause) { finish(asError(cause)); }
    };
    const error = () => finish(new Error("WebSocket candidate failed before ready"));
    const close = () => finish(new Error("WebSocket candidate closed before ready"));
    const abort = () => { socket.close(); finish(new Error("WebSocket candidate aborted")); };
    socket.addEventListener("open", open);
    socket.addEventListener("error", error);
    socket.addEventListener("close", close);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted === true) abort();
  });
}

function validateSubprotocol(socket: BrowserWebSocketLikeV2, expected: string): void {
  if (socket.protocol !== undefined && socket.protocol !== expected) {
    throw new Error(`unexpected WebSocket subprotocol ${socket.protocol}`);
  }
}

function linkAbort(signal: AbortSignal | undefined, controller: AbortController): () => void {
  if (signal === undefined) return () => undefined;
  const abort = () => controller.abort();
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) abort();
  return () => signal.removeEventListener("abort", abort);
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
  return signal.reason instanceof Error ? signal.reason : new Error("browser SessionV2 connect aborted");
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function browserConnectorPath(artifact: ArtifactV2 | undefined): FlowersecPath {
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
): FlowersecError {
  return new FlowersecError({
    path,
    stage,
    code,
    message: asError(cause).message,
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
): FlowersecError {
  if (error instanceof FlowersecError) {
    const merged = mergeDiagnostics(error.diagnostics, diagnostics);
    if (merged.length === error.diagnostics.length) return error;
    return new FlowersecError({
      path: error.path,
      stage: error.stage,
      code: error.code,
      message: flowersecErrorDetail(error),
      cause: error.cause ?? error,
      diagnostics: merged,
    });
  }
  return connectorError(
    path,
    stage,
    contextualErrorCode(error, fallbackCodeForStage(stage), cancellationSignal, timeoutSignal),
    error,
    diagnostics,
  );
}

function flowersecErrorDetail(error: FlowersecError): string {
  const prefix = `${error.path} ${error.stage} (${error.code}): `;
  return error.message.startsWith(prefix) ? error.message.slice(prefix.length) : error.message;
}

function fallbackCodeForStage(stage: FlowersecStage): FlowersecErrorCode {
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
  fallback: FlowersecErrorCode,
  cancellationSignal?: AbortSignal,
  timeoutSignal?: AbortSignal,
): FlowersecErrorCode {
  if (cancellationSignal?.aborted === true) return "canceled";
  if (timeoutSignal?.aborted === true) return "timeout";
  if (error instanceof TimeoutError || (error instanceof SessionV2Error && error.code === "timeout")) return "timeout";
  if (error instanceof AbortError ||
      (error instanceof SessionV2Error && error.code === "aborted") ||
      (error instanceof DOMException && error.name === "AbortError")) return "canceled";
  return fallback;
}

function cleanupErrorCode(
  error: unknown,
  fallback: FlowersecErrorCode,
  abortSources: ConnectorAbortSources,
  cleanupDeadline: AbortSignal,
): FlowersecErrorCode {
  return contextualErrorCode(
    error,
    fallback,
    abortSources.cancellationSignal,
    abortSources.timeoutSignal?.aborted === true ? abortSources.timeoutSignal : cleanupDeadline,
  );
}

function candidateFailure(
  candidate: CanonicalArtifactCandidateV2,
  stage: FlowersecStage,
  fallback: FlowersecErrorCode,
  error: unknown,
): CandidateFailure {
  const failure = asError(error);
  const code = contextualErrorCode(error, fallback);
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
  fallback: FlowersecErrorCode,
): FlowersecErrorCode {
  if (failures.some(({ diagnostic }) => diagnostic.code === "canceled")) return "canceled";
  if (failures.some(({ diagnostic }) => diagnostic.code === "timeout")) return "timeout";
  if (failures.some(({ diagnostic }) => diagnostic.code === "not_connected")) return "not_connected";
  return fallback;
}

function dominantDiagnosticCode(
  diagnostics: readonly FlowersecCandidateDiagnostic[],
  fallback: FlowersecErrorCode,
): FlowersecErrorCode {
  if (diagnostics.some(({ code }) => code === "canceled")) return "canceled";
  if (diagnostics.some(({ code }) => code === "timeout")) return "timeout";
  return fallback;
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
  const timer = setTimeout(() => controller.abort(new TimeoutError("browser SessionV2 establish deadline exceeded")), timeoutMs);
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
      if (!controller.signal.aborted) controller.abort(signal.reason instanceof Error ? signal.reason : new Error("browser SessionV2 connect aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
    cleanups.push(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  }
  return { signal: controller.signal, cancel: () => { for (const cleanup of cleanups.splice(0)) cleanup(); } };
}
