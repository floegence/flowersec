import type { Client } from "../client.js";
import { getClientTermination } from "../client-connect/termination.js";
import { emitObserverDiagnostic, withObserverContext, type ClientObserverLike, type DiagnosticEvent, type WsCloseKind, type WsErrorReason } from "../observability/observer.js";
import { SDK_DEFAULTS } from "../defaults.js";

export type { ArtifactAcquireContext, ArtifactSource } from "./artifactControlplane.js";
export { createArtifactResolver, createControlplaneArtifactSource } from "./artifactControlplane.js";

export type ConnectionStatus = "disconnected" | "connecting" | "connected" | "error";

export type AutoReconnectConfig = Readonly<{
  // Enable auto reconnect on failure / unexpected disconnect.
  // Default: false.
  enabled?: boolean;
  // Maximum total attempts (including the first).
  // Default: 5.
  maxAttempts?: number;
  // Base delay for the first retry.
  // Default: 500ms.
  initialDelayMs?: number;
  // Max delay cap.
  // Default: 10s.
  maxDelayMs?: number;
  // Exponential backoff factor.
  // Default: 1.8.
  factor?: number;
  // Random jitter ratio in [-ratio, +ratio].
  // Default: 0.2.
  jitterRatio?: number;
}>;

type AutoReconnectSettings = Readonly<{
  enabled: boolean;
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  factor: number;
  jitterRatio: number;
}>;

function normalizeAutoReconnect(cfg?: AutoReconnectConfig): AutoReconnectSettings {
  const settings = {
    enabled: cfg?.enabled === true,
    maxAttempts: cfg?.enabled === true ? (cfg.maxAttempts ?? SDK_DEFAULTS.reconnect.maxAttempts) : 1,
    initialDelayMs: cfg?.initialDelayMs ?? SDK_DEFAULTS.reconnect.initialDelayMs,
    maxDelayMs: cfg?.maxDelayMs ?? SDK_DEFAULTS.reconnect.maxDelayMs,
    factor: cfg?.factor ?? SDK_DEFAULTS.reconnect.factor,
    jitterRatio: cfg?.jitterRatio ?? SDK_DEFAULTS.reconnect.jitterRatio,
  };
  if (!Number.isSafeInteger(settings.maxAttempts) || settings.maxAttempts < 1) {
    throw new TypeError("autoReconnect.maxAttempts must be a positive integer");
  }
  if (!Number.isFinite(settings.initialDelayMs) || settings.initialDelayMs < 0) {
    throw new TypeError("autoReconnect.initialDelayMs must be a non-negative finite number");
  }
  if (!Number.isFinite(settings.maxDelayMs) || settings.maxDelayMs < 0) {
    throw new TypeError("autoReconnect.maxDelayMs must be a non-negative finite number");
  }
  if (!Number.isFinite(settings.factor) || settings.factor < 1) {
    throw new TypeError("autoReconnect.factor must be a finite number greater than or equal to one");
  }
  if (!Number.isFinite(settings.jitterRatio) || settings.jitterRatio < 0 || settings.jitterRatio > 1) {
    throw new TypeError("autoReconnect.jitterRatio must be a finite number between zero and one");
  }
  return settings;
}

function backoffDelayMs(attemptIndex: number, cfg: AutoReconnectSettings): number {
  const base = Math.min(cfg.maxDelayMs, cfg.initialDelayMs * Math.pow(cfg.factor, attemptIndex));
  const jitter = cfg.jitterRatio <= 0 ? 0 : base * cfg.jitterRatio * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(base + jitter));
}

export type ReconnectState = Readonly<{
  status: ConnectionStatus;
  error: Error | null;
  client: Client | null;
}>;

export type ReconnectListener = (state: ReconnectState) => void;

export type ConnectOnce = (args: Readonly<{ signal: AbortSignal; observer: ClientObserverLike }>) => Promise<Client>;

export type ConnectConfig = Readonly<{
  connectOnce: ConnectOnce;
  observer?: ClientObserverLike;
  autoReconnect?: AutoReconnectConfig;
}>;

export type ReconnectManager = Readonly<{
  state: () => ReconnectState;
  subscribe: (listener: ReconnectListener) => () => void;
  connect: (config: ConnectConfig) => Promise<void>;
  connectIfNeeded: (config: ConnectConfig) => Promise<void>;
  disconnect: () => void;
}>;

function isSameConfig(a: ConnectConfig | null, b: ConnectConfig): boolean {
  if (a == null) return false;
  if (a.connectOnce !== b.connectOnce) return false;
  if (a.observer !== b.observer) return false;

  const aa = normalizeAutoReconnect(a.autoReconnect);
  const bb = normalizeAutoReconnect(b.autoReconnect);
  return (
    aa.enabled === bb.enabled &&
    aa.maxAttempts === bb.maxAttempts &&
    aa.initialDelayMs === bb.initialDelayMs &&
    aa.maxDelayMs === bb.maxDelayMs &&
    aa.factor === bb.factor &&
    aa.jitterRatio === bb.jitterRatio
  );
}

export function createReconnectManager(): ReconnectManager {
  let s: ReconnectState = { status: "disconnected", error: null, client: null };

  const listeners = new Set<ReconnectListener>();
  const setState = (next: ReconnectState) => {
    s = next;
    for (const fn of listeners) {
      try {
        fn(s);
      } catch {
        // ignore listener errors
      }
    }
  };

  let token = 0;
  let active: ConnectConfig | null = null;
  let activeConnectPromise: Promise<void> | null = null;

  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let retryResolve: (() => void) | null = null;

  let attemptAbort: AbortController | null = null;
  let attemptSeq = 0;

  const cancelRetrySleep = () => {
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = null;
    }
    retryResolve?.();
    retryResolve = null;
  };

  const abortActiveAttempt = () => {
    attemptAbort?.abort("canceled");
    attemptAbort = null;
  };

  const closeClient = (value: Client | null): Error | null => {
    if (value == null) return null;
    try {
      value.close();
      return null;
    } catch (error) {
      return asError(error);
    }
  };

  const sleep = (ms: number) =>
    new Promise<void>((resolve) => {
      retryResolve = resolve;
      retryTimer = setTimeout(() => {
        retryTimer = null;
        retryResolve = null;
        resolve();
      }, ms);
    });

  const disconnectInternal = () => {
    cancelRetrySleep();
    abortActiveAttempt();
    active = null;
    activeConnectPromise = null;
    token += 1;
    attemptSeq = 0;

    const closeError = closeClient(s.client);
    if (closeError != null) {
      setState({ status: "error", error: closeError, client: null });
      throw closeError;
    }

    setState({ status: "disconnected", error: null, client: null });
  };

  const startReconnect = (t: number, cfg: ConnectConfig, error: Error) => {
    if (t !== token) return;
    if (active !== cfg) return;
    if (s.status !== "connected") return;

    const ar = normalizeAutoReconnect(cfg.autoReconnect);
    if (!ar.enabled) {
      const closeError = closeClient(s.client);
      const finalError = closeError == null
        ? error
        : new AggregateError([error, closeError], "reconnect termination and client close failed");
      setState({ status: "error", error: finalError, client: null });
      return;
    }

    // Restart the connection loop in the background.
    cancelRetrySleep();
    abortActiveAttempt();

    const closeError = closeClient(s.client);
    if (closeError != null) {
      setState({
        status: "error",
        error: new AggregateError([error, closeError], "reconnect termination and client close failed"),
        client: null,
      });
      return;
    }

    token += 1;
    const nextToken = token;

    const reconnectPromise = startConnectLoop(nextToken, cfg);
    setState({ status: "connecting", error, client: null });
    void reconnectPromise.catch(() => {
      // connectWithRetry updates state; keep errors observable via state().
    });
  };

  const createObserver = (t: number, cfg: ConnectConfig, currentAttemptSeq: number): ClientObserverLike | undefined => {
    const user = cfg.observer;
    return withObserverContext({
      onConnect: (...args) => user?.onConnect?.(...args),
      onAttach: (...args) => user?.onAttach?.(...args),
      onHandshake: (...args) => user?.onHandshake?.(...args),
      onWsClose: (kind: WsCloseKind, code?: number) => {
        user?.onWsClose?.(kind, code);
        if (kind === "peer_or_error") {
          startReconnect(t, cfg, new Error(`WebSocket closed (${code ?? "unknown"})`));
        }
      },
      onWsError: (reason: WsErrorReason) => {
        user?.onWsError?.(reason);
        startReconnect(t, cfg, new Error(`WebSocket error: ${reason}`));
      },
      onRpcCall: (...args) => user?.onRpcCall?.(...args),
      onRpcNotify: (...args) => user?.onRpcNotify?.(...args),
      onDiagnosticEvent: (event: DiagnosticEvent) => {
        user?.onDiagnosticEvent?.(event);
        if (event.code === "liveness_timeout") {
          startReconnect(t, cfg, new Error("liveness timeout"));
        }
      },
    }, {
      attemptSeq: currentAttemptSeq,
    });
  };

  const connectOnce = async (t: number, cfg: ConnectConfig, currentAttemptSeq: number): Promise<Client> => {
    abortActiveAttempt();
    attemptAbort = new AbortController();
    return await cfg.connectOnce({ signal: attemptAbort.signal, observer: createObserver(t, cfg, currentAttemptSeq) ?? {} });
  };

  const connectWithRetry = async (t: number, cfg: ConnectConfig): Promise<void> => {
    const ar = normalizeAutoReconnect(cfg.autoReconnect);
    let attempts = 0;

    for (;;) {
      if (t !== token) return;
      if (active !== cfg) return;

      attempts += 1;
      attemptSeq += 1;
      emitObserverDiagnostic(withObserverContext(cfg.observer, { attemptSeq }), {
        path: "auto",
        stage: "reconnect",
        code_domain: "event",
        code: attempts === 1 ? "reconnect_attempt" : "reconnect_retry_attempt",
        result: "retry",
      });
      try {
        const client = await connectOnce(t, cfg, attemptSeq);
        if (t !== token) {
          const closeError = closeClient(client);
          if (closeError != null) throw new ReconnectCleanupError(closeError);
          return;
        }
        if (active !== cfg) {
          const closeError = closeClient(client);
          if (closeError != null) throw new ReconnectCleanupError(closeError);
          return;
        }

        setState({ status: "connected", client, error: null });
        const termination = getClientTermination(client);
        if (termination != null) {
          void termination.then(
            ({ error }) => {
              if (s.client !== client) return;
              startReconnect(t, cfg, error);
            },
            (error: unknown) => {
              if (s.client !== client) return;
              startReconnect(t, cfg, asError(error));
            },
          );
        }
        emitObserverDiagnostic(withObserverContext(cfg.observer, { attemptSeq }), {
          path: "auto",
          stage: "reconnect",
          code_domain: "event",
          code: "reconnect_connected",
          result: "ok",
        });
        return;
      } catch (err) {
        if (err instanceof ReconnectCleanupError) throw err.cleanupError;
        const e = err instanceof Error ? err : new Error(String(err));
        if (t !== token) return;
        if (active !== cfg) return;

        const canRetry = ar.enabled && attempts < ar.maxAttempts;
        if (!canRetry) {
          setState({ status: "error", error: e, client: null });
          emitObserverDiagnostic(withObserverContext(cfg.observer, { attemptSeq }), {
            path: "auto",
            stage: "reconnect",
            code_domain: "event",
            code: "reconnect_exhausted",
            result: "fail",
          });
          throw e;
        }

        setState({ status: "connecting", error: e, client: null });
        const delay = backoffDelayMs(attempts - 1, ar);
        emitObserverDiagnostic(withObserverContext(cfg.observer, { attemptSeq }), {
          path: "auto",
          stage: "reconnect",
          code_domain: "event",
          code: "reconnect_scheduled",
          result: "retry",
        });
        await sleep(delay);
      }
    }
  };

  const startConnectLoop = (t: number, cfg: ConnectConfig): Promise<void> => {
    let resolveLoop!: () => void;
    let rejectLoop!: (error: unknown) => void;
    const loop = new Promise<void>((resolve, reject) => {
      resolveLoop = resolve;
      rejectLoop = reject;
    });
    let promise: Promise<void>;
    promise = loop.finally(() => {
      if (activeConnectPromise === promise) activeConnectPromise = null;
    });
    activeConnectPromise = promise;
    void connectWithRetry(t, cfg).then(resolveLoop, rejectLoop);
    return promise;
  };

  const connect = async (cfg: ConnectConfig): Promise<void> => {
    normalizeAutoReconnect(cfg.autoReconnect);
    cancelRetrySleep();
    abortActiveAttempt();

    token += 1;
    const t = token;
    active = cfg;
    attemptSeq = 0;

    const closeError = closeClient(s.client);
    if (closeError != null) {
      active = null;
      setState({ status: "error", error: closeError, client: null });
      throw closeError;
    }

    const connectPromise = startConnectLoop(t, cfg);
    setState({ status: "connecting", error: null, client: null });
    await connectPromise;
  };

  const connectIfNeeded = async (cfg: ConnectConfig): Promise<void> => {
    if (isSameConfig(active, cfg)) {
      if (activeConnectPromise) {
        await activeConnectPromise;
        return;
      }
      if (s.status === "connected" && s.client) return;
    }
    await connect(cfg);
  };

  const disconnect = () => {
    disconnectInternal();
  };

  return {
    state: () => s,
    subscribe: (listener) => {
      listeners.add(listener);
      // Push the current state immediately for convenience.
      try {
        listener(s);
      } catch {
        // ignore
      }
      return () => {
        listeners.delete(listener);
      };
    },
    connect,
    connectIfNeeded,
    disconnect,
  };
}

class ReconnectCleanupError extends Error {
  constructor(readonly cleanupError: Error) {
    super("reconnect cleanup failed", { cause: cleanupError });
    this.name = "ReconnectCleanupError";
  }
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}
