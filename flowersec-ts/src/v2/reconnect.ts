import {
  createArtifactAcquireContextV2,
  createArtifactV2Resolver,
  type ArtifactAcquireContextOptionsV2,
  type ArtifactLeaseV2,
  type ArtifactSourceV2,
} from "./artifactLease.js";
import type { OperationOptionsV2, SessionV2 } from "./contract.js";
import { ArtifactV2Error } from "./artifact.js";
import { unwrapArtifact } from "./opaqueArtifact.js";
import {
  AbortError,
  ConnectError,
  TimeoutError,
  connectErrorDetailsInternal,
  createConnectErrorInternal,
  type FlowersecErrorCode,
  type FlowersecPath,
  type FlowersecStage,
} from "../utils/errors.js";

export type SessionReconnectStatusV2 = "disconnected" | "connecting" | "connected" | "error";

export type SessionAutoReconnectConfigV2 = Readonly<{
  enabled?: boolean;
  maxAttempts?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  factor?: number;
  jitterRatio?: number;
}>;

export type SessionReconnectConfigV2 = Readonly<{
  source: ArtifactSourceV2;
  connect(lease: ArtifactLeaseV2, options: OperationOptionsV2): Promise<SessionV2>;
  acquireContext?: Omit<ArtifactAcquireContextOptionsV2, "signal">;
  autoReconnect?: SessionAutoReconnectConfigV2;
}>;

export type SessionReconnectStateV2 = Readonly<{
  status: SessionReconnectStatusV2;
  error: ConnectError | null;
  session: SessionV2 | null;
}>;

export type SessionReconnectManagerV2 = Readonly<{
  state(): SessionReconnectStateV2;
  subscribe(listener: (state: SessionReconnectStateV2) => void): () => void;
  connect(config: SessionReconnectConfigV2): Promise<void>;
  connectIfNeeded(config: SessionReconnectConfigV2): Promise<void>;
  disconnect(): Promise<void>;
}>;

type ReconnectSettings = Readonly<{
  enabled: boolean;
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  factor: number;
  jitterRatio: number;
}>;

const DEFAULT_SETTINGS: ReconnectSettings = Object.freeze({
  enabled: false,
  maxAttempts: 1,
  initialDelayMs: 500,
  maxDelayMs: 10_000,
  factor: 1.8,
  jitterRatio: 0.2,
});

const TERMINAL_RECONNECT_CODES: ReadonlySet<FlowersecErrorCode> = new Set([
  "invalid_input",
  "invalid_option",
  "role_mismatch",
  "transport_policy_denied",
  "invalid_psk",
  "invalid_suite",
  "missing_grant",
  "missing_connect_info",
  "missing_tunnel_url",
  "missing_ws_url",
  "missing_channel_id",
  "missing_token",
  "missing_init_exp",
]);

export function createSessionReconnectManagerV2(): SessionReconnectManagerV2 {
  return new SessionReconnectManager();
}

class SessionReconnectManager implements SessionReconnectManagerV2 {
  private current: SessionReconnectStateV2 = { status: "disconnected", error: null, session: null };
  private readonly listeners = new Set<(state: SessionReconnectStateV2) => void>();
  private readonly resolvers = new WeakMap<object, ReturnType<typeof createArtifactV2Resolver>>();
  private generation = 0;
  private activeConfig: SessionReconnectConfigV2 | null = null;
  private attemptAbort: AbortController | undefined;
  private connectPromise: Promise<void> | undefined;

  state(): SessionReconnectStateV2 {
    return this.current;
  }

  subscribe(listener: (state: SessionReconnectStateV2) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  async connect(config: SessionReconnectConfigV2): Promise<void> {
    let settings: ReconnectSettings;
    try {
      settings = validateReconnectConfig(config);
    } catch (error) {
      const failure = reconnectError(error, "auto", "validate", "invalid_option");
      if (this.current.session === null && this.connectPromise === undefined) {
        this.publish({ status: "error", error: failure, session: null });
      }
      throw failure;
    }
    const previousOperation = this.connectPromise;
    const generation = ++this.generation;
    this.attemptAbort?.abort(new Error("SessionV2 connection superseded"));
    this.attemptAbort = undefined;
    const previous = this.current.session;
    this.activeConfig = config;
    this.publish({ status: "connecting", error: null, session: null });

    const promise = this.replaceConnection(generation, config, settings, previous, previousOperation);
    this.connectPromise = promise;
    try {
      await promise;
    } finally {
      if (this.connectPromise === promise) this.connectPromise = undefined;
    }
  }

  async connectIfNeeded(config: SessionReconnectConfigV2): Promise<void> {
    if (this.activeConfig === config && this.current.status === "connected") return;
    if (this.activeConfig === config && this.current.status === "connecting" && this.connectPromise !== undefined) {
      await this.connectPromise;
      return;
    }
    await this.connect(config);
  }

  async disconnect(): Promise<void> {
    const pending = this.connectPromise;
    const generation = ++this.generation;
    this.activeConfig = null;
    this.attemptAbort?.abort(new Error("SessionV2 reconnect disconnected"));
    this.attemptAbort = undefined;
    const active = this.current.session;
    if (active !== null || pending !== undefined) {
      this.publish({ status: "connecting", error: null, session: null });
    }
    if (pending !== undefined) {
      try {
        await pending;
      } catch {
        // Superseded operations publish nothing and own their late cleanup.
      }
    }
    if (active !== null) {
      try {
        await active.close();
      } catch (error) {
        const failure = reconnectError(error, "auto", "close", "not_connected");
        if (this.generation === generation) {
          this.publish({ status: "error", error: failure, session: null });
        }
        throw failure;
      }
    }
    if (this.generation !== generation) return;
    this.publish({ status: "disconnected", error: null, session: null });
  }

  private async replaceConnection(
    generation: number,
    config: SessionReconnectConfigV2,
    settings: ReconnectSettings,
    previous: SessionV2 | null,
    previousOperation: Promise<void> | undefined,
  ): Promise<void> {
    if (previousOperation !== undefined) {
      try {
        await previousOperation;
      } catch {
        // The superseded operation has already normalized its own failure.
      }
    }
    if (!this.isActive(generation, config)) return;
    if (previous !== null) {
      try {
        await previous.close();
      } catch (error) {
        const failure = reconnectError(error, "auto", "close", "not_connected");
        if (this.isActive(generation, config)) this.publish({ status: "error", error: failure, session: null });
        throw failure;
      }
    }
    if (!this.isActive(generation, config)) return;

    await this.runAttempts(generation, config, settings, false);
  }

  private async runAttempts(
    generation: number,
    config: SessionReconnectConfigV2,
    settings: ReconnectSettings,
    delayBeforeFirstAttempt: boolean,
  ): Promise<void> {
    let lastError: ConnectError | undefined;
    for (let attempt = 0; attempt < settings.maxAttempts; attempt++) {
      if (!this.isActive(generation, config)) return;
      const controller = new AbortController();
      this.attemptAbort = controller;
      try {
        if (attempt > 0 || delayBeforeFirstAttempt) {
          await reconnectDelay(Math.max(0, attempt - (delayBeforeFirstAttempt ? 0 : 1)), settings, controller.signal);
        }
        if (!this.isActive(generation, config)) return;
        const resolver = this.resolver(config.source);
        let acquireContext: ReturnType<typeof createArtifactAcquireContextV2>;
        try {
          acquireContext = createArtifactAcquireContextV2(
            { ...config.acquireContext, signal: controller.signal },
          );
        } catch (error) {
          throw reconnectError(error, "auto", "validate", "invalid_option");
        }
        let lease: ArtifactLeaseV2;
        try {
          lease = await resolver(acquireContext);
        } catch (error) {
          const fallback = error instanceof ArtifactV2Error || config.source.kind === "once"
            ? "invalid_input"
            : "resolve_failed";
          throw reconnectError(error, "auto", "validate", fallback);
        }
        let session: SessionV2;
        try {
          session = await config.connect(lease, { signal: controller.signal });
        } catch (error) {
          throw reconnectError(error, unwrapArtifact(lease.artifact).path.kind, "connect", "dial_failed");
        }
        if (!this.isActive(generation, config)) {
          try {
            await session.close();
          } catch {
            // A stale session cannot publish; close remains its terminal action.
          }
          return;
        }
        this.attemptAbort = undefined;
        this.publish({ status: "connected", error: null, session });
        this.watchTermination(generation, config, settings, session);
        return;
      } catch (error) {
        lastError = reconnectError(error, "auto", "connect", "dial_failed");
        if (!this.isActive(generation, config)) return;
        if (isTerminalReconnectError(lastError)) {
          this.publish({ status: "error", error: lastError, session: null });
          throw lastError;
        }
      } finally {
        if (this.attemptAbort === controller) this.attemptAbort = undefined;
      }
    }
    const failure = lastError ?? reconnectError(
      new Error("SessionV2 reconnect attempts exhausted"),
      "auto",
      "connect",
      "dial_failed",
    );
    this.publish({ status: "error", error: failure, session: null });
    throw failure;
  }

  private watchTermination(
    generation: number,
    config: SessionReconnectConfigV2,
    settings: ReconnectSettings,
    session: SessionV2,
  ): void {
    void session.waitClosed().then(({ error }) => this.beginTermination(generation, config, settings, session, error));
  }

  private beginTermination(
    generation: number,
    config: SessionReconnectConfigV2,
    settings: ReconnectSettings,
    session: SessionV2,
    error: Error,
  ): void {
    if (!this.isActive(generation, config) || this.current.session !== session) return;
    const reconnect = this.handleTermination(generation, config, settings, session, error);
    this.connectPromise = reconnect;
    void reconnect.catch(() => undefined).finally(() => {
      if (this.connectPromise === reconnect) this.connectPromise = undefined;
    });
  }

  private async handleTermination(
    generation: number,
    config: SessionReconnectConfigV2,
    settings: ReconnectSettings,
    session: SessionV2,
    error: Error,
  ): Promise<void> {
    const failure = reconnectError(error, "auto", "close", "not_connected");
    const retry = settings.enabled && !isTerminalReconnectError(failure);
    this.publish({ status: retry ? "connecting" : "error", error: failure, session: null });
    try {
      await session.close();
    } catch (closeError) {
      if (!this.isActive(generation, config)) return;
      const closeFailure = reconnectError(closeError, "auto", "close", "not_connected");
      this.publish({ status: "error", error: closeFailure, session: null });
      throw closeFailure;
    }
    if (!retry || !this.isActive(generation, config)) return;
    await this.runAttempts(generation, config, settings, true);
  }

  private resolver(source: ArtifactSourceV2): ReturnType<typeof createArtifactV2Resolver> {
    const key = source as object;
    let resolver = this.resolvers.get(key);
    if (resolver === undefined) {
      resolver = createArtifactV2Resolver(source);
      this.resolvers.set(key, resolver);
    }
    return resolver;
  }

  private isActive(generation: number, config: SessionReconnectConfigV2): boolean {
    return this.generation === generation && this.activeConfig === config;
  }

  private publish(state: SessionReconnectStateV2): void {
    this.current = Object.freeze(state);
    for (const listener of this.listeners) {
      try { listener(this.current); } catch { /* Observers do not own lifecycle progress. */ }
    }
  }
}

function normalizeSettings(config?: SessionAutoReconnectConfigV2): ReconnectSettings {
  const enabled = config?.enabled === true;
  const settings = {
    enabled,
    maxAttempts: enabled ? (config.maxAttempts ?? 5) : 1,
    initialDelayMs: config?.initialDelayMs ?? DEFAULT_SETTINGS.initialDelayMs,
    maxDelayMs: config?.maxDelayMs ?? DEFAULT_SETTINGS.maxDelayMs,
    factor: config?.factor ?? DEFAULT_SETTINGS.factor,
    jitterRatio: config?.jitterRatio ?? DEFAULT_SETTINGS.jitterRatio,
  };
  if (!Number.isSafeInteger(settings.maxAttempts) || settings.maxAttempts < 1) {
    throw new TypeError("autoReconnect.maxAttempts must be a positive integer");
  }
  for (const [name, value] of [["initialDelayMs", settings.initialDelayMs], ["maxDelayMs", settings.maxDelayMs]] as const) {
    if (!Number.isFinite(value) || value < 0) throw new TypeError(`autoReconnect.${name} must be non-negative`);
  }
  if (!Number.isFinite(settings.factor) || settings.factor < 1) throw new TypeError("autoReconnect.factor must be at least one");
  if (!Number.isFinite(settings.jitterRatio) || settings.jitterRatio < 0 || settings.jitterRatio > 1) {
    throw new TypeError("autoReconnect.jitterRatio must be between zero and one");
  }
  return settings;
}

function validateReconnectConfig(config: SessionReconnectConfigV2): ReconnectSettings {
  if (config === null || typeof config !== "object") {
    throw new TypeError("SessionV2 reconnect config must be an object");
  }
  const source = config.source as unknown;
  if (source === null || typeof source !== "object") {
    throw new TypeError("SessionV2 reconnect source must be an object");
  }
  const sourceKind = (source as { kind?: unknown }).kind;
  if (sourceKind !== "once" && sourceKind !== "refreshable") {
    throw new TypeError("SessionV2 reconnect source kind must be once or refreshable");
  }
  if (typeof config.connect !== "function") {
    throw new TypeError("SessionV2 reconnect connect must be a function");
  }
  if (config.autoReconnect !== undefined &&
      (config.autoReconnect === null || typeof config.autoReconnect !== "object")) {
    throw new TypeError("SessionV2 auto reconnect settings must be an object");
  }
  const settings = normalizeSettings(config.autoReconnect);
  if (settings.enabled && sourceKind !== "refreshable") {
    throw new TypeError("SessionV2 auto reconnect requires a refreshable artifact source");
  }
  return settings;
}

async function reconnectDelay(attempt: number, settings: ReconnectSettings, signal: AbortSignal): Promise<void> {
  const base = Math.min(settings.maxDelayMs, settings.initialDelayMs * Math.pow(settings.factor, attempt));
  const jitter = settings.jitterRatio === 0 ? 0 : base * settings.jitterRatio * (Math.random() * 2 - 1);
  const delay = Math.max(0, Math.round(base + jitter));
  if (signal.aborted) throw abortSignalReason(signal);
  if (delay === 0) return;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, delay);
    const abort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(abortSignalReason(signal));
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

function isTerminalReconnectError(error: Error): boolean {
  if (error instanceof AbortError || error.name === "AbortError") return true;
  return error instanceof ConnectError && (
    error.code === "canceled" || TERMINAL_RECONNECT_CODES.has(connectErrorDetailsInternal(error).code)
  );
}

function abortSignalReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new AbortError("SessionV2 reconnect canceled");
}

function reconnectError(
  error: unknown,
  path: FlowersecPath,
  stage: FlowersecStage,
  fallbackCode: FlowersecErrorCode,
): ConnectError {
  if (error instanceof ConnectError) return error;
  const cause = error instanceof Error ? error : new Error(String(error));
  let code = fallbackCode;
  if (cause instanceof AbortError || cause.name === "AbortError") code = "canceled";
  if (cause instanceof TimeoutError || cause.name === "TimeoutError") code = "timeout";
  return createConnectErrorInternal({ path, stage, code, cause });
}
