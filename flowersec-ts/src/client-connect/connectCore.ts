import { clientHandshake } from "../e2ee/handshake.js";
import { ByteReader } from "../yamux/byteReader.js";
import { YamuxSession } from "../yamux/session.js";
import { DEFAULT_YAMUX_LIMITS, type YamuxLimits } from "../yamux/session.js";
import { SDK_DEFAULTS } from "../defaults.js";
import { RpcClient } from "../rpc/client.js";
import { writeStreamHello } from "../streamhello/streamHello.js";
import { emitObserverDiagnostic, normalizeObserver, nowSeconds, type AttachReason, type ClientObserverLike } from "../observability/observer.js";
import { base64urlDecode } from "../utils/base64url.js";
import { AbortError, FlowersecError, throwIfAborted } from "../utils/errors.js";
import { DEFAULT_WEB_SOCKET_LIMITS, WebSocketBinaryTransport, WsCloseError, type WebSocketLike, type WebSocketLimits } from "../ws-client/binaryTransport.js";
import type { ClientInternal } from "../client.js";
import type { ConnectScopeResolverMap } from "../connect/internalNormalize.js";
import {
  OriginMismatchError,
  WsFactoryRequiredError,
  classifyConnectError,
  classifyHandshakeError,
  createWebSocket,
  waitOpen,
  withAbortAndTimeout,
} from "./common.js";
import { prepareChannelId } from "./contract.js";
import { isTunnelAttachCloseReason } from "./tunnelAttachCloseReason.js";
import { enforceTransportSecurity, type TransportSecurityPolicy } from "./transportSecurity.js";
import { maxPlaintextBytes } from "../e2ee/record.js";
import { isYamuxPingTimeoutError, isYamuxResourceExhaustedError } from "../yamux/errors.js";
import { registerClientTermination } from "./termination.js";

export type LivenessOptions = Readonly<{
  intervalMs?: number;
  timeoutMs?: number;
}>;

export type ConnectOptionsBase = Readonly<{
  /** Explicit Origin value (required). In browsers this must match window.location.origin. */
  origin: string;
  /** Optional AbortSignal to cancel connect/handshake. */
  signal?: AbortSignal;
  /** Optional websocket connect timeout in milliseconds (0 disables). */
  connectTimeoutMs?: number;
  /** Optional total E2EE handshake timeout in milliseconds (0 disables). */
  handshakeTimeoutMs?: number;
  /** Feature bitset advertised during the E2EE handshake. */
  clientFeatures?: number;
  /** Maximum allowed bytes for handshake payloads (0 uses default). */
  maxHandshakePayload?: number;
  /** Maximum encrypted record size on the wire (0 uses default). */
  maxRecordBytes?: number;
  /** Maximum buffered plaintext bytes in the secure channel (0 uses default). */
  maxBufferedBytes?: number;
  /** Maximum queued outbound plaintext bytes in the secure channel (default 4 MiB; 0 uses default). */
  maxOutboundBufferedBytes?: number;
  /** Preferred plaintext bytes per outbound encrypted record (default 64 KiB). */
  outboundRecordChunkBytes?: number;
  /** WebSocket inbound and outbound queue limits. */
  webSocketLimits?: Partial<WebSocketLimits>;
  /** Yamux stream, frame, receive-memory, and per-stream write-queue limits. */
  yamuxLimits?: Partial<YamuxLimits>;
  /** Optional factory for creating the WebSocket instance. */
  wsFactory?: (url: string, origin: string) => WebSocketLike;
  /** Optional observer for client metrics. */
  observer?: ClientObserverLike;
  /** Policy evaluated before any WebSocket network activity. */
  transportSecurityPolicy?: TransportSecurityPolicy;
  /** Scope validators keyed by scope name. */
  scopeResolvers?: ConnectScopeResolverMap;
  /** Explicit compatibility switch for optional scope failures. */
  relaxedOptionalScopeValidation?: boolean;
  /** Acknowledged Yamux liveness checks, or false to disable automatic checks. */
  liveness?: false | LivenessOptions;
}>;

export type ConnectCoreArgs = Readonly<{
  path: "tunnel" | "direct";
  wsUrl: string;
  channelId: string;
  e2eePskB64u: string;
  defaultSuite: number;
  opts: ConnectOptionsBase;
  attach?: Readonly<{ attachJson: string; endpointInstanceId: string }>;
}>;

export async function connectCore(args: ConnectCoreArgs): Promise<ClientInternal> {
  const observer = normalizeObserver(args.opts.observer, { path: args.path });
  const signal = args.opts.signal;
  const connectStart = nowSeconds();
  let attachState: "not_started" | "sent" | "accepted" | "failed" = args.path === "tunnel" ? "not_started" : "accepted";

  const reportAttachSuccess = (): void => {
    if (args.path !== "tunnel" || attachState !== "sent") return;
    observer.onAttach("ok", undefined);
    attachState = "accepted";
  };

  const reportAttachFailure = (reason: AttachReason): void => {
    if (args.path !== "tunnel" || attachState !== "sent") return;
    observer.onAttach("fail", reason);
    attachState = "failed";
  };

  const origin = typeof args.opts.origin === "string" ? args.opts.origin.trim() : "";
  if (origin === "") {
    throw new FlowersecError({ path: args.path, stage: "validate", code: "missing_origin", message: "missing origin" });
  }

  const invalidOption = (message: string): never => {
    throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_option", message });
  };

  if (args.path === "tunnel" && args.attach == null) {
    throw new FlowersecError({
      path: args.path,
      stage: "validate",
      code: "invalid_option",
      message: "missing attach payload",
    });
  }

  const wsUrl = typeof args.wsUrl === "string" ? args.wsUrl.trim() : "";
  if (wsUrl === "") {
    const code = args.path === "tunnel" ? "missing_tunnel_url" : "missing_ws_url";
    throw new FlowersecError({ path: args.path, stage: "validate", code, message: "missing websocket url" });
  }

  const connectTimeoutMs = args.opts.connectTimeoutMs ?? SDK_DEFAULTS.transport.connectTimeoutMs;
  if (!Number.isFinite(connectTimeoutMs) || connectTimeoutMs < 0) {
    invalidOption("connectTimeoutMs must be a non-negative number");
  }
  const handshakeTimeoutMs = args.opts.handshakeTimeoutMs ?? SDK_DEFAULTS.transport.handshakeTimeoutMs;
  if (!Number.isFinite(handshakeTimeoutMs) || handshakeTimeoutMs < 0) {
    invalidOption("handshakeTimeoutMs must be a non-negative number");
  }

  const clientFeatures = args.opts.clientFeatures ?? 0;
  if (!Number.isSafeInteger(clientFeatures) || clientFeatures < 0 || clientFeatures > 0xffffffff) {
    invalidOption("clientFeatures must be a uint32");
  }

  const maxHandshakePayload = args.opts.maxHandshakePayload ?? 0;
  if (!Number.isSafeInteger(maxHandshakePayload) || maxHandshakePayload < 0) {
    invalidOption("maxHandshakePayload must be a non-negative integer");
  }
  const maxRecordBytes = args.opts.maxRecordBytes ?? 0;
  if (!Number.isSafeInteger(maxRecordBytes) || maxRecordBytes < 0) {
    invalidOption("maxRecordBytes must be a non-negative integer");
  }
  const maxBufferedBytes = args.opts.maxBufferedBytes ?? 0;
  if (!Number.isSafeInteger(maxBufferedBytes) || maxBufferedBytes < 0) {
    invalidOption("maxBufferedBytes must be a non-negative integer");
  }
  const maxOutboundBufferedBytes = args.opts.maxOutboundBufferedBytes ?? 0;
  if (!Number.isSafeInteger(maxOutboundBufferedBytes) || maxOutboundBufferedBytes < 0) {
    invalidOption("maxOutboundBufferedBytes must be a non-negative integer");
  }
  const effectiveMaxRecordBytes = maxRecordBytes > 0 ? maxRecordBytes : SDK_DEFAULTS.e2ee.maxRecordBytes;
  const outboundRecordChunkBytes = args.opts.outboundRecordChunkBytes ?? 64 * 1024;
  if (!Number.isSafeInteger(outboundRecordChunkBytes) || outboundRecordChunkBytes <= 0 || outboundRecordChunkBytes > maxPlaintextBytes(effectiveMaxRecordBytes)) {
    invalidOption("outboundRecordChunkBytes must be a positive integer within maxRecordBytes");
  }
  validateLimitObject(args.opts.webSocketLimits, "webSocketLimits", invalidOption);
  validateLimitObject(args.opts.yamuxLimits, "yamuxLimits", invalidOption);
  validateWebSocketLimitRelationships(args.opts.webSocketLimits, invalidOption);
  validateYamuxLimitRelationships(args.opts.yamuxLimits, invalidOption);
  const liveness = normalizeLiveness(args.opts.liveness, invalidOption);

  await enforceTransportSecurity({
    rawUrl: wsUrl,
    path: args.path,
    ...(args.opts.transportSecurityPolicy === undefined ? {} : { policy: args.opts.transportSecurityPolicy }),
    ...(args.opts.observer === undefined ? {} : { observer: args.opts.observer }),
  });

  const channelId = prepareChannelId(args.channelId, args.path);

  let psk: Uint8Array;
  try {
    const pskB64u = typeof args.e2eePskB64u === "string" ? args.e2eePskB64u.trim() : "";
    psk = base64urlDecode(pskB64u);
  } catch (e) {
    throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_psk", message: "invalid e2ee_psk_b64u", cause: e });
  }
  if (psk.length !== 32) {
    throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_psk", message: "psk must be 32 bytes" });
  }

  const suite = args.defaultSuite as unknown as 1 | 2;
  if (suite !== 1 && suite !== 2) {
    throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_suite", message: "invalid suite" });
  }

  let ws: WebSocketLike;
  try {
    ws = createWebSocket(wsUrl, origin, args.opts.wsFactory);
  } catch (e) {
    if (e instanceof OriginMismatchError) {
      throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_option", message: e.message, cause: e });
    }
    if (e instanceof WsFactoryRequiredError) {
      throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_option", message: e.message, cause: e });
    }
    throw new FlowersecError({ path: args.path, stage: "connect", code: "dial_failed", message: "dial failed", cause: e });
  }

  // Install close/error/message listeners before waiting for "open" to avoid a gap where a peer close
  // (for example a tunnel attach rejection with a reason token) can be missed and misclassified as a handshake timeout.
  const transport = new WebSocketBinaryTransport(ws, {
    ...(args.opts.webSocketLimits === undefined ? {} : { webSocketLimits: args.opts.webSocketLimits }),
    observer,
  });

  try {
    try {
      await waitOpen(ws, {
        timeoutMs: connectTimeoutMs,
        ...(signal !== undefined ? { signal } : {}),
      });
      observer.onConnect(args.path, "ok", undefined, nowSeconds() - connectStart);
    } catch (err) {
      const reason = classifyConnectError(err);
      observer.onConnect(args.path, "fail", reason, nowSeconds() - connectStart);
      const code = reason === "timeout" ? "timeout" : reason === "canceled" ? "canceled" : "dial_failed";
      throw new FlowersecError({
        path: args.path,
        stage: "connect",
        code,
        message: `connect failed: ${reason}`,
        cause: err,
      });
    }

    throwIfAborted(signal, "connect aborted");

    if (args.path === "tunnel") {
      try {
        ws.send(args.attach!.attachJson);
        attachState = "sent";
      } catch (err) {
        observer.onAttach("fail", "send_failed");
        attachState = "failed";
        throw new FlowersecError({ path: args.path, stage: "attach", code: "attach_failed", message: "attach failed", cause: err });
      }
    }

    const handshakeStart = nowSeconds();
    let secure: Awaited<ReturnType<typeof clientHandshake>>;
    try {
      secure = await withAbortAndTimeout(
        clientHandshake(transport, {
          channelId,
          suite,
          psk,
          clientFeatures,
          maxHandshakePayload: maxHandshakePayload > 0 ? maxHandshakePayload : SDK_DEFAULTS.e2ee.maxHandshakePayloadBytes,
          maxRecordBytes: effectiveMaxRecordBytes,
          outboundRecordChunkBytes,
          ...(maxBufferedBytes > 0 ? { maxBufferedBytes } : {}),
          ...(maxOutboundBufferedBytes > 0 ? { maxOutboundBufferedBytes } : {}),
          timeoutMs: handshakeTimeoutMs,
          ...(signal !== undefined ? { signal } : {}),
        }),
        {
          timeoutMs: handshakeTimeoutMs,
          ...(signal !== undefined ? { signal } : {}),
          onCancel: () => transport.close(),
        }
      );
      reportAttachSuccess();
      observer.onHandshake(args.path, "ok", undefined, nowSeconds() - handshakeStart);
    } catch (err) {
      const handshakeElapsedSeconds = nowSeconds() - handshakeStart;
      const handshakeCode = classifyHandshakeError(err);

      if (args.path === "tunnel" && err instanceof WsCloseError) {
        const reason = err.reason;
        if (isTunnelAttachCloseReason(reason)) {
          reportAttachFailure(reason);
          throw new FlowersecError({ path: args.path, stage: "attach", code: reason, message: "tunnel rejected attach", cause: err });
        }
      }

      if (args.path === "tunnel") {
        reportAttachFailure(handshakeCode === "timeout" ? "timeout" : handshakeCode === "canceled" ? "canceled" : "attach_failed");
      }
      observer.onHandshake(args.path, "fail", handshakeCode, handshakeElapsedSeconds);
      throw new FlowersecError({
        path: args.path,
        stage: "handshake",
        code: handshakeCode,
        message: "handshake failed",
        cause: err,
      });
    }

    const conn = {
      read: () => secure.read(),
      write: (b: Uint8Array) => secure.write(b),
      close: () => secure.close(),
    };
    let resolveTermination!: (termination: Readonly<{ error: Error }>) => void;
    const termination = new Promise<Readonly<{ error: Error }>>((resolve) => {
      resolveTermination = resolve;
    });
    let terminationReported = false;
    let closeAll = () => {
      runSyncCleanups([() => secure.close()]);
    };
    const reportTermination = (error: Error) => {
      if (terminationReported) return;
      terminationReported = true;
      let terminalError = error;
      try {
        closeAll();
      } catch (cleanupError) {
        terminalError = errorWithCleanup(error, cleanupError, "session termination cleanup failed");
      }
      resolveTermination({ error: terminalError });
    };

    const mux = new YamuxSession(conn, {
      client: true,
      ...(args.opts.yamuxLimits === undefined ? {} : { limits: args.opts.yamuxLimits }),
      onTerminal: reportTermination,
      onDiagnostic: (event) => emitObserverDiagnostic(args.opts.observer, {
        path: args.path,
        stage: "yamux",
        code_domain: "event",
        code: event.code,
        result: "fail",
        resource: event.resource,
        current: event.current,
        limit: event.limit,
      }),
    });
    closeAll = () => {
      runSyncCleanups([() => mux.close(), () => secure.close()]);
    };

    let rpcStream: Awaited<ReturnType<YamuxSession["openStream"]>>;
    try {
      rpcStream = await mux.openStream(signal === undefined ? {} : { signal });
    } catch (e) {
      const cleanupError = captureSyncCleanup(() => runSyncCleanups([() => mux.close(), () => secure.close()]));
      throw new FlowersecError({
        path: args.path,
        stage: "yamux",
        code: "open_stream_failed",
        message: "open rpc stream failed",
        cause: causeWithCleanup(e, cleanupError, "RPC stream setup cleanup failed"),
      });
    }

    const reader = new ByteReader(() => rpcStream.read());
    const readExactly = (n: number) => reader.readExactly(n);
    const write = (b: Uint8Array) => rpcStream.write(b);

    try {
      await writeStreamHello(write, "rpc");
    } catch (e) {
      const cleanupError = await captureAsyncCleanup(async () => {
        const streamCloseError = await captureAsyncCleanup(() => rpcStream.close());
        const stackCloseError = captureSyncCleanup(() => runSyncCleanups([() => mux.close(), () => secure.close()]));
        const combined = errorsFrom([streamCloseError, stackCloseError]);
        if (combined != null) throw combined;
      });
      throw new FlowersecError({
        path: args.path,
        stage: "rpc",
        code: "stream_hello_failed",
        message: "rpc stream hello failed",
        cause: causeWithCleanup(e, cleanupError, "RPC bootstrap cleanup failed"),
      });
    }

    const rpc = new RpcClient(readExactly, write, { observer, onTerminal: reportTermination });

    const ping = async (): Promise<void> => {
      try {
        await secure.sendPing();
      } catch (e) {
        throw new FlowersecError({ path: args.path, stage: "secure", code: "ping_failed", message: "ping failed", cause: e });
      }
    };

    const probeLiveness = async (): Promise<number> => {
      try {
        return await mux.probeLiveness(liveness.timeoutMs);
      } catch (e) {
        if (isYamuxPingTimeoutError(e)) {
          emitObserverDiagnostic(args.opts.observer, { path: args.path, stage: "yamux", code_domain: "event", code: "liveness_timeout", result: "fail" });
        }
        const error = new FlowersecError({ path: args.path, stage: "yamux", code: "ping_failed", message: "liveness probe failed", cause: e });
        reportTermination(error);
        throw error;
      }
    };

    let livenessTimer: ReturnType<typeof setInterval> | undefined;
    let livenessInFlight = false;
    const stopLiveness = () => {
      if (livenessTimer === undefined) return;
      clearInterval(livenessTimer);
      livenessTimer = undefined;
    };
    closeAll = () => {
      stopLiveness();
      runSyncCleanups([() => rpc.close(), () => mux.close(), () => secure.close()]);
    };
    if (liveness.intervalMs > 0) {
      livenessTimer = setInterval(() => {
        if (livenessInFlight) return;
        livenessInFlight = true;
        probeLiveness()
          .catch(() => {
            stopLiveness();
          })
          .finally(() => {
            livenessInFlight = false;
          });
      }, liveness.intervalMs);
      (livenessTimer as any)?.unref?.();
    }

    const client: ClientInternal = {
      path: args.path,
      ...(args.attach != null ? { endpointInstanceId: args.attach.endpointInstanceId } : {}),
      secure,
      mux,
      rpc,
      ping,
      rekey: async () => {
        try {
          await secure.rekeyNow();
        } catch (error) {
          throw new FlowersecError({ path: args.path, stage: "secure", code: "rekey_failed", message: "rekey failed", cause: error });
        }
      },
      probeLiveness,
      openStream: async (kind: string, opts: Readonly<{ signal?: AbortSignal }> = {}) => {
        if (kind == null || kind === "") throw new FlowersecError({ path: args.path, stage: "validate", code: "missing_stream_kind", message: "missing stream kind" });
        if (opts.signal?.aborted) {
          throw new FlowersecError({
            path: args.path,
            stage: "yamux",
            code: "canceled",
            message: "open stream aborted",
            cause: opts.signal.reason,
          });
        }
        const abortReason = (signal: AbortSignal): Error => {
          const r = signal.reason;
          if (r instanceof Error) return r;
          if (typeof r === "string" && r !== "") return new AbortError(r);
          return new AbortError("aborted");
        };
        const signal = opts.signal;
        let abortListener: (() => void) | undefined;
        let abortReset: Promise<unknown | undefined> | undefined;
        let s: Awaited<ReturnType<YamuxSession["openStream"]>>;
        try {
          s = await mux.openStream(signal === undefined ? {} : { signal });
        } catch (e) {
          if (signal?.aborted) {
            throw new FlowersecError({ path: args.path, stage: "yamux", code: "canceled", message: "open stream aborted", cause: signal.reason });
          }
          const exhausted = isYamuxResourceExhaustedError(e);
          throw new FlowersecError({ path: args.path, stage: "yamux", code: exhausted ? "resource_exhausted" : "open_stream_failed", message: exhausted ? "yamux stream limit reached" : "open stream failed", cause: e });
        }
        if (signal != null) {
          abortListener = () => {
            abortReset ??= captureAsyncCleanup(() => Promise.resolve(s.reset(abortReason(signal))));
          };
          signal.addEventListener("abort", abortListener, { once: true });
          if (signal.aborted) abortListener();
        }
        if (signal?.aborted) {
          if (abortListener != null) signal.removeEventListener("abort", abortListener);
          const cleanupError = await captureAsyncCleanup(async () => {
            const resetError = abortReset == null ? undefined : await abortReset;
            const closeError = await captureAsyncCleanup(() => s.close());
            const combined = errorsFrom([resetError, closeError]);
            if (combined != null) throw combined;
          });
          throw new FlowersecError({
            path: args.path,
            stage: "yamux",
            code: "canceled",
            message: "open stream aborted",
            cause: causeWithCleanup(signal.reason, cleanupError, "aborted stream cleanup failed"),
          });
        }
        try {
          await writeStreamHello((b) => s.write(b), kind);
        } catch (err) {
          if (signal?.aborted) {
            if (abortListener != null) signal.removeEventListener("abort", abortListener);
            const cleanupError = await captureAsyncCleanup(async () => {
              const resetError = abortReset == null ? undefined : await abortReset;
              const closeError = await captureAsyncCleanup(() => s.close());
              const combined = errorsFrom([resetError, closeError]);
              if (combined != null) throw combined;
            });
            throw new FlowersecError({
              path: args.path,
              stage: "yamux",
              code: "canceled",
              message: "open stream aborted",
              cause: causeWithCleanup(signal.reason, cleanupError, "aborted stream cleanup failed"),
            });
          }
          if (signal != null && abortListener != null) signal.removeEventListener("abort", abortListener);
          const cleanupError = await captureAsyncCleanup(() => s.close());
          throw new FlowersecError({
            path: args.path,
            stage: "rpc",
            code: "stream_hello_failed",
            message: "stream hello failed",
            cause: causeWithCleanup(err, cleanupError, "stream hello cleanup failed"),
          });
        }
        if (signal != null && abortListener != null) {
          // AbortSignal is only used to cancel the open + StreamHello phase.
          // After the stream is ready, callers should close/reset it explicitly.
          signal.removeEventListener("abort", abortListener);
        }
        return s;
      },
      close: closeAll,
    };
    registerClientTermination(client, termination);
    return client;
  } catch (e) {
    const cleanupError = captureSyncCleanup(() => transport.close());
    throw cleanupError == null ? e : errorWithCleanup(e, cleanupError, "transport cleanup failed");
  }
}

function runSyncCleanups(actions: readonly (() => void)[]): void {
  const failures: Error[] = [];
  for (const action of actions) {
    try {
      action();
    } catch (error) {
      failures.push(errorValue(error));
    }
  }
  if (failures.length > 0) throw new AggregateError(failures, "Flowersec cleanup failed");
}

function captureSyncCleanup(action: () => void): unknown | undefined {
  try {
    action();
    return undefined;
  } catch (error) {
    return error;
  }
}

async function captureAsyncCleanup(action: () => Promise<void>): Promise<unknown | undefined> {
  try {
    await action();
    return undefined;
  } catch (error) {
    return error;
  }
}

function causeWithCleanup(primary: unknown, cleanup: unknown | undefined, message: string): unknown {
  if (cleanup === undefined) return primary;
  return new AggregateError([errorValue(primary), errorValue(cleanup)], message);
}

function errorWithCleanup(primary: unknown, cleanup: unknown, message: string): Error {
  const cause = causeWithCleanup(primary, cleanup, message);
  if (primary instanceof FlowersecError) {
    return new FlowersecError({
      path: primary.path,
      stage: primary.stage,
      code: primary.code,
      message,
      cause,
    });
  }
  return new AggregateError([errorValue(primary), errorValue(cleanup)], message);
}

function errorsFrom(values: readonly (unknown | undefined)[]): AggregateError | undefined {
  const failures = values.filter((value): value is unknown => value !== undefined).map(errorValue);
  return failures.length === 0 ? undefined : new AggregateError(failures, "Flowersec cleanup failed");
}

function errorValue(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function validateLimitObject(
  input: Readonly<Record<string, number | undefined>> | undefined,
  name: string,
  invalid: (message: string) => never,
): void {
  if (input === undefined) return;
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined && (!Number.isSafeInteger(value) || value <= 0)) invalid(`${name}.${key} must be a positive integer`);
  }
}

function normalizeLiveness(
  input: false | LivenessOptions | undefined,
  invalid: (message: string) => never,
): { intervalMs: number; timeoutMs: number } {
  if (input === false || input === undefined) return { intervalMs: 0, timeoutMs: 10_000 };
  const intervalMs = input.intervalMs ?? 0;
  const timeoutMs = input.timeoutMs ?? (intervalMs > 0 ? Math.min(10_000, intervalMs) : 10_000);
  if (!Number.isFinite(intervalMs) || intervalMs < 0) invalid("liveness.intervalMs must be a non-negative number");
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) invalid("liveness.timeoutMs must be a positive number");
  return { intervalMs, timeoutMs };
}

function validateWebSocketLimitRelationships(input: Partial<WebSocketLimits> | undefined, invalid: (message: string) => never): void {
  if (input === undefined) return;
  const low = input.outboundLowWatermarkBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundLowWatermarkBytes;
  const high = input.outboundHighWatermarkBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundHighWatermarkBytes;
  const hard = input.outboundHardLimitBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundHardLimitBytes;
  if (low > high || high > hard) invalid("webSocketLimits outbound watermarks must satisfy low <= high <= hard");
}

function validateYamuxLimitRelationships(input: Partial<YamuxLimits> | undefined, invalid: (message: string) => never): void {
  if (input === undefined) return;
  const active = input.maxActiveStreams ?? DEFAULT_YAMUX_LIMITS.maxActiveStreams;
  const inbound = input.maxInboundStreams ?? DEFAULT_YAMUX_LIMITS.maxInboundStreams;
  const frame = input.maxFrameBytes ?? DEFAULT_YAMUX_LIMITS.maxFrameBytes;
  const outbound = input.preferredOutboundFrameBytes ?? Math.min(DEFAULT_YAMUX_LIMITS.preferredOutboundFrameBytes, frame);
  const streamReceive = input.maxStreamReceiveBytes ?? DEFAULT_YAMUX_LIMITS.maxStreamReceiveBytes;
  const sessionReceive = input.maxSessionReceiveBytes ?? DEFAULT_YAMUX_LIMITS.maxSessionReceiveBytes;
  if (inbound > active) invalid("yamuxLimits.maxInboundStreams must not exceed maxActiveStreams");
  if (outbound > frame) invalid("yamuxLimits.preferredOutboundFrameBytes must not exceed maxFrameBytes");
  if (frame > streamReceive) invalid("yamuxLimits.maxFrameBytes must not exceed maxStreamReceiveBytes");
  if (streamReceive < DEFAULT_YAMUX_LIMITS.maxStreamReceiveBytes) invalid("yamuxLimits.maxStreamReceiveBytes must cover the 256 KiB initial stream window");
  if (streamReceive > sessionReceive) invalid("yamuxLimits.maxStreamReceiveBytes must not exceed maxSessionReceiveBytes");
}
