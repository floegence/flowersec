import type { ClientPath } from "../client.js";

export type ConnectResult = "ok" | "fail";
export type ConnectReason =
  | "websocket_error"
  | "websocket_closed"
  | "timeout"
  | "canceled";

export type AttachResult = "ok" | "fail";
export type AttachReason =
  | "send_failed"
  | "too_many_connections"
  | "expected_attach"
  | "invalid_attach"
  | "invalid_token"
  | "channel_mismatch"
  | "role_mismatch"
  | "init_exp_mismatch"
  | "idle_timeout_mismatch"
  | "token_replay"
  | "tenant_mismatch"
  | "policy_denied"
  | "policy_error"
  | "replace_rate_limited"
  | "attach_failed"
  | "timeout"
  | "canceled";

export type HandshakeResult = "ok" | "fail";
export type HandshakeReason =
  | "auth_tag_mismatch"
  | "handshake_failed"
  | "invalid_suite"
  | "invalid_version"
  | "timestamp_after_init_exp"
  | "timestamp_out_of_skew"
  | "timeout"
  | "canceled";

export type WsCloseKind = "local" | "peer_or_error";

export type WsErrorReason =
  | "error"
  | "recv_buffer_exceeded"
  | "unexpected_text_frame"
  | "unexpected_message_type";

export type RpcCallResult =
  | "ok"
  | "rpc_error"
  | "handler_not_found"
  | "transport_error"
  | "canceled";

export type DiagnosticEvent = Readonly<{
  v: 1;
  namespace: "connect";
  path: ClientPath | "auto";
  stage:
    | "validate"
    | "normalize"
    | "scope"
    | "connect"
    | "attach"
    | "handshake"
    | "close"
    | "reconnect";
  code_domain: "error" | "event";
  code: string;
  result: "ok" | "fail" | "retry" | "skip";
  elapsed_ms: number;
  attempt_seq: number;
  trace_id?: string;
  session_id?: string;
}>;

type ObserverContext = Readonly<{
  path?: ClientPath | "auto";
  traceId?: string;
  sessionId?: string;
  attemptSeq?: number;
  attemptStartMs?: number;
  maxQueuedItems?: number;
}>;

type DeliveryItem = Readonly<{
  kind: "normal" | "terminal" | "overflow";
  deliver: () => void;
}>;

const OBSERVER_CONTEXT = Symbol.for("floegence.flowersec.observer_context");
const NORMALIZED_OBSERVER = Symbol.for(
  "floegence.flowersec.normalized_observer",
);
const DEFAULT_MAX_QUEUED_ITEMS = 64;

export type ClientObserver = {
  onConnect(
    path: ClientPath,
    result: ConnectResult,
    reason: ConnectReason | undefined,
    elapsedSeconds: number,
  ): void;
  onAttach(result: AttachResult, reason: AttachReason | undefined): void;
  onHandshake(
    path: ClientPath,
    result: HandshakeResult,
    reason: HandshakeReason | undefined,
    elapsedSeconds: number,
  ): void;
  onWsClose(kind: WsCloseKind, code?: number): void;
  onWsError(reason: WsErrorReason): void;
  onRpcCall(result: RpcCallResult, elapsedSeconds: number): void;
  onRpcNotify(): void;
  onDiagnosticEvent(event: DiagnosticEvent): void;
};

export type ClientObserverLike = Partial<ClientObserver>;

type DiagnosticEventInput = Omit<
  DiagnosticEvent,
  | "v"
  | "namespace"
  | "elapsed_ms"
  | "attempt_seq"
  | "trace_id"
  | "session_id"
  | "path"
> &
  Partial<Pick<DiagnosticEvent, "path">>;

type InternalNormalizedObserver = ClientObserver & {
  readonly [NORMALIZED_OBSERVER]: true;
  readonly [OBSERVER_CONTEXT]: ObserverContext;
  emitDiagnosticEvent: (event: DiagnosticEventInput) => void;
};

export const NoopObserver: ClientObserver = {
  onConnect: () => {},
  onAttach: () => {},
  onHandshake: () => {},
  onWsClose: () => {},
  onWsError: () => {},
  onRpcCall: () => {},
  onRpcNotify: () => {},
  onDiagnosticEvent: () => {},
};

function getObserverContext(observer?: ClientObserverLike): ObserverContext {
  const context = (observer as Record<symbol, unknown> | undefined)?.[
    OBSERVER_CONTEXT
  ];
  if (context == null || typeof context !== "object") return {};
  return context as ObserverContext;
}

function safeInvoke(fn: (() => void) | undefined): void {
  if (fn == null) return;
  try {
    fn();
  } catch {
    // Best effort only; observability must not affect connect semantics.
  }
}

function hasAnyHandlers(observer?: ClientObserverLike): boolean {
  if (observer == null) return false;
  return (
    observer.onConnect != null ||
    observer.onAttach != null ||
    observer.onHandshake != null ||
    observer.onWsClose != null ||
    observer.onWsError != null ||
    observer.onRpcCall != null ||
    observer.onRpcNotify != null ||
    observer.onDiagnosticEvent != null
  );
}

function buildDiagnosticEvent(
  context: ObserverContext,
  event: DiagnosticEventInput,
): DiagnosticEvent {
  return Object.freeze({
    v: 1,
    namespace: "connect",
    path: event.path ?? context.path ?? "auto",
    stage: event.stage,
    code_domain: event.code_domain,
    code: event.code,
    result: event.result,
    elapsed_ms: Math.max(
      0,
      Math.floor(
        nowMilliseconds() - (context.attemptStartMs ?? nowMilliseconds()),
      ),
    ),
    attempt_seq: Math.max(1, Math.floor(context.attemptSeq ?? 1)),
    ...(context.traceId === undefined ? {} : { trace_id: context.traceId }),
    ...(context.sessionId === undefined
      ? {}
      : { session_id: context.sessionId }),
  });
}

function mapConnectDiagnostic(
  path: ClientPath,
  result: ConnectResult,
  reason: ConnectReason | undefined,
): Omit<
  DiagnosticEvent,
  "v" | "namespace" | "elapsed_ms" | "attempt_seq" | "trace_id" | "session_id"
> {
  if (result === "ok") {
    return {
      path,
      stage: "connect",
      code_domain: "event",
      code: "connect_ok",
      result: "ok",
    };
  }
  return {
    path,
    stage: "connect",
    code_domain: "error",
    code:
      reason === "timeout" || reason === "canceled" ? reason : "dial_failed",
    result: "fail",
  };
}

function mapAttachDiagnostic(
  result: AttachResult,
  reason: AttachReason | undefined,
  path: ClientPath | "auto",
): Omit<
  DiagnosticEvent,
  "v" | "namespace" | "elapsed_ms" | "attempt_seq" | "trace_id" | "session_id"
> {
  if (result === "ok") {
    return {
      path,
      stage: "attach",
      code_domain: "event",
      code: "attach_ok",
      result: "ok",
    };
  }
  return {
    path,
    stage: "attach",
    code_domain: "error",
    code:
      reason === "send_failed" ? "attach_failed" : (reason ?? "attach_failed"),
    result: "fail",
  };
}

function mapHandshakeDiagnostic(
  path: ClientPath,
  result: HandshakeResult,
  reason: HandshakeReason | undefined,
): Omit<
  DiagnosticEvent,
  "v" | "namespace" | "elapsed_ms" | "attempt_seq" | "trace_id" | "session_id"
> {
  if (result === "ok") {
    return {
      path,
      stage: "handshake",
      code_domain: "event",
      code: "handshake_ok",
      result: "ok",
    };
  }
  return {
    path,
    stage: "handshake",
    code_domain: "error",
    code: reason ?? "handshake_failed",
    result: "fail",
  };
}

function mapWsCloseDiagnostic(
  kind: WsCloseKind,
  path: ClientPath | "auto",
): Omit<
  DiagnosticEvent,
  "v" | "namespace" | "elapsed_ms" | "attempt_seq" | "trace_id" | "session_id"
> {
  return {
    path,
    stage: "close",
    code_domain: "event",
    code: kind === "local" ? "ws_close_local" : "ws_close_peer_or_error",
    result: "skip",
  };
}

function mapWsErrorDiagnostic(
  path: ClientPath | "auto",
): Omit<
  DiagnosticEvent,
  "v" | "namespace" | "elapsed_ms" | "attempt_seq" | "trace_id" | "session_id"
> {
  return {
    path,
    stage: "close",
    code_domain: "event",
    code: "ws_error",
    result: "skip",
  };
}

class ObserverDispatcher implements InternalNormalizedObserver {
  readonly [NORMALIZED_OBSERVER] = true as const;
  readonly [OBSERVER_CONTEXT]: ObserverContext;

  private readonly queue: DeliveryItem[] = [];
  private readonly observer: ClientObserverLike;
  private readonly maxQueuedItems: number;
  private draining = false;
  private overflowQueued = false;

  constructor(observer: ClientObserverLike, context: ObserverContext) {
    this.observer = observer;
    this[OBSERVER_CONTEXT] = context;
    this.maxQueuedItems = Math.max(
      4,
      Math.floor(context.maxQueuedItems ?? DEFAULT_MAX_QUEUED_ITEMS),
    );
  }

  onConnect(
    path: ClientPath,
    result: ConnectResult,
    reason: ConnectReason | undefined,
    elapsedSeconds: number,
  ): void {
    const diagnostic = mapConnectDiagnostic(path, result, reason);
    this.enqueueCombined(
      () => this.observer.onConnect?.(path, result, reason, elapsedSeconds),
      diagnostic,
      result === "fail",
    );
  }

  onAttach(result: AttachResult, reason: AttachReason | undefined): void {
    const diagnostic = mapAttachDiagnostic(
      result,
      reason,
      this[OBSERVER_CONTEXT].path ?? "auto",
    );
    this.enqueueCombined(
      () => this.observer.onAttach?.(result, reason),
      diagnostic,
      result === "fail",
    );
  }

  onHandshake(
    path: ClientPath,
    result: HandshakeResult,
    reason: HandshakeReason | undefined,
    elapsedSeconds: number,
  ): void {
    const diagnostic = mapHandshakeDiagnostic(path, result, reason);
    this.enqueueCombined(
      () => this.observer.onHandshake?.(path, result, reason, elapsedSeconds),
      diagnostic,
      result === "fail",
    );
  }

  onWsClose(kind: WsCloseKind, code?: number): void {
    const diagnostic = mapWsCloseDiagnostic(
      kind,
      this[OBSERVER_CONTEXT].path ?? "auto",
    );
    this.enqueueCombined(
      () => this.observer.onWsClose?.(kind, code),
      diagnostic,
      false,
    );
  }

  onWsError(reason: WsErrorReason): void {
    const diagnostic = mapWsErrorDiagnostic(
      this[OBSERVER_CONTEXT].path ?? "auto",
    );
    this.enqueueCombined(
      () => this.observer.onWsError?.(reason),
      diagnostic,
      false,
    );
  }

  onRpcCall(result: RpcCallResult, elapsedSeconds: number): void {
    this.enqueueCombined(
      () => this.observer.onRpcCall?.(result, elapsedSeconds),
      undefined,
      false,
    );
  }

  onRpcNotify(): void {
    this.enqueueCombined(() => this.observer.onRpcNotify?.(), undefined, false);
  }

  onDiagnosticEvent(event: DiagnosticEvent): void {
    this.enqueueCombined(
      () => this.observer.onDiagnosticEvent?.(event),
      undefined,
      event.result === "fail",
    );
  }

  emitDiagnosticEvent(event: DiagnosticEventInput): void {
    const diagnostic = buildDiagnosticEvent(this[OBSERVER_CONTEXT], event);
    this.enqueue({
      kind:
        event.code === "diagnostics_overflow"
          ? "overflow"
          : event.result === "fail"
            ? "terminal"
            : "normal",
      deliver: () => this.observer.onDiagnosticEvent?.(diagnostic),
    });
  }

  private enqueueCombined(
    callback: (() => void) | undefined,
    diagnostic: DiagnosticEventInput | undefined,
    terminal: boolean,
  ): void {
    if (callback == null && diagnostic == null) return;
    const event =
      diagnostic == null
        ? undefined
        : buildDiagnosticEvent(this[OBSERVER_CONTEXT], diagnostic);
    this.enqueue({
      kind: terminal ? "terminal" : "normal",
      deliver: () => {
        safeInvoke(callback);
        if (event != null) {
          safeInvoke(() => this.observer.onDiagnosticEvent?.(event));
        }
      },
    });
  }

  private enqueue(item: DeliveryItem): void {
    if (this.queue.length >= this.maxQueuedItems) {
      if (!this.makeRoom(item.kind)) {
        return;
      }
    }
    if (item.kind === "overflow") {
      if (this.overflowQueued) return;
      this.overflowQueued = true;
    }
    this.queue.push(item);
    this.scheduleDrain();
  }

  private makeRoom(kind: DeliveryItem["kind"]): boolean {
    const removableIndex = this.queue.findIndex(
      (entry) => entry.kind === "normal",
    );
    if (removableIndex >= 0) {
      this.queue.splice(removableIndex, 1);
      if (kind === "normal") {
        this.queueOverflowEvent();
      }
      return true;
    }
    if (kind === "normal") {
      return false;
    }
    if (this.queue.length > 0) {
      const shifted = this.queue.shift();
      if (shifted?.kind === "overflow") this.overflowQueued = false;
      return true;
    }
    return true;
  }

  private queueOverflowEvent(): void {
    if (this.overflowQueued || this.observer.onDiagnosticEvent == null) return;
    this.enqueue({
      kind: "overflow",
      deliver: () => {
        this.overflowQueued = false;
        safeInvoke(() =>
          this.observer.onDiagnosticEvent?.(
            buildDiagnosticEvent(this[OBSERVER_CONTEXT], {
              stage: "reconnect",
              code_domain: "event",
              code: "diagnostics_overflow",
              result: "skip",
            }),
          ),
        );
      },
    });
  }

  private scheduleDrain(): void {
    if (this.draining) return;
    this.draining = true;
    queueMicrotask(() => this.drainOne());
  }

  private drainOne(): void {
    this.draining = false;
    const item = this.queue.shift();
    if (item == null) return;
    if (item.kind === "overflow") {
      this.overflowQueued = false;
    }
    safeInvoke(item.deliver);
    if (this.queue.length > 0) {
      this.scheduleDrain();
    }
  }
}

export function withObserverContext(
  observer: ClientObserverLike | undefined,
  context: ObserverContext,
): ClientObserverLike | undefined {
  if (observer == null && Object.keys(context).length === 0) return observer;
  const previous = getObserverContext(observer);
  return Object.assign({}, observer ?? {}, {
    [OBSERVER_CONTEXT]: {
      ...previous,
      ...context,
    },
  }) as ClientObserverLike;
}

export function emitObserverDiagnostic(
  observer: ClientObserverLike | undefined,
  event: DiagnosticEventInput,
): void {
  const normalized = normalizeObserver(observer);
  if ((normalized as Partial<InternalNormalizedObserver>).emitDiagnosticEvent) {
    (normalized as InternalNormalizedObserver).emitDiagnosticEvent(event);
    return;
  }
  safeInvoke(() =>
    normalized.onDiagnosticEvent(
      buildDiagnosticEvent(getObserverContext(observer), event),
    ),
  );
}

export function normalizeObserver(
  observer?: ClientObserverLike,
  context: ObserverContext = {},
): ClientObserver {
  if (
    (observer as Partial<InternalNormalizedObserver> | undefined)?.[
      NORMALIZED_OBSERVER
    ] === true
  ) {
    return observer as InternalNormalizedObserver;
  }
  if (!hasAnyHandlers(observer)) return NoopObserver;
  return new ObserverDispatcher(observer ?? {}, {
    attemptSeq: 1,
    attemptStartMs: nowMilliseconds(),
    ...getObserverContext(observer),
    ...context,
  });
}

export function nowSeconds(): number {
  return nowMilliseconds() / 1000;
}

function nowMilliseconds(): number {
  if (
    typeof performance !== "undefined" &&
    typeof performance.now === "function"
  ) {
    return performance.now();
  }
  return Date.now();
}
