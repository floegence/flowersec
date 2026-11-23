import type { RpcEnvelope, RpcError } from "./wire.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readRpcFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { assertRpcEnvelope, assertRpcError, assertRpcTypeId } from "./validate.js";
import { SDK_DEFAULTS } from "../defaults.js";

// RpcHandler processes a request and returns a payload or error.
export type RpcHandler = (payload: unknown, signal?: AbortSignal, context?: object) => Promise<{ payload: unknown; error?: RpcError }>;
type NotifyHandler = (payload: unknown, signal?: AbortSignal, context?: object) => unknown;

export type RpcServerOptions = Readonly<{
  maxFrameBytes?: number;
  maxConcurrentRequests?: number;
  maxQueuedRequests?: number;
  maxQueuedNotifications?: number;
}>;

export function rpcConcurrency(limit: number = SDK_DEFAULTS.rpc.maxConcurrentRequests): number {
  return positiveInteger(limit, "maxConcurrentRpcRequests");
}

export type RpcServerTransport = Readonly<{
  readExactly(n: number): Promise<Uint8Array>;
  write(bytes: Uint8Array): Promise<void>;
  close(error: unknown): void | Promise<void>;
}>;

const DEFAULT_RPC_SERVER_OPTIONS = Object.freeze({
  maxConcurrentRequests: SDK_DEFAULTS.rpc.maxConcurrentRequests,
  maxQueuedRequests: SDK_DEFAULTS.rpc.maxQueuedRequests,
  maxQueuedNotifications: SDK_DEFAULTS.rpc.maxQueuedNotifications,
});

type Work = Readonly<{ envelope: RpcEnvelope; release(): void }>;

export class RpcRouter {
  private handlers?: Map<number, RpcHandler>;
  private notifyHandlers?: Map<number, Set<NotifyHandler>>;
  constructor(private readonly registered?: Readonly<{
    requests: ReadonlyMap<number, RpcHandler>; notifications: ReadonlyMap<number, NotifyHandler>;
    context?: object;
  }>) {}

  register(typeId: number, handler: RpcHandler): void {
    if (this.registered) throw new Error("RPC registry is frozen");
    (this.handlers ??= new Map()).set(assertRpcTypeId(typeId), handler);
  }

  handler(typeId: number): RpcHandler | undefined {
    const handler = (this.registered?.requests ?? this.handlers)?.get(assertRpcTypeId(typeId));
    const context = this.registered?.context;
    return handler && context ? (payload, signal) => handler(payload, signal, context) : handler;
  }

  onNotify(typeId: number, handler: NotifyHandler): () => void {
    const normalized = assertRpcTypeId(typeId);
    const handlers = (this.notifyHandlers ??= new Map()).get(normalized) ?? new Set();
    handlers.add(handler);
    this.notifyHandlers.set(normalized, handlers);
    let subscribed = true;
    return () => {
      if (!subscribed) return;
      subscribed = false;
      handlers.delete(handler);
      if (handlers.size === 0) this.notifyHandlers?.delete(normalized);
    };
  }

  async dispatchNotification(typeId: number, payload: unknown, signal?: AbortSignal): Promise<void> {
    const normalized = assertRpcTypeId(typeId);
    if (signal?.aborted) return;
    const requestHandler = this.handlers?.get(normalized);
    if (requestHandler !== undefined) await requestHandler(payload, signal);
    if (signal?.aborted) return;
    const registered = this.registered?.notifications.get(normalized);
    if (registered) { try { await registered(payload, signal, this.registered?.context); } catch { /* Keep subscriptions isolated. */ } }
    for (const handler of [...(this.notifyHandlers?.get(normalized) ?? [])]) {
      if (signal?.aborted) return;
      try {
        await handler(payload, signal);
      } catch {
        // Application subscribers cannot stop RPC serving.
      }
    }
  }
}

// RpcServer dispatches request envelopes to registered handlers.
export class RpcServer {
  // Closed flag to stop the serve loop.
  private closed = false;
  private readonly options: Required<RpcServerOptions>;
  private readonly requests: Work[] = [];
  private readonly notifications: Work[] = [];
  private runningRequests = 0;
  private runningNotification = false;
  private readonly tasks = new Set<Promise<void>>();
  private readonly stopped = new AbortController();
  private writeChain: Promise<void> = Promise.resolve();
  private terminalError: unknown;
  private transportClosed = false;
  private transportCleanup: Promise<void> | undefined;

  constructor(
    private readonly transport: RpcServerTransport,
    options: RpcServerOptions = {},
    private readonly router: RpcRouter = new RpcRouter(),
  ) {
    this.options = {
      maxFrameBytes: options.maxFrameBytes ?? DEFAULT_MAX_JSON_FRAME_BYTES,
      maxConcurrentRequests: positiveInteger(options.maxConcurrentRequests ?? DEFAULT_RPC_SERVER_OPTIONS.maxConcurrentRequests, "maxConcurrentRequests"),
      maxQueuedRequests: nonNegativeInteger(options.maxQueuedRequests ?? DEFAULT_RPC_SERVER_OPTIONS.maxQueuedRequests, "maxQueuedRequests"),
      maxQueuedNotifications: nonNegativeInteger(options.maxQueuedNotifications ?? DEFAULT_RPC_SERVER_OPTIONS.maxQueuedNotifications, "maxQueuedNotifications"),
    };
  }

  // register binds a handler to a type ID.
  register(typeId: number, h: RpcHandler): void {
    this.router.register(typeId, h);
  }

  async notify(typeId: number, payload: unknown): Promise<void> {
    if (this.closed) throw new Error("rpc server closed");
    await this.writeEnvelope({
      type_id: assertRpcTypeId(typeId),
      request_id: 0,
      response_to: 0,
      payload,
    });
  }

  // serve handles request/response frames until closed or aborted.
  async serve(signal?: AbortSignal): Promise<void> {
    const abort = () => this.close(signal?.reason ?? new Error("aborted"));
    signal?.addEventListener("abort", abort, { once: true });
    try {
      if (signal?.aborted) abort();
      while (!this.closed) {
        const frame = await readRpcFrame(this.transport.readExactly, this.options.maxFrameBytes);
        let transferred = false;
        try {
          const v = assertRpcEnvelope(frame.value);
          if (this.closed || v.response_to !== 0) continue;
          const notify = v.request_id === 0;
          if (notify && this.runningNotification && this.notifications.length >= this.options.maxQueuedNotifications) throw new Error("rpc notification queue exhausted");
          if (!notify && this.runningRequests + this.requests.length >= this.options.maxConcurrentRequests + this.options.maxQueuedRequests) {
            await this.writeResponse(v, { payload: null, error: { code: 429, message: "server overloaded" } });
            continue;
          }
          (notify ? this.notifications : this.requests).push({ envelope: v, release: frame.release });
          transferred = true;
          this.dispatch(notify);
        } finally { if (!transferred) frame.release(); }
      }
    } catch (err) {
      this.close(err);
    } finally {
      signal?.removeEventListener("abort", abort);
    }
    if (this.terminalError !== undefined) throw this.terminalError;
  }

  // close stops the serve loop and closes the underlying RPC stream.
  close(error: unknown = new Error("rpc server closed")): void {
    if (!this.closed) {
      this.closed = true;
      this.terminalError = error;
      this.stopped.abort(error);
      for (const work of this.requests.splice(0)) work.release();
      for (const work of this.notifications.splice(0)) work.release();
    }
    if (!this.transportClosed) {
      this.transportClosed = true;
      this.transportCleanup = Promise.resolve(this.transport.close(error)).catch(() => undefined);
    }
  }

  private fail(error: unknown): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.close(error);
  }

  async waitHandlers(): Promise<void> { await Promise.allSettled([this.transportCleanup, this.writeChain, ...this.tasks]); }

  private dispatch(notify: boolean): void {
    if (this.closed || (notify ? this.runningNotification : this.runningRequests >= this.options.maxConcurrentRequests)) return;
    const work = (notify ? this.notifications : this.requests).shift();
    if (!work) return;
    if (notify) this.runningNotification = true; else this.runningRequests++;
    const task = Promise.resolve().then(async () => {
      if (this.closed) return;
      const v = work.envelope;
      if (notify) { await this.router.dispatchNotification(v.type_id, v.payload, this.stopped.signal); return; }
      const handler = this.router.handler(v.type_id);
      let result: Awaited<ReturnType<RpcHandler>>;
      try { result = handler ? await handler(v.payload, this.stopped.signal) : { payload: null, error: { code: 404, message: "handler not found" } }; }
      catch { result = { payload: null, error: { code: 500, message: "internal error" } }; }
      if (!this.closed) await this.writeResponse(v, result);
    }).catch(error => this.fail(error)).finally(() => {
      work.release(); this.tasks.delete(task);
      if (notify) this.runningNotification = false; else this.runningRequests--;
      this.dispatch(notify);
    });
    this.tasks.add(task);
  }

  private async writeResponse(request: RpcEnvelope, out: Awaited<ReturnType<RpcHandler>>): Promise<void> {
    let error: RpcError | undefined;
    if (out.error != null) {
      try { error = assertRpcError(out.error); }
      catch { error = { code: 500, message: "internal error" }; }
    }
    const resp: RpcEnvelope = {
      type_id: request.type_id,
      request_id: 0,
      response_to: request.request_id,
      payload: out.payload,
      ...(error != null ? { error } : {}),
    };
    await this.writeEnvelope(resp);
  }

  private async writeEnvelope(envelope: RpcEnvelope): Promise<void> {
    const write = this.writeChain.then(() => writeJsonFrame(this.transport.write, envelope, this.options.maxFrameBytes, true));
    this.writeChain = write;
    try {
      await write;
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`${name} must be a positive integer`);
  return value;
}

function nonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`${name} must be a non-negative integer`);
  return value;
}
