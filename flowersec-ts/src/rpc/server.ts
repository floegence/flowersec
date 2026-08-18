import type { RpcEnvelope, RpcError } from "./wire.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { assertRpcEnvelope, assertRpcError, assertRpcTypeId } from "./validate.js";
import { SDK_DEFAULTS } from "../defaults.js";

// RpcHandler processes a request and returns a payload or error.
export type RpcHandler = (payload: unknown) => Promise<{ payload: unknown; error?: RpcError }>;

export type RpcServerOptions = Readonly<{
  maxConcurrentRequests?: number;
  maxQueuedRequests?: number;
  maxQueuedNotifications?: number;
}>;

export type RpcServerTransport = Readonly<{
  readExactly(n: number): Promise<Uint8Array>;
  write(bytes: Uint8Array): Promise<void>;
  close(error: unknown): void;
}>;

const DEFAULT_RPC_SERVER_OPTIONS = Object.freeze({
  maxConcurrentRequests: SDK_DEFAULTS.rpc.maxConcurrentRequests,
  maxQueuedRequests: SDK_DEFAULTS.rpc.maxQueuedRequests,
  maxQueuedNotifications: SDK_DEFAULTS.rpc.maxQueuedNotifications,
});

type Work = Readonly<{ envelope: RpcEnvelope }>;

export class RpcRouter {
  private readonly handlers = new Map<number, RpcHandler>();
  private readonly notifyHandlers = new Map<number, Set<(payload: unknown) => void>>();

  register(typeId: number, handler: RpcHandler): void {
    this.handlers.set(assertRpcTypeId(typeId), handler);
  }

  handler(typeId: number): RpcHandler | undefined {
    return this.handlers.get(assertRpcTypeId(typeId));
  }

  onNotify(typeId: number, handler: (payload: unknown) => void): () => void {
    const normalized = assertRpcTypeId(typeId);
    const handlers = this.notifyHandlers.get(normalized) ?? new Set();
    handlers.add(handler);
    this.notifyHandlers.set(normalized, handlers);
    return () => {
      handlers.delete(handler);
      if (handlers.size === 0) this.notifyHandlers.delete(normalized);
    };
  }

  async dispatchNotification(typeId: number, payload: unknown): Promise<void> {
    const normalized = assertRpcTypeId(typeId);
    const requestHandler = this.handlers.get(normalized);
    if (requestHandler !== undefined) await requestHandler(payload);
    for (const handler of [...(this.notifyHandlers.get(normalized) ?? [])]) {
      try {
        handler(payload);
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
  private requestWaiters: Array<() => void> = [];
  private notificationWaiters: Array<() => void> = [];
  private writeChain: Promise<void> = Promise.resolve();
  private terminalError: unknown;
  private readonly terminalSignal: Promise<unknown>;
  private signalTerminal!: (error: unknown) => void;
  private transportClosed = false;
  private admittedRequests = 0;

  constructor(
    private readonly transport: RpcServerTransport,
    options: RpcServerOptions = {},
    private readonly router: RpcRouter = new RpcRouter(),
  ) {
    this.terminalSignal = new Promise((resolve) => { this.signalTerminal = resolve; });
    this.options = {
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
    const workers = Array.from({ length: this.options.maxConcurrentRequests }, () => this.requestWorker());
    workers.push(this.notificationWorker());
    const workerFailure = Promise.race(workers.map(async (worker) => {
      await worker;
      if (!this.closed) throw new Error("rpc worker ended before server shutdown");
      return await new Promise<never>(() => undefined);
    }));
    let failure: unknown;
    const aborted = abortPromise(signal);
    try {
      while (!this.closed) {
        if (signal?.aborted) throw signal.reason ?? new Error("aborted");
        const next = await Promise.race([
          readJsonFrame(this.transport.readExactly, DEFAULT_MAX_JSON_FRAME_BYTES),
          this.terminalSignal.then((error) => { throw error; }),
          workerFailure,
          ...(aborted === undefined ? [] : [aborted.promise]),
        ]);
        const v = assertRpcEnvelope(next);
        if (v.response_to !== 0) continue;
        if (v.request_id === 0) {
          if (this.notifications.length >= this.options.maxQueuedNotifications) {
            throw new Error("rpc notification queue exhausted");
          }
          this.notifications.push({ envelope: v });
          this.wakeOne(this.notificationWaiters);
          continue;
        }
        if (this.admittedRequests >= this.options.maxConcurrentRequests + this.options.maxQueuedRequests) {
          await this.writeResponse(v, { payload: null, error: { code: 429, message: "server overloaded" } });
          continue;
        }
        this.admittedRequests += 1;
        this.requests.push({ envelope: v });
        this.wakeOne(this.requestWaiters);
      }
    } catch (err) {
      failure = err;
      this.terminalError = err;
    } finally {
      aborted?.cleanup();
    }
    let closeError: unknown;
    try {
      this.close(failure ?? this.terminalError ?? new Error("rpc server closed"));
    } catch (error) {
      closeError = error;
    }
    const settled = await Promise.allSettled(workers);
    const workerErrors = settled
      .filter((result): result is PromiseRejectedResult => result.status === "rejected")
      .map((result) => result.reason)
      .filter((error) => error !== failure);
    const errors = [failure, closeError, ...workerErrors].filter((error) => error !== undefined);
    if (errors.length === 1) throw errors[0];
    if (errors.length > 1) throw new AggregateError(errors, "rpc server and cleanup failed");
    if (this.terminalError !== undefined) throw this.terminalError;
  }

  // close stops the serve loop and closes the underlying RPC stream.
  close(error: unknown = new Error("rpc server closed")): void {
    if (!this.closed) {
      this.closed = true;
      this.signalTerminal(error);
      for (const wake of this.requestWaiters.splice(0)) wake();
      for (const wake of this.notificationWaiters.splice(0)) wake();
    }
    if (!this.transportClosed) {
      this.transportClosed = true;
      this.transport.close(error);
    }
  }

  private fail(error: unknown): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.close(error);
  }

  private async requestWorker(): Promise<void> {
    while (!this.closed) {
      const work = await this.nextWork(this.requests, this.requestWaiters);
      if (work == null) return;
      const v = work.envelope;
      try {
        const h = this.router.handler(v.type_id);
        let out: Awaited<ReturnType<RpcHandler>>;
        if (h == null) out = { payload: null, error: { code: 404, message: "handler not found" } };
        else {
          const outcome = await Promise.race([
            Promise.resolve().then(() => h(v.payload)).then(
              (value) => ({ kind: "completed" as const, value }),
              () => ({
                kind: "completed" as const,
                value: { payload: null, error: { code: 500, message: "internal error" } } as const,
              }),
            ),
            this.terminalSignal.then(() => ({ kind: "terminated" as const })),
          ]);
          if (outcome.kind === "terminated") return;
          out = outcome.value;
        }
        if (this.closed) return;
        await this.writeResponse(v, out);
      } finally {
        this.admittedRequests = Math.max(0, this.admittedRequests - 1);
      }
    }
  }

  private async notificationWorker(): Promise<void> {
    while (!this.closed) {
      const work = await this.nextWork(this.notifications, this.notificationWaiters);
      if (work == null) return;
      const v = work.envelope;
      const completed = await Promise.race([
        Promise.resolve().then(() => this.router.dispatchNotification(v.type_id, v.payload)).then(() => true),
        this.terminalSignal.then(() => false),
      ]);
      if (!completed) return;
    }
  }

  private async nextWork(queue: Work[], waiters: Array<() => void>): Promise<Work | null> {
    while (!this.closed) {
      const work = queue.shift();
      if (work != null) return work;
      await new Promise<void>((resolve) => waiters.push(resolve));
    }
    return null;
  }

  private wakeOne(waiters: Array<() => void>): void {
    waiters.shift()?.();
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
    const write = this.writeChain.then(() => writeJsonFrame(this.transport.write, envelope, DEFAULT_MAX_JSON_FRAME_BYTES));
    this.writeChain = write;
    try {
      await write;
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }
}

function abortPromise(signal: AbortSignal | undefined): Readonly<{ promise: Promise<never>; cleanup(): void }> | undefined {
  if (signal === undefined || signal.aborted) return undefined;
  let onAbort!: () => void;
  const promise = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(signal.reason ?? new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
  });
  return { promise, cleanup: () => signal.removeEventListener("abort", onAbort) };
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`${name} must be a positive integer`);
  return value;
}

function nonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`${name} must be a non-negative integer`);
  return value;
}
