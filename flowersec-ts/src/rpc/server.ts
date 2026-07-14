import type { RpcEnvelope, RpcError } from "../gen/flowersec/rpc/v1.gen.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { assertRpcEnvelope } from "./validate.js";

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
  maxConcurrentRequests: 32,
  maxQueuedRequests: 128,
  maxQueuedNotifications: 128,
});

type Work = Readonly<{ envelope: RpcEnvelope }>;

// RpcServer dispatches request envelopes to registered handlers.
export class RpcServer {
  // Registered handlers keyed by type ID.
  private readonly handlers = new Map<number, RpcHandler>();
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

  constructor(
    private readonly transport: RpcServerTransport,
    options: RpcServerOptions = {},
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
    this.handlers.set(typeId >>> 0, h);
  }

  // serve handles request/response frames until closed or aborted.
  async serve(signal?: AbortSignal): Promise<void> {
    const supervise = (worker: Promise<void>): Promise<void> => worker.catch((err) => {
      this.fail(err);
    });
    const workers = Array.from({ length: this.options.maxConcurrentRequests }, () => supervise(this.requestWorker()));
    workers.push(supervise(this.notificationWorker()));
    try {
      while (!this.closed) {
        if (signal?.aborted) throw signal.reason ?? new Error("aborted");
        const next = await Promise.race([
          readJsonFrame(this.transport.readExactly, DEFAULT_MAX_JSON_FRAME_BYTES),
          this.terminalSignal.then((error) => { throw error; }),
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
        if (this.requests.length >= this.options.maxQueuedRequests) {
          await this.writeResponse(v, { payload: null, error: { code: 429, message: "server overloaded" } });
          continue;
        }
        this.requests.push({ envelope: v });
        this.wakeOne(this.requestWaiters);
      }
    } catch (err) {
      this.terminalError = err;
      this.close(err);
      throw err;
    } finally {
      this.close(this.terminalError ?? new Error("rpc server closed"));
      void Promise.allSettled(workers);
    }
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
      const h = this.handlers.get(v.type_id >>> 0);
      let out: Awaited<ReturnType<RpcHandler>>;
      if (h == null) out = { payload: null, error: { code: 404, message: "handler not found" } };
      else {
        try { out = await h(v.payload); }
        catch { out = { payload: null, error: { code: 500, message: "internal error" } }; }
      }
      if (this.closed) return;
      await this.writeResponse(v, out);
    }
  }

  private async notificationWorker(): Promise<void> {
    while (!this.closed) {
      const work = await this.nextWork(this.notifications, this.notificationWaiters);
      if (work == null) return;
      const v = work.envelope;
      const h = this.handlers.get(v.type_id >>> 0);
      if (h == null) continue;
      try { await h(v.payload); } catch { /* Notification failures are isolated. */ }
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
    const resp: RpcEnvelope = {
      type_id: request.type_id,
      request_id: 0,
      response_to: request.request_id,
      payload: out.payload,
      ...(out.error != null ? { error: out.error } : {}),
    };
    const write = this.writeChain.then(() => writeJsonFrame(this.transport.write, resp));
    this.writeChain = write.catch(() => {});
    await write;
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
