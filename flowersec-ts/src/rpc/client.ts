import type { RpcEnvelope, RpcError } from "./wire.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readRpcFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { assertRpcEnvelope, assertRpcTypeId } from "./validate.js";
import { SessionError } from "../public/contract.js";
import { SDK_DEFAULTS } from "../defaults.js";

// Guard against precision loss when encoding request IDs as numbers.
const MAX_SAFE_REQUEST_ID = BigInt(Number.MAX_SAFE_INTEGER);

type QueuedWrite = { run(): Promise<void>; cancel(reason: unknown): void };

// RpcClient sends request/response envelopes and dispatches notifications.
export class RpcClient {
  // Next request ID (bigint to avoid JS number precision loss).
  private nextId = 1n;
  // Pending requests keyed by request ID.
  private readonly pending = new Map<bigint, { typeId: number; resolve: (v: RpcEnvelope, release: () => void) => void; reject: (e: unknown) => void }>();
  // Notification handlers keyed by type ID.
  private readonly notifyHandlers = new Map<number, Set<(payload: unknown) => void>>();
  // Closed state to stop the read loop and reject calls.
  private closed = false;
  private readonly stopped = new AbortController();
  private readonly readTask: Promise<void>;
  private readonly writes = new Set<QueuedWrite>();
  private writeTask: Promise<void> | undefined;
  private notificationTail: Promise<void> = Promise.resolve();
  private notifications = 0;
  private readonly onTerminal: ((error: Error) => void) | undefined;
  private readonly maxFrameBytes: number;
  private readonly maxConcurrentRequests: number;
  private writing = false;

  constructor(
    private readonly readExactly: (n: number) => Promise<Uint8Array>,
    private readonly write: (b: Uint8Array, signal?: AbortSignal) => Promise<void>,
    opts: Readonly<{ onTerminal?: (error: Error) => void; maxFrameBytes?: number; maxConcurrentRequests?: number }> = {}
  ) {
    this.onTerminal = opts.onTerminal;
    this.maxFrameBytes = opts.maxFrameBytes ?? DEFAULT_MAX_JSON_FRAME_BYTES;
    this.maxConcurrentRequests = opts.maxConcurrentRequests ?? SDK_DEFAULTS.rpc.maxConcurrentRequests;
    this.readTask = this.readLoop();
  }

  // call sends a request and awaits a response or abort.
  async call(typeId: number, payload: unknown, signal?: AbortSignal): Promise<{ payload: unknown; error?: RpcError }> {
    if (this.closed) throw new Error("rpc client closed");
    if (signal?.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
    const validatedTypeId = assertRpcTypeId(typeId);
    if (this.nextId > MAX_SAFE_REQUEST_ID) throw new SessionError("request_id_exhausted");
    if (this.pending.size >= this.maxConcurrentRequests || this.writes.size + Number(this.writing) >= this.maxConcurrentRequests) throw new SessionError("resource_exhausted");
    const requestId = this.nextId;
    this.nextId += 1n;
    const env: RpcEnvelope = {
      type_id: validatedTypeId,
      request_id: Number(requestId),
      response_to: 0,
      payload
    };
    let releaseResponse: (() => void) | undefined;
    const p = new Promise<RpcEnvelope>((resolve, reject) => {
      this.pending.set(requestId, { typeId: validatedTypeId, resolve: (response, release) => {
        releaseResponse = release;
        resolve(response);
      }, reject });
    });
    let resp: RpcEnvelope;
    try {
      // Own both rejections before either side can settle. Cancellation covers
      // queued writes as well as the response wait.
      const lifetime = signal === undefined ? this.stopped.signal : AbortSignal.any([signal, this.stopped.signal]);
      const result = await raceAbort(Promise.all([this.writeEnvelope(env, lifetime), p]), lifetime);
      resp = result[1];
    } finally {
      this.pending.delete(requestId);
      releaseResponse?.();
    }
    if (resp.error == null) return { payload: resp.payload };
    return { payload: resp.payload, error: resp.error };
  }

  // close rejects all pending calls and stops the read loop.
  close(reason: Error = new Error("rpc closed")): void {
    if (this.closed) return;
    this.closed = true;
    this.stopped.abort(reason);
    for (const write of this.writes) write.cancel(reason);
    for (const [, p] of this.pending) p.reject(reason);
    this.pending.clear();
    this.notifyHandlers.clear();
  }

  async waitStopped(): Promise<void> {
    await Promise.allSettled([this.readTask, this.writeTask, this.notificationTail]);
  }

  // onNotify registers a handler for incoming notifications.
  onNotify(typeId: number, handler: (payload: unknown) => void): () => void {
    const tid = assertRpcTypeId(typeId);
    const set = this.notifyHandlers.get(tid) ?? new Set<(payload: unknown) => void>();
    set.add(handler);
    this.notifyHandlers.set(tid, set);
    return () => {
      const s = this.notifyHandlers.get(tid);
      s?.delete(handler);
      if (s != null && s.size === 0) this.notifyHandlers.delete(tid);
    };
  }

  // notify sends a one-way notification to the peer.
  async notify(typeId: number, payload: unknown, signal?: AbortSignal): Promise<void> {
    if (this.closed) throw new Error("rpc client closed");
    const validatedTypeId = assertRpcTypeId(typeId);
    const env: RpcEnvelope = {
      type_id: validatedTypeId,
      request_id: 0,
      response_to: 0,
      payload
    };
    const lifetime = signal === undefined ? this.stopped.signal : AbortSignal.any([signal, this.stopped.signal]);
    await raceAbort(this.writeEnvelope(env, lifetime), lifetime);
  }

  private writeEnvelope(envelope: RpcEnvelope, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(signal.reason);
    if (this.writes.size + Number(this.writing) >= this.maxConcurrentRequests) return Promise.reject(new SessionError("resource_exhausted"));
    return new Promise<void>((resolve, reject) => {
      const abort = () => entry.cancel(signal?.reason);
      const entry: QueuedWrite = {
        cancel: reason => {
          if (!this.writes.delete(entry)) return;
          signal?.removeEventListener("abort", abort);
          reject(reason);
        },
        run: async () => {
          signal?.removeEventListener("abort", abort);
          try {
            await writeJsonFrame(bytes => this.write(bytes, signal), envelope, this.maxFrameBytes, true);
            resolve();
          } catch (error) { reject(error); }
        },
      };
      this.writes.add(entry);
      signal?.addEventListener("abort", abort, { once: true });
      this.writeTask ??= Promise.resolve().then(async () => {
        try {
          for (const next of this.writes) {
            this.writes.delete(next);
            this.writing = true;
            await next.run();
            this.writing = false;
          }
        } finally { this.writeTask = undefined; }
      });
    });
  }

  private async readLoop(): Promise<void> {
    try {
      while (!this.closed) {
        const frame = await readRpcFrame(this.readExactly, this.maxFrameBytes);
        let transferred = false;
        try {
          if (this.closed) return;
          const v = assertRpcEnvelope(frame.value);
          if (v.response_to === 0) {
            if (v.request_id !== 0) throw new Error("rpc invalid request on client stream");
            const set = this.notifyHandlers.get(v.type_id);
            if (set?.size) {
              if (this.notifications >= SDK_DEFAULTS.rpc.maxQueuedNotifications + 1) throw new SessionError("resource_exhausted");
              const handlers = [...set];
              this.notifications++;
              transferred = true;
              this.notificationTail = this.notificationTail.then(async () => {
                for (const handler of handlers) {
                  if (this.closed) return;
                  try { await handler(v.payload); } catch { /* Subscribers are isolated. */ }
                }
              }).finally(() => { this.notifications--; frame.release(); });
            }
            continue;
          }
          const key = BigInt(v.response_to);
          const pending = this.pending.get(key);
          if (pending !== undefined) {
            if (pending.typeId !== v.type_id) throw new Error("rpc response method mismatch");
            this.pending.delete(key);
            transferred = true;
            pending.resolve(v, frame.release);
          }
        } finally { if (!transferred) frame.release(); }
      }
    } catch (e) {
      const unexpected = !this.closed;
      this.close(e instanceof Error ? e : new Error(String(e)));
      if (unexpected) {
        try {
          this.onTerminal?.(e instanceof Error ? e : new Error(String(e)));
        } catch {
          // Lifecycle callbacks must not escape the read loop.
        }
      }
    }
  }
}

// raceAbort resolves p unless the signal aborts first.
async function raceAbort<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
  void p.catch(() => undefined);
  if (signal == null) return p;
  if (signal.aborted) throw signal.reason ?? new Error("aborted");
  return await new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    void p.then(
      (v) => {
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener("abort", onAbort);
        reject(e);
      }
    );
  });
}
