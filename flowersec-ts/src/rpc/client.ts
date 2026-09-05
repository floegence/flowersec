import type { RpcEnvelope, RpcError } from "./wire.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { assertRpcEnvelope, assertRpcTypeId } from "./validate.js";

// Guard against precision loss when encoding request IDs as numbers.
const MAX_SAFE_REQUEST_ID = BigInt(Number.MAX_SAFE_INTEGER);

// RpcClient sends request/response envelopes and dispatches notifications.
export class RpcClient {
  // Next request ID (bigint to avoid JS number precision loss).
  private nextId = 1n;
  // Pending requests keyed by request ID.
  private readonly pending = new Map<bigint, { resolve: (v: RpcEnvelope) => void; reject: (e: unknown) => void }>();
  // Notification handlers keyed by type ID.
  private readonly notifyHandlers = new Map<number, Set<(payload: unknown) => void>>();
  // Closed state to stop the read loop and reject calls.
  private closed = false;
  private writeTail: Promise<void> = Promise.resolve();
  private readonly onTerminal: ((error: Error) => void) | undefined;

  constructor(
    private readonly readExactly: (n: number) => Promise<Uint8Array>,
    private readonly write: (b: Uint8Array, signal?: AbortSignal) => Promise<void>,
    opts: Readonly<{ onTerminal?: (error: Error) => void }> = {}
  ) {
    this.onTerminal = opts.onTerminal;
    void this.readLoop();
  }

  // call sends a request and awaits a response or abort.
  async call(typeId: number, payload: unknown, signal?: AbortSignal): Promise<{ payload: unknown; error?: RpcError }> {
    if (this.closed) throw new Error("rpc client closed");
    if (signal?.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
    const validatedTypeId = assertRpcTypeId(typeId);
    if (this.nextId > MAX_SAFE_REQUEST_ID) throw new Error("request id overflow");
    const requestId = this.nextId;
    this.nextId += 1n;
    const env: RpcEnvelope = {
      type_id: validatedTypeId,
      request_id: Number(requestId),
      response_to: 0,
      payload
    };
    const p = new Promise<RpcEnvelope>((resolve, reject) => {
      this.pending.set(requestId, { resolve, reject });
    });
    let resp: RpcEnvelope;
    try {
      // Own both rejections before either side can settle. Cancellation covers
      // queued writes as well as the response wait.
      const result = await raceAbort(Promise.all([this.writeEnvelope(env, signal), p]), signal);
      resp = result[1];
    } finally {
      this.pending.delete(requestId);
    }
    if (resp.error == null) return { payload: resp.payload };
    return { payload: resp.payload, error: resp.error };
  }

  // close rejects all pending calls and stops the read loop.
  close(): void {
    this.closed = true;
    for (const [, p] of this.pending) p.reject(new Error("rpc closed"));
    this.pending.clear();
    this.notifyHandlers.clear();
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
    await raceAbort(this.writeEnvelope(env, signal), signal);
  }

  private writeEnvelope(envelope: RpcEnvelope, signal?: AbortSignal): Promise<void> {
    const operation = this.writeTail.then(async () => {
      if (signal?.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
      if (this.closed) throw new Error("rpc client closed");
      await writeJsonFrame((bytes) => this.write(bytes, signal), envelope, DEFAULT_MAX_JSON_FRAME_BYTES);
    });
    this.writeTail = operation.catch(() => undefined);
    return operation;
  }

  private async readLoop(): Promise<void> {
    try {
      while (!this.closed) {
        const v = assertRpcEnvelope(await readJsonFrame(this.readExactly, DEFAULT_MAX_JSON_FRAME_BYTES));
        if (v.response_to === 0) {
          // Notification: response_to=0 and request_id=0.
          if (v.request_id === 0) {
            const set = this.notifyHandlers.get(v.type_id);
            if (set != null) {
              for (const h of set) {
                try {
                  h(v.payload);
                } catch {
                  // User handlers should not be able to take down the transport read loop.
                }
              }
            }
          }
          continue;
        }
        const key = BigInt(v.response_to);
        const p = this.pending.get(key);
        if (p != null) {
          this.pending.delete(key);
          p.resolve(v);
        }
      }
    } catch (e) {
      const unexpected = !this.closed;
      this.closed = true;
      for (const [, p] of this.pending) p.reject(e);
      this.pending.clear();
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
