import type { RpcEnvelope, RpcError } from "../gen/flowersec/rpc/v1.gen.js";
import { readJsonFrame, writeJsonFrame } from "./framing.js";

// Guard against precision loss when encoding request IDs as numbers.
const MAX_SAFE_REQUEST_ID = BigInt(Number.MAX_SAFE_INTEGER);

// RpcClient sends request/response envelopes and dispatches notifications.
export class RpcClient {
  private nextId = 1n;
  private readonly pending = new Map<bigint, { resolve: (v: RpcEnvelope) => void; reject: (e: unknown) => void }>();
  private readonly notifyHandlers = new Map<number, Set<(payload: unknown) => void>>();
  private closed = false;

  constructor(
    private readonly readExactly: (n: number) => Promise<Uint8Array>,
    private readonly write: (b: Uint8Array) => Promise<void>
  ) {
    void this.readLoop();
  }

  // call sends a request and awaits a response or abort.
  async call(typeId: number, payload: unknown, signal?: AbortSignal): Promise<{ payload: unknown; error?: RpcError }> {
    if (this.closed) throw new Error("rpc client closed");
    if (this.nextId > MAX_SAFE_REQUEST_ID) throw new Error("request id overflow");
    const requestId = this.nextId;
    this.nextId += 1n;
    const env: RpcEnvelope = {
      type_id: typeId >>> 0,
      request_id: Number(requestId),
      response_to: 0,
      payload
    };
    const p = new Promise<RpcEnvelope>((resolve, reject) => {
      this.pending.set(requestId, { resolve, reject });
    });
    try {
      await writeJsonFrame(this.write, env);
    } catch (e) {
      this.pending.delete(requestId);
      throw e;
    }
    if (signal?.aborted) {
      this.pending.delete(requestId);
      throw signal.reason ?? new Error("aborted");
    }
    let resp: RpcEnvelope;
    try {
      resp = await raceAbort(p, signal);
    } catch (e) {
      this.pending.delete(requestId);
      throw e;
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
    const tid = typeId >>> 0;
    const set = this.notifyHandlers.get(tid) ?? new Set<(payload: unknown) => void>();
    set.add(handler);
    this.notifyHandlers.set(tid, set);
    return () => {
      const s = this.notifyHandlers.get(tid);
      s?.delete(handler);
      if (s != null && s.size === 0) this.notifyHandlers.delete(tid);
    };
  }

  private async readLoop(): Promise<void> {
    try {
      while (!this.closed) {
        const v = (await readJsonFrame(this.readExactly, 1 << 20)) as RpcEnvelope;
        if (v.response_to === 0) {
          // Notification: response_to=0 and request_id=0.
          if (v.request_id === 0) {
            const set = this.notifyHandlers.get(v.type_id >>> 0);
            if (set != null) {
              for (const h of set) h(v.payload);
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
      this.closed = true;
      for (const [, p] of this.pending) p.reject(e);
      this.pending.clear();
    }
  }
}

// raceAbort resolves p unless the signal aborts first.
async function raceAbort<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
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
