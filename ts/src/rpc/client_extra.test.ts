import { describe, expect, test } from "vitest";
import type { RpcEnvelope } from "../gen/flowersec/rpc/v1.gen.js";
import { readU32be } from "../utils/bin.js";
import { RpcClient } from "./client.js";
import { writeJsonFrame } from "./framing.js";

class ByteQueue {
  private readonly chunks: Uint8Array[] = [];
  private readonly waiters: Array<{ n: number; resolve: (b: Uint8Array) => void; reject: (e: unknown) => void }> = [];
  private closedError: unknown = null;

  async write(b: Uint8Array): Promise<void> {
    if (this.closedError != null) throw this.closedError;
    this.chunks.push(b);
    this.flush();
  }

  readExactly(n: number): Promise<Uint8Array> {
    if (this.closedError != null) return Promise.reject(this.closedError);
    const out = this.tryRead(n);
    if (out != null) return Promise.resolve(out);
    return new Promise((resolve, reject) => {
      this.waiters.push({ n, resolve, reject });
    });
  }

  close(err: unknown): void {
    this.closedError = err;
    const ws = this.waiters.splice(0, this.waiters.length);
    for (const w of ws) w.reject(err);
  }

  private flush(): void {
    while (this.waiters.length > 0) {
      const next = this.waiters[0];
      const out = this.tryRead(next.n);
      if (out == null) return;
      this.waiters.shift();
      next.resolve(out);
    }
  }

  private tryRead(n: number): Uint8Array | null {
    let available = 0;
    for (const chunk of this.chunks) available += chunk.length;
    if (available < n) return null;
    const out = new Uint8Array(n);
    let offset = 0;
    let remaining = n;
    while (remaining > 0) {
      const chunk = this.chunks[0]!;
      if (chunk.length <= remaining) {
        out.set(chunk, offset);
        offset += chunk.length;
        remaining -= chunk.length;
        this.chunks.shift();
      } else {
        out.set(chunk.subarray(0, remaining), offset);
        this.chunks[0] = chunk.subarray(remaining);
        remaining = 0;
      }
    }
    return out;
  }
}

function decodeEnvelope(frame: Uint8Array): RpcEnvelope {
  const n = readU32be(frame, 0);
  const payload = frame.subarray(4, 4 + n);
  return JSON.parse(new TextDecoder().decode(payload)) as RpcEnvelope;
}

describe("RpcClient extra behavior", () => {
  test("abort while waiting records canceled", async () => {
    const q = new ByteQueue();
    const results: string[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async () => {}, {
      observer: {
        onRpcCall: (r) => results.push(r)
      }
    });

    const ctrl = new AbortController();
    const p = client.call(1, { ok: true }, ctrl.signal);
    ctrl.abort(new Error("aborted"));

    await expect(p).rejects.toThrow(/aborted/);
    client.close();
    q.close(new Error("eof"));

    expect(results).toEqual(["canceled"]);
  });

  test("transport write errors are surfaced and recorded", async () => {
    const q = new ByteQueue();
    const results: string[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async () => {
      throw new Error("write failed");
    }, {
      observer: {
        onRpcCall: (r) => results.push(r)
      }
    });

    await expect(client.call(1, { ok: true })).rejects.toThrow(/write failed/);
    client.close();
    q.close(new Error("eof"));
    expect(results).toEqual(["transport_error"]);
  });

  test("request id overflow is rejected", async () => {
    const q = new ByteQueue();
    const client = new RpcClient(q.readExactly.bind(q), async () => {});
    (client as any).nextId = BigInt(Number.MAX_SAFE_INTEGER) + 1n;

    await expect(client.call(1, { ok: true })).rejects.toThrow(/request id overflow/);
    client.close();
    q.close(new Error("eof"));
  });

  test("close rejects pending calls", async () => {
    const q = new ByteQueue();
    const client = new RpcClient(q.readExactly.bind(q), async () => {});
    const p = client.call(1, { ok: true });
    client.close();
    q.close(new Error("eof"));

    await expect(p).rejects.toThrow(/rpc closed/);
  });

  test("readLoop errors reject pending calls", async () => {
    const q = new ByteQueue();
    const client = new RpcClient(q.readExactly.bind(q), async () => {});
    const p = client.call(1, { ok: true });
    q.close(new Error("eof"));

    await expect(p).rejects.toThrow(/eof/);
    client.close();
  });

  test("observer records rpc_error and handler_not_found", async () => {
    const q = new ByteQueue();
    const results: string[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => {
      const env = decodeEnvelope(frame);
      if (env.request_id === 0) return;
      const error = env.type_id === 2 ? { code: 500, message: "boom" } : { code: 404, message: "missing" };
      await writeJsonFrame(q.write.bind(q), {
        type_id: env.type_id,
        request_id: 0,
        response_to: env.request_id,
        payload: { ok: true },
        error
      });
    }, {
      observer: {
        onRpcCall: (r) => results.push(r)
      }
    });

    await client.call(2, { ok: false });
    await client.call(3, { ok: false });

    client.close();
    q.close(new Error("eof"));
    expect(results).toEqual(["rpc_error", "handler_not_found"]);
  });

  test("notification handler errors do not stop readLoop", async () => {
    const q = new ByteQueue();
    let notifyOk = 0;
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => {
      const env = decodeEnvelope(frame);
      if (env.request_id === 0) return;
      await writeJsonFrame(q.write.bind(q), {
        type_id: env.type_id,
        request_id: 0,
        response_to: env.request_id,
        payload: env.payload
      });
    });

    client.onNotify(9, () => {
      throw new Error("boom");
    });
    client.onNotify(9, () => {
      notifyOk += 1;
    });

    await writeJsonFrame(q.write.bind(q), {
      type_id: 9,
      request_id: 0,
      response_to: 0,
      payload: { ping: true }
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(notifyOk).toBe(1);

    const resp = await client.call(1, { ok: true });
    expect(resp.payload).toEqual({ ok: true });

    client.close();
    q.close(new Error("eof"));
  });

  test("rejects rpc envelopes with unsafe u64 response_to", async () => {
    const q = new ByteQueue();
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => {
      const env = decodeEnvelope(frame);
      if (env.request_id === 0) return;
      // 2^53 is exactly representable but outside JS safe integer range.
      await writeJsonFrame(q.write.bind(q), {
        type_id: env.type_id,
        request_id: 0,
        response_to: 9007199254740992,
        payload: { ok: true }
      });
    });

    await expect(client.call(1, { ok: true })).rejects.toThrow(/bad rpc envelope: response_to/);
    client.close();
    q.close(new Error("eof"));
  });
});
