import { describe, expect, test, vi } from "vitest";
import type { RpcEnvelope } from "../gen/flowersec/rpc/v1.gen.js";
import { writeJsonFrame } from "../framing/jsonframe.js";
import { RpcServer } from "./server.js";
import { readU32be } from "../utils/bin.js";

class ByteQueue {
  private readonly chunks: Uint8Array[] = [];
  private readonly waiters: Array<{ n: number; resolve: (b: Uint8Array) => void; reject: (e: unknown) => void }> = [];
  private closedError: unknown = null;
  private readCount = 0;

  async write(b: Uint8Array): Promise<void> {
    if (this.closedError != null) throw this.closedError;
    this.chunks.push(b);
    this.flush();
  }

  readExactly(n: number): Promise<Uint8Array> {
    if (this.closedError != null) return Promise.reject(this.closedError);
    const out = this.tryRead(n);
    if (out != null) {
      this.readCount += 1;
      return Promise.resolve(out);
    }
    return new Promise((resolve, reject) => {
      this.waiters.push({
        n,
        resolve: (b) => {
          this.readCount += 1;
          resolve(b);
        },
        reject
      });
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

  reads(): number {
    return this.readCount;
  }
}

function decodeEnvelope(frame: Uint8Array): RpcEnvelope {
  const n = readU32be(frame, 0);
  const payload = frame.subarray(4, 4 + n);
  return JSON.parse(new TextDecoder().decode(payload)) as RpcEnvelope;
}

async function makeFrame(env: RpcEnvelope): Promise<Uint8Array> {
  let out = new Uint8Array();
  await writeJsonFrame(async (b) => {
    out = b;
  }, env);
  return out;
}

async function waitFor(condition: () => boolean, timeoutMs = 200): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timeout");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

describe("RpcServer", () => {
  test("returns handler_not_found when handler is missing", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(q.readExactly.bind(q), async (b) => {
      writes.push(b);
    });

    const request = await makeFrame({ type_id: 7, request_id: 9, response_to: 0, payload: { x: 1 } });
    await q.write(request);
    const serve = server.serve();

    await waitFor(() => writes.length === 1);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);

    expect(writes.length).toBe(1);
    const resp = decodeEnvelope(writes[0]!);
    expect(resp.response_to).toBe(9);
    expect(resp.error?.code).toBe(404);
  });

  test("notification handler errors do not stop serve loop", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(q.readExactly.bind(q), async (b) => {
      writes.push(b);
    });
    server.register(1, async () => {
      throw new Error("boom");
    });
    server.register(2, async (payload) => ({ payload }));

    const notify = await makeFrame({ type_id: 1, request_id: 0, response_to: 0, payload: { n: true } });
    const req = await makeFrame({ type_id: 2, request_id: 5, response_to: 0, payload: { ok: true } });
    await q.write(notify);
    await q.write(req);

    const serve = server.serve();
    await waitFor(() => writes.length === 1);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);

    expect(writes.length).toBe(1);
    const resp = decodeEnvelope(writes[0]!);
    expect(resp.response_to).toBe(5);
    expect(resp.payload).toEqual({ ok: true });
  });

  test("request handler errors do not stop serve loop", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(q.readExactly.bind(q), async (b) => {
      writes.push(b);
    });
    server.register(1, async () => {
      throw new Error("boom");
    });
    server.register(2, async (payload) => ({ payload }));

    const req1 = await makeFrame({ type_id: 1, request_id: 5, response_to: 0, payload: { x: 1 } });
    const req2 = await makeFrame({ type_id: 2, request_id: 6, response_to: 0, payload: { ok: true } });
    await q.write(req1);
    await q.write(req2);

    const serve = server.serve();
    await waitFor(() => writes.length === 2);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);

    const resp1 = decodeEnvelope(writes[0]!);
    expect(resp1.response_to).toBe(5);
    expect(resp1.error?.code).toBe(500);

    const resp2 = decodeEnvelope(writes[1]!);
    expect(resp2.response_to).toBe(6);
    expect(resp2.payload).toEqual({ ok: true });
  });

  test("ignores response_to frames", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(q.readExactly.bind(q), async (b) => {
      writes.push(b);
    });
    const respFrame = await makeFrame({ type_id: 1, request_id: 0, response_to: 99, payload: { ignore: true } });
    await q.write(respFrame);

    const serve = server.serve();
    await waitFor(() => q.reads() >= 2);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);

    expect(writes.length).toBe(0);
  });

  test("abort signal stops serve before reading", async () => {
    const q = new ByteQueue();
    const server = new RpcServer(q.readExactly.bind(q), async () => {});
    const ctrl = new AbortController();
    ctrl.abort(new Error("aborted"));
    await expect(server.serve(ctrl.signal)).rejects.toThrow(/aborted/);
  });

  test("write failures surface to caller", async () => {
    const q = new ByteQueue();
    const server = new RpcServer(q.readExactly.bind(q), async () => {
      throw new Error("write failed");
    });
    server.register(1, async (payload) => ({ payload }));

    const req = await makeFrame({ type_id: 1, request_id: 2, response_to: 0, payload: { ok: true } });
    await q.write(req);
    await expect(server.serve()).rejects.toThrow(/write failed/);
  });

  test("register accepts typeId normalization", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(q.readExactly.bind(q), async (b) => {
      writes.push(b);
    });
    const handler = vi.fn(async (payload) => ({ payload }));
    server.register(-1, handler);

    const req = await makeFrame({ type_id: 0xffffffff, request_id: 11, response_to: 0, payload: { x: 1 } });
    await q.write(req);
    const serve = server.serve();
    await waitFor(() => writes.length === 1);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(writes.length).toBe(1);
  });
});
