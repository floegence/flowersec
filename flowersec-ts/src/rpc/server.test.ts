import { describe, expect, test, vi } from "vitest";
import type { RpcEnvelope } from "./wire.js";
import { writeJsonFrame } from "../framing/jsonframe.js";
import { RpcRouter, RpcServer, type RpcServerTransport } from "./server.js";
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
      const next = this.waiters[0]!;
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
        this.chunks[0] = new Uint8Array(chunk.subarray(remaining));
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
  let out: Uint8Array<ArrayBufferLike> = new Uint8Array();
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

function makeTransport(
  queue: ByteQueue,
  write: (bytes: Uint8Array) => Promise<void>,
  close: (error: unknown) => void = (error) => { queue.close(error); },
): RpcServerTransport {
  return {
    readExactly: queue.readExactly.bind(queue),
    write,
    close,
  };
}

describe("RpcServer", () => {
  test("isolates inbound notification subscribers and honors unsubscribe", async () => {
    const router = new RpcRouter();
    const observed: unknown[] = [];
    router.onNotify(7, () => { throw new Error("subscriber failure"); });
    const unsubscribe = router.onNotify(7, (payload) => { observed.push(payload); });

    await router.dispatchNotification(7, { sequence: 1 });
    unsubscribe();
    await router.dispatchNotification(7, { sequence: 2 });

    expect(observed).toEqual([{ sequence: 1 }]);
  });

  test("sends server notifications through the serialized response writer", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(makeTransport(q, async (bytes) => {
      writes.push(bytes);
    }));
    await server.notify(2, { hello: "world" });
    expect(writes.map(decodeEnvelope)).toEqual([{
      type_id: 2,
      request_id: 0,
      response_to: 0,
      payload: { hello: "world" },
    }]);
    server.close();
    await expect(server.notify(2, {})).rejects.toThrow(/closed/);
  });

  test("executes requests concurrently and writes responses by completion order", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    let releaseSlow!: () => void;
    const slow = new Promise<void>((resolve) => { releaseSlow = resolve; });
    const server = new RpcServer(makeTransport(q, async (b) => { writes.push(b); }), { maxConcurrentRequests: 2 });
    server.register(1, async (payload) => { await slow; return { payload }; });
    server.register(2, async (payload) => ({ payload }));
    await q.write(await makeFrame({ type_id: 1, request_id: 1, response_to: 0, payload: "slow" }));
    await q.write(await makeFrame({ type_id: 2, request_id: 2, response_to: 0, payload: "fast" }));
    const serve = server.serve();
    await waitFor(() => writes.length === 1);
    expect(decodeEnvelope(writes[0]!).response_to).toBe(2);
    releaseSlow();
    await waitFor(() => writes.length === 2);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);
    expect(decodeEnvelope(writes[1]!).response_to).toBe(1);
  });

  test("returns 429 when the bounded request queue is full", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const server = new RpcServer(makeTransport(q, async (b) => { writes.push(b); }), { maxConcurrentRequests: 1, maxQueuedRequests: 1 });
    server.register(1, async (payload) => { await blocked; return { payload }; });
    await q.write(await makeFrame({ type_id: 1, request_id: 1, response_to: 0, payload: 1 }));
    await q.write(await makeFrame({ type_id: 1, request_id: 2, response_to: 0, payload: 2 }));
    await q.write(await makeFrame({ type_id: 1, request_id: 3, response_to: 0, payload: 3 }));
    const serve = server.serve();
    await waitFor(() => writes.some((frame) => decodeEnvelope(frame).error?.code === 429));
    expect(writes.map(decodeEnvelope).find((env) => env.error?.code === 429)).toMatchObject({ response_to: 3, error: { message: "server overloaded" } });
    release();
    await waitFor(() => writes.length === 3);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);
  });

  test("returns handler_not_found when handler is missing", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(makeTransport(q, async (b) => {
      writes.push(b);
    }));

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

  test("notification handler errors terminate the supervised serve loop", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(makeTransport(q, async (b) => {
      writes.push(b);
    }));
    server.register(1, async () => {
      throw new Error("boom");
    });
    const notify = await makeFrame({ type_id: 1, request_id: 0, response_to: 0, payload: { n: true } });
    await q.write(notify);

    const serve = server.serve();
    await expect(serve).rejects.toThrow(/boom/);
    expect(writes).toEqual([]);
  });

  test("request handler errors do not stop serve loop", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(makeTransport(q, async (b) => {
      writes.push(b);
    }));
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

  test("sanitizes invalid handler errors before writing a response", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(makeTransport(q, async (b) => { writes.push(b); }));
    const validASCII = "a".repeat(1_024);
    const validMultibyte = "é".repeat(512);
    const cases = [
      { typeId: 1, error: { code: 7, message: validASCII }, expected: { code: 7, message: validASCII } },
      { typeId: 2, error: { code: 7, message: validMultibyte }, expected: { code: 7, message: validMultibyte } },
      { typeId: 3, error: { code: 0 }, expected: { code: 500, message: "internal error" } },
      { typeId: 4, error: { code: 7, message: `${validASCII}a` }, expected: { code: 500, message: "internal error" } },
      { typeId: 5, error: { code: 7, message: `${validMultibyte}a` }, expected: { code: 500, message: "internal error" } },
      { typeId: 6, error: { code: 7, message: "\ud800" }, expected: { code: 500, message: "internal error" } },
      { typeId: 7, error: { code: 7, internal: "secret" }, expected: { code: 500, message: "internal error" } },
    ] as const;
    for (const item of cases) {
      server.register(item.typeId, async () => ({ payload: null, error: item.error as never }));
      await q.write(await makeFrame({ type_id: item.typeId, request_id: item.typeId, response_to: 0, payload: null }));
    }

    const serve = server.serve();
    await waitFor(() => writes.length === cases.length);
    q.close(new Error("eof"));
    await expect(serve).rejects.toThrow(/eof/);

    for (const [index, item] of cases.entries()) {
      expect(decodeEnvelope(writes[index]!).error, `type ${item.typeId}`).toEqual(item.expected);
    }
  });

  test("ignores response_to frames", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(makeTransport(q, async (b) => {
      writes.push(b);
    }));
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
    const server = new RpcServer(makeTransport(q, async () => {}));
    const ctrl = new AbortController();
    ctrl.abort(new Error("aborted"));
    await expect(server.serve(ctrl.signal)).rejects.toThrow(/aborted/);
  });

  test("abort interrupts an in-flight transport read and closes ownership", async () => {
    const q = new ByteQueue();
    const close = vi.fn((error: unknown) => q.close(error));
    const server = new RpcServer(makeTransport(q, async () => undefined, close));
    const ctrl = new AbortController();
    const serving = server.serve(ctrl.signal);
    await new Promise((resolve) => setTimeout(resolve, 0));
    ctrl.abort(new Error("in-flight abort"));
    await expect(Promise.race([
      serving,
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("serve remained pending")), 100)),
    ])).rejects.toThrow(/in-flight abort/);
    expect(close).toHaveBeenCalledTimes(1);
  });

  test("abort settles workers without waiting for permanent application handlers", async () => {
    for (const requestId of [1, 0]) {
      const q = new ByteQueue();
      let rejectHandler!: (error: unknown) => void;
      const blocked = new Promise<never>((_resolve, reject) => { rejectHandler = reject; });
      const close = vi.fn((error: unknown) => q.close(error));
      const server = new RpcServer(makeTransport(q, async () => undefined, close));
      server.register(1, async () => await blocked);
      await q.write(await makeFrame({ type_id: 1, request_id: requestId, response_to: 0, payload: null }));
      const ctrl = new AbortController();
      const serving = server.serve(ctrl.signal);
      await waitFor(() => q.reads() >= 2);
      ctrl.abort(new Error("handler abort"));
      await expect(Promise.race([
        serving,
        new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("serve remained pending")), 100)),
      ])).rejects.toThrow(/handler abort/);
      expect(close).toHaveBeenCalledTimes(1);

      rejectHandler(new Error("late handler rejection"));
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  });

  test("rejects oversized notifications and handler responses at the write boundary", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const close = vi.fn((error: unknown) => q.close(error));
    const server = new RpcServer(makeTransport(q, async (frame) => { writes.push(frame); }, close));
    const oversized = "x".repeat((1 << 20) + 1);
    await expect(server.notify(1, oversized)).rejects.toThrow(/frame too large/);
    expect(writes).toEqual([]);

    const q2 = new ByteQueue();
    const responseWrites: Uint8Array[] = [];
    const responseServer = new RpcServer(makeTransport(q2, async (frame) => { responseWrites.push(frame); }));
    responseServer.register(1, async () => ({ payload: oversized }));
    await q2.write(await makeFrame({ type_id: 1, request_id: 1, response_to: 0, payload: null }));
    await expect(responseServer.serve()).rejects.toThrow(/frame too large/);
    expect(responseWrites).toEqual([]);
  });

  test("write failures surface to caller", async () => {
    const q = new ByteQueue();
    const server = new RpcServer(makeTransport(q, async () => {
      throw new Error("write failed");
    }));
    server.register(1, async (payload) => ({ payload }));

    const req = await makeFrame({ type_id: 1, request_id: 2, response_to: 0, payload: { ok: true } });
    await q.write(req);
    await expect(server.serve()).rejects.toThrow(/write failed/);
  });

  test("server type IDs reject normalization aliases and accept max u32", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const server = new RpcServer(makeTransport(q, async (frame) => { writes.push(frame); }));
    const handler = vi.fn(async (payload) => ({ payload }));
    expect(() => server.register(-1, handler)).toThrow(/typeId/);
    expect(() => server.register(0, handler)).toThrow(/typeId/);
    expect(() => server.register(1.5, handler)).toThrow(/typeId/);
    expect(() => server.register(0x1_0000_0000, handler)).toThrow(/typeId/);
    server.register(0xffffffff, handler);
    await expect(server.notify(0xffff_ffff, null)).resolves.toBeUndefined();
    expect(decodeEnvelope(writes[0]!).type_id).toBe(0xffff_ffff);
    server.close();
  });

  test("notification queue overflow closes the RPC transport", async () => {
    const q = new ByteQueue();
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const close = vi.fn((error: unknown) => { q.close(error); });
    const server = new RpcServer(makeTransport(q, async () => {}, close), {
      maxConcurrentRequests: 1,
      maxQueuedNotifications: 1,
    });
    server.register(1, async () => { await blocked; return { payload: null }; });
    await q.write(await makeFrame({ type_id: 1, request_id: 0, response_to: 0, payload: 1 }));
    await q.write(await makeFrame({ type_id: 1, request_id: 0, response_to: 0, payload: 2 }));
    await q.write(await makeFrame({ type_id: 1, request_id: 0, response_to: 0, payload: 3 }));

    const serve = server.serve();
    const rejectedServe = expect(serve).rejects.toThrow(/notification queue exhausted/);
    await waitFor(() => close.mock.calls.length === 1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(close.mock.calls[0]?.[0]).toEqual(expect.objectContaining({ message: "rpc notification queue exhausted" }));
    release();
    await rejectedServe;
  });
});
