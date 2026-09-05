import { describe, expect, test } from "vitest";
import type { RpcEnvelope } from "./wire.js";
import { writeJsonFrame } from "../framing/jsonframe.js";
import { readU32be } from "../utils/bin.js";
import { RpcClient } from "./client.js";

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

function framePayload(payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(4 + payload.length);
  new DataView(frame.buffer).setUint32(0, payload.length);
  frame.set(payload, 4);
  return frame;
}

describe("RpcClient extra behavior", () => {
  test("owns response rejection while a write is still blocked", async () => {
    const q = new ByteQueue();
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const client = new RpcClient(q.readExactly.bind(q), async () => blocked);
    const result = client.call(1, null).catch((error: unknown) => error);
    q.close(new Error("peer disconnected"));
    expect(await result).toBeInstanceOf(Error);
    await new Promise((resolve) => setTimeout(resolve, 0));
    release();
    client.close();
  });

  test("cancels before sending and while queued without writing a canceled frame", async () => {
    const q = new ByteQueue();
    let writes = 0;
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const client = new RpcClient(q.readExactly.bind(q), async () => { writes += 1; await blocked; });
    await expect(client.call(1, null, AbortSignal.abort())).rejects.toThrow();
    expect(writes).toBe(0);
    const first = client.notify(1, null);
    await Promise.resolve();
    const controller = new AbortController();
    const queued = client.call(2, null, controller.signal);
    controller.abort();
    await expect(queued).rejects.toThrow();
    release();
    await first;
    expect(writes).toBe(1);
    client.close();
    q.close(new Error("closed"));
  });

  test("aborts the transport signal during a blocked write", async () => {
    const q = new ByteQueue();
    let started!: () => void;
    const writing = new Promise<void>((resolve) => { started = resolve; });
    let transportAborted = false;
    const client = new RpcClient(q.readExactly.bind(q), async (_frame, signal) => {
      started();
      await new Promise<void>((_resolve, reject) => signal!.addEventListener("abort", () => {
        transportAborted = true;
        reject(signal!.reason);
      }, { once: true }));
    });
    const controller = new AbortController();
    const result = client.call(1, null, controller.signal);
    await writing;
    controller.abort();
    await expect(result).rejects.toThrow();
    expect(transportAborted).toBe(true);
    client.close();
    q.close(new Error("closed"));
  });

  test("rejects invalid public type IDs without wire normalization", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => { writes.push(frame); });
    for (const typeId of [-1, 0, 1.5, 0x1_0000_0000, Number.NaN]) {
      await expect(client.call(typeId, null), `call ${typeId}`).rejects.toThrow(/typeId/);
      await expect(client.notify(typeId, null), `notify ${typeId}`).rejects.toThrow(/typeId/);
      expect(() => client.onNotify(typeId, () => undefined), `onNotify ${typeId}`).toThrow(/typeId/);
    }
    expect(() => client.onNotify(0xffff_ffff, () => undefined)).not.toThrow();
    expect(writes).toEqual([]);
    client.close();
    q.close(new Error("eof"));
  });

  test("accepts the maximum u32 type ID at every client entry point", async () => {
    const q = new ByteQueue();
    const envelopes: RpcEnvelope[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => {
      const envelope = decodeEnvelope(frame);
      envelopes.push(envelope);
      if (envelope.request_id !== 0) {
        await writeJsonFrame(q.write.bind(q), {
          type_id: envelope.type_id,
          request_id: 0,
          response_to: envelope.request_id,
          payload: "ok",
        });
      }
    });
    const unsubscribe = client.onNotify(0xffff_ffff, () => undefined);
    await expect(client.notify(0xffff_ffff, "notification")).resolves.toBeUndefined();
    await expect(client.call(0xffff_ffff, "request")).resolves.toEqual({ payload: "ok" });
    expect(envelopes.map((envelope) => envelope.type_id)).toEqual([0xffff_ffff, 0xffff_ffff]);
    unsubscribe();
    client.close();
    q.close(new Error("eof"));
  });

  test("rejects oversized request and notification frames before writing", async () => {
    const q = new ByteQueue();
    const writes: Uint8Array[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => { writes.push(frame); });
    const oversized = "x".repeat((1 << 20) + 1);
    await expect(client.call(1, oversized)).rejects.toThrow(/frame too large/);
    await expect(client.notify(1, oversized)).rejects.toThrow(/frame too large/);
    expect(writes).toEqual([]);
    client.close();
    q.close(new Error("eof"));
  });

  test("accepts request and notification envelopes at the exact RPC frame boundary", async () => {
    const q = new ByteQueue();
    const frameLengths: number[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => {
      frameLengths.push(readU32be(frame, 0));
      const request = decodeEnvelope(frame);
      if (request.request_id !== 0) {
        await writeJsonFrame(q.write.bind(q), {
          type_id: request.type_id,
          request_id: 0,
          response_to: request.request_id,
          payload: null,
        });
      }
    });
    const maximum = 1 << 20;
    const requestOverhead = new TextEncoder().encode(JSON.stringify({
      type_id: 1, request_id: 1, response_to: 0, payload: "",
    })).length;
    const notificationOverhead = new TextEncoder().encode(JSON.stringify({
      type_id: 1, request_id: 0, response_to: 0, payload: "",
    })).length;
    await expect(client.call(1, "x".repeat(maximum - requestOverhead))).resolves.toEqual({ payload: null });
    await expect(client.notify(1, "x".repeat(maximum - notificationOverhead))).resolves.toBeUndefined();
    expect(frameLengths).toEqual([maximum, maximum]);
    client.close();
    q.close(new Error("eof"));
  });

  test("abort while waiting cancels the call", async () => {
    const q = new ByteQueue();
    const client = new RpcClient(q.readExactly.bind(q), async () => {});

    const ctrl = new AbortController();
    const p = client.call(1, { ok: true }, ctrl.signal);
    ctrl.abort(new Error("aborted"));

    await expect(p).rejects.toThrow(/aborted/);
    client.close();
    q.close(new Error("eof"));

  });

  test("transport write errors are surfaced", async () => {
    const q = new ByteQueue();
    const client = new RpcClient(q.readExactly.bind(q), async () => {
      throw new Error("write failed");
    });

    await expect(client.call(1, { ok: true })).rejects.toThrow(/write failed/);
    client.close();
    q.close(new Error("eof"));
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

  test("readLoop reports unexpected termination once", async () => {
    const q = new ByteQueue();
    const terminal: Error[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async () => {}, {
      onTerminal: (error) => terminal.push(error),
    });

    q.close(new Error("rpc transport closed"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    q.close(new Error("second close"));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(terminal).toHaveLength(1);
    expect(terminal[0]?.message).toContain("rpc transport closed");
    client.close();
  });

  test("explicit close does not report unexpected termination", async () => {
    const q = new ByteQueue();
    const terminal: Error[] = [];
    const client = new RpcClient(q.readExactly.bind(q), async () => {}, {
      onTerminal: (error) => terminal.push(error),
    });

    client.close();
    q.close(new Error("closed after client close"));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(terminal).toEqual([]);
  });

  test("returns rpc_error and handler_not_found responses", async () => {
    const q = new ByteQueue();
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
    });

    await expect(client.call(2, { ok: false })).resolves.toMatchObject({ error: { code: 500 } });
    await expect(client.call(3, { ok: false })).resolves.toMatchObject({ error: { code: 404 } });

    client.close();
    q.close(new Error("eof"));
  });

  test("enforces application error invariants at the receive boundary", async () => {
    const validASCII = "a".repeat(1_024);
    const validMultibyte = "é".repeat(512);
    const cases = [
      { name: "ASCII 1024 bytes", error: { code: 7, message: validASCII }, valid: true },
      { name: "multibyte UTF-8 1024 bytes", error: { code: 7, message: validMultibyte }, valid: true },
      { name: "zero code", error: { code: 0 }, valid: false },
      { name: "ASCII 1025 bytes", error: { code: 7, message: `${validASCII}a` }, valid: false },
      { name: "multibyte UTF-8 1025 bytes", error: { code: 7, message: `${validMultibyte}a` }, valid: false },
      { name: "lone surrogate", error: { code: 7, message: "\ud800" }, valid: false },
      { name: "extra error field", error: { code: 7, internal: "secret" }, valid: false },
    ] as const;

    for (const item of cases) {
      const q = new ByteQueue();
      const client = new RpcClient(q.readExactly.bind(q), async (frame) => {
        const request = decodeEnvelope(frame);
        await writeJsonFrame(q.write.bind(q), {
          type_id: request.type_id,
          request_id: 0,
          response_to: request.request_id,
          payload: null,
          error: item.error as never,
        });
      });
      const call = client.call(1, null);
      if (item.valid) {
        await expect(call, item.name).resolves.toEqual({ payload: null, error: item.error });
      } else {
        await expect(call, item.name).rejects.toThrow();
      }
      client.close();
      q.close(new Error("eof"));
    }

    const q = new ByteQueue();
    const client = new RpcClient(q.readExactly.bind(q), async (frame) => {
      const request = decodeEnvelope(frame);
      const prefix = new TextEncoder().encode(
        `{"type_id":1,"request_id":0,"response_to":${request.request_id},"payload":null,"error":{"code":7,"message":"`,
      );
      const suffix = new TextEncoder().encode('"}}');
      const payload = new Uint8Array(prefix.length + 1 + suffix.length);
      payload.set(prefix);
      payload[prefix.length] = 0xff;
      payload.set(suffix, prefix.length + 1);
      await q.write(framePayload(payload));
    });
    await expect(client.call(1, null), "malformed UTF-8").rejects.toThrow();
    client.close();
    q.close(new Error("eof"));
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
