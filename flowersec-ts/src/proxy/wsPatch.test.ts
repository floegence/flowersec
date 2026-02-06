import { describe, expect, it } from "vitest";

import { installWebSocketPatch } from "./wsPatch.js";

class FakeYamuxStream {
  readonly writes: Uint8Array[] = [];

  async write(b: Uint8Array): Promise<void> {
    this.writes.push(b);
  }

  async read(): Promise<Uint8Array | null> {
    // Keep the read loop pending long enough so tests can trigger send().
    await new Promise((r) => setTimeout(r, 10));
    return null;
  }

  async close(): Promise<void> {}

  reset(_err: Error): void {}
}

describe("installWebSocketPatch", () => {
  it("proxies same host/port ws URLs by default (ws<->http scheme mapping)", async () => {
    const oldWS = (globalThis as any).WebSocket;
    const oldLoc = (globalThis as any).location;

    class OriginalWebSocket {
      readonly kind = "original";
      constructor(public readonly url: string, public readonly protocols?: string | string[]) {}
    }

    const calls: string[] = [];
    const runtime = {
      cookieJar: null as any,
      limits: { maxJsonFrameBytes: 1, maxChunkBytes: 1, maxBodyBytes: 1, maxWsFrameBytes: 1024 },
      dispose: () => {},
      openWebSocketStream: async (path: string) => {
        calls.push(path);
        return { stream: new FakeYamuxStream() as any, protocol: "" };
      }
    };

    (globalThis as any).WebSocket = OriginalWebSocket;
    (globalThis as any).location = {
      href: "http://127.0.0.1:5173/examples/ts/proxy-sandbox/app/",
      protocol: "http:",
      hostname: "127.0.0.1",
      port: "5173",
      origin: "http://127.0.0.1:5173"
    };

    try {
      const { uninstall } = installWebSocketPatch({ runtime });

      const a = new (globalThis as any).WebSocket("ws://example.com/ws");
      expect(a).toBeInstanceOf(OriginalWebSocket);
      expect((a as any).kind).toBe("original");
      expect(calls.length).toBe(0);

      const b = new (globalThis as any).WebSocket("ws://127.0.0.1:5173/ws");
      expect(b).not.toBeInstanceOf(OriginalWebSocket);

      const c = new (globalThis as any).WebSocket("/ws");
      expect(c).not.toBeInstanceOf(OriginalWebSocket);

      // Allow init() to run.
      await new Promise((r) => setTimeout(r, 0));
      expect(calls).toEqual(["/ws", "/ws"]);

      uninstall();
      const d = new (globalThis as any).WebSocket("ws://127.0.0.1:5173/ws");
      expect(d).toBeInstanceOf(OriginalWebSocket);
    } finally {
      (globalThis as any).WebSocket = oldWS;
      (globalThis as any).location = oldLoc;
    }
  });

  it("enforces maxWsFrameBytes (0 uses runtime limit; negative rejects)", async () => {
    const oldWS = (globalThis as any).WebSocket;
    const oldLoc = (globalThis as any).location;

    class OriginalWebSocket {
      constructor(_url: string, _protocols?: string | string[]) {}
    }

    const runtime = {
      cookieJar: null as any,
      limits: { maxJsonFrameBytes: 1, maxChunkBytes: 1, maxBodyBytes: 1, maxWsFrameBytes: 8 },
      dispose: () => {},
      openWebSocketStream: async (_path: string, _opts?: any) => ({ stream: new FakeYamuxStream() as any, protocol: "" })
    };

    (globalThis as any).WebSocket = OriginalWebSocket;
    (globalThis as any).location = {
      href: "http://127.0.0.1:5173/",
      protocol: "http:",
      hostname: "127.0.0.1",
      port: "5173",
      origin: "http://127.0.0.1:5173"
    };

    try {
      expect(() => installWebSocketPatch({ runtime, maxWsFrameBytes: -1 })).toThrow(/maxWsFrameBytes/);

      installWebSocketPatch({ runtime, maxWsFrameBytes: 0 });
      const ws = new (globalThis as any).WebSocket("/ws");

      let closedReason = "";
      (ws as any).onopen = () => {
        // 9 bytes > runtime max (8).
        (ws as any).send("123456789");
      };
      (ws as any).onclose = (ev: any) => {
        closedReason = String(ev?.reason ?? "");
      };

      for (let i = 0; i < 100 && closedReason === ""; i++) {
        await new Promise((r) => setTimeout(r, 1));
      }
      expect(closedReason).toContain("ws payload too large");
    } finally {
      (globalThis as any).WebSocket = oldWS;
      (globalThis as any).location = oldLoc;
    }
  });

  it("does not corrupt framing when a ping arrives while a send write is in-flight", async () => {
    const oldWS = (globalThis as any).WebSocket;
    const oldLoc = (globalThis as any).location;

    class OriginalWebSocket {
      constructor(_url: string, _protocols?: string | string[]) {}
    }

    const encodeFrame = (op: number, payload: Uint8Array) => {
      const out = new Uint8Array(5 + payload.length);
      out[0] = op & 0xff;
      // u32be length (big-endian).
      out[1] = (payload.length >>> 24) & 0xff;
      out[2] = (payload.length >>> 16) & 0xff;
      out[3] = (payload.length >>> 8) & 0xff;
      out[4] = payload.length & 0xff;
      out.set(payload, 5);
      return out;
    };

    const readU32be = (b: Uint8Array, off: number) =>
      (((b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!) >>> 0);

    const parseFrames = (chunks: readonly Uint8Array[]) => {
      const total = chunks.reduce((n, c) => n + c.length, 0);
      const buf = new Uint8Array(total);
      let w = 0;
      for (const c of chunks) {
        buf.set(c, w);
        w += c.length;
      }
      const frames: Array<{ op: number; payload: Uint8Array }> = [];
      let off = 0;
      while (off < buf.length) {
        if (buf.length - off < 5) throw new Error("truncated ws frame header");
        const op = buf[off]!;
        const n = readU32be(buf, off + 1);
        off += 5;
        if (buf.length - off < n) throw new Error("truncated ws frame payload");
        frames.push({ op, payload: buf.subarray(off, off + n) });
        off += n;
      }
      return frames;
    };

    class InterleavingYamuxStream {
      readonly writes: Uint8Array[] = [];
      writeCalls = 0;

      private firstChunkWrittenResolve: (() => void) | null = null;
      readonly firstChunkWritten = new Promise<void>((resolve) => (this.firstChunkWrittenResolve = resolve));

      private releaseFirstWriteResolve: (() => void) | null = null;
      private released = false;

      private readCount = 0;

      // Splits writes into two chunks and blocks the first write after the first chunk.
      async write(b: Uint8Array): Promise<void> {
        const callIndex = this.writeCalls++;
        const splitAt = Math.min(2, b.length);
        this.writes.push(b.subarray(0, splitAt));
        if (callIndex === 0) {
          this.firstChunkWrittenResolve?.();
          if (!this.released) {
            await new Promise<void>((resolve) => (this.releaseFirstWriteResolve = resolve));
          }
        }
        // Allow other tasks (readLoop / send) to run and attempt concurrent writes.
        await Promise.resolve();
        if (splitAt < b.length) this.writes.push(b.subarray(splitAt));
      }

      releaseFirstWrite(): void {
        this.released = true;
        this.releaseFirstWriteResolve?.();
      }

      async read(): Promise<Uint8Array | null> {
        // Deliver a ping frame only after the first write chunk has hit the wire.
        if (this.readCount === 0) {
          this.readCount++;
          await this.firstChunkWritten;
          return encodeFrame(9, new Uint8Array([1, 2, 3, 4]));
        }
        // End the stream after a short delay.
        await new Promise((r) => setTimeout(r, 10));
        return null;
      }

      async close(): Promise<void> {}
      reset(_err: Error): void {}
    }

    const stream = new InterleavingYamuxStream();
    const runtime = {
      cookieJar: null as any,
      limits: { maxJsonFrameBytes: 1, maxChunkBytes: 1, maxBodyBytes: 1, maxWsFrameBytes: 1024 },
      dispose: () => {},
      openWebSocketStream: async (_path: string, _opts?: any) => ({ stream: stream as any, protocol: "" })
    };

    (globalThis as any).WebSocket = OriginalWebSocket;
    (globalThis as any).location = {
      href: "http://127.0.0.1:5173/",
      protocol: "http:",
      hostname: "127.0.0.1",
      port: "5173",
      origin: "http://127.0.0.1:5173"
    };

    try {
      installWebSocketPatch({ runtime });

      const ws = new (globalThis as any).WebSocket("/ws");
      (ws as any).onopen = () => {
        (ws as any).send("hello");
      };

      // Wait until the first write is in-flight (blocked mid-header).
      await stream.firstChunkWritten;

      // If pong write is not serialized, it can start now (while first write is blocked) and corrupt framing.
      const start = Date.now();
      while (stream.writeCalls < 2 && Date.now() - start < 50) {
        await new Promise((r) => setTimeout(r, 1));
      }
      stream.releaseFirstWrite();

      // Allow queued writes to flush.
      await new Promise((r) => setTimeout(r, 20));

      const frames = parseFrames(stream.writes);
      const textFrames = frames.filter((f) => f.op === 1).map((f) => new TextDecoder().decode(f.payload));
      expect(textFrames).toContain("hello");

      const pongPayloads = frames.filter((f) => f.op === 10).map((f) => Array.from(f.payload));
      expect(pongPayloads).toContainEqual([1, 2, 3, 4]);
    } finally {
      (globalThis as any).WebSocket = oldWS;
      (globalThis as any).location = oldLoc;
    }
  });
});
