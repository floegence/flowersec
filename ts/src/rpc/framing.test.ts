import { describe, expect, test } from "vitest";
import { readJsonFrame, RpcFramingError, writeJsonFrame } from "./framing.js";

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
      const chunk = this.chunks[0];
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

describe("rpc framing", () => {
  test("writeJsonFrame emits a length-prefixed payload", async () => {
    const chunks: Uint8Array[] = [];
    await writeJsonFrame(async (b) => {
      chunks.push(b);
    }, { ok: true });
    expect(chunks.length).toBe(1);
    const out = chunks[0]!;
    const len = new DataView(out.buffer, out.byteOffset, out.byteLength).getUint32(0);
    const json = new TextDecoder().decode(out.subarray(4));
    expect(len).toBe(out.length - 4);
    expect(JSON.parse(json)).toEqual({ ok: true });
  });

  test("readJsonFrame rejects oversized frames", async () => {
    const q = new ByteQueue();
    const header = new Uint8Array([0, 0, 0, 5]);
    await q.write(header);
    await expect(readJsonFrame(q.readExactly.bind(q), 4)).rejects.toBeInstanceOf(RpcFramingError);
  });

  test("readJsonFrame rejects invalid JSON", async () => {
    const q = new ByteQueue();
    const payload = new TextEncoder().encode("not-json");
    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, payload.length);
    await q.write(header);
    await q.write(payload);
    await expect(readJsonFrame(q.readExactly.bind(q), 1024)).rejects.toBeInstanceOf(SyntaxError);
  });

  test("readJsonFrame surfaces read errors", async () => {
    const q = new ByteQueue();
    const header = new Uint8Array([0, 0, 0, 2]);
    await q.write(header);
    const p = readJsonFrame(q.readExactly.bind(q), 1024);
    q.close(new Error("eof"));
    await expect(p).rejects.toThrow(/eof/);
  });
});
