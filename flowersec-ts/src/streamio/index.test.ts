import { describe, expect, test } from "vitest";

import { AbortError } from "../utils/errors.js";
import { writeJsonFrame } from "../framing/jsonframe.js";
import { createByteReader, createJsonFrameChannel, openJsonFrameChannel, readExactly, readMaybe, readNBytes } from "./index.js";

class FakeStream {
  private readonly chunks: Array<Uint8Array | null> = [];
  private readonly waiters: Array<{ resolve: (b: Uint8Array | null) => void; reject: (e: unknown) => void }> = [];
  private err: Error | null = null;

  resetCalls: Error[] = [];
  writeCalls: Uint8Array[] = [];
  closeCalls = 0;

  push(b: Uint8Array): void {
    if (this.waiters.length > 0) {
      this.waiters.shift()!.resolve(b);
      return;
    }
    this.chunks.push(b);
  }

  end(): void {
    if (this.waiters.length > 0) {
      this.waiters.shift()!.resolve(null);
      return;
    }
    this.chunks.push(null);
  }

  read(): Promise<Uint8Array | null> {
    if (this.err != null) return Promise.reject(this.err);
    if (this.chunks.length > 0) return Promise.resolve(this.chunks.shift()!);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  reset(err: Error): void {
    this.resetCalls.push(err);
    this.err = err;
    const ws = this.waiters.splice(0, this.waiters.length);
    for (const w of ws) w.reject(err);
  }

  async write(b: Uint8Array): Promise<void> {
    this.writeCalls.push(b);
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
  }
}

describe("streamio", () => {
  test("readMaybe forwards chunks and returns null on EOF", async () => {
    const s = new FakeStream();
    s.push(new Uint8Array([1, 2]));
    s.end();

    await expect(readMaybe(s as any)).resolves.toEqual(new Uint8Array([1, 2]));
    await expect(readMaybe(s as any)).resolves.toBeNull();
  });

  test("createByteReader bridges YamuxStream.read() to ByteReader.readExactly()", async () => {
    const s = new FakeStream();
    s.push(new Uint8Array([1, 2]));
    s.push(new Uint8Array([3, 4, 5]));
    s.end();

    const r = createByteReader(s as any);
    await expect(r.readExactly(4)).resolves.toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  test("readNBytes reads exactly n bytes and reports progress", async () => {
    const s = new FakeStream();
    s.push(new Uint8Array([1, 2, 3]));
    s.push(new Uint8Array([4, 5]));
    s.end();

    const r = createByteReader(s as any);
    const progress: number[] = [];
    const out = await readNBytes(r, 5, { chunkSize: 2, onProgress: (n) => progress.push(n) });
    expect(out).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    expect(progress).toEqual([2, 4, 5]);
  });

  test("readExactly throws AbortError when signal is already aborted", async () => {
    const ac = new AbortController();
    ac.abort();

    const s = new FakeStream();
    const r = createByteReader(s as any);
    await expect(readExactly(r, 1, { signal: ac.signal })).rejects.toBeInstanceOf(AbortError);
  });

  test("createByteReader binds abort to stream.reset and unblocks pending reads", async () => {
    const ac = new AbortController();
    const s = new FakeStream();
    const r = createByteReader(s as any, { signal: ac.signal });

    const p = readNBytes(r, 1, { signal: ac.signal });
    const reason = new AbortError("aborted");
    ac.abort(reason);

    await expect(p).rejects.toBe(reason);
    expect(s.resetCalls.length).toBe(1);
  });

  test("createJsonFrameChannel reads and writes framed JSON values", async () => {
    const s = new FakeStream();
    const encoded: Uint8Array[] = [];
    await writeJsonFrame((b) => {
      encoded.push(b);
      return Promise.resolve();
    }, { ok: true, n: 3 });
    s.push(encoded[0]!);

    const channel = createJsonFrameChannel(s as any);
    await channel.writeFrame({ hello: "world" });
    await expect(channel.readFrame<{ ok: boolean; n: number }>()).resolves.toEqual({ ok: true, n: 3 });
    await channel.close();

    expect(s.writeCalls.length).toBe(1);
    expect(s.closeCalls).toBe(1);
  });

  test("openJsonFrameChannel opens the target kind and preserves the abort signal", async () => {
    const s = new FakeStream();
    const ac = new AbortController();
    const calls: Array<{ kind: string; signal?: AbortSignal }> = [];
    const client = {
      openStream: async (kind: string, opts?: Readonly<{ signal?: AbortSignal }>) => {
        calls.push({ kind, signal: opts?.signal });
        return s as any;
      },
    };

    const channel = await openJsonFrameChannel(client, "fs/read_file", { signal: ac.signal });

    expect(calls).toEqual([{ kind: "fs/read_file", signal: ac.signal }]);
    expect(channel.stream).toBe(s);
  });
});
