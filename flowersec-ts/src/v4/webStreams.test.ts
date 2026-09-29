import { describe, expect, it } from "vitest";
import { asWebStreams, V4WebStreamError } from "./webStreams.js";
import type { V4StreamOwner } from "./public.js";
import type { V4ReadResult, V4CloseResult, V4WriteProgress } from "../generated/transportV4APIResults.js";
import { registerStreamAdapter, type StreamAdapterOwner } from "./runtime/streamAdapter.js";

const complete = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n } as const);
const terminal: V4CloseResult = { direction: "c2s", send_drained: true, read_terminal: "eof", cleanup_status: complete };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function progress(n: number, requested: number, terminal_reason: V4WriteProgress["terminal_reason"] = "complete"): V4WriteProgress {
  return { requested_bytes: BigInt(requested), accepted_bytes: BigInt(n), phase: "terminal", terminal_reason, cleanup_status: complete };
}
function fixture(overrides: Partial<StreamAdapterOwner> = {}) {
  const stream = {} as V4StreamOwner, incoming = deferred<V4ReadResult>(), drain = deferred<V4CloseResult>();
  const counts = { reads: 0, closeWrite: 0, finish: 0, abortRead: 0, abortWrite: 0, reset: 0, release: 0 };
  const seen: number[] = [];
  const owner: StreamAdapterOwner = {
    readBytes: 64, check() {}, cleanupStatus: () => complete, invalidateWith() {}, sendStoppedWith() {}, cleanupWith() {}, rollback() {},
    read: () => { counts.reads++; return incoming.promise; },
    write: async bytes => { const n = Math.min(2, bytes.length); seen.push(...bytes.subarray(0, n)); return progress(n, bytes.length); },
    closeWrite: async () => { counts.closeWrite++; return terminal; },
    finish: () => { counts.finish++; return drain.promise; },
    reset: async () => { counts.reset++; return terminal; },
    abortRead: async () => { counts.abortRead++; return terminal; },
    abortWrite: async () => { counts.abortWrite++; return terminal; },
    release: () => { counts.release++; }, ...overrides,
  };
  registerStreamAdapter(stream, () => owner);
  return { stream, incoming, drain, counts, seen };
}
function read(bytes = new Uint8Array()): V4ReadResult {
  return { data: bytes, progress: { offset: 0n, filled: BigInt(bytes.length) }, wait_status: "ready", stream_status: "eof" };
}

describe("v4 standard Web Streams ownership", () => {
  it("uses actual native streams, partial writes and authenticated close without read-ahead", async () => {
    const f = fixture(), pair = asWebStreams(f.stream);
    expect(pair.readable).toBeInstanceOf(ReadableStream); expect(pair.writable).toBeInstanceOf(WritableStream);
    await Promise.resolve(); expect(f.counts.reads).toBe(0);
    const writer = pair.writable.getWriter(); await writer.write(new Uint8Array([1, 2, 3, 4, 5]));
    expect(f.seen).toEqual([1, 2, 3, 4, 5]);
    let closed = false; const closing = writer.close().then(() => { closed = true; });
    await expect.poll(() => f.counts.finish).toBe(1); expect(closed).toBe(false);
    f.drain.resolve(terminal); await closing; expect(f.counts.abortRead).toBe(0);
    const chunks: number[] = [], reading = pair.readable.pipeTo(new WritableStream({ write(bytes) { chunks.push(...bytes); } }));
    f.incoming.resolve(read(new Uint8Array([6, 7]))); await reading;
    expect(chunks).toEqual([6, 7]); await expect.poll(() => f.counts.release).toBe(1);
    expect(f.counts.reset).toBe(0); expect(f.counts.abortWrite).toBe(0);
  });
  it("bounds ignored-backpressure writes and promptly cancels the active accepted prefix", async () => {
    const entered = deferred<void>();
    const f = fixture({ write: (bytes, options) => new Promise(resolve => {
      entered.resolve(); options!.signal!.addEventListener("abort", () => resolve(progress(2, bytes.length, "canceled")), { once: true });
    }) });
    const pair = asWebStreams(f.stream, { maxPendingWrites: 2, maxWriteChunkBytes: 8, maxWriteBackingBytes: 8, maxQueuedWriteBytes: 16 });
    const writer = pair.writable.getWriter(); void writer.closed.catch(() => undefined);
    const first = writer.write(new Uint8Array(8)).catch(error => error as V4WebStreamError);
    await entered.promise;
    const second = writer.write(new Uint8Array(8)).catch(error => error);
    const overflow = writer.write(new Uint8Array(1)).catch(error => error);
    expect(await first).toMatchObject({ code: "write_capacity", progress: { requested_bytes: 8n, accepted_bytes: 2n } });
    expect(await second).toBeInstanceOf(V4WebStreamError); expect(await overflow).toBeInstanceOf(V4WebStreamError);
    expect(f.counts.abortWrite).toBe(1); expect(f.counts.abortRead).toBe(0);
    await pair.readable.cancel(); await expect.poll(() => f.counts.release).toBe(1);
  });
  it("handles native writer abort before a backpressured sink can complete", async () => {
    const entered = deferred<void>();
    const f = fixture({ write: (bytes, options) => new Promise(resolve => {
      entered.resolve(); options!.signal!.addEventListener("abort", () => resolve(progress(1, bytes.length, "canceled")), { once: true });
    }) });
    const pair = asWebStreams(f.stream), writer = pair.writable.getWriter(); void writer.closed.catch(() => undefined);
    const writing = writer.write(new Uint8Array(5)).catch(error => error);
    await entered.promise;
    const reason = Object.create(null) as object;
    Object.defineProperty(reason, "message", { get() { throw new Error("must not inspect reason"); } });
    await writer.abort(reason);
    expect(await writing).toMatchObject({ code: "aborted", progress: { requested_bytes: 5n, accepted_bytes: 1n } });
    expect(f.counts.abortWrite).toBe(1); expect(f.counts.abortRead).toBe(0);
    await pair.readable.cancel(); await expect.poll(() => f.counts.release).toBe(1);
  });
  it("charges a complete retained backing and rejects an invalid size even without sink.abort", async () => {
    const f = fixture(), pair = asWebStreams(f.stream, { maxWriteChunkBytes: 4, maxWriteBackingBytes: 4, maxQueuedWriteBytes: 8 });
    const writer = pair.writable.getWriter(); void writer.closed.catch(() => undefined);
    const bytes = new Uint8Array(new ArrayBuffer(32), 0, 1);
    Object.defineProperty(bytes, "buffer", { get() { throw new Error("must not inspect getter"); } });
    await expect(writer.write(bytes)).rejects.toMatchObject({ code: "write_capacity" });
    expect(f.seen).toEqual([]); expect(f.counts.abortWrite).toBe(1);
    await pair.readable.cancel(); await expect.poll(() => f.counts.release).toBe(1);
  });
  it("settles a reentrant cancel during the one native enqueue without republishing bytes", async () => {
    const f = fixture(), pair = asWebStreams(f.stream), reader = pair.readable.getReader();
    const pending = reader.read(); let intercepted = false, canceling: Promise<void> | undefined;
    const previous = Object.getOwnPropertyDescriptor(Object.prototype, "then");
    try {
      Object.defineProperty(Object.prototype, "then", { configurable: true, get() {
        if (!intercepted && Object.hasOwn(this, "done") && Object.hasOwn(this, "value") && this.value instanceof Uint8Array) {
          intercepted = true; this.value[0] = 99; canceling = reader.cancel();
        }
        return undefined;
      } });
      f.incoming.resolve(read(new Uint8Array([1, 2])));
      const result = await pending;
      expect(result.value).toEqual(new Uint8Array([99, 2])); expect(intercepted).toBe(true);
    } finally {
      if (previous === undefined) Reflect.deleteProperty(Object.prototype, "then"); else Object.defineProperty(Object.prototype, "then", previous);
    }
    await canceling; await pair.writable.abort();
    await expect.poll(() => f.counts.release).toBe(1); expect(f.counts.reads).toBe(1); expect(f.counts.reset).toBe(0);
  });
});
