import { describe, expect, it } from "vitest";
import { asNodeDuplex, V4NodeDuplexError } from "./streamDuplexV4.js";
import type { V4StreamOwner } from "../v4/public.js";
import type { V4CloseResult, V4ReadResult, V4WriteProgress } from "../generated/transportV4APIResults.js";
import { registerStreamAdapter, type StreamAdapterOwner } from "../v4/runtime/streamAdapter.js";

const complete = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n } as const);
const profile = Object.freeze({ maxChunkBytes: 65536, maxBackingBytes: 65536, maxPendingWrites: 4, maxQueuedBackingBytes: 262144 });
const closed: V4CloseResult = { direction: "c2s", send_drained: true, read_terminal: "eof", cleanup_status: complete };
const readEOF: V4ReadResult = { data: new Uint8Array(), progress: { offset: 0n, filled: 0n }, wait_status: "ready", stream_status: "eof" };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function progress(n: number, requested = n, terminal_reason: V4WriteProgress["terminal_reason"] = "complete"): V4WriteProgress {
  return { requested_bytes: BigInt(requested), accepted_bytes: BigInt(n), phase: "terminal", terminal_reason, cleanup_status: complete };
}
function fixture(overrides: Partial<StreamAdapterOwner> = {}) {
  const stream = {} as V4StreamOwner;
  const counts = { closeWrite: 0, finish: 0, reset: 0, release: 0 };
  const input = deferred<V4ReadResult>(), finish = deferred<V4CloseResult>();
  const seen: number[] = [];
  const owner: StreamAdapterOwner = {
    readBytes: 65536, check() {}, cleanupStatus: () => complete, invalidateWith() {}, sendStoppedWith() {}, cleanupWith() {}, rollback() {},
    async read(options) {
      if (options?.signal?.aborted) return { ...readEOF, stream_status: "aborted" };
      return new Promise(resolve => {
        const canceled = (): void => { resolve({ ...readEOF, stream_status: "aborted" }); };
        options?.signal?.addEventListener("abort", canceled, { once: true });
        void input.promise.then(value => { options?.signal?.removeEventListener("abort", canceled); resolve(value); });
      });
    },
    write: async bytes => { const part = bytes.subarray(0, 2); seen.push(...part); return progress(part.length, bytes.length); },
    closeWrite: async () => { counts.closeWrite++; return { ...closed, send_drained: false }; },
    finish: () => { counts.finish++; return finish.promise; },
    reset: async () => { counts.reset++; return { ...closed, send_drained: false, read_terminal: "abandoned" }; },
    abortRead: async () => closed, abortWrite: async () => closed,
    release: () => { counts.release++; }, ...overrides,
  };
  registerStreamAdapter(stream, () => owner);
  return { stream, owner, counts, input, finish, seen };
}
const checkpoint = (): Promise<void> => new Promise(resolve => setImmediate(resolve));

describe("native v4 Node Duplex lifecycle", () => {
  it.each(["send-first", "read-first"])("authenticates Finish before native success and normally cleans up %s", async order => {
    const f = fixture(), duplex = asNodeDuplex(f.stream, { producer: profile });
    const failures: Error[] = []; duplex.on("error", error => failures.push(error)); duplex.resume();
    let finalCallback = 0;
    duplex.end(new Uint8Array([1, 2, 3, 4, 5]), () => { finalCallback++; });
    await checkpoint(); expect(f.counts.closeWrite).toBe(1); expect(f.counts.finish).toBe(1);
    expect(f.seen).toEqual([1, 2, 3, 4, 5]); expect(finalCallback).toBe(0); expect(duplex.writableFinished).toBe(false);
    if (order === "read-first") { f.input.resolve(readEOF); await checkpoint(); expect(duplex.destroyed).toBe(false); }
    f.finish.resolve(closed); await checkpoint();
    expect(finalCallback).toBe(1);
    if (order === "send-first") { expect(duplex.destroyed).toBe(false); f.input.resolve(readEOF); }
    expect((await duplex.waitCleanup()).status).toBe("complete");
    expect(f.counts.reset).toBe(0); expect(f.counts.release).toBe(1); expect(failures).toEqual([]);
  });
  it("treats caller destroy(null) in a preceding end listener as abort", async () => {
    const f = fixture(), duplex = asNodeDuplex(f.stream, { producer: profile });
    const failures: Error[] = []; duplex.on("error", error => failures.push(error));
    duplex.prependOnceListener("end", () => duplex.destroy()); duplex.resume();
    duplex.end(); f.finish.resolve(closed); await checkpoint(); f.input.resolve(readEOF);
    expect((await duplex.waitCleanup()).status).toBe("complete");
    expect(f.counts.reset).toBe(1); expect(failures[0]).toMatchObject({ code: "aborted" });
  });
  it("retains partial acceptance on an abort and never lets late Finish turn it into success", async () => {
    const writing = deferred<V4WriteProgress>();
    const f = fixture({ write: () => writing.promise });
    const abort = new AbortController(), duplex = asNodeDuplex(f.stream, { producer: profile, signal: abort.signal });
    duplex.on("error", () => undefined);
    const written = new Promise<Error | null | undefined>(resolve => duplex.write(new Uint8Array(9), resolve));
    abort.abort(); writing.resolve(progress(3, 9, "canceled"));
    expect(await written).toMatchObject({ code: "aborted", progress: { requested_bytes: 9n, accepted_bytes: 3n } });
    expect((await duplex.waitCleanup()).status).toBe("complete"); expect(f.counts.reset).toBe(1);
    const g = fixture(), native = asNodeDuplex(g.stream, { producer: profile });
    native.on("error", () => undefined);
    const final = new Promise<Error | null | undefined>(resolve => native.end(resolve));
    await checkpoint(); native.destroy(); g.finish.resolve(closed);
    expect(await final).toBeInstanceOf(V4NodeDuplexError);
    expect((await native.waitCleanup()).status).toBe("complete"); expect(native.writableFinished).toBe(false);
  });
  it("bounds destroy waiting while retaining actual native I/O tails", async () => {
    const writing = deferred<V4WriteProgress>(), f = fixture({ write: () => writing.promise });
    const duplex = asNodeDuplex(f.stream, { producer: profile, cleanupTimeoutMS: 10 });
    duplex.on("error", () => undefined); duplex.write(new Uint8Array(8), () => undefined); duplex.destroy();
    expect((await duplex.waitCleanup()).status).toBe("cleanup_incomplete"); expect(f.counts.release).toBe(0);
    writing.resolve(progress(2, 8, "canceled"));
    await checkpoint(); await checkpoint();
    expect(duplex.cleanupStatus().status).toBe("complete"); expect(f.counts.release).toBe(1);
  });
  it("validates full backing rather than a tiny view or caller getters", async () => {
    const f = fixture(), duplex = asNodeDuplex(f.stream, { producer: { maxChunkBytes: 4, maxBackingBytes: 4, maxPendingWrites: 1, maxQueuedBackingBytes: 4 } });
    duplex.on("error", () => undefined);
    const chunk = Buffer.alloc(32).subarray(0, 1);
    Object.defineProperty(chunk, "buffer", { get() { throw new Error("must not inspect user getter"); } });
    expect(await new Promise(resolve => duplex.write(chunk, resolve))).toMatchObject({ code: "producer_profile" });
    expect((await duplex.waitCleanup()).status).toBe("complete"); expect(f.seen).toEqual([]); expect(f.counts.reset).toBe(1);
  });
});
