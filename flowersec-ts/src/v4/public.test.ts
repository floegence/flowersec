import { describe, expect, it, vi } from "vitest";
import { promiseHooks } from "node:v8";
import {
  V4ConnectionMaterial, V4OperationHandle, V4ReaderCursor, V4Session,
  V4TransportEnvironment, V4WriteOperation,
} from "./public.js";
import type {
  V4CursorReadOwner, V4EnvironmentOwner, V4MaterialOwner, V4ReaderSource,
  V4ReadState, V4SessionOwner, V4WriteRequestOwner,
} from "./public.js";
import type { V4CleanupStatus, V4WriteProgress } from "../generated/transportV4APIResults.js";

const encode = (value: string) => new TextEncoder().encode(value);
const decode = (value: Uint8Array) => new TextDecoder().decode(value);
const pendingCleanup: V4CleanupStatus = { status: "pending", core_cleanup: "pending", pending_callbacks: 1n };
const completeCleanup: V4CleanupStatus = { status: "complete", core_cleanup: "complete", pending_callbacks: 0n };
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function settle() { for (let i = 0; i < 12; i++) await Promise.resolve(); }

// A deterministic queue owner, not a transport. These tests exercise the public
// cursor's handoff while retaining source suffixes and the exclusive direction.
class QueueSource implements V4ReaderSource {
  chunks: Uint8Array[] = [];
  offset = 0n;
  ended = false;
  acquired = false;
  reads = 0;
  released = 0;
  denied = false;
  completion: ReturnType<typeof deferred<void>> | undefined;
  #wakeup: (() => void) | undefined;

  constructor(chunks: string[] = [], ended = false, offset = 0n) {
    this.chunks = chunks.map(encode); this.ended = ended; this.offset = offset;
  }
  feed(value: string): void { this.chunks.push(encode(value)); this.#wakeup?.(); }
  state(): V4ReadState { return { stream_status: this.ended && this.chunks.length === 0 ? "eof" : "open" }; }
  acquireCursor(target: bigint): V4CursorReadOwner {
    if (this.acquired) throw new Error("read_in_progress");
    if (target > 1024n) throw new Error("configuration_capacity");
    this.acquired = true;
    const storage = new Uint8Array(Number(target));
    return {
      startOffset: this.offset, storage, state: () => this.state(),
      read: async (maximum, transfer, signal) => {
        this.reads++;
        if (this.chunks.length === 0 && !this.ended) {
          await new Promise<void>((resolve, reject) => {
            const abort = () => { this.#wakeup = undefined; reject(new Error("aborted")); };
            this.#wakeup = () => { this.#wakeup = undefined; signal.removeEventListener("abort", abort); resolve(); };
            signal.addEventListener("abort", abort, { once: true });
            if (signal.aborted) abort();
          });
        }
        const chunk = this.chunks[0];
        if (chunk !== undefined) {
          const n = transfer(chunk.subarray(0, maximum));
          this.offset += BigInt(n);
          if (n === chunk.length) this.chunks.shift(); else this.chunks[0] = chunk.subarray(n);
        }
        await this.completion?.promise;
      },
      claimDelivery: () => { if (this.denied) throw new Error("authorization_denied"); },
      release: () => { this.acquired = false; this.released++; },
    };
  }
}

describe("v4 cursor ownership", () => {
  it("defers ready delivery and keeps its owner during a reentrant native resolver", async () => {
    const source = new QueueSource();
    const cursor = new V4ReaderCursor(source, { exact: 0n });
    let resultPromise: Promise<unknown> | undefined;
    let observed = false;
    const stop = promiseHooks.createHook({ settled(promise) {
      if (promise !== resultPromise) return;
      observed = true;
      expect(cursor.progress().delivered).toBe(false);
      expect(source.released).toBe(0);
      cursor.close();
      expect(source.released).toBe(0);
    } });
    try {
      resultPromise = cursor.readExactly();
      expect(cursor.progress().delivered).toBe(false);
      await resultPromise;
      expect(observed).toBe(true);
      expect(cursor.progress().delivered).toBe(true);
      expect(source.released).toBe(1);
    } finally { stop(); cursor.close(); }
  });

  it("reuses one read completion across repeated canceled waiters", async () => {
    const source = new QueueSource();
    const cursor = new V4ReaderCursor(source, { exact: 1n });
    const children = new WeakMap<Promise<unknown>, number>();
    let largestFanout = 0;
    const stop = promiseHooks.createHook({ init(_promise, parent) {
      if (parent === undefined) return;
      const count = (children.get(parent) ?? 0) + 1;
      children.set(parent, count); largestFanout = Math.max(largestFanout, count);
    } });
    try {
      for (let i = 0; i < 32; i++) {
        const signal = new AbortController();
        const pending = cursor.readExactly({ signal: signal.signal });
        await settle();
        signal.abort();
        expect((await pending).wait_status).toBe("wait_canceled");
      }
      expect(source.reads).toBe(1);
      expect(largestFanout).toBeLessThan(8);
      source.feed("x");
      expect(decode((await cursor.readExactly()).data)).toBe("x");
    } finally { stop(); cursor.close(); }
  });

  it("rejects ambiguous or unbounded targets before acquiring a direction", () => {
    const source = new QueueSource();
    for (const options of [{ exact: 2 }, { exact: -1n }, { exact: 1n, delimiter: encode("x") },
      { delimiter: encode("xx"), maxBytes: 1n }, { delimiter: encode("\n") }, { delimiter: new Uint8Array(), maxBytes: 2n }]) {
      expect(() => new V4ReaderCursor(source, options as never)).toThrow("invalid_argument");
      expect(source.acquired).toBe(false);
    }
    expect(() => new V4ReaderCursor({ read: vi.fn() } as never, { exact: 1n })).toThrow("owner_unavailable");
  });

  it("retains source suffixes and keeps a large absolute offset precise", async () => {
    const start = (1n << 53n) + 7n;
    const source = new QueueSource(["abcdef"], true, start);
    const cursor = new V4ReaderCursor(source, { exact: 3n });
    const result = await cursor.readExactly();
    expect(decode(result.data)).toBe("abc");
    expect(result.progress).toEqual({ offset: start + 3n, filled: 3n, target: 3n });
    expect(result.stream_status).toBe("open");
    expect(cursor.progress()).toMatchObject({ complete: true, delivered: true, transferred_bytes: 3n });
    await expect(cursor.readExactly()).rejects.toThrow("already_delivered");
    result.data[0] = 0;
    const suffix = await new V4ReaderCursor(source, { exact: 3n }).readExactly();
    expect(decode(suffix.data)).toBe("def");
    expect(suffix.stream_status).toBe("eof");
    expect(suffix.progress.offset).toBe(start + 6n);
  });

  it("reports short exact EOF once with the original target", async () => {
    const source = new QueueSource(["ab"], true, 8n);
    const cursor = new V4ReaderCursor(source, { exact: 4n });
    const result = await cursor.readExactly();
    expect(result).toMatchObject({ cause: "unexpected_eof", wait_status: "ready", stream_status: "eof",
      progress: { offset: 10n, filled: 2n, target: 4n } });
    expect(decode(result.data)).toBe("ab");
    await expect(cursor.takePrefix()).rejects.toThrow("already_delivered");
  });

  it("matches delimiters across segments and treats the exact cap boundary as success", async () => {
    const source = new QueueSource(["aab", "abENDtail"]);
    const delimiter = encode("ababEND");
    const cursor = new V4ReaderCursor(source, { delimiter, maxBytes: 8n });
    delimiter.fill(0);
    await expect(cursor.readLine()).rejects.toThrow("target_mismatch");
    const result = await cursor.readUntil();
    expect(decode(result.data)).toBe("aababEND");
    expect(result.cause).toBeUndefined();
    expect(decode((await new V4ReaderCursor(source, { exact: 4n }).readExactly()).data)).toBe("tail");
  });

  it("returns delimiter_not_found at the cap without consuming the next byte", async () => {
    const source = new QueueSource(["abcd\n"]);
    const cursor = new V4ReaderCursor(source, { delimiter: encode("\n"), maxBytes: 4n });
    const result = await cursor.readLine();
    expect(result).toMatchObject({ cause: "delimiter_not_found", stream_status: "open", progress: { filled: 4n, target: 4n } });
    expect(decode(source.chunks[0]!)).toBe("\n");
    expect(source.offset).toBe(4n);
  });

  it("cancels only a wait while preserving the prefix and exclusive read owner", async () => {
    const source = new QueueSource(["ab"], false, 10n);
    const cursor = new V4ReaderCursor(source, { exact: 4n });
    const controller = new AbortController();
    const waiting = cursor.readExactly({ signal: controller.signal });
    await settle();
    await expect(cursor.readExactly()).rejects.toThrow("read_in_progress");
    expect(() => new V4ReaderCursor(source, { exact: 1n })).toThrow("read_in_progress");
    controller.abort();
    expect(await waiting).toMatchObject({ wait_status: "wait_canceled", progress: { offset: 12n, filled: 0n, target: 4n } });
    expect(cursor.progress().transferred_bytes).toBe(2n);
    const resumed = cursor.readExactly();
    source.feed("cdtail");
    expect(decode((await resumed).data)).toBe("abcd");
    expect(decode(source.chunks[0]!)).toBe("tail");
  });

  it("TakePrefix never starts a network read and preserves an empty open prefix", async () => {
    const source = new QueueSource();
    const cursor = new V4ReaderCursor(source, { exact: 4n });
    const result = await cursor.takePrefix();
    expect(result).toMatchObject({ wait_status: "ready", stream_status: "open", progress: { offset: 0n, filled: 0n, target: 4n } });
    expect(result.cause).toBeUndefined();
    expect(source.reads).toBe(0);
    await expect(cursor.readExactly()).rejects.toThrow("already_delivered");
  });

  it("TakePrefix waits for a committed transfer to exit and stays frozen after wait cancellation", async () => {
    const source = new QueueSource(["ab"]);
    source.completion = deferred<void>();
    const cursor = new V4ReaderCursor(source, { exact: 4n });
    const original = cursor.readExactly();
    const originalFailed = expect(original).rejects.toThrow("prefix_frozen");
    await settle();
    expect(cursor.progress().transferred_bytes).toBe(2n);
    const controller = new AbortController();
    const prefix = cursor.takePrefix({ signal: controller.signal });
    controller.abort();
    expect((await prefix).wait_status).toBe("wait_canceled");
    expect(source.acquired).toBe(true);
    await expect(cursor.readExactly()).rejects.toThrow("prefix_frozen");
    source.completion.resolve();
    await originalFailed;
    const result = await cursor.takePrefix();
    expect(decode(result.data)).toBe("ab");
    expect(result.progress).toEqual({ offset: 2n, filled: 2n, target: 4n });
    expect(source.reads).toBe(1);
    expect(source.released).toBe(1);
  });

  it("committed EOF wins over a canceled wait even while the read exits", async () => {
    const source = new QueueSource(["ab"], true);
    source.completion = deferred<void>();
    const cursor = new V4ReaderCursor(source, { exact: 4n });
    const controller = new AbortController();
    const reading = cursor.readExactly({ signal: controller.signal });
    await settle();
    controller.abort();
    source.completion.resolve();
    expect(await reading).toMatchObject({ wait_status: "ready", stream_status: "eof", cause: "unexpected_eof", progress: { filled: 2n } });
  });

  it("exact zero uses the exclusive owner, respects cancellation and preserves EOF", async () => {
    const source = new QueueSource();
    const cursor = new V4ReaderCursor(source, { exact: 0n });
    const controller = new AbortController(); controller.abort();
    expect((await cursor.readExactly({ signal: controller.signal })).wait_status).toBe("wait_canceled");
    expect((await cursor.readExactly()).stream_status).toBe("open");
    expect(source.reads).toBe(0);
    const ended = new V4ReaderCursor(new QueueSource([], true), { exact: 0n });
    expect((await ended.readExactly({ signal: controller.signal })).stream_status).toBe("eof");
  });

  it("Close retains the direction until a borrowing read actually exits", async () => {
    const source = new QueueSource(["a"]); source.completion = deferred<void>();
    const cursor = new V4ReaderCursor(source, { exact: 2n });
    const waiting = cursor.readExactly();
    const failed = expect(waiting).rejects.toThrow("closed");
    await settle(); cursor.close();
    expect(source.acquired).toBe(true);
    expect(cursor.progress().transferred_bytes).toBe(1n);
    source.completion.resolve(); await failed;
    expect(source.released).toBe(1);
  });

  it("a closed result authorization gate cannot publish a complete candidate", async () => {
    const source = new QueueSource(["a"]); source.denied = true;
    const cursor = new V4ReaderCursor(source, { exact: 1n });
    await expect(cursor.readExactly()).rejects.toThrow("authorization_denied");
    expect(cursor.progress()).toMatchObject({ complete: true, delivered: false, transferred_bytes: 1n });
    cursor.close();
  });
});

describe("v4 owner projections", () => {
  it("requires real write owners and preserves partial terminal acceptance and pending cleanup", async () => {
    expect(() => new V4WriteOperation({ write: vi.fn() } as never, encode("abc"))).toThrow("owner_unavailable");
    const progress: V4WriteProgress = { requested_bytes: 3n, accepted_bytes: 2n, phase: "terminal", terminal_reason: "canceled", cleanup_status: pendingCleanup };
    const owner: V4WriteRequestOwner = {
      start: vi.fn(), cancel: vi.fn(), wait: vi.fn(async () => progress), progress: () => progress, cleanupStatus: () => pendingCleanup,
    };
    const prepareWrite = vi.fn(() => owner);
    const operation = new V4WriteOperation({ prepareWrite }, encode("abc"));
    operation.start(); operation.start();
    expect(owner.start).toHaveBeenCalledTimes(1);
    const controller = new AbortController();
    expect(await operation.wait({ signal: controller.signal })).toEqual(progress);
    expect(owner.wait).toHaveBeenCalledWith({ signal: controller.signal });
    expect(owner.cancel).not.toHaveBeenCalled();
    expect(operation.progress().accepted_bytes).toBe(2n);
    expect(operation.cleanupStatus()).toEqual(pendingCleanup);
    operation.cancel(); expect(owner.cancel).toHaveBeenCalledTimes(1);
  });

  it("does not invent execution cancellation or cleanup completion", () => {
    const owner = { start: vi.fn(), status: () => "accepted" as const, requestCancel: vi.fn(), waitStatus: vi.fn(async () => "accepted" as const), cleanupStatus: () => pendingCleanup };
    const operation = new V4OperationHandle(owner);
    operation.requestCancel();
    expect(operation.status()).toBe("accepted");
    expect(operation.cleanupStatus()).toEqual(pendingCleanup);
  });

  it("rejects generic sessions and ready sessions as connection material", () => {
    expect(() => new V4Session({ close: vi.fn() } as never)).toThrow("owner_unavailable");
    expect(() => new V4ConnectionMaterial({ close: vi.fn() } as never)).toThrow("owner_unavailable");
  });

  it("delegates aggregate close to the original environment and shares its bounded result", async () => {
    const first = sessionOwner(async () => { throw new Error("private provider detail"); });
    const second = sessionOwner(async () => undefined);
    const owners = [first, second];
    const runtime = environmentOwner(async () => owners.shift()!);
    runtime.close = vi.fn(async () => {
      await Promise.allSettled([first.close(), second.close()]);
      return { object_kind: "environment", lifecycle_state: "closed", cleanup_status: { ...pendingCleanup, status: "cleanup_incomplete" }, reason: "core_cleanup_failed" } as const;
    });
    const environment = new V4TransportEnvironment(runtime);
    await environment.connectMaterial(material()); await environment.connectMaterial(material());
    const closing = environment.close();
    expect(environment.close()).toBe(closing);
    await expect(closing).resolves.toMatchObject({ lifecycle_state: "closed", cleanup_status: { status: "cleanup_incomplete" }, reason: "core_cleanup_failed" });
    expect(first.close).toHaveBeenCalledTimes(1); expect(second.close).toHaveBeenCalledTimes(1);
    expect(runtime.close).toHaveBeenCalledTimes(1);
    expect(environment.cleanupStatus()).toEqual(pendingCleanup);
    await expect(environment.connectMaterial(material())).rejects.toThrow("closed");
  });

  it("consumes a material once and closes unpublished late sessions", async () => {
    const connecting = deferred<V4SessionOwner>();
    const runtime = environmentOwner(() => connecting.promise);
    const environment = new V4TransportEnvironment(runtime);
    const owner = { closeMaterial: vi.fn(async () => undefined) };
    const oneUse = new V4ConnectionMaterial(owner);
    const connect = environment.connectMaterial(oneUse);
    const rejected = expect(connect).rejects.toThrow("closed");
    await expect(environment.connectMaterial(oneUse)).rejects.toThrow("material_unavailable");
    await oneUse.close(); expect(owner.closeMaterial).not.toHaveBeenCalled();
    const closing = environment.close();
    const session = sessionOwner(async () => undefined);
    connecting.resolve(session);
    await rejected; await closing;
    expect(session.close).toHaveBeenCalledTimes(1);
    expect(runtime.connectMaterial).toHaveBeenCalledTimes(1);
  });

  it("does not consume material when connect is canceled before ownership transfer", async () => {
    const runtime = environmentOwner(async () => sessionOwner(async () => undefined));
    const environment = new V4TransportEnvironment(runtime);
    const owner = { closeMaterial: vi.fn(async () => undefined) };
    const oneUse = new V4ConnectionMaterial(owner);
    const controller = new AbortController(); controller.abort();
    await expect(environment.connectMaterial(oneUse, { signal: controller.signal })).rejects.toThrow("canceled");
    await oneUse.close(); await oneUse.close();
    expect(owner.closeMaterial).toHaveBeenCalledTimes(1);
    expect(runtime.connectMaterial).not.toHaveBeenCalled();
  });

  for (const action of ["close", "cancel", "close_material"] as const) {
    it(`keeps material ownership when Promise initialization wins with ${action}`, async () => {
      const runtime = environmentOwner(async () => sessionOwner(async () => undefined));
      const environment = new V4TransportEnvironment(runtime);
      const owner = { closeMaterial: vi.fn(async () => undefined) };
      const oneUse = new V4ConnectionMaterial(owner), abort = new AbortController();
      let entered = false;
      let closing: Promise<unknown> | undefined;
      const stop = promiseHooks.createHook({ init() {
        if (entered) return;
        entered = true;
        if (action === "close") closing = environment.close();
        else if (action === "cancel") abort.abort();
        else closing = oneUse.close();
      } });
      let connecting: Promise<V4Session>;
      try { connecting = environment.connectMaterial(oneUse, { signal: abort.signal }); }
      finally { stop(); }
      await expect(connecting).rejects.toThrow(action === "close" ? "closed" : action === "cancel" ? "canceled" : "material_unavailable");
      await closing;
      expect(entered).toBe(true);
      expect(runtime.connectMaterial).not.toHaveBeenCalled();
      await oneUse.close();
      expect(owner.closeMaterial).toHaveBeenCalledTimes(1);
      await environment.close();
    });
  }

  it("checks source connection admission after native Promise initialization", async () => {
    const runtime = environmentOwner(async () => sessionOwner(async () => undefined));
    runtime.connect = vi.fn(async () => sessionOwner(async () => undefined));
    const environment = new V4TransportEnvironment(runtime);
    const source = { acquire: vi.fn(async () => material()) };
    let entered = false;
    const stop = promiseHooks.createHook({ init() {
      if (entered) return;
      entered = true;
      void environment.close();
    } });
    let connecting: Promise<V4Session>;
    try { connecting = environment.connect(source); }
    finally { stop(); }
    await expect(connecting).rejects.toThrow("closed");
    expect(entered).toBe(true);
    expect(runtime.connect).not.toHaveBeenCalled();
    expect(source.acquire).not.toHaveBeenCalled();
  });

  it("lets only the first reentrant material transfer reach the runtime", async () => {
    const runtime = environmentOwner(async () => sessionOwner(async () => undefined));
    const environment = new V4TransportEnvironment(runtime), oneUse = material();
    let inner: Promise<V4Session> | undefined;
    let entered = false;
    const stop = promiseHooks.createHook({ init() {
      if (entered) return;
      entered = true;
      inner = environment.connectMaterial(oneUse);
      void inner.catch(() => undefined);
    } });
    let outer: Promise<V4Session>;
    try { outer = environment.connectMaterial(oneUse); }
    finally { stop(); }
    await expect(outer).rejects.toThrow("material_unavailable");
    const session = await inner;
    expect(session).toBeInstanceOf(V4Session);
    expect(runtime.connectMaterial).toHaveBeenCalledTimes(1);
    await session!.close(); await environment.close();
  });

  it("session close failure remains single flight and closes all new method gates", async () => {
    const runtime = sessionOwner(async () => { throw new Error("close failed"); });
    const session = new V4Session(runtime);
    const closing = session.close();
    expect(session.close()).toBe(closing);
    await expect(closing).rejects.toThrow("close failed");
    await expect(session.acceptStream()).rejects.toThrow("closed");
    await expect(session.rekey()).rejects.toThrow("closed");
    await expect(session.probeLiveness()).rejects.toThrow("closed");
    expect(session.cleanupStatus()).toEqual(completeCleanup);
    expect(runtime.close).toHaveBeenCalledTimes(1);
  });
});

function material(): V4ConnectionMaterial { return new V4ConnectionMaterial({ closeMaterial: async () => undefined }); }
function sessionOwner(close: () => Promise<void>): V4SessionOwner {
  return {
    info: () => { throw new Error("not used"); },
    openStream: async () => { throw new Error("not used"); },
    acceptStream: async () => { throw new Error("not used"); },
    openMessageStream: async () => { throw new Error("not used"); },
    acceptMessageStream: async () => { throw new Error("not used"); },
    registerMessageStream: () => { throw new Error("not used"); },
    registerStream: () => { throw new Error("not used"); },
    rekey: vi.fn(async () => undefined), probeLiveness: vi.fn(async () => ({ submitted: true, complete: true, elapsedMS: 0n })),
    drain: () => { throw new Error("not used"); }, waitCleanup: async () => completeCleanup,
    waitTermination: async () => undefined,
    close: vi.fn(async () => { await close(); return { object_kind: "session" as const, lifecycle_state: "session_aborted" as const, cleanup_status: completeCleanup, reason: "none" as const }; }),
    lifecycleResult: () => ({ object_kind: "session", lifecycle_state: "session_aborted", cleanup_status: completeCleanup, reason: "none" }), cleanupStatus: () => completeCleanup,
  };
}
function environmentOwner(connect: (material: V4MaterialOwner) => Promise<V4SessionOwner>): V4EnvironmentOwner {
  return { connect: async () => { throw new Error("not used"); }, connectMaterial: vi.fn(connect), close: vi.fn(async () => ({ object_kind: "environment" as const, lifecycle_state: "closed" as const, cleanup_status: pendingCleanup, reason: "none" as const })),
    lifecycleResult: () => ({ object_kind: "environment", lifecycle_state: "closed", cleanup_status: pendingCleanup, reason: "none" }), waitCleanup: async () => pendingCleanup, cleanupStatus: () => pendingCleanup };
}
