import { describe, expect, it } from "vitest";
import type { V4CloseResult, V4ReadResult, V4WriteProgress } from "../generated/transportV4APIResults.js";
import type { V4StreamOwner } from "../v4/public.js";
import { registerStreamAdapter, type StreamAdapterOwner } from "../v4/runtime/streamAdapter.js";
import { currentProxyStream, ProxyStreamError } from "./currentStream.js";
import { ProxyByteReader, writeAll } from "./stream.js";

const complete = { status: "complete", core_cleanup: "complete", pending_callbacks: 0n } as const;
const pending = { status: "pending", core_cleanup: "pending", pending_callbacks: 0n } as const;
const options = { readBytes: 64, inputBackingBytes: 256, finishTimeoutMS: 100, cleanupTimeoutMS: 100 };
const closeResult: V4CloseResult = { direction: "c2s", send_drained: true, read_terminal: "eof", cleanup_status: complete };
function fixture(overrides: Partial<StreamAdapterOwner> = {}) {
  const source = {} as V4StreamOwner;
  let releases = 0, resets = 0, ready = false, notify = () => {}, invalidate = () => {};
  const owner: StreamAdapterOwner = {
    readBytes: 64, check() {},
    async read() { return { data: new Uint8Array(), progress: { offset: 0n, filled: 0n }, wait_status: "ready", stream_status: "eof" }; },
    async write(bytes) { return { requested_bytes: BigInt(bytes.length), accepted_bytes: BigInt(bytes.length), phase: "terminal", terminal_reason: "complete", cleanup_status: complete }; },
    async closeWrite() { return closeResult; }, async finish() { return closeResult; },
    async reset() { resets++; return { ...closeResult, send_drained: false, cleanup_status: pending }; },
    async abortRead() { return closeResult; }, async abortWrite() { return closeResult; },
    cleanupStatus: () => ready ? complete : pending,
    invalidateWith(callback) { invalidate = callback; }, sendStoppedWith() {}, cleanupWith(callback) { notify = callback; },
    rollback() {}, release() { releases++; }, ...overrides,
  };
  registerStreamAdapter(source, () => owner);
  return { stream: currentProxyStream(source, options), releases: () => releases, resets: () => resets,
    complete: () => { ready = true; notify(); }, invalidate: () => invalidate() };
}

describe("current proxy Stream projection", () => {
  it("continues only successful short writes and preserves a failed accepted prefix", async () => {
    const writes: number[][] = [];
    const progress: V4WriteProgress = { requested_bytes: 3n, accepted_bytes: 1n, phase: "terminal", terminal_reason: "canceled", cleanup_status: pending };
    const f = fixture({ async write(bytes) {
      writes.push(Array.from(bytes));
      return writes.length === 1 ? { ...progress, requested_bytes: 5n, accepted_bytes: 2n, terminal_reason: "complete" } : progress;
    } });
    await expect(writeAll(f.stream, new Uint8Array([1, 2, 3, 4, 5]))).rejects.toEqual(new ProxyStreamError("write_failed", progress));
    expect(writes).toEqual([[1, 2, 3, 4, 5], [3, 4, 5]]);
    f.stream.dispose(); expect(f.releases()).toBe(0);
    f.complete(); expect(f.releases()).toBe(1);
  });

  it("delivers the final EOF prefix once and keeps ownership until framing exits", async () => {
    const f = fixture({ async read() { return { data: new Uint8Array([3, 4]), progress: { offset: 2n, filled: 2n }, wait_status: "ready", stream_status: "eof" }; } });
    const reader = new ProxyByteReader(f.stream);
    expect(await reader.readExactly(2)).toEqual(new Uint8Array([3, 4]));
    expect(await f.stream.read()).toBeNull();
    await f.stream.finish(); f.complete();
    expect(f.releases()).toBe(0);
    f.stream.dispose(); expect(f.releases()).toBe(1);
    expect(f.stream.cleanupStatus()).toEqual(complete);
    expect(f.resets()).toBe(0);
  });

  it("does not turn a canceled post-body observer into EOF or a stream reset", async () => {
    const canceled: V4ReadResult = { data: new Uint8Array(), progress: { offset: 0n, filled: 0n }, wait_status: "wait_canceled", stream_status: "open" };
    let calls = 0;
    const f = fixture({ async read() { calls++; return calls === 1 ? canceled : { ...canceled, wait_status: "ready", stream_status: "eof" }; } });
    await expect(f.stream.read()).rejects.toEqual(new ProxyStreamError("canceled", canceled));
    expect(await f.stream.read()).toBeNull(); expect(f.resets()).toBe(0);
    f.stream.dispose(); f.complete();
  });

  it("retains cleanup until the original reset tail exits", async () => {
    let done!: (value: V4CloseResult) => void;
    const f = fixture({ reset: () => new Promise(resolve => { done = resolve; }) });
    const resetting = f.stream.reset(); f.invalidate(); f.stream.dispose(); f.complete();
    expect(f.releases()).toBe(0); expect(f.stream.cleanupStatus()).toMatchObject({ status: "pending", pending_callbacks: 1n });
    done(closeResult); await resetting;
    expect(f.releases()).toBe(1); expect(f.stream.cleanupStatus()).toEqual(complete);
  });
});
