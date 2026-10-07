import { describe, expect, it } from "vitest";
import type { OperationOptions } from "../public/contract.js";
import type { V4CloseResult, V4ReadResult, V4TypedError, V4WriteProgress } from "../generated/transportV4APIResults.js";
import type { V4ReadState, V4StreamOwner } from "./public.js";
import { V4DuplexBridge } from "./duplexBridge.js";
import { ResourceError, ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { registerBridgeStreamAdapter, type BridgeStreamAdapterOwner } from "./runtime/streamAdapter.js";

const complete = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
const pending = Object.freeze({ status: "pending" as const, core_cleanup: "pending" as const, pending_callbacks: 1n });
function readResult(data: Uint8Array, status: V4ReadState["stream_status"] = "open", error?: V4TypedError): V4ReadResult {
  return { data, progress: { offset: 0n, filled: BigInt(data.length) }, wait_status: "ready", stream_status: status,
    ...(error === undefined ? {} : { error }) };
}
function writeResult(requested: number, accepted: number, reason: V4WriteProgress["terminal_reason"] = "complete"): V4WriteProgress {
  return { requested_bytes: BigInt(requested), accepted_bytes: BigInt(accepted), phase: "terminal", terminal_reason: reason, cleanup_status: complete };
}
function waitForAbort(options?: OperationOptions): Promise<V4ReadResult> {
  if (options?.signal?.aborted) return Promise.resolve(readResult(new Uint8Array(), "aborted"));
  return new Promise(resolve => options?.signal?.addEventListener("abort", () => resolve(readResult(new Uint8Array(), "aborted")), { once: true }));
}
// This private registry fixture exercises only bridge ownership and deterministic
// partial callbacks. Encrypted Stream integration lives in sessionRuntime.test.
function fixture() {
  const limit = new ResourceVector(Array<bigint>(11).fill(1000000n));
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 2, reservations: 8, references: 32,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const accounts = [root.account("tenant", "1".repeat(32), limit), root.account("environment", "2".repeat(32), limit)];
  let sequence = 0;
  function endpoint(initial: V4ReadResult[], physicallyComplete = true) {
    const stream = {} as V4StreamOwner;
    let state: V4ReadState = { stream_status: "open" }, cleanupChanged: (() => void) | undefined;
    let invalidated: (() => void) | undefined, released = false, claimed = false, physical = physicallyComplete;
    let resetCount = 0, closeWriteCount = 0, finishCount = 0, rollbackCount = 0;
    let write: (bytes: Uint8Array) => Promise<V4WriteProgress> = async bytes => writeResult(bytes.length, bytes.length);
    registerBridgeStreamAdapter(stream, profile => {
      if (claimed) throw new Error("stream_owned"); claimed = true;
      const reference = root.reserve({ accounts, owner: { tenant: "1".repeat(32), environment: "2".repeat(32),
        kind: "bridge_fixture", backing: (++sequence).toString(16).padStart(32, "0") },
        charge: new ResourceVector([4096n, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) });
      const resultBacking = root.reserve({ accounts, owner: { tenant: "1".repeat(32), environment: "2".repeat(32),
        kind: "bridge_fixture_result", backing: (++sequence).toString(16).padStart(32, "0") },
        charge: new ResourceVector([128n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) });
      const closed = (): V4CloseResult => ({ direction: "s2c", send_drained: true, read_terminal: "eof", cleanup_status: physical ? complete : pending });
      const release = (): void => { if (!released) { released = true; cleanupChanged = undefined; invalidated = undefined; reference.release(); } };
      const owner: BridgeStreamAdapterOwner = {
        endpointKind: "flowersec_stream", readBytes: profile.readBytes, resultBacking, check: () => { reference.check(); if (released) throw new Error("closed"); },
        read: async options => { const result = initial.shift() ?? await waitForAbort(options); state = { stream_status: result.stream_status,
          ...(result.error === undefined ? {} : { error: result.error }) }; return result; },
        write: bytes => write(bytes), closeWrite: async () => { closeWriteCount++; return closed(); },
        finish: async () => { finishCount++; return closed(); },
        reset: async () => { resetCount++; state = { stream_status: "aborted" }; invalidated?.(); return closed(); },
        abortRead: async () => closed(), abortWrite: async () => closed(), cleanupStatus: () => physical ? complete : pending,
        invalidateWith: callback => { invalidated = callback; }, sendStoppedWith: () => undefined,
        cleanupWith: callback => { cleanupChanged = callback; }, readState: () => state,
        rollback: () => { rollbackCount++; claimed = false; resultBacking.release(); release(); }, release,
      };
      return owner;
    });
    return { stream, setWrite: (next: typeof write) => { write = next; }, completePhysical: () => { physical = true; cleanupChanged?.(); },
      counts: () => ({ resetCount, closeWriteCount, finishCount, rollbackCount, released }) };
  }
  return { root, endpoint, close: () => { for (const account of accounts) account.close(); root.close(); } };
}

describe("DuplexBridge original owner lifecycle", () => {
  it("retains an unaccepted prefix and real charges after cleanup timeout until their owners exit", async () => {
    const f = fixture(), a = f.endpoint([readResult(new Uint8Array([1, 2, 3, 4]))], false), b = f.endpoint([], false);
    b.setWrite(async bytes => writeResult(bytes.length, 2, "failed"));
    const bridge = new V4DuplexBridge(a.stream, b.stream, { readChunkBytes: 4, cleanupTimeoutMS: 5, timeoutMS: 1000 });
    bridge.start();
    const result = await bridge.wait();
    expect(result).toMatchObject({ outcome: "failed", failure: "write_failed", a_to_b: { progress: {
      source_read_bytes: 4n, destination_accepted_bytes: 2n, unaccepted_tail: new Uint8Array([3, 4]) } } });
    const charged = f.root.snapshot().charged.values();
    expect((await bridge.waitCleanup()).status).toBe("cleanup_incomplete");
    expect(f.root.snapshot().charged.values()).toEqual(charged);
    expect(a.counts().released).toBe(false); expect(b.counts().released).toBe(false);
    a.completePhysical(); b.completePhysical();
    expect((await bridge.waitCleanup()).status).toBe("complete");
    expect(a.counts().resetCount).toBe(1); expect(b.counts().resetCount).toBe(1);
    expect(a.counts().released).toBe(true); expect(b.counts().released).toBe(true);
    expect(bridge.progress().a_to_b.unaccepted_tail_bytes).toBe(2n);
    expect(await bridge.wait()).toBe(result); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(false);
    result.release(); result.release(); expect(result.a_to_b.progress.unaccepted_tail).toEqual(new Uint8Array([0, 0]));
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("retries only an accepted writer remainder and finishes both owners after both EOFs", async () => {
    const f = fixture(), a = f.endpoint([readResult(new Uint8Array([1, 2, 3, 4]), "eof")]), b = f.endpoint([readResult(new Uint8Array([9]), "eof")]);
    const writes: number[][] = [];
    b.setWrite(async bytes => { writes.push([...bytes]); return writeResult(bytes.length, Math.min(2, bytes.length)); });
    const bridge = new V4DuplexBridge(a.stream, b.stream, { readChunkBytes: 4 }); bridge.start(); bridge.start();
    const result = await bridge.wait();
    expect(result.outcome).toBe("normal"); expect(writes).toEqual([[1, 2, 3, 4], [3, 4]]);
    expect(a.counts()).toMatchObject({ closeWriteCount: 1, finishCount: 1, resetCount: 0 });
    expect(b.counts()).toMatchObject({ closeWriteCount: 1, finishCount: 1, resetCount: 0 });
    expect((await bridge.waitCleanup()).status).toBe("complete"); result.release(); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("preserves the first typed read error and its disclosed tail without sending it", async () => {
    const f = fixture(), error: V4TypedError = { code: "stream_data_invalid", scope: "stream", retry_disposition: "preserve_facts" };
    const a = f.endpoint([readResult(new Uint8Array([7, 8]), "error", error)]), b = f.endpoint([]);
    let writes = 0; b.setWrite(async bytes => { writes++; return writeResult(bytes.length, bytes.length); });
    const bridge = new V4DuplexBridge(a.stream, b.stream, { readChunkBytes: 2 }); bridge.start();
    const result = await bridge.wait();
    expect(result).toMatchObject({ outcome: "failed", failure: "read_failed", first_error: error, a_to_b: { progress: {
      source_read_bytes: 2n, destination_accepted_bytes: 0n, unaccepted_tail: new Uint8Array([7, 8]) }, source_status: "error" } });
    expect(writes).toBe(0); expect(Object.isFrozen(result.first_error)).toBe(true);
    expect((await bridge.waitCleanup()).status).toBe("complete"); result.release(); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("cancels both prepared owners through the explicit operation signal without starting pumps", async () => {
    const f = fixture(), a = f.endpoint([]), b = f.endpoint([]), operation = new AbortController();
    operation.abort();
    const bridge = new V4DuplexBridge(a.stream, b.stream, { signal: operation.signal }); bridge.start();
    const result = await bridge.wait(); expect(result.outcome).toBe("aborted");
    expect(a.counts()).toMatchObject({ resetCount: 1, closeWriteCount: 0, finishCount: 0 });
    expect(b.counts()).toMatchObject({ resetCount: 1, closeWriteCount: 0, finishCount: 0 });
    expect((await bridge.waitCleanup()).status).toBe("complete"); result.release(); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("rolls back the first owner on resource rejection without disclosing an arbitrary cause", () => {
    const f = fixture(), a = f.endpoint([]), b = {} as V4StreamOwner;
    registerBridgeStreamAdapter(b, () => { throw new ResourceError("resource_exhausted"); });
    const baseline = f.root.snapshot().charged.values();
    expect(() => new V4DuplexBridge(a.stream, b)).toThrow("resource_exhausted");
    expect(a.counts()).toMatchObject({ rollbackCount: 1, released: true, resetCount: 0, closeWriteCount: 0, finishCount: 0 });
    expect(f.root.snapshot().charged.values()).toEqual(baseline); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("rejects native or duck-typed endpoints before any original I/O", () => {
    const f = fixture(), a = f.endpoint([]), native = { read: () => { throw new Error("must_not_read"); }, write: () => undefined } as unknown as V4StreamOwner;
    const baseline = f.root.snapshot().charged.values();
    expect(() => new V4DuplexBridge(a.stream, native)).toThrow("invalid_endpoint");
    expect(a.counts()).toMatchObject({ rollbackCount: 0, resetCount: 0, closeWriteCount: 0, finishCount: 0 });
    expect(f.root.snapshot().charged.values()).toEqual(baseline); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("expires the overall operation before Start and never launches a pump afterward", async () => {
    const f = fixture(), a = f.endpoint([]), b = f.endpoint([]);
    const bridge = new V4DuplexBridge(a.stream, b.stream, { timeoutMS: 5 });
    const result = await bridge.wait(); bridge.start();
    expect(result).toMatchObject({ outcome: "aborted", failure: "deadline_exceeded" });
    expect(a.counts()).toMatchObject({ resetCount: 1, closeWriteCount: 0, finishCount: 0 });
    expect(b.counts()).toMatchObject({ resetCount: 1, closeWriteCount: 0, finishCount: 0 });
    expect((await bridge.waitCleanup()).status).toBe("complete"); result.release(); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
});
