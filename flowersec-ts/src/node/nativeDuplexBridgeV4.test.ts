import { Socket } from "node:net";
import { describe, expect, it } from "vitest";
import type { OperationOptions } from "../public/contract.js";
import type { V4CloseResult, V4ReadResult } from "../generated/transportV4APIResults.js";
import type { V4StreamOwner } from "../v4/public.js";
import { ResourceRoot, ResourceVector } from "../v4/runtime/resources.js";
import { registerBridgeStreamAdapter, registerNativeBridgeDuplexAdapter } from "../v4/runtime/streamAdapter.js";
import { V4NodeDuplexBridge, claimNativeTCPBridge } from "./nativeDuplexBridgeV4.js";
import { V4DuplexBridge } from "../v4/duplexBridge.js";

const complete = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
const read = (data: Uint8Array, eof = false): V4ReadResult => ({ data, progress: { offset: 0n, filled: BigInt(data.length) },
  wait_status: "ready", stream_status: eof ? "eof" : "open" });

// The controlled Socket exercises native handoff event ordering. Actual encrypted
// Stream ownership and network transport are covered by runtime integration.
function fixture() {
  const limit = new ResourceVector(Array<bigint>(11).fill(1000000n));
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 2, reservations: 8, references: 32,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const accounts = [root.account("tenant", "1".repeat(32), limit), root.account("environment", "2".repeat(32), limit)];
  let sequence = 0, reads = 0, claimed = false;
  const reserve = () => root.reserve({ accounts, owner: { tenant: "1".repeat(32), environment: "2".repeat(32),
    kind: "native_bridge_fixture", backing: (++sequence).toString(16).padStart(32, "0") },
    charge: new ResourceVector([4096n, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) });
  const stream = {} as V4StreamOwner;
  const input = [read(new Uint8Array([1, 2, 3, 4])), read(new Uint8Array(), true)];
  registerBridgeStreamAdapter(stream, profile => {
    if (claimed) throw new Error("stream_owned"); claimed = true;
    const charge = reserve(), resultBacking = reserve(), nativeResultBacking = reserve(), nativeIOBacking = charge.borrow();
    const closed = (): V4CloseResult => ({ direction: "c2s", send_drained: true, read_terminal: "eof", cleanup_status: complete });
    const release = (): void => charge.release();
    return {
      endpointKind: "flowersec_stream", readBytes: profile.readBytes, resultBacking, nativeResultBacking, nativeIOBacking,
      check: () => charge.check(),
      read: async (_options?: OperationOptions) => { reads++; return input.shift() ?? read(new Uint8Array(), true); },
      write: async bytes => ({ requested_bytes: BigInt(bytes.length), accepted_bytes: BigInt(bytes.length), phase: "terminal", terminal_reason: "complete", cleanup_status: complete }),
      closeWrite: async () => closed(), finish: async () => closed(), reset: async () => closed(),
      abortRead: async () => closed(), abortWrite: async () => closed(), readState: () => ({ stream_status: "open" }),
      cleanupStatus: () => complete, invalidateWith: () => undefined, sendStoppedWith: () => undefined, cleanupWith: () => undefined,
      rollback: () => { nativeIOBacking.release(); nativeResultBacking.release(); resultBacking.release(); release(); claimed = false; }, release,
    };
  });
  const socket = new Socket({ allowHalfOpen: true, readableHighWaterMark: 4, writableHighWaterMark: 4 } as unknown as ConstructorParameters<typeof Socket>[0]);
  let callback: ((cause?: Error) => void) | undefined, buffer: Buffer | undefined;
  Object.defineProperty(socket, "read", { value: () => null });
  Object.defineProperty(socket, "write", { value: (input: Buffer, completed: (cause?: Error) => void) => {
    buffer = input; callback = completed;
    socket.emit("drain"); // The observer must already exist when write runs.
    return false;
  } });
  Object.defineProperty(socket, "destroy", { value: () => { socket.emit("close"); return socket; } });
  const nativeState = { claimed:false };
  registerNativeBridgeDuplexAdapter(socket,(profile,resultBacking,ioBacking) => claimNativeTCPBridge(socket,nativeState,profile,resultBacking,ioBacking,() => undefined));
  return { root, stream, socket, reads: () => reads, retainedInput: () => buffer,
    completeCallback: () => { const original = callback; callback = undefined; original?.(); },
    finishRead: () => socket.emit("end"), finishWrite: () => socket.emit("finish"),
    close: () => { for (const account of accounts) account.close(); root.close(); } };
}

async function turns(): Promise<void> { for (let index = 0; index < 12; index++) await Promise.resolve(); }

describe("native DuplexBridge callback custody", () => {
  it("captures synchronous drain and waits for callback exit before reading another chunk", async () => {
    const f = fixture();
    const bridge = new V4DuplexBridge(f.stream, f.socket as unknown as V4StreamOwner, { readChunkBytes: 4, timeoutMS: 1000, cleanupTimeoutMS: 5 });
    bridge.start(); await turns();
    expect(f.reads()).toBe(1);
    expect(bridge.progress().a_to_b.destination_accepted_bytes).toBe(4n);
    expect(f.retainedInput()).toEqual(Buffer.from([1, 2, 3, 4]));
    f.completeCallback(); await turns();
    expect(f.reads()).toBe(2);
    expect(f.retainedInput()).toEqual(Buffer.alloc(4));
    bridge.abort(); const result = await bridge.wait(); await bridge.waitCleanup(); result.release(); f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });

  it("retains input charge after close until the original late callback exits", async () => {
    const f = fixture();
    const bridge = new V4DuplexBridge(f.stream, f.socket as unknown as V4StreamOwner, { readChunkBytes: 4, timeoutMS: 1000, cleanupTimeoutMS: 5 });
    bridge.start(); await turns(); bridge.abort();
    const result = await bridge.wait();
    expect(result.a_to_b.progress.destination_accepted_bytes).toBe(4n);
    expect((await bridge.waitCleanup()).status).toBe("cleanup_incomplete");
    expect(f.retainedInput()).toEqual(Buffer.from([1, 2, 3, 4]));
    f.completeCallback(); await turns();
    expect(bridge.cleanupStatus().status).toBe("complete");
    expect(f.retainedInput()).toEqual(Buffer.alloc(4));
    result.release(); f.close(); expect(f.root.snapshot().cleanupComplete).toBe(true);
  });

  it("rejects raw socket adoption at the Node public entrypoint before reading", () => {
    const f = fixture();
    expect(() => new V4NodeDuplexBridge(f.stream,f.socket as unknown as V4StreamOwner,{readChunkBytes:4})).toThrow("owner_unavailable");
    expect(f.reads()).toBe(0); f.close(); expect(f.root.snapshot().cleanupComplete).toBe(true);
  });

  it("rejects a native endpoint with an existing consumer before reading", () => {
    const f = fixture(); f.socket.on("data", () => undefined);
    expect(() => new V4DuplexBridge(f.stream, f.socket as unknown as V4StreamOwner, { readChunkBytes: 4 })).toThrow("owner_unavailable");
    expect(f.reads()).toBe(0); f.close(); expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
});
