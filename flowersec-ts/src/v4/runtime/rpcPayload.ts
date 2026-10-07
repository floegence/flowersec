import { byteLength, byteSlice } from "./cbor.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";

const empty = new Uint8Array(), copy = Uint8Array.prototype.set;
export function rpcPayloadCharge(capacity: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(capacity) || capacity < 0 || capacity > 1048576 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  // Includes the enclosing input/completion, hash workspace, scalar header,
  // one bounded borrow and a fixed SDK error workspace retained in late mode.
  return new ResourceVector([BigInt(capacity) + 2304n + runtimeBytes, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export interface RPCPayloadBorrow {
  readonly bytes: Uint8Array;
  retainSend(reference: ResourceReference): ResourceReference;
  release(): void;
}

/** Actual backing ownership shared by request input and completion. Borrowing
 * never refunds the full allocation behind a view. Only one decoder/consumer
 * can hold the original payload at a time. */
export class RPCPayload {
  #reference: ResourceReference | undefined;
  #bytes: Uint8Array = empty;
  #borrowed = 0;
  #sealed = false;
  #closed = false;
  constructor(capacity: number, runtimeBytes: bigint, reference: ResourceReference) {
    this.#reference = reference.take(rpcPayloadCharge(capacity, runtimeBytes));
    try { this.#bytes = new Uint8Array(capacity); }
    catch (error) { this.close(); throw error; }
  }
  check(): void {
    if (this.#closed) throw new RPCProtocolError("rpc_payload_closed"); this.#reference!.checkRetained();
  }
  sameEnvironment(reference: ResourceReference): boolean { this.check(); return this.#reference!.sameEnvironment(reference); }
  write(offset: number, bytes: Uint8Array): void {
    this.check(); const n = byteLength(bytes);
    if (this.#sealed || this.#borrowed !== 0 || !Number.isSafeInteger(offset) || offset < 0 || offset > this.#bytes.length - n) throw new RPCProtocolError("rpc_payload_offset");
    copy.call(this.#bytes, bytes, offset);
  }
  seal(): void { this.check(); if (this.#borrowed !== 0) throw new RPCProtocolError("rpc_payload_borrow"); this.#sealed = true; }
  /** Only immutable retained results may have concurrent, separately charged
   * SDK readers. No shared view is handed directly to application code. */
  borrowShared(length: number): RPCPayloadBorrow {
    if (!this.#sealed || this.#borrowed >= 64) throw new RPCProtocolError("resource_exhausted"); return this.#borrow(length, true);
  }
  borrow(length: number): RPCPayloadBorrow { return this.#borrow(length, false); }
  #borrow(length: number, shared: boolean): RPCPayloadBorrow {
    this.check();
    if (!shared && this.#borrowed !== 0 || !Number.isSafeInteger(length) || length < 0 || length > this.#bytes.length) throw new RPCProtocolError("rpc_payload_borrow");
    this.#borrowed++; let held = true;
    return Object.freeze({ bytes: byteSlice(this.#bytes, 0, length), retainSend: (reference: ResourceReference) => {
      if (!held || this.#reference === undefined) throw new RPCProtocolError("rpc_payload_closed");
      return this.#reference.borrowInScopesOf(reference);
    }, release: () => {
      if (!held) return; held = false; this.#borrowed--; this.#collect();
    } });
  }
  close(): void { this.#closed = true; this.#collect(); }
  #collect(): void {
    if (!this.#closed || this.#borrowed !== 0) return;
    this.#bytes.fill(0); this.#bytes = empty; this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
