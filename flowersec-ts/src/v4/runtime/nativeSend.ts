import { RecordWorkspace } from "./recordWorkspace.js";
import { ResourceVector, type ResourceReference } from "./resources.js";

export function nativeOutputFrame(maxFrame: number, maxDataBytes: number): number {
  return Math.min(maxFrame, Math.max(4480, maxDataBytes + 100));
}
export function nativeSendEncodeCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(maxFrame) || maxFrame < 4480 || runtimeBytes <= 0n) throw new Error("configuration_capacity");
  return new ResourceVector([BigInt(maxFrame) + runtimeBytes + 128n, 0n, 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
/** One synchronous ordinary encoding/AEAD service. Ciphertext handed to a
 * provider has a separate original output owner; it never pins this service. */
export class NativeSendWorkspace {
  readonly crypto: RecordWorkspace;
  #reference: ResourceReference | undefined;
  #encode = new Uint8Array();
  #busy = false;
  #closed = false;
  constructor(maxFrame: number, runtimeBytes: bigint, crypto: ResourceReference, encode: ResourceReference) {
    this.crypto = new RecordWorkspace(maxFrame, runtimeBytes, crypto);
    try {
      this.#reference = encode.take(nativeSendEncodeCharge(maxFrame, runtimeBytes));
      this.#encode = new Uint8Array(maxFrame);
    } catch (error) { this.crypto.close(); this.#reference?.release(); this.#reference = undefined; throw error; }
  }
  available(): boolean { return !this.#closed && !this.#busy; }
  encode<T>(action: (storage: Uint8Array) => T): T {
    if (!this.available()) throw new Error(this.#closed ? "closed" : "busy");
    this.#reference!.check(); this.#busy = true;
    try { return action(this.#encode); }
    finally { this.#encode.fill(0); this.#busy = false; this.#collect(); }
  }
  close(): void { this.#closed = true; this.crypto.close(); this.#collect(); }
  #collect(): void {
    if (!this.#closed || this.#busy) return;
    this.#encode.fill(0); this.#encode = new Uint8Array(); this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined && this.crypto.cleanupComplete(); }
}
