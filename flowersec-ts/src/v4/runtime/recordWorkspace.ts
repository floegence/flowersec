import { ResourceVector, type ResourceReference } from "./resources.js";
import { envelopePrefixBytes, recordHeaderBytes, wire } from "./wireRegistry.js";

export function recordWorkspaceCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(maxFrame) || maxFrame < recordHeaderBytes + 16 || maxFrame > wire.resource_caps.max_payload_length || runtimeBytes <= 0n) throw new Error("configuration_capacity");
  // Input/coalescing, retained output and the actual AEAD library result.
  return new ResourceVector([BigInt(3 * (envelopePrefixBytes + maxFrame)) + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}

/** One shared ordinary AEAD position. Keys keep only a bounded link;
 * native I/O never occupies this workspace after the real crypto borrow ends. */
export class RecordWorkspace {
  #reference: ResourceReference | undefined;
  #input: Uint8Array;
  #output: Uint8Array;
  #users = 0;
  #active: object | undefined;
  #closed = false;
  constructor(readonly maxFrame: number, runtimeBytes: bigint, reference: ResourceReference) {
    this.#reference = reference.take(recordWorkspaceCharge(maxFrame, runtimeBytes));
    this.#input = this.#output = new Uint8Array();
    try { this.#input = new Uint8Array(envelopePrefixBytes + maxFrame); this.#output = new Uint8Array(envelopePrefixBytes + maxFrame); }
    catch (error) { this.close(); throw error; }
  }
  retain(original: ResourceReference): () => void {
    if (this.#closed || !this.#reference!.sameEnvironment(original)) throw new Error("invalid_resource_owner");
    this.#reference!.check(); this.#users++;
    let retained = true;
    return () => { if (!retained) return; retained = false; this.#users--; this.#cleanup(); };
  }
  acquire(owner: object): Readonly<{ input: Uint8Array; output: Uint8Array }> {
    if (this.#closed || this.#users === 0) throw new Error("closed");
    if (this.#active !== undefined) throw new Error("busy");
    this.#reference!.check(); this.#active = owner;
    return { input: this.#input, output: this.#output };
  }
  release(owner: object): void {
    if (this.#active !== owner) throw new Error("invalid_resource_owner");
    // The original cipher clears each touched range before returning it. A
    // small record does not repeatedly sweep the signed maximum frame size.
    this.#active = undefined; this.#cleanup();
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#active !== undefined || this.#users !== 0) return;
    this.#input.fill(0); this.#output.fill(0); this.#input = this.#output = new Uint8Array();
    this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
