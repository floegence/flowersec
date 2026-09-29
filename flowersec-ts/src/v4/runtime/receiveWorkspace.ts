import { CBORDecoder, cborDecoderCharge, type CBORDecoderConfig } from "./cbor.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { recordHeaderBytes, wire } from "./wireRegistry.js";

function configuration(maxFrame: number, runtimeBytes: bigint): CBORDecoderConfig {
  if (!Number.isSafeInteger(maxFrame) || maxFrame < 100 || maxFrame > wire.resource_caps.max_payload_length || runtimeBytes <= 0n) throw new Error("configuration_capacity");
  return { bytes: maxFrame - recordHeaderBytes - 16, nodes: 15, textBytes: 0, arrayItems: 1, runtimeBytes };
}
export function receiveWorkspaceCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([BigInt(configuration(maxFrame, runtimeBytes).bytes) + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function receiveWorkspaceDecoderCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector { return cborDecoderCharge(configuration(maxFrame, runtimeBytes)); }

/** Synchronous ordinary DATA schema work shares the same single service turn
 * as its AEAD. Application consumption never retains this workspace. */
export class ReceiveWorkspace {
  readonly maxPlainBytes: number;
  readonly #decoder: CBORDecoder;
  #scratch: Uint8Array;
  #reference: ResourceReference | undefined;
  #active: object | undefined;
  #users = 0;
  #closed = false;
  constructor(maxFrame: number, runtimeBytes: bigint, reference: ResourceReference, decoder: ResourceReference) {
    const config = configuration(maxFrame, runtimeBytes); this.maxPlainBytes = config.bytes;
    this.#reference = reference.take(receiveWorkspaceCharge(maxFrame, runtimeBytes)); this.#scratch = new Uint8Array();
    let parser: CBORDecoder | undefined;
    try { this.#scratch = new Uint8Array(config.bytes); this.#decoder = parser = new CBORDecoder(config, decoder); }
    catch (error) { this.#scratch.fill(0); parser?.close(); this.#reference.release(); this.#reference = undefined; throw error; }
  }
  retain(original: ResourceReference): () => void {
    if (this.#closed || !this.#reference!.sameEnvironment(original)) throw new Error("invalid_resource_owner");
    this.#reference!.check(); this.#users++;
    let retained = true;
    return () => { if (retained) { retained = false; this.#users--; this.#cleanup(); } };
  }
  acquire(owner: object): Readonly<{ scratch: Uint8Array; decoder: CBORDecoder }> {
    if (this.#closed || this.#users === 0) throw new Error("closed");
    if (this.#active !== undefined) throw new Error("busy");
    this.#reference!.check(); this.#active = owner; return { scratch: this.#scratch, decoder: this.#decoder };
  }
  release(owner: object, used: number): void {
    if (this.#active !== owner || !Number.isSafeInteger(used) || used < 0 || used > this.#scratch.length) throw new Error("invalid_resource_owner");
    // DATA work reports the touched prefix before copying, including failures.
    // A small frame must not sweep the signed maximum on every service turn.
    this.#scratch.fill(0, 0, used); this.#active = undefined; this.#cleanup();
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#active !== undefined || this.#users !== 0) return;
    this.#decoder.close(); this.#scratch.fill(0); this.#scratch = new Uint8Array(); this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined && this.#decoder.cleanupComplete(); }
}
