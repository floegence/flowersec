import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import { FixedCBORWriter } from "./cborWriter.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { ServiceContractSnapshot } from "./serviceContract.js";

const capability = Symbol("original fixed contract targets");
const empty = new Uint8Array();
const utf8 = new TextEncoder();
export const contractQueryRequestBytes = 2048;
export const contractQueryTargetResponseBytes = 9216;
export const contractQueryMaximumTargets = 8;

/** A known selector comes only from the original complete immutable body.
 * These SDK inputs do not authenticate its source or grant target access. */
export interface ContractQueryTarget {
  readonly namespace: string;
  readonly typeID: number;
  readonly wantedDigest?: Uint8Array;
  readonly known?: ServiceContractSnapshot;
}
interface Target {
  readonly namespace: string;
  readonly typeID: number;
  readonly wanted: Uint8Array | undefined;
  readonly knownDigest: Uint8Array | undefined;
  readonly known: ServiceContractSnapshot | undefined;
}
export interface ContractTargetIdentity {
  readonly namespace: string;
  readonly typeID: number;
  readonly hasWanted: boolean;
  readonly hasKnown: boolean;
}
function decoderConfig(runtimeBytes: bigint) { return { bytes: contractQueryRequestBytes, nodes: 80, textBytes: 128, arrayItems: 8, runtimeBytes }; }
export function contractQueryCodecCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return [new ResourceVector([BigInt(contractQueryRequestBytes + 128 + 64) + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]),
    cborDecoderCharge(decoderConfig(runtimeBytes))];
}
export function contractQueryTargetsCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  // Complete encoded request, bounded identity/string/digest projections and
  // original known-body pins coexist for the whole operation, including tails.
  return new ResourceVector([BigInt(contractQueryRequestBytes + 8 * 640) + runtimeBytes, 0n, 0n, 9n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (byteLength(a) !== byteLength(b)) return false;
  let difference = 0; for (let i = 0; i < byteLength(a); i++) difference |= a[i]! ^ b[i]!;
  return difference === 0;
}

/** Original request membership and selectors survive response decoding. The
 * remote projection has no known-body capability: received digest bytes cannot
 * mint one. Local requests pin every actual known body until their final exit. */
export class ContractQueryTargets {
  #reference: ResourceReference | undefined;
  #encoded: Uint8Array = empty;
  readonly #targets: Target[] = [];
  readonly #local: boolean;
  #owners = 1;
  constructor(token: symbol, document: CBORDocument, local: boolean, known: readonly (ServiceContractSnapshot | undefined)[],
    runtimeBytes: bigint, reference: ResourceReference) {
    if (token !== capability || document.schema() !== "ContractTargets") throw new RPCProtocolError("query_owner");
    this.#local = local; this.#reference = reference.take(contractQueryTargetsCharge(runtimeBytes));
    try {
      this.#encoded = new Uint8Array(document.encodedSize()); document.copyEncoded(0, this.#encoded);
      const array = document.field(0, 0), count = document.size(array);
      if (count < 1 || count > contractQueryMaximumTargets || known.length !== count) throw new RPCProtocolError("query_target_count");
      let index = 0;
      for (let node = document.firstChild(array); node >= 0; node = document.nextSibling(node), index++) {
        const digest = (id: number): Uint8Array | undefined => {
          const field = document.field(node, id); if (field < 0) return undefined;
          const value = new Uint8Array(32); document.copyPayload(field, value); return value;
        };
        const namespace = document.text(document.field(node, 0)), typeID = Number(document.uint(document.field(node, 1)));
        const wanted = digest(2), knownDigest = digest(3), body = known[index];
        if (body !== undefined && (!local || !body.sameEnvironment(this.#reference!) || body.namespace !== namespace ||
            body.typeID !== typeID || knownDigest === undefined || !body.hasDigest(knownDigest))) throw new RPCProtocolError("query_known_mismatch");
        if (local && (body === undefined) !== (knownDigest === undefined)) throw new RPCProtocolError("query_contract_body");
        this.#targets.push({ namespace, typeID, wanted, knownDigest, known: body?.retain() });
      }
      Object.freeze(this);
    } catch (error) { this.release(); throw error; }
  }
  #check(): void {
    if (this.#reference === undefined || this.#owners === 0) throw new RPCProtocolError("query_closed");
    this.#reference.checkRetained();
  }
  #target(index: number): Target {
    this.#check(); if (!Number.isSafeInteger(index) || index < 0 || index >= this.#targets.length) throw new RPCProtocolError("query_target_index");
    return this.#targets[index]!;
  }
  retain(): this { this.#check(); if (this.#owners === 65536) throw new RPCProtocolError("resource_exhausted"); this.#owners++; return this; }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  get local(): boolean { this.#check(); return this.#local; }
  get count(): number { this.#check(); return this.#targets.length; }
  get encodedBytes(): number { this.#check(); return this.#encoded.length; }
  get responseBytes(): number { return this.count * contractQueryTargetResponseBytes; }
  identity(index: number): ContractTargetIdentity {
    const target = this.#target(index);
    return Object.freeze({ namespace: target.namespace, typeID: target.typeID, hasWanted: target.wanted !== undefined, hasKnown: target.knownDigest !== undefined });
  }
  copyEncoded(destination: Uint8Array): number {
    this.#check(); if (byteLength(destination) < this.#encoded.length) throw new RPCProtocolError("configuration_capacity");
    Uint8Array.prototype.set.call(destination, this.#encoded); return this.#encoded.length;
  }
  copyDigest(index: number, selector: "wanted" | "known", destination: Uint8Array): boolean {
    const target = this.#target(index), value = selector === "wanted" ? target.wanted : target.knownDigest;
    if (value === undefined) return false;
    if (byteLength(destination) < 32) throw new RPCProtocolError("configuration_capacity");
    Uint8Array.prototype.set.call(destination, value); return true;
  }
  /** A response validates against this exact original method and wanted body.
   * The caller separately retains the selected snapshot and any Offer. */
  checkAvailable(index: number, contract: ServiceContractSnapshot): void {
    const target = this.#target(index);
    if (!contract.sameEnvironment(this.#reference!) || contract.namespace !== target.namespace || contract.typeID !== target.typeID) throw new RPCProtocolError("query_target_mismatch");
    if (target.wanted !== undefined && !contract.hasDigest(target.wanted)) throw new RPCProtocolError("query_wanted_mismatch");
  }
  unchanged(index: number, digest: Uint8Array): ServiceContractSnapshot {
    const target = this.#target(index);
    if (!this.#local || target.known === undefined || target.knownDigest === undefined) throw new RPCProtocolError("query_unchanged_without_known");
    if (!equal(digest, target.knownDigest) || !target.known.hasDigest(digest)) throw new RPCProtocolError("query_unchanged_mismatch");
    this.checkAvailable(index, target.known); return target.known.retain();
  }
  matchesKnown(index: number, contract: ServiceContractSnapshot): boolean {
    const target = this.#target(index); this.checkAvailable(index, contract);
    return target.knownDigest !== undefined && contract.hasDigest(target.knownDigest);
  }
  release(): void {
    if (this.#owners === 0 || --this.#owners !== 0) return;
    for (const target of this.#targets) { target.known?.release(); target.wanted?.fill(0); target.knownDigest?.fill(0); }
    this.#targets.length = 0; this.#encoded.fill(0); this.#encoded = empty;
    this.#reference?.release(); this.#reference = undefined;
  }
  toJSON(): object { return {}; }
}

/** At most 2 KiB in one SDK step. Both directions use the generated canonical
 * map rules; duplicate methods and unequal wanted/known selectors are rejected
 * before network publication. No wildcard or directory discovery is encoded. */
export class ContractQueryCodec {
  #reference: ResourceReference | undefined;
  #decoder: CBORDecoder | undefined;
  #scratch: Uint8Array = empty;
  #text: Uint8Array = empty;
  #digest: Uint8Array = empty;
  #working = false;
  #closed = false;
  constructor(readonly runtimeBytes: bigint, references: readonly ResourceReference[]) {
    const costs = contractQueryCodecCharges(runtimeBytes);
    if (references.length !== costs.length || !references[0]!.sameEnvironment(references[1]!)) throw new RPCProtocolError("query_owner");
    this.#reference = references[0]!.take(costs[0]!);
    try {
      this.#decoder = new CBORDecoder(decoderConfig(runtimeBytes), references[1]!);
      this.#scratch = new Uint8Array(contractQueryRequestBytes); this.#text = new Uint8Array(128); this.#digest = new Uint8Array(32);
      Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  #begin(reference: ResourceReference): void {
    if (this.#closed) throw new RPCProtocolError("query_closed");
    if (this.#working) throw new RPCProtocolError("query_busy");
    this.#reference!.check(); if (!this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("query_owner");
    this.#working = true;
  }
  prepare(targets: readonly ContractQueryTarget[], reference: ResourceReference): ContractQueryTargets {
    this.#begin(reference);
    const pins: (ServiceContractSnapshot | undefined)[] = [];
    let document: CBORDocument | undefined;
    try {
      if (!Array.isArray(targets) || targets.length < 1 || targets.length > contractQueryMaximumTargets) throw new RPCProtocolError("query_target_count");
      const count = targets.length, writer = new FixedCBORWriter(this.#scratch).map(1).uint(0).array(count);
      for (let index = 0; index < count; index++) {
        const input = targets[index]!;
        const { namespace, typeID, wantedDigest, known } = input;
        if (typeof namespace !== "string" || namespace.length < 1 || namespace.length > 128 || !Number.isSafeInteger(typeID) ||
            typeID < 1 || typeID > 0xffffffff || wantedDigest !== undefined && byteLength(wantedDigest) !== 32 ||
            known !== undefined && !(known instanceof ServiceContractSnapshot)) throw new RPCProtocolError("query_target");
        pins.push(known?.retain());
        const text = utf8.encodeInto(namespace, this.#text);
        if (text.read !== namespace.length) throw new RPCProtocolError("query_target");
        writer.map(2 + Number(wantedDigest !== undefined) + Number(known !== undefined)).uint(0).data(byteSlice(this.#text, 0, text.written), true).uint(1).uint(typeID);
        if (wantedDigest !== undefined) writer.uint(2).data(wantedDigest);
        if (known !== undefined) { known.copyDigest(this.#digest); writer.uint(3).data(this.#digest); }
      }
      document = this.#decoder!.decodeMap(writer.result(), "ContractTargets");
      if (this.#closed) throw new RPCProtocolError("query_closed");
      return new ContractQueryTargets(capability, document, true, pins, this.runtimeBytes, reference);
    } finally { document?.release(); for (const pin of pins) pin?.release(); this.#finish(); }
  }
  decode(bytes: Uint8Array, reference: ResourceReference): ContractQueryTargets {
    this.#begin(reference); let document: CBORDocument | undefined;
    try {
      document = this.#decoder!.decodeMap(bytes, "ContractTargets");
      const count = document.size(document.field(0, 0));
      return new ContractQueryTargets(capability, document, false, Array<ServiceContractSnapshot | undefined>(count).fill(undefined), this.runtimeBytes, reference);
    } finally { document?.release(); this.#finish(); }
  }
  #finish(): void { this.#scratch.fill(0); this.#text.fill(0); this.#digest.fill(0); this.#working = false; if (this.#closed) this.#cleanup(); }
  close(): void { if (this.#closed) return; this.#closed = true; if (!this.#working) this.#cleanup(); }
  #cleanup(): void {
    this.#decoder?.close(); this.#decoder = undefined;
    this.#scratch.fill(0); this.#text.fill(0); this.#digest.fill(0); this.#scratch = this.#text = this.#digest = empty;
    this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
