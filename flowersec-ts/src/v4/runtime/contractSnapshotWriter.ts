import { byteLength, byteSlice } from "./cbor.js";
import { FixedCBORWriter } from "./cborWriter.js";
import type { ContractQueryTargets } from "./contractQuery.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { AdmissionOffer, ServiceContractSnapshot } from "./serviceContract.js";
import { wireMaps } from "./schemaRegistry.js";

export type ContractSnapshotStatus = "available_full" | "available_unchanged" | "denied" | "unavailable";
export type ContractSnapshotChoice = Readonly<{
  status: "available_full" | "available_unchanged";
  contract: ServiceContractSnapshot;
  offer?: AdmissionOffer;
  maxOfferWindowMS?: bigint;
}> | Readonly<{ status: "denied" | "unavailable"; contract?: never; offer?: never; maxOfferWindowMS?: never }>;
interface Choice {
  readonly status: ContractSnapshotStatus;
  readonly code: number;
  readonly contract: ServiceContractSnapshot | undefined;
  readonly offer: Uint8Array;
}
const empty = new Uint8Array();
const statuses = wireMaps.ContractSnapshot!.fields[1]!.enum!;
const snapshotLimit = wireMaps.ContractSnapshot!.max_encoded_bytes!;
export function contractSnapshotWriterCharges(request: ContractQueryTargets, runtimeBytes: bigint): readonly ResourceVector[] {
  return contractSnapshotWriterCapacityCharges(request.count, runtimeBytes);
}
export function contractSnapshotWriterCapacityCharges(targets: number, runtimeBytes: bigint): readonly ResourceVector[] {
  if (!Number.isSafeInteger(targets) || targets < 1 || targets > 8 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return [new ResourceVector([4096n + 512n * BigInt(targets) + runtimeBytes, 0n, 0n, 9n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    rpcPayloadCharge(targets * 9216, runtimeBytes)];
}

/** One complete preadmitted response. The trusted per-target source selects
 * these choices after current authorization; this encoder cannot grant it.
 * Each step writes one bounded shell or <= 4096 body bytes. The fixed query
 * executor schedules steps fairly and rechecks permission before publication.
 * No partial response or body can escape through a result borrow. */
export class ContractSnapshotWriter {
  #reference: ResourceReference | undefined;
  #request: ContractQueryTargets | undefined;
  #payload: RPCPayload | undefined;
  readonly #choices: Choice[] = [];
  #scratch: Uint8Array = empty;
  #index = 0;
  #offset = 0;
  #bodyOffset = 0;
  #itemStart = 0;
  #phase: "envelope" | "head" | "body" | "offer" | "done" = "envelope";
  #borrowed = false;
  #closed = false;
  #working = false;
  #failure: unknown;
  constructor(request: ContractQueryTargets, choices: readonly ContractSnapshotChoice[], runtimeBytes: bigint, references: readonly ResourceReference[]) {
    const costs = contractSnapshotWriterCharges(request, runtimeBytes), count = request.count;
    if (!Array.isArray(choices) || choices.length !== count || references.length !== costs.length ||
        !references.every(ref => request.sameEnvironment(ref))) throw new RPCProtocolError("query_response_count");
    this.#reference = references[0]!.take(costs[0]!);
    try {
      this.#request = request.retain();
      this.#payload = new RPCPayload(request.responseBytes, runtimeBytes, references[1]!);
      this.#scratch = new Uint8Array(4096);
      for (let index = 0; index < count; index++) {
        const { status, contract, offer, maxOfferWindowMS } = choices[index]!;
        const code = Object.hasOwn(statuses, status) ? statuses[status] : undefined;
        if (code === undefined) throw new RPCProtocolError("query_response_status");
        if (status === "denied" || status === "unavailable") {
          if (contract !== undefined || offer !== undefined || maxOfferWindowMS !== undefined) throw new RPCProtocolError("query_refusal_fields");
          this.#choices.push({ status, code, contract: undefined, offer: empty }); continue;
        }
        if (!(contract instanceof ServiceContractSnapshot)) throw new RPCProtocolError("query_contract_body");
        request.checkAvailable(index, contract);
        if (status === "available_unchanged" && !request.matchesKnown(index, contract)) throw new RPCProtocolError("query_unchanged_mismatch");
        if ((offer !== undefined) !== (contract.semantics === "execution")) throw new RPCProtocolError("query_offer_presence");
        let encoded = empty;
        if (offer !== undefined) {
          if (!(offer instanceof AdmissionOffer) || maxOfferWindowMS === undefined) throw new RPCProtocolError("admission_offer_unavailable");
          const length = offer.copyEncoded(contract, maxOfferWindowMS, this.#scratch);
          if (length > 256) throw new RPCProtocolError("query_offer_size");
          encoded = new Uint8Array(byteSlice(this.#scratch, 0, length)); this.#scratch.fill(0);
        } else if (maxOfferWindowMS !== undefined) throw new RPCProtocolError("query_offer_presence");
        this.#choices.push({ status, code, contract: contract.retain(), offer: encoded });
      }
    } catch (error) { this.close(); throw error; }
  }
  #check(): void {
    if (this.#failure !== undefined) throw this.#failure;
    if (this.#closed) throw new RPCProtocolError("query_response_closed");
    this.#reference!.check(); this.#payload!.check();
  }
  #append(bytes: Uint8Array): void {
    const length = byteLength(bytes);
    if (length > 4096 || length > this.#request!.responseBytes - this.#offset) throw new RPCProtocolError("query_response_size");
    this.#payload!.write(this.#offset, bytes); this.#offset += length;
  }
  #nextItem(): void {
    if (this.#offset - this.#itemStart > snapshotLimit) throw new RPCProtocolError("query_response_size");
    this.#index++; this.#bodyOffset = 0; this.#phase = this.#index === this.#choices.length ? "done" : "head";
  }
  #done(): boolean { return this.#phase === "done"; }
  step(): boolean {
    this.#check(); if (this.#working) throw new RPCProtocolError("query_busy");
    if (this.#phase === "done") return true;
    this.#working = true;
    try {
      const writer = new FixedCBORWriter(this.#scratch);
      if (this.#phase === "envelope") {
        this.#append(writer.map(1).uint(0).array(this.#choices.length).result()); this.#phase = "head";
      } else {
        const choice = this.#choices[this.#index]!;
        if (this.#phase === "head") {
          this.#itemStart = this.#offset;
          const available = choice.contract !== undefined;
          writer.map(2 + Number(available) + Number(choice.offer.length !== 0)).uint(0).uint(this.#index).uint(1).uint(choice.code);
          if (!available) { this.#append(writer.result()); this.#nextItem(); }
          else if (choice.status === "available_full") {
            this.#append(writer.uint(2).bytesHeader(choice.contract!.encodedBytes()).result()); this.#phase = "body";
          } else {
            const digest = byteSlice(this.#scratch, 128, 160); choice.contract!.copyDigest(digest);
            this.#append(writer.uint(3).data(digest).result()); this.#phase = "offer";
          }
        } else if (this.#phase === "body") {
          const length = choice.contract!.copyEncodedRange(this.#bodyOffset, this.#scratch);
          this.#append(byteSlice(this.#scratch, 0, length)); this.#bodyOffset += length;
          if (this.#bodyOffset === choice.contract!.encodedBytes()) this.#phase = "offer";
        } else {
          if (choice.offer.length !== 0) this.#append(writer.uint(4).data(choice.offer).result());
          this.#nextItem();
        }
      }
      return this.#done();
    } catch (error) { this.#failure = error; this.close(); throw error; }
    finally { this.#scratch.fill(0); this.#working = false; this.#collect(); }
  }
  get encodedBytes(): number { this.#check(); if (this.#phase !== "done") throw new RPCProtocolError("query_response_incomplete"); return this.#offset; }
  borrow(): RPCPayloadBorrow {
    this.#check(); if (this.#phase !== "done" || this.#borrowed) throw new RPCProtocolError("query_response_incomplete");
    const borrow = this.#payload!.borrow(this.#offset); this.#borrowed = true;
    let released = false;
    return Object.freeze({ bytes: borrow.bytes, release: () => {
      if (released) return; released = true; borrow.release(); this.#borrowed = false; this.#collect();
    } });
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#payload?.close(); this.#collect(); }
  #collect(): void {
    if (!this.#closed || this.#working || this.#borrowed || this.#payload?.cleanupComplete() === false) return;
    for (const choice of this.#choices) { choice.contract?.release(); choice.offer.fill(0); }
    this.#choices.length = 0; this.#request?.release(); this.#request = undefined; this.#payload = undefined;
    this.#scratch.fill(0); this.#scratch = empty; this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
