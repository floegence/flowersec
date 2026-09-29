import { byteSlice, CBORDecoder, cborDecoderCharge, contractCBORDecoderCharge, type CBORDocument, type ContractCBORCursor } from "./cbor.js";
import type { ContractQueryTargets} from "./contractQuery.js";
import { contractQueryTargetResponseBytes } from "./contractQuery.js";
import type { ContractQueryExchange } from "./contractQueryExchange.js";
import type { ContractSnapshotStatus } from "./contractSnapshotWriter.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCCompletion } from "./rpcCompletion.js";
import type { RPCPayload} from "./rpcPayload.js";
import { type RPCPayloadBorrow } from "./rpcPayload.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";
import { AdmissionOffer, ServiceContractCapture } from "./serviceContract.js";
import { wireMaps } from "./schemaRegistry.js";

const capability = Symbol("complete contract snapshot batch");
const empty = new Uint8Array();
const statusCodes = wireMaps.ContractSnapshot!.fields[1]!.enum!;
const statuses = Object.freeze(Object.fromEntries(Object.entries(statusCodes).map(([name, code]) => [code, name as ContractSnapshotStatus])));
function envelopeConfig(runtimeBytes: bigint) { return { bytes: 73728, nodes: 100, textBytes: 0, arrayItems: 8, runtimeBytes }; }
function bodyConfig(runtimeBytes: bigint) { return { bytes: 8192, nodes: 768, textBytes: 128, arrayItems: 64, runtimeBytes }; }
function offerConfig(runtimeBytes: bigint) { return { bytes: 256, nodes: 16, textBytes: 0, arrayItems: 8, runtimeBytes }; }

/** One Session scratch set, reused serially by the original fixed SDK executor.
 * Both large decoders borrow the original exclusive response payload. */
export function contractSnapshotReaderCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return [new ResourceVector([512n + runtimeBytes, 0n, 0n, 12n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]),
    contractCBORDecoderCharge(envelopeConfig(runtimeBytes)), contractCBORDecoderCharge(bodyConfig(runtimeBytes)), cborDecoderCharge(offerConfig(runtimeBytes))];
}
/** Actual delivery copies coexist with the original response until validation
 * finishes. These positions must already belong to the acquisition/current/
 * candidate owner; the reader never allocates another completion or query pool.
 * Unchanged and refusal variants retain the same complete prepaid positions. */
export function contractSnapshotResultCharges(request: ContractQueryTargets, runtimeBytes: bigint): readonly ResourceVector[] {
  return contractSnapshotResultCapacityCharges(request.count, runtimeBytes);
}
export function contractSnapshotResultCapacityCharges(count: number, runtimeBytes: bigint): readonly ResourceVector[] {
  if (!Number.isSafeInteger(count) || count < 1 || count > 8 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const costs = [new ResourceVector([BigInt(count) * 256n + runtimeBytes, 0n, 0n, 9n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])];
  for (let i = 0; i < count; i++) costs.push(new ResourceVector([BigInt(contractQueryTargetResponseBytes) + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
  return costs;
}
export type ContractSnapshotItem = Readonly<{ status: "available_full" | "available_unchanged"; contract: ServiceContractSnapshot; offer: AdmissionOffer | undefined }> |
  Readonly<{ status: "denied" | "unavailable"; contract?: never; offer?: never }>;

/** Complete owned delivery. Items are borrowed from this batch: retain the
 * batch throughout installation, or retain the exact contract before release.
 * No item accessor is available while any target remains unvalidated. */
export class ContractSnapshotBatch {
  #reference: ResourceReference | undefined;
  readonly #positions: (ResourceReference | undefined)[] = [];
  readonly #items: (ContractSnapshotItem | undefined)[] = [];
  #complete = false;
  #owners = 1;
  constructor(token: symbol, request: ContractQueryTargets, runtimeBytes: bigint, references: readonly ResourceReference[]) {
    if (token !== capability) throw new RPCProtocolError("query_result_owner");
    const costs = contractSnapshotResultCharges(request, runtimeBytes);
    if (references.length !== costs.length || !references.every(ref => request.sameEnvironment(ref))) throw new RPCProtocolError("query_result_owner");
    this.#reference = references[0]!.take(costs[0]!);
    try {
      for (let i = 1; i < costs.length; i++) { this.#positions.push(references[i]!.take(costs[i]!)); this.#items.push(undefined); }
      Object.freeze(this);
    } catch (error) { this.release(); throw error; }
  }
  #check(): void { if (this.#reference === undefined) throw new RPCProtocolError("query_result_closed"); this.#reference.checkRetained(); }
  position(token: symbol, index: number): ResourceReference {
    this.#check(); if (token !== capability || this.#complete || this.#positions[index] === undefined) throw new RPCProtocolError("query_result_owner");
    return this.#positions[index]!;
  }
  put(token: symbol, index: number, item: ContractSnapshotItem): void {
    this.#check();
    if (token !== capability || this.#complete || !Number.isSafeInteger(index) || index < 0 || index >= this.#items.length || this.#items[index] !== undefined) throw new RPCProtocolError("query_result_owner");
    // A full body's original position has moved into its snapshot. All other
    // variants keep the unspent full position until this result is released.
    if (item.status === "available_full") this.#positions[index] = undefined;
    this.#items[index] = Object.freeze(item);
  }
  finish(token: symbol): void {
    this.#check(); if (token !== capability || this.#items.some(item => item === undefined)) throw new RPCProtocolError("query_result_incomplete");
    this.#complete = true;
  }
  retain(): this { this.#check(); if (!this.#complete || this.#owners === 65536) throw new RPCProtocolError("query_result_incomplete"); this.#owners++; return this; }
  get count(): number { this.#check(); if (!this.#complete) throw new RPCProtocolError("query_result_incomplete"); return this.#items.length; }
  item(index: number): ContractSnapshotItem {
    this.#check(); if (!this.#complete || !Number.isSafeInteger(index) || index < 0 || index >= this.#items.length) throw new RPCProtocolError("query_target_index");
    return this.#items[index]!;
  }
  release(): void {
    if (this.#owners === 0 || --this.#owners !== 0) return;
    for (const item of this.#items) item?.contract?.release();
    for (const position of this.#positions) position?.release();
    this.#items.length = this.#positions.length = 0; this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
  toJSON(): object { return {}; }
}

/** Incremental client response validation. Each call performs one bounded
 * syntax/schema step, one target association, <= 4 KiB of copy/hash work, or
 * one <= 256-byte Offer decode. The original exclusive payload borrow spans
 * every body decoder and capture; cancellation releases it only after those
 * users have detached. Scheduling and query permission remain external gates. */
export class ContractSnapshotReader {
  #reference: ResourceReference | undefined;
  #envelopeDecoder: CBORDecoder | undefined;
  #bodyDecoder: CBORDecoder | undefined;
  #offerDecoder: CBORDecoder | undefined;
  #scratch = empty;
  #request: ContractQueryTargets | undefined;
  #borrow: RPCPayloadBorrow | undefined;
  #completion: RPCCompletion | undefined;
  #exchange: ContractQueryExchange | undefined;
  #cursor: ContractCBORCursor | undefined;
  #envelope: CBORDocument | undefined;
  #capture: ServiceContractCapture | undefined;
  #contract: ServiceContractSnapshot | undefined;
  #result: ContractSnapshotBatch | undefined;
  readonly #windows: bigint[] = [];
  #phase: "idle" | "envelope" | "item" | "body" | "capture" | "offer" | "done" = "idle";
  #index = 0;
  #item = -1;
  #status: ContractSnapshotStatus = "unavailable";
  #closed = false;
  #working = false;
  constructor(readonly runtimeBytes: bigint, references: readonly ResourceReference[]) {
    const costs = contractSnapshotReaderCharges(runtimeBytes);
    if (references.length !== costs.length || !references.every(ref => references[0]!.sameEnvironment(ref))) throw new RPCProtocolError("query_decoder_owner");
    this.#reference = references[0]!.take(costs[0]!);
    try {
      this.#envelopeDecoder = CBORDecoder.contractScratch(envelopeConfig(runtimeBytes), references[1]!);
      this.#bodyDecoder = CBORDecoder.contractScratch(bodyConfig(runtimeBytes), references[2]!);
      this.#offerDecoder = new CBORDecoder(offerConfig(runtimeBytes), references[3]!);
      this.#scratch = new Uint8Array(512); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void {
    if (this.#closed) throw new RPCProtocolError("query_decoder_closed");
    if (this.#working) throw new RPCProtocolError("query_busy");
    this.#reference!.check();
    if (this.#exchange !== undefined) {
      this.#working = true;
      try { this.#exchange.checkDelivery(); }
      catch (error) { this.#reset(); throw error; }
      finally { this.#working = false; if (this.#closed) this.#cleanup(); }
      if (this.#closed) throw new RPCProtocolError("query_decoder_closed");
    }
    if (this.#completion !== undefined) {
      const progress = this.#completion.progress();
      if (progress.abandoned || !progress.done || progress.failure !== undefined || progress.sdkError !== undefined) {
        this.#reset(); throw new RPCProtocolError("query_result_unavailable");
      }
    }
  }
  beginResponse(exchange: ContractQueryExchange, maxOfferWindowsMS: readonly bigint[], references: readonly ResourceReference[]): void {
    this.#check(); if (this.#phase !== "idle") throw new RPCProtocolError("query_busy");
    const { targets: request, completion } = exchange.claimResponse();
    const progress = completion.progress();
    if (completion.request.kind !== "query_contracts_request" || completion.request.payloadBytes !== request.encodedBytes ||
        completion.responseLimit !== request.responseBytes || progress.header?.kind !== "query_contracts_response" || !progress.done ||
        progress.abandoned || progress.failure !== undefined || progress.sdkError !== undefined) throw new RPCProtocolError("query_response_binding");
    this.#begin(request, completion, progress.header.payloadBytes, maxOfferWindowsMS, references);
    this.#exchange = exchange;
  }
  /** Shared shape for the separately authorized bootstrap snapshot section.
   * This entry does not grant RPC source or bootstrap trust. */
  beginPayload(request: ContractQueryTargets, payload: RPCPayload, length: number, maxOfferWindowsMS: readonly bigint[], references: readonly ResourceReference[]): void {
    this.#begin(request, payload, length, maxOfferWindowsMS, references);
  }
  #begin(request: ContractQueryTargets, payload: RPCPayload | RPCCompletion, length: number, maxOfferWindowsMS: readonly bigint[], references: readonly ResourceReference[]): void {
    this.#check(); if (this.#phase !== "idle") throw new RPCProtocolError("query_busy");
    this.#working = true;
    try {
      if (!request.local || !request.sameEnvironment(this.#reference!) || !payload.sameEnvironment(this.#reference!) ||
          !Number.isSafeInteger(length) || length < 1 || length > request.responseBytes ||
          !Array.isArray(maxOfferWindowsMS) || maxOfferWindowsMS.length !== request.count) throw new RPCProtocolError("query_response_size");
      for (let i = 0; i < request.count; i++) {
        const window = maxOfferWindowsMS[i];
        if (typeof window !== "bigint" || window < 1n || window >= 1n << 64n) throw new RPCProtocolError("admission_offer_unavailable");
        this.#windows.push(window);
      }
      if (this.#closed) throw new RPCProtocolError("query_decoder_closed");
      this.#result = new ContractSnapshotBatch(capability, request, this.runtimeBytes, references);
      this.#request = request.retain();
      if (payload instanceof RPCCompletion) { this.#completion = payload; this.#borrow = payload.borrow(); }
      else this.#borrow = payload.borrow(length);
      this.#cursor = this.#envelopeDecoder!.beginContractMap(this.#borrow.bytes, "ContractSnapshots"); this.#phase = "envelope";
    } catch (error) { this.#reset(); throw error; }
    finally { this.#working = false; if (this.#closed) this.#cleanup(); }
  }
  #next(): void {
    this.#index++;
    if (this.#index === this.#request!.count) {
      this.#result!.finish(capability); this.#phase = "done";
      this.#envelope!.release(); this.#envelope = undefined;
      this.#borrow!.release(); this.#borrow = undefined; this.#request!.release(); this.#request = undefined; this.#windows.length = 0;
    } else { this.#item = this.#envelope!.nextSibling(this.#item); this.#phase = "item"; }
  }
  #finished(): boolean { return this.#phase === "done"; }
  step(): boolean {
    this.#check(); if (this.#phase === "idle") throw new RPCProtocolError("query_decoder_idle");
    if (this.#phase === "done") return true;
    this.#working = true;
    try {
      if (this.#phase === "envelope") {
        if (this.#cursor!.step()) {
          this.#envelope = this.#cursor!.take(); this.#cursor = undefined;
          const items = this.#envelope.field(0, 0);
          if (this.#envelope.schema() !== "ContractSnapshotsEnvelope" || this.#envelope.size(items) !== this.#request!.count) throw new RPCProtocolError("query_response_count");
          this.#item = this.#envelope.firstChild(items); this.#phase = "item";
        }
      } else if (this.#phase === "item") {
        const doc = this.#envelope!, item = this.#item;
        if (doc.uint(doc.field(item, 0)) !== BigInt(this.#index)) throw new RPCProtocolError("query_target_index");
        const status = statuses[Number(doc.uint(doc.field(item, 1)))];
        if (status === undefined) throw new RPCProtocolError("query_response_status");
        this.#status = status;
        if (status === "denied" || status === "unavailable") { this.#result!.put(capability, this.#index, { status }); this.#next(); }
        else if (status === "available_unchanged") {
          doc.copyPayload(doc.field(item, 3), this.#scratch);
          this.#contract = this.#request!.unchanged(this.#index, byteSlice(this.#scratch, 0, 32)); this.#phase = "offer";
        } else {
          const body = doc.field(item, 2), start = doc.encodedOffset(body, true);
          this.#cursor = this.#bodyDecoder!.beginContractMap(byteSlice(this.#borrow!.bytes, start, start + doc.size(body)), "ServiceContract"); this.#phase = "body";
        }
      } else if (this.#phase === "body") {
        if (this.#cursor!.step()) {
          const doc = this.#cursor!.take(); this.#cursor = undefined;
          try { this.#capture = new ServiceContractCapture(doc, this.runtimeBytes, this.#result!.position(capability, this.#index)); }
          catch (error) { doc.release(); throw error; }
          this.#phase = "capture";
        }
      } else if (this.#phase === "capture") {
        if (this.#capture!.step()) {
          this.#contract = this.#capture!.take(); this.#capture = undefined;
          this.#request!.checkAvailable(this.#index, this.#contract); this.#phase = "offer";
        }
      } else {
        const contract = this.#contract!, offerNode = this.#envelope!.field(this.#item, 4);
        if ((offerNode >= 0) !== (contract.semantics === "execution")) throw new RPCProtocolError("query_offer_presence");
        let offer: AdmissionOffer | undefined;
        if (offerNode >= 0) {
          const length = this.#envelope!.copyPayload(offerNode, this.#scratch);
          const doc = this.#offerDecoder!.decodeMap(byteSlice(this.#scratch, 0, length), "AdmissionOffer");
          try { offer = new AdmissionOffer(doc, contract, this.#windows[this.#index]!, byteSlice(this.#scratch, 256, 288)); }
          finally { doc.release(); }
        }
        if (this.#status !== "available_full" && this.#status !== "available_unchanged") throw new RPCProtocolError("query_response_status");
        this.#result!.put(capability, this.#index, { status: this.#status, contract, offer }); this.#contract = undefined; this.#next();
      }
      return this.#finished();
    } catch (error) { this.#reset(); throw error; }
    finally { this.#scratch.fill(0); this.#working = false; if (this.#closed) this.#cleanup(); }
  }
  take(): ContractSnapshotBatch {
    this.#check(); if (this.#phase !== "done" || this.#result === undefined) throw new RPCProtocolError("query_result_incomplete");
    const result = this.#result; this.#result = undefined; this.#reset(); return result;
  }
  cancel(): void { if (this.#working) throw new RPCProtocolError("query_busy"); this.#reset(); }
  #reset(): void {
    this.#cursor?.close(); this.#cursor = undefined; this.#capture?.close(); this.#capture = undefined;
    this.#contract?.release(); this.#contract = undefined; this.#result?.release(); this.#result = undefined;
    this.#envelope?.release(); this.#envelope = undefined;
    this.#borrow?.release(); this.#borrow = undefined; this.#request?.release(); this.#request = undefined;
    this.#completion = undefined;
    this.#exchange = undefined;
    this.#scratch.fill(0); this.#windows.length = 0; this.#phase = "idle"; this.#index = 0; this.#item = -1;
  }
  close(): void { this.#closed = true; if (!this.#working) this.#cleanup(); }
  #cleanup(): void {
    this.#reset(); this.#envelopeDecoder?.close(); this.#envelopeDecoder = undefined;
    this.#bodyDecoder?.close(); this.#bodyDecoder = undefined; this.#offerDecoder?.close(); this.#offerDecoder = undefined;
    this.#scratch = empty; this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
for (const constructor of [ContractSnapshotBatch, ContractSnapshotReader]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
