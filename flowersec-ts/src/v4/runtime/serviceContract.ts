import { sha256 } from "@noble/hashes/sha2.js";
import { transportV4ApplicationHeaders as application } from "../../generated/transportV4Registry.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import { checkContractAcceptance, type ContractAcceptance } from "./contractAcceptance.js";
import { credentialDigest } from "./credentialSupport.js";
import { FixedCBORWriter } from "./cborWriter.js";
import type { TrustedClock } from "./clock.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { wireDomains } from "./schemaRegistry.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";

export type ServiceCallShape = "unary" | "server_streaming" | "notify";
export type ServiceSemantics = "transient" | "execution" | "observation";
export interface ServiceMethodIdentity {
  readonly namespace: string;
  readonly typeID: number;
  readonly shape: ServiceCallShape;
  readonly semantics: ServiceSemantics;
  readonly requestRevision: string;
  readonly responseRevision: string;
}
const empty = new Uint8Array();
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const requestShapes: Readonly<Record<string, Readonly<Record<string, number>>>> = application.policy.contract_variants;
function contractDecoderConfig(runtimeBytes: bigint) { return { bytes: 8192, nodes: 1024, textBytes: 128, arrayItems: 64, runtimeBytes }; }
export function serviceContractDecoderCharge(runtimeBytes: bigint): ResourceVector { return cborDecoderCharge(contractDecoderConfig(runtimeBytes)); }
export function serviceContractCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  // Exact immutable encoded body, digest, comparisons, domain hashing and
  // compact scalar/string projections and the 29 root field spans. The decoder
  // is shared scratch; it is not retained once the complete body is captured.
  return new ResourceVector([8192n + 32n + 512n + 256n + 116n + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
// This is an accessor over an already schema-validated, privately owned body,
// not a parser entry point. Node identities are canonical byte offsets. Keeping
// only 29 root field spans avoids retaining a full decoder arena per result.
class ContractBody {
  readonly #fields = new Uint16Array(29);
  readonly #ends = new Uint16Array(29);
  constructor(readonly bytes: Uint8Array, document: CBORDocument) {
    if (document.schema() !== "ServiceContract" || document.encodedSize() !== bytes.length) throw new RPCProtocolError("service_contract_body");
    for (let id = 0; id < this.#fields.length; id++) {
      const node = document.field(0, id);
      this.#fields[id] = node < 0 ? 0xffff : document.encodedOffset(node);
      this.#ends[id] = node < 0 ? 0xffff : this.#fields[id]! + document.encodedSize(node);
    }
  }
  #head(node: number): { major: number; value: bigint; payload: number } {
    if (!Number.isSafeInteger(node) || node < 0 || node >= this.bytes.length) throw new RPCProtocolError("service_contract_body");
    const head = this.bytes[node++]!, additional = head & 31;
    let value = BigInt(additional);
    if (additional >= 24) { value = 0n; for (let i = 0; i < 2 ** (additional - 24); i++) value = value * 256n + BigInt(this.bytes[node++]!); }
    return { major: head >>> 5, value, payload: node };
  }
  #end(node: number): number {
    // Root field spans include the complete error catalog/content definition;
    // policy comparisons never rescan their descendants for every copy chunk.
    for (let id = 0; id < this.#fields.length; id++) if (this.#fields[id] === node) return this.#ends[id]!;
    const h = this.#head(node);
    if (h.major === 2 || h.major === 3) return h.payload + Number(h.value);
    if (h.major !== 4 && h.major !== 5) return h.payload;
    let end = h.payload;
    for (let count = Number(h.value) * (h.major === 5 ? 2 : 1); count > 0; count--) end = this.#end(end);
    return end;
  }
  schema(): string { return "ServiceContract"; }
  field(node: number, id: number): number {
    if (node === 0) { const value = this.#fields[id]; return value === undefined || value === 0xffff ? -1 : value; }
    const h = this.#head(node); if (h.major !== 5) throw new RPCProtocolError("service_contract_body");
    let at = h.payload;
    for (let count = Number(h.value); count > 0; count--) {
      const key = this.#head(at), value = key.payload;
      if (key.value === BigInt(id)) return value; at = this.#end(value);
    }
    return -1;
  }
  uint(node: number): bigint { const h = this.#head(node); if (h.major !== 0) throw new RPCProtocolError("service_contract_body"); return h.value; }
  boolean(node: number): boolean { const h = this.#head(node); if (h.major !== 7 || h.value !== 20n && h.value !== 21n) throw new RPCProtocolError("service_contract_body"); return h.value === 21n; }
  text(node: number): string { const h = this.#head(node); if (h.major !== 3) throw new RPCProtocolError("service_contract_body"); return utf8.decode(byteSlice(this.bytes, h.payload, h.payload + Number(h.value))); }
  size(node: number): number { return Number(this.#head(node).value); }
  firstChild(node: number): number { return this.#head(node).payload; }
  nextSibling(node: number): number { return this.#end(node); }
  encodedSize(node = 0): number { return node === 0 ? this.bytes.length : this.#end(node) - node; }
  copyRange(node: number, offset: number, destination: Uint8Array): number {
    const size = this.encodedSize(node);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > size) throw new RPCProtocolError("configuration_capacity");
    const length = Math.min(byteLength(destination), size - offset);
    Uint8Array.prototype.set.call(destination, byteSlice(this.bytes, node + offset, node + offset + length)); return length;
  }
  copyPayload(node: number, destination: Uint8Array): number {
    const h = this.#head(node), length = Number(h.value);
    if (h.major !== 2 && h.major !== 3 || byteLength(destination) < length) throw new RPCProtocolError("configuration_capacity");
    Uint8Array.prototype.set.call(destination, byteSlice(this.bytes, h.payload, h.payload + length)); return length;
  }
  release(): void { this.#fields.fill(0xffff); this.#ends.fill(0xffff); }
}
class SnapshotMaterial {
  constructor(readonly reference: ResourceReference, readonly encoded: Uint8Array, readonly digest: Uint8Array,
    readonly scratch: Uint8Array, readonly document: ContractBody) {}
}

/** Owns a completely schema-validated document while copying/hashing its exact
 * body in bounded steps. Only this owner can mint incremental snapshot material.
 * The document and its original input borrow must remain exclusive until done. */
export class ServiceContractCapture {
  #reference: ResourceReference | undefined;
  #document: CBORDocument | undefined;
  #encoded = empty;
  #digest = empty;
  #scratch = empty;
  #body: ContractBody | undefined;
  #hash: ReturnType<typeof sha256.create> | undefined;
  #offset = 0;
  #done = false;
  constructor(document: CBORDocument, readonly runtimeBytes: bigint, reference: ResourceReference) {
    if (document.schema() !== "ServiceContract" || document.encodedSize() > 8192 || !document.sameEnvironment(reference)) throw new RPCProtocolError("service_contract_body");
    this.#reference = reference.take(serviceContractCharge(runtimeBytes));
    this.#document = document;
    try {
      this.#encoded = new Uint8Array(document.encodedSize()); this.#digest = new Uint8Array(32); this.#scratch = new Uint8Array(768);
      const domain = wireDomains.find(value => value.name === "service_contract_digest");
      if (domain?.operation !== "sha256" || domain.input_schema.parts.length !== 1 || domain.input_schema.parts[0]!.encoding !== "lp-map" ||
          domain.input_schema.parts[0]!.projection !== "full" || domain.label_bytes.length > 512) throw new RPCProtocolError("registry_unresolved");
      const label = domain.label_bytes;
      for (let n = 0; n < label.length; n += 2) this.#scratch[n / 2] = Number.parseInt(label.slice(n, n + 2), 16);
      this.#hash = sha256.create(); this.#hash.update(byteSlice(this.#scratch, 0, label.length / 2));
      const length = this.#encoded.length;
      this.#scratch[0] = length >>> 24; this.#scratch[1] = length >>> 16; this.#scratch[2] = length >>> 8; this.#scratch[3] = length;
      this.#hash.update(byteSlice(this.#scratch, 0, 4)); this.#scratch.fill(0);
    } catch (error) { this.close(); throw error; }
  }
  step(): boolean {
    if (this.#reference === undefined) throw new RPCProtocolError("service_contract_closed");
    this.#reference.checkRetained(); if (this.#done) return true;
    try {
      if (this.#offset < this.#encoded.length) {
        // Copy + hash together touch at most 4 KiB in this step.
        const part = byteSlice(this.#encoded, this.#offset, Math.min(this.#offset + 2048, this.#encoded.length));
        this.#document!.copyRange(0, this.#offset, part); this.#hash!.update(part); this.#offset += part.length;
        return false;
      }
      this.#hash!.digestInto(this.#digest); this.#hash!.destroy(); this.#hash = undefined;
      this.#body = new ContractBody(this.#encoded, this.#document!);
      this.#document!.release(); this.#document = undefined; this.#done = true; return true;
    } catch (error) { this.close(); throw error; }
  }
  take(): ServiceContractSnapshot {
    if (!this.#done || this.#reference === undefined) throw new RPCProtocolError("service_contract_incomplete");
    this.#reference.checkRetained();
    const material = new SnapshotMaterial(this.#reference, this.#encoded, this.#digest, this.#scratch, this.#body!);
    this.#reference = undefined; this.#encoded = this.#digest = this.#scratch = empty; this.#body = undefined;
    return new ServiceContractSnapshot(material, this.runtimeBytes);
  }
  close(): void {
    this.#document?.release(); this.#document = undefined; this.#hash?.destroy(); this.#hash = undefined;
    this.#body?.release(); this.#body = undefined; this.#encoded.fill(0); this.#digest.fill(0); this.#scratch.fill(0);
    this.#encoded = this.#digest = this.#scratch = empty; this.#reference?.release(); this.#reference = undefined;
  }
}

/** The exact complete contract remains alive for binding, query-known, request
 * digest and execution/result owners. It is never reconstructed from a digest. */
export class ServiceContractSnapshot {
  #reference: ResourceReference | undefined;
  #document: ContractBody | undefined;
  #encoded: Uint8Array = empty;
  #digest: Uint8Array = empty;
  #scratch: Uint8Array = empty;
  #owners = 1;
  readonly namespace: string;
  readonly typeID: number;
  readonly shape: ServiceCallShape;
  readonly semantics: ServiceSemantics;
  readonly requestRevision: string;
  readonly responseRevision: string;
  readonly requestMaxBytes: number;
  readonly minResponseBytes: number;
  readonly maxResponseBytes: number;
  constructor(encoded: Uint8Array | SnapshotMaterial, runtimeBytes: bigint, reference?: ResourceReference, decoder?: ResourceReference) {
    let parsing: CBORDecoder | undefined, source: CBORDocument | undefined;
    try {
      if (encoded instanceof SnapshotMaterial) {
        this.#reference = encoded.reference; this.#encoded = encoded.encoded; this.#digest = encoded.digest;
        this.#scratch = encoded.scratch; this.#document = encoded.document;
      } else {
        if (reference === undefined || decoder === undefined || !reference.sameEnvironment(decoder)) throw new RPCProtocolError("service_contract_owner");
        this.#reference = reference.take(serviceContractCharge(runtimeBytes));
        parsing = new CBORDecoder(contractDecoderConfig(runtimeBytes), decoder);
        source = parsing.decodeMap(encoded, "ServiceContract");
        this.#encoded = new Uint8Array(source.encodedSize()); source.copyEncoded(0, this.#encoded);
        this.#digest = credentialDigest("service_contract_digest", this.#encoded); this.#scratch = new Uint8Array(768);
        this.#document = new ContractBody(this.#encoded, source);
      }
      const doc = this.#document;
      const shape = Number(doc.uint(doc.field(0, 2))), semantics = Number(doc.uint(doc.field(0, shape + 3)));
      this.namespace = doc.text(doc.field(0, 0)); this.typeID = Number(doc.uint(doc.field(0, 1)));
      this.shape = (["unary", "server_streaming", "notify"] as const)[shape]!;
      this.semantics = semantics === 1 ? "execution" : shape === 2 ? "observation" : "transient";
      this.requestRevision = doc.text(doc.field(0, 6)); this.responseRevision = doc.text(doc.field(0, 7));
      this.requestMaxBytes = Number(doc.uint(doc.field(0, 23)));
      this.minResponseBytes = Number(doc.uint(doc.field(0, 9))); this.maxResponseBytes = Number(doc.uint(doc.field(0, 10)));
      Object.freeze(this);
    } catch (error) { this.release(); throw error; }
    finally { source?.release(); parsing?.close(); }
  }
  #check(): ContractBody {
    if (this.#owners === 0 || this.#document === undefined) throw new RPCProtocolError("service_contract_closed");
    this.#reference!.checkRetained(); return this.#document;
  }
  retain(): this { this.#check(); if (this.#owners >= 65536) throw new RPCProtocolError("resource_exhausted"); this.#owners++; return this; }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  matchesIdentity(identity: ServiceMethodIdentity): boolean {
    const { namespace, typeID, shape, semantics, requestRevision, responseRevision } = identity;
    this.#check();
    return namespace === this.namespace && typeID === this.typeID && shape === this.shape && semantics === this.semantics &&
      requestRevision === this.requestRevision && responseRevision === this.responseRevision;
  }
  hasDigest(digest: Uint8Array): boolean {
    this.#check(); if (byteLength(digest) !== 32) return false;
    let difference = 0; for (let n = 0; n < 32; n++) difference |= digest[n]! ^ this.#digest[n]!; return difference === 0;
  }
  copyDigest(destination: Uint8Array): void {
    this.#check(); if (byteLength(destination) < 32) throw new RPCProtocolError("configuration_capacity");
    Uint8Array.prototype.set.call(destination, this.#digest);
  }
  encodedBytes(): number { this.#check(); return this.#encoded.length; }
  copyEncoded(destination: Uint8Array): number {
    this.#check(); if (byteLength(destination) < this.#encoded.length) throw new RPCProtocolError("configuration_capacity");
    Uint8Array.prototype.set.call(destination, this.#encoded); return this.#encoded.length;
  }
  copyEncodedRange(offset: number, destination: Uint8Array): number {
    this.#check();
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > this.#encoded.length) throw new RPCProtocolError("configuration_capacity");
    const length = Math.min(byteLength(destination), this.#encoded.length - offset);
    Uint8Array.prototype.set.call(destination, byteSlice(this.#encoded, offset, offset + length)); return length;
  }
  uint(id: number): bigint { const doc = this.#check(); return doc.uint(doc.field(0, id)); }
  optionalUint(id: number): bigint | undefined { const doc = this.#check(), node = doc.field(0, id); return node < 0 ? undefined : doc.uint(node); }
  optionalText(id: number): string | undefined { const doc = this.#check(), node = doc.field(0, id); return node < 0 ? undefined : doc.text(node); }
  boolean(id: number): boolean { const doc = this.#check(); return doc.boolean(doc.field(0, id)); }
  streamContentMode(): "none" | "retained" | undefined {
    const doc = this.#check(), policy = doc.field(0, 28);
    return policy < 0 ? undefined : doc.uint(doc.field(policy, 0)) === 0n ? "none" : "retained";
  }
  accepts(candidate: ServiceContractSnapshot, policy: ContractAcceptance, explicitUpdate = false): void {
    const original = this.#check(), next = candidate.#check();
    try { checkContractAcceptance(next, original, policy, byteSlice(this.#scratch, 0, 512), explicitUpdate); }
    finally { this.#scratch.fill(0); }
  }
  checkPolicy(policy: ContractAcceptance): void {
    try { checkContractAcceptance(this.#check(), undefined, policy, byteSlice(this.#scratch, 0, 512)); }
    finally { this.#scratch.fill(0); }
  }
  checkMethod(namespace: string, method: CapturedMethodDefinition): void {
    const doc = this.#check();
    if (!this.matchesIdentity({ namespace, typeID: method.typeID, shape: method.shape, semantics: method.semantics,
      requestRevision: method.request.revision, responseRevision: method.responseRevision }) ||
      this.requestMaxBytes > method.requestMaxBytes || this.minResponseBytes < method.minResponseLimitBytes || this.maxResponseBytes > method.maxResponseBytes ||
      doc.boolean(doc.field(0, 21)) !== method.restartFlush || this.optionalUint(22) !== method.restartFlushDeadlineMS ||
      method.requireDurable && this.optionalUint(13) !== 1n) throw new RPCProtocolError("service_definition_mismatch");
    const content = doc.field(0, 28), expectedContent = method.streamContent;
    if ((content >= 0 && doc.uint(doc.field(content, 0)) === 1n) !== (expectedContent !== undefined)) throw new RPCProtocolError("service_definition_mismatch");
    if (expectedContent !== undefined) {
      const node = doc.field(content, 6), bytes = new Uint8Array(doc.size(node));
      try {
        doc.copyPayload(node, bytes);
        if (doc.text(doc.field(content, 5)) !== expectedContent.schemaRevision || bytes.length !== expectedContent.canonical.length || bytes.some((value, i) => value !== expectedContent.canonical[i])) throw new RPCProtocolError("service_definition_mismatch");
      } finally { bytes.fill(0); }
    }
    const checkpoint = doc.field(0, 20);
    if ((checkpoint < 0 ? undefined : doc.text(checkpoint)) !== method.checkpointFormat) throw new RPCProtocolError("service_definition_mismatch");
    if (method.shape === "server_streaming" && (this.uint(24) > BigInt(method.maxItemCount!) || this.uint(25) > method.maxStreamPayloadBytes! || this.uint(26) > method.maxStreamDurationMS!)) throw new RPCProtocolError("service_definition_mismatch");
    const catalog = doc.field(0, 27);
    if (doc.size(catalog) !== method.errors.length) throw new RPCProtocolError("service_definition_mismatch");
    let index = 0;
    try {
      for (let node = doc.firstChild(catalog); index < method.errors.length; node = doc.nextSibling(node)) {
        const expected = method.errors[index++]!;
        if (doc.uint(doc.field(node, 0)) !== BigInt(expected.code) || doc.text(doc.field(node, 1)) !== expected.codec.revision ||
            doc.uint(doc.field(node, 2)) > BigInt(expected.maximum)) throw new RPCProtocolError("service_definition_mismatch");
        doc.copyPayload(doc.field(node, 3), this.#scratch);
        let different = 0; for (let j = 0; j < 32; j++) different |= this.#scratch[j]! ^ expected.codec.schema[j]!;
        if (different !== 0) throw new RPCProtocolError("service_definition_mismatch");
      }
    } finally { this.#scratch.fill(0); }
  }
  checkRequest(header: ApplicationHeader): void {
    const doc = this.#check(), variant = requestShapes[header.kind];
    if (variant === undefined || header.typeID !== this.typeID) throw new RPCProtocolError("application_contract_variant");
    for (const [id, expected] of Object.entries(variant)) {
      const node = doc.field(0, Number(id)); if (node < 0 || doc.uint(node) !== BigInt(expected)) throw new RPCProtocolError("application_contract_variant");
    }
    header.copyBytes(6, this.#scratch);
    try { if (!this.hasDigest(byteSlice(this.#scratch, 0, 32))) throw new RPCProtocolError("service_contract_mismatch"); }
    finally { this.#scratch.fill(0); }
    if (header.payloadBytes > this.requestMaxBytes) throw new RPCProtocolError("application_request_limit");
    if (header.has(8) && (header.uint(8) < BigInt(this.minResponseBytes) || header.uint(8) > BigInt(this.maxResponseBytes))) throw new RPCProtocolError("response_limit_unsupported");
  }
  /** Check the original error catalog even for an abandoned late response.
   * This reads only validated contract scalars and never enters a codec. */
  checkResponse(request: ApplicationHeader, response: ApplicationHeader): void {
    this.checkRequest(request); response.checkResponse(request);
    if (!response.isApplicationError()) return;
    const doc = this.#check(), catalog = doc.field(0, 27), code = response.uint(10);
    for (let node = doc.firstChild(catalog), left = doc.size(catalog); left > 0; left--, node = doc.nextSibling(node)) {
      if (doc.uint(doc.field(node, 0)) !== code) continue;
      if (BigInt(response.payloadBytes) > doc.uint(doc.field(node, 2))) throw new RPCProtocolError("application_error_limit");
      return;
    }
    throw new RPCProtocolError("application_error_code");
  }
  /** Initialize the original execution domain before streaming payload input.
   * The enclosing input owner must prepay the hasher and its backing. */
  seedExecutionHash(header: ApplicationHeader, hash: ReturnType<typeof sha256.create>, rejectionOnly = false): void {
    if (rejectionOnly) {
      this.#check(); header.copyBytes(6, this.#scratch);
      try { if (!this.hasDigest(byteSlice(this.#scratch, 0, 32))) throw new RPCProtocolError("service_contract_mismatch"); }
      finally { this.#scratch.fill(0); }
    } else this.checkRequest(header);
    if (!header.has(1) || header.isResponse() || !rejectionOnly && this.semantics !== "execution") throw new RPCProtocolError("application_execution_request");
    const domain = wireDomains.find(value => value.name === "execution_request_digest");
    if (domain?.operation !== "sha256" || domain.input_schema.parts.at(-1)?.name !== "payload") throw new RPCProtocolError("registry_unresolved");
    const integer = (number: bigint, width: number): void => {
      if (number < 0n || number >= 1n << BigInt(width * 8)) throw new RPCProtocolError("application_integer_range");
      for (let n = width - 1; n >= 0; n--) { this.#scratch[n] = Number(number & 255n); number >>= 8n; }
      hash.update(byteSlice(this.#scratch, 0, width));
    };
    const bytes = (value: Uint8Array): void => { integer(BigInt(byteLength(value)), 4); hash.update(value); };
    try {
      const label = domain.label_bytes;
      if (label.length / 2 > this.#scratch.length) throw new RPCProtocolError("registry_unresolved");
      for (let n = 0; n < label.length; n += 2) this.#scratch[n / 2] = Number.parseInt(label.slice(n, n + 2), 16);
      hash.update(byteSlice(this.#scratch, 0, label.length / 2));
      for (const part of domain.input_schema.parts) {
        if (part.name === "contract" && part.encoding === "lp-map") bytes(this.#encoded);
        else if (part.name === "payload" && part.encoding === "lp-bytes") integer(BigInt(header.payloadBytes), 4);
        else if (part.name === "operation_id" && part.encoding === "lp-bytes") {
          const id = byteSlice(this.#scratch, 32, 64); header.copyBytes(1, id); bytes(id);
        } else {
          const id = ({ message_kind: 0, type_id: 2, deadline_at_ms: 5, admission_mode: 7, response_limit_bytes: 8 } as Readonly<Record<string, number>>)[part.name];
          const width = ({ u8: 1, u32: 4, u64: 8 } as Readonly<Record<string, number>>)[part.encoding];
          if (id === undefined || width === undefined) throw new RPCProtocolError("registry_unresolved"); integer(header.uint(id), width);
        }
      }
    } finally { this.#scratch.fill(0); }
  }
  /** Hash the original request. Responses only echo its digest. */
  executionDigest(header: ApplicationHeader, payload: Uint8Array, destination: Uint8Array): void {
    if (byteLength(payload) !== header.payloadBytes || byteLength(destination) < 32) throw new RPCProtocolError("application_execution_request");
    const hash = sha256.create();
    try { this.seedExecutionHash(header, hash); hash.update(payload); hash.digestInto(byteSlice(destination, 0, 32)); }
    finally { hash.destroy(); }
  }
  verifyExecution(header: ApplicationHeader, payload: Uint8Array): void {
    // Destination avoids the domain workspace cleared by executionDigest.
    const expected = new Uint8Array(32), actual = new Uint8Array(32);
    try {
      this.executionDigest(header, payload, expected); header.copyBytes(4, actual);
      let difference = 0; for (let n = 0; n < 32; n++) difference |= expected[n]! ^ actual[n]!;
      if (difference !== 0) throw new RPCProtocolError("application_request_digest");
    } finally { expected.fill(0); actual.fill(0); }
  }
  release(): void {
    if (this.#owners === 0 || --this.#owners !== 0) return;
    this.#document?.release(); this.#document = undefined;
    this.#encoded.fill(0); this.#digest.fill(0); this.#scratch.fill(0); this.#encoded = this.#digest = this.#scratch = empty;
    this.#reference?.release(); this.#reference = undefined;
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ServiceContractSnapshot"; }
}

/** Immutable admission advertisement for one exact execution contract. It
 * conveys a window only; authorization, runtime capacity and once admission
 * still belong to the original request/registration owner. */
export class AdmissionOffer {
  readonly #digest: Uint8Array;
  readonly notBeforeMS: bigint;
  readonly notAfterMS: bigint;
  constructor(document: CBORDocument, contract: ServiceContractSnapshot, maxWindowMS: bigint, scratch: Uint8Array) {
    if (document.schema() !== "AdmissionOffer" || contract.semantics !== "execution" || typeof maxWindowMS !== "bigint" || maxWindowMS < 1n || maxWindowMS > (1n << 64n) - 1n || byteLength(scratch) < 32) throw new RPCProtocolError("admission_offer_unavailable");
    document.copyPayload(document.field(0, 0), scratch);
    if (!contract.hasDigest(byteSlice(scratch, 0, 32))) throw new RPCProtocolError("service_contract_mismatch");
    this.notBeforeMS = document.uint(document.field(0, 1)); this.notAfterMS = document.uint(document.field(0, 2));
    if (this.notAfterMS - this.notBeforeMS > maxWindowMS) throw new RPCProtocolError("admission_offer_unavailable");
    this.#digest = new Uint8Array(byteSlice(scratch, 0, 32));
    Object.freeze(this);
  }
  check(clock: TrustedClock, contract: ServiceContractSnapshot, cutoff: bigint): void {
    if (!contract.hasDigest(this.#digest)) throw new RPCProtocolError("service_contract_mismatch");
    const now = clock.sample().requireInterval();
    if (now.lowerMS < this.notBeforeMS || now.upperMS >= cutoff || cutoff > this.notAfterMS) throw new RPCProtocolError("admission_window_closed");
  }
  copyEncoded(contract: ServiceContractSnapshot, maxWindowMS: bigint, destination: Uint8Array): number {
    if (contract.semantics !== "execution" || !contract.hasDigest(this.#digest) || maxWindowMS < 1n ||
        this.notBeforeMS >= this.notAfterMS || this.notAfterMS - this.notBeforeMS > maxWindowMS) throw new RPCProtocolError("admission_offer_unavailable");
    return new FixedCBORWriter(destination).map(3).uint(0).data(this.#digest).uint(1).uint(this.notBeforeMS).uint(2).uint(this.notAfterMS).result().length;
  }
}
