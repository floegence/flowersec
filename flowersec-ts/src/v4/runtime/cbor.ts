import { transportV4CBORSyntaxLimits as policy } from "../../generated/transportV4Registry.js";
import type { ResourceReference} from "./resources.js";
import { ResourceVector } from "./resources.js";
import { CanonicalTextWorkspace, canonicalTextBackingBytes, type CanonicalTextFailure } from "./canonicalText.js";
import { captureDecodeContext, preflightMap, SchemaWorkspace, schemaWorkspaceBackingBytes, type CapturedDecodeContext, type DecodeContext } from "./schema.js";

export type CBORFailure = CanonicalTextFailure | "configuration_capacity" | "decoder_busy" | "decoder_closed" | "document_released" |
  "node_capacity" | "map_size" | "truncated" | "trailing_bytes" | "depth_limit" | "indefinite_length" | "unsupported_type" |
  "invalid_header" | "non_shortest_integer" | "array_limit" | "map_limit" | "field_id_type" | "duplicate_key" | "map_order" | "value_type" | "projection_field";
export class CBORWireError extends Error {
  readonly code: CBORFailure;
  constructor(code: CBORFailure) { super(code); this.name = "CBORWireError"; this.code = code; }
}
function reject(code: CBORFailure): never { throw new CBORWireError(code); }
const capability = Symbol("CBOR document");
const contractScratch = Symbol("borrowed contract scratch");
const emptyBytes = new Uint8Array(0), emptyNumbers = new BigUint64Array(0);
const emptyOffsets = new Uint32Array(0), emptyLinks = new Int32Array(0);
const typed = Object.getPrototypeOf(Uint8Array.prototype) as object;
const lengthGetter = Object.getOwnPropertyDescriptor(typed, "length")!.get!;
const bufferGetter = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
const offsetGetter = Object.getOwnPropertyDescriptor(typed, "byteOffset")!.get!;
const tagGetter = Object.getOwnPropertyDescriptor(typed, Symbol.toStringTag)!.get!;
const bufferLengthGetter = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength")!.get!;
const setBytes = Uint8Array.prototype.set;
const sliceView = Uint8Array.prototype.subarray;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export function byteLength(bytes: Uint8Array): number {
  try {
    if (tagGetter.call(bytes) !== "Uint8Array") reject("value_type");
    // This intrinsic rejects SharedArrayBuffer, including a view disguised by
    // its prototype. The one synchronous copy cannot race another JS agent.
    bufferLengthGetter.call(bufferGetter.call(bytes));
    return lengthGetter.call(bytes) as number;
  } catch { return reject("value_type"); }
}
// A synchronous borrowed view without consulting a caller's constructor or
// Symbol.species. It must not outlive the caller's current input operation.
export function byteSlice(bytes: Uint8Array, start: number, end: number): Uint8Array {
  const length = byteLength(bytes);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > length) reject("value_type");
  return new Uint8Array(bufferGetter.call(bytes) as ArrayBuffer, (offsetGetter.call(bytes) as number) + start, end - start);
}
export interface CBORDecoderConfig {
  readonly bytes: number;
  readonly nodes: number;
  readonly textBytes: number;
  // The containing shape validator must still impose each field's exact cap.
  // Namespace roster fields may use their separately admitted larger bound.
  readonly arrayItems: number;
  readonly runtimeBytes: bigint;
}
export function captureDecoderConfig(c: CBORDecoderConfig): CBORDecoderConfig {
  const bytes = c.bytes, nodes = c.nodes, textBytes = c.textBytes, arrayItems = c.arrayItems, runtimeBytes = c.runtimeBytes;
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 0x7fffffff || !Number.isSafeInteger(nodes) || nodes < 1 || nodes > 0x7fffffff ||
    !Number.isSafeInteger(textBytes) || textBytes < 0 || textBytes > bytes || !Number.isSafeInteger(arrayItems) || arrayItems < 1 || arrayItems > 0xffffffff ||
    typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) reject("configuration_capacity");
  canonicalTextBackingBytes(textBytes);
  return Object.freeze({ bytes, nodes, textBytes, arrayItems, runtimeBytes });
}
export function cborDecoderCharge(config: CBORDecoderConfig): ResourceVector {
  const c = captureDecoderConfig(config);
  // Input copy, fixed node arena, two complete normalization buffers, and its
  // fixed counting table. Runtime metadata/stack/allocator overhead is separate.
  const bytes = BigInt(c.bytes) + BigInt(c.nodes) * 33n + BigInt(canonicalTextBackingBytes(c.textBytes)) + BigInt(schemaWorkspaceBackingBytes);
  return new ResourceVector([bytes + c.runtimeBytes, 0n, 0n, BigInt(c.nodes) + 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function contractCBORDecoderCharge(config: CBORDecoderConfig): ResourceVector {
  const c = captureDecoderConfig(config);
  if (c.bytes > 73728 || c.nodes > 1024 || c.textBytes > 128 || c.arrayItems > 64) reject("configuration_capacity");
  // Input remains in the original exclusive RPC payload. Runtime metadata
  // includes nine parse frames and the fixed 384-entry schema traversal.
  return new ResourceVector([BigInt(c.nodes) * 33n + BigInt(canonicalTextBackingBytes(c.textBytes)) +
    BigInt(schemaWorkspaceBackingBytes) + c.runtimeBytes, 0n, 0n, BigInt(c.nodes) + 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
interface DocumentState { decoder: CBORDecoder | undefined; generation: bigint; schema?: string; context?: CapturedDecodeContext }
const documents = new WeakMap<CBORDocument, DocumentState>();
export type CBORKind = "uint" | "bytes" | "text" | "array" | "map" | "bool" | "null";

// A document is one exclusive lease on its decoder, not a heap tree. Numeric
// node indices are meaningful only through this original document generation.
// No mutable input/backing view escapes. Schema checks and signature authority
// remain mandatory; canonical syntax alone does not establish either.
export class CBORDocument {
  constructor(token: symbol, decoder: CBORDecoder, generation: bigint) {
    if (token !== capability) reject("document_released");
    documents.set(this, { decoder, generation }); Object.freeze(this);
  }
  #decoder(): CBORDecoder {
    const d = documents.get(this)?.decoder;
    if (d === undefined) reject("document_released");
    return d;
  }
  kind(node = 0): CBORKind { return this.#decoder().kind(this, node); }
  uint(node = 0): bigint { return this.#decoder().uint(this, node); }
  boolean(node = 0): boolean { return this.#decoder().boolean(this, node); }
  size(node = 0): number { return this.#decoder().size(this, node); }
  firstChild(node = 0): number { return this.#decoder().child(this, node, false); }
  nextSibling(node: number): number { return this.#decoder().child(this, node, true); }
  // Payload copy applies only to bytes/text. Encoded copy also includes the
  // canonical header and descendants, for original signature/digest inputs.
  copyPayload(node: number, destination: Uint8Array): number { return this.#decoder().copy(this, node, destination, false); }
  copyEncoded(node: number, destination: Uint8Array): number { return this.#decoder().copy(this, node, destination, true); }
  encodedSize(node = 0): number { return this.#decoder().encodedSize(this, node); }
  encodedOffset(node: number, payload = false): number { return this.#decoder().encodedOffset(this, node, payload); }
  sameEnvironment(reference: ResourceReference): boolean { return this.#decoder().sameEnvironment(this, reference); }
  payloadByte(node: number, offset: number): number { return this.#decoder().payloadByte(this, node, offset); }
  text(node: number): string { return this.#decoder().text(this, node); }
  field(node: number, id: number): number { return this.#decoder().field(this, node, id); }
  compare(a: number, b: number, payload = false): number { return this.#decoder().compare(this, a, b, payload); }
  copyRange(node: number, offset: number, destination: Uint8Array, payload = false): number {
    return this.#decoder().copyRange(this, node, offset, destination, payload);
  }
  // Embedded CBOR uses the same original input and finite arena. The containing
  // schema must authorize its interpretation; this method grants no authority.
  embedded(node: number): number { return this.#decoder().embedded(this, node); }
  copyWithoutField(id: number, destination: Uint8Array): number { return this.#decoder().copyWithoutField(this, id, destination); }
  copyReplacingBytes(id: number, replacement: Uint8Array, destination: Uint8Array): number {
    return this.#decoder().copyReplacingBytes(this, id, replacement, destination);
  }
  schema(): string | undefined { this.#decoder().kind(this, 0); return documents.get(this)?.schema; }
  selector(name: string): string | undefined { this.#decoder().kind(this, 0); return documents.get(this)?.context?.selectors[name]; }
  release(): void { documents.get(this)?.decoder?.release(this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.CBORDocument"; }
}
interface ContractParseFrame { node: number; previous: number; previousKey: number; remaining: number; seen: number }
interface ContractParseState {
  readonly cursor: ContractCBORCursor;
  readonly schema: "ServiceContract" | "ContractSnapshots";
  readonly context: CapturedDecodeContext;
  readonly frames: (ContractParseFrame | undefined)[];
  depth: number;
  phase: "parse" | "shape" | "done";
}
/** The original payload owner must hold its exclusive borrow through take and
 * document release. No unvalidated or partially validated document escapes. */
export class ContractCBORCursor {
  #decoder: CBORDecoder | undefined;
  constructor(token: symbol, decoder: CBORDecoder) {
    if (token !== contractScratch) reject("document_released");
    this.#decoder = decoder; Object.freeze(this);
  }
  step(): boolean { if (this.#decoder === undefined) reject("document_released"); return this.#decoder.stepContract(this); }
  take(): CBORDocument {
    if (this.#decoder === undefined) reject("document_released");
    const doc = this.#decoder.takeContract(this); this.#decoder = undefined; return doc;
  }
  close(): void { this.#decoder?.cancelContract(this); this.#decoder = undefined; }
}

// Synchronous parsing uses exclusively private, preadmitted backing. It has no
// waiter queue, application callbacks, dynamic container growth or host Unicode
// normalization. Closing fences new input and joins the actual document lease.
export class CBORDecoder {
  readonly #config: CBORDecoderConfig;
  readonly #borrowed: boolean;
  #input: Uint8Array;
  #major: Uint8Array;
  #number: BigUint64Array;
  #start: Uint32Array;
  #end: Uint32Array;
  #payload: Uint32Array;
  #first: Int32Array;
  #next: Int32Array;
  #embedded: Int32Array;
  #text: CanonicalTextWorkspace | undefined;
  #schema: SchemaWorkspace | undefined;
  #reservation: ResourceReference | undefined;
  #position = 0;
  #size = 0;
  #limit = 0;
  #used = 0;
  #generation = 0n;
  #current: CBORDocument | undefined;
  #closed = false;
  #decodingMap = false;
  #contract: ContractParseState | undefined;
  constructor(config: CBORDecoderConfig, reservation: ResourceReference, token?: symbol) {
    if (token !== undefined && token !== contractScratch) reject("configuration_capacity");
    const c = captureDecoderConfig(config), cost = token === contractScratch ? contractCBORDecoderCharge(c) : cborDecoderCharge(c);
    this.#borrowed = token === contractScratch;
    this.#reservation = reservation.take(cost);
    try {
      this.#config = c; this.#input = this.#borrowed ? emptyBytes : new Uint8Array(c.bytes); this.#major = new Uint8Array(c.nodes);
      this.#number = new BigUint64Array(c.nodes); this.#start = new Uint32Array(c.nodes); this.#end = new Uint32Array(c.nodes);
      this.#payload = new Uint32Array(c.nodes); this.#first = new Int32Array(c.nodes); this.#next = new Int32Array(c.nodes);
      this.#embedded = new Int32Array(c.nodes);
      this.#text = new CanonicalTextWorkspace(c.textBytes);
      this.#schema = new SchemaWorkspace(this.#borrowed);
    } catch (error) { this.#reservation.release(); this.#reservation = undefined; throw error; }
    Object.freeze(this);
  }
  static contractScratch(config: CBORDecoderConfig, reservation: ResourceReference): CBORDecoder {
    return new CBORDecoder(config, reservation, contractScratch);
  }
  beginContractMap(bytes: Uint8Array, schema: "ServiceContract" | "ContractSnapshots"): ContractCBORCursor {
    if (this.#closed) reject("decoder_closed");
    if (!this.#borrowed || this.#current !== undefined || this.#contract !== undefined) reject("decoder_busy");
    if (schema !== "ServiceContract" && schema !== "ContractSnapshots") reject("configuration_capacity");
    this.#reservation!.check();
    const n = byteLength(bytes), context = captureDecodeContext({});
    preflightMap(schema, n, context);
    if (n > this.#config.bytes) reject("map_size");
    if (this.#generation === (1n << 64n) - 1n) reject("decoder_closed");
    this.#input = byteSlice(bytes, 0, n); this.#size = this.#limit = n; this.#position = this.#used = 0; this.#generation++;
    try {
      const cursor = new ContractCBORCursor(contractScratch, this);
      this.#current = new CBORDocument(capability, this, this.#generation);
      this.#contract = { cursor, schema, context, frames: Array<ContractParseFrame | undefined>(9).fill(undefined), depth: 0, phase: "parse" };
      return cursor;
    } catch (error) { this.#current?.release(); this.#clear(); throw error; }
  }
  stepContract(cursor: ContractCBORCursor): boolean {
    const c = this.#contract;
    if (c === undefined || c.cursor !== cursor || this.#closed) reject("document_released");
    this.#reservation!.check();
    try {
      if (c.phase === "done") return true;
      if (c.phase === "shape") {
        if (this.#schema!.stepContract()) {
          const state = documents.get(this.#current!)!;
          state.schema = c.schema === "ContractSnapshots" ? "ContractSnapshotsEnvelope" : c.schema; state.context = c.context;
          c.phase = "done"; return true;
        }
        return false;
      }
      while (c.depth > 0 && c.frames[c.depth - 1]!.remaining === 0) {
        const frame = c.frames[--c.depth]!; this.#end[frame.node] = this.#position; c.frames[c.depth] = undefined;
      }
      if (c.depth === 0 && this.#used !== 0) {
        if (this.#position !== this.#size) reject("trailing_bytes");
        this.#schema!.beginContract(this.#current!, c.schema, c.context); c.phase = "shape"; return false;
      }
      const parent = c.depth === 0 ? undefined : c.frames[c.depth - 1]!;
      const node = this.#item(c.depth, true), major = this.#major[node]!;
      if (parent !== undefined) {
        if (this.#major[parent.node] === 5 && parent.seen % 2 === 0) {
          if (major !== 0 || this.#number[node]! > BigInt(policy.maxFieldID)) reject("field_id_type");
          if (parent.previousKey >= 0) {
            const order = this.#compare(parent.previousKey, node);
            if (order === 0) reject("duplicate_key"); if (order > 0) reject("map_order");
          }
          parent.previousKey = node;
        }
        if (parent.previous < 0) this.#first[parent.node] = node; else this.#next[parent.previous] = node;
        parent.previous = node; parent.seen++; parent.remaining--;
      }
      if (major === 4 || major === 5) {
        if (c.depth === c.frames.length) reject("depth_limit");
        c.frames[c.depth++] = { node, previous: -1, previousKey: -1, remaining: Number(this.#number[node]) * (major === 5 ? 2 : 1), seen: 0 };
      }
      return false;
    } catch (error) { this.cancelContract(cursor); throw error; }
  }
  takeContract(cursor: ContractCBORCursor): CBORDocument {
    if (this.#contract?.cursor !== cursor || this.#contract.phase !== "done") reject("document_released");
    this.#contract = undefined; return this.#current!;
  }
  cancelContract(cursor: ContractCBORCursor): void {
    if (this.#contract?.cursor !== cursor) return;
    this.#contract = undefined; this.#current?.release();
  }
  decode(bytes: Uint8Array): CBORDocument {
    if (this.#decodingMap) reject("decoder_busy");
    return this.#decode(bytes);
  }
  // The only entry point that brands a document with a schema validates every
  // registered stateless rule. Authentication, cross-object policy, freshness
  // and ownership remain separate gates in the consuming protocol.
  decodeMap(bytes: Uint8Array, schema: string, context: DecodeContext = {}): CBORDocument {
    if (this.#closed) reject("decoder_closed");
    if (this.#decodingMap || this.#current !== undefined) reject("decoder_busy");
    this.#decodingMap = true;
    let document: CBORDocument | undefined;
    try {
      const captured = captureDecodeContext(context);
      preflightMap(schema, byteLength(bytes), captured);
      document = this.#decode(bytes);
      this.#schema!.validate(document, schema, captured);
      const state = documents.get(document)!; state.schema = schema; state.context = captured;
      return document;
    } catch (error) { document?.release(); throw error; }
    finally { this.#decodingMap = false; if (this.#closed && this.#current === undefined) this.#dropBacking(); }
  }
  #decode(bytes: Uint8Array): CBORDocument {
    const n = byteLength(bytes);
    if (this.#closed) reject("decoder_closed");
    if (this.#borrowed) reject("configuration_capacity");
    if (this.#current !== undefined) reject("decoder_busy");
    this.#reservation!.check();
    if (n > this.#config.bytes) reject("map_size");
    if (this.#generation === (1n << 64n) - 1n) reject("decoder_closed");
    // Complete declared input size is checked before copying or adding nodes.
    this.#generation++; this.#size = n; this.#limit = n; this.#position = 0; this.#used = 0;
    try {
      setBytes.call(this.#input, bytes);
      this.#item(0);
      if (this.#position !== n) reject("trailing_bytes");
      const document = new CBORDocument(capability, this, this.#generation);
      this.#current = document;
      return document;
    } catch (error) { this.#clear(); throw error; }
  }
  #take(): number {
    if (this.#position === this.#limit) reject("truncated");
    return this.#input[this.#position++]!;
  }
  #item(depth: number, headOnly = false): number {
    if (depth > policy.maxDepth) reject("depth_limit");
    if (this.#used === this.#config.nodes) reject("node_capacity");
    const start = this.#position, header = this.#take(), major = header >>> 5, additional = header & 31;
    if (additional === 31) reject("indefinite_length");
    if (major === 7) {
      if (additional !== 20 && additional !== 21 && additional !== 22) reject("unsupported_type");
    } else if (major !== 0 && major !== 2 && major !== 3 && major !== 4 && major !== 5) reject("unsupported_type");
    if (additional > 27) reject("invalid_header");
    let value = BigInt(additional);
    if (additional >= 24) {
      value = 0n;
      for (let i = 0; i < 2 ** (additional - 24); i++) value = value * 256n + BigInt(this.#take());
      const minimum = additional === 24 ? 24n : additional === 25 ? 256n : additional === 26 ? 65536n : 4294967296n;
      if (value < minimum) reject("non_shortest_integer");
    }
    const node = this.#used++;
    this.#major[node] = major; this.#number[node] = value; this.#start[node] = start; this.#payload[node] = this.#position;
    this.#first[node] = -1; this.#next[node] = -1; this.#embedded[node] = -1;
    if (major === 2 || major === 3) {
      if (value > BigInt(this.#limit - this.#position)) reject("truncated");
      const end = this.#position + Number(value);
      if (major === 3) {
        const failure = this.#text!.check(this.#input, this.#position, end);
        if (failure !== undefined) reject(failure);
      }
      this.#position = end;
    } else if (major === 4 || major === 5) {
      if (major === 4 && value > BigInt(this.#config.arrayItems)) reject("array_limit");
      if (major === 5 && value > BigInt(policy.maxMapEntries)) reject("map_limit");
      const children = value * (major === 5 ? 2n : 1n);
      if (children > BigInt(this.#limit - this.#position)) reject("truncated");
      if (children > BigInt(this.#config.nodes - this.#used)) reject("node_capacity");
      if (headOnly) { this.#end[node] = this.#position; return node; }
      let previous = -1, previousKey = -1;
      for (let i = 0; i < Number(children); i++) {
        const child = this.#item(depth + 1);
        if (previous < 0) this.#first[node] = child;
        else this.#next[previous] = child;
        previous = child;
        if (major === 5 && i % 2 === 0) {
          const keyMajor = this.#major[child]!;
          if (keyMajor !== 0 && keyMajor !== 3 || keyMajor === 0 && this.#number[child]! > BigInt(policy.maxFieldID)) reject("field_id_type");
          if (previousKey >= 0) {
            if (keyMajor !== this.#major[previousKey]) reject("field_id_type");
            const order = this.#compare(previousKey, child);
            if (order === 0) reject("duplicate_key");
            if (order > 0) reject("map_order");
          }
          previousKey = child;
        }
      }
    }
    this.#end[node] = this.#position;
    return node;
  }
  #compare(a: number, b: number): number {
    const lengthA = this.#end[a]! - this.#start[a]!, lengthB = this.#end[b]! - this.#start[b]!;
    if (lengthA !== lengthB) return lengthA - lengthB;
    for (let i = 0; i < lengthA; i++) {
      const difference = this.#input[this.#start[a]! + i]! - this.#input[this.#start[b]! + i]!;
      if (difference !== 0) return difference;
    }
    return 0;
  }
  #check(document: CBORDocument, node: number): void {
    const d = documents.get(document);
    if (d === undefined || d.decoder !== this || d.generation !== this.#generation || this.#current !== document ||
      !Number.isSafeInteger(node) || node < 0 || node >= this.#used) reject("document_released");
    this.#reservation!.check();
  }
  kind(document: CBORDocument, node: number): CBORKind {
    this.#check(document, node);
    switch (this.#major[node]) {
      case 0: return "uint";
      case 2: return "bytes";
      case 3: return "text";
      case 4: return "array";
      case 5: return "map";
      default: return this.#number[node] === 22n ? "null" : "bool";
    }
  }
  uint(document: CBORDocument, node: number): bigint {
    this.#check(document, node);
    if (this.#major[node] !== 0) reject("value_type");
    return this.#number[node]!;
  }
  boolean(document: CBORDocument, node: number): boolean {
    this.#check(document, node);
    if (this.#major[node] !== 7 || this.#number[node] === 22n) reject("value_type");
    return this.#number[node] === 21n;
  }
  size(document: CBORDocument, node: number): number {
    this.#check(document, node);
    const major = this.#major[node]!;
    if (major < 2 || major > 5) reject("value_type");
    return Number(this.#number[node]);
  }
  child(document: CBORDocument, node: number, next: boolean): number {
    this.#check(document, node);
    return (next ? this.#next : this.#first)[node]!;
  }
  encodedSize(document: CBORDocument, node: number): number {
    this.#check(document, node); return this.#end[node]! - this.#start[node]!;
  }
  encodedOffset(document: CBORDocument, node: number, payload: boolean): number {
    this.#check(document, node);
    if (payload && this.#major[node] !== 2 && this.#major[node] !== 3) reject("value_type");
    return (payload ? this.#payload : this.#start)[node]! - this.#start[0]!;
  }
  sameEnvironment(document: CBORDocument, reference: ResourceReference): boolean {
    this.#check(document, 0); return this.#reservation!.sameEnvironment(reference);
  }
  payloadByte(document: CBORDocument, node: number, offset: number): number {
    this.#check(document, node);
    if (this.#major[node] !== 2 && this.#major[node] !== 3 || !Number.isSafeInteger(offset) || offset < 0 || offset >= Number(this.#number[node])) reject("value_type");
    return this.#input[this.#payload[node]! + offset]!;
  }
  text(document: CBORDocument, node: number): string {
    this.#check(document, node);
    if (this.#major[node] !== 3) reject("value_type");
    return utf8.decode(sliceView.call(this.#input, this.#payload[node], this.#end[node]));
  }
  field(document: CBORDocument, node: number, id: number): number {
    this.#check(document, node);
    if (this.#major[node] !== 5 || !Number.isSafeInteger(id) || id < 0 || id > policy.maxFieldID) reject("value_type");
    for (let key = this.#first[node]!; key >= 0;) {
      const value = this.#next[key]!;
      if (this.#major[key] !== 0) reject("field_id_type");
      if (this.#number[key] === BigInt(id)) return value;
      key = this.#next[value]!;
    }
    return -1;
  }
  compare(document: CBORDocument, a: number, b: number, payload: boolean): number {
    this.#check(document, a); this.#check(document, b);
    if (payload && (this.#major[a] !== 2 && this.#major[a] !== 3 || this.#major[b] !== 2 && this.#major[b] !== 3)) reject("value_type");
    const starts = payload ? this.#payload : this.#start, x = starts[a]!, y = starts[b]!;
    const xn = this.#end[a]! - x, yn = this.#end[b]! - y;
    for (let i = 0; i < Math.min(xn, yn); i++) { const diff = this.#input[x + i]! - this.#input[y + i]!; if (diff !== 0) return diff; }
    return xn - yn;
  }
  copyRange(document: CBORDocument, node: number, offset: number, destination: Uint8Array, payload: boolean): number {
    const capacity = byteLength(destination);
    this.#check(document, node);
    if (payload && this.#major[node] !== 2 && this.#major[node] !== 3) reject("value_type");
    const start = (payload ? this.#payload : this.#start)[node]!, size = this.#end[node]! - start;
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > size) reject("value_type");
    const count = Math.min(capacity, size - offset);
    setBytes.call(destination, sliceView.call(this.#input, start + offset, start + offset + count));
    return count;
  }
  embedded(document: CBORDocument, node: number): number {
    this.#check(document, node);
    if (this.#borrowed) reject("configuration_capacity");
    if (this.#major[node] !== 2) reject("value_type");
    if (this.#embedded[node]! >= 0) return this.#embedded[node]!;
    const position = this.#position, limit = this.#limit;
    try {
      this.#position = this.#payload[node]!; this.#limit = this.#end[node]!;
      const child = this.#item(0);
      if (this.#position !== this.#limit) reject("trailing_bytes");
      this.#embedded[node] = child;
      return child;
    } catch (error) { this.release(document); throw error; }
    finally { this.#position = position; this.#limit = limit; }
  }
  copyWithoutField(document: CBORDocument, id: number, destination: Uint8Array): number {
    const capacity = byteLength(destination), omitted = this.field(document, 0, id);
    if (omitted < 0) reject("projection_field");
    const count = Number(this.#number[0]!) - 1;
    let size = count < 24 ? 1 : 2;
    for (let key = this.#first[0]!; key >= 0;) {
      const value = this.#next[key]!;
      if (value !== omitted) size += this.#end[value]! - this.#start[key]!;
      key = this.#next[value]!;
    }
    if (capacity < size) reject("map_size");
    let at = 0;
    if (count < 24) destination[at++] = 0xa0 + count;
    else { destination[at++] = 0xb8; destination[at++] = count; }
    for (let key = this.#first[0]!; key >= 0;) {
      const value = this.#next[key]!;
      if (value !== omitted) {
        const start = this.#start[key]!, end = this.#end[value]!;
        setBytes.call(destination, sliceView.call(this.#input, start, end), at); at += end - start;
      }
      key = this.#next[value]!;
    }
    return size;
  }
  copyReplacingBytes(document: CBORDocument, id: number, replacement: Uint8Array, destination: Uint8Array): number {
    const length = byteLength(replacement), capacity = byteLength(destination), value = this.field(document, 0, id);
    if (value < 0 || this.#major[value] !== 2 || this.#number[value] !== BigInt(length)) reject("projection_field");
    const size = this.#end[0]! - this.#start[0]!;
    if (capacity < size) reject("map_size");
    // A replacement may alias a caller's destination. Reject overlapping byte
    // storage so the original copy cannot overwrite a requested signature.
    if (bufferGetter.call(replacement) === bufferGetter.call(destination)) reject("value_type");
    setBytes.call(destination, sliceView.call(this.#input, this.#start[0], this.#end[0]));
    setBytes.call(destination, replacement, this.#payload[value]! - this.#start[0]!);
    return size;
  }
  copy(document: CBORDocument, node: number, destination: Uint8Array, encoded: boolean): number {
    const capacity = byteLength(destination);
    this.#check(document, node);
    const major = this.#major[node];
    if (!encoded && major !== 2 && major !== 3) reject("value_type");
    const start = (encoded ? this.#start : this.#payload)[node]!, end = this.#end[node]!;
    if (capacity < end - start) reject("map_size");
    setBytes.call(destination, sliceView.call(this.#input, start, end));
    return end - start;
  }
  release(document: CBORDocument): void {
    const d = documents.get(document);
    if (d === undefined || d.decoder !== this || this.#current !== document) return;
    d.decoder = undefined; delete d.context; this.#current = undefined; this.#clear();
    if (this.#closed && !this.#decodingMap) this.#dropBacking();
  }
  #clear(): void {
    if (this.#borrowed) this.#input = emptyBytes; else this.#input.fill(0, 0, this.#size);
    this.#major.fill(0, 0, this.#used); this.#number.fill(0n, 0, this.#used);
    this.#start.fill(0, 0, this.#used); this.#end.fill(0, 0, this.#used); this.#payload.fill(0, 0, this.#used);
    this.#first.fill(-1, 0, this.#used); this.#next.fill(-1, 0, this.#used); this.#embedded.fill(-1, 0, this.#used); this.#text?.clear();
    this.#schema?.clear(); this.#size = 0; this.#used = 0; this.#position = 0; this.#limit = 0;
  }
  close(): void {
    this.#closed = true;
    if (this.#contract !== undefined) this.cancelContract(this.#contract.cursor);
    if (this.#current === undefined && !this.#decodingMap) this.#dropBacking();
  }
  #dropBacking(): void {
    this.#input = emptyBytes; this.#major = emptyBytes; this.#number = emptyNumbers;
    this.#start = emptyOffsets; this.#end = emptyOffsets; this.#payload = emptyOffsets;
    this.#first = emptyLinks; this.#next = emptyLinks; this.#embedded = emptyLinks; this.#text = undefined; this.#schema = undefined;
    this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#closed && this.#reservation === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.CBORDecoder"; }
}
for (const constructor of [CBORDecoder, CBORDocument, ContractCBORCursor]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
