import { transportV4FragmentRegistry as registry } from "../../generated/transportV4Registry.js";
import { byteLength, byteSlice } from "./cbor.js";
import { ResourceVector, type ResourceReference } from "./resources.js";

export type RPCFragmentKind = 0 | 1 | 2 | 3;
export interface RPCFragment {
  readonly kind: RPCFragmentKind;
  readonly serial: bigint;
  readonly replyTo?: bigint;
  readonly offset?: number;
  readonly header?: Uint8Array;
  readonly payload?: Uint8Array;
}
export interface RPCFragmentPart {
  readonly fragment: RPCFragment;
  readonly chunkOffset: number;
  readonly first: boolean;
  readonly last: boolean;
}
export class RPCProtocolError extends Error {
  constructor(readonly code: string) { super(code); this.name = "RPCProtocolError"; }
}
function fail(code: string): never { throw new RPCProtocolError(code); }
const names = ["BEGIN", "DATA", "ABORT", "STOP_OUTPUT"] as const;
const fixed = [18, 12, 12, 8] as const, minimum = [19, 13, 12, 8] as const, maximum = [530, 16379, 12, 8] as const;
if (registry.transport !== "rpc_reliable_ordered" || registry.length_prefix_bytes !== 4 || registry.length_counts !== "kind_and_body" ||
    registry.max_fragment_bytes !== 16384 || registry.max_body_length !== 16380 || Object.keys(registry.kinds).length !== 4 ||
    names.some((name, index) => { const kind = registry.kinds[name]; return kind.value !== index || kind.body_fixed_bytes !== fixed[index] ||
      kind.body_min_bytes !== minimum[index] || kind.body_max_bytes !== maximum[index]; })) fail("registry_unresolved");
export const rpcFragmentMaxBytes = registry.max_fragment_bytes;
export const rpcDataMaxBytes = registry.kinds.DATA.payload_max_bytes;
const empty = new Uint8Array();
const set = Uint8Array.prototype.set;
function uint(value: bigint, width: number): void {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << BigInt(width * 8)) fail("fragment_integer_range");
}
function read(bytes: Uint8Array, at: number, width: number): bigint {
  let value = 0n; for (let n = 0; n < width; n++) value = value * 256n + BigInt(bytes[at + n]!); return value;
}
function write(bytes: Uint8Array, at: number, width: number, value: bigint): void {
  for (let n = width - 1; n >= 0; n--) { bytes[at + n] = Number(value & 255n); value >>= 8n; }
}
function prefix(bytes: Uint8Array): { kind: RPCFragmentKind; total: number; fixed: number } {
  const body = Number(read(bytes, 0, 4)), kind = bytes[4]!;
  if (body < 1 || body > registry.max_body_length) fail("fragment_body_length");
  if (kind > 3) fail("fragment_unknown_kind");
  if (body - 1 < minimum[kind]! || body - 1 > maximum[kind]!) fail("fragment_kind_length");
  return { kind: kind as RPCFragmentKind, total: body + 4, fixed: 5 + fixed[kind]! };
}
function fields(kind: RPCFragmentKind, bytes: Uint8Array, total: number): RPCFragment {
  const serial = read(bytes, 5, 8);
  if (serial === 0n) fail("fragment_serial_range");
  if (kind === 0) {
    const length = Number(read(bytes, 21, 2));
    if (length < 1 || length > 512 || total !== 23 + length) fail("fragment_header_length");
    return { kind, serial, replyTo: read(bytes, 13, 8) };
  }
  return kind === 3 ? { kind, serial } : { kind, serial, offset: Number(read(bytes, 13, 4)) };
}
/** The caller owns destination storage. Copy variable input first so overlap
 * cannot let the binary prefix overwrite the original header or payload. */
export function encodeRPCFragment(input: RPCFragment, destination: Uint8Array): number {
  const kind = input.kind, serial = input.serial, replyTo = input.replyTo ?? 0n, offset = input.offset ?? 0;
  const header = input.header ?? empty, payload = input.payload ?? empty;
  const headerBytes = byteLength(header), payloadBytes = byteLength(payload), capacity = byteLength(destination);
  if (!Number.isInteger(kind) || kind < 0 || kind > 3) fail("fragment_unknown_kind");
  uint(serial, 8); uint(replyTo, 8);
  if (serial === 0n || !Number.isSafeInteger(offset) || offset < 0 || offset > 0xffffffff) fail("fragment_integer_range");
  let length = 5 + fixed[kind];
  if (kind === 0) {
    if (headerBytes < 1 || headerBytes > 512 || payloadBytes !== 0 || offset !== 0) fail("fragment_header_length");
    length += headerBytes;
  } else {
    if (headerBytes !== 0 || replyTo !== 0n) fail("fragment_fields");
    if (kind === 1) {
      if (payloadBytes < 1 || payloadBytes > rpcDataMaxBytes) fail("fragment_data_length"); length += payloadBytes;
    } else if (payloadBytes !== 0 || kind === 3 && offset !== 0) fail("fragment_fields");
  }
  if (capacity < length) fail("configuration_capacity");
  if (kind === 0) set.call(destination, header, 23);
  else if (kind === 1) set.call(destination, payload, 17);
  write(destination, 0, 4, BigInt(length - 4)); destination[4] = kind; write(destination, 5, 8, serial);
  if (kind === 0) { write(destination, 13, 8, replyTo); write(destination, 21, 2, BigInt(headerBytes)); }
  else if (kind !== 3) write(destination, 13, 4, BigInt(offset));
  return length;
}
export function decodeRPCFragment(bytes: Uint8Array): RPCFragment {
  const size = byteLength(bytes);
  if (size < 5) fail("fragment_truncated_length");
  const parsed = prefix(bytes);
  if (size !== parsed.total) fail("fragment_length_mismatch");
  const fragment = fields(parsed.kind, bytes, parsed.total);
  return parsed.kind === 0 ? { ...fragment, header: byteSlice(bytes, 23, size) } :
    parsed.kind === 1 ? { ...fragment, payload: byteSlice(bytes, 17, size) } : fragment;
}
export function rpcFragmentParserCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) fail("configuration_capacity");
  return new ResourceVector([535n + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
/** Single-reader production framing. DATA borrows the current admitted input;
 * the parser retains only a bounded fixed/BEGIN header across Stream reads. */
export class RPCFragmentParser {
  #reference: ResourceReference | undefined;
  #header = empty;
  #have = 0;
  #need = 5;
  #total = 0;
  #payloadRead = 0;
  #kind: RPCFragmentKind = 0;
  #current: RPCFragment | undefined;
  #failure: RPCProtocolError | undefined;
  constructor(runtimeBytes: bigint, reference: ResourceReference) {
    this.#reference = reference.take(rpcFragmentParserCharge(runtimeBytes));
    try { this.#header = new Uint8Array(535); }
    catch (error) { this.close(); throw error; }
  }
  /** A returned borrowed view is valid only until the next next()/close().
   * The channel transfers or discards it before returning receive credit. */
  next(input: Uint8Array): Readonly<{ consumed: number; part?: RPCFragmentPart }> {
    if (this.#failure !== undefined) throw this.#failure;
    this.#reference!.check();
    const length = byteLength(input);
    let consumed = 0;
    try {
      for (;;) {
        if (this.#have < this.#need) {
          const count = Math.min(this.#need - this.#have, length - consumed);
          set.call(this.#header, byteSlice(input, consumed, consumed + count), this.#have);
          this.#have += count; consumed += count;
          if (this.#have < this.#need) return { consumed };
        }
        if (this.#need === 5) {
          const p = prefix(this.#header); this.#kind = p.kind; this.#total = p.total; this.#need = p.fixed; continue;
        }
        if (this.#current === undefined) {
          this.#current = fields(this.#kind, this.#header, this.#total);
          if (this.#kind === 0) { this.#need = this.#total; continue; }
        }
        let fragment = this.#current, chunkOffset = 0, first = true, last = true;
        if (this.#kind === 0) fragment = { ...fragment, header: byteSlice(this.#header, 23, this.#total) };
        else if (this.#kind === 1) {
          const count = Math.min(length - consumed, this.#total - 17 - this.#payloadRead);
          if (count === 0) return { consumed };
          chunkOffset = this.#payloadRead; first = chunkOffset === 0;
          fragment = { ...fragment, payload: byteSlice(input, consumed, consumed + count) };
          consumed += count; this.#payloadRead += count; last = this.#payloadRead === this.#total - 17;
        }
        if (last) { this.#have = this.#total = this.#payloadRead = 0; this.#need = 5; this.#current = undefined; }
        return { consumed, part: { fragment, chunkOffset, first, last } };
      }
    } catch (error) {
      this.#failure = error instanceof RPCProtocolError ? error : new RPCProtocolError("fragment_invalid");
      this.#header.fill(0); this.#current = undefined; throw this.#failure;
    }
  }
  pending(): boolean { return this.#failure === undefined && this.#have !== 0; }
  end(): void {
    if (this.#failure !== undefined) throw this.#failure;
    if (this.#have !== 0) { this.#failure = new RPCProtocolError("fragment_truncated"); throw this.#failure; }
  }
  close(): void {
    this.#failure ??= new RPCProtocolError("fragment_closed"); this.#header.fill(0); this.#header = empty; this.#current = undefined;
    this.#reference?.release(); this.#reference = undefined;
  }
}
