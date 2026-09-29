import { byteLength, byteSlice } from "./cbor.js";
import type { ResourceReference} from "./resources.js";
import { ResourceVector } from "./resources.js";
import { binaryWidth, datagramScope, envelopePrefixBytes, inFrameClass, maxStreamScope, ownProfile, recordHeaderBytes, validFrameType, wire } from "./wireRegistry.js";

export type EnvelopeFailure = "configuration_capacity" | "envelope_closed" | "envelope_busy" | "envelope_failed" | "envelope_released" |
  "truncated" | "payload_too_large" | "invalid_flags" | "unknown_frame" | "invalid_scope" | "invalid_profile" | "frame_boundary";
export class EnvelopeError extends Error {
  readonly code: EnvelopeFailure;
  constructor(code: EnvelopeFailure) { super(code); this.name = "EnvelopeError"; this.code = code; }
}
function reject(code: EnvelopeFailure): never { throw new EnvelopeError(code); }
const capability = Symbol("original envelope");
const empty = new Uint8Array(0);
const copy = Uint8Array.prototype.set;
export interface EnvelopeDecoderConfig {
  readonly maxFrame: number;
  readonly mode: "message" | "stream";
  readonly runtimeBytes: bigint;
}
function capture(config: EnvelopeDecoderConfig): EnvelopeDecoderConfig {
  const maxFrame = config.maxFrame, mode = config.mode, runtimeBytes = config.runtimeBytes;
  if (!Number.isSafeInteger(maxFrame) || maxFrame < 1 || maxFrame > wire.resource_caps.max_payload_length || mode !== "message" && mode !== "stream" ||
    typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) reject("configuration_capacity");
  return Object.freeze({ maxFrame, mode, runtimeBytes });
}
export function envelopeDecoderCharge(config: EnvelopeDecoderConfig): ResourceVector {
  const c = capture(config);
  return new ResourceVector([BigInt(envelopePrefixBytes + c.maxFrame) + c.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export interface RecordHeader {
  readonly epoch: number;
  readonly scope: bigint;
  readonly sequence: bigint;
}
export interface ParsedRecord extends RecordHeader {
  readonly frameType: number;
  readonly ciphertextBytes: number;
}
export function inspectEnvelopePrefix(bytes: Uint8Array, maxFrame: number): Readonly<{ frameType: number; payloadBytes: number }> {
  if (bytes.length < envelopePrefixBytes) reject("truncated");
  let length = 0; for (let i = 0; i < 4; i++) length = length * 256 + bytes[i]!;
  if (length > maxFrame || length > wire.resource_caps.max_payload_length) reject("payload_too_large");
  if (!validFrameType(bytes[4]!)) reject("unknown_frame");
  if (bytes[5] !== 0 || bytes[6] !== 0 || bytes[7] !== 0) reject("invalid_flags");
  return { frameType: bytes[4]!, payloadBytes: length };
}
/** Unauthenticated fixed-header inspection. It confers no scope/key authority. */
export function inspectRecordPrefix(bytes: Uint8Array, payloadBytes: number, profile: string): ParsedRecord {
  const p = ownProfile(profile), frameType = bytes[4]!;
  if (p === undefined) reject("invalid_profile");
  if (!inFrameClass(frameType, "record_cipher") && !inFrameClass(frameType, "maintenance_record")) reject("unknown_frame");
  if (payloadBytes < recordHeaderBytes + p.tag_bytes || bytes.length < envelopePrefixBytes + recordHeaderBytes) reject("truncated");
  let at = envelopePrefixBytes;
  const integer = (width: number): bigint => { let n = 0n; for (let i = 0; i < width; i++) n = n * 256n + BigInt(bytes[at++]!); return n; };
  let epoch = 0, scope = 0n, sequence = 0n;
  for (const field of wire.header) {
    const value = integer(binaryWidth(field.type));
    if (field.name === "epoch") epoch = Number(value);
    else if (field.name === "sequence_scope") scope = value;
    else if (field.name === "sequence") sequence = value;
    else reject("configuration_capacity");
  }
  if (frameType === wire.frame_types.DATAGRAM) {
    if (scope !== datagramScope) reject("invalid_scope");
    if (payloadBytes + envelopePrefixBytes > wire.resource_caps.max_datagram_envelope) reject("payload_too_large");
  } else if (frameType === wire.frame_types.OPEN_STREAM || frameType === wire.frame_types.STREAM_DATA) {
    if (scope < BigInt(wire.resource_caps.scope_id.min) || scope > maxStreamScope) reject("invalid_scope");
  } else if (scope !== 0n) reject("invalid_scope");
  return Object.freeze({ epoch, scope, sequence, frameType, ciphertextBytes: payloadBytes - recordHeaderBytes });
}
interface FrameState { decoder: EnvelopeDecoder | undefined; generation: bigint }
const frames = new WeakMap<EnvelopeFrame, FrameState>();

// This lease proves binary framing only. It is never an authenticated record,
// scope association, current epoch, replay fact, or application delivery right.
export class EnvelopeFrame {
  constructor(token: symbol, decoder: EnvelopeDecoder, generation: bigint) {
    if (token !== capability) reject("envelope_released");
    frames.set(this, { decoder, generation }); Object.freeze(this);
  }
  #decoder(): EnvelopeDecoder { const d = frames.get(this)?.decoder; if (d === undefined) reject("envelope_released"); return d; }
  frameType(): number { return this.#decoder().frameType(this); }
  payloadBytes(): number { return this.#decoder().payloadBytes(this); }
  recordHeader(profile: string): ParsedRecord { return this.#decoder().recordHeader(this, profile); }
  copyPayload(destination: Uint8Array): number { return this.#decoder().copyFrame(this, destination, false); }
  copyEncoded(destination: Uint8Array): number { return this.#decoder().copyFrame(this, destination, true); }
  release(): void { frames.get(this)?.decoder?.release(this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.EnvelopeFrame"; }
}
export interface EnvelopeProgress { readonly consumed: number; readonly frame?: EnvelopeFrame }
export type EnvelopePrefixCheck = (frameType: number, payloadBytes: number) => void;

// One preadmitted body is assembled at a time. Byte-stream ingress consumes
// only through its first complete envelope; the caller retains any remainder.
// Message ingress accepts exactly one complete binary message, with no merging
// or fragmentation across WebSocket messages. No input alias or waiter is kept.
export class EnvelopeDecoder {
  readonly #config: EnvelopeDecoderConfig;
  #bytes: Uint8Array;
  #reservation: ResourceReference | undefined;
  #used = 0;
  #expected = -1;
  #current: EnvelopeFrame | undefined;
  #generation = 0n;
  #closed = false;
  #failed = false;
  constructor(config: EnvelopeDecoderConfig, reservation: ResourceReference, private readonly checkPrefix?: EnvelopePrefixCheck) {
    const c = capture(config);
    this.#reservation = reservation.take(envelopeDecoderCharge(c));
    try { this.#config = c; this.#bytes = new Uint8Array(envelopePrefixBytes + c.maxFrame); }
    catch (error) { this.#reservation.release(); this.#reservation = undefined; throw error; }
    Object.freeze(this);
  }
  #check(): void {
    if (this.#closed) reject("envelope_closed");
    if (this.#failed) reject("envelope_failed");
    if (this.#current !== undefined) reject("envelope_busy");
    this.#reservation!.check();
  }
  #prefix(bytes: Uint8Array): number {
    const prefix = inspectEnvelopePrefix(bytes, this.#config.maxFrame);
    this.checkPrefix?.(prefix.frameType, prefix.payloadBytes);
    return envelopePrefixBytes + prefix.payloadBytes;
  }
  readAllowance(quantum: number): number {
    this.#check();
    if (this.#config.mode !== "stream" || !Number.isSafeInteger(quantum) || quantum < 1) reject("configuration_capacity");
    return Math.min(quantum, (this.#expected < 0 ? envelopePrefixBytes : this.#expected) - this.#used);
  }
  /** A shared receiver discards one failed unpublished candidate only after
   * its original native direction has taken responsibility for the failure. */
  discardUnpublished(): void {
    if (this.#closed || this.#current !== undefined) reject("envelope_busy");
    this.#reservation!.check(); this.#clear(); this.#failed = false;
  }
  message(bytes: Uint8Array): EnvelopeFrame {
    this.#check();
    if (this.#config.mode !== "message") reject("frame_boundary");
    try {
      const length = byteLength(bytes);
      if (length < envelopePrefixBytes) reject("truncated");
      const expected = this.#prefix(bytes);
      if (length !== expected) reject("frame_boundary");
      // Full declared and actual sizes precede the only body copy.
      copy.call(this.#bytes, bytes); this.#used = expected; this.#expected = expected;
      return this.#publish();
    } catch (error) { this.#fail(); throw error; }
  }
  push(bytes: Uint8Array): EnvelopeProgress {
    this.#check();
    if (this.#config.mode !== "stream") reject("frame_boundary");
    try {
      const length = byteLength(bytes); let at = 0;
      if (this.#expected < 0) {
        const count = Math.min(envelopePrefixBytes - this.#used, length);
        copy.call(this.#bytes, byteSlice(bytes, 0, count), this.#used); this.#used += count; at += count;
        if (this.#used < envelopePrefixBytes) return Object.freeze({ consumed: at });
        this.#expected = this.#prefix(this.#bytes);
      }
      const count = Math.min(length - at, this.#expected - this.#used);
      copy.call(this.#bytes, byteSlice(bytes, at, at + count), this.#used); this.#used += count; at += count;
      return this.#used === this.#expected ? Object.freeze({ consumed: at, frame: this.#publish() }) : Object.freeze({ consumed: at });
    } catch (error) { this.#fail(); throw error; }
  }
  end(): void {
    if (this.#closed) return;
    if (this.#failed) reject("envelope_failed");
    if (this.#current !== undefined) reject("envelope_busy");
    this.#reservation!.check();
    if (this.#used !== 0) { this.#fail(); reject("truncated"); }
    this.close();
  }
  #publish(): EnvelopeFrame {
    if (this.#generation === (1n << 64n) - 1n) reject("envelope_closed");
    const frame = new EnvelopeFrame(capability, this, ++this.#generation); this.#current = frame; return frame;
  }
  #frame(frame: EnvelopeFrame): void {
    const state = frames.get(frame);
    if (state?.decoder !== this || state.generation !== this.#generation || this.#current !== frame) reject("envelope_released");
    if (this.#closed) reject("envelope_closed");
    this.#reservation!.check();
  }
  frameType(frame: EnvelopeFrame): number { this.#frame(frame); return this.#bytes[4]!; }
  payloadBytes(frame: EnvelopeFrame): number { this.#frame(frame); return this.#expected - envelopePrefixBytes; }
  copyFrame(frame: EnvelopeFrame, destination: Uint8Array, encoded: boolean): number {
    const capacity = byteLength(destination); this.#frame(frame);
    const start = encoded ? 0 : envelopePrefixBytes, length = this.#expected - start;
    if (capacity < length) reject("configuration_capacity");
    copy.call(destination, this.#bytes.subarray(start, this.#expected)); return length;
  }
  recordHeader(frame: EnvelopeFrame, profile: string): ParsedRecord {
    this.#frame(frame);
    return inspectRecordPrefix(this.#bytes, this.#expected - envelopePrefixBytes, profile);
  }
  release(frame: EnvelopeFrame): void {
    const state = frames.get(frame);
    if (state?.decoder !== this || this.#current !== frame) return;
    state.decoder = undefined; this.#current = undefined; this.#clear(); this.#cleanup();
  }
  #clear(): void { this.#bytes.fill(0, 0, this.#used); this.#used = 0; this.#expected = -1; }
  #fail(): void { this.#failed = true; this.#clear(); }
  close(): void { this.#closed = true; if (this.#current === undefined) this.#clear(); this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#current !== undefined) return;
    this.#bytes = empty; this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#closed && this.#reservation === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.EnvelopeDecoder"; }
}
for (const c of [EnvelopeDecoder, EnvelopeFrame]) { Object.freeze(c.prototype); Object.freeze(c); }
