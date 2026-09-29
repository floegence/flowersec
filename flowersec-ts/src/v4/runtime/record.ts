import { byteLength, byteSlice } from "./cbor.js";
import { EnvelopeError, type RecordHeader } from "./envelope.js";
import { wireDomains } from "./schemaRegistry.js";
import { binaryWidth, datagramScope, envelopePrefixBytes, inFrameClass, maxStreamScope, ownProfile, recordHeaderBytes, wire, type BinaryField } from "./wireRegistry.js";

// These pure encoders use caller-owned, already admitted destinations. They
// neither look up keys nor allocate peer-sized output, advance a sequence,
// consume a nonce, or establish record acceptance/replay state.
const copy = Uint8Array.prototype.set;
const maximum = (1n << 64n) - 1n;
export type RecordDirection = 0 | 1;
function configuration(): never { throw new EnvelopeError("configuration_capacity"); }
function checked(value: bigint, bytes: number): bigint {
  if (typeof value !== "bigint" || value < 0n || value >= 1n << BigInt(bytes * 8)) configuration();
  return value;
}
function captureHeader(header: RecordHeader): RecordHeader {
  const epoch = header.epoch, scope = header.scope, sequence = header.sequence;
  if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > 0xffffffff || typeof scope !== "bigint" || scope < 0n || scope > maximum ||
    typeof sequence !== "bigint" || sequence < 0n || sequence > maximum) configuration();
  return Object.freeze({ epoch, scope, sequence });
}
function writeInteger(output: Uint8Array, offset: number, value: bigint, bytes: number): number {
  for (let i = bytes - 1; i >= 0; i--) { output[offset + i] = Number(value & 255n); value >>= 8n; }
  return offset + bytes;
}
function validateLayout(layout: readonly BinaryField[], values: Readonly<Record<string, bigint>>): number {
  let size = 0;
  for (const field of layout) {
    const width = binaryWidth(field.type), value = field.const === undefined ? values[field.name] : BigInt(field.const);
    if (value === undefined) configuration();
    checked(value, width);
    if (field.max !== undefined && value > BigInt(field.max)) configuration();
    size += width;
  }
  return size;
}
function writeLayout(output: Uint8Array, at: number, layout: readonly BinaryField[], values: Readonly<Record<string, bigint>>): number {
  for (const field of layout) at = writeInteger(output, at, field.const === undefined ? values[field.name]! : BigInt(field.const), binaryWidth(field.type));
  return at;
}
export function validateRecordScope(frame: number, scope: bigint): void {
  if (typeof scope !== "bigint" || scope < 0n || scope > maximum) throw new EnvelopeError("invalid_scope");
  if (frame === wire.frame_types.DATAGRAM) {
    if (scope !== datagramScope) throw new EnvelopeError("invalid_scope");
  } else if (frame === wire.frame_types.OPEN_STREAM || frame === wire.frame_types.STREAM_DATA) {
    if (scope < BigInt(wire.resource_caps.scope_id.min) || scope > maxStreamScope) throw new EnvelopeError("invalid_scope");
  } else if (inFrameClass(frame, "maintenance_record") || inFrameClass(frame, "record_cipher")) {
    if (scope !== 0n) throw new EnvelopeError("invalid_scope");
  } else throw new EnvelopeError("unknown_frame");
}
export function encodeRecordPrefix(frame: number, original: RecordHeader, plaintextBytes: number, profile: string, maxFrame: number, output: Uint8Array): number {
  const header = captureHeader(original), p = ownProfile(profile), capacity = byteLength(output);
  if (p === undefined) throw new EnvelopeError("invalid_profile");
  validateRecordScope(frame, header.scope);
  if (!Number.isSafeInteger(maxFrame) || maxFrame < 1 || maxFrame > wire.resource_caps.max_payload_length || !Number.isSafeInteger(plaintextBytes) || plaintextBytes < 0) configuration();
  const payload = plaintextBytes + recordHeaderBytes + p.tag_bytes;
  if (payload > maxFrame || frame === wire.frame_types.DATAGRAM && payload + envelopePrefixBytes > wire.resource_caps.max_datagram_envelope) throw new EnvelopeError("payload_too_large");
  const envelope = { payload_length: BigInt(payload), frame_type: BigInt(frame) }, values = { epoch: BigInt(header.epoch), sequence_scope: header.scope, sequence: header.sequence };
  const size = validateLayout(wire.envelope.layout, envelope) + validateLayout(wire.header, values);
  if (capacity < size) configuration();
  const at = writeLayout(output, 0, wire.envelope.layout, envelope);
  return writeLayout(output, at, wire.header, values);
}
export function encodeRecordNonce(original: RecordHeader, output: Uint8Array): number {
  const header = captureHeader(original), capacity = byteLength(output), values = { epoch: BigInt(header.epoch), sequence: header.sequence };
  const size = validateLayout(wire.nonce, values);
  if (capacity < size) configuration();
  return writeLayout(output, 0, wire.nonce, values);
}
function domain(name: "record_key" | "record_aad", profile: string, direction: RecordDirection, bytes: Readonly<Record<string, Uint8Array>>,
  integers: Readonly<Record<string, bigint>>, output: Uint8Array): number {
  if (ownProfile(profile) === undefined) throw new EnvelopeError("invalid_profile");
  if (direction !== 0 && direction !== 1) configuration();
  const spec = wireDomains.find(d => d.name === name);
  if (spec === undefined) configuration();
  const capacity = byteLength(output);
  let size = spec.label_bytes.length / 2;
  // Every part is measured and validated before any destination write. Inputs
  // here are captured SDK primitives and original synchronous byte borrows.
  for (const part of spec.input_schema.parts) {
    if (part.encoding === "lp-ascii") {
      if (part.name !== "profile" || !/^[\x00-\x7f]+$/u.test(profile)) configuration();
      size += 4 + profile.length;
    } else if (part.encoding === "raw" || part.encoding === "lp-bytes") {
      const value = bytes[part.name]; if (value === undefined) configuration();
      const length = byteLength(value);
      if (part.length !== undefined && length !== part.length) configuration();
      size += length + (part.encoding === "raw" ? 0 : 4);
    } else {
      const width = part.encoding === "u8" ? 1 : part.encoding === "u32" ? 4 : part.encoding === "u64" ? 8 : 0;
      if (width === 0) configuration();
      const n = part.name === "direction" ? BigInt(direction) : integers[part.name];
      if (n === undefined) configuration();
      checked(n, width);
      if (part.enum !== undefined && !part.enum.some(v => BigInt(v) === n)) configuration();
      size += width;
    }
  }
  if (capacity < size) configuration();
  // Reject any destination that aliases a source; writing the leading label
  // cannot change a later original handshake hash or authenticated header.
  for (const value of Object.values(bytes)) if (byteSlice(value, 0, 0).buffer === byteSlice(output, 0, 0).buffer) configuration();
  let at = 0;
  for (let i = 0; i < spec.label_bytes.length / 2; i++) output[at++] = Number.parseInt(spec.label_bytes.slice(i * 2, i * 2 + 2), 16);
  for (const part of spec.input_schema.parts) {
    if (part.encoding === "lp-ascii") {
      at = writeInteger(output, at, BigInt(profile.length), 4);
      for (let i = 0; i < profile.length; i++) output[at++] = profile.charCodeAt(i);
    } else if (part.encoding === "raw" || part.encoding === "lp-bytes") {
      const value = bytes[part.name]!, length = byteLength(value);
      if (part.encoding !== "raw") at = writeInteger(output, at, BigInt(length), 4);
      copy.call(output, value, at); at += length;
    } else {
      const width = part.encoding === "u8" ? 1 : part.encoding === "u32" ? 4 : 8;
      at = writeInteger(output, at, part.name === "direction" ? BigInt(direction) : integers[part.name]!, width);
    }
  }
  return at;
}
export function encodeRecordKeyInfo(profile: string, handshakeHash: Uint8Array, epoch: number, direction: RecordDirection, scope: bigint, output: Uint8Array): number {
  const header = captureHeader({ epoch, scope, sequence: 0n });
  if (scope > maxStreamScope && scope !== datagramScope) throw new EnvelopeError("invalid_scope");
  if (byteLength(handshakeHash) !== 32) configuration();
  return domain("record_key", profile, direction, { handshake_hash: handshakeHash }, { epoch: BigInt(header.epoch), sequence_scope: header.scope }, output);
}
export function encodeRecordAAD(profile: string, direction: RecordDirection, originalPrefix: Uint8Array, output: Uint8Array): number {
  const size = byteLength(originalPrefix);
  if (size !== envelopePrefixBytes + recordHeaderBytes) throw new EnvelopeError("truncated");
  return domain("record_aad", profile, direction, { envelope_header: byteSlice(originalPrefix, 0, envelopePrefixBytes), record_header: byteSlice(originalPrefix, envelopePrefixBytes, size) }, {}, output);
}
