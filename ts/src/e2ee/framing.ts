import { concatBytes, readU32be, readU64be, u32be, u64be } from "../utils/bin.js";
import { HANDSHAKE_MAGIC, PROTOCOL_VERSION, RECORD_MAGIC } from "./constants.js";

const te = new TextEncoder();

// Handshake header byte size: magic + version + type + length.
export const HANDSHAKE_HEADER_LEN = 4 + 1 + 1 + 4;
// Record header byte size: magic + version + flags + seq + length.
export const RECORD_HEADER_LEN = 4 + 1 + 1 + 8 + 4;

// FramingError marks malformed or truncated frames.
export class FramingError extends Error {}

// encodeHandshakeFrame builds the handshake header plus JSON payload.
export function encodeHandshakeFrame(handshakeType: number, payloadJsonUtf8: Uint8Array): Uint8Array {
  const header = new Uint8Array(HANDSHAKE_HEADER_LEN);
  header.set(te.encode(HANDSHAKE_MAGIC), 0);
  header[4] = PROTOCOL_VERSION;
  header[5] = handshakeType & 0xff;
  header.set(u32be(payloadJsonUtf8.length), 6);
  return concatBytes([header, payloadJsonUtf8]);
}

// decodeHandshakeFrame validates the handshake header and extracts the payload.
export function decodeHandshakeFrame(
  frame: Uint8Array,
  maxPayloadBytes: number
): { handshakeType: number; payloadJsonUtf8: Uint8Array } {
  if (frame.length < HANDSHAKE_HEADER_LEN) throw new FramingError("handshake frame too short");
  if (new TextDecoder().decode(frame.slice(0, 4)) !== HANDSHAKE_MAGIC) throw new FramingError("bad handshake magic");
  if (frame[4] !== PROTOCOL_VERSION) throw new FramingError("bad handshake version");
  const handshakeType = frame[5]!;
  const n = readU32be(frame, 6);
  if (maxPayloadBytes > 0 && n > maxPayloadBytes) throw new FramingError("handshake payload too large");
  if (HANDSHAKE_HEADER_LEN + n !== frame.length) throw new FramingError("handshake length mismatch");
  return { handshakeType, payloadJsonUtf8: frame.slice(HANDSHAKE_HEADER_LEN) };
}

// looksLikeRecordFrame checks whether a frame matches the record header shape.
export function looksLikeRecordFrame(frame: Uint8Array, maxCiphertextBytes: number): boolean {
  if (frame.length < RECORD_HEADER_LEN) return false;
  if (new TextDecoder().decode(frame.slice(0, 4)) !== RECORD_MAGIC) return false;
  if (frame[4] !== PROTOCOL_VERSION) return false;
  const n = readU32be(frame, 14);
  if (maxCiphertextBytes > 0 && n > maxCiphertextBytes) return false;
  return RECORD_HEADER_LEN + n === frame.length;
}

// encodeU64beBigint converts a bigint into an 8-byte big-endian buffer.
export function encodeU64beBigint(n: bigint): Uint8Array {
  return u64be(n);
}

// decodeU64beBigint reads a bigint from an 8-byte big-endian buffer.
export function decodeU64beBigint(buf: Uint8Array, off: number): bigint {
  return readU64be(buf, off);
}
