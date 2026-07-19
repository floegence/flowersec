import { gcm } from "@noble/ciphers/aes";
import { concatBytes, readU32be, readU64be, u32be, u64be } from "../utils/bin.js";
import { PROTOCOL_VERSION, RECORD_MAGIC, RECORD_FLAG_APP, RECORD_FLAG_PING, RECORD_FLAG_REKEY } from "./constants.js";

const recordMagicBytes = new TextEncoder().encode(RECORD_MAGIC);

// RecordFlag identifies the semantic meaning of a record frame.
export type RecordFlag = typeof RECORD_FLAG_APP | typeof RECORD_FLAG_PING | typeof RECORD_FLAG_REKEY;

// RecordError marks record parsing or cryptographic failures.
export class RecordError extends Error {}

// maxRecordSeq is the sequence boundary where a key epoch must stop before uint64 wrap.
const maxRecordSeq = (1n << 64n) - 1n;

function assertRecordSeq(seq: bigint): void {
  if (seq < 0n || seq > maxRecordSeq) throw new RecordError("record seq out of range");
}

// maxPlaintextBytes returns the payload cap derived from a record size limit.
export function maxPlaintextBytes(maxRecordBytes: number): number {
  if (maxRecordBytes <= 0) return 0;
  return maxRecordBytes - (4 + 1 + 1 + 8 + 4) - 16;
}

// encryptRecord builds an AEAD-protected record frame.
export function encryptRecord(
  key: Uint8Array,
  noncePrefix: Uint8Array,
  flags: RecordFlag,
  seq: bigint,
  plaintext: Uint8Array,
  maxRecordBytes: number
): Uint8Array {
  if (key.length !== 32) throw new RecordError("key must be 32 bytes");
  if (noncePrefix.length !== 4) throw new RecordError("noncePrefix must be 4 bytes");
  assertRecordSeq(seq);
  const cipherLen = plaintext.length + 16;
  if (cipherLen > 0xffffffff) throw new RecordError("record too large");
  const header = new Uint8Array(4 + 1 + 1 + 8 + 4);
  header.set(recordMagicBytes, 0);
  header[4] = PROTOCOL_VERSION;
  header[5] = flags & 0xff;
  header.set(u64be(seq), 6);
  header.set(u32be(cipherLen), 14);

  const nonce = concatBytes([noncePrefix, u64be(seq)]);
  const cipher = gcm(key, nonce, header).encrypt(plaintext);
  const out = concatBytes([header, cipher]);
  if (maxRecordBytes > 0 && out.length > maxRecordBytes) throw new RecordError("record too large");
  return out;
}

// decryptRecord validates and decrypts a record frame.
export function decryptRecord(
  key: Uint8Array,
  noncePrefix: Uint8Array,
  frame: Uint8Array,
  expectSeq: bigint | null,
  maxRecordBytes: number
): { flags: number; seq: bigint; plaintext: Uint8Array } {
  if (key.length !== 32) throw new RecordError("key must be 32 bytes");
  if (noncePrefix.length !== 4) throw new RecordError("noncePrefix must be 4 bytes");
  const headerLen = 4 + 1 + 1 + 8 + 4;
  if (maxRecordBytes > 0 && frame.length > maxRecordBytes) throw new RecordError("record too large");
  if (frame.length < headerLen) throw new RecordError("record too short");
  if (
    frame[0] !== recordMagicBytes[0] ||
    frame[1] !== recordMagicBytes[1] ||
    frame[2] !== recordMagicBytes[2] ||
    frame[3] !== recordMagicBytes[3]
  ) {
    throw new RecordError("bad record magic");
  }
  if (frame[4] !== PROTOCOL_VERSION) throw new RecordError("bad record version");
  const flags = frame[5]!;
  if (flags !== RECORD_FLAG_APP && flags !== RECORD_FLAG_PING && flags !== RECORD_FLAG_REKEY) {
    throw new RecordError("bad record flag");
  }
  const seq = readU64be(frame, 6);
  if (expectSeq != null && seq !== expectSeq) throw new RecordError(`bad seq: got=${seq} want=${expectSeq}`);
  const n = readU32be(frame, 14);
  if (headerLen + n !== frame.length) throw new RecordError("length mismatch");
  const nonce = concatBytes([noncePrefix, u64be(seq)]);
  try {
    const plaintext = gcm(key, nonce, frame.subarray(0, headerLen)).decrypt(frame.subarray(headerLen));
    return { flags, seq, plaintext };
  } catch (e) {
    throw new RecordError(`decrypt failed: ${String(e)} len=${frame.length}`);
  }
}
