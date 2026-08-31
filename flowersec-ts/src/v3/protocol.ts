import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { expand } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { unicode151Assigned } from "../generated/unicode151.js";
import { FLOWERSEC_V3_CRYPTO_LABELS } from "./transportConstants.js";

const encoder = new TextEncoder();
const MAX_UINT32 = 0xffffffff;
const MAX_UINT64 = (1n << 64n) - 1n;
const SETUP_PREFACE_BYTES = 56;
const RECORD_HEADER_BYTES = 24;
const INNER_HEADER_BYTES = 8;
const MAX_DATA_BYTES = 16_384;
const MAX_CIPHERTEXT_BYTES = INNER_HEADER_BYTES + MAX_DATA_BYTES + 16;
const OPEN_FIXED_PAYLOAD_BYTES = 46;
const MAX_OPEN_BYTES = 8_192;
const MAX_OPEN_KIND_BYTES = 128;
const MAX_OPEN_METADATA_BYTES = 4_096;
const MAX_OPEN_METADATA_DEPTH = 4;
const MAX_OPEN_METADATA_NODES = 64;
const MAX_OPEN_METADATA_KEYS = 64;
const MAX_OPEN_METADATA_ARRAY = 32;
const MAX_OPEN_METADATA_KEY_BYTES = 64;
const MAX_OPEN_METADATA_STRING_BYTES = 512;
 const strictDecoder = new TextDecoder("utf-8", { fatal: true });

export class ProtocolV3Error extends Error {}

export enum DirectionV3 {
  ClientToServer = 1,
  ServerToClient = 2,
}

export enum CipherSuiteV3 {
  ChaCha20Poly1305 = 1,
  AES256GCM = 2,
}

export type EpochRootsV3 = Readonly<{
  epochSecret: Uint8Array;
  controlRoot: Uint8Array;
  streamRoot: Uint8Array;
  setupRoot: Uint8Array;
  rekeyRoot: Uint8Array;
}>;

export type RecordMaterialV3 = Readonly<{
  secret: Uint8Array;
  recordKey: Uint8Array;
  noncePrefix: Uint8Array;
}>;

export type SetupPrefaceV3 = Readonly<{
  openerRole: 1 | 2;
  logicalStreamID: bigint;
  initialSendEpoch: number;
  setupMAC: Uint8Array;
}>;

export type RecordHeaderV3 = Readonly<{
  epoch: number;
  sequence: bigint;
  ciphertextLength: number;
}>;

export type OpenPayloadV3 = Readonly<{
  logicalStreamID: bigint;
  fss3Hash: Uint8Array;
  kind: string;
  metadata: Uint8Array;
}>;

export enum InnerTypeV3 {
  Open = 1,
  OpenACK = 2,
  OpenReject = 3,
  Data = 4,
  FIN = 5,
  StreamKeyUpdate = 6,
  SessionReady = 16,
  Ping = 17,
  Pong = 18,
  SessionKeyUpdate = 19,
  StreamReset = 20,
  GoAway = 21,
  SessionClose = 22,
  SessionReadyACK = 23,
  SessionKeyUpdateACK = 24,
  StreamKeyUpdateACK = 25,
  SessionReadyConfirm = 26,
}

export type InnerRecordV3 = Readonly<{
  type: InnerTypeV3;
  payload: Uint8Array;
}>;

export type OpenRejectV3 = Readonly<{
  openHash: Uint8Array;
  reason: number;
  knownReason: boolean;
}>;

export type StreamKeyUpdateACKV3 = Readonly<{
  logicalStreamID: bigint;
  transition: bigint;
  epoch: number;
}>;

export function deriveEpochZero(
  sessionPRK: Uint8Array,
  direction: DirectionV3,
): EpochRootsV3 {
  assertBytes("session PRK", sessionPRK, 32);
  assertDirection(direction);
  const epochSecret = expand32(
    sessionPRK,
    labelWith(FLOWERSEC_V3_CRYPTO_LABELS["epoch-zero"], byte(direction)),
  );
  return deriveEpochRoots(epochSecret);
}

export function deriveEpochRoots(epochSecret: Uint8Array): EpochRootsV3 {
  assertBytes("epoch secret", epochSecret, 32);
  return {
    epochSecret: epochSecret.slice(),
    controlRoot: expand32(epochSecret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["control-root"])),
    streamRoot: expand32(epochSecret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["stream-root"])),
    setupRoot: expand32(epochSecret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["setup-root"])),
    rekeyRoot: expand32(epochSecret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["rekey-root"])),
  };
}

export function deriveNextEpoch(
  rekeyRoot: Uint8Array,
  h3: Uint8Array,
  direction: DirectionV3,
  nextEpoch: number,
): Uint8Array {
  assertBytes("rekey root", rekeyRoot, 32);
  assertBytes("H3", h3, 32);
  assertDirection(direction);
  assertU32("next epoch", nextEpoch);
  return expand32(
    rekeyRoot,
    labelWith(FLOWERSEC_V3_CRYPTO_LABELS["next-epoch"], h3, byte(direction), u32be(nextEpoch)),
  );
}

export function deriveStreamMaterial(
  streamRoot: Uint8Array,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV3,
  epoch: number,
): RecordMaterialV3 {
  assertBytes("stream root", streamRoot, 32);
  assertBytes("H3", h3, 32);
  assertLogicalStreamID(logicalStreamID);
  assertDirection(direction);
  assertU32("epoch", epoch);
  const secret = expand32(
    streamRoot,
    labelWith(
      FLOWERSEC_V3_CRYPTO_LABELS.stream,
      h3,
      u64be(logicalStreamID),
      byte(direction),
      u32be(epoch),
    ),
  );
  return {
    secret,
    recordKey: expand32(secret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["record-key"])),
    noncePrefix: expand(sha256, secret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS.nonce), 4),
  };
}

export function deriveControlMaterial(
  controlRoot: Uint8Array,
  h3: Uint8Array,
  direction: DirectionV3,
  epoch: number,
): RecordMaterialV3 {
  assertBytes("control root", controlRoot, 32);
  assertBytes("H3", h3, 32);
  assertDirection(direction);
  assertU32("epoch", epoch);
  const secret = expand32(
    controlRoot,
    labelWith(
      FLOWERSEC_V3_CRYPTO_LABELS.control,
      h3,
      u64be(0n),
      byte(direction),
      u32be(epoch),
    ),
  );
  return {
    secret,
    recordKey: expand32(secret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["record-key"])),
    noncePrefix: expand(sha256, secret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS.nonce), 4),
  };
}

export function computeSetupMAC(
  setupRoot: Uint8Array,
  h3: Uint8Array,
  preface: SetupPrefaceV3,
): Uint8Array {
  assertBytes("setup root", setupRoot, 32);
  assertBytes("H3", h3, 32);
  const raw = encodeSetupPreface(preface);
  return hmac(
    sha256,
    setupRoot,
    exactLabelWith(FLOWERSEC_V3_CRYPTO_LABELS["setup-mac"], h3, raw.subarray(0, 24)),
  );
}

export function encodeSetupPreface(preface: SetupPrefaceV3): Uint8Array {
  assertLogicalStreamID(preface.logicalStreamID);
  if (
    (preface.openerRole !== 1 && preface.openerRole !== 2) ||
    (preface.openerRole === 1 && (preface.logicalStreamID & 1n) !== 1n) ||
    (preface.openerRole === 2 && (preface.logicalStreamID & 1n) !== 0n)
  ) {
    throw new ProtocolV3Error("invalid FSS3 opener or logical stream ID");
  }
  assertU32("initial send epoch", preface.initialSendEpoch);
  assertBytes("setup MAC", preface.setupMAC, 32);
  const out = new Uint8Array(SETUP_PREFACE_BYTES);
  out.set(encoder.encode("FSS3"), 0);
  out[4] = 3;
  out[5] = preface.openerRole;
  out.set(u64be(preface.logicalStreamID), 8);
  out.set(u32be(preface.initialSendEpoch), 16);
  out.set(preface.setupMAC, 24);
  return out;
}

export function decodeSetupPrefaceV3(raw: Uint8Array): SetupPrefaceV3 {
  if (
    raw.length !== SETUP_PREFACE_BYTES ||
    raw[0] !== 0x46 || raw[1] !== 0x53 || raw[2] !== 0x53 || raw[3] !== 0x33 ||
    raw[4] !== 3 || raw[6] !== 0 || raw[7] !== 0 || readU32be(raw, 20) !== 0
  ) {
    throw new ProtocolV3Error("invalid FSS3 setup preface");
  }
  const openerRole = raw[5];
  const logicalStreamID = readU64be(raw, 8);
  if (
    (openerRole !== 1 && openerRole !== 2) ||
    logicalStreamID === 0n ||
    (openerRole === 1 && (logicalStreamID & 1n) !== 1n) ||
    (openerRole === 2 && (logicalStreamID & 1n) !== 0n)
  ) {
    throw new ProtocolV3Error("invalid FSS3 opener or logical stream ID");
  }
  return {
    openerRole,
    logicalStreamID,
    initialSendEpoch: readU32be(raw, 16),
    setupMAC: raw.slice(24, 56),
  };
}

export function verifySetupMAC(
  setupRoot: Uint8Array,
  h3: Uint8Array,
  preface: SetupPrefaceV3,
): boolean {
  const want = computeSetupMAC(setupRoot, h3, { ...preface, setupMAC: new Uint8Array(32) });
  return bytesEqual(want, preface.setupMAC);
}

export function computeFSS3HashV3(raw: Uint8Array): Uint8Array {
  decodeSetupPrefaceV3(raw);
  return computeValidatedFSS3HashV3Internal(raw);
}

/** @internal Hashes an FSS3 preface that was encoded or decoded by this module. */
export function computeValidatedFSS3HashV3Internal(raw: Uint8Array): Uint8Array {
  return sha256(raw);
}

export function encodeRecordHeader(header: RecordHeaderV3): Uint8Array {
  validateRecordHeader(header);
  const out = new Uint8Array(RECORD_HEADER_BYTES);
  out.set(encoder.encode("FSR3"), 0);
  out[4] = 3;
  out[5] = RECORD_HEADER_BYTES;
  out.set(u32be(header.epoch), 8);
  out.set(u64be(header.sequence), 12);
  out.set(u32be(header.ciphertextLength), 20);
  return out;
}

export function decodeRecordHeader(raw: Uint8Array): RecordHeaderV3 {
  if (
    raw.length !== RECORD_HEADER_BYTES ||
    raw[0] !== 0x46 ||
    raw[1] !== 0x53 ||
    raw[2] !== 0x52 ||
    raw[3] !== 0x33 ||
    raw[4] !== 3 ||
    raw[5] !== RECORD_HEADER_BYTES ||
    raw[6] !== 0 ||
    raw[7] !== 0
  ) {
    throw new ProtocolV3Error("invalid FSR3 header");
  }
  const header = {
    epoch: readU32be(raw, 8),
    sequence: readU64be(raw, 12),
    ciphertextLength: readU32be(raw, 20),
  };
  validateRecordHeader(header);
  return header;
}

export function buildDataInner(payload: Uint8Array): Uint8Array {
  if (payload.length < 1 || payload.length > MAX_DATA_BYTES) {
    throw new ProtocolV3Error("invalid v3 DATA payload length");
  }
  const out = new Uint8Array(INNER_HEADER_BYTES + payload.length);
  out[0] = 4;
  out.set(u32be(payload.length), 4);
  out.set(payload, INNER_HEADER_BYTES);
  return out;
}

export function encodeInnerRecordV3(type: InnerTypeV3, payload: Uint8Array): Uint8Array {
  validateInnerPayload(type, payload.length);
  const out = new Uint8Array(INNER_HEADER_BYTES + payload.length);
  out[0] = type;
  out.set(u32be(payload.length), 4);
  out.set(payload, INNER_HEADER_BYTES);
  return out;
}

export function decodeInnerRecordV3(raw: Uint8Array): InnerRecordV3 {
  if (raw.length < INNER_HEADER_BYTES || raw[1] !== 0 || raw[2] !== 0 || raw[3] !== 0) {
    throw new ProtocolV3Error("invalid FSR3 inner record");
  }
  const length = readU32be(raw, 4);
  if (raw.length !== INNER_HEADER_BYTES + length) {
    throw new ProtocolV3Error("invalid FSR3 inner record length");
  }
  const type = raw[0]! as InnerTypeV3;
  validateInnerPayload(type, length);
  return { type, payload: raw.slice(INNER_HEADER_BYTES) };
}

export function encodeOpenPayload(payload: OpenPayloadV3): Uint8Array {
  assertLogicalStreamID(payload.logicalStreamID);
  assertBytes("FSS3 hash", payload.fss3Hash, 32);
  const kind = validateOpenKind(payload.kind);
  const metadata = canonicalMetadata(payload.metadata, true);
  return encodeValidatedOpenPayload(payload.logicalStreamID, payload.fss3Hash, kind, metadata);
}

/** @internal Encodes OPEN directly from an application metadata value after one strict validation pass. */
export function encodeOpenPayloadFromMetadataV3Internal(
  payload: Readonly<{
    logicalStreamID: bigint;
    fss3Hash: Uint8Array;
    kind: string;
    metadata: unknown;
  }>,
): Uint8Array {
  assertLogicalStreamID(payload.logicalStreamID);
  assertBytes("FSS3 hash", payload.fss3Hash, 32);
  const kind = validateOpenKind(payload.kind);
  const metadata = encoder.encode(canonicalStreamMetadataJSONV3Internal(payload.metadata));
  return encodeValidatedOpenPayload(payload.logicalStreamID, payload.fss3Hash, kind, metadata);
}

function encodeValidatedOpenPayload(
  logicalStreamID: bigint,
  fss3Hash: Uint8Array,
  kind: Uint8Array,
  metadata: Uint8Array,
): Uint8Array {
  const total = OPEN_FIXED_PAYLOAD_BYTES + kind.length + metadata.length;
  if (total > MAX_OPEN_BYTES)
    throw new ProtocolV3Error("OPEN payload is too large");
  const out = new Uint8Array(total);
  out.set(u64be(logicalStreamID), 0);
  out.set(fss3Hash, 8);
  new DataView(out.buffer).setUint16(40, kind.length, false);
  new DataView(out.buffer).setUint32(42, metadata.length, false);
  out.set(kind, OPEN_FIXED_PAYLOAD_BYTES);
  out.set(metadata, OPEN_FIXED_PAYLOAD_BYTES + kind.length);
  return out;
}

export function decodeOpenPayload(raw: Uint8Array): OpenPayloadV3 {
  if (raw.length < OPEN_FIXED_PAYLOAD_BYTES || raw.length > MAX_OPEN_BYTES) {
    throw new ProtocolV3Error("invalid OPEN payload length");
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const logicalStreamID = view.getBigUint64(0, false);
  assertLogicalStreamID(logicalStreamID);
  const kindLength = view.getUint16(40, false);
  const metadataLength = view.getUint32(42, false);
  if (OPEN_FIXED_PAYLOAD_BYTES + kindLength + metadataLength !== raw.length) {
    throw new ProtocolV3Error("invalid OPEN field lengths");
  }
  let kind: string;
  try {
    kind = strictDecoder.decode(
      raw.subarray(
        OPEN_FIXED_PAYLOAD_BYTES,
        OPEN_FIXED_PAYLOAD_BYTES + kindLength,
      ),
    );
  } catch {
    throw new ProtocolV3Error("OPEN kind is not valid UTF-8");
  }
  validateOpenKind(kind);
  const metadata = canonicalMetadata(
    raw.subarray(OPEN_FIXED_PAYLOAD_BYTES + kindLength),
    false,
  );
  return {
    logicalStreamID,
    fss3Hash: raw.slice(8, 40),
    kind,
    metadata,
  };
}

export function computeOpenHashV3(rawOpenPayload: Uint8Array): Uint8Array {
  decodeOpenPayload(rawOpenPayload);
  return computeValidatedOpenHashV3Internal(rawOpenPayload);
}

/** @internal Hashes an OPEN payload that was encoded or decoded by this module. */
export function computeValidatedOpenHashV3Internal(rawOpenPayload: Uint8Array): Uint8Array {
  return sha256(concat(
    encoder.encode(FLOWERSEC_V3_CRYPTO_LABELS.open),
    u32be(rawOpenPayload.length),
    rawOpenPayload,
  ));
}

export function encodeOpenACKV3(openHash: Uint8Array): Uint8Array {
  assertBytes("OPEN hash", openHash, 32);
  return openHash.slice();
}

export function decodeOpenACKV3(raw: Uint8Array): Uint8Array {
  assertBytes("OPEN ACK", raw, 32);
  return raw.slice();
}

export function encodeOpenRejectV3(openHash: Uint8Array, reason: number): Uint8Array {
  assertBytes("OPEN hash", openHash, 32);
  if (!Number.isInteger(reason) || reason < 1 || reason > 5) {
    throw new ProtocolV3Error("invalid OPEN reject reason");
  }
  const out = new Uint8Array(34);
  out.set(openHash);
  new DataView(out.buffer).setUint16(32, reason, false);
  return out;
}

export function decodeOpenRejectV3(raw: Uint8Array): OpenRejectV3 {
  if (raw.length !== 34) throw new ProtocolV3Error("invalid OPEN reject payload");
  const reason = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint16(32, false);
  if (reason === 0) throw new ProtocolV3Error("invalid OPEN reject reason");
  return { openHash: raw.slice(0, 32), reason, knownReason: reason >= 1 && reason <= 5 };
}

export function encodeStreamKeyUpdateACKV3(value: StreamKeyUpdateACKV3): Uint8Array {
  assertLogicalStreamID(value.logicalStreamID);
  assertU64("stream rekey transition", value.transition);
  if (value.transition === 0n) throw new ProtocolV3Error("stream rekey transition must be non-zero");
  assertU32("stream rekey epoch", value.epoch);
  return concat(u64be(value.logicalStreamID), u64be(value.transition), u32be(value.epoch));
}

export function decodeStreamKeyUpdateACKV3(raw: Uint8Array): StreamKeyUpdateACKV3 {
  if (raw.length !== 20) throw new ProtocolV3Error("invalid STREAM_KEY_UPDATE_ACK payload");
  const value = {
    logicalStreamID: readU64be(raw, 0),
    transition: readU64be(raw, 8),
    epoch: readU32be(raw, 16),
  } as const;
  assertLogicalStreamID(value.logicalStreamID);
  if (value.transition === 0n) throw new ProtocolV3Error("stream rekey transition must be non-zero");
  if (value.epoch === 0) throw new ProtocolV3Error("stream rekey epoch must be non-zero");
  return value;
}

export function buildRecordAAD(
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV3,
  rawHeader: Uint8Array,
): Uint8Array {
  assertBytes("H3", h3, 32);
  assertU64("logical stream ID", logicalStreamID);
  assertDirection(direction);
  decodeRecordHeader(rawHeader);
  return buildValidatedRecordAAD(h3, logicalStreamID, direction, rawHeader);
}

function buildValidatedRecordAAD(
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV3,
  rawHeader: Uint8Array,
): Uint8Array {
  return exactLabelWith(
    FLOWERSEC_V3_CRYPTO_LABELS["record-aad"],
    h3,
    u64be(logicalStreamID),
    byte(direction),
    rawHeader,
  );
}

export function sealRecord(
  suite: CipherSuiteV3,
  material: RecordMaterialV3,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV3,
  header: RecordHeaderV3,
  plaintext: Uint8Array,
): Uint8Array {
  assertBytes("H3", h3, 32);
  assertDirection(direction);
  return sealRecordWireV3Internal(suite, material, h3, logicalStreamID, direction, header, plaintext).ciphertext;
}

/** @internal Seals a validated record and returns the single encoded header used as AAD and on wire. */
export function sealRecordWireV3Internal(
  suite: CipherSuiteV3,
  material: RecordMaterialV3,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV3,
  header: RecordHeaderV3,
  plaintext: Uint8Array,
): Readonly<{ rawHeader: Uint8Array; ciphertext: Uint8Array }> {
  validateMaterial(material);
  if (plaintext.length + 16 !== header.ciphertextLength) {
    throw new ProtocolV3Error(
      "FSR3 plaintext length does not match the header",
    );
  }
  const rawHeader = encodeRecordHeader(header);
  const nonce = concat(material.noncePrefix, u64be(header.sequence));
  const aad = buildValidatedRecordAAD(h3, logicalStreamID, direction, rawHeader);
  return { rawHeader, ciphertext: cipher(suite, material.recordKey, nonce, aad).encrypt(plaintext) };
}

export function openRecord(
  suite: CipherSuiteV3,
  material: RecordMaterialV3,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV3,
  header: RecordHeaderV3,
  ciphertext: Uint8Array,
): Uint8Array {
  assertBytes("H3", h3, 32);
  assertDirection(direction);
  const rawHeader = encodeRecordHeader(header);
  return openRecordWithRawHeaderV3Internal(
    suite, material, h3, logicalStreamID, direction, header, rawHeader, ciphertext,
  );
}

/** @internal Opens a record whose exact raw header was already decoded by this module. */
export function openRecordWithRawHeaderV3Internal(
  suite: CipherSuiteV3,
  material: RecordMaterialV3,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV3,
  header: RecordHeaderV3,
  rawHeader: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  validateMaterial(material);
  if (ciphertext.length !== header.ciphertextLength) {
    throw new ProtocolV3Error(
      "FSR3 ciphertext length does not match the header",
    );
  }
  const nonce = concat(material.noncePrefix, u64be(header.sequence));
  const aad = buildValidatedRecordAAD(h3, logicalStreamID, direction, rawHeader);
  try {
    return cipher(suite, material.recordKey, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new ProtocolV3Error("v3 record authentication failed");
  }
}

function cipher(
  suite: CipherSuiteV3,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
) {
  switch (suite) {
    case CipherSuiteV3.ChaCha20Poly1305:
      return chacha20poly1305(key, nonce, aad);
    case CipherSuiteV3.AES256GCM:
      return gcm(key, nonce, aad);
    default:
      throw new ProtocolV3Error("invalid v3 cipher suite");
  }
}

function validateMaterial(material: RecordMaterialV3): void {
  assertBytes("record key", material.recordKey, 32);
  assertBytes("nonce prefix", material.noncePrefix, 4);
}

function validateRecordHeader(header: RecordHeaderV3): void {
  assertU32("record epoch", header.epoch);
  assertU64("record sequence", header.sequence);
  if (
    !Number.isInteger(header.ciphertextLength) ||
    header.ciphertextLength < 16 ||
    header.ciphertextLength > MAX_CIPHERTEXT_BYTES
  ) {
    throw new ProtocolV3Error("invalid FSR3 ciphertext length");
  }
}

function validateInnerPayload(type: InnerTypeV3, length: number): void {
  switch (type) {
    case InnerTypeV3.Open:
      if (length >= 1 && length <= MAX_OPEN_BYTES) return;
      break;
    case InnerTypeV3.Data:
      if (length >= 1 && length <= MAX_DATA_BYTES) return;
      break;
    case InnerTypeV3.FIN:
    case InnerTypeV3.SessionReady:
    case InnerTypeV3.SessionReadyACK:
    case InnerTypeV3.SessionReadyConfirm:
      if (length === 0) return;
      break;
    case InnerTypeV3.OpenACK:
      if (length === 32) return;
      break;
    case InnerTypeV3.OpenReject:
      if (length === 34) return;
      break;
    case InnerTypeV3.StreamKeyUpdate:
      if (length === 12) return;
      break;
    case InnerTypeV3.Ping:
    case InnerTypeV3.Pong:
      if (length === 8) return;
      break;
    case InnerTypeV3.SessionKeyUpdate:
    case InnerTypeV3.SessionKeyUpdateACK:
    case InnerTypeV3.StreamKeyUpdateACK:
      if (length === 20) return;
      break;
    case InnerTypeV3.StreamReset:
    case InnerTypeV3.GoAway:
      if (length === 10) return;
      break;
    case InnerTypeV3.SessionClose:
      if (length === 2) return;
      break;
    default:
      throw new ProtocolV3Error(`unknown FSR3 inner type ${type}`);
  }
  throw new ProtocolV3Error(`invalid FSR3 inner payload length for type ${type}`);
}

function expand32(prk: Uint8Array, info: Uint8Array): Uint8Array {
  return expand(sha256, prk, info, 32);
}

function labelWith(label: string, ...parts: Uint8Array[]): Uint8Array {
  return concat(encoder.encode(label), byte(0), ...parts);
}

function exactLabelWith(label: string, ...parts: Uint8Array[]): Uint8Array {
  return concat(encoder.encode(label), ...parts);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function byte(value: number): Uint8Array {
  return Uint8Array.of(value);
}

function u32be(value: number): Uint8Array {
  assertU32("uint32", value);
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64be(value: bigint): Uint8Array {
  assertU64("uint64", value);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function readU32be(value: Uint8Array, offset: number): number {
  return new DataView(
    value.buffer,
    value.byteOffset,
    value.byteLength,
  ).getUint32(offset, false);
}

function readU64be(value: Uint8Array, offset: number): bigint {
  return new DataView(
    value.buffer,
    value.byteOffset,
    value.byteLength,
  ).getBigUint64(offset, false);
}

function assertDirection(direction: DirectionV3): void {
  if (
    direction !== DirectionV3.ClientToServer &&
    direction !== DirectionV3.ServerToClient
  ) {
    throw new ProtocolV3Error("invalid v3 direction");
  }
}

function assertLogicalStreamID(value: bigint): void {
  assertU64("logical stream ID", value);
  if (value === 0n)
    throw new ProtocolV3Error("logical stream ID must be non-zero");
}

function assertU32(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > MAX_UINT32) {
    throw new ProtocolV3Error(`${name} must be uint32`);
  }
}

function assertU64(name: string, value: bigint): void {
  if (value < 0n || value > MAX_UINT64)
    throw new ProtocolV3Error(`${name} must be uint64`);
}

function assertBytes(name: string, value: Uint8Array, length: number): void {
  if (value.length !== length)
    throw new ProtocolV3Error(`${name} must be ${length} bytes`);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function validateOpenKind(value: string): Uint8Array {
  const encoded = encoder.encode(value);
  if (!validApplicationStreamKind(value)) {
    throw new ProtocolV3Error("invalid OPEN kind");
  }
  return encoded;
}

/** @internal */
export function validApplicationStreamKind(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    !validOpenUnicodeString(value, MAX_OPEN_KIND_BYTES, false)
  ) {
    return false;
  }
  const scalars = Array.from(value);
  return !(
    isUnicodeWhitespace(scalars[0]!.codePointAt(0)!) ||
    isUnicodeWhitespace(scalars.at(-1)!.codePointAt(0)!)
  );
}

function canonicalMetadata(raw: Uint8Array, allowEmpty: boolean): Uint8Array {
  if (raw.length === 0 && allowEmpty) return encoder.encode("{}");
  if (raw.length === 0 || raw.length > MAX_OPEN_METADATA_BYTES) {
    throw new ProtocolV3Error("invalid OPEN metadata length");
  }
  let text: string;
  try {
    text = strictDecoder.decode(raw);
  } catch {
    throw new ProtocolV3Error("OPEN metadata is not valid UTF-8");
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new ProtocolV3Error("OPEN metadata is not valid JSON");
  }
  if (!isJSONObject(value))
    throw new ProtocolV3Error("OPEN metadata root must be an object");
  const canonical = canonicalStreamMetadataJSONV3Internal(value);
  if (
    canonical !== text ||
    encoder.encode(canonical).length > MAX_OPEN_METADATA_BYTES
  ) {
    throw new ProtocolV3Error("OPEN metadata is not canonical JSON");
  }
  return encoder.encode(canonical);
}

/** @internal Validates a public metadata value against the exact OPEN contract. */
export function canonicalStreamMetadataJSONV3Internal(value: unknown): string {
  if (!isJSONObject(value)) throw new ProtocolV3Error("OPEN metadata root must be an object");
  const state = { nodes: -1 };
  const canonical = canonicalValidatedMetadataJSONString(value, 1, state);
  if (encoder.encode(canonical).length > MAX_OPEN_METADATA_BYTES) {
    throw new ProtocolV3Error("OPEN metadata is too large");
  }
  return canonical;
}

function canonicalValidatedMetadataJSONString(
  value: unknown,
  depth: number,
  state: { nodes: number },
): string {
  if (depth > MAX_OPEN_METADATA_DEPTH)
    throw new ProtocolV3Error("OPEN metadata exceeds depth limit");
  state.nodes += 1;
  if (state.nodes > MAX_OPEN_METADATA_NODES)
    throw new ProtocolV3Error("OPEN metadata exceeds node limit");
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0))
      throw new ProtocolV3Error(
        "OPEN metadata number is not an I-JSON safe integer",
      );
    return value.toString(10);
  }
  if (typeof value === "string") {
    if (!validOpenUnicodeString(value, MAX_OPEN_METADATA_STRING_BYTES, true)) {
      throw new ProtocolV3Error("invalid OPEN metadata string");
    }
    return quoteCanonicalJSONString(value);
  }
  if (Array.isArray(value)) {
    const length = value.length;
    if (length > MAX_OPEN_METADATA_ARRAY)
      throw new ProtocolV3Error("OPEN metadata array is too large");
    const items = new Array<string>(length);
    for (let index = 0; index < length; index++) {
      const item = value[index];
      items[index] = canonicalValidatedMetadataJSONString(item, depth + 1, state);
    }
    return `[${items.join(",")}]`;
  }
  if (!isJSONObject(value))
    throw new ProtocolV3Error("unsupported OPEN metadata value");
  const keys = Object.keys(value).sort();
  if (keys.length > MAX_OPEN_METADATA_KEYS)
    throw new ProtocolV3Error("OPEN metadata object is too large");
  const members = new Array<string>(keys.length);
  let index = 0;
  for (const key of keys) {
    if (!validOpenUnicodeString(key, MAX_OPEN_METADATA_KEY_BYTES, false)) {
      throw new ProtocolV3Error("invalid OPEN metadata key");
    }
    const item = value[key];
    members[index++] = `${quoteCanonicalJSONString(key)}:${canonicalValidatedMetadataJSONString(item, depth + 1, state)}`;
  }
  return `{${members.join(",")}}`;
}

function quoteCanonicalJSONString(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function validOpenUnicodeString(
  value: string,
  maxBytes: number,
  allowEmpty: boolean,
): boolean {
  const bytes = encoder.encode(value);
  if (
    bytes.length > maxBytes ||
    (!allowEmpty && bytes.length === 0) ||
    value.normalize("NFC") !== value
  )
    return false;
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0)!;
    if (
      (codePoint >= 0xd800 && codePoint <= 0xdfff) ||
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      !unicode151Assigned(codePoint)
    ) {
      return false;
    }
  }
  return true;
}

 function isUnicodeWhitespace(codePoint: number): boolean {
  return (
    (codePoint >= 0x0009 && codePoint <= 0x000d) ||
    codePoint === 0x0020 ||
    codePoint === 0x0085 ||
    codePoint === 0x00a0 ||
    codePoint === 0x1680 ||
    (codePoint >= 0x2000 && codePoint <= 0x200a) ||
    codePoint === 0x2028 ||
    codePoint === 0x2029 ||
    codePoint === 0x202f ||
    codePoint === 0x205f ||
    codePoint === 0x3000
  );
}

function isJSONObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
