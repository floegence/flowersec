import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { CarrierUnreliableDatagramsV3 } from "./carrier.js";
import type {
  OperationOptionsV3,
  UnreliableMessageChannelV3,
  UnreliableMessageSendOptionsV3,
  UnreliableMessageSendResultV3,
} from "./contract.js";
import { CipherSuiteV3 } from "./protocol.js";
import type { DirectionV3 } from "./protocol.js";
import { UnreliableMessageError } from "../public/contract.js";
import { FLOWERSEC_V3_CRYPTO_LABELS } from "./transportConstants.js";

export const UNRELIABLE_MESSAGES_FEATURE_V3 = 0x00000001;
export const UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V3 = 976 as const;
export const UNRELIABLE_MESSAGE_WIRE_BYTES_V3 = 1_024 as const;

const HEADER_BYTES = 32;
const TAG_BYTES = 16;
const MIN_CIPHERTEXT_BYTES = TAG_BYTES + 1;
const MAX_CIPHERTEXT_BYTES = UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V3 + TAG_BYTES;
const MAX_PENDING_SENDS = 64;
const MAX_UINT32 = 0xffffffff;
const MAX_UINT64 = (1n << 64n) - 1n;
const encoder = new TextEncoder();

/** @internal */ export { UnreliableMessageError } from "../public/contract.js";

export type InternalUnreliableMessageChannelV3Options = Readonly<{
  transport: CarrierUnreliableDatagramsV3;
  suite: CipherSuiteV3;
  h3: Uint8Array;
  sendDirection: DirectionV3;
  receiveDirection: DirectionV3;
  currentSendEpoch(): Readonly<{ epoch: number; epochSecret: Uint8Array }>;
  receiveEpochSecret(epoch: number): Uint8Array | undefined;
  onProtocolFailure(): void;
  now?: () => number;
}>;

/** @internal */
export function createInternalUnreliableMessageChannelV3(
  options: InternalUnreliableMessageChannelV3Options,
): UnreliableMessageChannelV3 {
  return new InternalUnreliableMessageChannelV3(options);
}

class InternalUnreliableMessageChannelV3 implements UnreliableMessageChannelV3 {
  readonly maxMessageSize = UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V3;

  private readonly replay = new Map<number, ReplayWindow>();
  private readonly now: () => number;
  private nextSequence = 0n;
  private sendEpoch = -1;
  private pendingSends = 0;

  constructor(private readonly options: InternalUnreliableMessageChannelV3Options) {
    if (options.transport.maxDatagramSize < UNRELIABLE_MESSAGE_WIRE_BYTES_V3 || options.h3.byteLength !== 32) {
      throw new UnreliableMessageError("operation_failed");
    }
    this.now = options.now ?? Date.now;
  }

  async send(
    message: Uint8Array,
    options: UnreliableMessageSendOptionsV3,
  ): Promise<UnreliableMessageSendResultV3> {
    throwIfAborted(options.signal);
    if (!(message instanceof Uint8Array) || message.byteLength < 1) {
      throw new UnreliableMessageError("invalid_message");
    }
    if (message.byteLength > UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V3) {
      throw new UnreliableMessageError("too_large");
    }
    const payload = message.slice();
    const expiresAt = requireFutureExpiry(options.expiresAtUnixMs, this.now());
    if (expiresAt === undefined) return "dropped_expired";
    if (this.pendingSends >= MAX_PENDING_SENDS) return "dropped_budget";

    const roots = this.options.currentSendEpoch();
    if (roots.epoch !== this.sendEpoch) {
      this.sendEpoch = roots.epoch;
      this.nextSequence = 0n;
    }
    if (this.nextSequence > MAX_UINT64) throw new UnreliableMessageError("closed");
    const sequence = this.nextSequence++;
    const sealed = sealUnreliableMessageDatagramV3({
      suite: this.options.suite,
      epochSecret: roots.epochSecret,
      h3: this.options.h3,
      direction: this.options.sendDirection,
      epoch: roots.epoch,
      sequence,
      expiresAtUnixMs: BigInt(expiresAt),
      plaintext: payload,
    });

    this.pendingSends++;
    try {
      return await this.options.transport.send(sealed.wire, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        expiresAt,
      });
    } catch (error) {
      if (isAbortError(error)) throw new UnreliableMessageError("canceled");
      throw new UnreliableMessageError("operation_failed");
    } finally {
      this.pendingSends--;
    }
  }

  async receive(options: OperationOptionsV3 = {}): Promise<Uint8Array> {
    for (;;) {
      throwIfAborted(options.signal);
      let wire: Uint8Array;
      try {
        wire = await this.options.transport.receive(options);
      } catch (error) {
        if (isAbortError(error)) throw new UnreliableMessageError("canceled");
        throw new UnreliableMessageError("closed");
      }
      if (isPreviousVersionDatagram(wire)) {
        this.options.onProtocolFailure();
        throw new UnreliableMessageError("closed");
      }
      const decoded = decodeHeader(wire);
      if (decoded === undefined || decoded.expiresAtUnixMs <= BigInt(Math.floor(this.now()))) continue;
      const epochSecret = this.options.receiveEpochSecret(decoded.epoch);
      if (epochSecret === undefined) continue;
      const window = this.replay.get(decoded.epoch) ?? new ReplayWindow();
      if (window.seen(decoded.sequence)) continue;
      const material = deriveUnreliableMessageMaterialV3(
        epochSecret,
        this.options.h3,
        this.options.receiveDirection,
        decoded.epoch,
      );
      const nonce = concat(material.noncePrefix, u64be(decoded.sequence));
      const aad = labelWith(
        FLOWERSEC_V3_CRYPTO_LABELS["unreliable-aad"],
        this.options.h3,
        byte(this.options.receiveDirection),
        wire.subarray(0, HEADER_BYTES),
      );
      let plaintext: Uint8Array;
      try {
        plaintext = cipher(this.options.suite, material.recordKey, nonce, aad).decrypt(wire.subarray(HEADER_BYTES));
      } catch {
        continue;
      }
      if (plaintext.byteLength < 1 || plaintext.byteLength > UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V3) continue;
      window.mark(decoded.sequence);
      this.replay.set(decoded.epoch, window);
      pruneReplayEpochs(this.replay, decoded.epoch);
      return plaintext.slice();
    }
  }
}

function isPreviousVersionDatagram(wire: Uint8Array): boolean {
  if (!(wire instanceof Uint8Array) || wire.byteLength < 5 ||
      wire[0] !== 0x46 || wire[1] !== 0x53 || wire[2] !== 0x44) return false;
  return wire[3] === 0x32 || (wire[3] === 0x33 && wire[4] === 2);
}

type DecodedHeader = Readonly<{
  epoch: number;
  sequence: bigint;
  expiresAtUnixMs: bigint;
}>;

/** @internal */
export function encodeUnreliableMessageHeaderV3(
  epoch: number,
  sequence: bigint,
  expiresAtUnixMs: bigint,
  ciphertextLength: number,
): Uint8Array {
  if (!isUint32(epoch) || !isUint64(sequence) || !isUint64(expiresAtUnixMs) ||
      expiresAtUnixMs === 0n || !Number.isInteger(ciphertextLength) ||
      ciphertextLength < MIN_CIPHERTEXT_BYTES || ciphertextLength > MAX_CIPHERTEXT_BYTES) {
    throw new Error("invalid FSD3 header");
  }
  const header = new Uint8Array(HEADER_BYTES);
  header.set(encoder.encode("FSD3"));
  header[4] = 3;
  header[5] = 0;
  const view = new DataView(header.buffer);
  view.setUint16(6, HEADER_BYTES, false);
  view.setUint32(8, epoch, false);
  view.setBigUint64(12, sequence, false);
  view.setBigUint64(20, expiresAtUnixMs, false);
  view.setUint32(28, ciphertextLength, false);
  return header;
}

function decodeHeader(wire: Uint8Array): DecodedHeader | undefined {
  if (!(wire instanceof Uint8Array) || wire.byteLength < HEADER_BYTES + TAG_BYTES ||
      wire.byteLength > UNRELIABLE_MESSAGE_WIRE_BYTES_V3 ||
      wire[0] !== 0x46 || wire[1] !== 0x53 || wire[2] !== 0x44 || wire[3] !== 0x33 ||
      wire[4] !== 3 || wire[5] !== 0) return undefined;
  const view = new DataView(wire.buffer, wire.byteOffset, HEADER_BYTES);
  if (view.getUint16(6, false) !== HEADER_BYTES || view.getUint32(28, false) !== wire.byteLength - HEADER_BYTES) {
    return undefined;
  }
  const expiresAtUnixMs = view.getBigUint64(20, false);
  if (expiresAtUnixMs === 0n) return undefined;
  return {
    epoch: view.getUint32(8, false),
    sequence: view.getBigUint64(12, false),
    expiresAtUnixMs,
  };
}

export type UnreliableMessageMaterialV3 = Readonly<{
  unreliableRoot: Uint8Array;
  materialSecret: Uint8Array;
  recordKey: Uint8Array;
  noncePrefix: Uint8Array;
}>;

/** @internal */
export function deriveUnreliableMessageMaterialV3(
  epochSecret: Uint8Array,
  h3: Uint8Array,
  direction: DirectionV3,
  epoch: number,
): UnreliableMessageMaterialV3 {
  const unreliableRoot = expand(
    sha256,
    epochSecret,
    labelWith(FLOWERSEC_V3_CRYPTO_LABELS["unreliable-root"]),
    32,
  );
  const materialSecret = expand(
    sha256,
    unreliableRoot,
    labelWith(FLOWERSEC_V3_CRYPTO_LABELS.unreliable, h3, byte(direction), u32be(epoch)),
    32,
  );
  return {
    unreliableRoot,
    materialSecret,
    recordKey: expand(sha256, materialSecret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["unreliable-key"]), 32),
    noncePrefix: expand(sha256, materialSecret, labelWith(FLOWERSEC_V3_CRYPTO_LABELS["unreliable-nonce"]), 4),
  };
}

export type SealUnreliableMessageDatagramV3Options = Readonly<{
  suite: CipherSuiteV3;
  epochSecret: Uint8Array;
  h3: Uint8Array;
  direction: DirectionV3;
  epoch: number;
  sequence: bigint;
  expiresAtUnixMs: bigint;
  plaintext: Uint8Array;
}>;

export type SealedUnreliableMessageDatagramV3 = Readonly<{
  material: UnreliableMessageMaterialV3;
  nonce: Uint8Array;
  header: Uint8Array;
  aad: Uint8Array;
  ciphertext: Uint8Array;
  wire: Uint8Array;
}>;

/** @internal */
export function sealUnreliableMessageDatagramV3(
  options: SealUnreliableMessageDatagramV3Options,
): SealedUnreliableMessageDatagramV3 {
  const header = encodeUnreliableMessageHeaderV3(
    options.epoch,
    options.sequence,
    options.expiresAtUnixMs,
    options.plaintext.byteLength + TAG_BYTES,
  );
  const material = deriveUnreliableMessageMaterialV3(
    options.epochSecret,
    options.h3,
    options.direction,
    options.epoch,
  );
  const nonce = concat(material.noncePrefix, u64be(options.sequence));
  const aad = labelWith(
    FLOWERSEC_V3_CRYPTO_LABELS["unreliable-aad"],
    options.h3,
    byte(options.direction),
    header,
  );
  const ciphertext = cipher(options.suite, material.recordKey, nonce, aad).encrypt(options.plaintext);
  return {
    material,
    nonce,
    header,
    aad,
    ciphertext,
    wire: concat(header, ciphertext),
  };
}

function cipher(suite: CipherSuiteV3, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array) {
  if (suite === CipherSuiteV3.ChaCha20Poly1305) return chacha20poly1305(key, nonce, aad);
  if (suite === CipherSuiteV3.AES256GCM) return gcm(key, nonce, aad);
  throw new UnreliableMessageError("operation_failed");
}

class ReplayWindow {
  private highest = -1n;
  private bitmap = 0n;

  seen(sequence: bigint): boolean {
    if (this.highest < 0n || sequence > this.highest) return false;
    const distance = this.highest - sequence;
    return distance >= 64n || (this.bitmap & (1n << distance)) !== 0n;
  }

  mark(sequence: bigint): void {
    if (this.highest < 0n) {
      this.highest = sequence;
      this.bitmap = 1n;
      return;
    }
    if (sequence > this.highest) {
      const shift = sequence - this.highest;
      this.bitmap = shift >= 64n ? 1n : ((this.bitmap << shift) | 1n) & ((1n << 64n) - 1n);
      this.highest = sequence;
      return;
    }
    this.bitmap |= 1n << (this.highest - sequence);
  }
}

function pruneReplayEpochs(windows: Map<number, ReplayWindow>, current: number): void {
  for (const epoch of windows.keys()) {
    if (epoch + 1 < current || epoch > current + 1) windows.delete(epoch);
  }
}


function requireFutureExpiry(value: number, now: number): number | undefined {
  if (!Number.isSafeInteger(value) || value < 0) throw new UnreliableMessageError("invalid_message");
  return value <= now ? undefined : value;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new UnreliableMessageError("canceled");
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError" ||
    error instanceof Error && error.name === "AbortError";
}

function labelWith(label: string, ...parts: Uint8Array[]): Uint8Array {
  return concat(encoder.encode(label), byte(0), ...parts);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function byte(value: number): Uint8Array {
  return Uint8Array.of(value);
}

function u32be(value: number): Uint8Array {
  if (!isUint32(value)) throw new Error("invalid FSD3 uint32");
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64be(value: bigint): Uint8Array {
  if (!isUint64(value)) throw new Error("invalid FSD3 uint64");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function isUint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32;
}

function isUint64(value: bigint): boolean {
  return typeof value === "bigint" && value >= 0n && value <= MAX_UINT64;
}
