import { gcm } from "@noble/ciphers/aes";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { expand } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import type { CarrierUnreliableDatagramsV2 } from "./carrier.js";
import type {
  OperationOptionsV2,
  UnreliableMessageChannelV2,
  UnreliableMessageSendOptionsV2,
  UnreliableMessageSendResultV2,
  UnreliableMessageV2,
} from "./contract.js";
import { CipherSuiteV2 } from "./protocol.js";
import type { DirectionV2 } from "./protocol.js";

export const UNRELIABLE_MESSAGES_FEATURE_V2 = 0x00000001;
export const UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V2 = 1_024 as const;
export const UNRELIABLE_MESSAGE_WIRE_BYTES_V2 = 1_072 as const;

const HEADER_BYTES = 32;
const TAG_BYTES = 16;
const MAX_PENDING_SENDS = 64;
const MAX_UINT64 = (1n << 64n) - 1n;
const encoder = new TextEncoder();
const messages = new WeakSet<object>();

export class UnreliableMessageError extends Error {
  constructor(readonly code: "invalid_message" | "closed" | "operation_failed") {
    super(`Flowersec unreliable message failed (code=${code})`);
    this.name = "UnreliableMessageError";
  }
}

export function createUnreliableMessageV2(data: Uint8Array): UnreliableMessageV2 {
  if (!(data instanceof Uint8Array) || data.byteLength < 1 ||
      data.byteLength > UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V2) {
    throw new UnreliableMessageError("invalid_message");
  }
  const value = Object.freeze({ data: data.slice() });
  messages.add(value);
  return value as UnreliableMessageV2;
}

export type InternalUnreliableMessageChannelV2Options = Readonly<{
  transport: CarrierUnreliableDatagramsV2;
  suite: CipherSuiteV2;
  h3: Uint8Array;
  sendDirection: DirectionV2;
  receiveDirection: DirectionV2;
  currentSendEpoch(): Readonly<{ epoch: number; epochSecret: Uint8Array }>;
  receiveEpochSecret(epoch: number): Uint8Array | undefined;
  now?: () => number;
}>;

/** @internal */
export function createInternalUnreliableMessageChannelV2(
  options: InternalUnreliableMessageChannelV2Options,
): UnreliableMessageChannelV2 {
  return new InternalUnreliableMessageChannelV2(options);
}

class InternalUnreliableMessageChannelV2 implements UnreliableMessageChannelV2 {
  readonly maxMessageSize = UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V2;

  private readonly replay = new Map<number, ReplayWindow>();
  private readonly now: () => number;
  private nextSequence = 0n;
  private sendEpoch = -1;
  private pendingSends = 0;

  constructor(private readonly options: InternalUnreliableMessageChannelV2Options) {
    if (options.transport.maxDatagramSize < UNRELIABLE_MESSAGE_WIRE_BYTES_V2 || options.h3.byteLength !== 32) {
      throw new UnreliableMessageError("operation_failed");
    }
    this.now = options.now ?? Date.now;
  }

  async send(
    message: UnreliableMessageV2,
    options: UnreliableMessageSendOptionsV2,
  ): Promise<UnreliableMessageSendResultV2> {
    throwIfAborted(options.signal);
    if (!isUnreliableMessage(message)) throw new UnreliableMessageError("invalid_message");
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
    const sealed = sealUnreliableMessageDatagramV2({
      suite: this.options.suite,
      epochSecret: roots.epochSecret,
      h3: this.options.h3,
      direction: this.options.sendDirection,
      epoch: roots.epoch,
      sequence,
      expiresAtUnixMs: BigInt(expiresAt),
      plaintext: message.data,
    });

    this.pendingSends++;
    try {
      return await this.options.transport.send(sealed.wire, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        expiresAt,
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new UnreliableMessageError("operation_failed");
    } finally {
      this.pendingSends--;
    }
  }

  async receive(options: OperationOptionsV2 = {}): Promise<UnreliableMessageV2> {
    for (;;) {
      throwIfAborted(options.signal);
      let wire: Uint8Array;
      try {
        wire = await this.options.transport.receive(options);
      } catch (error) {
        if (isAbortError(error)) throw error;
        throw new UnreliableMessageError("closed");
      }
      const decoded = decodeHeader(wire);
      if (decoded === undefined || decoded.expiresAtUnixMs <= BigInt(Math.floor(this.now()))) continue;
      const epochSecret = this.options.receiveEpochSecret(decoded.epoch);
      if (epochSecret === undefined) continue;
      const window = this.replay.get(decoded.epoch) ?? new ReplayWindow();
      if (window.seen(decoded.sequence)) continue;
      const material = deriveUnreliableMessageMaterialV2(
        epochSecret,
        this.options.h3,
        this.options.receiveDirection,
        decoded.epoch,
      );
      const nonce = concat(material.noncePrefix, u64be(decoded.sequence));
      const aad = labelWith(
        "flowersec-v2-unreliable",
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
      if (plaintext.byteLength < 1 || plaintext.byteLength > UNRELIABLE_MESSAGE_MAX_PLAINTEXT_BYTES_V2) continue;
      window.mark(decoded.sequence);
      this.replay.set(decoded.epoch, window);
      pruneReplayEpochs(this.replay, decoded.epoch);
      return createUnreliableMessageV2(plaintext);
    }
  }
}

type DecodedHeader = Readonly<{
  epoch: number;
  sequence: bigint;
  expiresAtUnixMs: bigint;
}>;

/** @internal */
export function encodeUnreliableMessageHeaderV2(
  epoch: number,
  sequence: bigint,
  expiresAtUnixMs: bigint,
  ciphertextLength: number,
): Uint8Array {
  const header = new Uint8Array(HEADER_BYTES);
  header.set(encoder.encode("FSD2"));
  header[4] = 2;
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
      wire.byteLength > UNRELIABLE_MESSAGE_WIRE_BYTES_V2 ||
      wire[0] !== 0x46 || wire[1] !== 0x53 || wire[2] !== 0x44 || wire[3] !== 0x32 ||
      wire[4] !== 2 || wire[5] !== 0) return undefined;
  const view = new DataView(wire.buffer, wire.byteOffset, HEADER_BYTES);
  if (view.getUint16(6, false) !== HEADER_BYTES || view.getUint32(28, false) !== wire.byteLength - HEADER_BYTES) {
    return undefined;
  }
  return {
    epoch: view.getUint32(8, false),
    sequence: view.getBigUint64(12, false),
    expiresAtUnixMs: view.getBigUint64(20, false),
  };
}

export type UnreliableMessageMaterialV2 = Readonly<{
  unreliableRoot: Uint8Array;
  materialSecret: Uint8Array;
  recordKey: Uint8Array;
  noncePrefix: Uint8Array;
}>;

/** @internal */
export function deriveUnreliableMessageMaterialV2(
  epochSecret: Uint8Array,
  h3: Uint8Array,
  direction: DirectionV2,
  epoch: number,
): UnreliableMessageMaterialV2 {
  const unreliableRoot = expand(sha256, epochSecret, labelWith("flowersec v2 unreliable root"), 32);
  const materialSecret = expand(
    sha256,
    unreliableRoot,
    labelWith("flowersec v2 unreliable", h3, byte(direction), u32be(epoch)),
    32,
  );
  return {
    unreliableRoot,
    materialSecret,
    recordKey: expand(sha256, materialSecret, labelWith("flowersec v2 unreliable key"), 32),
    noncePrefix: expand(sha256, materialSecret, labelWith("flowersec v2 unreliable nonce"), 4),
  };
}

export type SealUnreliableMessageDatagramV2Options = Readonly<{
  suite: CipherSuiteV2;
  epochSecret: Uint8Array;
  h3: Uint8Array;
  direction: DirectionV2;
  epoch: number;
  sequence: bigint;
  expiresAtUnixMs: bigint;
  plaintext: Uint8Array;
}>;

export type SealedUnreliableMessageDatagramV2 = Readonly<{
  material: UnreliableMessageMaterialV2;
  nonce: Uint8Array;
  header: Uint8Array;
  aad: Uint8Array;
  ciphertext: Uint8Array;
  wire: Uint8Array;
}>;

/** @internal */
export function sealUnreliableMessageDatagramV2(
  options: SealUnreliableMessageDatagramV2Options,
): SealedUnreliableMessageDatagramV2 {
  const header = encodeUnreliableMessageHeaderV2(
    options.epoch,
    options.sequence,
    options.expiresAtUnixMs,
    options.plaintext.byteLength + TAG_BYTES,
  );
  const material = deriveUnreliableMessageMaterialV2(
    options.epochSecret,
    options.h3,
    options.direction,
    options.epoch,
  );
  const nonce = concat(material.noncePrefix, u64be(options.sequence));
  const aad = labelWith("flowersec-v2-unreliable", options.h3, byte(options.direction), header);
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

function cipher(suite: CipherSuiteV2, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array) {
  if (suite === CipherSuiteV2.ChaCha20Poly1305) return chacha20poly1305(key, nonce, aad);
  if (suite === CipherSuiteV2.AES256GCM) return gcm(key, nonce, aad);
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

function isUnreliableMessage(value: unknown): value is UnreliableMessageV2 {
  return typeof value === "object" && value !== null && messages.has(value);
}

function requireFutureExpiry(value: number, now: number): number | undefined {
  if (!Number.isSafeInteger(value) || value < 0) throw new UnreliableMessageError("invalid_message");
  return value <= now ? undefined : value;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new DOMException("operation aborted", "AbortError");
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
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64be(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}
