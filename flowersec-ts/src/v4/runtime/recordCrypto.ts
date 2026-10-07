import { gcm } from "@noble/ciphers/aes.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { byteLength, byteSlice } from "./cbor.js";
import type { TrustedClock } from "./clock.js";
import { type ClockSample } from "./clock.js";
import type { CryptoEpochUsage, CryptoKeyPositions, CryptoKeyUsage, CryptoUsageLedger} from "./cryptoUsage.js";
import { RecordCryptoError, cryptoFailure, type RecordCryptoFailure } from "./cryptoUsage.js";
import type { TrustedDeadline } from "./deadline.js";
import { EnvelopeFrame, type RecordHeader } from "./envelope.js";
import { encodeRecordAAD, encodeRecordKeyInfo, encodeRecordNonce, encodeRecordPrefix, validateRecordScope, type RecordDirection } from "./record.js";
import { ReplayWindow } from "./replayWindow.js";
import { RecordWorkspace } from "./recordWorkspace.js";
import type { ResourceReference} from "./resources.js";
import { ResourceVector } from "./resources.js";
import { datagramScope, envelopePrefixBytes, ownProfile, recordHeaderBytes, wire } from "./wireRegistry.js";

const capability = Symbol("original record key");
const empty = new Uint8Array(0);
const maximum = (1n << 64n) - 1n;
const copy = Uint8Array.prototype.set;
const prefixBytes = envelopePrefixBytes + recordHeaderBytes;

// This is a trusted internal owner projection, never an application hook.
// It must recheck the original authorization, allowed epoch/READY/rekey phase,
// scope, direction and datagram guard, without I/O, user code or replacement
// Session lookup. AEAD and replay alone do not establish those authorities.
export interface RecordAuthorization {
  check(frameType: number, header: RecordHeader, direction: RecordDirection): void;
}
export interface RecordEpochConfig {
  readonly clock: TrustedClock;
  readonly born: ClockSample;
  readonly authorizationDeadline: TrustedDeadline;
  readonly epoch: number;
  readonly runtimeBytes: bigint;
  /** Captured by NoiseHandshake.finish; direct construction may omit these
   * legacy fields, but a supplied value is always checked against the ledger
   * and the original READY context. */
  readonly profile?: string;
  readonly transportContextDigest?: Uint8Array;
  readonly admissionBinding?: Uint8Array;
}
export interface RecordCipherConfig { readonly maxFrame: number; readonly runtimeBytes: bigint; readonly workspace?: RecordWorkspace }
export interface ReceiveRecordBinding {
  readonly epoch: number;
  readonly scope: bigint;
  readonly direction: RecordDirection;
}
export interface IncomingRecordInfo extends ReceiveRecordBinding {
  readonly sequence: bigint;
  readonly frameType: number;
  readonly plaintextBytes: number;
}
export class RecordTicketError extends Error {
  readonly code: RecordCryptoFailure;
  readonly header: RecordHeader;
  // Irreversible crypto precharge is not proof of provider submission or
  // peer receipt. The original Session ticket owns those separate facts.
  readonly precharged = true;
  constructor(code: RecordCryptoFailure, header: RecordHeader) { super(code); this.name = "RecordTicketError"; this.code = code; this.header = header; Object.freeze(this); }
}
function cipherConfig(config: RecordCipherConfig): RecordCipherConfig {
  const maxFrame = config.maxFrame, runtimeBytes = config.runtimeBytes;
  if (!Number.isSafeInteger(maxFrame) || maxFrame < recordHeaderBytes + 16 || maxFrame > wire.resource_caps.max_payload_length ||
    typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) cryptoFailure("configuration_capacity");
  const workspace = config.workspace;
  if (workspace !== undefined && (!(workspace instanceof RecordWorkspace) || workspace.maxFrame < maxFrame)) cryptoFailure("configuration_capacity");
  return Object.freeze({ maxFrame, runtimeBytes, ...(workspace === undefined ? {} : { workspace }) });
}
export function recordCipherCharge(config: RecordCipherConfig): ResourceVector {
  const c = cipherConfig(config);
  // Input, retained output and the actual library's transient result all have
  // full capacity. Nonce, AAD, KDF info, key and replay backing are also prepaid.
  // Library schedules, stack, handles and allocator overhead require the host
  // RuntimeBytes allowance; this declaration does not qualify a runtime.
  const backing = c.workspace === undefined ? 3 * (envelopePrefixBytes + c.maxFrame) : 0;
  return new ResourceVector([BigInt(backing + 12 + 512 + 64 + 32) + c.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function recordEpochCharge(runtimeBytes: bigint): ResourceVector {
  if (typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) cryptoFailure("configuration_capacity");
  return new ResourceVector([96n + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}

// Raw material enters only at this software crypto boundary, after the
// original Noise/rekey completion owner has authorized its creation. The root
// cannot be exported or used as an AEAD key. This owner does not itself prove
// Noise completion, rekey barriers, or production profile qualification.
export class RecordEpoch {
  #ledger: CryptoUsageLedger | undefined;
  readonly #usage: CryptoEpochUsage;
  #deadline: TrustedDeadline | undefined;
  #rootCap: bigint;
  #authorizationDeadline: TrustedDeadline | undefined;
  readonly #number: number;
  #root: Uint8Array = empty;
  #hash: Uint8Array = empty;
  #context: Uint8Array = empty;
  #successor = false;
  #reservation: ResourceReference | undefined;
  #busy = false;
  #closed = false;
  #keys = 0;
  constructor(config: RecordEpochConfig, root: Uint8Array, handshakeHash: Uint8Array, ledger: CryptoUsageLedger, reservation: ResourceReference) {
    const clock = config.clock, born = config.born, authorization = config.authorizationDeadline, number = config.epoch, runtimeBytes = config.runtimeBytes;
    if (byteLength(root) !== 32 || byteLength(handshakeHash) !== 32 || !ledger.belongsTo(reservation) || !ledger.belongsToClock(clock) || !authorization.belongsTo(clock)) cryptoFailure("configuration_capacity");
    if (config.profile !== undefined && config.profile !== ledger.profile) cryptoFailure("crypto_owner");
    if (config.transportContextDigest !== undefined && byteLength(config.transportContextDigest) !== 32) cryptoFailure("configuration_capacity");
    if (config.admissionBinding !== undefined && byteLength(config.admissionBinding) !== 32) cryptoFailure("configuration_capacity");
    this.#reservation = reservation.take(recordEpochCharge(runtimeBytes)); this.#ledger = ledger; this.#number = number; this.#authorizationDeadline = authorization;
    let usage: CryptoEpochUsage | undefined;
    try {
      this.#root = new Uint8Array(32); this.#hash = new Uint8Array(32); this.#context = new Uint8Array(32);
      if (config.transportContextDigest !== undefined) copy.call(this.#context, config.transportContextDigest);
      copy.call(this.#root, byteSlice(root, 0, 32)); copy.call(this.#hash, byteSlice(handshakeHash, 0, 32));
      this.#rootCap = born.requireInterval().lowerMS + ledger.rootMaxAgeMS;
      this.#deadline = authorization.forkAgeAt(born, ledger.rootMaxAgeMS);
      usage = ledger.newEpoch(number); this.#usage = usage;
    } catch (error) {
      this.#root?.fill(0); this.#hash?.fill(0); this.#context.fill(0); usage?.close(); this.#reservation.release(); this.#reservation = undefined; throw error;
    }
    Object.freeze(this);
  }
  #check(): void {
    if (this.#closed) cryptoFailure("crypto_closed");
    this.#reservation!.check(); this.#ledger!.epochNumber(this.#usage); this.#authorizationDeadline!.check();
    if (this.#closed) cryptoFailure("crypto_closed");
    this.#deadline!.check();
    if (this.#closed) cryptoFailure("crypto_closed");
  }
  derive(scope: bigint, direction: RecordDirection, config: RecordCipherConfig, authorization: RecordAuthorization, reservation: ResourceReference, positions?: CryptoKeyPositions): RecordCipher {
    const c = cipherConfig(config), check = authorization.check.bind(authorization);
    if (this.#busy) cryptoFailure("crypto_busy");
    this.#busy = true;
    let owned: ResourceReference | undefined, usage: CryptoKeyUsage | undefined, key: Uint8Array | undefined;
    let info: Uint8Array | undefined;
    try {
      this.#check();
      if (!this.#reservation!.sameEnvironment(reservation)) cryptoFailure("crypto_owner");
      owned = reservation.take(recordCipherCharge(c));
      info = new Uint8Array(256);
      usage = this.#ledger!.derive(this.#usage, scope, direction, positions);
      const n = encodeRecordKeyInfo(this.#ledger!.profile, this.#hash, this.#number, direction, scope, info);
      // The actual KDF starts under the original root's current deadline.
      this.#check();
      key = expand(sha256, this.#root, info.subarray(0, n), 32);
      this.#check();
      const cipher = new RecordCipher(capability, this, this.#ledger!, usage, owned, c, key, this.#number, scope, direction, check);
      owned = undefined; usage = undefined; this.#keys++;
      return cipher;
    } finally {
      info?.fill(0); key?.fill(0); usage?.close(); owned?.release(); this.#busy = false; this.#cleanup();
    }
  }
  /** Internal retirement binding copied only into the Session's original paid
   * digest workspace. It grants no key, record or completion authority. */
  copyHandshakeHash(destination: Uint8Array): void {
    this.#check(); if (byteLength(destination) !== 32) cryptoFailure("configuration_capacity");
    copy.call(destination, this.#hash);
  }
  copyContextDigest(destination: Uint8Array): void {
    this.#check(); if (byteLength(destination) !== 32) cryptoFailure("configuration_capacity"); copy.call(destination, this.#context);
  }
  rekeySafetySnapshot(): Readonly<{ epoch: number; remainingMS: bigint; rootMaxAgeMS: bigint; rootAgeLimited: boolean; triggered: boolean }> {
    this.#check();
    return Object.freeze({ ...this.#ledger!.rekeySafetySnapshot(this.#usage), remainingMS: this.#deadline!.remainingMS(),
      rootMaxAgeMS: this.#ledger!.rootMaxAgeMS, rootAgeLimited: this.#authorizationDeadline!.cap >= this.#rootCap });
  }
  safetyDeadline(): TrustedDeadline {
    this.#check(); return this.#deadline!.fork(this.#deadline!.cap);
  }
  deriveRekeySecret(info: Uint8Array, destination: Uint8Array): void {
    this.#check(); if (byteLength(destination) !== 32 || byteLength(info) > 512) cryptoFailure("configuration_capacity");
    const secret = expand(sha256, this.#root, info, 32);
    try { this.#check(); copy.call(destination, secret); } finally { secret.fill(0); }
  }
  installSuccessor(root: Uint8Array, config: RecordEpochConfig, reservation: ResourceReference): RecordEpoch {
    this.#check(); if (this.#successor || config.epoch !== this.#number + 1) cryptoFailure("record_epoch");
    this.#successor = true;
    return new RecordEpoch({ ...config, authorizationDeadline: this.#authorizationDeadline!, transportContextDigest: this.#context }, root, this.#hash, this.#ledger!, reservation);
  }
  checkOriginal(token: symbol): void { if (token !== capability) cryptoFailure("crypto_owner"); this.#check(); }
  checkLogical(token: symbol): void {
    if (token !== capability) cryptoFailure("crypto_owner");
    if (this.#closed) cryptoFailure("crypto_closed");
    this.#reservation!.check(); this.#ledger!.epochNumber(this.#usage);
  }
  retireKey(token: symbol): void { if (token !== capability) cryptoFailure("crypto_owner"); this.#keys--; this.#cleanup(); }
  close(): void {
    if (this.#closed) return;
    this.#closed = true; this.#usage.close(); this.#cleanup();
  }
  #cleanup(): void {
    if (!this.#closed || this.#busy) return;
    this.#root.fill(0); this.#hash.fill(0); this.#context.fill(0); this.#root = empty; this.#hash = empty; this.#context = empty;
    if (this.#keys !== 0) return;
    this.#ledger = undefined; this.#deadline = undefined; this.#authorizationDeadline = undefined;
    this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#reservation === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.RecordEpoch"; }
}

interface PacketState { owner: RecordCipher | undefined; readonly header: RecordHeader; readonly frame: number; readonly incoming: boolean; accepted: boolean; length: number; validated?: () => void }
const packets = new WeakMap<RecordPacket, PacketState>();
export class RecordPacket {
  constructor(token: symbol, state: PacketState) { if (token !== capability) cryptoFailure("crypto_owner"); packets.set(this, state); Object.freeze(this); }
  #owner(): RecordCipher { const owner = packets.get(this)?.owner; if (owner === undefined) cryptoFailure("record_released"); return owner; }
  copyBytes(destination: Uint8Array): number { return this.#owner().copyPacket(capability, this, destination); }
  // The internal protocol decoder validates the complete plaintext before
  // committing. For datagrams this call and the admitted queue decision must
  // occur in one synchronous original owner turn, with no intervening await.
  // A full queue still commits then releases: replay eligibility is consumed.
  observeValidation(callback: () => void): void {
    const state = packets.get(this);
    if (state?.owner === undefined || !state.incoming || state.accepted || state.validated !== undefined) cryptoFailure("crypto_owner");
    state.validated = callback;
  }
  commitValidated(): void { this.#owner().commitPacket(capability, this); }
  release(): void { packets.get(this)?.owner?.releasePacket(capability, this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.RecordPacket"; }
}

// One direction/scope/epoch key, one preadmitted work/output position, and no
// asynchronous waiter or replacement key lookup. The Session owns selection
// and input-error scope. Bytes remain private until copied into admitted caller
// storage and the original lease retains backing through actual consumption.
export class RecordCipher {
  readonly #config: RecordCipherConfig;
  #ledger: CryptoUsageLedger | undefined;
  readonly #usage: CryptoKeyUsage;
  readonly #number: number;
  readonly #scope: bigint;
  readonly #direction: RecordDirection;
  readonly #incoming: boolean;
  #epoch: RecordEpoch | undefined;
  #authorization: RecordAuthorization["check"] | undefined;
  #reservation: ResourceReference | undefined;
  #key: Uint8Array;
  #input: Uint8Array;
  #output: Uint8Array;
  #aad: Uint8Array;
  #nonce: Uint8Array;
  #replay: ReplayWindow | undefined;
  #packet: RecordPacket | undefined;
  #next = 0n;
  #exhausted = false;
  #working = false;
  #closed = false;
  #goodCalls = 0n;
  #goodBlocks = 0n;
  #goodBytes = 0n;
  #pendingCost: readonly [bigint, bigint, bigint] | undefined;
  #workspaceRelease: (() => void) | undefined;
  #workspaceActive = false;
  #inputUsed = 0;
  #outputUsed = 0;
  constructor(token: symbol, epoch: RecordEpoch, ledger: CryptoUsageLedger, usage: CryptoKeyUsage, reservation: ResourceReference,
    config: RecordCipherConfig, key: Uint8Array, number: number, scope: bigint, direction: RecordDirection, authorization: RecordAuthorization["check"]) {
    if (token !== capability) cryptoFailure("crypto_owner");
    this.#config = config; this.#ledger = ledger; this.#usage = usage; this.#number = number; this.#scope = scope; this.#direction = direction;
    this.#epoch = epoch; this.#reservation = reservation; this.#authorization = authorization; this.#incoming = direction !== ledger.sendDirection;
    this.#key = empty; this.#input = empty; this.#output = empty; this.#aad = empty; this.#nonce = empty;
    try {
      this.#key = new Uint8Array(32); copy.call(this.#key, byteSlice(key, 0, 32));
      if (config.workspace === undefined) {
        this.#input = new Uint8Array(envelopePrefixBytes + config.maxFrame); this.#output = new Uint8Array(envelopePrefixBytes + config.maxFrame);
      } else {
        if (scope === 0n || scope === datagramScope) cryptoFailure("crypto_owner");
        this.#workspaceRelease = config.workspace.retain(reservation);
      }
      this.#aad = new Uint8Array(256); this.#nonce = new Uint8Array(12); this.#replay = scope === datagramScope ? new ReplayWindow() : undefined;
    } catch (error) { this.#workspaceRelease?.(); this.#key.fill(0); this.#input.fill(0); this.#output.fill(0); this.#aad.fill(0); this.#nonce.fill(0); throw error; }
    Object.freeze(this);
  }
  #check(frame: number, header: RecordHeader): void {
    if (this.#closed) cryptoFailure("crypto_closed");
    this.#reservation!.check(); this.#ledger!.checkKey(this.#usage); this.#epoch!.checkOriginal(capability);
    if (this.#closed) cryptoFailure("crypto_closed");
    if (this.#incoming && this.#scope === datagramScope) this.#ledger!.checkDatagramReceive();
    if (this.#closed) cryptoFailure("crypto_closed");
    this.#authorization!(frame, header, this.#direction);
    if (this.#closed) cryptoFailure("crypto_closed");
    this.#reservation!.check(); this.#ledger!.checkKey(this.#usage); this.#epoch!.checkLogical(capability);
  }
  #begin(incoming: boolean): void {
    if (this.#closed) cryptoFailure("crypto_closed");
    if (incoming !== this.#incoming) cryptoFailure("crypto_owner");
    if (this.#working || this.#packet !== undefined) cryptoFailure("crypto_busy");
    if (this.#config.workspace !== undefined) {
      const buffers = this.#config.workspace.acquire(this);
      this.#input = buffers.input; this.#output = buffers.output; this.#workspaceActive = true;
    }
    this.#working = true;
  }
  #advance(): void { if (this.#next === maximum) this.#exhausted = true; else this.#next++; }
  seal(frame: number, plaintext: Uint8Array, ticket?: () => void): RecordPacket {
    const length = byteLength(plaintext); this.#begin(false);
    let result: Uint8Array | undefined;
    let charged = false;
    const header = Object.freeze({ epoch: this.#number, scope: this.#scope, sequence: this.#next });
    try {
      if (this.#exhausted) cryptoFailure("record_sequence");
      this.#outputUsed = Math.min(prefixBytes, this.#output.length);
      encodeRecordPrefix(frame, header, length, this.#ledger!.profile, this.#config.maxFrame, this.#output);
      this.#inputUsed = length;
      copy.call(this.#input, byteSlice(plaintext, 0, length));
      const aadLength = encodeRecordAAD(this.#ledger!.profile, this.#direction, this.#output.subarray(0, prefixBytes), this.#aad);
      encodeRecordNonce(header, this.#nonce); this.#check(frame, header);
      this.#usage.precharge(frame, aadLength, length); this.#advance(); charged = true; ticket?.();
      this.#check(frame, header); // Usage may be prepaid; security time cannot.
      result = this.#cipher(aadLength).encrypt(this.#input.subarray(0, length));
      if (result.length !== length + 16) cryptoFailure("record_authentication");
      this.#check(frame, header); this.#outputUsed = prefixBytes + result.length; copy.call(this.#output, result, prefixBytes);
      return this.#publish(header, frame, false, prefixBytes + result.length);
    } catch (error) {
      // A skipped reliable nonce cannot be retried under the same key.
      if (charged && this.#scope !== datagramScope) this.close();
      if (charged) throw new RecordTicketError(error instanceof RecordCryptoError ? error.code : "security_unavailable", header);
      throw error;
    } finally { result?.fill(0); this.#finishWork(); }
  }
  open(envelope: EnvelopeFrame): RecordPacket {
    this.#begin(true);
    let result: Uint8Array | undefined;
    let attempt = false, outcome: "authenticated" | "failed" | "not_called" | "indeterminate" = "not_called";
    try {
      const parsed = EnvelopeFrame.prototype.recordHeader.call(envelope, this.#ledger!.profile);
      if (parsed.epoch !== this.#number) cryptoFailure("record_epoch");
      if (parsed.scope !== this.#scope) cryptoFailure("record_scope");
      validateRecordScope(parsed.frameType, parsed.scope);
      if (parsed.ciphertextBytes + recordHeaderBytes > this.#config.maxFrame) cryptoFailure("configuration_capacity");
      if (this.#replay !== undefined) { if (!this.#replay.allows(parsed.sequence)) cryptoFailure("record_replay"); }
      else if (this.#exhausted || parsed.sequence !== this.#next) cryptoFailure("record_sequence");
      const header = Object.freeze({ epoch: parsed.epoch, scope: parsed.scope, sequence: parsed.sequence });
      this.#inputUsed = envelopePrefixBytes + recordHeaderBytes + parsed.ciphertextBytes;
      const length = EnvelopeFrame.prototype.copyEncoded.call(envelope, this.#input);
      const aadLength = encodeRecordAAD(this.#ledger!.profile, this.#direction, this.#input.subarray(0, prefixBytes), this.#aad);
      encodeRecordNonce(header, this.#nonce); this.#check(parsed.frameType, header);
      if (this.#scope === datagramScope) { this.#ledger!.reserveDatagramAttempt(); attempt = true; }
      this.#pendingCost = this.#usage.precharge(parsed.frameType, aadLength, parsed.ciphertextBytes - 16);
      this.#check(parsed.frameType, header);
      const cipher = this.#cipher(aadLength);
      try { result = cipher.decrypt(this.#input.subarray(prefixBytes, length)); outcome = "authenticated"; }
      catch (error) {
        // These are the pinned library's authentication failure sentinels.
        // A different provider failure is not counted as an invalid peer tag.
        const invalid = error instanceof Error && (error.message === "invalid tag" || error.message === "aes-gcm: invalid tag");
        outcome = invalid ? "failed" : "indeterminate";
        cryptoFailure(invalid ? "record_authentication" : "crypto_provider_unavailable");
      }
      if (result.length !== parsed.ciphertextBytes - 16) cryptoFailure("record_authentication");
      this.#check(parsed.frameType, header); this.#outputUsed = result.length; copy.call(this.#output, result);
      return this.#publish(header, parsed.frameType, true, result.length);
    } catch (error) { if (this.#scope !== datagramScope) this.close(); throw error; }
    finally {
      result?.fill(0);
      if (attempt) this.#ledger!.finishDatagramAttempt(outcome);
      this.#finishWork();
    }
  }
  #cipher(aadLength: number): ReturnType<typeof gcm> {
    const profile = ownProfile(this.#ledger!.profile)!;
    if (profile.record_aead === "chacha20-poly1305") return chacha20poly1305(this.#key, this.#nonce, this.#aad.subarray(0, aadLength));
    if (profile.record_aead === "aes-256-gcm") return gcm(this.#key, this.#nonce, this.#aad.subarray(0, aadLength));
    return cryptoFailure("configuration_capacity");
  }
  #publish(header: RecordHeader, frame: number, incoming: boolean, length: number): RecordPacket {
    const packet = new RecordPacket(capability, { owner: this, header, frame, incoming, accepted: !incoming, length }); this.#packet = packet; return packet;
  }
  #finishWork(): void {
    this.#input.fill(0, 0, this.#inputUsed); this.#inputUsed = 0;
    this.#aad.fill(0); this.#nonce.fill(0); this.#working = false;
    if (this.#packet === undefined) { this.#output.fill(0, 0, this.#outputUsed); this.#outputUsed = 0; this.#pendingCost = undefined; }
    this.#releaseWorkspace(); this.#cleanup();
  }
  #releaseWorkspace(): void {
    if (!this.#workspaceActive || this.#working || this.#packet !== undefined) return;
    this.#config.workspace!.release(this); this.#workspaceActive = false; this.#input = this.#output = empty;
  }
  #original(token: symbol, packet: RecordPacket): PacketState {
    const p = packets.get(packet);
    if (token !== capability || p?.owner !== this || this.#packet !== packet) cryptoFailure("record_released");
    this.#check(p.frame, p.header);
    if (p.owner !== this || this.#packet !== packet) cryptoFailure("record_released");
    return p;
  }
  receiveBinding(reservation: ResourceReference): ReceiveRecordBinding {
    if (this.#closed || !this.#incoming || this.#scope === 0n || this.#scope === datagramScope ||
        !this.#reservation!.sameEnvironment(reservation)) cryptoFailure("crypto_owner");
    return Object.freeze({ epoch: this.#number, scope: this.#scope, direction: this.#direction });
  }
  sharesReceiveDirection(other: RecordCipher): boolean {
    return !this.#closed && !other.#closed && this.#incoming && other.#incoming && this.#ledger === other.#ledger &&
      this.#scope === other.#scope && this.#direction === other.#direction;
  }
  // An original packet capability, not caller-supplied decoded metadata, binds
  // the receive queue to this exact authenticated key and direction.
  inspectIncoming(packet: RecordPacket): IncomingRecordInfo {
    const p = this.#original(capability, packet);
    if (!p.incoming || p.accepted) cryptoFailure("crypto_owner");
    return Object.freeze({ ...p.header, direction: this.#direction, frameType: p.frame, plaintextBytes: p.length });
  }
  copyPacket(token: symbol, packet: RecordPacket, destination: Uint8Array): number {
    const capacity = byteLength(destination), p = this.#original(token, packet);
    if (capacity < p.length) cryptoFailure("configuration_capacity");
    copy.call(destination, this.#output.subarray(0, p.length)); return p.length;
  }
  commitPacket(token: symbol, packet: RecordPacket): void {
    const p = this.#original(token, packet);
    if (!p.incoming || p.accepted) cryptoFailure("crypto_owner");
    const cost = this.#pendingCost!;
    if (this.#replay !== undefined) this.#replay.commit(p.header.sequence);
    else { if (this.#exhausted || p.header.sequence !== this.#next) cryptoFailure("record_sequence"); this.#advance(); }
    this.#goodCalls += cost[0]; this.#goodBlocks += cost[1]; this.#goodBytes += cost[2];
    if (this.#replay !== undefined) this.#ledger!.acceptDatagram(this.#usage, cost);
    p.accepted = true;
    const validated = p.validated; delete p.validated; validated?.();
  }
  releasePacket(token: symbol, packet: RecordPacket): void {
    if (token !== capability) cryptoFailure("crypto_owner");
    const p = packets.get(packet); if (p?.owner !== this || this.#packet !== packet) return;
    p.owner = undefined; delete p.validated; this.#packet = undefined; this.#output.fill(0, 0, this.#outputUsed); this.#outputUsed = 0; this.#pendingCost = undefined;
    if (p.incoming && !p.accepted && this.#replay === undefined) this.close();
    this.#releaseWorkspace(); this.#cleanup();
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#working || this.#packet !== undefined || this.#reservation === undefined) return;
    this.#releaseWorkspace(); this.#workspaceRelease?.(); this.#workspaceRelease = undefined;
    this.#key.fill(0); this.#input.fill(0); this.#output.fill(0); this.#aad.fill(0); this.#nonce.fill(0); this.#replay?.clear();
    this.#key = empty; this.#input = empty; this.#output = empty; this.#aad = empty; this.#nonce = empty; this.#replay = undefined;
    this.#authorization = undefined; this.#usage.close(); this.#epoch!.retireKey(capability); this.#epoch = undefined;
    this.#ledger = undefined;
    this.#reservation.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#reservation === undefined; }
  frontier(): Readonly<{ epoch: number; scope: bigint; next: bigint; direction: RecordDirection }> {
    if (this.#closed || this.#working || this.#packet !== undefined || this.#exhausted) cryptoFailure("crypto_busy");
    this.#reservation!.check(); this.#epoch!.checkOriginal(capability);
    return Object.freeze({ epoch: this.#number, scope: this.#scope, next: this.#next, direction: this.#direction });
  }
  usageSnapshot(): Readonly<{ attempts: ReturnType<CryptoUsageLedger["usageSnapshot"]>; good: readonly [bigint, bigint, bigint] }> {
    if (this.#closed) cryptoFailure("crypto_closed");
    return Object.freeze({ attempts: this.#ledger!.usageSnapshot(this.#usage), good: Object.freeze([this.#goodCalls, this.#goodBlocks, this.#goodBytes]) as readonly [bigint, bigint, bigint] });
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.RecordCipher"; }
}
for (const c of [RecordEpoch, RecordPacket, RecordCipher]) { Object.freeze(c.prototype); Object.freeze(c); }
