import { x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import type { ClockSample, TrustedClock } from "./clock.js";
import type { TrustedDeadline } from "./deadline.js";
import { FixedCBORWriter } from "./openAdmission.js";
import { type RecordEpoch, type RecordEpochConfig } from "./recordCrypto.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { wireDomains } from "./schemaRegistry.js";
import { ownProfile } from "./wireRegistry.js";

import { hostRandomFill, randomDH, type RandomFill } from "./random.js";

const empty = new Uint8Array();
const set = Uint8Array.prototype.set;
export interface RekeyEntry { readonly scope: bigint; readonly next: bigint }
export interface RekeyConfig {
  readonly random?: RandomFill; readonly profile: string; readonly epoch: number; readonly clock: TrustedClock;
  readonly deadline: TrustedDeadline; readonly authorizationDeadline: TrustedDeadline; readonly maxFrame: number; readonly maxScopes: number;
  readonly runtimeBytes: bigint; readonly direction: 0 | 1;
}
export type RekeyStorageConfig = Pick<RekeyConfig, "maxFrame" | "maxScopes" | "runtimeBytes">;
function storageBytes(c: RekeyStorageConfig): number {
  if (!Number.isSafeInteger(c.maxFrame) || c.maxFrame < 256 || !Number.isSafeInteger(c.maxScopes) || c.maxScopes < 0 || c.maxScopes > 1035 || c.runtimeBytes <= 0n) {
    throw new Error("rekey_configuration");
  }
  // A canonical barrier entry is at most 21 bytes (two uint64 map fields).
  // 256 bytes covers the fixed map, P-256 key, digests, ID, epoch and MAC.
  // Route frame limits still apply; ordinary DATA capacity is not duplicated
  // into each of the round's six independent retained/transient buffers.
  return Math.min(c.maxFrame, 256 + c.maxScopes * 21);
}
export function rekeyRoundCharge(c: RekeyStorageConfig): ResourceVector {
  return new ResourceVector([BigInt(storageBytes(c) * 6 + 2048 + c.maxScopes * 32) + c.runtimeBytes, 0n, 0n, BigInt(c.maxScopes * 2 + 1), 1n, 1n, 1n, 0n, 0n, 1n, 0n]);
}
function decoderConfig(c: RekeyStorageConfig): { bytes: number; nodes: number; textBytes: number; arrayItems: number; runtimeBytes: bigint } {
  return { bytes: storageBytes(c), nodes: c.maxScopes * 5 + 32, textBytes: 0, arrayItems: 1035, runtimeBytes: c.runtimeBytes };
}
export function rekeyDecoderCharge(c: RekeyStorageConfig): ResourceVector { return cborDecoderCharge(decoderConfig(c)); }

/** Generated-domain encoding into a fixed original workspace. No secrets or
 * roots cross a public API, and phase projections always use complete CBOR. */
export function rekeyDomain(name: string, profile: string, epoch: number, values: Readonly<Record<string, Uint8Array>>,
  phase: number, destination: Uint8Array): Uint8Array {
  const domain = wireDomains.find(item => item.name === name); if (domain === undefined) throw new Error("rekey_domain");
  let at = 0;
  const integer = (value: bigint, n: number): void => {
    if (value < 0n || value >= 1n << BigInt(n * 8) || at + n > byteLength(destination)) throw new Error("rekey_domain");
    for (let i = n - 1; i >= 0; i--) { destination[at + i] = Number(value & 255n); value >>= 8n; } at += n;
  };
  const bytes = (value: Uint8Array): void => { if (at + byteLength(value) > byteLength(destination)) throw new Error("rekey_domain"); set.call(destination, value, at); at += byteLength(value); };
  for (let i = 0; i < domain.label_bytes.length; i += 2) integer(BigInt(Number.parseInt(domain.label_bytes.slice(i, i + 2), 16)), 1);
  for (const part of domain.input_schema.parts) {
    if (part.name === "profile") {
      integer(BigInt(profile.length), 4); for (const char of profile) integer(BigInt(char.charCodeAt(0)), 1);
    } else if (part.encoding.startsWith("lp-")) {
      const value = values[part.name]; if (value === undefined || part.length !== undefined && byteLength(value) !== part.length) throw new Error("rekey_domain");
      integer(BigInt(byteLength(value)), 4); bytes(value);
    } else {
      const value = part.name === "epoch" ? epoch : part.name === "next_epoch" ? epoch + 1 : part.name === "phase" ? phase : part.name === "role" ? (phase % 2 === 1 ? 0 : 1) : -1;
      integer(BigInt(value), part.encoding === "u8" ? 1 : part.encoding === "u32" ? 4 : 8);
    }
  }
  return byteSlice(destination, 0, at);
}
export class RekeyRound {
  readonly #config: RekeyConfig;
  #decoder: CBORDecoder | undefined;
  #reservation: ResourceReference | undefined;
  #secret = empty; #root = empty; #hash = empty; #context = empty; #id = empty; #private = empty; #public = empty;
  #init = empty; #reply = empty; #unsigned = empty; #workspace = empty; #out = empty; #digest = empty; #transcript = empty;
  #initSize = 0; #replySize = 0; #phase = 0; #born: ClockSample | undefined;
  #candidate: RecordEpoch | undefined;
  #closed = false;
  constructor(c: RekeyConfig, private readonly original: RecordEpoch, reservation: ResourceReference, decoderReservation: ResourceReference) {
    this.#config = Object.freeze({ ...c });
    if (ownProfile(c.profile) === undefined || !Number.isSafeInteger(c.epoch) || c.epoch < 0 || c.epoch >= 0xffffffff) throw new Error("rekey_configuration");
    const bytes = storageBytes(c);
    if (!reservation.sameEnvironment(decoderReservation)) throw new Error("rekey_owner");
    this.#reservation = reservation.take(rekeyRoundCharge(c));
    try {
      this.#decoder = new CBORDecoder(decoderConfig(c), decoderReservation);
      this.#secret = new Uint8Array(32); this.#root = new Uint8Array(32); this.#hash = new Uint8Array(32); this.#context = new Uint8Array(32); this.#id = new Uint8Array(16);
      this.#init = new Uint8Array(bytes); this.#reply = new Uint8Array(bytes); this.#unsigned = new Uint8Array(bytes);
      this.#workspace = new Uint8Array(bytes * 2 + 1024); this.#out = new Uint8Array(bytes); this.#digest = new Uint8Array(32); this.#transcript = new Uint8Array(32);
      original.copyHandshakeHash(this.#hash); original.copyContextDigest(this.#context);
      original.deriveRekeySecret(rekeyDomain("rekey_secret", c.profile, c.epoch, this.#values(), 0, this.#workspace), this.#secret);
      this.#workspace.fill(0);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new Error("rekey_closed"); this.#reservation!.check(); this.#config.deadline.check(); }
  #values(extra: Readonly<Record<string, Uint8Array>> = {}): Readonly<Record<string, Uint8Array>> {
    return { handshake_hash: this.#hash, context_digest: this.#context, rekey_id: this.#id, ...extra };
  }
  #ephemeral(): void {
    if (this.#private.length !== 0) throw new Error("rekey_state");
    const x = ownProfile(this.#config.profile)!.dh_algorithm === 0;
    this.#private = randomDH(x, this.#config.random ?? hostRandomFill);
    this.#public = x ? x25519.getPublicKey(this.#private) : p256.getPublicKey(this.#private, false);
  }
  #mac(phase: number, unsigned: Uint8Array): Uint8Array {
    const c = this.#config, base = phase < 3 ? this.#secret : this.#root;
    const key = expand(sha256, base, rekeyDomain("rekey_confirm_key", c.profile, c.epoch, this.#values(), phase, this.#workspace), 32);
    try { return hmac(sha256, key, rekeyDomain("rekey_confirm_mac", c.profile, c.epoch, this.#values({ message: unsigned }), phase, this.#workspace)); }
    finally { key.fill(0); this.#workspace.fill(0); }
  }
  #build(phase: number, fields: (writer: FixedCBORWriter) => void): Uint8Array {
    const count = phase === 2 ? 7 : 6, macID = phase === 2 ? 6 : 5;
    const core = (writer: FixedCBORWriter): void => {
      writer.uint(0).uint(phase).uint(1).data(this.#id).uint(2).uint(this.#config.epoch + 1); fields(writer);
    };
    const unsigned = new FixedCBORWriter(this.#unsigned).map(count - 1); core(unsigned);
    const mac = this.#mac(phase, unsigned.result());
    try {
      const out = new FixedCBORWriter(this.#out).map(count); core(out); out.uint(macID).data(mac); return out.result();
    } finally { mac.fill(0); this.#unsigned.fill(0); }
  }
  #barrier(writer: FixedCBORWriter, entries: readonly RekeyEntry[]): void {
    if (entries.length > this.#config.maxScopes) throw new Error("rekey_capacity");
    writer.array(entries.length); let previous = 0n;
    for (const entry of entries) {
      if (entry.scope <= previous) throw new Error("rekey_barrier"); previous = entry.scope;
      writer.map(2).uint(0).uint(entry.scope).uint(1).uint(entry.next);
    }
  }
  buildInit(entries: readonly RekeyEntry[]): Uint8Array {
    this.#check(); if (this.#config.direction !== 0 || this.#phase !== 0) throw new Error("rekey_state");
    (this.#config.random ?? hostRandomFill)(this.#id); this.#ephemeral();
    const body = this.#build(1, writer => { writer.uint(3).data(this.#public).uint(4); this.#barrier(writer, entries); });
    set.call(this.#init, body); this.#initSize = byteLength(body); this.#digestInit(); this.#phase = 1; return body;
  }
  #digestInit(): void {
    const hash = sha256(rekeyDomain("rekey_init_digest", this.#config.profile, this.#config.epoch, this.#values({ init: byteSlice(this.#init, 0, this.#initSize) }), 0, this.#workspace));
    set.call(this.#digest, hash); hash.fill(0); this.#workspace.fill(0);
  }
  #verify(doc: CBORDocument, phase: number): void {
    const id = doc.field(0, 1);
    if (doc.uint(doc.field(0, 0)) !== BigInt(phase) || doc.uint(doc.field(0, 2)) !== BigInt(this.#config.epoch + 1)) throw new Error("rekey_association");
    for (let i = 0; i < 16; i++) if (doc.payloadByte(id, i) !== this.#id[i]) throw new Error("rekey_association");
    const macID = phase === 2 ? 6 : 5, size = doc.copyWithoutField(macID, this.#unsigned), mac = this.#mac(phase, byteSlice(this.#unsigned, 0, size));
    let delta = 0; for (let i = 0; i < 32; i++) delta |= mac[i]! ^ doc.payloadByte(doc.field(0, macID), i);
    mac.fill(0); this.#unsigned.fill(0); if (delta !== 0) throw new Error("rekey_mac");
  }
  #decode(body: Uint8Array, phase: number): CBORDocument {
    return this.#decoder!.decodeMap(body, ["REKEY_REQUEST", "REKEY_INIT", "REKEY_REPLY", "REKEY_COMMIT", "REKEY_ACK"][phase]!, { selectors: { crypto_profile_id: this.#config.profile } });
  }
  acceptInit(body: Uint8Array): readonly RekeyEntry[] {
    this.#check(); if (this.#config.direction !== 1 || this.#phase !== 0) throw new Error("rekey_state");
    const doc = this.#decode(body, 1);
    try { doc.copyPayload(doc.field(0, 1), this.#id); this.#verify(doc, 1); set.call(this.#init, body); this.#initSize = byteLength(body); this.#digestInit(); this.#phase = 1; return this.#entries(doc, 4); }
    finally { doc.release(); }
  }
  #entries(doc: CBORDocument, field: number): readonly RekeyEntry[] {
    const node = doc.field(0, field), entries: RekeyEntry[] = [];
    if (doc.size(node) > this.#config.maxScopes) throw new Error("rekey_capacity");
    for (let item = doc.firstChild(node); item >= 0; item = doc.nextSibling(item)) entries.push({ scope: doc.uint(doc.field(item, 0)), next: doc.uint(doc.field(item, 1)) });
    return entries;
  }
  buildReply(entries: readonly RekeyEntry[]): Uint8Array {
    this.#check(); if (this.#config.direction !== 1 || this.#phase !== 1) throw new Error("rekey_state");
    this.#ephemeral();
    const body = this.#build(2, writer => { writer.uint(3).data(this.#digest).uint(4).data(this.#public).uint(5); this.#barrier(writer, entries); });
    set.call(this.#reply, body); this.#replySize = byteLength(body);
    const init = this.#decode(byteSlice(this.#init, 0, this.#initSize), 1);
    try { this.#derive(init, 3); } finally { init.release(); }
    this.#phase = 2; return body;
  }
  acceptReply(body: Uint8Array): readonly RekeyEntry[] {
    this.#check(); if (this.#config.direction !== 0 || this.#phase !== 1) throw new Error("rekey_state");
    const doc = this.#decode(body, 2);
    try {
      this.#verify(doc, 2); for (let i = 0; i < 32; i++) if (doc.payloadByte(doc.field(0, 3), i) !== this.#digest[i]) throw new Error("rekey_digest");
      set.call(this.#reply, body); this.#replySize = byteLength(body); this.#derive(doc, 4); this.#phase = 2; return this.#entries(doc, 5);
    } finally { doc.release(); }
  }
  #derive(doc: CBORDocument, field: number): void {
    const c = this.#config, transcript = sha256(rekeyDomain("rekey_transcript", c.profile, c.epoch,
      this.#values({ init: byteSlice(this.#init, 0, this.#initSize), reply: byteSlice(this.#reply, 0, this.#replySize) }), 0, this.#workspace));
    set.call(this.#transcript, transcript); transcript.fill(0);
    const peer = new Uint8Array(doc.size(doc.field(0, field))); doc.copyPayload(doc.field(0, field), peer);
    const x = ownProfile(c.profile)!.dh_algorithm === 0;
    let shared: Uint8Array | undefined, prk: Uint8Array | undefined, root: Uint8Array | undefined;
    try {
      shared = x ? x25519.getSharedSecret(this.#private, peer) : p256.getSharedSecret(this.#private, peer, false).slice(1, 33);
      if (shared.every(n => n === 0)) throw new Error("rekey_dh");
      this.#born = c.deadline.sample(); prk = extract(sha256, shared, this.#secret);
      root = expand(sha256, prk, rekeyDomain("rekey_root", c.profile, c.epoch, this.#values({ transcript_digest: this.#transcript }), 0, this.#workspace), 32);
      set.call(this.#root, root); this.#check();
    } finally { shared?.fill(0); prk?.fill(0); root?.fill(0); peer.fill(0); this.#private.fill(0); this.#private = empty; this.#workspace.fill(0); }
  }
  install(reservation: ResourceReference): RecordEpoch {
    this.#check(); if (this.#phase !== 2 || this.#born === undefined || this.#candidate !== undefined) throw new Error("rekey_state");
    const c = this.#config;
    this.#candidate = this.original.installSuccessor(this.#root, { clock: c.clock, born: this.#born, authorizationDeadline: c.authorizationDeadline,
      epoch: c.epoch + 1, runtimeBytes: c.runtimeBytes } satisfies RecordEpochConfig, reservation);
    return this.#candidate;
  }
  buildMarker(oldNext: bigint): Uint8Array {
    this.#check(); if (this.#candidate === undefined || this.#phase !== 2 && this.#phase !== 3) throw new Error("rekey_state");
    const phase = this.#config.direction === 0 ? 3 : 4;
    const body = this.#build(phase, writer => writer.uint(3).data(this.#transcript).uint(4).uint(oldNext)); this.#phase = phase; return body;
  }
  acceptMarker(body: Uint8Array, oldNext: bigint): void {
    this.#check(); const phase = this.#config.direction === 0 ? 4 : 3;
    if (this.#candidate === undefined || this.#phase !== (phase === 4 ? 3 : 2)) throw new Error("rekey_state");
    const doc = this.#decode(body, phase);
    try {
      this.#verify(doc, phase);
      if (doc.uint(doc.field(0, 4)) !== oldNext) throw new Error("rekey_frontier");
      for (let i = 0; i < 32; i++) if (doc.payloadByte(doc.field(0, 3), i) !== this.#transcript[i]) throw new Error("rekey_digest");
      this.#phase = phase;
    } finally { doc.release(); }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#decoder?.close();
    for (const bytes of [this.#secret, this.#root, this.#hash, this.#context, this.#id, this.#private, this.#public, this.#init, this.#reply, this.#unsigned, this.#workspace, this.#out, this.#digest, this.#transcript]) bytes.fill(0);
    this.#secret = this.#root = this.#hash = this.#context = this.#id = this.#private = this.#public = this.#init = this.#reply = this.#unsigned = this.#workspace = this.#out = this.#digest = this.#transcript = empty;
    this.#reservation?.release(); this.#reservation = undefined;
  }
}
