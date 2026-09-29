import { byteLength, byteSlice } from "./cbor.js";
import { hmac } from "@noble/hashes/hmac.js";
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { verifyEd25519 } from "./ed25519.js";
import { RecordEpoch, type RecordEpochConfig } from "./recordCrypto.js";
import type { ResourceReference } from "./resources.js";
import type { CryptoUsageLedger } from "./cryptoUsage.js";
import { transportV4NoiseWasmBase64 } from "./noiseWasmBinary.js";
import { ownProfile } from "./wireRegistry.js";
import { wireDomains } from "./schemaRegistry.js";
import type { ClockSample, TrustedClock } from "./clock.js";
import type { TrustedDeadline } from "./deadline.js";

export type NoiseProfile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" | "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1";
export type NoiseRole = "client" | "server";
export type NoiseFailure = "noise_configuration" | "noise_busy" | "noise_closed" | "noise_state" | "noise_authentication";
export class NoiseHandshakeError extends Error { readonly code: NoiseFailure; constructor(code: NoiseFailure) { super(code); this.name = "NoiseHandshakeError"; this.code = code; } }
function fail(code: NoiseFailure): never { throw new NoiseHandshakeError(code); }
const empty = new Uint8Array(0), maximumInput = 1_048_576;
export interface ReadyIdentitySigner { readonly publicKey: Uint8Array; sign(message: Uint8Array): Uint8Array; }
export interface ReadyConfig { readonly localCertificateDigest: Uint8Array; readonly peerCertificateDigest: Uint8Array; readonly fsbDigest: Uint8Array; readonly fsaDigest: Uint8Array; readonly admissionBinding: Uint8Array; readonly transportContextDigest: Uint8Array; readonly selectedFeatures: bigint | number; }
/**
 * The Noise prologue is an authenticated protocol value.  Callers provide
 * the already validated, immutable FSB4/FSA4 canonical maps; they cannot
 * select an arbitrary prologue or silently substitute a digest.  The two
 * role bytes in the prologue are fixed by the protocol (client=0, server=1).
 */
export interface NoiseHandshakeConfig { readonly clock: TrustedClock; readonly authorizationDeadline: TrustedDeadline; readonly preparationDeadline: TrustedDeadline; readonly profile: NoiseProfile; readonly role: NoiseRole; readonly localStaticPrivate: Uint8Array; readonly localStaticPublic: Uint8Array; readonly peerStaticPublic: Uint8Array; readonly psk: Uint8Array; readonly ephemeralPrivate: Uint8Array; readonly contextDigest: Uint8Array; readonly fsb: Uint8Array; readonly fsa: Uint8Array; }
function decodeBase64(value: string): Uint8Array { const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; const out = new Uint8Array(Math.floor(value.length * 3 / 4)); let acc = 0, bits = 0, at = 0; for (const char of value) { if (char === "=") break; const digit = alphabet.indexOf(char); if (digit < 0) fail("noise_configuration"); acc = ((acc << 6) | digit) & 0xffffff; bits += 6; if (bits >= 8) { bits -= 8; out[at++] = (acc >> bits) & 255; } } return at === out.length ? out : out.subarray(0, at); }
let wasmModule: WebAssembly.Module | undefined;
type NoiseExports = { readonly memory: WebAssembly.Memory; readonly fs_noise_abi: () => number; readonly fs_noise_io: () => number; readonly fs_noise_start: () => number; readonly fs_noise_write: () => number; readonly fs_noise_read: (size: number) => number; readonly fs_noise_finish: () => number; readonly fs_noise_close: () => void };
function instance(): NoiseExports { wasmModule ??= new WebAssembly.Module(decodeBase64(transportV4NoiseWasmBase64) as unknown as BufferSource); const value = new WebAssembly.Instance(wasmModule).exports as unknown as NoiseExports; if (value.fs_noise_abi() !== 1 || value.memory === undefined) fail("noise_configuration"); return value; }
function copyInto(e: NoiseExports, source: Uint8Array, offset: number): void { const pointer = e.fs_noise_io(); if (!Number.isSafeInteger(pointer) || pointer < 0 || pointer + offset + source.length > e.memory.buffer.byteLength) fail("noise_configuration"); new Uint8Array(e.memory.buffer, pointer + offset, source.length).set(source); }
function copyOut(e: NoiseExports, size: number): Uint8Array { const pointer = e.fs_noise_io(); if (!Number.isSafeInteger(pointer) || pointer < 0 || pointer + size > e.memory.buffer.byteLength) fail("noise_configuration"); return Uint8Array.from(new Uint8Array(e.memory.buffer, pointer, size)); }
function profileCode(profile: NoiseProfile): 0 | 1 { if (profile === "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1") return 0; if (profile === "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1") return 1; fail("noise_configuration"); }
function roleCode(role: NoiseRole): 0 | 1 { if (role === "client") return 0; if (role === "server") return 1; fail("noise_configuration"); }
function bytes(value: Uint8Array, size: number, code: NoiseFailure): Uint8Array { try { if (byteLength(value) !== size) fail(code); const out = new Uint8Array(size); out.set(byteSlice(value, 0, size)); return out; } catch { fail(code); } }
function equalBytes(a: Uint8Array, b: Uint8Array): boolean { if (a.length !== b.length) return false; let n = 0; for (let i = 0; i < a.length; i++) n |= a[i]! ^ b[i]!; return n === 0; }
function unsigned(value: bigint, width: number): Uint8Array { if (value < 0n || value >= 1n << BigInt(width * 8)) fail("noise_configuration"); const out = new Uint8Array(width); for (let i = width - 1; i >= 0; i--) { out[i] = Number(value & 255n); value >>= 8n; } return out; }
function head(major: number, value: bigint): Uint8Array { if (value < 24n) return Uint8Array.of(major * 32 + Number(value)); for (const [width, ai] of [[1, 24], [2, 25], [4, 26], [8, 27]] as const) if (value < 1n << BigInt(width * 8)) return Uint8Array.from([major * 32 + ai, ...unsigned(value, width)]); fail("noise_configuration"); }
function concat(...parts: Uint8Array[]): Uint8Array { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let offset = 0; for (const part of parts) { out.set(part, offset); offset += part.length; } return out; }
function cborBytes(value: Uint8Array): Uint8Array { return concat(head(2, BigInt(value.length)), value); }
function cborText(value: string): Uint8Array { const raw = new TextEncoder().encode(value); return concat(head(3, BigInt(raw.length)), raw); }
function cborMap(entries: readonly [number, Uint8Array][]): Uint8Array { const sorted = [...entries].sort(([a], [b]) => a - b); for (let i = 1; i < sorted.length; i++) if (sorted[i - 1]![0] >= sorted[i]![0]) fail("noise_configuration"); return concat(head(5, BigInt(sorted.length)), ...sorted.flatMap(([id, value]) => [head(0, BigInt(id)), value])); }
function lp(value: Uint8Array): Uint8Array { return concat(unsigned(BigInt(value.length), 4), value); }
function label(name: string): Uint8Array { const item = wireDomains.find(value => value.name === name); if (item === undefined) fail("noise_configuration"); const out = new Uint8Array(item.label_bytes.length / 2); for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(item.label_bytes.slice(i * 2, i * 2 + 2), 16); return out; }
function domain(name: string, ...parts: Uint8Array[]): Uint8Array { return concat(label(name), ...parts.map(value => concat(unsigned(BigInt(value.length), 4), value))); }
const noisePrologueLabel = new TextEncoder().encode("flowersec/v4/noise-prologue\0");
const profileRevision = new TextEncoder().encode("4");
function noisePrologue(profile: NoiseProfile, contextDigest: Uint8Array, fsb: Uint8Array, fsa: Uint8Array): Uint8Array {
  // This is the byte-level definition in 3.5.2.  In particular, the role
  // bytes are raw u8 values and the FSB4/FSA4 values are the complete original
  // canonical maps, including their signatures.  There is deliberately no
  // caller supplied prologue parameter.
  return concat(noisePrologueLabel, lp(profileRevision), lp(new TextEncoder().encode(profile)), Uint8Array.of(0, 1),
    lp(contextDigest), lp(fsb), lp(fsa));
}
type ReadyParts = { role: number; profile: NoiseProfile; hash: Uint8Array; fsb: Uint8Array; fsa: Uint8Array; transport: Uint8Array; binding: Uint8Array; certificate: Uint8Array };
function context(role: number, profile: NoiseProfile, hash: Uint8Array, config: ReadyConfig, certificate: Uint8Array): ReadyParts { if (role !== 0 && role !== 1) fail("noise_configuration"); return { role, profile, hash: bytes(hash, 32, "noise_configuration"), fsb: bytes(config.fsbDigest, 32, "noise_configuration"), fsa: bytes(config.fsaDigest, 32, "noise_configuration"), transport: bytes(config.transportContextDigest, 32, "noise_configuration"), binding: bytes(config.admissionBinding, 32, "noise_configuration"), certificate: bytes(certificate, 32, "noise_configuration") }; }
function proofInput(c: ReadyParts): Uint8Array { return cborMap([[0, head(0, BigInt(c.role))], [1, cborText(c.profile)], [2, cborBytes(c.hash)], [3, cborBytes(c.fsb)], [4, cborBytes(c.fsa)], [5, cborBytes(c.transport)], [6, cborBytes(c.binding)], [7, cborBytes(c.certificate)]]); }
function macInput(c: ReadyParts, selected: bigint, proof: Uint8Array): Uint8Array { if (selected < 0n || selected > 3n) fail("noise_configuration"); return cborMap([[0, head(0, BigInt(c.role))], [1, cborText(c.profile)], [2, cborBytes(c.hash)], [3, cborBytes(c.fsb)], [4, cborBytes(c.fsa)], [5, cborBytes(c.transport)], [6, cborBytes(c.binding)], [7, cborBytes(c.certificate)], [8, head(0, selected)], [9, cborBytes(proof)]]); }
function feature(value: bigint | number): bigint { if (typeof value === "bigint") return value; if (!Number.isSafeInteger(value) || value < 0) fail("noise_configuration"); return BigInt(value); }
function readyKey(root: Uint8Array, profile: NoiseProfile, hash: Uint8Array, transport: Uint8Array, role: number): Uint8Array {
  // ready_key allocates the role as the registry's trailing raw u8. The
  // domain helper is length-prefixed for every component and would encode a
  // four-byte length before that role, producing a transcript that differs
  // from the cross-SDK corpus.
  const profileBytes = new TextEncoder().encode(profile);
  const transportBytes = bytes(transport, 32, "noise_configuration");
  const info = concat(label("ready_key"), unsigned(BigInt(profileBytes.length), 4), profileBytes,
    unsigned(BigInt(hash.length), 4), hash, unsigned(BigInt(transportBytes.length), 4), transportBytes,
    Uint8Array.of(role));
  return expand(sha256, bytes(root, 32, "noise_configuration"), info, 32);
}
function readyWire(proof: Uint8Array, confirmation: Uint8Array): Uint8Array { if (proof.length !== 64 || confirmation.length !== 32) fail("noise_authentication"); return cborMap([[0, cborBytes(proof)], [1, cborBytes(confirmation)]]); }
function decodeReadyWire(input: Uint8Array): [Uint8Array, Uint8Array] { if (byteLength(input) !== 103) fail("noise_authentication"); const wire = byteSlice(input, 0, 103); if (wire[0] !== 0xa2 || wire[1] !== 0 || wire[2] !== 0x58 || wire[3] !== 0x40 || wire[68] !== 1 || wire[69] !== 0x58 || wire[70] !== 0x20) fail("noise_authentication"); return [bytes(wire.slice(4, 68), 64, "noise_authentication"), bytes(wire.slice(71), 32, "noise_authentication")]; }
function copyReady(config: ReadyConfig): ReadyConfig { const selectedFeatures = feature(config.selectedFeatures); if (selectedFeatures > 3n) fail("noise_configuration"); return Object.freeze({ localCertificateDigest: bytes(config.localCertificateDigest, 32, "noise_configuration"), peerCertificateDigest: bytes(config.peerCertificateDigest, 32, "noise_configuration"), fsbDigest: bytes(config.fsbDigest, 32, "noise_configuration"), fsaDigest: bytes(config.fsaDigest, 32, "noise_configuration"), admissionBinding: bytes(config.admissionBinding, 32, "noise_configuration"), transportContextDigest: bytes(config.transportContextDigest, 32, "noise_configuration"), selectedFeatures }); }
function sameReady(a: ReadyConfig, b: ReadyConfig): boolean { return a.selectedFeatures === b.selectedFeatures && equalBytes(a.localCertificateDigest, b.localCertificateDigest) && equalBytes(a.peerCertificateDigest, b.peerCertificateDigest) && equalBytes(a.fsbDigest, b.fsbDigest) && equalBytes(a.fsaDigest, b.fsaDigest) && equalBytes(a.admissionBinding, b.admissionBinding) && equalBytes(a.transportContextDigest, b.transportContextDigest); }

// Implemented by the admitted maintenance output owner. Returning true means
// that the original READY has crossed its irreversible submission boundary;
// merely queueing an application callback is not submission.
export interface ReadyPublicationOwner { submitReady(payload: Uint8Array): boolean; }

export class NoiseHandshake {
  readonly #clock: TrustedClock;
  readonly #authorizationDeadline: TrustedDeadline;
  readonly #preparationDeadline: TrustedDeadline;
  #born: ClockSample | undefined;
  #readyPayload: Uint8Array = empty;
  #readySubmitted = false;
  #publishingReady = false;
  #preparedEpoch: { owner: RecordEpoch; ledger: CryptoUsageLedger; reservation: ResourceReference; runtimeBytes: bigint; epoch: number } | undefined;
  readonly #profile: NoiseProfile; readonly #role: NoiseRole; #contextDigest: Uint8Array = empty; #fsbDigest: Uint8Array = empty; #fsaDigest: Uint8Array = empty; #exports: NoiseExports | undefined; #root: Uint8Array = empty; #hash: Uint8Array = empty; #closed = false; #written = false; #read = false; #complete = false; #finished = false; #localReady = false; #peerReady = false; #ready: ReadyConfig | undefined;
  constructor(config: NoiseHandshakeConfig) {
    this.#clock = config.clock;
    this.#authorizationDeadline = config.authorizationDeadline;
    this.#preparationDeadline = config.preparationDeadline;
    if (!this.#authorizationDeadline.belongsTo(this.#clock) || !this.#preparationDeadline.belongsTo(this.#clock)) fail("noise_configuration");
    this.#checkDeadline();
    const profile = config.profile, descriptor = ownProfile(profile);
    if (descriptor === undefined) fail("noise_configuration");
    const localPrivate = bytes(config.localStaticPrivate, 32, "noise_configuration"), localPublic = bytes(config.localStaticPublic, descriptor.dh_public_bytes, "noise_configuration"), peerPublic = bytes(config.peerStaticPublic, descriptor.dh_public_bytes, "noise_configuration"), psk = bytes(config.psk, 32, "noise_configuration"), ephemeral = bytes(config.ephemeralPrivate, 32, "noise_configuration"), contextDigest = bytes(config.contextDigest, 32, "noise_configuration"), fsb = bytes(config.fsb, byteLength(config.fsb), "noise_configuration"), fsa = bytes(config.fsa, byteLength(config.fsa), "noise_configuration");
    if (fsb.length === 0 || fsa.length === 0 || fsb.length > 65536 || fsa.length > 65536) fail("noise_configuration");
    const prologue = noisePrologue(profile, contextDigest, fsb, fsa);
    if (prologue.length === 0 || prologue.length > maximumInput - 266) fail("noise_configuration");
    const e = instance();
    try { const io = e.fs_noise_io(); if (!Number.isSafeInteger(io) || io < 0 || io + maximumInput > e.memory.buffer.byteLength) fail("noise_configuration"); const view = new Uint8Array(e.memory.buffer, io, maximumInput); view.fill(0); view[0] = profileCode(profile); view[1] = roleCode(config.role); view.set(localPrivate, 4); view.set(localPublic, 36); view.set(peerPublic, 101); view.set(psk, 166); view.set(ephemeral, 198); new DataView(view.buffer, view.byteOffset, view.byteLength).setUint32(230, prologue.length); view.set(contextDigest, 234); view.set(prologue, 266); if (e.fs_noise_start() < 0) fail("noise_authentication"); this.#exports = e; this.#profile = profile; this.#role = config.role; this.#contextDigest = contextDigest.slice();
      // The digest is part of the authenticated READY context and must be
      // derived from the exact original FSB4/FSA4 bytes. A caller supplied
      // digest is only an assertion checked below, never an authority.
      this.#fsbDigest = sha256(domain("fsb_digest", fsb));
      this.#fsaDigest = sha256(domain("fsa_digest", fsa));
    } catch (error) { e.fs_noise_close(); if (error instanceof NoiseHandshakeError) throw error; fail("noise_authentication"); } finally { localPrivate.fill(0); psk.fill(0); ephemeral.fill(0); contextDigest.fill(0); fsb.fill(0); fsa.fill(0); prologue.fill(0); }
  }
  get profile(): NoiseProfile { return this.#profile; } get role(): NoiseRole { return this.#role; }
  #checkDeadline(): void { this.#authorizationDeadline.check(); this.#preparationDeadline.check(); }
  writeMessage(): Uint8Array { this.#checkDeadline(); const e = this.#exports; if (e === undefined || this.#closed || this.#finished || this.#complete || this.#written) fail("noise_state"); const size = e.fs_noise_write(); if (size !== ownProfile(this.#profile)!.handshake_message_bytes) { this.close(); fail("noise_authentication"); } this.#written = true; const output = copyOut(e, size); new Uint8Array(e.memory.buffer, e.fs_noise_io(), size).fill(0); if (this.#read) this.#deriveRoot(); return output; }
  readMessage(message: Uint8Array): void { this.#checkDeadline(); const e = this.#exports; if (e === undefined || this.#closed || this.#finished || this.#complete || this.#read) fail("noise_state"); const size = byteLength(message); if (size !== ownProfile(this.#profile)!.handshake_message_bytes) { this.close(); fail("noise_authentication"); } copyInto(e, message, 0); if (e.fs_noise_read(size) < 0) { this.close(); fail("noise_authentication"); } this.#read = true; if (this.#written) this.#deriveRoot(); }
  createReady(signer: ReadyIdentitySigner, config: ReadyConfig): Uint8Array { this.#deriveRoot(); if (this.#closed || this.#localReady) fail("noise_state"); const captured = copyReady(config); if (!equalBytes(captured.fsbDigest, this.#fsbDigest) || !equalBytes(captured.fsaDigest, this.#fsaDigest) || !equalBytes(captured.transportContextDigest, this.#contextDigest)) { captured.fsbDigest.fill(0); captured.fsaDigest.fill(0); this.close(); fail("noise_authentication"); } const ready = this.#ready ?? (this.#ready = captured); if (!sameReady(ready, captured)) { this.close(); fail("noise_authentication"); } const role = roleCode(this.#role), c = context(role, this.#profile, this.#hash, ready, ready.localCertificateDigest), message = domain("ready_identity", proofInput(c)); const publicKey = bytes(signer.publicKey, 32, "noise_configuration"), proof = bytes(signer.sign(message), 64, "noise_authentication"); if (!verifyEd25519(proof, message, publicKey)) { this.close(); fail("noise_authentication"); } const key = readyKey(this.#root, this.#profile, this.#hash, ready.transportContextDigest, role); try { const confirmation = hmac(sha256, key, domain("ready_mac", macInput(c, feature(ready.selectedFeatures), proof))); this.#checkDeadline(); this.#localReady = true; this.#readyPayload = readyWire(proof, confirmation); return this.#readyPayload.slice(); } finally { key.fill(0); } }
  verifyReady(input: Uint8Array, peerPublicKey: Uint8Array, config: ReadyConfig): void { this.#deriveRoot(); if (this.#closed || this.#peerReady) fail("noise_state"); const captured = copyReady(config); if (!equalBytes(captured.fsbDigest, this.#fsbDigest) || !equalBytes(captured.fsaDigest, this.#fsaDigest) || !equalBytes(captured.transportContextDigest, this.#contextDigest)) { captured.fsbDigest.fill(0); captured.fsaDigest.fill(0); this.close(); fail("noise_authentication"); } const ready = this.#ready ?? (this.#ready = captured); if (!sameReady(ready, captured)) { this.close(); fail("noise_authentication"); } const [proof, confirmation] = decodeReadyWire(input), role = 1 - roleCode(this.#role), c = context(role, this.#profile, this.#hash, ready, ready.peerCertificateDigest); if (!verifyEd25519(proof, domain("ready_identity", proofInput(c)), bytes(peerPublicKey, 32, "noise_authentication"))) { this.close(); fail("noise_authentication"); } const key = readyKey(this.#root, this.#profile, this.#hash, ready.transportContextDigest, role); try { const expected = hmac(sha256, key, domain("ready_mac", macInput(c, feature(ready.selectedFeatures), proof))); if (!equalBytes(expected, confirmation)) { expected.fill(0); this.close(); fail("noise_authentication"); } expected.fill(0); this.#peerReady = true; } finally { key.fill(0); } }
  submitReady(owner: ReadyPublicationOwner): void {
    this.#checkDeadline();
    if (this.#closed || !this.#localReady || this.#readySubmitted || this.#publishingReady) fail("noise_state");
    this.#publishingReady = true;
    try {
      // The transport owns this copy if it accepts. The retained original is
      // never exposed to a provider or to the caller of createReady.
      if (!owner.submitReady(this.#readyPayload.slice())) fail("noise_busy");
      this.#checkDeadline();
      if (this.#closed) fail("noise_closed");
      this.#readySubmitted = true;
      this.#readyPayload.fill(0); this.#readyPayload = empty;
    } catch (error) { this.close(); throw error; }
    finally { this.#publishingReady = false; }
  }
  /** Private initial key ownership may precede READY publication. It grants
   * no application I/O authority; Session keeps that gate closed until finish.
   * Failure destroys this exact epoch and its already derived directions. */
  prepareEpoch(config: Omit<RecordEpochConfig, "epoch" | "clock" | "born" | "authorizationDeadline"> & { readonly epoch?: number }, ledger: CryptoUsageLedger, reservation: ResourceReference): RecordEpoch {
    this.#deriveRoot();
    if (this.#closed || this.#finished || this.#readySubmitted || !this.#localReady || this.#ready === undefined ||
        this.#born === undefined || this.#preparedEpoch !== undefined || (config.epoch ?? 0) !== 0) fail("noise_state");
    const owner = new RecordEpoch({ ...config, clock: this.#clock, born: this.#born, authorizationDeadline: this.#authorizationDeadline,
      epoch: 0, profile: this.#profile, transportContextDigest: this.#contextDigest, admissionBinding: this.#ready.admissionBinding },
      this.#root, this.#hash, ledger, reservation);
    this.#preparedEpoch = { owner, ledger, reservation, runtimeBytes: config.runtimeBytes, epoch: 0 };
    return owner;
  }
  finish(config: Omit<RecordEpochConfig, "epoch" | "clock" | "born" | "authorizationDeadline"> & { readonly epoch?: number }, ledger: CryptoUsageLedger, reservation: ResourceReference): RecordEpoch {
    this.#deriveRoot();
    if (this.#exports === undefined || this.#closed || this.#finished || !this.#readySubmitted || !this.#peerReady || this.#ready === undefined || this.#born === undefined) fail("noise_state");
    this.#finished = true;
    const epoch = config.epoch ?? 0;
    try {
      if (this.#preparedEpoch !== undefined) {
        const prepared = this.#preparedEpoch;
        if (prepared.ledger !== ledger || prepared.reservation !== reservation || prepared.runtimeBytes !== config.runtimeBytes || prepared.epoch !== epoch) fail("noise_state");
        this.#preparedEpoch = undefined;
        return prepared.owner;
      }
      return new RecordEpoch({ ...config, clock: this.#clock, born: this.#born, authorizationDeadline: this.#authorizationDeadline,
        epoch, profile: this.#profile, transportContextDigest: this.#contextDigest, admissionBinding: this.#ready.admissionBinding },
        this.#root, this.#hash, ledger, reservation);
    } finally { this.close(); }
  }
  #deriveRoot(): void {
    this.#checkDeadline();
    if (this.#complete) return;
    const e = this.#exports;
    if (e === undefined || this.#closed || !this.#written || !this.#read) fail("noise_state");
    // Capture the original conservative birth sample before the KDF starts.
    // READY and later epoch installation cannot replace it with a newer sample.
    this.#born = this.#clock.sample(); this.#authorizationDeadline.checkAt(this.#born); this.#preparationDeadline.checkAt(this.#born);
    const size = e.fs_noise_finish();
    if (size !== 64) { this.close(); fail("noise_authentication"); }
    const output = copyOut(e, size);
    new Uint8Array(e.memory.buffer, e.fs_noise_io(), size).fill(0);
    try {
      // The primitive ABI already applies initial-root Expand to Split i2r.
      // Its first 32 bytes are the root, followed by the final handshake hash;
      // deriving again here changes every READY/record key across SDKs.
      this.#root = output.slice(0, 32);
      this.#hash = output.slice(32);
      this.#checkDeadline(); this.#complete = true;
    } catch (error) { this.close(); throw error; }
    finally { output.fill(0); }
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#preparedEpoch?.owner.close(); this.#preparedEpoch = undefined; this.#readyPayload.fill(0); this.#readyPayload = empty; this.#born = undefined; this.#exports?.fs_noise_close(); this.#exports = undefined; this.#root.fill(0); this.#hash.fill(0); this.#contextDigest.fill(0); this.#fsbDigest.fill(0); this.#fsaDigest.fill(0); if (this.#ready !== undefined) { this.#ready.localCertificateDigest.fill(0); this.#ready.peerCertificateDigest.fill(0); this.#ready.fsbDigest.fill(0); this.#ready.fsaDigest.fill(0); this.#ready.admissionBinding.fill(0); this.#ready.transportContextDigest.fill(0); this.#ready = undefined; } this.#root = empty; this.#hash = empty; this.#contextDigest = empty; this.#fsbDigest = empty; this.#fsaDigest = empty; }
}
for (const constructor of [NoiseHandshake, NoiseHandshakeError]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
