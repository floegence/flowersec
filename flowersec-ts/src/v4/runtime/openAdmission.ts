import { managementSpec } from "./executionManagementCodec.js";
import { FixedCBORWriter } from "./cborWriter.js";
export { FixedCBORWriter } from "./cborWriter.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import type { RecordDirection } from "./record.js";
import type { IncomingRecordInfo, RecordCipher, RecordPacket } from "./recordCrypto.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { wireDomains } from "./schemaRegistry.js";
import { wire } from "./wireRegistry.js";
import { transportV4StreamStateRegistry } from "../../generated/transportV4Registry.js";

export const bootstrapSpec = transportV4StreamStateRegistry.bootstrap;

const maximum = (1n << 64n) - 1n;
const snapshotBytes = 128 + 4096;
const openBytes = snapshotBytes + 128;
const token = Symbol("original OPEN owner");
const empty = new Uint8Array();
const copy = Uint8Array.prototype.set;
const encodeText = new TextEncoder();
export type StreamClass = 0 | 1 | 2;
const usedBytes = Math.ceil(wire.streams.client_ordinals / 8) + Math.ceil(wire.streams.server_ordinals / 8);
const domain = wireDomains.find(value => value.name === "open_digest");
if (domain?.operation !== "sha256" || domain.input_schema.parts[0]?.projection !== "without_open_digest") throw new Error("wire_registry");
const openLabel = Uint8Array.from(domain.label_bytes.match(/../gu)!.map(part => Number.parseInt(part, 16)));

export class OpenAdmissionError extends Error {
  constructor(readonly code: "configuration_capacity" | "open_capacity" | "open_closed" | "open_association" | "open_state" | "open_digest" | "open_rejected") {
    super(code); this.name = "OpenAdmissionError";
  }
}
function fail(code: OpenAdmissionError["code"]): never { throw new OpenAdmissionError(code); }
function bounded(value: number, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail("configuration_capacity");
  return value;
}

export interface OpenAdmissionConfig {
  readonly direction: RecordDirection;
  readonly maxActive: number;
  readonly maxPending: number;
  readonly ingressItems: number;
  readonly ingressBytes: number;
  readonly terminalCapacity: number;
  readonly rejectionReserve: number;
  readonly runtimeBytes: bigint;
  readonly perClass: readonly [number, number, number];
  readonly perOpener: readonly [readonly [number, number, number], readonly [number, number, number]];
  readonly protected: readonly [readonly [number, number, number], readonly [number, number, number]];
}
function capture(config: OpenAdmissionConfig): OpenAdmissionConfig {
  const direction = config.direction;
  if (direction !== 0 && direction !== 1 || typeof config.runtimeBytes !== "bigint" || config.runtimeBytes <= 0n) fail("configuration_capacity");
  const maxActive = bounded(config.maxActive, 0, 2 ** 21), maxPending = bounded(config.maxPending, 0, Math.min(128, maxActive));
  const ingressItems = bounded(config.ingressItems, 1, 128), ingressBytes = bounded(config.ingressBytes, 1, 512 * 1024);
  const terminalCapacity = bounded(config.terminalCapacity, 1, 4096);
  const rejectionReserve = bounded(config.rejectionReserve, ingressItems, Math.min(128, terminalCapacity));
  const perClass = Object.freeze(config.perClass.map(n => bounded(n, 0, maxActive))) as unknown as OpenAdmissionConfig["perClass"];
  const perOpener = Object.freeze(config.perOpener.map(row => Object.freeze(row.map((n, i) => bounded(n, 0, perClass[i]!))))) as unknown as OpenAdmissionConfig["perOpener"];
  const protectedSlots = Object.freeze(config.protected.map((row, r) => Object.freeze(row.map((n, c) => bounded(n, 0, perOpener[r]![c]!))))) as unknown as OpenAdmissionConfig["protected"];
  if (perClass.length !== 3 || perOpener.length !== 2 || protectedSlots.length !== 2 ||
      perOpener.some(row => row.length !== 3) || protectedSlots.some(row => row.length !== 3) ||
      protectedSlots.flat().reduce((a, b) => a + b, 0) > Math.min(maxActive, terminalCapacity - rejectionReserve)) fail("configuration_capacity");
  return Object.freeze({ direction, maxActive, maxPending, ingressItems, ingressBytes, terminalCapacity, rejectionReserve,
    perClass, perOpener, protected: protectedSlots, runtimeBytes: config.runtimeBytes });
}
export function openAdmissionCharge(config: OpenAdmissionConfig): ResourceVector {
  const c = capture(config), slots = c.terminalCapacity + c.ingressItems + 1;
  // Slots retain immutable OPEN association through retirement, independently
  // of active and ingress admission. The fixed snapshots are cleared when the
  // original operation no longer needs them; no map grows with lifetime IDs.
  const bytes = usedBytes * 3 + 96 + slots * (snapshotBytes + 32 + 256) + openBytes * 2 + 36;
  // Pending ingress and the one serial verifier coexist with terminal proofs.
  // One prepaid maintenance continuation publishes direct rejections.
  return new ResourceVector([BigInt(bytes) + c.runtimeBytes, 0n, 0n, BigInt(slots), BigInt(c.ingressItems + 1), 1n, 0n, 0n, 0n, 0n, 0n]);
}
export function openDecoderCharge(runtimeBytes: bigint): ResourceVector { return cborDecoderCharge(decoderConfig(runtimeBytes)); }
export function checkBootstrapCapacity(config: OpenAdmissionConfig): void {
  const c = capture(config);
  const unused = c.protected.reduce((sum, row, r) => sum + row.reduce((n, count, kind) =>
    n + Math.max(0, count - Number(r === 0 && kind === 1)), 0), 0);
  if (c.maxActive <= unused || c.terminalCapacity - c.rejectionReserve <= unused || c.perClass[1] < 1 || c.perOpener[0][1] < 1) fail("configuration_capacity");
}
function decoderConfig(runtimeBytes: bigint): Readonly<{ bytes: number; nodes: number; textBytes: number; arrayItems: number; runtimeBytes: bigint }> {
  return { bytes: openBytes, nodes: 272, textBytes: 128, arrayItems: 1, runtimeBytes };
}
type Phase = "free" | "bootstrap_reserved" | "local_prepared" | "local_opening" | "peer_verifying" | "peer_pending" | "live" | "rejected" | "recent" | "stable" | "closed";
interface Slot {
  generation: number; phase: Phase; scope: bigint; epoch: number; currentEpoch: number; local: boolean;
  streamClass: StreamClass; active: boolean; ingress: boolean; localLimit: bigint; peerLimit: bigint;
  kindBytes: number; metadataBytes: number; readonly storage: Uint8Array; readonly digest: Uint8Array;
  proof: "none" | "positive" | "rejection"; ingressCharge: number; resultSubmitted: boolean;
  bootstrap: boolean; prefixBound: boolean;
}
interface HandleState { readonly owner: OpenAdmission; readonly index: number; readonly generation: number; readonly scope: bigint; readonly epoch: number; readonly local: boolean }
const handles = new WeakMap<OpenHandle, HandleState>();

/** A capability for the original admitted OPEN, never caller-supplied numbers. */
export class OpenHandle {
  constructor(capability: symbol, owner: OpenAdmission, index: number, generation: number, scope: bigint, epoch: number, local: boolean) {
    if (capability !== token) fail("open_association");
    handles.set(this, { owner, index, generation, scope, epoch, local }); Object.freeze(this);
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.OpenHandle"; }
}
export interface OpenSnapshot {
  readonly scope: bigint; readonly epoch: number; readonly openEpoch: number; readonly local: boolean;
  readonly phase: Phase; readonly localReceiveLimit: bigint; readonly peerReceiveLimit: bigint;
}

/** Session-owned bounded OPEN transaction. Submitted IDs and proof tokens are
 * retained until authenticated retirement or complete Session shutdown. This
 * owner never interprets native EOF, cancellation, or GC as a peer outcome. */
export class OpenAdmission {
  readonly #config: OpenAdmissionConfig;
  readonly #slots: Slot[];
  #decoder: CBORDecoder | undefined;
  readonly #index = new Map<bigint, OpenHandle>();
  #reservation: ResourceReference | undefined;
  #used: Uint8Array = empty;
  #stable: Uint8Array = empty;
  // Canceled, unsubmitted IDs are stable for handle lifetime only. Shared
  // ingress refusal requires a separate authenticated retirement fact.
  #authenticatedRetired: Uint8Array = empty;
  readonly #byOpener = new Uint32Array(6);
  readonly #lifetime = new BigUint64Array(6);
  #input: Uint8Array = empty;
  #projection: Uint8Array = empty;
  #length: Uint8Array = empty;
  #digest: Uint8Array = empty;
  #next = 1n;
  #highestLocalAccepted = 0n;
  #highestPeerAccepted = 0n;
  #active = 0;
  #opening = 0;
  #ingress = 0;
  #ingressBytes = 0;
  #positiveProofs = 0;
  #rejectionProofs = 0;
  #closed = false;
  #working = false;
  constructor(config: OpenAdmissionConfig, reservation: ResourceReference, decoderReservation: ResourceReference) {
    this.#config = capture(config);
    if (!reservation.sameEnvironment(decoderReservation)) fail("configuration_capacity");
    this.#reservation = reservation.take(openAdmissionCharge(this.#config));
    this.#slots = [];
    try {
      this.#decoder = new CBORDecoder(decoderConfig(config.runtimeBytes), decoderReservation);
      this.#used = new Uint8Array(usedBytes); this.#stable = new Uint8Array(usedBytes); this.#authenticatedRetired = new Uint8Array(usedBytes);
      this.#input = new Uint8Array(openBytes); this.#projection = new Uint8Array(openBytes);
      this.#length = new Uint8Array(4); this.#digest = new Uint8Array(32);
      for (let i = 0; i < this.#config.terminalCapacity + this.#config.ingressItems + 1; i++) this.#slots.push({
        streamClass: 0, generation: 0, phase: "free", scope: 0n, epoch: 0, currentEpoch: 0, local: false, active: false, ingress: false,
        localLimit: 0n, peerLimit: 0n, kindBytes: 0, metadataBytes: 0, storage: new Uint8Array(snapshotBytes), digest: new Uint8Array(32),
        proof: "none", ingressCharge: 0, resultSubmitted: false, bootstrap: false, prefixBound: false,
      });
    } catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) fail("open_closed"); this.#reservation!.check(); }
  #slot(handle: OpenHandle): Slot {
    const h = handles.get(handle);
    if (h?.owner !== this) fail("open_association");
    const slot = this.#slots[h.index];
    if (slot === undefined || slot.generation !== h.generation || slot.phase === "free") fail("open_association");
    return slot;
  }
  #scope(scope: bigint, direction: RecordDirection): readonly [number, number] {
    const ordinal = (scope + 1n - BigInt(direction)) / 2n, cap = direction === 0 ? wire.streams.client_ordinals : wire.streams.server_ordinals;
    if (scope <= 0n || (scope + 1n) % 2n !== BigInt(direction) || ordinal < 1n || ordinal > BigInt(cap)) fail("open_association");
    const bit = Number(ordinal - 1n), offset = direction === 0 ? 0 : Math.ceil(wire.streams.client_ordinals / 8);
    return [offset + Math.floor(bit / 8), 1 << (bit % 8)];
  }
  #allocate(scope: bigint, epoch: number, local: boolean): OpenHandle {
    if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > 0xffffffff) fail("open_association");
    const [index, mask] = this.#scope(scope, local ? this.#config.direction : this.#config.direction === 0 ? 1 : 0);
    if ((this.#used[index]! & mask) !== 0 || this.#index.has(scope)) fail("open_association");
    const slotIndex = this.#slots.findIndex(slot => slot.phase === "free" && slot.generation < Number.MAX_SAFE_INTEGER);
    if (slotIndex < 0) fail("open_capacity");
    const slot = this.#slots[slotIndex]!;
    slot.generation++; slot.scope = scope; slot.epoch = slot.currentEpoch = epoch; slot.local = local;
    slot.phase = local ? "local_prepared" : "peer_verifying";
    const handle = new OpenHandle(token, this, slotIndex, slot.generation, scope, epoch, local);
    this.#index.set(scope, handle);
    return handle;
  }
  lookup(scope: bigint): OpenHandle | undefined { return this.#index.get(scope); }
  pendingPeer(): OpenHandle | undefined {
    this.#check();
    for (const [scope, handle] of this.#index) if (this.#slot(handle).phase === "peer_pending" && scope > 0n) return handle;
    return undefined;
  }
  pendingPeers(): readonly OpenHandle[] {
    this.#check();
    return [...this.#index.values()].filter(handle => this.#slot(handle).phase === "peer_pending");
  }
  kind(handle: OpenHandle): string {
    this.#check(); const slot = this.#slot(handle);
    return new TextDecoder("utf-8", { fatal: true }).decode(byteSlice(slot.storage, 0, slot.kindBytes));
  }
  classification(handle: OpenHandle): StreamClass { this.#check(); return this.#slot(handle).streamClass; }
  peerLimit(handle: OpenHandle): bigint { this.#check(); return this.#slot(handle).peerLimit; }
  phase(handle: OpenHandle): Phase { return this.snapshot(handle).phase; }
  snapshot(handle: OpenHandle): OpenSnapshot {
    this.#check();
    const original = handles.get(handle);
    if (original?.owner !== this) fail("open_association");
    if (this.isStable(original.scope)) return Object.freeze({ scope: original.scope, epoch: original.epoch, openEpoch: original.epoch, local: original.local,
      phase: "stable", localReceiveLimit: 0n, peerReceiveLimit: 0n });
    const slot = this.#slot(handle);
    return Object.freeze({ scope: slot.scope, epoch: slot.currentEpoch, openEpoch: slot.epoch, local: slot.local, phase: slot.phase,
      localReceiveLimit: slot.localLimit, peerReceiveLimit: slot.peerLimit });
  }
  counts(): Readonly<{ active: number; opening: number; ingress: number; ingressBytes: number; positiveProofs: number; rejectionProofs: number }> {
    return Object.freeze({ active: this.#active, opening: this.#opening, ingress: this.#ingress, ingressBytes: this.#ingressBytes,
      positiveProofs: this.#positiveProofs, rejectionProofs: this.#rejectionProofs });
  }
  managementAllocations(): bigint { this.#check(); return this.#lifetime[2]!; }
  highestAccepted(local: boolean): bigint { return local ? this.#highestLocalAccepted : this.#highestPeerAccepted; }
  /** READY owns the fixed scope before publication. This is neither an OPEN
   * contender nor an invented accepted response. The permanent ID, class-I
   * lifetime and positive terminal token are charged exactly once. */
  prepareBootstrap(profile: "services" | "execution"): OpenHandle {
    this.#check();
    if (!bootstrapSpec.profiles.includes(profile) || this.#working || this.#next !== 1n || this.#index.size !== 0) fail("open_state");
    this.#positiveAvailable(0, 1);
    const handle = this.#allocate(BigInt(bootstrapSpec.scope), 0, this.#config.direction === 0), slot = this.#slot(handle);
    slot.bootstrap = true; slot.phase = "bootstrap_reserved"; slot.streamClass = 1;
    slot.localLimit = slot.peerLimit = BigInt(bootstrapSpec.initial_receive_limit);
    slot.kindBytes = encodeText.encodeInto(bootstrapSpec.kind, slot.storage).written;
    slot.active = true; slot.proof = "positive";
    this.#active++; this.#positiveProofs++; this.#byOpener[1] = this.#byOpener[1]! + 1; this.#lifetime[1] = this.#lifetime[1]! + 1n;
    this.#markUsed(slot);
    if (this.#config.direction === 0) this.#next++;
    return handle;
  }
  completeBootstrap(handle: OpenHandle): void {
    this.#check(); const slot = this.#slot(handle);
    if (!slot.bootstrap || slot.phase !== "bootstrap_reserved") fail("open_state");
    slot.phase = "live";
    if (slot.local) this.#highestLocalAccepted = slot.scope; else this.#highestPeerAccepted = slot.scope;
  }
  isBootstrap(handle: OpenHandle): boolean { this.#check(); return this.#slot(handle).bootstrap; }
  bootstrapBound(handle: OpenHandle): boolean { this.#check(); const slot = this.#slot(handle); return slot.bootstrap && slot.prefixBound; }
  encodeBootstrap(handle: OpenHandle, destination: Uint8Array): Uint8Array {
    this.authorize(handle, wire.frame_types.OPEN_STREAM!, this.#config.direction);
    const slot = this.#slot(handle), writer = new FixedCBORWriter(this.#projection);
    this.#fields(writer.map(8), slot, slot.currentEpoch); this.#hash(writer.result(), slot.digest);
    const result = new FixedCBORWriter(destination);
    this.#fields(result.map(9), slot, slot.currentEpoch); result.uint(8).data(slot.digest);
    return result.result();
  }
  submittedBootstrap(handle: OpenHandle): void {
    this.authorize(handle, wire.frame_types.OPEN_STREAM!, this.#config.direction);
    this.#slot(handle).prefixBound = true;
  }
  receiveBootstrap(handle: OpenHandle, cipher: RecordCipher, packet: RecordPacket): void {
    this.#check(); const slot = this.#slot(handle), info = cipher.inspectIncoming(packet);
    if (this.#working || !slot.bootstrap || slot.local || slot.phase !== "live" || slot.prefixBound ||
        info.scope !== slot.scope || info.epoch !== slot.currentEpoch || info.sequence !== 0n ||
        info.direction !== 0 || info.frameType !== wire.frame_types.OPEN_STREAM) fail("open_association");
    this.#working = true;
    let doc: CBORDocument | undefined;
    try {
      const n = packet.copyBytes(this.#input); doc = this.#decoder!.decodeMap(byteSlice(this.#input, 0, n), "OPEN_STREAM");
      this.#association(doc, info);
      if (doc.text(doc.field(0, 5)) !== bootstrapSpec.kind || doc.size(doc.field(0, 6)) !== 0 ||
          doc.uint(doc.field(0, 7)) !== BigInt(bootstrapSpec.initial_receive_limit)) fail("open_association");
      const size = doc.copyWithoutField(8, this.#projection); this.#hash(byteSlice(this.#projection, 0, size), this.#digest);
      doc.copyPayload(doc.field(0, 8), slot.digest);
      if (!equal(this.#digest, slot.digest)) fail("open_digest");
      this.#check(); packet.commitValidated(); slot.prefixBound = true;
      // Existing credit, offsets, keys and class/lifetime accounting survive.
    } finally { doc?.release(); packet.release(); this.#input.fill(0); this.#projection.fill(0); this.#digest.fill(0); this.#working = false; }
  }
  prepareLocal(epoch: number, streamClass: StreamClass, kind: string, metadata: Uint8Array, initialReceiveLimit: bigint): OpenHandle {
    this.#check();
    const managementFuture = this.#config.direction === 0 && streamClass !== 2 && this.#config.protected[0][2] === 1 && this.#byOpener[2] === 0 ? 1 : 0;
    if (this.#working || this.#opening >= this.#config.maxPending - managementFuture) fail("open_capacity");
    this.#positiveAvailable(this.#config.direction, streamClass);
    // Server-originated business OPEN cannot consume the next opportunity
    // already awaited by an authenticated client business contender.
    if (this.#config.direction === 1 && streamClass === 0 && this.#slots.some(slot => slot.phase === "peer_pending")) fail("open_capacity");
    if (typeof kind !== "string" || kind.length < 1 || kind.length > 128 || byteLength(metadata) > 4096 ||
        initialReceiveLimit < 0n || initialReceiveLimit > maximum) fail("configuration_capacity");
    // encodeInto writes into prepaid scratch; UTF-16 input cannot cause a
    // length-proportional uncharged intermediate buffer.
    const encoded = encodeText.encodeInto(kind, byteSlice(this.#projection, 0, 128));
    if (encoded.read !== kind.length || encoded.written === 0) fail("configuration_capacity");
    const scope = 2n * this.#next - 1n + BigInt(this.#config.direction);
    const handle = this.#allocate(scope, epoch, true), slot = this.#slot(handle);
    slot.streamClass = streamClass; this.#byOpener[this.#config.direction * 3 + streamClass] = this.#byOpener[this.#config.direction * 3 + streamClass]! + 1; this.#lifetime[this.#config.direction * 3 + streamClass] = this.#lifetime[this.#config.direction * 3 + streamClass]! + 1n;
    this.#next++; this.#active++; this.#opening++; this.#positiveProofs++; slot.proof = "positive"; slot.active = true; slot.localLimit = initialReceiveLimit;
    slot.kindBytes = encoded.written; slot.metadataBytes = byteLength(metadata);
    copy.call(slot.storage, byteSlice(this.#projection, 0, slot.kindBytes)); copy.call(slot.storage, metadata, slot.kindBytes);
    try {
      const wire = this.encodeLocal(handle, this.#input);
      const document = this.#decoder!.decodeMap(wire, "OPEN_STREAM"); document.release();
      return handle;
    } catch (error) { this.cancelUnsubmitted(handle); throw error; }
    finally { this.#input.fill(0); this.#projection.fill(0); }
  }
  encodeLocal(handle: OpenHandle, destination: Uint8Array): Uint8Array {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase !== "local_prepared") fail("open_state");
    const writer = new FixedCBORWriter(this.#projection);
    this.#fields(writer.reset().map(8), slot); this.#hash(writer.result(), slot.digest);
    const result = new FixedCBORWriter(destination);
    this.#fields(result.map(9), slot); result.uint(8).data(slot.digest);
    return result.result();
  }
  #fields(writer: FixedCBORWriter, slot: Slot, epoch = slot.epoch): void {
    writer.uint(0).uint(slot.scope).uint(1).uint(this.#config.direction).uint(2).uint(slot.scope)
      .uint(3).uint(epoch).uint(4).uint(0).uint(5).data(byteSlice(slot.storage, 0, slot.kindBytes), true)
      .uint(6).data(byteSlice(slot.storage, slot.kindBytes, slot.kindBytes + slot.metadataBytes)).uint(7).uint(slot.localLimit);
  }
  #hash(projection: Uint8Array, destination: Uint8Array): void {
    let n = byteLength(projection);
    for (let i = 3; i >= 0; i--) { this.#length[i] = n % 256; n = Math.floor(n / 256); }
    const hash = sha256.create();
    try { hash.update(openLabel).update(this.#length).update(projection).digestInto(destination); }
    finally { hash.destroy(); this.#length.fill(0); }
  }
  submittedLocal(handle: OpenHandle): void {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase !== "local_prepared") fail("open_state"); this.#markUsed(slot); slot.phase = "local_opening";
  }
  cancelUnsubmitted(handle: OpenHandle): void {
    const slot = this.#slot(handle);
    if (slot.phase !== "local_prepared") fail("open_state");
    const [index, mask] = this.#scope(slot.scope, this.#config.direction);
    this.#markUsed(slot); this.#stable[index] = this.#stable[index]! | mask;
    this.#byOpener[this.#config.direction * 3 + slot.streamClass] = this.#byOpener[this.#config.direction * 3 + slot.streamClass]! - 1; this.#active--; this.#opening--; this.#positiveProofs--; this.#release(slot);
  }
  reservePeer(scope: bigint, epoch: number): OpenHandle {
    this.#check();
    if (this.#slots.some(slot => slot.phase === "peer_verifying")) fail("open_capacity");
    return this.#allocate(scope, epoch, false);
  }
  /** Authentication, complete schema/digest validation and ingress accounting
   * commit the same original packet in one synchronous owner turn. */
  receivePeer(handle: OpenHandle, cipher: RecordCipher, packet: RecordPacket): "pending" | "rejected" {
    this.#check(); const slot = this.#slot(handle), info = cipher.inspectIncoming(packet);
    if (this.#working || slot.phase !== "peer_verifying" || info.scope !== slot.scope || info.epoch !== slot.epoch ||
        info.frameType !== wire.frame_types.OPEN_STREAM || info.sequence !== 0n || info.direction === this.#config.direction) fail("open_association");
    this.#working = true;
    let doc: CBORDocument | undefined;
    try {
      const n = packet.copyBytes(this.#input); doc = this.#decoder!.decodeMap(byteSlice(this.#input, 0, n), "OPEN_STREAM");
      this.#association(doc, info);
      const kind = doc.field(0, 5), metadata = doc.field(0, 6), bytes = doc.size(kind) + doc.size(metadata);
      const ingressCharge = bytes + 512;
      const management = this.#config.direction === 1 && this.#config.protected[0][2] === 1 && doc.text(kind) === managementSpec.kind;
      const unusedManagement = !management && this.#config.direction === 1 && this.#config.protected[0][2] === 1 && this.#byOpener[2] === 0 ? 1 : 0;
      const staged = this.#ingress < this.#config.ingressItems - unusedManagement && ingressCharge <= this.#config.ingressBytes - this.#ingressBytes - 640 * unusedManagement;
      const size = doc.copyWithoutField(8, this.#projection); this.#hash(byteSlice(this.#projection, 0, size), this.#digest);
      doc.copyPayload(doc.field(0, 8), slot.digest);
      if (!equal(this.#digest, slot.digest)) fail("open_digest");
      if (!staged) {
        // The original terminal reserve owns the result before any state is
        // committed. No application metadata escapes the shared decoder.
        this.#reserveRejection(slot); this.#check(); packet.commitValidated();
        this.#markUsed(slot); slot.phase = "rejected"; return "rejected";
      }
      slot.kindBytes = doc.size(kind); slot.metadataBytes = doc.size(metadata);
      doc.copyPayload(kind, byteSlice(slot.storage, 0, slot.kindBytes));
      doc.copyPayload(metadata, byteSlice(slot.storage, slot.kindBytes, bytes));
      slot.peerLimit = doc.uint(doc.field(0, 7));
      this.#check(); packet.commitValidated();
      slot.phase = "peer_pending"; slot.ingress = true; slot.ingressCharge = ingressCharge;
      this.#ingress++; this.#ingressBytes += ingressCharge; return "pending";
    } finally { doc?.release(); packet.release(); this.#input.fill(0); this.#projection.fill(0); this.#digest.fill(0); this.#working = false; }
  }
  #association(doc: CBORDocument, info: IncomingRecordInfo): void {
    if (doc.uint(doc.field(0, 0)) !== info.scope || doc.uint(doc.field(0, 1)) !== BigInt(info.direction) ||
        doc.uint(doc.field(0, 2)) !== info.scope || doc.uint(doc.field(0, 3)) !== BigInt(info.epoch) ||
        doc.uint(doc.field(0, 4)) !== info.sequence) fail("open_association");
  }
  /** Borrow the original prepaid decoder until the caller releases the document.
   * Metadata rejection remains attached to this authenticated pending OPEN. */
  metadataDocument(handle: OpenHandle): CBORDocument | undefined {
    this.#check(); const slot = this.#slot(handle);
    if (!["peer_pending", "live"].includes(slot.phase) || this.#working) fail("open_state");
    if (slot.metadataBytes === 0) return undefined;
    const raw = byteSlice(slot.storage, slot.kindBytes, slot.kindBytes + slot.metadataBytes);
    const shell = this.#decoder!.decode(raw);
    let typed = false;
    try { typed = shell.text(shell.field(0, 0)) === "flowersec/typed-message"; } finally { shell.release(); }
    return this.#decoder!.decodeMap(raw, typed ? "TypedMessageMetadata" : "StreamMetadata");
  }
  copyOffer(handle: OpenHandle, kind: Uint8Array, metadata: Uint8Array): Readonly<{ kindBytes: number; metadataBytes: number }> {
    this.#check(); const slot = this.#slot(handle);
    if (!["local_prepared", "local_opening", "peer_pending", "live"].includes(slot.phase) || byteLength(kind) < slot.kindBytes || byteLength(metadata) < slot.metadataBytes) fail("open_state");
    copy.call(kind, byteSlice(slot.storage, 0, slot.kindBytes)); copy.call(metadata, byteSlice(slot.storage, slot.kindBytes, slot.kindBytes + slot.metadataBytes));
    return Object.freeze({ kindBytes: slot.kindBytes, metadataBytes: slot.metadataBytes });
  }
  /** Checks before preparation and again in the actual submission gate. */
  checkAccept(handle: OpenHandle, streamClass: StreamClass): void {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase !== "peer_pending") fail("open_state");
    this.#positiveAvailable(this.#config.direction === 0 ? 1 : 0, streamClass, slot.proof === "positive");
  }
  /** Acquire before any application projection or authorization callback. A
   * full terminal budget leaves the original authenticated ingress pending. */
  reserveAuthorization(handle: OpenHandle, streamClass: StreamClass): boolean {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase !== "peer_pending") fail("open_state");
    if (slot.proof !== "none") return true;
    try { this.checkAccept(handle, streamClass); }
    catch (error) { if (error instanceof OpenAdmissionError && error.code === "open_capacity") return false; throw error; }
    slot.proof = "positive"; this.#positiveProofs++; return true;
  }
  canReject(handle: OpenHandle): boolean {
    this.#check(); const slot = this.#slot(handle);
    return slot.proof !== "none" || this.#rejectionProofs < this.#config.rejectionReserve;
  }
  #reserveRejection(slot: Slot): void {
    if (slot.proof !== "none") return;
    if (this.#rejectionProofs >= this.#config.rejectionReserve) fail("open_capacity");
    slot.proof = "rejection"; this.#rejectionProofs++;
  }
  encodeResult(handle: OpenHandle, limit: bigint, destination: Uint8Array, streamClass: StreamClass, rejection?: number): Uint8Array {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase !== "peer_pending" && !(slot.phase === "rejected" && !slot.local && !slot.resultSubmitted && rejection !== undefined) ||
        limit < 0n || limit > maximum || rejection !== undefined && limit !== 0n) fail("open_state");
    if (rejection === undefined) this.checkAccept(handle, streamClass);
    else this.#reserveRejection(slot);
    const writer = new FixedCBORWriter(destination).map(rejection === undefined ? 8 : 12);
    writer.uint(0).uint(slot.scope).uint(1).uint(this.#config.direction === 0 ? 1 : 0).uint(2).uint(rejection === undefined ? 0 : 1)
      .uint(3).uint(slot.epoch).uint(4).uint(0).uint(5).data(slot.digest).uint(6).uint(limit);
    if (rejection !== undefined) writer.uint(7).uint(slot.epoch).uint(8).uint(1).uint(9).uint(0);
    writer.uint(10).uint(1); if (rejection !== undefined) writer.uint(11).uint(rejection);
    const result = writer.result(), doc = this.#decoder!.decodeMap(result, "OPEN_ACCEPT"); doc.release(); return result;
  }
  /** Called only in the original output ticket gate after all direction owners
   * exist. It must not be delayed until a native completion callback. */
  acceptedPeer(handle: OpenHandle, initialReceiveLimit: bigint, streamClass: StreamClass): void {
    this.checkAccept(handle, streamClass); const slot = this.#slot(handle);
    if (initialReceiveLimit < 0n || initialReceiveLimit > maximum) fail("configuration_capacity");
    slot.streamClass = streamClass; this.#byOpener[(1 - this.#config.direction) * 3 + streamClass] = this.#byOpener[(1 - this.#config.direction) * 3 + streamClass]! + 1; this.#lifetime[(1 - this.#config.direction) * 3 + streamClass] = this.#lifetime[(1 - this.#config.direction) * 3 + streamClass]! + 1n;
    slot.localLimit = initialReceiveLimit; slot.phase = "live"; slot.active = true;
    if (slot.scope > this.#highestPeerAccepted) this.#highestPeerAccepted = slot.scope;
    this.#active++;
    if (slot.proof !== "positive") { this.#positiveProofs++; if (slot.proof === "rejection") this.#rejectionProofs--; slot.proof = "positive"; }
    this.#markUsed(slot); this.#leaveIngress(slot);
  }
  rejectedPeer(handle: OpenHandle): void {
    this.#check(); const slot = this.#slot(handle);
    if (slot.local || slot.phase !== "peer_pending" && !(slot.phase === "rejected" && !slot.resultSubmitted)) fail("open_state");
    this.#reserveRejection(slot); this.#markUsed(slot);
    slot.phase = "rejected"; slot.resultSubmitted = true; this.#leaveIngress(slot);
  }
  receiveResult(doc: CBORDocument, packet: RecordPacket): OpenHandle {
    this.#check(); if (doc.schema() !== "OPEN_ACCEPT") fail("open_association");
    const handle = this.#index.get(doc.uint(doc.field(0, 0))); if (handle === undefined) fail("open_association");
    const slot = this.#slot(handle);
    if (slot.phase !== "local_opening" || doc.uint(doc.field(0, 1)) !== BigInt(this.#config.direction) ||
        doc.uint(doc.field(0, 3)) !== BigInt(slot.epoch) || doc.uint(doc.field(0, 4)) !== 0n) fail("open_association");
    doc.copyPayload(doc.field(0, 5), this.#digest);
    try { if (!equal(slot.digest, this.#digest)) fail("open_association"); } finally { this.#digest.fill(0); }
    const rejected = doc.uint(doc.field(0, 2)) === 1n, limit = doc.uint(doc.field(0, 6));
    this.#check(); packet.commitValidated(); this.#opening--;
    if (rejected) { slot.phase = "rejected"; slot.active = false; this.#byOpener[this.#config.direction * 3 + slot.streamClass] = this.#byOpener[this.#config.direction * 3 + slot.streamClass]! - 1; this.#active--; }
    else { slot.phase = "live"; slot.peerLimit = limit; if (slot.scope > this.#highestLocalAccepted) this.#highestLocalAccepted = slot.scope; }
    // Accepted adapters verify the original OPEN binding after the outcome.
    // Its fixed slot backing was admitted with OPEN and survives until retire.
    if (rejected) { slot.storage.fill(0); slot.kindBytes = slot.metadataBytes = 0; }
    return handle;
  }
  authorize(handle: OpenHandle, frame: number, direction: RecordDirection): void {
    this.#check(); const slot = this.#slot(handle);
    if (slot.bootstrap) {
      if (slot.phase !== "live") fail("open_state");
      if (frame === wire.frame_types.OPEN_STREAM && direction === 0 && !slot.prefixBound ||
          frame === wire.frame_types.STREAM_DATA && slot.prefixBound) return;
      fail("open_state");
    }
    if (frame === wire.frame_types.OPEN_STREAM) {
      if (slot.local && direction === this.#config.direction && slot.phase === "local_prepared" ||
          !slot.local && direction !== this.#config.direction && slot.phase === "peer_verifying") return;
    } else if (frame === wire.frame_types.STREAM_DATA && slot.phase === "live") return;
    fail("open_state");
  }
  #positiveAvailable(role: RecordDirection, streamClass: StreamClass, ownsProof = false): void {
    bounded(streamClass, 0, 2);
    let unused = 0;
    for (let r = 0; r < 2; r++) for (let c = 0; c < 3; c++) {
      const after = this.#byOpener[r * 3 + c]! + (r === role && c === streamClass ? 1 : 0);
      unused += Math.max(0, this.#config.protected[r]![c]! - after);
    }
    const lifetime = streamClass === 2 ? 16n : 1048576n;
    if (this.#active + unused >= this.#config.maxActive ||
        this.#positiveProofs - Number(ownsProof) + unused >= this.#config.terminalCapacity - this.#config.rejectionReserve ||
        this.#byOpener[role * 3 + streamClass]! >= this.#config.perOpener[role]![streamClass]! ||
        this.#byOpener[streamClass]! + this.#byOpener[3 + streamClass]! >= this.#config.perClass[streamClass]! ||
        this.#lifetime[role * 3 + streamClass]! >= lifetime || role === 1 && streamClass === 2) fail("open_capacity");
  }
  terminal(handle: OpenHandle): void {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase === "recent" || slot.phase === "rejected") return;
    if (slot.phase !== "live" || !slot.active) fail("open_state");
    slot.phase = "recent"; slot.active = false; this.#active--;
    const role = slot.local ? this.#config.direction : 1 - this.#config.direction;
    this.#byOpener[role * 3 + slot.streamClass] = this.#byOpener[role * 3 + slot.streamClass]! - 1;
  }
  isStable(scope: bigint): boolean {
    this.#check(); const role = Number((scope + 1n) % 2n) as RecordDirection, [at, mask] = this.#scope(scope, role);
    return (this.#stable[at]! & mask) !== 0;
  }
  isAuthenticatedRetired(scope: bigint): boolean {
    this.#check(); const role = Number((scope + 1n) % 2n) as RecordDirection, [at, mask] = this.#scope(scope, role);
    return (this.#authenticatedRetired[at]! & mask) !== 0;
  }
  /** Commit the authenticated retirement fence. Existing barrier and native
   * publication owners can retain the original proof slot after this point. */
  retire(handle: OpenHandle, retainProof = false): void {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase !== "recent" && slot.phase !== "rejected") fail("open_state");
    if (slot.phase === "rejected" && !slot.local && !slot.resultSubmitted) fail("open_state");
    const role = slot.local ? this.#config.direction : this.#config.direction === 0 ? 1 : 0, [at, mask] = this.#scope(slot.scope, role);
    this.#stable[at] = this.#stable[at]! | mask;
    this.#authenticatedRetired[at] = this.#authenticatedRetired[at]! | mask;
    slot.phase = "stable";
    if (!retainProof) this.releaseRetired(handle);
  }
  /** Release the same token only after its last real proof owner has exited. */
  releaseRetired(handle: OpenHandle): void {
    this.#check(); const slot = this.#slot(handle);
    if (slot.phase !== "stable") fail("open_state");
    if (slot.proof === "positive") this.#positiveProofs--; else if (slot.proof === "rejection") this.#rejectionProofs--; else fail("open_state");
    this.#release(slot);
  }
  completeRekey(epoch: number): void {
    this.#check();
    for (const slot of this.#slots) if (slot.phase === "live" || slot.phase === "local_opening" || slot.phase === "peer_pending") {
      if (slot.currentEpoch + 1 !== epoch) fail("open_state"); slot.currentEpoch = epoch;
    }
  }
  #leaveIngress(slot: Slot): void {
    if (slot.ingress) { this.#ingress--; this.#ingressBytes -= slot.ingressCharge; slot.ingress = false; slot.ingressCharge = 0; }
    // Accepted adapters still validate the exact original offer. This fixed
    // slot backing was prepaid with OPEN and remains charged until retirement.
    if (slot.phase !== "live") { slot.storage.fill(0); slot.kindBytes = slot.metadataBytes = 0; }
  }
  #release(slot: Slot): void {
    this.#index.delete(slot.scope); slot.storage.fill(0); slot.digest.fill(0); slot.phase = "free"; slot.scope = 0n;
    slot.localLimit = slot.peerLimit = 0n; slot.active = slot.ingress = false; slot.kindBytes = slot.metadataBytes = 0;
    slot.proof = "none"; slot.ingressCharge = 0; slot.resultSubmitted = false; slot.bootstrap = slot.prefixBound = false;
  }
  #markUsed(slot: Slot): void {
    const [index, mask] = this.#scope(slot.scope, slot.local ? this.#config.direction : this.#config.direction === 0 ? 1 : 0);
    this.#used[index] = this.#used[index]! | mask;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#decoder?.close();
    for (const slot of this.#slots) this.#release(slot);
    this.#used.fill(0); this.#stable.fill(0); this.#authenticatedRetired.fill(0); this.#byOpener.fill(0); this.#lifetime.fill(0n); this.#input.fill(0); this.#projection.fill(0); this.#digest.fill(0); this.#length.fill(0);
    this.#authenticatedRetired = this.#stable = this.#used = this.#input = this.#projection = this.#digest = this.#length = empty;
    this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#reservation === undefined && (this.#decoder?.cleanupComplete() ?? true); }
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (byteLength(a) !== byteLength(b)) return false;
  let difference = 0; for (let i = 0; i < byteLength(a); i++) difference |= a[i]! ^ b[i]!;
  return difference === 0;
}
