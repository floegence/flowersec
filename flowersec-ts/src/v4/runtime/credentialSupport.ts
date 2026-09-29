import { sha256 } from "@noble/hashes/sha2.js";
import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import type { TrustedClock } from "./clock.js";
import { ResourceVector, type ResourceAccount, type ResourceOwner, type ResourceReference, type ResourceRoot, type ProtectedResourceReservation } from "./resources.js";
import type { DecodeContext } from "./schema.js";
import { namedField, wireDomains } from "./schemaRegistry.js";
import { SignedMapCodec, signedMapCodecCharge } from "./signedMap.js";

export class CredentialError extends Error {
  constructor(readonly code: "credential_invalid" | "credential_untrusted" | "credential_expired" | "credential_revoked" | "credential_binding" | "credential_closed" | "configuration_capacity") {
    super(code); this.name = "CredentialError";
  }
}
export function requireCredential(condition: unknown, code: CredentialError["code"] = "credential_binding"): asserts condition {
  if (!condition) throw new CredentialError(code);
}
export interface CredentialResources {
  readonly root: ResourceRoot; readonly accounts: readonly ResourceAccount[]; readonly owner: ResourceOwner;
  readonly runtimeBytes: bigint;
}
let nextWorkOwner = 0n;
export function credentialOwner(resources: CredentialResources, kind: string): ResourceOwner {
  const next = ++nextWorkOwner; requireCredential(next <= 0xffffffffffffffffn, "configuration_capacity");
  return { ...resources.owner, kind: `credential_${kind}_${next}` };
}
/** One actual job belongs to the original root and retains all decoder/signature
 * backing. Peer-selected schema sizes cannot create an uncharged work area. */
export class CredentialWork {
  readonly #resources: CredentialResources;
  #reservation: ResourceReference | undefined;
  #scratch: Uint8Array;
  #signatureNodes = 32768;
  #signatureSlots: readonly [ProtectedResourceReservation, ProtectedResourceReservation] | undefined;
  #parserSlots: { slot: ProtectedResourceReservation; busy: boolean }[] = [];
  #parserConfig: { bytes: number; nodes: number } | undefined;
  constructor(resources: CredentialResources, bytes: number, reservation: ResourceReference) {
    this.#resources = Object.freeze({ ...resources, owner: Object.freeze({ ...resources.owner }), accounts: Object.freeze([...resources.accounts]) });
    this.#reservation = reservation.take(credentialWorkCharge(bytes, resources.runtimeBytes));
    try { this.#scratch = new Uint8Array(bytes); }
    catch (error) { this.#reservation.release(); this.#reservation = undefined; throw error; }
  }
  check(): void { requireCredential(this.#reservation !== undefined, "credential_closed"); this.#reservation.check(); }
  sameEnvironment(reference: ResourceReference): boolean { this.check(); return this.#reservation!.sameEnvironment(reference); }
  reserve(kind: string, charge: ResourceVector): ResourceReference {
    this.check(); const r = this.#resources;
    const ref = r.root.reserve({ owner: credentialOwner(r, kind), accounts: r.accounts, charge });
    try { requireCredential(this.#reservation!.sameEnvironment(ref), "credential_binding"); return ref; }
    catch (error) { ref.release(); throw error; }
  }
  protect(kind: string, charge: ResourceVector, aliases = 0): ProtectedResourceReservation {
    const ref = this.reserve(kind, charge), retained: ResourceReference[] = [];
    try { for (let n = 0; n < aliases; n++) retained.push(ref.borrow()); return this.#resources.root.protect(ref, charge, retained); }
    finally { ref.release(); for (const alias of retained) alias.release(); }
  }
  prepaySignatures(bytes: number, nodes: number): void {
    requireCredential(this.#signatureSlots === undefined, "credential_binding");
    const decoder = { bytes, nodes, textBytes: Math.min(bytes, 4096), arrayItems: nodes, runtimeBytes: this.#resources.runtimeBytes };
    const a = this.protect("signature_decoder", cborDecoderCharge(decoder), 1);
    try {
      const costs = ["TrustConfig", "TrustBootstrapResponse", "FreshnessHead"].map(schema => signedMapCodecCharge({ schema, decoder, runtimeBytes: this.#resources.runtimeBytes }));
      // The bootstrap signature domain has the longest label of these maps.
      const b = this.protect("signature", costs.reduce((max, value) => value.values()[0]! > max.values()[0]! ? value : max), 1);
      this.#signatureSlots = [a, b]; this.#signatureNodes = nodes;
    } catch (error) { a.close(); throw error; }
  }
  prepayParsers(bytes: number, nodes: number, count: number): void {
    requireCredential(this.#parserConfig === undefined && Number.isSafeInteger(count) && count > 0 && count <= 8);
    const config = { bytes, nodes, textBytes: Math.min(bytes, 4096), arrayItems: nodes, runtimeBytes: this.#resources.runtimeBytes };
    try {
      for (let index = 0; index < count; index++) this.#parserSlots.push({ slot: this.protect("parser", cborDecoderCharge(config), 1), busy: false });
      this.#parserConfig = { bytes, nodes };
    } catch (error) { for (const entry of this.#parserSlots) entry.slot.close(); this.#parserSlots = []; throw error; }
  }
  parse(raw: Uint8Array, schema: string, cap: number, nodes = 16384, context: DecodeContext = {}, prepaid?: ResourceReference, released?: () => void): OwnedCredentialMap {
    this.check(); requireCredential(byteLength(raw) <= cap, "configuration_capacity");
    const boundedNodes = Math.min(nodes, byteLength(raw));
    const config = { bytes: cap, nodes: boundedNodes, textBytes: Math.min(cap, 4096), arrayItems: boundedNodes, runtimeBytes: this.#resources.runtimeBytes };
    const slot = prepaid === undefined && this.#parserConfig !== undefined ? this.#parserSlots.find(entry => !entry.busy) : undefined;
    if (prepaid === undefined && this.#parserConfig !== undefined) requireCredential(slot !== undefined && cap <= this.#parserConfig.bytes && boundedNodes <= this.#parserConfig.nodes, "configuration_capacity");
    if (slot !== undefined) slot.busy = true;
    let ref: ResourceReference | undefined, decoder: CBORDecoder | undefined;
    try {
      ref = prepaid ?? slot?.slot.checkout() ?? this.reserve("decoder", cborDecoderCharge(config)); decoder = new CBORDecoder(config, ref);
      return new OwnedCredentialMap(decoder, decoder.decodeMap(raw, schema, context), schema, () => { if (slot !== undefined) slot.busy = false; released?.(); });
    } catch (error) { decoder?.close(); if (slot !== undefined) slot.busy = false; throw error; } finally { ref?.release(); }
  }
  verify(map: OwnedCredentialMap, publicKey: Uint8Array, context: DecodeContext = {}): void {
    this.check(); const size = map.doc.encodedSize(); requireCredential(size <= this.#scratch.length, "configuration_capacity");
    map.doc.copyEncoded(0, this.#scratch);
    const config = { schema: map.schema, decoder: { bytes: size, nodes: Math.min(this.#signatureNodes, size), textBytes: Math.min(size, 4096), arrayItems: Math.min(this.#signatureNodes, size), runtimeBytes: this.#resources.runtimeBytes }, runtimeBytes: this.#resources.runtimeBytes };
    const a = this.#signatureSlots?.[0].checkout() ?? this.reserve("signature_decoder", cborDecoderCharge(config.decoder)); let b: ResourceReference | undefined, codec: SignedMapCodec | undefined;
    try {
      b = this.#signatureSlots?.[1].checkout() ?? this.reserve("signature", signedMapCodecCharge(config)); codec = new SignedMapCodec(config, a, b);
      const signed = codec.verify(byteSlice(this.#scratch, 0, size), publicKey, context); signed.release();
    } finally { codec?.close(); a.release(); b?.release(); this.#scratch.fill(0); }
  }
  digest(map: OwnedCredentialMap, name: string, node = 0): Uint8Array {
    this.check(); const n = map.doc.encodedSize(node); requireCredential(n <= this.#scratch.length, "configuration_capacity");
    map.doc.copyEncoded(node, this.#scratch);
    try { return credentialDigest(name, byteSlice(this.#scratch, 0, n)); } finally { this.#scratch.fill(0); }
  }
  close(): void { for (const entry of this.#parserSlots) entry.slot.closeAfterUse(); this.#parserSlots = []; for (const slot of this.#signatureSlots ?? []) slot.closeAfterUse(); this.#signatureSlots = undefined; this.#scratch.fill(0); this.#scratch = new Uint8Array(); this.#reservation?.release(); this.#reservation = undefined; }
}
export function credentialWorkCharge(bytes: number, runtimeBytes: bigint): ResourceVector {
  requireCredential(Number.isSafeInteger(bytes) && bytes > 0 && bytes <= 1 << 24 && runtimeBytes > 0n, "configuration_capacity");
  return new ResourceVector([BigInt(bytes) + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export class OwnedCredentialMap {
  #references = 1;
  constructor(private readonly decoder: CBORDecoder, readonly doc: CBORDocument, readonly schema: string, private readonly released?: () => void) {}
  retain(): this { requireCredential(this.#references > 0, "credential_closed"); this.#references++; return this; }
  field(name: string, node = 0, schema = this.schema): number {
    const id = namedField(schema, name); requireCredential(id !== undefined, "credential_invalid");
    const value = this.doc.field(node, id); requireCredential(value >= 0, "credential_invalid"); return value;
  }
  optional(name: string, node = 0, schema = this.schema): number {
    const id = namedField(schema, name); requireCredential(id !== undefined, "credential_invalid"); return this.doc.field(node, id);
  }
  uint(name: string, node = 0, schema = this.schema): bigint { return this.doc.uint(this.field(name, node, schema)); }
  text(name: string, node = 0, schema = this.schema): string { return this.doc.text(this.field(name, node, schema)); }
  bytes(name: string, node = 0, schema = this.schema): Uint8Array {
    const value = this.field(name, node, schema), bytes = new Uint8Array(this.doc.size(value)); this.doc.copyPayload(value, bytes); return bytes;
  }
  encoded(node = 0): Uint8Array { const bytes = new Uint8Array(this.doc.encodedSize(node)); this.doc.copyEncoded(node, bytes); return bytes; }
  *items(name: string, node = 0, schema = this.schema): Generator<number> {
    for (let n = this.doc.firstChild(this.field(name, node, schema)); n >= 0; n = this.doc.nextSibling(n)) yield n;
  }
  close(): void { if (this.#references > 0 && --this.#references === 0) { this.doc.release(); this.decoder.close(); this.released?.(); } }
}
export function credentialDigest(name: string, encoded: Uint8Array): Uint8Array {
  const d = wireDomains.find(v => v.name === name);
  requireCredential(d?.operation === "sha256" && d.input_schema.parts.length === 1 && d.input_schema.parts[0]!.encoding === "lp-map" && d.input_schema.parts[0]!.projection === "full", "credential_invalid");
  const label = Uint8Array.from(d.label_bytes.match(/../gu)!.map(v => Number.parseInt(v, 16))), length = new Uint8Array(4), n = byteLength(encoded);
  length[0] = n >>> 24; length[1] = n >>> 16; length[2] = n >>> 8; length[3] = n;
  const hash = sha256.create(); try { return hash.update(label).update(length).update(encoded).digest(); }
  finally { hash.destroy(); length.fill(0); }
}
export function equalCredential(a: Uint8Array, b: Uint8Array): boolean {
  if (byteLength(a) !== byteLength(b)) return false;
  let different = 0; for (let i = 0; i < byteLength(a); i++) different |= a[i]! ^ b[i]!; return different === 0;
}
export function checkCredentialTime(clock: TrustedClock, from: bigint, until: bigint): void {
  const now = clock.sample().requireInterval(); requireCredential(from < until && now.lowerMS >= from && now.upperMS < until, "credential_expired");
}
export function credentialTimeAdd(a: bigint, b: bigint): bigint {
  const n = a + b; requireCredential(a >= 0n && b >= 0n && n <= (1n << 64n) - 1n, "credential_invalid"); return n;
}
