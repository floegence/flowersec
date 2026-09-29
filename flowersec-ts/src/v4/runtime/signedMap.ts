import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { byteLength, captureDecoderConfig, CBORDecoder, type CBORDecoderConfig, type CBORDocument, type CBORKind } from "./cbor.js";
import { verifyEd25519 } from "./ed25519.js";
import type { ResourceReference} from "./resources.js";
import { ResourceVector } from "./resources.js";
import { captureDecodeContext, type DecodeContext } from "./schema.js";
import { namedField, own, wireDomains, wireMaps, type WireDomain } from "./schemaRegistry.js";

export type SignatureFailure = "signature_schema" | "signature_invalid" | "signature_projection" | "signature_capacity" |
  "signature_owner" | "signature_busy" | "signature_closed" | "signature_released" | "digest_schema" | "signature_field" |
  "signature_generation_failed" | "signature_key_purpose";
export class SignatureValidationError extends Error {
  readonly code: SignatureFailure;
  constructor(code: SignatureFailure) { super(code); this.name = "SignatureValidationError"; this.code = code; }
}
function reject(code: SignatureFailure): never { throw new SignatureValidationError(code); }
const capability = Symbol("signed original map");
const empty = new Uint8Array(0);
const copy = Uint8Array.prototype.set;
function domainFor(schema: string): WireDomain {
  const domain = wireDomains.find(d => d.operation === "ed25519" && d.input_schema.parts.length === 1 && d.input_schema.parts[0]!.encoding === "lp-map" &&
    d.input_schema.parts[0]!.schema_ref === schema && d.input_schema.parts[0]!.projection === "without_signature");
  if (domain === undefined || own(wireMaps, schema)?.signature_field === undefined) reject("signature_schema");
  return domain;
}
export interface SignedMapCodecConfig {
  readonly schema: string;
  readonly decoder: CBORDecoderConfig;
  readonly runtimeBytes: bigint;
}
interface CapturedConfig extends SignedMapCodecConfig { readonly domain: WireDomain; readonly labelBytes: number }
function capture(config: SignedMapCodecConfig): CapturedConfig {
  const schema = config.schema, decoder = captureDecoderConfig(config.decoder), runtimeBytes = config.runtimeBytes;
  const domain = domainFor(schema);
  if (typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) reject("signature_capacity");
  let labelBytes = domain.label_bytes.length / 2;
  for (const d of wireDomains) if (d.operation === "sha256" && d.input_schema.parts.length === 1 && d.input_schema.parts[0]!.schema_ref === schema && d.input_schema.parts[0]!.encoding === "lp-map") {
    labelBytes = Math.max(labelBytes, d.label_bytes.length / 2);
  }
  return Object.freeze({ schema, decoder, runtimeBytes, domain, labelBytes });
}
// This is the codec's work/message charge, in addition to cborDecoderCharge.
// Composition reserves both atomically in the same root/tenant/Environment.
// runtimeBytes covers the chosen library's curve/hash work and JS metadata.
export function signedMapCodecCharge(config: SignedMapCodecConfig): ResourceVector {
  const c = capture(config), bytes = BigInt(c.decoder.bytes) * 2n + BigInt(c.labelBytes) + 4n + 32n + 64n + 32n;
  return new ResourceVector([bytes + c.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
const signed = new WeakMap<SignedMap, SignedMapCodec>();

// A mathematical fact over one immutable original material owner. No shared
// cache holds Artifact/PSK input, and no result is serialized or restored as
// authorization. Its caller must independently check issuer purpose, trust,
// freshness, revocation, identities, containing bindings and the once gates.
export class SignedMap {
  constructor(token: symbol, codec: SignedMapCodec) {
    if (token !== capability) reject("signature_owner");
    signed.set(this, codec); Object.freeze(this);
  }
  #codec(): SignedMapCodec { const c = signed.get(this); if (c === undefined) reject("signature_released"); return c; }
  schema(): string { return this.#codec().schema(this); }
  selector(name: string): string | undefined { return this.#codec().document(this, capability).selector(name); }
  field(name: string): number { return this.#codec().field(this, name); }
  kind(node = 0): CBORKind { return this.#codec().document(this, capability).kind(node); }
  uint(node: number): bigint { return this.#codec().document(this, capability).uint(node); }
  boolean(node: number): boolean { return this.#codec().document(this, capability).boolean(node); }
  text(node: number): string { return this.#codec().document(this, capability).text(node); }
  size(node: number): number { return this.#codec().document(this, capability).size(node); }
  firstChild(node: number): number { return this.#codec().document(this, capability).firstChild(node); }
  nextSibling(node: number): number { return this.#codec().document(this, capability).nextSibling(node); }
  copyPayload(node: number, destination: Uint8Array): number { return this.#codec().document(this, capability).copyPayload(node, destination); }
  copyEncoded(destination: Uint8Array): number { return this.#codec().document(this, capability).copyEncoded(0, destination); }
  encodedSize(): number { return this.#codec().document(this, capability).encodedSize(); }
  copyKey(destination: Uint8Array): void { this.#codec().copyKey(this, destination); }
  digest(domain: string, destination: Uint8Array): void { this.#codec().digest(this, domain, destination); }
  release(): void { signed.get(this)?.release(this); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.SignedMap"; }
}

// A codec has one fixed schema, one actual work slot and no waiter queue. It
// retains its original charge until both synchronous work and the actual
// material lease exit. Close is an admission fence, never a GC-based refund.
export class SignedMapCodec {
  readonly #config: CapturedConfig;
  readonly #decoder: CBORDecoder;
  readonly #signatureID: number;
  #message: Uint8Array;
  #encoded: Uint8Array;
  #publicKey: Uint8Array;
  #signature: Uint8Array;
  #digest: Uint8Array;
  #reservation: ResourceReference | undefined;
  #document: CBORDocument | undefined;
  #current: SignedMap | undefined;
  #busy = false;
  #closed = false;
  constructor(config: SignedMapCodecConfig, decoderReservation: ResourceReference, workReservation: ResourceReference) {
    const c = capture(config), charge = signedMapCodecCharge(c);
    if (decoderReservation === workReservation || !decoderReservation.sameEnvironment(workReservation)) reject("signature_owner");
    this.#reservation = workReservation.take(charge);
    try {
      this.#config = c; this.#signatureID = wireMaps[c.schema]!.signature_field!;
      this.#message = new Uint8Array(c.decoder.bytes + c.labelBytes + 4);
      this.#encoded = new Uint8Array(c.decoder.bytes);
      this.#publicKey = new Uint8Array(32); this.#signature = new Uint8Array(64); this.#digest = new Uint8Array(32);
      this.#decoder = new CBORDecoder(c.decoder, decoderReservation);
    } catch (error) { this.#reservation.release(); this.#reservation = undefined; throw error; }
    Object.freeze(this);
  }
  verify(input: Uint8Array, publicKey: Uint8Array, context: DecodeContext = {}): SignedMap {
    if (this.#closed) reject("signature_closed");
    if (this.#busy || this.#current !== undefined) reject("signature_busy");
    this.#reservation!.check();
    this.#busy = true;
    let document: CBORDocument | undefined;
    try {
      if (byteLength(publicKey) !== 32) reject("signature_invalid");
      copy.call(this.#publicKey, publicKey);
      // Shape, relations, canonical text and embedded original bindings precede
      // expensive point work. This performs Pure Ed25519 with the exact domain.
      document = this.#decoder.decodeMap(input, this.#config.schema, context);
      const signatureNode = document.field(0, this.#signatureID);
      if (signatureNode < 0 || document.kind(signatureNode) !== "bytes" || document.size(signatureNode) !== 64) reject("signature_invalid");
      document.copyPayload(signatureNode, this.#signature);
      const length = this.#input(document, this.#config.domain, true);
      if (!verifyEd25519(this.#signature, this.#message.subarray(0, length), this.#publicKey)) reject("signature_invalid");
      if (this.#closed) reject("signature_closed");
      this.#reservation!.check();
      const result = new SignedMap(capability, this);
      this.#document = document; this.#current = result;
      return result;
    } finally {
      this.#message.fill(0); this.#signature.fill(0); this.#busy = false;
      if (this.#current === undefined) { document?.release(); this.#publicKey.fill(0); }
      this.#cleanup();
    }
  }
  // Issuer/control composition supplies a locally constructed canonical map
  // with one all-zero signature placeholder. The exact registered projection
  // is signed once. Neither validation nor a failed generation retries, changes
  // the message/key, or advances an authorization owner's transaction.
  sign(input: Uint8Array, key: SoftwareSigningKey, context: DecodeContext, current: () => boolean): SignedMap {
    if (this.#closed) reject("signature_closed");
    if (this.#busy || this.#current !== undefined) reject("signature_busy");
    this.#reservation!.check();
    this.#busy = true;
    let document: CBORDocument | undefined;
    try {
      const captured = captureDecodeContext(context);
      document = this.#decoder.decodeMap(input, this.#config.schema, captured);
      const node = document.field(0, this.#signatureID);
      if (node < 0 || document.kind(node) !== "bytes" || document.size(node) !== 64) reject("signature_projection");
      for (let i = 0; i < 64; i++) if (document.payloadByte(node, i) !== 0) reject("signature_projection");
      const length = this.#input(document, this.#config.domain, true);
      this.#guard(current);
      key.signOriginal(capability, this.#reservation!, this.#config.schema, this.#message.subarray(0, length), this.#signature, this.#publicKey);
      this.#guard(current);
      // Copy the fixed-size signature into a new local object. Never mutate a
      // received document, normalize signed input, or retain the signing input.
      const size = document.copyReplacingBytes(this.#signatureID, this.#signature, this.#encoded);
      document.release(); document = undefined;
      document = this.#decoder.decodeMap(this.#encoded.subarray(0, size), this.#config.schema, captured);
      this.#guard(current);
      const result = new SignedMap(capability, this);
      this.#document = document; this.#current = result;
      return result;
    } finally {
      this.#message.fill(0); this.#signature.fill(0); this.#encoded.fill(0); this.#busy = false;
      if (this.#current === undefined) { document?.release(); this.#publicKey.fill(0); }
      this.#cleanup();
    }
  }
  #guard(current: () => boolean): void {
    let permitted = false;
    try { permitted = current(); } catch { reject("signature_owner"); }
    if (!permitted) reject("signature_owner");
    if (this.#closed) reject("signature_closed");
    this.#reservation!.check();
  }
  #input(document: CBORDocument, domain: WireDomain, omitSignature: boolean): number {
    const labelBytes = domain.label_bytes.length / 2, offset = labelBytes + 4;
    if (offset > this.#message.length) reject("signature_capacity");
    const target = this.#message.subarray(offset), count = omitSignature ? document.copyWithoutField(this.#signatureID, target) : document.copyEncoded(0, target);
    for (let i = 0; i < labelBytes; i++) this.#message[i] = Number.parseInt(domain.label_bytes.slice(i * 2, i * 2 + 2), 16);
    this.#message[labelBytes] = count >>> 24; this.#message[labelBytes + 1] = count >>> 16; this.#message[labelBytes + 2] = count >>> 8; this.#message[labelBytes + 3] = count;
    return offset + count;
  }
  document(value: SignedMap, token: symbol): CBORDocument {
    if (token !== capability || this.#current !== value || this.#document === undefined) reject("signature_released");
    if (this.#closed) reject("signature_closed");
    this.#reservation!.check();
    return this.#document;
  }
  schema(value: SignedMap): string { this.document(value, capability); return this.#config.schema; }
  field(value: SignedMap, name: string): number {
    const document = this.document(value, capability), id = namedField(this.#config.schema, name);
    if (id === undefined) reject("signature_field");
    return document.field(0, id);
  }
  copyKey(value: SignedMap, destination: Uint8Array): void {
    if (byteLength(destination) !== 32) reject("signature_capacity");
    this.document(value, capability); copy.call(destination, this.#publicKey);
  }
  digest(value: SignedMap, name: string, destination: Uint8Array): void {
    if (byteLength(destination) !== 32) reject("signature_capacity");
    const document = this.document(value, capability);
    if (this.#busy) reject("signature_busy");
    const domain = wireDomains.find(d => d.name === name), part = domain?.input_schema.parts[0];
    if (domain === undefined || domain.operation !== "sha256" || domain.input_schema.parts.length !== 1 || part?.encoding !== "lp-map" ||
      part.schema_ref !== this.#config.schema || part.projection !== "full" && part.projection !== "without_signature") reject("digest_schema");
    this.#busy = true;
    const hash = sha256.create();
    try {
      const length = this.#input(document, domain, part.projection === "without_signature");
      hash.update(this.#message.subarray(0, length)); hash.digestInto(this.#digest);
      copy.call(destination, this.#digest);
    } finally { hash.destroy(); this.#message.fill(0); this.#digest.fill(0); this.#busy = false; }
  }
  release(value: SignedMap): void {
    if (this.#current !== value) return;
    signed.delete(value); this.#document?.release(); this.#document = undefined; this.#current = undefined;
    this.#message.fill(0); this.#encoded.fill(0); this.#signature.fill(0); this.#publicKey.fill(0); this.#digest.fill(0);
    this.#cleanup();
  }
  close(): void { this.#closed = true; this.#decoder.close(); this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#busy || this.#current !== undefined) return;
    this.#message = empty; this.#encoded = empty; this.#signature = empty; this.#publicKey = empty; this.#digest = empty;
    this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#closed && this.#reservation === undefined && this.#decoder.cleanupComplete(); }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.SignedMapCodec"; }
}

export interface SoftwareSigningKeyConfig {
  readonly schemas: readonly string[];
  readonly runtimeBytes: bigint;
}
function captureKeyConfig(config: SoftwareSigningKeyConfig): SoftwareSigningKeyConfig {
  const input = config.schemas, count = input.length, runtimeBytes = config.runtimeBytes;
  if (!Number.isSafeInteger(count) || count < 1 || count > wireDomains.length || typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) reject("signature_capacity");
  const schemas: string[] = [];
  for (let i = 0; i < count; i++) {
    const schema = input[i]!; domainFor(schema);
    if (schemas.includes(schema)) reject("signature_key_purpose");
    schemas.push(schema);
  }
  return Object.freeze({ schemas: Object.freeze(schemas), runtimeBytes });
}
export function softwareSigningKeyCharge(config: SoftwareSigningKeyConfig): ResourceVector {
  const c = captureKeyConfig(config);
  // Owned seed/public key, one generated public-key result and one signature.
  // The qualified allowance also covers the library's internal derivation,
  // hash/point workspace and purpose metadata. No hardware claim is made.
  return new ResourceVector([32n + 32n + 32n + 64n + c.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}

// The software adapter imports one private seed into SDK-owned storage. Its
// only signing use is the codec's validated, schema-bound message. It exposes
// public bytes but no seed/key export, generic sign API, Debug or JSON contents.
export class SoftwareSigningKey {
  readonly #config: SoftwareSigningKeyConfig;
  #seed: Uint8Array = empty;
  #public: Uint8Array = empty;
  #reservation: ResourceReference | undefined;
  #closed = false;
  #busy = false;
  constructor(config: SoftwareSigningKeyConfig, seed: Uint8Array, reservation: ResourceReference) {
    const c = captureKeyConfig(config);
    if (byteLength(seed) !== 32) reject("signature_capacity");
    this.#reservation = reservation.take(softwareSigningKeyCharge(c));
    this.#config = c;
    try {
      this.#seed = new Uint8Array(32); this.#public = new Uint8Array(32);
      copy.call(this.#seed, seed);
      const publicKey = ed25519.getPublicKey(this.#seed);
      try {
        const point = ed25519.Point.fromBytes(publicKey, false);
        if (point.is0() || !point.isTorsionFree()) reject("signature_generation_failed");
        copy.call(this.#public, publicKey);
      } finally { publicKey.fill(0); }
    } catch {
      this.#seed.fill(0); this.#public.fill(0); this.#seed = empty; this.#public = empty;
      this.#reservation.release(); this.#reservation = undefined;
      reject("signature_generation_failed");
    }
    Object.freeze(this);
  }
  copyPublicKey(destination: Uint8Array): void {
    if (byteLength(destination) !== 32) reject("signature_capacity");
    if (this.#closed) reject("signature_closed");
    this.#reservation!.check(); copy.call(destination, this.#public);
  }
  signOriginal(token: symbol, owner: ResourceReference, schema: string, message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): void {
    if (token !== capability) reject("signature_owner");
    if (this.#closed) reject("signature_closed");
    if (this.#busy) reject("signature_busy");
    if (!this.#config.schemas.includes(schema)) reject("signature_key_purpose");
    if (!this.#reservation!.sameEnvironment(owner)) reject("signature_owner");
    this.#busy = true;
    let generated: Uint8Array | undefined;
    try {
      generated = ed25519.sign(message, this.#seed);
      if (!verifyEd25519(generated, message, this.#public)) reject("signature_generation_failed");
      copy.call(signature, generated); copy.call(publicKey, this.#public);
    } catch { reject("signature_generation_failed"); }
    finally { generated?.fill(0); this.#busy = false; this.#cleanup(); }
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#busy) return;
    this.#seed.fill(0); this.#public.fill(0); this.#seed = empty; this.#public = empty;
    this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#closed && this.#reservation === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.SoftwareSigningKey"; }
}
for (const c of [SignedMap, SignedMapCodec, SoftwareSigningKey]) { Object.freeze(c.prototype); Object.freeze(c); }
