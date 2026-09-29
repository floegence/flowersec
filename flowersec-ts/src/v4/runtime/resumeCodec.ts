import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import { FixedCBORWriter } from "./cborWriter.js";
import { equalCredential } from "./credentialSupport.js";
import { hex, unhex } from "./executionManagementCodec.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { checkpointDomain, type CheckpointVerificationKey } from "./checkpointToken.js";
import { verifyEd25519 } from "./ed25519.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { V4Checkpoint } from "../checkpoint.js";

export interface ResumeTargetFacts { readonly transportContextDigest: string; readonly streamID: bigint; }
export interface ResumeTokenFacts {
  readonly tenant: string; readonly subject: string; readonly audience: string; readonly namespace: string;
  readonly operation: string; readonly requestDigest: string; readonly checkpoint: V4Checkpoint;
  readonly generation: bigint; readonly issuedAtMS: bigint; readonly expiresAtMS: bigint;
  readonly nonce: string; readonly keyID: string; readonly protection: "ed25519" | "hmac_sha256";
}
export interface ResumeRequestFacts extends ResumeTargetFacts { readonly claims: ResumeTokenFacts; readonly token: Uint8Array; }
export interface ResumeOutcome { readonly status: "accepted" | "rejected" | "unknown"; readonly checkpoint?: V4Checkpoint; readonly generation?: bigint; }
const settings = (runtimeBytes: bigint) => ({ bytes: 9345, nodes: 128, textBytes: 1024, arrayItems: 8, runtimeBytes });
export const resumeCodecCharges = (runtimeBytes: bigint): readonly ResourceVector[] => [
  new ResourceVector([65536n + runtimeBytes, 0n, 0n, 32n, 1n, 3n, 0n, 0n, 0n, 0n, 0n]), cborDecoderCharge(settings(runtimeBytes)),
];
const invalid = (): never => { throw new RPCProtocolError("resume_binding"); };
function checkpoint(doc: CBORDocument, node: number): V4Checkpoint {
  const position = new Uint8Array(doc.size(doc.field(node, 1))); doc.copyPayload(doc.field(node, 1), position);
  return Object.freeze({ format: doc.text(doc.field(node, 0)), position });
}
function fixed(doc: CBORDocument, node: number, size: number): Uint8Array {
  const bytes = new Uint8Array(size); if (doc.copyPayload(node, bytes) !== size) invalid(); return bytes;
}
function writeCheckpoint(writer: FixedCBORWriter, value: V4Checkpoint): void {
  writer.map(2).uint(0).data(new TextEncoder().encode(value.format), true).uint(1).data(value.position);
}
/** One prepaid canonical parser/encoder for recovery messages. Parsing alone
 * grants no authorization, consumption, generation or target ownership. */
export class ResumeCodec {
  #reference: ResourceReference | undefined;
  #decoder: CBORDecoder | undefined;
  readonly #scratch = new Uint8Array(9345);
  constructor(runtimeBytes: bigint, references: readonly ResourceReference[]) {
    this.#reference = references[0]!.take(resumeCodecCharges(runtimeBytes)[0]!);
    try { this.#decoder = new CBORDecoder(settings(runtimeBytes), references[1]!); }
    catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#reference === undefined) invalid(); this.#reference!.checkRetained(); }
  #claims(doc: CBORDocument, token: number): ResumeTokenFacts {
    const node = doc.field(token, 0), issuedAtMS = doc.uint(doc.field(node, 8)), expiresAtMS = doc.uint(doc.field(node, 9));
    if (issuedAtMS >= expiresAtMS) invalid();
    return Object.freeze({ tenant: doc.text(doc.field(node, 0)), subject: doc.text(doc.field(node, 1)), audience: doc.text(doc.field(node, 2)), namespace: doc.text(doc.field(node, 3)),
      operation: hex(fixed(doc, doc.field(node, 4), 32)), requestDigest: hex(fixed(doc, doc.field(node, 5), 32)), checkpoint: checkpoint(doc, doc.field(node, 6)),
      protection: doc.size(doc.field(token, 2)) === 64 ? "ed25519" : "hmac_sha256", generation: doc.uint(doc.field(node, 7)), issuedAtMS, expiresAtMS, nonce: hex(fixed(doc, doc.field(node, 10), 32)), keyID: hex(fixed(doc, doc.field(token, 1), 16)) });
  }
  token(bytes: Uint8Array): ResumeTokenFacts {
    this.#check();
    // Protection is a local schema discriminator only; no claims are exposed
    // until the complete selected registry schema has passed validation.
    const probe = this.#decoder!.decode(bytes);
    let size: number;
    try { size = probe.size(probe.field(0, 2)); } finally { probe.release(); }
    if (size !== 32 && size !== 64) invalid();
    const doc = this.#decoder!.decodeMap(bytes, size === 64 ? "ResumeSignedToken" : "ResumeMACToken");
    try { return this.#claims(doc, 0); } finally { doc.release(); }
  }
  #verify(doc: CBORDocument, token: number, protection: "ed25519" | "hmac_sha256", keys: readonly CheckpointVerificationKey[]): void {
    const keyID = fixed(doc, doc.field(token, 1), 16);
    const key = keys.find(value => value.protection === protection && equalCredential(value.keyID, keyID));
    if (key === undefined) invalid();
    const label = checkpointDomain(protection), claims = new Uint8Array(4893), projection = new Uint8Array(4980), macInput = new Uint8Array(5080);
    let expected: Uint8Array | undefined;
    try {
      const size = doc.copyEncoded(doc.field(token, 0), claims), writer = new FixedCBORWriter(projection);
      writer.map(2).uint(0).encoded(claims.subarray(0, size)).uint(1).data(keyID);
      const unsigned = writer.result();
      macInput.set(label); new DataView(macInput.buffer).setUint32(label.length, unsigned.length); macInput.set(unsigned, label.length + 4);
      const input = macInput.subarray(0, label.length + 4 + unsigned.length);
      if (key!.protection === "hmac_sha256") {
        expected = hmac(sha256, key!.macKey, input);
        if (!equalCredential(expected, fixed(doc, doc.field(token, 2), 32))) invalid();
      } else if (!verifyEd25519(fixed(doc, doc.field(token, 2), 64), input, key!.publicKey)) invalid();
    } finally { keyID.fill(0); claims.fill(0); projection.fill(0); macInput.fill(0); expected?.fill(0); }
  }
  request(bytes: Uint8Array, keys: readonly CheckpointVerificationKey[], maximumTokenBytes: number): ResumeRequestFacts {
    this.#check(); const doc = this.#decoder!.decodeMap(bytes, "ResumeRequest");
    let claims: ResumeTokenFacts | undefined, expected: V4Checkpoint | undefined;
    try {
      const tokenNode = doc.field(0, 3);
      if (doc.size(tokenNode) > maximumTokenBytes) invalid();
      const protection = doc.uint(doc.field(0, 2)) === 0n ? "ed25519" : "hmac_sha256";
      const embedded = doc.embedded(tokenNode); this.#verify(doc, embedded, protection, keys); claims = this.#claims(doc, embedded);
      expected = checkpoint(doc, doc.field(0, 5));
      if (hex(fixed(doc, doc.field(0, 0), 32)) !== claims.operation || hex(fixed(doc, doc.field(0, 1), 32)) !== claims.requestDigest ||
          doc.uint(doc.field(0, 4)) !== claims.generation || expected.format !== claims.checkpoint.format || !equalCredential(expected.position, claims.checkpoint.position)) invalid();
      const token = new Uint8Array(doc.size(tokenNode)); doc.copyPayload(tokenNode, token);
      const result = Object.freeze({ claims, token, transportContextDigest: hex(fixed(doc, doc.field(0, 6), 32)), streamID: doc.uint(doc.field(0, 7)) });
      claims = undefined; return result;
    } finally { doc.release(); claims?.checkpoint.position.fill(0); expected?.position.fill(0); }
  }
  encodeRequest(token: Uint8Array, target: ResumeTargetFacts, destination: Uint8Array): number {
    this.#check();
    if (!/^[0-9a-f]{64}$/u.test(target.transportContextDigest) || /^0+$/u.test(target.transportContextDigest) || target.streamID < 1n || target.streamID >= 1n << 63n) invalid();
    const claims = this.token(token);
    try {
      const writer = new FixedCBORWriter(this.#scratch).map(8).uint(0).data(unhex(claims.operation)).uint(1).data(unhex(claims.requestDigest))
        .uint(2).uint(claims.protection === "ed25519" ? 0 : 1).uint(3).data(token).uint(4).uint(claims.generation).uint(5);
      writeCheckpoint(writer, claims.checkpoint); writer.uint(6).data(unhex(target.transportContextDigest)).uint(7).uint(target.streamID);
      const encoded = writer.result(); if (destination.length < encoded.length) invalid(); destination.set(encoded); return encoded.length;
    } finally { claims.checkpoint.position.fill(0); this.#scratch.fill(0); }
  }
  encodeResult(value: ResumeOutcome): Uint8Array {
    this.#check(); const progress = value.checkpoint !== undefined && value.generation !== undefined;
    if (value.status === "accepted" && !progress || (value.checkpoint === undefined) !== (value.generation === undefined)) invalid();
    try {
      const writer = new FixedCBORWriter(this.#scratch).map(progress ? 2 : 1).uint(0).uint(value.status === "accepted" ? 0 : value.status === "rejected" ? 1 : 2);
      if (progress) { writer.uint(1).map(2).uint(0); writeCheckpoint(writer, value.checkpoint!); writer.uint(1).uint(value.generation!); }
      return new Uint8Array(writer.result());
    } finally { this.#scratch.fill(0); }
  }
  result(bytes: Uint8Array): ResumeOutcome {
    this.#check(); const doc = this.#decoder!.decodeMap(bytes, "ResumeResult");
    try {
      const status = ["accepted", "rejected", "unknown"] as const, index = Number(doc.uint(doc.field(0, 0))), progress = doc.field(0, 1);
      if (status[index] === undefined || index === 0 && progress < 0) invalid();
      return Object.freeze({ status: status[index]!, ...(progress < 0 ? {} : { checkpoint: checkpoint(doc, doc.field(progress, 0)), generation: doc.uint(doc.field(progress, 1)) }) });
    } finally { doc.release(); }
  }
  close(): void { this.#decoder?.close(); this.#decoder = undefined; this.#scratch.fill(0); this.#reference?.release(); this.#reference = undefined; }
}
Object.freeze(ResumeCodec.prototype); Object.freeze(ResumeCodec);
