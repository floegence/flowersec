import { ed25519 } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { V4Checkpoint, V4CheckpointIssuanceOptions } from "../checkpoint.js";
import { captureExecutionTarget, unhex, type ExecutionTarget } from "./executionManagementCodec.js";
import { FixedCBORWriter } from "./cborWriter.js";
import { byteLength } from "./cbor.js";
import { wireDomains, table } from "./schemaRegistry.js";
import { RPCProtocolError } from "./rpcFragment.js";
export type CheckpointSigningKey = Readonly<{ protection: "hmac_sha256"; keyID: Uint8Array; macKey: Uint8Array }> |
  Readonly<{ protection: "ed25519"; keyID: Uint8Array; seed: Uint8Array }>;
export type CheckpointVerificationKey = Readonly<{ protection: "hmac_sha256"; keyID: Uint8Array; macKey: Uint8Array }> |
  Readonly<{ protection: "ed25519"; keyID: Uint8Array; publicKey: Uint8Array }>;
export function checkpointDomain(protection: CheckpointSigningKey["protection"]) {
  const domain = wireDomains.find(d => protection === "hmac_sha256" ? d.name === "resume_token_mac" && d.operation === "hmac-sha256" :
    d.operation === "ed25519" && d.input_schema.parts.length === 1 && d.input_schema.parts[0]!.schema_ref === "ResumeSignedToken" &&
    d.input_schema.parts[0]!.encoding === "lp-map" && d.input_schema.parts[0]!.projection === "without_signature");
  if (domain === undefined) throw new RPCProtocolError("configuration_capacity");
  return unhex(domain.label_bytes);
}
export interface CheckpointSessionPolicy { readonly maxIssuedTokenDurationMS: bigint; readonly maxTokenBytes: number; }
export function applicationResumeFeature(): bigint {
  const bit = table<Readonly<Record<string, { readonly bit: number }>>>("feature_registry")?.application_progress_resume?.bit;
  if (bit === undefined || bit < 0 || bit >= 64) throw new RPCProtocolError("configuration_capacity");
  return 1n << BigInt(bit);
}
export function captureCheckpoint(original: ExecutionTarget, checkpoint: V4Checkpoint, options: V4CheckpointIssuanceOptions) {
  const target = captureExecutionTarget(original), { format, position } = checkpoint;
  const { durationMS, applicationDurationLimitMS, historyNotAfterMS } = options;
  if (typeof format !== "string" || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(format) ||
      byteLength(position) > 4096 || position.buffer instanceof SharedArrayBuffer ||
      [durationMS, applicationDurationLimitMS, historyNotAfterMS].some(v => typeof v !== "bigint" || v < 1n || v >= 1n << 64n)) throw new RPCProtocolError("service_failed");
  return { target, checkpoint: { format, position: new Uint8Array(position) }, options: { durationMS, applicationDurationLimitMS, historyNotAfterMS } };
}
/** Fixed canonical registry projection. Its caller owns the single bounded
 * issuance workspace and independent application key, never a Session key. */
export function checkpointToken(target: ExecutionTarget, checkpoint: V4Checkpoint, generation: bigint, issued: bigint, expires: bigint,
  nonce: Uint8Array, key: CheckpointSigningKey): Uint8Array {
  const keyID = key.keyID;
  const claimsBuffer = new Uint8Array(4893), tokenBuffer = new Uint8Array(4980), macBuffer = new Uint8Array(5080);
  const claims = new FixedCBORWriter(claimsBuffer), token = new FixedCBORWriter(tokenBuffer), encoder = new TextEncoder();
  let tag: Uint8Array | undefined;
  try {
    claims.map(11);
    [target.tenant, target.subject, target.audience, target.namespace].forEach((value, id) => claims.uint(id).data(encoder.encode(value), true));
    claims.uint(4).data(unhex(target.operation)).uint(5).data(unhex(target.requestDigest)).uint(6).map(2)
      .uint(0).data(encoder.encode(checkpoint.format), true).uint(1).data(checkpoint.position)
      .uint(7).uint(generation).uint(8).uint(issued).uint(9).uint(expires).uint(10).data(nonce);
    token.map(2).uint(0).encoded(claims.result()).uint(1).data(keyID);
    const label = checkpointDomain(key.protection), projection = token.result();
    macBuffer.set(label); new DataView(macBuffer.buffer).setUint32(label.length, projection.length);
    macBuffer.set(projection, label.length + 4);
    const input = macBuffer.subarray(0, label.length + 4 + projection.length);
    tag = key.protection === "hmac_sha256" ? hmac(sha256, key.macKey, input) : ed25519.sign(input, key.seed);
    token.reset().map(3).uint(0).encoded(claims.result()).uint(1).data(keyID).uint(2).data(tag);
    return new Uint8Array(token.result());
  } finally { claimsBuffer.fill(0); tokenBuffer.fill(0); macBuffer.fill(0); tag?.fill(0); }
}
