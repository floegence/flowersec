import { types } from "node:util";
import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { rekeyCreditReference } from "./transport-v4-rekey-credit.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const fields = (schema, type, map) => Object.fromEntries(Object.entries(schema.frame_maps[type].fields)
  .map(([id, field]) => [field.name, map.get(BigInt(id))]));

// Structural capacity composition. The original authority/consumer/acceptor
// must independently authenticate this exact Artifact and fixed TimeProfile.
// No signature/trust/time/once check or real service reservation occurs here.
// The full signed interval cannot be replaced with root/activation/local age.
export function deriveRekeyCapacityReference(schema, artifactInput, timeProfile) {
  requireThat(timeProfile !== null && typeof timeProfile === "object" && !types.isProxy(timeProfile) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(timeProfile)), "rekey_capacity_time_profile");
  const names = ["rate_numerator", "rate_denominator", "quantization_ms"], keys = Reflect.ownKeys(timeProfile);
  requireThat(keys.length === names.length && keys.every(key => names.includes(key)), "rekey_capacity_time_fields");
  const time = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(timeProfile, name);
    requireThat(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "rekey_capacity_time_data");
    time[name] = descriptor.value;
  }
  const view = referenceByteView(artifactInput);
  requireThat(view.length <= schema.frame_maps.Artifact.max_encoded_bytes, "rekey_capacity_artifact_size");
  const original = Buffer.alloc(view.length); original.set(view);
  const artifact = fields(schema, "Artifact", decodeMap(schema, "Artifact", original));
  const contract = fields(schema, "SessionContract", artifact.session_contract);
  const envelope = fields(schema, "RekeyEnvelope", contract.rekey_envelope);
  const service = rekeyCreditReference(schema, artifact.crypto_profile_id, "service", {
    ...time, burst_rounds: envelope.burst_rounds.toString(), refill_period_ms: envelope.refill_period_ms.toString(),
    request_start_budget_ms: envelope.request_start_budget_ms.toString(), issued_at_ms: artifact.issued_at_ms.toString(),
    session_not_after_ms: artifact.session_not_after_ms.toString(),
  });
  // The independent digest includes the original signature, with no alternate
  // unsigned projection or caller-supplied capacity/profile/epoch override.
  // Exact backing keeps the public digest from exposing pooled Artifact copies.
  const digest = Buffer.alloc(32);
  digest.write(evaluateDomain(schema, "artifact_digest", { artifact: original }).output_hex, "hex");
  return Object.freeze({ artifact_digest: digest, request_start_budget_ms: envelope.request_start_budget_ms.toString(), service });
}
