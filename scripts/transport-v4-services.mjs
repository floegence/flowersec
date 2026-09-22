// Stateless reference for contract/Offer membership. Trusted registration,
// current authorization, time, execution and resource ownership remain runtime
// obligations. Successful verification does not admit an operation.
import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";

function field(schema, name, map, key) {
  const id = Object.entries(schema.frame_maps[name].fields).find(([,entry]) => entry.name === key)[0];
  return map.get(BigInt(id));
}

export function verifyServiceOffer(schema, contractBytes, offerBytes, maxWindowMs) {
  if (typeof maxWindowMs !== "bigint" || maxWindowMs <= 0n || maxWindowMs >= (1n << 64n)) throw new VectorError("offer_policy_range");
  const contract = decodeMap(schema,"ServiceContract",contractBytes);
  const shape = field(schema,"ServiceContract",contract,"call_shape");
  const definitions = Object.values(schema.frame_maps.ServiceContract.fields);
  const shapeName = Object.entries(definitions.find(entry => entry.name === "call_shape").enum).find(([,code]) => BigInt(code) === shape)[0];
  const selector = shapeName + "_semantics";
  const execution = definitions.find(entry => entry.name === selector).enum.execution;
  if (field(schema,"ServiceContract",contract,selector) !== BigInt(execution)) throw new VectorError("offer_not_applicable");
  const offer = decodeMap(schema,"AdmissionOffer",offerBytes);
  const digest = evaluateDomain(schema,"service_contract_digest",{contract:contractBytes}).output_hex;
  if (!field(schema,"AdmissionOffer",offer,"service_contract_digest").equals(Buffer.from(digest,"hex"))) throw new VectorError("offer_contract_mismatch");
  const start = field(schema,"AdmissionOffer",offer,"not_before_ms"), end = field(schema,"AdmissionOffer",offer,"not_after_ms");
  if (end - start > maxWindowMs) throw new VectorError("offer_window");
  return {not_before_ms:start,not_after_ms:end};
}
