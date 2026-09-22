// Structural reference only. Token-key trust, current caller/service permission,
// exact local incarnation and exclusive Stream ownership, Offer/time admission,
// durable token consumption and generation CAS are external application gates.
import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";
import { decodeApplicationHeader, verifyExecutionRequest, verifyApplicationResponse } from "./transport-v4-application-headers.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const fields = (schema, type, map) => Object.fromEntries(Object.entries(schema.frame_maps[type].fields).map(([id, field]) => [field.name, map.get(BigInt(id))]));
function capture(input, cap) {
  const view = referenceByteView(input);
  requireThat(view.length <= cap, "resume_input_size");
  return Buffer.from(view);
}
function read(schema, type, input) {
  const bytes = capture(input, schema.frame_maps[type].max_encoded_bytes);
  return { bytes, values: fields(schema, type, decodeMap(schema, type, bytes)) };
}
function tokenFromRequest(schema, request) {
  const type = request.protection === 0n ? "ResumeSignedToken" : "ResumeMACToken";
  const token = read(schema, type, request.token);
  return { ...token, claims: fields(schema, "ResumeTokenClaims", token.values.claims) };
}

export function verifyResumeRequestReference(schema, headerInput, contractInput, payloadInput, targetContextInput, targetStreamId) {
  const headerBytes = capture(headerInput, schema.frame_maps.ApplicationHeader.max_encoded_bytes);
  const header = decodeApplicationHeader(schema, headerBytes);
  requireThat(header.kind === "resume_request", "resume_request_kind");
  const contract = capture(contractInput, schema.frame_maps.ServiceContract.max_encoded_bytes);
  const request = read(schema, "ResumeRequest", payloadInput);
  verifyExecutionRequest(schema, headerBytes, contract, request.bytes);
  // Context bytes and local stream ID must come from the captured target owner,
  // never from the peer's payload. Equality alone proves no Session authority.
  const context = capture(targetContextInput, 32);
  requireThat(context.length === 32 && typeof targetStreamId === "bigint" && targetStreamId >= 1n &&
    targetStreamId <= BigInt(schema.resource_caps.scope_id.max), "resume_target_type");
  requireThat(request.values.transport_context_digest.equals(context) && request.values.stream_id === targetStreamId, "resume_target_binding");
  const token = tokenFromRequest(schema, request.values);
  requireThat(!header.map.get(1n).equals(request.values.original_operation_id), "resume_operation_reuse");
  // Scalar copies preserve the original byte association without exposing Maps
  // or retaining the caller's mutable storage. They are not reusable permits.
  return Object.freeze({ operation_id: header.map.get(1n).toString("hex"), request_digest: header.map.get(4n).toString("hex"),
    original_operation_id: request.values.original_operation_id.toString("hex"), generation: token.claims.generation,
    transport_context_digest: context.toString("hex"), stream_id: targetStreamId });
}

// Current policy limits this input's complete token bytes, not its already
// issued lifetime. Issuance must separately reserve application history and
// check the signed/application duration intersection at the original time lower.
export function verifyResumeTokenUseReference(schema, requestInput, currentPolicyInput, lowerMs, upperMs) {
  const request = read(schema, "ResumeRequest", requestInput), policy = read(schema, "ResumePolicy", currentPolicyInput).values;
  requireThat(policy.enabled, "resume_disabled");
  requireThat(typeof lowerMs === "bigint" && typeof upperMs === "bigint" && lowerMs >= 0n &&
    lowerMs <= upperMs && upperMs <= 0xffffffffffffffffn, "resume_time_interval");
  const { claims } = tokenFromRequest(schema, request.values);
  requireThat(BigInt(request.values.token.length) <= policy.max_token_bytes, "resume_token_policy_size");
  requireThat(lowerMs >= claims.issued_at_ms && upperMs < claims.expires_at_ms, "resume_token_time");
  return Object.freeze({ issued_at_ms: claims.issued_at_ms, expires_at_ms: claims.expires_at_ms, generation: claims.generation });
}

export function verifyResumeResponseReference(schema, requestHeaderInput, contractInput, requestPayloadInput, responseHeaderInput, responsePayloadInput) {
  const requestHeader = capture(requestHeaderInput, schema.frame_maps.ApplicationHeader.max_encoded_bytes);
  requireThat(decodeApplicationHeader(schema, requestHeader).kind === "resume_request", "resume_request_kind");
  const request = read(schema, "ResumeRequest", requestPayloadInput);
  const contract = capture(contractInput, schema.frame_maps.ServiceContract.max_encoded_bytes);
  verifyExecutionRequest(schema, requestHeader, contract, request.bytes);
  const header = verifyApplicationResponse(schema, requestHeader, responseHeaderInput);
  requireThat(header.kind === "resume_response", "resume_response_kind");
  requireThat(BigInt(request.bytes.length) === decodeApplicationHeader(schema, requestHeader).map.get(3n), "application_payload_length");
  const result = read(schema, "ResumeResult", responsePayloadInput);
  requireThat(BigInt(result.bytes.length) === header.map.get(3n), "application_payload_length");
  const progress = result.values.progress === undefined ? null : fields(schema, "ResumeProgress", result.values.progress);
  if (result.values.status === 0n) requireThat(progress.new_generation > request.values.generation, "resume_generation_not_advanced");
  const statuses = Object.values(schema.frame_maps.ResumeResult.fields).find(field => field.name === "status").enum;
  return Object.freeze({ status: Object.keys(statuses).find(name => BigInt(statuses[name]) === result.values.status),
    new_generation: progress?.new_generation ?? null });
}
