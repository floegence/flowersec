// Registry-driven structural reference. A matching projection grants no trust,
// admission, ParentWinner, relay claim or dispatch authority.
import { decodeMap, encodeCBOR, mapFromNames, projectMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const field = (schema, name, key) => {
  const entry = Object.entries(schema.frame_maps[name]?.fields ?? {}).find(([, value]) => value.name === key);
  requireThat(entry !== undefined, "unknown_field");
  return {id:BigInt(entry[0]), ...entry[1]};
};
const get = (schema, name, map, key) => map.get(field(schema,name,key).id);
const same = (left, right) => Buffer.isBuffer(left) && Buffer.isBuffer(right) ? left.equals(right) : left === right;
const own = (bytes) => { const result = Buffer.alloc(bytes.length); bytes.copy(result); return result; };
const hash = (schema, name, args) => own(Buffer.from(evaluateDomain(schema,name,args).output_hex,"hex"));

// Issuer construction starts from the complete signed Artifact and a fixed
// index list. It never accepts a supplied set/digest to repair or normalize.
export function derivePoolSelection(schema, artifactBytes, indices) {
  const artifact = decodeMap(schema,"Artifact",artifactBytes);
  const array = field(schema,"PoolSelectionRef","candidate_indices");
  requireThat(Array.isArray(indices) && indices.length >= array.min_items && indices.length <= array.max_items,"array_length");
  const candidates = get(schema,"Artifact",artifact,"candidates");
  const entries = indices.map((index) => {
    requireThat(typeof index === "bigint" || (typeof index === "number" && Number.isSafeInteger(index)),"integer_type");
    const n = BigInt(index);
    requireThat(n >= 0n && n <= BigInt(array.items.max),"field_range");
    requireThat(n < BigInt(candidates.length),"pool_index_membership");
    const candidate = candidates[Number(n)];
    const route = projectMap(schema,"candidate_route",candidate);
    // Decoder byte fields are views of the complete Artifact. Do not retain
    // that secret-bearing backing through the returned public member values.
    const sourceID = get(schema,"Candidate",candidate,"candidate_id");
    const candidateID = own(sourceID);
    return {candidate_index:n, candidate_id:candidateID, route_digest:hash(schema,"route_digest",{route:encodeCBOR(route)})};
  });
  const artifactDigest = hash(schema,"artifact_digest",{artifact:artifactBytes});
  const values = {artifact_digest:artifactDigest,entries};
  const bytes = own(encodeCBOR(mapFromNames(schema,"PoolSelectionSet",values)));
  decodeMap(schema,"PoolSelectionSet",bytes); // Reject duplicates/order; never sort.
  return {
    bytes, values,
    candidate_set_digest:hash(schema,"candidate_set_digest",{selection:bytes}),
    route_set_digest:hash(schema,"route_set_digest",{selection:bytes}),
  };
}

// Received references must match recomputation; construction cannot silently
// replace a received Artifact digest, candidate set or original index order.
export function verifyPoolSelection(schema, artifactBytes, referenceBytes) {
  const reference = decodeMap(schema,"PoolSelectionRef",referenceBytes);
  const result = derivePoolSelection(schema,artifactBytes,get(schema,"PoolSelectionRef",reference,"candidate_indices"));
  requireThat(same(get(schema,"PoolSelectionRef",reference,"artifact_digest"),result.values.artifact_digest),"pool_artifact_digest");
  requireThat(same(get(schema,"PoolSelectionRef",reference,"candidate_set_digest"),result.candidate_set_digest),"pool_candidate_set_digest");
  return result;
}

export function verifyPoolSet(schema, artifactBytes, indices, setBytes) {
  decodeMap(schema,"PoolSelectionSet",setBytes);
  const result = derivePoolSelection(schema,artifactBytes,indices);
  requireThat(same(setBytes,result.bytes),"pool_set_membership");
  return result;
}

// The immutable source profile is an explicit caller context, never detected
// from the wire shape. Only Artifact/proof/winner projection is checked here;
// original issuer trust, certificate possession, budget/once owners and actual
// claim-time resources still require their independent admission gates.
export function verifyPoolAuthorization(schema, artifactBytes, fsbBytes, context = {}) {
  requireThat(context.activation_source_profile === "preauthorized_pool","pool_source_profile");
  const artifact = decodeMap(schema,"Artifact",artifactBytes);
  const profile = get(schema,"Artifact",artifact,"crypto_profile_id");
  requireThat(context.crypto_profile_id === undefined || context.crypto_profile_id === profile,"pool_crypto_profile");
  context = {...context,crypto_profile_id:profile};
  const fsb = decodeMap(schema,"FSB4",fsbBytes,context);
  const proof = decodeMap(schema,"ActivationAuthorization",get(schema,"FSB4",fsb,"activation_authorization"),context);
  const result = verifyPoolSelection(schema,artifactBytes,encodeCBOR(get(schema,"ActivationAuthorization",proof,"candidate_selection")));
  for (const key of ["tenant_id","issuer_key_id","lease_id","session_nonce"]) {
    requireThat(same(get(schema,"Artifact",artifact,key),get(schema,"FSB4",fsb,key)),"pool_artifact_binding");
  }
  requireThat(same(get(schema,"FSB4",fsb,"artifact_digest"),result.values.artifact_digest),"pool_artifact_digest");
  for (const key of ["client_identity_digest","server_identity_digest","audience"]) {
    requireThat(same(get(schema,"Artifact",artifact,key),get(schema,"ActivationAuthorization",proof,key)),"pool_artifact_binding");
  }
  requireThat(get(schema,"ActivationAuthorization",proof,"activation_not_after_ms") <= get(schema,"Artifact",artifact,"initiation_not_after_ms") &&
    get(schema,"ActivationAuthorization",proof,"session_not_after_ms") <= get(schema,"Artifact",artifact,"session_not_after_ms"),"pool_parent_deadline");
  requireThat(same(get(schema,"ActivationAuthorization",proof,"route_selection"),result.route_set_digest),"pool_route_set_digest");
  requireThat(result.values.entries.some((entry) => same(entry.candidate_id,get(schema,"FSB4",fsb,"candidate_id")) && same(entry.route_digest,get(schema,"FSB4",fsb,"route_digest"))),"pool_winner_membership");
  return result;
}
