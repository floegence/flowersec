import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";

// Stateless original-byte relations only. Independent TrustConfig/signatures,
// fixed parent-to-authority continuity, current revocation and cohort policy,
// trusted time, original TxA/TxB or issuance ownership and actual admission are
// separate gates. No input or result is a permit, renewal or retirement proof.
const requireThat = (ok, code) => { if (!ok) throw new VectorError(code); };
const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) ? a.equals(b) : a === b;
const fields = (schema,type,map) => Object.fromEntries(Object.entries(schema.frame_maps[type].fields).map(([id,f]) => [f.name,map.get(BigInt(id))]));
function read(schema, type, input, context = {}) {
  const view = referenceByteView(input), cap = schema.frame_maps[type].max_encoded_bytes;
  requireThat(Number.isSafeInteger(cap) && cap > 0, "activation_delegation_cap");
  requireThat(view.length <= cap, "activation_delegation_input_size");
  const bytes = Buffer.alloc(view.length); bytes.set(view);
  const map = decodeMap(schema, type, bytes, context);
  const values = fields(schema,type,map);
  return { bytes, values };
}
const digest = (schema, name, args) => evaluateDomain(schema, name, args).output_hex;

export function verifyActivationDelegationContinuityReference(schema, originalInput, refreshedInput) {
  const original = read(schema,"ConnectionActivationDelegation",originalInput);
  const refreshed = read(schema,"ConnectionActivationDelegation",refreshedInput);
  for (const name of ["tenant_id","revocation_authority_id","authority_generation","signing_key_id"]) {
    requireThat(same(original.values[name],refreshed.values[name]),"activation_delegation_identity");
  }
  requireThat(original.bytes.equals(refreshed.bytes),"activation_delegation_changed");
  return digest(schema,"connection_activation_delegation_digest",{delegation:original.bytes});
}

export function verifyActivationDelegationReference(schema, delegationInput, authorityInput, capacityInput, artifactInput, proofInput, sourceProfile) {
  requireThat(typeof sourceProfile === "string" && schema.external_contexts.activation_source_profile.includes(sourceProfile), "activation_delegation_source");
  const delegation = read(schema, "ConnectionActivationDelegation", delegationInput), d = delegation.values;
  const authority = read(schema, "OnceAuthorityRef", authorityInput).values;
  const capacity = read(schema, "NamespaceCapacity", capacityInput);
  const artifact = read(schema, "Artifact", artifactInput), a = artifact.values;
  const proof = read(schema, "ActivationAuthorization", proofInput, { activation_source_profile:sourceProfile }).values;
  for (const value of [d, authority, capacity.values, proof]) requireThat(value.tenant_id === a.tenant_id, "activation_delegation_tenant");
  requireThat(d.revocation_authority_id === a.revocation_authority_id && capacity.values.revocation_authority_id === a.revocation_authority_id &&
    d.authority_generation === a.revocation_authority_generation && same(d.namespace_capacity_digest, a.namespace_capacity_digest) &&
    d.namespace_capacity_digest.toString("hex") === digest(schema, "namespace_capacity_digest", {capacity:capacity.bytes}), "activation_delegation_namespace");
  requireThat(same(d.artifact_issuer_key_id,a.issuer_key_id) && same(authority.artifact_issuer_key_id,a.issuer_key_id) &&
    same(proof.artifact_issuer_key_id,a.issuer_key_id) && d.authority_id === authority.spend_authority_id &&
    proof.authority_id === authority.spend_authority_id && proof.signing_key_id === d.signing_key_id, "activation_delegation_authority");
  if (sourceProfile === "preauthorized_pool") {
    const selection = fields(schema,"PoolSelectionRef",proof.candidate_selection);
    const original = fields(schema,"OnceAuthorityRef",selection.once_authority_ref);
    for (const name of Object.keys(authority)) requireThat(same(original[name],authority[name]),"activation_delegation_authority");
  }
  for (const name of ["lease_id", "client_identity_digest", "server_identity_digest", "audience"]) requireThat(same(proof[name],a[name]), "activation_delegation_parent");
  requireThat(proof.artifact_digest.toString("hex") === digest(schema,"artifact_digest",{artifact:artifact.bytes}), "activation_delegation_parent");
  requireThat(a.revocation_epoch >= d.first_parent_cohort && a.revocation_epoch <= d.last_parent_cohort, "activation_delegation_cohort");
  // Actual proof issuance may be later than the parent's original cohort;
  // it never changes that cohort or restarts its original influence bound.
  requireThat(proof.issued_at_ms >= a.issued_at_ms && proof.issued_at_ms >= d.signing_not_before_ms && proof.issued_at_ms < d.signing_not_after_ms, "activation_delegation_signing_time");
  // This authorization has connection purpose only. An unrelated certificate
  // H_c overflow cannot invalidate its otherwise representable connection bound.
  // All terms are nonnegative uint64s, so the final checked bound also proves
  // representability of each intermediate cohort addition and multiplication.
  const cohortEnd = capacity.values.cohort_time_origin_ms + (a.revocation_epoch + 1n) * capacity.values.cohort_duration_ms;
  const impact = cohortEnd + capacity.values.max_connection_impact_ms;
  requireThat(impact <= 0xffffffffffffffffn,"activation_delegation_impact_overflow");
  requireThat(a.issued_at_ms >= cohortEnd - capacity.values.cohort_duration_ms && a.issued_at_ms < cohortEnd,"activation_delegation_parent_cohort");
  requireThat(proof.activation_not_after_ms <= a.initiation_not_after_ms && proof.activation_not_after_ms <= d.max_activation_not_after_ms &&
    proof.session_not_after_ms <= a.session_not_after_ms && proof.session_not_after_ms <= d.max_session_not_after_ms &&
    a.session_not_after_ms <= impact, "activation_delegation_impact");
  // Only immutable scalar copies leave this function. Original key and all
  // restrictions participate in the independent full-entry digest.
  return Object.freeze({ delegation_digest:digest(schema,"connection_activation_delegation_digest",{delegation:delegation.bytes}),
    signing_key_id:d.signing_key_id, issuer_key_id:d.issuer_key_id.toString("hex"), authority_id:d.authority_id,
    max_affected_cohorts:Object.freeze([...d.max_affected_cohorts]),
    signing_not_before_ms:d.signing_not_before_ms, signing_not_after_ms:d.signing_not_after_ms });
}
