import { decodeMap, encodeMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";

// Stateless reference relations only. Independent TrustConfig authentication,
// fixed namespace/publication mappings, signature verification, trusted time,
// State completeness and atomic continuity remain mandatory external gates.
// These functions never authorize admission, publish a Head or mutate an owner.
const MAX = 0xffffffffffffffffn;
const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const uint = value => {
  requireThat(typeof value === "bigint" && value >= 0n && value <= MAX, "revocation_uint64");
  return value;
};
const add = (a, b) => {
  requireThat(a <= MAX - b, "revocation_overflow");
  return a + b;
};
const multiply = (a, b) => {
  requireThat(b === 0n || a <= MAX / b, "revocation_overflow");
  return a * b;
};
const same = (a, b) => Buffer.isBuffer(a) ? Buffer.isBuffer(b) && a.equals(b) : a === b;

function object(schema, name, input, limits = {}) {
  let view;
  try { view = referenceByteView(input); } catch { throw new VectorError("revocation_input_bytes"); }
  const definition = schema.frame_maps[name];
  const maximum = definition.max_encoded_bytes ?? limits[definition.max_encoded_bytes_ref];
  requireThat(Number.isSafeInteger(maximum) && maximum > 0, "limit_unresolved");
  requireThat(view.length <= maximum, "revocation_input_size");
  const bytes = Buffer.from(view);
  const map = decodeMap(schema, name, bytes, limits);
  const fields = Object.fromEntries(Object.entries(definition.fields).map(([id, field]) => [field.name, map.get(BigInt(id))]));
  return {bytes, fields};
}
const digest = (schema, name, input, bytes, limits) => Buffer.from(evaluateDomain(schema, name, {[input]:bytes}, limits).output_hex, "hex");
const matches = (left, right, names, code) => {
  for (const name of names) requireThat(same(left[name], right[name]), code);
};
const namespaceFields = ["tenant_id", "revocation_authority_id"];
const headFields = [...namespaceFields, "schema_revision", "namespace_capacity_digest", "authority_generation", "publication_policy_id", "publication_policy_revision"];

// The descriptor must already be independently authenticated and pinned to the
// original namespace. This projection checks representability, not actual
// physical allocation, full subscription admission or available work budget.
export function namespaceParserLimitsReference(schema, capacityBytes) {
  const capacity = object(schema,"NamespaceCapacity",capacityBytes).fields;
  requireThat(capacity.max_state_encoded_bytes <= 0xffffffffn, "revocation_parser_capacity");
  const limits = {};
  for (const [name,parameter] of Object.entries(schema.validation_parameters)) {
    if (parameter.capacity_field === undefined) continue;
    let bound = capacity[parameter.capacity_field] / BigInt(parameter.divisor);
    if (parameter.byte_capacity_field !== undefined) {
      const byteBound = capacity[parameter.byte_capacity_field] / BigInt(parameter.minimum_item_bytes);
      if (byteBound < bound) bound = byteBound;
    }
    const maximum = parameter.unit === "bytes" ? BigInt(Number.MAX_SAFE_INTEGER) : 0xffffffffn;
    requireThat(bound >= (parameter.unit === "bytes" ? 1n : 0n) && bound <= maximum, "revocation_parser_capacity");
    limits[name] = Number(bound);
  }
  return Object.freeze(limits);
}

function fieldsOf(schema, name, map) {
  return Object.fromEntries(Object.entries(schema.frame_maps[name].fields).map(([id,field]) => [field.name,map.get(BigInt(id))]));
}
const classes = ["certificate", "connection"];
const start = (capacity, cohort) => add(capacity.cohort_time_origin_ms,multiply(cohort,capacity.cohort_duration_ms));

function stateReference(schema, capacityBytes, stateBytes) {
  const limits = namespaceParserLimitsReference(schema,capacityBytes);
  const capacity = object(schema,"NamespaceCapacity",capacityBytes);
  const state = object(schema,"RevocationState",stateBytes,limits);
  matches(capacity.fields,state.fields,namespaceFields,"revocation_namespace");
  requireThat(state.fields.namespace_capacity_digest.equals(digest(schema,"namespace_capacity_digest","capacity",capacity.bytes)),"revocation_capacity_digest");
  const segments = state.fields.cohort_policy_segments.map(map => ({map,fields:fieldsOf(schema,"CohortPolicySegment",map)}));
  for (const {fields:segment} of segments) {
    const end = start(capacity.fields,add(segment.last_cohort,1n));
    for (const kind of classes) {
      const impact = segment[kind+"_impact_ms"];
      if (impact === undefined) continue;
      requireThat(impact <= capacity.fields["max_"+kind+"_impact_ms"],"revocation_segment_impact");
      add(end,impact);
      add(end,capacity.fields["max_"+kind+"_impact_ms"]);
    }
  }
  // Canonical whole-map byte order is not numeric cohort order. Sort bounded
  // references per class to reject overlap in O(n log n), not pairwise O(n^2).
  for (const kind of classes) {
    const selected = segments.filter(segment => segment.fields[kind+"_impact_ms"] !== undefined)
      .sort((a,b) => a.fields.first_cohort < b.fields.first_cohort ? -1 : a.fields.first_cohort > b.fields.first_cohort ? 1 : 0);
    for (let i=1;i<selected.length;i++) requireThat(selected[i-1].fields.last_cohort < selected[i].fields.first_cohort,"revocation_segment_overlap");
  }
  return {capacity,state,segments,limits};
}

export function checkStateReferenceBindings(schema, capacityBytes, headBytes, stateBytes) {
  const {capacity,state,limits} = stateReference(schema,capacityBytes,stateBytes);
  const head = object(schema,"FreshnessHead",headBytes);
  capacityBinding(schema,capacity,head);
  matches(state.fields,head.fields,headFields,"revocation_state_binding");
  requireThat(state.fields.credential_revocation_floors.every((floor,index) => floor === head.fields.credential_revocation_floors[index]),"revocation_state_floors");
  requireThat(head.fields.state_encoded_bytes === BigInt(state.bytes.length),"revocation_state_length");
  requireThat(head.fields.state_digest.equals(digest(schema,"revocation_state_digest","state",state.bytes,limits)),"revocation_state_digest");
  // Head signature/trust/time, complete authenticated history and atomic
  // installation are separate obligations; this relation installs no State.
}

function selectCohort(reference, kind, cohort) {
  uint(cohort);
  const index = classes.indexOf(kind);
  requireThat(index >= 0,"revocation_class_context");
  requireThat(cohort >= reference.state.fields.credential_revocation_floors[index],"revocation_floor_rejected");
  const segment = reference.segments.find(({fields}) => fields[kind+"_impact_ms"] !== undefined && fields.first_cohort <= cohort && cohort <= fields.last_cohort)?.fields;
  requireThat(segment !== undefined,"revocation_segment_missing");
  const capacity = reference.capacity.fields, end = start(capacity,add(cohort,1n));
  return Object.freeze({
    issuance_not_before_ms:start(capacity,segment.first_cohort),
    issuance_not_after_ms:start(capacity,add(segment.last_cohort,1n)),
    cohort_not_before_ms:start(capacity,cohort),cohort_not_after_ms:end,
    impact_not_after_ms:add(end,segment[kind+"_impact_ms"]),
    immutable_gc_not_before_ms:add(end,capacity["max_"+kind+"_impact_ms"])
  });
}

// Class/cohort and signing windows below are private reference context from
// independently authenticated originals, never caller-selected wire fields.
export function cohortPolicyReference(schema, capacityBytes, stateBytes, kind, cohort) {
  return selectCohort(stateReference(schema,capacityBytes,stateBytes),kind,cohort);
}

function signingWindow(issuedAt, notBefore, notAfter) {
  uint(issuedAt); uint(notBefore); uint(notAfter);
  requireThat(notBefore < notAfter && issuedAt >= notBefore && issuedAt < notAfter,"revocation_issuer_window");
}

export function checkCohortIssuanceReference(schema, capacityBytes, stateBytes, kind, cohort, issuedAt, issuerNotBefore, issuerNotAfter, latestImpact) {
  const selected = cohortPolicyReference(schema,capacityBytes,stateBytes,kind,cohort);
  signingWindow(issuedAt,issuerNotBefore,issuerNotAfter); uint(latestImpact);
  requireThat(issuedAt >= selected.cohort_not_before_ms && issuedAt < selected.cohort_not_after_ms,"revocation_cohort_issuance");
  requireThat(latestImpact > issuedAt && latestImpact <= selected.impact_not_after_ms,"revocation_credential_impact");
  return selected;
}

export function checkActivationCohortReference(schema, capacityBytes, stateBytes, parentCohort, parentSessionNotAfter, activationIssuedAt, signerNotBefore, signerNotAfter, activationImpact) {
  const selected = cohortPolicyReference(schema,capacityBytes,stateBytes,"connection",parentCohort);
  signingWindow(activationIssuedAt,signerNotBefore,signerNotAfter);
  uint(parentSessionNotAfter); uint(activationImpact);
  requireThat(parentSessionNotAfter <= selected.impact_not_after_ms && activationIssuedAt < activationImpact && activationImpact <= parentSessionNotAfter,"revocation_activation_impact");
  return selected;
}

export function checkGrantCohortReference(schema, grantCapacityBytes, grantStateBytes, grantCohort, issuedAt, signerNotBefore, signerNotAfter, notAfter, parentCapacityBytes, parentStateBytes, parentCohort, parentSessionNotAfter) {
  const own = checkCohortIssuanceReference(schema,grantCapacityBytes,grantStateBytes,"connection",grantCohort,issuedAt,signerNotBefore,signerNotAfter,notAfter);
  const parent = cohortPolicyReference(schema,parentCapacityBytes,parentStateBytes,"connection",parentCohort);
  uint(parentSessionNotAfter);
  requireThat(parentSessionNotAfter <= parent.impact_not_after_ms && notAfter <= parentSessionNotAfter,"revocation_grant_parent_impact");
  return Object.freeze({grant:own,parent});
}

export function checkRetainedCohortsReference(schema, capacityBytes, previousBytes, nextBytes, exitedSegments) {
  const previous = stateReference(schema,capacityBytes,previousBytes), next = stateReference(schema,capacityBytes,nextBytes);
  matches(previous.state.fields,next.state.fields,headFields,"revocation_state_binding");
  next.state.fields.credential_revocation_floors.forEach((floor,index) => requireThat(floor >= previous.state.fields.credential_revocation_floors[index],"revocation_floor_rollback"));
  requireThat(exitedSegments instanceof Set,"revocation_reference_context");
  const retained = new Set(next.segments.map(segment => encodeMap(schema,"CohortPolicySegment",segment.map).toString("hex")));
  for (const segment of previous.segments) {
    const original = encodeMap(schema,"CohortPolicySegment",segment.map).toString("hex");
    if (retained.has(original)) continue;
    for (const [index,kind] of classes.entries()) if (segment.fields[kind+"_impact_ms"] !== undefined) {
      requireThat(next.state.fields.credential_revocation_floors[index] > segment.fields.last_cohort,"revocation_segment_retained");
    }
    requireThat(exitedSegments.has(original),"revocation_segment_references");
  }
  // The external owner must prove reference exit and the Head's mature,
  // permanent floor commit. Supplied evidence never performs GC or retirement.
}

export function issuerImpactFrontiersReference(schema, capacityBytes, entryBytes) {
  const limits = namespaceParserLimitsReference(schema,capacityBytes);
  const entry = object(schema,"RevokedIssuerEntry",entryBytes,limits).fields;
  const impactDefinition = schema.frame_maps.IssuerAuthorizationImpact;
  const key = BigInt(Object.entries(impactDefinition.fields).find(([,field]) => field.name === "max_affected_cohorts")[0]);
  const combined = [null,null];
  for (const authorization of entry.authorizations) {
    authorization.get(key).forEach((cohort,index) => {
      if (cohort !== null && (combined[index] === null || cohort > combined[index])) combined[index] = cohort;
    });
  }
  // All supplied originals participate. This does not prove the list contains
  // every original permission or authenticate which classes were authorized.
  return Object.freeze(combined);
}

function bound(capacity, cohort, impactField) {
  uint(cohort);
  const end = add(capacity.cohort_time_origin_ms, multiply(add(cohort, 1n), capacity.cohort_duration_ms));
  return add(end, capacity[impactField]);
}

export function cohortImpactBounds(schema, capacityBytes, cohort) {
  const capacity = object(schema, "NamespaceCapacity", capacityBytes).fields;
  return {
    certificate:bound(capacity, cohort, "max_certificate_impact_ms"),
    connection:bound(capacity, cohort, "max_connection_impact_ms")
  };
}

// These are relations between supplied original objects, not authenticated
// State membership or permission to remove a record. Namespace/generation,
// capacity/H_c, permanent floors, trust retirement and live references still
// belong to the complete State/trust/continuity owner.
export function matchRevokedCertificateEvidenceReference(schema, entryBytes, certificateBytes) {
  const entry = object(schema,"RevokedCertificateEntry",entryBytes).fields;
  const certificate = object(schema,"IdentityCertificate",certificateBytes);
  requireThat(entry.certificate_digest.equals(digest(schema,"certificate_digest","certificate",certificate.bytes)), "revocation_evidence_digest");
  requireThat(entry.cohort === certificate.fields.revocation_epoch && entry.expires_at_ms === certificate.fields.expires_at_ms, "revocation_certificate_evidence");
}

export function matchRevokedLeaseEvidenceReference(schema, entryBytes, artifactBytes) {
  const entry = object(schema,"RevokedLeaseEntry",entryBytes).fields;
  const artifact = object(schema,"Artifact",artifactBytes);
  requireThat(entry.artifact_digest.equals(digest(schema,"artifact_digest","artifact",artifact.bytes)), "revocation_evidence_digest");
  matches(entry,artifact.fields,["issuer_key_id","lease_id"], "revocation_lease_evidence");
  requireThat(entry.cohort === artifact.fields.revocation_epoch && entry.latest_impact_not_after_ms >= artifact.fields.session_not_after_ms, "revocation_lease_evidence");
}

export function checkIssuerImpactPurposesReference(schema, impactBytes, certificateAuthorized, connectionAuthorized) {
  const impact = object(schema,"IssuerAuthorizationImpact",impactBytes).fields;
  // Both arguments must come from the independently authenticated original
  // authorization identified by authorization_digest. Missing history is not false.
  requireThat(typeof certificateAuthorized === "boolean" && typeof connectionAuthorized === "boolean", "revocation_purpose_context");
  [certificateAuthorized,connectionAuthorized].forEach((authorized,index) => {
    requireThat((impact.max_affected_cohorts[index] !== null) === authorized, "revocation_impact_purpose");
  });
}

export function joinIssuerImpactFrontiersReference(schema, leftBytes, rightBytes) {
  const left = object(schema,"IssuerAuthorizationImpact",leftBytes).fields.max_affected_cohorts;
  const right = object(schema,"IssuerAuthorizationImpact",rightBytes).fields.max_affected_cohorts;
  // Componentwise union of two originals for the same authenticated issuer.
  // This relation does not aggregate/prove a complete multi-delegation history
  // and neither checks nor installs a GC frontier.
  return Object.freeze(left.map((value,index) => value === null ? right[index] : right[index] === null || value >= right[index] ? value : right[index]));
}

function capacityBinding(schema, capacity, head) {
  matches(capacity.fields, head.fields, namespaceFields, "revocation_namespace");
  requireThat(head.fields.namespace_capacity_digest.equals(digest(schema, "namespace_capacity_digest", "capacity", capacity.bytes)), "revocation_capacity_digest");
  requireThat(BigInt(head.bytes.length) <= capacity.fields.max_head_encoded_bytes, "revocation_head_capacity");
  requireThat(head.fields.state_encoded_bytes <= capacity.fields.max_state_encoded_bytes, "revocation_state_capacity");
}

function headBindings(schema, capacity, delegation, head, publicationLifetimeMs, timeLowerMs, timeUpperMs) {
  uint(publicationLifetimeMs); uint(timeLowerMs); uint(timeUpperMs);
  requireThat(publicationLifetimeMs > 0n && timeLowerMs <= timeUpperMs, "revocation_time_context");
  capacityBinding(schema, capacity, head);
  matches(delegation.fields, head.fields, headFields, "revocation_delegation_binding");
  requireThat(head.fields.signing_key_id.equals(delegation.fields.signer_key_id), "revocation_signer_key");
  requireThat(head.fields.signer_delegation_digest.equals(digest(schema, "head_signer_delegation_digest", "delegation", delegation.bytes)), "revocation_delegation_digest");
  requireThat(delegation.fields.not_after_ms <= add(delegation.fields.issued_at_ms, publicationLifetimeMs), "revocation_delegation_lifetime");
  requireThat(head.fields.this_update_ms >= delegation.fields.issued_at_ms && head.fields.this_update_ms < delegation.fields.not_after_ms, "revocation_head_issuance");
  requireThat(timeLowerMs >= head.fields.this_update_ms, "revocation_time_pending");
  requireThat(timeUpperMs < head.fields.next_update_ms && timeUpperMs < delegation.fields.not_after_ms, "revocation_expired");
  // The TrustConfig's own original deadline must additionally hold. A new
  // delegation for the same key cannot extend this Head's digest-bound interval.
}

export function checkHeadReferenceBindings(schema, capacityBytes, delegationBytes, headBytes, publicationLifetimeMs, timeLowerMs, timeUpperMs) {
  headBindings(schema, object(schema, "NamespaceCapacity", capacityBytes), object(schema, "HeadSignerDelegation", delegationBytes), object(schema, "FreshnessHead", headBytes), publicationLifetimeMs, timeLowerMs, timeUpperMs);
}

export function credentialPolicyRequirements(schema, policyBytes) {
  const policy = object(schema, "CredentialRevocationPolicy", policyBytes).fields;
  return Object.freeze({max_staleness_ms:policy.max_staleness_ms, max_head_signer_lifetime_ms:policy.max_head_signer_lifetime_ms});
}

export function intersectCredentialRequirements(leftStalenessMs, leftSignerMs, rightStalenessMs, rightSignerMs) {
  for (const value of [leftStalenessMs,leftSignerMs,rightStalenessMs,rightSignerMs]) {
    uint(value);
    requireThat(value > 0n, "revocation_requirement");
  }
  // Fold only independently authenticated original role-closure requirements.
  // This arithmetic does not discover dependencies or prove closure completeness.
  return Object.freeze({
    max_staleness_ms:leftStalenessMs < rightStalenessMs ? leftStalenessMs : rightStalenessMs,
    max_head_signer_lifetime_ms:leftSignerMs < rightSignerMs ? leftSignerMs : rightSignerMs
  });
}

export function namespacePolicyDeadlineReference(schema, capacityBytes, policyBytes, delegationBytes, headBytes, maxStalenessMs, maxSignerMs, trustNotAfterMs, credentialNotAfterMs, timeLowerMs, timeUpperMs) {
  for (const value of [maxStalenessMs,maxSignerMs,trustNotAfterMs,credentialNotAfterMs,timeLowerMs,timeUpperMs]) uint(value);
  requireThat(maxStalenessMs > 0n && maxSignerMs > 0n, "revocation_requirement");
  requireThat(timeLowerMs <= timeUpperMs, "revocation_time_context");
  const capacity = object(schema, "NamespaceCapacity", capacityBytes);
  const policy = object(schema, "PublicationPolicy", policyBytes).fields;
  const delegation = object(schema, "HeadSignerDelegation", delegationBytes);
  const head = object(schema, "FreshnessHead", headBytes);
  matches(policy, head.fields, ["publication_policy_id","publication_policy_revision"], "revocation_publication_policy");
  // Check the immutable publication envelope, even if this delegation is short
  // or almost expired. Policy names/revisions never order security strength.
  requireThat(policy.max_signer_lifetime_ms <= maxSignerMs, "revocation_policy_incompatible");
  headBindings(schema, capacity, delegation, head, policy.max_signer_lifetime_ms, timeLowerMs, timeUpperMs);
  requireThat(head.fields.next_update_ms - head.fields.this_update_ms <= policy.max_head_validity_ms, "revocation_head_validity");
  const stalenessDeadline = add(head.fields.this_update_ms, maxStalenessMs);
  const earlier = (a,b) => a < b ? a : b;
  const namespaceDeadline = [head.fields.next_update_ms,stalenessDeadline,delegation.fields.not_after_ms,trustNotAfterMs].reduce(earlier);
  const authorizationDeadline = earlier(namespaceDeadline, credentialNotAfterMs);
  requireThat(timeUpperMs < authorizationDeadline, "revocation_expired");
  return Object.freeze({namespace_deadline_ms:namespaceDeadline, authorization_deadline_ms:authorizationDeadline});
  // Callers must establish active State pairing, original TrustConfig/credential
  // deadlines, the complete role closure and all immediate known-denial gates.
  // Neither observed/pinned times nor current time can refresh these deadlines.
}

export function checkHeadReferenceTransition(schema, capacityBytes, previousBytes, nextBytes, timeLowerMs) {
  uint(timeLowerMs);
  const capacity = object(schema, "NamespaceCapacity", capacityBytes);
  const previous = object(schema, "FreshnessHead", previousBytes);
  const next = object(schema, "FreshnessHead", nextBytes);
  capacityBinding(schema, capacity, previous);
  capacityBinding(schema, capacity, next);
  matches(previous.fields, next.fields, headFields, "revocation_transition_binding");
  const before = previous.fields.head_sequence, after = next.fields.head_sequence;
  requireThat(after >= before, "revocation_head_rollback");
  if (after === before) {
    requireThat(previous.bytes.equals(next.bytes), "revocation_head_equivocation");
    return "duplicate"; // No new time, deadline, content or authorization.
  }
  const impacts = ["max_certificate_impact_ms", "max_connection_impact_ms"];
  for (let index = 0; index < impacts.length; index++) {
    const oldFloor = previous.fields.credential_revocation_floors[index];
    const newFloor = next.fields.credential_revocation_floors[index];
    requireThat(newFloor >= oldFloor, "revocation_floor_rollback");
    if (newFloor > oldFloor) requireThat(timeLowerMs >= bound(capacity.fields, newFloor - 1n, impacts[index]), "revocation_floor_immature");
  }
  return "advance"; // A reference relation, not a committed high-water update.
}
