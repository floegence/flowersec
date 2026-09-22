import { decodeMap, encodeCBOR, mapFromNames, projectMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const field = (schema, type, name) => Object.entries(schema.frame_maps[type].fields).find(([, value]) => value.name === name);
const get = (schema, type, map, name) => map.get(BigInt(field(schema, type, name)[0]));
const fields = (schema, type, map) => Object.fromEntries(Object.entries(schema.frame_maps[type].fields).map(([key, value]) => [value.name, map.get(BigInt(key))]));
const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) ? a.equals(b) : a === b;
const own = bytes => { const copy = Buffer.alloc(bytes.length); copy.set(bytes); return copy; };
const hash = (schema, name, args) => Buffer.from(evaluateDomain(schema, name, args).output_hex, "hex");

function read(schema, type, input) {
  const view = referenceByteView(input);
  const cap = schema.frame_maps[type].max_encoded_bytes;
  requireThat(Number.isSafeInteger(cap) && view.length <= cap, "namespace_input_size");
  const bytes = own(view), map = decodeMap(schema, type, bytes);
  return { bytes, map, values: fields(schema, type, map) };
}

function endpoint(schema, artifact, input, role) {
  const certificate = read(schema, "IdentityCertificate", input), c = certificate.values;
  const name = role === 0n ? "client_identity_digest" : "server_identity_digest";
  requireThat(c.role === role && c.tenant_id === artifact.tenant_id && c.audience === artifact.audience &&
    c.crypto_profile_id === artifact.crypto_profile_id, "namespace_identity_binding");
  requireThat(same(hash(schema, "certificate_digest", { certificate: certificate.bytes }), artifact[name]), "namespace_identity_digest");
  return certificate;
}

// Issuer-only structural composition. All supplied originals must already have
// independent trust, signature, purpose, time and revocation validation. The
// issuer has both endpoints and hop originals; an endpoint must never acquire
// the other leg's private material just to run this reference. Activation
// signers use the parent's existing namespace, not another hidden dependency.
// No returned value authenticates a namespace or reserves a subscription.
export function deriveIssuerNamespaceClosure(schema, artifactInput, candidateIndex, clientInput, serverInput,
  clientGrantInput = null, clientRelayInput = null, serverGrantInput = null, serverRelayInput = null) {
  const original = read(schema, "Artifact", artifactInput), a = original.values;
  requireThat(Number.isSafeInteger(candidateIndex) && candidateIndex >= 0 && candidateIndex < a.candidates.length, "namespace_candidate_index");
  const candidate = a.candidates[candidateIndex], c = fields(schema, "Candidate", candidate);
  const tunnel = c.path_kind === 1n;
  const hopInputs = [clientGrantInput, clientRelayInput, serverGrantInput, serverRelayInput];
  requireThat(hopInputs.every(input => (input !== null) === tunnel), "namespace_hop_presence");
  const client = endpoint(schema, a, clientInput, 0n), server = endpoint(schema, a, serverInput, 1n);
  const namespaces = new Map();
  const add = (value, generation, mask) => {
    const key = JSON.stringify([value.tenant_id, value.revocation_authority_id]);
    const previous = namespaces.get(key);
    if (previous) {
      requireThat(previous.generation === generation && same(previous.namespace_capacity_digest, value.namespace_capacity_digest), "namespace_mapping_conflict");
      previous.role_mask |= mask;
    } else {
      namespaces.set(key, { tenant_id: value.tenant_id, revocation_authority_id: value.revocation_authority_id,
        generation, namespace_capacity_digest: own(value.namespace_capacity_digest), role_mask: mask });
    }
  };
  const commonMask = tunnel ? 7n : 3n;
  for (const value of [a, client.values, server.values]) add(value, value.revocation_authority_generation, commonMask);
  if (tunnel) {
    const route = encodeCBOR(projectMap(schema, "candidate_route", candidate));
    const artifactDigest = hash(schema, "artifact_digest", { artifact: original.bytes });
    const contractDigest = hash(schema, "session_contract_digest", { session_contract: encodeCBOR(a.session_contract) });
    const grants = [];
    for (const [grantInput, relayInput, mask] of [[clientGrantInput, clientRelayInput, 5n], [serverGrantInput, serverRelayInput, 6n]]) {
      const grant = read(schema, "Grant", grantInput), g = grant.values;
      const parent = fields(schema, "GrantParentRef", g.parent_ref), ns = fields(schema, "GrantNamespace", g.namespace);
      // Relay service/audience comes from independent issuance/deployment
      // authority; it need not equal the application certificate audience.
      requireThat(g.tenant_id === a.tenant_id, "namespace_grant_binding");
      requireThat(encodeCBOR(g.route_descriptor).equals(route) && same(g.session_contract_digest, contractDigest), "namespace_grant_route");
      requireThat(same(g.identity_digests[0], a.client_identity_digest) && same(g.identity_digests[1], a.server_identity_digest), "namespace_grant_identity");
      for (const [target, source] of [["authority_generation", "revocation_authority_generation"], ["artifact_issuer_key_id", "issuer_key_id"],
        ...["tenant_id", "revocation_authority_id", "namespace_capacity_digest", "revocation_policy_id", "revocation_policy_revision",
          "lease_id", "revocation_epoch", "issued_at_ms", "initiation_not_after_ms", "session_not_after_ms"].map(name => [name, name])]) {
        requireThat(same(parent[target], a[source]), "namespace_grant_parent");
      }
      requireThat(same(parent.artifact_digest, artifactDigest), "namespace_grant_parent");
      requireThat(ns.role_mask === mask && ns.tenant_id === a.tenant_id, "namespace_grant_role");
      const relay = read(schema, "IdentityCertificate", relayInput), r = relay.values;
      requireThat(r.role === 2n && r.tenant_id === a.tenant_id && same(hash(schema, "certificate_digest", { certificate: relay.bytes }), g.relay_identity_digest), "namespace_relay_identity");
      add(ns, ns.generation, mask);
      // The grant's authenticated relay identity is also a credential
      // dependency of this hop; its namespace cannot appear only after spend.
      add(r, r.revocation_authority_generation, mask);
      grants.push(g);
    }
    for (const name of ["attempt_id", "pairing_id", "service", "audience"]) {
      requireThat(same(grants[0][name], grants[1][name]), "namespace_grant_pair");
    }
  }
  const maximum = field(schema, "Candidate", "revocation_namespace_refs")[1].max_items;
  requireThat(namespaces.size <= maximum, "namespace_closure_capacity");
  const refs = [...namespaces.values()].map(value => mapFromNames(schema, "RevocationNamespaceRef", value));
  refs.sort((a, b) => Buffer.compare(encodeCBOR(a), encodeCBOR(b)));
  // Re-encode only newly derived public references. Never return a byte view
  // into the Artifact's secret-bearing backing or repair a received Candidate.
  return own(encodeCBOR(refs));
}

export function verifyIssuerNamespaceClosure(schema, artifactInput, candidateIndex, ...originals) {
  const expected = deriveIssuerNamespaceClosure(schema, artifactInput, candidateIndex, ...originals);
  const artifact = read(schema, "Artifact", artifactInput);
  const candidate = artifact.values.candidates[candidateIndex];
  const actual = encodeCBOR(get(schema, "Candidate", candidate, "revocation_namespace_refs"));
  requireThat(actual.equals(expected), "namespace_closure_mismatch");
  return expected;
}
