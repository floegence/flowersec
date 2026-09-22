import { types } from "node:util";
import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";
import { verifyIssuerNamespaceClosure } from "./transport-v4-namespace-closure.mjs";
import { intersectCredentialRequirements } from "./transport-v4-revocation.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const fields = (schema, type, map) => Object.fromEntries(Object.entries(schema.frame_maps[type].fields).map(([key, value]) => [value.name, map.get(BigInt(key))]));
const own = bytes => { const copy = Buffer.alloc(bytes.length); copy.set(bytes); return copy; };

function read(schema, type, input) {
  const view = referenceByteView(input);
  requireThat(view.length <= schema.frame_maps[type].max_encoded_bytes, "credential_policy_input_size");
  const bytes = own(view);
  return { bytes, values: fields(schema, type, decodeMap(schema, type, bytes)) };
}

function capture(input, names) {
  requireThat(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(input)), "credential_policy_context");
  // Check the small own-key set before obtaining descriptors or copying bytes.
  const keys = Reflect.ownKeys(input);
  requireThat(keys.length === names.length && keys.every(key => names.includes(key)), "credential_policy_context_fields");
  const captured = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    requireThat(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "credential_policy_context_data");
    captured[name] = descriptor.value;
  }
  return captured;
}

// Issuer-only structural reference. Each policy must come from the independent
// original trusted mapping for that credential's namespace/reference. Matching
// an ID/revision is not TrustConfig authentication, permission or continuity.
// Endpoints must not obtain the other hop's private material to call this helper.
// ActivationAuthorization inherits the parent's policy; it has no separate
// policy entry or permission to introduce a competing requirement.
export function verifyIssuerCredentialPoliciesReference(schema, artifactInput, candidateIndex, clientInput, serverInput, policyInput,
  clientGrantInput = null, clientRelayInput = null, serverGrantInput = null, serverRelayInput = null) {
  const artifact = read(schema, "Artifact", artifactInput);
  requireThat(Number.isSafeInteger(candidateIndex) && candidateIndex >= 0 && candidateIndex < artifact.values.candidates.length,
    "credential_policy_candidate_index");
  const candidate = artifact.values.candidates[candidateIndex];
  const tunnel = fields(schema, "Candidate", candidate).path_kind === 1n;
  const names = ["artifact", "client", "server", ...(tunnel ? ["client_grant", "client_relay", "server_grant", "server_relay"] : [])];
  const policies = capture(policyInput, names);
  const hopInputs = [clientGrantInput, clientRelayInput, serverGrantInput, serverRelayInput];
  requireThat(hopInputs.every(input => (input !== null) === tunnel), "credential_policy_hop_presence");
  const credentials = [artifact, read(schema, "IdentityCertificate", clientInput), read(schema, "IdentityCertificate", serverInput)];
  if (tunnel) for (const [index, input] of hopInputs.entries()) credentials.push(read(schema, index % 2 === 0 ? "Grant" : "IdentityCertificate", input));
  // Validate complete signed dependency references and all original parent,
  // route, identity, grant and pair bindings before deriving requirements.
  verifyIssuerNamespaceClosure(schema, artifact.bytes, candidateIndex, ...credentials.slice(1).map(value => value.bytes));
  const references = new Map();
  const requirements = credentials.map((credential, index) => {
    const value = tunnel && (index === 3 || index === 5) ? fields(schema, "GrantNamespace", credential.values.namespace) : credential.values;
    const policy = read(schema, "CredentialRevocationPolicy", policies[names[index]]), p = policy.values;
    requireThat(p.revocation_policy_id === value.revocation_policy_id && p.revocation_policy_revision === value.revocation_policy_revision,
      "credential_policy_reference");
    const reference = JSON.stringify([p.revocation_policy_id, p.revocation_policy_revision.toString()]);
    const previous = references.get(reference);
    requireThat(previous === undefined || previous.equals(policy.bytes), "credential_policy_equivocation");
    references.set(reference, policy.bytes);
    return Object.freeze({ max_staleness_ms: p.max_staleness_ms, max_head_signer_lifetime_ms: p.max_head_signer_lifetime_ms });
  });
  const parent = requirements[0];
  // Compare numeric limits, never the names or revision ordering. A later
  // grant cannot narrow either bound beyond the already signed parent policy.
  for (const policy of requirements.slice(1)) requireThat(parent.max_staleness_ms <= policy.max_staleness_ms &&
    parent.max_head_signer_lifetime_ms <= policy.max_head_signer_lifetime_ms, "credential_policy_parent_envelope");
  const result = requirements.reduce((left, right) => intersectCredentialRequirements(left.max_staleness_ms,
    left.max_head_signer_lifetime_ms, right.max_staleness_ms, right.max_head_signer_lifetime_ms));
  // Both endpoint closures include the parent and both endpoint identities;
  // each hop adds its own grant/relay. Since the parent is no wider than every
  // dependency, this pair is their common minimum, including the relay role.
  // Each namespace must still independently pass its fixed PublicationPolicy,
  // complete State/Head/trust/time/revocation and role-local authorization gates.
  return Object.freeze(result);
}
