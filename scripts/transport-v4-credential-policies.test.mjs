import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeCBOR, decodeMap, encodeCBOR, mapFromNames, projectMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { deriveIssuerNamespaceClosure } from "./transport-v4-namespace-closure.mjs";
import { verifyIssuerCredentialPoliciesReference } from "./transport-v4-credential-policies.mjs";
import { namespacePolicyDeadlineReference } from "./transport-v4-revocation.mjs";

const { schema, files } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const original = id => Buffer.from(corpus.vectors.find(vector => vector.id === id).hex, "hex");
const key = (type, name) => BigInt(Object.entries(schema.frame_maps[type].fields).find(([, value]) => value.name === name)[0]);
const get = (type, map, name) => map.get(key(type, name));
const set = (type, map, changes) => { for (const [name, value] of Object.entries(changes)) map.set(key(type, name), value); };
const hash = (domain, name, map) => Buffer.from(evaluateDomain(schema, domain, { [name]: encodeCBOR(map) }).output_hex, "hex");
const fail = (run, code) => assert.throws(run, error => error instanceof VectorError && error.code === code);
const MAX = 0xffffffffffffffffn;

function fixture(tunnel = false) {
  const artifact = decodeMap(schema, "Artifact", original("artifact_transport_fields"));
  const candidate = get("Artifact", artifact, "candidates")[tunnel ? 1 : 0];
  set("Artifact", artifact, { candidates: [candidate] });
  const certificate = role => {
    const map = decodeMap(schema, "IdentityCertificate", original("certificate_fields"));
    set("IdentityCertificate", map, { role });
    return map;
  };
  const client = certificate(0n), server = certificate(1n), relay = [certificate(2n), certificate(2n)];
  const grants = tunnel ? ["grant_fields", "grant_server_namespace"].map(id => decodeMap(schema, "Grant", original(id))) : [];
  const names = ["artifact", "client", "server", ...(tunnel ? ["client_grant", "client_relay", "server_grant", "server_relay"] : [])];
  const credential = { artifact: ["Artifact", artifact], client: ["IdentityCertificate", client], server: ["IdentityCertificate", server] };
  if (tunnel) for (const [i, side] of ["client", "server"].entries()) {
    const namespace = get("Grant", grants[i], "namespace");
    set("GrantNamespace", namespace, { generation: get("Artifact", artifact, "revocation_authority_generation"),
      revocation_authority_id: get("Artifact", artifact, "revocation_authority_id"),
      namespace_capacity_digest: get("Artifact", artifact, "namespace_capacity_digest") });
    credential[side + "_grant"] = ["GrantNamespace", namespace];
    credential[side + "_relay"] = ["IdentityCertificate", relay[i]];
  }
  const policies = Object.fromEntries(names.map(name => [name, decodeMap(schema, "CredentialRevocationPolicy", original("credential_policy_online"))]));
  names.forEach((name, i) => {
    const [type, map] = credential[name], reference = { revocation_policy_id: "policy-" + i, revocation_policy_revision: BigInt(i + 1) };
    set(type, map, reference); set("CredentialRevocationPolicy", policies[name], reference);
  });
  const args = () => [schema, encodeCBOR(artifact), 0, encodeCBOR(client), encodeCBOR(server),
    Object.fromEntries(names.map(name => [name, encodeCBOR(policies[name])])),
    ...(tunnel ? [encodeCBOR(grants[0]), encodeCBOR(relay[0]), encodeCBOR(grants[1]), encodeCBOR(relay[1])] : [])];
  const sync = () => {
    set("Artifact", artifact, { client_identity_digest: hash("certificate_digest", "certificate", client), server_identity_digest: hash("certificate_digest", "certificate", server) });
    const route = projectMap(schema, "candidate_route", candidate);
    grants.forEach((grant, i) => set("Grant", grant, {
      route_descriptor: route, route_digest: hash("route_digest", "route", route),
      session_contract_digest: hash("session_contract_digest", "session_contract", get("Artifact", artifact, "session_contract")),
      identity_digests: [get("Artifact", artifact, "client_identity_digest"), get("Artifact", artifact, "server_identity_digest")],
      relay_identity_digest: hash("certificate_digest", "certificate", relay[i]),
    }));
    const parent = () => {
      const values = Object.fromEntries(Object.values(schema.frame_maps.GrantParentRef.fields).map(({ name }) => [name,
        name === "artifact_digest" ? hash("artifact_digest", "artifact", artifact) : get("Artifact", artifact,
          { authority_generation: "revocation_authority_generation", artifact_issuer_key_id: "issuer_key_id" }[name] ?? name)]));
      grants.forEach(grant => set("Grant", grant, { parent_ref: mapFromNames(schema, "GrantParentRef", values) }));
    };
    parent();
    const a = args();
    set("Candidate", candidate, { revocation_namespace_refs: decodeCBOR(deriveIssuerNamespaceClosure(...a.slice(0, 5), ...a.slice(6))) });
    parent();
  };
  sync();
  return { artifact, candidate, client, server, grants, relay, names, credential, policies, args, sync };
}

test("v4.credential_policies.closure: direct and tunnel use every original credential requirement", () => {
  for (const tunnel of [false, true]) {
    const f = fixture(tunnel);
    assert.deepEqual(verifyIssuerCredentialPoliciesReference(...f.args()), { max_staleness_ms: 300000n, max_head_signer_lifetime_ms: 86400000n });
    assert.ok(Object.isFrozen(verifyIssuerCredentialPoliciesReference(...f.args())));
    // Numerical intersection across separately varying dimensions; IDs and
    // revisions deliberately order differently from the actual requirements.
    for (const name of f.names.slice(1)) set("CredentialRevocationPolicy", f.policies[name], { max_staleness_ms: MAX, max_head_signer_lifetime_ms: MAX });
    assert.deepEqual(verifyIssuerCredentialPoliciesReference(...f.args()), { max_staleness_ms: 300000n, max_head_signer_lifetime_ms: 86400000n });
  }
});

test("v4.credential_policies.parent: neither lifetime dimension may be narrowed by a bound credential", () => {
  for (const tunnel of [false, true]) for (const name of fixture(tunnel).names.slice(1)) {
    for (const field of ["max_staleness_ms", "max_head_signer_lifetime_ms"]) {
      const f = fixture(tunnel), value = get("CredentialRevocationPolicy", f.policies.artifact, field);
      set("CredentialRevocationPolicy", f.policies[name], { [field]: value - 1n });
      fail(() => verifyIssuerCredentialPoliciesReference(...f.args()), "credential_policy_parent_envelope");
      set("CredentialRevocationPolicy", f.policies.artifact, { [field]: value - 1n });
      assert.equal(verifyIssuerCredentialPoliciesReference(...f.args())[field], value - 1n);
    }
  }
});

test("v4.credential_policies.references: exact original IDs/revisions and consistent contents are mandatory", () => {
  for (const name of fixture(true).names) for (const change of [{ revocation_policy_id: "another" }, { revocation_policy_revision: MAX }]) {
    const f = fixture(true); set("CredentialRevocationPolicy", f.policies[name], change);
    fail(() => verifyIssuerCredentialPoliciesReference(...f.args()), "credential_policy_reference");
  }
  const f = fixture(true), common = { revocation_policy_id: "shared", revocation_policy_revision: 1n };
  for (const name of f.names) {
    const [type, map] = f.credential[name]; set(type, map, common); set("CredentialRevocationPolicy", f.policies[name], common);
  }
  f.sync(); assert.equal(verifyIssuerCredentialPoliciesReference(...f.args()).max_staleness_ms, 300000n);
  set("CredentialRevocationPolicy", f.policies.server_relay, { max_staleness_ms: 300001n });
  fail(() => verifyIssuerCredentialPoliciesReference(...f.args()), "credential_policy_equivocation");
});

test("v4.credential_policies.originals: matching policies cannot replace signed credential and namespace bindings", () => {
  const certificate = fixture(true);
  set("IdentityCertificate", certificate.client, { signature: Buffer.alloc(64, 99) });
  fail(() => verifyIssuerCredentialPoliciesReference(...certificate.args()), "namespace_identity_digest");
  const grant = fixture(true);
  set("GrantParentRef", get("Grant", grant.grants[0], "parent_ref"), { artifact_digest: Buffer.alloc(32, 99) });
  fail(() => verifyIssuerCredentialPoliciesReference(...grant.args()), "namespace_grant_parent");
  const closure = fixture(); get("Candidate", closure.candidate, "revocation_namespace_refs").pop();
  assert.throws(() => verifyIssuerCredentialPoliciesReference(...closure.args()), /namespace_closure_mismatch|array_length/u);
});

test("v4.credential_policies.publication: a short current head cannot repair an incompatible publication envelope", () => {
  const requirements = verifyIssuerCredentialPoliciesReference(...fixture(true).args());
  const policy = decodeMap(schema, "PublicationPolicy", original("publication_policy"));
  const check = () => namespacePolicyDeadlineReference(schema, original("namespace_capacity_fields"), encodeCBOR(policy),
    original("head_delegation_fields"), original("freshness_head_fields"), requirements.max_staleness_ms,
    requirements.max_head_signer_lifetime_ms, 100000n, 100000n, 1100n, 1200n);
  assert.equal(check().authorization_deadline_ms, 50000n);
  set("PublicationPolicy", policy, { max_signer_lifetime_ms: 604800000n });
  fail(check, "revocation_policy_incompatible");
});

test("v4.credential_policies.context: exact original-role entries reject extra, missing and inherited inputs", () => {
  for (const tunnel of [false, true]) {
    const f = fixture(tunnel);
    for (const name of f.names) {
      const args = f.args(); delete args[5][name];
      fail(() => verifyIssuerCredentialPoliciesReference(...args), "credential_policy_context_fields");
    }
    for (const name of ["activation", "publication", "client_grant_unused"]) {
      const args = f.args(); args[5][name] = original("credential_policy_online");
      fail(() => verifyIssuerCredentialPoliciesReference(...args), "credential_policy_context_fields");
    }
    const args = f.args(); args[5] = Object.assign(Object.create(null), args[5]);
    assert.equal(verifyIssuerCredentialPoliciesReference(...args).max_staleness_ms, 300000n);
  }
  const direct = fixture().args(); direct[6] = original("grant_fields");
  fail(() => verifyIssuerCredentialPoliciesReference(...direct), "credential_policy_hop_presence");
  const tunnel = fixture(true).args(); tunnel[9] = null;
  fail(() => verifyIssuerCredentialPoliciesReference(...tunnel), "credential_policy_hop_presence");
});

test("v4.credential_policies.hooks: context, byte metadata and candidate coercion never call caller hooks", () => {
  const f = fixture(); let called = 0;
  const trap = () => { called++; throw new Error("caller hook"); };
  for (const input of [new Proxy({}, { get: trap, ownKeys: trap, getPrototypeOf: trap }), Object.create(new Proxy({}, { get: trap })),
    Object.defineProperty({ client: null, server: null }, "artifact", { get: trap, enumerable: true })]) {
    const args = f.args(); args[5] = input;
    assert.throws(() => verifyIssuerCredentialPoliciesReference(...args), VectorError);
  }
  for (const input of [new Proxy(original("credential_policy_online"), { get: trap }), { valueOf: trap }]) {
    const args = f.args(); args[5].artifact = input;
    assert.throws(() => verifyIssuerCredentialPoliciesReference(...args), TypeError);
  }
  for (const index of [{ toString: trap, valueOf: trap }, "0", 0n, -1, 0.5, 1, NaN]) {
    const args = f.args(); args[2] = index;
    fail(() => verifyIssuerCredentialPoliciesReference(...args), "credential_policy_candidate_index");
  }
  assert.equal(called, 0);
});

test("v4.credential_policies.bounds: every original and policy is bounded before copy and strict decoding", () => {
  const f = fixture(true);
  for (const [position, type] of [[1, "Artifact"], [3, "IdentityCertificate"], [4, "IdentityCertificate"], [6, "Grant"],
    [7, "IdentityCertificate"], [8, "Grant"], [9, "IdentityCertificate"]]) {
    const args = f.args(); args[position] = Buffer.alloc(schema.frame_maps[type].max_encoded_bytes + 1);
    fail(() => verifyIssuerCredentialPoliciesReference(...args), "credential_policy_input_size");
  }
  for (const name of f.names) {
    const args = f.args(); args[5][name] = Buffer.alloc(schema.frame_maps.CredentialRevocationPolicy.max_encoded_bytes + 1);
    fail(() => verifyIssuerCredentialPoliciesReference(...args), "credential_policy_input_size");
    const truncated = f.args(); truncated[5][name] = truncated[5][name].subarray(0, -1);
    assert.throws(() => verifyIssuerCredentialPoliciesReference(...truncated), /truncated/u);
    for (const changes of [{ max_staleness_ms: 0n }, { max_head_signer_lifetime_ms: 0n }]) {
      const g = fixture(true); set("CredentialRevocationPolicy", g.policies[name], changes);
      assert.throws(() => verifyIssuerCredentialPoliciesReference(...g.args()), /field_range/u);
    }
  }
});

test("v4.credential_policies.ownership: outputs retain only immutable numeric requirements", () => {
  const f = fixture(true), args = f.args(), before = args.slice(1).filter(Buffer.isBuffer).map(Buffer.from);
  const result = verifyIssuerCredentialPoliciesReference(...args);
  args.slice(1).filter(Buffer.isBuffer).forEach((bytes, index) => assert.deepEqual(bytes, before[index]));
  args.slice(1).filter(Buffer.isBuffer).forEach(bytes => bytes.fill(0));
  Object.values(args[5]).forEach(bytes => bytes.fill(0));
  assert.deepEqual(result, { max_staleness_ms: 300000n, max_head_signer_lifetime_ms: 86400000n });
  assert.deepEqual(Object.values(result).map(value => typeof value), ["bigint", "bigint"]);
});
