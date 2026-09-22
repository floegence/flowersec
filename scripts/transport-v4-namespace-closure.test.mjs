import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeCBOR, decodeMap, encodeCBOR, mapFromNames, projectMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { deriveIssuerNamespaceClosure, verifyIssuerNamespaceClosure } from "./transport-v4-namespace-closure.mjs";

const { schema, files } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const original = id => Buffer.from(corpus.vectors.find(vector => vector.id === id).hex, "hex");
const key = (type, name) => BigInt(Object.entries(schema.frame_maps[type].fields).find(([, value]) => value.name === name)[0]);
const get = (type, map, name) => map.get(key(type, name));
const set = (type, map, changes) => { for (const [name, value] of Object.entries(changes)) map.set(key(type, name), value); };
const hash = (domain, name, map) => Buffer.from(evaluateDomain(schema, domain, { [name]: encodeCBOR(map) }).output_hex, "hex");
const fail = (run, code) => assert.throws(run, error => error instanceof VectorError && error.code === code);

function fixture(tunnel = false, common = 0) {
  const artifact = decodeMap(schema, "Artifact", original("artifact_transport_fields"));
  const candidate = get("Artifact", artifact, "candidates")[tunnel ? 1 : 0];
  set("Artifact", artifact, { candidates: [candidate] });
  const names = ["parent", "client", "server", "client-grant", "client-relay", "server-grant", "server-relay"];
  const namespace = i => common & (1 << i) ? "shared" : names[i];
  set("Artifact", artifact, { revocation_authority_id: namespace(0) });
  const certificate = (role, i) => {
    const map = decodeMap(schema, "IdentityCertificate", original("certificate_fields"));
    set("IdentityCertificate", map, { role, revocation_authority_id: namespace(i) });
    return map;
  };
  const client = certificate(0n, 1), server = certificate(1n, 2);
  const clientRelay = certificate(2n, 4), serverRelay = certificate(2n, 6);
  const grants = tunnel ? ["grant_fields", "grant_server_namespace"].map(id => decodeMap(schema, "Grant", original(id))) : [];
  const syncIdentities = () => {
    set("Artifact", artifact, {
      client_identity_digest: hash("certificate_digest", "certificate", client),
      server_identity_digest: hash("certificate_digest", "certificate", server),
    });
    grants.forEach((grant, side) => set("Grant", grant, {
      identity_digests: [get("Artifact", artifact, "client_identity_digest"), get("Artifact", artifact, "server_identity_digest")],
      relay_identity_digest: hash("certificate_digest", "certificate", side === 0 ? clientRelay : serverRelay),
    }));
  };
  const syncParent = () => {
    const parent = Object.fromEntries(Object.values(schema.frame_maps.GrantParentRef.fields).map(({ name }) => {
      const source = { authority_generation: "revocation_authority_generation", artifact_issuer_key_id: "issuer_key_id" }[name] ?? name;
      return [name, name === "artifact_digest" ? hash("artifact_digest", "artifact", artifact) : get("Artifact", artifact, source)];
    }));
    grants.forEach(grant => set("Grant", grant, { parent_ref: mapFromNames(schema, "GrantParentRef", parent) }));
  };
  syncIdentities();
  if (tunnel) {
    const route = projectMap(schema, "candidate_route", candidate);
    grants.forEach((grant, side) => {
      set("Grant", grant, {
        route_descriptor: decodeCBOR(encodeCBOR(route)), route_digest: hash("route_digest", "route", route),
        session_contract_digest: hash("session_contract_digest", "session_contract", get("Artifact", artifact, "session_contract")),
        // Distinct application and relay audiences are deliberate.
        audience: "relay-audience", service: "relay-service", issued_at_ms: 100n,
        legs: ["client_leg", "server_leg"].map((name, i) => mapFromNames(schema, "GrantLegRef", {
          leg_id: get(schema.frame_maps.Candidate.fields[key("Candidate", name)].schema_ref, get("Candidate", candidate, name), "leg_id"), logical_role: BigInt(i),
        })),
      });
      set("GrantNamespace", get("Grant", grant, "namespace"), {
        revocation_authority_id: namespace(side === 0 ? 3 : 5), generation: 1n,
        namespace_capacity_digest: get("Artifact", artifact, "namespace_capacity_digest"), role_mask: side === 0 ? 5n : 6n,
      });
    });
  }
  const args = () => [schema, encodeCBOR(artifact), 0, encodeCBOR(client), encodeCBOR(server),
    ...(tunnel ? [encodeCBOR(grants[0]), encodeCBOR(clientRelay), encodeCBOR(grants[1]), encodeCBOR(serverRelay)] : [])];
  syncParent();
  const derived = deriveIssuerNamespaceClosure(...args());
  set("Candidate", candidate, { revocation_namespace_refs: decodeCBOR(derived) });
  // The issuer fixes public dependencies first; final grants then bind the
  // complete signed Artifact. No grant digest is embedded into that Artifact.
  syncParent();
  return { artifact, candidate, client, server, grants, clientRelay, serverRelay, args, syncIdentities, syncParent };
}

const refs = bytes => decodeCBOR(bytes).map(map => Object.fromEntries(Object.entries(schema.frame_maps.RevocationNamespaceRef.fields).map(([id, value]) => [value.name, map.get(BigInt(id))])));
const masks = bytes => Object.fromEntries(refs(bytes).map(ref => [ref.revocation_authority_id, ref.role_mask]));

test("v4.namespace_closure.direct: parent and both endpoint originals form the signed closure", () => {
  const f = fixture();
  assert.deepEqual(masks(verifyIssuerNamespaceClosure(...f.args())), { client: 3n, parent: 3n, server: 3n });
  assert.equal(refs(verifyIssuerNamespaceClosure(...fixture(false, 7).args())).length, 1);
  const args = f.args(); args[5] = original("grant_fields");
  fail(() => deriveIssuerNamespaceClosure(...args), "namespace_hop_presence");
});

test("v4.namespace_closure.tunnel: seven actual dependencies preserve leg-local and shared role masks", () => {
  const f = fixture(true);
  assert.deepEqual(masks(verifyIssuerNamespaceClosure(...f.args())), {
    parent: 7n, client: 7n, server: 7n, "client-grant": 5n, "client-relay": 5n, "server-grant": 6n, "server-relay": 6n,
  });
  const encoded = decodeCBOR(verifyIssuerNamespaceClosure(...f.args())).map(encodeCBOR);
  assert.deepEqual(encoded, [...encoded].sort(Buffer.compare));
  // Both physical dial directions in the generated mixed WS/QUIC route still
  // use logical endpoint roles. No TLS-direction-based role substitution.
  assert.notEqual(get("Artifact", f.artifact, "audience"), get("Grant", f.grants[0], "audience"));
  for (let i = 5; i < 9; i++) {
    const args = f.args(); args[i] = null;
    fail(() => deriveIssuerNamespaceClosure(...args), "namespace_hop_presence");
  }
});

test("v4.namespace_closure.unions: every subset of the seven credentials may share a namespace", () => {
  const names = ["parent", "client", "server", "client-grant", "client-relay", "server-grant", "server-relay"];
  const roles = [7n, 7n, 7n, 5n, 5n, 6n, 6n];
  for (let selected = 0; selected < 128; selected++) {
    const expected = {};
    names.forEach((name, i) => { const target = selected & (1 << i) ? "shared" : name; expected[target] = (expected[target] ?? 0n) | roles[i]; });
    assert.deepEqual(masks(verifyIssuerNamespaceClosure(...fixture(true, selected).args())), expected);
  }
});

test("v4.namespace_closure.mapping: conflicting generations and immutable capacities cannot merge", () => {
  for (const field of ["revocation_authority_generation", "namespace_capacity_digest"]) {
    for (const credential of ["client", "server", "clientRelay", "serverRelay"]) {
      const f = fixture(true, 127);
      set("IdentityCertificate", f[credential], { [field]: field === "namespace_capacity_digest" ? Buffer.alloc(32, 99) : 2n });
      f.syncIdentities(); f.syncParent();
      fail(() => deriveIssuerNamespaceClosure(...f.args()), "namespace_mapping_conflict");
    }
  }
  for (let side = 0; side < 2; side++) {
    for (const changes of [{ generation: 2n }, { namespace_capacity_digest: Buffer.alloc(32, 99) }]) {
      const f = fixture(true, 127);
      set("GrantNamespace", get("Grant", f.grants[side], "namespace"), changes);
      fail(() => deriveIssuerNamespaceClosure(...f.args()), "namespace_mapping_conflict");
    }
  }
});

test("v4.namespace_closure.identity: exact signature-bearing identities, tenant, role and audience bind endpoints", () => {
  for (const credential of ["client", "server"]) {
    for (const changes of [{ tenant_id: "another" }, { audience: "another" }, { role: 2n }]) {
      const f = fixture(); set("IdentityCertificate", f[credential], changes);
      fail(() => deriveIssuerNamespaceClosure(...f.args()), "namespace_identity_binding");
    }
    for (const changes of [{ signature: Buffer.alloc(64, 99) }, { subject_id: "another" }]) {
      const f = fixture(); set("IdentityCertificate", f[credential], changes);
      fail(() => deriveIssuerNamespaceClosure(...f.args()), "namespace_identity_digest");
    }
  }
  for (const credential of ["clientRelay", "serverRelay"]) {
    for (const changes of [{ tenant_id: "another" }, { role: 0n }, { signature: Buffer.alloc(64, 99) }]) {
      const f = fixture(true); set("IdentityCertificate", f[credential], changes);
      fail(() => deriveIssuerNamespaceClosure(...f.args()), "namespace_relay_identity");
    }
  }
});

test("v4.namespace_closure.grants: each leg binds the complete parent, contract, route, identities and pair", () => {
  for (let side = 0; side < 2; side++) {
    for (const name of Object.values(schema.frame_maps.GrantParentRef.fields).map(value => value.name)) {
      const f = fixture(true), parent = get("Grant", f.grants[side], "parent_ref"), value = get("GrantParentRef", parent, name);
      set("GrantParentRef", parent, { [name]: Buffer.isBuffer(value) ? Buffer.alloc(value.length, 99) : typeof value === "bigint" ? value + 1n : "another" });
      assert.throws(() => deriveIssuerNamespaceClosure(...f.args()), /namespace_grant_parent|field_order|field_equality/u, name);
    }
    for (const name of ["attempt_id", "pairing_id", "service", "audience"]) {
      const f = fixture(true), value = get("Grant", f.grants[side], name);
      set("Grant", f.grants[side], { [name]: Buffer.isBuffer(value) ? Buffer.alloc(value.length, 99) : "another" });
      fail(() => deriveIssuerNamespaceClosure(...f.args()), "namespace_grant_pair");
    }
    const f = fixture(true);
    set("Grant", f.grants[side], { session_contract_digest: Buffer.alloc(32, 99) });
    fail(() => deriveIssuerNamespaceClosure(...f.args()), "namespace_grant_route");
    const identity = fixture(true);
    set("Grant", identity.grants[side], { identity_digests: [Buffer.alloc(32, 99), Buffer.alloc(32, 98)] });
    fail(() => deriveIssuerNamespaceClosure(...identity.args()), "namespace_grant_identity");
    const role = fixture(true);
    set("GrantNamespace", get("Grant", role.grants[side], "namespace"), { role_mask: side === 0 ? 6n : 5n });
    fail(() => deriveIssuerNamespaceClosure(...role.args()), "namespace_grant_role");
    const route = fixture(true), descriptor = get("Grant", route.grants[side], "route_descriptor");
    set("Route", descriptor, { candidate_id: Buffer.alloc(16, 99) });
    set("Grant", route.grants[side], { route_digest: hash("route_digest", "route", descriptor) });
    fail(() => deriveIssuerNamespaceClosure(...route.args()), "namespace_grant_route");
  }
  const changed = fixture(true);
  set("Artifact", changed.artifact, { signature: Buffer.alloc(64, 99) });
  fail(() => deriveIssuerNamespaceClosure(...changed.args()), "namespace_grant_parent");
});

test("v4.namespace_closure.received: missing, extra, reordered or substituted signed refs are never repaired", () => {
  for (const tunnel of [false, true]) {
    for (const change of [
      values => values.pop(),
      values => { const extra = new Map(values[0]); set("RevocationNamespaceRef", extra, { revocation_authority_id: "extra" }); values.push(extra); values.sort((a, b) => Buffer.compare(encodeCBOR(a), encodeCBOR(b))); },
      values => values.reverse(),
      values => values.push(values[0]),
      values => set("RevocationNamespaceRef", values[0], { generation: 2n }),
      values => set("RevocationNamespaceRef", values[0], { namespace_capacity_digest: Buffer.alloc(32, 99) }),
      values => set("RevocationNamespaceRef", values[0], { role_mask: 1n }),
    ]) {
      const f = fixture(tunnel), values = get("Candidate", f.candidate, "revocation_namespace_refs");
      change(values);
      // Bind otherwise legal changed Artifact bytes into both final grants.
      // Malformed ordering is rejected even before a digest can be formed.
      assert.throws(() => { f.syncParent(); verifyIssuerNamespaceClosure(...f.args()); }, /namespace_closure_mismatch|item_order|item_identity/u);
    }
  }
});

test("v4.namespace_closure.ownership: outputs have detached exact backing and caller hooks never run", () => {
  const f = fixture(true), args = f.args(), before = args.slice(1).map(value => typeof value === "number" ? value : Buffer.from(value));
  const output = verifyIssuerNamespaceClosure(...args), saved = Buffer.from(output);
  assert.equal(output.buffer.byteLength, output.length);
  args.slice(1).forEach((value, i) => { if (typeof value !== "number") assert.deepEqual(value, before[i]); });
  args[1].fill(0); assert.deepEqual(output, saved);
  output.fill(0); assert.deepEqual(verifyIssuerNamespaceClosure(...f.args()), saved);
  let called = 0;
  const trap = () => { called++; throw new Error("caller hook"); };
  const bytes = f.args()[1];
  const inherited = new Uint8Array(bytes); Object.setPrototypeOf(inherited, new Proxy(Uint8Array.prototype, { getPrototypeOf: trap, get: trap }));
  const shadowed = new Uint8Array(bytes); Object.defineProperty(shadowed, "length", { get: trap });
  for (const input of [new Proxy(bytes, { get: trap, getPrototypeOf: trap }), inherited, shadowed, { valueOf: trap }]) {
    const changed = f.args(); changed[1] = input;
    assert.throws(() => deriveIssuerNamespaceClosure(...changed), TypeError);
  }
  for (const index of [-1, 1, 0.5, NaN, Infinity, "0", false, 0n, { valueOf: trap }]) {
    const changed = f.args(); changed[2] = index;
    fail(() => deriveIssuerNamespaceClosure(...changed), "namespace_candidate_index");
  }
  assert.equal(called, 0);
});

test("v4.namespace_closure.bounds: every original is bounded and structurally decoded before composition", () => {
  const f = fixture(true);
  for (const [position, type] of [[1, "Artifact"], [3, "IdentityCertificate"], [4, "IdentityCertificate"], [5, "Grant"], [6, "IdentityCertificate"], [7, "Grant"], [8, "IdentityCertificate"]]) {
    const tooLarge = f.args(); tooLarge[position] = Buffer.alloc(schema.frame_maps[type].max_encoded_bytes + 1);
    fail(() => deriveIssuerNamespaceClosure(...tooLarge), "namespace_input_size");
    const truncated = f.args(); truncated[position] = truncated[position].subarray(0, -1);
    assert.throws(() => deriveIssuerNamespaceClosure(...truncated), /truncated/u);
  }
});
