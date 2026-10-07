import assert from "node:assert/strict";
import test from "node:test";

import {
  assertCurrentMaterial,
  assertEndpointTunnelPublication,
  assertNoSyntheticCleanupCounters,
  assertTunnelPublication,
} from "./server-parity-material.mjs";

// These bytes exercise only publication-envelope preservation. The SDK owners
// independently verify canonical credentials, signatures and original spends.
const bytes = (length, byte = 1) => Buffer.alloc(length, byte).toString("base64");
const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
function publication() {
  const namespaces = [{
    tenant: "tenant", authority: "issuer", generation: 1,
    root_key_id: bytes(16), root_public_key: bytes(32),
    bootstrap_url: "https://127.0.0.1:4443/bootstrap", state_url: "https://127.0.0.1:4443/state",
  }];
  const original = {
    wire_revision: 4, profile, source: "preauthorized_pool", role: 0,
    generation: { source: bytes(16), generation: 1 },
    artifact: bytes(4), activation: bytes(4, 2),
    client_certificate: bytes(4, 3), server_certificate: bytes(4, 4),
    route: bytes(4, 5), route_digest: bytes(32, 6),
    identity_seed: bytes(32, 7), dh_seed: bytes(32, 8),
    activation_signing_key_id: "activation", namespaces,
    tunnels: [0, 1].map(role => ({
      candidate_index: 0, role, grant: bytes(4, 10 + role),
      relay_certificate: bytes(4, 12), grant_namespace: 0, relay_namespace: 0,
    })),
    relay_deployment: { RouteDigest: Array(32).fill(6), Profile: "native" },
  };
  const server = { ...structuredClone(original), role: 1, identity_seed: bytes(32, 13), dh_seed: bytes(32, 14) };
  return {
    wire_revision: 4, profile, source: "preauthorized_pool", route_digest: original.route_digest,
    endpoint_a_artifact_json: JSON.stringify(original), endpoint_b_artifact_json: JSON.stringify(server),
    verification_records: namespaces,
    authorizations: original.tunnels.map(tunnel => ({
      ...tunnel, endpoint_namespace: 0,
      endpoint_certificate: tunnel.role === 0 ? original.client_certificate : original.server_certificate,
    })),
    client_tls_certificate_pem: "independent client certificate input",
    client_tls_private_key_pem: "independent client key input",
    server_tls_certificate_pem: "independent certificate input",
    server_tls_private_key_pem: "independent key input",
  };
}
function changeMaterial(relay, field, change) {
  const material = JSON.parse(relay[field]);
  change(material);
  relay[field] = JSON.stringify(material);
}

test("paired publication retains both Grants and independent endpoint identities", () => {
  const relay = publication();
  const result = assertTunnelPublication(relay, "original");
  assert.equal(result.client.role, 0);
  assert.equal(result.server.role, 1);
  assert.deepEqual(result.client.tunnels, result.server.tunnels);
  assert.notEqual(result.client.identity_seed, result.server.identity_seed);
  assertEndpointTunnelPublication(structuredClone(relay), relay, "endpoint");
});

for (const field of ["artifact", "activation", "client_certificate", "server_certificate", "route", "activation_signing_key_id"]) {
  test(`paired publication rejects independently changed ${field}`, () => {
    const relay = publication();
    changeMaterial(relay, "endpoint_b_artifact_json", material => {
      material[field] = field === "activation_signing_key_id" ? "replacement" : bytes(4, 99);
    });
    assert.throws(() => assertTunnelPublication(relay, "changed"), /original endpoint records disagree/);
  });
}

test("both endpoints retain the complete original Grant pair", () => {
  for (const field of ["endpoint_a_artifact_json", "endpoint_b_artifact_json"]) {
    const relay = publication();
    changeMaterial(relay, field, material => material.tunnels.splice(0, 1));
    assert.throws(() => assertTunnelPublication(relay, "missing"), /disagree|both original Grant/);
  }
});

test("relay authorization cannot substitute a Grant, identity or namespace selector", () => {
  for (const field of ["grant", "endpoint_certificate", "relay_certificate", "candidate_index", "endpoint_namespace"]) {
    const relay = publication();
    relay.authorizations[0][field] = field === "candidate_index" ? 1 : field === "endpoint_namespace" ? 1 : bytes(4, 99);
    assert.throws(() => assertTunnelPublication(relay, "tuple"), /original committed leg tuple|namespace record/);
  }
});

test("relay deployment requires the exact original digest and finite host policy shape", () => {
  for (const change of [
    material => { material.relay_deployment.RouteDigest[0] ^= 1; },
    material => { material.relay_deployment.decision = "foreign"; },
    material => { delete material.relay_deployment; },
  ]) {
    const relay = publication();
    changeMaterial(relay, "endpoint_a_artifact_json", change);
    assert.throws(() => assertTunnelPublication(relay, "deployment"), /exact relay deployment/);
  }
});

test("endpoint publication is the complete original serialized source record", () => {
  const relay = publication();
  const endpoint = structuredClone(relay);
  endpoint.verification_records[0].generation++;
  assert.throws(() => assertEndpointTunnelPublication(endpoint, relay, "endpoint"), /altered original/);
  const other = structuredClone(relay);
  other.source = "live_authority";
  assert.throws(() => assertEndpointTunnelPublication(other, relay, "source"), /changed the original source/);
});

test("direct material does not require a tunnel deployment", () => {
  const relay = publication();
  const material = JSON.parse(relay.endpoint_a_artifact_json);
  material.tunnels = [];
  delete material.relay_deployment;
  assert.equal(assertCurrentMaterial(JSON.stringify(material), "direct").tunnels.length, 0);
});

test("cleanup joins cannot be replaced by declared synthetic counters", () => {
  assertNoSyntheticCleanupCounters({ type: "endpoint-a-result", cases: ["cleanup"] }, "joined");
  for (const field of ["active_pairs", "active_legs", "active_sessions", "active_streams", "application_handlers", "released_leases"]) {
    assert.throws(() => assertNoSyntheticCleanupCounters({ [field]: 0 }, "counter"), /synthetic cleanup counter/);
  }
});
