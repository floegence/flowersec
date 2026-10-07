import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Reference, encode, type Value } from "../v4/testSupport/cbor.js";
import { wireMaps } from "../v4/runtime/schemaRegistry.js";
import { credentialDigest } from "../v4/runtime/credentialSupport.js";
import { peerField, type CurrentPoolPeerMaterial } from "./currentPeer.js";
import { inspectCurrentTunnelMaterial, requireDefaultCurrentTunnelRoute, currentTunnelAuthorizations } from "./currentTunnelMaterial.js";
import { requireCurrentTunnelPublication, type CurrentRelayReady } from "./serverParityPeer.js";
import { testCertificatePEM } from "../testSupport/tlsFixture.js";

const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/corpus.json", import.meta.url), "utf8")) as { vectors: { id: string; hex: string }[] };
const uint = (value: number): Value => ({ kind: "uint", value: BigInt(value) });
const text = (value: string): Value => ({ kind: "text", value });
const bytes = (value: Uint8Array): Value => ({ kind: "bytes", value });
const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64");
function seed(id: string): Value {
  const vector = corpus.vectors.find(item => item.id === id); if (vector === undefined) throw new Error("missing canonical syntax seed");
  const decoded = new Reference().decode(new Uint8Array(Buffer.from(vector.hex, "hex")), "", {}, 270336n);
  if (!decoded.ok) throw new Error("invalid canonical syntax seed"); return decoded.value;
}
function replace(source: Value, schema: string, fields: Record<string, Value>, remove: readonly string[] = []): Value {
  if (source.kind !== "map") throw new Error("expected syntax map");
  const id = (name: string): bigint => { const item = Object.entries(wireMaps[schema]!.fields).find(([, entry]) => entry.name === name); if (item === undefined) throw new Error(`unknown syntax field ${name}`); return BigInt(item[0]); };
  const changed = new Map(Object.entries(fields).map(([name, value]) => [id(name), value])), deleted = remove.map(id);
  const result = source.value.filter(([key]) => key.kind !== "uint" || !deleted.includes(key.value)).map(([key, value]): [Value, Value] => [key, key.kind === "uint" ? changed.get(key.value) ?? value : value]);
  for (const [key, value] of changed) if (!result.some(([item]) => item.kind === "uint" && item.value === key)) result.push([{ kind: "uint", value: key }, value]);
  result.sort(([left], [right]) => Number((left as { kind: "uint"; value: bigint }).value - (right as { kind: "uint"; value: bigint }).value));
  return { kind: "map", value: result };
}

// These are detached syntax fixtures only. They do not carry issuance rights,
// namespace trust, or proof of any cryptographic or durable admission.
function publication(clientCarrier: 0 | 1, serverCarrier: 0 | 1, serverDialer: 1 | 2 = 2) {
  const grant = seed("grant_fields"), baseRoute = peerField(grant, "Grant", "route_descriptor");
  const leg = (side: 0 | 1, carrier: 0 | 1) => replace(peerField(baseRoute, "Route", side === 0 ? "client_leg" : "server_leg"), "Leg", {
    endpoint_role: uint(side), dialer_role: uint(side === 0 ? 0 : serverDialer), listener_role: uint(side === 0 || serverDialer === 1 ? 2 : 1),
    carrier: uint(carrier), host: text("127.0.0.1"), port: uint(12000 + side), path: text(carrier === 1 ? "/flowersec/v4/tunnel" : ""),
  });
  const clientLeg = leg(0, clientCarrier), serverLeg = leg(1, serverCarrier), route = replace(baseRoute, "Route", { path_kind: uint(1), client_leg: clientLeg, server_leg: serverLeg });
  const routeBytes = encode(route), routeDigest = credentialDigest("route_digest", routeBytes), parent = seed("artifact_services_fields"), candidates = peerField(parent, "Artifact", "candidates");
  if (candidates.kind !== "array" || candidates.value.length === 0) throw new Error("candidate syntax seed missing");
  const candidate = replace(candidates.value[0]!, "Candidate", { path_kind: uint(1), candidate_id: peerField(route, "Route", "candidate_id"), client_leg: clientLeg, server_leg: serverLeg }, ["direct_leg"]);
  const artifact = replace(parent, "Artifact", { candidates: { kind: "array", value: [candidate] } });
  const tunnels = ([0, 1] as const).map(role => ({ candidate_index: 0, role, grant: b64(encode(replace(grant, "Grant", {
    route_descriptor: route, route_digest: bytes(routeDigest), namespace: replace(peerField(grant, "Grant", "namespace"), "GrantNamespace", { role_mask: uint(4 | 1 << role) }),
  }))), relay_certificate: b64(Uint8Array.of(3)), grant_namespace: 0, relay_namespace: 0 }));
  const material = (role: 0 | 1): CurrentPoolPeerMaterial => ({ wire_revision: 4, source: "preauthorized_pool", profile: "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", role,
    generation: { source: b64(new Uint8Array(16).fill(1)), generation: 1 }, artifact: b64(encode(artifact)), activation: b64(Uint8Array.of(1)),
    client_certificate: b64(Uint8Array.of(2)), server_certificate: b64(Uint8Array.of(4)), route: b64(routeBytes), route_digest: b64(routeDigest), activation_signing_key_id: "activation", identity_seed: b64(new Uint8Array(32).fill(5)), dh_seed: b64(new Uint8Array(32).fill(6)),
    namespaces: [{ tenant: "tenant", authority: "authority", generation: 1, root_key_id: b64(new Uint8Array(16).fill(7)), root_public_key: b64(new Uint8Array(32).fill(8)), bootstrap_url: "https://127.0.0.1/bootstrap", state_url: "https://127.0.0.1/state" }], tunnels });
  const paired = { wire_revision: 4 as const, endpoint_a_artifact_json: JSON.stringify(material(0)), endpoint_b_artifact_json: JSON.stringify(material(1)) };
  const ready: CurrentRelayReady = { type: "relay-ready", runtime: "go", path: "tunnel", source: "preauthorized_pool", profile: material(0).profile,
    carrier: clientCarrier === 0 ? "raw-quic" : "websocket", server_carrier: serverCarrier === 0 ? "raw-quic" : "websocket", route_digest: b64(routeDigest), trust_pem: testCertificatePEM, origin: "https://client.example", ...paired };
  return { paired, ready };
}

describe("current complete tunnel publication binding", () => {
  it.each([[0, 0], [0, 1], [1, 0], [1, 1]] as const)("retains independent client/server carriers %i/%i", (client, server) => {
    const { paired, ready } = publication(client, server), inspected = inspectCurrentTunnelMaterial(paired.endpoint_b_artifact_json, 1);
    expect(inspected.clientLeg).toMatchObject({ endpointRole: 0, dialerRole: 0, listenerRole: 2, port: 12000 });
    expect(inspected.serverLeg).toMatchObject({ endpointRole: 1, dialerRole: 2, listenerRole: 1, port: 12001 });
    expect(() => requireCurrentTunnelPublication(paired, ready)).not.toThrow();
    expect(currentTunnelAuthorizations(paired.endpoint_a_artifact_json).map(item => item.role)).toEqual([0, 1]);
  });
  it("does not silently reverse an independently signed server dial route", () => {
    const { paired } = publication(1, 1, 1), inspected = inspectCurrentTunnelMaterial(paired.endpoint_b_artifact_json, 1);
    expect(inspected.serverLeg).toMatchObject({ dialerRole: 1, listenerRole: 2 });
    expect(() => requireDefaultCurrentTunnelRoute(inspected)).toThrow("other physical directions");
  });
  it("rejects an endpoint-specific replacement of the paired activation", () => {
    const { paired, ready } = publication(1, 0), server = JSON.parse(paired.endpoint_b_artifact_json) as CurrentPoolPeerMaterial;
    const changed = { ...paired, endpoint_b_artifact_json: JSON.stringify({ ...server, activation: b64(Uint8Array.of(9)) }) };
    expect(() => requireCurrentTunnelPublication(changed, ready)).toThrow("same original paired publication");
  });
  it("requires both original logical Grants in each endpoint record", () => {
    const { paired } = publication(1, 1), client = JSON.parse(paired.endpoint_a_artifact_json) as CurrentPoolPeerMaterial;
    expect(() => inspectCurrentTunnelMaterial(JSON.stringify({ ...client, tunnels: [client.tunnels[0]] }), 0)).toThrow("both original logical sides");
  });
  it("does not accept an independently configured carrier that disagrees with the route", () => {
    const { paired, ready } = publication(1, 0);
    expect(() => requireCurrentTunnelPublication(paired, { ...ready, server_carrier: "websocket" })).toThrow("fixed relay deployment");
  });
});
