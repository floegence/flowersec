import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeCBOR, decodeMap, encodeCBOR, projectMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { deriveHelloContextReference, verifyHelloContextReference } from "./transport-v4-hello-context.mjs";

const { schema, files } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const original = id => Buffer.from(corpus.vectors.find(vector => vector.id === id).hex, "hex");
const key = (type, name) => BigInt(Object.entries(schema.frame_maps[type].fields).find(([, value]) => value.name === name)[0]);
const get = (type, map, name) => map.get(key(type, name));
const set = (type, map, changes) => { for (const [name, value] of Object.entries(changes)) map.set(key(type, name), value); };
const hash = (domain, name, map) => Buffer.from(evaluateDomain(schema, domain, { [name]: encodeCBOR(map) }).output_hex, "hex");
const fail = (run, code) => assert.throws(run, error => error instanceof VectorError && error.code === code);
const lp = bytes => { const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length); return Buffer.concat([prefix, bytes]); };

function fixture(kind = "direct", resume = true, mode = 1n) {
  const artifact = decodeMap(schema, "Artifact", original(kind === "local" ? "artifact_local_fields" : resume ? "artifact_execution_fields" : "artifact_transport_fields"));
  set("Artifact", artifact, { required_features: 0n });
  const index = kind === "tunnel" ? 1 : 0;
  const candidate = get("Artifact", artifact, "candidates")[index];
  const client = decodeMap(schema, "ClientHello", original("client_hello_fields"));
  const server = decodeMap(schema, "ServerHello", original("server_hello_fields"));
  const context = { attempt_id: Buffer.alloc(16, 31), route_allowed_features: 3n, binding_mode: mode,
    exporter_bytes: mode === 0n ? Buffer.alloc(32, 32) : Buffer.alloc(0) };
  const selected = kind === "local" ? 0n : (resume ? 2n : 0n) | (kind === "direct" ? 1n : 0n);
  set("ServerHello", server, { selected_features: selected, binding_mode: mode });
  const sync = () => {
    const shared = {
      crypto_profile_id: get("Artifact", artifact, "crypto_profile_id"),
      artifact_digest: hash("artifact_digest", "artifact", artifact),
      candidate_id: get("Candidate", candidate, "candidate_id"),
      route_digest: hash("route_digest", "route", projectMap(schema, "candidate_route", candidate)),
      attempt_id: context.attempt_id, client_nonce: get("Artifact", artifact, "session_nonce"),
    };
    set("ClientHello", client, shared); set("ServerHello", server, shared);
  };
  const args = () => [schema, encodeCBOR(artifact), index, encodeCBOR(client), encodeCBOR(server), context];
  sync();
  return { artifact, candidate, client, server, context, sync, args };
}

test("v4.hello_context.transcript: complete canonical hellos bind independently recomputed context domains", () => {
  for (const [kind, mode, selected, path, access] of [["direct", 0n, 3n, 0n, 0n], ["direct", 1n, 3n, 0n, 0n], ["tunnel", 1n, 2n, 1n, 0n], ["local", 1n, 0n, 0n, 1n]]) {
    const f = fixture(kind, true, mode), result = deriveHelloContextReference(...f.args());
    const hello = createHash("sha256").update(Buffer.concat([Buffer.from("flowersec/v4/hello-transcript\0"), lp(encodeCBOR(f.client)), lp(encodeCBOR(f.server))])).digest();
    const expected = new Map([
      [0n, "4"], [1n, get("Artifact", f.artifact, "crypto_profile_id")], [2n, access], [3n, path],
      [4n, get("ClientHello", f.client, "artifact_digest")], [5n, get("ClientHello", f.client, "route_digest")],
      [6n, f.context.attempt_id], [7n, get("Artifact", f.artifact, "session_nonce")], [8n, hello], [9n, selected],
      [10n, mode], [11n, mode === 0n ? 1n : 0n], [12n, f.context.exporter_bytes],
    ]);
    assert.deepEqual(result.bytes, encodeCBOR(expected));
    assert.deepEqual(result.hello_transcript_digest, hello);
    assert.deepEqual(result.transport_context_digest, createHash("sha256").update(Buffer.concat([Buffer.from("flowersec/v4/transport-context\0"), lp(result.bytes)])).digest());
    assert.deepEqual(verifyHelloContextReference(...f.args(), result.bytes), result);
  }
  const p256 = fixture();
  set("Artifact", p256.artifact, { crypto_profile_id: "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1" });
  p256.sync();
  assert.equal(decodeCBOR(deriveHelloContextReference(...p256.args()).bytes).get(1n), get("Artifact", p256.artifact, "crypto_profile_id"));
});

test("v4.hello_context.features: exact intersection preserves all compatible allowed/offer/route combinations", () => {
  for (const resume of [false, true]) for (let allowed = 0; allowed < 4; allowed++) {
    if (resume && (allowed & 2) === 0) continue; // Enabled policy requires that signed allow bit.
    for (let client = 0; client < 4; client++) for (let server = 0; server < 4; server++) for (let route = 0; route < 4; route++) {
      const f = fixture("direct", resume), expected = BigInt(allowed & client & server & route & (resume ? 3 : 1));
      set("Artifact", f.artifact, { allowed_features: BigInt(allowed) });
      set("ClientHello", f.client, { offered_features: BigInt(client) });
      set("ServerHello", f.server, { server_offered_features: BigInt(server), selected_features: expected });
      f.context.route_allowed_features = BigInt(route); f.sync();
      assert.equal(deriveHelloContextReference(...f.args()).selected_features, expected);
      set("ServerHello", f.server, { selected_features: expected ^ 1n });
      fail(() => deriveHelloContextReference(...f.args()), "hello_feature_selection");
    }
  }
});

test("v4.hello_context.optional: unknown optional bits and hints stay in the complete transcript", () => {
  for (const [type, target, field] of [["ClientHello", "client", "offered_features"], ["ServerHello", "server", "server_offered_features"]]) {
    const f = fixture(), before = deriveHelloContextReference(...f.args());
    set(type, f[target], { [field]: 3n | (1n << 63n) });
    const after = deriveHelloContextReference(...f.args());
    assert.equal(after.selected_features, 3n);
    assert.notDeepEqual(after.hello_transcript_digest, before.hello_transcript_digest);
    assert.notDeepEqual(after.transport_context_digest, before.transport_context_digest);
  }
  for (const [type, target, name] of [["ClientHello", "client", "client_identity_hint"], ["ServerHello", "server", "server_identity_hint"], ["ServerHello", "server", "server_nonce"]]) {
    const f = fixture(), before = deriveHelloContextReference(...f.args());
    set(type, f[target], { [name]: Buffer.alloc(name.endsWith("hint") ? 2048 : 32, 99) });
    const after = deriveHelloContextReference(...f.args());
    assert.notDeepEqual(after.hello_transcript_digest, before.hello_transcript_digest);
  }
});

test("v4.hello_context.required: policy and route filtering never remove a required feature silently", () => {
  for (const kind of ["direct", "tunnel"]) {
    const f = fixture(kind);
    set("Artifact", f.artifact, { required_features: 1n }); f.context.route_allowed_features = 2n; f.sync();
    fail(() => deriveHelloContextReference(...f.args()), "hello_required_features");
  }
  const unknown = fixture();
  set("Artifact", unknown.artifact, { allowed_features: 3n | (1n << 63n), required_features: 1n << 63n }); unknown.sync();
  fail(() => deriveHelloContextReference(...unknown.args()), "hello_required_features");
  const disabled = fixture("direct", false);
  set("ServerHello", disabled.server, { selected_features: 3n });
  fail(() => deriveHelloContextReference(...disabled.args()), "hello_feature_selection");
  const tunnel = fixture("tunnel");
  set("ServerHello", tunnel.server, { selected_features: 3n });
  fail(() => deriveHelloContextReference(...tunnel.args()), "hello_feature_selection");
});

test("v4.hello_context.carriers: datagram selection requires every signed leg to carry it natively", () => {
  const changeCarrier = (leg, name, path) => {
    const value = Object.values(schema.frame_maps.Leg.fields).find(field => field.name === "carrier").enum[name];
    const tuple = schema.carrier_tuples[name][path];
    set("Leg", leg, { carrier: BigInt(value), alpn: tuple.alpn, path: tuple.path, subprotocol: tuple.subprotocol });
    if (name === "raw_quic") leg.delete(key("Leg", "origin_policy"));
  };
  const native = fixture("tunnel");
  changeCarrier(get("Candidate", native.candidate, "client_leg"), "raw_quic", "tunnel");
  set("ServerHello", native.server, { selected_features: 3n }); native.sync();
  assert.equal(deriveHelloContextReference(...native.args()).selected_features, 3n);
  // A whole-route trusted restriction still removes datagram on native legs.
  native.context.route_allowed_features = 2n;
  fail(() => deriveHelloContextReference(...native.args()), "hello_feature_selection");
  const ws = fixture();
  changeCarrier(get("Candidate", ws.candidate, "direct_leg"), "websocket", "direct"); ws.sync();
  fail(() => deriveHelloContextReference(...ws.args()), "hello_feature_selection");
  set("ServerHello", ws.server, { selected_features: 2n });
  assert.equal(deriveHelloContextReference(...ws.args()).selected_features, 2n);
  const wt = fixture("tunnel");
  changeCarrier(get("Candidate", wt.candidate, "client_leg"), "webtransport", "tunnel");
  set("ServerHello", wt.server, { selected_features: 3n }); wt.sync();
  assert.equal(deriveHelloContextReference(...wt.args()).selected_features, 3n);
  // The second leg is equally authoritative; checking only the client leg
  // would incorrectly keep native datagram in this inverse mixed route.
  const reverse = fixture("tunnel");
  changeCarrier(get("Candidate", reverse.candidate, "client_leg"), "raw_quic", "tunnel");
  changeCarrier(get("Candidate", reverse.candidate, "server_leg"), "websocket", "tunnel");
  set("ServerHello", reverse.server, { selected_features: 3n }); reverse.sync();
  fail(() => deriveHelloContextReference(...reverse.args()), "hello_feature_selection");
  set("ServerHello", reverse.server, { selected_features: 2n });
  assert.equal(deriveHelloContextReference(...reverse.args()).selected_features, 2n);
});

test("v4.hello_context.originals: parent signature, candidate, route, attempt, nonce and crypto must match", () => {
  const replacements = { artifact_digest: Buffer.alloc(32, 99), candidate_id: Buffer.alloc(16, 99), route_digest: Buffer.alloc(32, 99),
    attempt_id: Buffer.alloc(16, 99), client_nonce: Buffer.alloc(32, 99), crypto_profile_id: "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1" };
  for (const [name, value] of Object.entries(replacements)) {
    const f = fixture(); set("ClientHello", f.client, { [name]: value });
    fail(() => deriveHelloContextReference(...f.args()), "hello_artifact_binding");
    const echo = fixture(); set("ServerHello", echo.server, { [name]: value });
    fail(() => deriveHelloContextReference(...echo.args()), "hello_server_echo");
  }
  const a = fixture(); set("Artifact", a.artifact, { signature: Buffer.alloc(64, 99) });
  fail(() => deriveHelloContextReference(...a.args()), "hello_artifact_binding");
  const route = fixture(), direct = get("Candidate", route.candidate, "direct_leg");
  set("Leg", direct, { host: "other.example" });
  // Rebind the complete Artifact only, leaving the original selected Route.
  const newDigest = hash("artifact_digest", "artifact", route.artifact);
  set("ClientHello", route.client, { artifact_digest: newDigest }); set("ServerHello", route.server, { artifact_digest: newDigest });
  fail(() => deriveHelloContextReference(...route.args()), "hello_artifact_binding");
  const replay = fixture(); replay.context.attempt_id = Buffer.alloc(16, 99);
  fail(() => deriveHelloContextReference(...replay.args()), "hello_artifact_binding");
});

test("v4.hello_context.binding: original common selection and exact exporter bytes cannot downgrade", () => {
  const f = fixture(); set("ClientHello", f.client, { supported_binding_modes: 1n });
  fail(() => deriveHelloContextReference(...f.args()), "hello_binding_selection");
  const changed = fixture("direct", true, 0n); set("ServerHello", changed.server, { binding_mode: 1n });
  fail(() => deriveHelloContextReference(...changed.args()), "hello_binding_selection");
  for (const kind of ["tunnel", "local"]) fail(() => deriveHelloContextReference(...fixture(kind, true, 0n).args()), "variant_constant");
  for (const [mode, sizes] of [[0n, [0, 31, 33]], [1n, [1, 32]]]) {
    for (const size of sizes) { const f = fixture("direct", true, mode); f.context.exporter_bytes = Buffer.alloc(size); fail(() => deriveHelloContextReference(...f.args()), "hello_exporter_size"); }
  }
  const exporter = fixture("direct", true, 0n), first = deriveHelloContextReference(...exporter.args());
  exporter.context.exporter_bytes = Buffer.alloc(32, 99);
  const second = deriveHelloContextReference(...exporter.args());
  assert.deepEqual(first.hello_transcript_digest, second.hello_transcript_digest);
  assert.notDeepEqual(first.transport_context_digest, second.transport_context_digest);
});

test("v4.hello_context.received: every context field and noncanonical representation is checked without repair", () => {
  const f = fixture(), result = deriveHelloContextReference(...f.args());
  for (const [id, value] of decodeCBOR(result.bytes)) {
    const changed = decodeCBOR(result.bytes);
    changed.set(id, Buffer.isBuffer(value) ? Buffer.alloc(value.length + 1, 99) : typeof value === "bigint" ? value + 1n : "another");
    fail(() => verifyHelloContextReference(...f.args(), encodeCBOR(changed)), "hello_transport_context");
  }
  for (const bytes of [result.bytes.subarray(0, -1), Buffer.concat([result.bytes, Buffer.from([0])]), Buffer.concat([Buffer.from([0xb8, 13]), result.bytes.subarray(1)])]) {
    fail(() => verifyHelloContextReference(...f.args(), bytes), "hello_transport_context");
  }
});

test("v4.hello_context.inputs: malformed context, originals and caller hooks fail before use", () => {
  const f = fixture();
  for (const name of Object.keys(f.context)) { const bad = { ...f.context }; delete bad[name]; const args = f.args(); args[5] = bad; fail(() => deriveHelloContextReference(...args), "hello_context_fields"); }
  for (const value of [-1n, 4n, 3, "3", null]) { const args = f.args(); args[5] = { ...f.context, route_allowed_features: value }; fail(() => deriveHelloContextReference(...args), "hello_route_features"); }
  for (const value of [-1n, 2n, 1, "1", null]) { const args = f.args(); args[5] = { ...f.context, binding_mode: value }; fail(() => deriveHelloContextReference(...args), "hello_binding_mode"); }
  for (const index of [-1, 2, 0.5, NaN, "0", 0n, false]) { const args = f.args(); args[2] = index; fail(() => deriveHelloContextReference(...args), "hello_candidate_index"); }
  for (const [position, type] of [[1, "Artifact"], [3, "ClientHello"], [4, "ServerHello"]]) {
    const args = f.args(); args[position] = Buffer.alloc(schema.frame_maps[type].max_encoded_bytes + 1);
    fail(() => deriveHelloContextReference(...args), "hello_input_size");
    const short = f.args(); short[position] = short[position].subarray(0, -1);
    assert.throws(() => deriveHelloContextReference(...short), /truncated/u);
  }
  let called = 0; const trap = () => { called++; throw new Error("caller hook"); };
  const accessor = { ...f.context }; Object.defineProperty(accessor, "binding_mode", { get: trap });
  const inherited = Object.create(new Proxy(Object.prototype, { getPrototypeOf: trap, get: trap }));
  for (const context of [new Proxy(f.context, { getPrototypeOf: trap, ownKeys: trap, get: trap }), accessor, inherited]) {
    const args = f.args(); args[5] = context;
    assert.throws(() => deriveHelloContextReference(...args), /hello_context_object|hello_context_data/u);
  }
  for (const name of ["attempt_id", "exporter_bytes"]) {
    const bytes = new Uint8Array(f.context[name]); Object.setPrototypeOf(bytes, new Proxy(Uint8Array.prototype, { getPrototypeOf: trap, get: trap }));
    const args = f.args(); args[5] = { ...f.context, [name]: bytes };
    assert.throws(() => deriveHelloContextReference(...args), TypeError);
  }
  assert.equal(called, 0);
});

test("v4.hello_context.ownership: returned public bytes and digests retain no input or sibling backing", () => {
  const f = fixture("direct", true, 0n), args = f.args(), before = args.slice(1, 5).map(value => typeof value === "number" ? value : Buffer.from(value));
  const result = deriveHelloContextReference(...args);
  for (const value of [result.bytes, result.hello_transcript_digest, result.transport_context_digest]) assert.equal(value.buffer.byteLength, value.length);
  assert.notEqual(result.bytes.buffer, result.hello_transcript_digest.buffer);
  const saved = Buffer.from(result.bytes);
  args.slice(1, 5).forEach((value, i) => { if (typeof value !== "number") { assert.deepEqual(value, before[i]); value.fill(0); } });
  f.context.exporter_bytes.fill(0); f.context.attempt_id.fill(0);
  assert.deepEqual(result.bytes, saved);
  result.hello_transcript_digest.fill(0); assert.deepEqual(result.bytes, saved);
});
