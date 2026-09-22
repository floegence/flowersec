import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeCBOR, decodeMap, encodeCBOR, projectMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { deriveHelloContextReference } from "./transport-v4-hello-context.mjs";
import { derivePoolSelection } from "./transport-v4-pool.mjs";
import { verifyAdmissionRequestReference, verifyAdmissionResponseReference } from "./transport-v4-admission-context.mjs";

const { schema, files } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const original = id => Buffer.from(corpus.vectors.find(vector => vector.id === id).hex, "hex");
const key = (type, name) => BigInt(Object.entries(schema.frame_maps[type].fields).find(([, value]) => value.name === name)[0]);
const get = (type, map, name) => map.get(key(type, name));
const set = (type, map, changes) => { for (const [name, value] of Object.entries(changes)) map.set(key(type, name), value); };
const hash = (domain, name, map, context = {}) => Buffer.from(evaluateDomain(schema, domain, { [name]: encodeCBOR(map) }, context).output_hex, "hex");
const fail = (run, code) => assert.throws(run, error => error instanceof VectorError && error.code === code);

function fixture(sourceProfile = "live_authority") {
  const context = { activation_source_profile: sourceProfile };
  const artifact = decodeMap(schema, "Artifact", original("artifact_transport_fields"));
  const candidate = get("Artifact", artifact, "candidates")[0];
  const fsb = decodeMap(schema, "FSB4", original("fsb_fields"), { activation_source_profile: "live_authority" });
  const fsa = decodeMap(schema, "FSA4", original("fsa_admitted_fields"));
  const clientCertificate = decodeMap(schema, "IdentityCertificate", get("FSB4", fsb, "client_certificate"));
  const serverCertificate = decodeMap(schema, "IdentityCertificate", get("FSA4", fsa, "server_certificate"));
  set("Artifact", artifact, {
    client_identity_digest: hash("certificate_digest", "certificate", clientCertificate),
    server_identity_digest: hash("certificate_digest", "certificate", serverCertificate),
  });
  const client = decodeMap(schema, "ClientHello", original("client_hello_fields"));
  const server = decodeMap(schema, "ServerHello", original("server_hello_fields"));
  const helloContext = { attempt_id: Buffer.alloc(16, 31), route_allowed_features: 3n, binding_mode: 1n, exporter_bytes: Buffer.alloc(0) };
  const shared = {
    crypto_profile_id: get("Artifact", artifact, "crypto_profile_id"), artifact_digest: hash("artifact_digest", "artifact", artifact),
    candidate_id: get("Candidate", candidate, "candidate_id"), route_digest: hash("route_digest", "route", projectMap(schema, "candidate_route", candidate)),
    attempt_id: helloContext.attempt_id, client_nonce: get("Artifact", artifact, "session_nonce"),
  };
  set("ClientHello", client, shared); set("ServerHello", server, { ...shared, selected_features: 1n, binding_mode: 1n });
  const args = () => [schema, encodeCBOR(artifact), 0, encodeCBOR(client), encodeCBOR(server), helloContext];
  const hello = deriveHelloContextReference(...args());
  const proof = sourceProfile === "preauthorized_pool" ? decodeMap(schema, "ActivationAuthorization", original("activation_pool_fields"), context) : decodeMap(schema, "ActivationAuthorization", get("FSB4", fsb, "activation_authorization"), context);
  set("ActivationAuthorization", proof, {
    tenant_id: get("Artifact", artifact, "tenant_id"), artifact_issuer_key_id: get("Artifact", artifact, "issuer_key_id"),
    lease_id: get("Artifact", artifact, "lease_id"), artifact_digest: shared.artifact_digest, attempt_id: helloContext.attempt_id,
    client_identity_digest: get("Artifact", artifact, "client_identity_digest"), server_identity_digest: get("Artifact", artifact, "server_identity_digest"),
    audience: get("Artifact", artifact, "audience"), issued_at_ms: 2n, activation_not_after_ms: 500000n, session_not_after_ms: 1000000n,
  });
  if (sourceProfile === "preauthorized_pool") {
    const selected = derivePoolSelection(schema, encodeCBOR(artifact), [0, 1]);
    set("PoolSelectionRef", get("ActivationAuthorization", proof, "candidate_selection"), {
      artifact_digest: selected.values.artifact_digest, candidate_indices: [0n, 1n], candidate_set_digest: selected.candidate_set_digest,
    });
    set("ActivationAuthorization", proof, { route_selection: selected.route_set_digest });
  } else set("ActivationAuthorization", proof, { candidate_selection: shared.candidate_id, route_selection: shared.route_digest });
  const commitProof = () => set("FSB4", fsb, { activation_authorization: encodeCBOR(proof) });
  set("FSB4", fsb, {
    artifact_digest: shared.artifact_digest, tenant_id: get("Artifact", artifact, "tenant_id"), issuer_key_id: get("Artifact", artifact, "issuer_key_id"),
    lease_id: get("Artifact", artifact, "lease_id"), session_nonce: get("Artifact", artifact, "session_nonce"), candidate_id: shared.candidate_id,
    route_digest: shared.route_digest, attempt_id: shared.attempt_id, hello_transcript_digest: hello.hello_transcript_digest,
    selected_features: hello.selected_features, binding_mode: hello.binding_mode, transport_context_digest: hello.transport_context_digest,
  });
  commitProof();
  const syncResponse = () => set("FSA4", fsa, { admission_binding: hash("admission_binding", "fsb", fsb, context) });
  set("FSA4", fsa, {
    status: 0n, code: 0n, route_digest: shared.route_digest, hello_transcript_digest: hello.hello_transcript_digest,
    selected_features: hello.selected_features, binding_mode: hello.binding_mode, transport_context_digest: hello.transport_context_digest,
    client_identity_digest: get("Artifact", artifact, "client_identity_digest"), server_identity_digest: get("Artifact", artifact, "server_identity_digest"),
  });
  syncResponse();
  const requestArgs = () => [...args(), encodeCBOR(fsb), sourceProfile];
  const responseArgs = () => [...args(), encodeCBOR(fsa), encodeCBOR(fsb), sourceProfile];
  const reject = () => set("FSA4", fsa, { status: 1n, code: BigInt(Object.values(schema.admission_rejection_codes)[0]), server_epoch: 0n,
    reservation_key: Buffer.alloc(32), admission_binding: Buffer.alloc(32), transport_context_digest: Buffer.alloc(32),
    client_identity_digest: Buffer.alloc(32), server_identity_digest: Buffer.alloc(32) });
  return { artifact, candidate, client, server, helloContext, proof, fsb, fsa, clientCertificate, serverCertificate,
    args, requestArgs, responseArgs, commitProof, syncResponse, reject };
}

test("v4.admission_context.accepted: both immutable source variants bind complete FSB4 and FSA4", () => {
  for (const source of ["live_authority", "preauthorized_pool"]) {
    const f = fixture(source), result = verifyAdmissionRequestReference(...f.requestArgs());
    const bytes = encodeCBOR(f.fsb), prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
    const expected = createHash("sha256").update(Buffer.concat([Buffer.from("flowersec/v4/admission-binding\0"), prefix, bytes])).digest();
    assert.deepEqual(result.admission_binding, expected);
    const response = verifyAdmissionResponseReference(...f.responseArgs());
    assert.equal(response.status, "admitted");
    assert.deepEqual(response.admission_binding, expected);
    assert.equal(response.server_epoch, get("FSA4", f.fsa, "server_epoch"));
    assert.deepEqual(response.reservation_key, get("FSA4", f.fsa, "reservation_key"));
  }
});

test("v4.admission_context.rejected: sentinel replies authenticate no admitted identity or request", () => {
  const f = fixture(); f.reject();
  // A rejection source may have a different valid certificate within the
  // expected issuer/trust/tenant/audience/role/profile. Digest equality is only
  // an admitted condition; independent trust/signatures are not tested here.
  set("IdentityCertificate", f.serverCertificate, { subject_id: "rejection-source", signature: Buffer.alloc(64, 99) });
  set("FSA4", f.fsa, { server_certificate: encodeCBOR(f.serverCertificate) });
  assert.deepEqual(verifyAdmissionResponseReference(...f.args(), encodeCBOR(f.fsa)), { status: "rejected", code: get("FSA4", f.fsa, "code") });
  assert.deepEqual(verifyAdmissionResponseReference(...f.args(), encodeCBOR(f.fsa), Buffer.from([0xff])), { status: "rejected", code: get("FSA4", f.fsa, "code") });
  assert.throws(() => verifyAdmissionResponseReference(...fixture().args(), encodeCBOR(fixture().fsa)), /admission_source_profile/u);
});

test("v4.admission_context.request: FSB4 is checked against the original parent and negotiated context", () => {
  for (const [name, value, code] of [
    ["session_nonce", Buffer.alloc(32, 99), "admission_parent_binding"],
    ["hello_transcript_digest", Buffer.alloc(32, 99), "admission_hello_binding"],
    ["selected_features", 0n, "admission_hello_binding"],
    ["binding_mode", 0n, "admission_hello_binding"],
    ["transport_context_digest", Buffer.alloc(32, 99), "admission_hello_binding"],
  ]) {
    const f = fixture(); set("FSB4", f.fsb, { [name]: value });
    fail(() => verifyAdmissionRequestReference(...f.requestArgs()), code);
  }
  // Preserve the internal FSB/proof equality while substituting the parent.
  for (const [fsbName, proofName, value] of [
    ["issuer_key_id", "artifact_issuer_key_id", Buffer.alloc(16, 99)],
    ["lease_id", "lease_id", Buffer.alloc(16, 99)],
    ["artifact_digest", "artifact_digest", Buffer.alloc(32, 99)],
    ["attempt_id", "attempt_id", Buffer.alloc(16, 99)],
    ["candidate_id", "candidate_selection", Buffer.alloc(16, 99)],
    ["route_digest", "route_selection", Buffer.alloc(32, 99)],
  ]) {
    const f = fixture(); set("FSB4", f.fsb, { [fsbName]: value }); set("ActivationAuthorization", f.proof, { [proofName]: value }); f.commitProof();
    assert.throws(() => verifyAdmissionRequestReference(...f.requestArgs()), /admission_parent_binding|admission_hello_binding/u);
  }
});

test("v4.admission_context.proof: both identities, parent deadlines and original pool membership remain bound", () => {
  for (const source of ["live_authority", "preauthorized_pool"]) {
    for (const name of ["client_identity_digest", "server_identity_digest"]) {
      const f = fixture(source); set("ActivationAuthorization", f.proof, { [name]: Buffer.alloc(32, 99) }); f.commitProof();
      fail(() => verifyAdmissionRequestReference(...f.requestArgs()), "admission_proof_binding");
    }
    for (const changes of [{ activation_not_after_ms: 500001n }, { session_not_after_ms: 1000001n }]) {
      const f = fixture(source); set("ActivationAuthorization", f.proof, changes); f.commitProof();
      fail(() => verifyAdmissionRequestReference(...f.requestArgs()), "admission_proof_deadline");
    }
  }
  const route = fixture("preauthorized_pool");
  set("ActivationAuthorization", route.proof, { route_selection: Buffer.alloc(32, 99) }); route.commitProof();
  fail(() => verifyAdmissionRequestReference(...route.requestArgs()), "pool_route_set_digest");
  const subset = fixture("preauthorized_pool");
  set("PoolSelectionRef", get("ActivationAuthorization", subset.proof, "candidate_selection"), { candidate_indices: [1n] }); subset.commitProof();
  fail(() => verifyAdmissionRequestReference(...subset.requestArgs()), "pool_candidate_set_digest");
  for (const source of ["live_authority", "preauthorized_pool"]) {
    const f = fixture(source), args = f.requestArgs(); args[7] = source === "live_authority" ? "preauthorized_pool" : "live_authority";
    assert.throws(() => verifyAdmissionRequestReference(...args));
    args[7] = "auto"; fail(() => verifyAdmissionRequestReference(...args), "admission_source_profile");
  }
});

test("v4.admission_context.identities: admitted identities use exact complete certificate bytes", () => {
  const client = fixture(); set("IdentityCertificate", client.clientCertificate, { signature: Buffer.alloc(64, 99) });
  set("FSB4", client.fsb, { client_certificate: encodeCBOR(client.clientCertificate) });
  fail(() => verifyAdmissionRequestReference(...client.requestArgs()), "admission_client_digest");
  const server = fixture(); set("IdentityCertificate", server.serverCertificate, { signature: Buffer.alloc(64, 99) });
  set("FSA4", server.fsa, { server_certificate: encodeCBOR(server.serverCertificate) });
  fail(() => verifyAdmissionResponseReference(...server.responseArgs()), "admission_response_server");
  for (const rejected of [false, true]) for (const changes of [{ tenant_id: "another" }, { audience: "another" }]) {
    const f = fixture(); if (rejected) f.reject();
    set("IdentityCertificate", f.serverCertificate, changes); set("FSA4", f.fsa, { server_certificate: encodeCBOR(f.serverCertificate) });
    fail(() => verifyAdmissionResponseReference(...f.responseArgs()), "admission_identity_context");
  }
});

test("v4.admission_context.full_bytes: FSB signature, proof and nonce remain inside admission binding", () => {
  for (const target of ["client_signature", "proof_signature", "admission_nonce"]) {
    const f = fixture(), before = verifyAdmissionRequestReference(...f.requestArgs());
    if (target === "proof_signature") { set("ActivationAuthorization", f.proof, { signature: Buffer.alloc(64, 99) }); f.commitProof(); }
    else set("FSB4", f.fsb, { [target]: Buffer.alloc(target === "admission_nonce" ? 32 : 64, 99) });
    // This reference does not verify signatures or regenerate a local nonce.
    // Changed raw bytes must nevertheless fail an unchanged server binding.
    const after = verifyAdmissionRequestReference(...f.requestArgs());
    assert.notDeepEqual(after.admission_binding, before.admission_binding);
    assert.notDeepEqual(after.fsb_digest, before.fsb_digest);
    fail(() => verifyAdmissionResponseReference(...f.responseArgs()), "admission_response_binding");
  }
  const f = fixture(), first = verifyAdmissionResponseReference(...f.responseArgs());
  set("FSA4", f.fsa, { server_signature: Buffer.alloc(64, 99) });
  assert.notDeepEqual(first.fsa_digest, verifyAdmissionResponseReference(...f.responseArgs()).fsa_digest);
});

test("v4.admission_context.response: admitted response binds request, context and both identity digests", () => {
  for (const [name, code] of [["admission_binding", "admission_response_binding"], ["transport_context_digest", "admission_response_binding"],
    ["client_identity_digest", "admission_response_client"], ["server_identity_digest", "admission_response_server"]]) {
    const f = fixture(); set("FSA4", f.fsa, { [name]: Buffer.alloc(32, 99) });
    fail(() => verifyAdmissionResponseReference(...f.responseArgs()), code);
  }
  for (const rejected of [false, true]) for (const [name, value] of [
    ["route_digest", Buffer.alloc(32, 99)], ["hello_transcript_digest", Buffer.alloc(32, 99)], ["selected_features", 0n], ["binding_mode", 0n],
  ]) {
    const f = fixture(); if (rejected) f.reject(); set("FSA4", f.fsa, { [name]: value });
    fail(() => verifyAdmissionResponseReference(...f.responseArgs()), "admission_response_echo");
  }
});

test("v4.admission_context.sentinels: every rejection sentinel and required field remains exact", () => {
  for (const name of ["reservation_key", "admission_binding", "transport_context_digest", "client_identity_digest", "server_identity_digest"]) {
    for (const value of [Buffer.alloc(32, 99), Buffer.alloc(0)]) {
      const f = fixture(); f.reject(); set("FSA4", f.fsa, { [name]: value });
      assert.throws(() => verifyAdmissionResponseReference(...f.responseArgs()), /variant_zero|field_length/u);
    }
  }
  for (const changes of [{ server_epoch: 1n }, { code: 0n }, { status: 2n }]) {
    const f = fixture(); f.reject(); set("FSA4", f.fsa, changes);
    assert.throws(() => verifyAdmissionResponseReference(...f.responseArgs()));
  }
  const f = fixture(); f.reject(); f.fsa.delete(key("FSA4", "server_certificate"));
  assert.throws(() => verifyAdmissionResponseReference(...f.responseArgs()), /missing_field/u);
});

test("v4.admission_context.inputs: bounded originals and explicit source refuse coercion and hostile byte views", () => {
  const f = fixture();
  for (const [type, position, makeArgs, run] of [["FSB4", 6, f.requestArgs, verifyAdmissionRequestReference], ["FSA4", 6, f.responseArgs, verifyAdmissionResponseReference]]) {
    const args = makeArgs(); args[position] = Buffer.alloc(schema.frame_maps[type].max_encoded_bytes + 1);
    fail(() => run(...args), "admission_input_size");
    const short = makeArgs(); short[position] = short[position].subarray(0, -1);
    assert.throws(() => run(...short), /truncated/u);
  }
  let calls = 0; const trap = () => { calls++; throw new Error("caller hook"); };
  const source = f.requestArgs(); source[7] = { toString: trap };
  fail(() => verifyAdmissionRequestReference(...source), "admission_source_profile");
  for (const [makeArgs, run] of [[f.requestArgs, verifyAdmissionRequestReference], [f.responseArgs, verifyAdmissionResponseReference]]) {
    const args = makeArgs(), input = new Uint8Array(args[6]); Object.setPrototypeOf(input, new Proxy(Uint8Array.prototype, { get: trap, getPrototypeOf: trap }));
    args[6] = input; assert.throws(() => run(...args), TypeError);
  }
  assert.equal(calls, 0);
});

test("v4.admission_context.ownership: returned digests and opaque key have detached exact backing", () => {
  const f = fixture(), request = verifyAdmissionRequestReference(...f.requestArgs()), args = f.responseArgs();
  const result = verifyAdmissionResponseReference(...args), snapshot = Object.fromEntries(Object.entries(result).map(([name, value]) => [name, Buffer.isBuffer(value) ? Buffer.from(value) : value]));
  for (const value of [...Object.values(request), ...Object.values(result)]) if (Buffer.isBuffer(value)) assert.equal(value.buffer.byteLength, value.length);
  for (const value of args) if (Buffer.isBuffer(value)) value.fill(0);
  assert.deepEqual(result, snapshot);
  result.reservation_key.fill(0); assert.deepEqual(result.admission_binding, snapshot.admission_binding);
  assert.equal(decodeCBOR(encodeCBOR(f.fsa)).size, 14);
});
