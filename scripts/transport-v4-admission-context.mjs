import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";
import { deriveHelloContextReference } from "./transport-v4-hello-context.mjs";
import { verifyPoolAuthorization } from "./transport-v4-pool.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const own = bytes => { const result = Buffer.alloc(bytes.length); result.set(bytes); return result; };
const fields = (schema, type, map) => Object.fromEntries(Object.entries(schema.frame_maps[type].fields).map(([key, value]) => [value.name, map.get(BigInt(key))]));
const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) ? a.equals(b) : a === b;
const hash = (schema, name, args, context = {}) => own(Buffer.from(evaluateDomain(schema, name, args, context).output_hex, "hex"));

function read(schema, type, input, context = {}) {
  const view = referenceByteView(input);
  requireThat(view.length <= schema.frame_maps[type].max_encoded_bytes, "admission_input_size");
  const bytes = own(view);
  return { bytes, values: fields(schema, type, decodeMap(schema, type, bytes, context)) };
}

function originals(schema, artifactInput, candidateIndex, clientInput, serverInput, helloContext) {
  const artifact = read(schema, "Artifact", artifactInput);
  const hello = deriveHelloContextReference(schema, artifact.bytes, candidateIndex, clientInput, serverInput, helloContext);
  const transport = fields(schema, "TransportContext", decodeMap(schema, "TransportContext", hello.bytes));
  const candidate = fields(schema, "Candidate", artifact.values.candidates[candidateIndex]);
  return { artifact, hello, transport, candidate };
}

function identity(schema, artifact, input, role) {
  const certificate = read(schema, "IdentityCertificate", input), c = certificate.values;
  requireThat(c.role === role && c.tenant_id === artifact.tenant_id && c.audience === artifact.audience &&
    c.crypto_profile_id === artifact.crypto_profile_id, "admission_identity_context");
  return certificate;
}

function request(schema, source, fsbInput, sourceProfile) {
  requireThat(typeof sourceProfile === "string" && schema.external_contexts.activation_source_profile.includes(sourceProfile), "admission_source_profile");
  const { artifact, hello, transport, candidate } = source, a = artifact.values;
  const context = { activation_source_profile: sourceProfile, crypto_profile_id: a.crypto_profile_id };
  const fsb = read(schema, "FSB4", fsbInput, context), f = fsb.values;
  for (const name of ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"]) requireThat(same(f[name], a[name]), "admission_parent_binding");
  for (const name of ["artifact_digest", "route_digest", "attempt_id", "hello_transcript_digest", "selected_features", "binding_mode"]) {
    requireThat(same(f[name], transport[name]), "admission_hello_binding");
  }
  requireThat(same(f.candidate_id, candidate.candidate_id) && same(f.transport_context_digest, hello.transport_context_digest), "admission_hello_binding");
  const client = identity(schema, a, f.client_certificate, 0n);
  const digest = hash(schema, "certificate_digest", { certificate: client.bytes });
  requireThat(same(digest, a.client_identity_digest), "admission_client_digest");
  const proof = read(schema, "ActivationAuthorization", f.activation_authorization, context).values;
  for (const name of ["client_identity_digest", "server_identity_digest", "audience"]) requireThat(same(proof[name], a[name]), "admission_proof_binding");
  requireThat(proof.activation_not_after_ms <= a.initiation_not_after_ms && proof.session_not_after_ms <= a.session_not_after_ms, "admission_proof_deadline");
  if (sourceProfile === "preauthorized_pool") verifyPoolAuthorization(schema, artifact.bytes, fsb.bytes, context);
  return {
    admission_binding: hash(schema, "admission_binding", { fsb: fsb.bytes }, context),
    fsb_digest: hash(schema, "fsb_digest", { fsb: fsb.bytes }, context),
    client_identity_digest: digest,
  };
}

// Structural composition only. Originals and the source profile must be fixed
// by the original owner, with independent signatures/trust/purpose/authority,
// time/revocation and actual carrier checks. These functions do not authenticate
// inputs, create once records, reserve resources or authorize Noise/READY.
// Admission nonce generation/immutability and all phase/dispatch guards remain
// the original live owner's responsibility; a matching digest is not a receipt.
export function verifyAdmissionRequestReference(schema, artifactInput, candidateIndex, clientInput, serverInput, helloContext, fsbInput, sourceProfile) {
  return request(schema, originals(schema, artifactInput, candidateIndex, clientInput, serverInput, helloContext), fsbInput, sourceProfile);
}

// A rejection can arrive for an invalid request. It therefore does not require
// a structurally valid FSB4 or a successful request proof, and never compares
// its zero identity sentinel with the Artifact's admitted server identity.
// The rejection certificate still requires independent expected issuer/trust,
// signature, time and revocation checks beyond the context checks below.
export function verifyAdmissionResponseReference(schema, artifactInput, candidateIndex, clientInput, serverInput, helloContext, fsaInput,
  fsbInput = null, sourceProfile = null) {
  const source = originals(schema, artifactInput, candidateIndex, clientInput, serverInput, helloContext);
  const { artifact, hello, transport } = source, a = artifact.values;
  const fsa = read(schema, "FSA4", fsaInput, { crypto_profile_id: a.crypto_profile_id }), f = fsa.values;
  const server = identity(schema, a, f.server_certificate, 1n);
  for (const name of ["route_digest", "hello_transcript_digest", "selected_features", "binding_mode"]) {
    requireThat(same(f[name], transport[name]), "admission_response_echo");
  }
  // The decoder already enforces the exact status/code/sentinel variants.
  if (f.status === 1n) return { status: "rejected", code: f.code };
  const expected = request(schema, source, fsbInput, sourceProfile);
  requireThat(same(f.admission_binding, expected.admission_binding) && same(f.transport_context_digest, hello.transport_context_digest), "admission_response_binding");
  requireThat(same(f.client_identity_digest, a.client_identity_digest), "admission_response_client");
  const serverDigest = hash(schema, "certificate_digest", { certificate: server.bytes });
  requireThat(same(serverDigest, a.server_identity_digest) && same(serverDigest, f.server_identity_digest), "admission_response_server");
  // Client-side opaque observations only. The server must separately compare
  // epoch/key with its original committed CAS, owner and one-shot start guard.
  return { status: "admitted", code: f.code, server_epoch: f.server_epoch,
    reservation_key: own(f.reservation_key), admission_binding: expected.admission_binding,
    fsb_digest: expected.fsb_digest, fsa_digest: hash(schema, "fsa_digest", { fsa: fsa.bytes }, { crypto_profile_id: a.crypto_profile_id }) };
}
