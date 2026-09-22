import { types } from "node:util";
import { decodeMap, encodeCBOR, mapFromNames, projectMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const own = bytes => { const copy = Buffer.alloc(bytes.length); copy.set(bytes); return copy; };
const fields = (schema, type, map) => Object.fromEntries(Object.entries(schema.frame_maps[type].fields).map(([key, value]) => [value.name, map.get(BigInt(key))]));
const field = (schema, type, name) => Object.values(schema.frame_maps[type].fields).find(value => value.name === name);
const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) ? a.equals(b) : a === b;
const hash = (schema, name, inputs) => own(Buffer.from(evaluateDomain(schema, name, inputs).output_hex, "hex"));

function read(schema, type, input) {
  const view = referenceByteView(input);
  requireThat(view.length <= schema.frame_maps[type].max_encoded_bytes, "hello_input_size");
  const bytes = own(view);
  return { bytes, values: fields(schema, type, decodeMap(schema, type, bytes)) };
}

function capture(input) {
  requireThat(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(input)), "hello_context_object");
  const names = ["attempt_id", "route_allowed_features", "binding_mode", "exporter_bytes"];
  const descriptors = Object.getOwnPropertyDescriptors(input), keys = Reflect.ownKeys(descriptors);
  requireThat(keys.length === names.length && keys.every(key => names.includes(key)), "hello_context_fields");
  const result = Object.create(null);
  for (const name of names) {
    const descriptor = descriptors[name];
    requireThat(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "hello_context_data");
    result[name] = descriptor.value;
  }
  return result;
}

// Structural reference over one original selected attempt and two complete
// hellos. The context is independently fixed by the trusted original owner:
// route_allowed_features is the compiled whole-route/provider/grant/policy
// intersection; binding_mode is the prior permitted common choice; exporter
// bytes come from the actual carrier's specified exporter. These caller values
// are NOT capability evidence, policy authorization or a production owner.
// No signature, CSPRNG, freshness, once, ordering, dispatch or READY authority
// is established. Unknown optional offer bits remain in the full transcript.
export function deriveHelloContextReference(schema, artifactInput, candidateIndex, clientInput, serverInput, contextInput) {
  const context = capture(contextInput);
  const knownFeatures = Object.values(schema.feature_registry).reduce((mask, value) => mask | (1n << BigInt(value.bit)), 0n);
  requireThat(typeof context.route_allowed_features === "bigint" && context.route_allowed_features >= 0n &&
    (context.route_allowed_features & ~knownFeatures) === 0n, "hello_route_features");
  const modes = field(schema, "ServerHello", "binding_mode").enum;
  requireThat(typeof context.binding_mode === "bigint" && Object.values(modes).some(value => BigInt(value) === context.binding_mode), "hello_binding_mode");
  const attempt = referenceByteView(context.attempt_id);
  requireThat(attempt.length === field(schema, "ClientHello", "attempt_id").length, "hello_attempt_size");
  const expectedAttempt = own(attempt);
  const exporter = referenceByteView(context.exporter_bytes);
  const exporterMode = context.binding_mode === BigInt(modes.direct_exporter);
  requireThat(exporter.length === (exporterMode ? field(schema, "TransportContext", "exporter_bytes").max_bytes : 0), "hello_exporter_size");
  const exporterBytes = own(exporter);
  const artifact = read(schema, "Artifact", artifactInput), a = artifact.values;
  const client = read(schema, "ClientHello", clientInput), c = client.values;
  const server = read(schema, "ServerHello", serverInput), s = server.values;
  requireThat(Number.isSafeInteger(candidateIndex) && candidateIndex >= 0 && candidateIndex < a.candidates.length, "hello_candidate_index");
  const candidate = a.candidates[candidateIndex], route = projectMap(schema, "candidate_route", candidate);
  const r = fields(schema, "Route", route);
  const legs = r.path_kind === BigInt(field(schema, "Route", "path_kind").enum.direct) ? [r.direct_leg] : [r.client_leg, r.server_leg];
  const legValues = legs.map(leg => fields(schema, "Leg", leg));
  const artifactDigest = hash(schema, "artifact_digest", { artifact: artifact.bytes });
  const routeDigest = hash(schema, "route_digest", { route: encodeCBOR(route) });
  for (const [name, expected] of Object.entries({ crypto_profile_id: a.crypto_profile_id, artifact_digest: artifactDigest,
    candidate_id: r.candidate_id, route_digest: routeDigest, attempt_id: expectedAttempt, client_nonce: a.session_nonce })) {
    requireThat(same(c[name], expected), "hello_artifact_binding");
  }
  for (const name of ["protocol_id", "profile_revision", "crypto_profile_id", "artifact_digest", "candidate_id", "route_digest", "attempt_id", "client_nonce"]) {
    requireThat(same(s[name], c[name]), "hello_server_echo");
  }
  requireThat(s.binding_mode === context.binding_mode && (c.supported_binding_modes & (1n << context.binding_mode)) !== 0n, "hello_binding_selection");
  let selected = a.allowed_features & c.offered_features & s.server_offered_features & context.route_allowed_features & knownFeatures;
  const resumeBit = 1n << BigInt(schema.feature_registry.application_progress_resume.bit);
  if (!fields(schema, "ResumePolicy", a.resume_policy).enabled) selected &= ~resumeBit;
  const datagramBit = 1n << BigInt(schema.feature_registry.datagram.bit);
  if (legValues.some(leg => leg.carrier === BigInt(field(schema, "Leg", "carrier").enum.websocket))) selected &= ~datagramBit;
  requireThat((a.required_features & ~selected) === 0n, "hello_required_features");
  requireThat(s.selected_features === selected, "hello_feature_selection");
  const helloDigest = hash(schema, "hello_transcript_digest", { client_hello: client.bytes, server_hello: server.bytes });
  const bytes = own(encodeCBOR(mapFromNames(schema, "TransportContext", {
    profile_revision: c.profile_revision, crypto_profile_id: a.crypto_profile_id, access_class: legValues[0].access_class,
    path_kind: r.path_kind, artifact_digest: artifactDigest, route_digest: routeDigest, attempt_id: expectedAttempt,
    session_nonce: a.session_nonce, hello_transcript_digest: helloDigest, selected_features: selected,
    binding_mode: context.binding_mode, exporter_present: exporterMode ? 1n : 0n, exporter_bytes: exporterBytes,
  })));
  // The registry rejects exporter mode on tunnel/local_loopback, as well as
  // any inconsistent mode/presence/length. Never switch modes on failure.
  decodeMap(schema, "TransportContext", bytes);
  return { bytes, hello_transcript_digest: helloDigest,
    transport_context_digest: hash(schema, "transport_context_digest", { context: bytes }),
    selected_features: selected, binding_mode: context.binding_mode };
}

export function verifyHelloContextReference(schema, artifactInput, candidateIndex, clientInput, serverInput, contextInput, receivedInput) {
  const expected = deriveHelloContextReference(schema, artifactInput, candidateIndex, clientInput, serverInput, contextInput);
  const received = referenceByteView(receivedInput);
  requireThat(received.length === expected.bytes.length && received.equals(expected.bytes), "hello_transport_context");
  return expected;
}
