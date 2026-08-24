#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const checkOnly = process.argv.length === 3 && process.argv[2] === "--check";
if (process.argv.length > (checkOnly ? 3 : 2)) throw new Error("usage: generate_contract_vectors.mjs [--check]");
const SAFE_MAX = 9_007_199_254_740_991;
const PROFILE = "flowersec/3";
const PIN_A = Buffer.alloc(32, 0x11).toString("base64url");
const PIN_B = Buffer.alloc(32, 0x80).toString("base64url");
const PIN_C = Buffer.from([...Array(32).keys()]).toString("base64url");
const PIN_D = Buffer.from([...Array(32).keys()].reverse()).toString("base64url");
// Raw 0xfb sorts after 0x00, while its canonical base64url '-' prefix sorts first.
const PIN_RAW_HIGH_ASCII_LOW = Buffer.from([0xfb, ...Buffer.alloc(31, 0x44)]).toString("base64url");
const PIN_RAW_LOW_ASCII_HIGH = Buffer.from([0x00, ...Buffer.alloc(31, 0xdd)]).toString("base64url");

function canonicalJSON(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error("non-JCS number");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (typeof value !== "object") throw new Error("non-JCS value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
}

function asciiCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function lp(bytes) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function digest(label, value) {
  const bytes = Buffer.from(typeof value === "string" ? value : canonicalJSON(value));
  return createHash("sha256").update(Buffer.from(label)).update(lp(bytes)).digest();
}

function digestResult(label, value) {
  const canonical = typeof value === "string" ? value : canonicalJSON(value);
  const valueDigest = digest(label, canonical);
  return {
    canonical_json: canonical,
    digest_hex: valueDigest.toString("hex"),
    digest_b64u: valueDigest.toString("base64url"),
  };
}

function write(name, value) {
  const rendered = `${JSON.stringify(value, null, 2)}\n`;
  if (checkOnly) {
    const checkedIn = readFileSync(join(root, name), "utf8");
    if (checkedIn !== rendered) throw new Error(`${name} is not reproducible; regenerate contract vectors`);
    return;
  }
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, name), rendered);
}

function pin(value_b64u, not_after_unix_s) {
  return { algorithm: "sha-256", not_after_unix_s, value_b64u };
}

function pinPolicy(...pins) {
  return {
    mode: "pin",
    pins: [...pins].sort((left, right) =>
      asciiCompare(left.algorithm, right.algorithm) || asciiCompare(left.value_b64u, right.value_b64u)),
  };
}

function sessionProjection(session) {
  return {
    allowed_suites: session.allowed_suites,
    channel_id: session.channel_id,
    default_suite: session.default_suite,
    establish_timeout_seconds: session.establish_timeout_seconds,
    idle_timeout_seconds: session.idle_timeout_seconds,
    max_inbound_streams: session.max_inbound_streams,
    profile: PROFILE,
    rekey_completion_timeout_seconds: session.rekey_completion_timeout_seconds,
    rekey_prepare_timeout_seconds: session.rekey_prepare_timeout_seconds,
    selected_features: session.selected_features,
  };
}

function buildSession() {
  const session = {
    channel_id: "channel-3",
    init_expire_at_unix_s: 2_000_000_000,
    idle_timeout_seconds: 60,
    establish_timeout_seconds: 30,
    rekey_prepare_timeout_seconds: 10,
    rekey_completion_timeout_seconds: 30,
    max_inbound_streams: 64,
    e2ee_psk_b64u: Buffer.from([...Array(32).keys()].map((value) => value + 1)).toString("base64url"),
    allowed_suites: [1, 2],
    default_suite: 1,
    selected_features: 0,
    contract_hash_b64u: "",
  };
  session.contract_hash_b64u = digest(
    "flowersec-v3-session-contract\0",
    sessionProjection(session),
  ).toString("base64url");
  return session;
}

function candidateSet(candidates) {
  const canonical = candidates.map((candidate) => ({
    carrier: candidate.carrier,
    id: candidate.id,
    normalized_url: candidate.normalized_url,
    tls: candidate.tls,
    wire_profile: candidate.wire_profile,
  })).sort((left, right) => asciiCompare(left.id, right.id));
  const result = digestResult("flowersec-v3-candidates\0", canonical);
  return { candidates: canonical, ...result };
}

function fsb3(artifact, chosenCandidateID) {
  const set = candidateSet(artifact.path.candidates);
  const common = {
    candidate_set_hash_b64u: set.digest_b64u,
    candidates: set.candidates,
    channel_id: artifact.session.channel_id,
    chosen_candidate_id: chosenCandidateID,
    listener_audience: artifact.path.listener_audience,
    profile: PROFILE,
    rendezvous_group_id: artifact.path.rendezvous_group_id,
    session_contract_hash_b64u: artifact.session.contract_hash_b64u,
  };
  const payload = artifact.path.kind === "direct"
    ? { ...common, routing_token: artifact.path.routing_token }
    : {
        attach_token: artifact.path.token,
        ...common,
        endpoint_instance_id: artifact.path.local_endpoint_instance_id,
        role: artifact.path.role,
      };
  const payloadBytes = Buffer.from(canonicalJSON(payload));
  const header = Buffer.alloc(12);
  header.write("FSB3", 0, "ascii");
  header[4] = 3;
  header[5] = artifact.path.kind === "direct" ? 1 : 2;
  header.writeUInt16BE(0, 6);
  header.writeUInt32BE(payloadBytes.length, 8);
  return Buffer.concat([header, payloadBytes]);
}

function fsa3(status, reason) {
  const reasonBytes = Buffer.from(reason);
  const frame = Buffer.alloc(8 + reasonBytes.length);
  frame.write("FSA3", 0, "ascii");
  frame[4] = 3;
  frame[5] = status;
  frame.writeUInt16BE(reasonBytes.length, 6);
  reasonBytes.copy(frame, 8);
  return frame.toString("hex");
}

function fsb3Frame(pathCode, payload) {
  const payloadBytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const header = Buffer.alloc(12);
  header.write("FSB3", 0, "ascii");
  header[4] = 3;
  header[5] = pathCode;
  header.writeUInt32BE(payloadBytes.length, 8);
  return Buffer.concat([header, payloadBytes]);
}

function frameNegative(id, kind, value, errorCode) {
  return { id, kind, value_hex: Buffer.from(value).toString("hex"), error_code: errorCode };
}

function payloadWithCanonicalBytes(target) {
  const payload = {};
  for (let index = 0; index < 64; index += 1) {
    const key = `k${String(index).padStart(2, "0")}`;
    payload[key] = "";
    const remaining = target - Buffer.byteLength(canonicalJSON(payload));
    if (remaining >= 0 && remaining <= 1_024) {
      payload[key] = "x".repeat(remaining);
      if (Buffer.byteLength(canonicalJSON(payload)) === target) return payload;
    }
    payload[key] = "x".repeat(1_024);
  }
  throw new Error(`cannot construct scoped payload with ${target} canonical bytes`);
}

function nestedArrayDepth(depth) {
  let value = null;
  for (let index = 1; index < depth; index += 1) value = [value];
  return value;
}

function nodeCountPayload(nodes) {
  if (nodes === 256) return { items: [[...Array(63).fill(null)], [...Array(63).fill(null)], [...Array(62).fill(null)], [...Array(62).fill(null)]] };
  if (nodes === 257) return { items: [[...Array(63).fill(null)], [...Array(63).fill(null)], [...Array(63).fill(null)], [...Array(62).fill(null)]] };
  throw new Error(`unsupported scoped node target ${nodes}`);
}

function artifactVector(kind, selectedCandidates) {
  const session = buildSession();
  const wire = `flowersec-${kind}/3`;
  const suffix = kind === "direct" ? "direct" : "tunnel";
  const candidates = selectedCandidates ?? [
    {
      id: "w-ca",
      carrier: "websocket",
      url: `WSS://EXAMPLE.com:443/flowersec/v3/${suffix}`,
      normalized_url: `wss://example.com/flowersec/v3/${suffix}`,
      wire_profile: wire,
      tls: { mode: "ca" },
    },
    {
      id: "q-pin",
      carrier: "raw_quic",
      url: "quic://[2001:0db8::1]:443/",
      normalized_url: "quic://[2001:db8::1]",
      wire_profile: wire,
      tls: pinPolicy(pin(PIN_A, 2_000_000_100), pin(PIN_B, 2_000_000_200)),
    },
    {
      id: "t-pin",
      carrier: "webtransport",
      url: `https://example.net:443/flowersec/webtransport/v3/${suffix}`,
      normalized_url: `https://example.net/flowersec/webtransport/v3/${suffix}`,
      wire_profile: wire,
      tls: pinPolicy(
        pin(PIN_A, 2_000_000_100),
        pin(PIN_B, 2_000_000_200),
        pin(PIN_RAW_HIGH_ASCII_LOW, 2_000_000_300),
        pin(PIN_RAW_LOW_ASCII_HIGH, 2_000_000_400),
      ),
    },
    {
      id: "w-pin",
      carrier: "websocket",
      url: `wss://pin.example.org/flowersec/v3/${suffix}`,
      normalized_url: `wss://pin.example.org/flowersec/v3/${suffix}`,
      wire_profile: wire,
      tls: pinPolicy(pin(PIN_C, 2_000_000_300)),
    },
  ];
  const path = kind === "direct"
    ? {
        kind,
        rendezvous_group_id: "group-3",
        listener_audience: "listener-3",
        routing_token: "routing-token-v3",
        candidates: candidates.map(({ normalized_url, ...candidate }) => candidate),
      }
    : {
        kind,
        rendezvous_group_id: "group-3",
        listener_audience: "listener-3",
        role: 1,
        local_endpoint_instance_id: "endpoint-client",
        expected_peer_endpoint_instance_id: "endpoint-server",
        token: "attach-token-v3",
        candidates: candidates.map(({ normalized_url, ...candidate }) => candidate),
      };
  const artifact = {
    v: 3,
    profile: PROFILE,
    session,
    path,
    scoped: [{
      scope: "security.context",
      scope_version: 1,
      critical: true,
      payload: {
        "😀": [-SAFE_MAX, SAFE_MAX, true, null, "portable"],
        "\ue000": { nested: "utf16-key-order" },
      },
    }],
    correlation: { v: 3, tags: [{ key: "trace", value: "transport-v3-vector" }] },
  };
  const canonicalSet = candidateSet(candidates);
  const winners = canonicalSet.candidates.map(({ id }) => {
    const frame = fsb3({ ...artifact, path: { ...path, candidates } }, id);
    return {
      candidate_id: id,
      fsb3_hex: frame.toString("hex"),
      admission_binding_hex: createHash("sha256")
        .update(Buffer.from("flowersec-v3-admission\0"))
        .update(frame)
        .digest("hex"),
    };
  });
  const admissions = createHash("sha256").update(Buffer.from("flowersec-v3-acceptor-admissions\0"));
  for (const winner of [...winners].sort((left, right) => asciiCompare(left.candidate_id, right.candidate_id))) {
    admissions.update(lp(Buffer.from(winner.fsb3_hex, "hex")));
  }
  return {
    id: `${kind}-mixed-security`,
    path_kind: kind,
    artifact_json: canonicalJSON(artifact),
    session_canonical_json: canonicalJSON(sessionProjection(session)),
    session_contract_hash_b64u: session.contract_hash_b64u,
    candidates_canonical_json: canonicalSet.canonical_json,
    candidate_set_hash_b64u: canonicalSet.digest_b64u,
    tls_policy_digests: canonicalSet.candidates.map((candidate) => ({
      candidate_id: candidate.id,
      ...digestResult("flowersec-v3-tls-policy\0", candidate.tls),
    })),
    winners,
    acceptor_admissions_hash_hex: admissions.digest("hex"),
  };
}

const direct = artifactVector("direct");
const directObject = JSON.parse(direct.artifact_json);
const baseCandidate = directObject.path.candidates[0];
const directSingle = {
  ...artifactVector("direct", [{
    ...baseCandidate,
    normalized_url: "wss://example.com/flowersec/v3/direct",
  }]),
  id: "direct-single-candidate",
};
const tunnel = artifactVector("tunnel");
const tunnelObject = JSON.parse(tunnel.artifact_json);

function refreshSessionContractHash(artifact) {
  artifact.session.contract_hash_b64u = digest(
    "flowersec-v3-session-contract\0",
    sessionProjection(artifact.session),
  ).toString("base64url");
}

function artifactBoundary(id, source, mutate, accepted = true) {
  const value = structuredClone(source);
  mutate(value);
  if (accepted) refreshSessionContractHash(value);
  return { id, accepted, artifact_json: canonicalJSON(value) };
}

function scopedPayloadBoundary(id, payload, accepted = true, payloadIsRootObject = false) {
  return artifactBoundary(id, directObject, (artifact) => {
    artifact.scoped = [{
      scope: "boundary",
      scope_version: 1,
      critical: true,
      payload: payloadIsRootObject ? payload : { value: payload },
    }];
  }, accepted);
}

function artifactMutation(id, mutate) {
  const value = structuredClone(directObject);
  mutate(value);
  return { id, kind: "artifact_json", value: canonicalJSON(value), error_code: "invalid_artifact" };
}

function rawArtifactMutation(id, mutate) {
  return rawArtifactMutationFrom(id, directObject, mutate);
}

function rawArtifactMutationFrom(id, source, mutate) {
  const value = structuredClone(source);
  mutate(value);
  return { id, kind: "artifact_json", value: canonicalJSON(value), error_code: "invalid_artifact" };
}

function textualArtifactMutation(id, mutate, search, replacement) {
  const value = structuredClone(directObject);
  mutate(value);
  const canonical = canonicalJSON(value);
  if (!canonical.includes(search)) throw new Error(`missing textual mutation source for ${id}`);
  return {
    id,
    kind: "artifact_json",
    value: canonical.replace(search, replacement),
    error_code: "invalid_artifact",
  };
}

const directFrame = Buffer.from(direct.winners.find(({ candidate_id }) => candidate_id === "w-ca").fsb3_hex, "hex");
const tunnelFrame = Buffer.from(tunnel.winners.find(({ candidate_id }) => candidate_id === "q-pin").fsb3_hex, "hex");
const directPayload = JSON.parse(directFrame.subarray(12).toString("utf8"));
const directPayloadBytes = directFrame.subarray(12);

function mutateFrameHeader(source, mutate) {
  const value = Buffer.from(source);
  mutate(value);
  return value;
}

function mutateFSB3Payload(id, mutate) {
  const value = structuredClone(directPayload);
  mutate(value);
  return frameNegative(id, "fsb3", fsb3Frame(1, canonicalJSON(value)), "invalid_fsb3");
}

const invalidUTF8FSB3Payload = Buffer.from(directPayloadBytes);
invalidUTF8FSB3Payload[invalidUTF8FSB3Payload.indexOf(Buffer.from("flowersec/3"))] = 0xff;
const invalidUTF8Artifact = Buffer.from(direct.artifact_json);
invalidUTF8Artifact[invalidUTF8Artifact.indexOf(Buffer.from("flowersec/3"))] = 0xff;

const fsb3Negative = [
  frameNegative("fsb3-v2-magic", "fsb3", mutateFrameHeader(directFrame, (value) => { value[3] = 0x32; }), "invalid_fsb3"),
  frameNegative("fsb3-v2-version", "fsb3", mutateFrameHeader(directFrame, (value) => { value[4] = 2; }), "invalid_fsb3"),
  frameNegative("fsb3-direct-payload-tunnel-variant", "fsb3", mutateFrameHeader(directFrame, (value) => { value[5] = 2; }), "invalid_fsb3"),
  frameNegative("fsb3-tunnel-payload-direct-variant", "fsb3", mutateFrameHeader(tunnelFrame, (value) => { value[5] = 1; }), "invalid_fsb3"),
  frameNegative("fsb3-unknown-path-code", "fsb3", mutateFrameHeader(directFrame, (value) => { value[5] = 3; }), "invalid_fsb3"),
  frameNegative("fsb3-reserved-nonzero", "fsb3", mutateFrameHeader(directFrame, (value) => { value[7] = 1; }), "invalid_fsb3"),
  frameNegative("fsb3-zero-payload", "fsb3", fsb3Frame(1, Buffer.alloc(0)), "invalid_fsb3"),
  frameNegative("fsb3-declared-payload-too-large", "fsb3", mutateFrameHeader(fsb3Frame(1, Buffer.from("{}")), (value) => { value.writeUInt32BE(32_769, 8); }), "fsb3_payload_too_large"),
  frameNegative("fsb3-trailing-byte", "fsb3", Buffer.concat([directFrame, Buffer.from([0])]), "invalid_fsb3"),
  frameNegative("fsb3-invalid-utf8", "fsb3", fsb3Frame(1, invalidUTF8FSB3Payload), "invalid_fsb3"),
  mutateFSB3Payload("fsb3-missing-field", (value) => { delete value.chosen_candidate_id; }),
  mutateFSB3Payload("fsb3-unknown-field", (value) => { value.future = true; }),
  frameNegative(
    "fsb3-duplicate-key",
    "fsb3",
    fsb3Frame(1, directPayloadBytes.toString("utf8").replace('"profile":"flowersec/3"', '"profile":"flowersec/3","profile":"flowersec/3"')),
    "invalid_fsb3",
  ),
  frameNegative("fsb3-non-jcs", "fsb3", fsb3Frame(1, JSON.stringify(directPayload, null, 1)), "noncanonical_fsb3"),
];

const fsa3Negative = [
  frameNegative("fsa3-v2-magic", "fsa3", mutateFrameHeader(Buffer.from(fsa3(1, "invalid_token"), "hex"), (value) => { value[3] = 0x32; }), "invalid_fsa3"),
  frameNegative("fsa3-v2-version", "fsa3", mutateFrameHeader(Buffer.from(fsa3(1, "invalid_token"), "hex"), (value) => { value[4] = 2; }), "invalid_fsa3"),
  frameNegative("fsa3-unknown-status", "fsa3", Buffer.from(fsa3(3, "invalid_token"), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-success-with-reason", "fsa3", Buffer.from(fsa3(0, "invalid_token"), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-reject-empty-reason", "fsa3", Buffer.from(fsa3(1, ""), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-invalid-reason-lead", "fsa3", Buffer.from(fsa3(1, "1invalid"), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-invalid-reason-character", "fsa3", Buffer.from(fsa3(1, "invalid-token"), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-forbidden-tls-reason", "fsa3", Buffer.from(fsa3(1, "tls_pin_mismatch"), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-expired-artifact-reject-status", "fsa3", Buffer.from(fsa3(1, "expired_artifact"), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-reason-too-long", "fsa3", Buffer.from(fsa3(1, "a".repeat(65)), "hex"), "invalid_fsa3"),
  frameNegative("fsa3-trailing-byte", "fsa3", Buffer.concat([Buffer.from(fsa3(1, "invalid_token"), "hex"), Buffer.from([0])]), "invalid_fsa3"),
  frameNegative("fsa3-invalid-utf8", "fsa3", Buffer.from([0x46, 0x53, 0x41, 0x33, 3, 1, 0, 1, 0xff]), "invalid_fsa3"),
  frameNegative("fsa3-truncated-reason", "fsa3", Buffer.from([0x46, 0x53, 0x41, 0x33, 3, 1, 0, 2, 0x61]), "invalid_fsa3"),
];

const artifactVectors = {
  version: 3,
  profile: PROFILE,
  source: {
    producer: "testdata/transport_v3/generate_contract_vectors.mjs",
    design_sha256: "236b332e6cf2f755b918721c8535191b2f8c8861bc32c07da329f823c1f04eba",
  },
  constants: {
    maximum_safe_integer: SAFE_MAX,
    tls_policy_digest_label: "flowersec-v3-tls-policy\u0000",
    candidate_set_digest_label: "flowersec-v3-candidates\u0000",
    admission_binding_label: "flowersec-v3-admission\u0000",
    acceptor_admissions_label: "flowersec-v3-acceptor-admissions\u0000",
  },
  positive: [direct, tunnel, directSingle],
  scalar_boundaries: [
    artifactBoundary("session-channel-id-min", directObject, (artifact) => { artifact.session.channel_id = "a"; }),
    artifactBoundary("session-channel-id-max", directObject, (artifact) => { artifact.session.channel_id = "a".repeat(128); }),
    artifactBoundary("session-init-expiry-min", directObject, (artifact) => { artifact.session.init_expire_at_unix_s = 1; }),
    artifactBoundary("session-init-expiry-max", directObject, (artifact) => { artifact.session.init_expire_at_unix_s = SAFE_MAX; }),
    artifactBoundary("session-idle-timeout-min", directObject, (artifact) => { artifact.session.idle_timeout_seconds = 0; }),
    artifactBoundary("session-idle-timeout-max", directObject, (artifact) => { artifact.session.idle_timeout_seconds = 4_294_967_295; }),
    artifactBoundary("session-max-inbound-streams-min", directObject, (artifact) => { artifact.session.max_inbound_streams = 1; }),
    artifactBoundary("session-max-inbound-streams-max", directObject, (artifact) => { artifact.session.max_inbound_streams = 128; }),
    artifactBoundary("session-single-suite", directObject, (artifact) => { artifact.session.allowed_suites = [1]; artifact.session.default_suite = 1; }),
    artifactBoundary("session-default-suite-two", directObject, (artifact) => { artifact.session.default_suite = 2; }),
    artifactBoundary("direct-registry-identifiers-min", directObject, (artifact) => {
      artifact.path.rendezvous_group_id = "a";
      artifact.path.listener_audience = "b";
    }),
    artifactBoundary("direct-registry-identifiers-max", directObject, (artifact) => {
      artifact.path.rendezvous_group_id = "a".repeat(128);
      artifact.path.listener_audience = "b".repeat(128);
    }),
    artifactBoundary("direct-routing-token-min", directObject, (artifact) => { artifact.path.routing_token = "a"; }),
    artifactBoundary("direct-routing-token-max", directObject, (artifact) => { artifact.path.routing_token = "a".repeat(8_192); }),
    artifactBoundary("tunnel-role-min-identifiers-token", tunnelObject, (artifact) => {
      artifact.path.role = 1;
      artifact.path.rendezvous_group_id = "a";
      artifact.path.listener_audience = "b";
      artifact.path.local_endpoint_instance_id = "c";
      artifact.path.expected_peer_endpoint_instance_id = "d";
      artifact.path.token = "e";
    }),
    artifactBoundary("tunnel-role-max-identifiers-token", tunnelObject, (artifact) => {
      artifact.path.role = 2;
      artifact.path.rendezvous_group_id = "a".repeat(128);
      artifact.path.listener_audience = "b".repeat(128);
      artifact.path.local_endpoint_instance_id = "c".repeat(128);
      artifact.path.expected_peer_endpoint_instance_id = "d".repeat(128);
      artifact.path.token = "e".repeat(8_192);
    }),
    artifactBoundary("candidate-id-min", directObject, (artifact) => { artifact.path.candidates[0].id = "a"; }),
    artifactBoundary("candidate-id-max", directObject, (artifact) => { artifact.path.candidates[0].id = "a".repeat(64); }),
    artifactBoundary("candidate-longest-dns-host", directObject, (artifact) => {
      const host = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(57), "com"].join(".");
      artifact.path.candidates[0].url = `wss://${host}/flowersec/v3/direct`;
    }),
    artifactBoundary("scope-name-version-critical-min", directObject, (artifact) => {
      artifact.scoped = [{ scope: "a", scope_version: 1, critical: false, payload: {} }];
    }),
    artifactBoundary("scope-name-version-critical-max", directObject, (artifact) => {
      artifact.scoped = [{ scope: `a${"b".repeat(63)}`, scope_version: 65_535, critical: true, payload: {} }];
    }),
    artifactBoundary("scope-count-zero", directObject, (artifact) => { artifact.scoped = []; }),
    artifactBoundary("scope-count-eight", directObject, (artifact) => {
      artifact.scoped = Array.from({ length: 8 }, (_, index) => ({ scope: `s${index}`, scope_version: 1, critical: false, payload: {} }));
    }),
    artifactBoundary("correlation-tags-zero", directObject, (artifact) => { artifact.correlation.tags = []; }),
    artifactBoundary("correlation-key-value-min", directObject, (artifact) => { artifact.correlation.tags = [{ key: "a", value: "b" }]; }),
    artifactBoundary("correlation-key-value-max", directObject, (artifact) => {
      artifact.correlation.tags = [{ key: `a${"b".repeat(31)}`, value: "c".repeat(128) }];
    }),
    artifactBoundary("correlation-tags-eight", directObject, (artifact) => {
      artifact.correlation.tags = Array.from({ length: 8 }, (_, index) => ({ key: `k${index}`, value: `v${index}` }));
    }),
  ],
  scalar_coverage: {
    "artifact.v": ["direct-mixed-security", "artifact-wrong-version"],
    "artifact.profile": ["direct-mixed-security", "v2-profile-cross-version"],
    "session.channel_id": ["session-channel-id-min", "session-channel-id-max", "session-channel-empty", "session-channel-invalid-character", "session-channel-non-ascii", "session-channel-too-long"],
    "session.init_expire_at_unix_s": ["session-init-expiry-min", "session-init-expiry-max", "session-init-expiry-zero"],
    "session.idle_timeout_seconds": ["session-idle-timeout-min", "session-idle-timeout-max", "session-idle-timeout-negative", "session-idle-timeout-too-large"],
    "session.establish_timeout_seconds": ["direct-mixed-security", "session-establish-timeout-not-fixed"],
    "session.rekey_prepare_timeout_seconds": ["direct-mixed-security", "session-rekey-prepare-not-fixed"],
    "session.rekey_completion_timeout_seconds": ["direct-mixed-security", "session-rekey-completion-not-fixed"],
    "session.max_inbound_streams": ["session-max-inbound-streams-min", "session-max-inbound-streams-max", "session-max-inbound-zero", "session-max-inbound-too-large"],
    "session.e2ee_psk_b64u": ["direct-mixed-security", "session-psk-wrong-length", "session-psk-padded"],
    "session.default_suite": ["session-single-suite", "session-default-suite-two", "session-default-not-allowed"],
    "session.selected_features": ["direct-mixed-security", "session-features-not-zero"],
    "session.contract_hash_b64u": ["direct-mixed-security", "session-contract-hash-mismatch"],
    "path.rendezvous_group_id": ["direct-registry-identifiers-min", "direct-registry-identifiers-max", "direct-rendezvous-group-empty", "direct-rendezvous-group-invalid-character", "direct-rendezvous-group-too-long", "direct-rendezvous-group-non-ascii"],
    "path.listener_audience": ["direct-registry-identifiers-min", "direct-registry-identifiers-max", "direct-listener-audience-empty", "direct-listener-audience-invalid-character", "direct-listener-audience-too-long", "direct-listener-audience-non-ascii"],
    "path.routing_token": ["direct-routing-token-min", "direct-routing-token-max", "direct-routing-token-empty", "direct-routing-token-too-long", "direct-routing-token-non-ascii"],
    "path.role": ["tunnel-role-min-identifiers-token", "tunnel-role-max-identifiers-token", "direct-cross-variant-role", "tunnel-role-zero", "tunnel-role-three"],
    "path.local_endpoint_instance_id": ["tunnel-role-min-identifiers-token", "tunnel-role-max-identifiers-token", "tunnel-local-endpoint-empty", "tunnel-local-endpoint-invalid-character", "tunnel-local-endpoint-too-long", "tunnel-local-endpoint-non-ascii", "tunnel-endpoint-identifiers-equal"],
    "path.expected_peer_endpoint_instance_id": ["tunnel-role-min-identifiers-token", "tunnel-role-max-identifiers-token", "tunnel-peer-endpoint-empty", "tunnel-peer-endpoint-invalid-character", "tunnel-peer-endpoint-too-long", "tunnel-peer-endpoint-non-ascii", "tunnel-endpoint-identifiers-equal"],
    "path.token": ["tunnel-role-min-identifiers-token", "tunnel-role-max-identifiers-token", "tunnel-token-empty", "tunnel-token-too-long", "tunnel-token-non-ascii"],
    "path.kind": ["direct-mixed-security", "tunnel-mixed-security", "v2-path-cross-version", "path-kind-unknown"],
    "candidate.id": ["candidate-id-min", "candidate-id-max", "candidate-id-empty", "candidate-id-invalid-character"],
    "candidate.carrier": ["direct-mixed-security", "candidate-carrier-unknown"],
    "candidate.url": ["direct-mixed-security", "candidate-longest-dns-host", "candidate-url-query"],
    "candidate.wire_profile": ["direct-mixed-security", "tunnel-mixed-security", "candidate-wire-profile-mismatch"],
    "scope.scope": ["scope-name-version-critical-min", "scope-name-version-critical-max", "scope-name-invalid"],
    "scope.scope_version": ["scope-name-version-critical-min", "scope-name-version-critical-max", "scope-version-zero"],
    "scope.critical": ["scope-name-version-critical-min", "scope-name-version-critical-max"],
    "correlation.v": ["direct-mixed-security", "correlation-wrong-version", "correlation-version-noninteger"],
    "correlation.tags[].key": ["correlation-key-value-min", "correlation-key-value-max", "correlation-tag-empty-key", "correlation-tag-invalid-key", "correlation-tag-key-too-long", "correlation-tag-key-non-ascii"],
    "correlation.tags[].value": ["correlation-key-value-min", "correlation-key-value-max", "correlation-tag-empty-value", "correlation-tag-value-too-long", "correlation-tag-value-non-ascii"],
  },
  scoped_payload_boundaries: [
    scopedPayloadBoundary("scope-payload-canonical-bytes-max", payloadWithCanonicalBytes(4_096), true, true),
    scopedPayloadBoundary("scope-payload-canonical-bytes-over", payloadWithCanonicalBytes(4_097), false, true),
    scopedPayloadBoundary("scope-payload-depth-max", nestedArrayDepth(15)),
    scopedPayloadBoundary("scope-payload-depth-over", nestedArrayDepth(16), false),
    scopedPayloadBoundary("scope-payload-nodes-max", nodeCountPayload(256), true, true),
    scopedPayloadBoundary("scope-payload-nodes-over", nodeCountPayload(257), false, true),
    scopedPayloadBoundary("scope-payload-object-members-max", Object.fromEntries(Array.from({ length: 64 }, (_, index) => [`k${String(index).padStart(2, "0")}`, null])), true, true),
    scopedPayloadBoundary("scope-payload-object-members-over", Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`k${String(index).padStart(2, "0")}`, null])), false, true),
    scopedPayloadBoundary("scope-payload-key-order-utf16", { "\uE000": 2, "😀": 1, a: 3 }, true, true),
    scopedPayloadBoundary("scope-payload-array-items-max", Array(64).fill(null)),
    scopedPayloadBoundary("scope-payload-array-items-over", Array(65).fill(null), false),
    scopedPayloadBoundary("scope-payload-key-bytes-max", { [`a${"b".repeat(127)}`]: null }, true, true),
    scopedPayloadBoundary("scope-payload-key-bytes-over", { [`a${"b".repeat(128)}`]: null }, false, true),
    scopedPayloadBoundary("scope-payload-string-bytes-max", "a".repeat(1_024)),
    scopedPayloadBoundary("scope-payload-string-bytes-over", "a".repeat(1_025), false),
    scopedPayloadBoundary("scope-payload-signed-safe-integer-min", -SAFE_MAX),
    scopedPayloadBoundary("scope-payload-signed-safe-integer-max", SAFE_MAX),
  ],
  artifact_byte_negative: [
    frameNegative("artifact-invalid-utf8", "artifact", invalidUTF8Artifact, "invalid_artifact"),
    frameNegative("artifact-trailing-byte", "artifact", Buffer.concat([Buffer.from(direct.artifact_json), Buffer.from([0x20])]), "invalid_artifact"),
  ],
  fsb3_negative: fsb3Negative,
  fsa3_negative: fsa3Negative,
  active_pin_snapshots: [
    {
      id: "single-pin-expired-exclusive-boundary",
      attempt_now: 2_000_000_100,
      declared: pinPolicy(pin(PIN_A, 2_000_000_100)),
      active_value_b64u: [],
      result: "tls_policy_expired",
    },
    {
      id: "overlap-both-active",
      attempt_now: 2_000_000_000,
      declared: pinPolicy(pin(PIN_A, 2_000_000_100), pin(PIN_B, 2_000_000_200)),
      active_value_b64u: [PIN_A, PIN_B].sort(),
      result: "attempt",
    },
    {
      id: "old-expired-new-active",
      attempt_now: 2_000_000_100,
      declared: pinPolicy(pin(PIN_A, 2_000_000_100), pin(PIN_B, 2_000_000_200)),
      active_value_b64u: [PIN_B],
      result: "attempt",
    },
    {
      id: "all-expired-exclusive-boundary",
      attempt_now: 2_000_000_200,
      declared: pinPolicy(pin(PIN_A, 2_000_000_100), pin(PIN_B, 2_000_000_200)),
      active_value_b64u: [],
      result: "tls_policy_expired",
    },
  ],
  fsa3: [
    { id: "success", status: 0, reason: "", frame_hex: fsa3(0, "") },
    { id: "reject-invalid-token", status: 1, reason: "invalid_token", frame_hex: fsa3(1, "invalid_token") },
    { id: "retry-capacity", status: 2, reason: "capacity", frame_hex: fsa3(2, "capacity") },
    { id: "retry-expired-artifact", status: 2, reason: "expired_artifact", frame_hex: fsa3(2, "expired_artifact") },
  ],
  negative: [
    {
      id: "artifact-duplicate-profile",
      kind: "artifact_json",
      value: direct.artifact_json.replace('"profile":"flowersec/3"', '"profile":"flowersec/3","profile":"flowersec/3"'),
      error_code: "invalid_artifact",
    },
    artifactMutation("candidate-missing-tls", (artifact) => { delete artifact.path.candidates[0].tls; }),
    artifactMutation("candidate-unknown-tls-mode", (artifact) => { artifact.path.candidates[0].tls.mode = "tofu"; }),
    artifactMutation("candidate-ca-extra-pins", (artifact) => { artifact.path.candidates[0].tls.pins = []; }),
    artifactMutation("pin-unknown-algorithm", (artifact) => { artifact.path.candidates[1].tls.pins[0].algorithm = "sha-512"; }),
    artifactMutation("pin-padded-base64url", (artifact) => { artifact.path.candidates[1].tls.pins[0].value_b64u += "="; }),
    artifactMutation("pin-not-sorted", (artifact) => { artifact.path.candidates[1].tls.pins.reverse(); }),
    artifactMutation("pin-duplicate", (artifact) => { artifact.path.candidates[1].tls.pins[1] = artifact.path.candidates[1].tls.pins[0]; }),
    artifactMutation("same-endpoint-ca-pin", (artifact) => {
      artifact.path.candidates.push({ ...baseCandidate, id: "same-pin", tls: pinPolicy(pin(PIN_D, 2_000_000_400)) });
    }),
    artifactMutation("v2-profile-cross-version", (artifact) => { artifact.profile = "flowersec/2"; }),
    artifactMutation("v2-path-cross-version", (artifact) => {
      artifact.path.candidates[0].url = "wss://example.com/flowersec/v2/direct";
    }),
    artifactMutation("candidate-unknown-field", (artifact) => { artifact.path.candidates[0].priority = 1; }),
    rawArtifactMutation("artifact-missing-version", (artifact) => { delete artifact.v; }),
    rawArtifactMutation("artifact-unknown-field", (artifact) => { artifact.future = true; }),
    rawArtifactMutation("artifact-wrong-version", (artifact) => { artifact.v = 2; }),
    rawArtifactMutation("session-channel-empty", (artifact) => { artifact.session.channel_id = ""; }),
    rawArtifactMutation("session-channel-invalid-character", (artifact) => { artifact.session.channel_id = "channel/3"; }),
    rawArtifactMutation("session-channel-non-ascii", (artifact) => { artifact.session.channel_id = "caf\u00e9"; }),
    rawArtifactMutation("session-channel-too-long", (artifact) => { artifact.session.channel_id = "a".repeat(129); }),
    rawArtifactMutation("session-init-expiry-zero", (artifact) => { artifact.session.init_expire_at_unix_s = 0; }),
    rawArtifactMutation("session-idle-timeout-negative", (artifact) => { artifact.session.idle_timeout_seconds = -1; }),
    rawArtifactMutation("session-idle-timeout-too-large", (artifact) => { artifact.session.idle_timeout_seconds = 4_294_967_296; }),
    rawArtifactMutation("session-establish-timeout-not-fixed", (artifact) => { artifact.session.establish_timeout_seconds = 29; }),
    rawArtifactMutation("session-rekey-prepare-not-fixed", (artifact) => { artifact.session.rekey_prepare_timeout_seconds = 11; }),
    rawArtifactMutation("session-rekey-completion-not-fixed", (artifact) => { artifact.session.rekey_completion_timeout_seconds = 31; }),
    rawArtifactMutation("session-max-inbound-zero", (artifact) => { artifact.session.max_inbound_streams = 0; }),
    rawArtifactMutation("session-max-inbound-too-large", (artifact) => { artifact.session.max_inbound_streams = 129; }),
    rawArtifactMutation("session-psk-wrong-length", (artifact) => { artifact.session.e2ee_psk_b64u = Buffer.alloc(31).toString("base64url"); }),
    rawArtifactMutation("session-psk-padded", (artifact) => { artifact.session.e2ee_psk_b64u += "="; }),
    rawArtifactMutation("session-suite-empty", (artifact) => { artifact.session.allowed_suites = []; }),
    rawArtifactMutation("session-suite-not-sorted", (artifact) => { artifact.session.allowed_suites = [2, 1]; }),
    rawArtifactMutation("session-suite-duplicate", (artifact) => { artifact.session.allowed_suites = [1, 1]; }),
    rawArtifactMutation("session-suite-unknown", (artifact) => { artifact.session.allowed_suites = [1, 3]; }),
    rawArtifactMutation("session-default-not-allowed", (artifact) => { artifact.session.default_suite = 3; }),
    rawArtifactMutation("session-features-not-zero", (artifact) => { artifact.session.selected_features = 1; }),
    rawArtifactMutation("session-contract-hash-mismatch", (artifact) => { artifact.session.contract_hash_b64u = Buffer.alloc(32).toString("base64url"); }),
    rawArtifactMutation("direct-routing-token-empty", (artifact) => { artifact.path.routing_token = ""; }),
    rawArtifactMutation("direct-routing-token-too-long", (artifact) => { artifact.path.routing_token = "a".repeat(8_193); }),
    rawArtifactMutation("direct-routing-token-non-ascii", (artifact) => { artifact.path.routing_token = "route-\u00e9"; }),
    rawArtifactMutation("direct-rendezvous-group-empty", (artifact) => { artifact.path.rendezvous_group_id = ""; }),
    rawArtifactMutation("direct-rendezvous-group-invalid-character", (artifact) => { artifact.path.rendezvous_group_id = "group/3"; }),
    rawArtifactMutation("direct-rendezvous-group-too-long", (artifact) => { artifact.path.rendezvous_group_id = "a".repeat(129); }),
    rawArtifactMutation("direct-rendezvous-group-non-ascii", (artifact) => { artifact.path.rendezvous_group_id = "\u7fa4\u7ec4"; }),
    rawArtifactMutation("direct-listener-audience-empty", (artifact) => { artifact.path.listener_audience = ""; }),
    rawArtifactMutation("direct-listener-audience-invalid-character", (artifact) => { artifact.path.listener_audience = "listener/3"; }),
    rawArtifactMutation("direct-listener-audience-too-long", (artifact) => { artifact.path.listener_audience = "a".repeat(129); }),
    rawArtifactMutation("direct-listener-audience-non-ascii", (artifact) => { artifact.path.listener_audience = "\u76d1\u542c"; }),
    rawArtifactMutation("direct-cross-variant-role", (artifact) => { artifact.path.role = 1; }),
    rawArtifactMutationFrom("tunnel-role-zero", tunnelObject, (artifact) => { artifact.path.role = 0; }),
    rawArtifactMutationFrom("tunnel-role-three", tunnelObject, (artifact) => { artifact.path.role = 3; }),
    rawArtifactMutationFrom("tunnel-local-endpoint-empty", tunnelObject, (artifact) => { artifact.path.local_endpoint_instance_id = ""; }),
    rawArtifactMutationFrom("tunnel-local-endpoint-invalid-character", tunnelObject, (artifact) => { artifact.path.local_endpoint_instance_id = "endpoint/client"; }),
    rawArtifactMutationFrom("tunnel-local-endpoint-too-long", tunnelObject, (artifact) => { artifact.path.local_endpoint_instance_id = "a".repeat(129); }),
    rawArtifactMutationFrom("tunnel-local-endpoint-non-ascii", tunnelObject, (artifact) => { artifact.path.local_endpoint_instance_id = "\u672c\u5730"; }),
    rawArtifactMutationFrom("tunnel-peer-endpoint-empty", tunnelObject, (artifact) => { artifact.path.expected_peer_endpoint_instance_id = ""; }),
    rawArtifactMutationFrom("tunnel-peer-endpoint-invalid-character", tunnelObject, (artifact) => { artifact.path.expected_peer_endpoint_instance_id = "endpoint/server"; }),
    rawArtifactMutationFrom("tunnel-peer-endpoint-too-long", tunnelObject, (artifact) => { artifact.path.expected_peer_endpoint_instance_id = "a".repeat(129); }),
    rawArtifactMutationFrom("tunnel-peer-endpoint-non-ascii", tunnelObject, (artifact) => { artifact.path.expected_peer_endpoint_instance_id = "\u8fdc\u7aef"; }),
    rawArtifactMutationFrom("tunnel-endpoint-identifiers-equal", tunnelObject, (artifact) => {
      artifact.path.expected_peer_endpoint_instance_id = artifact.path.local_endpoint_instance_id;
    }),
    rawArtifactMutationFrom("tunnel-token-empty", tunnelObject, (artifact) => { artifact.path.token = ""; }),
    rawArtifactMutationFrom("tunnel-token-too-long", tunnelObject, (artifact) => { artifact.path.token = "a".repeat(8_193); }),
    rawArtifactMutationFrom("tunnel-token-non-ascii", tunnelObject, (artifact) => { artifact.path.token = "attach-\u00e9"; }),
    rawArtifactMutation("path-kind-unknown", (artifact) => { artifact.path.kind = "other"; }),
    rawArtifactMutation("candidate-count-zero", (artifact) => { artifact.path.candidates = []; }),
    rawArtifactMutation("candidate-count-five", (artifact) => {
      artifact.path.candidates.push({ ...artifact.path.candidates[0], id: "extra", url: "wss://extra.example/flowersec/v3/direct" });
    }),
    rawArtifactMutation("candidate-id-empty", (artifact) => { artifact.path.candidates[0].id = ""; }),
    rawArtifactMutation("candidate-id-invalid-character", (artifact) => { artifact.path.candidates[0].id = "Upper"; }),
    rawArtifactMutation("candidate-id-duplicate", (artifact) => { artifact.path.candidates[1].id = artifact.path.candidates[0].id; }),
    rawArtifactMutation("candidate-carrier-unknown", (artifact) => { artifact.path.candidates[0].carrier = "tcp"; }),
    rawArtifactMutation("candidate-wire-profile-mismatch", (artifact) => { artifact.path.candidates[0].wire_profile = "flowersec-tunnel/3"; }),
    rawArtifactMutation("candidate-plaintext-websocket", (artifact) => { artifact.path.candidates[0].url = "ws://127.0.0.1/flowersec/v3/direct"; }),
    rawArtifactMutation("candidate-url-query", (artifact) => { artifact.path.candidates[0].url += "?x=1"; }),
    rawArtifactMutation("candidate-url-percent", (artifact) => { artifact.path.candidates[0].url = "wss://example.com/%66lowersec/v3/direct"; }),
    rawArtifactMutation("candidate-duplicate-endpoint", (artifact) => {
      artifact.path.candidates[1] = { ...artifact.path.candidates[0], id: "duplicate-endpoint" };
    }),
    rawArtifactMutation("pin-empty", (artifact) => { artifact.path.candidates[1].tls.pins = []; }),
    rawArtifactMutation("pin-count-five", (artifact) => {
      artifact.path.candidates[2].tls.pins.push(pin(PIN_C, 2_000_000_500));
    }),
    rawArtifactMutation("pin-expiry-zero", (artifact) => { artifact.path.candidates[1].tls.pins[0].not_after_unix_s = 0; }),
    textualArtifactMutation(
      "pin-expiry-fraction",
      (artifact) => { artifact.path.candidates[1].tls.pins[0].not_after_unix_s = 1; },
      '"not_after_unix_s":1',
      '"not_after_unix_s":1.5',
    ),
    textualArtifactMutation(
      "pin-expiry-exponent",
      (artifact) => { artifact.path.candidates[1].tls.pins[0].not_after_unix_s = 1; },
      '"not_after_unix_s":1',
      '"not_after_unix_s":1e0',
    ),
    textualArtifactMutation(
      "pin-expiry-negative-zero",
      (artifact) => { artifact.path.candidates[1].tls.pins[0].not_after_unix_s = 1; },
      '"not_after_unix_s":1',
      '"not_after_unix_s":-0',
    ),
    rawArtifactMutation("pin-value-wrong-length", (artifact) => { artifact.path.candidates[1].tls.pins[0].value_b64u = Buffer.alloc(31).toString("base64url"); }),
    rawArtifactMutation("scope-name-invalid", (artifact) => {
      artifact.scoped = [{ scope: "Upper", scope_version: 1, critical: false, payload: {} }];
    }),
    rawArtifactMutation("scope-version-zero", (artifact) => {
      artifact.scoped = [{ scope: "test", scope_version: 0, critical: false, payload: {} }];
    }),
    rawArtifactMutation("scope-duplicate", (artifact) => {
      artifact.scoped = [
        { scope: "test", scope_version: 1, critical: false, payload: {} },
        { scope: "test", scope_version: 1, critical: true, payload: {} },
      ];
    }),
    textualArtifactMutation(
      "scope-payload-fraction",
      (artifact) => {
        artifact.scoped = [{ scope: "test", scope_version: 1, critical: false, payload: { value: 1 } }];
      },
      '"value":1',
      '"value":1.5',
    ),
    textualArtifactMutation(
      "scope-payload-exponent",
      (artifact) => {
        artifact.scoped = [{ scope: "test", scope_version: 1, critical: false, payload: { value: 1 } }];
      },
      '"value":1',
      '"value":1e0',
    ),
    textualArtifactMutation(
      "scope-payload-negative-zero",
      (artifact) => {
        artifact.scoped = [{ scope: "test", scope_version: 1, critical: false, payload: { value: 1 } }];
      },
      '"value":1',
      '"value":-0',
    ),
    textualArtifactMutation(
      "scope-payload-positive-safe-integer-overflow",
      (artifact) => {
        artifact.scoped = [{ scope: "test", scope_version: 1, critical: false, payload: { value: SAFE_MAX } }];
      },
      `"value":${SAFE_MAX}`,
      '"value":9007199254740992',
    ),
    textualArtifactMutation(
      "scope-payload-negative-safe-integer-overflow",
      (artifact) => {
        artifact.scoped = [{ scope: "test", scope_version: 1, critical: false, payload: { value: -SAFE_MAX } }];
      },
      `"value":-${SAFE_MAX}`,
      '"value":-9007199254740992',
    ),
    rawArtifactMutation("correlation-wrong-version", (artifact) => { artifact.correlation.v = 2; }),
    textualArtifactMutation(
      "correlation-version-noninteger",
      (artifact) => { artifact.correlation.v = 3; },
      '"v":3',
      '"v":3.5',
    ),
    rawArtifactMutation("correlation-tag-empty-value", (artifact) => {
      artifact.correlation.tags = [{ key: "request", value: "" }];
    }),
    rawArtifactMutation("correlation-tag-value-too-long", (artifact) => {
      artifact.correlation.tags = [{ key: "request", value: "v".repeat(129) }];
    }),
    rawArtifactMutation("correlation-tag-value-non-ascii", (artifact) => {
      artifact.correlation.tags = [{ key: "request", value: "\u8bf7\u6c42" }];
    }),
    rawArtifactMutation("correlation-tag-empty-key", (artifact) => {
      artifact.correlation.tags = [{ key: "", value: "request" }];
    }),
    rawArtifactMutation("correlation-tag-invalid-key", (artifact) => {
      artifact.correlation.tags = [{ key: "Upper", value: "request" }];
    }),
    rawArtifactMutation("correlation-tag-key-too-long", (artifact) => {
      artifact.correlation.tags = [{ key: `a${"b".repeat(32)}`, value: "request" }];
    }),
    rawArtifactMutation("correlation-tag-key-non-ascii", (artifact) => {
      artifact.correlation.tags = [{ key: "\u8bf7\u6c42", value: "request" }];
    }),
    rawArtifactMutation("correlation-tag-duplicate", (artifact) => {
      artifact.correlation.tags = [{ key: "request", value: "a" }, { key: "request", value: "b" }];
    }),
  ],
};
write("artifact_vectors.json", artifactVectors);

const handshakeFixtures = JSON.parse(readFileSync(join(root, "handshake_vectors.json"), "utf8"));
const cryptoFixtures = JSON.parse(readFileSync(join(root, "crypto_vectors.json"), "utf8"));
const datagramFixtures = JSON.parse(readFileSync(join(root, "datagram_vectors.json"), "utf8"));
const isolationFrame = (id, hex) => {
  const value = Buffer.from(hex, "hex");
  const magic = Buffer.from(value);
  magic[3] = 0x32;
  const version = Buffer.from(value);
  version[4] = 2;
  return { id, v3_hex: hex, v2_magic_hex: magic.toString("hex"), v2_version_hex: version.toString("hex") };
};
const isolationSourceFrame = direct.winners.find(({ candidate_id }) => candidate_id === "w-ca").fsb3_hex;
const v2FrameIdentifiers = [
  ["FSB3", "FSB2"], ["FSA3", "FSA2"], ["FSC3", "FSC2"],
  ["FSH3", "FSH2"], ["FSS3", "FSS2"], ["FSR3", "FSR2"], ["FSD3", "FSD2"],
].map(([v3, v2]) => ({ v3, v2, error_code: "version_isolation" }));
const v2ProfileIdentifiers = [
  ["session", "flowersec/3", "flowersec/2"],
  ["direct", "flowersec-direct/3", "flowersec-direct/2"],
  ["tunnel", "flowersec-tunnel/3", "flowersec-tunnel/2"],
].map(([id, v3, v2]) => ({ id, v3, v2, error_code: "version_isolation" }));
const v2PathIdentifiers = [
  ["websocket-direct", "/flowersec/v3/direct", "/flowersec/v2/direct"],
  ["websocket-tunnel", "/flowersec/v3/tunnel", "/flowersec/v2/tunnel"],
  ["webtransport-direct", "/flowersec/webtransport/v3/direct", "/flowersec/webtransport/v2/direct"],
  ["webtransport-tunnel", "/flowersec/webtransport/v3/tunnel", "/flowersec/webtransport/v2/tunnel"],
].map(([id, v3, v2]) => ({ id, v3, v2, error_code: "version_isolation" }));
const v2SubprotocolIdentifiers = [
  ["websocket-direct", "flowersec.direct.v3", "flowersec.direct.v2"],
  ["websocket-tunnel", "flowersec.tunnel.v3", "flowersec.tunnel.v2"],
].map(([id, v3, v2]) => ({ id, v3, v2, error_code: "version_isolation" }));
const v2ALPNIdentifiers = [
  ["direct", "flowersec-direct/3", "flowersec-direct/2"],
  ["tunnel", "flowersec-tunnel/3", "flowersec-tunnel/2"],
].map(([id, v3, v2]) => ({ id, v3, v2, error_code: "version_isolation" }));
const v2CryptoLabels = [
  ["session-contract", "flowersec-v3-session-contract\0", "flowersec-v2-session-contract\0"],
  ["candidates", "flowersec-v3-candidates\0", "flowersec-v2-candidates\0"],
  ["admission", "flowersec-v3-admission\0", "flowersec-v2-admission\0"],
  ["runtime-capability", "flowersec-v3-runtime-capability\0", "flowersec-v2-runtime-capability\0"],
  ["handshake", "flowersec-v3-handshake\0", "flowersec-v2-handshake\0"],
  ["server-finished", "flowersec v3 server finished", "flowersec v2 server finished"],
  ["client-finished", "flowersec v3 client finished", "flowersec v2 client finished"],
  ["epoch-zero", "flowersec v3 epoch zero", "flowersec v2 epoch zero"],
  ["control-root", "flowersec v3 control root", "flowersec v2 control root"],
  ["stream-root", "flowersec v3 stream root", "flowersec v2 stream root"],
  ["setup-root", "flowersec v3 setup root", "flowersec v2 setup root"],
  ["rekey-root", "flowersec v3 rekey root", "flowersec v2 rekey root"],
  ["next-epoch", "flowersec v3 next epoch", "flowersec v2 next epoch"],
  ["stream", "flowersec v3 stream", "flowersec v2 stream"],
  ["control", "flowersec v3 control", "flowersec v2 control"],
  ["record-key", "flowersec v3 record key", "flowersec v2 record key"],
  ["nonce", "flowersec v3 nonce", "flowersec v2 nonce"],
  ["unreliable-root", "flowersec v3 unreliable root", "flowersec v2 unreliable root"],
  ["unreliable", "flowersec v3 unreliable", "flowersec v2 unreliable"],
  ["unreliable-key", "flowersec v3 unreliable key", "flowersec v2 unreliable key"],
  ["unreliable-nonce", "flowersec v3 unreliable nonce", "flowersec v2 unreliable nonce"],
  ["unreliable-aad", "flowersec-v3-unreliable", "flowersec-v2-unreliable"],
  ["setup-mac", "flowersec-v3-setup\0", "flowersec-v2-setup\0"],
  ["record-aad", "flowersec-v3-record\0", "flowersec-v2-record\0"],
  ["open", "flowersec-v3-open\0", "flowersec-v2-open\0"],
  ["acceptor-admissions", "flowersec-v3-acceptor-admissions\0", "flowersec-v2-acceptor-admissions\0"],
].map(([id, v3, v2]) => ({ id, v3, v2, error_code: "version_isolation" }));
write("version_isolation_vectors.json", {
  version: 3,
  source: {
    design_sha256: "236b332e6cf2f755b918721c8535191b2f8c8861bc32c07da329f823c1f04eba",
    producer: "testdata/transport_v3/generate_contract_vectors.mjs",
    rules_are_not_extended_by_vectors: true,
  },
  frames: [
    isolationFrame("fsb3", isolationSourceFrame),
    isolationFrame("fsa3", fsa3(1, "invalid_token")),
    isolationFrame("fsc3", handshakeFixtures.vectors[0].fsc3_hex),
    isolationFrame("fsh3", handshakeFixtures.vectors[0].client_init_hex),
    isolationFrame("fss3", cryptoFixtures.vectors[0].fss3_hex),
    isolationFrame("fsr3", cryptoFixtures.vectors[0].fsr3_header_hex),
    isolationFrame("fsd3", datagramFixtures.vectors[0].header_hex),
  ],
  profile_mutations: v2ProfileIdentifiers,
  path_mutations: v2PathIdentifiers,
  subprotocol_mutations: v2SubprotocolIdentifiers,
  alpn_mutations: v2ALPNIdentifiers,
  crypto_label_mutations: v2CryptoLabels,
  identifier_sets: {
    magic: v2FrameIdentifiers,
    profile: v2ProfileIdentifiers,
    path: v2PathIdentifiers,
    subprotocol: v2SubprotocolIdentifiers,
    alpn: v2ALPNIdentifiers,
    crypto_label: v2CryptoLabels,
  },
  inherited_codecs: {
    fsh3: {
      fixture: "handshake_vectors.json",
      frame_id: "x25519-direct",
      inherited_codec_from: "transport_v2",
      semantic: "FSH3 keeps the inherited canonical handshake JSON codec after versioned framing replacement",
    },
    open: {
      fixture: "open_unicode_vectors.json",
      vector_id: "minimal-string-escaping",
      inherited_codec_from: "transport_v2",
      semantic: "OPEN keeps the inherited non-JCS session codec and is not artifact JCS input",
    },
    rpc: {
      inherited_codec_from: "transport_v2",
      envelope_json: "{\"payload\":{\"ratio\":1.5},\"request_id\":1,\"response_to\":0,\"type_id\":7}",
      semantic: "RPC keeps the inherited application JSON value domain; float payload is not artifact JCS",
    },
  },
});

const W4 = [
  ["dial", "direct", "client", true, false, false],
  ["dial", "tunnel", "client", true, false, false],
  ["dial", "tunnel", "server", true, false, false],
  ["listen", "direct", "server", true, false, false],
];
const Q4M = [
  ["dial", "direct", "client", true, true, true],
  ["dial", "tunnel", "client", true, true, true],
  ["dial", "tunnel", "server", true, true, true],
  ["listen", "direct", "server", true, true, false],
];
const H4 = Q4M.map((tuple) => [...tuple.slice(0, 5), false]);

function tuples(carrier, source, modes, omitListen = false) {
  return source.filter(([networkMode]) => !(omitListen && networkMode === "listen")).map(
    ([networkMode, path, sessionRole, reliableStreams, datagrams, migration]) => ({
      carrier,
      datagrams,
      migration,
      networkMode,
      path,
      reliableStreams,
      securityModes: networkMode === "listen" ? [] : modes,
      sessionRole,
    }),
  );
}

function capability(name, language, runtime, tupleGroups, unsupported) {
  const descriptor = {
    language,
    runtime,
    schemaVersion: 3,
    tuples: tupleGroups.flat().sort((left, right) => {
      const leftKey = [left.carrier, left.networkMode, left.sessionRole, left.path];
      const rightKey = [right.carrier, right.networkMode, right.sessionRole, right.path];
      for (let index = 0; index < leftKey.length; index++) {
        if (leftKey[index] < rightKey[index]) return -1;
        if (leftKey[index] > rightKey[index]) return 1;
      }
      return 0;
    }),
    unsupported: unsupported.map(([carrier, reason]) => ({ carrier, reason }))
      .sort((left, right) => asciiCompare(left.carrier, right.carrier)),
  };
  return { name, ...digestResult("flowersec-v3-runtime-capability\0", descriptor) };
}

const both = ["ca", "pin"];
const capabilityDescriptors = [
  capability("go-native", "go", "native", [
    tuples("websocket", W4, both), tuples("raw_quic", Q4M, both), tuples("webtransport", H4, both),
  ], []),
  capability("typescript-browser-ca-only", "typescript", "browser", [
    tuples("websocket", W4, ["ca"], true), tuples("webtransport", H4, ["ca"], true),
  ], [["raw_quic", "browser_no_raw_udp"]]),
  capability("typescript-browser-chromium-151.0.7922.34", "typescript", "browser", [
    tuples("websocket", W4, ["ca"], true), tuples("webtransport", H4, both, true),
  ], [["raw_quic", "browser_no_raw_udp"]]),
  capability("typescript-node", "typescript", "node", [
    tuples("websocket", W4, both), tuples("raw_quic", Q4M.map((tuple) => [...tuple.slice(0, 5), false]), both),
  ], [["webtransport", "node_webtransport_driver_unavailable"]]),
  capability("rust-native", "rust", "native", [
    tuples("websocket", W4, both), tuples("raw_quic", Q4M, both),
  ], [["webtransport", "driver_unavailable"]]),
  capability("swift-ios", "swift", "ios", [tuples("websocket", W4, both, true)], [
    ["raw_quic", "swift_apple_client_profile_excludes_raw_quic"],
    ["webtransport", "swift_apple_client_profile_excludes_webtransport"],
  ]),
  capability("swift-macos", "swift", "macos", [tuples("websocket", W4, both, true)], [
    ["raw_quic", "swift_apple_client_profile_excludes_raw_quic"],
    ["webtransport", "swift_apple_client_profile_excludes_webtransport"],
  ]),
  capability("swift-linux", "swift", "linux", [], [
    ["raw_quic", "swift_apple_client_profile_excludes_raw_quic"],
    ["websocket", "websocket_adapter_not_supported_on_linux"],
    ["webtransport", "swift_apple_client_profile_excludes_webtransport"],
  ]),
];

function invalidCapability(id, mutate) {
  const descriptor = JSON.parse(capabilityDescriptors[0].canonical_json);
  mutate(descriptor);
  return { id, value: canonicalJSON(descriptor), error_code: "invalid_capability" };
}

const capabilityInvalid = [
  invalidCapability("schema-version-v2", (value) => { value.schemaVersion = 2; }),
  invalidCapability("adapter-not-composed-first-release", (value) => {
    value.tuples = value.tuples.filter(({ carrier }) => carrier !== "webtransport");
    value.unsupported = [{ carrier: "webtransport", reason: "adapter_not_composed" }];
  }),
  invalidCapability("duplicate-tuple-identity", (value) => { value.tuples.splice(1, 0, structuredClone(value.tuples[0])); }),
  invalidCapability("dial-security-modes-empty", (value) => { value.tuples.find(({ networkMode }) => networkMode === "dial").securityModes = []; }),
  invalidCapability("listen-security-modes-ca", (value) => { value.tuples.find(({ networkMode }) => networkMode === "listen").securityModes = ["ca"]; }),
  invalidCapability("carrier-not-partitioned", (value) => { value.tuples = value.tuples.filter(({ carrier }) => carrier === "raw_quic"); }),
  invalidCapability("unknown-reason", (value) => {
    value.tuples = value.tuples.filter(({ carrier }) => carrier === "raw_quic");
    value.unsupported = [{ carrier: "websocket", reason: "unknown" }, { carrier: "webtransport", reason: "adapter_not_composed" }];
  }),
  invalidCapability("reliable-streams-false", (value) => { value.tuples[0].reliableStreams = false; }),
  invalidCapability("reliable-streams-not-boolean", (value) => { value.tuples[0].reliableStreams = 1; }),
  invalidCapability("datagrams-not-boolean", (value) => { value.tuples[0].datagrams = "true"; }),
  invalidCapability("migration-not-boolean", (value) => { value.tuples[0].migration = 1; }),
  invalidCapability("unknown-carrier", (value) => { value.tuples[0].carrier = "tcp"; }),
  invalidCapability("unknown-network-mode", (value) => { value.tuples[0].networkMode = "connect"; }),
  invalidCapability("unknown-path", (value) => { value.tuples[0].path = "relay"; }),
  invalidCapability("unknown-session-role", (value) => { value.tuples[0].sessionRole = "peer"; }),
  invalidCapability("dial-direct-server-closed-tuple", (value) => { value.tuples[0].sessionRole = "server"; }),
  invalidCapability("listen-tunnel-client-closed-tuple", (value) => {
    const tuple = value.tuples.find(({ networkMode }) => networkMode === "listen");
    tuple.path = "tunnel";
    tuple.sessionRole = "client";
  }),
  invalidCapability("websocket-datagrams-true", (value) => {
    const tuple = value.tuples.find(({ carrier }) => carrier === "websocket");
    tuple.datagrams = true;
  }),
  invalidCapability("websocket-migration-true", (value) => {
    const tuple = value.tuples.find(({ carrier }) => carrier === "websocket");
    tuple.migration = true;
  }),
  invalidCapability("security-modes-reversed", (value) => { value.tuples[0].securityModes = ["pin", "ca"]; }),
  invalidCapability("security-modes-duplicate", (value) => { value.tuples[0].securityModes = ["ca", "ca"]; }),
  invalidCapability("security-mode-unknown", (value) => { value.tuples[0].securityModes = ["tofu"]; }),
  invalidCapability("tuple-order-not-ascii", (value) => { value.tuples.reverse(); }),
  invalidCapability("unsupported-overlaps-tuple", (value) => { value.unsupported = [{ carrier: "websocket", reason: "adapter_not_composed" }]; }),
  invalidCapability("unsupported-duplicate-carrier", (value) => {
    value.tuples = value.tuples.filter(({ carrier }) => carrier !== "webtransport");
    value.unsupported = [{ carrier: "webtransport", reason: "adapter_not_composed" }, { carrier: "webtransport", reason: "driver_unavailable" }];
  }),
  invalidCapability("language-invalid", (value) => { value.language = "TypeScript"; }),
  invalidCapability("runtime-invalid", (value) => { value.runtime = "node-js"; }),
  invalidCapability("missing-tuples", (value) => { delete value.tuples; }),
  invalidCapability("unknown-descriptor-field", (value) => { value.future = true; }),
  {
    id: "duplicate-descriptor-field",
    value: capabilityDescriptors[0].canonical_json.replace('"language":"go"', '"language":"go","language":"go"'),
    error_code: "invalid_capability",
  },
  {
    id: "non-jcs-descriptor",
    value: JSON.stringify(JSON.parse(capabilityDescriptors[0].canonical_json), null, 1),
    error_code: "invalid_capability",
  },
];

const capabilityVectors = {
  version: 3,
  digest_label: "flowersec-v3-runtime-capability\u0000",
  exact_browser_pin_provider: {
    family: "Chromium",
    full_version: "151.0.7922.34",
    playwright: "1.62.1",
    browser_js_p256_proof: false,
    browser_may_accept_non_rsa_non_p256: true,
    browser_non_p256_cross_runtime_interoperability: false,
    sdk_must_not_claim_js_p256_verification: true,
  },
  vectors: capabilityDescriptors,
  invalid: capabilityInvalid,
};
write("capability_vectors.json", capabilityVectors);

const controllerExpected = (overrides = {}) => ({
  final_state: "failed", public_error: null, disposition: null,
  acquisitions: 0, connect_attempts: 0, transports_created: 0,
  replacement_acquisitions: 0, replacement_quota_used: 0,
  spend_callbacks: 0, retire_callbacks: 0,
  lease_terminal_states: [], retry_delays_ms: [],
  ...overrides,
});

const controllerVectors = {
  version: 3,
  defaults: {
    maximum_attempts: 0,
    initial_backoff_ms: 250,
    maximum_backoff_ms: 30000,
    jitter_ms: 0,
    wall_clock_recheck_max_interval_ms: 1000,
    maximum_retry_after_unix_ms: 253402300799999,
    maximum_policy_sensitive_replacement_leases_per_cycle: 1,
  },
  public_errors: [
    "artifact_invalid",
    "expired_artifact",
    "transport_security_unsupported",
    "transport_security_failed",
    "connection_failed",
  ],
  failure_phases: ["artifact", "connect", "session"],
  internal_transport_results: [
    ["invalid_artifact", null, "terminal"],
    ["expired_artifact", null, "acquire_primary"],
    ["tls_unsupported", null, "skip_candidate"],
    ["tls_policy_expired", null, "policy_refresh"],
    ["tls_failed", "ca_untrusted", "candidate_terminal"],
    ["tls_failed", "pin_mismatch", "policy_refresh"],
    ["tls_failed", "unknown", "policy_refresh_for_pin"],
    ["connection_failed", "browser_pin_opaque", "policy_sensitive_replacement"],
  ],
  retry_after: {
    valid: [0, 253402300799999],
    invalid: [-1, 1.5, "1000", 253402300800000, "NaN", "Infinity"],
    aggregate: "maximum_absolute_unix_ms",
  },
  backoff_vectors: Array.from({ length: 12 }, (_, index) => ({
    consecutive_failure: index + 1,
    delay_ms: Math.min(250 * (2 ** index), 30000),
  })),
  scenarios: [
    {
      id: "pin-mismatch-changed-pin-success",
      driver: "policy-replacement",
      steps: ["acquire_primary", "claim_A", "pin_mismatch", "retire_A", "acquire_replacement_immediate", "claim_B", "changed_pin", "tls_winner", "commit_spend_B", "established"],
      input: { replacement_policy: "changed_pin" },
      expected: {
        final_state: "connected", public_error: null, disposition: null,
        acquisitions: 2, connect_attempts: 2, transports_created: 2,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 1, retire_callbacks: 1,
        lease_terminal_states: ["retired", "consumed"], retry_delays_ms: [],
      },
    },
    {
      id: "pin-mismatch-same-policy-terminal",
      driver: "policy-replacement",
      steps: ["acquire_primary", "claim_A", "pin_mismatch", "retire_A", "acquire_replacement_immediate", "claim_B", "same_policy_digest", "retire_B"],
      input: { replacement_policy: "same_pin" },
      expected: {
        final_state: "failed", public_error: "transport_security_failed", disposition: "terminal",
        acquisitions: 2, connect_attempts: 1, transports_created: 1,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 0, retire_callbacks: 2,
        lease_terminal_states: ["retired", "retired"], retry_delays_ms: [],
      },
    },
    {
      id: "pin-to-ca-filtered",
      driver: "policy-replacement",
      steps: ["pin_mismatch_A", "replacement_same_endpoint_ca", "filter_ca", "empty_eligible_set", "retire_B"],
      input: { replacement_policy: "ca" },
      expected: {
        final_state: "failed", public_error: "transport_security_failed", disposition: "terminal",
        acquisitions: 2, connect_attempts: 1, transports_created: 1,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 0, retire_callbacks: 2,
        lease_terminal_states: ["retired", "retired"], retry_delays_ms: [], no_mode_downgrade: true,
      },
    },
    {
      id: "browser-opaque-exhausted",
      driver: "policy-replacement",
      steps: ["browser_pin_opaque_A", "retire_A", "acquire_replacement_immediate", "claim_B", "replacement_same_digest", "retire_B"],
      input: { replacement_policy: "same_pin", trigger: "browser_pin_opaque" },
      expected: {
        final_state: "failed", public_error: "connection_failed", failure_phase: "connect",
        disposition: "terminal",
        acquisitions: 2, connect_attempts: 1, transports_created: 1,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 0, retire_callbacks: 2,
        lease_terminal_states: ["retired", "retired"], retry_delays_ms: [], tls_error_claimed: false,
      },
    },
    {
      id: "all-unsupported",
      driver: "candidate-capability-filter",
      steps: ["acquire_primary", "claim_A", "skip_tls_unsupported", "skip_tls_unsupported", "retire_A"],
      input: { candidate_results: ["tls_unsupported", "tls_unsupported"] },
      expected: {
        final_state: "failed", public_error: "transport_security_unsupported", disposition: "terminal",
        acquisitions: 1, connect_attempts: 1, transports_created: 0,
        replacement_acquisitions: 0, replacement_quota_used: 0,
        spend_callbacks: 0, retire_callbacks: 1,
        lease_terminal_states: ["retired"], retry_delays_ms: [],
      },
    },
    {
      id: "mixed-security-opaque-policy-refresh",
      driver: "policy-replacement",
      steps: ["tls_failed_ca_untrusted_w_ca", "browser_pin_opaque_w_pin", "refresh_on_union_of_native_and_opaque_triggers", "acquire_replacement_immediate", "claim_B", "changed_pin", "commit_spend_B", "established"],
      input: { replacement_policy: "changed_pin", trigger: "mixed_security_opaque" },
      expected: {
        final_state: "connected", public_error: null, disposition: null,
        acquisitions: 2, connect_attempts: 2, transports_created: 2,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 1, retire_callbacks: 1,
        lease_terminal_states: ["retired", "consumed"], retry_delays_ms: [],
      },
    },
    {
      id: "replacement-expired-returns-primary",
      driver: "replacement-expiry",
      steps: ["acquire_primary", "claim_A", "policy_trigger_A", "retire_A", "acquire_replacement_immediate", "claim_B", "B_race_end_expired", "retire_B", "wait_backoff_ordinal_2", "acquire_primary", "claim_C", "blocked_old_pin", "commit_spend_C", "established"],
      input: { wake_retry_manually: true },
      expected: {
        final_state: "connected", public_error: null, disposition: null,
        acquisitions: 3, connect_attempts: 3, transports_created: 3,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 1, retire_callbacks: 2,
        lease_terminal_states: ["retired", "retired", "consumed"], retry_delays_ms: [500],
        blocked_policy_remains_blocked: true,
      },
    },
    {
      id: "replacement-expired-before-race-returns-primary",
      driver: "replacement-expiry",
      steps: ["acquire_primary", "claim_A", "policy_trigger_A", "retire_A", "acquire_replacement_immediate", "claim_B", "B_expired_before_race", "retire_B", "wait_backoff_ordinal_2", "acquire_primary", "claim_C", "blocked_old_pin", "commit_spend_C", "established"],
      input: { expiry_boundary: "before_race", wake_retry_manually: true },
      expected: {
        final_state: "connected", public_error: null, disposition: null,
        acquisitions: 3, connect_attempts: 2, transports_created: 2,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 1, retire_callbacks: 2,
        lease_terminal_states: ["retired", "retired", "consumed"], retry_delays_ms: [500],
        blocked_policy_remains_blocked: true,
      },
    },
    {
      id: "replacement-acquisition-retryable-continues-search",
      driver: "replacement-acquisition",
      steps: ["acquire_primary", "claim_A", "policy_trigger_A", "retire_A", "acquire_replacement_retryable", "wait_backoff_ordinal_2", "acquire_replacement", "claim_B", "changed_pin", "tls_winner", "commit_spend_B", "established"],
      input: { replacement_acquisition_failure: "retryable", wake_retry_manually: true },
      expected: {
        final_state: "connected", public_error: null, disposition: null,
        acquisitions: 3, connect_attempts: 2, transports_created: 2,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 1, retire_callbacks: 1,
        lease_terminal_states: ["retired", "consumed"], retry_delays_ms: [500],
      },
    },
    {
      id: "post-spend-retry-preserves-quota",
      driver: "post-spend-retry",
      steps: ["acquire_primary", "claim_A", "policy_trigger_A", "retire_A", "acquire_replacement_immediate", "claim_B", "tls_winner_B", "commit_spend_B", "fsa_retryable", "wait_backoff_ordinal_2", "acquire_primary", "claim_C", "second_policy_trigger", "retire_C", "terminal"],
      input: { wake_retry_manually: true },
      expected: {
        final_state: "failed", public_error: "transport_security_failed", disposition: "terminal",
        acquisitions: 3, connect_attempts: 3, transports_created: 3,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 1, retire_callbacks: 2,
        lease_terminal_states: ["retired", "consumed", "retired"], retry_delays_ms: [500],
      },
    },
    {
      id: "lease-cancellation-first",
      driver: "lease-cancel-race",
      steps: ["acquire_started", "cancel_linearized", "late_lease", "source_claim", "source_retire", "close_cleanup_complete"],
      input: { linearization_winner: "cancellation" },
      expected: {
        final_state: "closed", public_error: null, disposition: null,
        acquisitions: 1, connect_attempts: 0, transports_created: 0,
        replacement_acquisitions: 0, replacement_quota_used: 0,
        spend_callbacks: 0, retire_callbacks: 1,
        lease_terminal_states: ["retired"], retry_delays_ms: [],
        source_cancellation_propagated: true,
        close_waits_for_acquire_settlement: true,
      },
    },
    {
      id: "lease-delivery-first",
      driver: "lease-cancel-race",
      steps: ["lease_delivery_linearized", "controller_claim", "connect_started", "cancel", "controller_retire", "close_cleanup_complete"],
      input: { linearization_winner: "delivery" },
      expected: {
        final_state: "closed", public_error: null, disposition: null,
        acquisitions: 1, connect_attempts: 1, transports_created: 1,
        replacement_acquisitions: 0, replacement_quota_used: 0,
        spend_callbacks: 0, retire_callbacks: 1,
        lease_terminal_states: ["retired"], retry_delays_ms: [],
        source_cancellation_propagated: true,
        close_waits_for_acquire_settlement: true,
      },
    },
    {
      id: "attempt-exhaustion",
      driver: "attempt-exhaustion",
      steps: ["acquire_primary_failure", "wait_backoff_ordinal_1", "acquire_primary_failure", "budget_exhausted"],
      input: { maximum_attempts: 2, wake_retry_manually: true },
      expected: {
        final_state: "failed", public_error: "connection_failed", failure_phase: "artifact",
        disposition: "terminal",
        acquisitions: 2, connect_attempts: 0, transports_created: 0,
        replacement_acquisitions: 0, replacement_quota_used: 0,
        spend_callbacks: 0, retire_callbacks: 0,
        lease_terminal_states: [], retry_delays_ms: [250],
      },
    },
    {
      id: "invalid-source-retry-after",
      driver: "source-contract-validation",
      steps: ["acquire_primary_invalid_retry_after", "reject_source_contract", "terminalize_artifact_invalid"],
      input: { retry_after_unix_ms: 253402300800000 },
      expected: {
        final_state: "failed", public_error: "artifact_invalid", failure_phase: "artifact",
        disposition: "terminal", acquisitions: 1, connect_attempts: 0, transports_created: 0,
        replacement_acquisitions: 0, replacement_quota_used: 0,
        spend_callbacks: 0, retire_callbacks: 0,
        lease_terminal_states: [], retry_delays_ms: [], attempt: 1, failure_ordinal: 1,
      },
    },
    {
      id: "retry-after-and-monotonic-backoff",
      driver: "retry-after-clock",
      steps: ["acquire_primary_retry_after", "wait_wall_recheck", "reject_retry_now", "advance_wall_and_monotonic", "wait_wall_recheck", "advance_wall_to_deadline", "acquire_primary", "claim_A", "commit_spend_A", "established"],
      input: {
        wall_start_ms: 1000, monotonic_start_ms: 0, retry_after_unix_ms: 5000,
        failure_ordinal: 1, backoff_ms: 250, wall_advances_ms: [1000, 3000], monotonic_advances_ms: [250, 0],
      },
      expected: {
        final_state: "connected", public_error: null, disposition: null,
        acquisitions: 2, connect_attempts: 1, transports_created: 1,
        replacement_acquisitions: 0, replacement_quota_used: 0,
        spend_callbacks: 1, retire_callbacks: 0,
        lease_terminal_states: ["consumed"], retry_delays_ms: [250, 1000],
        retry_now_allowed_before_deadline: false, wall_end_ms: 5000, monotonic_end_ms: 250,
      },
    },
    {
      id: "race-order-independent-security-priority",
      driver: "candidate-failure-aggregation",
      steps: ["run_each_completion_permutation", "aggregate_security_priority", "project_public_failure"],
      input: { permutations: [
          ["tls_unsupported", "connection_failed", "tls_failed"],
          ["tls_unsupported", "tls_failed", "connection_failed"],
          ["tls_failed", "tls_unsupported", "connection_failed"],
          ["tls_failed", "connection_failed", "tls_unsupported"],
          ["connection_failed", "tls_failed", "tls_unsupported"],
          ["connection_failed", "tls_unsupported", "tls_failed"],
        ] },
      expected: {
        final_state: "failed", public_error: "transport_security_failed", disposition: "terminal",
        acquisitions: 1, connect_attempts: 3, transports_created: 3,
        replacement_acquisitions: 0, replacement_quota_used: 0,
        spend_callbacks: 0, retire_callbacks: 1,
        lease_terminal_states: ["retired"], retry_delays_ms: [], order_independent: true,
      },
    },
    {
      id: "failure-ordinal-counts-attempt-once",
      driver: "failure-ordinal",
      steps: ["candidate_A_fails", "candidate_B_fails", "aggregate_attempt_failure", "increment_failure_ordinal_once", "wait_backoff_ordinal_1"],
      input: { candidate_results: ["connection_failed", "connection_failed"] },
      expected: controllerExpected({
        final_state: "waiting", public_error: "connection_failed", disposition: "retryable",
        acquisitions: 1, connect_attempts: 2, transports_created: 2,
        retire_callbacks: 1, lease_terminal_states: ["retired"], retry_delays_ms: [250],
        failure_ordinal: 1,
      }),
    },
    {
      id: "artifact-expiry-before-race",
      driver: "expiry-boundary",
      steps: ["claim_A", "observe_expired_before_race", "retire_A", "refresh_primary"],
      input: { expiry_boundary: "before_race" },
      expected: controllerExpected({
        final_state: "waiting", public_error: "expired_artifact", disposition: "retryable",
        acquisitions: 1, retire_callbacks: 1, lease_terminal_states: ["retired"], retry_delays_ms: [250],
        credential_bytes_written: 0,
      }),
    },
    {
      id: "artifact-expiry-at-race-end",
      driver: "expiry-boundary",
      steps: ["claim_A", "start_candidate_race", "select_tls_winner", "observe_expired_at_race_end", "abort_winner", "retire_A", "refresh_primary"],
      input: { expiry_boundary: "race_end" },
      expected: controllerExpected({
        final_state: "waiting", public_error: "expired_artifact", disposition: "retryable",
        acquisitions: 1, connect_attempts: 1, transports_created: 1,
        retire_callbacks: 1, lease_terminal_states: ["retired"], retry_delays_ms: [250],
        credential_bytes_written: 0,
      }),
    },
    {
      id: "artifact-expiry-immediately-before-spend",
      driver: "expiry-boundary",
      steps: ["claim_A", "select_tls_winner", "observe_expired_before_spend", "abort_winner", "retire_A", "refresh_primary"],
      input: { expiry_boundary: "before_spend" },
      expected: controllerExpected({
        final_state: "waiting", public_error: "expired_artifact", disposition: "retryable",
        acquisitions: 1, connect_attempts: 1, transports_created: 1,
        retire_callbacks: 1, lease_terminal_states: ["retired"], retry_delays_ms: [250],
        credential_bytes_written: 0,
      }),
    },
    {
      id: "artifact-expiry-after-spend",
      driver: "expiry-boundary",
      steps: ["claim_A", "select_tls_winner", "commit_spend_A", "observe_expired_after_spend", "fail_without_reuse", "refresh_primary"],
      input: { expiry_boundary: "after_spend" },
      expected: controllerExpected({
        final_state: "waiting", public_error: "expired_artifact", disposition: "retryable",
        acquisitions: 1, connect_attempts: 1, transports_created: 1,
        spend_callbacks: 1, lease_terminal_states: ["consumed"], retry_delays_ms: [250],
        credential_bytes_written: 0,
      }),
    },
    {
      id: "established-session-termination-resets-cycle",
      driver: "cycle-reset",
      steps: ["ordinary_failure", "wait_backoff_ordinal_1", "establish_session", "reset_failure_ordinal_and_quota", "session_terminates", "wait_backoff_ordinal_1", "acquire_fresh_primary"],
      input: { wake_retry_manually: true },
      expected: controllerExpected({
        final_state: "connected", acquisitions: 3, connect_attempts: 3, transports_created: 3,
        spend_callbacks: 2, retire_callbacks: 1,
        lease_terminal_states: ["retired", "consumed", "consumed"], retry_delays_ms: [250, 250],
        failure_ordinal: 1, replacement_quota_used: 0,
      }),
    },
    {
      id: "established-session-terminal-termination-resets-cycle",
      driver: "cycle-reset-terminal",
      steps: ["establish_session", "reset_failure_ordinal_and_quota", "session_terminates_terminal", "fail_new_cycle"],
      input: {},
      expected: controllerExpected({
        final_state: "failed", public_error: "connection_failed", disposition: "terminal",
        acquisitions: 1, connect_attempts: 1, transports_created: 1,
        spend_callbacks: 1, lease_terminal_states: ["consumed"], retry_delays_ms: [],
        failure_ordinal: 1, replacement_quota_used: 0, attempt: 0,
      }),
    },
    {
      id: "retry-after-wall-clock-forward-jump",
      driver: "retry-clock-boundary",
      steps: ["wait_retry_after", "wall_clock_jumps_forward", "monotonic_backoff_satisfied", "retry"],
      input: { wall_start_ms: 1000, monotonic_start_ms: 0, retry_after_unix_ms: 5000, failure_ordinal: 1, backoff_ms: 250, wall_advances_ms: [5000], monotonic_advances_ms: [250] },
      expected: controllerExpected({ final_state: "connecting", retry_delays_ms: [250], wall_end_ms: 6000, monotonic_end_ms: 250 }),
    },
    {
      id: "retry-after-wall-clock-backward-jump",
      driver: "retry-clock-boundary",
      steps: ["wait_retry_after", "wall_clock_jumps_backward", "reread_wall_within_1000", "remain_waiting"],
      input: { wall_start_ms: 4000, monotonic_start_ms: 0, retry_after_unix_ms: 5000, failure_ordinal: 1, backoff_ms: 250, wall_advances_ms: [-2000, 3000], monotonic_advances_ms: [1000, 1000] },
      expected: controllerExpected({ final_state: "connecting", retry_delays_ms: [250, 1000], wall_end_ms: 5000, monotonic_end_ms: 2000 }),
    },
    {
      id: "retry-after-wall-reread-bounded",
      driver: "retry-clock-boundary",
      steps: ["wait_retry_after_far_future", "sleep_at_most_1000", "reread_wall"],
      input: { wall_start_ms: 0, monotonic_start_ms: 0, retry_after_unix_ms: 100000, failure_ordinal: 8, backoff_ms: 30000, wall_advances_ms: [1000], monotonic_advances_ms: [1000] },
      expected: controllerExpected({ final_state: "waiting", retry_delays_ms: [1000], wall_end_ms: 1000, monotonic_end_ms: 1000, maximum_wall_reread_ms: 1000 }),
    },
    {
      id: "monotonic-timer-safe-integer-saturation",
      driver: "retry-clock-boundary",
      steps: ["monotonic_near_safe_integer", "add_backoff_saturating", "sleep_remaining_one", "reach_safe_integer"],
      input: { wall_start_ms: 0, monotonic_start_ms: 9007199254740990, retry_after_unix_ms: 0, failure_ordinal: 1, backoff_ms: 250, wall_advances_ms: [0], monotonic_advances_ms: [1] },
      expected: controllerExpected({ final_state: "connecting", retry_delays_ms: [1], wall_end_ms: 0, monotonic_end_ms: 9007199254740991, timer_saturated: true }),
    },
    {
      id: "single-ca-untrusted-terminal",
      driver: "candidate-security-aggregation",
      steps: ["create_ca_transport", "ca_verification_fails", "aggregate_ca_untrusted", "retire_A", "terminal"],
      input: { candidate_results: ["ca_untrusted"] },
      expected: controllerExpected({
        public_error: "transport_security_failed", disposition: "terminal",
        acquisitions: 1, connect_attempts: 1, transports_created: 1,
        retire_callbacks: 1, lease_terminal_states: ["retired"], tls_error_claimed: true,
      }),
    },
    {
      id: "ca-untrusted-dominates-ordinary-failure",
      driver: "candidate-security-aggregation",
      steps: ["race_ca_and_ordinary", "ca_verification_fails", "ordinary_dial_fails", "aggregate_security_priority", "retire_A", "terminal"],
      input: { candidate_results: ["ca_untrusted", "connection_failed"] },
      expected: controllerExpected({
        public_error: "transport_security_failed", disposition: "terminal",
        acquisitions: 1, connect_attempts: 2, transports_created: 2,
        retire_callbacks: 1, lease_terminal_states: ["retired"], tls_error_claimed: true, order_independent: true,
      }),
    },
    {
      id: "multiple-pin-trigger-endpoints-filtered",
      driver: "multi-trigger-replacement",
      steps: ["pin_mismatch_endpoint_A", "pin_mismatch_endpoint_B", "retire_primary", "acquire_one_replacement", "require_changed_pin_for_A_and_B", "filter_same_pin_and_ca", "terminal"],
      input: { candidate_results: ["pin_mismatch", "pin_mismatch"] },
      expected: controllerExpected({
        public_error: "transport_security_failed", disposition: "terminal",
        acquisitions: 2, connect_attempts: 2, transports_created: 2,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        retire_callbacks: 2, lease_terminal_states: ["retired", "retired"], no_mode_downgrade: true,
      }),
    },
    {
      id: "retire-cleanup-failure-does-not-retry-lease",
      driver: "retire-cleanup",
      steps: ["claim_A", "pre_spend_failure", "retire_A", "cleanup_fails", "do_not_reuse_A", "continue_with_fresh_lease"],
      input: { wake_retry_manually: true },
      expected: controllerExpected({
        final_state: "connected", acquisitions: 2, connect_attempts: 2, transports_created: 2,
        spend_callbacks: 1, retire_callbacks: 1,
        lease_terminal_states: ["retired", "consumed"], retry_delays_ms: [250], cleanup_error_ignored: true,
      }),
    },
    {
      id: "ordinary-retry-refresh-preserves-replacement-quota",
      driver: "quota-preservation",
      steps: ["ordinary_failure_A", "retire_A", "wait_backoff_ordinal_1", "acquire_fresh_primary_B", "pin_mismatch_B", "retire_B", "acquire_replacement_C", "changed_pin", "commit_spend_C", "established"],
      input: { wake_retry_manually: true },
      expected: controllerExpected({
        final_state: "connected", acquisitions: 3, connect_attempts: 3, transports_created: 3,
        replacement_acquisitions: 1, replacement_quota_used: 1,
        spend_callbacks: 1, retire_callbacks: 2,
        lease_terminal_states: ["retired", "retired", "consumed"], retry_delays_ms: [250],
      }),
    },
    {
      id: "attempt-counter-safe-integer-saturation",
      driver: "attempt-saturation",
      steps: ["attempt_at_safe_integer", "increment_saturating", "remain_safe_integer"],
      input: { initial_attempt: 9007199254740991, maximum_attempts: 9007199254740991 },
      expected: controllerExpected({ final_state: "connecting", acquisitions: 0, attempt: 9007199254740991, counter_saturated: true }),
    },
    {
      id: "capability-snapshot-invalidation-barrier",
      driver: "capability-barrier",
      steps: ["snapshot_capability", "prepare_candidate", "invalidate_runtime_capability", "recheck_before_tls", "abort_without_transport", "retire_A"],
      input: { candidate_results: ["tls_unsupported"] },
      expected: controllerExpected({
        public_error: "transport_security_unsupported", disposition: "terminal",
        acquisitions: 1, connect_attempts: 1, transports_created: 0,
        retire_callbacks: 1, lease_terminal_states: ["retired"], capability_rechecked: true,
      }),
    },
    ...[
      ["primary-fsa3-reject-consumes-spent", "primary", "fsa_reject", "connection_failed", "terminal", 1, 1, 1, 0, "consumed"],
      ["primary-fsa3-retryable-consumes-spent", "primary", "fsa_retryable", "connection_failed", "retryable", 1, 1, 1, 0, "consumed"],
      ["replacement-fsa3-reject-consumes-spent", "replacement", "fsa_reject", "connection_failed", "terminal", 2, 2, 1, 1, "consumed"],
      ["replacement-fsa3-retryable-consumes-spent", "replacement", "fsa_retryable", "connection_failed", "retryable", 2, 2, 1, 1, "consumed"],
      ["primary-fsh3-failure-consumes-spent", "primary", "fsh_failure", "connection_failed", "retryable", 1, 1, 1, 0, "consumed"],
      ["replacement-fsh3-failure-consumes-spent", "replacement", "fsh_failure", "connection_failed", "retryable", 2, 2, 1, 1, "consumed"],
    ].map(([id, phase, admission_result, public_error, disposition, acquisitions, connects, spends, retires, final_lease]) => ({
      id,
      driver: "admission-spend-boundary",
      steps: phase === "primary"
        ? ["acquire_primary", "claim_A", "tls_winner", "commit_spend_A", admission_result, "classify"]
        : ["acquire_primary", "claim_A", "pin_mismatch", "retire_A", "acquire_replacement", "claim_B", "tls_winner", "commit_spend_B", admission_result, "classify"],
      input: { phase, admission_result },
      expected: controllerExpected({
        final_state: disposition === "terminal" ? "failed" : "waiting", public_error, disposition,
        acquisitions, connect_attempts: connects, transports_created: connects,
        replacement_acquisitions: phase === "replacement" ? 1 : 0,
        replacement_quota_used: phase === "replacement" ? 1 : 0,
        spend_callbacks: spends, retire_callbacks: retires,
        lease_terminal_states: phase === "replacement" ? ["retired", final_lease] : [final_lease],
        retry_delays_ms: disposition === "retryable" ? [phase === "replacement" ? 500 : 250] : [],
      }),
    })),
    {
      id: "artifact-source-repeats-consumed-lease",
      driver: "duplicate-lease-identity",
      steps: ["acquire_A", "claim_A", "commit_spend_A", "retry", "source_returns_A_again", "claim_rejected", "artifact_invalid_terminal"],
      input: { repeated_terminal_state: "consumed" },
      expected: controllerExpected({
        public_error: "artifact_invalid", disposition: "terminal",
        acquisitions: 2, connect_attempts: 1, transports_created: 1,
        spend_callbacks: 1, lease_terminal_states: ["consumed"], retry_delays_ms: [250],
      }),
    },
    {
      id: "artifact-source-repeats-retired-lease",
      driver: "duplicate-lease-identity",
      steps: ["acquire_A", "claim_A", "retire_A", "retry", "source_returns_A_again", "claim_rejected", "artifact_invalid_terminal"],
      input: { repeated_terminal_state: "retired" },
      expected: controllerExpected({
        public_error: "artifact_invalid", disposition: "terminal",
        acquisitions: 2, connect_attempts: 1, transports_created: 1,
        retire_callbacks: 1, lease_terminal_states: ["retired"], retry_delays_ms: [250],
      }),
    },
  ],
  browser_capability_scenarios: [{
    id: "concurrent-capability-invalidation-replacement-barrier",
    driver: "capability-linearization-barrier",
    steps: [
      "start_two_controller_acquisitions",
      "snapshot_enabled_for_both",
      "release_concurrent_acquisition_barrier",
      "opaque_primary_enters_retire_barrier",
      "second_pin_constructor_throws_not_supported",
      "linearize_registry_ca_only",
      "old_snapshot_live_gate_rejects_without_constructor",
      "release_primary_retirement",
      "acquire_replacement_B_with_fresh_ca_only_snapshot",
      "skip_changed_pin_without_constructor",
      "construct_new_endpoint_ca_only",
      "retire_all_leases_and_preserve_replacement_quota",
    ],
    input: {
      concurrent_controllers: 2,
      initial_capability: "enabled",
      invalidated_capability: "ca_only",
      primary_trigger: "browser_pin_opaque",
      invalidation_trigger: "synchronous_not_supported",
      replacement_candidates: ["changed_pin_same_endpoint", "new_ca_endpoint"],
    },
    expected: controllerExpected({
      public_error: "connection_failed", disposition: "terminal",
      acquisitions: 3, connect_attempts: 4, transports_created: 2,
      replacement_acquisitions: 1, replacement_quota_used: 1,
      retire_callbacks: 3, lease_terminal_states: ["retired", "retired", "retired"],
      concurrent_acquisition_peak: 2,
      controller_connector_attempts: 3,
      capability_snapshots: ["enabled", "enabled", "ca_only"],
      pin_constructor_calls: 2, ca_constructor_calls: 1,
      old_snapshot_live_gate_failures: 1,
      post_invalidation_pin_constructor_calls: 0,
      replacement_dial_candidate_ids: ["replacement-ca"],
      peer_final_state: "failed",
      peer_public_error: "transport_security_unsupported",
    }),
  }],
  lease_state_machine: {
    states: ["idle", "claimed", "spending", "consumed", "retired"],
    transitions: [
      ["idle", "claimed", "claim"],
      ["claimed", "spending", "commitSpend"],
      ["spending", "consumed", "durable_result"],
      ["claimed", "retired", "retire"],
    ],
    terminal_states: ["consumed", "retired"],
  },
};

const controllerFailurePhaseByScenario = new Map([
  ["pin-mismatch-same-policy-terminal", "connect"],
  ["pin-to-ca-filtered", "connect"],
  ["browser-opaque-exhausted", "connect"],
  ["all-unsupported", "connect"],
  ["post-spend-retry-preserves-quota", "connect"],
  ["attempt-exhaustion", "artifact"],
  ["invalid-source-retry-after", "artifact"],
  ["race-order-independent-security-priority", "connect"],
  ["failure-ordinal-counts-attempt-once", "connect"],
  ["artifact-expiry-before-race", "connect"],
  ["artifact-expiry-at-race-end", "connect"],
  ["artifact-expiry-immediately-before-spend", "connect"],
  ["artifact-expiry-after-spend", "connect"],
  ["established-session-terminal-termination-resets-cycle", "session"],
  ["single-ca-untrusted-terminal", "connect"],
  ["ca-untrusted-dominates-ordinary-failure", "connect"],
  ["multiple-pin-trigger-endpoints-filtered", "connect"],
  ["capability-snapshot-invalidation-barrier", "connect"],
  ["primary-fsa3-reject-consumes-spent", "connect"],
  ["primary-fsa3-retryable-consumes-spent", "connect"],
  ["replacement-fsa3-reject-consumes-spent", "connect"],
  ["replacement-fsa3-retryable-consumes-spent", "connect"],
  ["primary-fsh3-failure-consumes-spent", "connect"],
  ["replacement-fsh3-failure-consumes-spent", "connect"],
  ["artifact-source-repeats-consumed-lease", "artifact"],
  ["artifact-source-repeats-retired-lease", "artifact"],
  ["concurrent-capability-invalidation-replacement-barrier", "connect"],
]);
for (const scenario of [...controllerVectors.scenarios, ...controllerVectors.browser_capability_scenarios]) {
  const failurePhase = controllerFailurePhaseByScenario.get(scenario.id) ?? null;
  if ((scenario.expected.public_error === null) !== (failurePhase === null)) {
    throw new Error(`controller failure phase is incomplete for ${scenario.id}`);
  }
  scenario.expected.failure_phase = failurePhase;
}
write("controller_vectors.json", controllerVectors);

const inherited = [
  "idna_vectors.json",
  "open_unicode_vectors.json",
  "rpc_error_vectors.json",
  "rpc_malformed_envelopes.json",
  "rpc_notification_vectors.json",
  "session_handler_vectors.json",
];
for (const name of inherited) {
  const value = JSON.parse(readFileSync(join(root, "..", "transport_v2", name), "utf8"));
  value.inherited_codec_from = "transport_v2";
  value.transport_contract_version = 3;
  if (name === "session_handler_vectors.json") {
    const reserved = value.stream_kinds.find(({ id }) => id === "reserved-rpc-kind");
    if (reserved === undefined) throw new Error("missing inherited reserved RPC stream-kind vector");
    value.stream_kinds.splice(value.stream_kinds.indexOf(reserved), 0, {
      ...reserved,
      id: "reserved-previous-rpc-kind",
    });
    reserved.unit = "flowersec.rpc.v3";
  }
  if (name === "idna_vectors.json") {
    value.url_normalization = {
      positive: [
        {
          id: "canonical-ipv4",
          carrier: "websocket",
          path_kind: "direct",
          input: "WSS://127.0.0.1:443/flowersec/v3/direct",
          normalized: "wss://127.0.0.1/flowersec/v3/direct",
          whatwg_roundtrip: true,
        },
        {
          id: "unicode-host",
          carrier: "websocket",
          path_kind: "direct",
          input: "wss://bücher.example/flowersec/v3/direct",
          normalized: "wss://xn--bcher-kva.example/flowersec/v3/direct",
          whatwg_roundtrip: true,
        },
        {
          id: "ipv6-rfc5952",
          carrier: "raw_quic",
          path_kind: "direct",
          input: "quic://[2001:0db8:0:0:0:0:0:1]:0443/",
          normalized: "quic://[2001:db8::1]",
          whatwg_roundtrip: true,
        },
        {
          id: "non-default-port",
          carrier: "webtransport",
          path_kind: "tunnel",
          input: "HTTPS://EXAMPLE.COM:8443/flowersec/webtransport/v3/tunnel",
          normalized: "https://example.com:8443/flowersec/webtransport/v3/tunnel",
          whatwg_roundtrip: true,
        },
        {
          id: "nonnumeric-final-dns-label",
          carrier: "websocket",
          path_kind: "direct",
          input: "wss://gateway.123a/flowersec/v3/direct",
          normalized: "wss://gateway.123a/flowersec/v3/direct",
          whatwg_roundtrip: true,
        },
      ],
      negative: [
        ["ipv4-leading-zero", "websocket", "direct", "wss://127.0.0.01/flowersec/v3/direct"],
        ["ipv4-short", "websocket", "direct", "wss://127.1/flowersec/v3/direct"],
        ["single-integer", "websocket", "direct", "wss://2130706433/flowersec/v3/direct"],
        ["legacy-hex", "websocket", "direct", "wss://0x7f000001/flowersec/v3/direct"],
        ["mixed-hex-first", "websocket", "direct", "wss://0x7f.0.0.1/flowersec/v3/direct"],
        ["mixed-hex-last", "websocket", "direct", "wss://1.2.3.0x7f/flowersec/v3/direct"],
        ["dns-final-decimal", "websocket", "direct", "wss://example.1/flowersec/v3/direct"],
        ["dns-final-empty-hex", "websocket", "direct", "wss://example.0x/flowersec/v3/direct"],
        ["dns-empty-label", "websocket", "direct", "wss://example..com/flowersec/v3/direct"],
        ["dns-trailing-dot", "websocket", "direct", "wss://example.com./flowersec/v3/direct"],
        ["empty-url", "websocket", "direct", ""],
        ["empty-authority", "websocket", "direct", "wss:///flowersec/v3/direct"],
        ["empty-host", "websocket", "direct", "wss://:443/flowersec/v3/direct"],
        ["empty-port", "websocket", "direct", "wss://example.com:/flowersec/v3/direct"],
        ["zero-port", "websocket", "direct", "wss://example.com:0/flowersec/v3/direct"],
        ["port-overflow", "websocket", "direct", "wss://example.com:65536/flowersec/v3/direct"],
        ["nondigit-port", "websocket", "direct", "wss://example.com:https/flowersec/v3/direct"],
        ["ipv6-unclosed-bracket", "websocket", "direct", "wss://[2001:db8::1/flowersec/v3/direct"],
        ["ipv6-bracketless", "websocket", "direct", "wss://2001:db8::1/flowersec/v3/direct"],
        ["ipv6-zone-id", "websocket", "direct", "wss://[fe80::1%25en0]/flowersec/v3/direct"],
        ["ipv6-embedded-ipv4", "websocket", "direct", "wss://[::ffff:192.0.2.128]/flowersec/v3/direct"],
        ["oversized-url", "websocket", "direct", `wss://${"a".repeat(2_020)}.example/flowersec/v3/direct`],
        ["oversized-dns-label", "websocket", "direct", `wss://${"a".repeat(64)}.example/flowersec/v3/direct`],
        ["oversized-dns-host", "websocket", "direct", `wss://${`${"a".repeat(63)}.`.repeat(4)}example/flowersec/v3/direct`],
        ["oversized-authority", "websocket", "direct", `wss://${"a".repeat(256)}/flowersec/v3/direct`],
        ["websocket-scheme-mismatch", "websocket", "direct", "https://example.com/flowersec/v3/direct"],
        ["webtransport-scheme-mismatch", "webtransport", "direct", "wss://example.com/flowersec/webtransport/v3/direct"],
        ["raw-quic-scheme-mismatch", "raw_quic", "direct", "wss://example.com"],
        ["direct-path-mismatch", "websocket", "direct", "wss://example.com/flowersec/v3/tunnel"],
        ["tunnel-path-mismatch", "websocket", "tunnel", "wss://example.com/flowersec/v3/direct"],
        ["webtransport-path-mismatch", "webtransport", "direct", "https://example.com/flowersec/v3/direct"],
        ["raw-quic-path", "raw_quic", "direct", "quic://example.com/flowersec/v3/direct"],
        ["percent-escape", "websocket", "direct", "wss://example.com/%66lowersec/v3/direct"],
        ["userinfo", "websocket", "direct", "wss://user@example.com/flowersec/v3/direct"],
        ["query", "websocket", "direct", "wss://example.com/flowersec/v3/direct?x=1"],
        ["fragment", "websocket", "direct", "wss://example.com/flowersec/v3/direct#x"],
        ["backslash", "websocket", "direct", "wss://example.com\\flowersec/v3/direct"],
      ].map(([id, carrier, path_kind, input]) => ({
        id,
        carrier,
        path_kind,
        input,
        error_code: "invalid_artifact",
      })),
    };
  }
  if (name === "open_unicode_vectors.json") {
    value.negative.push({
      id: "metadata-negative-zero",
      kind: "rpc",
      metadata_json: "{\"a\":-0}",
    });
  }
  write(name, value);
}
