#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative));
const json = (relative) => JSON.parse(read(relative).toString("utf8"));

function canonicalJSON(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    assert(Number.isSafeInteger(value) && !Object.is(value, -0));
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  assert.equal(typeof value, "object");
  return "{" + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ":" + canonicalJSON(value[key])).join(",") + "}";
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

const registry = json("stability/transport_v3_contract.json");
assert.equal(Array.isArray(registry.fixture_generation), true,
  "transport v3 fixture generation ownership must be an explicit list");
assert.deepEqual(registry.fixture_generation.map(({ producer }) => producer), [
  "testdata/transport_v3/generate_contract_vectors.mjs",
  "testdata/transport_v3/generate_crypto_vectors.mjs",
  "testdata/transport_v3/generate_handshake_vectors.mjs",
  "flowersec-go/internal/cmd/issuer-admission-vectors/main.go",
]);
const generatedOutputs = new Set();
for (const fixtureGeneration of registry.fixture_generation) {
  assert.deepEqual(fixtureGeneration.check_command.at(-1), "--check");
  for (const output of fixtureGeneration.outputs) {
    assert.equal(generatedOutputs.has(output), false, `fixture output has duplicate owners: ${output}`);
    generatedOutputs.add(output);
  }
  const generation = spawnSync(
    fixtureGeneration.check_command[0],
    fixtureGeneration.check_command.slice(1),
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(generation.status, 0,
    `transport v3 fixture regeneration check failed: ${generation.stderr || generation.stdout}`);
}
const artifactVectors = json("testdata/transport_v3/artifact_vectors.json");
assert.equal(
  canonicalJSON(json("flowersec-swift/Tests/FlowersecTests/Fixtures/transport_v3_direct_artifact.json")),
  artifactVectors.positive[0].artifact_json,
  "the bundled iOS artifact must stay identical to the shared direct vector",
);
assert.equal(registry.version, 3);
assert.equal(registry.status, "final");
assert.equal(registry.design.version, "3.0.0");
assert.equal(registry.design.baseline_commit, "026cb52d116d2a04de50d0f0621fff57c7657120");
assert.equal(
  registry.design.sha256,
  "236b332e6cf2f755b918721c8535191b2f8c8861bc32c07da329f823c1f04eba",
);
assert.equal(registry.design.source_path, "docs/TRANSPORT_V3_DESIGN.zh-CN.md");
assert.equal(
  createHash("sha256").update(read(registry.design.source_path)).digest("hex"),
  registry.design.sha256,
  "the checked-in Chinese v3 source must match the frozen design digest",
);
assert.equal(registry.profiles.session, "flowersec/3");
assert.equal(registry.frame_family.bootstrap, "FSB3");
assert.equal(registry.frame_family.datagram, "FSD3");
assert.deepEqual(registry.artifact_schema.collection_rules["path.candidates"].unique_by, [
  ["id"],
  ["endpoint_key"],
], "candidate IDs and endpoint keys must each be independently unique");
assert.deepEqual({
  open_kind_bytes_min: registry.limits.open_kind_bytes_min,
  open_kind_bytes_max: registry.limits.open_kind_bytes_max,
  open_metadata_bytes: registry.limits.open_metadata_bytes,
  open_metadata_depth: registry.limits.open_metadata_depth,
  open_metadata_nodes: registry.limits.open_metadata_nodes,
  open_metadata_object_members: registry.limits.open_metadata_object_members,
  open_metadata_array_elements: registry.limits.open_metadata_array_elements,
  open_metadata_key_bytes: registry.limits.open_metadata_key_bytes,
  open_metadata_string_bytes: registry.limits.open_metadata_string_bytes,
}, {
  open_kind_bytes_min: 1,
  open_kind_bytes_max: 128,
  open_metadata_bytes: 4096,
  open_metadata_depth: 4,
  open_metadata_nodes: 64,
  open_metadata_object_members: 64,
  open_metadata_array_elements: 32,
  open_metadata_key_bytes: 64,
  open_metadata_string_bytes: 512,
});
assert.deepEqual(registry.tls_policy.modes, ["ca", "pin"]);
assert.equal(registry.tls_policy.mode_fallback, false);
assert.equal(registry.capability.first_release_emits_adapter_not_composed, false);
assert.deepEqual(registry.capability.dynamic_conversions, [
  { runtime: "typescript/browser", trigger: "websocket_api_unavailable", carrier: "websocket", from: ["W3", ["ca"]], to: ["unsupported", "browser_websocket_api_unavailable"] },
  { runtime: "typescript/browser", trigger: "webtransport_api_unavailable", carrier: "webtransport", from: ["H3", ["ca"]], to: ["unsupported", "browser_webtransport_api_unavailable"] },
  { runtime: "typescript/node", trigger: "native_addon_unavailable", carrier: "raw_quic", from: ["Q4N", ["ca", "pin"]], to: ["unsupported", "node_native_transport_unavailable"] },
  { runtime: "typescript/browser", trigger: "pin_provider_not_registered", carrier: "webtransport", from: ["H3", ["ca", "pin"]], to: ["H3", ["ca"]] },
]);
assert.equal(registry.capability.browser_pin_provider.snapshot_semantics, "immutable_with_live_pin_gate");
assert.equal(registry.capability.browser_pin_provider.replacement_refreshes_snapshot, true);
assert.equal(registry.controller.maximum_policy_sensitive_replacement_leases_per_cycle, 1);
assert.deepEqual(registry.url_normalization.forbidden_characters, ["\\", "?", "#", "%"]);
assert.deepEqual(registry.lease.terminal_states, ["consumed", "retired"]);
assert.deepEqual(Object.keys(registry.artifact_schema.scalar_rules).sort(), [
  "artifact.profile",
  "artifact.v",
  "candidate.carrier",
  "candidate.id",
  "candidate.url",
  "candidate.wire_profile",
  "correlation.tags[].key",
  "correlation.tags[].value",
  "correlation.v",
  "path.expected_peer_endpoint_instance_id",
  "path.kind",
  "path.listener_audience",
  "path.local_endpoint_instance_id",
  "path.rendezvous_group_id",
  "path.role",
  "path.routing_token",
  "path.token",
  "scope.critical",
  "scope.scope",
  "scope.scope_version",
  "session.channel_id",
  "session.contract_hash_b64u",
  "session.default_suite",
  "session.e2ee_psk_b64u",
  "session.establish_timeout_seconds",
  "session.idle_timeout_seconds",
  "session.init_expire_at_unix_s",
  "session.max_inbound_streams",
  "session.rekey_completion_timeout_seconds",
  "session.rekey_prepare_timeout_seconds",
  "session.selected_features",
].sort());
assert.deepEqual(Object.keys(registry.capability.closed_tuple_sets).sort(), ["H3", "H4", "Q4M", "Q4N", "W3", "W4"]);
assert.deepEqual(Object.keys(registry.capability.runtime_matrix).sort(), registry.capability.runtime_identities.slice().sort());
assert.equal(registry.controller.maximum_attempts_max, Number.MAX_SAFE_INTEGER);
assert.equal(registry.controller.attempt_counter_saturates_at, Number.MAX_SAFE_INTEGER);
assert.deepEqual(registry.controller.blocked_policy_key, ["endpoint_key", "complete_declared_tls_policy_digest"]);
assert.equal(registry.controller.replacement_same_endpoint_pin_to_ca, false);
assert.deepEqual(registry.fsa3.statuses, { success: 0, reject: 1, retryable: 2 });
assert.deepEqual(registry.fsa3.required_reason_status, { expired_artifact: "retryable" });
assert.equal(registry.fsa3.transport_security_reasons_forbidden, true);
assert.equal(registry.control_plane.redacted_input_error_text, "flowersec control-plane input is invalid");
assert.equal(registry.control_plane.redacted_issuance_error_text, "flowersec artifact issuance failed");
assert.deepEqual(registry.control_plane.scheme_carrier_mapping, {
  wss: "websocket",
  quic: "raw_quic",
  https: "webtransport",
});
assert.equal(registry.url_normalization.scheme_pattern, "^[A-Za-z][A-Za-z0-9+.-]*$");
assert.equal(registry.url_normalization.scheme_lowercase, true);
assert.equal(registry.url_normalization.input_utf8_bytes_min, 1);
assert.equal(registry.url_normalization.input_utf8_bytes_max, 2048);
assert.equal(registry.url_normalization.split_delimiter, "first_literal_://");
assert.equal(registry.url_normalization.authority_split, "first_ascii_slash");
assert.equal(registry.url_normalization.authority_non_empty, true);
assert.equal(registry.url_normalization.userinfo_forbidden, true);
assert.equal(registry.url_normalization.authority_at_sign_forbidden, true);
assert.equal(registry.url_normalization.authority_bracketed_ipv6_only, true);
assert.equal(registry.url_normalization.authority_closing_bracket_required, true);
assert.equal(registry.url_normalization.unbracketed_authority_max_colons, 1);
assert.equal(registry.url_normalization.path_is_opaque_after_first_slash, true);
assert.equal(registry.url_normalization.path_empty_allowed_only_for_raw_quic, true);
assert.deepEqual(registry.url_normalization.ipv4, {
  ascii_digit_dot_requires_four_octets: true,
  octet_minimum: 0,
  octet_maximum: 255,
  leading_zero_forbidden: true,
});
assert.deepEqual(registry.url_normalization.dns, {
  empty_label_forbidden: true,
  trailing_dot_forbidden: true,
  label_bytes_max: 63,
  host_bytes_max: 253,
});
assert.deepEqual(registry.url_normalization.ipv6, {
  rfc5952_lowercase_compressed: true,
  zone_id_forbidden: true,
  embedded_dotted_decimal_forbidden: true,
});
assert.deepEqual(registry.url_normalization.idna, {
  unicode_version: "15.1",
  profile: "UTS46 lookup",
  transitional: false,
  std3: true,
  check_hyphens: true,
  check_contextj: true,
  check_bidi: true,
  check_dns_length: true,
  output: "lowercase_alabel",
});

for (const relative of Object.values(registry.docs)) {
  assert(fs.existsSync(path.join(root, relative)), "missing v3 document " + relative);
  const source = read(relative).toString("utf8");
  assert.match(source, /Status: final/);
  assert.match(source, /Version: 3\.0\.0/);
  assert.match(source, /flowersec\/3/);
  assert.match(source, /serverCertificateHashes|FSB3/);
}
const wireDocument = read(registry.docs.wire).toString("utf8");
const architectureDocument = read(registry.docs.architecture).toString("utf8");
assert(!wireDocument.includes("flowersec-v2-tls-policy"),
  "the v3-only TLS policy domain must not be represented as a v2 replacement");
assert.match(wireDocument, /Normative priority is:\s*\n\s*1\. the final Chinese v3 design;\s*\n\s*2\. the frozen v2 baseline sources/,
  "the wire contract must preserve the final design's frozen-v2 priority tier");
assert.match(wireDocument, /English transcription is a required derived consistency artifact, not an\s+independent priority tier/,
  "the derived English transcription must not become a normative priority tier");
assert(architectureDocument.includes("`errors.As` to recover `ControlPlaneError`"),
  "the architecture must define errors.As for ControlPlaneError");
assert(architectureDocument.includes("`Unwrap()` returns only `ErrInvalidControlPlaneInput`"),
  "the architecture must freeze the ControlPlaneError unwrap sentinel");
assert(architectureDocument.includes("`ErrIssuanceFailed` is independent"),
  "the architecture must keep issuance failures outside ControlPlaneError");
assert(Array.isArray(registry.design.traceability) && registry.design.traceability.length >= 16,
  "design traceability must cover all major v3 domains");
const traceabilityClauses = registry.design.traceability.map((entry) => entry.clause);
for (const requiredClause of [
  "3.1", "3.2", "3.3", "3.4", "4", "5", "6", "7", "8", "9", "10", "11",
  "12.1", "12.2", "12.3", "12.4", "13.1", "13.2", "13.3", "13.4", "14", "15",
]) assert(traceabilityClauses.includes(requiredClause), `missing traceability clause: ${requiredClause}`);
assert.equal(new Set(traceabilityClauses).size, traceabilityClauses.length, "traceability clause IDs must be unique");
const allFixtureReferences = registry.wire_fixtures
  .map((fixture) => `wire_fixtures[id=${fixture.id}]`)
  .sort();
function resolveRegistryReference(reference) {
  let current = registry;
  for (const segment of reference.split(".")) {
    const match = /^([a-z0-9_]+)(?:\[id=([a-z0-9_]+)\])?$/.exec(segment);
    assert(match, `invalid registry path segment ${segment}`);
    assert(current !== null && typeof current === "object" && !Array.isArray(current),
      `${reference} segment ${segment} does not select an object`);
    assert(Object.hasOwn(current, match[1]), `${reference} unknown registry field ${match[1]}`);
    current = current[match[1]];
    if (match[2] !== undefined) {
      assert(Array.isArray(current), `${reference} field ${match[1]} is not selectable by id`);
      current = current.find((item) => item?.id === match[2]);
      assert.notEqual(current, undefined, `${reference} has no id ${match[2]}`);
    }
  }
  return current;
}
for (const clause of ["12.1", "13.1"]) {
  const entry = registry.design.traceability.find((candidate) => candidate.clause === clause);
  const fixtureReferences = entry.registry_vector
    .filter((reference) => reference.startsWith("wire_fixtures[id="))
    .sort();
  assert.deepEqual(fixtureReferences, allFixtureReferences,
    `${clause} traceability must cover the complete v3 fixture inventory`);
}
const clause4 = registry.design.traceability.find((candidate) => candidate.clause === "4");
assert(clause4.registry_vector.includes("wire_fixtures[id=open_unicode]"),
  "clause 4 traceability must cover the OPEN Unicode fixture");
for (const entry of registry.design.traceability) {
  assert(typeof entry.clause === "string" && entry.clause.length > 0, "traceability clause ID is required");
  assert(typeof entry.title === "string" && entry.title.length > 0, `${entry.clause} traceability title is required`);
  for (const field of ["source", "tests", "docs", "registry_vector"]) {
    assert(Array.isArray(entry[field]) && entry[field].length > 0, `${entry.clause} ${field} is required`);
  }
  for (const relative of [...entry.source, ...entry.tests, ...entry.docs]) {
    assert(fs.existsSync(path.join(root, relative)), `${entry.clause} missing traceability path ${relative}`);
  }
  assert(entry.registry_vector.some((reference) => reference.startsWith("wire_fixtures[id=")),
    `${entry.clause} must reference a wire fixture`);
  for (const reference of entry.registry_vector) {
    assert(typeof reference === "string" && reference.length > 0, `${entry.clause} registry/vector reference is required`);
    resolveRegistryReference(reference);
  }
}
for (const fixture of registry.wire_fixtures) {
  assert(fs.existsSync(path.join(root, fixture.path)), "missing fixture " + fixture.path);
}
for (const output of generatedOutputs) {
  assert(registry.wire_fixtures.some(({ path: fixturePath }) => fixturePath === output),
    `generated output is not registered as a wire fixture: ${output}`);
}
for (const fixture of registry.wire_fixtures) {
  const owners = registry.fixture_generation.filter((generation) => generation.outputs.includes(fixture.path));
  assert.equal(owners.length, 1, `${fixture.path} must have exactly one fixture generator owner`);
}
assert.deepEqual(new Set(registry.wire_fixtures.map((fixture) => fixture.id)), new Set([
  "artifact_admission",
  "capability",
  "controller",
  "crypto",
  "datagram",
  "handshake",
  "idna",
  "issuer_admission",
  "open_unicode",
  "rpc_error",
  "rpc_malformed_envelopes",
  "rpc_notifications",
  "session_handlers",
  "session_wire",
  "version_isolation",
]));
for (const fixture of registry.wire_fixtures) {
  assert.deepEqual(Object.keys(fixture.consumers).sort(), ["go", "rust", "swift", "typescript"],
    `${fixture.id} consumer languages`);
  for (const consumer of Object.values(fixture.consumers).flat()) {
    assert(fs.existsSync(path.join(root, consumer)), `${fixture.id} missing consumer ${consumer}`);
  }
}

const artifacts = json("testdata/transport_v3/artifact_vectors.json");
assert.equal(artifacts.version, 3);
assert.equal(artifacts.profile, "flowersec/3");
assert.deepEqual(
  artifacts.positive.map((vector) => [vector.id, vector.winners.length]),
  [["direct-mixed-security", 4], ["tunnel-mixed-security", 4], ["direct-single-candidate", 1]],
);
const declaredPinCounts = new Set();
for (const vector of artifacts.positive) {
  const artifact = JSON.parse(vector.artifact_json);
  assert.equal(canonicalJSON(artifact), vector.artifact_json, vector.id + " artifact JCS");
  const projection = {
    allowed_suites: artifact.session.allowed_suites,
    channel_id: artifact.session.channel_id,
    default_suite: artifact.session.default_suite,
    establish_timeout_seconds: artifact.session.establish_timeout_seconds,
    idle_timeout_seconds: artifact.session.idle_timeout_seconds,
    max_inbound_streams: artifact.session.max_inbound_streams,
    profile: "flowersec/3",
    rekey_completion_timeout_seconds: artifact.session.rekey_completion_timeout_seconds,
    rekey_prepare_timeout_seconds: artifact.session.rekey_prepare_timeout_seconds,
    selected_features: artifact.session.selected_features,
  };
  assert.equal(canonicalJSON(projection), vector.session_canonical_json);
  assert.equal(
    digest("flowersec-v3-session-contract\0", projection).toString("base64url"),
    vector.session_contract_hash_b64u,
  );
  assert.equal(
    digest("flowersec-v3-candidates\0", vector.candidates_canonical_json).toString("base64url"),
    vector.candidate_set_hash_b64u,
  );
  for (const policy of vector.tls_policy_digests) {
    assert.equal(
      digest("flowersec-v3-tls-policy\0", policy.canonical_json).toString("hex"),
      policy.digest_hex,
    );
    assert.equal(Buffer.from(policy.digest_hex, "hex").toString("base64url"), policy.digest_b64u);
    const decodedPolicy = JSON.parse(policy.canonical_json);
    declaredPinCounts.add(decodedPolicy.mode === "pin" ? decodedPolicy.pins.length : 0);
  }
  const admissions = createHash("sha256").update(Buffer.from("flowersec-v3-acceptor-admissions\0"));
  const ordered = [...vector.winners].sort((left, right) =>
    left.candidate_id < right.candidate_id ? -1 : left.candidate_id > right.candidate_id ? 1 : 0);
  for (const winner of ordered) {
    const frame = Buffer.from(winner.fsb3_hex, "hex");
    assert.equal(frame.subarray(0, 4).toString("ascii"), "FSB3");
    assert.equal(frame[4], 3);
    assert.equal(frame.readUInt16BE(6), 0);
    assert.equal(frame.readUInt32BE(8), frame.length - 12);
    const payload = frame.subarray(12).toString("utf8");
    assert.equal(canonicalJSON(JSON.parse(payload)), payload);
    assert.equal(
      createHash("sha256").update(Buffer.from("flowersec-v3-admission\0")).update(frame).digest("hex"),
      winner.admission_binding_hex,
    );
    admissions.update(lp(frame));
  }
  assert.equal(admissions.digest("hex"), vector.acceptor_admissions_hash_hex);
}
assert.deepEqual(declaredPinCounts, new Set([0, 1, 2, 4]));
const requiredArtifactNegative = new Set([
  "artifact-duplicate-profile", "artifact-missing-version", "artifact-unknown-field",
  "session-contract-hash-mismatch", "session-suite-not-sorted", "direct-cross-variant-role",
  "candidate-count-zero", "candidate-count-five", "candidate-duplicate-endpoint",
  "candidate-plaintext-websocket", "pin-unknown-algorithm", "pin-not-sorted",
  "pin-expiry-fraction", "pin-expiry-exponent", "pin-expiry-negative-zero",
  "scope-payload-fraction", "scope-payload-exponent", "scope-payload-negative-zero", "scope-payload-positive-safe-integer-overflow",
  "scope-payload-negative-safe-integer-overflow", "scope-duplicate",
  "correlation-tag-duplicate", "v2-profile-cross-version", "v2-path-cross-version",
  "tunnel-endpoint-identifiers-equal", "tunnel-role-zero", "tunnel-token-non-ascii",
]);
const artifactNegative = new Set(artifacts.negative.map((vector) => vector.id));
for (const id of requiredArtifactNegative) assert(artifactNegative.has(id), `missing artifact rejection vector ${id}`);
assert.deepEqual(
  Object.keys(artifacts.scalar_coverage).sort(),
  Object.keys(registry.artifact_schema.scalar_rules).sort(),
  "every registered artifact scalar must map to shared boundary vectors",
);
const artifactVectorIDs = new Set([
  ...artifacts.positive.map((vector) => vector.id),
  ...artifacts.negative.map((vector) => vector.id),
  ...artifacts.scalar_boundaries.map((vector) => vector.id),
  ...artifacts.scoped_payload_boundaries.map((vector) => vector.id),
]);
for (const [field, ids] of Object.entries(artifacts.scalar_coverage)) {
  assert(ids.length >= 2, `${field} must have positive and rejection/boundary coverage`);
  for (const id of ids) assert(artifactVectorIDs.has(id), `${field} references missing vector ${id}`);
}
assert(artifacts.scalar_boundaries.length >= 25);
assert(artifacts.scoped_payload_boundaries.length >= 16);
assert(artifacts.scoped_payload_boundaries.some((vector) => vector.id === "scope-payload-canonical-bytes-max" && vector.accepted));
assert(artifacts.scoped_payload_boundaries.some((vector) => vector.id === "scope-payload-canonical-bytes-over" && !vector.accepted));
for (const vector of [...artifacts.scalar_boundaries, ...artifacts.scoped_payload_boundaries]) {
  assert.equal(canonicalJSON(JSON.parse(vector.artifact_json)), vector.artifact_json, vector.id);
}
assert.deepEqual(new Set(artifacts.artifact_byte_negative.map((vector) => vector.id)), new Set([
  "artifact-invalid-utf8", "artifact-trailing-byte",
]));
const singlePinExpiry = artifacts.active_pin_snapshots.find(
  (vector) => vector.id === "single-pin-expired-exclusive-boundary",
);
assert(singlePinExpiry, "missing single-pin exclusive-expiry vector");
assert.equal(singlePinExpiry.declared.mode, "pin");
assert.equal(singlePinExpiry.declared.pins.length, 1);
assert.equal(singlePinExpiry.attempt_now, singlePinExpiry.declared.pins[0].not_after_unix_s);
assert.deepEqual(singlePinExpiry.active_value_b64u, []);
assert.equal(singlePinExpiry.result, "tls_policy_expired");
for (const vector of artifacts.active_pin_snapshots) {
  assert(["attempt", "tls_policy_expired"].includes(vector.result), `${vector.id} result`);
  if (vector.result === "tls_policy_expired") assert.deepEqual(vector.active_value_b64u, [], vector.id);
}
assert(artifacts.fsb3_negative.length >= 14);
assert(artifacts.fsa3_negative.length >= 12);
for (const [name, vectors] of [["FSB3", artifacts.fsb3_negative], ["FSA3", artifacts.fsa3_negative]]) {
  const ids = new Set(vectors.map((vector) => vector.id));
  assert.equal(ids.size, vectors.length, `${name} rejection vector IDs must be unique`);
  assert(vectors.every((vector) => typeof vector.value_hex === "string" && vector.value_hex.length >= 2));
}

for (const item of artifacts.fsa3) {
  const frame = Buffer.from(item.frame_hex, "hex");
  assert.equal(frame.subarray(0, 4).toString("ascii"), "FSA3");
  assert.equal(frame[4], 3);
  assert.equal(frame[5], item.status);
  assert.equal(frame.readUInt16BE(6), Buffer.byteLength(item.reason));
  assert.equal(frame.subarray(8).toString("ascii"), item.reason);
}
const expiredAdmission = artifacts.fsa3.find((item) => item.id === "retry-expired-artifact");
assert.deepEqual(expiredAdmission, {
  id: "retry-expired-artifact",
  status: 2,
  reason: "expired_artifact",
  frame_hex: "4653413303020010657870697265645f6172746966616374",
});

const capabilities = json("testdata/transport_v3/capability_vectors.json");
assert.equal(capabilities.version, 3);
assert.equal(capabilities.exact_browser_pin_provider.full_version, "151.0.7922.34");
assert.equal(json("flowersec-ts/package.json").devDependencies["@playwright/test"], "1.62.1");
for (const vector of capabilities.vectors) {
  assert.equal(canonicalJSON(JSON.parse(vector.canonical_json)), vector.canonical_json);
  assert.equal(
    digest("flowersec-v3-runtime-capability\0", vector.canonical_json).toString("hex"),
    vector.digest_hex,
  );
}
assert(capabilities.invalid.length >= 30);
const requiredCapabilityInvalid = new Set([
  "schema-version-v2", "duplicate-tuple-identity", "reliable-streams-false",
  "reliable-streams-not-boolean", "datagrams-not-boolean", "migration-not-boolean",
  "unknown-path", "unknown-session-role", "dial-direct-server-closed-tuple",
  "listen-tunnel-client-closed-tuple", "security-modes-reversed",
  "security-modes-duplicate", "security-mode-unknown", "tuple-order-not-ascii",
  "duplicate-descriptor-field", "non-jcs-descriptor",
]);
const capabilityInvalid = new Set(capabilities.invalid.map((vector) => vector.id));
for (const id of requiredCapabilityInvalid) assert(capabilityInvalid.has(id), `missing capability rejection vector ${id}`);

const controller = json("testdata/transport_v3/controller_vectors.json");
assert.equal(controller.version, 3);
assert.equal(controller.defaults.initial_backoff_ms, 250);
assert.equal(controller.defaults.maximum_backoff_ms, 30000);
assert.equal(controller.defaults.wall_clock_recheck_max_interval_ms, 1000);
assert.equal(controller.defaults.maximum_policy_sensitive_replacement_leases_per_cycle, 1);
assert(controller.scenarios.some((item) => item.id === "pin-to-ca-filtered"));
assert(controller.scenarios.some((item) => item.id === "lease-cancellation-first"));
assert(controller.scenarios.some((item) => item.id === "post-spend-retry-preserves-quota"));
assert(controller.scenarios.some((item) => item.id === "replacement-expired-before-race-returns-primary"));
assert(controller.scenarios.some((item) => item.id === "replacement-acquisition-retryable-continues-search"));
const replacementBeforeRace = controller.scenarios.find((item) => item.id === "replacement-expired-before-race-returns-primary");
assert.equal(replacementBeforeRace.input.expiry_boundary, "before_race");
assert.deepEqual(replacementBeforeRace.expected.lease_terminal_states, ["retired", "retired", "consumed"]);
const replacementSearch = controller.scenarios.find((item) => item.id === "replacement-acquisition-retryable-continues-search");
assert.equal(replacementSearch.input.replacement_acquisition_failure, "retryable");
assert.deepEqual(replacementSearch.expected.retry_delays_ms, [500]);
assert(Array.isArray(controller.browser_capability_scenarios));
assert(controller.browser_capability_scenarios.length > 0);
const sharedControllerIDs = new Set(controller.scenarios.map((item) => item.id));
const browserCapabilityIDs = new Set();
for (const scenario of controller.browser_capability_scenarios) {
  assert.equal(typeof scenario.id, "string");
  assert(!sharedControllerIDs.has(scenario.id), `browser capability scenario duplicates shared ID ${scenario.id}`);
  assert(!browserCapabilityIDs.has(scenario.id), `duplicate browser capability scenario ${scenario.id}`);
  browserCapabilityIDs.add(scenario.id);
}
const capabilityBarrier = controller.browser_capability_scenarios.find(
  (item) => item.id === "concurrent-capability-invalidation-replacement-barrier",
);
assert(capabilityBarrier, "missing concurrent browser capability invalidation barrier");
assert.equal(capabilityBarrier.driver, "capability-linearization-barrier");
assert.deepEqual(capabilityBarrier.expected.capability_snapshots, ["enabled", "enabled", "ca_only"]);
assert.equal(capabilityBarrier.expected.old_snapshot_live_gate_failures, 1);
assert.equal(capabilityBarrier.expected.post_invalidation_pin_constructor_calls, 0);
assert.equal(capabilityBarrier.expected.replacement_quota_used, 1);
assert.deepEqual(capabilityBarrier.expected.lease_terminal_states, ["retired", "retired", "retired"]);

const idna = json("testdata/transport_v3/idna_vectors.json");
assert.equal(idna.unicode_version, "15.1.0");
for (const id of ["a-label", "unicode-15-1-extension-i", "unicode-15-1-extension-i-alabel"]) {
  assert(idna.positive.some((item) => item.id === id), `missing root IDNA positive vector ${id}`);
}
for (const id of ["post-unicode-15-1-u-label", "post-unicode-15-1-a-label"]) {
  assert(idna.negative.some((item) => item.id === id), `missing root IDNA negative vector ${id}`);
}
assert.deepEqual(idna.url_normalization.positive.map((item) => item.id), [
  "canonical-ipv4",
  "unicode-host",
  "ipv6-rfc5952",
  "non-default-port",
  "nonnumeric-final-dns-label",
]);
assert(idna.url_normalization.positive.every((item) => item.whatwg_roundtrip === true));
assert.deepEqual(idna.url_normalization.negative.map((item) => item.id), [
  "ipv4-leading-zero",
  "ipv4-short",
  "single-integer",
  "legacy-hex",
  "mixed-hex-first",
  "mixed-hex-last",
  "dns-final-decimal",
  "dns-final-empty-hex",
  "dns-empty-label",
  "dns-trailing-dot",
  "empty-url",
  "empty-authority",
  "empty-host",
  "empty-port",
  "zero-port",
  "port-overflow",
  "nondigit-port",
  "ipv6-unclosed-bracket",
  "ipv6-bracketless",
  "ipv6-zone-id",
  "ipv6-embedded-ipv4",
  "oversized-url",
  "oversized-dns-label",
  "oversized-dns-host",
  "oversized-authority",
  "websocket-scheme-mismatch",
  "webtransport-scheme-mismatch",
  "raw-quic-scheme-mismatch",
  "direct-path-mismatch",
  "tunnel-path-mismatch",
  "webtransport-path-mismatch",
  "raw-quic-path",
  "percent-escape",
  "userinfo",
  "query",
  "fragment",
  "backslash",
]);
assert(idna.url_normalization.negative.every((item) => item.error_code === "invalid_artifact"));
const backslashURL = idna.url_normalization.negative.find((item) => item.id === "backslash").input;
assert.equal(backslashURL, "wss://example.com\\flowersec/v3/direct");
assert.equal([...backslashURL].filter((character) => character === "\\").length, 1);

const crypto = json("testdata/transport_v3/crypto_vectors.json");
for (const vector of crypto.vectors) {
  assert(vector.fss3_hex.startsWith("4653533303"));
  assert(vector.fsr3_header_hex.startsWith("4653523303"));
  assert(Buffer.from(vector.aad_hex, "hex").includes(Buffer.from("flowersec-v3-record\0")));
}
const datagram = json("testdata/transport_v3/datagram_vectors.json");
assert.deepEqual(datagram.vectors.map((item) => item.suite), [1, 2]);
for (const vector of datagram.vectors) assert(vector.header_hex.startsWith("4653443303"));
const handshake = json("testdata/transport_v3/handshake_vectors.json");
assert.equal(handshake.profile, "flowersec/3");
for (const vector of handshake.vectors) {
  assert(vector.fsc3_hex.startsWith("4653433303"));
  assert(vector.client_init_hex.startsWith("4653483303"));
}

const versionIsolation = json("testdata/transport_v3/version_isolation_vectors.json");
assert.equal(versionIsolation.version, 3);
assert.equal(versionIsolation.source.design_sha256, registry.design.sha256);
assert.equal(versionIsolation.source.rules_are_not_extended_by_vectors, true);
assert.deepEqual(versionIsolation.frames.map((frame) => frame.id), [
  "fsb3", "fsa3", "fsc3", "fsh3", "fss3", "fsr3", "fsd3",
]);
for (const frame of versionIsolation.frames) {
  const v3 = Buffer.from(frame.v3_hex, "hex");
  const v2Magic = Buffer.from(frame.v2_magic_hex, "hex");
  const v2Version = Buffer.from(frame.v2_version_hex, "hex");
  assert.equal(v2Magic.length, v3.length, `${frame.id} magic mutation length`);
  assert.equal(v2Version.length, v3.length, `${frame.id} version mutation length`);
  assert.equal(v3[3], 0x33, `${frame.id} v3 magic suffix`);
  assert.equal(v2Magic[3], 0x32, `${frame.id} v2 magic mutation`);
  assert.equal(v3[4], 3, `${frame.id} v3 version`);
  assert.equal(v2Version[4], 2, `${frame.id} v2 version mutation`);
  assert.deepEqual(v2Magic.subarray(0, 3), v3.subarray(0, 3), `${frame.id} magic prefix`);
  assert.deepEqual(v2Magic.subarray(4), v3.subarray(4), `${frame.id} magic mutation scope`);
  assert.deepEqual(v2Version.subarray(0, 4), v3.subarray(0, 4), `${frame.id} version prefix`);
  assert.deepEqual(v2Version.subarray(5), v3.subarray(5), `${frame.id} version mutation scope`);
  assert.notEqual(frame.v3_hex, frame.v2_magic_hex, `${frame.id} magic isolation`);
  assert.notEqual(frame.v3_hex, frame.v2_version_hex, `${frame.id} version isolation`);
}
assert.deepEqual(registry.version_isolation.rejection_fields, ["magic", "profile", "path", "subprotocol", "alpn", "crypto_label"]);
assert.deepEqual(registry.version_isolation.v2_identifiers.magic, ["FSB2", "FSA2", "FSC2", "FSH2", "FSS2", "FSR2", "FSD2"]);
assert.deepEqual(registry.version_isolation.v2_identifiers.profiles, ["flowersec/2", "flowersec-direct/2", "flowersec-tunnel/2"]);
assert.deepEqual(registry.version_isolation.v2_identifiers.paths, [
  "/flowersec/v2/direct", "/flowersec/v2/tunnel",
  "/flowersec/webtransport/v2/direct", "/flowersec/webtransport/v2/tunnel",
]);
assert.deepEqual(registry.version_isolation.v2_identifiers.subprotocols, ["flowersec.direct.v2", "flowersec.tunnel.v2"]);
assert.deepEqual(registry.version_isolation.v2_identifiers.alpn, ["flowersec-direct/2", "flowersec-tunnel/2"]);
for (const field of ["profile_mutations", "path_mutations", "subprotocol_mutations", "alpn_mutations", "crypto_label_mutations"]) {
  assert(Array.isArray(versionIsolation[field]) && versionIsolation[field].length > 0, `${field} is required`);
  for (const mutation of versionIsolation[field]) {
    assert.equal(mutation.error_code, "version_isolation", `${field}/${mutation.id}`);
    assert.notEqual(mutation.v3, mutation.v2, `${field}/${mutation.id} must cross versions`);
  }
}
assert.deepEqual(
  versionIsolation.identifier_sets.magic.map((item) => item.v2),
  registry.version_isolation.v2_identifiers.magic,
);
assert.deepEqual(
  versionIsolation.identifier_sets.profile.map((item) => item.v2),
  registry.version_isolation.v2_identifiers.profiles,
);
assert.deepEqual(
  versionIsolation.identifier_sets.path.map((item) => item.v2),
  registry.version_isolation.v2_identifiers.paths,
);
assert.deepEqual(
  versionIsolation.identifier_sets.subprotocol.map((item) => item.v2),
  registry.version_isolation.v2_identifiers.subprotocols,
);
assert.deepEqual(
  versionIsolation.identifier_sets.alpn.map((item) => item.v2),
  registry.version_isolation.v2_identifiers.alpn,
);
assert.deepEqual(
  versionIsolation.identifier_sets.crypto_label.map((item) => item.v2),
  registry.version_isolation.v2_identifiers.crypto_labels,
);
assert.equal(versionIsolation.inherited_codecs.fsh3.inherited_codec_from, "transport_v2");
assert.equal(versionIsolation.inherited_codecs.open.inherited_codec_from, "transport_v2");
assert.equal(versionIsolation.inherited_codecs.rpc.inherited_codec_from, "transport_v2");
assert.match(versionIsolation.inherited_codecs.rpc.envelope_json, /"ratio":1\.5/);

const forbiddenCrypto = /flowersec v2 (?:server finished|client finished|epoch zero|control root|stream root|setup root|rekey root|next epoch|stream|control|record key|nonce|unreliable)|flowersec-v2-(?:handshake|setup|record|open|unreliable)/;
function walk(relative) {
  const absolute = path.join(root, relative);
  if (!fs.existsSync(absolute)) return [];
  const result = [];
  for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
    const child = path.join(relative, entry.name);
    if (entry.isDirectory()) result.push(...walk(child));
    else result.push(child);
  }
  return result;
}
for (const relative of [
  ...walk("flowersec-ts/src/v3"),
  ...walk("flowersec-go/internal/protocolv3"),
  ...walk("flowersec-rust/src"),
  ...walk("flowersec-swift/Sources/Flowersec"),
]) {
  if (!/[vV]3/.test(path.basename(relative)) && !relative.includes("/v3/") && !relative.includes("protocolv3")) continue;
  if (!/\.(?:ts|go|rs|swift)$/.test(relative)) continue;
  assert.doesNotMatch(read(relative).toString("utf8"), forbiddenCrypto, relative + " contains a v2 crypto domain");
}

console.log("Flowersec v3 contract vectors and registry are internally consistent");
