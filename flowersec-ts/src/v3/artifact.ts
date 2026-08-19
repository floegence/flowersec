import { sha256 } from "@noble/hashes/sha2.js";

import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { concatBytes, readU32be, u32be } from "../utils/bin.js";
import { toASCII } from "../vendor/tr46.js";
import { canonicalizeJCSV3, type JCSValue } from "./jcs.js";
import { preflightJSONV3 } from "./jsonPreflight.js";
import {
  FLOWERSEC_V3_CRYPTO_LABELS,
  FLOWERSEC_V3_PROFILE,
  wireProfileForPathV3,
} from "./transportConstants.js";

export type ArtifactCarrierV3 = "websocket" | "raw_quic" | "webtransport";
export type ArtifactPathKindV3 = "direct" | "tunnel";

export type CertificatePinV3 = Readonly<{
  algorithm: "sha-256";
  not_after_unix_s: number;
  value_b64u: string;
}>;

export type TransportSecurityPolicyV3 =
  | Readonly<{ mode: "ca" }>
  | Readonly<{ mode: "pin"; pins: readonly CertificatePinV3[] }>;

export type ArtifactCandidateV3 = Readonly<{
  id: string;
  carrier: ArtifactCarrierV3;
  url: string;
  wire_profile: string;
  tls: TransportSecurityPolicyV3;
  normalized_url?: string;
}>;

export type CanonicalArtifactCandidateV3 = Readonly<{
  carrier: ArtifactCarrierV3;
  id: string;
  normalized_url: string;
  tls: TransportSecurityPolicyV3;
  wire_profile: string;
}>;

export type SessionContractV3 = Readonly<{
  channel_id: string;
  init_expire_at_unix_s: number;
  idle_timeout_seconds: number;
  establish_timeout_seconds: number;
  rekey_prepare_timeout_seconds: number;
  rekey_completion_timeout_seconds: number;
  max_inbound_streams: number;
  e2ee_psk_b64u: string;
  allowed_suites: readonly number[];
  default_suite: number;
  selected_features: number;
  contract_hash_b64u: string;
}>;

export type DirectArtifactPathV3 = Readonly<{
  kind: "direct";
  rendezvous_group_id: string;
  listener_audience: string;
  routing_token: string;
  candidates: readonly ArtifactCandidateV3[];
}>;

export type TunnelArtifactPathV3 = Readonly<{
  kind: "tunnel";
  rendezvous_group_id: string;
  listener_audience: string;
  role: 1 | 2;
  local_endpoint_instance_id: string;
  expected_peer_endpoint_instance_id: string;
  token: string;
  candidates: readonly ArtifactCandidateV3[];
}>;

export type ScopeMetadataV3 = Readonly<{
  scope: string;
  scope_version: number;
  critical: boolean;
  payload: Readonly<Record<string, unknown>>;
}>;

export type CorrelationTagV3 = Readonly<{
  key: string;
  value: string;
}>;

export type CorrelationContextV3 = Readonly<{
  v: 3;
  tags: readonly CorrelationTagV3[];
}>;

export type ArtifactV3 = Readonly<{
  v: 3;
  profile: typeof FLOWERSEC_V3_PROFILE;
  session: SessionContractV3;
  path: DirectArtifactPathV3 | TunnelArtifactPathV3;
  scoped: readonly ScopeMetadataV3[];
  correlation: CorrelationContextV3;
}>;

type CommonFSB3RequestV3 = Readonly<{
  profile: typeof FLOWERSEC_V3_PROFILE;
  channel_id: string;
  session_contract_hash_b64u: string;
  rendezvous_group_id: string;
  candidates: readonly CanonicalArtifactCandidateV3[];
  candidate_set_hash_b64u: string;
  chosen_candidate_id: string;
  listener_audience: string;
}>;

export type DirectFSB3RequestV3 = CommonFSB3RequestV3 &
  Readonly<{
    pathKind: "direct";
    routing_token: string;
  }>;

export type TunnelFSB3RequestV3 = CommonFSB3RequestV3 &
  Readonly<{
    pathKind: "tunnel";
    role: 1 | 2;
    endpoint_instance_id: string;
    attach_token: string;
  }>;

export type FSB3RequestV3 = DirectFSB3RequestV3 | TunnelFSB3RequestV3;

export type DecodedFSB3RequestV3 = Readonly<{
  request: FSB3RequestV3;
  raw: Uint8Array;
  localAdmissionBinding: Uint8Array;
}>;

export enum AdmissionStatusV3 {
  Success = 0,
  Reject = 1,
  Retryable = 2,
}

export type AdmissionResponseV3 = Readonly<{
  status: AdmissionStatusV3;
  reason: string;
}>;

export type ArtifactV3ErrorCode =
  | "artifact_too_large"
  | "fsb3_payload_too_large"
  | "invalid_artifact"
  | "invalid_candidate"
  | "invalid_fsa3"
  | "invalid_fsb3"
  | "noncanonical_fsb3";

export class ArtifactV3Error extends Error {
  readonly code: ArtifactV3ErrorCode;

  constructor(code: ArtifactV3ErrorCode, message: string) {
    super(message);
    this.name = "ArtifactV3Error";
    this.code = code;
  }
}

export type LabeledHashV3 = Readonly<{
  canonicalJSON: string;
  hash: Uint8Array;
  hashBase64URL: string;
}>;

export type CanonicalCandidateSetV3 = LabeledHashV3 &
  Readonly<{
    candidates: readonly CanonicalArtifactCandidateV3[];
  }>;

const PROFILE = FLOWERSEC_V3_PROFILE;
const MAX_ARTIFACT_JSON_BYTES = 65_536;
const MAX_CANDIDATES = 4;
const MAX_CANONICAL_CANDIDATE_BYTES = 2_304;
const MAX_CANONICAL_CANDIDATE_SET_BYTES = 12 * 1_024;
const MAX_CANONICAL_FSB3_PAYLOAD = 32_768;
const MAX_ADMISSION_REASON_BYTES = 64;
const MAX_ADMISSION_CREDENTIAL_BYTES = 8_192;
const FSB3_HEADER_BYTES = 12;
const FSA3_HEADER_BYTES = 8;
const FORBIDDEN_FSA3_REASONS = new Set([
  "browser_pin_opaque",
  "ca_untrusted",
  "pin_mismatch",
  "pin_tls_unknown",
  "tls_failed",
  "tls_pin_mismatch",
  "tls_policy_expired",
  "tls_untrusted",
  "tls_unsupported",
  "transport_security_failed",
  "transport_security_unsupported",
]);
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const registryIDPattern = /^[A-Za-z0-9._~-]+$/;
const candidateIDPattern = /^[a-z0-9][a-z0-9._-]*$/;
const scopePattern = /^[a-z][a-z0-9._-]{0,63}$/;
const correlationKeyPattern = /^[a-z][a-z0-9._-]{0,31}$/;

export function computeSessionContractHashV3(session: SessionContractV3): LabeledHashV3 {
  validateSession(session);
  const canonicalJSON = canonicalizeJCSV3({
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
  });
  return labeledHash(FLOWERSEC_V3_CRYPTO_LABELS["session-contract"], canonicalJSON);
}

export function canonicalizeCandidatesV3(
  kind: ArtifactPathKindV3,
  candidates: readonly ArtifactCandidateV3[],
): CanonicalCandidateSetV3 {
  if (kind !== "direct" && kind !== "tunnel") throw invalidCandidate("path kind");
  if (!Array.isArray(candidates) || candidates.length < 1 || candidates.length > MAX_CANDIDATES) {
    throw invalidCandidate("candidate count");
  }
  const ids = new Set<string>();
  const endpoints = new Set<string>();
  const canonical: CanonicalArtifactCandidateV3[] = [];
  for (const candidate of candidates) {
    validateCandidateShape(candidate);
    if (!candidateIDPattern.test(candidate.id) || utf8Length(candidate.id) > 64) {
      throw invalidCandidate("candidate id");
    }
    if (ids.has(candidate.id)) throw invalidCandidate("duplicate candidate id");
    ids.add(candidate.id);
    if (utf8Length(candidate.url) < 1 || utf8Length(candidate.url) > 2_048) {
      throw invalidCandidate("candidate URL length");
    }
    const normalizedURL = normalizeCandidateURL(kind, candidate.carrier, candidate.url);
    if (utf8Length(normalizedURL) > 2_048) throw invalidCandidate("normalized URL length");
    if (candidate.normalized_url !== undefined && candidate.normalized_url !== normalizedURL) {
      throw invalidCandidate("normalized URL mismatch");
    }
    const wireProfile = wireProfileForPathV3(kind);
    if (candidate.wire_profile !== wireProfile) throw invalidCandidate("wire profile");
    validateTLSPolicy(candidate.tls, "invalid_candidate");
    const endpoint = `${candidate.carrier}\0${kind}\0${normalizedURL}`;
    if (endpoints.has(endpoint)) throw invalidCandidate("duplicate endpoint key");
    endpoints.add(endpoint);
    const item: CanonicalArtifactCandidateV3 = {
      carrier: candidate.carrier,
      id: candidate.id,
      normalized_url: normalizedURL,
      tls: candidate.tls,
      wire_profile: candidate.wire_profile,
    };
    if (utf8Length(canonicalizeJCSV3(item as unknown as JCSValue)) > MAX_CANONICAL_CANDIDATE_BYTES) {
      throw invalidCandidate("canonical candidate too large");
    }
    canonical.push(item);
  }
  canonical.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const canonicalJSON = canonicalizeJCSV3(canonical as unknown as JCSValue);
  if (utf8Length(canonicalJSON) > MAX_CANONICAL_CANDIDATE_SET_BYTES) {
    throw invalidCandidate("canonical candidate set too large");
  }
  return {
    candidates: canonical,
    ...labeledHash(FLOWERSEC_V3_CRYPTO_LABELS.candidates, canonicalJSON),
  };
}

export function decodeArtifactV3JSON(raw: string | Uint8Array): ArtifactV3 {
  const text = decodeBoundedJSON(raw);
  let value: unknown;
  try {
    value = parseStrictJSON(text, true);
  } catch (error) {
    throw invalidArtifact(`strict JSON: ${errorMessage(error)}`);
  }
  let artifact: ArtifactV3;
  let canonicalCandidates: CanonicalCandidateSetV3;
  try {
    artifact = decodeArtifactValue(value);
    canonicalCandidates = validateArtifactV3(artifact);
    if (text !== decoder.decode(encodeArtifactV3JSON(artifact))) throw invalidArtifact("non-canonical JCS");
  } catch (error) {
    if (error instanceof ArtifactV3Error && error.code === "invalid_candidate") {
      throw invalidArtifact("candidate");
    }
    throw error;
  }
  const normalizedByID = new Map(
    canonicalCandidates.candidates.map((candidate) => [candidate.id, candidate.normalized_url]),
  );
  return {
    ...artifact,
    path: {
      ...artifact.path,
      candidates: artifact.path.candidates.map((candidate) => ({
        ...candidate,
        normalized_url: normalizedByID.get(candidate.id),
      })),
    } as DirectArtifactPathV3 | TunnelArtifactPathV3,
  };
}

export function encodeArtifactV3JSON(artifact: ArtifactV3): Uint8Array {
  validateArtifactV3(artifact);
  const wire = {
    v: artifact.v,
    profile: artifact.profile,
    session: artifactSessionWire(artifact.session),
    path: artifact.path.kind === "direct" ? directPathWire(artifact.path) : tunnelPathWire(artifact.path),
    scoped: artifact.scoped.map((scope) => ({
      scope: scope.scope,
      scope_version: scope.scope_version,
      critical: scope.critical,
      payload: scope.payload,
    })),
    correlation: {
      v: artifact.correlation.v,
      tags: artifact.correlation.tags.map((tag) => ({ key: tag.key, value: tag.value })),
    },
  };
  const raw = encoder.encode(canonicalizeJCSV3(wire as JCSValue));
  if (raw.length > MAX_ARTIFACT_JSON_BYTES) {
    throw new ArtifactV3Error("artifact_too_large", "Flowersec v3 artifact is too large");
  }
  return raw;
}

export function validateArtifactV3(artifact: ArtifactV3): CanonicalCandidateSetV3 {
  validateArtifactShape(artifact);
  if (artifact.v !== 3 || artifact.profile !== PROFILE) throw invalidArtifact("version or profile");
  const sessionHash = computeSessionContractHashV3(artifact.session);
  if (sessionHash.hashBase64URL !== artifact.session.contract_hash_b64u) {
    throw invalidArtifact("session contract hash");
  }
  const candidateSet = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates);
  if (!validRegistryID(artifact.path.rendezvous_group_id, 128) || !validRegistryID(artifact.path.listener_audience, 128)) {
    throw invalidArtifact("rendezvous group or listener audience");
  }
  if (artifact.path.kind === "direct") {
    if (!validASCII(artifact.path.routing_token, MAX_ADMISSION_CREDENTIAL_BYTES)) {
      throw invalidArtifact("direct path variant");
    }
  } else {
    if (
      (artifact.path.role !== 1 && artifact.path.role !== 2) ||
      !validRegistryID(artifact.path.local_endpoint_instance_id, 128) ||
      !validRegistryID(artifact.path.expected_peer_endpoint_instance_id, 128) ||
      artifact.path.local_endpoint_instance_id === artifact.path.expected_peer_endpoint_instance_id ||
      !validASCII(artifact.path.token, MAX_ADMISSION_CREDENTIAL_BYTES)
    ) {
      throw invalidArtifact("tunnel path variant");
    }
  }
  validateScopes(artifact.scoped);
  validateCorrelationShape(artifact.correlation);
  for (const candidate of candidateSet.candidates) {
    const request = requestFromValidatedArtifact(artifact, candidateSet, candidate.id);
    if (marshalFSB3Payload(request).length > MAX_CANONICAL_FSB3_PAYLOAD) {
      throw new ArtifactV3Error("fsb3_payload_too_large", "FSB3 canonical payload is too large");
    }
  }
  return candidateSet;
}

export function buildFSB3RequestV3(artifact: ArtifactV3, chosenCandidateID: string): FSB3RequestV3 {
  const candidateSet = validateArtifactV3(artifact);
  const request = requestFromValidatedArtifact(artifact, candidateSet, chosenCandidateID);
  validateFSB3Request(request);
  return request;
}

export function encodeFSB3RequestV3(request: FSB3RequestV3): Uint8Array {
  validateFSB3Request(request);
  const payload = marshalFSB3Payload(request);
  if (payload.length > MAX_CANONICAL_FSB3_PAYLOAD) {
    throw new ArtifactV3Error("fsb3_payload_too_large", "FSB3 canonical payload is too large");
  }
  const out = new Uint8Array(FSB3_HEADER_BYTES + payload.length);
  out.set(encoder.encode("FSB3"), 0);
  out[4] = 3;
  out[5] = request.pathKind === "direct" ? 1 : 2;
  out.set(u32be(payload.length), 8);
  out.set(payload, FSB3_HEADER_BYTES);
  return out;
}

export function decodeFSB3RequestV3(raw: Uint8Array): DecodedFSB3RequestV3 {
  if (raw.length < FSB3_HEADER_BYTES) throw invalidFSB3("truncated header");
  if (
    raw[0] !== 0x46 ||
    raw[1] !== 0x53 ||
    raw[2] !== 0x42 ||
    raw[3] !== 0x33 ||
    raw[4] !== 3 ||
    raw[6] !== 0 ||
    raw[7] !== 0
  ) {
    throw invalidFSB3("header");
  }
  const pathKind = pathKindFromCode(raw[5]!);
  const payloadLength = readU32be(raw, 8);
  if (payloadLength > MAX_CANONICAL_FSB3_PAYLOAD) {
    throw new ArtifactV3Error("fsb3_payload_too_large", "FSB3 canonical payload is too large");
  }
  if (payloadLength === 0 || raw.length !== FSB3_HEADER_BYTES + payloadLength) {
    throw invalidFSB3("payload length");
  }
  const payload = raw.subarray(FSB3_HEADER_BYTES);
  let text: string;
  let value: unknown;
  try {
    text = decoder.decode(payload);
    value = parseStrictJSON(text);
  } catch (error) {
    throw invalidFSB3(`strict JSON: ${errorMessage(error)}`);
  }
  const request = decodeFSB3Value(pathKind, value);
  validateFSB3Request(request);
  if (!bytesEqual(payload, marshalFSB3Payload(request))) {
    throw new ArtifactV3Error("noncanonical_fsb3", "FSB3 payload is not canonical");
  }
  const copied = new Uint8Array(raw);
  return {
    request,
    raw: copied,
    localAdmissionBinding: admissionBindingV3(copied),
  };
}

export function admissionBindingV3(rawFSB3: Uint8Array): Uint8Array {
  return sha256(concatBytes([encoder.encode(FLOWERSEC_V3_CRYPTO_LABELS.admission), rawFSB3]));
}

export function acceptorAdmissionsHashV3(framesByCandidateID: ReadonlyMap<string, Uint8Array>): Uint8Array {
  if (framesByCandidateID.size < 1 || framesByCandidateID.size > MAX_CANDIDATES) {
    throw invalidFSB3("acceptor admissions count");
  }
  const ordered = [...framesByCandidateID.entries()].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0);
  const parts: Uint8Array[] = [encoder.encode(FLOWERSEC_V3_CRYPTO_LABELS["acceptor-admissions"])];
  let previous = "";
  for (const [candidateID, frame] of ordered) {
    if (!candidateIDPattern.test(candidateID) || candidateID <= previous) throw invalidFSB3("candidate ordering");
    const decoded = decodeFSB3RequestV3(frame);
    if (decoded.request.chosen_candidate_id !== candidateID) throw invalidFSB3("chosen candidate binding");
    parts.push(u32be(frame.length), frame);
    previous = candidateID;
  }
  return sha256(concatBytes(parts));
}

// Server-side encoding requires an audited registry for every rejection.
// Success has no reason and therefore needs no registry entry.
export function encodeFSA3ResponseV3(
  response: AdmissionResponseV3,
  admissionReasons: ReadonlySet<string> = new Set(),
): Uint8Array {
  validateFSA3Response(response, admissionReasons, true);
  const reason = encoder.encode(response.reason);
  const out = new Uint8Array(FSA3_HEADER_BYTES + reason.length);
  out.set(encoder.encode("FSA3"), 0);
  out[4] = 3;
  out[5] = response.status;
  new DataView(out.buffer).setUint16(6, reason.length, false);
  out.set(reason, FSA3_HEADER_BYTES);
  return out;
}

// Clients accept any canonical bounded rejection token. Deployment policy is
// server-owned and is not duplicated as a client-side reason registry.
export function decodeFSA3ResponseV3(raw: Uint8Array): AdmissionResponseV3 {
  if (raw.length < FSA3_HEADER_BYTES) throw invalidFSA3("truncated header");
  if (raw[0] !== 0x46 || raw[1] !== 0x53 || raw[2] !== 0x41 || raw[3] !== 0x33 || raw[4] !== 3) {
    throw invalidFSA3("header");
  }
  const reasonLength = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint16(6, false);
  if (reasonLength > MAX_ADMISSION_REASON_BYTES || raw.length !== FSA3_HEADER_BYTES + reasonLength) {
    throw invalidFSA3("reason length");
  }
  let reason: string;
  try {
    reason = decoder.decode(raw.subarray(FSA3_HEADER_BYTES));
  } catch {
    throw invalidFSA3("reason encoding");
  }
  const response = { status: raw[5]! as AdmissionStatusV3, reason };
  validateFSA3Response(response, new Set(), false);
  return response;
}

function validateSession(session: SessionContractV3): void {
  assertRecord(session, "session", "invalid_artifact");
  assertExactKeys(
    session,
    [
      "channel_id",
      "init_expire_at_unix_s",
      "idle_timeout_seconds",
      "establish_timeout_seconds",
      "rekey_prepare_timeout_seconds",
      "rekey_completion_timeout_seconds",
      "max_inbound_streams",
      "e2ee_psk_b64u",
      "allowed_suites",
      "default_suite",
      "selected_features",
      "contract_hash_b64u",
    ],
    "session",
    "invalid_artifact",
  );
  if (!validRegistryID(session.channel_id, 128)) throw invalidArtifact("channel_id");
  assertSafeInteger(session.init_expire_at_unix_s, 1, Number.MAX_SAFE_INTEGER, "init expiry");
  assertSafeInteger(session.idle_timeout_seconds, 0, 0xffff_ffff, "idle timeout");
  if (
    session.establish_timeout_seconds !== 30 ||
    session.rekey_prepare_timeout_seconds !== 10 ||
    session.rekey_completion_timeout_seconds !== 30
  ) {
    throw invalidArtifact("fixed session timing");
  }
  assertSafeInteger(session.max_inbound_streams, 1, 128, "max inbound streams");
  assertCanonical32(session.e2ee_psk_b64u, "e2ee PSK", "invalid_artifact");
  assertCanonical32(session.contract_hash_b64u, "contract hash", "invalid_artifact");
  if (!Array.isArray(session.allowed_suites) || session.allowed_suites.length < 1) {
    throw invalidArtifact("allowed suites");
  }
  let previous = 0;
  const suites = new Set<number>();
  for (const suite of session.allowed_suites) {
    if ((suite !== 1 && suite !== 2) || suite <= previous || suites.has(suite)) {
      throw invalidArtifact("allowed suites");
    }
    previous = suite;
    suites.add(suite);
  }
  if (!suites.has(session.default_suite)) throw invalidArtifact("default suite");
  if (session.selected_features !== 0) throw invalidArtifact("selected features");
}

function validateArtifactShape(artifact: ArtifactV3): void {
  assertRecord(artifact, "artifact", "invalid_artifact");
  assertExactKeys(artifact, ["v", "profile", "session", "path", "scoped", "correlation"], "artifact", "invalid_artifact");
  validateSession(artifact.session);
  validatePathShape(artifact.path, true);
  if (!Array.isArray(artifact.scoped)) throw invalidArtifact("scoped");
  validateCorrelationShape(artifact.correlation);
}

function validatePathShape(path: DirectArtifactPathV3 | TunnelArtifactPathV3, allowNormalized: boolean): void {
  assertRecord(path, "path", "invalid_artifact");
  if (path.kind === "direct") {
    assertExactKeys(path, ["kind", "rendezvous_group_id", "listener_audience", "routing_token", "candidates"], "direct path", "invalid_artifact");
  } else if (path.kind === "tunnel") {
    assertExactKeys(
      path,
      [
        "kind",
        "rendezvous_group_id",
        "listener_audience",
        "role",
        "local_endpoint_instance_id",
        "expected_peer_endpoint_instance_id",
        "token",
        "candidates",
      ],
      "tunnel path",
      "invalid_artifact",
    );
  } else {
    throw invalidArtifact("path kind");
  }
  if (!Array.isArray(path.candidates)) throw invalidArtifact("candidates");
  for (const candidate of path.candidates) validateCandidateShape(candidate, allowNormalized);
}

function validateCandidateShape(candidate: ArtifactCandidateV3, allowNormalized = true): void {
  assertRecord(candidate, "candidate", "invalid_candidate");
  const keys = allowNormalized
    ? ["id", "carrier", "url", "wire_profile", "tls", ...(candidate.normalized_url === undefined ? [] : ["normalized_url"])]
    : ["id", "carrier", "url", "wire_profile", "tls"];
  assertExactKeys(candidate, keys, "candidate", "invalid_candidate");
  if (
    typeof candidate.id !== "string" ||
    typeof candidate.carrier !== "string" ||
    typeof candidate.url !== "string" ||
    typeof candidate.wire_profile !== "string" ||
    (candidate.normalized_url !== undefined && typeof candidate.normalized_url !== "string")
  ) {
    throw invalidCandidate("candidate field type");
  }
  validateTLSPolicy(candidate.tls, "invalid_candidate");
}

export function tlsPolicyDigestV3(policy: TransportSecurityPolicyV3): LabeledHashV3 {
  validateTLSPolicy(policy, "invalid_artifact");
  return labeledHash("flowersec-v3-tls-policy\0", canonicalizeJCSV3(policy));
}

export function activePinsV3(policy: TransportSecurityPolicyV3, attemptNowUnixSeconds: number): readonly CertificatePinV3[] {
  validateTLSPolicy(policy, "invalid_artifact");
  assertSafeInteger(attemptNowUnixSeconds, 0, Number.MAX_SAFE_INTEGER, "attempt time");
  return policy.mode === "pin"
    ? Object.freeze(policy.pins.filter((pin) => attemptNowUnixSeconds < pin.not_after_unix_s))
    : Object.freeze([]);
}

function validateTLSPolicy(
  value: unknown,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3",
): asserts value is TransportSecurityPolicyV3 {
  const policy = requireRecord(value, "TLS policy", code);
  if (policy.mode === "ca") {
    assertExactKeys(policy, ["mode"], "CA TLS policy", code);
    return;
  }
  if (policy.mode !== "pin") throw codecError(code, "TLS policy mode");
  assertExactKeys(policy, ["mode", "pins"], "pin TLS policy", code);
  if (!Array.isArray(policy.pins) || policy.pins.length < 1 || policy.pins.length > 4) {
    throw codecError(code, "pin count");
  }
  let previous = "";
  const seen = new Set<string>();
  for (const input of policy.pins) {
    const pin = requireRecord(input, "pin", code);
    assertExactKeys(pin, ["algorithm", "value_b64u", "not_after_unix_s"], "pin", code);
    if (pin.algorithm !== "sha-256") throw codecError(code, "pin algorithm");
    const encoded = requireString(pin.value_b64u, "pin value", code);
    assertCanonical32(encoded, "pin value", code);
    assertSafeInteger(pin.not_after_unix_s, 1, Number.MAX_SAFE_INTEGER, "pin expiry", code);
    if (encoded <= previous || seen.has(encoded)) throw codecError(code, "pin ordering or duplicate");
    previous = encoded;
    seen.add(encoded);
  }
}

function decodeTLSPolicyValue(
  value: unknown,
  code: "invalid_artifact" | "invalid_fsb3",
): TransportSecurityPolicyV3 {
  validateTLSPolicy(value, code);
  if (value.mode === "ca") return Object.freeze({ mode: "ca" });
  return Object.freeze({
    mode: "pin",
    pins: Object.freeze(value.pins.map((pin) => Object.freeze({ ...pin }))),
  });
}

function validateScopes(scopes: readonly ScopeMetadataV3[]): void {
  if (!Array.isArray(scopes) || scopes.length > 8) throw invalidArtifact("scoped");
  const seen = new Set<string>();
  for (const scope of scopes) {
    assertRecord(scope, "scope", "invalid_artifact");
    assertExactKeys(scope, ["scope", "scope_version", "critical", "payload"], "scope", "invalid_artifact");
    const scopeVersion = scope.scope_version;
    if (
      typeof scope.scope !== "string" ||
      !scopePattern.test(scope.scope) ||
      typeof scopeVersion !== "number" ||
      !Number.isInteger(scopeVersion) ||
      scopeVersion < 1 ||
      scopeVersion > 0xffff ||
      typeof scope.critical !== "boolean" ||
      !isRecord(scope.payload)
    ) {
      throw invalidArtifact("scope metadata");
    }
    validateScopedPayload(scope.payload);
    if (seen.has(scope.scope)) throw invalidArtifact("duplicate scope");
    seen.add(scope.scope);
  }
}

function validateScopedPayload(payload: Readonly<Record<string, unknown>>): void {
  let nodes = 0;
  const visit = (value: unknown, depth: number): void => {
    nodes += 1;
    if (depth > 16 || nodes > 256) throw invalidArtifact("scope payload resources");
    if (value === null || typeof value === "boolean") return;
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw invalidArtifact("scope payload number");
      return;
    }
    if (typeof value === "string") {
      if (utf8Length(value) > 1_024) throw invalidArtifact("scope payload string");
      return;
    }
    if (Array.isArray(value)) {
      if (value.length > 64) throw invalidArtifact("scope payload array");
      for (const item of value) visit(item, depth + 1);
      return;
    }
    if (!isRecord(value)) throw invalidArtifact("scope payload value");
    const entries = Object.entries(value);
    if (entries.length > 64) throw invalidArtifact("scope payload members");
    for (const [key, item] of entries) {
      if (utf8Length(key) > 128) throw invalidArtifact("scope payload key");
      visit(item, depth + 1);
    }
  };
  visit(payload, 1);
  let canonical: string;
  try {
    canonical = canonicalizeJCSV3(payload as JCSValue);
  } catch {
    throw invalidArtifact("scope payload JCS value");
  }
  if (utf8Length(canonical) > 4_096) throw invalidArtifact("scope payload bytes");
}

function validateCorrelationShape(correlation: CorrelationContextV3): void {
  assertRecord(correlation, "correlation", "invalid_artifact");
  assertExactKeys(correlation, ["v", "tags"], "correlation", "invalid_artifact");
  if (correlation.v !== 3 || !Array.isArray(correlation.tags) || correlation.tags.length > 8) {
    throw invalidArtifact("correlation");
  }
  const seen = new Set<string>();
  for (const tag of correlation.tags) {
    assertRecord(tag, "correlation tag", "invalid_artifact");
    assertExactKeys(tag, ["key", "value"], "correlation tag", "invalid_artifact");
    if (
      typeof tag.key !== "string" ||
      typeof tag.value !== "string" ||
      !correlationKeyPattern.test(tag.key) ||
      !validASCII(tag.value, 128) ||
      seen.has(tag.key)
    ) {
      throw invalidArtifact("correlation tag");
    }
    seen.add(tag.key);
  }
}

function normalizeCandidateURL(
  kind: ArtifactPathKindV3,
  carrier: ArtifactCarrierV3,
  raw: string,
): string {
  if (/[\\?#%]/.test(raw)) throw invalidCandidate("forbidden URL component");
  const separator = raw.indexOf("://");
  if (separator <= 0) throw invalidCandidate("absolute URL");
  const scheme = raw.slice(0, separator).toLowerCase();
  const remainder = raw.slice(separator + 3);
  const pathAt = remainder.indexOf("/");
  const authority = pathAt < 0 ? remainder : remainder.slice(0, pathAt);
  let path = pathAt < 0 ? "" : remainder.slice(pathAt);
  if (authority === "" || authority.includes("@")) throw invalidCandidate("URL authority");
  const normalizedAuthority = normalizeAuthority(authority);
  let expectedScheme: string;
  let expectedPath = "";
  switch (carrier) {
    case "websocket":
      expectedScheme = "wss";
      expectedPath = `/flowersec/v3/${kind}`;
      break;
    case "raw_quic":
      expectedScheme = "quic";
      if (path !== "" && path !== "/") throw invalidCandidate("raw QUIC path");
      path = "";
      break;
    case "webtransport":
      expectedScheme = "https";
      expectedPath = `/flowersec/webtransport/v3/${kind}`;
      break;
    default:
      throw invalidCandidate("carrier registry");
  }
  if (scheme !== expectedScheme) throw invalidCandidate("carrier scheme");
  if (carrier !== "raw_quic" && path !== expectedPath) throw invalidCandidate("carrier URL path");
  return `${scheme}://${normalizedAuthority}${path}`;
}

function normalizeAuthority(authority: string): string {
  let host: string;
  let portText = "";
  if (authority.startsWith("[")) {
    const closing = authority.indexOf("]");
    if (closing < 0 || authority.indexOf("]", closing + 1) >= 0) throw invalidCandidate("IPv6 authority");
    host = authority.slice(1, closing);
    const tail = authority.slice(closing + 1);
    if (tail !== "") {
      if (!tail.startsWith(":") || tail.length === 1) throw invalidCandidate("IPv6 port");
      portText = tail.slice(1);
    }
    if (host.includes(".")) throw invalidCandidate("IPv6 dotted subset");
    let parsed: URL;
    try {
      parsed = new URL(`http://[${host}]/`);
    } catch {
      throw invalidCandidate("IPv6 host");
    }
    const canonical = parsed.hostname;
    if (!canonical.startsWith("[") || !canonical.endsWith("]")) throw invalidCandidate("IPv6 host");
    host = canonical.toLowerCase();
  } else {
    if ((authority.match(/:/g)?.length ?? 0) > 1) throw invalidCandidate("unbracketed IPv6");
    const colon = authority.lastIndexOf(":");
    if (colon >= 0) {
      host = authority.slice(0, colon);
      portText = authority.slice(colon + 1);
      if (portText === "") throw invalidCandidate("empty port");
    } else {
      host = authority;
    }
    host = normalizeDNSOrIPv4(host);
  }
  if (portText === "") return host;
  if (!/^\d+$/.test(portText)) throw invalidCandidate("port");
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 0xffff) throw invalidCandidate("port");
  return port === 443 ? host : `${host}:${port}`;
}

function normalizeDNSOrIPv4(host: string): string {
  if (host === "" || host.endsWith(".")) throw invalidCandidate("DNS host");
  const lower = host.toLowerCase();
  if (/^[0-9.]+$/.test(lower)) {
    const parts = lower.split(".");
    if (
      parts.length !== 4 ||
      parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)
    ) {
      throw invalidCandidate("IPv4 host");
    }
    return parts.map((part) => String(Number(part))).join(".");
  }
  const ascii = toASCII(host, {
    checkHyphens: true,
    checkBidi: true,
    checkJoiners: true,
    useSTD3ASCIIRules: true,
    verifyDNSLength: true,
    transitionalProcessing: false,
  });
  if (ascii === null || ascii.endsWith(".")) throw invalidCandidate("DNS label");
  const normalized = ascii.toLowerCase();
  const finalLabel = normalized.slice(normalized.lastIndexOf(".") + 1);
  if (/^\d+$/.test(finalLabel) || /^0x[0-9a-f]*$/i.test(finalLabel)) {
    throw invalidCandidate("WHATWG numeric host ambiguity");
  }
  return normalized;
}

function requestFromValidatedArtifact(
  artifact: ArtifactV3,
  candidateSet: CanonicalCandidateSetV3,
  chosenCandidateID: string,
): FSB3RequestV3 {
  const common = {
    profile: PROFILE,
    channel_id: artifact.session.channel_id,
    session_contract_hash_b64u: artifact.session.contract_hash_b64u,
    rendezvous_group_id: artifact.path.rendezvous_group_id,
    candidates: candidateSet.candidates,
    candidate_set_hash_b64u: candidateSet.hashBase64URL,
    chosen_candidate_id: chosenCandidateID,
    listener_audience: artifact.path.listener_audience,
  } as const;
  if (artifact.path.kind === "direct") {
    return { pathKind: "direct", ...common, routing_token: artifact.path.routing_token };
  }
  return {
    pathKind: "tunnel",
    ...common,
    role: artifact.path.role,
    endpoint_instance_id: artifact.path.local_endpoint_instance_id,
    attach_token: artifact.path.token,
  };
}

function validateFSB3Request(request: FSB3RequestV3): void {
  try {
    if (request.pathKind !== "direct" && request.pathKind !== "tunnel") throw new Error("path kind");
    if (request.profile !== PROFILE) throw new Error("profile");
    if (
      !validRegistryID(request.channel_id, 128) ||
      !validRegistryID(request.rendezvous_group_id, 128) ||
      !validRegistryID(request.listener_audience, 128)
    ) {
      throw new Error("registry id");
    }
    assertCanonical32(request.session_contract_hash_b64u, "session hash", "invalid_fsb3");
    assertCanonical32(request.candidate_set_hash_b64u, "candidate hash", "invalid_fsb3");
    const source = request.candidates.map((candidate) => ({
      id: candidate.id,
      carrier: candidate.carrier,
      url: candidate.normalized_url,
      normalized_url: candidate.normalized_url,
      tls: candidate.tls,
      wire_profile: candidate.wire_profile,
    }));
    const canonical = canonicalizeCandidatesV3(request.pathKind, source);
    if (
      canonical.hashBase64URL !== request.candidate_set_hash_b64u ||
      canonicalizeJCSV3(canonical.candidates as unknown as JCSValue) !==
        canonicalizeJCSV3(request.candidates as unknown as JCSValue)
    ) {
      throw new Error("candidate hash or ordering");
    }
    if (!request.candidates.some((candidate) => candidate.id === request.chosen_candidate_id)) {
      throw new Error("chosen candidate");
    }
    if (request.pathKind === "direct") {
      if (!validASCII(request.routing_token, MAX_ADMISSION_CREDENTIAL_BYTES)) throw new Error("direct variant");
    } else if (
      (request.role !== 1 && request.role !== 2) ||
      !validRegistryID(request.endpoint_instance_id, 128) ||
      !validASCII(request.attach_token, MAX_ADMISSION_CREDENTIAL_BYTES)
    ) {
      throw new Error("tunnel variant");
    }
  } catch (error) {
    if (error instanceof ArtifactV3Error && error.code === "invalid_fsb3") throw error;
    throw invalidFSB3(errorMessage(error));
  }
}

function marshalFSB3Payload(request: FSB3RequestV3): Uint8Array {
  const wire =
    request.pathKind === "direct"
      ? {
          candidate_set_hash_b64u: request.candidate_set_hash_b64u,
          candidates: request.candidates,
          channel_id: request.channel_id,
          chosen_candidate_id: request.chosen_candidate_id,
          listener_audience: request.listener_audience,
          profile: request.profile,
          rendezvous_group_id: request.rendezvous_group_id,
          routing_token: request.routing_token,
          session_contract_hash_b64u: request.session_contract_hash_b64u,
        }
      : {
          attach_token: request.attach_token,
          candidate_set_hash_b64u: request.candidate_set_hash_b64u,
          candidates: request.candidates,
          channel_id: request.channel_id,
          chosen_candidate_id: request.chosen_candidate_id,
          endpoint_instance_id: request.endpoint_instance_id,
          listener_audience: request.listener_audience,
          profile: request.profile,
          rendezvous_group_id: request.rendezvous_group_id,
          role: request.role,
          session_contract_hash_b64u: request.session_contract_hash_b64u,
        };
  return encoder.encode(canonicalizeJCSV3(wire as unknown as JCSValue));
}

function decodeArtifactValue(value: unknown): ArtifactV3 {
  const top = requireRecord(value, "artifact");
  assertExactKeys(top, ["v", "profile", "session", "path", "scoped", "correlation"], "artifact", "invalid_artifact");
  if (top.v !== 3 || top.profile !== PROFILE) throw invalidArtifact("version or profile");
  const session = decodeSessionValue(top.session);
  const path = decodePathValue(top.path);
  const scoped = decodeScopesValue(top.scoped);
  const correlation = decodeCorrelationValue(top.correlation);
  return { v: 3, profile: PROFILE, session, path, scoped, correlation };
}

function decodeSessionValue(value: unknown): SessionContractV3 {
  const session = requireRecord(value, "session");
  assertExactKeys(
    session,
    [
      "channel_id",
      "init_expire_at_unix_s",
      "idle_timeout_seconds",
      "establish_timeout_seconds",
      "rekey_prepare_timeout_seconds",
      "rekey_completion_timeout_seconds",
      "max_inbound_streams",
      "e2ee_psk_b64u",
      "allowed_suites",
      "default_suite",
      "selected_features",
      "contract_hash_b64u",
    ],
    "session",
    "invalid_artifact",
  );
  const decoded = session as unknown as SessionContractV3;
  validateSession(decoded);
  return decoded;
}

function decodePathValue(value: unknown): DirectArtifactPathV3 | TunnelArtifactPathV3 {
  const path = requireRecord(value, "path");
  if (path.kind === "direct") {
    assertExactKeys(path, ["kind", "rendezvous_group_id", "listener_audience", "routing_token", "candidates"], "direct path", "invalid_artifact");
    return {
      kind: "direct",
      rendezvous_group_id: requireString(path.rendezvous_group_id, "rendezvous group"),
      listener_audience: requireString(path.listener_audience, "listener audience"),
      routing_token: requireString(path.routing_token, "routing token"),
      candidates: decodeCandidatesValue(path.candidates),
    };
  }
  if (path.kind === "tunnel") {
    assertExactKeys(
      path,
      [
        "kind",
        "rendezvous_group_id",
        "listener_audience",
        "role",
        "local_endpoint_instance_id",
        "expected_peer_endpoint_instance_id",
        "token",
        "candidates",
      ],
      "tunnel path",
      "invalid_artifact",
    );
    if (path.role !== 1 && path.role !== 2) throw invalidArtifact("tunnel role");
    return {
      kind: "tunnel",
      rendezvous_group_id: requireString(path.rendezvous_group_id, "rendezvous group"),
      listener_audience: requireString(path.listener_audience, "listener audience"),
      role: path.role,
      local_endpoint_instance_id: requireString(path.local_endpoint_instance_id, "local endpoint"),
      expected_peer_endpoint_instance_id: requireString(path.expected_peer_endpoint_instance_id, "peer endpoint"),
      token: requireString(path.token, "attach token"),
      candidates: decodeCandidatesValue(path.candidates),
    };
  }
  throw invalidArtifact("path kind");
}

function decodeCandidatesValue(value: unknown): readonly ArtifactCandidateV3[] {
  if (!Array.isArray(value)) throw invalidArtifact("candidates");
  return value.map((item) => {
    const candidate = requireRecord(item, "candidate");
    assertExactKeys(candidate, ["id", "carrier", "url", "wire_profile", "tls"], "candidate", "invalid_artifact");
    const tls = decodeTLSPolicyValue(candidate.tls, "invalid_artifact");
    return {
      id: requireString(candidate.id, "candidate id"),
      carrier: requireString(candidate.carrier, "candidate carrier") as ArtifactCarrierV3,
      url: requireString(candidate.url, "candidate URL"),
      wire_profile: requireString(candidate.wire_profile, "wire profile"),
      tls,
    };
  });
}

function decodeScopesValue(value: unknown): readonly ScopeMetadataV3[] {
  if (!Array.isArray(value)) throw invalidArtifact("scoped");
  return value.map((item) => {
    const scope = requireRecord(item, "scope");
    assertExactKeys(scope, ["scope", "scope_version", "critical", "payload"], "scope", "invalid_artifact");
    if (typeof scope.critical !== "boolean" || !isRecord(scope.payload)) throw invalidArtifact("scope metadata");
    return {
      scope: requireString(scope.scope, "scope name"),
      scope_version: requireNumber(scope.scope_version, "scope version"),
      critical: scope.critical,
      payload: scope.payload,
    };
  });
}

function decodeCorrelationValue(value: unknown): CorrelationContextV3 {
  const correlation = requireRecord(value, "correlation");
  assertExactKeys(correlation, ["v", "tags"], "correlation", "invalid_artifact");
  if (correlation.v !== 3 || !Array.isArray(correlation.tags)) throw invalidArtifact("correlation");
  return {
    v: 3,
    tags: correlation.tags.map((item) => {
      const tag = requireRecord(item, "correlation tag");
      assertExactKeys(tag, ["key", "value"], "correlation tag", "invalid_artifact");
      return {
        key: requireString(tag.key, "correlation key"),
        value: requireString(tag.value, "correlation value"),
      };
    }),
  };
}

function decodeFSB3Value(pathKind: ArtifactPathKindV3, value: unknown): FSB3RequestV3 {
  const wire = requireRecord(value, "FSB3 payload", "invalid_fsb3");
  const commonKeys = [
    "candidate_set_hash_b64u",
    "candidates",
    "channel_id",
    "chosen_candidate_id",
    "listener_audience",
    "profile",
    "rendezvous_group_id",
    "session_contract_hash_b64u",
  ];
  if (pathKind === "direct") {
    assertExactKeys(wire, [...commonKeys, "routing_token"], "direct FSB3", "invalid_fsb3");
  } else {
    assertExactKeys(wire, [...commonKeys, "attach_token", "endpoint_instance_id", "role"], "tunnel FSB3", "invalid_fsb3");
  }
  const candidates = decodeCanonicalCandidatesValue(wire.candidates);
  const common = {
    profile: requireString(wire.profile, "profile", "invalid_fsb3") as typeof FLOWERSEC_V3_PROFILE,
    channel_id: requireString(wire.channel_id, "channel ID", "invalid_fsb3"),
    session_contract_hash_b64u: requireString(wire.session_contract_hash_b64u, "session hash", "invalid_fsb3"),
    rendezvous_group_id: requireString(wire.rendezvous_group_id, "rendezvous group", "invalid_fsb3"),
    candidates,
    candidate_set_hash_b64u: requireString(wire.candidate_set_hash_b64u, "candidate hash", "invalid_fsb3"),
    chosen_candidate_id: requireString(wire.chosen_candidate_id, "chosen candidate", "invalid_fsb3"),
    listener_audience: requireString(wire.listener_audience, "listener audience", "invalid_fsb3"),
  } as const;
  if (pathKind === "direct") {
    return {
      pathKind,
      ...common,
      routing_token: requireString(wire.routing_token, "routing token", "invalid_fsb3"),
    };
  }
  if (wire.role !== 1 && wire.role !== 2) throw invalidFSB3("role");
  return {
    pathKind,
    ...common,
    role: wire.role,
    endpoint_instance_id: requireString(wire.endpoint_instance_id, "endpoint instance", "invalid_fsb3"),
    attach_token: requireString(wire.attach_token, "attach token", "invalid_fsb3"),
  };
}

function decodeCanonicalCandidatesValue(value: unknown): readonly CanonicalArtifactCandidateV3[] {
  if (!Array.isArray(value)) throw invalidFSB3("candidates");
  return value.map((item) => {
    const candidate = requireRecord(item, "canonical candidate", "invalid_fsb3");
    assertExactKeys(candidate, ["carrier", "id", "normalized_url", "tls", "wire_profile"], "canonical candidate", "invalid_fsb3");
    return {
      carrier: requireString(candidate.carrier, "carrier", "invalid_fsb3") as ArtifactCarrierV3,
      id: requireString(candidate.id, "candidate ID", "invalid_fsb3"),
      normalized_url: requireString(candidate.normalized_url, "normalized URL", "invalid_fsb3"),
      tls: decodeTLSPolicyValue(candidate.tls, "invalid_fsb3"),
      wire_profile: requireString(candidate.wire_profile, "wire profile", "invalid_fsb3"),
    };
  });
}

function artifactSessionWire(session: SessionContractV3): Record<string, unknown> {
  return {
    channel_id: session.channel_id,
    init_expire_at_unix_s: session.init_expire_at_unix_s,
    idle_timeout_seconds: session.idle_timeout_seconds,
    establish_timeout_seconds: session.establish_timeout_seconds,
    rekey_prepare_timeout_seconds: session.rekey_prepare_timeout_seconds,
    rekey_completion_timeout_seconds: session.rekey_completion_timeout_seconds,
    max_inbound_streams: session.max_inbound_streams,
    e2ee_psk_b64u: session.e2ee_psk_b64u,
    allowed_suites: session.allowed_suites,
    default_suite: session.default_suite,
    selected_features: session.selected_features,
    contract_hash_b64u: session.contract_hash_b64u,
  };
}

function directPathWire(path: DirectArtifactPathV3): Record<string, unknown> {
  return {
    kind: path.kind,
    rendezvous_group_id: path.rendezvous_group_id,
    listener_audience: path.listener_audience,
    routing_token: path.routing_token,
    candidates: path.candidates.map(candidateWire),
  };
}

function tunnelPathWire(path: TunnelArtifactPathV3): Record<string, unknown> {
  return {
    kind: path.kind,
    rendezvous_group_id: path.rendezvous_group_id,
    listener_audience: path.listener_audience,
    role: path.role,
    local_endpoint_instance_id: path.local_endpoint_instance_id,
    expected_peer_endpoint_instance_id: path.expected_peer_endpoint_instance_id,
    token: path.token,
    candidates: path.candidates.map(candidateWire),
  };
}

function candidateWire(candidate: ArtifactCandidateV3): Record<string, unknown> {
  return {
    id: candidate.id,
    carrier: candidate.carrier,
    url: candidate.url,
    wire_profile: candidate.wire_profile,
    tls: candidate.tls,
  };
}

function validateFSA3Response(
  response: AdmissionResponseV3,
  admissionReasons: ReadonlySet<string>,
  requireRegisteredReason: boolean,
): void {
  switch (response.status) {
    case AdmissionStatusV3.Success:
      if (response.reason !== "") throw invalidFSA3("success reason");
      return;
    case AdmissionStatusV3.Reject:
    case AdmissionStatusV3.Retryable:
      if (!/^[a-z][a-z0-9_]*$/.test(response.reason) || utf8Length(response.reason) > MAX_ADMISSION_REASON_BYTES) {
        throw invalidFSA3("reason token");
      }
      if (FORBIDDEN_FSA3_REASONS.has(response.reason)) throw invalidFSA3("transport security reason");
      if (requireRegisteredReason && !admissionReasons.has(response.reason)) {
        throw invalidFSA3("unregistered reason");
      }
      return;
    default:
      throw invalidFSA3("status");
  }
}

function labeledHash(label: string, canonicalJSON: string): LabeledHashV3 {
  const canonical = encoder.encode(canonicalJSON);
  const hash = sha256(concatBytes([encoder.encode(label), u32be(canonical.length), canonical]));
  return { canonicalJSON, hash, hashBase64URL: base64urlEncode(hash) };
}

function assertCanonical32(
  value: unknown,
  name: string,
  errorCode: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3",
): Uint8Array {
  if (typeof value !== "string") throw codecError(errorCode, `${name} type`);
  try {
    const decoded = base64urlDecode(value);
    if (decoded.length !== 32 || base64urlEncode(decoded) !== value) throw new Error("length");
    return decoded;
  } catch {
    throw codecError(errorCode, `${name} encoding`);
  }
}

function decodeBoundedJSON(raw: string | Uint8Array): string {
  if (typeof raw === "string") {
    if (utf8Length(raw) > MAX_ARTIFACT_JSON_BYTES) {
      throw new ArtifactV3Error("artifact_too_large", "Flowersec v3 artifact is too large");
    }
    return raw;
  }
  if (raw.length > MAX_ARTIFACT_JSON_BYTES) {
    throw new ArtifactV3Error("artifact_too_large", "Flowersec v3 artifact is too large");
  }
  try {
    return decoder.decode(raw);
  } catch {
    throw invalidArtifact("UTF-8");
  }
}

function parseStrictJSON(text: string, scanScopedPayloads = false): unknown {
  preflightJSONV3(text, scanScopedPayloads);
  return JSON.parse(text) as unknown;
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  name: string,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3",
): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || expected.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw codecError(code, `${name} fields`);
  }
}

function assertRecord(
  value: unknown,
  name: string,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3",
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) throw codecError(code, `${name} object`);
}

function requireRecord(
  value: unknown,
  name: string,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3" = "invalid_artifact",
): Record<string, unknown> {
  if (!isRecord(value)) throw codecError(code, `${name} object`);
  return value;
}

function requireString(
  value: unknown,
  name: string,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3" = "invalid_artifact",
): string {
  if (typeof value !== "string") throw codecError(code, `${name} string`);
  return value;
}

function requireNumber(value: unknown, name: string): number {
  if (typeof value !== "number") throw invalidArtifact(`${name} number`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertSafeInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  name: string,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3" = "invalid_artifact",
): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw codecError(code, name);
  }
}

function validRegistryID(value: unknown, maximum: number): value is string {
  return typeof value === "string" && utf8Length(value) >= 1 && utf8Length(value) <= maximum && registryIDPattern.test(value);
}

function validASCII(value: unknown, maximum: number): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (value.charCodeAt(index) > 0x7f) return false;
  }
  return true;
}

function utf8Length(value: string): number {
  return encoder.encode(value).length;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function pathKindFromCode(code: number): ArtifactPathKindV3 {
  if (code === 1) return "direct";
  if (code === 2) return "tunnel";
  throw invalidFSB3("path code");
}

function codecError(
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb3",
  detail: string,
): ArtifactV3Error {
  switch (code) {
    case "invalid_artifact":
      return invalidArtifact(detail);
    case "invalid_candidate":
      return invalidCandidate(detail);
    case "invalid_fsb3":
      return invalidFSB3(detail);
  }
}

function invalidArtifact(detail: string): ArtifactV3Error {
  return new ArtifactV3Error("invalid_artifact", `invalid Flowersec v3 artifact: ${detail}`);
}

function invalidCandidate(detail: string): ArtifactV3Error {
  return new ArtifactV3Error("invalid_candidate", `invalid Flowersec v3 candidate: ${detail}`);
}

function invalidFSB3(detail: string): ArtifactV3Error {
  return new ArtifactV3Error("invalid_fsb3", `invalid FSB3 admission request: ${detail}`);
}

function invalidFSA3(detail: string): ArtifactV3Error {
  return new ArtifactV3Error("invalid_fsa3", `invalid FSA3 admission response: ${detail}`);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
