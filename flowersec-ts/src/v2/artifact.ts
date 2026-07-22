import { sha256 } from "@noble/hashes/sha256";

import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { concatBytes, readU32be, u32be } from "../utils/bin.js";
import { toASCII } from "../vendor/tr46.js";

export type ArtifactCarrierV2 = "websocket" | "raw_quic" | "webtransport";
export type ArtifactPathKindV2 = "direct" | "tunnel";

export type ArtifactCandidateV2 = Readonly<{
  id: string;
  carrier: ArtifactCarrierV2;
  url: string;
  wire_profile: string;
  normalized_url?: string;
}>;

export type CanonicalArtifactCandidateV2 = Readonly<{
  carrier: ArtifactCarrierV2;
  id: string;
  normalized_url: string;
  wire_profile: string;
}>;

export type SessionContractV2 = Readonly<{
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

export type DirectArtifactPathV2 = Readonly<{
  kind: "direct";
  rendezvous_group_id: string;
  listener_audience: string;
  routing_token: string;
  candidates: readonly ArtifactCandidateV2[];
}>;

export type TunnelArtifactPathV2 = Readonly<{
  kind: "tunnel";
  rendezvous_group_id: string;
  listener_audience: string;
  role: 1 | 2;
  local_endpoint_instance_id: string;
  expected_peer_endpoint_instance_id: string;
  token: string;
  candidates: readonly ArtifactCandidateV2[];
}>;

export type ScopeMetadataV2 = Readonly<{
  scope: string;
  scope_version: number;
  critical: boolean;
  payload: Readonly<Record<string, unknown>>;
}>;

export type CorrelationTagV2 = Readonly<{
  key: string;
  value: string;
}>;

export type CorrelationContextV2 = Readonly<{
  v: 2;
  tags: readonly CorrelationTagV2[];
}>;

export type ArtifactV2 = Readonly<{
  v: 2;
  profile: "flowersec/2";
  session: SessionContractV2;
  path: DirectArtifactPathV2 | TunnelArtifactPathV2;
  scoped: readonly ScopeMetadataV2[];
  correlation: CorrelationContextV2;
}>;

type CommonFSB2RequestV2 = Readonly<{
  profile: "flowersec/2";
  channel_id: string;
  session_contract_hash_b64u: string;
  rendezvous_group_id: string;
  candidates: readonly CanonicalArtifactCandidateV2[];
  candidate_set_hash_b64u: string;
  chosen_candidate_id: string;
  listener_audience: string;
}>;

export type DirectFSB2RequestV2 = CommonFSB2RequestV2 &
  Readonly<{
    pathKind: "direct";
    routing_token: string;
  }>;

export type TunnelFSB2RequestV2 = CommonFSB2RequestV2 &
  Readonly<{
    pathKind: "tunnel";
    role: 1 | 2;
    endpoint_instance_id: string;
    attach_token: string;
  }>;

export type FSB2RequestV2 = DirectFSB2RequestV2 | TunnelFSB2RequestV2;

export type DecodedFSB2RequestV2 = Readonly<{
  request: FSB2RequestV2;
  raw: Uint8Array;
  localAdmissionBinding: Uint8Array;
}>;

export enum AdmissionStatusV2 {
  Success = 0,
  Reject = 1,
  Retryable = 2,
}

export type AdmissionResponseV2 = Readonly<{
  status: AdmissionStatusV2;
  reason: string;
}>;

export type ArtifactV2ErrorCode =
  | "artifact_too_large"
  | "fsb2_payload_too_large"
  | "invalid_artifact"
  | "invalid_candidate"
  | "invalid_fsa2"
  | "invalid_fsb2"
  | "noncanonical_fsb2"
  | "unknown_admission_reason";

export class ArtifactV2Error extends Error {
  readonly code: ArtifactV2ErrorCode;

  constructor(code: ArtifactV2ErrorCode, message: string) {
    super(message);
    this.name = "ArtifactV2Error";
    this.code = code;
  }
}

export type LabeledHashV2 = Readonly<{
  canonicalJSON: string;
  hash: Uint8Array;
  hashBase64URL: string;
}>;

export type CanonicalCandidateSetV2 = LabeledHashV2 &
  Readonly<{
    candidates: readonly CanonicalArtifactCandidateV2[];
  }>;

const PROFILE = "flowersec/2";
const MAX_ARTIFACT_JSON_BYTES = 65_536;
const MAX_CANDIDATES = 4;
const MAX_CANONICAL_CANDIDATE_BYTES = 2_304;
const MAX_CANONICAL_CANDIDATE_SET_BYTES = 12 * 1_024;
const MAX_CANONICAL_FSB2_PAYLOAD = 32_768;
const MAX_ADMISSION_REASON_BYTES = 64;
const MAX_ADMISSION_CREDENTIAL_BYTES = 8_192;
const FSB2_HEADER_BYTES = 12;
const FSA2_HEADER_BYTES = 8;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const registryIDPattern = /^[A-Za-z0-9._~-]+$/;
const candidateIDPattern = /^[a-z0-9][a-z0-9._-]*$/;
const scopePattern = /^[a-z][a-z0-9._-]{0,63}$/;
const correlationKeyPattern = /^[a-z][a-z0-9._-]{0,31}$/;

export function computeSessionContractHashV2(session: SessionContractV2): LabeledHashV2 {
  validateSession(session);
  const canonicalJSON = JSON.stringify({
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
  return labeledHash("flowersec-v2-session-contract\0", canonicalJSON);
}

export function canonicalizeCandidatesV2(
  kind: ArtifactPathKindV2,
  candidates: readonly ArtifactCandidateV2[],
): CanonicalCandidateSetV2 {
  if (kind !== "direct" && kind !== "tunnel") throw invalidCandidate("path kind");
  if (!Array.isArray(candidates) || candidates.length < 1 || candidates.length > MAX_CANDIDATES) {
    throw invalidCandidate("candidate count");
  }
  const ids = new Set<string>();
  const tuples = new Set<string>();
  const canonical: CanonicalArtifactCandidateV2[] = [];
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
    const wireProfile = `flowersec-${kind}/2`;
    if (candidate.wire_profile !== wireProfile) throw invalidCandidate("wire profile");
    const tuple = `${candidate.carrier}\0${normalizedURL}\0${candidate.wire_profile}`;
    if (tuples.has(tuple)) throw invalidCandidate("duplicate normalized tuple");
    tuples.add(tuple);
    const item: CanonicalArtifactCandidateV2 = {
      carrier: candidate.carrier,
      id: candidate.id,
      normalized_url: normalizedURL,
      wire_profile: candidate.wire_profile,
    };
    if (utf8Length(JSON.stringify(item)) > MAX_CANONICAL_CANDIDATE_BYTES) {
      throw invalidCandidate("canonical candidate too large");
    }
    canonical.push(item);
  }
  canonical.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const canonicalJSON = JSON.stringify(canonical);
  if (utf8Length(canonicalJSON) > MAX_CANONICAL_CANDIDATE_SET_BYTES) {
    throw invalidCandidate("canonical candidate set too large");
  }
  return { candidates: canonical, ...labeledHash("flowersec-v2-candidates\0", canonicalJSON) };
}

export function decodeArtifactV2JSON(raw: string | Uint8Array): ArtifactV2 {
  const text = decodeBoundedJSON(raw);
  let value: unknown;
  try {
    value = parseStrictJSON(text);
  } catch (error) {
    throw invalidArtifact(`strict JSON: ${errorMessage(error)}`);
  }
  const artifact = decodeArtifactValue(value);
  const canonicalCandidates = validateArtifactV2(artifact);
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
    } as DirectArtifactPathV2 | TunnelArtifactPathV2,
  };
}

export function encodeArtifactV2JSON(artifact: ArtifactV2): Uint8Array {
  validateArtifactV2(artifact);
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
  const raw = encoder.encode(JSON.stringify(wire));
  if (raw.length > MAX_ARTIFACT_JSON_BYTES) {
    throw new ArtifactV2Error("artifact_too_large", "Flowersec v2 artifact is too large");
  }
  return raw;
}

export function validateArtifactV2(artifact: ArtifactV2): CanonicalCandidateSetV2 {
  validateArtifactShape(artifact);
  if (artifact.v !== 2 || artifact.profile !== PROFILE) throw invalidArtifact("version or profile");
  const sessionHash = computeSessionContractHashV2(artifact.session);
  if (sessionHash.hashBase64URL !== artifact.session.contract_hash_b64u) {
    throw invalidArtifact("session contract hash");
  }
  const candidateSet = canonicalizeCandidatesV2(artifact.path.kind, artifact.path.candidates);
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
    if (marshalFSB2Payload(request).length > MAX_CANONICAL_FSB2_PAYLOAD) {
      throw new ArtifactV2Error("fsb2_payload_too_large", "FSB2 canonical payload is too large");
    }
  }
  return candidateSet;
}

export function buildFSB2RequestV2(artifact: ArtifactV2, chosenCandidateID: string): FSB2RequestV2 {
  const candidateSet = validateArtifactV2(artifact);
  const request = requestFromValidatedArtifact(artifact, candidateSet, chosenCandidateID);
  validateFSB2Request(request);
  return request;
}

export function encodeFSB2RequestV2(request: FSB2RequestV2): Uint8Array {
  validateFSB2Request(request);
  const payload = marshalFSB2Payload(request);
  if (payload.length > MAX_CANONICAL_FSB2_PAYLOAD) {
    throw new ArtifactV2Error("fsb2_payload_too_large", "FSB2 canonical payload is too large");
  }
  const out = new Uint8Array(FSB2_HEADER_BYTES + payload.length);
  out.set(encoder.encode("FSB2"), 0);
  out[4] = 2;
  out[5] = request.pathKind === "direct" ? 1 : 2;
  out.set(u32be(payload.length), 8);
  out.set(payload, FSB2_HEADER_BYTES);
  return out;
}

export function decodeFSB2RequestV2(raw: Uint8Array): DecodedFSB2RequestV2 {
  if (raw.length < FSB2_HEADER_BYTES) throw invalidFSB2("truncated header");
  if (
    raw[0] !== 0x46 ||
    raw[1] !== 0x53 ||
    raw[2] !== 0x42 ||
    raw[3] !== 0x32 ||
    raw[4] !== 2 ||
    raw[6] !== 0 ||
    raw[7] !== 0
  ) {
    throw invalidFSB2("header");
  }
  const pathKind = pathKindFromCode(raw[5]!);
  const payloadLength = readU32be(raw, 8);
  if (payloadLength > MAX_CANONICAL_FSB2_PAYLOAD) {
    throw new ArtifactV2Error("fsb2_payload_too_large", "FSB2 canonical payload is too large");
  }
  if (payloadLength === 0 || raw.length !== FSB2_HEADER_BYTES + payloadLength) {
    throw invalidFSB2("payload length");
  }
  const payload = raw.subarray(FSB2_HEADER_BYTES);
  let text: string;
  let value: unknown;
  try {
    text = decoder.decode(payload);
    value = parseStrictJSON(text);
  } catch (error) {
    throw invalidFSB2(`strict JSON: ${errorMessage(error)}`);
  }
  const request = decodeFSB2Value(pathKind, value);
  validateFSB2Request(request);
  if (!bytesEqual(payload, marshalFSB2Payload(request))) {
    throw new ArtifactV2Error("noncanonical_fsb2", "FSB2 payload is not canonical");
  }
  const copied = new Uint8Array(raw);
  return {
    request,
    raw: copied,
    localAdmissionBinding: admissionBindingV2(copied),
  };
}

export function admissionBindingV2(rawFSB2: Uint8Array): Uint8Array {
  return sha256(concatBytes([encoder.encode("flowersec-v2-admission\0"), rawFSB2]));
}

export function encodeFSA2ResponseV2(
  response: AdmissionResponseV2,
  reasons: ReadonlySet<string>,
): Uint8Array {
  validateFSA2Response(response, reasons);
  const reason = encoder.encode(response.reason);
  const out = new Uint8Array(FSA2_HEADER_BYTES + reason.length);
  out.set(encoder.encode("FSA2"), 0);
  out[4] = 2;
  out[5] = response.status;
  new DataView(out.buffer).setUint16(6, reason.length, false);
  out.set(reason, FSA2_HEADER_BYTES);
  return out;
}

export function decodeFSA2ResponseV2(
  raw: Uint8Array,
  reasons: ReadonlySet<string>,
): AdmissionResponseV2 {
  if (raw.length < FSA2_HEADER_BYTES) throw invalidFSA2("truncated header");
  if (raw[0] !== 0x46 || raw[1] !== 0x53 || raw[2] !== 0x41 || raw[3] !== 0x32 || raw[4] !== 2) {
    throw invalidFSA2("header");
  }
  const reasonLength = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint16(6, false);
  if (reasonLength > MAX_ADMISSION_REASON_BYTES || raw.length !== FSA2_HEADER_BYTES + reasonLength) {
    throw invalidFSA2("reason length");
  }
  let reason: string;
  try {
    reason = decoder.decode(raw.subarray(FSA2_HEADER_BYTES));
  } catch {
    throw invalidFSA2("reason encoding");
  }
  const response = { status: raw[5]! as AdmissionStatusV2, reason };
  validateFSA2Response(response, reasons);
  return response;
}

function validateSession(session: SessionContractV2): void {
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

function validateArtifactShape(artifact: ArtifactV2): void {
  assertRecord(artifact, "artifact", "invalid_artifact");
  assertExactKeys(artifact, ["v", "profile", "session", "path", "scoped", "correlation"], "artifact", "invalid_artifact");
  validateSession(artifact.session);
  validatePathShape(artifact.path, true);
  if (!Array.isArray(artifact.scoped)) throw invalidArtifact("scoped");
  validateCorrelationShape(artifact.correlation);
}

function validatePathShape(path: DirectArtifactPathV2 | TunnelArtifactPathV2, allowNormalized: boolean): void {
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

function validateCandidateShape(candidate: ArtifactCandidateV2, allowNormalized = true): void {
  assertRecord(candidate, "candidate", "invalid_candidate");
  const keys = allowNormalized
    ? ["id", "carrier", "url", "wire_profile", ...(candidate.normalized_url === undefined ? [] : ["normalized_url"])]
    : ["id", "carrier", "url", "wire_profile"];
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
}

function validateScopes(scopes: readonly ScopeMetadataV2[]): void {
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
      !isRecord(scope.payload) ||
      utf8Length(JSON.stringify(scope.payload)) > 4_096
    ) {
      throw invalidArtifact("scope metadata");
    }
    if (seen.has(scope.scope)) throw invalidArtifact("duplicate scope");
    seen.add(scope.scope);
  }
}

function validateCorrelationShape(correlation: CorrelationContextV2): void {
  assertRecord(correlation, "correlation", "invalid_artifact");
  assertExactKeys(correlation, ["v", "tags"], "correlation", "invalid_artifact");
  if (correlation.v !== 2 || !Array.isArray(correlation.tags) || correlation.tags.length > 8) {
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
  kind: ArtifactPathKindV2,
  carrier: ArtifactCarrierV2,
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
      expectedPath = `/flowersec/v2/${kind}`;
      break;
    case "raw_quic":
      expectedScheme = "quic";
      if (path !== "" && path !== "/") throw invalidCandidate("raw QUIC path");
      path = "";
      break;
    case "webtransport":
      expectedScheme = "https";
      expectedPath = `/flowersec/webtransport/v2/${kind}`;
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
  return ascii.toLowerCase();
}

function requestFromValidatedArtifact(
  artifact: ArtifactV2,
  candidateSet: CanonicalCandidateSetV2,
  chosenCandidateID: string,
): FSB2RequestV2 {
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

function validateFSB2Request(request: FSB2RequestV2): void {
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
    assertCanonical32(request.session_contract_hash_b64u, "session hash", "invalid_fsb2");
    assertCanonical32(request.candidate_set_hash_b64u, "candidate hash", "invalid_fsb2");
    const source = request.candidates.map((candidate) => ({
      id: candidate.id,
      carrier: candidate.carrier,
      url: candidate.normalized_url,
      normalized_url: candidate.normalized_url,
      wire_profile: candidate.wire_profile,
    }));
    const canonical = canonicalizeCandidatesV2(request.pathKind, source);
    if (
      canonical.hashBase64URL !== request.candidate_set_hash_b64u ||
      JSON.stringify(canonical.candidates) !== JSON.stringify(request.candidates)
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
    if (error instanceof ArtifactV2Error && error.code === "invalid_fsb2") throw error;
    throw invalidFSB2(errorMessage(error));
  }
}

function marshalFSB2Payload(request: FSB2RequestV2): Uint8Array {
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
  return encoder.encode(JSON.stringify(wire));
}

function decodeArtifactValue(value: unknown): ArtifactV2 {
  const top = requireRecord(value, "artifact");
  assertExactKeys(top, ["v", "profile", "session", "path", "scoped", "correlation"], "artifact", "invalid_artifact");
  if (top.v !== 2 || top.profile !== PROFILE) throw invalidArtifact("version or profile");
  const session = decodeSessionValue(top.session);
  const path = decodePathValue(top.path);
  const scoped = decodeScopesValue(top.scoped);
  const correlation = decodeCorrelationValue(top.correlation);
  return { v: 2, profile: PROFILE, session, path, scoped, correlation };
}

function decodeSessionValue(value: unknown): SessionContractV2 {
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
  const decoded = session as unknown as SessionContractV2;
  validateSession(decoded);
  return decoded;
}

function decodePathValue(value: unknown): DirectArtifactPathV2 | TunnelArtifactPathV2 {
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

function decodeCandidatesValue(value: unknown): readonly ArtifactCandidateV2[] {
  if (!Array.isArray(value)) throw invalidArtifact("candidates");
  return value.map((item) => {
    const candidate = requireRecord(item, "candidate");
    assertExactKeys(candidate, ["id", "carrier", "url", "wire_profile"], "candidate", "invalid_artifact");
    return {
      id: requireString(candidate.id, "candidate id"),
      carrier: requireString(candidate.carrier, "candidate carrier") as ArtifactCarrierV2,
      url: requireString(candidate.url, "candidate URL"),
      wire_profile: requireString(candidate.wire_profile, "wire profile"),
    };
  });
}

function decodeScopesValue(value: unknown): readonly ScopeMetadataV2[] {
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

function decodeCorrelationValue(value: unknown): CorrelationContextV2 {
  const correlation = requireRecord(value, "correlation");
  assertExactKeys(correlation, ["v", "tags"], "correlation", "invalid_artifact");
  if (correlation.v !== 2 || !Array.isArray(correlation.tags)) throw invalidArtifact("correlation");
  return {
    v: 2,
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

function decodeFSB2Value(pathKind: ArtifactPathKindV2, value: unknown): FSB2RequestV2 {
  const wire = requireRecord(value, "FSB2 payload", "invalid_fsb2");
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
    assertExactKeys(wire, [...commonKeys, "routing_token"], "direct FSB2", "invalid_fsb2");
  } else {
    assertExactKeys(wire, [...commonKeys, "attach_token", "endpoint_instance_id", "role"], "tunnel FSB2", "invalid_fsb2");
  }
  const candidates = decodeCanonicalCandidatesValue(wire.candidates);
  const common = {
    profile: requireString(wire.profile, "profile", "invalid_fsb2") as "flowersec/2",
    channel_id: requireString(wire.channel_id, "channel ID", "invalid_fsb2"),
    session_contract_hash_b64u: requireString(wire.session_contract_hash_b64u, "session hash", "invalid_fsb2"),
    rendezvous_group_id: requireString(wire.rendezvous_group_id, "rendezvous group", "invalid_fsb2"),
    candidates,
    candidate_set_hash_b64u: requireString(wire.candidate_set_hash_b64u, "candidate hash", "invalid_fsb2"),
    chosen_candidate_id: requireString(wire.chosen_candidate_id, "chosen candidate", "invalid_fsb2"),
    listener_audience: requireString(wire.listener_audience, "listener audience", "invalid_fsb2"),
  } as const;
  if (pathKind === "direct") {
    return {
      pathKind,
      ...common,
      routing_token: requireString(wire.routing_token, "routing token", "invalid_fsb2"),
    };
  }
  if (wire.role !== 1 && wire.role !== 2) throw invalidFSB2("role");
  return {
    pathKind,
    ...common,
    role: wire.role,
    endpoint_instance_id: requireString(wire.endpoint_instance_id, "endpoint instance", "invalid_fsb2"),
    attach_token: requireString(wire.attach_token, "attach token", "invalid_fsb2"),
  };
}

function decodeCanonicalCandidatesValue(value: unknown): readonly CanonicalArtifactCandidateV2[] {
  if (!Array.isArray(value)) throw invalidFSB2("candidates");
  return value.map((item) => {
    const candidate = requireRecord(item, "canonical candidate", "invalid_fsb2");
    assertExactKeys(candidate, ["carrier", "id", "normalized_url", "wire_profile"], "canonical candidate", "invalid_fsb2");
    return {
      carrier: requireString(candidate.carrier, "carrier", "invalid_fsb2") as ArtifactCarrierV2,
      id: requireString(candidate.id, "candidate ID", "invalid_fsb2"),
      normalized_url: requireString(candidate.normalized_url, "normalized URL", "invalid_fsb2"),
      wire_profile: requireString(candidate.wire_profile, "wire profile", "invalid_fsb2"),
    };
  });
}

function artifactSessionWire(session: SessionContractV2): Record<string, unknown> {
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

function directPathWire(path: DirectArtifactPathV2): Record<string, unknown> {
  return {
    kind: path.kind,
    rendezvous_group_id: path.rendezvous_group_id,
    listener_audience: path.listener_audience,
    routing_token: path.routing_token,
    candidates: path.candidates.map(candidateWire),
  };
}

function tunnelPathWire(path: TunnelArtifactPathV2): Record<string, unknown> {
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

function candidateWire(candidate: ArtifactCandidateV2): Record<string, unknown> {
  return {
    id: candidate.id,
    carrier: candidate.carrier,
    url: candidate.url,
    wire_profile: candidate.wire_profile,
  };
}

function validateFSA2Response(response: AdmissionResponseV2, reasons: ReadonlySet<string>): void {
  switch (response.status) {
    case AdmissionStatusV2.Success:
      if (response.reason !== "") throw invalidFSA2("success reason");
      return;
    case AdmissionStatusV2.Reject:
    case AdmissionStatusV2.Retryable:
      if (!/^[a-z][a-z0-9_]*$/.test(response.reason) || utf8Length(response.reason) > MAX_ADMISSION_REASON_BYTES) {
        throw invalidFSA2("reason token");
      }
      if (!reasons.has(response.reason)) {
        throw new ArtifactV2Error("unknown_admission_reason", `unknown FSA2 reason ${response.reason}`);
      }
      return;
    default:
      throw invalidFSA2("status");
  }
}

function labeledHash(label: string, canonicalJSON: string): LabeledHashV2 {
  const canonical = encoder.encode(canonicalJSON);
  const hash = sha256(concatBytes([encoder.encode(label), u32be(canonical.length), canonical]));
  return { canonicalJSON, hash, hashBase64URL: base64urlEncode(hash) };
}

function assertCanonical32(
  value: unknown,
  name: string,
  errorCode: "invalid_artifact" | "invalid_fsb2",
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
      throw new ArtifactV2Error("artifact_too_large", "Flowersec v2 artifact is too large");
    }
    return raw;
  }
  if (raw.length > MAX_ARTIFACT_JSON_BYTES) {
    throw new ArtifactV2Error("artifact_too_large", "Flowersec v2 artifact is too large");
  }
  try {
    return decoder.decode(raw);
  } catch {
    throw invalidArtifact("UTF-8");
  }
}

function parseStrictJSON(text: string): unknown {
  new DuplicateJSONKeyScanner(text).scan();
  return JSON.parse(text) as unknown;
}

class DuplicateJSONKeyScanner {
  private index = 0;

  constructor(private readonly text: string) {}

  scan(): void {
    this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) throw new Error("trailing JSON value");
  }

  private value(depth: number): void {
    if (depth > 128) throw new Error("JSON nesting is too deep");
    this.whitespace();
    const char = this.text[this.index];
    if (char === "{") return this.object(depth + 1);
    if (char === "[") return this.array(depth + 1);
    if (char === '"') {
      this.string();
      return;
    }
    if (char === "t") return this.literal("true");
    if (char === "f") return this.literal("false");
    if (char === "n") return this.literal("null");
    this.number();
  }

  private object(depth: number): void {
    this.index += 1;
    this.whitespace();
    const seen = new Set<string>();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return;
    }
    while (true) {
      this.whitespace();
      if (this.text[this.index] !== '"') throw new Error("JSON object key is not a string");
      const key = this.string();
      if (seen.has(key)) throw new Error(`duplicate JSON field ${JSON.stringify(key)}`);
      seen.add(key);
      this.whitespace();
      if (this.text[this.index] !== ":") throw new Error("missing JSON colon");
      this.index += 1;
      this.value(depth);
      this.whitespace();
      const next = this.text[this.index];
      if (next === "}") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new Error("invalid JSON object separator");
      this.index += 1;
    }
  }

  private array(depth: number): void {
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return;
    }
    while (true) {
      this.value(depth);
      this.whitespace();
      const next = this.text[this.index];
      if (next === "]") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new Error("invalid JSON array separator");
      this.index += 1;
    }
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        return JSON.parse(this.text.slice(start, this.index)) as string;
      }
      if (code < 0x20) throw new Error("control character in JSON string");
      if (code === 0x5c) {
        this.index += 1;
        const escaped = this.text[this.index];
        if (escaped === "u") {
          const digits = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) throw new Error("invalid JSON unicode escape");
          this.index += 5;
          continue;
        }
        if (escaped === undefined || !'"\\/bfnrt'.includes(escaped)) {
          throw new Error("invalid JSON escape");
        }
      }
      this.index += 1;
    }
    throw new Error("unterminated JSON string");
  }

  private number(): void {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.text.slice(this.index));
    if (match === null) throw new Error("invalid JSON value");
    this.index += match[0].length;
  }

  private literal(value: string): void {
    if (!this.text.startsWith(value, this.index)) throw new Error("invalid JSON literal");
    this.index += value.length;
  }

  private whitespace(): void {
    while (/[\u0009\u000a\u000d\u0020]/.test(this.text[this.index] ?? "")) this.index += 1;
  }
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  name: string,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb2",
): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || expected.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw codecError(code, `${name} fields`);
  }
}

function assertRecord(
  value: unknown,
  name: string,
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb2",
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) throw codecError(code, `${name} object`);
}

function requireRecord(
  value: unknown,
  name: string,
  code: "invalid_artifact" | "invalid_fsb2" = "invalid_artifact",
): Record<string, unknown> {
  if (!isRecord(value)) throw codecError(code, `${name} object`);
  return value;
}

function requireString(
  value: unknown,
  name: string,
  code: "invalid_artifact" | "invalid_fsb2" = "invalid_artifact",
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

function assertSafeInteger(value: unknown, minimum: number, maximum: number, name: string): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalidArtifact(name);
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

function pathKindFromCode(code: number): ArtifactPathKindV2 {
  if (code === 1) return "direct";
  if (code === 2) return "tunnel";
  throw invalidFSB2("path code");
}

function codecError(
  code: "invalid_artifact" | "invalid_candidate" | "invalid_fsb2",
  detail: string,
): ArtifactV2Error {
  switch (code) {
    case "invalid_artifact":
      return invalidArtifact(detail);
    case "invalid_candidate":
      return invalidCandidate(detail);
    case "invalid_fsb2":
      return invalidFSB2(detail);
  }
}

function invalidArtifact(detail: string): ArtifactV2Error {
  return new ArtifactV2Error("invalid_artifact", `invalid Flowersec v2 artifact: ${detail}`);
}

function invalidCandidate(detail: string): ArtifactV2Error {
  return new ArtifactV2Error("invalid_candidate", `invalid Flowersec v2 candidate: ${detail}`);
}

function invalidFSB2(detail: string): ArtifactV2Error {
  return new ArtifactV2Error("invalid_fsb2", `invalid FSB2 admission request: ${detail}`);
}

function invalidFSA2(detail: string): ArtifactV2Error {
  return new ArtifactV2Error("invalid_fsa2", `invalid FSA2 admission response: ${detail}`);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
