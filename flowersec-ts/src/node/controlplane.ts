import { randomBytes as nodeRandomBytes, timingSafeEqual } from "node:crypto";

import {
  buildFSB2RequestV2,
  canonicalizeCandidatesV2,
  computeSessionContractHashV2,
  decodeArtifactV2JSON,
  decodeFSB2RequestV2,
  encodeArtifactV2JSON,
  encodeFSB2RequestV2,
  type ArtifactCandidateV2,
  type ArtifactV2,
  type ArtifactCarrierV2,
  type SessionContractV2,
} from "../v2/artifact.js";
import { wrapArtifact, type Artifact } from "../public/artifact.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { sha256 } from "@noble/hashes/sha2.js";

const MAX_RECORD_BYTES = 96 * 1024;
const LEASE_ID = /^[A-Za-z0-9._~-]{1,128}$/u;
const REASON = /^[a-z][a-z0-9_]*$/u;
const PROFILE = "flowersec/2" as const;

export type ControlPlaneErrorCode = "invalid_input" | "issuance_failed";

export class ControlPlaneError extends Error {
  constructor(readonly code: ControlPlaneErrorCode) {
    super(`Flowersec control-plane failed (code=${code})`);
    this.name = "ControlPlaneError";
  }
}

type Endpoint = Readonly<{ carrier: ArtifactCarrierV2; url: string }>;

/** Validated listener URLs used when issuing opaque artifacts. */
export class EndpointSet {
  readonly #endpoints: readonly Endpoint[];

  constructor(...urls: readonly string[]) {
    if (urls.length < 1 || urls.length > 4) throw invalidInput();
    const values: Endpoint[] = [];
    for (const url of urls) {
      if (url.length === 0 || url.trim() !== url) throw invalidInput();
      const separator = url.indexOf("://");
      if (separator <= 0) throw invalidInput();
      const scheme = url.slice(0, separator).toLowerCase();
      const carrier = scheme === "ws" || scheme === "wss"
        ? "websocket"
        : scheme === "quic"
          ? "raw_quic"
          : scheme === "https"
            ? "webtransport"
            : undefined;
      if (carrier === undefined) throw invalidInput();
      values.push({ carrier, url });
    }
    this.#endpoints = Object.freeze(values);
  }

  /** @internal */
  toCandidates(kind: "direct" | "tunnel"): readonly ArtifactCandidateV2[] {
    const counts = new Map<ArtifactCarrierV2, number>();
    const candidates = this.#endpoints.map(({ carrier, url }) => {
      const count = (counts.get(carrier) ?? 0) + 1;
      counts.set(carrier, count);
      const base = carrier === "websocket" ? "websocket" : carrier === "raw_quic" ? "raw-quic" : "webtransport";
      return {
        id: count === 1 ? base : `${base}-${count}`,
        carrier,
        url,
        wire_profile: `flowersec-${kind}/2`,
      };
    });
    try {
      canonicalizeCandidatesV2(kind, candidates);
    } catch {
      throw invalidInput();
    }
    return candidates;
  }
}

export function createEndpointSet(...urls: readonly string[]): EndpointSet {
  return new EndpointSet(...urls);
}

export type SessionOptions = Readonly<{
  channelId: string;
  expiresAtUnixSeconds?: number;
  idleTimeoutSeconds?: number;
  maxInboundStreams?: number;
}>;

export type Scope = Readonly<{
  name: string;
  version: number;
  critical: boolean;
  payload: Readonly<Record<string, unknown>>;
}>;

export type ArtifactMetadata = Readonly<{
  scopes?: readonly Scope[];
  correlationTags?: Readonly<Record<string, string>>;
}>;

export type DirectIssueOptions = Readonly<{
  session: SessionOptions;
  endpoints: EndpointSet;
  rendezvousGroupId: string;
  listenerAudience: string;
  upstreamAddress: string;
  metadata?: ArtifactMetadata;
}>;

export type TunnelIssueOptions = Readonly<{
  session: SessionOptions;
  endpoints: EndpointSet;
  rendezvousGroupId: string;
  listenerAudience: string;
  firstEndpointId: string;
  secondEndpointId: string;
  allowReplacement?: boolean;
  firstMetadata?: ArtifactMetadata;
  secondMetadata?: ArtifactMetadata;
}>;

export class Issuer {
  readonly #now: () => number;
  readonly #random: (size: number) => Uint8Array;

  constructor() {
    this.#now = () => Math.floor(Date.now() / 1000);
    this.#random = (size) => nodeRandomBytes(size);
  }

  issueDirect(options: DirectIssueOptions): IssuedArtifact {
    const session = this.#session(options.session);
    const candidates = options.endpoints.toCandidates("direct");
    if (!validTCPAddress(options.upstreamAddress)) throw invalidInput();
    const credential = this.#credential();
    const artifact: ArtifactV2 = {
      v: 2, profile: PROFILE, session,
      path: {
        kind: "direct",
        rendezvous_group_id: options.rendezvousGroupId,
        listener_audience: options.listenerAudience,
        routing_token: credential,
        candidates,
      },
      scoped: metadataScopes(options.metadata),
      correlation: metadataCorrelation(options.metadata),
    };
    return this.#issued(artifact, options.upstreamAddress, false);
  }

  issueTunnelPair(options: TunnelIssueOptions): IssuedTunnelPair {
    const session = this.#session(options.session);
    const candidates = options.endpoints.toCandidates("tunnel");
    if (!validID(options.firstEndpointId) || !validID(options.secondEndpointId) || options.firstEndpointId === options.secondEndpointId) throw invalidInput();
    const allowReplacement = options.allowReplacement ?? false;
    const build = (role: 1 | 2, local: string, peer: string, token: string, metadata?: ArtifactMetadata): IssuedArtifact => this.#issued({
      v: 2, profile: PROFILE, session,
      path: {
        kind: "tunnel", rendezvous_group_id: options.rendezvousGroupId,
        listener_audience: options.listenerAudience, role,
        local_endpoint_instance_id: local,
        expected_peer_endpoint_instance_id: peer,
        token, candidates,
      },
      scoped: metadataScopes(metadata), correlation: metadataCorrelation(metadata),
    }, "", allowReplacement);
    return {
      first: build(1, options.firstEndpointId, options.secondEndpointId, this.#credential(), options.firstMetadata),
      second: build(2, options.secondEndpointId, options.firstEndpointId, this.#credential(), options.secondMetadata),
    };
  }

  #session(options: SessionOptions): SessionContractV2 {
    const now = this.#now();
    const expires = options.expiresAtUnixSeconds ?? now + 60;
    const idle = options.idleTimeoutSeconds ?? 60;
    const max = options.maxInboundStreams ?? 32;
    if (!validID(options.channelId) || !Number.isSafeInteger(expires) || expires <= now || expires > now + 300 ||
        !Number.isSafeInteger(idle) || idle < 0 || idle > 0xffff_ffff || !Number.isSafeInteger(max) || max < 1 || max > 128) throw invalidInput();
    const psk = this.#random(32);
    if (psk.length !== 32) throw issuanceFailed();
    const unsigned = {
      channel_id: options.channelId, init_expire_at_unix_s: expires,
      idle_timeout_seconds: idle, establish_timeout_seconds: 30,
      rekey_prepare_timeout_seconds: 10, rekey_completion_timeout_seconds: 30,
      max_inbound_streams: max, e2ee_psk_b64u: base64urlEncode(psk),
      allowed_suites: [1, 2], default_suite: 1, selected_features: 0,
    };
    const hash = computeSessionContractHashV2({ ...unsigned, contract_hash_b64u: "A".repeat(43) }).hashBase64URL;
    return { ...unsigned, contract_hash_b64u: hash };
  }

  #credential(): string {
    const value = this.#random(32);
    if (value.length !== 32) throw issuanceFailed();
    return base64urlEncode(value);
  }

  #issued(artifact: ArtifactV2, directUpstream: string, allowReplacement: boolean): IssuedArtifact {
    try {
      const bytes = encodeArtifactV2JSON(artifact);
      return new IssuedArtifact(bytes, AuthorizationRecord.create(bytes, artifact, directUpstream, allowReplacement));
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw invalidInput();
    }
  }
}

export class IssuedArtifact {
  #artifact: Uint8Array;
  #record: AuthorizationRecord;

  /** @internal */
  constructor(artifact: Uint8Array, record: AuthorizationRecord) {
    this.#artifact = artifact.slice();
    this.#record = record;
  }

  artifactJSON(): Uint8Array { return this.#artifact.slice(); }
  authorizationRecord(): AuthorizationRecord { return this.#record; }
  lookupKey(): string { return this.#record.lookupKey(); }

}

export type IssuedTunnelPair = Readonly<{ first: IssuedArtifact; second: IssuedArtifact }>;

export class AuthorizationRecord {
  readonly #artifact: ArtifactV2;
  readonly #artifactJSON: Uint8Array;
  readonly #lookup: string;
  readonly #upstream: string;
  readonly #allowReplacement: boolean;

  private constructor(artifactJSON: Uint8Array, artifact: ArtifactV2, upstream: string, allowReplacement: boolean) {
    const credential = artifact.path.kind === "direct" ? artifact.path.routing_token : artifact.path.token;
    if (artifact.path.kind === "direct" ? upstream === "" || allowReplacement : upstream !== "") throw invalidInput();
    this.#artifact = artifact;
    this.#artifactJSON = artifactJSON.slice();
    this.#lookup = base64urlEncode(sha256(new TextEncoder().encode(credential)));
    this.#upstream = upstream;
    this.#allowReplacement = allowReplacement;
  }

  /** @internal */
  static create(artifactJSON: Uint8Array, artifact: ArtifactV2, upstream: string, allowReplacement: boolean): AuthorizationRecord {
    return new AuthorizationRecord(artifactJSON, artifact, upstream, allowReplacement);
  }

  lookupKey(): string { return this.#lookup; }
  encode(): Uint8Array {
    const wire = {
      schema_version: 1,
      artifact_base64url: base64urlEncode(this.#artifactJSON),
      lookup_key: this.#lookup,
      ...(this.#upstream === "" ? {} : { direct_upstream: this.#upstream }),
      allow_replacement: this.#allowReplacement,
    };
    return new TextEncoder().encode(JSON.stringify(wire));
  }

  static parse(encoded: string | Uint8Array): AuthorizationRecord {
    const bytes = typeof encoded === "string" ? new TextEncoder().encode(encoded) : encoded;
    if (bytes.length === 0 || bytes.length > MAX_RECORD_BYTES) throw invalidInput();
    const wire = strictObject(bytes);
    assertExactKeys(wire, ["schema_version", "artifact_base64url", "lookup_key", "direct_upstream", "allow_replacement"], ["direct_upstream"]);
    if (wire.schema_version !== 1 || typeof wire.artifact_base64url !== "string" || typeof wire.lookup_key !== "string" || typeof wire.allow_replacement !== "boolean") throw invalidInput();
    const artifactJSON = base64urlDecode(wire.artifact_base64url);
    const artifact = decodeArtifactV2JSON(artifactJSON);
    const upstream = wire.direct_upstream === undefined ? "" : wire.direct_upstream;
    if (typeof upstream !== "string") throw invalidInput();
    const record = AuthorizationRecord.create(artifactJSON, artifact, upstream, wire.allow_replacement);
    if (record.lookupKey() !== wire.lookup_key) throw invalidInput();
    return record;
  }

  /** @internal */
  get artifact(): ArtifactV2 { return this.#artifact; }
  /** @internal */
  get artifactJSON(): Uint8Array { return this.#artifactJSON.slice(); }
  /** @internal */
  get upstream(): string { return this.#upstream; }
  /** @internal */
  get allowReplacement(): boolean { return this.#allowReplacement; }
}

export class RuntimeAuthorizationRequest {
  readonly #decoded: ReturnType<typeof decodeFSB2RequestV2>;
  readonly #lookup: string;
  readonly #carrier: ArtifactCarrierV2;

  private constructor(decoded: ReturnType<typeof decodeFSB2RequestV2>, carrier: ArtifactCarrierV2) {
    this.#decoded = decoded;
    this.#carrier = carrier;
    const credential = decoded.request.pathKind === "direct" ? decoded.request.routing_token : decoded.request.attach_token;
    this.#lookup = base64urlEncode(sha256(new TextEncoder().encode(credential)));
  }

  /** @internal */
  static fromDecoded(decoded: ReturnType<typeof decodeFSB2RequestV2>, carrier: ArtifactCarrierV2): RuntimeAuthorizationRequest {
    return new RuntimeAuthorizationRequest(decoded, carrier);
  }

  static parse(encoded: string | Uint8Array): RuntimeAuthorizationRequest {
    const wire = strictObject(typeof encoded === "string" ? new TextEncoder().encode(encoded) : encoded);
    assertExactKeys(wire, ["fsb2_base64url", "carrier", "remote_address"]);
    if (typeof wire.fsb2_base64url !== "string" || typeof wire.carrier !== "string" || typeof wire.remote_address !== "string" || !validObservedText(wire.remote_address)) throw invalidInput();
    const decoded = decodeFSB2RequestV2(base64urlDecode(wire.fsb2_base64url));
    const candidate = decoded.request.candidates.find((item) => item.id === decoded.request.chosen_candidate_id);
    if (candidate === undefined || candidate.carrier !== wire.carrier) throw invalidInput();
    return new RuntimeAuthorizationRequest(decoded, candidate.carrier);
  }

  lookupKey(): string { return this.#lookup; }
  /** @internal */ get decoded(): ReturnType<typeof decodeFSB2RequestV2> { return this.#decoded; }
  /** @internal */ get carrier(): ArtifactCarrierV2 { return this.#carrier; }
}

/** @internal */
export function runtimeAuthorizationRequestFromDecoded(
  decoded: ReturnType<typeof decodeFSB2RequestV2>,
): RuntimeAuthorizationRequest {
  const candidate = decoded.request.candidates.find((item) => item.id === decoded.request.chosen_candidate_id);
  if (candidate === undefined) throw invalidInput();
  return RuntimeAuthorizationRequest.fromDecoded(decoded, candidate.carrier);
}

export type DirectAuthorizationDecision =
  | Readonly<{
    decision: "allow";
    artifact: Artifact;
  }>
  | Readonly<{ decision: "reject" | "retry"; reason: string }>;

export type TunnelAuthorizationDecision =
  | Readonly<{
    decision: "allow";
    credentialId: string;
    leaseId: string;
    expiresAtUnixSeconds: number;
    expectedPeerEndpointInstanceId: string;
    allowReplacement?: boolean;
  }>
  | Readonly<{ decision: "reject" | "retry"; reason: string }>;

type DirectAllowDecision = Extract<DirectAuthorizationDecision, Readonly<{ decision: "allow" }>>;
type DirectRuntimeAllowDecision = DirectAllowDecision & Readonly<{
  leaseId: string;
  expiresAtUnixSeconds: number;
}>;
type DirectDenyDecision = Extract<DirectAuthorizationDecision, Readonly<{ decision: "reject" | "retry" }>>;
type TunnelAllowDecision = Extract<TunnelAuthorizationDecision, Readonly<{ decision: "allow" }>>;
type TunnelDenyDecision = Extract<TunnelAuthorizationDecision, Readonly<{ decision: "reject" | "retry" }>>;

export class AuthorizationResponse<Decision extends DirectAuthorizationDecision = DirectAuthorizationDecision> {
  readonly #json: Uint8Array;
  readonly #decision: Decision;
  readonly decision: Decision["decision"];
  readonly artifact: Decision extends DirectAllowDecision ? Artifact : undefined;
  readonly leaseId: Decision extends DirectRuntimeAllowDecision ? string : undefined;
  readonly expiresAtUnixSeconds: Decision extends DirectRuntimeAllowDecision ? number : undefined;
  readonly reason: Decision extends DirectDenyDecision ? string : undefined;
  /** @internal */
  constructor(json: Uint8Array, decision: Decision) {
    this.#json = json.slice();
    this.#decision = decision;
    this.decision = decision.decision;
    this.artifact = (decision.decision === "allow" ? decision.artifact : undefined) as AuthorizationResponse<Decision>["artifact"];
    this.leaseId = (decision.decision === "allow" && "leaseId" in decision ? decision.leaseId : undefined) as AuthorizationResponse<Decision>["leaseId"];
    this.expiresAtUnixSeconds = (decision.decision === "allow" && "expiresAtUnixSeconds" in decision ? decision.expiresAtUnixSeconds : undefined) as AuthorizationResponse<Decision>["expiresAtUnixSeconds"];
    this.reason = (decision.decision === "allow" ? undefined : decision.reason) as AuthorizationResponse<Decision>["reason"];
  }
  json(): Uint8Array { return this.#json.slice(); }
  /** @internal */
  asDecision(): Decision { return this.#decision; }
}

export class TunnelAuthorizationResponse<Decision extends TunnelAuthorizationDecision = TunnelAuthorizationDecision> {
  readonly #json: Uint8Array;
  readonly #decision: Decision;
  readonly decision: Decision["decision"];
  readonly credentialId: Decision extends TunnelAllowDecision ? string : undefined;
  readonly leaseId: Decision extends TunnelAllowDecision ? string : undefined;
  readonly expiresAtUnixSeconds: Decision extends TunnelAllowDecision ? number : undefined;
  readonly expectedPeerEndpointInstanceId: Decision extends TunnelAllowDecision ? string : undefined;
  readonly allowReplacement: Decision extends TunnelAllowDecision ? boolean | undefined : undefined;
  readonly reason: Decision extends TunnelDenyDecision ? string : undefined;
  /** @internal */
  constructor(json: Uint8Array, decision: Decision) {
    this.#json = json.slice();
    this.#decision = decision;
    this.decision = decision.decision;
    this.credentialId = (decision.decision === "allow" ? decision.credentialId : undefined) as TunnelAuthorizationResponse<Decision>["credentialId"];
    this.leaseId = (decision.decision === "allow" ? decision.leaseId : undefined) as TunnelAuthorizationResponse<Decision>["leaseId"];
    this.expiresAtUnixSeconds = (decision.decision === "allow" ? decision.expiresAtUnixSeconds : undefined) as TunnelAuthorizationResponse<Decision>["expiresAtUnixSeconds"];
    this.expectedPeerEndpointInstanceId = (decision.decision === "allow" ? decision.expectedPeerEndpointInstanceId : undefined) as TunnelAuthorizationResponse<Decision>["expectedPeerEndpointInstanceId"];
    this.allowReplacement = (decision.decision === "allow" ? decision.allowReplacement : undefined) as TunnelAuthorizationResponse<Decision>["allowReplacement"];
    this.reason = (decision.decision === "allow" ? undefined : decision.reason) as TunnelAuthorizationResponse<Decision>["reason"];
  }
  json(): Uint8Array { return this.#json.slice(); }
  /** @internal */
  asDecision(): Decision { return this.#decision; }
}

export function authorizeRuntime(request: RuntimeAuthorizationRequest, record: AuthorizationRecord, leaseId: string, nowUnixSeconds = Math.floor(Date.now() / 1000)): AuthorizationResponse<DirectRuntimeAllowDecision> {
  if (!(request instanceof RuntimeAuthorizationRequest) || !(record instanceof AuthorizationRecord) || !LEASE_ID.test(leaseId) || request.lookupKey() !== record.lookupKey()) throw invalidInput();
  const artifact = record.artifact;
  if (nowUnixSeconds >= artifact.session.init_expire_at_unix_s) throw invalidInput();
  const expected = encodeFSB2RequestV2(buildFSB2RequestV2(artifact, request.decoded.request.chosen_candidate_id));
  if (!bytesEqual(expected, request.decoded.raw)) throw invalidInput();
  const base = { decision: "allow", credential_id: record.lookupKey(), lease_id: leaseId, expires_at: new Date(artifact.session.init_expire_at_unix_s * 1000).toISOString() } as Record<string, unknown>;
  if (artifact.path.kind !== "direct") throw invalidInput();
  base.direct = { session: sessionWire(artifact.session), upstream: { network: "tcp", address: record.upstream } };
  return new AuthorizationResponse(
    new TextEncoder().encode(JSON.stringify(base)),
    {
      decision: "allow",
      artifact: wrapArtifact(artifact),
      leaseId,
      expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
    },
  );
}

export function authorizeTunnelRuntime(request: RuntimeAuthorizationRequest, record: AuthorizationRecord, leaseId: string, nowUnixSeconds = Math.floor(Date.now() / 1000)): TunnelAuthorizationResponse<TunnelAllowDecision> {
  if (!(request instanceof RuntimeAuthorizationRequest) || !(record instanceof AuthorizationRecord) || !LEASE_ID.test(leaseId) || request.lookupKey() !== record.lookupKey()) throw invalidInput();
  const artifact = record.artifact;
  if (artifact.path.kind !== "tunnel" || nowUnixSeconds >= artifact.session.init_expire_at_unix_s) throw invalidInput();
  const expected = encodeFSB2RequestV2(buildFSB2RequestV2(artifact, request.decoded.request.chosen_candidate_id));
  if (!bytesEqual(expected, request.decoded.raw)) throw invalidInput();
  const decision: TunnelAuthorizationDecision = {
    decision: "allow",
    credentialId: record.lookupKey(),
    leaseId,
    expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
    expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id,
    allowReplacement: record.allowReplacement,
  };
  return new TunnelAuthorizationResponse(new TextEncoder().encode(JSON.stringify({
    decision: "allow",
    credential_id: decision.credentialId,
    lease_id: decision.leaseId,
    expires_at: new Date(decision.expiresAtUnixSeconds * 1000).toISOString(),
    expected_peer_endpoint_instance_id: decision.expectedPeerEndpointInstanceId,
    allow_replacement: decision.allowReplacement,
  })), decision);
}

export function rejectRuntime(reason: string, retryable: boolean): AuthorizationResponse<DirectDenyDecision> {
  if (!REASON.test(reason) || reason.length > 64) throw invalidInput();
  const decision: DirectAuthorizationDecision = { decision: retryable ? "retry" : "reject", reason };
  return new AuthorizationResponse(new TextEncoder().encode(JSON.stringify(decision)), decision);
}

export function rejectTunnelRuntime(reason: string, retryable: boolean): TunnelAuthorizationResponse<TunnelDenyDecision> {
  if (!REASON.test(reason) || reason.length > 64) throw invalidInput();
  const decision: TunnelAuthorizationDecision = { decision: retryable ? "retry" : "reject", reason };
  return new TunnelAuthorizationResponse(new TextEncoder().encode(JSON.stringify(decision)), decision);
}

export function parseAuthorizationRecord(encoded: string | Uint8Array): AuthorizationRecord { return AuthorizationRecord.parse(encoded); }
export function parseRuntimeAuthorizationRequest(encoded: string | Uint8Array): RuntimeAuthorizationRequest { return RuntimeAuthorizationRequest.parse(encoded); }

function sessionWire(session: SessionContractV2): Record<string, unknown> {
  return {
    channel_id: session.channel_id, init_expire_at_unix_seconds: session.init_expire_at_unix_s,
    idle_timeout_seconds: session.idle_timeout_seconds, establish_timeout_seconds: session.establish_timeout_seconds,
    rekey_prepare_timeout_seconds: session.rekey_prepare_timeout_seconds,
    rekey_completion_timeout_seconds: session.rekey_completion_timeout_seconds,
    max_inbound_streams: session.max_inbound_streams, e2ee_psk_base64url: session.e2ee_psk_b64u,
    allowed_suites: session.allowed_suites, default_suite: session.default_suite, selected_features: session.selected_features,
  };
}

function metadataScopes(metadata?: ArtifactMetadata): ArtifactV2["scoped"] {
  return (metadata?.scopes ?? []).map((scope) => ({ scope: scope.name, scope_version: scope.version, critical: scope.critical, payload: scope.payload }));
}
function metadataCorrelation(metadata?: ArtifactMetadata): ArtifactV2["correlation"] {
  const tags = Object.entries(metadata?.correlationTags ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }));
  return { v: 2, tags };
}
function validID(value: string): boolean { return /^[A-Za-z0-9._~-]{1,128}$/u.test(value); }
function validTCPAddress(value: string): boolean {
  if (value.length === 0 || /[\s/]/u.test(value)) return false;
  let host: string;
  let portText: string;
  if (value.startsWith("[")) {
    const closing = value.indexOf("]");
    if (closing < 2 || value[closing + 1] !== ":") return false;
    host = value.slice(1, closing);
    portText = value.slice(closing + 2);
  } else {
    const separator = value.lastIndexOf(":");
    if (separator <= 0 || value.indexOf(":") !== separator) return false;
    host = value.slice(0, separator);
    portText = value.slice(separator + 1);
  }
  if (host.length === 0 || !/^\d{1,5}$/u.test(portText)) return false;
  const port = Number(portText);
  return port >= 1 && port <= 65_535;
}
function validObservedText(value: string): boolean { return value.length > 0 && value.length <= 512 && !/[\u0000-\u001f\u007f]/u.test(value); }
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
function strictObject(bytes: Uint8Array): Record<string, any> {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw invalidInput(); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw invalidInput();
  return value as Record<string, any>;
}
function assertExactKeys(value: Record<string, unknown>, allowed: readonly string[], optional: readonly string[] = []): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) if (!allowedSet.has(key)) throw invalidInput();
  for (const key of allowed) if (!optional.includes(key) && !(key in value)) throw invalidInput();
}
function invalidInput(): ControlPlaneError { return new ControlPlaneError("invalid_input"); }
function issuanceFailed(): ControlPlaneError { return new ControlPlaneError("issuance_failed"); }
