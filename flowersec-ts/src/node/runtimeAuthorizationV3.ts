import { createHash, timingSafeEqual } from "node:crypto";

import {
  buildFSB3RequestV3,
  encodeFSB3RequestV3,
  type DecodedFSB3RequestV3,
} from "../v3/artifact.js";
import {
  unwrapArtifactHandleV3,
  type ArtifactHandleV3,
} from "../v3/publicApi.js";

const ID = /^[A-Za-z0-9._~-]{1,128}$/u;

type RuntimeAuthorizationRequestStateV3 = Readonly<{
  lookupKey: string;
  decoded: DecodedFSB3RequestV3;
  requestDigest: Uint8Array;
}>;

const requests = new WeakMap<RuntimeAuthorizationRequestV3, RuntimeAuthorizationRequestStateV3>();

/** Opaque, secret-free authorization lookup for one observed FSB3 request. */
export class RuntimeAuthorizationRequestV3 {
  readonly #lookupKey: string;

  private constructor(lookupKey: string) {
    this.#lookupKey = lookupKey;
  }

  /** Returns the non-secret credential digest used to locate authorization state. */
  lookupKey(): string { return this.#lookupKey; }

  /** Check the complete Direct request against a host record before consuming it. */
  matchesDirectArtifact(handle: ArtifactHandleV3): boolean {
    const observed = requests.get(this);
    const artifact = unwrapArtifactHandleV3(handle);
    if (observed?.decoded.request.pathKind !== "direct" || artifact.path.kind !== "direct" ||
        artifact.session.init_expire_at_unix_s <= Math.floor(Date.now() / 1_000)) return false;
    const chosen = observed.decoded.request.chosen_candidate_id;
    if (!artifact.path.candidates.some(candidate => candidate.id === chosen)) return false;
    const expected = encodeFSB3RequestV3(buildFSB3RequestV3(artifact, chosen));
    return constantTimeEqual(expected, observed.decoded.raw);
  }

  toString(): string { return "Flowersec.RuntimeAuthorizationRequestV3"; }

  toJSON(): Readonly<Record<string, never>> { return Object.freeze({}); }

  /** @internal */
  static fromDecoded(decoded: DecodedFSB3RequestV3): RuntimeAuthorizationRequestV3 {
    const credential = decoded.request.pathKind === "direct"
      ? decoded.request.routing_token
      : decoded.request.attach_token;
    const lookupKey = createHash("sha256").update(credential, "utf8").digest("base64url");
    const request = new RuntimeAuthorizationRequestV3(lookupKey);
    requests.set(request, Object.freeze({
      lookupKey,
      decoded,
      requestDigest: createHash("sha256").update(decoded.raw).digest(),
    }));
    Object.freeze(request);
    return request;
  }
}

/**
 * Opaque, secret-free proof that a tunnel authorization record exactly matched
 * one observed FSB3 request.
 */
export class TunnelAuthorizationGrantV3 {
  declare private readonly tunnelAuthorizationGrantBrand: void;
  private constructor() {}

  toString(): string { return "Flowersec.TunnelAuthorizationGrantV3"; }

  toJSON(): Readonly<Record<string, never>> { return Object.freeze({}); }
}

export type TunnelAuthorizationGrantOptionsV3 = Readonly<{
  leaseId: string;
  allowReplacement?: boolean;
}>;

/** An authority-produced record for a relay; it contains no token or session key. */
export type TunnelVerificationRecord = Readonly<{
  authorityScope: string;
  credentialId: string;
  expiresAtUnixSeconds: number;
  expectedPeerEndpointInstanceId: string;
  requestDigests: Readonly<Record<string, string>>;
}>;

/** Run at the issuing authority. Provision the result over a trusted channel. */
export function createTunnelVerificationRecord(handle: ArtifactHandleV3, authorityScope: string): TunnelVerificationRecord {
  const artifact = unwrapArtifactHandleV3(handle);
  if (artifact.path.kind !== "tunnel" || !ID.test(authorityScope)) throw invalidAuthorization();
  const requestDigests = Object.create(null) as Record<string, string>;
  for (const candidate of artifact.path.candidates) {
    const raw = encodeFSB3RequestV3(buildFSB3RequestV3(artifact, candidate.id));
    requestDigests[candidate.id] = createHash("sha256").update(raw).digest("base64url");
  }
  return Object.freeze({ authorityScope, requestDigests: Object.freeze(requestDigests),
    credentialId: createHash("sha256").update(artifact.path.token).digest("base64url"),
    expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
    expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id });
}

/** @internal */
export type TunnelAuthorizationGrantClaimsV3 = Readonly<{
  authorityScope: string;
  requestDigest: Uint8Array;
  credentialId: string;
  leaseId: string;
  expiresAtUnixSeconds: number;
  expectedPeerEndpointInstanceId: string;
  allowReplacement: boolean;
}>;

type TunnelAuthorizationGrantRecordV3 = {
  readonly claims: TunnelAuthorizationGrantClaimsV3;
  consumed: boolean;
};

const grants = new WeakMap<TunnelAuthorizationGrantV3, TunnelAuthorizationGrantRecordV3>();

/**
 * Verifies a trusted authorization artifact against the complete observed FSB3
 * and mints a request-bound grant that contains no artifact secrets.
 */
export function verifyTunnelAuthorizationGrantV3(
  request: RuntimeAuthorizationRequestV3,
  record: TunnelVerificationRecord,
  options: TunnelAuthorizationGrantOptionsV3,
): TunnelAuthorizationGrantV3 {
  const observed = requests.get(request);
  if (observed === undefined || typeof options !== "object" || options === null ||
    !ID.test(options.leaseId) ||
    (options.allowReplacement !== undefined && typeof options.allowReplacement !== "boolean")) {
    throw invalidAuthorization();
  }
  try {
    const received = observed.decoded.request;
    if (received.pathKind !== "tunnel" || typeof record.authorityScope !== "string" || !ID.test(record.authorityScope) ||
      record.credentialId !== observed.lookupKey || !Number.isSafeInteger(record.expiresAtUnixSeconds) ||
      record.expiresAtUnixSeconds <= Math.floor(Date.now() / 1_000) || typeof record.expectedPeerEndpointInstanceId !== "string" ||
      !ID.test(record.expectedPeerEndpointInstanceId) || record.expectedPeerEndpointInstanceId === received.endpoint_instance_id ||
      !Object.hasOwn(record.requestDigests, received.chosen_candidate_id)) {
      throw invalidAuthorization();
    }
    const expected = record.requestDigests[received.chosen_candidate_id];
    if (typeof expected !== "string" || expected !== Buffer.from(observed.requestDigest).toString("base64url")) throw invalidAuthorization();
    const grant = new (TunnelAuthorizationGrantV3 as unknown as {
      new(): TunnelAuthorizationGrantV3;
    })();
    grants.set(grant, {
      claims: Object.freeze({
        authorityScope: record.authorityScope,
        requestDigest: observed.requestDigest.slice(),
        credentialId: observed.lookupKey,
        leaseId: options.leaseId,
        expiresAtUnixSeconds: record.expiresAtUnixSeconds,
        expectedPeerEndpointInstanceId: record.expectedPeerEndpointInstanceId,
        allowReplacement: options.allowReplacement === true,
      }),
      consumed: false,
    });
    return Object.freeze(grant) as TunnelAuthorizationGrantV3;
  } catch (error) {
    if (error instanceof TypeError && error.message === "invalid Flowersec tunnel authorization") {
      throw error;
    }
    throw invalidAuthorization();
  }
}

/** @internal */
export function inspectTunnelAuthorizationGrantV3(
  grant: TunnelAuthorizationGrantV3,
): TunnelAuthorizationGrantClaimsV3 | undefined {
  return grants.get(grant)?.claims;
}

/** @internal */
export function validateTunnelAuthorizationGrantV3(
  grant: TunnelAuthorizationGrantV3,
  request: RuntimeAuthorizationRequestV3,
): TunnelAuthorizationGrantClaimsV3 | undefined {
  const record = grants.get(grant);
  const claims = record?.claims;
  const observed = requests.get(request);
  if (record?.consumed !== false || claims === undefined || observed === undefined ||
    claims.credentialId !== observed.lookupKey ||
    !constantTimeEqual(claims.requestDigest, observed.requestDigest)) return undefined;
  return claims;
}

/** @internal */
export function consumeTunnelAuthorizationGrantV3(
  grant: TunnelAuthorizationGrantV3,
  request: RuntimeAuthorizationRequestV3,
): TunnelAuthorizationGrantClaimsV3 | undefined {
  const claims = validateTunnelAuthorizationGrantV3(grant, request);
  const record = grants.get(grant);
  if (claims === undefined || record === undefined) return undefined;
  record.consumed = true;
  return claims;
}

/** @internal */
export function retireTunnelAuthorizationGrantV3(
  grant: TunnelAuthorizationGrantV3,
): TunnelAuthorizationGrantClaimsV3 | undefined {
  const record = grants.get(grant);
  if (record === undefined || record.consumed) return undefined;
  record.consumed = true;
  return record.claims;
}

/** @internal */
export function runtimeAuthorizationRequestV3FromDecoded(
  decoded: DecodedFSB3RequestV3,
): RuntimeAuthorizationRequestV3 {
  return RuntimeAuthorizationRequestV3.fromDecoded(decoded);
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

function invalidAuthorization(): TypeError {
  return new TypeError("invalid Flowersec tunnel authorization");
}
