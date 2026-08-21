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

/** @internal */
export type TunnelAuthorizationGrantClaimsV3 = Readonly<{
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
  artifactHandle: ArtifactHandleV3,
  options: TunnelAuthorizationGrantOptionsV3,
): TunnelAuthorizationGrantV3 {
  const observed = requests.get(request);
  if (observed === undefined || typeof options !== "object" || options === null ||
    !ID.test(options.leaseId) ||
    (options.allowReplacement !== undefined && typeof options.allowReplacement !== "boolean")) {
    throw invalidAuthorization();
  }
  try {
    const artifact = unwrapArtifactHandleV3(artifactHandle);
    const received = observed.decoded.request;
    if (artifact.path.kind !== "tunnel" || received.pathKind !== "tunnel" ||
      artifact.session.init_expire_at_unix_s <= Math.floor(Date.now() / 1_000) ||
      artifact.path.expected_peer_endpoint_instance_id === received.endpoint_instance_id) {
      throw invalidAuthorization();
    }
    const expected = encodeFSB3RequestV3(buildFSB3RequestV3(
      artifact,
      received.chosen_candidate_id,
    ));
    if (!constantTimeEqual(expected, observed.decoded.raw)) throw invalidAuthorization();
    const grant = new (TunnelAuthorizationGrantV3 as unknown as {
      new(): TunnelAuthorizationGrantV3;
    })();
    grants.set(grant, {
      claims: Object.freeze({
        requestDigest: observed.requestDigest.slice(),
        credentialId: observed.lookupKey,
        leaseId: options.leaseId,
        expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
        expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id,
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
