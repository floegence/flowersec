import { validateArtifactV2 } from "./artifact.js";
import { parseArtifact, unwrapArtifact, type Artifact } from "./opaqueArtifact.js";
import {
  runtimeCapabilityDigestHexV2,
  validateRuntimeCapabilityDescriptorV2,
  type RuntimeCapabilityDescriptorV2,
} from "./capability.js";

export type ArtifactVersionPolicyV2 = Readonly<{
  artifactVersions: readonly [2];
  sessionProfiles: readonly ["flowersec/2"];
}>;

export const TRANSPORT_V2_VERSION_POLICY: ArtifactVersionPolicyV2 = Object.freeze({
  artifactVersions: Object.freeze([2]) as readonly [2],
  sessionProfiles: Object.freeze(["flowersec/2"]) as readonly ["flowersec/2"],
});

export type ArtifactAcquireContextV2 = Readonly<{
  traceId?: string;
  signal?: AbortSignal;
  versionPolicy: ArtifactVersionPolicyV2;
  capability: RuntimeCapabilityDescriptorV2;
  capabilityDigestHex: string;
}>;

export type ArtifactAcquireContextOptionsV2 = Readonly<{
  traceId?: string;
  signal?: AbortSignal;
  versionPolicy?: ArtifactVersionPolicyV2;
}>;

export type ArtifactInputV2 = Artifact | string | Uint8Array;

export type ArtifactLeaseV2 = Readonly<{
  artifact: Artifact;
  commitSpend(signal?: AbortSignal): Promise<void>;
}>;

export type ArtifactSourceV2 =
  | Readonly<{
    kind: "once";
    artifact: ArtifactInputV2;
    commitSpend(signal?: AbortSignal): Promise<void>;
  }>
  | Readonly<{
    kind: "refreshable";
    acquire(context: ArtifactAcquireContextV2): Promise<ArtifactLeaseV2>;
  }>;

export type ArtifactDecoderV2 = (input: string | Uint8Array) => Artifact;

export function createArtifactAcquireContextV2(
  capability: RuntimeCapabilityDescriptorV2,
  options: ArtifactAcquireContextOptionsV2 = {},
): ArtifactAcquireContextV2 {
  validateRuntimeCapabilityDescriptorV2(capability);
  const context: ArtifactAcquireContextV2 = {
    ...(options.traceId === undefined ? {} : { traceId: options.traceId }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    versionPolicy: options.versionPolicy ?? TRANSPORT_V2_VERSION_POLICY,
    capability,
    capabilityDigestHex: runtimeCapabilityDigestHexV2(capability),
  };
  validateAcquireContext(context);
  return Object.freeze(context);
}

export function createArtifactLeaseV2(
  input: ArtifactInputV2,
  commitSpend: (signal?: AbortSignal) => Promise<void>,
  decode: ArtifactDecoderV2 = parseArtifact,
): ArtifactLeaseV2 {
  const artifact = typeof input === "string" || input instanceof Uint8Array
    ? decode(input)
    : validateArtifact(input);
  return Object.freeze({ artifact, commitSpend });
}

export function createArtifactV2Resolver(
  source: ArtifactSourceV2,
  decode: ArtifactDecoderV2 = parseArtifact,
): (context: ArtifactAcquireContextV2) => Promise<ArtifactLeaseV2> {
  let consumed = false;
  return async (context) => {
    validateAcquireContext(context);
    throwIfAborted(context.signal);
    if (source.kind === "refreshable") {
      const lease = await source.acquire(context);
      validateArtifact(lease.artifact);
      return lease;
    }
    if (consumed) throw new Error("one-time ArtifactV2 source has already been consumed");
    consumed = true;
    return createArtifactLeaseV2(source.artifact, source.commitSpend, decode);
  };
}

function validateAcquireContext(context: ArtifactAcquireContextV2): void {
  validateRuntimeCapabilityDescriptorV2(context.capability);
  if (context.capabilityDigestHex !== runtimeCapabilityDigestHexV2(context.capability)) {
    throw new TypeError("artifact acquisition capability digest does not match its descriptor");
  }
  if (context.versionPolicy.artifactVersions.length !== 1 || context.versionPolicy.artifactVersions[0] !== 2 ||
      context.versionPolicy.sessionProfiles.length !== 1 || context.versionPolicy.sessionProfiles[0] !== "flowersec/2") {
    throw new TypeError("artifact acquisition version policy must require Transport v2");
  }
  if (context.traceId !== undefined && (context.traceId.length === 0 || context.traceId.length > 128)) {
    throw new TypeError("artifact acquisition traceId must contain 1..128 characters");
  }
}

function validateArtifact(artifact: Artifact): Artifact {
  validateArtifactV2(unwrapArtifact(artifact));
  return artifact;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted !== true) return;
  throw signal.reason instanceof Error ? signal.reason : new Error("artifact acquisition aborted");
}
