import { validateArtifactV2 } from "./artifact.js";
import { unwrapArtifact, type Artifact } from "./opaqueArtifact.js";

export type ArtifactAcquireContextV2 = Readonly<{
  traceId?: string;
  signal?: AbortSignal;
}>;

export type ArtifactAcquireContextOptionsV2 = Readonly<{
  traceId?: string;
  signal?: AbortSignal;
}>;

export class ArtifactLeaseError extends Error {
  readonly code = "already_consumed";

  constructor() {
    super("Flowersec artifact lease has already been consumed");
    this.name = "ArtifactLeaseError";
  }
}

class ArtifactLeaseV2Value {
  readonly #artifactLeaseBrand = undefined;
  readonly artifact: Artifact;

  constructor(artifact: Artifact) {
    this.artifact = artifact;
    Object.freeze(this);
  }
}

export type ArtifactLeaseV2 = ArtifactLeaseV2Value;

type ArtifactLeaseStateV2 = {
  state: "idle" | "spending" | "consumed";
  readonly commitSpend: (signal?: AbortSignal) => Promise<void>;
};

const artifactLeaseStatesV2 = new WeakMap<ArtifactLeaseV2, ArtifactLeaseStateV2>();

export type ArtifactSourceV2 =
  | Readonly<{
    kind: "once";
    artifact: Artifact;
    commitSpend(signal?: AbortSignal): Promise<void>;
  }>
  | Readonly<{
    kind: "refreshable";
    acquire(context: ArtifactAcquireContextV2): Promise<ArtifactLeaseV2>;
  }>;

export function createArtifactAcquireContextV2(
  options: ArtifactAcquireContextOptionsV2 = {},
): ArtifactAcquireContextV2 {
  const context: ArtifactAcquireContextV2 = {
    ...(options.traceId === undefined ? {} : { traceId: options.traceId }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
  validateAcquireContext(context);
  return Object.freeze(context);
}

export function createArtifactLeaseV2(
  artifact: Artifact,
  commitSpend: (signal?: AbortSignal) => Promise<void>,
): ArtifactLeaseV2 {
  const validated = validateArtifact(artifact);
  const lease = new ArtifactLeaseV2Value(validated);
  artifactLeaseStatesV2.set(lease, { state: "idle", commitSpend });
  return lease;
}

/** @internal Connector-owned durable spend transition. */
export async function commitArtifactLeaseSpendV2(
  lease: ArtifactLeaseV2,
  signal?: AbortSignal,
): Promise<void> {
  const leaseState = artifactLeaseStatesV2.get(lease);
  if (leaseState === undefined || leaseState.state !== "idle") throw new ArtifactLeaseError();
  leaseState.state = "spending";
  try {
    await leaseState.commitSpend(signal);
    leaseState.state = "consumed";
  } catch (error) {
    leaseState.state = "idle";
    throw error;
  }
}

export function createArtifactV2Resolver(
  source: ArtifactSourceV2,
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
    return createArtifactLeaseV2(source.artifact, source.commitSpend);
  };
}

function validateAcquireContext(context: ArtifactAcquireContextV2): void {
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
