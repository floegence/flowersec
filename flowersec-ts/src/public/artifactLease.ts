import { validateArtifactV2 } from "../v2/artifact.js";
import { unwrapArtifact, type Artifact } from "./artifact.js";

export class ArtifactLeaseError extends Error {
  readonly code = "already_consumed";

  constructor() {
    super("Flowersec artifact lease has already been consumed");
    this.name = "ArtifactLeaseError";
  }
}

export class ArtifactLease {
  readonly #artifactLeaseBrand = undefined;
  readonly artifact: Artifact;

  private constructor(artifact: Artifact) {
    this.artifact = artifact;
    Object.freeze(this);
  }

  /** @internal */
  static create(artifact: Artifact): ArtifactLease {
    return new ArtifactLease(artifact);
  }
}

type ArtifactLeaseState = {
  state: "idle" | "spending" | "consumed";
  readonly commitSpend: (signal?: AbortSignal) => Promise<void>;
};

const artifactLeaseStates = new WeakMap<ArtifactLease, ArtifactLeaseState>();

export function createArtifactLease(
  artifact: Artifact,
  commitSpend: (signal?: AbortSignal) => Promise<void>,
): ArtifactLease {
  validateArtifactV2(unwrapArtifact(artifact));
  const lease = ArtifactLease.create(artifact);
  artifactLeaseStates.set(lease, { state: "idle", commitSpend });
  return lease;
}

/** @internal Connector-owned durable spend transition. */
export async function commitArtifactLeaseSpend(
  lease: ArtifactLease,
  signal?: AbortSignal,
): Promise<void> {
  const leaseState = artifactLeaseStates.get(lease);
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
