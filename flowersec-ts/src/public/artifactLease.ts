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

  private constructor() {
    Object.freeze(this);
  }

  /** @internal */
  static create(): ArtifactLease {
    return new ArtifactLease();
  }
}

type ArtifactLeaseState = {
  readonly artifact: Artifact;
  state: "idle" | "spending" | "consumed";
  readonly commitSpend: (signal?: AbortSignal) => Promise<void>;
};

const artifactLeaseStates = new WeakMap<ArtifactLease, ArtifactLeaseState>();

export function createArtifactLease(
  artifact: Artifact,
  commitSpend: (signal?: AbortSignal) => Promise<void>,
): ArtifactLease {
  validateArtifactV2(unwrapArtifact(artifact));
  const lease = ArtifactLease.create();
  artifactLeaseStates.set(lease, { artifact, state: "idle", commitSpend });
  return lease;
}

/** @internal Connector-owned access to validated lease material. */
export function artifactLeaseArtifact(lease: ArtifactLease): Artifact {
  const leaseState = artifactLeaseStates.get(lease);
  if (leaseState === undefined) throw new ArtifactLeaseError();
  return leaseState.artifact;
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
