import { validateArtifactV2 } from "./artifact.js";
import { unwrapArtifact, type Artifact } from "./opaqueArtifact.js";

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

function validateArtifact(artifact: Artifact): Artifact {
  validateArtifactV2(unwrapArtifact(artifact));
  return artifact;
}
