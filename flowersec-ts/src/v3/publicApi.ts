import {
  ArtifactV3Error,
  decodeArtifactV3JSON,
  validateArtifactV3,
  type ArtifactV3,
} from "./artifact.js";
import {
  createArtifactLeaseV3Internal,
  type ArtifactLeaseV3,
} from "./artifactLease.js";

const artifacts = new WeakMap<ArtifactHandleV3, ArtifactV3>();

export class ArtifactHandleV3 {
  declare private readonly artifactHandleBrand: void;
  private constructor() {}
}

export type ArtifactParseErrorCodeV3 = "artifact_too_large" | "invalid_artifact";

export class ArtifactParseErrorV3 extends Error {
  constructor(readonly code: ArtifactParseErrorCodeV3) {
    super(`Flowersec v3 artifact parsing failed (code=${code})`);
    this.name = "ArtifactError";
  }
}

export function parseArtifactV3(input: string | Uint8Array): ArtifactHandleV3 {
  try {
    const value = decodeArtifactV3JSON(input);
    const handle = new (ArtifactHandleV3 as unknown as { new(): ArtifactHandleV3 })();
    artifacts.set(handle, value);
    return Object.freeze(handle) as ArtifactHandleV3;
  } catch (error) {
    throw new ArtifactParseErrorV3(
      error instanceof ArtifactV3Error && error.code === "artifact_too_large"
        ? "artifact_too_large"
        : "invalid_artifact",
    );
  }
}

export function createArtifactLeaseV3(
  artifact: ArtifactHandleV3,
  commitSpend: (signal?: AbortSignal) => Promise<void>,
  retireCleanup?: () => Promise<void>,
): ArtifactLeaseV3 {
  const value = artifacts.get(artifact);
  if (value === undefined) throw new ArtifactParseErrorV3("invalid_artifact");
  try {
    validateArtifactV3(value);
    return createArtifactLeaseV3Internal(value, commitSpend, retireCleanup);
  } catch {
    throw new ArtifactParseErrorV3("invalid_artifact");
  }
}

/** @internal */
export function unwrapArtifactHandleV3(handle: ArtifactHandleV3): ArtifactV3 {
  const value = artifacts.get(handle);
  if (value === undefined) throw new ArtifactParseErrorV3("invalid_artifact");
  return value;
}
