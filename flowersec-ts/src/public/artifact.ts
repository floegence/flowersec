import { ArtifactV2Error, decodeArtifactV2JSON, type ArtifactV2 } from "../v2/artifact.js";

const artifactValues = new WeakMap<Artifact, ArtifactV2>();

export class Artifact {
  declare private readonly artifactBrand: void;
  private constructor() {}
}

export type ArtifactErrorCode = "artifact_too_large" | "invalid_artifact" | "invalid_candidate";

/** A stable, redacted failure returned while parsing an opaque artifact. */
export class ArtifactError extends Error {
  constructor(readonly code: ArtifactErrorCode) {
    super(`Flowersec artifact parsing failed (code=${code})`);
    this.name = "ArtifactError";
  }
}

export function parseArtifact(input: string | Uint8Array): Artifact {
  try {
    return wrapArtifact(decodeArtifactV2JSON(input));
  } catch (error) {
    if (error instanceof ArtifactV2Error) {
      switch (error.code) {
        case "artifact_too_large":
        case "invalid_candidate":
          throw new ArtifactError(error.code);
        default:
          throw new ArtifactError("invalid_artifact");
      }
    }
    throw new ArtifactError("invalid_artifact");
  }
}

/** @internal */
export function wrapArtifact(value: ArtifactV2): Artifact {
  const artifact = new (Artifact as unknown as { new(): Artifact })();
  artifactValues.set(artifact, value);
  return Object.freeze(artifact) as Artifact;
}

/** @internal */
export function unwrapArtifact(artifact: Artifact): ArtifactV2 {
  const value = artifactValues.get(artifact);
  if (value === undefined) throw new TypeError("invalid Flowersec artifact handle");
  return value;
}
