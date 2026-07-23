import { decodeArtifactV2JSON, type ArtifactV2 } from "./artifact.js";

const artifactValues = new WeakMap<Artifact, ArtifactV2>();

export class Artifact {
  declare private readonly artifactBrand: void;
  private constructor() {}
}

export function parseArtifact(input: string | Uint8Array): Artifact {
  return wrapArtifact(decodeArtifactV2JSON(input));
}

export function wrapArtifact(value: ArtifactV2): Artifact {
  const artifact = new (Artifact as unknown as { new(): Artifact })();
  artifactValues.set(artifact, value);
  return Object.freeze(artifact) as Artifact;
}

export function unwrapArtifact(artifact: Artifact): ArtifactV2 {
  const value = artifactValues.get(artifact);
  if (value === undefined) throw new TypeError("invalid Flowersec artifact handle");
  return value;
}
