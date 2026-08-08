import type { ArtifactLease } from "../public/artifactLease.js";
import { commitArtifactLeaseSpend, createArtifactLease } from "../public/artifactLease.js";

/** @internal */
export { ArtifactLease, ArtifactLeaseError, createArtifactLease } from "../public/artifactLease.js";

/** @internal */
export type ArtifactLeaseV2 = ArtifactLease;

/** @internal */
export const createArtifactLeaseV2 = createArtifactLease;

/** @internal */
export const commitArtifactLeaseSpendV2 = commitArtifactLeaseSpend;
