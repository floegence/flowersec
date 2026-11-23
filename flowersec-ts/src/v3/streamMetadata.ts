import {
  createStreamMetadata,
  streamMetadataValues,
  type StreamMetadata,
} from "../public/streamMetadata.js";

/** @internal */
export { createStreamMetadata, StreamMetadataError } from "../public/streamMetadata.js";
/** @internal */
export type { StreamMetadata } from "../public/streamMetadata.js";

/** @internal */
export type StreamMetadataV3 = StreamMetadata;

/** @internal */
export const createStreamMetadataV3 = createStreamMetadata;

/** @internal */
export const streamMetadataValuesV3 = streamMetadataValues;
