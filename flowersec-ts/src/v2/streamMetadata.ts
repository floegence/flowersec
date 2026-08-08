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
export type StreamMetadataV2 = StreamMetadata;

/** @internal */
export const createStreamMetadataV2 = createStreamMetadata;

/** @internal */
export const streamMetadataValuesV2 = streamMetadataValues;
