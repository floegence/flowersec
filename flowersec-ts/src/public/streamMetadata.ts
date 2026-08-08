import { canonicalStreamMetadataJSONV2Internal } from "../v2/protocol.js";
import type { JsonObject } from "./contract.js";

export class StreamMetadataError extends Error {
  constructor() {
    super("invalid Flowersec stream metadata");
    this.name = "StreamMetadataError";
  }
}

export class StreamMetadata {
  declare private readonly streamMetadataBrand: void;

  private constructor(readonly values: JsonObject) {
    Object.freeze(this);
  }

  /** @internal */
  static fromCanonicalValues(values: JsonObject): StreamMetadata {
    return new StreamMetadata(values);
  }
}

export function createStreamMetadata(values: JsonObject): StreamMetadata {
  try {
    const canonical = canonicalStreamMetadataJSONV2Internal(values);
    return StreamMetadata.fromCanonicalValues(deepFreeze(JSON.parse(canonical) as JsonObject));
  } catch {
    throw new StreamMetadataError();
  }
}

/** @internal */
export function streamMetadataValues(metadata: StreamMetadata): JsonObject {
  if (!(metadata instanceof StreamMetadata)) throw new StreamMetadataError();
  return metadata.values;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
