import type { JsonObjectV2 } from "./contract.js";
import { canonicalStreamMetadataJSONV2Internal } from "./protocol.js";

export class StreamMetadataError extends Error {
  constructor() {
    super("invalid Flowersec stream metadata");
    this.name = "StreamMetadataError";
  }
}

export class StreamMetadataV2 {
  declare private readonly streamMetadataBrand: void;

  private constructor(readonly values: JsonObjectV2) {
    Object.freeze(this);
  }

  /** @internal */
  static fromCanonicalValues(values: JsonObjectV2): StreamMetadataV2 {
    return new StreamMetadataV2(values);
  }
}

export function createStreamMetadataV2(values: JsonObjectV2): StreamMetadataV2 {
  try {
    const canonical = canonicalStreamMetadataJSONV2Internal(values);
    return StreamMetadataV2.fromCanonicalValues(deepFreeze(JSON.parse(canonical) as JsonObjectV2));
  } catch {
    throw new StreamMetadataError();
  }
}

/** @internal */
export function streamMetadataValuesV2(metadata: StreamMetadataV2): JsonObjectV2 {
  if (!(metadata instanceof StreamMetadataV2)) throw new StreamMetadataError();
  return metadata.values;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
