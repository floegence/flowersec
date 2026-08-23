import { describe, expect, test } from "vitest";

import { createStreamMetadataV2, StreamMetadataError } from "./streamMetadata.js";

describe("public stream metadata", () => {
  test("validates once and returns defensive readonly snapshots", () => {
    const nested = { accepted: true };
    const source = { purpose: "health", attempt: 1, nested };
    const metadata = createStreamMetadataV2(source);

    source.purpose = "mutated";
    nested.accepted = false;
    expect(metadata.values).toEqual({ purpose: "health", attempt: 1, nested: { accepted: true } });

    const snapshot = metadata.values as { purpose: string };
    expect(() => { snapshot.purpose = "changed"; }).toThrow();
    expect(metadata.values).toEqual({ purpose: "health", attempt: 1, nested: { accepted: true } });
  });

  test("rejects values that cannot enter the shared OPEN contract", () => {
    expect(() => createStreamMetadataV2({ fraction: 1.5 })).toThrow(StreamMetadataError);
    expect(() => createStreamMetadataV2({ unsafe: 9_007_199_254_740_992 })).toThrow(StreamMetadataError);
    expect(() => createStreamMetadataV2({ negative_zero: -0 })).toThrow(StreamMetadataError);
    expect(() => createStreamMetadataV2({ value: "a".repeat(513) })).toThrow(StreamMetadataError);
  });

  test("reads dynamic properties once while creating the canonical snapshot", () => {
    let reads = 0;
    const source = Object.defineProperty({}, "value", {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? 1 : Number.MAX_SAFE_INTEGER + 1;
      },
    });

    const metadata = createStreamMetadataV2(source);

    expect(metadata.values).toEqual({ value: 1 });
    expect(reads).toBe(1);
  });
});
