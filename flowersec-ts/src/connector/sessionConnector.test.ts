import { describe, expect, test, vi } from "vitest";

import type { ArtifactV2, CanonicalArtifactCandidateV2 } from "../v2/artifact.js";
import {
  composeCandidateAttemptFactoryV2,
  type CandidateAttemptFactoryV2,
} from "./sessionConnector.js";

describe("neutral session connector candidate composition", () => {
  test("routes each carrier to its runtime-owned factory", () => {
    const candidate = {
      carrier: "webtransport",
      id: "t1",
      normalized_url: "https://example.test/flowersec/webtransport/v2/direct",
      wire_profile: "native-quic-v2",
    } as CanonicalArtifactCandidateV2;
    const artifact = {} as ArtifactV2;
    const attempt = { candidate, ready: vi.fn(), abort: vi.fn() };
    const create = vi.fn(() => attempt);
    const factory = composeCandidateAttemptFactoryV2({
      webtransport: { create } satisfies CandidateAttemptFactoryV2,
    });

    expect(factory.create(candidate, artifact)).toBe(attempt);
    expect(create).toHaveBeenCalledWith(candidate, artifact);
  });

  test("fails closed when the runtime does not implement a carrier", () => {
    const candidate = { carrier: "raw_quic" } as CanonicalArtifactCandidateV2;
    expect(() => composeCandidateAttemptFactoryV2({}).create(candidate, {} as ArtifactV2))
      .toThrow("runtime does not implement raw_quic");
  });
});
