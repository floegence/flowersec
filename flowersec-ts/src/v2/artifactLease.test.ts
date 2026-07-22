import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  TRANSPORT_V2_VERSION_POLICY,
  createArtifactAcquireContextV2,
  createArtifactLeaseV2,
  createArtifactV2Resolver,
  type ArtifactLeaseV2,
  type ArtifactSourceV2,
} from "./artifactLease.js";
import { BROWSER_RUNTIME_CAPABILITY_V2, runtimeCapabilityDigestHexV2 } from "./capability.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const rawArtifact = fixture.positive[0]!.artifact_json;

describe("ArtifactV2 acquisition and durable spend leases", () => {
  test("decodes serialized acquisition results into a consumable lease", async () => {
    const spends: AbortSignal[] = [];
    const controller = new AbortController();
    const lease = createArtifactLeaseV2(rawArtifact, async (signal) => {
      if (signal !== undefined) spends.push(signal);
    });

    expect(lease.artifact.profile).toBe("flowersec/2");
    await lease.commitSpend(controller.signal);
    expect(spends).toEqual([controller.signal]);
  });

  test("consumes one-time sources once and refreshable sources for each acquisition", async () => {
    const oneTime: ArtifactSourceV2 = {
      kind: "once",
      artifact: rawArtifact,
      commitSpend: async () => undefined,
    };
    const resolveOnce = createArtifactV2Resolver(oneTime);
    await expect(resolveOnce(createArtifactAcquireContextV2(
      BROWSER_RUNTIME_CAPABILITY_V2,
      { traceId: "trace-1" },
    ))).resolves.toMatchObject({
      artifact: { v: 2, profile: "flowersec/2" },
    });
    await expect(resolveOnce(createArtifactAcquireContextV2(BROWSER_RUNTIME_CAPABILITY_V2))).rejects.toThrow("already been consumed");

    const acquired: unknown[] = [];
    const refreshable: ArtifactSourceV2 = {
      kind: "refreshable",
      acquire: async (context): Promise<ArtifactLeaseV2> => {
        acquired.push(context);
        return createArtifactLeaseV2(rawArtifact, async () => undefined);
      },
    };
    const resolveRefreshable = createArtifactV2Resolver(refreshable);
    await resolveRefreshable(createArtifactAcquireContextV2(BROWSER_RUNTIME_CAPABILITY_V2, { traceId: "trace-a" }));
    expect(acquired).toEqual([expect.objectContaining({
      traceId: "trace-a",
      versionPolicy: TRANSPORT_V2_VERSION_POLICY,
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      capabilityDigestHex: runtimeCapabilityDigestHexV2(BROWSER_RUNTIME_CAPABILITY_V2),
    })]);
  });

  test("rejects a forged capability digest before invoking the source", async () => {
    let calls = 0;
    const resolve = createArtifactV2Resolver({
      kind: "refreshable",
      acquire: async () => {
        calls++;
        return createArtifactLeaseV2(rawArtifact, async () => undefined);
      },
    });
    const context = {
      ...createArtifactAcquireContextV2(BROWSER_RUNTIME_CAPABILITY_V2),
      capabilityDigestHex: "00".repeat(32),
    };
    await expect(resolve(context)).rejects.toThrow(/digest/i);
    expect(calls).toBe(0);
  });
});
