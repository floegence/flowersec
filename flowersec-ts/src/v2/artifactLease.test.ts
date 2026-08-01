import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  createArtifactAcquireContextV2,
  createArtifactLeaseV2,
  createArtifactV2Resolver,
  type ArtifactLeaseError,
  type ArtifactLeaseV2,
  type ArtifactSourceV2,
} from "./artifactLease.js";
import { parseArtifact, unwrapArtifact } from "./opaqueArtifact.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const rawArtifact = fixture.positive[0]!.artifact_json;
const artifact = parseArtifact(rawArtifact);

describe("ArtifactV2 acquisition and durable spend leases", () => {
  test("decodes serialized acquisition results into a consumable lease", async () => {
    const spends: AbortSignal[] = [];
    const controller = new AbortController();
    const lease = createArtifactLeaseV2(artifact, async (signal) => {
      if (signal !== undefined) spends.push(signal);
    });

    expect(Object.keys(lease.artifact)).toEqual([]);
    expect(JSON.stringify(lease.artifact)).toBe("{}");
    expect(unwrapArtifact(lease.artifact).profile).toBe("flowersec/2");
    await lease.commitSpend(controller.signal);
    expect(spends).toEqual([controller.signal]);
  });

  test("authorizes exactly one concurrent durable spend and rejects later reuse", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let calls = 0;
    const lease = createArtifactLeaseV2(artifact, async () => {
      calls++;
      await gate;
    });

    const first = lease.commitSpend();
    const second = lease.commitSpend();
    await expect(second).rejects.toMatchObject({
      name: "ArtifactLeaseError",
      code: "already_consumed",
    } satisfies Partial<ArtifactLeaseError>);
    release();
    await expect(first).resolves.toBeUndefined();
    await expect(lease.commitSpend()).rejects.toMatchObject({ code: "already_consumed" });
    expect(calls).toBe(1);
  });

  test("allows durable spend retry after the callback fails", async () => {
    let calls = 0;
    const lease = createArtifactLeaseV2(artifact, async () => {
      calls++;
      if (calls === 1) throw new Error("durability failed");
    });

    await expect(lease.commitSpend()).rejects.toThrow("durability failed");
    await expect(lease.commitSpend()).resolves.toBeUndefined();
    expect(calls).toBe(2);
  });

  test("consumes one-time sources once and refreshable sources for each acquisition", async () => {
    const oneTime: ArtifactSourceV2 = {
      kind: "once",
      artifact,
      commitSpend: async () => undefined,
    };
    const resolveOnce = createArtifactV2Resolver(oneTime);
    await expect(resolveOnce(createArtifactAcquireContextV2(
      { traceId: "trace-1" },
    ))).resolves.toMatchObject({ artifact: {} });
    await expect(resolveOnce(createArtifactAcquireContextV2())).rejects.toThrow("already been consumed");

    const acquired: unknown[] = [];
    const refreshable: ArtifactSourceV2 = {
      kind: "refreshable",
      acquire: async (context): Promise<ArtifactLeaseV2> => {
        acquired.push(context);
        return createArtifactLeaseV2(artifact, async () => undefined);
      },
    };
    const resolveRefreshable = createArtifactV2Resolver(refreshable);
    await resolveRefreshable(createArtifactAcquireContextV2({ traceId: "trace-a" }));
    expect(acquired).toEqual([expect.objectContaining({
      traceId: "trace-a",
    })]);
  });

  test("keeps acquisition context focused on request metadata", () => {
    const signal = new AbortController().signal;
    expect(createArtifactAcquireContextV2({ traceId: "trace-a", signal })).toEqual({
      traceId: "trace-a",
      signal,
    });
  });
});
