import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  createArtifactLeaseV2,
  commitArtifactLeaseSpendV2,
  type ArtifactLeaseError,
} from "./artifactLease.js";
import { parseArtifact } from "./opaqueArtifact.js";

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

    expect(Object.prototype.hasOwnProperty.call(lease, "artifact")).toBe(false);
    expect(JSON.stringify(lease)).toBe("{}");
    await commitArtifactLeaseSpendV2(lease, controller.signal);
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

    const first = commitArtifactLeaseSpendV2(lease);
    const second = commitArtifactLeaseSpendV2(lease);
    await expect(second).rejects.toMatchObject({
      name: "ArtifactLeaseError",
      code: "already_consumed",
    } satisfies Partial<ArtifactLeaseError>);
    release();
    await expect(first).resolves.toBeUndefined();
    await expect(commitArtifactLeaseSpendV2(lease)).rejects.toMatchObject({ code: "already_consumed" });
    expect(calls).toBe(1);
  });

  test("burns the lease after the durable spend callback fails", async () => {
    let calls = 0;
    const lease = createArtifactLeaseV2(artifact, async () => {
      calls++;
      if (calls === 1) throw new Error("durability failed");
    });

    await expect(commitArtifactLeaseSpendV2(lease)).rejects.toThrow("durability failed");
    await expect(commitArtifactLeaseSpendV2(lease)).rejects.toMatchObject({ code: "already_consumed" });
    expect(calls).toBe(1);
  });

  test("burns the lease after spend cancellation", async () => {
    let calls = 0;
    const controller = new AbortController();
    controller.abort();
    const lease = createArtifactLeaseV2(artifact, async (signal) => {
      calls++;
      if (signal?.aborted === true) throw new DOMException("aborted", "AbortError");
    });

    await expect(commitArtifactLeaseSpendV2(lease, controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    await expect(commitArtifactLeaseSpendV2(lease)).rejects.toMatchObject({ code: "already_consumed" });
    expect(calls).toBe(1);
  });
});
