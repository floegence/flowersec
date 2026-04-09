import { beforeAll, describe, expect, test } from "vitest";

import {
  ensureBuiltDist,
  makeDirectArtifactEnvelope,
  makeTunnelArtifactEnvelope,
  runNodeDemoScript,
  startDirectDemo,
  startGoHarness,
} from "./demoTestUtils.js";

const demoOrigin = "https://app.redeven.com";

describe("example node demo scripts", () => {
  beforeAll(() => {
    ensureBuiltDist();
  });

  test("artifact-first tunnel demos run against the Go harness", { timeout: 180000 }, async () => {
    const harness = await startGoHarness();
    try {
      const simpleTunnelEnvelope = JSON.stringify(makeTunnelArtifactEnvelope(harness.ready.grant_client));

      const artifactClientOut = runNodeDemoScript("node-artifact-client.mjs", {
        env: {
          FSEC_CONTROLPLANE_BASE_URL: harness.ready.controlplane_base_url,
          FSEC_ORIGIN: demoOrigin,
        },
      });
      expect(artifactClientOut).toBe("ok\n");

      const simpleOut = runNodeDemoScript("node-tunnel-client.mjs", {
        input: simpleTunnelEnvelope,
        env: { FSEC_ORIGIN: demoOrigin },
      });
      expectDemoRPCOutput(simpleOut);

      const advancedArtifactResp = await fetch(new URL("/v1/connect/artifact", harness.ready.controlplane_base_url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ endpoint_id: "server-1" }),
      });
      expect(advancedArtifactResp.ok).toBe(true);
      const advancedTunnelEnvelope = JSON.stringify(await advancedArtifactResp.json());

      const advancedOut = runNodeDemoScript("node-tunnel-client-advanced.mjs", {
        input: advancedTunnelEnvelope,
        env: { FSEC_ORIGIN: demoOrigin },
      });
      expectDemoRPCOutput(advancedOut);
    } finally {
      await harness.stop();
    }
  });

  test("direct demos accept artifact envelopes and stream metadata payloads", { timeout: 180000 }, async () => {
    const directDemo = await startDirectDemo(demoOrigin);
    try {
      const directEnvelope = JSON.stringify(makeDirectArtifactEnvelope(directDemo.ready));

      const simpleOut = runNodeDemoScript("node-direct-client.mjs", {
        input: directEnvelope,
        env: { FSEC_ORIGIN: demoOrigin },
      });
      expectDemoRPCOutput(simpleOut);

      const advancedOut = runNodeDemoScript("node-direct-client-advanced.mjs", {
        input: directEnvelope,
        env: { FSEC_ORIGIN: demoOrigin },
      });
      expectDemoRPCOutput(advancedOut);

      const metaBytesOut = runNodeDemoScript("stream-meta-bytes/node-direct-client.mjs", {
        input: directEnvelope,
        env: {
          FSEC_ORIGIN: demoOrigin,
          FSEC_META_BYTES: "4096",
          FSEC_META_FILL_BYTE: "122",
        },
      });
      expect(metaBytesOut).toContain('"content_len":4096');
      expect(metaBytesOut).toContain("bytes: 4096");
      expect(metaBytesOut).toContain("bytes_head_hex: 7a7a7a7a");
    } finally {
      await directDemo.stop();
    }
  });
});

function expectDemoRPCOutput(output: string): void {
  expect(output).toContain('rpc response: {"ok":true}');
  expect(output).toContain('rpc notify: {"hello":"world"}');
  expect(output).toContain('echo response: "hello over yamux stream: echo"');
}
