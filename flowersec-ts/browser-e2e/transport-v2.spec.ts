import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..");

test("real browser exposes only opaque Transport v2 artifacts and connector entrypoints", async ({ page }) => {
  const fixture = JSON.parse(await readFile(
    path.join(repositoryRoot, "testdata", "transport_v2", "artifact_vectors.json"),
    "utf8",
  )) as { positive: Array<{ artifact_json: string }> };
  const site = await startBrowserModuleSite();
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      const artifact = sdk.parseArtifact(artifactJSON);
      return {
        artifactKeys: Object.keys(artifact),
        artifactJSON: JSON.stringify(artifact),
        frozen: Object.isFrozen(artifact),
        connectorType: typeof sdk.connectBrowserSessionV2,
        capabilityExported: "detectBrowserRuntimeCapabilityV2" in sdk,
      };
    }, fixture.positive[0]!.artifact_json);

    expect(result.artifactKeys).toEqual([]);
    expect(result.artifactJSON).toBe("{}");
    expect(result.frozen).toBe(true);
    expect(result.connectorType).toBe("function");
    expect(result.capabilityExported).toBe(false);
  } finally {
    await site.close();
  }
});
