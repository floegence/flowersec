import fs from "node:fs/promises";

import { describe, expect, test } from "vitest";

import { assertConnectArtifact } from "./artifact.js";

type FixtureCase = Readonly<{
  id: string;
  input: string;
  ok: boolean;
  normalized?: string;
  error_contains?: string;
}>;

type FixtureManifest = Readonly<{
  version: 1;
  cases: readonly FixtureCase[];
}>;

const FIXTURE_ROOT = new URL("../../../testdata/connect_artifact_cases/", import.meta.url);
const manifest = (await readJSON("manifest.json")) as FixtureManifest;

async function readJSON(path: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(new URL(path, FIXTURE_ROOT), "utf8")) as unknown;
}

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => normalize(entry));
  if (value != null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = normalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

describe("ConnectArtifact shared fixtures", () => {
  for (const item of manifest.cases) {
    test(item.id, async () => {
      const input = await readJSON(item.input);
      if (!item.ok) {
        expect(() => assertConnectArtifact(input)).toThrow(item.error_contains ?? /bad/);
        return;
      }

      const artifact = assertConnectArtifact(input);
      if (item.normalized == null) return;
      const expected = await readJSON(item.normalized);
      expect(normalize(artifact)).toEqual(normalize(expected));
    });
  }
});
