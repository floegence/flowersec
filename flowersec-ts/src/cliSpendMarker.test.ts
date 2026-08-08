import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { claimSpendMarker } from "./cliSpendMarker.js";

const scratch: string[] = [];

afterEach(() => {
  for (const directory of scratch.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("CLI durable spend marker", () => {
  it("atomically claims a new marker exactly once", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "flowersec-spend-marker-"));
    scratch.push(directory);
    const marker = path.join(directory, "spent");

    claimSpendMarker(marker);

    expect(readFileSync(marker)).toHaveLength(0);
    expect(statSync(marker).mode & 0o777).toBe(0o600);
    expect(() => claimSpendMarker(marker)).toThrow(`spend marker already exists: ${marker}`);
  });

  it("does not replace an existing marker", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "flowersec-spend-marker-"));
    scratch.push(directory);
    const marker = path.join(directory, "spent");
    writeFileSync(marker, "owned");

    expect(() => claimSpendMarker(marker)).toThrow(`spend marker already exists: ${marker}`);
    expect(readFileSync(marker, "utf8")).toBe("owned");
  });
});
