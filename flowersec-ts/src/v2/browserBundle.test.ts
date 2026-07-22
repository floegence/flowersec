import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

describe("browser package graph", () => {
  test("does not retain a bare tr46 module specifier", () => {
    const entry = fileURLToPath(new URL("../../dist/browser/index.js", import.meta.url));
    const pending = [entry];
    const visited = new Set<string>();
    const bareSpecifiers: string[] = [];

    while (pending.length > 0) {
      const file = pending.pop()!;
      if (visited.has(file)) continue;
      visited.add(file);
      const source = readFileSync(file, "utf8");
      for (const match of source.matchAll(/(?:from\s+|import\s*)["']([^"']+)["']/g)) {
        const specifier = match[1]!;
        if (!specifier.startsWith(".")) {
          bareSpecifiers.push(specifier);
          continue;
        }
        pending.push(resolve(dirname(file), specifier));
      }
    }

    expect(bareSpecifiers).not.toContain("tr46");
  });
});
