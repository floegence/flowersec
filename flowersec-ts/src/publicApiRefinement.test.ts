import { describe, expect, test } from "vitest";
import ts from "typescript";
import * as browser from "./browser/index.js";
import * as node from "./node/index.js";

describe("final public SDK names", () => {
  test("declaration closure does not check file access before reading", async () => {
    const fs = await import("node:fs/promises");
    const source = await fs.readFile(new URL("./publicApiRefinement.test.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/await expect\(fs\.access\(file\)\)/u);
  });

  test("browser and node subpaths expose environment-neutral operations", () => {
    expect(typeof browser.connect).toBe("function");
    expect(typeof browser.createConnectionController).toBe("function");
    expect(typeof browser.StreamHandlers).toBe("function");
    expect(typeof node.connect).toBe("function");
    expect(typeof node.createConnectionController).toBe("function");
    expect(typeof node.StreamHandlers).toBe("function");
    expect("connectBrowserSession" in browser).toBe(false);
    expect("createBrowserConnectionController" in browser).toBe(false);
    expect("connectNodeSession" in node).toBe(false);
    expect("createNodeConnectionController" in node).toBe(false);
  });

  test("built public declarations contain no versioned or internal SDK types", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const root = path.resolve(process.cwd(), "dist");
    const entrypoints = [
      "facade.d.ts",
      "browser/index.d.ts",
      "node/index.d.ts",
      "proxy/index.d.ts",
    ].map((file) => path.join(root, file));
    const retained = new Set<string>();
    const pending = [...entrypoints];
    const resolveDeclaration = (importer: string, specifier: string): string | undefined => {
      const resolved = path.resolve(path.dirname(importer), specifier);
      const candidates = [
        resolved.replace(/\.js$/u, ".d.ts"),
        `${resolved}.d.ts`,
        resolved,
      ];
      return candidates.find((candidate) => candidate.startsWith(`${root}${path.sep}`) && candidate.endsWith(".d.ts"));
    };
    const readDeclaration = async (file: string): Promise<string> => {
      try {
        return await fs.readFile(file, "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") {
          throw new Error(`missing public declaration ${file}`, { cause: error });
        }
        throw error;
      }
    };
    while (pending.length > 0) {
      const file = pending.pop();
      if (file === undefined || retained.has(file)) continue;
      expect(file.startsWith(`${root}${path.sep}`)).toBe(true);
      const source = await readDeclaration(file);
      retained.add(file);
      const parsed = ts.preProcessFile(source, true, true);
      for (const imported of parsed.importedFiles) {
        if (!imported.fileName.startsWith(".")) continue;
        const dependency = resolveDeclaration(file, imported.fileName);
        expect(dependency, `unresolvable public declaration import ${imported.fileName} from ${file}`).toBeDefined();
        pending.push(dependency!);
      }
    }
    expect(retained.size).toBeGreaterThan(0);
    const publicSource = await Promise.all([...retained].map((file) => fs.readFile(file, "utf8"))).then((sources) => sources.join("\n"));
    expect(publicSource).not.toMatch(/\b[A-Za-z_$][A-Za-z0-9_$]*V2\b/u);
    expect(publicSource).not.toMatch(/(?:^|["'\/])(?:v2|connector)(?:["'\/]|\.)/u);
    expect(publicSource).not.toMatch(/(?:^|["'\/])utils\/errors(?:["'\/]|\.)/u);
  });
});
