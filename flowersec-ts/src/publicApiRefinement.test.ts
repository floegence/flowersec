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

  test("built public declarations expose v2 only through the explicit compatibility namespaces", async () => {
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
    const declarations = await Promise.all([...retained].map(async (file) => ({
      file,
      source: await fs.readFile(file, "utf8"),
    })));
    const allowedV2References = new Map<string, readonly string[]>([
      [path.join(root, "facade.d.ts"), ['export * as v2 from "./v2/index.js";']],
      [path.join(root, "browser/index.d.ts"), ['export * as v2 from "./v2.js";']],
      [path.join(root, "browser/v2.d.ts"), ['export * from "../v2/index.js";']],
      [path.join(root, "node/index.d.ts"), ['export * as v2 from "./v2.js";']],
      [path.join(root, "node/v2.d.ts"), ['export * from "../v2/index.js";']],
    ]);
    const publicSource = declarations.map(({ file, source }) => {
      let guardedSource = source;
      for (const reference of allowedV2References.get(file) ?? []) {
        expect(guardedSource.split(reference)).toHaveLength(2);
        guardedSource = guardedSource.replace(reference, "");
      }
      return guardedSource;
    }).join("\n");
    expect(publicSource).not.toMatch(/\b[A-Za-z_$][A-Za-z0-9_$]*V2\b/u);
    expect(publicSource).not.toMatch(/(?:^|["'\/])(?:v2|connector)(?:["'\/]|\.)/u);
    expect(publicSource).not.toMatch(/(?:^|["'\/])utils\/errors(?:["'\/]|\.)/u);
  });

  test("Node v3 server callbacks expose only the opaque authorization lookup", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const root = path.resolve(process.cwd(), "dist/node");
    const publicServerDeclarations = await Promise.all([
      "acceptorV3.d.ts",
      "runtimeAuthorizationV3.d.ts",
      "tunnelRuntimeV3.d.ts",
    ].map((file) => fs.readFile(path.join(root, file), "utf8")));
    const source = publicServerDeclarations.join("\n");
    expect(source).toContain("RuntimeAuthorizationRequestV3");
    expect(source).toContain("lookupKey(): string");
    expect(source).not.toContain("DecodedFSB3RequestV3");
    expect(source).not.toContain("nowUnixSeconds");
    for (const secretField of [
      "localAdmissionBinding",
      "routing_token",
      "attach_token",
      "candidates",
      "pins",
    ]) {
      expect(source).not.toContain(secretField);
    }
  });

  test("public Controller acquisition and options hide runtime capabilities and clocks", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const root = path.resolve(process.cwd(), "dist");
    const core = await fs.readFile(path.join(root, "v3/connectionController.d.ts"), "utf8");
    const artifactSource = core.slice(
      core.indexOf("export type ArtifactSourceV3"),
      core.indexOf("export type ManagedSessionV3"),
    );
    expect(artifactSource).toContain("signal: AbortSignal");
    expect(artifactSource).not.toContain("RuntimeCapabilityDescriptorV3");
    expect(artifactSource).not.toContain("capability:");

    const facade = await fs.readFile(path.join(root, "facade.d.ts"), "utf8");
    const publicOptions = facade.slice(
      facade.indexOf("export type ConnectionControllerOptions ="),
      facade.indexOf("export { ConnectionControllerV3Error"),
    );
    expect(publicOptions).toContain("maximumAttempts?: number");
    expect(publicOptions).not.toContain("ControllerClockV3");
    expect(publicOptions).not.toContain("nowUnixSeconds");
    expect(publicOptions).not.toContain("capabilitySnapshot");
    expect(publicOptions).not.toContain("projectSessionFailure");
  });
});
