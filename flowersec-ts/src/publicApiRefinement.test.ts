import { describe, expect, test } from "vitest";
import * as core from "./facade.js";
import * as browser from "./browser/index.js";
import * as node from "./node/index.js";
import * as proxy from "./proxy/index.js";

describe("final public SDK names", () => {
  test("declaration closure does not check file access before reading", async () => {
    const fs = await import("node:fs/promises");
    const source = await fs.readFile(new URL("./publicApiRefinement.test.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/await expect\(fs\.access\(file\)\)/u);
  });

  test("browser and node subpaths expose environment-neutral operations", () => {
    expect(typeof browser.connect).toBe("function");
    expect(typeof browser.createConnectionController).toBe("function");
    expect(typeof browser.createHandlerPlan).toBe("function");
    expect("StreamHandlers" in browser).toBe(false);
    expect(typeof node.connect).toBe("function");
    expect(typeof node.createConnectionController).toBe("function");
    expect(typeof node.createHandlerPlan).toBe("function");
    expect("StreamHandlers" in node).toBe(false);
    expect("connectBrowserSession" in browser).toBe(false);
    expect("createBrowserConnectionController" in browser).toBe(false);
    expect("connectNodeSession" in node).toBe(false);
    expect("createNodeConnectionController" in node).toBe(false);
  });

  test("pool operations share original opaque owners across every public entrypoint", () => {
    for (const entry of [core, browser, node, proxy]) {
      expect(entry.PreauthorizedPoolSource).toBe(core.PreauthorizedPoolSource);
      expect(entry.TopUpHandle).toBe(core.TopUpHandle);
      expect(entry.createSessionPoolControl).toBe(core.createSessionPoolControl);
      expect("createOriginalPoolSource" in entry).toBe(false);
      expect("registerPoolJournalStore" in entry).toBe(false);
      expect("proxyRequestAssociation" in entry).toBe(false);
      expect("serviceWorkerPublicationOwner" in entry).toBe(false);
    }
    expect(typeof core.TopUpHandle.prototype.status).toBe("function");
    expect(typeof core.TopUpHandle.prototype.cleanupStatus).toBe("function");
    expect(typeof core.TopUpHandle.prototype.waitCleanup).toBe("function");
    expect("id" in core.TopUpHandle.prototype).toBe(false);
    expect("operationID" in core.TopUpHandle.prototype).toBe(false);
    expect("operation_id" in core.TopUpHandle.prototype).toBe(false);
    expect(typeof proxy.createProxySurface).toBe("function");
    for (const entry of [core, browser, node]) expect("createProxySurface" in entry).toBe(false);
  });

  test("v2 namespaces and deprecated versioned aliases are absent", () => {
    for (const entry of [core, browser, node]) {
      expect("v2" in entry).toBe(false);
      for (const name of Object.keys(entry)) expect(name).not.toMatch(/V[23]$/u);
    }
  });

  test("built public declaration closure contains no v2 API or runtime", async () => {
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
      const imports = source.matchAll(/(?:\bfrom\s+|\bimport\s*\(\s*)["']([^"']+)["']/gu);
      for (const imported of imports) {
        const specifier = imported[1];
        if (specifier === undefined || !specifier.startsWith(".")) continue;
        const dependency = resolveDeclaration(file, specifier);
        expect(dependency, `unresolvable public declaration import ${specifier} from ${file}`).toBeDefined();
        pending.push(dependency!);
      }
    }
    expect(retained.size).toBeGreaterThan(0);
    const declarations = await Promise.all([...retained].map(async (file) => ({
      file,
      source: await fs.readFile(file, "utf8"),
    })));
    const publicSource = declarations.map(({ source }) => source).join("\n");
    expect(publicSource).not.toMatch(/\b[A-Za-z_$][A-Za-z0-9_$]*V2\b/u);
    expect(publicSource).not.toMatch(/(?:^|["'\/])(?:v2|connector)(?:["'\/]|\.)/u);
    expect(publicSource).not.toMatch(/(?:^|["'\/])utils\/errors(?:["'\/]|\.)/u);
  });

  test("ordinary server callbacks retain current Environment and application ownership", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const root = path.resolve(process.cwd(), "dist");
    const declarations = await Promise.all([
      "node/acceptorCurrent.d.ts", "v4/serve.d.ts", "v4/handlerPlan.d.ts",
    ].map(file => fs.readFile(path.join(root, file), "utf8")));
    const source = declarations.join("\n");
    expect(source).toContain("V4TransportEnvironment");
    expect(source).toContain("authorizeApplication");
    expect(source).toContain("ApplicationAuthorizationLease");
    expect(source).toContain("ServeReleaseContext");
    expect(source).not.toContain("DecodedFSB3RequestV3");
    expect(source).not.toContain("ArtifactV3");
    expect("parseArtifact" in node).toBe(false);
    expect("createArtifactLease" in node).toBe(false);
    expect("SessionHandlers" in node).toBe(false);
  });

  test("ordinary Controller uses an original source and preserves bounded initialization", async () => {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const root = path.resolve(process.cwd(), "dist");
    const controller = await fs.readFile(path.join(root, "v4/controller.d.ts"), "utf8");
    const options = controller.slice(controller.indexOf("export interface V4ControllerConfig"), controller.indexOf("export type V4ControllerReplaceOptions"));
    expect(options).toContain("source: V4ConnectionMaterialSource");
    expect(options).toContain("attemptTimeoutMS?: bigint");
    expect(options).toContain("initializeServices?: Dependencies");
    expect(options).toContain("initializeApplicationBytes?: bigint");
    expect(options).not.toContain("ControllerClockV3");
    expect(options).not.toContain("nowUnixSeconds");
    expect(options).not.toContain("capabilitySnapshot");
    for (const entry of [core, browser, node]) {
      expect(entry.connect).toBe(core.connect);
      expect(entry.createConnectionController).toBe(core.createConnectionController);
      expect(entry.Session).toBe(core.Session);
      expect(entry.TransportEnvironment).toBe(core.TransportEnvironment);
      expect("parseArtifact" in entry).toBe(false);
      expect("createArtifactLease" in entry).toBe(false);
    }
  });
});
