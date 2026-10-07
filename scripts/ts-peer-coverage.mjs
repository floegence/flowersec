import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { Session } from "node:inspector/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { isMainThread } from "node:worker_threads";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = path.join(repositoryRoot, "flowersec-ts/src");
const peerEntry = path.join(sourceRoot, "interop/serverParityPeer.ts");
const sourcePrefix = `${pathToFileURL(sourceRoot).href}/`;
const sha256 = value => createHash("sha256").update(value).digest("hex");
const namedFunctionHelpers = [
  "var __defProp=Object.defineProperty;var __name=(target,value)=>__defProp(target,\"name\",{value,configurable:true});",
  // The pinned compiler renames its parameter when the source declares value.
  "var __defProp=Object.defineProperty;var __name=(target,value2)=>__defProp(target,\"name\",{value:value2,configurable:true});",
];

// Only the original standalone peer installs an inspector. The matrix process,
// native addon and workers retain their ordinary execution and cleanup owners.
if (isMainThread && process.env.FLOWERSEC_PARITY_TS_COVERAGE_DIRECTORY !== undefined
    && path.resolve(process.argv[1] ?? "") === peerEntry) {
  const directory = process.env.FLOWERSEC_PARITY_TS_COVERAGE_DIRECTORY;
  if (!path.isAbsolute(directory)) throw new Error("Node peer coverage requires an absolute directory");
  const inspector = new Session();
  inspector.connect();
  await inspector.post("Debugger.enable");
  await inspector.post("Profiler.enable");
  await inspector.post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
  process.once("beforeExit", async () => {
    try {
      if (process.exitCode !== undefined && process.exitCode !== 0) return;
      const result = await inspector.post("Profiler.takePreciseCoverage");
      const scripts = [];
      for (const coverage of result.result) {
        if (!coverage.url.startsWith(sourcePrefix)) continue;
        const file = fileURLToPath(coverage.url);
        if (!file.endsWith(".ts") || file.endsWith(".test.ts")) throw new Error(`Unexpected peer source: ${file}`);
        const { scriptSource: code } = await inspector.post("Debugger.getScriptSource", { scriptId: coverage.scriptId });
        const original = await readFile(file, "utf8");
        const match = code.match(/\/\/# sourceMappingURL=data:application\/json(?:;charset=utf-8)?;base64,([^\s]+)/u);
        if (match === null) throw new Error(`Executed TypeScript source map missing: ${file}`);
        const sourceMap = JSON.parse(Buffer.from(match[1], "base64").toString("utf8"));
        if (sourceMap.sources?.length !== 1 || sourceMap.sources[0] !== file
            || sourceMap.sourcesContent?.[0] != null && sourceMap.sourcesContent[0] !== original) {
          throw new Error(`Executed TypeScript source map disagrees with current source: ${file}`);
        }
        // tsx omits sourcesContent. Bind the map to the original file, which the
        // parent verifies again before accepting any of this process's counts.
        sourceMap.sourcesContent = [original];
        scripts.push({ coverage, code, sourceMap, sourceSHA256: sha256(original) });
      }
      if (!scripts.some(script => fileURLToPath(script.coverage.url) === peerEntry)) throw new Error("Node peer produced no source coverage");
      await writeFile(path.join(directory, `peer-${process.pid}.json`), JSON.stringify({
        pid: process.pid, role: process.argv[2], scripts,
      }), { flag: "wx" });
    } catch (error) {
      process.stderr.write(`Node peer coverage failed: ${error.stack ?? error}\n`);
      process.exitCode = 1;
    } finally {
      await inspector.post("Profiler.stopPreciseCoverage");
      inspector.disconnect();
    }
  });
}

export function nodePeerCoverageEnvironment(directory) {
  return {
    FLOWERSEC_PARITY_TS_COVERAGE_DIRECTORY: directory,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --import=${pathToFileURL(fileURLToPath(import.meta.url)).href}`.trim(),
  };
}

export async function readNodePeerCoverage(directory, expectedRoles) {
  const require = createRequire(path.join(repositoryRoot, "flowersec-ts/package.json"));
  const { default: convert } = await import(require.resolve("ast-v8-to-istanbul"));
  const { parseAstAsync } = await import(require.resolve("vitest/node"));
  const { createCoverageMap } = require("istanbul-lib-coverage");
  const merged = createCoverageMap({}), roles = [];
  const names = (await readdir(directory)).filter(name => /^peer-\d+\.json$/u.test(name));
  if (names.length !== expectedRoles.length) throw new Error(`Expected ${expectedRoles.length} successful Node peer profiles, received ${names.length}`);
  for (const name of names) {
    const record = JSON.parse(await readFile(path.join(directory, name), "utf8"));
    if (name !== `peer-${record.pid}.json` || !Array.isArray(record.scripts) || record.scripts.length === 0) throw new Error(`Invalid Node peer coverage: ${name}`);
    roles.push(record.role);
    const seen = new Set();
    for (const script of record.scripts) {
      if (!script.coverage.url.startsWith(sourcePrefix) || seen.has(script.coverage.url)) throw new Error("Invalid or duplicate Node peer source");
      seen.add(script.coverage.url);
      const file = fileURLToPath(script.coverage.url), original = await readFile(file, "utf8");
      if (sha256(original) !== script.sourceSHA256 || script.sourceMap.sourcesContent[0] !== original) throw new Error(`Node peer source changed: ${file}`);
      const hasHelper = namedFunctionHelpers.some(helper => script.code.startsWith(helper));
      if (hasHelper && /\b(?:__defProp|__name)\b/u.test(original)) throw new Error(`Compiler helper collides with original source: ${file}`);
      merged.merge(await convert({ code: script.code, sourceMap: script.sourceMap,
        ast: await parseAstAsync(script.code), coverage: script.coverage, wrapperLength: 0,
        ignoreNode: (node, type) => {
          if (!hasHelper) return;
          // These exact nodes are injected by tsx's keepNames transform. No
          // original source node is excluded from the coverage denominator.
          if (node.type === "VariableDeclarator" && node.id.type === "Identifier"
              && ["__defProp", "__name"].includes(node.id.name)) return "ignore-this-and-nested-nodes";
          if (type === "statement" && node.type === "ExpressionStatement"
              && node.expression.type === "CallExpression" && node.expression.callee.type === "Identifier"
              && node.expression.callee.name === "__name") return true;
        },
      }));
    }
  }
  if (JSON.stringify(roles.sort()) !== JSON.stringify([...expectedRoles].sort())) throw new Error("Node coverage roles disagree with the successful parity workflows");
  return merged;
}

export function addNodePeerCoverage(original, peers) {
  const unmatched = { statements: 0, functions: 0, branches: 0 };
  for (const file of peers.files()) {
    const peer = peers.fileCoverageFor(file).toJSON();
    if (!original.files().includes(file)) { original.addFileCoverage(peer); continue; }
    const target = original.fileCoverageFor(file).data;
    for (const [map, counts, metric, key] of [
      ["statementMap", "s", "statements", location => JSON.stringify(location)],
      ["fnMap", "f", "functions", fn => JSON.stringify(fn.loc)],
      ["branchMap", "b", "branches", branch => JSON.stringify([branch.type, branch.locations])],
    ]) {
      if (Object.keys(target[map]).length !== Object.keys(peer[map]).length) throw new Error(`Node coverage source mapping differs: ${file} ${map}`);
      const positions = new Map();
      for (const [id, entry] of Object.entries(target[map])) {
        const position = key(entry);
        if (positions.has(position)) throw new Error(`Ambiguous original coverage position: ${file} ${map}`);
        positions.set(position, id);
      }
      for (const [id, entry] of Object.entries(peer[map])) {
        const matched = positions.get(key(entry));
        if (matched === undefined) {
          unmatched[metric] += Array.isArray(peer[counts][id])
            ? peer[counts][id].filter(count => count > 0).length : Number(peer[counts][id] > 0);
          continue;
        }
        if (counts === "b") {
          for (let index = 0; index < target.b[matched].length; index++) target.b[matched][index] += peer.b[id][index];
        } else target[counts][matched] += peer[counts][id];
      }
    }
  }
  // Different transpilers sometimes place the same construct at slightly
  // different source positions. Preserve every original denominator and give
  // no additional credit to counts without an identical source location.
  console.log(`Node peer covered positions without an identical Vitest mapping (not credited): ${JSON.stringify(unmatched)}`);
}
