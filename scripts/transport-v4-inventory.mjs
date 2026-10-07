#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { collectReleaseVersions, validateReleaseVersions } from "./check-release-version-consistency.mjs";

const root = path.resolve(import.meta.dirname, "..");
const output = "stability/transport_v4_inventory.json";

export function v3SourceTokens(line) {
  // X.509v3 and the WebSocket RSV3 bit are current external standards.
  const source = line.replace(/x509v3|X\.509v3|\bX509Version::V3\b|\brsv3\b/gu, "")
    .replace(/AGFzbQ[A-Za-z0-9+/]*={0,2}/gu, encoded => {
      const binary = Buffer.from(encoded, "base64");
      if (!binary.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) return encoded;
      // Generated WASM bytes are not source identifiers. Retain actual old
      // protocol markers inside the decoded module instead of scanning the
      // incidental Base64 alphabet; surrounding loader code stays in scope.
      return (binary.toString("latin1").match(/protocolv3|artifactv3|session_?v3|FS[ABH]3|flowersec(?:[./-](?:direct|tunnel))?[/.]3/gu) ?? []).join(" ");
    });
  // Scan each identifier start once, including generated loader code.
  return [...new Set(source.match(/protocolv3|artifactv3|session_?v3|(?<![A-Za-z_])[A-Za-z_]*[vV]3|FS[ABH]3|flowersec(?:[./-](?:direct|tunnel))?[/.]3/gu) ?? [])].sort();
}

export function collectV4Inventory(repository = root) {
  const listed = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], {cwd:repository, encoding:"utf8", maxBuffer:32*1024*1024});
  if (listed.status !== 0) throw new Error(listed.stderr || "source inventory failed");
  const paths = [...new Set(listed.stdout.split("\0").filter(Boolean))].sort();
  const sourceHits = [];
  for (const file of paths) {
    if (!/^flowersec-(?:go\/|(?:rust|native-transport|node-native)\/src\/|swift\/Sources\/|ts\/src\/)/u.test(file)) continue;
    if (!/\.(?:go|rs|swift|ts)$/u.test(file) || /(?:_test\.go|(?:\.test|\.spec)\.ts|_tests?\.rs)$/u.test(file)) continue;
    if (!fs.existsSync(path.join(repository,file))) continue;
    const lines = fs.readFileSync(path.join(repository,file),"utf8").split("\n");
    const hits = lines.flatMap((line,index) => {
      const tokens = v3SourceTokens(line);
      return tokens.length ? [{line:index+1, tokens}] : [];
    });
    if (hits.length || /[vV]3/u.test(file)) sourceHits.push({
      path:file, action:"replace_before_v4_runtime",
      first_matching_line:hits[0]?.line ?? null,
      matching_lines:hits.length,
    });
  }
  const versions = collectReleaseVersions(repository);
  const currentVersion = validateReleaseVersions(versions);
  return {
    target_version:"6.0.0", target_wire:"flowersec/4", current_version:currentVersion,
    scan_scope:"Tracked and unignored SDK source candidates; text hits require reachability review, not a runtime proof",
    release_coordinates:versions,
    go_module:fs.readFileSync(path.join(repository,"flowersec-go/go.mod"),"utf8").match(/^module (.+)$/mu)?.[1],
    v3_source_candidates:sourceHits,
  };
}

export function checkV4Inventory(repository = root, requireV4 = false) {
  const inventory = collectV4Inventory(repository);
  const expected = `${JSON.stringify(inventory,null,2)}\n`;
  const file = path.join(repository,output);
  if (!fs.existsSync(file) || fs.readFileSync(file,"utf8") !== expected) throw new Error("v4 source/version inventory drift; run scripts/transport-v4-inventory.mjs --write");
  if (requireV4 && (inventory.current_version !== "6.0.0" || inventory.v3_source_candidates.length)) throw new Error("v4 production gate blocked: package versions or v3 source candidates remain");
  return inventory;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || !["--write","--check","--require-v4"].includes(process.argv[2])) throw new Error("usage: transport-v4-inventory.mjs --write|--check|--require-v4");
  const inventory = process.argv[2] === "--write" ? collectV4Inventory() : checkV4Inventory(root,process.argv[2] === "--require-v4");
  if (process.argv[2] === "--write") fs.writeFileSync(path.join(root,output),`${JSON.stringify(inventory,null,2)}\n`);
  console.log(`Source inventory: ${inventory.v3_source_candidates.length} v3 candidates; ${inventory.release_coordinates.length} release sources at ${inventory.current_version}.`);
}
