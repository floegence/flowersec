#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const sourceCommit = process.argv[2];
if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? "") || process.argv.length !== 3) {
  throw new Error("usage: scripts/stage-npm-release-metadata.mjs <source-commit-sha>");
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const coreRelative = "flowersec-ts/package.json";
const wrapperRelative = "flowersec-node-native/package.json";
const platformRelatives = [
  "flowersec-node-native/npm/darwin-arm64/package.json",
  "flowersec-node-native/npm/darwin-x64/package.json",
  "flowersec-node-native/npm/linux-arm64-gnu/package.json",
  "flowersec-node-native/npm/linux-x64-gnu/package.json",
];

function readManifest(relative) {
  return JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));
}

function writeManifest(relative, manifest) {
  fs.writeFileSync(path.join(root, relative), `${JSON.stringify(manifest, null, 2)}\n`);
}

const core = readManifest(coreRelative);
const wrapper = readManifest(wrapperRelative);
const platformManifests = platformRelatives.map((relative) => [relative, readManifest(relative)]);
const version = core.version;
if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) {
  throw new Error("core npm manifest must declare a canonical version");
}
if (wrapper.name !== "@floegence/flowersec-node-native" || wrapper.version !== version) {
  throw new Error("native wrapper manifest must match the core package version");
}
for (const [relative, manifest] of platformManifests) {
  if (manifest.version !== version) {
    throw new Error(`native platform manifest ${relative} must match the core package version`);
  }
}

core.optionalDependencies = {
  ...(core.optionalDependencies ?? {}),
  "@floegence/flowersec-node-native": version,
};
for (const manifest of [core, wrapper, ...platformManifests.map(([, value]) => value)]) {
  manifest.flowersecSourceCommit = sourceCommit;
}

writeManifest(coreRelative, core);
writeManifest(wrapperRelative, wrapper);
for (const [relative, manifest] of platformManifests) writeManifest(relative, manifest);
