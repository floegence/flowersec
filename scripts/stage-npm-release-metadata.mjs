#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const sourceCommit = process.argv[2];
if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? "") || process.argv.length !== 3) {
  throw new Error("usage: scripts/stage-npm-release-metadata.mjs <source-commit-sha>");
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifests = [
  "flowersec-ts/package.json",
  "flowersec-node-native/package.json",
  "flowersec-node-native/npm/darwin-arm64/package.json",
  "flowersec-node-native/npm/darwin-x64/package.json",
  "flowersec-node-native/npm/linux-arm64-gnu/package.json",
  "flowersec-node-native/npm/linux-x64-gnu/package.json",
];

for (const relative of manifests) {
  const manifestPath = path.join(root, relative);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  manifest.flowersecSourceCommit = sourceCommit;
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}
