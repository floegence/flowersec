#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function productionCacheManifest(packageJSON, lock) {
  const dependencies = packageJSON?.dependencies;
  if (dependencies == null || typeof dependencies !== "object" || Array.isArray(dependencies)) {
    throw new Error("published package must declare production dependencies");
  }
  const sorted = {};
  for (const name of Object.keys(dependencies).sort()) {
    const range = dependencies[name];
    const locked = lock?.packages?.[`node_modules/${name}`];
    if (typeof range !== "string" || range === ""
      || /^[a-z]+:|^(?:\.|\/|~)/i.test(range)
      || typeof locked?.version !== "string" || locked.dev === true) {
      throw new Error(`production dependency ${name} must have a registry range and lock entry`);
    }
    sorted[name] = range;
  }
  return {
    name: "flowersec-package-cache-preflight",
    private: true,
    dependencies: sorted,
  };
}

export function prepareTSPackageCache(packageJSON, lock, options = {}) {
  const makeScratch = options.makeScratch ?? (() => fs.mkdtempSync(
    path.join(os.tmpdir(), "flowersec-ts-package-cache-"),
  ));
  const cleanup = options.cleanup ?? ((scratch) => fs.rmSync(scratch, {
    recursive: true,
    force: true,
  }));
  const run = options.run ?? spawnSync;
  const scratch = makeScratch();
  try {
    fs.writeFileSync(
      path.join(scratch, "package.json"),
      `${JSON.stringify(productionCacheManifest(packageJSON, lock), null, 2)}\n`,
    );
    const result = run("npm", [
      "install",
      "--ignore-scripts",
      "--no-package-lock",
      "--audit=false",
      "--fund=false",
      "--offline=false",
      "--prefer-online",
    ], {
      cwd: scratch,
      encoding: "utf8",
      stdio: "inherit",
    });
    if (result.error != null || result.status !== 0) {
      throw new Error(`failed to prepare npm package cache: ${result.error?.message ?? `exit ${result.status}`}`);
    }
  } finally {
    cleanup(scratch);
  }
}

function main() {
  const packageRoot = path.resolve(import.meta.dirname, "../flowersec-ts");
  const packageJSON = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  const lock = JSON.parse(fs.readFileSync(path.join(packageRoot, "package-lock.json"), "utf8"));
  prepareTSPackageCache(packageJSON, lock);
  const count = Object.keys(productionCacheManifest(packageJSON, lock).dependencies).length;
  process.stdout.write(`prepared ${count} production npm dependency ranges for offline verification\n`);
}

if (process.argv[1] != null && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
