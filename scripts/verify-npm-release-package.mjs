#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const [packageName, version, sourceSHA] = process.argv.slice(2);
assert.match(packageName ?? "", /^@floegence\//);
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);
assert.match(sourceSHA ?? "", /^[0-9a-f]{40}$/);

let metadata;
for (let attempt = 1; attempt <= 30; attempt++) {
  try {
    metadata = JSON.parse((await execFileAsync("npm", ["view", `${packageName}@${version}`, "--json"], { encoding: "utf8" })).stdout);
    if (metadata?.version === version && metadata?.dist?.tarball && metadata?.dist?.integrity) break;
  } catch (error) {
    if (attempt === 30) throw error;
  }
  if (attempt === 30) throw new Error(`${packageName}@${version} did not become readable`);
  await new Promise((resolve) => setTimeout(resolve, 10_000));
}
assert.equal(metadata.name, packageName);
assert.equal(metadata.version, version);
assert.match(metadata.dist?.tarball ?? "", /^https:\/\//);
assert.match(metadata.dist?.integrity ?? "", /^sha512-/);

const tarball = new Uint8Array(await (await fetch(metadata.dist.tarball)).arrayBuffer());
const digest = `sha512-${crypto.createHash("sha512").update(tarball).digest("base64")}`;
assert.equal(digest, metadata.dist.integrity, `${packageName}@${version} tarball integrity mismatch`);
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-npm-readback-"));
try {
  const archive = path.join(temporary, "package.tgz");
  await fs.writeFile(archive, tarball);
  await execFileAsync("tar", ["-xzf", archive, "-C", temporary]);
  const manifest = JSON.parse(await fs.readFile(path.join(temporary, "package/package.json"), "utf8"));
  assert.equal(manifest.name, packageName);
  assert.equal(manifest.version, version);
  assert.equal(manifest.flowersecSourceCommit, sourceSHA, `${packageName}@${version} source commit mismatch`);
  if (packageName === "@floegence/flowersec-node-native") {
    const optional = manifest.optionalDependencies ?? {};
    for (const platform of ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]) {
      assert.equal(optional[`@floegence/flowersec-node-native-${platform}`], version);
    }
  }
  if (packageName === "@floegence/flowersec-core") {
    assert.equal(manifest.optionalDependencies?.["@floegence/flowersec-node-native"], version);
    await fs.access(path.join(temporary, "package/dist/node/index.js"));
    await fs.access(path.join(temporary, "package/dist/browser/index.js"));
  }
  const platform = packageName.match(/flowersec-node-native-(darwin|linux)-(arm64|x64)(?:-gnu)?$/);
  if (platform !== null) {
    const [, operatingSystem, cpu] = platform;
    assert.deepEqual(manifest.os, [operatingSystem]);
    assert.deepEqual(manifest.cpu, [cpu]);
    if (operatingSystem === "linux") assert.deepEqual(manifest.libc, ["glibc"]);
    else assert.equal(manifest.libc, undefined);
    const expectedMain = `flowersec-node-native.${packageName.slice("@floegence/flowersec-node-native-".length)}.node`;
    assert.equal(manifest.main, expectedMain);
    assert.ok(manifest.files?.includes(expectedMain));
    await fs.access(path.join(temporary, "package", expectedMain));
  }
} finally {
  await fs.rm(temporary, { recursive: true, force: true });
}
