#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 16 * 1024 * 1024;
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
assertRegistryURL(metadata.dist.tarball, new Set(["registry.npmjs.org"]));

const response = await fetch(metadata.dist.tarball);
assert.equal(response.ok, true);
assertRegistryURL(response.url, new Set(["registry.npmjs.org"]));
assertResponseSize(response, MAX_ARCHIVE_BYTES);
const tarball = new Uint8Array(await response.arrayBuffer());
assert.ok(tarball.byteLength <= MAX_ARCHIVE_BYTES, "npm archive exceeds the readback limit");
const digest = `sha512-${crypto.createHash("sha512").update(tarball).digest("base64")}`;
assert.equal(digest, metadata.dist.integrity, `${packageName}@${version} tarball integrity mismatch`);
const entries = await assertSafeArchive(tarball, "package/");
assert.ok(entries.has("package/package.json"), "npm archive is missing package.json");
const manifest = JSON.parse((await readArchiveEntry(tarball, "package/package.json")).toString("utf8"));
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
  assert.ok(entries.has("package/dist/node/index.js"));
  assert.ok(entries.has("package/dist/browser/index.js"));
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
  assert.ok(entries.has(`package/${expectedMain}`));
}

function assertResponseSize(response, maximum) {
  const value = response.headers.get("content-length");
  if (value === null) return;
  const length = Number(value);
  assert.ok(Number.isSafeInteger(length) && length >= 0 && length <= maximum, "invalid registry archive size");
}

function assertRegistryURL(value, allowedHosts) {
  const url = new URL(value);
  assert.equal(url.protocol, "https:");
  assert.ok(allowedHosts.has(url.hostname), `unexpected registry download host ${url.hostname}`);
}

async function assertSafeArchive(archiveBytes, requiredRoot) {
  const paths = splitListing(await runTar(["-tzf", "-"], archiveBytes, MAX_ARCHIVE_BYTES));
  const details = splitListing(await runTar(["-tvzf", "-"], archiveBytes, MAX_ARCHIVE_BYTES));
  assert.equal(details.length, paths.length, "archive inventory is ambiguous");
  const unique = new Set();
  for (let index = 0; index < paths.length; index++) {
    const entry = paths[index];
    assertSafePath(entry, requiredRoot);
    assert.equal(unique.has(entry), false, `duplicate archive entry ${entry}`);
    unique.add(entry);
    assert.ok(details[index].startsWith("-") || details[index].startsWith("d"), `archive links are not allowed: ${entry}`);
  }
  return unique;
}

function assertSafePath(entry, requiredRoot) {
  assert.ok(entry.startsWith(requiredRoot), `archive entry escapes the package root: ${entry}`);
  assert.equal(entry.startsWith("/"), false);
  assert.equal(entry.includes("\\"), false);
  const segments = entry.split("/");
  assert.equal(segments.some((segment) => segment === "." || segment === ".."), false);
}

function splitListing(output) {
  return output.toString("utf8").split("\n").filter((line) => line.length > 0);
}

async function readArchiveEntry(archiveBytes, entry) {
  return await runTar(["-xOzf", "-", entry], archiveBytes, MAX_ENTRY_BYTES);
}

async function runTar(args, archiveBytes, maximumOutputBytes) {
  return await new Promise((resolve, reject) => {
    const child = spawn("tar", args, { stdio: ["pipe", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(error);
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maximumOutputBytes) return fail(new Error("tar output exceeds the readback limit"));
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= 64 * 1024) stderr.push(chunk);
    });
    child.once("error", fail);
    child.once("close", (code) => {
      if (settled) return;
      settled = true;
      if (code === 0) resolve(Buffer.concat(stdout));
      else reject(new Error(`tar readback failed: ${Buffer.concat(stderr).toString("utf8").trim()}`));
    });
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") fail(error);
    });
    child.stdin.end(archiveBytes);
  });
}
