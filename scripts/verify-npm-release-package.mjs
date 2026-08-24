#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { execFileBounded, fetchResponseBody, killProcessGroup } from "./release-readback.mjs";

const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 16 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 30_000;
const MAX_ATTEMPTS = 6;
const [packageName, version, sourceSHA] = process.argv.slice(2);
assert.match(packageName ?? "", /^@floegence\//);
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);
assert.match(sourceSHA ?? "", /^[0-9a-f]{40}$/);

let metadata;
for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
  try {
    metadata = JSON.parse((await execFileBounded("npm", ["view", `${packageName}@${version}`, "--json"], { maxStdoutBytes: 4 * 1024 * 1024 }, COMMAND_TIMEOUT_MS)).stdout);
    if (metadata?.version === version && metadata?.dist?.tarball && metadata?.dist?.integrity) break;
  } catch (error) {
    if (attempt === MAX_ATTEMPTS || !isRetryableNpmError(error)) throw error;
  }
  if (attempt === MAX_ATTEMPTS) throw new Error(`${packageName}@${version} did not become readable`);
  await new Promise((resolve) => setTimeout(resolve, 10_000));
}
assert.equal(metadata.name, packageName);
assert.equal(metadata.version, version);
assert.match(metadata.dist?.tarball ?? "", /^https:\/\//);
assert.match(metadata.dist?.integrity ?? "", /^sha512-/);
assertRegistryURL(metadata.dist.tarball, new Set(["registry.npmjs.org"]));

let archive;
for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
  try {
    archive = await fetchResponseBody(
      metadata.dist.tarball,
      {},
      MAX_ARCHIVE_BYTES,
      undefined,
      (candidate) => assertRegistryURL(candidate.url, new Set(["registry.npmjs.org"]), candidate.redirectedFrom),
    );
    if (!archive.response.ok) {
      const error = new Error(`${packageName}@${version} download status ${archive.response.status}`);
      error.retryable = archive.response.status === 408 || archive.response.status === 429 || archive.response.status >= 500;
      throw error;
    }
    break;
  } catch (error) {
    if (!isRetryableRegistryError(error) || attempt === MAX_ATTEMPTS) throw error;
    await new Promise((resolve) => setTimeout(resolve, 10_000));
  }
}
const { response, body } = archive;
assert.equal(response.ok, true);
assertRegistryURL(response.url, new Set(["registry.npmjs.org"]));
const tarball = new Uint8Array(body);
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

function isRetryableNpmError(error) {
  const text = `${error.code ?? ""} ${error.message ?? ""} ${error.stderr ?? ""}`;
  return /E404|E408|E429|E5\d\d|ENOTFOUND|ECONNRESET|ECONNREFUSED|ETIMEDOUT|timed out/i.test(text);
}

function isRetryableRegistryError(error) {
  if (error?.retryable !== undefined) return error.retryable;
  return /timed out|fetch failed|ECONNRESET|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|socket/i.test(`${error?.code ?? ""} ${error?.message ?? ""}`);
}

function assertRegistryURL(value, allowedHosts, redirectedFrom = undefined) {
  const url = new URL(value);
  assert.equal(url.protocol, "https:");
  assert.ok(allowedHosts.has(url.hostname), `unexpected registry download host ${url.hostname}`);
  if (redirectedFrom !== undefined) {
    assert.equal(new URL(redirectedFrom).hostname, url.hostname);
  }
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
    const child = spawn("tar", args, { stdio: ["pipe", "pipe", "pipe"], detached: true });
    let timedOut = false;
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const terminate = () => {
      try {
        killProcessGroup(child);
        return undefined;
      } catch (error) {
        return error;
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      const terminationError = terminate();
      if (terminationError !== undefined && !settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error("tar readback failed to terminate timed-out child process group", { cause: terminationError }));
      }
    }, COMMAND_TIMEOUT_MS);
    const fail = (error) => {
      if (settled) return;
      clearTimeout(timer);
      const terminationError = terminate();
      settled = true;
      if (timedOut) {
        reject(terminationError === undefined ? new Error(`tar readback timed out after ${COMMAND_TIMEOUT_MS}ms`) : new Error("tar readback failed to terminate child process group", { cause: terminationError }));
        return;
      }
      reject(terminationError === undefined ? error : new Error("tar readback failed to terminate child process group", { cause: terminationError }));
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
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error(`tar readback timed out after ${COMMAND_TIMEOUT_MS}ms`));
        return;
      }
      if (code === 0) resolve(Buffer.concat(stdout));
      else reject(new Error(`tar readback failed: ${Buffer.concat(stderr).toString("utf8").trim()}`));
    });
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") fail(error);
    });
    child.stdin.end(archiveBytes);
  });
}
