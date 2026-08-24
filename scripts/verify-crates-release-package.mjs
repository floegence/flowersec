#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { fetchResponseBody, killProcessGroup } from "./release-readback.mjs";

const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 2 * 1024 * 1024;
const MAX_ATTEMPTS = 6;
const [crateName, version, sourceSHA] = process.argv.slice(2);
assert.match(crateName ?? "", /^flowersec(?:-native-transport)?$/);
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);
assert.match(sourceSHA ?? "", /^[0-9a-f]{40}$/);
const requestHeaders = Object.freeze({
  "User-Agent": `flowersec-release-readback/${version} (https://github.com/floegence/flowersec)`,
});

let metadata;
for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
  try {
    const { response, body } = await fetchResponseBody(
      `https://crates.io/api/v1/crates/${crateName}/${version}`,
      { headers: requestHeaders },
      MAX_ENTRY_BYTES,
      undefined,
      (candidate) => assertRegistryURL(candidate.url, new Set(["crates.io"])),
    );
    if (response.ok) {
      try {
        metadata = JSON.parse(body.toString("utf8"));
      } catch (error) {
        error.retryable = false;
        throw error;
      }
      break;
    }
    if (response.status !== 404) {
      const error = new Error(`${crateName}@${version} registry status ${response.status}`);
      error.retryable = response.status === 408 || response.status === 429 || response.status >= 500;
      throw error;
    }
  } catch (error) {
    if (!isRetryableRegistryError(error) || attempt === MAX_ATTEMPTS) throw error;
  }
  if (attempt === MAX_ATTEMPTS) throw new Error(`${crateName}@${version} did not become readable`);
  await new Promise((resolve) => setTimeout(resolve, 10_000));
}
assert.equal(metadata.version?.num, version);
assert.match(metadata.version?.checksum ?? "", /^[0-9a-f]{64}$/);
let archive;
for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
  try {
    archive = await fetchResponseBody(
      `https://crates.io/api/v1/crates/${crateName}/${version}/download`,
      { headers: requestHeaders },
      MAX_ARCHIVE_BYTES,
      undefined,
      (candidate) => assertRegistryURL(
        candidate.url,
        new Set(["crates.io", "static.crates.io"]),
        candidate.redirectedFrom,
      ),
    );
    if (!archive.response.ok) {
      const error = new Error(`${crateName}@${version} download status ${archive.response.status}`);
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
assertRegistryURL(response.url, new Set(["crates.io", "static.crates.io"]));
const archiveBytes = new Uint8Array(body);
assert.equal(crypto.createHash("sha256").update(archiveBytes).digest("hex"), metadata.version.checksum);
const root = `${crateName}-${version}`;
const entries = await assertSafeArchive(archiveBytes, `${root}/`);
const cargoPath = `${root}/Cargo.toml`;
const vcsPath = `${root}/.cargo_vcs_info.json`;
assert.ok(entries.has(cargoPath), "crate archive is missing Cargo.toml");
assert.ok(entries.has(vcsPath), "crate archive is missing .cargo_vcs_info.json");
const cargo = (await readArchiveEntry(archiveBytes, cargoPath)).toString("utf8");
const vcs = JSON.parse((await readArchiveEntry(archiveBytes, vcsPath)).toString("utf8"));
const packageSection = tomlSection(cargo, "package");
assert.equal(tomlValue(packageSection, "name"), `"${crateName}"`);
assert.equal(tomlValue(packageSection, "version"), `"${version}"`);
assert.equal(vcs.git?.sha1, sourceSHA);
if (crateName === "flowersec") {
  const dependencySection = tomlSection(cargo, "dependencies.flowersec-native-transport");
  assert.equal(tomlValue(dependencySection, "version"), `"=${version}"`);
  assert.equal(dependencySection.some((line) => line.startsWith("path =") || line.startsWith("git =")), false);
}

function assertRegistryURL(value, allowedHosts, redirectedFrom = undefined) {
  const url = new URL(value);
  assert.equal(url.protocol, "https:");
  assert.ok(allowedHosts.has(url.hostname), `unexpected registry download host ${url.hostname}`);
  if (redirectedFrom !== undefined) {
    const source = new URL(redirectedFrom);
    assert.equal(source.hostname, "crates.io");
    assert.equal(url.hostname, "static.crates.io");
  }
}

function isRetryableRegistryError(error) {
  if (error?.retryable !== undefined) return error.retryable;
  return /timed out|fetch failed|ECONNRESET|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|socket/i.test(`${error?.code ?? ""} ${error?.message ?? ""}`);
}

function tomlSection(source, name) {
  const lines = source.split("\n").map((line) => line.trim());
  const heading = `[${name}]`;
  assert.equal(lines.filter((line) => line === heading).length, 1, `expected one ${heading} section`);
  const start = lines.indexOf(heading);
  assert.notEqual(start, -1, `missing [${name}] section`);
  const end = lines.findIndex((line, index) => index > start && line.startsWith("[") && line.endsWith("]"));
  return lines.slice(start + 1, end < 0 ? undefined : end);
}

function tomlValue(section, key) {
  const prefix = `${key} =`;
  const matches = section.filter((line) => line.startsWith(prefix));
  assert.equal(matches.length, 1, `expected one ${key} field`);
  return matches[0].slice(prefix.length).trim();
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
    }, 30_000);
    const fail = (error) => {
      if (settled) return;
      clearTimeout(timer);
      const terminationError = terminate();
      settled = true;
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
        reject(new Error("tar readback timed out after 30000ms"));
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
