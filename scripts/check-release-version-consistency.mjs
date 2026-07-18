#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const releaseSources = [
  "flowersec-ts/package.json",
  "flowersec-ts/package-lock.json",
  "flowersec-rust/Cargo.toml",
  "flowersec-rust/Cargo.lock",
  "flowersec-rust/fuzz/Cargo.lock",
  "examples/rust/Cargo.lock",
];

function readJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`cannot read ${filePath}: ${error.message}`);
  }
}

function requireVersion(value, label) {
  if (typeof value !== "string" || !/^\d+\.\d+\.\d+$/.test(value)) {
    throw new Error(`${label} must contain a semantic version`);
  }
  return value;
}

function cargoMetadataVersion(manifestPath) {
  const cargo = process.env.CARGO || "cargo";
  const result = spawnSync(
    cargo,
    ["metadata", "--locked", "--format-version", "1", "--manifest-path", manifestPath],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  if (result.status !== 0) {
    const details = result.error?.message || result.stderr || result.stdout;
    throw new Error(
      `cargo metadata failed for ${manifestPath}: ${details}`.trim(),
    );
  }

  let metadata;
  try {
    metadata = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`cargo metadata returned invalid JSON for ${manifestPath}: ${error.message}`);
  }
  const packages = metadata.packages?.filter(
    (pkg) => pkg.name === "flowersec" && pkg.source === null,
  );
  if (!Array.isArray(packages) || packages.length !== 1) {
    throw new Error(`cargo metadata for ${manifestPath} must contain one local flowersec package`);
  }
  return requireVersion(packages[0].version, manifestPath);
}

export function collectReleaseVersions(
  root,
  { cargoMetadata = cargoMetadataVersion } = {},
) {
  const tsPackagePath = path.join(root, "flowersec-ts/package.json");
  const tsLockPath = path.join(root, "flowersec-ts/package-lock.json");
  const tsPackage = readJSON(tsPackagePath);
  const tsLock = readJSON(tsLockPath);
  const tsPackageVersion = requireVersion(
    tsPackage.version,
    "flowersec-ts/package.json",
  );
  const tsLockVersion = requireVersion(
    tsLock.version,
    "flowersec-ts/package-lock.json",
  );
  const tsLockRootVersion = requireVersion(
    tsLock.packages?.[""]?.version,
    "flowersec-ts/package-lock.json packages['']",
  );
  if (tsLockVersion !== tsLockRootVersion) {
    throw new Error(
      `flowersec-ts/package-lock.json contains inconsistent versions: ${tsLockVersion} and ${tsLockRootVersion}`,
    );
  }

  const rustManifestVersion = cargoMetadata(
    path.join(root, "flowersec-rust/Cargo.toml"),
  );
  const fuzzLockVersion = cargoMetadata(
    path.join(root, "flowersec-rust/fuzz/Cargo.toml"),
  );
  const exampleLockVersion = cargoMetadata(
    path.join(root, "examples/rust/Cargo.toml"),
  );

  return [
    { label: releaseSources[0], version: tsPackageVersion },
    { label: releaseSources[1], version: tsLockVersion },
    { label: releaseSources[2], version: rustManifestVersion },
    { label: releaseSources[3], version: rustManifestVersion },
    { label: releaseSources[4], version: fuzzLockVersion },
    { label: releaseSources[5], version: exampleLockVersion },
  ];
}

export function validateReleaseVersions(versions, expectedVersion = "") {
  const byLabel = new Map(versions.map((entry) => [entry.label, entry.version]));
  const missing = releaseSources.filter((label) => !byLabel.has(label));
  const extra = [...byLabel.keys()].filter((label) => !releaseSources.includes(label));
  if (missing.length > 0 || extra.length > 0 || versions.length !== releaseSources.length) {
    throw new Error(
      `release version sources must match the maintained set; missing=${missing.join(",") || "none"}, extra=${extra.join(",") || "none"}`,
    );
  }

  for (const label of releaseSources) {
    requireVersion(byLabel.get(label), label);
  }
  const distinct = new Set(releaseSources.map((label) => byLabel.get(label)));
  if (distinct.size !== 1) {
    const facts = releaseSources
      .map((label) => `${label}=${byLabel.get(label)}`)
      .join(", ");
    throw new Error(`release versions are inconsistent: ${facts}`);
  }

  const version = byLabel.get(releaseSources[0]);
  if (expectedVersion !== "" && version !== expectedVersion) {
    throw new Error(
      `requested release version ${expectedVersion} does not match maintained version ${version}`,
    );
  }
  return version;
}

function main() {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const expectedVersion = process.argv[2] || "";
  if (process.argv.length > 3) {
    throw new Error("usage: scripts/check-release-version-consistency.mjs [version]");
  }
  const version = validateReleaseVersions(
    collectReleaseVersions(root),
    expectedVersion,
  );
  process.stdout.write(`release versions OK: ${version} across ${releaseSources.length} sources\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
