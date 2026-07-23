#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function comparePackages(left, right) {
  if (left.name !== right.name) return left.name < right.name ? -1 : 1;
  if (left.version !== right.version) return left.version < right.version ? -1 : 1;
  return 0;
}

function run(command, args, cwd, environment = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr}`);
  }
  return result.stdout;
}

function readJSON(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

export function collectNpmPackages(lockfile) {
  if (!lockfile || typeof lockfile.packages !== "object" || lockfile.packages === null) {
    throw new Error("npm lockfile has no packages object");
  }
  const unique = new Map();
  for (const [packagePath, metadata] of Object.entries(lockfile.packages)) {
    const marker = "node_modules/";
    const markerIndex = packagePath.lastIndexOf(marker);
    if (markerIndex < 0 || metadata.link === true) continue;
    const name = packagePath.slice(markerIndex + marker.length);
    if (!name || typeof metadata.version !== "string" || metadata.version === "") {
      throw new Error(`npm package ${packagePath} has no exact version`);
    }
    if (typeof metadata.license !== "string" || metadata.license === "") {
      throw new Error(`npm package ${name}@${metadata.version} has no license identifier`);
    }
    const key = `${name}\0${metadata.version}`;
    const value = { name, version: metadata.version, license: metadata.license };
    const previous = unique.get(key);
    if (previous && previous.license !== value.license) {
      throw new Error(`npm package ${name}@${metadata.version} has conflicting licenses`);
    }
    unique.set(key, value);
  }
  return [...unique.values()].sort(comparePackages);
}

export function collectPublishedRustPackages(metadata) {
  if (!metadata?.resolve?.root || !Array.isArray(metadata.resolve.nodes) || !Array.isArray(metadata.packages)) {
    throw new Error("cargo metadata has no resolved package graph");
  }
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  const packages = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const visited = new Set([metadata.resolve.root]);
  const pending = [metadata.resolve.root];
  while (pending.length > 0) {
    const id = pending.shift();
    const node = nodes.get(id);
    if (!node) throw new Error(`cargo metadata is missing resolve node ${id}`);
    for (const dependency of node.deps ?? []) {
      const kinds = dependency.dep_kinds ?? [];
      const isPublishedDependency = kinds.length === 0 || kinds.some((entry) => entry.kind !== "dev");
      if (!isPublishedDependency || visited.has(dependency.pkg)) continue;
      visited.add(dependency.pkg);
      pending.push(dependency.pkg);
    }
  }
  const result = [];
  for (const id of visited) {
    const pkg = packages.get(id);
    if (!pkg) throw new Error(`cargo metadata is missing package ${id}`);
    if (pkg.source === null) continue;
    if (typeof pkg.license !== "string" || pkg.license === "") {
      throw new Error(`Rust crate ${pkg.name}@${pkg.version} has no license identifier`);
    }
    result.push({ name: pkg.name, version: pkg.version, license: pkg.license });
  }
  return result.sort(comparePackages);
}

function collectGoModules(repoRoot, licenseMap) {
  const template = '{{if .Version}}{{printf "%s\\t%s" .Path .Version}}{{end}}';
  const output = run(
    "go",
    ["list", "-m", "-f", template, "all"],
    repoRoot,
    { GOWORK: path.join(repoRoot, "go.work") },
  );
  const modules = output.split("\n").filter(Boolean).map((line) => {
    const [name, version, extra] = line.split("\t");
    if (!name || !version || extra !== undefined) throw new Error(`invalid go list module line: ${line}`);
    const license = licenseMap[name];
    if (!license?.license || !license?.file) {
      throw new Error(`Go module ${name} is missing from scripts/third-party-go-licenses.json`);
    }
    return { name, version, license: license.license, file: license.file };
  }).sort(comparePackages);
  const selected = new Set(modules.map((module) => module.name));
  const staleMappings = Object.keys(licenseMap).filter((name) => !selected.has(name));
  if (staleMappings.length > 0) {
    throw new Error(`stale Go license mappings: ${staleMappings.sort().join(", ")}`);
  }
  return modules;
}

function collectRustMetadata(repoRoot) {
  const output = run(
    "cargo",
    [
      "metadata",
      "--manifest-path", path.join(repoRoot, "flowersec-rust/Cargo.toml"),
      "--locked",
      "--all-features",
      "--format-version=1",
    ],
    repoRoot,
  );
  return JSON.parse(output);
}

export function renderNotices(inventory) {
  const lines = [
    "# Third Party Notices",
    "",
    "This repository includes third-party open source software through the Go workspace, npm package lock, and the published Rust crate dependency graph.",
    "",
    "Data sources:",
    "- Go workspace build list from the repository root (`go list -m all` under `go.work`; local workspace modules excluded)",
    "- npm package entries from `flowersec-ts/package-lock.json` as unique `name@version` pairs",
    "- non-development dependency closure of the published `flowersec-rust` crate from locked Cargo metadata with all crate features enabled",
    "",
    "License identifiers are derived from the reviewed Go module mapping, npm lock metadata, and Cargo package metadata.",
    "For authoritative license texts and copyright notices, refer to each upstream project.",
    "",
    "## Go Modules",
    "",
    ...inventory.go.map((entry) => `- ${entry.name} ${entry.version} (License: ${entry.license}; File: ${entry.file})`),
    "",
    "## npm Packages",
    "",
    ...inventory.npm.map((entry) => `- ${entry.name}@${entry.version} (License: ${entry.license})`),
    "",
    "## Rust Crates",
    "",
    ...inventory.rust.map((entry) => `- ${entry.name}@${entry.version} (License: ${entry.license})`),
    "",
  ];
  return lines.join("\n");
}

export function generateNotices(repoRoot) {
  const licenseMap = readJSON(path.join(repoRoot, "scripts/third-party-go-licenses.json"));
  return renderNotices({
    go: collectGoModules(repoRoot, licenseMap),
    npm: collectNpmPackages(readJSON(path.join(repoRoot, "flowersec-ts/package-lock.json"))),
    rust: collectPublishedRustPackages(collectRustMetadata(repoRoot)),
  });
}

export function checkNoticesContent(expected, actual) {
  if (actual !== expected) {
    throw new Error("THIRD_PARTY_NOTICES.md is out of date; run `make third-party-notices`");
  }
}

function main() {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const noticesPath = path.join(repoRoot, "THIRD_PARTY_NOTICES.md");
  const expected = generateNotices(repoRoot);
  if (process.argv.length === 2) {
    writeFileSync(noticesPath, expected);
    process.stdout.write("updated THIRD_PARTY_NOTICES.md\n");
    return;
  }
  if (process.argv.length === 3 && process.argv[2] === "--check") {
    checkNoticesContent(expected, readFileSync(noticesPath, "utf8"));
    process.stdout.write("THIRD_PARTY_NOTICES.md is current\n");
    return;
  }
  throw new Error("usage: generate-third-party-notices.mjs [--check]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
