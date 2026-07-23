#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const cargoAuditVersion = "0.22.2";
const cargoDenyVersion = "0.19.9";

function defaultRun(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: { ...process.env, ...options.env },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr}`,
    );
  }
  return result.stdout;
}

export function rustSecurityContexts(repoRoot) {
  return [
    {
      manifest: path.join(repoRoot, "flowersec-rust/Cargo.toml"),
      lockfile: path.join(repoRoot, "flowersec-rust/Cargo.lock"),
    },
    {
      manifest: path.join(repoRoot, "flowersec-rust/fuzz/Cargo.toml"),
      lockfile: path.join(repoRoot, "flowersec-rust/fuzz/Cargo.lock"),
    },
    {
      manifest: path.join(repoRoot, "examples/rust/Cargo.toml"),
      lockfile: path.join(repoRoot, "examples/rust/Cargo.lock"),
    },
  ];
}

function assertToolVersion(output, expected, label) {
  const escaped = expected.replaceAll(".", "\\.");
  if (!new RegExp(`(?:^|\\s)${escaped}(?:\\s|$)`).test(output.trim())) {
    throw new Error(`${label} must be ${expected}, got: ${output.trim()}`);
  }
}

export function runRustSecurityChecks({ repoRoot, run = defaultRun }) {
  assertToolVersion(run("cargo", ["audit", "--version"], { cwd: repoRoot }), cargoAuditVersion, "cargo-audit");
  assertToolVersion(run("cargo", ["deny", "--version"], { cwd: repoRoot }), cargoDenyVersion, "cargo-deny");

  const denyConfig = path.join(repoRoot, "flowersec-rust/deny.toml");
  const contexts = rustSecurityContexts(repoRoot);
  for (const context of contexts) {
    for (const requiredFile of [context.manifest, context.lockfile, denyConfig]) {
      if (!fs.existsSync(requiredFile)) throw new Error(`missing Rust security input: ${requiredFile}`);
    }
    run(
      "cargo",
      ["audit", "--file", context.lockfile, "--deny", "warnings"],
      { cwd: repoRoot },
    );
    run(
      "cargo",
      [
        "deny", "--manifest-path", context.manifest, "--locked", "--all-features",
        "check", "--config", denyConfig,
      ],
      { cwd: repoRoot },
    );
  }
  return contexts;
}

function main() {
  if (process.argv.length !== 2) throw new Error("usage: check-rust-security.mjs");
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  for (const context of runRustSecurityChecks({ repoRoot })) {
    process.stdout.write(`verified ${path.relative(repoRoot, context.lockfile)}\n`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
