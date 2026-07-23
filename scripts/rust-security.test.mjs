import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const checkerPath = path.join(sourceRoot, "scripts/check-rust-security.mjs");

async function loadChecker() {
  assert.ok(fs.existsSync(checkerPath), "scripts/check-rust-security.mjs must exist");
  return import(pathToFileURL(checkerPath));
}

test("Rust security inventory includes main, fuzz, and example lock contexts", async () => {
  const { rustSecurityContexts } = await loadChecker();
  assert.deepEqual(rustSecurityContexts(sourceRoot), [
    {
      manifest: path.join(sourceRoot, "flowersec-rust/Cargo.toml"),
      lockfile: path.join(sourceRoot, "flowersec-rust/Cargo.lock"),
    },
    {
      manifest: path.join(sourceRoot, "flowersec-rust/fuzz/Cargo.toml"),
      lockfile: path.join(sourceRoot, "flowersec-rust/fuzz/Cargo.lock"),
    },
    {
      manifest: path.join(sourceRoot, "examples/rust/Cargo.toml"),
      lockfile: path.join(sourceRoot, "examples/rust/Cargo.lock"),
    },
  ]);
});

test("every Rust lock is audited and denied without suppressions", async () => {
  const { runRustSecurityChecks } = await loadChecker();
  const calls = [];
  const run = (command, args, options) => {
    calls.push({ command, args, options });
    if (args.join(" ") === "audit --version") return "cargo-audit-audit 0.22.2\n";
    if (args.join(" ") === "deny --version") return "cargo-deny 0.19.9\n";
    return "";
  };

  runRustSecurityChecks({ repoRoot: sourceRoot, run });
  assert.equal(calls.length, 8);
  for (const context of [
    ["flowersec-rust/Cargo.toml", "flowersec-rust/Cargo.lock"],
    ["flowersec-rust/fuzz/Cargo.toml", "flowersec-rust/fuzz/Cargo.lock"],
    ["examples/rust/Cargo.toml", "examples/rust/Cargo.lock"],
  ]) {
    const manifest = path.join(sourceRoot, context[0]);
    const lockfile = path.join(sourceRoot, context[1]);
    assert.ok(calls.some((call) => call.command === "cargo"
      && JSON.stringify(call.args) === JSON.stringify([
        "audit", "--file", lockfile, "--deny", "warnings",
      ])));
    assert.ok(calls.some((call) => call.command === "cargo"
      && JSON.stringify(call.args) === JSON.stringify([
        "deny", "--manifest-path", manifest, "--locked", "--all-features",
        "check", "--config", path.join(sourceRoot, "flowersec-rust/deny.toml"),
      ])));
  }
});

test("Rust security policy has no advisory suppression and is wired to release checks", async () => {
  await loadChecker();
  const policy = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/deny.toml"), "utf8");
  assert.match(policy, /^\[advisories\]\nignore = \[\]$/m);
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(makefile, /^rust-audit:\n\tnode scripts\/check-rust-security\.mjs$/m);
});

test("non-published Rust roots remain licensed and version their local Flowersec edge", () => {
  for (const manifestPath of [
    "flowersec-rust/fuzz/Cargo.toml",
    "examples/rust/Cargo.toml",
  ]) {
    const manifest = fs.readFileSync(path.join(sourceRoot, manifestPath), "utf8");
    assert.match(manifest, /^license = "MIT"$/m, `${manifestPath} must declare its license`);
    assert.match(
      manifest,
      /^flowersec = \{ version = "=0\.28\.0", path = "[^"]+" \}$/m,
      `${manifestPath} must not use a wildcard local dependency`,
    );
  }
  const policy = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/deny.toml"), "utf8");
  assert.match(policy, /^  "NCSA",$/m);
});
