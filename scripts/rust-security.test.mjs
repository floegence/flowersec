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

test("Rust security inventory includes every maintained Cargo root", async () => {
  const { rustSecurityContexts } = await loadChecker();
  assert.deepEqual(rustSecurityContexts(sourceRoot), [
    {
      manifest: path.join(sourceRoot, "flowersec-rust/Cargo.toml"),
      lockfile: path.join(sourceRoot, "flowersec-rust/Cargo.lock"),
    },
    {
      manifest: path.join(sourceRoot, "flowersec-native-transport/Cargo.toml"),
      lockfile: path.join(sourceRoot, "flowersec-native-transport/Cargo.lock"),
    },
    {
      manifest: path.join(sourceRoot, "flowersec-node-native/Cargo.toml"),
      lockfile: path.join(sourceRoot, "flowersec-node-native/Cargo.lock"),
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
  assert.equal(calls.length, 12);
  for (const context of [
    ["flowersec-rust/Cargo.toml", "flowersec-rust/Cargo.lock"],
    ["flowersec-native-transport/Cargo.toml", "flowersec-native-transport/Cargo.lock"],
    ["flowersec-node-native/Cargo.toml", "flowersec-node-native/Cargo.lock"],
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

test("final Rust security checks reuse the preflight database without network access", async () => {
  const { runRustSecurityChecks } = await loadChecker();
  const calls = [];
  const run = (command, args) => {
    calls.push({ command, args });
    if (args.join(" ") === "audit --version") return "cargo-audit-audit 0.22.2\n";
    if (args.join(" ") === "deny --version") return "cargo-deny 0.19.9\n";
    return "";
  };

  runRustSecurityChecks({ repoRoot: sourceRoot, run, offline: true });
  const audits = calls.filter((call) => call.args[0] === "audit" && call.args[1] !== "--version");
  const denies = calls.filter((call) => call.args[0] === "deny" && call.args[1] !== "--version");
  assert.equal(audits.length, 5);
  assert.equal(denies.length, 5);
  for (const call of audits) assert.ok(call.args.includes("--no-fetch"));
  for (const call of denies) assert.ok(call.args.includes("--disable-fetch"));
});

test("Rust security policy has no advisory suppression and is wired to release checks", async () => {
  await loadChecker();
  const policy = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/deny.toml"), "utf8");
  assert.match(policy, /^\[advisories\]\nignore = \[\]$/m);
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(makefile, /^rust-audit:\n\tnode scripts\/check-rust-security\.mjs$/m);
});

test("non-published Rust roots remain licensed and version their local Flowersec edge", () => {
  const publishedManifest = fs.readFileSync(
    path.join(sourceRoot, "flowersec-rust/Cargo.toml"),
    "utf8",
  );
  const publishedVersion = publishedManifest.match(/^version = "(\d+\.\d+\.\d+)"$/m)?.[1];
  assert.ok(publishedVersion, "flowersec-rust/Cargo.toml must declare a release version");
  const escapedVersion = publishedVersion.replaceAll(".", "\\.");
  for (const manifestPath of [
    "flowersec-rust/fuzz/Cargo.toml",
    "examples/rust/Cargo.toml",
  ]) {
    const manifest = fs.readFileSync(path.join(sourceRoot, manifestPath), "utf8");
    assert.match(manifest, /^license = "MIT"$/m, `${manifestPath} must declare its license`);
    assert.match(
      manifest,
      new RegExp(
        `^flowersec = \\{ version = "=${escapedVersion}", path = "[^"]+"(?:, features = \\["__flowersec_internal_fuzzing"\\])? \\}$`,
        "m",
      ),
      `${manifestPath} must not use a wildcard local dependency`,
    );
  }
  const policy = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/deny.toml"), "utf8");
  assert.match(policy, /^  "NCSA",$/m);
});

test("Rust native runtime owns carrier trust without implicit platform root stores", () => {
  const manifest = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/Cargo.toml"), "utf8");
  const readme = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/README.md"), "utf8");
  const connector = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/src/connector_v2.rs"), "utf8");
  const runtime = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/src/native_runtime_v2.rs"), "utf8");
  const crateRoot = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/src/lib.rs"), "utf8");
  const fuzzManifest = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/fuzz/Cargo.toml"), "utf8");

  assert.match(
    manifest,
    /^\[features\]\ndefault = \[\]\n__flowersec_internal_fuzzing = \[\]$/m,
  );
  assert.match(crateRoot, /#\[cfg\(feature = "__flowersec_internal_fuzzing"\)\]\n#\[doc\(hidden\)\]\npub mod fuzzing/u);
  assert.match(fuzzManifest, /features = \["__flowersec_internal_fuzzing"\]/u);
  assert.doesNotMatch(manifest, /rustls-(?:native|webpki)-roots/u);
  assert.match(
    manifest,
    /^tokio-tungstenite = \{ version = "[^"]+", default-features = false, features = \["connect"\] \}$/m,
  );
  assert.match(readme, /CA candidates use platform trust roots by default/u);
  assert.match(readme, /Pin candidates use\s+only the active leaf-certificate SHA-256 pins/u);
  assert.match(readme, /never fall back to CA verification/u);
  assert.match(readme, /No system trust store is selected\s+implicitly outside the explicit CA policy/u);
  assert.doesNotMatch(readme, /plaintext direct WebSocket/u);
  assert.doesNotMatch(connector, /impl Default for ConnectorOptions/u);
  assert.doesNotMatch(connector, /trust_roots_der/u);
  assert.match(runtime, /pub fn new\(\) -> Self/u);
  assert.match(runtime, /pub fn with_trust_roots_der\(/u);
});

test("serde_with is absent or patched for GHSA-7gcf-g7xr-8hxj without drifting the published MSRV", async () => {
  const { rustSecurityContexts } = await loadChecker();
  for (const { lockfile } of rustSecurityContexts(sourceRoot)) {
    const lock = fs.readFileSync(lockfile, "utf8");
    const match = lock.match(/\[\[package\]\]\nname = "serde_with"\nversion = "(\d+)\.(\d+)\.(\d+)"/u);
    if (match == null) continue;
    const version = match.slice(1).map(Number);
    assert.ok(
      version[0] > 3 || (version[0] === 3 && (version[1] > 21 || (version[1] === 21 && version[2] >= 0))),
      `${path.relative(sourceRoot, lockfile)} must use serde_with 3.21.0 or newer`,
    );
  }

  const manifest = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/Cargo.toml"), "utf8");
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const readme = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/README.md"), "utf8");
  assert.match(manifest, /^rust-version = "1\.88"$/m);
  assert.match(makefile, /^\tcd flowersec-rust && rustup run 1\.88\.0 cargo check --all-targets --all-features$/m);
  assert.match(readme, /targets Rust 1\.88 or newer/);

  const releaseCargoRecipes = makefile
    .split("\n")
    .filter((line) => /\bcargo (?:fmt|clippy|test|doc|check|package|publish|llvm-cov)\b/u.test(line));
  assert.ok(releaseCargoRecipes.length > 0, "Makefile must retain Rust release cargo recipes");
  for (const line of releaseCargoRecipes) {
    assert.match(
      line,
      /\brustup run 1\.88\.0 cargo\b/u,
      `Rust release recipe must use the published MSRV toolchain: ${line}`,
    );
  }
});
