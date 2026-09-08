import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readToolchains, checkRuntime, repositoryRoot } from "./toolchains.mjs";
import { verifyToolchainPolicy } from "./check-toolchain-policy.mjs";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-toolchains-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const ignored = new Set([".git", ".build", ".swiftpm", ".flowersec", "node_modules", "target", "dist", "coverage", "sbom"]);
  fs.cpSync(repositoryRoot, root, { recursive: true, filter: (source) => !ignored.has(path.basename(source)) });
  return root;
}

test("maintained toolchain declarations satisfy one policy", () => verifyToolchainPolicy());

test("independent declaration drift and removal of enforcement fail closed", (t) => {
  const root = fixture(t);
  for (const [file, from, to, error] of [
    [".nvmrc", "26.8.1", "24.20.0", /\.nvmrc/],
    ["scripts/test-host-init.sh", "readonly node_version=26.8.1", "readonly node_version=24.20.0", /test host node/],
    ["flowersec-ts/package.json", '"node": ">=24.20.0"', '"node": ">=26.8.1"', /Node minimum/],
    ["rust-toolchain.toml", 'channel = "1.98.0"', 'channel = "stable"', /rust-toolchain/],
    ["flowersec-native-transport/Cargo.toml", 'rust-version = "1.88"', 'rust-version = "1.98"', /Cargo.toml/],
    ["examples/swift/Package.swift", "swift-tools-version: 6.1", "swift-tools-version: 6.3", /Package.swift/],
    ["scripts/test-host-init.sh", "readonly swift_version=6.3.1", "readonly swift_version=6.1.3", /test host swift/],
    ["Makefile", "export GOTOOLCHAIN := local", "export GOTOOLCHAIN := auto", /automatic Go/],
    ["Makefile", "test:\n\tnode scripts/toolchains.mjs --check-runtime go node rust swift\n", "test:\n", /test must validate/],
    ["Makefile", "cargo semver-checks", "cargo +stable semver-checks", /floating toolchains/],
  ]) {
    const location = path.join(root, file);
    const original = fs.readFileSync(location, "utf8");
    assert.ok(original.includes(from), `fixture must modify ${file}`);
    fs.writeFileSync(location, original.replace(from, to));
    assert.throws(() => verifyToolchainPolicy(root), error);
    fs.writeFileSync(location, original);
  }
});

test("authoritative config rejects floating, missing and unknown version fields", (t) => {
  const root = fixture(t);
  for (const mutate of [
    (config) => { config.rust.version = "stable"; },
    (config) => { config.rust.nightly = "nightly"; },
    (config) => { delete config.go.version; },
    (config) => { config.node.fallback = "latest"; },
    (config) => { config.node.minimum = "99.0.0"; },
  ]) {
    const config = structuredClone(readToolchains());
    mutate(config);
    fs.writeFileSync(path.join(root, "toolchains.json"), JSON.stringify(config));
    assert.throws(() => readToolchains(root), /exact version|invalid|must satisfy/);
  }
});

test("new scripts cannot hide compiler pins in multiline argument arrays", (t) => {
  const root = fixture(t);
  const script = path.join(root, "scripts/new-build.mjs");
  fs.writeFileSync(script, 'run("rustup", [\n  "run",\n  "1.88.0",\n  "cargo", "build"\n]);\n');
  assert.throws(() => verifyToolchainPolicy(root), /new-build.mjs must obtain Rust versions/);
  fs.writeFileSync(script, 'const environment = { GOTOOLCHAIN: "go1.27.0" };\n');
  assert.throws(() => verifyToolchainPolicy(root), /new-build.mjs must obtain Go versions/);
});

test("runtime detects mismatched tools before work and distinguishes explicit compatibility roles", () => {
  const config = readToolchains();
  const run = (command, args, options) => {
    if (command === "go") assert.equal(options.env.GOTOOLCHAIN, "local");
    const outputs = { go: `go version go${config.go.version} darwin/arm64`, node: `v${config.node.version}`,
      rustc: `rustc ${config.rust.version} (fixture)`, swift: `Apple Swift version ${config.swift.version} (fixture)`,
      xcodebuild: `Xcode ${config.swift.xcode}\nBuild version fixture` };
    return { status: 0, stdout: outputs[command] };
  };
  checkRuntime(["go", "node", "rust", "swift"], { run, env: {}, platform: "darwin" });
  assert.throws(() => checkRuntime(["go"], { run, env: { GOTOOLCHAIN: "auto" } }), /GOTOOLCHAIN/);
  for (const language of ["go", "node", "rust", "swift"]) {
    assert.throws(() => checkRuntime([language], { env: {}, platform: "linux", run: () => ({ status: 0, stdout: "unexpected version" }) }), /expected.*actual/);
  }
  const nodeMinimum = () => ({ status: 0, stdout: `v${config.node.minimum}` });
  assert.throws(() => checkRuntime(["node"], { run: nodeMinimum }), /node: expected/);
  checkRuntime(["node-minimum"], { run: nodeMinimum });
  assert.throws(() => checkRuntime(["node-minimum"], { run }), /node-minimum: expected/);
  const minimum = () => ({ status: 0, stdout: `rustc ${config.rust.msrv} (fixture)` });
  assert.throws(() => checkRuntime(["rust"], { run: minimum }), /rust: expected/);
  checkRuntime(["rust-msrv"], { run: minimum });
  const compilers = (_command, args) => ({ status: 0, stdout: `Version ${args[0].endsWith("/tsc6") ? config.typescript.compatibilityVersion : config.typescript.version}` });
  checkRuntime(["typescript"], { run: compilers });
  assert.throws(() => checkRuntime(["typescript"], {
    run: () => ({ status: 0, stdout: `Version ${config.typescript.version}` }),
  }), /TypeScript compatibility compiler: expected/);
  for (const key of ["RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"]) {
    assert.throws(() => checkRuntime(["rust"], { run, env: { [key]: "/another/compiler" } }), /must be unset/);
  }
  assert.throws(() => checkRuntime(["go"], { env: {}, run: () => ({ status: 1, stderr: "missing compiler" }) }), /cannot inspect go/);
});
