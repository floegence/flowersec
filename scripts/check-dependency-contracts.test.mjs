import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const checker = path.join(repositoryRoot, "scripts/check-dependency-contracts.mjs");

function write(root, relativePath, contents) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
}

function baselineContract() {
  return {
    version: 1,
    dependencies: [
      {
        ecosystem: "gomod",
        package: "github.com/quic-go/quic-go",
        boundary: "go-raw-quic",
        scope: "production",
        requiredCapabilities: ["client", "server", "bidi-stream", "datagram", "close"],
        protocol: "quic-rfc-9000-rfc-9221",
        publicApiOnly: true,
        platforms: ["linux-amd64", "linux-arm64", "macos-arm64"],
        conformanceTests: ["carrier/go-direct"],
        upgradeGroup: "go-webtransport-stack",
      },
      {
        ecosystem: "gomod",
        package: "github.com/quic-go/webtransport-go",
        boundary: "go-webtransport",
        scope: "production",
        requiredCapabilities: ["client", "server", "bidi-stream", "datagram", "origin", "close"],
        protocol: "webtransport-over-http3",
        publicApiOnly: true,
        platforms: ["linux-amd64", "linux-arm64", "macos-arm64"],
        conformanceTests: ["carrier/go-direct"],
        upgradeGroup: "go-webtransport-stack",
      },
      {
        ecosystem: "cargo",
        package: "quinn",
        boundary: "rust-raw-quic",
        scope: "production",
        requiredCapabilities: ["client", "server", "bidi-stream", "datagram", "close"],
        protocol: "quic-rfc-9000-rfc-9221",
        publicApiOnly: true,
        platforms: ["linux-amd64", "linux-arm64", "macos-arm64"],
        conformanceTests: ["interop/rust-go/raw-quic/direct"],
        upgradeGroup: "rust-quic-stack",
      },
      {
        ecosystem: "cargo",
        package: "rustls",
        boundary: "rust-tls",
        scope: "production",
        requiredCapabilities: ["tls-1.3", "explicit-trust-roots"],
        protocol: "tls-1.3",
        publicApiOnly: true,
        platforms: ["linux-amd64", "linux-arm64", "macos-arm64"],
        conformanceTests: ["protocol/rust"],
        upgradeGroup: "rust-quic-stack",
      },
      {
        ecosystem: "npm",
        package: "ws",
        boundary: "node-websocket",
        scope: "production",
        requiredCapabilities: ["client", "server", "close"],
        protocol: "websocket-rfc-6455",
        publicApiOnly: true,
        platforms: ["linux-amd64", "linux-arm64", "macos-arm64"],
        conformanceTests: ["interop/typescript-go/wss/direct"],
        upgradeGroup: null,
      },
      {
        ecosystem: "swiftpm",
        package: "async-http-client",
        boundary: "swift-websocket",
        scope: "production",
        requiredCapabilities: ["client", "explicit-trust-roots", "close"],
        protocol: "websocket-rfc-6455",
        publicApiOnly: true,
        platforms: ["macos-arm64", "ios-arm64"],
        conformanceTests: ["interop/swift-go/wss/direct"],
        upgradeGroup: null,
      },
    ],
  };
}

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-dependency-contract-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  write(root, "stability/dependency_contracts.json", `${JSON.stringify(baselineContract(), null, 2)}\n`);
  write(root, "flowersec-go/go.mod", `module example.com/fixture\n\ngo 1.26\n\nrequire (\n\tgithub.com/quic-go/quic-go v0.61.0\n\tgithub.com/quic-go/webtransport-go v0.12.0\n)\n`);
  write(root, "flowersec-go/go.sum", "github.com/quic-go/quic-go v0.61.0 h1:fixture\ngithub.com/quic-go/webtransport-go v0.12.0 h1:fixture\n");
  write(root, "flowersec-rust/Cargo.toml", `[package]\nname = "fixture"\nversion = "0.1.0"\n\n[dependencies]\nquinn = "=0.11.11"\nrustls = { version = "0.23", default-features = false, features = ["ring", "std"] }\n`);
  write(root, "flowersec-rust/Cargo.lock", `version = 4\n\n[[package]]\nname = "quinn"\nversion = "0.11.11"\n\n[[package]]\nname = "rustls"\nversion = "0.23.0"\n`);
  write(root, "flowersec-ts/package.json", `${JSON.stringify({ engines: { node: ">=24.20.0" }, dependencies: { ws: "8.21.2" } }, null, 2)}\n`);
  write(root, "flowersec-ts/package-lock.json", `${JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { ws: "8.21.2" } }, "node_modules/ws": { version: "8.21.2", integrity: "sha512-fixture", engines: { node: ">=10.0.0" } } } }, null, 2)}\n`);
  const swiftLock = { version: 3, pins: [{ identity: "async-http-client", state: { revision: "abc", version: "1.36.0" } }] };
  write(root, "Package.resolved", `${JSON.stringify(swiftLock, null, 2)}\n`);
  write(root, "examples/swift/Package.resolved", `${JSON.stringify(swiftLock, null, 2)}\n`);
  write(root, "flowersec-ts/src/node/adapter.ts", "export const adapter = true;\n");
  write(root, "flowersec-rust/src/lib.rs", "pub fn fixture() {}\n");
  write(root, "flowersec-go/internal/cmd/flowersec-test/registry.go", `package main\nfunc registry() {\n commandEntry("carrier/go-direct")\n commandEntry("interop/rust-go/raw-quic/direct")\n commandEntry("protocol/rust")\n commandEntry("interop/typescript-go/wss/direct")\n commandEntry("interop/swift-go/wss/direct")\n}\n`);
  return root;
}

function runChecker(root) {
  return spawnSync(process.execPath, [checker, "--root", root], { encoding: "utf8" });
}

function expectFailure(t, mutate, pattern) {
  const root = createFixture(t);
  mutate(root);
  const result = runChecker(root);
  assert.notEqual(result.status, 0, "invalid dependency fixture unexpectedly passed");
  assert.match(result.stderr, pattern);
}

test("dependency contract schema and a valid fixture pass", (t) => {
  const result = runChecker(createFixture(t));
  assert.equal(result.status, 0, result.stderr);
});

test("Cargo protocol patches and vendored transport stacks are rejected", (t) => {
  expectFailure(t, (root) => {
    fs.appendFileSync(path.join(root, "flowersec-rust/Cargo.toml"), "\n[patch.crates-io]\nwtransport-proto = { path = \"vendor/wtransport-proto\" }\n");
    write(root, "flowersec-rust/vendor/wtransport-proto/src/lib.rs", "// vendored protocol\n");
  }, /local Cargo protocol patch|vendored transport\/protocol stack/);
});

test("private Node dependency subpaths and native fields are rejected", (t) => {
  expectFailure(t, (root) => {
    write(root, "flowersec-ts/src/node/adapter.ts", `import type { QUICConnection } from "@matrixai/quic/native/types.js";\nexport const bridge = (value) => value.dgramSendVec ?? value.conn;\n`);
  }, /private dependency subpath|private native field/);
});

test("Node engines cover every direct production dependency minimum", (t) => {
  expectFailure(t, (root) => {
    const manifestPath = path.join(root, "flowersec-ts/package.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.engines.node = ">=20.0.0";
    manifest.dependencies["@noble/hashes"] = "2.3.0";
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const lockPath = path.join(root, "flowersec-ts/package-lock.json");
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    lock.packages[""].dependencies["@noble/hashes"] = "2.3.0";
    lock.packages["node_modules/@noble/hashes"] = { version: "2.3.0", engines: { node: ">=24.20.0" } };
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  }, /Node engine .* below .*24\.20\.0/);
});

test("Swift root and example shared pins cannot drift", (t) => {
  expectFailure(t, (root) => {
    const examplePath = path.join(root, "examples/swift/Package.resolved");
    const lock = JSON.parse(fs.readFileSync(examplePath, "utf8"));
    lock.pins[0].state = { revision: "def", version: "1.35.0" };
    fs.writeFileSync(examplePath, `${JSON.stringify(lock, null, 2)}\n`);
  }, /Swift shared pin .* differs/);
});

test("legacy WebTransport wire, parsers, and fallbacks are rejected", (t) => {
  expectFailure(t, (root) => {
    write(root, "flowersec-ts/src/node/adapter.ts", `export const protocol = ":protocol=webtransport";\nexport const legacyParserFallback = true;\n`);
  }, /legacy WebTransport wire|legacy parser or fallback/);
});

test("every high-impact dependency names a registered executable test", (t) => {
  expectFailure(t, (root) => {
    const contractPath = path.join(root, "stability/dependency_contracts.json");
    const contract = JSON.parse(fs.readFileSync(contractPath, "utf8"));
    contract.dependencies[0].conformanceTests = ["missing/test-id"];
    fs.writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  }, /unknown conformance test ID missing\/test-id/);
});

test("retired unsupported capability tests cannot remain registered", (t) => {
  expectFailure(t, (root) => {
    fs.appendFileSync(
      path.join(root, "flowersec-go/internal/cmd/flowersec-test/registry.go"),
      '\nfunc retired() { commandEntry("carrier/rust-webtransport-direct") }\n',
    );
  }, /retired unsupported capability test ID carrier\/rust-webtransport-direct/);
});

test("contract dependencies must resolve in their ecosystem lockfiles", (t) => {
  expectFailure(t, (root) => {
    write(root, "flowersec-rust/Cargo.lock", `version = 4\n\n[[package]]\nname = "rustls"\nversion = "0.23.0"\n`);
  }, /cargo dependency quinn is missing from flowersec-rust\/Cargo\.lock/);
});

test("upgrade groups contain coordinated protocol stack members", (t) => {
  expectFailure(t, (root) => {
    const contractPath = path.join(root, "stability/dependency_contracts.json");
    const contract = JSON.parse(fs.readFileSync(contractPath, "utf8"));
    contract.dependencies[1].upgradeGroup = null;
    fs.writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  }, /upgrade group go-webtransport-stack must contain at least two dependencies/);
});

test("new native Cargo manifests cannot hide high-impact dependencies", (t) => {
  expectFailure(t, (root) => {
    write(root, "flowersec-native-transport/Cargo.toml", `[package]\nname = "flowersec-native-transport"\nversion = "2.3.7"\n\n[dependencies]\nquinn = "=0.11.11"\n`);
    write(root, "flowersec-native-transport/Cargo.lock", `version = 4\n\n[[package]]\nname = "quinn"\nversion = "0.11.11"\n`);
    write(root, "flowersec-node-native/Cargo.toml", `[package]\nname = "flowersec-node-native"\nversion = "2.3.7"\n\n[dependencies]\nnapi = "=3.12.1"\n`);
    write(root, "flowersec-node-native/Cargo.lock", `version = 4\n\n[[package]]\nname = "napi"\nversion = "3.12.1"\n`);
  }, /high-impact cargo dependency napi has no contract/);
});

test("optional production npm dependencies are checked like regular dependencies", (t) => {
  expectFailure(t, (root) => {
    const manifestPath = path.join(root, "flowersec-ts/package.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.optionalDependencies = { "@matrixai/quic": "0.9.0" };
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const lockPath = path.join(root, "flowersec-ts/package-lock.json");
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    lock.packages[""] .optionalDependencies = { "@matrixai/quic": "0.9.0" };
    lock.packages["node_modules/@matrixai/quic"] = { version: "0.9.0", integrity: "sha512-fixture" };
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  }, /high-impact npm dependency @matrixai\/quic has no contract/);
});

test("optional dependencies cannot use incomplete lock metadata", (t) => {
  expectFailure(t, (root) => {
    const manifestPath = path.join(root, "flowersec-ts/package.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest.optionalDependencies = { ws: "8.21.2" };
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const lockPath = path.join(root, "flowersec-ts/package-lock.json");
    const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    lock.packages[""] .optionalDependencies = { ws: "8.21.2" };
    delete lock.packages["node_modules/ws"].version;
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  }, /npm dependency ws has no exact version/);
});

test("the repository satisfies its dependency contracts", () => {
  const result = runChecker(repositoryRoot);
  assert.equal(result.status, 0, result.stderr);
});
