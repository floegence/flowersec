#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import "./test-transport-v3-contract.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const exists = (relative) => fs.existsSync(path.join(root, relative));
const run = (command, args) => spawnSync(command, args, {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
});

const makefile = read("Makefile");
const registry = read("flowersec-go/internal/cmd/flowersec-test/registry.go");
const capabilities = JSON.parse(read("stability/language_capabilities.json"));
const apiManifest = JSON.parse(read("stability/api_contract_manifest.json"));
const packageJSON = JSON.parse(read("flowersec-ts/package.json"));

assert.equal(read("flowersec-go/go.mod").match(/^module (.+)$/m)?.[1], "github.com/floegence/flowersec/flowersec-go/v5");
assert.equal(packageJSON.version, "5.0.1");
assert.equal(packageJSON.engines.node, ">=24.20.0");
assert.deepEqual(packageJSON.bin, { "flowersec-ts-cli": "./dist/cli.js" });
assert.equal(read("Package.swift").match(/^\/\/ Flowersec release major: (\d+)$/m)?.[1], "5");
assert.match(read("flowersec-rust/Cargo.toml"), /^version = "5\.0\.1"$/m);

const rustlsFeatures = run("cargo", [
  "tree", "--locked", "--manifest-path", "flowersec-rust/Cargo.toml",
  "-e", "features", "-i", "rustls",
]);
assert.equal(rustlsFeatures.status, 0, rustlsFeatures.stderr);
assert.doesNotMatch(rustlsFeatures.stdout, /feature "tls12"/u);

const retiredPaths = [
  "docs/TRANSPORT_V2_ARCHITECTURE.md",
  "docs/TRANSPORT_V2_WIRE.md",
  "stability/transport_v2_contract.json",
  "testdata/transport_v2",
  "flowersec-rust/src/transport_v2.rs",
  "flowersec-ts/src/v2",
  "flowersec-go/internal/protocolv2",
  "flowersec-swift/Sources/Flowersec/TransportV2.swift",
  "reference/presets",
  "tools/idlgen",
  "flowersec-go/internal/testgen",
];
for (const relative of retiredPaths) {
  assert.equal(exists(relative), false, `retired path remains: ${relative}`);
}

const markdown = run("git", ["ls-files", "-z", "--", "*.md"]);
assert.equal(markdown.status, 0, markdown.stderr);
for (const relative of markdown.stdout.split("\0").filter((item) => item !== "" && exists(item))) {
  if (relative === "AGENTS.md" || relative.endsWith("THIRD_PARTY_NOTICES.md")) continue;
  const source = read(relative);
  assert.doesNotMatch(source, /\bV2\b|\bv2\b|deprecated\s+.*V3|legacy\s+(?:API|runtime|connector|artifact)/iu,
    `${relative} describes retired public behavior`);
  assert.doesNotMatch(source, /Flowersec 2\.3\.|Flowersec 3\.2\.|@floegence\/flowersec-core@(?:2|3)\./u,
    `${relative} contains stale package-version guidance`);
}

assert.equal(capabilities.version, 3);
assert.equal(capabilities.deployment_profiles.application_wire, "flowersec/3");
assert.equal(capabilities.portable_capabilities.length, 16);
assert.equal(capabilities.portable_capabilities.some(({ id }) => id.includes("v2")), false);
const controlPlane = capabilities.portable_capabilities.find(({ id }) => id === "controlplane_issue_authorize");
assert.ok(controlPlane);
assert.equal(controlPlane.implementations.go.status, "supported");
assert.equal(controlPlane.implementations.go.entrypoint, "flowersec-go/v5/controlplane");
assert.doesNotMatch(JSON.stringify(capabilities), /flowersec-go\/(?:v[1-4]\/)?controlplane/u);
const proxy = capabilities.portable_capabilities.find(({ id }) => id === "browser_proxy_runtime");
assert.ok(proxy);
for (const [language, testID] of [
  ["go", "server/go-proxy"],
  ["typescript", "server/typescript-proxy"],
  ["rust", "server/rust-proxy"],
]) {
  assert.equal(proxy.implementations[language].status, "supported");
  assert.deepEqual(proxy.implementations[language].test_ids, [testID]);
  assert.match(registry, new RegExp(`"${testID.replaceAll("/", "\\/")}"`, "u"));
}
assert.equal(proxy.implementations.swift.status, "unsupported");
for (const unit of capabilities.server_parity_contract.units.filter((item) => item["deployment-role"] === "proxy-server")) {
  assert.equal(unit.status, "supported");
  assert.equal(unit.test_ids.length, 1);
}

for (const subpath of apiManifest.ts.subpaths) {
  for (const symbol of [...subpath.runtime_exports, ...subpath.type_exports]) {
    assert.doesNotMatch(symbol, /V2|V3|^v2$/u, `versioned TypeScript symbol remains: ${symbol}`);
  }
}
assert.deepEqual(apiManifest.ts.bins, [{
  name: "flowersec-ts-cli",
  path: "./dist/cli.js",
  source: "flowersec-ts/src/cli.ts",
  requires_shebang: true,
}]);
assert.deepEqual(apiManifest.native_abi, {
  package: "@floegence/flowersec-node-native",
  contract_version: 3,
  wire_version: 3,
  runtime_exports: ["bindRawQuic", "connectRawQuic", "contractVersion"],
});
assert.equal(apiManifest.rust.compile_entries.some((entry) => /flowersec::v[23]::/u.test(entry)), false);
assert.equal(apiManifest.swift.symbols.some(({ name }) => /V2|V3/u.test(name)), false);

const cli = read("flowersec-ts/src/cli.ts");
assert.equal(cli.startsWith("#!/usr/bin/env node\n"), true);
assert.match(cli, /required\(values, "certificate"\)/u);
assert.match(cli, /required\(values, "private-key"\)/u);
assert.match(cli, /createArtifactLease/u);
assert.match(cli, /createAcceptor/u);
assert.doesNotMatch(cli, /connectV3|createAcceptorV3|node\.v2/u);

const nodeEntrypoint = read("flowersec-ts/src/node/index.ts");
assert.match(nodeEntrypoint, /export \{ ProxyServer, ProxyServerError \}/u);
assert.match(nodeEntrypoint, /export type \{ ProxyServerOptions \}/u);
const nativeDeclaration = read("flowersec-node-native/index.d.ts");
assert.match(nativeDeclaration, /readonly wireVersion: 3;/u);
assert.match(nativeDeclaration, /connectRawQuic\(/u);
assert.match(nativeDeclaration, /bindRawQuic\(/u);
assert.doesNotMatch(nativeDeclaration, /RawQuicV2|RawQuicV3/u);

assert.match(makefile, /^precommit:\n\t\$\(MAKE\) precommit-source$/m);
assert.match(makefile, /^test:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test run --suite acceptance$/m);
assert.doesNotMatch(makefile, /transport-v2|reference\/presets/u);
const pushMain = read("scripts/push-main.sh");
assert.equal((pushMain.match(/^make test$/gm) ?? []).length, 1);
assert.doesNotMatch(pushMain, /^make (?:precommit|check)$/m);
assert.doesNotMatch(read("scripts/release.sh"), /\bmake\b|flowersec-test|test-host-init/u);

const generatedReadme = run(process.execPath, ["scripts/generate-readme-capabilities.mjs", "--check"]);
assert.equal(generatedReadme.status, 0, generatedReadme.stderr);

const productionFiles = run("git", [
  "ls-files", "-z", "--",
  "flowersec-go/**/*.go",
  "flowersec-rust/src/**/*.rs",
  "flowersec-swift/Sources/**/*.swift",
  "flowersec-ts/src/**/*.ts",
  "flowersec-native-transport/src/**/*.rs",
  "flowersec-node-native/src/**/*.rs",
]);
assert.equal(productionFiles.status, 0, productionFiles.stderr);
for (const relative of productionFiles.stdout.split("\0").filter((item) => item !== "" && exists(item))) {
  if (/(?:_test\.go|\.test\.ts)$/u.test(relative)) continue;
  const source = read(relative);
  assert.doesNotMatch(source,
    /--ignore-certificate-errors|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized\s*:\s*false|danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)/u,
    `${relative} enables insecure TLS verification`);
  assert.doesNotMatch(source,
    /(?:export|public|pub)\s+(?:type\s+|class\s+|struct\s+|enum\s+|func\s+|fn\s+|const\s+)?\w*V2\b/u,
    `${relative} exposes a retired V2 symbol`);
  assert.doesNotMatch(source,
    /SessionUnreliable(?:Unavailable|TooLarge|Dropped)|LegacyUnreliableSessionErrorCode|absoluteUnixMilliseconds/u,
    `${relative} contains a removed Flowersec compatibility API`);
}

assert.doesNotMatch(read("flowersec-go/proxy_server.go"), /func \(server \*ProxyServer\) Register\(/u);
assert.doesNotMatch(read("flowersec-go/connector.go"), /func \(err \*UnreliableMessageError\) Unwrap\(/u);
assert.doesNotMatch(read("docs/API_CONTRACT.md"), /UnreliableMessageError[^\n]*unwrap/iu);
assert.doesNotMatch(read("flowersec-ts/src/v3/security.ts"), /get disposition\(|absoluteUnixMilliseconds/u);
assert.doesNotMatch(read("flowersec-rust/src/proxy_server.rs"), /pub fn register\(/u);
assert.doesNotMatch(read("flowersec-rust/src/transport.rs"),
  /UnreliableMessageError::(?:InvalidInput|Expired|DroppedBudget|Failed)/u);
const proxyPublicEntrypoint = read("flowersec-ts/src/proxy/index.ts");
assert.match(proxyPublicEntrypoint, /registerProxyAppWindowWithServiceWorkerRuntime/u);
assert.doesNotMatch(proxyPublicEntrypoint,
  /RuntimeFetchMessage|parseRuntimeRequest|flowersec-proxy:fetch|response_flow_control|external_origin/u);

process.stdout.write("Flowersec 5 architecture contract is internally consistent\n");
