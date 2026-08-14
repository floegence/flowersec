#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  generateDirectCellDimensions,
  generateTunnelTopologyDimensions,
} from "./server-parity-matrix.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const makefile = read("Makefile");
const rustlsFeatureGraph = spawnSync(
  "cargo",
  ["tree", "--locked", "--manifest-path", "flowersec-rust/Cargo.toml", "-e", "features", "-i", "rustls"],
  { cwd: root, encoding: "utf8" },
);
assert.equal(rustlsFeatureGraph.status, 0, rustlsFeatureGraph.stderr);
assert.doesNotMatch(rustlsFeatureGraph.stdout, /feature "tls12"/, "Rust production feature graph enables TLS 1.2");

const trackedMarkdown = spawnSync(
  "git", ["ls-files", "-z", "--", "*.md"],
  { cwd: root, encoding: "utf8" },
);
assert.equal(trackedMarkdown.status, 0, trackedMarkdown.stderr);
const maintainedDocumentation = trackedMarkdown.stdout.split("\0").filter((relative) => (
  relative !== "" && relative !== "AGENTS.md"
  && fs.existsSync(path.join(root, relative))
  && !relative.endsWith("THIRD_PARTY_NOTICES.md")
  && !relative.endsWith("SBOM_SCOPE.md")
));
const releaseEvolution = /\b(?:earlier coordinated releases?|coordinated (?:patch )?release|introduced in \d|completed (?:for .* )?in \d|legacy fallback|earlier-version|older .* deployments?)\b|does not restore|not a restored|removed (?:artifact-first )?v1|compatibility (?:alias|CLI)/i;
const staleFlowersecVersion = /Flowersec 2\.3\.[0-3]\b|@floegence\/flowersec-core@2\.3\.[0-3]\b|flowersec-go\/v2\.3\.[0-3]\b|flowersec@2\.3\.[0-3]\b/;
for (const relative of maintainedDocumentation) {
  const contents = read(relative);
  assert.doesNotMatch(contents, releaseEvolution, `${relative} contains release evolution or compatibility history`);
  assert.doesNotMatch(contents, staleFlowersecVersion, `${relative} contains a stale Flowersec release version`);
}
const currentDocumentation = maintainedDocumentation.map(read).join("\n");
for (const token of [
  "ConnectionController", "NewAcceptor", "SessionHandlers",
  "loopback plaintext WebSocket", "stability/language_capabilities.json",
]) assert.match(currentDocumentation, new RegExp(escapeRegex(token)), `documentation misses current token ${token}`);

const retiredPaths = [
  "tools/idlgen", "idl/manifest.core.txt", "idl/manifest.examples.txt",
  "flowersec-go/gen", "flowersec-go/internal/testgen", "flowersec-ts/src/gen",
  "flowersec-ts/src/_examples", "flowersec-rust/src/gen",
  "flowersec-swift/Sources/Flowersec/Generated", "examples/gen",
  "scripts/transport-v2-runner.sh", "scripts/transport-v2-runner-host.py",
  "scripts/transport-v2-runner-agent.sh", "scripts/transport-v2-runner-kvm.py",
  "scripts/transport-v2-focused-tail-remote.sh", "scripts/flowersec-test-helper",
  "scripts/ubuntu-test-runner.sh", "scripts/run-transport-v2-test.sh",
  "scripts/run-transport-v2-diagnostic.sh", "scripts/run-transport-performance.sh",
  "scripts/run-go-test-race-shards.sh", "tools/transportcheck",
  "flowersec-go/internal/cmd/transport-acceptance-runner",
  "flowersec-go/internal/transporttest/acceptance",
  "flowersec-rust/examples/transport_test_runner.rs",
  "flowersec-ts/scripts/browser-acceptance-core.node-test.mjs",
];
for (const relative of retiredPaths) assert.equal(fs.existsSync(path.join(root, relative)), false, `retired path remains: ${relative}`);

assert.doesNotMatch(makefile, /\bgen(?:-core|-examples|-check)?\b|tools\/idlgen|manifest\.(?:core|examples)\.txt/,
  "the repository gate must not advertise unused IDL generation");

const forbidden = /transportcheck|transport-test-runner|transport-acceptance-runner|flowersec-test-helper|ubuntu-test-runner|run-transport-v2|execution[_ -]request|final_command|gate receipt|raw_transport_execution|performance_manifest|case_registry|runner ABI/i;
assert.doesNotMatch(makefile, forbidden);
assert.match(makefile, /^test:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test run --suite acceptance$/m);
assert.match(makefile, /^test-resume:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test resume --suite acceptance$/m);
assert.match(makefile, /^precommit:\n\t\$\(MAKE\) precommit-source$/m);
{
  const recipe = makefile.match(/^browser-smoke:[^\n]*\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(recipe, /flowersec-test run --suite browser-smoke/);
  assert.doesNotMatch(recipe, /FLOWERSEC_TEST_HOST/);
}
for (const target of ["diagnostic", "performance"]) {
  const recipe = makefile.match(new RegExp(`^${target}:[^\\n]*\\n((?:\\t.*\\n)+)` , "m"))?.[1] ?? "";
  assert.match(recipe, /FLOWERSEC_TEST_HOST/);
}
const releaseCheckRecipe = makefile.match(/^release-check:[^\n]*\n((?:\t.*\n)+)/m)?.[1] ?? "";
assert.doesNotMatch(releaseCheckRecipe, /flowersec-test|test-host-init|make check|evidence|receipt/i);
assert.doesNotMatch(read("scripts/release.sh"), /\bmake\b|flowersec-test|test-host-init|evidence|receipt/i);
const pushMain = read("scripts/push-main.sh");
assert.equal((pushMain.match(/^make test$/gm) ?? []).length, 1);
assert.doesNotMatch(pushMain, /^make (?:precommit|check)$/m);
assert.match(pushMain, /FLOWERSEC_PUSH_MAIN_SHA="\$head" git push origin "refs\/heads\/main:refs\/heads\/main"/);

const main = read("flowersec-go/internal/cmd/flowersec-test/main.go");
const registry = read("flowersec-go/internal/cmd/flowersec-test/registry.go");
const goWebTransportAdapter = read("flowersec-go/internal/carrier/webtransport/webtransport.go");
const dependencyContracts = read("stability/dependency_contracts.json");
const transportContract = read("stability/transport_v2_contract.json");
const capabilityContracts = read("stability/language_capabilities.json");
const transportArchitecture = read("docs/TRANSPORT_V2_ARCHITECTURE.md");
const testMatrix = read("docs/TEST_MATRIX.md");
const apiChangePolicy = read("docs/API_CHANGE_POLICY.md");
const rustReadme = read("flowersec-rust/README.md");
const typescriptReadme = read("flowersec-ts/README.md");
const directParityRunner = read("scripts/test-server-parity-direct.mjs");
const tunnelParityRunner = read("scripts/test-server-parity-tunnel.mjs");
const parityMatrixGenerator = read("scripts/server-parity-matrix.mjs");
const browserCarrier = read("flowersec-ts/src/browser/webTransportClient.ts") + read("flowersec-ts/src/transport/webTransportAdapter.ts");
const browserCarrierTests = read("flowersec-ts/src/transport/webTransportAdapter.test.ts");
const browserAcceptanceRunner = read("flowersec-ts/scripts/browser-test-runner-core.mjs") + read("flowersec-ts/playwright.config.ts");
const browserAcceptanceWorker = read("flowersec-ts/scripts/browser-test-runner.mjs");
const playwrightConfig = read("flowersec-ts/playwright.config.ts");
const stripComments = (source) => source
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/^\s*\/\/.*$/gm, "");
for (const source of [browserCarrier, browserCarrierTests].map(stripComments)) {
  assert.doesNotMatch(source, /allowPooling/);
  assert.doesNotMatch(source, /\bfactory\s*\(\s*url\s*,/);
  assert.doesNotMatch(source, /new\s+Constructor\s*\(\s*url\s*,/);
}
assert.match(browserCarrier, /new Constructor\(parsed\.href\)/);
assert.doesNotMatch(browserAcceptanceRunner, /ExtendQuicHandshakeTimeout|QuicHandshakeTimeout|MaxIdleTimeBeforeCryptoHandshake|force-fieldtrial|quic-client-connection-options/i);
assert.doesNotMatch(browserAcceptanceWorker, /__flowersecCancelArtifact|expected_failure|assertFullyResolved|resolved\s*=\s*new Set/);
assert.match(playwrightConfig, /ignoreHTTPSErrors:\s*true/,
  "browser tests must explicitly trust their self-signed local fixture");
assert.doesNotMatch(playwrightConfig, /--ignore-certificate-errors/,
  "browser tests must not disable Chromium certificate validation globally");
const ignoreHTTPSErrorsFiles = spawnSync(
  "git", ["grep", "-l", "ignoreHTTPSErrors", "--", "flowersec-ts"],
  { cwd: root, encoding: "utf8" },
);
assert.equal(ignoreHTTPSErrorsFiles.status, 0, ignoreHTTPSErrorsFiles.stderr);
assert.deepEqual(ignoreHTTPSErrorsFiles.stdout.trim().split("\n").sort(), [
  "flowersec-ts/playwright.config.ts",
  "flowersec-ts/scripts/browser-capacity-controller.mjs",
  "flowersec-ts/scripts/browser-test-runner.mjs",
], "self-signed certificate trust must remain confined to Playwright test configuration and runners");
const productionSourceFiles = spawnSync(
  "git", ["ls-files", "--", "flowersec-go/**/*.go", "flowersec-rust/src/**/*.rs", "flowersec-swift/Sources/**/*.swift", "flowersec-ts/src/**/*.ts", "flowersec-native-transport/src/**/*.rs", "flowersec-node-native/src/**/*.rs"],
  { cwd: root, encoding: "utf8" },
);
assert.equal(productionSourceFiles.status, 0, productionSourceFiles.stderr);
const productionSources = productionSourceFiles.stdout.trim().split("\n")
  .filter((relative) => relative !== "" && !/(?:_test\.go|\.test\.ts)$/.test(relative))
  .map(read)
  .join("\n");
assert.doesNotMatch(productionSources,
  /--ignore-certificate-errors|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|\.InsecureSkipVerify\s*=\s*true|danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)/,
  "production source must not enable an insecure TLS verification fallback");
assert.match(testMatrix, /release\/npm-consumer\/go-node-raw-quic\/direct-session/,
  "test matrix must identify the post-publication Go-to-Node registry consumer boundary");
assert.match(apiChangePolicy, /WebTransport preserves transport-managed passive rebinding but does not expose application-managed active migration/,
  "API policy must not overclaim WebTransport active migration");
assert.match(main, /type progress struct \{\n\s*Plan\s+string\s+`json:"plan"`\n\s*SourceSHA\s+string\s+`json:"source_sha"`\n\s*Suite\s+string\s+`json:"suite"`\n\s*Completed\s+\[\]string\s+`json:"completed"`/);
assert.match(main, /filepath\.Join\(stateDir, safeName\(\*suite\), "test-progress\.json"\)/);
assert.doesNotMatch(main, /namespace|bpftool|Chromium|QLOG|pcap|fault|shard|stage|base_sha|final_sha|config_digest/i);
assert.match(main, /atomicWrite|firstIncomplete|context\.WithTimeout|signal\.NotifyContext/);
assert.match(main, /externalHostRoot = "\/var\/lib\/flowersec-test"/);
assert.doesNotMatch(main, /\bsudo\b|runuser|SUDO_USER|reexec/i);
assert.match(registry, /func registry\(\) \[\]registeredTest/);
for (const id of [
  "controller/go", "controller/go-real-network-restart", "controller/typescript", "controller/typescript-real-network-restart", "controller/rust", "controller/rust-raw-quic",
  "protocol/go", "protocol/typescript", "protocol/rust",
  "carrier/go-direct", "carrier/go-tunnel",
  "carrier/rust-websocket-direct", "carrier/rust-websocket-tunnel",
  "server/typescript-acceptor",
  "interop/typescript-go/wss/direct", "interop/typescript-go/wss/tunnel",
  "interop/rust-go/raw-quic/direct", "interop/rust-go/raw-quic/tunnel",
  "interop/go-rust/raw-quic/direct", "interop/go-rust/raw-quic/tunnel",
  "interop/server-parity/direct-matrix", "interop/server-parity/tunnel-matrix",
  "interop/swift-go/wss/direct",
  "interop/swift-via-go-to-rust/wss/tunnel",
  "browser/chromium/websocket/go/direct",
  "browser/chromium/websocket/node/direct",
  "browser/chromium/websocket/via-go-to-rust/tunnel",
  "controller/swift-real-network-restart",
]) assert.match(registry, new RegExp(`"${escapeRegex(id)}"`));
for (const retiredID of [
  "carrier/typescript-raw-quic-direct", "carrier/typescript-raw-quic-tunnel",
  "carrier/rust-webtransport-direct", "carrier/rust-webtransport-tunnel",
  "integration/typescript/node-webtransport", "carrier/typescript-webtransport-tunnel-runtime",
  "interop/typescript-go/webtransport/direct", "interop/typescript-go/webtransport/tunnel",
]) assert.doesNotMatch(registry, new RegExp(`"${escapeRegex(retiredID)}"`));
assert.match(registry, /"server\/typescript-acceptor"[\s\S]*freezes handlers before establishing a direct WebSocket Session/);
assert.match(registry, /if runtime\.GOOS ===? "darwin"/);
const acceptanceRegistry = registry.match(/func registry\(\)[\s\S]*?func browserSmokeEntry/)?.[0] ?? "";
assert.doesNotMatch(acceptanceRegistry, /commandEntry\("browser\/[^"]+",\s*"acceptance"/);
assert.match(registry, /browserSmokeEntry\("browser\/chromium\/webtransport\/direct"/);
assert.match(registry, /func browserSmokeEntry[\s\S]*commandEntry\(id, "browser-smoke"/);
assert.match(registry, /browserCompatibilityEntry\("browser\/firefox\/webtransport-capability"/);
assert.match(registry, /browserCompatibilityEntry\("browser\/webkit\/webtransport-capability"/);
assert.match(registry, /func browserCompatibilityEntry[\s\S]*commandEntry\(id, "browser-compat"/);
assert.doesNotMatch(acceptanceRegistry, /--report|--artifact-dir|performance_manifest|case_registry|raw_execution/i);
for (const [name, source] of [
  ["Go WebTransport adapter", goWebTransportAdapter],
  ["dependency contract", dependencyContracts],
  ["transport contract", transportContract],
  ["capability contract", capabilityContracts],
  ["transport architecture", transportArchitecture],
  ["Rust README", rustReadme],
  ["TypeScript README", typescriptReadme],
  ["acceptance registry", registry],
]) {
  assert.doesNotMatch(source, /draft-?15|2c7cf000|webtransport_required_quic_settings/i, `${name} owns draft-specific WebTransport wire`);
}
for (const id of [
  "coverage/go", "coverage/typescript", "coverage/rust", "coverage/swift", "race/go",
  "diagnostic/weaknet/raw-quic/direct", "diagnostic/weaknet/websocket/direct",
  "diagnostic/kernel/topology-lifecycle", "diagnostic/kernel/fault-schedules",
  "diagnostic/kernel/reorder-duplicate-outage", "diagnostic/kernel/socket-traversal",
]) assert.match(registry, new RegExp(`"${escapeRegex(id)}"`));
assert.doesNotMatch(registry, /"diagnostic\/(?:protocol|browser|interop|weaknet|kernel-outage|quic)"/);
assert.match(directParityRunner, /required[\s\S]{0,80}unsupported|unsupported[\s\S]{0,80}required/i,
  "direct required matrix runner must reject unsupported cells");
assert.match(tunnelParityRunner, /required[\s\S]{0,80}unsupported|unsupported[\s\S]{0,80}required/i,
  "tunnel required matrix runner must reject unsupported topologies");
assert.match(parityMatrixGenerator, /language_capabilities\.json/,
  "server parity dimensions must derive from the capability manifest");
assert.match(directParityRunner, /FLOWERSEC_PARITY_CLIENT_PROFILE/,
  "the existing direct parity runner must own client-profile interop cells");
assert.match(tunnelParityRunner, /FLOWERSEC_PARITY_CLIENT_PROFILE/,
  "the existing tunnel parity runner must own client-profile interop cells");

const hostInit = read("scripts/test-host-init.sh");
const hostEntry = read("scripts/test-host.sh");
const interopMatrix = JSON.parse(read("stability/interop_matrix.json"));
const capabilityManifest = JSON.parse(read("stability/language_capabilities.json"));
const registryIDs = new Set([...registry.matchAll(/(?:commandEntry|commandEntryWithEnvironment|vitestEntry|browserSmokeEntry|browserCompatibilityEntry|performanceCapacityEntry|privilegedGoTestEntry|throughputEntry|flowersecWeaknetEntry)\("([^"]+)"/g)].map((match) => match[1]));
const deploymentProfiles = capabilityManifest.deployment_profiles;
assert.equal(deploymentProfiles?.version, 1);
assert.equal(deploymentProfiles?.application_wire, "shared_across_runtimes_and_carriers");
assert.deepEqual(deploymentProfiles?.profiles?.map(({ id }) => id), [
  "native-server-core", "browser-client", "apple-client", "webtransport-server",
]);
assert.deepEqual(deploymentProfiles.profiles[0], {
  id: "native-server-core",
  claimed_runtimes: ["go", "rust", "node-typescript"],
  transport_runtime_ids: ["go_native", "rust_native", "typescript_node"],
  required_roles: ["endpoint-client", "direct-server", "tunnel-runtime"],
  required_carriers: ["websocket", "raw-quic"],
  required_paths: {
    "endpoint-client": ["direct", "tunnel"],
    "direct-server": ["direct"],
    "tunnel-runtime": ["tunnel"],
  },
  required_capability_ids: ["opaque_artifact", "opaque_connector", "secure_session", "rpc_call_notify", "validated_stream_metadata", "connection_controller", "server_acceptor_session", "server_session_handlers", "controlplane_issue_authorize", "server_admission_paths", "browser_proxy_runtime", "carrier_contract", "wire_security"],
  optional_carriers: ["webtransport"],
  required_tuple_count: 18,
  required_path_unit_count: 24,
});
assert.equal(interopMatrix.version, 3);
const serverRuntimes = ["go", "rust", "node-typescript"];
const serverCarriers = ["websocket", "raw-quic", "webtransport"];
const requiredMatrixCarriers = ["websocket", "raw-quic"];
const requiredServerRoles = [
  { deploymentRole: "endpoint-client", path: "direct", feature: "connect" },
  { deploymentRole: "endpoint-client", path: "tunnel", feature: "connect" },
  { deploymentRole: "direct-server", path: "direct", feature: "accept" },
  { deploymentRole: "tunnel-runtime", path: "tunnel", feature: "pair-forward" },
];
const parityUnits = capabilityManifest.server_parity_contract?.units ?? [];
const parityUnitsByKey = new Map(parityUnits.map((unit) => [
  `${unit.runtime}/${unit["deployment-role"]}/${unit.carrier}/${unit.path}/${unit.feature}`,
  unit,
]));
const parityContractProblems = [];
for (const runtime of serverRuntimes) for (const carrier of serverCarriers) for (const role of requiredServerRoles) {
  const key = `${runtime}/${role.deploymentRole}/${carrier}/${role.path}/${role.feature}`;
  const unit = parityUnitsByKey.get(key);
  if (unit === undefined) parityContractProblems.push(`missing required server unit ${key}`);
  else if (unit.status === "supported") {
    if (typeof unit.entrypoint !== "string" || unit.entrypoint.length === 0) {
      parityContractProblems.push(`supported server unit ${key} has no production entrypoint`);
    }
    if (!Array.isArray(unit.test_ids) || unit.test_ids.length !== 1 || !registryIDs.has(unit.test_ids[0])) {
      parityContractProblems.push(`supported server unit ${key} has no executable test ID`);
    }
    if ("reason" in unit) parityContractProblems.push(`supported server unit ${key} carries an unsupported reason`);
  } else if (unit.status === "unsupported") {
    if (typeof unit.reason !== "string" || unit.reason.length === 0) {
      parityContractProblems.push(`unsupported server unit ${key} has no stable reason`);
    }
    if ("entrypoint" in unit || "test_ids" in unit) {
      parityContractProblems.push(`unsupported server unit ${key} claims a production entrypoint or test ID`);
    }
  } else {
    parityContractProblems.push(`server unit ${key} has invalid status ${String(unit.status)}`);
  }
}
for (const [kind, cells] of [["direct", interopMatrix.direct_cells], ["tunnel", interopMatrix.tunnel_topologies]]) {
  for (const carrier of requiredMatrixCarriers) {
    const count = cells.filter((cell) => (kind === "direct" ? cell.carrier : cell.ingress_carrier_a) === carrier).length;
    if (count !== 9) parityContractProblems.push(`${kind} ${carrier} has ${count} cells, want 9`);
  }
}
for (const [kind, actualCells, generatedCells] of [
  ["direct", interopMatrix.direct_cells, generateDirectCellDimensions()],
  ["tunnel", interopMatrix.tunnel_topologies, generateTunnelTopologyDimensions()],
]) {
  const actualByID = new Map(actualCells.map((cell) => [cell.id, cell]));
  for (const generated of generatedCells) {
    const actual = actualByID.get(generated.id);
    if (actual === undefined || !Object.entries(generated).every(([key, value]) => actual[key] === value)) {
      parityContractProblems.push(`${kind} matrix misses generated cell ${generated.id}`);
    }
    actualByID.delete(generated.id);
  }
  for (const id of actualByID.keys()) parityContractProblems.push(`${kind} matrix has non-generated cell ${id}`);
}
const nativeDriverFiles = [
  "flowersec-native-transport/Cargo.toml",
  "flowersec-native-transport/src/lib.rs",
  "flowersec-native-transport/tests/public_boundary.rs",
  "flowersec-node-native/Cargo.toml",
  "flowersec-node-native/package.json",
  "flowersec-node-native/src/lib.rs",
];
for (const relative of nativeDriverFiles) {
  if (!fs.existsSync(path.join(root, relative))) parityContractProblems.push(`missing native transport production unit ${relative}`);
}
if (fs.existsSync(path.join(root, "flowersec-native-transport/src/lib.rs"))) {
  const nativePublicBoundary = read("flowersec-native-transport/src/lib.rs");
  if (/\bpub\s+(?:use\s+)?(?:quinn|napi|wtransport|web_transport)\b/.test(nativePublicBoundary)) {
    parityContractProblems.push("native transport public boundary leaks a dependency implementation type");
  }
}
const nativePlatforms = ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"];
for (const platform of nativePlatforms) {
  const relative = `flowersec-node-native/npm/${platform}/package.json`;
  if (!fs.existsSync(path.join(root, relative))) parityContractProblems.push(`missing native addon prebuilt package ${platform}`);
}
if (fs.existsSync(path.join(root, "flowersec-node-native/package.json"))) {
  const corePackage = JSON.parse(read("flowersec-ts/package.json"));
  const nativePackage = JSON.parse(read("flowersec-node-native/package.json"));
  const expectedOptionalPackages = Object.fromEntries(nativePlatforms.map((platform) => [
    `@floegence/flowersec-node-native-${platform}`,
    corePackage.version,
  ]));
  if (nativePackage.version !== corePackage.version || nativePackage.engines?.node !== corePackage.engines?.node) {
    parityContractProblems.push("native addon wrapper version or Node runtime does not match the core package");
  }
  if (JSON.stringify(nativePackage.optionalDependencies) !== JSON.stringify(expectedOptionalPackages)) {
    parityContractProblems.push("native addon wrapper does not declare the exact prebuilt package set");
  }
  const platformContracts = {
    "darwin-arm64": { os: ["darwin"], cpu: ["arm64"] },
    "darwin-x64": { os: ["darwin"], cpu: ["x64"] },
    "linux-arm64-gnu": { os: ["linux"], cpu: ["arm64"], libc: ["glibc"] },
    "linux-x64-gnu": { os: ["linux"], cpu: ["x64"], libc: ["glibc"] },
  };
  for (const [platform, expected] of Object.entries(platformContracts)) {
    const relative = `flowersec-node-native/npm/${platform}/package.json`;
    if (!fs.existsSync(path.join(root, relative))) continue;
    const manifest = JSON.parse(read(relative));
    const binary = `flowersec-node-native.${platform}.node`;
    if (manifest.name !== `@floegence/flowersec-node-native-${platform}` ||
        manifest.version !== corePackage.version || manifest.engines?.node !== corePackage.engines?.node ||
        JSON.stringify(manifest.os) !== JSON.stringify(expected.os) ||
        JSON.stringify(manifest.cpu) !== JSON.stringify(expected.cpu) ||
        JSON.stringify(manifest.libc) !== JSON.stringify(expected.libc) ||
        manifest.main !== binary || JSON.stringify(manifest.files) !== JSON.stringify([
          binary,
          "LICENSE",
          "README.md",
          "THIRD_PARTY_NOTICES.md",
          "sbom/**",
        ])) {
      parityContractProblems.push(`native addon prebuilt package ${platform} has an invalid platform contract`);
    }
  }
}
assert.deepEqual(parityContractProblems, [], "server parity required tuple contract is incomplete");
const interopCells = [...interopMatrix.direct_cells, ...interopMatrix.tunnel_topologies];
assert.ok(interopMatrix.direct_cells.length > 0 && interopMatrix.tunnel_topologies.length > 0);
for (const cell of interopCells) {
  assert.equal(cell.status, "supported", `required interop cell ${cell.id} must be supported`);
  assert.equal(cell.test_ids?.length, 1, `supported interop cell ${cell.id} must use one test ID`);
  assert.equal("reason" in cell, false, `supported interop cell ${cell.id} must not carry a reason`);
  assert.equal("evidence" in cell, false, `interop cell ${cell.id} retains source evidence`);
  for (const id of cell.test_ids ?? []) assert.ok(registryIDs.has(id), `interop cell ${cell.id} references unknown test_id ${id}`);
}
for (const capability of capabilityManifest.portable_capabilities) {
  for (const implementation of Object.values(capability.implementations)) {
    assert.ok(["supported", "unsupported"].includes(implementation.status), `${capability.id} has an invalid implementation status`);
    if (implementation.status === "supported") {
      assert.equal(implementation.test_ids?.length, 1, `${capability.id} supported implementation must have one test_id`);
      if (capability.layer !== "portable_core") {
        assert.ok(typeof implementation.entrypoint === "string" && implementation.entrypoint.length > 0, `${capability.id} supported implementation must name an entrypoint`);
      }
      assert.equal("reason" in implementation, false, `${capability.id} supported implementation must not carry a reason`);
      assert.ok(registryIDs.has(implementation.test_ids[0]), `${capability.id} references unknown test_id ${implementation.test_ids[0]}`);
    } else {
      assert.equal("test_ids" in implementation, false, `${capability.id} unsupported implementation must not claim test IDs`);
      assert.equal("entrypoint" in implementation, false, `${capability.id} unsupported implementation must not claim an entrypoint`);
      assert.ok(typeof implementation.reason === "string" && implementation.reason.length > 0, `${capability.id} unsupported implementation must carry a stable reason`);
    }
  }
}
for (const capability of capabilityManifest.runtime_specific_capabilities) {
  assert.ok(capability.test_ids?.length >= 1, `${capability.id} must have test_ids`);
  for (const testID of capability.test_ids) assert.ok(registryIDs.has(testID), `${capability.id} references unknown test_id ${testID}`);
}
for (const fixture of capabilityManifest.shared_fixtures) {
  for (const consumers of Object.values(fixture.consumers)) {
    assert.equal(consumers.length, 1, `${fixture.id} must have one consumer per language`);
    assert.ok(registryIDs.has(consumers[0]), `${fixture.id} references unknown consumer ${consumers[0]}`);
  }
}
assert.doesNotMatch(read("stability/interop_matrix.json") + read("stability/language_capabilities.json"), /"evidence"/);
const browserEnsure = read("flowersec-ts/scripts/ensure-playwright-browsers.mjs");
const packageManifest = read("flowersec-ts/package.json");
assert.match(hostInit, /VERSION_ID/);
assert.match(hostInit, /goproxy\.cn|npmmirror\.com|rsproxy\.cn/);
assert.match(hostInit, /\[source\.crates-io\][\s\S]*replace-with = "rsproxy"[\s\S]*\[source\.rsproxy\]/);
assert.match(hostInit, /BTF|bpftool|netns|cgroup|Chromium|Swift 6\.1/i);
assert.match(hostInit, /clang -target bpf -O2 -x c -c/);
assert.match(hostInit, /npm --prefix "\$source_root\/flowersec-ts" run ensure:browser/);
assert.match(hostInit, /PLAYWRIGHT_DOWNLOAD_HOST|playwright_download_host/);
assert.match(hostInit, /PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT|playwright_download_timeout/);
assert.match(hostInit, /curl -fILsS --max-time/);
assert.doesNotMatch(hostInit, /ensure:browser:webkit|install chromium webkit/);
assert.match(browserEnsure, /requested\.length === 0 \? \["chromium"\]/);
assert.match(browserEnsure, /import \{ chromium, firefox, webkit \}/);
assert.match(browserEnsure, /const browsers = \{ chromium, firefox, webkit \}/);
assert.match(browserEnsure, /PLAYWRIGHT_DOWNLOAD_HOST/);
assert.match(browserEnsure, /PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT/);
assert.match(browserEnsure, /fs\.accessSync\(file, fs\.constants\.X_OK\)/);
assert.match(packageManifest, /"ensure:browser": "node \.\/scripts\/ensure-playwright-browsers\.mjs chromium"/);
assert.match(packageManifest, /"test:browser:firefox": "npm run ensure:browser:firefox[^"]*--project=firefox-compat"/);
assert.match(packageManifest, /"ensure:browser:webkit": "node \.\/scripts\/ensure-playwright-browsers\.mjs webkit"/);
assert.match(hostInit, /browser-test-runner\.mjs" --runtime-canary/);
assert.match(hostInit, /playwright_chromium/);
assert.match(hostInit, /init_tmp_baseline=\$\(mktemp[\s\S]*finalize_init_temps[\s\S]*comm -13[\s\S]*swift_canary=\$\(mktemp -d[\s\S]*TMPDIR="\$swift_canary" swiftc/);
assert.doesNotMatch(hostInit, /chromium_path=.*command -v chromium/);
for (const executable of ["go", "make", "node", "npm", "rustup", "cargo", "rustc", "swift", "swiftc", "git", "curl", "jq", "tar", "xz", "gcc", "g++", "clang", "clang++", "pkg-config", "python3", "sh", "realpath", "ip", "nsenter", "tc", "nft", "iptables", "ethtool", "bpftool", "sysctl", "mount", "mountpoint", "umount"]) {
  const boundary = /^[A-Za-z0-9_]+$/.test(executable) ? `\\b${escapeRegex(executable)}\\b` : escapeRegex(executable);
  assert.match(hostInit, new RegExp(boundary), `host init must check ${executable}`);
}
assert.match(hostInit, /bpftool feature probe kernel/);
assert.match(hostInit, /ip netns list/);
assert.doesNotMatch(hostInit, /ip netns add|ip link add name .* type veth|tc qdisc add|bpftool prog load|nft add table|iptables -t filter -N/);
assert.match(read("flowersec-go/internal/transporttest/linuxnetlab/integration_linux_test.go"), /t\.Cleanup|ApplyFaultProfile/);
assert.match(hostInit, /flowersec-swift-canary[\s\S]*swiftc/);
assert.doesNotMatch(hostInit, /swift test|TransportV2|IDNAHostV2/);
assert.match(hostInit, /clang\+\+ -std=c\+\+17 -x c\+\+ -fsyntax-only/);
assert.match(hostInit, /ip netns list/);
assert.match(hostInit, /rm -f -- \/etc\/profile\.d\/flowersec-mainland-sources\.sh/);
assert.doesNotMatch(hostInit, /test[-_ ]id|progress/i);
assert.doesNotMatch(hostInit + hostEntry, /SUDO_USER|runuser|chown|\/home\/tang|--runner-user/);
assert.match(hostEntry, /sudo -n true/);
assert.ok(hostEntry.split("\n").includes("    https://ghfast.top/https://github.com/*) printf '%s\\n' \"$1\" ;;"));
assert.match(hostEntry, /HOME="\$host_home" PATH="\$host_path" TMPDIR="\$host_tmp"/);
assert.match(hostEntry, /git -C "\$host_workspace" checkout --detach --force "\$source_sha"/);
assert.match(hostEntry, /status --porcelain --untracked-files=all/);
assert.doesNotMatch(hostEntry, /status --porcelain --untracked-files=no/);
assert.doesNotMatch(hostEntry, /sudo -E|sudo su|ssh |scp |rsync /);
assert.match(hostEntry, /readonly host_open_file_limit=65536/);
assert.match(hostEntry, /hard_limit=\$\(ulimit -Hn\)/);
assert.match(hostEntry, /ulimit -Sn "\$host_open_file_limit"/);
assert.match(hostEntry, /soft_limit=\$\(ulimit -Sn\)/);
const rootLimitCheck = hostEntry.indexOf("  configure_open_file_limit\n", hostEntry.indexOf("if [[ ${1:-} == --root ]]"));
const workspaceSync = hostEntry.indexOf('  sync_workspace "$source_sha" "$source_url"', rootLimitCheck);
const runnerExec = hostEntry.indexOf('  exec "$runner" "$action" "$@"', workspaceSync);
assert.ok(rootLimitCheck >= 0 && workspaceSync > rootLimitCheck && runnerExec > workspaceSync,
  "canonical root entry must set the file descriptor limit before workspace setup and runner execution");
assert.match(hostInit, /fd_soft=\$\(ulimit -Sn\)/);
assert.match(hostInit, /\[\[ \$fd_soft == 65536 \]\]/);
assert.doesNotMatch(hostInit, /ulimit -n 65536/);
assert.match(hostEntry, /flowersec-test-\$source_sha/);
assert.match(hostEntry, /go -C flowersec-go build -o "\$temporary_runner"/);
assert.doesNotMatch(hostEntry, /go -C flowersec-go run/);
assert.match(hostInit, /\(cd "\$host_home" && "\$swiftly" install 6\.1/);
assert.match(hostInit, /\.swift-version/);
assert.doesNotMatch(registry, /runtime\.GOOS == "darwin" \|\| runtime\.GOOS == "linux"/);

const performance = fs.readdirSync(path.join(root, "flowersec-go/internal/transporttest/performance"))
  .filter((name) => name.endsWith(".go") && !name.endsWith("_test.go"))
  .map((name) => read(`flowersec-go/internal/transporttest/performance/${name}`)).join("\n");
assert.doesNotMatch(performance, /raw_execution|manifest digest|report publication|artifact integrity/i);

for (const testName of [
  "TestRedDoesNotAdvanceAndResumeRunsTheFirstIncompleteTest",
  "TestResumeContinuesThroughAllIncompleteTests",
  "TestRunAlwaysStartsFreshAndProgressHasOnlyIdentityAndCompleted",
  "TestResumeStartsFreshWhenSourceSHAChanges",
  "TestTimedOutTestReceivesCancellationAndFinishesTeardown",
  "TestFreshRunClearsOldFailureLogs",
  "TestPrivilegedSuitesRequireFixedRootEnvironment",
  "TestLocalSuitesDoNotRequireRoot",
]) assert.match(read("flowersec-go/internal/cmd/flowersec-test/main_test.go"), new RegExp(`func ${testName}`));

for (const target of ["test", "precommit", "browser-smoke", "diagnostic", "performance", "check", "release-check"]) {
  const result = spawnSync("make", ["--no-print-directory", "-n", target], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, 0, `${target}: ${result.stderr}`);
  if (target === "test" || target === "precommit") assert.doesNotMatch(result.stdout, /performance|capacity|soak|pcap|qlog|report|artifact-dir|transportcheck/i);
  if (target === "release-check") assert.doesNotMatch(result.stdout, /flowersec-test|test-host-init|FLOWERSEC_TEST_RUNNER/i);
}
const finalGraph = spawnSync("make", ["--no-print-directory", "-n", "final-integration-lanes"], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
assert.equal(finalGraph.status, 0, finalGraph.stderr);
assert.match(finalGraph.stdout, /flowersec-test run --suite browser-smoke/);
assert.doesNotMatch(finalGraph.stdout, /FLOWERSEC_TEST_HOST|scripts\/test-host\.sh/);

process.stdout.write("test architecture contract is GREEN\n");
