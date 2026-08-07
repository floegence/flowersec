#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const makefile = read("Makefile");

const retiredPaths = [
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
const browserCarrier = read("flowersec-ts/src/browser/webTransportClient.ts") + read("flowersec-ts/src/transport/webTransportAdapter.ts");
const browserCarrierTests = read("flowersec-ts/src/transport/webTransportAdapter.test.ts");
const browserAcceptanceRunner = read("flowersec-ts/scripts/browser-test-runner-core.mjs") + read("flowersec-ts/playwright.config.ts");
const browserAcceptanceWorker = read("flowersec-ts/scripts/browser-test-runner.mjs");
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
assert.match(main, /type progress struct \{\n\s*Plan\s+string\s+`json:"plan"`\n\s*SourceSHA\s+string\s+`json:"source_sha"`\n\s*Suite\s+string\s+`json:"suite"`\n\s*Completed\s+\[\]string\s+`json:"completed"`/);
assert.match(main, /filepath\.Join\(stateDir, safeName\(\*suite\), "test-progress\.json"\)/);
assert.doesNotMatch(main, /namespace|bpftool|Chromium|QLOG|pcap|fault|shard|stage|base_sha|final_sha|config_digest/i);
assert.match(main, /atomicWrite|firstIncomplete|context\.WithTimeout|signal\.NotifyContext/);
assert.match(main, /externalHostRoot = "\/var\/lib\/flowersec-test"/);
assert.doesNotMatch(main, /\bsudo\b|runuser|SUDO_USER|reexec/i);
assert.match(registry, /func registry\(\) \[\]registeredTest/);
for (const id of [
  "controller/go", "controller/typescript", "controller/rust", "controller/rust-raw-quic",
  "protocol/go", "protocol/typescript", "protocol/rust",
  "carrier/go-direct", "carrier/go-tunnel",
  "integration/typescript/node-webtransport",
  "interop/typescript-go/wss/direct", "interop/typescript-go/wss/tunnel",
  "interop/typescript-go/webtransport/direct", "interop/typescript-go/webtransport/tunnel",
  "interop/rust-go/raw-quic/direct", "interop/rust-go/raw-quic/tunnel",
  "interop/swift-go/wss/direct", "interop/swift-go/wss/tunnel",
]) assert.match(registry, new RegExp(`"${escapeRegex(id)}"`));
assert.match(registry, /"interop\/typescript-go\/webtransport\/direct"[\s\S]*webTransport\.integration\.test\.ts/);
assert.match(registry, /if runtime\.GOOS ===? "darwin"/);
const acceptanceRegistry = registry.match(/func registry\(\)[\s\S]*?func browserSmokeEntry/)?.[0] ?? "";
assert.doesNotMatch(acceptanceRegistry, /commandEntry\("browser\/[^"]+",\s*"acceptance"/);
assert.match(registry, /browserSmokeEntry\("browser\/chromium\/webtransport\/direct"/);
assert.match(registry, /func browserSmokeEntry[\s\S]*commandEntry\(id, "browser-smoke"/);
assert.match(registry, /browserCompatibilityEntry\("browser\/firefox\/webtransport-capability"/);
assert.match(registry, /browserCompatibilityEntry\("browser\/webkit\/webtransport-capability"/);
assert.match(registry, /func browserCompatibilityEntry[\s\S]*commandEntry\(id, "browser-compat"/);
assert.doesNotMatch(acceptanceRegistry, /--report|--artifact-dir|performance_manifest|case_registry|raw_execution/i);
for (const id of [
  "coverage/go", "coverage/typescript", "coverage/rust", "coverage/swift", "race/go",
  "diagnostic/weaknet/raw-quic/direct", "diagnostic/weaknet/websocket/direct",
  "diagnostic/kernel/topology-lifecycle", "diagnostic/kernel/fault-schedules",
  "diagnostic/kernel/reorder-duplicate-outage", "diagnostic/kernel/socket-traversal",
]) assert.match(registry, new RegExp(`"${escapeRegex(id)}"`));
assert.doesNotMatch(registry, /"diagnostic\/(?:protocol|browser|interop|weaknet|kernel-outage|quic)"/);

const hostInit = read("scripts/test-host-init.sh");
const hostEntry = read("scripts/test-host.sh");
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
assert.match(hostInit, /bpftool prog load/);
assert.match(hostInit, /tc.*clsact|clsact.*tc/);
assert.match(hostInit, /nft add table/);
assert.match(hostInit, /iptables/);
assert.match(hostInit, /flowersec-swift-canary[\s\S]*swiftc/);
assert.doesNotMatch(hostInit, /swift test|TransportV2|IDNAHostV2/);
assert.match(hostInit, /clang\+\+ -std=c\+\+17 -x c\+\+ -fsyntax-only/);
assert.match(hostInit, /trap 'cleanup_probe; finalize_init_temps' EXIT/);
assert.match(hostInit, /cleanup_probe\ntrap - EXIT/);
assert.match(hostInit, /host capability canary cleanup left resources/);
assert.match(hostInit, /BPF verifier load/);
assert.match(hostInit, /network namespaces/);
assert.match(hostInit, /rm -f -- \/etc\/profile\.d\/flowersec-mainland-sources\.sh/);
assert.doesNotMatch(hostInit, /test[-_ ]id|progress/i);
assert.doesNotMatch(hostInit + hostEntry, /SUDO_USER|runuser|chown|\/home\/tang|--runner-user/);
assert.match(hostEntry, /sudo -n true/);
assert.match(hostEntry, /https:\/\/ghfast\.top\/https:\/\/github\.com/);
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
assert.match(registry, /runtime\.GOOS == "darwin" \|\| runtime\.GOOS == "linux"/);

const performance = fs.readdirSync(path.join(root, "flowersec-go/internal/transporttest/performance"))
  .filter((name) => name.endsWith(".go") && !name.endsWith("_test.go"))
  .map((name) => read(`flowersec-go/internal/transporttest/performance/${name}`)).join("\n");
assert.doesNotMatch(performance, /raw_execution|manifest digest|report publication|artifact integrity/i);

for (const testName of [
  "TestRedDoesNotAdvanceAndResumeRunsTheFirstIncompleteTest",
  "TestResumeStopsAfterTheFirstIncompleteTest",
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
