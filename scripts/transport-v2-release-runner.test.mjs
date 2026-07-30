#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const scriptsDirectory = path.dirname(fileURLToPath(import.meta.url));
const sourceRoot = path.dirname(scriptsDirectory);
const runnerPath = path.join(scriptsDirectory, "transport-v2-release-runner.sh");

function runRunner(args) {
  return spawnSync("bash", [runnerPath, ...args], {
    cwd: sourceRoot,
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
  });
}

test("release wrapper rejects calls outside the two-flag Make contract", () => {
  for (const args of [
    [],
    ["--target", "all"],
    ["--report", "/tmp/report.unsigned.json"],
    ["--target", "unknown", "--report", "/tmp/report.unsigned.json"],
    ["--target", "all", "--report", "relative/report.unsigned.json"],
    ["--target", "all", "--report", "/tmp/report.unsigned.json", "--extra"],
  ]) {
    const result = runRunner(args);
    assert.notEqual(result.status, 0, `${args.join(" ")} unexpectedly succeeded`);
  }
});

test("release wrapper accepts every Make release target before path validation", () => {
  for (const target of [
    "all", "transport-conformance-smoke", "transport-conformance-full", "weaknet-full", "weaknet-system",
    "quic-native-smoke", "quic-native-proof", "quic-native-race", "bench-transport-capacity",
    "bench-transport-soak", "bench-transport-ab",
  ]) {
    const result = runRunner(["--target", target, "--report", "relative-report.json"]);
    assert.match(result.stderr, /report path must be absolute/, `${target} was not accepted by the target parser`);
  }
});

test("release wrapper freezes the audited source, host, builds, and collect argv", () => {
  const runner = fs.readFileSync(runnerPath, "utf8");
  assert.match(runner, /^#!\/usr\/bin\/env bash\n\nset -euo pipefail$/m);
  assert.match(runner, /export PATH=\/usr\/local\/go\/bin:[^\n]+/);
  assert.match(runner, /export GOFLAGS=-mod=readonly/);
  assert.match(runner, /export GOWORK=off/);
  assert.match(runner, /report must use one fresh direct child directory under \/evidence/);
  assert.match(runner, /install -d -o root -g root -m 0700 "\$report_directory"/);
  assert.match(runner, /chown -R "\$release_owner_uid:\$release_owner_gid" "\$report_directory"/);
  assert.match(runner, /readonly source_root=\/workspace\/flowersec/);
  assert.match(runner, /git -C "\$source_root" status --porcelain --untracked-files=all/);
  assert.match(runner, /merge-base --is-ancestor "\$base_sha" "\$final_sha"/);
	assert.match(runner, /git clone --quiet --no-local --no-checkout "\$source_root" "\$base_source_root"/);
	assert.match(runner, /checkout --quiet --detach "\$base_sha"/);
	assert.match(runner, /base and final performance manifests must be byte-identical/);
  assert.match(runner, /ID:-} == ubuntu && \$\{VERSION_ID:-} == 24\.04/);
  assert.match(runner, /actual_kernel=\$\(uname -r\)/);
  assert.match(runner, /host kernel \$actual_kernel does not match frozen policy \$expected_kernel/);
  assert.match(runner, /ip netns add "\$probe_namespace"/);
  assert.match(runner, /go build -trimpath -buildvcs=false -o "\$low_level_runner"/);
	assert.match(runner, /cargo build --locked --release --example transport_release_runner/);
	assert.match(runner, /CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="\$rust_target_directory"/);
	assert.match(runner, /Rust release runner build is unavailable/);
	assert.match(runner, /go build -race -trimpath -buildvcs=false -o "\$race_low_level_runner"/);
	assert.match(runner, /go build -trimpath -buildvcs=false -o "\$base_low_level_runner"/);
  assert.match(runner, /vcs\\\.revision=/);
  assert.match(runner, /vcs\\\.modified=/);
  assert.match(runner, /case \$\(uname -m\) in/);
  assert.match(runner, /x86_64\)[\s\S]*bpf_target_arch=x86[\s\S]*bpf_system_include=\/usr\/include\/x86_64-linux-gnu/);
  assert.match(runner, /aarch64\)[\s\S]*bpf_target_arch=arm64[\s\S]*bpf_system_include=\/usr\/include\/aarch64-linux-gnu/);
  assert.match(runner, /clang -O2 -g -Wall -Werror -target bpf/);
  assert.match(runner, /-D"__TARGET_ARCH_\$\{bpf_target_arch\}"/);
  assert.match(runner, /-I"\$bpf_system_include"/);
  assert.match(runner, /runner build changed the source checkout/);
  assert.match(runner, /"\$transportcheck" collect \\/);
	assert.match(runner, /FLOWERSEC_RUST_RELEASE_RUNNER="\$rust_release_runner" "\$transportcheck" collect/);
  for (const flag of [
    "manifest", "registry", "repo", "base-repo", "base-sha", "final-sha", "target", "report", "artifact-dir",
    "runner-executable", "race-runner-executable", "base-runner-executable", "runner-wrapper", "bpf-object", "host-bpftool",
    "trust-policy", "effective-config", "kernel-release",
  ]) {
    assert.match(runner, new RegExp(`-${flag} `), `collect argv omits -${flag}`);
  }
  assert.doesNotMatch(runner, /PRIVATE KEY|key-file|transportcheck" sign/);
});

test("release wrapper contains low-level temporary files in its private build root", () => {
  const runner = fs.readFileSync(runnerPath, "utf8");
  const buildRoot = runner.indexOf("build_directory=$(mktemp -d /tmp/flowersec-transport-release-build.XXXXXX)");
  const tempExport = runner.indexOf('export TMPDIR="$build_directory"');
  const firstBuild = runner.indexOf("go build -trimpath");
  assert.notEqual(buildRoot, -1, "wrapper must create one private build root");
  assert.notEqual(tempExport, -1, "wrapper must bind child temporary files to the private build root");
  assert.notEqual(firstBuild, -1, "wrapper must build the low-level runner");
  assert.ok(buildRoot < tempExport && tempExport < firstBuild, "TMPDIR must be bound before any child build or workload");
  assert.match(runner, /rm -rf -- "\$build_directory"/);
});

test("release wrapper rebuilds the final browser bundle before collection", () => {
  const runner = fs.readFileSync(runnerPath, "utf8");
  const finalCheckoutClean = runner.indexOf('git -C "$source_root" status --porcelain --untracked-files=all');
  const browserDirectory = runner.indexOf('cd "$source_root/flowersec-ts"');
  const browserBuild = runner.indexOf("npm run build", browserDirectory);
  const collection = runner.indexOf('"$transportcheck" collect');

  assert.notEqual(finalCheckoutClean, -1, "wrapper must verify the final checkout is clean");
  assert.notEqual(browserDirectory, -1, "wrapper must build from the final TypeScript checkout");
  assert.notEqual(browserBuild, -1, "wrapper must run the clean browser build");
  assert.notEqual(collection, -1, "wrapper must invoke the evidence collector");
  assert.ok(finalCheckoutClean < browserDirectory, "the final checkout must be clean before building browser dist");
  assert.ok(browserBuild < collection, "browser dist must be rebuilt before evidence collection");
});

test("release wrapper collects bounded capacity parts before strict merge", () => {
  const runner = fs.readFileSync(runnerPath, "utf8");
  assert.match(
    runner,
    /readonly capacity_batches="stream-wss stream-quic stream-direct direct-carriers tunnel-matrix webtransport-quic webtransport-wss"/,
  );
  assert.match(runner, /collect_part "\$target" "\$part_report" "\$part_directory" -capacity-batch "\$batch"/);
  assert.match(runner, /"\$transportcheck" merge-capacity \\/);
  assert.match(runner, /"\$\{part_report_args\[@\]\}"/);
  assert.ok(
    runner.indexOf('collect_part "$target" "$part_report"') < runner.indexOf('"$transportcheck" merge-capacity'),
    "capacity merge must happen only after every partial collector returns",
  );
});

test("provision installs the source-matched wrapper at one stable container path", () => {
  const provision = fs.readFileSync(path.join(scriptsDirectory, "provision-transport-release-runner.sh"), "utf8");
  assert.match(provision, /docker exec "\$container_name" install -m 0555/);
  assert.match(provision, /\/workspace\/flowersec\/scripts\/transport-v2-release-runner\.sh/);
  assert.match(provision, /\/usr\/local\/bin\/flowersec-transport-v2-release-runner/);
  assert.match(provision, /test -x \/usr\/local\/bin\/flowersec-transport-v2-release-runner/);
  assert.match(provision, /git config --global --add safe\.directory \/workspace\/flowersec/);
  assert.match(provision, /git config --global --add safe\.directory \/workspace\/flowersec\/\.git/);
  assert.match(provision, /git -C \/workspace\/flowersec rev-parse --show-toplevel/);
  assert.match(provision, /sudo install -d -o root -g root -m 0755 "\$runner_root\/evidence"/);
  assert.match(provision, /FLOWERSEC_RELEASE_OWNER_UID=\$release_owner_uid/);
  assert.match(provision, /FLOWERSEC_RELEASE_OWNER_GID=\$release_owner_gid/);
  assert.match(provision, /--init/);
  assert.match(provision, /--privileged \\\n  --cgroup-parent flowersec-release\.slice \\\n  --network host/);
  assert.doesNotMatch(provision, /--(?:cgroupns|pid) host/);
  const dependencyInstall = provision.indexOf("npm ci --audit=false");
  const browserBuild = provision.indexOf("npm run build");
  const browserInstall = provision.indexOf("npx playwright install chromium");
  assert.notEqual(dependencyInstall, -1, "provision must install the frozen TypeScript dependencies");
  assert.notEqual(browserBuild, -1, "provision must build the browser bundle from the clean checkout");
  assert.notEqual(browserInstall, -1, "provision must install the pinned Chromium runtime");
  assert.ok(dependencyInstall < browserBuild, "dependencies must be installed before the browser bundle is built");
  assert.ok(browserBuild < browserInstall, "the browser bundle must be built before Chromium is installed");
});

test("failed provision stops its task-owned container and preserves the failure status", () => {
  const provision = fs.readFileSync(path.join(scriptsDirectory, "provision-transport-release-runner.sh"), "utf8");
  const oldContainerRemoval = provision.indexOf('docker rm --force "$container_name"');
  const failureTrap = provision.indexOf("trap 'cleanup_failed_provision $?' EXIT");
  const containerStart = provision.indexOf("docker run --detach");
  const successMarker = provision.indexOf("provision_complete=1");

  assert.notEqual(oldContainerRemoval, -1, "provision must remove only its exact stale container");
  assert.notEqual(failureTrap, -1, "provision must install a failure cleanup trap");
  assert.notEqual(containerStart, -1, "provision must start its dedicated container");
  assert.notEqual(successMarker, -1, "provision must explicitly mark successful completion");
  assert.ok(oldContainerRemoval < failureTrap, "failure cleanup must not affect the previous container");
  assert.ok(failureTrap < containerStart, "failure cleanup must cover container creation");
  assert.ok(containerStart < successMarker, "provision cannot mark completion before setup finishes");
  assert.match(provision, /trap 'cleanup_failed_provision 129' HUP/);
  assert.match(provision, /trap 'cleanup_failed_provision 130' INT/);
  assert.match(provision, /trap 'cleanup_failed_provision 143' TERM/);
  const cleanup = provision.match(/cleanup_failed_provision\(\) \{\n([\s\S]*?)\n\}/)?.[1] ?? "";
  assert.match(cleanup, /trap - EXIT HUP INT TERM/);
  assert.match(cleanup, /docker stop --time 10 "\$container_name"/);
  assert.match(cleanup, /exit "\$status"/);
  assert.match(provision, /provision_complete=1\ntrap - EXIT HUP INT TERM\n?$/);
});

test("release wrapper delegates cgroup controllers with a bounded live-process retry", () => {
  const runner = fs.readFileSync(runnerPath, "utf8");
  assert.match(runner, /readonly required_cgroup_controllers="cpuset cpu memory pids"/);
  assert.match(runner, /for \(\(cgroup_attempt = 1; cgroup_attempt <= 100; cgroup_attempt\+\+\)\)/);
  assert.match(runner, /done < \/sys\/fs\/cgroup\/cgroup\.procs/);
  assert.match(runner, /\[\[ ! -s \/sys\/fs\/cgroup\/cgroup\.procs \]\] &&/);
  assert.match(runner, /echo "\+cpuset \+cpu \+memory \+pids" > \/sys\/fs\/cgroup\/cgroup\.subtree_control/);
  assert.match(runner, /sleep 0\.05/);
  assert.match(runner, /within 5 seconds/);
});

test("release wrapper owns and cleans only exact network-lab kernel state", () => {
  const runner = fs.readFileSync(runnerPath, "utf8");
  assert.match(runner, /readonly bpf_pin_parent=\/sys\/fs\/bpf/);
  assert.match(runner, /\^f\[csr\]-\[0-9a-f\]\{8\}\$/);
  assert.match(runner, /\^flowersec-fc-\[0-9a-f\]\{8\}-fs-\[0-9a-f\]\{8\}\$/);
  assert.match(runner, /find "\$bpf_pin_parent" -xdev -mindepth 1 -maxdepth 1 -type d -name 'flowersec-fc-\?\?\?\?\?\?\?\?-fs-\?\?\?\?\?\?\?\?'/);
  assert.match(runner, /ip netns del "\$namespace"/);
  assert.match(runner, /find "\$path" -xdev -type f -delete/);
  assert.match(runner, /find "\$path" -xdev -depth -type d -exec rmdir \{\} \\;/);
  assert.match(runner, /runner left network namespaces/);
  assert.match(runner, /runner left BPF pins/);
});
