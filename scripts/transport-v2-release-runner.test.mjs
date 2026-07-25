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
    "all", "transport-conformance-full", "weaknet-full", "weaknet-system",
    "quic-native-proof", "quic-native-race", "bench-transport-capacity",
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
  assert.match(runner, /ID:-} == ubuntu && \$\{VERSION_ID:-} == 24\.04/);
  assert.match(runner, /actual_kernel=\$\(uname -r\)/);
  assert.match(runner, /host kernel \$actual_kernel does not match frozen policy \$expected_kernel/);
  assert.match(runner, /ip netns add "\$probe_namespace"/);
  assert.match(runner, /go build -trimpath -buildvcs=true -o "\$low_level_runner"/);
  assert.match(runner, /vcs\\\.revision=/);
  assert.match(runner, /vcs\\\.modified=/);
  assert.match(runner, /clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86/);
  assert.match(runner, /runner build changed the source checkout/);
  assert.match(runner, /"\$transportcheck" collect \\/);
  for (const flag of [
    "manifest", "registry", "repo", "base-sha", "final-sha", "target", "report", "artifact-dir",
    "runner-executable", "runner-wrapper", "bpf-object", "host-bpftool",
    "trust-policy", "effective-config", "kernel-release",
  ]) {
    assert.match(runner, new RegExp(`-${flag} `), `collect argv omits -${flag}`);
  }
  assert.doesNotMatch(runner, /PRIVATE KEY|key-file|transportcheck" sign/);
});

test("provision installs the source-matched wrapper at one stable container path", () => {
  const provision = fs.readFileSync(path.join(scriptsDirectory, "provision-transport-release-runner.sh"), "utf8");
  assert.match(provision, /docker exec "\$container_name" install -m 0555/);
  assert.match(provision, /\/workspace\/flowersec\/scripts\/transport-v2-release-runner\.sh/);
  assert.match(provision, /\/usr\/local\/bin\/flowersec-transport-v2-release-runner/);
  assert.match(provision, /test -x \/usr\/local\/bin\/flowersec-transport-v2-release-runner/);
  assert.match(provision, /sudo install -d -o root -g root -m 0755 "\$runner_root\/evidence"/);
  assert.match(provision, /FLOWERSEC_RELEASE_OWNER_UID=\$release_owner_uid/);
  assert.match(provision, /FLOWERSEC_RELEASE_OWNER_GID=\$release_owner_gid/);
});
