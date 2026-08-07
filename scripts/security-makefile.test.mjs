import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const checker = path.join(root, "scripts/check-security-makefile.mjs");
const canonical = fs.readFileSync(path.join(root, "Makefile"), "utf8");

function check(source) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-make-contract-"));
  const makefile = path.join(directory, "Makefile");
  fs.writeFileSync(makefile, source);
  const result = spawnSync("node", [checker, makefile], { cwd: root, encoding: "utf8" });
  fs.rmSync(directory, { recursive: true, force: true });
  return result;
}

function dryRun(target) {
  return spawnSync("make", ["--no-print-directory", "-n", target], {
    cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024,
  });
}

test("current Make graph satisfies the security contract", () => {
  const result = check(canonical);
  assert.equal(result.status, 0, result.stderr);
});

test("local and external test targets remain separated", () => {
  for (const [target, action, suite] of [
    ["browser-smoke", "run", "browser-smoke"],
    ["diagnostic", "run", "diagnostic"],
    ["performance", "run", "performance"],
  ]) {
    const recipe = canonical.match(new RegExp(`^${target}:\\n((?:\\t.*\\n)+)`, "m"))?.[1] ?? "";
    assert.equal(recipe.trim(), `$(FLOWERSEC_TEST_HOST) ${action} --suite ${suite}`);
  }
  assert.match(canonical, /^test:\n\t\$\(MAKE\) go-test ts-test$/m);
  assert.match(canonical, /^precommit:\n\t\$\(MAKE\) precommit-source$/m);
  const ordinary = dryRun("test");
  const precommit = dryRun("precommit");
  assert.equal(ordinary.status, 0, ordinary.stderr);
  assert.equal(precommit.status, 0, precommit.stderr);
  assert.doesNotMatch(ordinary.stdout + precommit.stdout, /capacity|soak|pcap|qlog|transportcheck|artifact-dir|report/i);
});

test("complete gate preserves bounded ordered phases", () => {
  const result = dryRun("check");
  assert.equal(result.status, 0, result.stderr);
  const check = canonical.match(/^check: security-makefile-check\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const tokens = ["final-network-preflight", "final-offline-contracts", "final-package-validation", "final-integration-lanes", "final-post-validation"];
  const positions = tokens.map((token) => check.indexOf(token));
  assert.ok(positions.every((position, index) => position >= 0 && (index === 0 || position > positions[index - 1])));
  assert.match(result.stdout, /go test -race/);
  assert.match(result.stdout, /npm run test:coverage/);
  assert.match(result.stdout, /--enable-code-coverage/);
  assert.match(result.stdout, /cargo llvm-cov/);
  assert.doesNotMatch(result.stdout, /transportcheck|test evidence|receipt/i);
});

test("release and publication gates stay source-only", () => {
  const release = canonical.match(/^release-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.equal(release.trim(), "node scripts/check-release-version-consistency.mjs");
  const source = fs.readFileSync(path.join(root, "scripts/release.sh"), "utf8");
  assert.doesNotMatch(source, /\bmake\b|flowersec-test|test-host-init|receipt|test evidence/i);
});

test("protected recipes and definitions cannot be replaced", () => {
  for (const mutation of [
    canonical.replace("test:\n\t$(MAKE) go-test ts-test", "test:\n\t@true"),
    canonical.replace("browser-smoke:\n\t$(FLOWERSEC_TEST_HOST) run --suite browser-smoke", "browser-smoke:\n\t@true"),
    canonical.replace("precommit:\n\t$(MAKE) precommit-source", "precommit:\n\t$(MAKE) check"),
    canonical.replace("final-race-check:\n\t$(MAKE) go-test-race", "final-race-check:\n\t@true"),
    `${canonical}\nsecurity-dependency-check:\n\t@true\n`,
  ]) {
    assert.notEqual(mutation, canonical);
    const result = check(mutation);
    assert.notEqual(result.status, 0, mutation.slice(-100));
  }
});

test("Make control-flow injection and failure suppression are rejected", () => {
  for (const addition of [
    "MAKE := true", "SHELL := /usr/bin/true", ".IGNORE:", ".ONESHELL:",
    "include untrusted.mk", "TARGET := test\n$(TARGET):", "UNTRUSTED := $(shell true)",
    "release-check: MAKE := true",
  ]) {
    const result = check(`${canonical}\n${addition}\n`);
    assert.notEqual(result.status, 0, addition);
  }
});

test("security dependency inventory cannot be bypassed", () => {
  for (const mutation of [
    canonical.replace("scripts/test-architecture-contract.mjs", ""),
    canonical.replace("generate-source-inventory.mjs --check", "generate-source-inventory.mjs"),
    canonical.replace("node scripts/check-security-makefile.mjs Makefile", "@true"),
  ]) {
    assert.notEqual(mutation, canonical);
    const result = check(mutation);
    assert.notEqual(result.status, 0);
  }
});

test("language security controls remain present", () => {
  for (const command of [
    "npm audit --audit-level=info --include=prod --include=dev --include=optional --include=peer",
    "node scripts/check-go-security.mjs",
    "node scripts/check-rust-security.mjs",
    "node scripts/check-swift-security.mjs",
    "cargo package --allow-dirty --offline",
  ]) assert.match(canonical, new RegExp(command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});
