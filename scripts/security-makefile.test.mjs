import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const checker = path.join(sourceRoot, "scripts/check-security-makefile.mjs");
const canonical = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
const gmake = (process.env.PATH ?? "")
  .split(path.delimiter)
  .map((directory) => path.join(directory, "gmake"))
  .find((candidate) => fs.existsSync(candidate));

function check(makefile, extraEnv = {}, makeBinary) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-make-security-"));
  fs.writeFileSync(path.join(root, "Makefile"), makefile);
  const env = { ...process.env, ...extraEnv };
  if (makeBinary !== undefined) {
    fs.symlinkSync(makeBinary, path.join(root, "make"));
    env.PATH = `${root}${path.delimiter}${env.PATH ?? ""}`;
  }
  const result = spawnSync("node", [checker, path.join(root, "Makefile")], {
    cwd: sourceRoot,
    encoding: "utf8",
    env,
  });
  fs.rmSync(root, { recursive: true, force: true });
  return result;
}

function replaceTargetRecipeLine(makefile, target, line, replacement) {
  const expression = new RegExp(`^${target}:[^\\n]*\\n(?:\\t.*\\n)*`, "m");
  const match = expression.exec(makefile);
  assert.ok(match, `${target} recipe must exist`);
  const mutatedBlock = match[0].replace(line, replacement);
  assert.notEqual(mutatedBlock, match[0], `${target} must contain ${line}`);
  return `${makefile.slice(0, match.index)}${mutatedBlock}${makefile.slice(match.index + match[0].length)}`;
}

test("effective Make graph keeps the security gate complete and reachable", () => {
  assert.equal(fs.existsSync(checker), true, "security Make graph checker must exist");
  const result = check(canonical);
  assert.equal(result.status, 0, result.stderr);
});

test("effective Make recipe parsing supports GNU Make 4.4", { skip: gmake === undefined }, () => {
  const result = check(canonical, {}, gmake);
  assert.equal(result.status, 0, result.stderr);
});

test("effective Make database ignores marker text in variable definitions", () => {
  const markerText = [
    "define HARMLESS_DATABASE_MARKERS",
    "# Files",
    "forged-target:",
    "# files hash-table stats:",
    "endef",
    "",
  ].join("\n");
  const result = check(`${markerText}${canonical}`);
  assert.equal(result.status, 0, result.stderr);
});

test("Make control variables cannot neutralize recursive security gates", () => {
  for (const assignment of [
    "MAKE := true",
    "MAKE_COMMAND := true",
    "SHELL := /usr/bin/true",
    ".SHELLFLAGS := -c true",
  ]) {
    const result = check(`${canonical}\n${assignment}\n`);
    assert.notEqual(result.status, 0, `${assignment} must be rejected`);
    assert.match(result.stderr, /control variable|MAKE|SHELL/i);
  }
});

test("protected targets cannot carry target-specific Make controls", () => {
  for (const mutation of [
    "release-check: MAKE := true",
    "dummy release-check: MAKE := true",
    "release-%: MAKE := true",
    "release-%: private MAKE := true",
    "release-%: export MAKE := true",
    "swift-%: SWIFT_SOURCE_GUARD_PATTERN := a^",
    "swift-source-guard: SWIFT_SOURCE_GUARD_PATTERN := a^",
    "TARGET := swift-check\n$(TARGET): SWIFT_SOURCE_GUARD_PATTERN := a^",
    "%: SHELL := /usr/bin/true",
    "%: MAKE \\\n:= true",
    "%: SHELL \\\n:= /usr/bin/true",
    "%: MAKEFLAGS \\\n:= -i",
    "%: MAKE \\\r\n:= true",
    "%: SHELL \\\r\n:= /usr/bin/true",
    "%: MAKEFLAGS \\\r\n:= -i",
  ]) {
    const mutated = mutation.startsWith("release-check:")
      ? canonical.replace(/^release-check:$/m, mutation)
      : `${canonical}\n${mutation}\n`;
    assert.notEqual(mutated, canonical);
    const result = check(mutated);
    assert.notEqual(result.status, 0, `${mutation} must be rejected`);
    assert.match(result.stderr, /release-check|target-specific|control variable|continuation|dynamic/i);
  }
});

test("audited targets cannot be generated dynamically", () => {
  for (const mutated of [
    canonical.replace(/^release-check:$/m, "RELEASE_TARGET := release-check\n$(RELEASE_TARGET):"),
    `${canonical}\n$(eval GENERATED_TARGET := release-check)\n`,
    `${canonical}\nINJECTED_RULE = swift-%: SWIFT_SOURCE_GUARD_PATTERN := a^\n$(call eval,$(INJECTED_RULE))\n`,
    `${canonical}\nUNTRUSTED := $(shell exit 0)\n`,
  ]) {
    assert.notEqual(mutated, canonical);
    const result = check(mutated);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /dynamic|generate|rewrite/i);
  }
});

test("security gate configuration cannot be overridden by source or environment", () => {
  for (const mutation of [
    "CHECK_INTEROP := 0",
    "CHECK_INTEROP := 1 ",
    "YAMUX_INTEROP := 0",
    "SWIFT_SOURCE_GUARD_PATTERN := a^",
  ]) {
    const result = check(`${canonical}\n${mutation}\n`);
    assert.notEqual(result.status, 0, `${mutation} must be rejected`);
    assert.match(result.stderr, /configuration|effective|variable|expected/i);
  }

  for (const [name, value] of [
    ["CHECK_INTEROP", "0"],
    ["CHECK_INTEROP", " 1"],
    ["YAMUX_INTEROP", "0"],
  ]) {
    const result = check(canonical, { [name]: value });
    assert.notEqual(result.status, 0, `${name}=${value} must be rejected`);
    assert.match(result.stderr, /configuration|effective|variable|expected/i);
  }
});

test("shell assignment is rejected before GNU Make evaluates it", { skip: gmake === undefined }, () => {
  const marker = path.join(os.tmpdir(), `flowersec-make-shell-${process.pid}-${Date.now()}`);
  fs.rmSync(marker, { force: true });
  const result = check(`${canonical}\nUNTRUSTED != printf executed > ${marker}\n`, {}, gmake);
  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(marker), false, "Make shell assignment executed before validation");
  fs.rmSync(marker, { force: true });
});

test("Swift source guard recipe cannot be replaced with a no-op", () => {
  const mutated = canonical.replace(
    /^swift-source-guard:\n(?:\t.*\n)+/m,
    "swift-source-guard:\n\t@:\n",
  );
  assert.notEqual(mutated, canonical);
  const result = check(mutated);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /swift-source-guard.*recipe|exact audited command/i);
});

test("security dependency gate requires its pinned Node validators and a fresh npm build", () => {
  assert.match(canonical, /^ts-build: ts-ensure-deps$/m);
  assert.match(canonical, /^security-dependency-check: ts-build$/m);
  const disconnected = canonical.replace(
    /^security-dependency-check: ts-build$/m,
    "security-dependency-check:",
  );
  const result = check(disconnected);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /security-dependency-check.*ts-build/i);

  const dependenciesDisconnected = canonical.replace(/^ts-build: ts-ensure-deps$/m, "ts-build:");
  const dependenciesResult = check(dependenciesDisconnected);
  assert.notEqual(dependenciesResult.status, 0);
  assert.match(dependenciesResult.stderr, /ts-build.*ts-ensure-deps/i);
});

test("effective Make graph rejects recipe override and missing inventory freshness", () => {
  const overridden = `${canonical}\nsecurity-dependency-check:\n\t@:\n`;
  const overrideResult = check(overridden);
  assert.notEqual(overrideResult.status, 0);
  assert.match(overrideResult.stderr, /duplicate|overrid/i);

  const staleAllowed = canonical.replace("generate-source-inventory.mjs --check", "generate-source-inventory.mjs");
  const staleResult = check(staleAllowed);
  assert.notEqual(staleResult.status, 0);
  assert.match(staleResult.stderr, /--check|fresh|exact|recipe/i);

  const checkerNoOp = canonical.replace(
    "security-makefile-check:\n\tnode scripts/check-security-makefile.mjs Makefile",
    "security-makefile-check:\n\t@:",
  );
  assert.notEqual(checkerNoOp, canonical);
  const checkerResult = check(checkerNoOp);
  assert.notEqual(checkerResult.status, 0);
  assert.match(checkerResult.stderr, /security-makefile-check.*recipe/i);

  const ignoredFailure = canonical.replace(
    "\tnode --test scripts/security-dependencies.test.mjs",
    "\t-node --test scripts/security-dependencies.test.mjs",
  );
  assert.notEqual(ignoredFailure, canonical);
  const ignoredResult = check(ignoredFailure);
  assert.notEqual(ignoredResult.status, 0);
  assert.match(ignoredResult.stderr, /exact|ignore|recipe/i);

  const swallowedFailure = canonical.replace(
    "scripts/security-makefile.test.mjs\n\tnode scripts/generate-source-inventory.mjs --check",
    "scripts/security-makefile.test.mjs || true\n\tnode scripts/generate-source-inventory.mjs --check",
  );
  assert.notEqual(swallowedFailure, canonical);
  const swallowedResult = check(swallowedFailure);
  assert.notEqual(swallowedResult.status, 0);
  assert.match(swallowedResult.stderr, /exact|shell|recipe/i);
});

test("npm package freshness cannot bypass the exact clean build", () => {
  const exactLine = "\tcd flowersec-ts && rm -rf dist && npm run build";
  for (const replacement of [
    "\t@:",
    `\t-${exactLine.slice(1)}`,
    `${exactLine} || true`,
    "\tcd flowersec-ts && npm run build",
    "\tcd flowersec-ts && rm -rf dist",
  ]) {
    const mutated = replaceTargetRecipeLine(canonical, "ts-build", exactLine, replacement);
    const result = check(mutated);
    assert.notEqual(result.status, 0, `${replacement} must not bypass a clean npm build`);
    assert.match(result.stderr, /ts-build.*recipe|exact audited command/i);
  }
});

test("npm audit cannot omit dependencies or downgrade the severity threshold", () => {
  const exactLine = "\tcd flowersec-ts && npm audit --audit-level=info --include=prod --include=dev --include=optional --include=peer";
  for (const replacement of [
    "\tcd flowersec-ts && npm audit",
    "\tcd flowersec-ts && npm audit --audit-level=high",
    "\tcd flowersec-ts && npm audit --omit=dev",
    `${exactLine} || true`,
    `\t-${exactLine.slice(1)}`,
  ]) {
    const mutated = replaceTargetRecipeLine(canonical, "ts-audit", exactLine, replacement);
    const result = check(mutated);
    assert.notEqual(result.status, 0, `${replacement} must not weaken npm audit`);
    assert.match(result.stderr, /ts-audit.*recipe|exact audited command/i);
  }
});

test("effective Make graph rejects security gate removal from precommit and check", () => {
  for (const target of ["precommit", "check"]) {
    const disconnected = canonical.replace(
      new RegExp(`^${target}: security-makefile-check security-dependency-check$`, "m"),
      `${target}:`,
    );
    assert.notEqual(disconnected, canonical, `${target} must declare security prerequisites`);
    const result = check(disconnected);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(`${target}.*security`, "i"));
  }
});

test("check cannot suppress or disconnect any ecosystem security scanner", () => {
  for (const scanner of ["go-vulncheck", "ts-audit", "swift-check", "rust-release-check"]) {
    const exactLine = `\t$(MAKE) ${scanner}`;
    for (const replacement of ["", `\t-$(MAKE) ${scanner}`, `${exactLine} || true`]) {
      const mutated = replaceTargetRecipeLine(canonical, "check", exactLine, replacement);
      const result = check(mutated);
      assert.notEqual(result.status, 0, `${scanner} mutation must fail`);
      assert.match(result.stderr, /check must call|exact, unsuppressed/i);
    }
  }
});

test("precommit cannot disconnect language security wrappers", () => {
  for (const wrapper of ["precommit-go", "precommit-ts", "precommit-swift", "precommit-rust"]) {
    const exactLine = `\t$(MAKE) ${wrapper}`;
    const mutated = replaceTargetRecipeLine(canonical, "precommit", exactLine, "");
    const result = check(mutated);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(`precommit.*${wrapper}|${wrapper}.*exact`, "i"));
  }
});

test("release-check cannot suppress or disconnect the complete check gate", () => {
  const exactLine = "\t$(MAKE) check";
  for (const replacement of ["", "\t-$(MAKE) check", `${exactLine} || true`]) {
    const mutated = replaceTargetRecipeLine(canonical, "release-check", exactLine, replacement);
    const result = check(mutated);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /release-check.*check|exact, unsuppressed/i);
  }
  const ignored = check(`${canonical}\n.IGNORE: release-check\n`);
  assert.notEqual(ignored.status, 0);
  assert.match(ignored.stderr, /IGNORE.*release-check|release-check.*IGNORE/i);
});

test("effective Make graph rejects non-phony security targets", () => {
  const nonPhony = canonical.replace(
    /^\.PHONY: (.*)security-dependency-check /m,
    ".PHONY: $1",
  );
  assert.notEqual(nonPhony, canonical);
  const result = check(nonPhony);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /security-dependency-check.*phony/i);
});

test("Make special targets cannot suppress security failures", () => {
  for (const specialTarget of [
    ".IGNORE:",
    ".IGNORE: go-vulncheck",
    ".IGNORE: check security-makefile-check precommit-swift",
    ".ONESHELL:",
  ]) {
    const result = check(`${canonical}\n${specialTarget}\n`);
    assert.notEqual(result.status, 0, `${specialTarget} must be rejected`);
    assert.match(result.stderr, /IGNORE|ONESHELL|suppress/i);
  }
});
