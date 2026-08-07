#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const requiredSecurityTests = [
  "scripts/security-dependencies.test.mjs",
  "scripts/go-security.test.mjs",
  "scripts/rust-security.test.mjs",
  "scripts/swift-security.test.mjs",
  "scripts/prepare-ts-package-cache.test.mjs",
  "scripts/security-makefile.test.mjs",
  "scripts/run-final-stage.test.mjs",
  "scripts/run-final-lanes.test.mjs",
  "scripts/run-precommit-wave.test.mjs",
  "scripts/test-architecture-contract.mjs",
];

const protectedVariables = new Set([
  ".RECIPEPREFIX", ".SHELLFLAGS", "GNUMAKEFLAGS", "MAKE", "MAKE_COMMAND",
  "MAKECMDGOALS", "MAKEFILE_LIST", "MAKEFILES", "MAKEFLAGS", "MAKELEVEL",
  "MAKEOVERRIDES", "MAKE_RESTARTS", "MFLAGS", "PATH", "SHELL",
]);

const protectedTargets = [
  "test", "test-resume", "coverage-race", "browser-smoke", "browser-compat", "precommit", "precommit-source",
  "diagnostic", "performance", "security-makefile-check", "security-dependency-check",
  "security-package-check", "release-policy-check", "release-version-check", "release-test",
  "release-check", "check", "final-network-preflight", "final-offline-contracts",
  "final-package-validation", "final-integration-lanes", "final-post-validation",
  "final-go-check", "final-race-check", "final-ts-check", "final-swift-check",
  "final-rust-check", "go-test-race", "go-vulncheck", "ts-audit",
  "swift-security-check", "swift-source-guard", "rust-audit",
];

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function targetBlock(source, target) {
  const match = new RegExp(`^${escapeRegExp(target)}:([^\\n]*)\\n((?:\\t.*\\n)*)`, "m").exec(source);
  if (!match) throw new Error(`Makefile target ${target} is missing`);
  return {
    prerequisites: match[1].trim().split(/\s+/).filter(Boolean),
    recipe: match[2].trimEnd().split("\n").filter(Boolean),
  };
}

function exactRecipe(source, target, expected) {
  const actual = targetBlock(source, target).recipe;
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${target} recipe must be ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`);
  }
}

function validateSource(source) {
  if (/\$[({](?:eval|file|shell)\b|\$[({]\s*call(?:[\s,})]|$)/.test(source)) {
    throw new Error("Makefile must not generate or rewrite Make syntax dynamically");
  }
  if (/^(?:-?include|sinclude|load|ifeq|ifneq|ifdef|ifndef|else|endif)(?:\s|$)/m.test(source)) {
    throw new Error("Makefile must not load or conditionally replace the audited graph");
  }
  if (/^\.(?:IGNORE|ONESHELL)\s*:/m.test(source)) {
    throw new Error("Makefile must not suppress recipe failures");
  }
  for (const [index, line] of source.split("\n").entries()) {
    if (line.startsWith("\t") || line.trim() === "" || line.trimStart().startsWith("#")) continue;
    if (/\\$/.test(line)) throw new Error(`Makefile line ${index + 1} uses a non-recipe continuation`);
    const assignment = /^(?:override\s+|export\s+|private\s+)*([^:=+?!\s]+)\s*(?::=|\?=|\+=|!=|=)/.exec(line.trim());
    if (assignment && (assignment[0].includes("!=") || protectedVariables.has(assignment[1]) || assignment[1].includes("$"))) {
      throw new Error(`Makefile line ${index + 1} assigns a protected control variable`);
    }
    if (/^[^:]*\$[({][^:]*:/.test(line)) throw new Error(`Makefile line ${index + 1} declares a dynamic target`);
    const targetAssignment = /^([^:]+):[^\n]*(?:override\s+|export\s+|private\s+)*(\S+)\s*(?::=|\?=|\+=|!=|=)/.exec(line);
    if (targetAssignment && (protectedVariables.has(targetAssignment[2]) || protectedTargets.some((target) => targetAssignment[1].trim().split(/\s+/).includes(target)))) {
      throw new Error(`Makefile line ${index + 1} assigns target-specific control state`);
    }
  }
  for (const target of protectedTargets) {
    const count = [...source.matchAll(new RegExp(`^${escapeRegExp(target)}\\s*:`, "gm"))].length;
    if (count !== 1) throw new Error(`Makefile target ${target} has ${count} definitions`);
    if (!new RegExp(`^\\.PHONY:.*(?:^|\\s)${escapeRegExp(target)}(?:\\s|$)`, "m").test(source)) {
      throw new Error(`${target} must be phony`);
    }
  }
}

function verifyGraph(source) {
  exactRecipe(source, "test", ["\tgo -C flowersec-go run ./internal/cmd/flowersec-test run --suite acceptance"]);
  exactRecipe(source, "test-resume", ["\tgo -C flowersec-go run ./internal/cmd/flowersec-test resume --suite acceptance"]);
  exactRecipe(source, "coverage-race", ["\tgo -C flowersec-go run ./internal/cmd/flowersec-test run --suite coverage-race"]);
  exactRecipe(source, "browser-smoke", ["\tgo -C flowersec-go run ./internal/cmd/flowersec-test run --suite browser-smoke"]);
  exactRecipe(source, "browser-compat", ["\tgo -C flowersec-go run ./internal/cmd/flowersec-test run --suite browser-compat"]);
  exactRecipe(source, "precommit", ["\t$(MAKE) precommit-source"]);
  exactRecipe(source, "diagnostic", ["\t$(FLOWERSEC_TEST_HOST) run --suite diagnostic"]);
  exactRecipe(source, "performance", ["\t$(FLOWERSEC_TEST_HOST) run --suite performance"]);
  exactRecipe(source, "security-makefile-check", ["\tnode scripts/check-security-makefile.mjs Makefile"]);
  exactRecipe(source, "security-dependency-check", [
    `\tnode --test ${requiredSecurityTests.join(" ")}`,
    "\tnode scripts/generate-source-inventory.mjs --check",
  ]);
  exactRecipe(source, "release-policy-check", [
    "\t./scripts/check-release-workflow-policy.sh",
    "\t$(MAKE) release-version-check",
    "\t$(MAKE) release-test",
  ]);
  exactRecipe(source, "release-version-check", ["\tnode scripts/check-release-version-consistency.mjs"]);
  exactRecipe(source, "release-test", ["\tnode --test scripts/check-release-version-consistency.test.mjs scripts/release.test.mjs"]);
  exactRecipe(source, "release-check", ["\tnode scripts/check-release-version-consistency.mjs"]);
  exactRecipe(source, "final-post-validation", ["\t$(MAKE) example-check"]);
  exactRecipe(source, "final-race-check", ["\t$(MAKE) go-test-race"]);

  const check = targetBlock(source, "check");
  if (JSON.stringify(check.prerequisites) !== JSON.stringify(["security-makefile-check"])) {
    throw new Error("check must have only security-makefile-check as its prerequisite");
  }
  for (const token of ["release-policy-check", "final-network-preflight", "final-offline-contracts", "final-package-validation", "final-integration-lanes", "final-post-validation"]) {
    if (!check.recipe.some((line) => line.includes(token))) throw new Error(`check is missing ${token}`);
  }
  const order = ["final-network-preflight", "final-offline-contracts", "final-package-validation", "final-integration-lanes", "final-post-validation"]
    .map((token) => check.recipe.findIndex((line) => line.includes(token)));
  if (order.some((value, index) => value < 0 || index > 0 && value <= order[index - 1])) throw new Error("check phase order is invalid");

  if (/transportcheck|transport-test-runner|ubuntu-test-runner|run-transport-v2|flowersec-test-helper|CHECK_INTEROP/.test(source)) {
    throw new Error("Makefile retains retired test orchestration");
  }

}

export function verifySecurityMakefile(makefile) {
  const source = fs.readFileSync(makefile, "utf8").replace(/\r\n?/g, "\n");
  validateSource(source);
  verifyGraph(source);
}

try {
  if (process.argv.length !== 3) throw new Error("usage: check-security-makefile.mjs <Makefile>");
  verifySecurityMakefile(path.resolve(process.argv[2]));
  process.stdout.write("verified effective security Make graph\n");
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
