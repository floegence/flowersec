#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const requiredSecurityTests = [
  "scripts/security-dependencies.test.mjs",
  "scripts/go-security.test.mjs",
  "scripts/rust-security.test.mjs",
  "scripts/swift-security.test.mjs",
  "scripts/security-makefile.test.mjs",
];

const protectedMakeControlVariables = new Set([
  ".RECIPEPREFIX",
  ".SHELLFLAGS",
  "GNUMAKEFLAGS",
  "MAKE",
  "MAKE_COMMAND",
  "MAKECMDGOALS",
  "MAKEFILE_LIST",
  "MAKEFILES",
  "MAKEFLAGS",
  "MAKELEVEL",
  "MAKEOVERRIDES",
  "MAKE_RESTARTS",
  "MFLAGS",
  "PATH",
  "SHELL",
]);

const expectedSecurityConfiguration = new Map([
  ["CHECK_INTEROP", "1"],
  ["YAMUX_INTEROP", "1"],
  ["YAMUX_INTEROP_STRESS", "0"],
  ["YAMUX_INTEROP_CLIENT_RST", "0"],
  ["YAMUX_INTEROP_DEBUG", "0"],
  ["SWIFT_SOURCE_GUARD_PATTERN", "Redeven|redeven|RedevenFlowersec|RedevenRPCClient|FlowersecDirectClient|FlowersecDirectSession|FlowersecDirectError|RuntimeFS|RuntimeGit|RuntimeTerminal|RuntimeFlower|RuntimeTypedRPC|RuntimeJSONValue|RuntimeRPCPayload|FlowerMessage|TerminalSession|MonitorSnapshot|direct runtime"],
  ["SWIFT_SOURCE_GUARD_PATHS", "flowersec-swift/Sources Package.swift README.md flowersec-swift/README.md docs examples .github"],
  ["SWIFT_SOURCE_GUARD_PRUNE", ".build .git .swiftpm dist node_modules"],
  ["SWIFT_SOURCE_GUARD_FILE_GLOBS", "-name '*.go' -o -name '*.json' -o -name '*.md' -o -name '*.mjs' -o -name '*.swift' -o -name '*.ts' -o -name '*.tsx' -o -name '*.txt' -o -name '*.yaml' -o -name '*.yml'"],
]);

const expectedSwiftSourceGuardRecipe = [
  "\t@status=1; \\",
  "\tif command -v rg >/dev/null 2>&1; then \\",
  "\tif rg -n --glob '!.build/**' --glob '!.git/**' --glob '!.swiftpm/**' --glob '!dist/**' --glob '!node_modules/**' '$(SWIFT_SOURCE_GUARD_PATTERN)' $(SWIFT_SOURCE_GUARD_PATHS); then \\",
  "\tstatus=0; \\",
  "\telse \\",
  "\tstatus=$$?; \\",
  "\tfi; \\",
  "\telse \\",
  "\tmatches=$$(find $(SWIFT_SOURCE_GUARD_PATHS) $$(printf ' -name %s -o' $(SWIFT_SOURCE_GUARD_PRUNE) | sed 's/ -o$$//') -prune -o -type f \\( $(SWIFT_SOURCE_GUARD_FILE_GLOBS) \\) -exec grep -InE '$(SWIFT_SOURCE_GUARD_PATTERN)' {} +); \\",
  "\tif [ -n \"$$matches\" ]; then \\",
  "\tprintf \"%s\\n\" \"$$matches\"; \\",
  "\tstatus=0; \\",
  "\telse \\",
  "\tstatus=1; \\",
  "\tfi; \\",
  "\tfi; \\",
  "\tif [ \"$$status\" = \"0\" ]; then \\",
  "\techo \"Swift SDK contains downstream product semantics\"; \\",
  "\texit 1; \\",
  "\tfi; \\",
  "\tif [ \"$$status\" != \"1\" ]; then \\",
  "\techo \"Swift source guard scan failed\"; \\",
  "\texit \"$$status\"; \\",
  "\tfi",
];

function runMake(makefile, args) {
  return spawnSync("make", ["--no-print-directory", ...args, "-f", makefile], {
    cwd: path.dirname(makefile),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function targetDefinitionCount(source, target) {
  const expression = new RegExp(`^${escapeRegExp(target)}\\s*:`, "gm");
  return [...source.matchAll(expression)].length;
}

function effectiveVariable(database, name) {
  const expression = new RegExp(`^${escapeRegExp(name)}[ \\t]*(?::=|=) ([^\\n]*)$`, "gm");
  const matches = [...database.matchAll(expression)];
  if (matches.length !== 1) {
    throw new Error(`effective Make configuration variable ${name} has ${matches.length} definitions`);
  }
  return matches[0][1];
}

function validateMakefileSource(source, protectedTargets) {
  if (/\$[({](?:eval|file|shell)\b/.test(source) || /\$[({]\s*call(?:[\s,})]|$)/.test(source)) {
    throw new Error("Makefile must not generate or rewrite Make syntax dynamically");
  }

  let inDefine = false;
  for (const [index, line] of source.split("\n").entries()) {
    if (line.startsWith("\t")) continue;
    const trimmed = line.trim();
    if (inDefine) {
      if (/^endef(?:\s|$)/.test(trimmed)) inDefine = false;
      continue;
    }
    if (/\\$/.test(line)) {
      throw new Error(`Makefile line ${index + 1} must not use non-recipe backslash continuation`);
    }
    if (/^(?:(?:override|export|private)\s+)*define(?:\s|$)/.test(trimmed)) {
      const name = trimmed.replace(/^(?:(?:override|export|private)\s+)*define\s*/, "").trim();
      if (name.includes("$") || protectedMakeControlVariables.has(name)) {
        throw new Error(`Makefile line ${index + 1} must not define a dynamic or protected Make control variable`);
      }
      inDefine = true;
      continue;
    }
    if (/^(?:-?include|sinclude|load)(?:\s|$)/.test(trimmed)) {
      throw new Error(`Makefile line ${index + 1} must not load external Make syntax`);
    }
    if (/^(?:ifeq|ifneq|ifdef|ifndef|else|endif)(?:\s|$)/.test(trimmed)) {
      throw new Error(`Makefile line ${index + 1} must not conditionally redefine the audited Make graph`);
    }
    if (/^\$[({]/.test(trimmed)) {
      throw new Error(`Makefile line ${index + 1} must not expand dynamic Make syntax`);
    }

    const assignmentText = trimmed.replace(/^(?:(?:override|export|private)\s+)*/, "");
    const assignmentOperator = /(?:::=|::?=|\+=|\?=|!=|=)/.exec(assignmentText);
    const ruleSeparator = /:(?![:=])/.exec(assignmentText);
    if (assignmentOperator?.[0] === "!=") {
      throw new Error(`Makefile line ${index + 1} must not execute a shell assignment`);
    }
    if (assignmentOperator && (!ruleSeparator || assignmentOperator.index < ruleSeparator.index)) {
      const name = assignmentText.slice(0, assignmentOperator.index).trim();
      if (name.includes("$") || protectedMakeControlVariables.has(name)) {
        throw new Error(`Makefile line ${index + 1} must not assign a dynamic or protected Make control variable: ${name}`);
      }
      continue;
    }

    if (ruleSeparator) {
      const targets = assignmentText.slice(0, ruleSeparator.index).trim().split(/\s+/).filter(Boolean);
      const ruleBody = assignmentText.slice(ruleSeparator.index + 1).trim();
      if (targets.some((target) => target.includes("$"))) {
        throw new Error(`Makefile line ${index + 1} must not declare a dynamically named target`);
      }
      const targetAssignment = /^(?:(?:override|export|private)\s+)*(.+?)\s*(?:::=|::?=|\+=|\?=|!=|=)/.exec(ruleBody);
      if (targetAssignment) {
        const name = targetAssignment[1].trim();
        const protectedTarget = targets.find((target) => protectedTargets.includes(target));
        const patternTarget = targets.find((target) => target.includes("%"));
        if (protectedMakeControlVariables.has(name) || expectedSecurityConfiguration.has(name) || name.includes("$") || protectedTarget || patternTarget) {
          const scope = protectedTarget
            ? ` on ${protectedTarget}`
            : patternTarget
              ? ` on pattern target ${patternTarget}`
              : "";
          throw new Error(`Makefile line ${index + 1} must not assign a target-specific control variable${scope}: ${name}`);
        }
        continue;
      }
    }
  }
  if (inDefine) throw new Error("Makefile contains an unterminated define block");
}

function effectivePrerequisites(database, target) {
  database = makeFilesDatabase(database);
  const expression = new RegExp(`^${escapeRegExp(target)}:([^\\n]*)$`, "m");
  const match = expression.exec(database);
  if (!match) throw new Error(`effective Make graph has no ${target} target`);
  return match[1].trim().split(/\s+/).filter(Boolean);
}

function effectiveTargetBlock(database, target) {
  database = makeFilesDatabase(database);
  const expression = new RegExp(`^${escapeRegExp(target)}:[^\\n]*$`, "m");
  const match = expression.exec(database);
  if (!match) throw new Error(`effective Make graph has no ${target} target`);
  const end = database.indexOf("\n\n", match.index);
  return database.slice(match.index, end < 0 ? database.length : end);
}

function makeFilesDatabase(database) {
  const startMarker = "# Files\n";
  const endMarker = "# files hash-table stats:";
  const end = database.lastIndexOf(endMarker);
  const start = end < 0 ? -1 : database.lastIndexOf(startMarker, end);
  if (start < 0 || end < start + startMarker.length) {
    throw new Error("cannot locate the final effective Make files database");
  }
  return database.slice(start + startMarker.length, end);
}

function effectiveRecipe(database, target) {
  const block = effectiveTargetBlock(database, target);
  const lines = block.split("\n");
  const marker = lines.findIndex((line) => /^#\s+(?:commands|recipe) to execute/.test(line));
  if (marker < 0) return [];
  return lines
    .slice(marker + 1)
    .filter((line) => line.startsWith("\t") && line.trim() !== "")
    .map((line) => line.replace(/^\t[ \t]*/, "\t"));
}

export function verifySecurityMakefile(makefile) {
  const source = fs.readFileSync(makefile, "utf8").replace(/\r\n?/g, "\n");
  const protectedTargets = [
    "security-makefile-check",
    "security-dependency-check",
    "security-package-check",
    "ts-ensure-deps",
    "ts-build",
    "ts-test-short",
    "go-test-race",
    "go-vulncheck",
    "ts-audit",
    "swift-security-check",
    "swift-source-guard",
    "swift-check",
    "rust-audit",
    "rust-release-check",
    "rust-test-short",
    "release-policy-check",
    "release-version-check",
    "release-test",
    "release-check",
    "precommit",
    "check",
    "final-integration-lanes",
    "final-go-check",
    "final-ts-check",
    "final-swift-check",
    "final-rust-check",
  ];
  validateMakefileSource(source, protectedTargets);
  for (const target of protectedTargets) {
    const count = targetDefinitionCount(source, target);
    if (count !== 1) throw new Error(`Makefile target ${target} has ${count} definitions; duplicate or override recipes are forbidden`);
  }

  const database = runMake(makefile, ["-pRrq"]);
  if (![0, 1].includes(database.status) || database.error) {
    throw new Error(`cannot parse effective Make graph: ${database.error?.message ?? database.stderr}`);
  }
  if (database.stderr.trim() !== "") {
    throw new Error(`Make reported a duplicate or overridden recipe: ${database.stderr.trim()}`);
  }
  for (const [name, expected] of expectedSecurityConfiguration) {
    const actual = effectiveVariable(database.stdout, name);
    if (actual !== expected) {
      throw new Error(`effective Make configuration variable ${name} must equal ${JSON.stringify(expected)}; got ${JSON.stringify(actual)}`);
    }
  }

  const failureCriticalTargets = new Set([
    ...protectedTargets,
    "precommit-go",
    "precommit-ts",
    "precommit-swift",
    "precommit-rust",
  ]);
  const ignore = /^\.IGNORE:([^\n]*)$/m.exec(database.stdout);
  if (ignore) {
    const ignoredTargets = ignore[1].trim().split(/\s+/).filter(Boolean);
    if (ignoredTargets.length === 0) {
      throw new Error("global .IGNORE suppresses every security failure");
    }
    const protectedIgnored = ignoredTargets.filter((target) => failureCriticalTargets.has(target));
    if (protectedIgnored.length > 0) {
      throw new Error(`.IGNORE suppresses security targets: ${protectedIgnored.join(", ")}`);
    }
  }
  if (/^\.ONESHELL:/m.test(database.stdout)) {
    throw new Error(".ONESHELL can suppress an earlier security recipe failure");
  }

  for (const target of protectedTargets) {
    if (!/#\s+Phony target\b/.test(effectiveTargetBlock(database.stdout, target))) {
      throw new Error(`${target} must remain an effective phony target`);
    }
  }

  for (const target of ["precommit", "check"]) {
    const prerequisites = new Set(effectivePrerequisites(database.stdout, target));
    for (const required of ["security-makefile-check", "security-dependency-check"]) {
      if (!prerequisites.has(required)) {
        throw new Error(`Makefile target ${target} effective graph is missing security prerequisite ${required}`);
      }
    }
  }
  if (!effectivePrerequisites(database.stdout, "security-dependency-check").includes("ts-ensure-deps")) {
    throw new Error("security-dependency-check effective graph is missing ts-ensure-deps");
  }
  if (!effectivePrerequisites(database.stdout, "security-package-check").includes("ts-build")) {
    throw new Error("security-package-check effective graph is missing ts-build");
  }
  if (!effectivePrerequisites(database.stdout, "ts-build").includes("ts-ensure-deps")) {
    throw new Error("ts-build effective graph is missing ts-ensure-deps");
  }

  const exactTestCommand = `\tnode --test ${requiredSecurityTests.join(" ")}`;
  const expectedRecipes = new Map([
    ["security-makefile-check", ["\tnode scripts/check-security-makefile.mjs Makefile"]],
    ["security-dependency-check", [
      exactTestCommand,
      "\tnode scripts/generate-source-inventory.mjs --check",
    ]],
    ["security-package-check", ["\tnode --test scripts/source-inventory.test.mjs"]],
    ["ts-build", ["\tcd flowersec-ts && rm -rf dist && npm run build"]],
    ["ts-test-short", ["\tcd flowersec-ts && npx vitest run --exclude 'src/**/*.integration.test.ts' --exclude 'src/v2/session_go_interop.test.ts' --exclude 'src/v2/browserBundle.test.ts'"]],
    ["go-test-race", [
      "\tcd flowersec-go && go test -race -timeout=5m ./...",
      "\tcd tools/idlgen && go test -race -timeout=5m ./...",
      "\tcd tools/releasenotes && go test -race -timeout=5m ./...",
      "\tcd tools/stabilitycheck && go test -race -timeout=5m ./...",
      "\t./scripts/run-go-test-race-shards.sh tools/transportcheck 18 5m 18 race 1",
    ]],
    ["go-vulncheck", ["\tnode scripts/check-go-security.mjs"]],
    ["ts-audit", ["\tcd flowersec-ts && npm audit --audit-level=info --include=prod --include=dev --include=optional --include=peer"]],
    ["swift-security-check", ["\tnode scripts/check-swift-security.mjs"]],
    ["swift-source-guard", expectedSwiftSourceGuardRecipe],
    ["rust-audit", ["\tnode scripts/check-rust-security.mjs"]],
    ["release-policy-check", [
      "\t./scripts/check-release-workflow-policy.sh",
      "\t$(MAKE) release-version-check",
      "\t$(MAKE) release-test",
    ]],
    ["release-version-check", ["\tnode scripts/check-release-version-consistency.mjs"]],
    ["release-test", ["\tnode --test scripts/check-release-version-consistency.test.mjs scripts/release.test.mjs"]],
    ["release-check", [
      "\t$(MAKE) check",
      "\t$(MAKE) transport-v2-signed-evidence-check",
    ]],
    ["final-integration-lanes", ["\t$(MAKE) -j5 final-go-check final-race-check final-ts-check final-swift-check final-rust-check"]],
    ["final-go-check", [
      "\t$(MAKE) transport-v2-unit",
      "\t$(MAKE) weaknet-smoke",
      "\t$(MAKE) quic-native-smoke",
      "\t$(MAKE) go-vet",
      "\t$(MAKE) go-test",
      "\t$(MAKE) go-cover-check",
      "\t$(MAKE) go-vulncheck",
    ]],
    ["final-race-check", ["\t$(MAKE) go-test-race"]],
    ["final-ts-check", [
      "\t$(MAKE) ts-lint",
      "\t$(MAKE) ts-build",
      "\t$(MAKE) ts-browser-ensure",
      "\t$(MAKE) ts-browser-e2e",
      "\t$(MAKE) ts-test",
      "\t$(MAKE) ts-cover-check",
      "\t$(MAKE) ts-package-check",
      "\t$(MAKE) ts-audit",
    ]],
    ["swift-check", [
      "\t$(MAKE) swift-package-check",
      "\t$(MAKE) swift-security-check",
      "\t$(MAKE) swift-source-guard",
      "\t$(MAKE) swift-build",
      "\t$(MAKE) swift-test",
      "\t$(MAKE) swift-cover-check",
    ]],
    ["final-swift-check", ["\t$(MAKE) swift-check"]],
    ["final-rust-check", ["\t$(MAKE) rust-release-check"]],
    ["rust-test-short", ["\tcd flowersec-rust && rustup run 1.88.0 cargo test --all-features --lib"]],
    ["precommit-go", [
      "\t$(MAKE) fmt-check",
      "\t$(MAKE) go-vet",
      "\t$(MAKE) go-test-short",
      "\t$(MAKE) go-cover-check",
    ]],
    ["precommit-ts", [
      "\t$(MAKE) ts-ensure-deps",
      "\t$(MAKE) ts-lint",
      "\t$(MAKE) ts-test-short",
    ]],
    ["precommit-swift", [
      "\t$(MAKE) swift-package-check",
      "\t$(MAKE) swift-security-check",
      "\t$(MAKE) swift-source-guard",
    ]],
    ["precommit-rust", [
      "\t$(MAKE) rust-fmt-check",
      "\t$(MAKE) rust-clippy",
      "\t$(MAKE) rust-test-short",
    ]],
  ]);
  for (const [target, expected] of expectedRecipes) {
    const actual = effectiveRecipe(database.stdout, target);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`${target} effective recipe must use ${JSON.stringify(expected)} exactly; got ${JSON.stringify(actual)}`);
    }
  }

  for (const [target, requiredCalls] of [
    ["check", ["release-policy-check", "security-package-check", "final-integration-lanes"]],
    ["precommit", ["release-policy-check", "precommit-go", "precommit-ts", "precommit-swift", "precommit-rust"]],
  ]) {
    const recipe = effectiveRecipe(database.stdout, target);
    for (const required of requiredCalls) {
      const exactCall = `\t$(MAKE) ${required}`;
      if (recipe.filter((line) => line === exactCall).length !== 1) {
        throw new Error(`${target} must call ${required} with one exact, unsuppressed recipe line`);
      }
    }
  }

  const precommitDryRun = runMake(makefile, ["-n", "precommit"]);
  const finalDryRun = runMake(makefile, ["-n", "check"]);
  for (const [label, result] of [["precommit", precommitDryRun], ["check", finalDryRun]]) {
    if (result.status !== 0 || result.error || result.stderr.trim() !== "") {
      throw new Error(`cannot inspect ${label} Make graph: ${result.error?.message ?? result.stderr}`);
    }
  }
  const finalOnlyCommands = [
    "cd flowersec-go && go test -timeout=5m ./...",
    "npm run test:coverage",
    "npm run verify:package",
    "swift build",
    "swift test --enable-code-coverage",
    "cargo package --allow-dirty",
    "cargo publish --dry-run --allow-dirty",
  ];
  for (const command of finalOnlyCommands) {
    if (precommitDryRun.stdout.includes(command)) {
      throw new Error(`precommit must not reach final-only command: ${command}`);
    }
    if (!finalDryRun.stdout.includes(command)) {
      throw new Error(`check must retain final-only command: ${command}`);
    }
  }

  for (const [target, requiredPrerequisite] of [["rust-release-check", "rust-audit"]]) {
    if (!effectivePrerequisites(database.stdout, target).includes(requiredPrerequisite)) {
      throw new Error(`${target} effective graph is missing ${requiredPrerequisite}`);
    }
  }

  const dryRun = runMake(makefile, ["-n", "security-dependency-check"]);
  if (dryRun.status !== 0 || dryRun.error || dryRun.stderr.trim() !== "") {
    throw new Error(`cannot inspect effective security-dependency-check recipe: ${dryRun.error?.message ?? dryRun.stderr}`);
  }
  const commands = dryRun.stdout.trim().split("\n").map((line) => line.trim()).filter(Boolean);
  const testCommand = commands.find((line) => line.startsWith("node --test "));
  if (!testCommand) throw new Error("effective security-dependency-check has no Node test command");
  for (const requiredTest of requiredSecurityTests) {
    if (!testCommand.split(/\s+/).includes(requiredTest)) {
      throw new Error(`effective security-dependency-check omits ${requiredTest}`);
    }
  }
  if (!commands.includes("node scripts/generate-source-inventory.mjs --check")) {
    throw new Error("effective security-dependency-check must enforce source inventory freshness with --check");
  }
}

function main() {
  if (process.argv.length !== 3) throw new Error("usage: check-security-makefile.mjs <Makefile>");
  verifySecurityMakefile(path.resolve(process.argv[2]));
  process.stdout.write("verified effective security Make graph\n");
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
