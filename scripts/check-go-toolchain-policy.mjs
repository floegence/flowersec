#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  containerDockerfileContracts,
  parseDockerfile,
} from "./check-container-release-policy.mjs";
import { goSecurityToolVersions } from "./check-go-security.mjs";

export const goSecurityBaseline = "1.27.0";
const goToolchain = `go${goSecurityBaseline}`;
const forbiddenGoVersion = [1, 26, 5].join(".");

export function parseGoModPolicy(source, label) {
  const directives = source.split("\n").flatMap((line) => {
    const match = /^\s*(go|toolchain)\s+(\S+)\s*(?:\/\/.*)?$/.exec(line);
    return match ? [{ name: match[1], value: match[2] }] : [];
  });
  const goDirectives = directives.filter(({ name }) => name === "go");
  if (goDirectives.length !== 1) throw new Error(`${label} must contain exactly one go directive`);
  if (directives.some(({ name }) => name === "toolchain")) {
    throw new Error(`${label} must not contain a toolchain directive`);
  }
  return goDirectives[0].value;
}

export function parseSetupGoSteps(source, label) {
  const lines = source.split("\n");
  const steps = [];
  for (let index = 0; index < lines.length; index += 1) {
    const item = /^(\s*)-\s+(.*)$/.exec(lines[index]);
    if (!item) continue;
    const indentation = item[1].length;
    const block = [item[2]];
    while (index + 1 < lines.length) {
      const nextItem = /^(\s*)-\s+/.exec(lines[index + 1]);
      if (nextItem && nextItem[1].length <= indentation) break;
      block.push(lines[index + 1]);
      index += 1;
    }
    const uses = block.flatMap((line) => {
      const match = /^\s*uses:\s*([^#\s]+)(?:\s+#.*)?$/.exec(line);
      return match ? [match[1]] : [];
    });
    if (!uses.some((value) => value.startsWith("actions/setup-go@"))) continue;
    const versionFiles = block.flatMap((line) => {
      const match = /^\s*go-version-file:\s*([^#\s]+)(?:\s+#.*)?$/.exec(line);
      return match ? [match[1]] : [];
    });
    if (uses.length !== 1 || versionFiles.length !== 1) {
      throw new Error(`${label} setup-go step must contain one action and one go-version-file`);
    }
    steps.push({ uses: uses[0], versionFile: versionFiles[0] });
  }
  return steps;
}

function read(repoRoot, relative) {
  return fs.readFileSync(path.join(repoRoot, relative), "utf8");
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} must be ${expected}; found ${actual}`);
}

function uniqueCapture(source, pattern, label) {
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1) throw new Error(`${label} must occur exactly once; found ${matches.length}`);
  return matches[0][1];
}

export function verifyGoToolchainPolicy(repoRoot) {
  const moduleFiles = [
    "flowersec-go/go.mod",
    "tools/releasenotes/go.mod",
    "tools/stabilitycheck/go.mod",
  ];
  for (const relative of moduleFiles) {
    assertEqual(parseGoModPolicy(read(repoRoot, relative), relative), goSecurityBaseline, relative);
  }

  const dockerfile = read(repoRoot, "docker/flowersec-runtime/Dockerfile");
  const instructions = parseDockerfile(dockerfile);
  const buildStages = instructions.filter(({ instruction }) => instruction === "FROM");
  if (buildStages.length !== 2) throw new Error("runtime Dockerfile must contain exactly two FROM instructions");
  const image = /^--platform=\$BUILDPLATFORM\s+golang:([^@\s]+)@sha256:[0-9a-f]{64}\s+AS\s+build$/.exec(
    buildStages[0].value,
  );
  if (!image) throw new Error("runtime Dockerfile builder must be a digest-pinned golang build stage");
  assertEqual(image[1], `${goSecurityBaseline}-alpine`, "runtime Dockerfile Go builder tag");
  const contractBuilder = containerDockerfileContracts["docker/flowersec-runtime/Dockerfile"].buildFrom;
  const contractImage = /\bgolang:([^@\s]+)@sha256:[0-9a-f]{64}\b/.exec(contractBuilder)?.[1];
  assertEqual(contractImage, `${goSecurityBaseline}-alpine`, "runtime Dockerfile policy Go builder tag");

  const workflowContracts = new Map([
    [".github/workflows/ci.yml", 1],
    [".github/workflows/release.yml", 2],
  ]);
  for (const [relative, expectedCount] of workflowContracts) {
    const steps = parseSetupGoSteps(read(repoRoot, relative), relative);
    if (steps.length !== expectedCount) {
      throw new Error(`${relative} must contain ${expectedCount} setup-go step(s); found ${steps.length}`);
    }
    for (const step of steps) {
      assertEqual(step.versionFile, "flowersec-go/go.mod", `${relative} setup-go version file`);
    }
  }

  const securityScanner = read(repoRoot, "scripts/check-go-security.mjs");
  assertEqual(
    uniqueCapture(securityScanner, /^\s*goToolchain:\s*"(go[^"]+)",$/gm, "Go security scanner toolchain"),
    goToolchain,
    "Go security scanner toolchain",
  );
  assertEqual(goSecurityToolVersions({}).goToolchain, goToolchain, "loaded Go security scanner toolchain");

  const hostInit = read(repoRoot, "scripts/test-host-init.sh");
  const hostVersion = /^readonly go_version=(\S+)$/m.exec(hostInit)?.[1];
  assertEqual(hostVersion, goSecurityBaseline, "test host Go version");
  if (!hostInit.includes('go${go_version}.linux-${go_arch}.tar.gz')
    || !hostInit.includes('grep -F "go${go_version}"')) {
    throw new Error("test host bootstrap must derive downloads and validation from go_version");
  }

  const inventoryGenerator = read(repoRoot, "scripts/generate-source-inventory.mjs");
  assertEqual(
    uniqueCapture(inventoryGenerator, /^\s*GOTOOLCHAIN:\s*"(go[^"]+)",$/gm, "source inventory Go toolchain"),
    goToolchain,
    "source inventory Go toolchain",
  );
  const finalStage = read(repoRoot, "scripts/run-final-stage.mjs");
  assertEqual(
    uniqueCapture(finalStage, /^\s*\|\| state\.version !== "(go[^"]+)"$/gm, "final stage Go toolchain"),
    goToolchain,
    "final stage Go toolchain",
  );
  const stabilitySource = read(repoRoot, "tools/stabilitycheck/main.go");
  assertEqual(
    uniqueCapture(stabilitySource, /^const repoGoToolchain = "(go[^"]+)"$/gm, "stability checker Go toolchain"),
    goToolchain,
    "stability checker Go toolchain",
  );
  const banned = [];
  const ignored = new Set([".build", ".git", ".swiftpm", "coverage", "dist", "node_modules", "target", "test-results"]);
  const pending = [repoRoot];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink() || ignored.has(entry.name)) continue;
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        pending.push(entryPath);
      } else if (entry.isFile()) {
        const contents = fs.readFileSync(entryPath);
        if (contents.includes(Buffer.from(forbiddenGoVersion))) {
          banned.push(path.relative(repoRoot, entryPath));
        }
      }
    }
  }
  if (banned.length > 0) {
    throw new Error(`Go ${forbiddenGoVersion} is forbidden in maintained sources: ${banned.sort().join(", ")}`);
  }
}

function main() {
  if (process.argv.length !== 2) throw new Error("usage: check-go-toolchain-policy.mjs");
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  verifyGoToolchainPolicy(repoRoot);
  process.stdout.write(`Go toolchain policy is ${goSecurityBaseline}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
