#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function defaultRun(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: { ...process.env, ...options.env },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const location = options.cwd ? ` in ${options.cwd}` : "";
    throw new Error(
      `${command} ${args.join(" ")} failed${location}: ${result.error?.message ?? result.stderr}`,
    );
  }
  return result.stdout;
}

const ignoredModuleSearchDirectories = new Set([
  ".build",
  ".git",
  ".swiftpm",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "test-results",
  "vendor",
]);

const fixedGoSecurityTools = {
  govulncheckVersion: "v1.1.4",
  goToolchain: "go1.26.5",
};

export function goSecurityToolVersions(environment = process.env) {
  for (const [variable, expected] of [
    ["GOVULNCHECK_VERSION", fixedGoSecurityTools.govulncheckVersion],
    ["GOVULNCHECK_GOTOOLCHAIN", fixedGoSecurityTools.goToolchain],
  ]) {
    if (environment[variable] !== undefined && environment[variable] !== expected) {
      throw new Error(`${variable} must not override the fixed value ${expected}`);
    }
  }
  return { ...fixedGoSecurityTools };
}

function relativeModuleDirectory(repoRoot, moduleDir) {
  const relative = path.relative(repoRoot, moduleDir);
  return relative === "" ? "." : relative.split(path.sep).join("/");
}

export function discoverGoModuleDirectories(repoRoot) {
  const modules = [];
  const pending = [repoRoot];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const entryPath = path.join(directory, entry.name);
      if (entry.isFile() && entry.name === "go.mod") {
        modules.push(directory);
      } else if (entry.isDirectory() && !ignoredModuleSearchDirectories.has(entry.name)) {
        pending.push(entryPath);
      }
    }
  }
  return [...new Set(modules)].sort();
}

function normalizeManifestModules(repoRoot, manifest) {
  if (!Array.isArray(manifest?.modules) || manifest.modules.length === 0) {
    throw new Error("Go security manifest contains no modules");
  }
  const modules = new Set();
  for (const entry of manifest.modules) {
    if (typeof entry !== "string" || entry === "") {
      throw new Error("Go security manifest contains an invalid module path");
    }
    const moduleDir = path.resolve(repoRoot, entry);
    const relative = path.relative(repoRoot, moduleDir);
    if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new Error(`Go security manifest module is outside the repository: ${entry}`);
    }
    modules.add(moduleDir);
  }
  return modules;
}

function assertSameModuleSet(repoRoot, leftLabel, left, rightLabel, right) {
  for (const moduleDir of left) {
    if (!right.has(moduleDir)) {
      throw new Error(
        `${leftLabel} Go module ${relativeModuleDirectory(repoRoot, moduleDir)} is absent from ${rightLabel}`,
      );
    }
  }
  for (const moduleDir of right) {
    if (!left.has(moduleDir)) {
      throw new Error(
        `${rightLabel} Go module ${relativeModuleDirectory(repoRoot, moduleDir)} is absent from ${leftLabel}`,
      );
    }
  }
}

export function collectGoModuleDirectories(
  repoRoot,
  manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "scripts/go-security-modules.json"), "utf8")),
  discoveredModules = discoverGoModuleDirectories(repoRoot),
) {
  const manifestModules = normalizeManifestModules(repoRoot, manifest);
  const treeModules = new Set(discoveredModules.map((moduleDir) => path.resolve(moduleDir)));
  assertSameModuleSet(repoRoot, "maintained tree", treeModules, "security manifest", manifestModules);
  return [...treeModules].sort();
}

export function runGoSecurityChecks({
  repoRoot,
  govulncheckVersion,
  goToolchain,
  moduleManifest,
  discoverModules = discoverGoModuleDirectories,
  run = defaultRun,
}) {
  const manifest = moduleManifest ?? JSON.parse(
    fs.readFileSync(path.join(repoRoot, "scripts/go-security-modules.json"), "utf8"),
  );
  const modules = collectGoModuleDirectories(repoRoot, manifest, discoverModules(repoRoot));
  const environment = {
    GOTOOLCHAIN: goToolchain,
    GOWORK: "off",
  };

  for (const moduleDir of modules) {
    if (!fs.existsSync(path.join(moduleDir, "go.mod"))) {
      throw new Error(`workspace module has no go.mod: ${moduleDir}`);
    }
    run("go", ["mod", "verify"], { cwd: moduleDir, env: environment });
    run("go", ["list", "-m", "-json", "all"], { cwd: moduleDir, env: environment });
    run(
      "go",
      ["run", `golang.org/x/vuln/cmd/govulncheck@${govulncheckVersion}`, "./..."],
      { cwd: moduleDir, env: environment },
    );
  }
  return modules;
}

export function prepareOfflineGoToolchain({
  repoRoot,
  goToolchain,
  run = defaultRun,
  statePath = path.join(repoRoot, ".flowersec", "final-go-toolchain.json"),
}) {
  const environment = { GOTOOLCHAIN: goToolchain, GOWORK: "off" };
  const [reportedRoot, reportedVersion, extra] = run(
    "go",
    ["env", "GOROOT", "GOVERSION"],
    { cwd: path.join(repoRoot, "flowersec-go"), env: environment },
  ).trim().split(/\r?\n/);
  if (!reportedRoot || reportedVersion !== goToolchain || extra !== undefined) {
    throw new Error(`cannot resolve exact ${goToolchain} toolchain root`);
  }
  const binaryName = process.platform === "win32" ? "go.exe" : "go";
  const binary = fs.realpathSync(path.join(reportedRoot, "bin", binaryName));
  if (!fs.statSync(binary).isFile()) throw new Error(`Go toolchain is not a regular file: ${binary}`);
  const version = run(binary, ["version"], {
    cwd: repoRoot,
    env: { GOTOOLCHAIN: "local", GOWORK: "off" },
  }).trim();
  if (!version.startsWith(`go version ${goToolchain} `)) {
    throw new Error(`resolved Go toolchain version mismatch: ${version}`);
  }
  const sourceHead = run("git", ["rev-parse", "HEAD"], { cwd: repoRoot }).trim();
  if (!/^[0-9a-f]{40}$/.test(sourceHead)) throw new Error("cannot bind Go toolchain to source HEAD");
  const state = {
    schema: "flowersec-final-go-toolchain-v1",
    sourceHead,
    version: goToolchain,
    binary,
    sha256: createHash("sha256").update(fs.readFileSync(binary)).digest("hex"),
  };
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  const temporary = `${statePath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(state)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    fs.renameSync(temporary, statePath);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
  return state;
}

function main() {
  if (process.argv.length > 3
    || (process.argv.length === 3 && process.argv[2] !== "--prepare-offline-toolchain")) {
    throw new Error("usage: check-go-security.mjs [--prepare-offline-toolchain]");
  }
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const tools = goSecurityToolVersions();
  if (process.argv[2] === "--prepare-offline-toolchain") {
    const state = prepareOfflineGoToolchain({ repoRoot, goToolchain: tools.goToolchain });
    process.stdout.write(`prepared ${state.version} offline toolchain for ${state.sourceHead}\n`);
    return;
  }
  const modules = runGoSecurityChecks({
    repoRoot,
    ...tools,
  });
  for (const moduleDir of modules) {
    process.stdout.write(`verified ${path.relative(repoRoot, moduleDir)}\n`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
