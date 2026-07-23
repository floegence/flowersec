#!/usr/bin/env node

import { spawnSync } from "node:child_process";
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

function main() {
  if (process.argv.length !== 2) {
    throw new Error("usage: check-go-security.mjs");
  }
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const tools = goSecurityToolVersions();
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
