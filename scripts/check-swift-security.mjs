#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env ?? process.env,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr}`);
  }
  return result.stdout;
}

export const repositoryLocalGitEnvironmentVariables = Object.freeze([
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_CONFIG",
  "GIT_CONFIG_COUNT",
  "GIT_CONFIG_PARAMETERS",
  "GIT_DIR",
  "GIT_GRAFT_FILE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_OBJECT_DIRECTORY",
  "GIT_PREFIX",
  "GIT_QUARANTINE_PATH",
  "GIT_REPLACE_REF_BASE",
  "GIT_SHALLOW_FILE",
  "GIT_WORK_TREE",
]);

export function swiftSecurityGitEnvironment(environment = process.env) {
  const isolated = { ...environment };
  for (const variable of Object.keys(isolated)) {
    if (variable.startsWith("GIT_")) delete isolated[variable];
  }
  return {
    ...isolated,
    GIT_CONFIG_GLOBAL: os.devNull,
    GIT_CONFIG_SYSTEM: os.devNull,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
}

const lockWaitState = new Int32Array(new SharedArrayBuffer(4));

function ensureDirectoryPath(directory, trustedRoot) {
  const absolute = path.resolve(directory);
  const root = path.resolve(trustedRoot);
  const relative = path.relative(root, absolute);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`SwiftPM cache path escapes repository root: ${absolute}`);
  }
  const rootStat = fs.lstatSync(root);
  if (rootStat.isSymbolicLink()) throw new Error(`refusing symlinked repository root: ${root}`);
  if (!rootStat.isDirectory()) throw new Error(`repository root is not a directory: ${root}`);
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) throw new Error(`refusing symlinked SwiftPM cache directory: ${current}`);
      if (!stat.isDirectory()) throw new Error(`SwiftPM cache path is not a directory: ${current}`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      fs.mkdirSync(current, { mode: 0o700 });
    }
  }
  const physicalRoot = fs.realpathSync(root);
  const physicalDirectory = fs.realpathSync(absolute);
  const physicalRelative = path.relative(physicalRoot, physicalDirectory);
  if (physicalRelative === ".."
    || physicalRelative.startsWith(`..${path.sep}`)
    || path.isAbsolute(physicalRelative)) {
    throw new Error(`SwiftPM cache path escapes physical repository root: ${physicalDirectory}`);
  }
}

function assertSafeDirectory(pathValue, label) {
  try {
    const stat = fs.lstatSync(pathValue);
    if (stat.isSymbolicLink()) throw new Error(`refusing symlinked ${label}: ${pathValue}`);
    if (!stat.isDirectory()) throw new Error(`${label} is not a directory: ${pathValue}`);
  } catch (error) {
    if (error.code === "ELOOP") {
      throw new Error(`refusing symlinked ${label}: ${pathValue}`, { cause: error });
    }
    if (error.code !== "ENOENT") throw error;
  }
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error.code === "ESRCH") return false;
    if (error.code === "EPERM") return true;
    throw error;
  }
}

function readSwiftCacheLock(lockPath) {
  let stat;
  try {
    stat = fs.lstatSync(lockPath);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
  if (stat.isSymbolicLink()) throw new Error(`refusing symlinked SwiftPM cache lock: ${lockPath}`);
  if (!stat.isDirectory()) throw new Error(`SwiftPM cache lock is not a directory: ${lockPath}`);
  let ownerContents;
  let owner;
  const ownerPath = path.join(lockPath, "owner.json");
  let ownerFile;
  try {
    ownerFile = fs.openSync(ownerPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const ownerStat = fs.fstatSync(ownerFile);
    if (!ownerStat.isFile()) throw new Error(`SwiftPM cache lock owner is not a file: ${ownerPath}`);
    ownerContents = fs.readFileSync(ownerFile, "utf8");
  } catch (error) {
    if (error.code === "ELOOP") {
      throw new Error(`refusing symlinked SwiftPM cache lock owner: ${ownerPath}`, { cause: error });
    }
    if (error.code !== "ENOENT") throw error;
  } finally {
    if (ownerFile !== undefined) fs.closeSync(ownerFile);
  }
  if (ownerContents !== undefined) {
    try {
      owner = JSON.parse(ownerContents);
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
  }
  return { dev: stat.dev, ino: stat.ino, mtimeMs: stat.mtimeMs, ownerContents, owner };
}

function sameSwiftCacheLock(left, right) {
  return left?.dev === right?.dev
    && left?.ino === right?.ino
    && left?.ownerContents === right?.ownerContents;
}

function createOwnedSwiftCacheLock(lockPath, lockToken) {
  let created = false;
  let ownerFile;
  try {
    fs.mkdirSync(lockPath, { mode: 0o700 });
    created = true;
    ownerFile = fs.openSync(
      path.join(lockPath, "owner.json"),
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.writeFileSync(
      ownerFile,
      `${JSON.stringify({ pid: process.pid, token: lockToken, createdAt: new Date().toISOString() })}\n`,
    );
    return true;
  } catch (error) {
    if (created) {
      fs.rmSync(lockPath, { recursive: true, force: true });
      throw error;
    }
    if (error.code === "EEXIST") return false;
    throw error;
  } finally {
    if (ownerFile !== undefined) fs.closeSync(ownerFile);
  }
}

function removeStaleSwiftCacheLocks(lockPath) {
  const parent = path.dirname(lockPath);
  const prefix = `${path.basename(lockPath)}.stale-`;
  for (const entry of fs.readdirSync(parent)) {
    if (entry.startsWith(prefix)) {
      fs.rmSync(path.join(parent, entry), { recursive: true, force: true });
    }
  }
}

function invalidateSwiftCache(cachePath) {
  assertSafeDirectory(cachePath, "SwiftPM cache");
  const quarantinePath = `${cachePath}.quarantine-${process.pid}-${Date.now()}-${randomUUID()}`;
  try {
    fs.renameSync(cachePath, quarantinePath);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  assertSafeDirectory(quarantinePath, "quarantined SwiftPM cache");
  fs.rmSync(quarantinePath, { recursive: true, force: true });
}

function claimSwiftCacheRecovery(recoveryPath, staleLockMs) {
  const recoveryToken = randomUUID();
  if (createOwnedSwiftCacheLock(recoveryPath, recoveryToken)) return recoveryToken;
  const observed = readSwiftCacheLock(recoveryPath);
  if (!observed) return claimSwiftCacheRecovery(recoveryPath, staleLockMs);
  const validOwner = Number.isSafeInteger(observed.owner?.pid)
    && observed.owner.pid > 0
    && typeof observed.owner.token === "string"
    && observed.owner.token !== "";
  if (validOwner && observed.owner.failed !== true && processIsAlive(observed.owner.pid)) return undefined;
  if (!validOwner && Date.now() - observed.mtimeMs < staleLockMs) return undefined;
  if (!sameSwiftCacheLock(observed, readSwiftCacheLock(recoveryPath))) return undefined;
  const staleRecovery = `${recoveryPath}.stale-${process.pid}-${Date.now()}-${randomUUID()}`;
  try {
    fs.renameSync(recoveryPath, staleRecovery);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
  if (!sameSwiftCacheLock(observed, readSwiftCacheLock(staleRecovery))) {
    try {
      fs.renameSync(staleRecovery, recoveryPath);
    } catch (error) {
      throw new Error(`SwiftPM cache recovery lock changed during takeover: ${recoveryPath}`, { cause: error });
    }
    return undefined;
  }
  if (!createOwnedSwiftCacheLock(recoveryPath, recoveryToken)) {
    fs.rmSync(staleRecovery, { recursive: true, force: true });
    return undefined;
  }
  try {
    fs.rmSync(staleRecovery, { recursive: true, force: true });
  } catch (error) {
    markSwiftCacheRecoveryFailed(recoveryPath, recoveryToken);
    throw error;
  }
  return recoveryToken;
}

function markSwiftCacheRecoveryFailed(recoveryPath, recoveryToken) {
  if (!ownsSwiftCacheLock(recoveryPath, recoveryToken)) return;
  const ownerPath = path.join(recoveryPath, "owner.json");
  const temporaryOwner = path.join(recoveryPath, `owner.failed-${randomUUID()}.json`);
  let ownerFile;
  try {
    ownerFile = fs.openSync(
      temporaryOwner,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.writeFileSync(ownerFile, `${JSON.stringify({
      pid: process.pid,
      token: recoveryToken,
      failed: true,
      failedAt: new Date().toISOString(),
    })}\n`);
    fs.closeSync(ownerFile);
    ownerFile = undefined;
    fs.renameSync(temporaryOwner, ownerPath);
  } finally {
    if (ownerFile !== undefined) fs.closeSync(ownerFile);
    fs.rmSync(temporaryOwner, { force: true });
  }
}

function recoverDeadSwiftCacheLock(lockPath, recoveryPath, cachePath, staleLockMs, lockToken) {
  const observed = readSwiftCacheLock(lockPath);
  if (!observed) return "retry";
  const validOwner = Number.isSafeInteger(observed.owner?.pid)
    && observed.owner.pid > 0
    && typeof observed.owner.token === "string"
    && observed.owner.token !== "";
  if (validOwner && processIsAlive(observed.owner.pid)) return "wait";
  if (!validOwner && Date.now() - observed.mtimeMs < staleLockMs) return "wait";
  const recoveryToken = claimSwiftCacheRecovery(recoveryPath, staleLockMs);
  if (!recoveryToken) return "wait";

  const stalePath = `${lockPath}.stale-${process.pid}-${Date.now()}-${randomUUID()}`;
  let acquired = false;
  let cleanupComplete = false;
  try {
    if (!sameSwiftCacheLock(observed, readSwiftCacheLock(lockPath))) {
      cleanupComplete = true;
      return "wait";
    }
    try {
      fs.renameSync(lockPath, stalePath);
    } catch (error) {
      if (error.code === "ENOENT") {
        cleanupComplete = true;
        return "retry";
      }
      throw error;
    }
    const moved = readSwiftCacheLock(stalePath);
    if (!sameSwiftCacheLock(observed, moved)) {
      try {
        fs.renameSync(stalePath, lockPath);
      } catch (error) {
        throw new Error(`SwiftPM cache lock changed during stale recovery: ${lockPath}`, { cause: error });
      }
      cleanupComplete = true;
      return "wait";
    }

    acquired = createOwnedSwiftCacheLock(lockPath, lockToken);
    if (acquired) assertOwnsSwiftCacheLock(lockPath, lockToken);
    // A contender can win the new lock only if it checked for EEXIST before
    // this recovery marker was created. Every new owner waits on the marker.
    invalidateSwiftCache(cachePath);
    if (acquired) assertOwnsSwiftCacheLock(lockPath, lockToken);
    fs.rmSync(stalePath, { recursive: true, force: true });
    cleanupComplete = true;
    return acquired ? "acquired" : "wait";
  } catch (error) {
    if (acquired && ownsSwiftCacheLock(lockPath, lockToken)) {
      fs.rmSync(lockPath, { recursive: true, force: true });
    }
    markSwiftCacheRecoveryFailed(recoveryPath, recoveryToken);
    throw error;
  } finally {
    if (cleanupComplete && ownsSwiftCacheLock(recoveryPath, recoveryToken)) {
      fs.rmSync(recoveryPath, { recursive: true, force: true });
    }
  }
}

function ownsSwiftCacheLock(lockPath, lockToken) {
  const snapshot = readSwiftCacheLock(lockPath);
  return snapshot?.owner?.pid === process.pid && snapshot.owner.token === lockToken;
}

function assertOwnsSwiftCacheLock(lockPath, lockToken) {
  if (!ownsSwiftCacheLock(lockPath, lockToken)) {
    throw new Error(`lost SwiftPM cache lock ownership: ${lockPath}`);
  }
}

function finishSwiftCacheRecoveryAsOwner({
  cachePath,
  deadline,
  lockPath,
  lockToken,
  pollMs,
  recoveryPath,
  staleLockMs,
}) {
  for (;;) {
    const recovery = readSwiftCacheLock(recoveryPath);
    if (!recovery) return;
    const validOwner = Number.isSafeInteger(recovery.owner?.pid)
      && recovery.owner.pid > 0
      && typeof recovery.owner.token === "string"
      && recovery.owner.token !== "";
    if (validOwner && recovery.owner.failed !== true && processIsAlive(recovery.owner.pid)) {
      if (Date.now() >= deadline) {
        throw new Error(`timed out waiting for SwiftPM cache recovery: ${recoveryPath}`);
      }
      Atomics.wait(lockWaitState, 0, 0, pollMs);
      continue;
    }
    if (!validOwner && Date.now() - recovery.mtimeMs < staleLockMs) {
      if (Date.now() >= deadline) {
        throw new Error(`timed out waiting for SwiftPM cache recovery: ${recoveryPath}`);
      }
      Atomics.wait(lockWaitState, 0, 0, pollMs);
      continue;
    }
    assertOwnsSwiftCacheLock(lockPath, lockToken);
    if (!sameSwiftCacheLock(recovery, readSwiftCacheLock(recoveryPath))) continue;
    const staleRecovery = `${recoveryPath}.stale-${process.pid}-${Date.now()}-${randomUUID()}`;
    try {
      fs.renameSync(recoveryPath, staleRecovery);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (!sameSwiftCacheLock(recovery, readSwiftCacheLock(staleRecovery))) {
      fs.renameSync(staleRecovery, recoveryPath);
      continue;
    }
    const recoveryToken = randomUUID();
    let ownsRecovery = false;
    try {
      ownsRecovery = createOwnedSwiftCacheLock(recoveryPath, recoveryToken);
      if (!ownsRecovery) {
        fs.rmSync(staleRecovery, { recursive: true, force: true });
        continue;
      }
      assertOwnsSwiftCacheLock(lockPath, lockToken);
      fs.rmSync(staleRecovery, { recursive: true, force: true });
      invalidateSwiftCache(cachePath);
      assertOwnsSwiftCacheLock(lockPath, lockToken);
      removeStaleSwiftCacheLocks(lockPath);
      assertOwnsSwiftCacheLock(recoveryPath, recoveryToken);
      fs.rmSync(recoveryPath, { recursive: true, force: true });
      return;
    } catch (error) {
      if (ownsRecovery) markSwiftCacheRecoveryFailed(recoveryPath, recoveryToken);
      throw error;
    }
  }
}

export function swiftSecurityCachePath(repoRoot) {
  return path.join(repoRoot, ".build", "security", "swiftpm-cache");
}

export function withSwiftSecurityCache(repoRoot, action, options = {}) {
  const cachePath = options.cachePath ?? swiftSecurityCachePath(repoRoot);
  const lockPath = `${cachePath}.lock`;
  const recoveryPath = `${lockPath}.recovery`;
  const timeoutMs = options.timeoutMs ?? 5 * 60 * 1000;
  const pollMs = options.pollMs ?? 100;
  const maxAttempts = options.maxAttempts ?? 2;
  const staleLockMs = options.staleLockMs ?? 5 * 1000;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new Error("maxAttempts must be a positive integer");
  }
  for (const [name, value] of [["timeoutMs", timeoutMs], ["pollMs", pollMs], ["staleLockMs", staleLockMs]]) {
    if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative number`);
  }
  ensureDirectoryPath(path.dirname(cachePath), repoRoot);
  assertSafeDirectory(cachePath, "SwiftPM cache");
  assertSafeDirectory(lockPath, "SwiftPM cache lock");
  assertSafeDirectory(recoveryPath, "SwiftPM cache recovery lock");

  const deadline = Date.now() + timeoutMs;
  const lockToken = randomUUID();
  for (;;) {
    if (createOwnedSwiftCacheLock(lockPath, lockToken)) {
      try {
        finishSwiftCacheRecoveryAsOwner({
          cachePath,
          deadline,
          lockPath,
          lockToken,
          pollMs,
          recoveryPath,
          staleLockMs,
        });
      } catch (error) {
        if (ownsSwiftCacheLock(lockPath, lockToken)) {
          fs.rmSync(lockPath, { recursive: true, force: true });
        }
        throw error;
      }
      break;
    }
    assertSafeDirectory(lockPath, "SwiftPM cache lock");
    assertSafeDirectory(cachePath, "SwiftPM cache");
    const recovery = recoverDeadSwiftCacheLock(
      lockPath,
      recoveryPath,
      cachePath,
      staleLockMs,
      lockToken,
    );
    if (recovery === "acquired") break;
    if (recovery === "retry") continue;
    if (Date.now() >= deadline) throw new Error(`timed out waiting for SwiftPM cache lock: ${lockPath}`);
    Atomics.wait(lockWaitState, 0, 0, pollMs);
  }

  try {
    let lastError;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      assertOwnsSwiftCacheLock(lockPath, lockToken);
      try {
        const result = action(cachePath, attempt);
        assertOwnsSwiftCacheLock(lockPath, lockToken);
        return result;
      } catch (error) {
        if (!ownsSwiftCacheLock(lockPath, lockToken)) {
          throw new Error(`lost SwiftPM cache lock ownership: ${lockPath}`, { cause: error });
        }
        lastError = error;
        if (attempt < maxAttempts) {
          assertOwnsSwiftCacheLock(lockPath, lockToken);
          invalidateSwiftCache(cachePath);
          assertOwnsSwiftCacheLock(lockPath, lockToken);
        }
      }
    }
    throw lastError;
  } finally {
    if (ownsSwiftCacheLock(lockPath, lockToken)) {
      fs.rmSync(lockPath, { recursive: true, force: true });
    }
  }
}

export function swiftSecurityContexts(repoRoot) {
  return [
    { packageRoot: repoRoot, lockfile: path.join(repoRoot, "Package.resolved") },
    {
      packageRoot: path.join(repoRoot, "examples/swift"),
      lockfile: path.join(repoRoot, "examples/swift/Package.resolved"),
    },
  ];
}

export function normalizeSwiftPins(lockfile) {
  if (lockfile?.version !== 3) throw new Error(`unsupported Package.resolved version: ${lockfile?.version}`);
  if (!/^[a-f0-9]{64}$/.test(lockfile.originHash ?? "")) {
    throw new Error("Package.resolved has an invalid or missing originHash");
  }
  if (!Array.isArray(lockfile.pins) || lockfile.pins.length === 0) {
    throw new Error("Package.resolved has no pins");
  }
  const identities = new Set();
  const pins = lockfile.pins.map((pin) => {
    if (typeof pin?.identity !== "string" || pin.identity === "") {
      throw new Error("Swift pin has no identity");
    }
    if (identities.has(pin.identity)) throw new Error(`duplicate pin: ${pin.identity}`);
    identities.add(pin.identity);
    if (pin.kind !== "remoteSourceControl") {
      throw new Error(`Swift pin ${pin.identity} is not remote source control`);
    }
    if (typeof pin.location !== "string" || pin.location === "") {
      throw new Error(`Swift pin ${pin.identity} has no location`);
    }
    if (typeof pin.state?.revision !== "string" || pin.state.revision === "") {
      throw new Error(`Swift pin ${pin.identity} has no revision`);
    }
    if (typeof pin.state?.version !== "string" || pin.state.version === "") {
      throw new Error(`Swift pin ${pin.identity} has no version`);
    }
    return pin;
  });
  return pins.sort((left, right) => left.identity.localeCompare(right.identity));
}

export const requiredSwiftToolchainVersion = "6.3.1";

function assertSwiftToolchain(versionOutput) {
  const match = /Apple Swift version ([0-9]+\.[0-9]+\.[0-9]+)/.exec(versionOutput);
  if (!match) throw new Error("cannot determine Apple Swift toolchain version");
  if (match[1] !== requiredSwiftToolchainVersion) {
    throw new Error(
      `Swift security resolution requires ${requiredSwiftToolchainVersion}, found ${match[1]}`,
    );
  }
}

function isResolvedRemote(node) {
  return typeof node?.version === "string" && node.version !== "unspecified";
}

function annotateResolvedRevisions(node, inspectRevision) {
  if (isResolvedRemote(node)) {
    if (typeof node.path !== "string" || node.path === "") {
      throw new Error(`resolved Swift package ${node.identity} has no checkout path`);
    }
    node.revision = inspectRevision(node.path);
    if (!/^[a-f0-9]{40}$/.test(node.revision)) {
      throw new Error(`resolved Swift package ${node.identity} has an invalid revision`);
    }
  }
  for (const dependency of node.dependencies ?? []) {
    annotateResolvedRevisions(dependency, inspectRevision);
  }
  return node;
}

export function resolveSwiftSecurityContexts(repoRoot, options = {}) {
  const commandRunner = options.run ?? run;
  const inspectRevision = options.inspectRevision ?? ((checkout) => (
    inspectSwiftRevision(checkout, commandRunner)
  ));
  const makeScratch = options.makeScratch ?? ((label) => fs.mkdtempSync(
    path.join(os.tmpdir(), `flowersec-swift-security-${label}-`),
  ));
  const cleanupScratch = options.cleanupScratch ?? ((scratch) => fs.rmSync(
    scratch,
    { recursive: true, force: true },
  ));

  assertSwiftToolchain(commandRunner("swift", ["--version"]));
  return swiftSecurityContexts(repoRoot).map((context, index) => {
    const label = index === 0 ? "root" : "example";
    return withSwiftSecurityCache(repoRoot, (cachePath) => {
      const scratch = makeScratch(label);
      try {
        const graph = JSON.parse(commandRunner(
          "swift",
          [
            "package",
            "--cache-path",
            cachePath,
            "--package-path",
            context.packageRoot,
            "--scratch-path",
            scratch,
            "--skip-update",
            "--only-use-versions-from-resolved-file",
            "show-dependencies",
            "--format",
            "json",
          ],
          { cwd: context.packageRoot, env: swiftSecurityGitEnvironment() },
        ));
        return { ...context, graph: annotateResolvedRevisions(graph, inspectRevision) };
      } finally {
        cleanupScratch(scratch);
      }
    }, { maxAttempts: options.run ? 1 : 2 });
  });
}

export function inspectSwiftRevision(checkout, commandRunner = run) {
  return commandRunner(
    "git",
    ["-C", checkout, "rev-parse", "HEAD"],
    { env: swiftSecurityGitEnvironment() },
  ).trim();
}

export function dumpSwiftPackage(repoRoot, commandRunner = run) {
  return commandRunner(
    "swift",
    ["package", "dump-package"],
    { cwd: repoRoot, env: swiftSecurityGitEnvironment() },
  );
}

function parseVersion(version, label) {
  const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(version);
  if (!match) throw new Error(`${label} has invalid version ${version}`);
  return match.slice(1).map(Number);
}

function compareVersions(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function remoteDeclarations(manifest) {
  const declarations = [];
  for (const dependency of manifest?.dependencies ?? []) {
    for (const sourceControl of dependency.sourceControl ?? []) {
      const remote = sourceControl.location?.remote?.[0]?.urlString;
      const range = sourceControl.requirement?.range?.[0];
      if (!sourceControl.identity || !remote || !range?.lowerBound || !range?.upperBound) {
        throw new Error("Swift remote dependency has an unsupported declaration");
      }
      declarations.push({
        identity: sourceControl.identity,
        location: remote,
        lowerBound: range.lowerBound,
        upperBound: range.upperBound,
      });
    }
  }
  if (declarations.length === 0) throw new Error("root Swift package has no remote dependencies");
  return declarations;
}

function normalizeResolvedGraphPins(graph) {
  const pins = new Map();
  const pending = [graph];
  while (pending.length > 0) {
    const node = pending.pop();
    pending.push(...(node.dependencies ?? []));
    if (!isResolvedRemote(node)) continue;
    for (const [field, value] of [
      ["identity", node.identity],
      ["location", node.url],
      ["version", node.version],
      ["revision", node.revision],
    ]) {
      if (typeof value !== "string" || value === "") {
        throw new Error(`resolved Swift package has no ${field}`);
      }
    }
    const pin = {
      identity: node.identity,
      location: node.url,
      revision: node.revision,
      version: node.version,
    };
    const previous = pins.get(pin.identity);
    if (previous && JSON.stringify(previous) !== JSON.stringify(pin)) {
      throw new Error(`resolved Swift graph conflicts for ${pin.identity}`);
    }
    pins.set(pin.identity, pin);
  }
  return pins;
}

function assertLockMatchesGraph(label, lockPins, graph) {
  const locked = new Map(lockPins.map((pin) => [pin.identity, {
    identity: pin.identity,
    location: pin.location,
    revision: pin.state.revision,
    version: pin.state.version,
  }]));
  const resolved = normalizeResolvedGraphPins(graph);
  for (const [identity, graphPin] of resolved) {
    const lockPin = locked.get(identity);
    if (!lockPin) throw new Error(`${label} resolved graph package ${identity} is missing from lock`);
    if (JSON.stringify(lockPin) !== JSON.stringify(graphPin)) {
      throw new Error(`${label} lock differs from resolved graph for ${identity}`);
    }
  }
  for (const identity of locked.keys()) {
    if (!resolved.has(identity)) {
      throw new Error(`${label} package ${identity} is present in lock but absent from resolved graph`);
    }
  }
}

function assertExampleUsesLocalRoot(exampleGraph, repoRoot) {
  const expected = path.resolve(repoRoot);
  const localRoot = (exampleGraph.dependencies ?? []).find((dependency) => (
    dependency.version === "unspecified"
    && typeof dependency.path === "string"
    && path.resolve(dependency.path) === expected
  ));
  if (!localRoot) throw new Error("example Swift graph does not use the local Flowersec root");
}

export function verifySwiftSecurity({
  rootManifest,
  rootLock,
  rootGraph,
  exampleLock,
  exampleGraph,
  repoRoot,
}) {
  const rootPins = normalizeSwiftPins(rootLock);
  const examplePins = normalizeSwiftPins(exampleLock);
  const rootByIdentity = new Map(rootPins.map((pin) => [pin.identity, pin]));

  for (const declaration of remoteDeclarations(rootManifest)) {
    const pin = rootByIdentity.get(declaration.identity);
    if (!pin) throw new Error(`missing Swift pin: ${declaration.identity}`);
    if (pin.location !== declaration.location) {
      throw new Error(`Swift pin location mismatch: ${declaration.identity}`);
    }
    const selected = parseVersion(pin.state.version, declaration.identity);
    const lower = parseVersion(declaration.lowerBound, `${declaration.identity} lower bound`);
    const upper = parseVersion(declaration.upperBound, `${declaration.identity} upper bound`);
    if (compareVersions(selected, lower) < 0 || compareVersions(selected, upper) >= 0) {
      throw new Error(`Swift pin is outside its declared range: ${declaration.identity}`);
    }
  }

  assertLockMatchesGraph("root Swift", rootPins, rootGraph);
  assertLockMatchesGraph("example Swift", examplePins, exampleGraph);
  assertExampleUsesLocalRoot(exampleGraph, repoRoot);
}

function main() {
  if (process.argv.length !== 2) throw new Error("usage: check-swift-security.mjs");
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const [rootContext, exampleContext] = swiftSecurityContexts(repoRoot);
  for (const context of [rootContext, exampleContext]) {
    if (!fs.existsSync(context.lockfile)) throw new Error(`missing Swift lock: ${context.lockfile}`);
  }
  const lockContents = [rootContext, exampleContext].map((context) => (
    fs.readFileSync(context.lockfile, "utf8")
  ));
  const [resolvedRoot, resolvedExample] = resolveSwiftSecurityContexts(repoRoot);
  for (const [index, context] of [rootContext, exampleContext].entries()) {
    if (fs.readFileSync(context.lockfile, "utf8") !== lockContents[index]) {
      throw new Error(`Swift resolver modified ${context.lockfile}`);
    }
  }
  verifySwiftSecurity({
    rootManifest: JSON.parse(dumpSwiftPackage(repoRoot)),
    rootLock: JSON.parse(fs.readFileSync(rootContext.lockfile, "utf8")),
    rootGraph: resolvedRoot.graph,
    exampleLock: JSON.parse(fs.readFileSync(exampleContext.lockfile, "utf8")),
    exampleGraph: resolvedExample.graph,
    repoRoot,
  });
  process.stdout.write("SwiftPM locks match both isolated, pinned-toolchain dependency graphs.\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
