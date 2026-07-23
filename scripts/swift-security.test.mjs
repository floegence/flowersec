import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const checkerPath = path.join(sourceRoot, "scripts/check-swift-security.mjs");

async function loadChecker() {
  assert.ok(fs.existsSync(checkerPath), "scripts/check-swift-security.mjs must exist");
  return import(pathToFileURL(checkerPath));
}

function assertHermeticGitEnvironment(environment) {
  assert.equal(environment.GIT_CONFIG_GLOBAL, os.devNull);
  assert.equal(environment.GIT_CONFIG_SYSTEM, os.devNull);
  assert.equal(environment.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(environment.GIT_TERMINAL_PROMPT, "0");
  for (const variable of [
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
  ]) assert.equal(variable in environment, false, `${variable} must be scrubbed`);
  for (const variable of Object.keys(environment)) {
    assert.equal(/^GIT_CONFIG_(?:KEY|VALUE)_[0-9]+$/.test(variable), false);
  }
}

function runNodeSnippet(source, environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "--eval", source], {
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`child exited ${code ?? signal}: ${stderr}`));
    });
  });
}

test("Swift security inventory contains the root and example locks", async () => {
  const { swiftSecurityContexts } = await loadChecker();
  assert.deepEqual(swiftSecurityContexts(sourceRoot), [
    {
      packageRoot: sourceRoot,
      lockfile: path.join(sourceRoot, "Package.resolved"),
    },
    {
      packageRoot: path.join(sourceRoot, "examples/swift"),
      lockfile: path.join(sourceRoot, "examples/swift/Package.resolved"),
    },
  ]);
  assert.equal(fs.existsSync(path.join(sourceRoot, "Package.resolved")), true);
  assert.equal(fs.existsSync(path.join(sourceRoot, "examples/swift/Package.resolved")), true);
});

test("Swift locks reject missing, duplicate, or incomplete pins", async () => {
  const { normalizeSwiftPins } = await loadChecker();
  const validPin = {
    identity: "swift-crypto",
    kind: "remoteSourceControl",
    location: "https://github.com/apple/swift-crypto.git",
    state: { revision: "abc123", version: "4.5.0" },
  };
  const originHash = "a".repeat(64);
  assert.deepEqual(normalizeSwiftPins({ version: 3, originHash, pins: [validPin] }), [validPin]);
  assert.throws(() => normalizeSwiftPins({ version: 3, originHash, pins: [] }), /no pins/);
  assert.throws(() => normalizeSwiftPins({ version: 3, originHash: "stale", pins: [validPin] }), /originHash/);
  assert.throws(
    () => normalizeSwiftPins({ version: 3, originHash, pins: [validPin, validPin] }),
    /duplicate pin/,
  );
  assert.throws(
    () => normalizeSwiftPins({
      version: 3,
      originHash,
      pins: [{ ...validPin, state: { revision: "", version: "4.5.0" } }],
    }),
    /revision/,
  );
});

test("Swift locks match independently resolved complete graphs", async () => {
  const { verifySwiftSecurity } = await loadChecker();
  const directPin = {
    identity: "swift-crypto",
    kind: "remoteSourceControl",
    location: "https://github.com/apple/swift-crypto.git",
    state: { revision: "direct-revision", version: "4.5.0" },
  };
  const transitivePin = {
    identity: "swift-asn1",
    kind: "remoteSourceControl",
    location: "https://github.com/apple/swift-asn1.git",
    state: { revision: "transitive-revision", version: "1.7.1" },
  };
  const rootLock = {
    version: 3,
    originHash: "a".repeat(64),
    pins: [directPin, transitivePin],
  };
  const rootGraph = {
    identity: "flowersec",
    url: sourceRoot,
    version: "unspecified",
    path: sourceRoot,
    dependencies: [{
      identity: "swift-crypto",
      url: directPin.location,
      version: directPin.state.version,
      revision: directPin.state.revision,
      dependencies: [{
        identity: "swift-asn1",
        url: transitivePin.location,
        version: transitivePin.state.version,
        revision: transitivePin.state.revision,
        dependencies: [],
      }],
    }],
  };
  const exampleRoot = path.join(sourceRoot, "examples/swift");
  const exampleGraph = {
    identity: "swift-example",
    url: exampleRoot,
    version: "unspecified",
    path: exampleRoot,
    dependencies: [{
      identity: "flowersec",
      url: sourceRoot,
      version: "unspecified",
      path: sourceRoot,
      dependencies: rootGraph.dependencies,
    }],
  };
  const declarations = {
    dependencies: [{
      sourceControl: [{
        identity: "swift-crypto",
        location: { remote: [{ urlString: "https://github.com/apple/swift-crypto.git" }] },
        requirement: { range: [{ lowerBound: "4.5.0", upperBound: "5.0.0" }] },
      }],
    }],
  };
  assert.doesNotThrow(() => verifySwiftSecurity({
    rootManifest: declarations,
    rootLock,
    rootGraph,
    exampleLock: rootLock,
    exampleGraph,
    repoRoot: sourceRoot,
  }));

  const incompleteLock = { version: 3, originHash: "a".repeat(64), pins: [directPin] };
  assert.throws(() => verifySwiftSecurity({
    rootManifest: declarations,
    rootLock: incompleteLock,
    rootGraph,
    exampleLock: incompleteLock,
    exampleGraph,
    repoRoot: sourceRoot,
  }), /resolved graph.*swift-asn1.*lock|lock.*swift-asn1/i);

  const staleLock = {
    version: 3,
    originHash: "a".repeat(64),
    pins: [...rootLock.pins, {
      identity: "stale-extra",
      kind: "remoteSourceControl",
      location: "https://example.com/stale-extra.git",
      state: { revision: "stale-revision", version: "1.0.0" },
    }],
  };
  assert.throws(() => verifySwiftSecurity({
    rootManifest: declarations,
    rootLock: staleLock,
    rootGraph,
    exampleLock: staleLock,
    exampleGraph,
    repoRoot: sourceRoot,
  }), /stale-extra.*lock.*resolved graph/i);

  assert.throws(() => verifySwiftSecurity({
    rootManifest: declarations,
    rootLock,
    rootGraph,
    exampleLock: rootLock,
    exampleGraph: {
      ...exampleGraph,
      dependencies: [{ ...exampleGraph.dependencies[0], path: path.join(sourceRoot, "wrong-root") }],
    },
    repoRoot: sourceRoot,
  }), /local Flowersec root/i);
});

test("Swift resolver is pinned and inspects root and example in isolated scratch paths", async () => {
  const { resolveSwiftSecurityContexts, swiftSecurityCachePath } = await loadChecker();
  assert.equal(typeof resolveSwiftSecurityContexts, "function");
  const calls = [];
  const graph = {
    identity: "fixture",
    url: sourceRoot,
    version: "unspecified",
    path: sourceRoot,
    dependencies: [],
  };
  const resolved = resolveSwiftSecurityContexts(sourceRoot, {
    run(command, args, options) {
      calls.push({ command, args, options });
      if (args[0] === "--version") {
        return "swift-driver version: 1.148.6 Apple Swift version 6.3.1";
      }
      return JSON.stringify(graph);
    },
    inspectRevision: () => "fixture-revision",
    makeScratch: (label) => path.join("/tmp", `swift-security-${label}`),
  });
  assert.equal(resolved.length, 2);
  assert.equal(calls[0].command, "swift");
  assert.deepEqual(calls.slice(1).map((call) => call.options.cwd), [
    sourceRoot,
    path.join(sourceRoot, "examples/swift"),
  ]);
  for (const [index, call] of calls.slice(1).entries()) {
    assert.ok(call.args.includes("--only-use-versions-from-resolved-file"));
    assert.ok(call.args.includes("--skip-update"));
    assertHermeticGitEnvironment(call.options.env);
    assert.ok(call.args.includes("--cache-path"));
    const cacheIndex = call.args.indexOf("--cache-path");
    assert.equal(call.args[cacheIndex + 1], swiftSecurityCachePath(sourceRoot));
    assert.ok(call.args.includes("--scratch-path"));
    assert.equal(call.args.includes("--disable-sandbox"), false);
    assert.ok(call.args.includes("show-dependencies"));
    assert.ok(call.args.includes("json"));
  }
});

test("Swift revision and manifest inspection use hermetic Git configuration", async () => {
  const { dumpSwiftPackage, resolveSwiftSecurityContexts } = await loadChecker();
  const calls = [];
  const graph = {
    identity: "fixture-root",
    url: sourceRoot,
    version: "unspecified",
    path: sourceRoot,
    dependencies: [{
      identity: "swift-crypto",
      url: "https://github.com/apple/swift-crypto.git",
      version: "1.0.0",
      path: sourceRoot,
      dependencies: [],
    }],
  };
  resolveSwiftSecurityContexts(sourceRoot, {
    run(command, args, options) {
      calls.push({ command, args, options });
      if (args[0] === "--version") return "Apple Swift version 6.3.1";
      if (command === "git") return `${"a".repeat(40)}\n`;
      return JSON.stringify(graph);
    },
  });
  const gitCalls = calls.filter((call) => call.command === "git");
  assert.equal(gitCalls.length, 2);
  for (const call of gitCalls) {
    assertHermeticGitEnvironment(call.options.env);
  }

  dumpSwiftPackage(sourceRoot, (command, args, options) => {
    assert.equal(command, "swift");
    assert.deepEqual(args, ["package", "dump-package"]);
    assertHermeticGitEnvironment(options.env);
    return "{}";
  });
});

test("Swift Git commands ignore hostile inherited repository variables", async () => {
  const { dumpSwiftPackage, inspectSwiftRevision, swiftSecurityGitEnvironment } = await loadChecker();
  const hostile = {
    GIT_DIR: path.join(sourceRoot, "does-not-exist.git"),
    GIT_WORK_TREE: "/tmp/incorrect-worktree",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "flowersec.injected",
    GIT_CONFIG_VALUE_0: "true",
  };
  const original = Object.fromEntries(Object.keys(hostile).map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, hostile);
    const expected = spawnSync("git", ["-C", sourceRoot, "rev-parse", "HEAD"], {
      encoding: "utf8",
      env: swiftSecurityGitEnvironment(),
    });
    assert.equal(expected.status, 0, expected.stderr);
    assert.equal(inspectSwiftRevision(sourceRoot), expected.stdout.trim());
    const manifest = JSON.parse(dumpSwiftPackage(sourceRoot));
    assert.equal(manifest.name, "Flowersec");
    const injected = spawnSync("git", ["config", "--get", "flowersec.injected"], {
      encoding: "utf8",
      env: swiftSecurityGitEnvironment(),
    });
    assert.notEqual(injected.status, 0);
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("Swift cache lock reuses the cache and releases it on success and failure", async (t) => {
  const { swiftSecurityCachePath, withSwiftSecurityCache } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-cache-test-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  const cachePath = swiftSecurityCachePath(repoRoot);
  const attempts = [];
  assert.equal(withSwiftSecurityCache(repoRoot, (received, attempt) => {
    attempts.push({ received, attempt });
    fs.mkdirSync(received, { recursive: true });
    fs.writeFileSync(path.join(received, "marker"), "cached");
    return "ok";
  }), "ok");
  assert.equal(withSwiftSecurityCache(repoRoot, (received, attempt) => {
    attempts.push({ received, attempt });
    return fs.readFileSync(path.join(received, "marker"), "utf8");
  }), "cached");
  assert.deepEqual(attempts, [
    { received: cachePath, attempt: 1 },
    { received: cachePath, attempt: 1 },
  ]);
  assert.equal(fs.existsSync(`${cachePath}.lock`), false);

  assert.throws(() => withSwiftSecurityCache(repoRoot, (received, attempt) => {
    attempts.push({ received, attempt });
    if (attempt === 2) assert.equal(fs.existsSync(path.join(received, "marker")), false);
    throw new Error("cache action failed");
  }, { maxAttempts: 2 }), /cache action failed/);
  assert.deepEqual(attempts.slice(2), [
    { received: cachePath, attempt: 1 },
    { received: cachePath, attempt: 2 },
  ]);
  assert.equal(fs.existsSync(`${cachePath}.lock`), false);
});

test("Swift cache lock recovers dead owners but refuses live owners", async (t) => {
  const { swiftSecurityCachePath, withSwiftSecurityCache } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-lock-test-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  const cachePath = swiftSecurityCachePath(repoRoot);
  const lockPath = `${cachePath}.lock`;
  const recoveryPath = `${lockPath}.recovery`;
  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({ pid: 99999999, token: "dead" }));
  assert.equal(withSwiftSecurityCache(repoRoot, () => "recovered", { timeoutMs: 100, pollMs: 1 }), "recovered");
  assert.equal(fs.existsSync(lockPath), false);

  fs.mkdirSync(cachePath, { recursive: true });
  fs.writeFileSync(path.join(cachePath, "abandoned"), "partial");
  fs.mkdirSync(recoveryPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(recoveryPath, "owner.json"), JSON.stringify({
    pid: 99999999,
    token: "dead-recovery",
  }));
  assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
    assert.equal(fs.existsSync(path.join(received, "abandoned")), false);
    return "recovered";
  }, { timeoutMs: 100, pollMs: 1 }), "recovered");
  assert.equal(fs.existsSync(recoveryPath), false);

  fs.mkdirSync(cachePath, { recursive: true });
  fs.writeFileSync(path.join(cachePath, "dual-dead"), "partial");
  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({
    pid: 99999999,
    token: "dead-main",
  }));
  fs.mkdirSync(recoveryPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(recoveryPath, "owner.json"), JSON.stringify({
    pid: 99999998,
    token: "dead-recovery",
  }));
  assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
    assert.equal(fs.existsSync(path.join(received, "dual-dead")), false);
    return "recovered";
  }, { timeoutMs: 100, pollMs: 1, staleLockMs: 0 }), "recovered");
  assert.equal(fs.existsSync(lockPath), false);
  assert.equal(fs.existsSync(recoveryPath), false);

  fs.mkdirSync(cachePath, { recursive: true });
  fs.writeFileSync(path.join(cachePath, "failed-cleanup"), "partial");
  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({
    pid: 99999999,
    token: "dead-before-fault",
  }));
  const rmSync = fs.rmSync;
  let injectedCleanupFailure = false;
  try {
    fs.rmSync = (target, options) => {
      if (target.startsWith(`${cachePath}.quarantine-`) && !injectedCleanupFailure) {
        injectedCleanupFailure = true;
        throw new Error("cleanup fault");
      }
      return rmSync(target, options);
    };
    assert.throws(
      () => withSwiftSecurityCache(repoRoot, () => "unreachable", { timeoutMs: 100, pollMs: 1 }),
      /cleanup fault/,
    );
  } finally {
    fs.rmSync = rmSync;
  }
  assert.equal(injectedCleanupFailure, true);
  assert.equal(fs.existsSync(lockPath), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(recoveryPath, "owner.json"), "utf8")).failed, true);
  assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
    assert.equal(fs.existsSync(path.join(received, "failed-cleanup")), false);
    return "recovered";
  }, { timeoutMs: 100, pollMs: 1 }), "recovered");
  assert.equal(fs.existsSync(recoveryPath), false);

  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  assert.equal(withSwiftSecurityCache(repoRoot, () => "recovered", {
    timeoutMs: 100,
    pollMs: 1,
    staleLockMs: 0,
  }), "recovered");
  assert.equal(fs.existsSync(lockPath), false);

  fs.mkdirSync(cachePath, { recursive: true });
  fs.writeFileSync(path.join(cachePath, "partial"), "stale");
  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), "not-json");
  assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
    assert.equal(fs.existsSync(path.join(received, "partial")), false);
    return "recovered";
  }, { timeoutMs: 100, pollMs: 1, staleLockMs: 0 }), "recovered");
  assert.equal(fs.existsSync(lockPath), false);

  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({ pid: process.pid, token: "live" }));
  assert.throws(
    () => withSwiftSecurityCache(repoRoot, () => "unreachable", {
      timeoutMs: 10,
      pollMs: 1,
      staleLockMs: 0,
    }),
    /timed out waiting for SwiftPM cache lock/,
  );
  fs.rmSync(lockPath, { recursive: true, force: true });

  assert.throws(() => withSwiftSecurityCache(repoRoot, (received) => {
    fs.mkdirSync(received, { recursive: true });
    fs.writeFileSync(path.join(received, "marker"), "must-survive");
    fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({
      pid: process.pid,
      token: "foreign",
    }));
    throw new Error("foreign lock");
  }, { maxAttempts: 2 }), /lost SwiftPM cache lock/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(lockPath, "owner.json"), "utf8")).token, "foreign");
  assert.equal(fs.readFileSync(path.join(cachePath, "marker"), "utf8"), "must-survive");
  fs.rmSync(lockPath, { recursive: true, force: true });

  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  const ownerTarget = path.join(repoRoot, "outside-owner.json");
  fs.writeFileSync(ownerTarget, JSON.stringify({ pid: process.pid, token: "outside" }));
  fs.symlinkSync(ownerTarget, path.join(lockPath, "owner.json"));
  assert.throws(
    () => withSwiftSecurityCache(repoRoot, () => "unreachable"),
    /refusing symlinked SwiftPM cache lock owner/,
  );
  fs.rmSync(lockPath, { recursive: true, force: true });

  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({ pid: 99999999, token: "dead-aba" }));
  const displacedLock = `${lockPath}.displaced`;
  const renameSync = fs.renameSync;
  let injectedReplacement = false;
  let actionCalls = 0;
  try {
    fs.renameSync = (source, destination) => {
      if (source === lockPath && !injectedReplacement) {
        injectedReplacement = true;
        renameSync(source, displacedLock);
        fs.mkdirSync(source, { mode: 0o700 });
        fs.writeFileSync(path.join(source, "owner.json"), JSON.stringify({
          pid: process.pid,
          token: "replacement",
        }));
      }
      return renameSync(source, destination);
    };
    assert.throws(() => withSwiftSecurityCache(repoRoot, () => {
      actionCalls += 1;
    }, { timeoutMs: 10, pollMs: 1 }), /timed out waiting for SwiftPM cache lock/);
  } finally {
    fs.renameSync = renameSync;
  }
  assert.equal(actionCalls, 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(lockPath, "owner.json"), "utf8")).token, "replacement");
  fs.rmSync(lockPath, { recursive: true, force: true });
  fs.rmSync(displacedLock, { recursive: true, force: true });

  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({
    pid: 99999999,
    token: "dead-handoff",
  }));
  const handoffRenameSync = fs.renameSync;
  let injectedHandoff = false;
  let handoffActionCalls = 0;
  try {
    fs.renameSync = (source, destination) => {
      const result = handoffRenameSync(source, destination);
      if (source === lockPath && !injectedHandoff) {
        injectedHandoff = true;
        fs.mkdirSync(source, { mode: 0o700 });
        fs.writeFileSync(path.join(source, "owner.json"), JSON.stringify({
          pid: process.pid,
          token: "waiting-handoff",
        }));
        fs.mkdirSync(cachePath, { recursive: true });
        fs.writeFileSync(path.join(cachePath, "waiting-owner"), "not-in-action");
      }
      return result;
    };
    assert.throws(() => withSwiftSecurityCache(repoRoot, () => {
      handoffActionCalls += 1;
    }, { timeoutMs: 10, pollMs: 1 }), /timed out waiting for SwiftPM cache lock/);
  } finally {
    fs.renameSync = handoffRenameSync;
  }
  assert.equal(handoffActionCalls, 0);
  assert.equal(injectedHandoff, true);
  assert.equal(fs.existsSync(path.join(cachePath, "waiting-owner")), false);
  assert.equal(fs.existsSync(recoveryPath), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(lockPath, "owner.json"), "utf8")).token, "waiting-handoff");
  fs.rmSync(lockPath, { recursive: true, force: true });

  const physicalRoot = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-root-target-"));
  const symlinkRoot = `${physicalRoot}-link`;
  fs.symlinkSync(physicalRoot, symlinkRoot);
  t.after(() => fs.rmSync(symlinkRoot, { force: true }));
  t.after(() => fs.rmSync(physicalRoot, { recursive: true, force: true }));
  assert.throws(
    () => withSwiftSecurityCache(symlinkRoot, () => "unreachable"),
    /refusing symlinked repository root/,
  );

  const outside = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-outside-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  fs.rmSync(path.join(repoRoot, ".build"), { recursive: true, force: true });
  fs.symlinkSync(outside, path.join(repoRoot, ".build"));
  assert.throws(
    () => withSwiftSecurityCache(repoRoot, () => "unreachable"),
    /refusing symlinked SwiftPM cache directory/,
  );
});

test("Swift cache invalidation never exposes failed cleanup contents", async (t) => {
  const { swiftSecurityCachePath, withSwiftSecurityCache } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-invalidation-test-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  const cachePath = swiftSecurityCachePath(repoRoot);
  const lockPath = `${cachePath}.lock`;
  const recoveryPath = `${lockPath}.recovery`;
  const originalRmSync = fs.rmSync;

  fs.mkdirSync(cachePath, { recursive: true });
  fs.writeFileSync(path.join(cachePath, "pre-rename-stale"), "partial");
  fs.mkdirSync(recoveryPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(recoveryPath, "owner.json"), JSON.stringify({
    pid: 99999999,
    token: "dead-before-cache-rename",
  }));
  const originalRenameSync = fs.renameSync;
  let preRenameFailure = false;
  try {
    fs.renameSync = (source, destination) => {
      if (source === cachePath && !preRenameFailure) {
        preRenameFailure = true;
        const error = new Error("pre-quarantine rename fault");
        error.code = "EACCES";
        throw error;
      }
      return originalRenameSync(source, destination);
    };
    assert.throws(
      () => withSwiftSecurityCache(repoRoot, () => "unreachable", { timeoutMs: 100, pollMs: 1 }),
      /pre-quarantine rename fault/,
    );
  } finally {
    fs.renameSync = originalRenameSync;
  }
  assert.equal(preRenameFailure, true);
  assert.equal(fs.existsSync(recoveryPath), true);
  assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
    assert.equal(fs.existsSync(path.join(received, "pre-rename-stale")), false);
    return "fresh-after-pre-rename-fault";
  }, { timeoutMs: 100, pollMs: 1 }), "fresh-after-pre-rename-fault");

  fs.mkdirSync(cachePath, { recursive: true });
  fs.writeFileSync(path.join(cachePath, "takeover-stale"), "partial");
  fs.mkdirSync(recoveryPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(recoveryPath, "owner.json"), JSON.stringify({
    pid: 99999999,
    token: "dead-takeover",
  }));
  let takeoverCleanupFailure = false;
  try {
    fs.rmSync = (target, options) => {
      if (target.startsWith(`${cachePath}.quarantine-`) && !takeoverCleanupFailure) {
        takeoverCleanupFailure = true;
        throw new Error("takeover quarantine cleanup fault");
      }
      return originalRmSync(target, options);
    };
    assert.throws(
      () => withSwiftSecurityCache(repoRoot, () => "unreachable", { timeoutMs: 100, pollMs: 1 }),
      /takeover quarantine cleanup fault/,
    );
  } finally {
    fs.rmSync = originalRmSync;
  }
  assert.equal(takeoverCleanupFailure, true);
  assert.equal(fs.existsSync(cachePath), false);
  assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
    assert.equal(fs.existsSync(path.join(received, "takeover-stale")), false);
    return "fresh-after-takeover";
  }), "fresh-after-takeover");

  let retryCleanupFailure = false;
  try {
    fs.rmSync = (target, options) => {
      if (target.startsWith(`${cachePath}.quarantine-`) && !retryCleanupFailure) {
        retryCleanupFailure = true;
        throw new Error("retry quarantine cleanup fault");
      }
      return originalRmSync(target, options);
    };
    assert.throws(() => withSwiftSecurityCache(repoRoot, (received) => {
      fs.mkdirSync(received, { recursive: true });
      fs.writeFileSync(path.join(received, "retry-stale"), "partial");
      throw new Error("cache action fault");
    }, { maxAttempts: 2 }), /retry quarantine cleanup fault/);
  } finally {
    fs.rmSync = originalRmSync;
  }
  assert.equal(retryCleanupFailure, true);
  assert.equal(fs.existsSync(cachePath), false);
  assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
    assert.equal(fs.existsSync(path.join(received, "retry-stale")), false);
    return "fresh-after-retry";
  }), "fresh-after-retry");
});

test("Swift cache invalidation tolerates a lost rename race", async (t) => {
  const { swiftSecurityCachePath, withSwiftSecurityCache } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-rename-race-test-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  const cachePath = swiftSecurityCachePath(repoRoot);
  const originalRenameSync = fs.renameSync;
  let injectedRace = false;
  let actionCalls = 0;
  try {
    fs.renameSync = (source, destination) => {
      if (source === cachePath && !injectedRace) {
        injectedRace = true;
        fs.rmSync(source, { recursive: true, force: true });
        const error = new Error("cache disappeared during rename");
        error.code = "ENOENT";
        throw error;
      }
      return originalRenameSync(source, destination);
    };
    assert.equal(withSwiftSecurityCache(repoRoot, (received) => {
      actionCalls += 1;
      if (actionCalls === 1) {
        fs.mkdirSync(received, { recursive: true });
        fs.writeFileSync(path.join(received, "partial"), "stale");
        throw new Error("retry");
      }
      assert.equal(fs.existsSync(path.join(received, "partial")), false);
      return "recovered";
    }, { maxAttempts: 2 }), "recovered");
  } finally {
    fs.renameSync = originalRenameSync;
  }
  assert.equal(injectedRace, true);
  assert.equal(actionCalls, 2);
});

test("Swift cache invalidation quarantines a symlink swap without following it", async (t) => {
  const { swiftSecurityCachePath, withSwiftSecurityCache } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-symlink-race-test-"));
  const outside = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-symlink-target-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  const cachePath = swiftSecurityCachePath(repoRoot);
  const outsideMarker = path.join(outside, "must-survive");
  fs.writeFileSync(outsideMarker, "safe");
  const originalRenameSync = fs.renameSync;
  let injectedSwap = false;
  try {
    fs.renameSync = (source, destination) => {
      if (source === cachePath && !injectedSwap) {
        injectedSwap = true;
        fs.rmSync(source, { recursive: true, force: true });
        fs.symlinkSync(outside, source);
      }
      return originalRenameSync(source, destination);
    };
    assert.throws(() => withSwiftSecurityCache(repoRoot, (received) => {
      fs.mkdirSync(received, { recursive: true });
      throw new Error("retry");
    }, { maxAttempts: 2 }), /refusing symlinked quarantined SwiftPM cache/);
  } finally {
    fs.renameSync = originalRenameSync;
  }
  assert.equal(injectedSwap, true);
  assert.equal(fs.readFileSync(outsideMarker, "utf8"), "safe");
  assert.equal(fs.existsSync(cachePath), false);
  assert.equal(withSwiftSecurityCache(repoRoot, () => "fresh"), "fresh");
});

test("Swift cache serializes concurrent stale-owner recovery", async (t) => {
  const { swiftSecurityCachePath } = await loadChecker();
  const repoRoot = fs.mkdtempSync(path.join("/tmp", "flowersec-swift-concurrency-test-"));
  t.after(() => fs.rmSync(repoRoot, { recursive: true, force: true }));
  const cachePath = swiftSecurityCachePath(repoRoot);
  const lockPath = `${cachePath}.lock`;
  const events = path.join(repoRoot, "events.log");
  fs.mkdirSync(lockPath, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(lockPath, "owner.json"), JSON.stringify({ pid: 99999999, token: "dead" }));
  fs.mkdirSync(cachePath, { recursive: true });
  fs.writeFileSync(path.join(cachePath, "partial"), "stale");
  const moduleUrl = pathToFileURL(checkerPath).href;
  const script = `
    import fs from "node:fs";
    import { withSwiftSecurityCache } from ${JSON.stringify(moduleUrl)};
    const repoRoot = process.env.FLOWERSEC_TEST_REPO;
    const events = process.env.FLOWERSEC_TEST_EVENTS;
    withSwiftSecurityCache(repoRoot, (cachePath) => {
      fs.mkdirSync(cachePath, { recursive: true });
      const marker = "owner-" + process.pid;
      fs.writeFileSync(cachePath + "/" + marker, "held");
      fs.appendFileSync(events, "start " + process.pid + "\\n");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 60);
      if (fs.readFileSync(cachePath + "/" + marker, "utf8") !== "held") {
        throw new Error("cache marker was removed while lock was held");
      }
      fs.appendFileSync(events, "end " + process.pid + "\\n");
    }, { timeoutMs: 3000, pollMs: 1 });
  `;
  const environment = {
    ...process.env,
    FLOWERSEC_TEST_REPO: repoRoot,
    FLOWERSEC_TEST_EVENTS: events,
  };
  await Promise.all([runNodeSnippet(script, environment), runNodeSnippet(script, environment)]);
  const lines = fs.readFileSync(events, "utf8").trim().split("\n");
  assert.equal(lines.length, 4);
  assert.match(lines[0], /^start /);
  assert.match(lines[1], /^end /);
  assert.match(lines[2], /^start /);
  assert.match(lines[3], /^end /);
  assert.equal(fs.existsSync(path.join(cachePath, "partial")), false);
  assert.equal(fs.readdirSync(cachePath).filter((entry) => entry.startsWith("owner-")).length, 2);
  assert.equal(fs.existsSync(lockPath), false);
});

test("Swift resolver uses unique disposable caches and cleans every failure path", async () => {
  const { resolveSwiftSecurityContexts } = await loadChecker();
  const graph = {
    identity: "fixture",
    url: sourceRoot,
    version: "unspecified",
    path: sourceRoot,
    dependencies: [],
  };
  const scratchPaths = [];
  const runner = (command, args) => {
    if (args[0] === "--version") {
      return "swift-driver version: 1.148.6 Apple Swift version 6.3.1";
    }
    scratchPaths.push(args[args.indexOf("--scratch-path") + 1]);
    return JSON.stringify(graph);
  };
  resolveSwiftSecurityContexts(sourceRoot, { run: runner });
  resolveSwiftSecurityContexts(sourceRoot, { run: runner });
  assert.equal(new Set(scratchPaths).size, 4);
  for (const scratch of scratchPaths) assert.equal(fs.existsSync(scratch), false);

  const failures = [
    { output: () => { throw new Error("runner failed"); }, pattern: /runner failed/ },
    { output: () => "not-json", pattern: /JSON/ },
    {
      output: () => JSON.stringify({
        identity: "remote",
        version: "1.0.0",
        path: sourceRoot,
        dependencies: [],
      }),
      inspectRevision: () => { throw new Error("revision failed"); },
      pattern: /revision failed/,
    },
  ];
  for (const failure of failures) {
    let failedScratch;
    assert.throws(() => resolveSwiftSecurityContexts(sourceRoot, {
      run(command, args) {
        if (args[0] === "--version") {
          return "swift-driver version: 1.148.6 Apple Swift version 6.3.1";
        }
        failedScratch = args[args.indexOf("--scratch-path") + 1];
        return failure.output();
      },
      inspectRevision: failure.inspectRevision,
    }), failure.pattern);
    assert.ok(failedScratch);
    assert.equal(fs.existsSync(failedScratch), false);
  }
});

test("Swift security checker is wired into the Swift gate", async () => {
  await loadChecker();
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(makefile, /^swift-security-check:\n\tnode scripts\/check-swift-security\.mjs$/m);
  assert.match(
    makefile,
    /^swift-check: swift-package-check swift-security-check swift-source-guard swift-build swift-test swift-cover-check$/m,
  );
});
