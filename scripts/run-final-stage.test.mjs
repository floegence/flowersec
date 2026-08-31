#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const runner = path.join(import.meta.dirname, "run-final-stage.mjs");
const helperMode = process.argv[2];

if (helperMode === "descendant") {
  setTimeout(() => fs.writeFileSync(process.argv[3], "late"), Number(process.argv[4]));
} else if (helperMode === "parent") {
  spawn(process.execPath, [import.meta.filename, "descendant", process.argv[3], process.argv[4]], { stdio: "ignore" });
  process.stderr.write("final-stage-helper-ready\n");
  setInterval(() => {}, 1_000);
} else {

function run(args, options = {}) {
  return spawnSync(process.execPath, [runner, ...args], { encoding: "utf8", ...options });
}

function isolatedGitEnvironment(overrides = {}) {
  const environment = { ...process.env, ...overrides };
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
  ]) delete environment[variable];
  return environment;
}

test("final stage wrapper validates its closed command contract", () => {
  for (const args of [
    [],
    ["0", "race", "true"],
    ["596", "race", "true"],
    ["1", "unknown", "true"],
    ["1", "race"],
  ]) {
    assert.notEqual(run(args).status, 0, args.join(" "));
  }
});

test("final stage wrapper preserves success and failure status", () => {
  assert.equal(run(["1", "preflight", process.execPath, "-e", "process.exit(0)"]).status, 0);
  assert.equal(run(["1", "contracts", process.execPath, "-e", "process.exit(0)"]).status, 0);
  assert.equal(run(["1", "packages", process.execPath, "-e", "process.exit(0)"]).status, 0);
  assert.equal(run(["1", "race", process.execPath, "-e", "process.exit(0)"]).status, 0);
  assert.equal(run(["1", "languages", process.execPath, "-e", "process.exit(23)"]).status, 23);
  assert.equal(run(["1", "browser", process.execPath, "-e", "process.exit(0)"]).status, 0);
  assert.equal(run(["1", "post", process.execPath, "-e", "process.exit(0)"]).status, 0);
});

test("offline stages use the exact prefetched Go toolchain and reject drift", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-final-go-toolchain-"));
  try {
    const gitEnvironment = isolatedGitEnvironment();
    assert.equal(spawnSync("git", ["init", "-q"], { cwd: root, env: gitEnvironment }).status, 0);
    assert.equal(spawnSync("git", ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "fixture"], { cwd: root, env: gitEnvironment }).status, 0);
    const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8", env: gitEnvironment }).stdout.trim();
    const bin = path.join(root, "toolchain", "bin");
    const binary = path.join(bin, "go");
    fs.mkdirSync(path.join(root, ".flowersec"), { recursive: true });
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(binary, "#!/bin/sh\nprintf 'go version go1.27.0 test/arch\\n'\n", { mode: 0o755 });
    const state = {
      schema: "flowersec-final-go-toolchain-v1",
      sourceHead: head,
      version: "go1.27.0",
      binary,
      sha256: createHash("sha256").update(fs.readFileSync(binary)).digest("hex"),
    };
    fs.writeFileSync(path.join(root, ".flowersec", "final-go-toolchain.json"), `${JSON.stringify(state)}\n`);
    const environment = isolatedGitEnvironment({
      GOSUMDB: "off",
      GOPROXY: "off",
    });
    const check = [
      "const { spawnSync } = require('node:child_process');",
      "if (process.env.GOTOOLCHAIN !== 'local') process.exit(21);",
      "const result = spawnSync('go', ['version'], { encoding: 'utf8' });",
      "if (result.status !== 0 || !result.stdout.includes('go1.27.0 test/arch')) process.exit(22);",
    ].join("");
    assert.equal(run(["5", "packages", process.execPath, "-e", check], { cwd: root, env: environment }).status, 0);
    fs.appendFileSync(binary, "# drift\n");
    const drifted = run(["5", "packages", process.execPath, "-e", "process.exit(0)"], { cwd: root, env: environment });
    assert.notEqual(drifted.status, 0);
    assert.match(drifted.stderr, /digest changed after preflight/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("offline toolchain state and binary reads use no-follow file descriptors", () => {
  const source = fs.readFileSync(runner, "utf8");
  assert.match(source, /openSync\(filePath, fs\.constants\.O_RDONLY \| fs\.constants\.O_NOFOLLOW\)/);
  assert.match(source, /fstatSync\(descriptor\)/);
  assert.match(source, /readFileSync\(descriptor\)/);
  assert.match(source, /readRegularFileNoFollow\(statePath/);
  assert.match(source, /readRegularFileNoFollow\(state\.binary/);
  assert.doesNotMatch(source, /lstatSync\(/);
});

test("final stage kill fallbacks do not delay a drained process group", () => {
  const source = fs.readFileSync(runner, "utf8");
  assert.equal(
    source.match(/killTimer\.unref\(\);/g)?.length,
    2,
    "timeout and forwarded-signal fallbacks must both be unreferenced",
  );
});

test("final stage wrapper terminates the complete child process group", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-final-stage-"));
  const marker = path.join(root, "child-finished");
  try {
    const result = run(["1", "race", process.execPath, import.meta.filename, "parent", marker, "1500"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /race stage exceeded 1 seconds/);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 700);
    assert.equal(fs.existsSync(marker), false, "timed-out descendants must not survive the stage");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("final stage wrapper forwards external termination to descendants", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-final-signal-"));
  const marker = path.join(root, "child-finished");
  try {
    const child = spawn(process.execPath, [runner, "5", "languages", process.execPath, import.meta.filename, "parent", marker, "700"], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    let readyTimer;
    const ready = new Promise((resolve, reject) => {
      readyTimer = setTimeout(() => reject(new Error(`final stage helper did not become ready\n${stderr}`)), 5_000);
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
        if (stderr.includes("final-stage-helper-ready\n")) resolve();
      });
    });
    const exited = new Promise((resolve) => {
      child.on("exit", (code, signal) => resolve({ code, signal }));
    });
    await ready;
    clearTimeout(readyTimer);
    assert.equal(child.kill("SIGTERM"), true);
    const result = { ...await exited, stderr };
    assert.equal(result.signal, null);
    assert.equal(result.code, 143, result.stderr);
    await new Promise((resolve) => setTimeout(resolve, 800));
    assert.equal(fs.existsSync(marker), false, "externally terminated descendants must not survive the stage");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
}
