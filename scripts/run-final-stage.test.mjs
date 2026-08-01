#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";

const runner = path.join(import.meta.dirname, "run-final-stage.mjs");
const helperMode = process.argv[2];

if (helperMode === "descendant") {
  setTimeout(() => fs.writeFileSync(process.argv[3], "late"), 2_500);
} else if (helperMode === "parent") {
  spawn(process.execPath, [import.meta.filename, "descendant", process.argv[3]], { stdio: "ignore" });
  setInterval(() => {}, 1_000);
} else {

function run(args) {
  return spawnSync(process.execPath, [runner, ...args], { encoding: "utf8" });
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
  assert.equal(run(["1", "packages", process.execPath, "-e", "process.exit(0)"]).status, 0);
  assert.equal(run(["1", "race", process.execPath, "-e", "process.exit(0)"]).status, 0);
  assert.equal(run(["1", "languages", process.execPath, "-e", "process.exit(23)"]).status, 23);
});

test("final stage wrapper terminates the complete child process group", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-final-stage-"));
  const marker = path.join(root, "child-finished");
  try {
    const result = run(["1", "race", process.execPath, import.meta.filename, "parent", marker]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /race stage exceeded 1 seconds/);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1800);
    assert.equal(fs.existsSync(marker), false, "timed-out descendants must not survive the stage");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("final stage wrapper forwards external termination to descendants", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-final-signal-"));
  const marker = path.join(root, "child-finished");
  try {
    const child = spawn(process.execPath, [runner, "5", "languages", process.execPath, import.meta.filename, "parent", marker], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    await new Promise((resolve) => setTimeout(resolve, 250));
    child.kill("SIGTERM");
    const result = await new Promise((resolve) => {
      let stderr = "";
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.on("exit", (code, signal) => resolve({ code, signal, stderr }));
    });
    assert.equal(result.signal, null);
    assert.equal(result.code, 143, result.stderr);
    await new Promise((resolve) => setTimeout(resolve, 2_800));
    assert.equal(fs.existsSync(marker), false, "externally terminated descendants must not survive the stage");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
}
