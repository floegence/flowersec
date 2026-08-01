#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const runner = path.join(import.meta.dirname, "run-final-lanes.mjs");
const helper = path.join(import.meta.dirname, "run-final-lanes-test-helper.mjs");

test("parallel final lanes report the first failure and stop peer work", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-final-lanes-"));
  try {
    const peerStopped = path.join(root, "peer-stopped");
    const executable = path.join(root, "lane-helper");
    fs.copyFileSync(helper, executable);
    fs.chmodSync(executable, 0o755);
    const result = spawnSync(process.execPath, [
      runner,
      executable,
      "fail:23",
      `wait:${peerStopped}`,
    ], { encoding: "utf8", timeout: 10_000 });
    assert.equal(result.status, 23, result.stderr);
    assert.match(result.stderr, /first final lane failure: fail:23 exited with status 23/);
    assert.equal(fs.existsSync(peerStopped), true, "running peer lane must receive bounded termination");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("parallel final lanes require at least two closed lane commands", () => {
  const result = spawnSync(process.execPath, [runner, "true"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage:/);
});

test("parallel final lanes reject duplicate lane targets", () => {
  const result = spawnSync(process.execPath, [runner, process.execPath, "same", "same"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage:/);
});
