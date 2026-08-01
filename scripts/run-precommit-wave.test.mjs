#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const runner = path.join(import.meta.dirname, "run-precommit-wave.mjs");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-precommit-wave-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const helper = path.join(root, "lane-helper");
  fs.writeFileSync(helper, [
    "#!/usr/bin/env node",
    'import fs from "node:fs";',
    'const target = process.argv[2] ?? "";',
    'if (target === "success") { process.stdout.write("success output\\n"); process.exit(0); }',
    'else if (target === "fail") { process.stderr.write("failure output\\n"); setTimeout(() => process.exit(23), 50); }',
    'else if (target === "wait") { process.on("SIGTERM", () => { fs.writeFileSync(process.env.FLOWERSEC_TEST_MARKER, "stopped\\n"); process.exit(0); }); setInterval(() => {}, 100); }',
    "else { process.exit(2); }",
    "",
  ].join("\n"));
  fs.chmodSync(helper, 0o755);
  return { helper, root };
}

test("precommit wave validates its closed phase and target contract", (t) => {
  const { helper, root } = fixture(t);
  for (const args of [
    [],
    ["unknown", helper, "success"],
    ["static", helper, "success"],
    ["languages", helper, "same", "same"],
    ["generate", helper, "success", "wait"],
  ]) {
    const result = spawnSync(process.execPath, [runner, ...args], { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 2, `${args.join(" ")}\n${result.stderr}`);
  }
});

test("precommit wave records isolated logs, status, and timing", (t) => {
  const { helper, root } = fixture(t);
  const result = spawnSync(process.execPath, [runner, "generate", helper, "success"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const logRoot = path.join(root, ".flowersec/precommit-logs/generate");
  assert.equal(fs.readFileSync(path.join(logRoot, "success.stdout.log"), "utf8"), "success output\n");
  assert.equal(fs.readFileSync(path.join(logRoot, "success.stderr.log"), "utf8"), "");
  const status = JSON.parse(fs.readFileSync(path.join(logRoot, "status.json"), "utf8"));
  assert.equal(status.phase, "generate");
  assert.equal(status.lanes[0].target, "success");
  assert.equal(status.lanes[0].status, 0);
  assert.ok(status.lanes[0].durationMs >= 0);
});

test("precommit wave keeps inherited Make dry runs side-effect free", (t) => {
  const { helper, root } = fixture(t);
  const result = spawnSync(process.execPath, [runner, "generate", helper, "success"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, MAKEFLAGS: "n" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, new RegExp(`${helper.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} success`));
  assert.equal(fs.existsSync(path.join(root, ".flowersec")), false);
});

test("precommit wave preserves the first failure and stops peer process groups", (t) => {
  const { helper, root } = fixture(t);
  const marker = path.join(root, "peer-stopped");
  const result = spawnSync(process.execPath, [runner, "static", helper, "fail", "wait"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, FLOWERSEC_TEST_MARKER: marker },
    timeout: 5_000,
  });
  assert.equal(result.status, 23, result.stderr);
  assert.match(result.stderr, /first precommit static lane failure: fail exited with status 23/);
  assert.equal(fs.existsSync(marker), true, "peer process group must receive SIGTERM");
  const status = JSON.parse(fs.readFileSync(path.join(root, ".flowersec/precommit-logs/static/status.json"), "utf8"));
  assert.deepEqual(status.firstFailure, { target: "fail", status: 23 });
  assert.equal(status.lanes.length, 2);
});
