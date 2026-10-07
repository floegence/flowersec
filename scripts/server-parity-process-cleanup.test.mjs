import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { test } from "node:test";
import { stopAndJoinParityProcesses } from "./server-parity-browser-installation.mjs";

test("parity cleanup joins a child whose stdout ends before its exit event", async () => {
  const child = spawn(process.execPath, ["-e", ""], {
    detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"],
  });
  const completion = once(child, "close");
  await once(child.stdout, "end");
  await stopAndJoinParityProcesses([{ child, completion }]);
  assert.notEqual(child.exitCode ?? child.signalCode, null);
  if (process.platform !== "win32") assert.throws(() => process.kill(-child.pid, 0), { code: "ESRCH" });
});

test("parity cleanup terminates and joins a live original child", async () => {
  const child = spawn(process.execPath, ["-e", "console.log('ready'); setInterval(() => {}, 1000)"], {
    detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"],
  });
  const completion = once(child, "close");
  await once(child.stdout, "data");
  await stopAndJoinParityProcesses([{ child, completion }]);
  assert.notEqual(child.exitCode ?? child.signalCode, null);
});

test("parity cleanup preserves a permission error when the group still exists", { skip: process.platform === "win32" }, async t => {
  const denied = Object.assign(new Error("denied"), { code: "EPERM" });
  t.mock.method(process, "kill", (_pid, signal) => { if (signal !== 0) throw denied; return true; });
  await assert.rejects(stopAndJoinParityProcesses([{ child: { pid: 123 }, completion: Promise.resolve() }]), error => {
    assert.ok(error instanceof AggregateError);
    assert.deepEqual(error.errors, [denied]);
    return true;
  });
});

test("parity cleanup waits for a transient denied group probe after joining", { skip: process.platform === "win32" }, async t => {
  let probes = 0;
  t.mock.method(process, "kill", (_pid, signal) => {
    if (signal !== 0) return true;
    probes++;
    throw Object.assign(new Error(probes === 1 ? "reaping" : "gone"), { code: probes === 1 ? "EPERM" : "ESRCH" });
  });
  await stopAndJoinParityProcesses([{ child: { pid: 123 }, completion: Promise.resolve() }]);
  assert.equal(probes, 2);
});
