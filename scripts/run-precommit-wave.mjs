#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const [, , phase, command, ...targets] = process.argv;
const serialPhases = new Set(["generate", "dependencies"]);
const parallelPhases = new Set(["static", "languages"]);
const validTarget = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const validPhase = serialPhases.has(phase) || parallelPhases.has(phase);
const validTargetCount = serialPhases.has(phase) ? targets.length === 1 : targets.length >= 2;

if (!validPhase || !command || !validTargetCount
  || new Set(targets).size !== targets.length
  || targets.some((target) => !validTarget.test(target))) {
  process.stderr.write(
    "usage: run-precommit-wave.mjs <generate|dependencies> <command> <target>\n"
      + "   or: run-precommit-wave.mjs <static|languages> <command> <target> <target> [target...]\n",
  );
  process.exit(2);
}

const makeFlags = (process.env.MAKEFLAGS ?? "").split(/\s+/).filter(Boolean);
const makeDryRun = makeFlags.some((flag) => (
  flag === "--just-print"
  || flag === "--dry-run"
  || flag === "--recon"
  || (/^-?[A-Za-z]+$/.test(flag) && flag.replace(/^-/, "").includes("n"))
));
if (makeDryRun) {
  for (const target of targets) process.stdout.write(`${command} ${target}\n`);
  process.exit(0);
}

const logRoot = path.resolve(".flowersec", "precommit-logs", phase);
fs.rmSync(logRoot, { recursive: true, force: true });
fs.mkdirSync(logRoot, { recursive: true });

const startedAt = new Date();
const startedMs = Date.now();
const children = new Map();
const lanes = targets.map((target) => ({ target, startedMs: Date.now() }));
const laneByTarget = new Map(lanes.map((lane) => [lane.target, lane]));
const settledChildren = new WeakSet();
let remaining = targets.length;
let firstFailure;
let forwardedSignal;
let killTimer;

function signalChild(child, signal) {
  if (!Number.isInteger(child.pid)) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

function stopRunning(signal, exceptTarget) {
  for (const [target, child] of children) {
    if (target !== exceptTarget && child.exitCode === null && child.signalCode === null) {
      signalChild(child, signal);
    }
  }
}

function armKillFallback() {
  if (killTimer) return;
  killTimer = setTimeout(() => stopRunning("SIGKILL"), 5_000);
  killTimer.unref();
}

function statusFor(code, signal) {
  if (code !== null) return code;
  return 128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15, SIGKILL: 9 }[signal] ?? 1);
}

function writeStatus() {
  const finishedAt = new Date();
  const status = {
    phase,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: Date.now() - startedMs,
    firstFailure: firstFailure ?? null,
    lanes: lanes.map(({ startedMs: laneStartedMs, ...lane }) => ({
      ...lane,
      durationMs: lane.durationMs ?? Date.now() - laneStartedMs,
    })),
  };
  const temporary = path.join(logRoot, "status.json.tmp");
  fs.writeFileSync(temporary, `${JSON.stringify(status, null, 2)}\n`);
  fs.renameSync(temporary, path.join(logRoot, "status.json"));
  process.stdout.write(`[precommit:${phase}] completed in ${status.durationMs}ms\n`);
}

function finishLane(child, target, code, signal) {
  if (settledChildren.has(child)) return;
  settledChildren.add(child);
  const lane = laneByTarget.get(target);
  lane.status = statusFor(code, signal);
  lane.signal = signal;
  lane.durationMs = Date.now() - lane.startedMs;
  remaining -= 1;

  if (!firstFailure && !forwardedSignal && lane.status !== 0) {
    firstFailure = { target, status: lane.status };
    process.stderr.write(
      `first precommit ${phase} lane failure: ${target} exited with status ${lane.status}\n`,
    );
    stopRunning("SIGTERM", target);
    armKillFallback();
  }

  if (remaining !== 0) return;
  if (killTimer) clearTimeout(killTimer);
  writeStatus();
  process.exitCode = forwardedSignal
    ? 128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 }[forwardedSignal])
    : (firstFailure?.status ?? 0);
}

process.stdout.write(`[precommit:${phase}] starting ${targets.length} lane(s)\n`);
for (const target of targets) {
  const stdoutPath = path.join(logRoot, `${target}.stdout.log`);
  const stderrPath = path.join(logRoot, `${target}.stderr.log`);
  fs.writeFileSync(stdoutPath, "");
  fs.writeFileSync(stderrPath, "");

  const child = spawn(command, [target], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.set(target, child);
  child.stdout?.on("data", (chunk) => {
    fs.appendFileSync(stdoutPath, chunk);
    process.stdout.write(chunk);
  });
  child.stderr?.on("data", (chunk) => {
    fs.appendFileSync(stderrPath, chunk);
    process.stderr.write(chunk);
  });
  child.once("error", (error) => {
    const message = `cannot start precommit ${phase} lane ${target}: ${error.message}\n`;
    fs.appendFileSync(stderrPath, message);
    process.stderr.write(message);
    finishLane(child, target, 1, null);
  });
  child.once("close", (code, signal) => finishLane(child, target, code, signal));
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    if (forwardedSignal) return;
    forwardedSignal = signal;
    stopRunning(signal);
    armKillFallback();
  });
}
