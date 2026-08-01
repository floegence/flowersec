#!/usr/bin/env node

import { spawn } from "node:child_process";

const [, , command, ...targets] = process.argv;
if (!command || targets.length < 2 || new Set(targets).size !== targets.length
  || targets.some((target) => target === "" || target.startsWith("-"))) {
  process.stderr.write("usage: run-final-lanes.mjs <command> <target> <target> [target...]\n");
  process.exit(2);
}

const children = new Map();
const settledChildren = new WeakSet();
let remaining = targets.length;
let firstFailure;
let forwardedSignal;
let killTimer;

function signalChild(child, signal) {
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

function stopPeers(failedTarget) {
  for (const [target, child] of children) {
    if (target !== failedTarget && child.exitCode === null && child.signalCode === null) {
      signalChild(child, "SIGTERM");
    }
  }
  killTimer = setTimeout(() => {
    for (const child of children.values()) {
      if (child.exitCode === null && child.signalCode === null) signalChild(child, "SIGKILL");
    }
  }, 5_000);
  killTimer.unref();
}

function finishLane(child, target, code, signal) {
  if (settledChildren.has(child)) return;
  settledChildren.add(child);
  remaining -= 1;
  if (!firstFailure && !forwardedSignal && (code !== 0 || signal !== null)) {
    const status = code ?? (signal === "SIGTERM" ? 143 : 137);
    firstFailure = { target, status };
    process.stderr.write(`first final lane failure: ${target} exited with status ${status}\n`);
    stopPeers(target);
  }
  if (remaining !== 0) return;
  if (killTimer) clearTimeout(killTimer);
  if (forwardedSignal) {
    process.exitCode = 128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 }[forwardedSignal]);
  } else {
    process.exitCode = firstFailure?.status ?? 0;
  }
}

for (const target of targets) {
  const child = spawn(command, [target], { detached: true, stdio: "inherit" });
  children.set(target, child);
  child.once("error", (error) => {
    process.stderr.write(`cannot start final lane ${target}: ${error.message}\n`);
    finishLane(child, target, 1, null);
  });
  child.once("exit", (code, signal) => finishLane(child, target, code, signal));
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    if (forwardedSignal) return;
    forwardedSignal = signal;
    for (const child of children.values()) {
      if (child.exitCode === null && child.signalCode === null) signalChild(child, signal);
    }
    killTimer = setTimeout(() => {
      for (const child of children.values()) {
        if (child.exitCode === null && child.signalCode === null) signalChild(child, "SIGKILL");
      }
    }, 5_000);
    killTimer.unref();
  });
}
