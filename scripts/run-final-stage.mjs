#!/usr/bin/env node

import { spawn } from "node:child_process";

const [, , secondsText, stage, command, ...args] = process.argv;
const seconds = Number(secondsText);
if (!Number.isInteger(seconds) || seconds < 1 || seconds > 595
  || !["preflight", "contracts", "packages", "race", "languages", "post"].includes(stage) || !command) {
  process.stderr.write("usage: run-final-stage.mjs <1-595 seconds> <preflight|contracts|packages|race|languages|post> <command> [args...]\n");
  process.exit(2);
}

const child = spawn(command, args, {
  detached: true,
  stdio: "inherit",
});
let timedOut = false;
let killTimer;
let forwardedSignal;

function signalGroup(signal) {
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

const timeout = setTimeout(() => {
  timedOut = true;
  process.stderr.write(`${stage} stage exceeded ${seconds} seconds; terminating its process group\n`);
  signalGroup("SIGTERM");
  killTimer = setTimeout(() => signalGroup("SIGKILL"), 5_000);
}, seconds * 1_000);
timeout.unref();

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    if (forwardedSignal) return;
    forwardedSignal = signal;
    clearTimeout(timeout);
    signalGroup(signal);
    killTimer = setTimeout(() => signalGroup("SIGKILL"), 5_000);
  });
}

child.on("error", (error) => {
  clearTimeout(timeout);
  process.stderr.write(`cannot start ${stage} stage: ${error.message}\n`);
  process.exitCode = 1;
});

child.on("exit", (code, signal) => {
  clearTimeout(timeout);
  if (timedOut) {
    process.exitCode = 124;
  } else if (forwardedSignal) {
    process.exitCode = 128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 }[forwardedSignal]);
  } else if (code !== null) {
    process.exitCode = code;
  } else {
    process.stderr.write(`${stage} stage terminated by ${signal}\n`);
    process.exitCode = 128 + (signal === "SIGTERM" ? 15 : 9);
  }
});
