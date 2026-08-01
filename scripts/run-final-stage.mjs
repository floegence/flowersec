#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const [, , secondsText, stage, command, ...args] = process.argv;
const seconds = Number(secondsText);
if (!Number.isInteger(seconds) || seconds < 1 || seconds > 595
  || !["preflight", "contracts", "packages", "race", "languages", "post"].includes(stage) || !command) {
  process.stderr.write("usage: run-final-stage.mjs <1-595 seconds> <preflight|contracts|packages|race|languages|post> <command> [args...]\n");
  process.exit(2);
}

function offlineEnvironment() {
  if (stage === "preflight" || process.env.GOSUMDB !== "off") return process.env;
  const makeFlags = (process.env.MAKEFLAGS ?? "").split(/\s+/).filter(Boolean);
  const makeDryRun = makeFlags.some((flag) => (
    flag === "--just-print"
    || flag === "--dry-run"
    || flag === "--recon"
    || (/^-?[A-Za-z]+$/.test(flag) && flag.replace(/^-/, "").includes("n"))
  ));
  if (makeDryRun) return process.env;
  const statePath = path.join(process.cwd(), ".flowersec", "final-go-toolchain.json");
  const linked = fs.lstatSync(statePath);
  if (!linked.isFile() || linked.isSymbolicLink()) throw new Error("offline Go toolchain state must be a regular file");
  const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
  if (state.schema !== "flowersec-final-go-toolchain-v1"
    || state.version !== "go1.26.5"
    || typeof state.binary !== "string"
    || !path.isAbsolute(state.binary)
    || !/^[0-9a-f]{64}$/.test(state.sha256)
    || !/^[0-9a-f]{40}$/.test(state.sourceHead)) {
    throw new Error("offline Go toolchain state is invalid");
  }
  const binaryInfo = fs.lstatSync(state.binary);
  if (!binaryInfo.isFile() || binaryInfo.isSymbolicLink()) {
    throw new Error("offline Go toolchain must be a regular file");
  }
  const digest = createHash("sha256").update(fs.readFileSync(state.binary)).digest("hex");
  if (digest !== state.sha256) throw new Error("offline Go toolchain digest changed after preflight");
  const head = spawnSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" });
  if (head.status !== 0 || head.stdout.trim() !== state.sourceHead) {
    throw new Error("offline Go toolchain state belongs to another source HEAD");
  }
  const version = spawnSync(state.binary, ["version"], {
    encoding: "utf8",
    env: { ...process.env, GOTOOLCHAIN: "local", GOWORK: "off" },
  });
  if (version.status !== 0 || !version.stdout.startsWith(`go version ${state.version} `)) {
    throw new Error("offline Go toolchain version changed after preflight");
  }
  return {
    ...process.env,
    PATH: `${path.dirname(state.binary)}${path.delimiter}${process.env.PATH ?? ""}`,
    GOTOOLCHAIN: "local",
    GOWORK: "off",
  };
}

let childEnvironment;
try {
  childEnvironment = offlineEnvironment();
} catch (error) {
  process.stderr.write(`cannot start ${stage} stage: ${error.message}\n`);
  process.exit(1);
}

const child = spawn(command, args, {
  detached: true,
  stdio: "inherit",
  env: childEnvironment,
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
  killTimer.unref();
}, seconds * 1_000);
timeout.unref();

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {
    if (forwardedSignal) return;
    forwardedSignal = signal;
    clearTimeout(timeout);
    signalGroup(signal);
    killTimer = setTimeout(() => signalGroup("SIGKILL"), 5_000);
    killTimer.unref();
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
