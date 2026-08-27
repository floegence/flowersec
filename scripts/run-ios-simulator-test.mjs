#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const minimumIOSMajor = 26;
const udidPattern = /^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$/;

export function selectIOSSimulator(payload) {
  if (payload === null || typeof payload !== "object" || payload.devices === null ||
      typeof payload.devices !== "object") {
    throw new Error("simctl returned an invalid device inventory");
  }
  const candidates = [];
  for (const [runtime, devices] of Object.entries(payload.devices)) {
    const match = /^com\.apple\.CoreSimulator\.SimRuntime\.iOS-(\d+)(?:-(\d+))?/.exec(runtime);
    if (match === null || !Array.isArray(devices)) continue;
    const version = [Number(match[1]), Number(match[2] ?? 0)];
    if (version[0] < minimumIOSMajor) continue;
    for (const device of devices) {
      if (device === null || typeof device !== "object" || device.isAvailable === false ||
          typeof device.name !== "string" || typeof device.udid !== "string" ||
          !udidPattern.test(device.udid) || !["Booted", "Shutdown"].includes(device.state)) continue;
      candidates.push({ name: device.name, udid: device.udid, state: device.state, version });
    }
  }
  candidates.sort((left, right) =>
    Number(right.state === "Booted") - Number(left.state === "Booted") ||
    right.version[0] - left.version[0] || right.version[1] - left.version[1] ||
    left.name.localeCompare(right.name) || left.udid.localeCompare(right.udid));
  if (candidates.length === 0) {
    throw new Error(`no available iOS ${minimumIOSMajor}+ Simulator is installed`);
  }
  return candidates[0];
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit", ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const error = new Error(`${command} exited with status ${result.status ?? 1}`);
    error.exitStatus = result.status ?? 1;
    throw error;
  }
}

function runCleanup(commands) {
  let failure;
  for (const [command, args] of commands) {
    try {
      run(command, args);
    } catch (error) {
      failure ??= error;
    }
  }
  if (failure) throw failure;
}

function main() {
  const preflight = process.argv.slice(2);
  if (preflight.length > 1 || (preflight.length === 1 && preflight[0] !== "--preflight")) {
    process.stderr.write("usage: run-ios-simulator-test.mjs [--preflight]\n");
    process.exit(2);
  }
  const inventory = JSON.parse(execFileSync(
    "xcrun", ["simctl", "list", "devices", "available", "--json"],
    { cwd: root, encoding: "utf8" },
  ));
  const simulator = selectIOSSimulator(inventory);
  if (simulator.state !== "Booted") run("xcrun", ["simctl", "boot", simulator.udid]);
  run("xcrun", ["simctl", "bootstatus", simulator.udid, "-b"]);
  process.stdout.write(
    `iOS Simulator ready: ${simulator.name} (${simulator.udid}), iOS ${simulator.version.join(".")}\n`,
  );
  if (preflight[0] === "--preflight") return;
  const fixtureDirectory = mkdtempSync(`${os.tmpdir()}/flowersec-ios-tls-`);
  const certificatePath = path.join(fixtureDirectory, "leaf.pem");
  const privateKeyPath = path.join(fixtureDirectory, "leaf-key.pem");
  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-sha256", "-nodes", "-days", "7", "-subj", "/CN=localhost",
      "-addext", "basicConstraints=critical,CA:FALSE",
      "-addext", "keyUsage=critical,digitalSignature",
      "-addext", "extendedKeyUsage=serverAuth",
      "-addext", "subjectAltName=DNS:localhost", "-keyout", privateKeyPath,
      "-out", certificatePath,
    ], { cwd: root, stdio: "ignore" });
    // xcodebuild does not forward arbitrary parent environment variables to
    // Simulator test runners. Set them in the Simulator launch environment and
    // always remove them before deleting the short-lived fixture.
    run("xcrun", [
      "simctl", "spawn", simulator.udid, "launchctl", "setenv",
      "FLOWERSEC_IOS_TEST_CERT", certificatePath,
    ]);
    run("xcrun", [
      "simctl", "spawn", simulator.udid, "launchctl", "setenv",
      "FLOWERSEC_IOS_TEST_KEY", privateKeyPath,
    ]);
    run("xcodebuild", [
      "-quiet", "-scheme", "Flowersec",
      "-destination", `platform=iOS Simulator,id=${simulator.udid}`,
      "-parallel-testing-enabled", "NO", "test",
      "-only-testing:FlowersecTests/ConnectorV2Tests/testProductionV3IOSAdapterBuildsPinnedTLSHandlerAndVerifiesLeaf",
      "-only-testing:FlowersecTests/ConnectorV2Tests/testProductionV3IOSAdapterRejectsWrongPinAndBuildsConfiguredCA",
      "CODE_SIGNING_ALLOWED=NO",
    ]);
  } finally {
    try {
      runCleanup([
        ["xcrun", [
          "simctl", "spawn", simulator.udid, "launchctl", "unsetenv",
          "FLOWERSEC_IOS_TEST_CERT",
        ]],
        ["xcrun", [
          "simctl", "spawn", simulator.udid, "launchctl", "unsetenv",
          "FLOWERSEC_IOS_TEST_KEY",
        ]],
      ]);
    } finally {
      rmSync(fixtureDirectory, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    main();
  } catch (error) {
    if (Number.isInteger(error?.exitStatus)) {
      process.exitCode = error.exitStatus;
    } else {
      throw error;
    }
  }
}
