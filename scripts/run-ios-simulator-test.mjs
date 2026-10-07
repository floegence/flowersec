#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const minimumIOSMajor = 26;
const udidPattern = /^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$/;

export function selectIOSSimulator(payload, requestedID) {
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
  if (requestedID !== undefined) {
    const requested = candidates.find(({ udid }) => udid === requestedID);
    if (!requested) throw new Error(`requested Simulator ${requestedID} is not an available iOS ${minimumIOSMajor}+ device`);
    return requested;
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

const suites = {
  connector: [
    "TransportNativeSessionTests/testActualPublicPoolWSSHandshakeStreamsRekeyAndPingForBothProfiles",
    "TransportNativeSessionTests/testPublicSessionUsesSignedLeafPinAndPreservesBothDirectionsMetadata",
    "TransportNativeSessionTests/testCurrentLoopbackHTTPPreservesOriginalAuthenticationAndRefusesTLSBeforeAcquire",
  ],
  "client-handlers": [
    "TransportNativeSessionTests/testClientRegisteredHandlersReceiveNativeRPCAndNotify",
    "TransportNativeSessionTests/testControllerRegisteredHandlersReceiveNativeRPCAndNotifyAfterReplacement",
    "TransportNativeSessionTests/testControllerRefusesSecondReplacementUntilOriginalRetiredNotificationCallbackExits",
  ],
  "server-acceptor": [
    "TransportOriginalLiveServerTests/testPoolServerSourcePreservesCanceledAcquireAndAuthenticatedAllowHandoff",
    "TransportOriginalLiveServerTests/testOriginalServerAllowACKRetryAndContinuousRelayForwarding",
    "TransportOriginalLiveServerTests/testNativeRelayUsesEachSignedDirectionIndependently",
    "TransportOriginalLiveServerTests/testTransferredOriginalMaterialRetainsCarrierAfterSourceClose",
    "TransportOriginalLiveServerTests/testCompletedSourceCleanupStaysCompleteDuringTransferredMaterialAndEnvironmentClose",
    "TransportOriginalLiveServerTests/testOriginalAdmissionCommitResultLossNeverProducesFSAOrReady",
  ],
  "server-session-handlers": [
    "TransportOriginalLiveServerTests/testServePublishesAuthenticatedPlanAndReleasesOriginalLeaseAfterDrain",
    "TransportOriginalLiveServerTests/testServeDrainDuringApplicationAuthorizationCannotCommitAdmissionOrPublishReady",
    "TransportOriginalLiveServerTests/testServeDrainWinsBeforeQueuedOnSessionAndPreventsRawDispatch",
    "TransportOriginalLiveServerTests/testServeRequestRejectionPreservesHealthySiblingSession",
    "ServiceApplicationOwnershipV4Tests/testServerUnaryKeepsOriginalKPositionThroughBlockedPublication",
    "ServiceApplicationOwnershipV4Tests/testServerUnknownTypeDrainsOriginalInputAndKeepsRPCChannelAvailable",
    "ServiceApplicationOwnershipV4Tests/testServerExecutionNotificationDispatchesWithoutObservationSubscribers",
    "streamHandlersServeEstablishedEndpointClientSession()",
    "streamHandlersApplySharedOpenKindContract()",
    "streamHandlersIsolateFailuresAndContinueDispatch()",
    "streamHandlersApplyRawMetadataContractBeforeHandler()",
    "streamHandlersEnforceConcurrencyAndCloseBeforeWaitingForCancellation()",
  ],
};

export function iosTestsForSuite(suite) {
  if (!Object.hasOwn(suites, suite)) throw new Error(`unknown iOS test suite: ${suite}`);
  return [...suites[suite]];
}

export function verifyIOSTestResults(report, expected) {
  const normalize = (id) => id.replace(/^FlowersecTests\//u, "").replace(/\(\)$/u, "");
  const results = new Map();
  function visit(nodes) {
    for (const node of nodes ?? []) {
      if (node.nodeType === "Test Case" && typeof node.nodeIdentifier === "string") {
        results.set(normalize(node.nodeIdentifier), node.result);
      }
      visit(node.children);
    }
  }
  visit(report.testNodes);
  const missing = expected.filter((id) => results.get(normalize(id)) !== "Passed");
  if (missing.length > 0) throw new Error(`iOS tests did not pass or execute: ${missing.join(", ")}`);
  return expected.length;
}

function main() {
  const { values } = parseArgs({ options: {
    preflight: { type: "boolean", default: false },
    suite: { type: "string", default: "connector" },
  } });
  const expected = iosTestsForSuite(values.suite);
  const inventory = JSON.parse(execFileSync(
    "xcrun", ["simctl", "list", "devices", "available", "--json"],
    { cwd: root, encoding: "utf8" },
  ));
  const simulator = selectIOSSimulator(inventory, process.env.FLOWERSEC_IOS_SIMULATOR_ID);
  if (simulator.state !== "Booted") run("xcrun", ["simctl", "boot", simulator.udid]);
  run("xcrun", ["simctl", "bootstatus", simulator.udid, "-b"]);
  process.stdout.write(
    `iOS Simulator ready: ${simulator.name} (${simulator.udid}), iOS ${simulator.version.join(".")}\n`,
  );
  if (values.preflight) return;
  mkdirSync(path.join(root, ".flowersec"), { recursive: true });
  const scratch = mkdtempSync(path.join(root, ".flowersec", "ios-simulator-"));
  const resultBundle = path.join(scratch, "tests.xcresult");
  try {
    // Native connector and server tests share the package's original TLS resources
    // and exercise the same NIO provider on macOS and iOS.
    const result = spawnSync("xcodebuild", [
      "-quiet", "-scheme", "Flowersec",
      "-disableAutomaticPackageResolution", "-onlyUsePackageVersionsFromResolvedFile", "-skipPackageUpdates",
      "-destination", `platform=iOS Simulator,id=${simulator.udid}`,
      "-parallel-testing-enabled", "NO", "-resultBundlePath", resultBundle, "test",
      ...expected.map((id) => `-only-testing:FlowersecTests/${id}`),
      "CODE_SIGNING_ALLOWED=NO",
    ], { cwd: root, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      // Preserve failure details in the caller's log before removing the bundle.
      spawnSync("xcrun", ["xcresulttool", "get", "test-results", "tests", "--path", resultBundle, "--compact"],
        { cwd: root, stdio: "inherit" });
      const error = new Error(`xcodebuild exited with status ${result.status ?? 1}`);
      error.exitStatus = result.status ?? 1;
      throw error;
    }
    const report = JSON.parse(execFileSync("xcrun", [
      "xcresulttool", "get", "test-results", "tests", "--path", resultBundle, "--compact",
    ], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }));
    process.stdout.write(`${JSON.stringify(report)}\n`);
    const count = verifyIOSTestResults(report, expected);
    process.stdout.write(`iOS suite ${values.suite}: ${count} expected tests passed\n`);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
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
