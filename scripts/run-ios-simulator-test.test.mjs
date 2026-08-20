import assert from "node:assert/strict";
import test from "node:test";

import { selectIOSSimulator } from "./run-ios-simulator-test.mjs";

const id = (suffix) => `00000000-0000-0000-0000-${suffix.padStart(12, "0")}`;

test("prefers a booted compatible simulator, then the newest runtime", () => {
  const selected = selectIOSSimulator({ devices: {
    "com.apple.CoreSimulator.SimRuntime.iOS-27-0": [
      { isAvailable: true, name: "New", state: "Shutdown", udid: id("1") },
    ],
    "com.apple.CoreSimulator.SimRuntime.iOS-26-4": [
      { isAvailable: true, name: "Ready", state: "Booted", udid: id("2") },
    ],
  } });
  assert.equal(selected.name, "Ready");
});

test("rejects unavailable, malformed, and pre-iOS 26 devices", () => {
  assert.throws(() => selectIOSSimulator({ devices: {
    "com.apple.CoreSimulator.SimRuntime.iOS-25-4": [
      { isAvailable: true, name: "Old", state: "Booted", udid: id("1") },
    ],
    "com.apple.CoreSimulator.SimRuntime.iOS-26-4": [
      { isAvailable: false, name: "Unavailable", state: "Booted", udid: id("2") },
      { isAvailable: true, name: "Malformed", state: "Booted", udid: "local-machine-id" },
    ],
  } }), /no available iOS 26\+/);
});
