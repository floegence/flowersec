import assert from "node:assert/strict";
import test from "node:test";

import { iosTestsForSuite, selectIOSSimulator, verifyIOSTestResults } from "./run-ios-simulator-test.mjs";

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


test("explicit simulator selection cannot fall back to another task's booted device", () => {
  const inventory = { devices: {
    "com.apple.CoreSimulator.SimRuntime.iOS-26-4": [
      { isAvailable: true, name: "Other task", state: "Booted", udid: id("1") },
      { isAvailable: true, name: "Dedicated", state: "Shutdown", udid: id("2") },
    ],
    "com.apple.CoreSimulator.SimRuntime.iOS-25-4": [
      { isAvailable: true, name: "Old", state: "Booted", udid: id("3") },
    ],
  } };
  assert.equal(selectIOSSimulator(inventory, id("2")).name, "Dedicated");
  for (const requested of [id("3"), id("4"), "invalid"]) {
    assert.throws(() => selectIOSSimulator(inventory, requested), /requested Simulator/);
  }
});

test("each simulator suite requires its selected tests to execute and pass", () => {
  for (const suite of ["connector", "client-handlers", "server-acceptor", "server-session-handlers"]) {
    const expected = iosTestsForSuite(suite);
    assert.ok(expected.length > 0);
    assert.equal(new Set(expected).size, expected.length);
    const testNodes = [{ nodeType: "Unit test bundle", children: expected.map((name) => ({
      nodeType: "Test Case", nodeIdentifier: name.replace(/\(\)$/u, "") + "()", result: "Passed",
    })) }];
    assert.equal(verifyIOSTestResults({ testNodes }, expected), expected.length);
    assert.throws(() => verifyIOSTestResults({ testNodes: [] }, expected), /did not pass or execute/);
    for (const result of ["Skipped", "Failed", "Expected Failure"]) {
      testNodes[0].children[0].result = result;
      assert.throws(() => verifyIOSTestResults({ testNodes }, expected), /did not pass or execute/);
    }
  }
  assert.throws(() => iosTestsForSuite("misspelled"), /unknown iOS test suite/);
});
