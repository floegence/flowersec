"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const loaderSource = fs.readFileSync(path.join(__dirname, "index.js"), "utf8");

const supportedPlatforms = [
  ["darwin", "arm64", undefined, "@floegence/flowersec-node-native-darwin-arm64"],
  ["darwin", "x64", undefined, "@floegence/flowersec-node-native-darwin-x64"],
  ["linux", "arm64", "2.35", "@floegence/flowersec-node-native-linux-arm64-gnu"],
  ["linux", "x64", "2.35", "@floegence/flowersec-node-native-linux-x64-gnu"],
];

for (const [platform, arch, glibcVersion, expectedPackage] of supportedPlatforms) {
  test(`loads ${expectedPackage} for ${platform}-${arch}`, () => {
    const addon = Object.freeze({ contractVersion: () => 2 });
    const loaded = executeLoader({ platform, arch, glibcVersion, resolve: (specifier) => {
      assert.equal(specifier, expectedPackage);
      return addon;
    } });

    assert.equal(loaded.exports, addon);
    assert.deepEqual(loaded.requests, [expectedPackage]);
  });
}

test("rejects Linux musl without attempting to load a glibc package", () => {
  const loaded = executeLoader({ platform: "linux", arch: "x64" });

  assert.equal(loaded.requests.length, 0);
  assertUnavailable(loaded.error);
});

test("rejects an unknown platform and architecture without resolving a package", () => {
  const loaded = executeLoader({ platform: "win32", arch: "x64", glibcVersion: "2.35" });

  assert.equal(loaded.requests.length, 0);
  assertUnavailable(loaded.error);
});

test("maps a missing optional package to the public unavailable error", () => {
  const loaded = executeLoader({
    platform: "linux",
    arch: "x64",
    glibcVersion: "2.35",
    resolve: () => {
      const error = new Error("Cannot find module");
      error.code = "MODULE_NOT_FOUND";
      throw error;
    },
  });

  assert.deepEqual(loaded.requests, ["@floegence/flowersec-node-native-linux-x64-gnu"]);
  assertUnavailable(loaded.error);
});

test("maps native binary initialization failure to the public unavailable error", () => {
  const loaded = executeLoader({
    platform: "darwin",
    arch: "arm64",
    resolve: () => { throw new Error("dlopen failed: invalid binary"); },
  });

  assert.deepEqual(loaded.requests, ["@floegence/flowersec-node-native-darwin-arm64"]);
  assertUnavailable(loaded.error);
});

function executeLoader({ platform, arch, glibcVersion, resolve = () => undefined }) {
  const requests = [];
  const module = { exports: {} };
  let error;
  try {
    vm.runInNewContext(loaderSource, {
      Error,
      Object,
      module,
      process: {
        platform,
        arch,
        report: glibcVersion === undefined
          ? { getReport: () => ({ header: {} }) }
          : { getReport: () => ({ header: { glibcVersionRuntime: glibcVersion } }) },
      },
      require: (specifier) => {
        requests.push(specifier);
        return resolve(specifier);
      },
    }, { filename: "flowersec-node-native/index.js" });
  } catch (cause) {
    error = cause;
  }
  return { exports: module.exports, requests, error };
}

function assertUnavailable(error) {
  assert.ok(error instanceof Error);
  assert.equal(error.message, "Flowersec native transport is unavailable on this platform");
  assert.equal(error.code, "native_transport_unavailable");
}
