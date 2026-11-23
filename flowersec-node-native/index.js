"use strict";

const platformPackages = Object.freeze({
  "darwin-arm64": "@floegence/flowersec-node-native-darwin-arm64",
  "darwin-x64": "@floegence/flowersec-node-native-darwin-x64",
  "linux-arm64": "@floegence/flowersec-node-native-linux-arm64-gnu",
  "linux-x64": "@floegence/flowersec-node-native-linux-x64-gnu",
});

const platformKey = `${process.platform}-${process.arch}`;
const platformPackage = platformPackages[platformKey];
if (platformPackage === undefined || (process.platform === "linux" && !isGlibc())) {
  throw unavailable();
}

try {
  module.exports = require(platformPackage);
} catch {
  throw unavailable();
}

function isGlibc() {
  const report = process.report?.getReport?.();
  return typeof report?.header?.glibcVersionRuntime === "string";
}

function unavailable() {
  const error = new Error("Flowersec native transport is unavailable on this platform");
  error.code = "native_transport_unavailable";
  return error;
}
