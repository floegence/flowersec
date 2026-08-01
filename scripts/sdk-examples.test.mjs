import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

test("network-capable SDK examples require a durable spend receipt", () => {
  const swift = read("examples/swift/Sources/FlowersecSwiftClientExample/main.swift");
  assert.doesNotMatch(swift, /commitSpend:\s*\{\s*\}/, "Swift must not teach an empty durable-spend callback");
  assert.match(swift, /FSEC_SPEND_RECEIPT_V2_PATH/);
  assert.match(swift, /commitSpendReceipt/);

  const typescript = read("examples/ts/node-client.mjs");
  assert.match(typescript, /createArtifactLeaseV2/);
  assert.match(typescript, /["']wx["']/);
  assert.match(typescript, /\.sync\(\)/);

  const go = read("flowersec-go/example_client_test.go");
  assert.match(go, /os\.O_CREATE\s*\|\s*os\.O_EXCL/);
  assert.match(go, /receipt\.Sync\(\)/);
});

test("consumer examples stay on opaque public SDK entrypoints", () => {
  const typescript = read("examples/ts/node-client.mjs");
  assert.match(typescript, /@floegence\/flowersec-core\/node/);
  assert.doesNotMatch(typescript, /(?:candidate|credential|rawFSB2|sessionKey)/i);

  const go = read("flowersec-go/example_client_test.go");
  assert.match(go, /flowersec\.ParseArtifact/);
  assert.match(go, /flowersec\.NewArtifactLease/);
  assert.match(go, /flowersec\.NewConnector/);
  assert.doesNotMatch(go, /\/internal\//);
});
