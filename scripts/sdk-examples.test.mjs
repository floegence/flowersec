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
  assert.match(typescript, /createArtifactLease/);
  assert.doesNotMatch(typescript, /createArtifactLeaseV2/);
  assert.match(typescript, /["']wx["']/);
  assert.match(typescript, /\.sync\(\)/);

  const go = read("flowersec-go/example_client_test.go");
  assert.match(go, /os\.O_CREATE\s*\|\s*os\.O_EXCL/);
  assert.match(go, /receipt\.Sync\(\)/);
});

test("atomic spend receipt examples sync the parent directory", () => {
  const go = read("flowersec-go/example_client_test.go");
  assert.match(go, /filepath\.Dir\(path\)/);
  assert.match(go, /directory\.Sync\(\)/);

  const typescript = read("examples/ts/node-client.mjs");
  assert.match(typescript, /dirname\(receiptPath\)/);
  assert.match(typescript, /directory\.sync\(\)/);

  const swift = read("examples/swift/Sources/FlowersecSwiftClientExample/main.swift");
  assert.match(swift, /deletingLastPathComponent\(\)/);
  assert.match(swift, /syncDirectory/);
  assert.match(swift, /fsync\(descriptor\)/);

  const rust = read("examples/rust/src/main.rs");
  assert.match(rust, /sync_parent_directory/);
  assert.match(rust, /directory\.sync_all\(\)/);
});

test("consumer examples stay on opaque public SDK entrypoints", () => {
  const typescript = read("examples/ts/node-client.mjs");
  assert.match(typescript, /@floegence\/flowersec-core\/node/);
  assert.doesNotMatch(typescript, /(?:candidate|credential|rawFSB2|sessionKey)/i);

  const go = read("flowersec-go/example_client_test.go");
  assert.match(go, /flowersec\.ParseArtifact/);
  assert.match(go, /flowersec\.NewArtifactLease/);
  assert.match(go, /flowersec\.Connect/);
  assert.doesNotMatch(go, /flowersec\.NewConnector/);
  assert.doesNotMatch(go, /\/internal\//);
});

test("consumer examples classify public connection and session failures", () => {
  const examples = [
    {
      name: "Go",
      source: read("flowersec-go/example_client_test.go"),
      classifiers: [/flowersec\.ClassifyConnectError/, /flowersec\.ClassifySessionError/],
    },
    {
      name: "TypeScript",
      source: read("examples/ts/node-client.mjs"),
      classifiers: [/classifyConnectError/, /classifySessionError/],
    },
    {
      name: "Swift",
      source: read("examples/swift/Sources/FlowersecSwiftClientExample/main.swift"),
      classifiers: [/classifyConnectError/, /classifySessionError/],
    },
    {
      name: "Rust",
      source: read("examples/rust/src/main.rs"),
      classifiers: [/classify_connect_error/, /classify_session_error/],
    },
  ];

  for (const example of examples) {
    for (const classifier of example.classifiers) {
      assert.match(example.source, classifier, `${example.name} example must show public recovery classification`);
    }
  }

  const rustReadme = read("flowersec-rust/README.md");
  assert.match(rustReadme, /ConnectorOptions::new\(vec!\[root_der\]\)/);
  assert.match(rustReadme, /requires explicit DER trust roots/u);
});

test("durable spend guidance covers three production persistence patterns", () => {
  const apiContract = read("docs/API_CONTRACT.md");
  assert.match(apiContract, /Database uniqueness/u);
  assert.match(apiContract, /Atomic file/u);
  assert.match(apiContract, /Transactional state/u);
  assert.match(apiContract, /uncertain.*spent/isu);
});

test("portable contract documents unreliable messages as an explicit SDK profile capability", () => {
  const readme = read("README.md");
  const apiContract = read("docs/API_CONTRACT.md");

  assert.match(readme, /\| Negotiated unreliable message channel \| Yes \| Yes \| No \| Yes \|/u);
  assert.match(apiContract, /Unreliable messages are an SDK-profile capability/u);
  assert.match(apiContract, /Swift currently exposes no public unreliable-message channel/u);
});
