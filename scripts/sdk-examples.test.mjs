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

test("consumer examples expose structured connection and session recovery", () => {
  const examples = [
    {
      name: "Go",
      source: read("flowersec-go/example_client_test.go"),
      classifiers: [/RetryDisposition\(\)/],
    },
    {
      name: "TypeScript",
      source: read("examples/ts/node-client.mjs"),
      classifiers: [/ConnectError/, /SessionError/],
    },
    {
      name: "Swift",
      source: read("examples/swift/Sources/FlowersecSwiftClientExample/main.swift"),
      classifiers: [/retryDispositionV2/],
    },
    {
      name: "Rust",
      source: read("examples/rust/src/main.rs"),
      classifiers: [/connection_error=/, /session_error=/],
    },
  ];

  for (const example of examples) {
    for (const classifier of example.classifiers) {
      assert.match(example.source, classifier, `${example.name} example must show structured recovery`);
    }
  }

  const rustReadme = read("flowersec-rust/README.md");
  assert.match(
    rustReadme,
    /ConnectorOptions::new\(\)\s*\.with_trust_roots_der\(vec!\[root_der\]\)/u,
  );
  assert.match(rustReadme, /TLS connection candidates require explicit, non-empty DER trust roots/u);
  assert.match(rustReadme, /Exact-loopback\nplaintext direct WebSocket candidates do not require trust roots/u);
});

test("four SDK examples use the maintained parity application contract", () => {
  const examples = [
    ["Go", read("flowersec-go/example_client_test.go")],
    ["TypeScript", read("examples/ts/node-client.mjs")],
    ["Swift", read("examples/swift/Sources/FlowersecSwiftClientExample/main.swift")],
    ["Rust", read("examples/rust/src/main.rs")],
  ];

  for (const [language, source] of examples) {
    assert.match(source, /7_?001/u, `${language} must use typed RPC type 7001`);
    assert.match(source, /7_?002/u, `${language} must use notification type 7002`);
    assert.match(source, /parity\.echo/u, `${language} must use the parity echo stream`);
    assert.match(source, /hello/u, `${language} must write the shared stream request`);
    assert.match(source, /world/u, `${language} must validate the shared stream response`);
  }
});

test("Swift example preserves the primary failure while propagating final close errors", () => {
  const swift = read("examples/swift/Sources/FlowersecSwiftClientExample/main.swift");
  assert.match(swift, /try\? await session\.close\(\)\s+throw error/u);
  assert.match(swift, /try await session\.close\(\)\s+\}/u);
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

  assert.match(readme, /\| Unreliable messages when available \| Yes \| Yes \| No \| Yes \|/u);
  assert.match(apiContract, /Unreliable messages are an SDK-profile capability/u);
  assert.match(apiContract, /Swift currently exposes no public unreliable-message channel/u);
});
