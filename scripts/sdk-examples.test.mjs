import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { finishExampleProcesses } from "./sdk-example-processes.mjs";
import { cleanupParityArtifact, ParityProcessCleanupError, parityCleanupIncomplete, parityProcessDeadline } from "./server-parity-browser-installation.mjs";

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function read(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function readRustConsumer() {
  return ["examples/rust/src/main.rs", "examples/rust/src/engineering_material.rs"].map(read).join("\n");
}

function readGoConsumer() {
  return [
    "flowersec-go/example_client_test.go",
    ...["client", "bootstrap", "application", "fixture", "workflow"].map(
      name => `flowersec-go/examples/parityclient/${name}.go`,
    ),
  ].map(read).join("\n");
}

for (const cause of ["server deadline", "global interruption"]) {
  test(`example ${cause} waits for the original client cleanup before releasing artifacts`, async () => {
    const controller = new AbortController(), global = new AbortController();
    let release, canceled, finished = false, releasedArtifacts = false;
    const cleanup = new Promise(resolve => { release = resolve; });
    const cancellation = new Promise(resolve => { canceled = resolve; });
    const client = new Promise((resolve, reject) => controller.signal.addEventListener("abort", () => {
      canceled();
      void cleanup.then(() => reject(controller.signal.reason));
    }, { once: true }));
    const server = parityProcessDeadline(() => [], cause === "server deadline" ? 1 : undefined, "server deadline", reason => controller.abort(reason));
    global.signal.addEventListener("abort", () => server.cancel(global.signal.reason), { once: true });
    if (cause === "global interruption") global.abort(new Error(cause));
    await cancellation;
    const original = controller.signal.reason;
    const joining = finishExampleProcesses(client, controller, () => server.finish(original), original);
    void joining.then(() => { finished = true; }, () => { finished = true; });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(controller.signal.reason, original); assert.equal(finished, false);
    release();
    await assert.rejects(joining, error => {
      assert.ok(error instanceof AggregateError); assert.deepEqual(error.errors, [original, original]); return true;
    });
    assert.equal(finished, true);
    await cleanupParityArtifact(original, () => { releasedArtifacts = true; });
    assert.equal(releasedArtifacts, true);
  });
}

test("example dual join preserves physical cleanup failure and keeps process-owned artifacts", async () => {
  const controller = new AbortController(), primary = new Error("server stopped"), denied = new Error("client group still exists");
  const clientFailure = new ParityProcessCleanupError([primary, denied], "client cleanup incomplete");
  let releaseServer, serverJoined = false, releasedArtifacts = false;
  const serverTail = new Promise(resolve => { releaseServer = resolve; });
  const joining = finishExampleProcesses(Promise.reject(clientFailure), controller, async () => {
    await serverTail; serverJoined = true; throw primary;
  }, primary);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(serverJoined, false);
  releaseServer();
  let failure;
  await assert.rejects(joining, error => {
    failure = error; assert.ok(error instanceof AggregateError); assert.deepEqual(error.errors, [clientFailure, primary]);
    assert.equal(parityCleanupIncomplete(error), true); return true;
  });
  assert.equal(serverJoined, true);
  await cleanupParityArtifact(failure, () => { releasedArtifacts = true; });
  assert.equal(releasedArtifacts, false);
});

test("network-capable SDK examples require a durable spend receipt", () => {
  const swift = read("examples/swift/Sources/FlowersecSwiftClientExample/FlowersecSwiftClientExample.swift");
  assert.doesNotMatch(swift, /commitSpend:\s*\{\s*\}/, "Swift must not teach an empty durable-spend callback");
  assert.match(swift, /FSEC_SPEND_RECEIPT_V3_PATH/);
  assert.match(swift, /commitSpendReceipt/);

  const typescript = read("examples/ts/node-client.mjs");
  assert.match(typescript, /createArtifactLease/);
  assert.doesNotMatch(typescript, /createArtifactLeaseV2/);
  assert.match(typescript, /["']wx["']/);
  assert.match(typescript, /\.sync\(\)/);

  const go = readGoConsumer();
  assert.match(go, /os\.O_CREATE\s*\|\s*os\.O_EXCL/);
  assert.match(go, /receipt\.Sync\(\)/);
});

test("atomic spend receipt examples sync the parent directory", () => {
  const go = readGoConsumer();
  assert.match(go, /filepath\.Dir\(path\)/);
  assert.match(go, /directory\.Sync\(\)/);

  const typescript = read("examples/ts/node-client.mjs");
  assert.match(typescript, /dirname\(receiptPath\)/);
  assert.match(typescript, /directory\.sync\(\)/);

  const swift = read("examples/swift/Sources/FlowersecSwiftClientExample/FlowersecSwiftClientExample.swift");
  assert.match(swift, /deletingLastPathComponent\(\)/);
  assert.match(swift, /syncDirectory/);
  assert.match(swift, /fsync\(descriptor\)/);

  const rust = readRustConsumer();
  assert.match(rust, /sync_parent_directory/);
  assert.match(rust, /directory\.sync_all\(\)/);
  assert.match(rust, /create_new\(true\)/);
});

test("consumer examples stay on opaque public SDK entrypoints", () => {
  const typescript = read("examples/ts/node-client.mjs");
  assert.match(typescript, /@floegence\/flowersec-core\/node/);
  assert.doesNotMatch(typescript, /(?:candidate|credential|rawFSB2|sessionKey)/i);

  const go = readGoConsumer();
  assert.match(go, /client\.Connect\(ctx\)/);
  assert.match(go, /client\.SpendStatus\(\)\.CommitKnown/);
  assert.match(go, /client\.SourceAcquisitions\(\)\s*!==?\s*1/);
  assert.match(go, /fs\.Connect\(ctx, c\.source/);
  assert.match(go, /if s\.acquired/);
  assert.match(go, /s\.acquired = true/);
  assert.doesNotMatch(go, /flowersec\.NewConnector/);
  assert.doesNotMatch(go, /\/internal\//);
});

test("consumer examples expose structured connection and session recovery", () => {
  const examples = [
    {
      name: "Go",
      source: readGoConsumer(),
      classifiers: [/RetryDisposition\(\)/],
    },
    {
      name: "TypeScript",
      source: read("examples/ts/node-client.mjs"),
      classifiers: [/ConnectError/, /SessionError/],
    },
    {
      name: "Swift",
      source: read("examples/swift/Sources/FlowersecSwiftClientExample/FlowersecSwiftClientExample.swift"),
      classifiers: [/retryDisposition\(for:/],
    },
    {
      name: "Rust",
      source: readRustConsumer(),
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
    /ConnectorOptions::new\(\)\s*\.with_trust_roots_der\(roots\)/u,
  );
  assert.match(rustReadme, /CA candidates use platform or explicit DER trust roots/u);
  assert.match(rustReadme, /Pin candidates use only\s+the active artifact-bound leaf-certificate SHA-256 pins/u);
  assert.match(rustReadme, /never fall back to\s+CA verification/u);
  assert.doesNotMatch(rustReadme, /plaintext direct WebSocket/u);
});

test("four SDK examples use the maintained parity application contract", () => {
  const examples = [
    ["Go", readGoConsumer()],
    ["TypeScript", read("examples/ts/node-client.mjs")],
    ["Swift", read("examples/swift/Sources/FlowersecSwiftClientExample/FlowersecSwiftClientExample.swift")],
    ["Rust", readRustConsumer()],
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
  const swift = read("examples/swift/Sources/FlowersecSwiftClientExample/FlowersecSwiftClientExample.swift");
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

  assert.match(readme, /\| Negotiated unreliable messages \| Yes \| Yes \| No \| Yes \|/u);
  assert.match(apiContract, /Unreliable messages are an SDK-profile capability/u);
  assert.match(apiContract, /Swift explicitly reports the capability as unsupported/u);
});

test("built public SDK examples run the shared application contract", () => {
  const runner = read("scripts/test-sdk-examples-e2e.mjs");
  const makefile = read("Makefile");
  const registry = read("flowersec-go/internal/cmd/flowersec-test/registry.go");

  for (const language of ["go", "typescript", "rust", "swift"]) {
    assert.match(runner, new RegExp(`name: "${language}"`));
  }
  assert.match(runner, /npm", \[\s*"pack"/u);
  assert.match(runner, /prepare: async \(\) => await runProcess\("swift", \[\s*"build"/u);
  assert.match(runner, /"run",\s*"--skip-build"/u);
  assert.match(runner, /await example\.prepare\?\.\(\);\s*await runExample\(example\);/u);
  assert.match(runner, /"--scratch-path", path\.join\(scratch, "swift-build"\)/u);
  assert.match(runner, /"--only-use-versions-from-resolved-file"/u);
  assert.match(runner, /"rpc", "notification", "stream-fin", "liveness", "close"/u);
  assert.match(makefile, /example-check:[\s\S]*node scripts\/test-sdk-examples-e2e\.mjs/u);
  assert.match(registry, /"examples\/public-sdk-e2e"[\s\S]*"scripts\/test-sdk-examples-e2e\.mjs"/u);
});
