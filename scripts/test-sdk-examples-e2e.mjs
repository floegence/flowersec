#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { readToolchains } from "./toolchains.mjs";
import { assertCurrentPeer, assertCurrentMaterial } from "./server-parity-material.mjs";
import { prepareServerParityNativeAddon } from "./server-parity-native-addon.mjs";
import { cleanupParityArtifact, parityProcessDeadline } from "./server-parity-browser-installation.mjs";
import { finishExampleProcesses } from "./sdk-example-processes.mjs";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const toolchains = readToolchains(repositoryRoot);
// Source compilation has its own preparation budget. Runtime examples retain
// their shorter process and original connection deadlines.
const preparationTimeoutMS = 300_000;
const controller = new AbortController();
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.once(signal, () => controller.abort(new Error(`SDK examples interrupted by ${signal}`)));
}
const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-sdk-examples-"));
const serverBinary = path.join(scratch, "server-parity-peer");
let nativeAddon, failure;

try {
  await execFileAsync("go", [
    "build", "-o", serverBinary, "./internal/cmd/server-parity-peer",
  ], { cwd: path.join(repositoryRoot, "flowersec-go"), signal: controller.signal });
  nativeAddon = await prepareServerParityNativeAddon(repositoryRoot, true, { signal: controller.signal });
  const typescript = await preparePackedTypeScriptExample();
  const examples = [
    {
      name: "go",
      run: async (fixture) => await runProcess("go", [
        "test", "-count=1", "-run", "^TestExampleConnectE2E$", ".",
      ], path.join(repositoryRoot, "flowersec-go"), fixture.environment, fixture.signal),
    },
    {
      name: "typescript",
      run: async (fixture) => await runProcess(process.execPath, [
        typescript.entry, fixture.artifactPath, fixture.origin,
        fixture.receiptPath, fixture.trustPEMPath,
      ], typescript.root, { ...fixture.environment, ...nativeAddon.environment }, fixture.signal),
    },
    {
      name: "rust",
      prepare: async () => await runProcess("rustup", [
        "run", toolchains.rust.version, "cargo", "build", "--locked",
        "--manifest-path", "examples/rust/Cargo.toml",
      ], repositoryRoot, process.env, controller.signal, preparationTimeoutMS),
      run: async (fixture) => await runProcess("rustup", [
        "run", toolchains.rust.version, "cargo", "run", "--quiet", "--locked",
        "--manifest-path", "examples/rust/Cargo.toml", "--", "connect",
        fixture.artifactPath, fixture.trustDERPath, fixture.receiptPath,
      ], repositoryRoot, fixture.environment, fixture.signal),
    },
    ...(process.platform === "darwin" ? [{
      name: "swift",
      prepare: async () => await runProcess("swift", [
        "build",
        "--package-path", "examples/swift",
        "--scratch-path", path.join(scratch, "swift-build"),
        "--cache-path", path.join(repositoryRoot, ".flowersec", "swiftpm-cache"),
        "--skip-update",
        "--only-use-versions-from-resolved-file",
      ], repositoryRoot, process.env, controller.signal, preparationTimeoutMS),
      run: async (fixture) => await runProcess("swift", [
        "run",
        "--skip-build",
        "--package-path", "examples/swift",
        "--scratch-path", path.join(scratch, "swift-build"),
        "--cache-path", path.join(repositoryRoot, ".flowersec", "swiftpm-cache"),
        "--skip-update",
        "--only-use-versions-from-resolved-file",
      ], repositoryRoot, fixture.environment, fixture.signal),
    }] : []),
  ];

  for (const example of examples) {
    await example.prepare?.();
    await runExample(example);
    process.stdout.write(`public SDK example E2E OK: ${example.name}\n`);
  }
  const required = process.platform === "darwin" ? 4 : 3;
  assert.equal(examples.length, required);
  process.stdout.write(`public SDK examples E2E OK: ${examples.length} languages\n`);
} catch (error) {
  failure = error; throw error;
} finally {
  if (nativeAddon !== undefined) await cleanupParityArtifact(failure, () => nativeAddon.cleanup());
  await cleanupParityArtifact(failure, () => fs.rm(scratch, { recursive: true, force: true }));
}

async function preparePackedTypeScriptExample() {
  const packRoot = path.join(scratch, "typescript-pack");
  const consumerRoot = path.join(scratch, "typescript-consumer");
  await fs.mkdir(packRoot, { recursive: true });
  await fs.mkdir(consumerRoot, { recursive: true });
  const { stdout } = await execFileAsync("npm", [
    "pack", "--silent", "--pack-destination", packRoot,
  ], { cwd: path.join(repositoryRoot, "flowersec-ts"), signal: controller.signal });
  const tarball = path.join(packRoot, stdout.trim().split(/\r?\n/u).at(-1));
  await fs.writeFile(
    path.join(consumerRoot, "package.json"),
    '{"name":"flowersec-example-consumer","private":true,"type":"module"}\n',
  );
  await execFileAsync("npm", [
    "install", "--ignore-scripts", "--no-package-lock", "--offline", tarball,
  ], { cwd: consumerRoot, signal: controller.signal });
  // The packed engineering adapter validates its hash-pinned test input.
  // Provision that reference data independently of the installed public SDK.
  const unicodeRoot = path.join(consumerRoot, "node_modules", "@floegence", "testdata", "unicode15_1");
  await fs.mkdir(unicodeRoot, { recursive: true });
  await fs.copyFile(path.join(repositoryRoot, "testdata", "unicode15_1", "normalization_generated.json"),
    path.join(unicodeRoot, "normalization_generated.json"));
  // Keep the repository example's relative engineering-fixture import, with
  // both that fixture and the public entrypoint coming from the packed SDK.
  const entry = path.join(consumerRoot, "examples", "ts", "node-client.mjs");
  await fs.mkdir(path.dirname(entry), { recursive: true });
  await fs.symlink(path.join(consumerRoot, "node_modules", "@floegence", "flowersec-core"),
    path.join(consumerRoot, "flowersec-ts"), process.platform === "win32" ? "junction" : "dir");
  await fs.copyFile(path.join(repositoryRoot, "examples/ts/node-client.mjs"), entry);
  return { root: consumerRoot, entry };
}

async function runExample(example) {
  const exampleRoot = path.join(scratch, example.name);
  await fs.mkdir(exampleRoot, { recursive: true });
  const origin = "https://sdk-example.example";
  const server = spawn(serverBinary, ["server", "--carrier", "websocket", "--workload", "sdk-example"], {
    cwd: repositoryRoot,
    detached: true,
    env: {
      ...process.env,
      FLOWERSEC_SERVER_PARITY_PEER: "1",
      FLOWERSEC_PARITY_TEST_ONLY: "1",
      FLOWERSEC_PARITY_CLIENT_PROFILE: `example-${example.name}`,
      FLOWERSEC_PARITY_ORIGIN: origin,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const lines = createInterface({ input: server.stdout });
  const messages = lines[Symbol.asyncIterator]();
  let serverErrors = "";
  server.stderr.setEncoding("utf8");
  server.stderr.on("data", (chunk) => {
    serverErrors = `${serverErrors}${chunk}`.slice(-65_536);
  });
  const completion = childExit(server);
  const clientController = new AbortController();
  const deadline = parityProcessDeadline(() => [{ child: server, completion }], 150_000, `${example.name} example server deadline`,
    reason => clientController.abort(reason));
  void completion.then(code => {
    if (code !== 0) deadline.cancel(new Error(`${example.name} example server exited ${code}\n${serverErrors}`));
  }, error => deadline.cancel(error));
  const abort = () => deadline.cancel(controller.signal.reason);
  controller.signal.addEventListener("abort", abort, { once: true });
  if (controller.signal.aborted) abort();
  let failure, clientCompletion;
  try {
    const ready = JSON.parse(await deadline.wait(nextLine(messages, `${example.name} server readiness`)));
    assert.equal(ready.type, "ready");
    assert.equal(ready.carrier, "websocket");
    assert.equal(ready.path, "direct");
    assert.equal(ready.origin, origin);
    assertCurrentPeer(ready, example.name);
    assertCurrentMaterial(ready.artifact_json, example.name, ready);

    const artifactPath = path.join(exampleRoot, "artifact.json");
    const trustPEMPath = path.join(exampleRoot, "trust.pem");
    const trustDERPath = path.join(exampleRoot, "trust.der");
    const receiptPath = path.join(exampleRoot, "artifact.spent");
    await fs.writeFile(artifactPath, ready.artifact_json);
    await fs.writeFile(trustPEMPath, ready.trust_pem);
    await execFileAsync("openssl", [
      "x509", "-in", trustPEMPath, "-outform", "DER", "-out", trustDERPath,
    ], { signal: clientController.signal });
    const environment = {
      ...process.env,
      FSEC_MATERIAL_PATH: artifactPath,
      FSEC_ORIGIN: origin,
      FSEC_SPEND_RECEIPT_PATH: receiptPath,
      FSEC_TRUST_ROOT_PEM_PATH: trustPEMPath,
      FSEC_EXAMPLE_STREAM_CELL: "direct",
    };
    deadline.check();
    clientCompletion = example.run({
      artifactPath, environment, origin, receiptPath, trustDERPath, trustPEMPath,
      signal: clientController.signal,
    });
    await deadline.wait(clientCompletion);
    await fs.access(receiptPath);

    const result = JSON.parse(await deadline.wait(nextLine(messages, `${example.name} server result`)));
    assert.equal(result.type, "server-result");
    for (const requiredCase of [
      "admission", "rpc", "notification", "stream-fin", "liveness", "close", "cleanup",
    ]) {
      assert.equal(
        result.cases.includes(requiredCase),
        true,
        `${example.name} did not exercise ${requiredCase}`,
      );
    }
    assert.equal(await deadline.wait(completion), 0, serverErrors);
  } catch (error) {
    failure = new Error(
      `${example.name} example E2E: ${error instanceof Error ? error.message : String(error)}` +
      (serverErrors === "" ? "" : `\n${serverErrors}`),
      { cause: error },
    );
  } finally {
    try {
      await finishExampleProcesses(clientCompletion, clientController,
        () => deadline.finish(failure, () => lines.close()), failure);
    }
    finally { controller.signal.removeEventListener("abort", abort); }
  }
}

async function runProcess(command, arguments_, cwd, environment, signal = controller.signal, timeoutMS = 120_000) {
  signal.throwIfAborted();
  const child = spawn(command, arguments_, {
    cwd,
    env: environment,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout = `${stdout}${chunk}`.slice(-65_536); });
  child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-65_536); });
  const completion = childExit(child);
  const deadline = parityProcessDeadline(() => [{ child, completion }], timeoutMS, `${command} example process deadline`);
  const abort = () => deadline.cancel(signal.reason);
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) abort();
  let failure;
  try {
    const code = await deadline.wait(completion);
    if (code !== 0) {
      throw new Error(`${command} exited ${code}\n${stdout}\n${stderr}`);
    }
  } catch (error) {
    failure = error;
  } finally {
    try { await deadline.finish(failure); }
    finally { signal.removeEventListener("abort", abort); }
  }
}

async function nextLine(iterator, label) {
  const next = await iterator.next();
  if (next.done || next.value.trim() === "") {
    throw new Error(`${label} was not published`);
  }
  return next.value;
}

async function childExit(child) {
  if ((child.exitCode !== null || child.signalCode !== null) && child.stdout?.closed && child.stderr?.closed) return child.exitCode ?? 1;
  return await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code ?? 1));
  });
}
