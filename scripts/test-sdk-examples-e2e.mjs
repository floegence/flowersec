#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(import.meta.dirname, "..");
const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-sdk-examples-"));
const serverBinary = path.join(scratch, "server-parity-peer");

try {
  await execFileAsync("go", [
    "build", "-o", serverBinary, "./internal/cmd/server-parity-peer",
  ], { cwd: path.join(repositoryRoot, "flowersec-go") });
  const typescript = await preparePackedTypeScriptExample();
  const examples = [
    {
      name: "go",
      run: async (fixture) => await runProcess("go", [
        "test", "-count=1", "-run", "^TestExampleConnectE2E$", ".",
      ], path.join(repositoryRoot, "flowersec-go"), fixture.environment),
    },
    {
      name: "typescript",
      run: async (fixture) => await runProcess(process.execPath, [
        typescript.entry, fixture.artifactPath, fixture.origin,
        fixture.receiptPath, fixture.trustPEMPath,
      ], typescript.root, fixture.environment),
    },
    {
      name: "rust",
      run: async (fixture) => await runProcess("rustup", [
        "run", "1.88.0", "cargo", "run", "--quiet", "--locked",
        "--manifest-path", "examples/rust/Cargo.toml", "--", "connect-v3",
        fixture.artifactPath, fixture.trustDERPath, fixture.receiptPath,
      ], repositoryRoot, fixture.environment),
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
      ], repositoryRoot, process.env),
      run: async (fixture) => await runProcess("swift", [
        "run",
        "--skip-build",
        "--package-path", "examples/swift",
        "--scratch-path", path.join(scratch, "swift-build"),
        "--cache-path", path.join(repositoryRoot, ".flowersec", "swiftpm-cache"),
        "--skip-update",
        "--only-use-versions-from-resolved-file",
      ], repositoryRoot, fixture.environment),
    }] : []),
  ];

  for (const example of examples) {
    await example.prepare?.();
    await runExample(example);
  }
  const required = process.platform === "darwin" ? 4 : 3;
  assert.equal(examples.length, required);
  process.stdout.write(`public SDK examples E2E OK: ${examples.length} languages\n`);
} finally {
  await fs.rm(scratch, { recursive: true, force: true });
}

async function preparePackedTypeScriptExample() {
  const packRoot = path.join(scratch, "typescript-pack");
  const consumerRoot = path.join(scratch, "typescript-consumer");
  await fs.mkdir(packRoot, { recursive: true });
  await fs.mkdir(consumerRoot, { recursive: true });
  const { stdout } = await execFileAsync("npm", [
    "pack", "--silent", "--pack-destination", packRoot,
  ], { cwd: path.join(repositoryRoot, "flowersec-ts") });
  const tarball = path.join(packRoot, stdout.trim().split(/\r?\n/u).at(-1));
  await fs.writeFile(
    path.join(consumerRoot, "package.json"),
    '{"name":"flowersec-example-consumer","private":true,"type":"module"}\n',
  );
  await execFileAsync("npm", [
    "install", "--ignore-scripts", "--no-package-lock", "--offline", tarball,
  ], { cwd: consumerRoot });
  const entry = path.join(consumerRoot, "node-client.mjs");
  await fs.copyFile(path.join(repositoryRoot, "examples/ts/node-client.mjs"), entry);
  return { root: consumerRoot, entry };
}

async function runExample(example) {
  const exampleRoot = path.join(scratch, example.name);
  await fs.mkdir(exampleRoot, { recursive: true });
  const origin = "https://sdk-example.example";
  const server = spawn(serverBinary, ["server", "--carrier", "websocket"], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      FLOWERSEC_SERVER_PARITY_PEER: "1",
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
  const timeout = setTimeout(() => server.kill("SIGKILL"), 150_000);
  try {
    const ready = JSON.parse(await nextLine(messages, `${example.name} server readiness`));
    assert.equal(ready.type, "ready");
    assert.equal(ready.carrier, "websocket");
    assert.equal(ready.path, "direct");
    assert.equal(ready.origin, origin);

    const artifactPath = path.join(exampleRoot, "artifact.json");
    const trustPEMPath = path.join(exampleRoot, "trust.pem");
    const trustDERPath = path.join(exampleRoot, "trust.der");
    const receiptPath = path.join(exampleRoot, "artifact.spent");
    await fs.writeFile(artifactPath, ready.artifact_json);
    await fs.writeFile(trustPEMPath, ready.trust_pem);
    await execFileAsync("openssl", [
      "x509", "-in", trustPEMPath, "-outform", "DER", "-out", trustDERPath,
    ]);
    const environment = {
      ...process.env,
      FSEC_ARTIFACT_V3_PATH: artifactPath,
      FSEC_ORIGIN: origin,
      FSEC_SPEND_RECEIPT_V3_PATH: receiptPath,
      FSEC_TRUST_ROOT_PEM_PATH: trustPEMPath,
      FSEC_EXAMPLE_STREAM_CELL: "direct",
    };
    await example.run({
      artifactPath, environment, origin, receiptPath, trustDERPath, trustPEMPath,
    });
    await fs.access(receiptPath);

    const result = JSON.parse(await nextLine(messages, `${example.name} server result`));
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
    assert.equal(await childExit(server), 0, serverErrors);
  } catch (error) {
    server.kill("SIGKILL");
    throw new Error(
      `${example.name} example E2E: ${error instanceof Error ? error.message : String(error)}` +
      (serverErrors === "" ? "" : `\n${serverErrors}`),
    );
  } finally {
    clearTimeout(timeout);
    lines.close();
  }
}

async function runProcess(command, arguments_, cwd, environment) {
  const child = spawn(command, arguments_, {
    cwd,
    env: environment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout = `${stdout}${chunk}`.slice(-65_536); });
  child.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-65_536); });
  const timeout = setTimeout(() => child.kill("SIGKILL"), 120_000);
  try {
    const code = await childExit(child);
    if (code !== 0) {
      throw new Error(`${command} exited ${code}\n${stdout}\n${stderr}`);
    }
  } finally {
    clearTimeout(timeout);
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
  if (child.exitCode !== null) return child.exitCode;
  return await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code ?? 1));
  });
}
