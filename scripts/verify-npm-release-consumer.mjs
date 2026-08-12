#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const version = process.argv[2];
assert.match(version ?? "", /^\d+\.\d+\.\d+$/);
const testID = "release/npm-consumer/go-node-raw-quic/direct-session";
const root = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-npm-consumer-"));
try {
  await fs.writeFile(path.join(root, "package.json"), '{"private":true,"type":"module"}\n');
  await execFileAsync("npm", ["install", "--ignore-scripts", "--audit=false", `@floegence/flowersec-core@${version}`, `@floegence/flowersec-node-native@${version}`], { cwd: root });
  const wrapper = await import(path.join(root, "node_modules/@floegence/flowersec-node-native/index.js"));
  const addon = wrapper.default ?? wrapper;
  assert.equal(addon.contractVersion(), 1);
  const addonPath = path.join(root, "node_modules/@floegence/flowersec-node-native/index.js");
  await execFileAsync(process.execPath, [path.resolve("scripts/native-addon-smoke.mjs")], {
    env: { ...process.env, FLOWERSEC_NATIVE_ADDON_PATH: addonPath },
  });

  const goRoot = path.join(root, "go-consumer");
  await fs.mkdir(goRoot);
  await fs.copyFile(
    path.resolve("scripts/fixtures/npm-release-go-node-raw-quic/main.go"),
    path.join(goRoot, "main.go"),
  );
  await fs.writeFile(path.join(goRoot, "go.mod"), [
    "module flowersec_release_consumer",
    "",
    "go 1.26.5",
    "",
    `require github.com/floegence/flowersec/flowersec-go/v2 v${version}`,
    "",
  ].join("\n"));
  const goEnvironment = { ...process.env, GOWORK: "off", GOTOOLCHAIN: "local" };
  await execFileAsync("go", ["mod", "tidy"], { cwd: goRoot, env: goEnvironment });

  const clientPath = path.join(root, "go-node-raw-quic-consumer.mjs");
  await fs.writeFile(clientPath, `
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import {
  connect,
  createArtifactLease,
  parseArtifact,
} from "@floegence/flowersec-core/node";

const ready = JSON.parse(await fs.readFile(process.argv[2], "utf8"));
assert.equal(ready.test_id, ${JSON.stringify(testID)});
const session = await connect(
  createArtifactLease(parseArtifact(ready.artifact_json), async () => undefined),
  { origin: ready.origin, tls: { ca: ready.trust_pem } },
);
const rpc = await session.rpc.call(7001, { value: "ping" }, (payload) => payload);
assert.deepEqual(rpc, { ok: true, payload: { server: "go-release-consumer" } });
const stream = await session.openStream("release.consumer.echo");
await stream.write(new TextEncoder().encode("hello-node"));
await stream.closeWrite();
const chunks = [];
for (;;) {
  const chunk = await stream.read();
  if (chunk === null) break;
  chunks.push(chunk);
}
assert.equal(new TextDecoder().decode(Buffer.concat(chunks)), "go:hello-node");
await session.close();
process.stdout.write(JSON.stringify({
  type: "client-result",
  test_id: ${JSON.stringify(testID)},
  cases: ["handshake", "rpc", "stream", "stream-fin", "close"],
}) + "\\n");
`);
  await runGoNodeRawQUICConsumer(goRoot, goEnvironment, clientPath, root);

  const browserRoot = path.join(root, "browser-only");
  await fs.mkdir(browserRoot);
  await fs.writeFile(path.join(browserRoot, "package.json"), '{"private":true,"type":"module"}\n');
  await execFileAsync("npm", ["install", "--ignore-scripts", "--omit=optional", "--audit=false", `@floegence/flowersec-core@${version}`], { cwd: browserRoot });
  await execFileAsync(process.execPath, ["--input-type=module", "--eval", "await import('@floegence/flowersec-core/browser')"], { cwd: browserRoot });
} finally {
  await fs.rm(root, { recursive: true, force: true });
}

async function runGoNodeRawQUICConsumer(goRoot, goEnvironment, clientPath, consumerRoot) {
  const peer = spawn("go", ["run", "."], {
    cwd: goRoot,
    env: goEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const lines = createInterface({ input: peer.stdout });
  let stderr = "";
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk) => { stderr = `${stderr}${chunk}`.slice(-65_536); });
  const timeout = setTimeout(() => peer.kill("SIGKILL"), 45_000);
  try {
    const ready = JSON.parse(await nextLine(lines, "Go peer ready"));
    assert.equal(ready.type, "ready");
    assert.equal(ready.test_id, testID);
    const readyPath = path.join(consumerRoot, "go-peer-ready.json");
    await fs.writeFile(readyPath, JSON.stringify(ready));
    const client = await execFileAsync(process.execPath, [clientPath, readyPath], {
      cwd: consumerRoot,
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });
    const clientResult = JSON.parse(client.stdout.trim());
    assertResult(clientResult, "client-result", ["handshake", "rpc", "stream", "stream-fin", "close"]);
    const serverResult = JSON.parse(await nextLine(lines, "Go peer result"));
    assertResult(serverResult, "result", ["handshake", "rpc", "stream", "stream-fin", "close", "cleanup"]);
    const exitCode = await childExit(peer);
    assert.equal(exitCode, 0, stderr);
    process.stdout.write(`${testID} GREEN\n`);
  } catch (error) {
    peer.kill("SIGKILL");
    throw new Error(`${testID}: ${error instanceof Error ? error.message : String(error)}${stderr === "" ? "" : `\n${stderr}`}`);
  } finally {
    clearTimeout(timeout);
    lines.close();
  }
}

function assertResult(result, type, cases) {
  assert.equal(result.type, type);
  assert.equal(result.test_id, testID);
  assert.deepEqual(result.cases, cases);
}

async function nextLine(lines, label) {
  const next = await lines[Symbol.asyncIterator]().next();
  if (next.done || next.value.trim() === "") throw new Error(`${label} was not published`);
  return next.value;
}

async function childExit(child) {
  if (child.exitCode !== null) return child.exitCode;
  return await new Promise((resolve) => child.once("exit", resolve));
}
