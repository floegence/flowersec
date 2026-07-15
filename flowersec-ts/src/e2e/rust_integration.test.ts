import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { createDemoSession } from "../_examples/flowersec/demo/v1.facade.gen.js";
import type { Client } from "../client.js";
import { connectDirectNode, connectTunnelNode } from "../node/index.js";
import { createProxyRuntime } from "../proxy/runtime.js";
import { AllowPlaintextForLoopback } from "../facade.js";
import { createByteReader } from "../streamio/index.js";

import { createExitPromise } from "./harnessProcess.js";
import { createLineReader, createTextBuffer, type LineReader, readJsonLine } from "./interopUtils.js";

type RustHarnessReady = Readonly<{
  v: 1;
  event: "ready";
  direct_info: unknown;
}>;

type GoExternalReady = Readonly<{
  grant_client: unknown;
  grant_server: unknown;
}>;

type HarnessProcess = Readonly<{
  proc: ChildProcess;
  reader: LineReader;
  stderr: () => string;
}>;

describe("rust<->ts integration", () => {
  test("ts client talks to Rust endpoint with RPC, notifications, streams, liveness, and proxy", { timeout: 120000 }, async () => {
    const harness = startRustHarness();
    let client: Client | undefined;
    try {
      const ready = await readHarnessJson<RustHarnessReady>(harness, "Rust direct harness", 60000);
      expect(ready).toMatchObject({ v: 1, event: "ready" });

      client = await connectDirectNode(ready.direct_info as any, {
        origin: "https://app.example.com",
        transportSecurityPolicy: AllowPlaintextForLoopback,
        liveness: false,
      });
      await exerciseRustEndpoint(client);
    } finally {
      client?.close();
      await stopHarness(harness);
    }
  });

  test("ts client talks through Go tunnel to the Rust server endpoint", { timeout: 120000 }, async () => {
    let goHarness: HarnessProcess | undefined;
    let rustHarness: HarnessProcess | undefined;
    let client: Client | undefined;
    try {
      const started = await startGoExternalReady();
      goHarness = started.harness;
      const ready = started.ready;
      rustHarness = startRustHarness(ready.grant_server);
      await expect(readHarnessJson(rustHarness, "Rust tunnel harness", 60000)).resolves.toMatchObject({
        v: 1,
        event: "attaching",
      });

      client = await connectTunnelNode(ready.grant_client as any, {
        origin: "https://app.redeven.com",
        transportSecurityPolicy: AllowPlaintextForLoopback,
        liveness: false,
      });
      await exerciseRustEndpoint(client);
    } finally {
      client?.close();
      await Promise.all([
        rustHarness === undefined ? Promise.resolve() : stopHarness(rustHarness),
        goHarness === undefined ? Promise.resolve() : stopHarness(goHarness),
      ]);
    }
  });
});

function startRustHarness(serverGrant?: unknown): HarnessProcess {
  const rustCwd = path.join(process.cwd(), "..", "flowersec-rust");
  execFileSync("cargo", ["build", "--quiet", "--example", "interop_harness"], {
    cwd: rustCwd,
    stdio: ["ignore", "inherit", "inherit"],
  });
  const executable = path.join(
    rustCwd,
    "target",
    "debug",
    "examples",
    process.platform === "win32" ? "interop_harness.exe" : "interop_harness",
  );
  const args = serverGrant === undefined
    ? []
    : ["--tunnel-grant-json", JSON.stringify(serverGrant)];
  return spawnHarness(executable, args);
}

function startGoExternalHarness(): HarnessProcess {
  const goCwd = path.join(process.cwd(), "..", "flowersec-go");
  const binDir = path.join(goCwd, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const executable = path.join(
    binDir,
    process.platform === "win32" ? "flowersec-e2e-harness-test.exe" : "flowersec-e2e-harness-test",
  );
  execFileSync("go", ["build", "-o", executable, "./internal/cmd/flowersec-e2e-harness"], {
    cwd: goCwd,
    stdio: ["ignore", "inherit", "inherit"],
  });
  return spawnHarness(executable, ["-external-server"]);
}

async function startGoExternalReady(): Promise<Readonly<{ harness: HarnessProcess; ready: GoExternalReady }>> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const harness = startGoExternalHarness();
    try {
      return {
        harness,
        ready: await readHarnessJson<GoExternalReady>(harness, "Go tunnel harness", 60000),
      };
    } catch (error) {
      lastError = error;
      await stopHarness(harness);
      if (!String(error).includes("signal=SIGKILL")) {
        throw error;
      }
    }
  }
  throw lastError;
}

function spawnHarness(executable: string, args: readonly string[]): HarnessProcess {
  const proc = spawn(executable, [...args], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (!proc.stdout || !proc.stderr) {
    throw new Error(`failed to capture harness stdio: ${executable}`);
  }
  return {
    proc,
    reader: createLineReader(proc.stdout),
    stderr: createTextBuffer(proc.stderr),
  };
}

async function readHarnessJson<T>(harness: HarnessProcess, label: string, timeoutMs: number): Promise<T> {
  try {
    return await Promise.race([
      readJsonLine<T>(harness.reader, timeoutMs),
      createExitPromise(harness.proc).then(({ code, signal }) => {
        throw new Error(`${label} exited before readiness (code=${String(code)}, signal=${String(signal)})`);
      }),
    ]);
  } catch (error) {
    throw new Error(`${label} failed: ${String(error)}\nstderr:\n${harness.stderr()}`);
  }
}

async function stopHarness(harness: HarnessProcess): Promise<void> {
  const exit = createExitPromise(harness.proc);
  if (harness.proc.exitCode == null && harness.proc.signalCode == null) {
    harness.proc.kill("SIGTERM");
  }
  await exit.catch(() => undefined);
}

async function exerciseRustEndpoint(client: Client) {
  const demo = createDemoSession(client);
  const runtime = createProxyRuntime({ client });
  try {
    const notified = waitNotify(demo.demo, 2000);
    await expect(demo.demo.ping({})).resolves.toEqual({ ok: true });
    await expect(notified).resolves.toEqual({ hello: "world" });

    const echo = await client.openStream("echo");
    const payload = new TextEncoder().encode("interop-stream-v1");
    await echo.write(payload);
    await expect(echo.read()).resolves.toEqual(payload);
    await echo.close();
    await expect(client.probeLiveness()).resolves.toBeGreaterThanOrEqual(0);

    await expect(proxyFetch(runtime, "/http")).resolves.toEqual({
      status: 200,
      body: "flowersec-rust-proxy-ok",
    });

    const websocket = await runtime.openWebSocketStream("/ws");
    const reader = createByteReader(websocket.stream);
    const websocketPayload = new TextEncoder().encode("ts-rust-websocket");
    await websocket.stream.write(proxyWebSocketFrame(1, websocketPayload));
    const header = await reader.readExactly(5);
    expect(header[0]).toBe(1);
    const length = readU32be(header, 1);
    await expect(reader.readExactly(length)).resolves.toEqual(websocketPayload);
    await websocket.stream.close();
  } finally {
    runtime.dispose();
    demo.close();
  }
}

async function proxyFetch(runtime: ReturnType<typeof createProxyRuntime>, requestPath: string) {
  const channel = new MessageChannel();
  const chunks: Uint8Array[] = [];
  let status = 0;
  const result = new Promise<{ status: number; body: string }>((resolve, reject) => {
    channel.port1.onmessage = (event) => {
      const message = event.data as any;
      switch (message?.type) {
        case "flowersec-proxy:response_meta":
          status = message.status;
          break;
        case "flowersec-proxy:response_chunk":
          chunks.push(new Uint8Array(message.data));
          break;
        case "flowersec-proxy:response_end": {
          const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
          const body = new Uint8Array(length);
          let offset = 0;
          for (const chunk of chunks) {
            body.set(chunk, offset);
            offset += chunk.length;
          }
          channel.port1.close();
          resolve({ status, body: new TextDecoder().decode(body) });
          break;
        }
        case "flowersec-proxy:response_error":
          channel.port1.close();
          reject(new Error(message.message));
          break;
      }
    };
  });
  runtime.dispatchFetch(
    {
      id: "ts-rust-http",
      method: "GET",
      path: requestPath,
      headers: [],
    },
    channel.port2,
  );
  return await result;
}

function proxyWebSocketFrame(operation: number, payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + payload.length);
  frame[0] = operation;
  new DataView(frame.buffer).setUint32(1, payload.length);
  frame.set(payload, 5);
  return frame;
}

function readU32be(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset);
}

function waitNotify(demo: { onHello: (handler: (payload: any) => void) => () => void }, timeoutMs: number) {
  return new Promise<any>((resolve, reject) => {
    let unsubscribe = () => {};
    const timeout = setTimeout(() => {
      unsubscribe();
      reject(new Error("timeout waiting for Rust notification"));
    }, timeoutMs);
    timeout.unref?.();
    unsubscribe = demo.onHello((payload) => {
      clearTimeout(timeout);
      unsubscribe();
      resolve(payload);
    });
  });
}
