import { expect, test } from "@playwright/test";
import { execFile } from "node:child_process";
import { spawn, type ChildProcess } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Readable } from "node:stream";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const goRoot = path.join(packageRoot, "..", "flowersec-go");
const execFileAsync = promisify(execFile);
const readyTimeoutMs = 20_000;
const processExitTimeoutMs = 3_000;
const maximumReadyLineBytes = 64 * 1024;
const maximumStderrBytes = 16 * 1024;

type TunnelGrant = Readonly<{
  default_suite: number;
  allowed_suites: readonly number[];
}> & Readonly<Record<string, unknown>>;

type GoHarnessReady = Readonly<{
  grant_client: TunnelGrant;
}>;

type GoHarness = Readonly<{
  ready: GoHarnessReady;
  stop: () => Promise<void>;
}>;

test("browser SDK completes a P-256 session through the Go tunnel", async ({ page }) => {
  test.setTimeout(90_000);

  const site = await startBrowserModuleSite();
  let harness: GoHarness | undefined;
  let testFailure: unknown;
  try {
    harness = await startGoHarness(site.origin);
    expect(harness.ready.grant_client.allowed_suites).toEqual([2]);
    expect(harness.ready.grant_client.default_suite).toBe(2);

    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (ready) => {
      const [{ connectBrowser, AllowPlaintextForLoopback }, { createDemoSession }] = await Promise.all([
        import("/dist/browser/index.js"),
        import("/dist/_examples/flowersec/demo/v1.facade.gen.js"),
      ]);
      const artifact = {
        v: 1,
        transport: "tunnel",
        tunnel_grant: ready.grant_client,
      };
      const client = await connectBrowser(artifact, {
        transportSecurityPolicy: AllowPlaintextForLoopback,
        liveness: false,
      });
      const session = createDemoSession(client);
      let rpcResponse: unknown;
      let notification: unknown;
      let echoedBytes = 0;
      let echoMatches = false;
      let streamClosed = false;
      let clientClosed = false;
      try {
        const hello = new Promise<unknown>((resolve, reject) => {
          let unsubscribe = () => {};
          const timer = window.setTimeout(() => {
            unsubscribe();
            reject(new Error("timed out waiting for the Go notification"));
          }, 5_000);
          unsubscribe = session.demo.onHello((payload) => {
            window.clearTimeout(timer);
            unsubscribe();
            resolve(payload);
          });
        });

        rpcResponse = await session.demo.ping({});
        notification = await hello;
        const stream = await client.openStream("echo");
        const payload = new Uint8Array(96 * 1024);
        for (let index = 0; index < payload.byteLength; index += 1) {
          payload[index] = (index * 17) % 251;
        }
        let echoed: Uint8Array;
        try {
          const split = 37 * 1024;
          await stream.write(payload.subarray(0, split));
          await stream.write(payload.subarray(split));
          echoed = await readExactly(stream, payload.byteLength);
        } finally {
          await stream.close();
          streamClosed = true;
        }

        echoedBytes = echoed.byteLength;
        echoMatches = echoed.every((value, index) => value === payload[index]);
      } finally {
        client.close();
        clientClosed = true;
      }

      let postCloseError: unknown;
      try {
        await client.openStream("echo");
      } catch (error) {
        postCloseError = error;
      }
      const typedPostCloseError = postCloseError as { path?: unknown; stage?: unknown; code?: unknown } | undefined;
      return {
        path: client.path,
        rpcResponse,
        notification,
        echoedBytes,
        echoMatches,
        streamClosed,
        clientClosed,
        postCloseError: {
          path: typedPostCloseError?.path,
          stage: typedPostCloseError?.stage,
          code: typedPostCloseError?.code,
        },
      };

      async function readExactly(
        stream: Readonly<{ read: () => Promise<Uint8Array | null> }>,
        length: number,
      ): Promise<Uint8Array> {
        const output = new Uint8Array(length);
        let offset = 0;
        while (offset < length) {
          const chunk = await stream.read();
          if (chunk == null) throw new Error("echo stream ended before the payload was complete");
          if (offset + chunk.byteLength > length) throw new Error("echo stream returned more data than expected");
          output.set(chunk, offset);
          offset += chunk.byteLength;
        }
        return output;
      }
    }, harness.ready);

    expect(result).toEqual({
      path: "tunnel",
      rpcResponse: { ok: true },
      notification: { hello: "world" },
      echoedBytes: 96 * 1024,
      echoMatches: true,
      streamClosed: true,
      clientClosed: true,
      postCloseError: {
        path: "tunnel",
        stage: "yamux",
        code: "open_stream_failed",
      },
    });
  } catch (error) {
    testFailure = error;
  }

  const cleanupErrors = await settleCleanups([
    ...(harness === undefined ? [] : [harness.stop]),
    site.close,
  ]);
  if (testFailure !== undefined) {
    if (cleanupErrors.length > 0) {
      throw new AggregateError([asError(testFailure), ...cleanupErrors], "browser tunnel E2E and cleanup failed");
    }
    throw testFailure;
  }
  if (cleanupErrors.length > 0) throw new AggregateError(cleanupErrors, "browser tunnel E2E cleanup failed");
});

async function startGoHarness(origin: string): Promise<GoHarness> {
  const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-browser-tunnel-"));
  const binary = path.join(temporaryDirectory, "flowersec-e2e-harness");
  try {
    await execFileAsync("go", ["build", "-o", binary, "./internal/cmd/flowersec-e2e-harness"], {
      cwd: goRoot,
      maxBuffer: maximumStderrBytes,
      timeout: 60_000,
    });
  } catch (error) {
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
    throw new Error("failed to build the Go E2E harness", { cause: error });
  }

  const child = spawn(binary, [`-allow-origin=${origin}`, "-suite=p256"], {
    cwd: goRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stderr = new BoundedTail(maximumStderrBytes);
  child.stderr.on("data", (chunk: Buffer) => stderr.append(chunk));
  const lifecycle = childLifecycle(child);
  let stopPromise: Promise<void> | undefined;
  const stop = () => {
    stopPromise ??= stopChild(child, lifecycle.exited).finally(async () => {
      await fs.rm(temporaryDirectory, { recursive: true, force: true });
    });
    return stopPromise;
  };

  try {
    const first = await withTimeout(
      Promise.race([
        readReady(child.stdout).then((ready) => ({ kind: "ready" as const, ready })),
        lifecycle.event.then((event) => ({ kind: "lifecycle" as const, event })),
      ]),
      readyTimeoutMs,
      "Go E2E harness did not become ready in time",
    );
    if (first.kind === "lifecycle") {
      const message = first.event.kind === "error"
        ? `Go E2E harness failed to start: ${first.event.error.message}`
        : `Go E2E harness exited before ready (code=${String(first.event.code)}, signal=${String(first.event.signal)})`;
      throw processError(message, stderr);
    }
    return { ready: first.ready, stop };
  } catch (error) {
    const failure = processError(asError(error).message, stderr);
    try {
      await stop();
    } catch (cleanupError) {
      throw new AggregateError([failure, asError(cleanupError)], "Go E2E harness startup and cleanup failed");
    }
    throw failure;
  }
}

function childLifecycle(child: ChildProcess): Readonly<{
  event: Promise<
    | Readonly<{ kind: "error"; error: Error }>
    | Readonly<{ kind: "exit"; code: number | null; signal: NodeJS.Signals | null }>
  >;
  exited: Promise<void>;
}> {
  let resolveExited!: () => void;
  const exited = new Promise<void>((resolve) => {
    resolveExited = resolve;
  });
  const event = new Promise<
    | Readonly<{ kind: "error"; error: Error }>
    | Readonly<{ kind: "exit"; code: number | null; signal: NodeJS.Signals | null }>
  >((resolve) => {
    child.once("error", (error) => resolve({ kind: "error", error }));
    child.once("exit", (code, signal) => {
      resolveExited();
      resolve({ kind: "exit", code, signal });
    });
  });
  return { event, exited };
}

async function stopChild(child: ChildProcess, exited: Promise<void>): Promise<void> {
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  if (await settlesWithin(exited, processExitTimeoutMs)) return;
  child.kill("SIGKILL");
  if (!await settlesWithin(exited, processExitTimeoutMs)) {
    throw new Error("Go E2E harness did not exit after SIGKILL");
  }
}

async function readReady(stdout: Readable): Promise<GoHarnessReady> {
  const line = await new Promise<Buffer>((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const finish = (error?: Error, value?: Buffer) => {
      stdout.off("data", onData);
      stdout.off("error", onError);
      error === undefined ? resolve(value ?? Buffer.alloc(0)) : reject(error);
    };
    const onError = (error: Error) => finish(new Error(`failed to read Go harness output: ${error.message}`));
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.byteLength > maximumReadyLineBytes) {
        finish(new Error("Go harness ready output exceeded the line limit"));
        return;
      }
      const newline = buffered.indexOf(0x0a);
      if (newline >= 0) finish(undefined, buffered.subarray(0, newline));
    };
    stdout.on("data", onData);
    stdout.once("error", onError);
  });

  let value: unknown;
  try {
    value = JSON.parse(line.toString("utf8"));
  } catch {
    throw new Error("Go E2E harness emitted invalid ready JSON");
  }
  if (!isGoHarnessReady(value)) throw new Error("Go E2E harness emitted an invalid ready payload");
  return value;
}

function isGoHarnessReady(value: unknown): value is GoHarnessReady {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const grant = (value as Record<string, unknown>).grant_client;
  if (grant == null || typeof grant !== "object" || Array.isArray(grant)) return false;
  const candidate = grant as Record<string, unknown>;
  return typeof candidate.tunnel_url === "string" && candidate.tunnel_url.startsWith("ws://127.0.0.1:") &&
    typeof candidate.channel_id === "string" && candidate.channel_id.length > 0 &&
    typeof candidate.token === "string" && candidate.token.length > 0 &&
    typeof candidate.e2ee_psk_b64u === "string" && candidate.e2ee_psk_b64u.length > 0 &&
    Array.isArray(candidate.allowed_suites) && candidate.allowed_suites.every((suite) => typeof suite === "number") &&
    typeof candidate.default_suite === "number";
}

class BoundedTail {
  private value = Buffer.alloc(0);

  constructor(private readonly maximumBytes: number) {}

  append(chunk: Buffer): void {
    const combined = Buffer.concat([this.value, chunk]);
    this.value = combined.byteLength <= this.maximumBytes
      ? combined
      : combined.subarray(combined.byteLength - this.maximumBytes);
  }

  text(): string {
    return this.value.toString("utf8").trim();
  }
}

function processError(message: string, stderr: BoundedTail): Error {
  const detail = stderr.text();
  return new Error(detail === "" ? message : `${message}\nProcess stderr (bounded tail):\n${detail}`);
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function settlesWithin(promise: Promise<void>, timeoutMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise.then(() => true),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function settleCleanups(cleanups: readonly (() => Promise<void>)[]): Promise<Error[]> {
  const results = await Promise.allSettled(cleanups.map(async (cleanup) => await cleanup()));
  return results.flatMap((result) => result.status === "rejected" ? [asError(result.reason)] : []);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
