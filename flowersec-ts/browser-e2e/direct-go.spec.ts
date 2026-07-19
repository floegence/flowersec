import { expect, test } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..");
const examplesRoot = path.join(repositoryRoot, "examples");
const readyTimeoutMs = 20_000;
const processExitTimeoutMs = 3_000;
const maximumReadyLineBytes = 64 * 1024;
const maximumStderrBytes = 16 * 1024;

type DirectDemoReady = Readonly<{
  ws_url: string;
  channel_id: string;
  e2ee_psk_b64u: string;
  default_suite: number;
  channel_init_expire_at_unix_s: number;
  example_type_ids: Readonly<Record<string, number>>;
  example_stream_kinds: Readonly<Record<string, string>>;
}>;

type DirectDemoHarness = Readonly<{
  ready: DirectDemoReady;
  stop: () => Promise<void>;
}>;

test("browser SDK connects to the Go direct endpoint", async ({ page }) => {
  test.setTimeout(90_000);

  const site = await startBrowserModuleSite();
  let harness: DirectDemoHarness | undefined;
  let testFailure: unknown;
  const resourceFailures: string[] = [];
  page.on("requestfailed", (request) => {
    resourceFailures.push(`${safePathname(request.url())}: ${request.failure()?.errorText ?? "request failed"}`);
  });
  page.on("response", (response) => {
    if (response.status() >= 400) resourceFailures.push(`${safePathname(response.url())}: HTTP ${response.status()}`);
  });

  try {
    harness = await startDirectDemo(site.origin);
    await page.goto(site.origin, { waitUntil: "networkidle" });

    const result = await page.evaluate(async (ready) => {
      const originalWebSocket = window.WebSocket;
      const [{ connectBrowser, AllowPlaintextForLoopback }, { createDemoSession }] = await Promise.all([
        import("/dist/browser/index.js"),
        import("/dist/_examples/flowersec/demo/v1.facade.gen.js"),
      ]);

      const artifact = {
        v: 1,
        transport: "direct",
        direct_info: {
          ws_url: ready.ws_url,
          channel_id: ready.channel_id,
          e2ee_psk_b64u: ready.e2ee_psk_b64u,
          default_suite: ready.default_suite,
          channel_init_expire_at_unix_s: ready.channel_init_expire_at_unix_s,
        },
      } as const;
      const client = await connectBrowser(artifact, {
        transportSecurityPolicy: AllowPlaintextForLoopback,
        liveness: false,
      });
      const session = createDemoSession(client);
      let closeCalled = false;
      let rpcResponse: unknown;
      let notification: unknown;
      let echoedText = "";

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
        const payload = new TextEncoder().encode("browser-go-direct-echo");
        try {
          await stream.write(payload);
          const echoed = await readExactly(stream, payload.byteLength);
          echoedText = new TextDecoder().decode(echoed);
        } finally {
          await stream.close();
        }
      } finally {
        client.close();
        closeCalled = true;
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
        defaultSuite: ready.default_suite,
        rpcResponse,
        notification,
        echoedText,
        closeCalled,
        nativeWebSocketUnchanged:
          window.WebSocket === originalWebSocket &&
          Function.prototype.toString.call(originalWebSocket).includes("[native code]"),
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
      path: "direct",
      defaultSuite: 1,
      rpcResponse: { ok: true },
      notification: { hello: "world" },
      echoedText: "browser-go-direct-echo",
      closeCalled: true,
      nativeWebSocketUnchanged: true,
      postCloseError: {
        path: "direct",
        stage: "yamux",
        code: "open_stream_failed",
      },
    });
  } catch (error) {
    testFailure = resourceFailures.length === 0
      ? error
      : new Error(`browser module loading failed: ${resourceFailures.join(", ")}`, { cause: error });
  }

  const cleanupErrors = await settleCleanups([
    ...(harness === undefined ? [] : [harness.stop]),
    site.close,
  ]);
  if (testFailure !== undefined) {
    if (cleanupErrors.length > 0) {
      throw new AggregateError([asError(testFailure), ...cleanupErrors], "browser direct E2E and cleanup failed");
    }
    throw testFailure;
  }
  if (cleanupErrors.length > 0) throw new AggregateError(cleanupErrors, "browser direct E2E cleanup failed");
});

async function startDirectDemo(origin: string): Promise<DirectDemoHarness> {
  const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "flowersec-browser-go-"));
  const binary = path.join(temporaryDirectory, "flowersec-direct-demo");
  try {
    await runBoundedProcess("go", ["build", "-o", binary, "./go/direct_demo"], examplesRoot, 60_000);
  } catch (error) {
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
    throw error;
  }

  const child = spawn(binary, ["--allow-origin", origin], {
    cwd: repositoryRoot,
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
      "Go direct demo did not become ready in time",
    );
    if (first.kind === "lifecycle") {
      const message = first.event.kind === "error"
        ? `Go direct demo failed to start: ${first.event.error.message}`
        : `Go direct demo exited before ready (code=${String(first.event.code)}, signal=${String(first.event.signal)})`;
      throw processError(message, stderr);
    }
    return { ready: first.ready, stop };
  } catch (error) {
    const failure = processError(asError(error).message, stderr);
    try {
      await stop();
    } catch (cleanupError) {
      throw new AggregateError([failure, asError(cleanupError)], "Go direct demo startup and cleanup failed");
    }
    throw failure;
  }
}

async function runBoundedProcess(
  command: string,
  args: readonly string[],
  cwd: string,
  timeoutMs: number,
): Promise<void> {
  const child = spawn(command, args, { cwd, stdio: ["ignore", "ignore", "pipe"] });
  const stderr = new BoundedTail(maximumStderrBytes);
  child.stderr.on("data", (chunk: Buffer) => stderr.append(chunk));
  const lifecycle = childLifecycle(child);
  let event: Awaited<typeof lifecycle.event>;
  try {
    event = await withTimeout(lifecycle.event, timeoutMs, `${command} timed out`);
  } catch (error) {
    try {
      await stopChild(child, lifecycle.exited);
    } catch (cleanupError) {
      throw new AggregateError([asError(error), asError(cleanupError)], `${command} and cleanup failed`);
    }
    throw processError(asError(error).message, stderr);
  }
  if (event.kind === "error") throw processError(`${command} failed to start: ${event.error.message}`, stderr);
  if (event.code !== 0) throw processError(`${command} failed with exit code ${String(event.code)}`, stderr);
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
    throw new Error("Go direct demo did not exit after SIGKILL");
  }
}

async function readReady(stdout: Readable): Promise<DirectDemoReady> {
  const line = await new Promise<Buffer>((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const finish = (error?: Error, value?: Buffer) => {
      stdout.off("data", onData);
      stdout.off("error", onError);
      error === undefined ? resolve(value ?? Buffer.alloc(0)) : reject(error);
    };
    const onError = (error: Error) => finish(new Error(`failed to read Go ready output: ${error.message}`));
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.byteLength > maximumReadyLineBytes) {
        finish(new Error("Go ready output exceeded the line limit"));
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
    throw new Error("Go direct demo emitted invalid ready JSON");
  }
  if (!isDirectDemoReady(value)) throw new Error("Go direct demo emitted an invalid ready payload");
  return value;
}

function isDirectDemoReady(value: unknown): value is DirectDemoReady {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const ready = value as Record<string, unknown>;
  return typeof ready.ws_url === "string" && ready.ws_url.startsWith("ws://127.0.0.1:") &&
    typeof ready.channel_id === "string" && ready.channel_id.length > 0 &&
    typeof ready.e2ee_psk_b64u === "string" && ready.e2ee_psk_b64u.length > 0 &&
    ready.default_suite === 1 &&
    typeof ready.channel_init_expire_at_unix_s === "number" &&
    isRecordWithValue(ready.example_type_ids, "rpc_request", 1) &&
    isRecordWithValue(ready.example_type_ids, "rpc_notify", 2) &&
    isRecordWithValue(ready.example_stream_kinds, "echo", "echo");
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

function safePathname(rawUrl: string): string {
  try {
    return new URL(rawUrl).pathname;
  } catch {
    return "<invalid-url>";
  }
}

function isRecordWithValue(record: unknown, key: string, expected: unknown): boolean {
  return record != null && typeof record === "object" && !Array.isArray(record) &&
    (record as Record<string, unknown>)[key] === expected;
}
