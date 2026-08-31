import { expect, test, type Page } from "@playwright/test";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { WebSocketServer, type WebSocket } from "ws";

import { createProxyServiceWorkerScript } from "../src/proxy/serviceWorker.js";
import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..");

test("Chromium runs the Service Worker proxy product chain", async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium Service Worker coverage");
  test.setTimeout(60_000);
  const script = createProxyServiceWorkerScript({
    maxRequestBodyBytes: 4,
    passthrough: { paths: ["/", "/proxy-sw.js"], prefixes: ["/dist/", "/node_modules/"] },
    proxyPathPrefix: "/proxy/",
    stripProxyPathPrefix: true,
    injectHTML: {
      mode: "external_module",
      scriptUrl: "/dist/proxy/index.js",
      runtimeGlobal: "__flowersecProxyRuntime",
      excludePathPrefixes: ["/proxy/no-inject"],
    },
  });
  const upstream = await startProxyUpstream();
  const site = await startBrowserModuleSite({ serviceWorkerScript: script });
  const primaryPeer = startProxyPeer(upstream.origin, site.origin);
  const primaryStderr = captureStderr(primaryPeer);
  let recoveryPeer: ReturnType<typeof spawn> | undefined;
  let recoveryStderr: string[] = [];
  let appPage: Page | undefined;
  let recoveryPage: Page | undefined;
  try {
    const primary = JSON.parse(await firstLine(primaryPeer.stdout)) as { artifact_json: string };
    await page.goto(site.origin, { waitUntil: "networkidle" });
    await installRuntimePage(page, primary.artifact_json, site.origin);
    appPage = await context.newPage();
    await appPage.goto(site.origin, { waitUntil: "networkidle" });

    const firstChunk = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/stream");
      const reader = response.body!.getReader();
      (globalThis as typeof globalThis & { __flowersecStreamReader?: ReadableStreamDefaultReader<Uint8Array> })
        .__flowersecStreamReader = reader;
      const first = await reader.read();
      return new TextDecoder().decode(first.value);
    });
    expect(firstChunk).toBe("alpha-");
    upstream.releaseStream();
    await expect(appPage.evaluate(async () => {
      const holder = globalThis as typeof globalThis & { __flowersecStreamReader?: ReadableStreamDefaultReader<Uint8Array> };
      const reader = holder.__flowersecStreamReader;
      if (reader === undefined) throw new Error("stream reader was not retained");
      let result = "";
      for (;;) {
        const value = await reader.read();
        if (value.done) break;
        result += new TextDecoder().decode(value.value);
      }
      delete holder.__flowersecStreamReader;
      return result;
    })).resolves.toBe("beta");

    await appPage.reload({ waitUntil: "networkidle" });
    await expect(appPage.evaluate(async () => await (await fetch("/proxy/echo")).text()))
      .resolves.toBe("proxied");

    await appPage.evaluate(async () => {
      const response = await fetch("/proxy/abort");
      const reader = response.body!.getReader();
      await reader.read();
      await reader.cancel();
    });
    await Promise.race([
      upstream.canceled,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("upstream cancel was not propagated")), 5_000)),
    ]);

    const oversized = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/upload", { method: "POST", body: "12345" });
      return { status: response.status, body: await response.text() };
    });
    expect(oversized).toEqual({ status: 413, body: "proxy request too large" });
    const failed = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/error");
      return { status: response.status, body: await response.text() };
    });
    expect(failed).toEqual({ status: 502, body: "proxy request failed" });

    const html = await appPage.evaluate(async () => await (await fetch("/proxy/html")).text());
    expect(html).toContain("data-flowersec-runtime-global=\"__flowersecProxyRuntime\"");
    const excluded = await appPage.evaluate(async () => await (await fetch("/proxy/no-inject")).text());
    expect(excluded).not.toContain("data-flowersec-runtime-global");

    await expect(page.evaluate(runWebSocketPatchContract)).resolves.toEqual({
      echoed: "patched-echo",
      restored: true,
    });

    await page.close();
    expect(await processExit(primaryPeer), primaryStderr.join("")).toBe(0);
    const unavailable = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/echo");
      return { status: response.status, body: await response.text() };
    });
    expect(unavailable).toEqual({ status: 503, body: "proxy runtime unavailable" });

    recoveryPeer = startProxyPeer(upstream.origin, site.origin);
    recoveryStderr = captureStderr(recoveryPeer);
    const recovery = JSON.parse(await firstLine(recoveryPeer.stdout)) as { artifact_json: string };
    recoveryPage = await context.newPage();
    await recoveryPage.goto(site.origin, { waitUntil: "networkidle" });
    await installRuntimePage(recoveryPage, recovery.artifact_json, site.origin);
    await expect(appPage.evaluate(async () => await (await fetch("/proxy/echo")).text()))
      .resolves.toBe("proxied");
    await disposeRuntimePage(recoveryPage);
    expect(await processExit(recoveryPeer), recoveryStderr.join("")).toBe(0);
  } finally {
    const cleanupPage = recoveryPage ?? appPage;
    if (cleanupPage !== undefined && !cleanupPage.isClosed()) {
      await cleanupPage.evaluate(async () => {
        for (const registration of await navigator.serviceWorker.getRegistrations()) await registration.unregister();
      }).catch(() => undefined);
    }
    await recoveryPage?.close().catch(() => undefined);
    await appPage?.close().catch(() => undefined);
    if (!page.isClosed()) await page.close().catch(() => undefined);
    await stopPeer(recoveryPeer).catch(() => undefined);
    await stopPeer(primaryPeer);
    await site.close();
    await upstream.close();
  }
});

async function installRuntimePage(page: Page, artifactJSON: string, externalOrigin: string): Promise<void> {
  await page.evaluate(async ({ artifactJSON: encodedArtifact, externalOrigin: origin }) => {
    const proxy = await import("/dist/proxy/index.js");
    const sdk = await import("/dist/browser/index.js");
    const handle = await proxy.connectProxyBrowser(
      sdk.createArtifactLease(sdk.parseArtifact(encodedArtifact), async () => undefined),
      {
        runtime: { externalOrigin: origin, maxBodyBytes: 4_096, maxChunkBytes: 8, maxWsFrameBytes: 32 },
        serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/", controllerTimeoutMs: 5_000 },
      },
    );
    const holder = globalThis as typeof globalThis & {
      __flowersecProxyHandle?: typeof handle;
      __flowersecProxyRuntime?: typeof handle.runtime;
    };
    holder.__flowersecProxyHandle = handle;
    holder.__flowersecProxyRuntime = handle.runtime;
    await proxy.ensureServiceWorkerRuntimeRegistered();
  }, { artifactJSON, externalOrigin });
}

async function disposeRuntimePage(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const holder = globalThis as typeof globalThis & {
      __flowersecProxyHandle?: { dispose(): Promise<void> };
      __flowersecProxyRuntime?: unknown;
    };
    await holder.__flowersecProxyHandle?.dispose();
    delete holder.__flowersecProxyHandle;
    delete holder.__flowersecProxyRuntime;
  });
}

async function runWebSocketPatchContract(): Promise<Readonly<{ echoed: string; restored: boolean }>> {
  const proxy = await import("/dist/proxy/index.js");
  const holder = globalThis as typeof globalThis & { __flowersecProxyRuntime?: Parameters<typeof proxy.installWebSocketPatch>[0]["runtime"] };
  if (holder.__flowersecProxyRuntime === undefined) throw new Error("production proxy runtime was not retained");
  const NativeWebSocket = globalThis.WebSocket;
  const patch = proxy.installWebSocketPatch({ runtime: holder.__flowersecProxyRuntime, shouldProxy: () => true });
  let echoed = "";
  try {
    const socket = new WebSocket("ws://proxy.invalid/echo", "chat");
    echoed = await new Promise<string>((resolve, reject) => {
      socket.onerror = () => reject(new Error("patched WebSocket failed"));
      socket.onopen = () => socket.send("patched-echo");
      socket.onmessage = (event) => resolve(String(event.data));
    });
    socket.close(1000, "done");
  } finally {
    patch.uninstall();
  }
  return { echoed, restored: globalThis.WebSocket === NativeWebSocket };
}

function startProxyPeer(upstream: string, origin: string): ReturnType<typeof spawn> {
  return spawn("go", [
    "run", "./internal/cmd/ts-proxy-peer", "--upstream", upstream, "--origin", origin,
    "--max-body-bytes", "4096", "--http-timeout", "15s",
  ], {
    cwd: path.join(repositoryRoot, "flowersec-go"),
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function startProxyUpstream(): Promise<Readonly<{
  origin: string;
  canceled: Promise<void>;
  releaseStream(): void;
  close(): Promise<void>;
}>> {
  let releaseStream!: () => void;
  const streamReleased = new Promise<void>((resolve) => { releaseStream = resolve; });
  let markCanceled!: () => void;
  const canceled = new Promise<void>((resolve) => { markCanceled = resolve; });
  const server = createServer(async (request, response) => {
    if (request.url === "/stream") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.write("alpha-");
      await streamReleased;
      response.end("beta");
      return;
    }
    if (request.url === "/abort") {
      let settled = false;
      const observeCancel = () => {
        if (settled) return;
        settled = true;
        markCanceled();
      };
      request.once("aborted", observeCancel);
      response.once("close", observeCancel);
      response.writeHead(200, { "content-type": "text/plain" });
      response.write("first");
      return;
    }
    if (request.url === "/error") {
      request.socket.destroy();
      return;
    }
    if (request.url === "/html" || request.url === "/no-inject") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><html><head><title>proxied</title></head><body>ok</body></html>");
      return;
    }
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("proxied");
  });
  const sockets = new Set<WebSocket>();
  const webSockets = new WebSocketServer({ server, perMessageDeflate: false, maxPayload: 32 });
  webSockets.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("message", (data, isBinary) => socket.send(data, { binary: isBinary }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("proxy upstream did not bind");
  return Object.freeze({
    origin: `http://127.0.0.1:${address.port}`,
    canceled,
    releaseStream,
    close: async () => {
      for (const socket of sockets) socket.terminate();
      await new Promise<void>((resolve) => webSockets.close(() => resolve()));
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  });
}

function captureStderr(peer: ReturnType<typeof spawn>): string[] {
  const stderr: string[] = [];
  peer.stderr?.setEncoding("utf8");
  peer.stderr?.on("data", (chunk: string) => stderr.push(chunk));
  return stderr;
}

async function firstLine(stream: NodeJS.ReadableStream | null): Promise<string> {
  if (stream === null) throw new Error("Go peer stdout is unavailable");
  stream.setEncoding("utf8");
  return await new Promise<string>((resolve, reject) => {
    let buffered = "";
    const data = (chunk: string) => {
      buffered += chunk;
      const index = buffered.indexOf("\n");
      if (index < 0) return;
      cleanup();
      resolve(buffered.slice(0, index).trim());
    };
    const end = () => { cleanup(); reject(new Error("Go peer exited before publishing endpoint")); };
    const cleanup = () => { stream.removeListener("data", data); stream.removeListener("end", end); };
    stream.on("data", data);
    stream.on("end", end);
  });
}

async function processExit(peer: ReturnType<typeof spawn>): Promise<number | null> {
  if (peer.exitCode !== null) return peer.exitCode;
  return await new Promise((resolve) => peer.once("exit", (code) => resolve(code)));
}

async function stopPeer(peer: ReturnType<typeof spawn> | undefined): Promise<void> {
  if (peer === undefined || peer.exitCode !== null) return;
  peer.kill("SIGTERM");
  const stopped = await Promise.race([
    processExit(peer).then(() => true),
    new Promise<false>((resolve) => setTimeout(() => resolve(false), 1_000)),
  ]);
  if (stopped || peer.exitCode !== null) return;
  peer.kill("SIGKILL");
  await processExit(peer);
}
