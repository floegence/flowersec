import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";
import { WebSocketServer, type RawData, type WebSocket } from "ws";

import { connect, createArtifactLease, parseArtifact, SessionError } from "../node/v2.js";
import { createProxyRuntime } from "../proxy/runtime.js";
import { ProxyByteReader, writeAll } from "../proxy/stream.js";

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));
const TEST_RESPONSE_COOKIE = "theme=light; Secure; HttpOnly; SameSite=Strict";

describe("Browser TypeScript ProxyServer interoperability", () => {
  test("runs Browser TypeScript HTTP and WebSocket semantics against Go ProxyServer", async () => {
    await runMatrixCell("go");
  }, 30_000);

  test("runs Browser TypeScript HTTP and WebSocket semantics against Rust ProxyServer", async () => {
    await runMatrixCell("rust");
  }, 30_000);

  test("runs Browser TypeScript HTTP and WebSocket semantics against Node.js TypeScript ProxyServer", async () => {
    await runMatrixCell("node-typescript");
  }, 30_000);
});

type Runtime = "go" | "rust" | "node-typescript";
type ProxyRuntime = ReturnType<typeof createProxyRuntime>;
type ProxyRequest = Parameters<ProxyRuntime["dispatchFetch"]>[0];
type PeerEndpoint = Readonly<{ runtime: Runtime; artifact_json: string; origin: string }>;

async function runMatrixCell(runtime: Runtime): Promise<void> {
  const observed: Array<Readonly<{
    body: string;
    authorization?: string;
    cookie?: string;
    host?: string;
    forwardedProto?: string;
    origin?: string;
    requestID?: string;
  }>> = [];
  let slowStartedResolve!: () => void;
  const slowStarted = new Promise<void>((resolve) => { slowStartedResolve = resolve; });
  let phase = "spawn";
  const upstream = createServer(async (request, response) => {
    if (request.url === "/slow") {
      slowStartedResolve();
      request.on("error", () => undefined);
      return;
    }
    if (request.url === "/large") {
      response.writeHead(200, { "content-length": "9", "content-type": "text/plain" });
      response.end("123456789");
      return;
    }
    const chunks: Buffer[] = [];
    try {
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
    } catch {
      return;
    }
    observed.push({
      body: Buffer.concat(chunks).toString("utf8"),
      ...(request.headers.authorization === undefined ? {} : { authorization: request.headers.authorization }),
      ...(request.headers.cookie === undefined ? {} : { cookie: request.headers.cookie }),
      ...(request.headers.host === undefined ? {} : { host: request.headers.host }),
      ...(request.headers["x-forwarded-proto"] === undefined ? {} : { forwardedProto: request.headers["x-forwarded-proto"] as string }),
      ...(request.headers.origin === undefined ? {} : { origin: request.headers.origin }),
      ...(request.headers["x-request-id"] === undefined ? {} : { requestID: request.headers["x-request-id"] as string }),
    });
    response.writeHead(201, {
      "content-type": "text/plain",
      "location": "/hidden",
      "set-cookie": TEST_RESPONSE_COOKIE,
      "x-visible": "yes",
    });
    response.end("proxied");
  });
  const sockets = new Set<WebSocket>();
  const handshakes: Array<Readonly<{ origin?: string; host?: string }>> = [];
  const messages: Array<Readonly<{ text: string; binary: boolean }>> = [];
  const webSockets = new WebSocketServer({
    server: upstream,
    perMessageDeflate: false,
    maxPayload: 64,
    handleProtocols(protocols) { return protocols.has("chat") ? "chat" : false; },
    verifyClient(info, done) {
      if (info.req.url === "/reject") { done(false, 403, "Forbidden"); return; }
      done(true);
    },
  });
  webSockets.on("connection", (socket, request) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    handshakes.push({
      ...(request.headers.origin === undefined ? {} : { origin: request.headers.origin }),
      ...(request.headers.host === undefined ? {} : { host: request.headers.host }),
    });
    socket.on("message", (data, isBinary) => {
      messages.push({ text: webSocketDataBuffer(data).toString("utf8"), binary: isBinary });
      socket.send(data, { binary: isBinary });
    });
  });
  await new Promise<void>((resolve, reject) => {
    upstream.once("error", reject);
    upstream.listen(0, "127.0.0.1", resolve);
  });
  const address = upstream.address();
  if (address === null || typeof address === "string") throw new Error("proxy upstream did not bind");
  const upstreamOrigin = `http://127.0.0.1:${address.port}`;
  const peer = spawnPeer(runtime, upstreamOrigin);
  const stderr: string[] = [];
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
  let session: Awaited<ReturnType<typeof connect>> | undefined;
  let proxyRuntime: ProxyRuntime | undefined;
  try {
    const endpoint = await readEndpoint(peer.stdout, runtime);
    session = await connect(
      createArtifactLease(parseArtifact(endpoint.artifact_json), async () => undefined),
      { origin: endpoint.origin },
    );
    proxyRuntime = createProxyRuntime({
      session,
      externalOrigin: "https://app.example",
      maxBodyBytes: 32,
      maxWsFrameBytes: 32,
      extraRequestHeaders: ["origin", "x-request-id"],
      extraResponseHeaders: ["x-visible"],
    });

    phase = "http-success";
    const success = await dispatch(proxyRuntime, {
      id: "success",
      method: "POST",
      path: "/resource",
      headers: [
        { name: "content-type", value: "text/plain" },
        { name: "authorization", value: "secret" },
        { name: "cookie", value: "public=ok; secret=no; private_token=no" },
        { name: "host", value: "attacker.example" },
        { name: "origin", value: "https://app.example" },
        { name: "x-request-id", value: "visible" },
      ],
      body: new TextEncoder().encode("request").buffer,
    });
    expect(success.map((message) => message.type)).toEqual([
      "flowersec-proxy:response_meta",
      "flowersec-proxy:response_chunk",
      "flowersec-proxy:response_end",
    ]);
    expect(success[0]).toMatchObject({ status: 201 });
    expect(success[0]?.headers).toEqual(expect.arrayContaining([
      { name: "content-type", value: "text/plain" },
      { name: "x-visible", value: "yes" },
    ]));
    expect(success[0]?.headers).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "location" }),
      expect.objectContaining({ name: "set-cookie" }),
    ]));
    expect(TEST_RESPONSE_COOKIE).toContain("Secure");
    expect(TEST_RESPONSE_COOKIE).toContain("HttpOnly");
    expect(new TextDecoder().decode(new Uint8Array(success[1]!.data as ArrayBuffer))).toBe("proxied");
    expect(observed).toEqual([{
      body: "request",
      host: `127.0.0.1:${address.port}`,
      forwardedProto: "https",
      origin: "https://app.example",
      requestID: "visible",
    }]);

    phase = "origin-rejection";
    const wrongOrigin = createProxyRuntime({ session, externalOrigin: "https://other.example" });
    await expect(dispatch(wrongOrigin, { id: "origin", method: "GET", path: "/", headers: [] }))
      .resolves.toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_error", code: "operation_failed" }));
    wrongOrigin.dispose();

    phase = "request-limit";
    await expect(dispatch(proxyRuntime, {
      id: "request-too-large", method: "POST", path: "/resource", headers: [], body: new Uint8Array(9).buffer,
    })).resolves.toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_error", code: "operation_failed" }));
    phase = "response-limit";
    await expect(dispatch(proxyRuntime, {
      id: "response-too-large", method: "GET", path: "/large", headers: [],
    })).resolves.toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_error", code: "operation_failed" }));

    phase = "cancel";
    const canceled = dispatchCancellable(proxyRuntime, { id: "cancel", method: "GET", path: "/slow", headers: [] });
    await slowStarted;
    canceled.abort();
    await expect(canceled.result).resolves.toContainEqual(expect.objectContaining({
      type: "flowersec-proxy:response_error", code: "canceled", status: 499,
    }));

    phase = "websocket-open";
    const opened = await proxyRuntime.openWebSocketStream("/echo", { protocols: ["chat"] });
    expect(opened.protocol).toBe("chat");
    const reader = new ProxyByteReader(opened.stream);
    phase = "websocket-text";
    await writeWebSocketFrame(opened.stream, 1, new TextEncoder().encode("text"));
    await expect(readWebSocketFrame(reader)).resolves.toEqual({ operation: 1, payload: new TextEncoder().encode("text") });
    phase = "websocket-binary";
    await writeWebSocketFrame(opened.stream, 2, Uint8Array.of(1, 2, 3));
    await expect(readWebSocketFrame(reader)).resolves.toEqual({ operation: 2, payload: Uint8Array.of(1, 2, 3) });
    phase = "websocket-close";
    await writeWebSocketFrame(opened.stream, 8, webSocketClosePayload(1000, "done"));
    try {
      expect((await readWebSocketFrame(reader)).operation).toBe(8);
    } catch (error) {
      if (runtime !== "go" || !(error instanceof SessionError) || error.code !== "stream_reset") throw error;
    }
    await opened.stream.close().catch(() => undefined);
    expect(messages).toEqual([
      { text: "text", binary: false },
      { text: "\u0001\u0002\u0003", binary: true },
    ]);
    expect(handshakes[0]).toEqual({ origin: upstreamOrigin, host: `127.0.0.1:${address.port}` });

    phase = "websocket-reject";
    await expect(proxyRuntime.openWebSocketStream("/reject", { protocols: ["chat"] }))
      .rejects.toMatchObject({ code: "operation_failed" });
    phase = "websocket-limit";
    const oversized = await proxyRuntime.openWebSocketStream("/echo", { protocols: ["chat"] });
    await writeWebSocketFrame(oversized.stream, 2, new Uint8Array(33));
    await expect(oversized.stream.read()).rejects.toMatchObject({ code: "stream_reset" });
    phase = "websocket-reset";
    const reset = await proxyRuntime.openWebSocketStream("/echo", { protocols: ["chat"] });
    await reset.stream.reset();

    proxyRuntime.dispose();
    proxyRuntime = undefined;
    await session.close();
    session = undefined;
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } catch (error) {
    throw new Error(`${runtime} ProxyServer matrix failed during ${phase}: ${error instanceof Error ? error.message : String(error)}; handshakes=${JSON.stringify(handshakes)}\n${stderr.join("")}`);
  } finally {
    proxyRuntime?.dispose();
    await session?.close().catch(() => undefined);
    if (peer.exitCode === null) peer.kill("SIGKILL");
    for (const socket of sockets) socket.terminate();
    await new Promise<void>((resolve) => webSockets.close(() => resolve()));
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  }
}

function spawnPeer(runtime: Runtime, upstream: string): ChildProcessWithoutNullStreams {
  if (runtime === "go") {
    return spawn("go", ["run", "./internal/cmd/ts-proxy-peer-v2", "--upstream", upstream], {
      cwd: `${repositoryRoot}/flowersec-go`, stdio: ["pipe", "pipe", "pipe"],
    });
  }
  if (runtime === "node-typescript") {
    return spawn(process.execPath, ["--import", "tsx", "src/interop/proxyServerPeer.ts", "--upstream", upstream], {
      cwd: `${repositoryRoot}/flowersec-ts`, stdio: ["pipe", "pipe", "pipe"],
    });
  }
  return spawn("rustup", [
    "run", "1.88.0", "cargo", "test", "--quiet", "--manifest-path", `${repositoryRoot}/flowersec-rust/Cargo.toml`,
    "--test", "proxy_server_interop_peer", "browser_typescript_proxy_runtime_uses_rust_proxy_server",
    "--", "--ignored", "--exact", "--nocapture",
  ], {
    cwd: repositoryRoot,
    env: { ...process.env, FLOWERSEC_PROXY_UPSTREAM: upstream },
    stdio: ["pipe", "pipe", "pipe"],
  });
}

function webSocketDataBuffer(data: RawData): Buffer {
  if (data instanceof ArrayBuffer) return Buffer.from(new Uint8Array(data));
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}

async function readEndpoint(stream: NodeJS.ReadableStream, runtime: Runtime): Promise<PeerEndpoint> {
  stream.setEncoding("utf8");
  return await new Promise<PeerEndpoint>((resolve, reject) => {
    let buffered = "";
    const data = (chunk: string) => {
      buffered += chunk;
      const lines = buffered.split("\n");
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        const start = line.indexOf("{");
        if (start < 0) continue;
        try {
          const endpoint = JSON.parse(line.slice(start)) as PeerEndpoint;
          if (endpoint.runtime === runtime && typeof endpoint.artifact_json === "string") {
            cleanup(); resolve(endpoint); return;
          }
        } catch { /* wait for the endpoint line */ }
      }
    };
    const end = () => { cleanup(); reject(new Error(`${runtime} peer exited before publishing an endpoint`)); };
    const cleanup = () => { stream.removeListener("data", data); stream.removeListener("end", end); };
    stream.on("data", data);
    stream.on("end", end);
  });
}

async function processExit(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  if (child.exitCode !== null) return child.exitCode;
  return await new Promise((resolve) => child.once("exit", (code) => resolve(code)));
}

async function dispatch(runtime: ProxyRuntime, request: ProxyRequest): Promise<Record<string, unknown>[]> {
  return await dispatchCancellable(runtime, request).result;
}

function dispatchCancellable(runtime: ProxyRuntime, request: ProxyRequest): Readonly<{
  result: Promise<Record<string, unknown>[]>;
  abort(): void;
}> {
  const channel = new MessageChannel();
  const result = new Promise<Record<string, unknown>[]>((resolve, reject) => {
    const messages: Record<string, unknown>[] = [];
    const timeout = setTimeout(() => reject(new Error("proxy response timed out")), 5_000);
    channel.port2.onmessage = (event) => {
      const message = event.data as Record<string, unknown>;
      messages.push(message);
      if (message.type === "flowersec-proxy:response_end" || message.type === "flowersec-proxy:response_error") {
        clearTimeout(timeout); channel.port2.close(); resolve(messages);
      }
    };
    channel.port2.start();
  });
  runtime.dispatchFetch(request, channel.port1);
  return Object.freeze({ result, abort: () => channel.port2.postMessage({ type: "flowersec-proxy:abort" }) });
}

async function writeWebSocketFrame(stream: Parameters<typeof writeAll>[0], operation: number, payload: Uint8Array): Promise<void> {
  const frame = new Uint8Array(5 + payload.length);
  frame[0] = operation;
  new DataView(frame.buffer).setUint32(1, payload.length, false);
  frame.set(payload, 5);
  await writeAll(stream, frame);
}

async function readWebSocketFrame(reader: ProxyByteReader): Promise<Readonly<{ operation: number; payload: Uint8Array }>> {
  const header = await reader.readExactly(5);
  const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(1, false);
  return Object.freeze({ operation: header[0]!, payload: await reader.readExactly(length) });
}

function webSocketClosePayload(code: number, reason: string): Uint8Array {
  const text = new TextEncoder().encode(reason);
  const payload = new Uint8Array(2 + text.length);
  new DataView(payload.buffer).setUint16(0, code, false);
  payload.set(text, 2);
  return payload;
}
