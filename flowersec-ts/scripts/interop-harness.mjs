import { createServer } from "node:http";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { MessageChannel } from "node:worker_threads";
import { WebSocketServer } from "ws";

import {
  acceptDirectNode,
  AllowPlaintextForLoopback,
  connectDirectNode,
  connectTunnelEndpointNode,
  connectTunnelNode,
  serveProxyStream,
} from "../dist/node/index.js";
import { createProxyRuntime } from "../dist/proxy/runtime.js";
import { PROXY_KIND_HTTP1, PROXY_KIND_WS } from "../dist/proxy/constants.js";
import { RpcRouter, RpcServer } from "../dist/rpc/server.js";
import { createByteReader } from "../dist/streamio/index.js";
import { YamuxStreamResetError } from "../dist/yamux/errors.js";
import { createReconnectManager } from "../dist/reconnect/index.js";
import { FlowersecError } from "../dist/utils/errors.js";
import { Supervisor } from "./interop-supervisor.mjs";

const VERSION = 1;
const CASES = ["connect", "rekey", "streams", "rpc", "liveness", "proxy", "reconnect", "limits", "diagnostics"];
const SATURATION_GATE_KIND = "interop-rpc-saturation-gate";
const LIMIT_CASES = ["active_streams", "inbound_streams", "frame", "stream_receive", "session_receive", "proxy_body"];
const DIAGNOSTIC_CONTRACTS = new Map([
  ["rpc_queue", ["rpc", "resource_exhausted"]],
  ["active_streams", ["yamux", "resource_exhausted"]],
  ["inbound_streams", ["yamux", "resource_exhausted"]],
  ["frame", ["yamux", "resource_exhausted"]],
  ["stream_receive", ["yamux", "resource_exhausted"]],
  ["session_receive", ["yamux", "resource_exhausted"]],
  ["proxy_body", ["rpc", "resource_exhausted"]],
]);
const encoder = new TextEncoder();
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[Symbol.asyncIterator]();

async function main() {
  await emit({ v: VERSION, event: "hello", language: "typescript", roles: ["client", "server"], cases: CASES });
  let requestId = "";
  try {
    const command = await readCommand();
    requestId = command.request_id;
    if (command.event === "run_client") {
      const outcome = await withDeadline(command.deadline_ms, exerciseClient(command));
      await emit({
        v: VERSION,
        event: "result",
        request_id: requestId,
        metrics: outcome.metrics,
        diagnostics: outcome.diagnostics,
      });
    } else {
      await withDeadline(command.deadline_ms, serve(command));
    }
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ event: "harness_failed", message: errorMessage(error), stack: asError(error).stack })}\n`);
    await emit({
      v: VERSION,
      event: "fatal",
      ...(requestId === "" ? {} : { request_id: requestId }),
      stage: "harness",
      code: "typescript_harness_failed",
      message: errorMessage(error),
    });
    process.exitCode = 1;
  }
}

async function readCommand() {
  const value = await readLine();
  assertExactKeys(value, [
    "v", "event", "request_id", "profile", "transport", "suite", "deadline_ms", "origin",
    "upstream_url", "workload", "reconnect_artifacts", "limit_artifacts", "limit_case",
  ], ["direct_info", "direct_credential", "tunnel_grant"]);
  if (value.v !== VERSION || (value.event !== "run_client" && value.event !== "serve")) throw new Error("invalid command envelope");
  if (typeof value.request_id !== "string" || value.request_id === "") throw new Error("request_id is required");
  if (value.transport !== "direct" && value.transport !== "tunnel") throw new Error("invalid transport");
  if (value.suite !== "x25519" && value.suite !== "p256") throw new Error("invalid suite");
  if (!Number.isSafeInteger(value.deadline_ms) || value.deadline_ms <= 0) throw new Error("invalid deadline_ms");
  validateWorkload(value.workload);
  if (!Array.isArray(value.reconnect_artifacts)) throw new Error("reconnect_artifacts must be an array");
  if (!Array.isArray(value.limit_artifacts) || typeof value.limit_case !== "string") throw new Error("invalid limit plan fields");
  const direct = value.transport === "direct";
  const client = value.event === "run_client";
  const expected = client ? (direct ? "direct_info" : "tunnel_grant") : (direct ? "direct_credential" : "tunnel_grant");
  for (const field of ["direct_info", "direct_credential", "tunnel_grant"]) {
    if ((field === expected) !== (value[field] != null)) throw new Error(`command requires only ${expected}`);
  }
  if (client) {
    if (value.reconnect_artifacts.length !== value.workload.reconnect_cycles + 1) {
      throw new Error("client command requires one fresh artifact per reconnect session");
    }
    value.reconnect_artifacts.forEach((artifact) => validateClientArtifact(artifact, value.transport));
    const expectedLimits = Math.max(0, value.workload.limit_checks - 1);
    if (value.limit_case !== "" || value.limit_artifacts.length !== expectedLimits) throw new Error("client command contains an invalid limit plan");
    value.limit_artifacts.forEach((artifact, index) => {
      assertExactKeys(artifact, ["name"], ["direct_info", "tunnel_grant"]);
      if (artifact.name !== LIMIT_CASES[index]) throw new Error("client limit artifacts must follow the canonical order");
      validateClientArtifact(artifact, value.transport, ["name"]);
    });
  } else if (value.reconnect_artifacts.length !== 0) {
    throw new Error("server command must not contain client reconnect artifacts");
  } else if (value.limit_artifacts.length !== 0 || (value.limit_case !== "" && !LIMIT_CASES.includes(value.limit_case))) {
    throw new Error("server command contains an invalid limit plan");
  }
  return value;
}

function validateClientArtifact(value, transport, required = []) {
  assertExactKeys(value, required, ["direct_info", "tunnel_grant"]);
  const direct = value.direct_info != null;
  const tunnel = value.tunnel_grant != null;
  if (transport === "direct" ? (!direct || tunnel) : (!tunnel || direct)) {
    throw new Error(`invalid ${transport} reconnect artifact`);
  }
}

function validateWorkload(value) {
  assertObject(value, "workload");
  assertExactKeys(value, ["streams", "rekey", "liveness_probes", "rpc", "proxy", "reconnect_cycles", "limit_checks"]);
  assertExactKeys(value.streams, ["concurrent", "bytes_per_stream", "chunk_bytes", "slow_readers", "churn", "fin", "reset"]);
  assertExactKeys(value.rekey, ["client", "server", "concurrent"]);
  assertExactKeys(value.rpc, [
    "calls", "notifications", "cancellations", "timeouts",
    "saturation_active", "saturation_queued", "saturation_rejected",
  ]);
  assertExactKeys(value.proxy, ["http_requests", "http_body_bytes", "websocket_frames", "websocket_frame_bytes"]);
  const positive = [
    ...Object.values(value.streams), value.rekey.client, value.rekey.server, value.liveness_probes,
    value.rpc.calls, value.rpc.notifications, value.rpc.cancellations, value.rpc.timeouts,
    value.rpc.saturation_active, value.rpc.saturation_queued, value.rpc.saturation_rejected,
    value.proxy.http_requests, value.proxy.http_body_bytes, value.proxy.websocket_frames,
    value.proxy.websocket_frame_bytes, value.reconnect_cycles, value.limit_checks,
  ];
  if (positive.some((item) => !Number.isSafeInteger(item) || item <= 0)) throw new Error("workload values must be positive integers");
  if (!Number.isSafeInteger(value.rekey.concurrent) || value.rekey.concurrent < 0 || value.rpc.saturation_rejected !== 1) throw new Error("invalid rekey/RPC workload");
}

async function connectClient(command) {
  const options = {
    origin: command.origin,
    transportSecurityPolicy: AllowPlaintextForLoopback,
    liveness: false,
  };
  return command.transport === "direct"
    ? await connectDirectNode(command.direct_info, options)
    : await connectTunnelNode(command.tunnel_grant, options);
}

async function exerciseClient(command) {
  const diagnostics = [];
  const client = await connectClient(command);
  const workload = command.workload;
  const metrics = emptyMetrics();
  metrics.sessions = 1;
  const notifications = [];
  const unsubscribe = client.rpc.onNotify(2, (payload) => {
    if (!isObject(payload) || payload.hello !== "world") throw new Error("invalid notification payload");
    notifications.push(payload);
  });
  try {
    for (let index = 0; index < workload.rekey.client; index += 1) {
      await client.rekey();
      metrics.rekeys += 1;
      await rpcEcho(client, index, false);
    }
    for (let index = 0; index < workload.rekey.server; index += 1) {
      await rpcControl(client, 3);
      metrics.rekeys += 1;
    }
    for (let index = 0; index < workload.rekey.concurrent; index += 1) {
      await Promise.all([client.rekey(), rpcControl(client, 3)]);
      metrics.rekeys += 2;
    }
    await exerciseStreams(client, workload.streams, metrics);
    for (let index = 0; index < workload.liveness_probes; index += 1) {
      await client.probeLiveness();
      metrics.liveness_probes += 1;
    }
    for (let index = 0; index < workload.rpc.calls; index += 1) {
      await rpcEcho(client, index, index < workload.rpc.notifications);
      metrics.rpc_calls += 1;
    }
    const queueRejections = await exerciseRPCSaturation(client, workload.rpc);
    metrics.rpc_queue_rejections += queueRejections;
    metrics.resource_rejections += queueRejections;
    metrics.limit_checks += 1;
    diagnostics.push(diagnosticFor("rpc_queue", command.transport));
    for (let index = 0; index < workload.rpc.cancellations; index += 1) {
      const controller = new AbortController();
      controller.abort(new Error("interop cancellation"));
      await expectRejected(client.rpc.call(4, {}, controller.signal), "RPC cancellation");
      metrics.rpc_cancellations += 1;
    }
    for (let index = 0; index < workload.rpc.timeouts; index += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error("interop timeout")), 1);
      try {
        await expectRejected(client.rpc.call(4, {}, controller.signal), "RPC timeout");
      } finally {
        clearTimeout(timer);
      }
      metrics.rpc_timeouts += 1;
    }
    await waitUntil(() => notifications.length >= workload.rpc.notifications, command.deadline_ms);
    metrics.rpc_notifications = workload.rpc.notifications;
    await exerciseProxy(client, workload.proxy, metrics);
    await rpcControl(client, 5);
  } finally {
    unsubscribe();
    client.close();
  }
  await exerciseReconnect(command, metrics);
  await exerciseLimits(command, metrics, diagnostics);
  return { metrics, diagnostics };
}

async function exerciseLimits(command, metrics, diagnostics) {
  for (const artifact of command.limit_artifacts) {
    const options = {
      origin: command.origin,
      transportSecurityPolicy: AllowPlaintextForLoopback,
      liveness: false,
      ...(artifact.name === "active_streams"
        ? { yamuxLimits: { maxActiveStreams: 2, maxInboundStreams: 1 } }
        : {}),
    };
    let client;
    try {
      client = command.transport === "direct"
        ? await connectDirectNode(artifact.direct_info, options)
        : await connectTunnelNode(artifact.tunnel_grant, options);
    } catch (error) {
      throw new Error(`limit ${artifact.name} connect failed: ${errorMessage(error)}`, { cause: error });
    }
    try {
      let backpressure;
      try {
        backpressure = await exerciseLimitAction(client, artifact.name);
      } catch (error) {
        throw new Error(`limit ${artifact.name} failed: ${errorMessage(error)}`, { cause: error });
      }
      metrics.sessions += 1;
      metrics.limit_checks += 1;
      if (backpressure) metrics.backpressure_checks += 1;
      else metrics.resource_rejections += 1;
      diagnostics.push(diagnosticFor(artifact.name, command.transport));
    } finally {
      client.close();
    }
  }
}

async function exerciseLimitAction(client, name) {
  switch (name) {
    case "active_streams": {
      const held = await client.openStream("hold");
      try {
        await client.openStream("hold");
      } catch (error) {
        if (error instanceof FlowersecError && error.code === "resource_exhausted") {
          await held.reset(new Error("active stream check complete"));
          await rpcControl(client, 5);
          return false;
        }
        throw error;
      }
      throw new Error("active stream limit unexpectedly accepted a stream");
    }
    case "inbound_streams":
    case "frame": {
      const stream = await client.openStream("hold");
      if (name === "frame") await stream.write(new Uint8Array(2048));
      await expectPromiseFailureWithin(stream.read(), 1000, `${name} stream`);
      if (name === "inbound_streams") await rpcControl(client, 5);
      return false;
    }
    case "stream_receive": {
      const stream = await client.openStream("hold");
      const write = stream.write(new Uint8Array((256 * 1024) + 1));
      const settled = await settlesWithin(write, 100);
      if (settled) throw new Error("stream receive boundary did not apply backpressure");
      await stream.reset(new Error("interop backpressure check complete"));
      const [writeResult] = await Promise.allSettled([write]);
      if (writeResult.status !== "rejected") {
        throw new Error("reset released the backpressured write without an error");
      }
      await rpcControl(client, 5);
      return true;
    }
    case "session_receive": {
      const first = await client.openStream("hold");
      const second = await client.openStream("hold");
      const writes = Promise.allSettled([
        first.write(new Uint8Array(256 * 1024)),
        second.write(new Uint8Array(256 * 1024)),
      ]);
      const probeError = await expectPromiseFailureWithin(client.probeLiveness(), 1000, "session receive probe");
      if (!(probeError instanceof FlowersecError) || probeError.code !== "ping_failed") {
        throw new Error(`session receive probe returned ${errorMessage(probeError)}`, { cause: probeError });
      }
      const writeResults = await withDeadline(1000, writes);
      if (writeResults.every((result) => result.status === "fulfilled")) {
        throw new Error("session receive limit allowed both writes to complete");
      }
      return false;
    }
    case "proxy_body": {
      const runtime = createProxyRuntime({ client });
      try {
        const error = await expectPromiseFailureWithin(
          proxyHTTP(runtime, new Uint8Array(1025), 0),
          1000,
          "proxy body limit",
        );
        if (!(error instanceof ProxyHTTPError) || error.code !== "request_body_too_large") {
          throw new Error(`proxy body limit returned ${errorMessage(error)}`, { cause: error });
        }
      } finally {
        runtime.dispose();
      }
      await rpcControl(client, 5);
      return false;
    }
    default:
      throw new Error(`unknown limit case ${name}`);
  }
}

async function settlesWithin(promise, milliseconds) {
  const marker = Symbol("timeout");
  const outcome = await Promise.race([
    promise.then(() => true, () => true),
    delay(milliseconds).then(() => marker),
  ]);
  return outcome !== marker;
}

async function expectPromiseFailureWithin(promise, milliseconds, label) {
  const marker = Symbol("timeout");
  const outcome = await Promise.race([
    promise.then(() => ({ ok: true }), (error) => ({ ok: false, error })),
    delay(milliseconds).then(() => marker),
  ]);
  if (outcome === marker) throw new Error(`${label} did not fail before the deadline`);
  if (outcome.ok) throw new Error(`${label} unexpectedly succeeded`);
  return outcome.error;
}

async function exerciseReconnect(command, metrics) {
  let nextArtifact = 0;
  const manager = createReconnectManager();
  const config = {
    connectOnce: async ({ signal, observer }) => {
      const artifact = command.reconnect_artifacts[nextArtifact];
      if (artifact == null) throw new Error("reconnect artifact sequence exhausted");
      nextArtifact += 1;
      const options = {
        origin: command.origin,
        transportSecurityPolicy: AllowPlaintextForLoopback,
        liveness: false,
        signal,
        observer,
      };
      return command.transport === "direct"
        ? await connectDirectNode(artifact.direct_info, options)
        : await connectTunnelNode(artifact.tunnel_grant, options);
    },
    autoReconnect: {
      enabled: true,
      maxAttempts: 1,
      initialDelayMs: 0,
      maxDelayMs: 0,
      factor: 1,
      jitterRatio: 0,
    },
  };
  try {
    await manager.connect(config);
    metrics.sessions += 1;
    for (let index = 0; index < command.workload.reconnect_cycles; index += 1) {
      const previous = manager.state().client;
      if (previous == null) throw new Error("reconnect manager has no connected client");
      await rpcControl(previous, 6);
      const connected = await waitForReconnectClient(manager, previous, command.deadline_ms);
      await rpcEcho(connected, index, false);
      metrics.sessions += 1;
      metrics.reconnects += 1;
    }
    const finalClient = manager.state().client;
    if (finalClient == null) throw new Error("reconnect manager lost the final client");
    await rpcControl(finalClient, 5);
    if (nextArtifact !== command.reconnect_artifacts.length) {
      throw new Error("reconnect artifact sequence was not consumed exactly");
    }
  } finally {
    manager.disconnect();
  }
}

async function waitForReconnectClient(manager, previous, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const state = manager.state();
    if (state.status === "error") throw state.error ?? new Error("reconnect manager failed");
    if (state.status === "connected" && state.client != null && state.client !== previous) return state.client;
    if (Date.now() >= deadline) throw new Error("reconnect deadline exceeded");
    await delay(1);
  }
}

async function exerciseStreams(client, workload, metrics) {
  await Promise.all(Array.from({ length: workload.concurrent }, async (_, index) => {
    const stream = await client.openStream("echo");
    const payload = new Uint8Array(workload.bytes_per_stream).fill(index % 251);
    for (let offset = 0; offset < payload.length; offset += workload.chunk_bytes) {
      const chunk = payload.subarray(offset, Math.min(payload.length, offset + workload.chunk_bytes));
      await stream.write(chunk);
      metrics.bytes_written += chunk.length;
    }
    if (index < workload.slow_readers) {
      await delay(25);
      metrics.slow_readers += 1;
    }
    const echoed = await readExactly(stream, payload.length);
    metrics.bytes_read += echoed.length;
    if (!equalBytes(payload, echoed)) throw new Error("echo payload mismatch");
    await stream.close();
    metrics.streams += 1;
  }));
  for (let index = 0; index < workload.churn; index += 1) {
    const stream = await client.openStream("churn");
    if (await stream.read() !== null) throw new Error("churn stream produced data before FIN");
    await stream.close();
    metrics.streams += 1;
  }
  for (let index = 0; index < workload.fin; index += 1) {
    const stream = await client.openStream("echo");
    await stream.close();
    if (await stream.read() !== null) throw new Error("FIN stream produced data after FIN");
    metrics.streams += 1;
    metrics.fins += 1;
  }
  for (let index = 0; index < workload.reset; index += 1) {
    const stream = await client.openStream("echo");
    await stream.reset();
    metrics.streams += 1;
    metrics.resets += 1;
  }
}

async function exerciseRPCSaturation(client, workload) {
  const total = workload.saturation_active + workload.saturation_queued + workload.saturation_rejected;
  const gate = await client.openStream(SATURATION_GATE_KIND);
  let gateReleased = false;
  let outcomes;
  try {
    outcomes = await Promise.all(Array.from({ length: total }, async () => {
      const outcome = await client.rpc.call(7, {});
      if (outcome.error?.code === 429 && !gateReleased) {
        gateReleased = true;
        await gate.write(new Uint8Array([1]));
        await gate.close();
      }
      return outcome;
    }));
  } finally {
    if (!gateReleased) await gate.reset(new Error("RPC saturation ended before queue rejection"));
  }
  let succeeded = 0;
  let rejected = 0;
  for (const outcome of outcomes) {
    if (outcome.error == null) {
      if (!isObject(outcome.payload) || outcome.payload.ok !== true) throw new Error("invalid saturation RPC response");
      succeeded += 1;
    } else if (outcome.error.code === 429) {
      rejected += 1;
    } else {
      throw new Error(`saturation RPC returned code ${outcome.error.code}`);
    }
  }
  if (succeeded !== workload.saturation_active + workload.saturation_queued || rejected !== workload.saturation_rejected) {
    throw new Error(`RPC saturation got ${succeeded} successes and ${rejected} rejections`);
  }
  return rejected;
}

async function exerciseProxy(client, workload, metrics) {
  const runtime = createProxyRuntime({ client });
  try {
    const body = new Uint8Array(workload.http_body_bytes).fill(0x70);
    for (let index = 0; index < workload.http_requests; index += 1) {
      const response = await proxyHTTP(runtime, body, index);
      if (response.status !== 200 || !equalBytes(response.body, body)) throw new Error("proxy HTTP response mismatch");
      metrics.http_requests += 1;
    }
    const opened = await runtime.openWebSocketStream("/ws");
    const reader = createByteReader(opened.stream);
    const payload = new Uint8Array(workload.websocket_frame_bytes).fill(0x77);
    for (let index = 0; index < workload.websocket_frames; index += 1) {
      await writeWSFrame(opened.stream, 1, payload);
      const frame = await readWSFrame(reader);
      if (frame.op !== 1 || !equalBytes(frame.payload, payload)) throw new Error("proxy WebSocket response mismatch");
      metrics.websocket_frames += 1;
    }
    await writeWSFrame(opened.stream, 8, new Uint8Array());
    await opened.stream.close();
  } finally {
    runtime.dispose();
  }
}

async function proxyHTTP(runtime, body, sequence) {
  const channel = new MessageChannel();
  const chunks = [];
  return await new Promise((resolve, reject) => {
    let status = 0;
    channel.port2.on("message", (message) => {
      if (message?.type === "flowersec-proxy:response_meta") {
        status = message.status;
        channel.port2.postMessage({ type: "flowersec-proxy:response_credit" });
        return;
      }
      if (message?.type === "flowersec-proxy:response_chunk") {
        chunks.push(new Uint8Array(message.data));
        channel.port2.postMessage({ type: "flowersec-proxy:response_credit" });
        return;
      }
      if (message?.type === "flowersec-proxy:response_end") {
        channel.port2.close();
        resolve({ status, body: concatBytes(chunks) });
        return;
      }
      if (message?.type === "flowersec-proxy:response_error") {
        channel.port2.close();
        reject(new ProxyHTTPError(message.status, message.code, message.message));
      }
    });
    channel.port2.on("messageerror", reject);
    runtime.dispatchFetch({ id: `typescript-${sequence}`, method: "POST", path: "/http", headers: [], body: body.buffer.slice(0) }, channel.port1);
  });
}

async function serve(command) {
  const controller = new AbortController();
  const supervisor = new Supervisor(controller, (error) => {
    process.stderr.write(`${JSON.stringify({ event: "task_failed", message: errorMessage(error), stack: asError(error).stack })}\n`);
  });
  let directServer;
  let session;
  try {
    if (command.transport === "direct") {
      const credential = command.direct_credential;
      directServer = new WebSocketServer({ host: "127.0.0.1", port: 0, perMessageDeflate: false });
      await once(directServer, "listening");
      const address = directServer.address();
      if (address == null || typeof address === "string") throw new Error("missing direct listener address");
      const sessionPromise = new Promise((resolve, reject) => {
        directServer.once("connection", (websocket) => {
          acceptDirectNode(websocket, {
            channelId: credential.channel_id,
            suite: credential.suite,
            psk: credential.e2ee_psk_b64u,
            initExpireAtUnixS: credential.init_expires_at_unix_s,
          }, {
            secureTransport: false,
            transportSecurityPolicy: AllowPlaintextForLoopback,
            yamuxLimits: serverYamuxLimits(command),
          })
            .then(resolve, reject);
        });
      });
      await emit({
        v: VERSION, event: "ready", request_id: command.request_id,
        direct_info: {
          ws_url: `ws://127.0.0.1:${address.port}`,
          channel_id: credential.channel_id,
          e2ee_psk_b64u: credential.e2ee_psk_b64u,
          channel_init_expire_at_unix_s: credential.init_expires_at_unix_s,
          default_suite: credential.suite,
        },
      });
      session = await sessionPromise;
    } else {
      const sessionPromise = connectTunnelEndpointNode(command.tunnel_grant, {
        origin: command.origin,
        transportSecurityPolicy: AllowPlaintextForLoopback,
        yamuxLimits: serverYamuxLimits(command),
        signal: controller.signal,
      });
      await emit({ v: VERSION, event: "ready", request_id: command.request_id });
      session = await sessionPromise;
    }
    const metrics = emptyMetrics();
    metrics.sessions = 1;
    supervisor.run(serveSession(session, command, controller.signal, metrics, supervisor));
    const stop = await Promise.race([readLine(), supervisor.waitForFailure()]);
    assertExactKeys(stop, ["v", "event", "request_id"]);
    if (stop.v !== VERSION || stop.event !== "stop" || stop.request_id !== command.request_id) throw new Error("invalid stop event");
    supervisor.stop(new Error("interop stop"));
    session.close();
    await supervisor.finish();
    await emit({ v: VERSION, event: "result", request_id: command.request_id, metrics, diagnostics: [] });
  } finally {
    supervisor.stop(new Error("interop server cleanup"));
    session?.close();
    if (directServer != null) await closeWebSocketServer(directServer);
  }
}

function serverYamuxLimits(command) {
  const required = command.workload.streams.concurrent + 1;
  const limits = { maxActiveStreams: Math.max(64, required), maxInboundStreams: Math.max(32, required) };
  if (command.limit_case === "inbound_streams") limits.maxInboundStreams = 1;
  if (command.limit_case === "frame") {
    limits.maxFrameBytes = 1024;
    limits.preferredOutboundFrameBytes = 1024;
  }
  if (command.limit_case === "session_receive") limits.maxSessionReceiveBytes = 256 * 1024;
  return limits;
}

async function serveSession(session, command, signal, metrics, supervisor) {
  const upstreamURL = command.upstream_url;
  const accepted = await session.acceptStream({ signal });
  if (accepted.kind !== "rpc") throw new Error("first stream must be RPC");
  const reader = createByteReader(accepted.stream, { signal });
  const router = new RpcRouter();
  let intentionalDisconnect = false;
  let releaseSaturation;
  let saturationGateSeen = false;
  const saturationReleased = new Promise((resolve) => { releaseSaturation = resolve; });
  const rpc = new RpcServer({
    readExactly: (length) => reader.readExactly(length),
    write: (bytes) => accepted.stream.write(bytes),
    close: (error) => {
      supervisor.run(accepted.stream.reset(asError(error)));
    },
  }, {
    maxConcurrentRequests: command.workload.rpc.saturation_active,
    maxQueuedRequests: command.workload.rpc.saturation_queued,
    maxQueuedNotifications: command.workload.rpc.saturation_queued,
  }, router);
  router.register(1, async (payload) => {
    assertObject(payload, "RPC payload");
    if (payload.notify === true) await rpc.notify(2, { hello: "world" });
    return { payload: { value: payload.value } };
  });
  router.register(3, async () => {
    await session.rekey();
    metrics.rekeys += 1;
    return { payload: { ok: true } };
  });
  router.register(4, async () => {
    await delay(100, signal);
    return { payload: { ok: true } };
  });
  router.register(5, async () => {
    intentionalDisconnect = true;
    return { payload: { ok: true } };
  });
  router.register(6, async () => {
    intentionalDisconnect = true;
    supervisor.run(delay(50, signal).then(() => session.close()));
    return { payload: { ok: true } };
  });
  router.register(7, async () => {
    await Promise.race([
      saturationReleased,
      waitForAbort(signal).then(() => { throw signal.reason ?? new Error("interop server stopped"); }),
    ]);
    return { payload: { ok: true } };
  });
  const rpcTask = rpc.serve(signal);
  let loopError;
  try {
    while (!signal.aborted) {
      let next;
      try {
        next = await Promise.race([
          session.acceptStream({ signal }),
          rpcTask.then(() => { throw new Error("RPC server stopped before the endpoint session"); }),
        ]);
      } catch (error) {
        if (intentionalDisconnect) break;
        if (error?.cause instanceof YamuxStreamResetError) {
          metrics.resets += 1;
          continue;
        }
        throw error;
      }
      if (next.kind === "echo") {
        await echo(next.stream, signal, metrics);
      } else if (next.kind === "churn") {
        await next.stream.close();
      } else if (next.kind === "hold") {
        await waitForAbort(signal);
      } else if (next.kind === SATURATION_GATE_KIND) {
        if (saturationGateSeen) throw new Error("duplicate RPC saturation gate stream");
        saturationGateSeen = true;
        const gateSignal = await createByteReader(next.stream, { signal }).readExactly(1);
        if (gateSignal[0] !== 1) throw new Error("invalid RPC saturation gate signal");
        releaseSaturation();
        await next.stream.close();
      } else if (next.kind === PROXY_KIND_HTTP1 || next.kind === PROXY_KIND_WS) {
        await serveProxyStream(next.kind, next.stream, {
          upstream: upstreamURL,
          upstreamOrigin: upstreamURL,
          ...(command.limit_case === "proxy_body" ? { maxBodyBytes: 1024 } : {}),
        }, signal);
      } else {
        await next.stream.reset(new Error(`unsupported stream kind ${next.kind}`));
        throw new Error(`unsupported stream kind ${next.kind}`);
      }
    }
  } catch (error) {
    loopError = error;
    throw error;
  } finally {
    rpc.close(new Error("interop server stopped"));
    const outcome = await Promise.allSettled([rpcTask]);
    if (loopError == null && !signal.aborted && !intentionalDisconnect && outcome[0].status === "rejected") throw outcome[0].reason;
  }
}

async function waitForAbort(signal) {
  if (signal.aborted) return;
  await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
}

async function echo(stream, signal, metrics) {
  try {
    while (!signal.aborted) {
      const payload = await stream.read();
      if (payload == null) break;
      await stream.write(payload);
      metrics.bytes_read += payload.length;
      metrics.bytes_written += payload.length;
    }
    await stream.close();
  } catch (error) {
    if (error instanceof YamuxStreamResetError) return;
    if (signal.aborted) return;
    let resetError;
    try { await stream.reset(asError(error)); } catch (value) { resetError = value; }
    throw resetError == null ? error : new AggregateError([error, resetError], "echo and reset failed");
  }
}

async function rpcEcho(client, value, notify) {
  const response = await client.rpc.call(1, { value, notify });
  if (response.error != null || !isObject(response.payload) || response.payload.value !== value) throw new Error("invalid RPC echo response");
}

async function rpcControl(client, typeId) {
  const response = await client.rpc.call(typeId, {});
  if (response.error != null) throw new Error(`control RPC failed: ${response.error.code}`);
}

async function readExactly(stream, length) {
  const output = new Uint8Array(length);
  let offset = 0;
  while (offset < length) {
    const chunk = await stream.read();
    if (chunk == null) throw new Error("stream reached EOF before expected payload");
    if (chunk.length > length - offset) throw new Error("stream returned more data than expected");
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

async function writeWSFrame(stream, op, payload) {
  const header = new Uint8Array(5);
  header[0] = op;
  new DataView(header.buffer).setUint32(1, payload.length, false);
  await stream.write(header);
  if (payload.length > 0) await stream.write(payload);
}

async function readWSFrame(reader) {
  const header = await reader.readExactly(5);
  const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(1, false);
  return { op: header[0], payload: length === 0 ? new Uint8Array() : await reader.readExactly(length) };
}

async function readLine() {
  const next = await lines.next();
  if (next.done) throw new Error("protocol stdin reached EOF");
  let value;
  try { value = JSON.parse(next.value); } catch (error) { throw new Error(`invalid protocol JSON: ${errorMessage(error)}`); }
  assertObject(value, "protocol event");
  return value;
}

async function emit(value) {
  const line = JSON.stringify(value);
  await new Promise((resolve, reject) => process.stdout.write(`${line}\n`, (error) => error == null ? resolve() : reject(error)));
}

function assertExactKeys(value, required, optional = []) {
  assertObject(value, "object");
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new Error(`unknown field ${key}`);
  for (const key of required) if (!(key in value)) throw new Error(`missing field ${key}`);
}

function assertObject(value, label) {
  if (!isObject(value)) throw new Error(`${label} must be an object`);
}
function isObject(value) { return value != null && typeof value === "object" && !Array.isArray(value); }
function asError(value) { return value instanceof Error ? value : new Error(String(value)); }
function errorMessage(value) { return asError(value).message; }
function equalBytes(left, right) { return left.length === right.length && left.every((value, index) => value === right[index]); }
function concatBytes(chunks) {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}
function emptyMetrics() {
  return {
    sessions: 0, rekeys: 0, streams: 0, slow_readers: 0, fins: 0, resets: 0, bytes_written: 0, bytes_read: 0,
    rpc_calls: 0, rpc_notifications: 0, rpc_cancellations: 0, rpc_timeouts: 0,
    rpc_queue_rejections: 0, limit_checks: 0, backpressure_checks: 0,
    http_requests: 0, websocket_frames: 0, reconnects: 0, liveness_probes: 0,
    resource_rejections: 0,
  };
}
async function expectRejected(promise, label) {
  try { await promise; } catch { return; }
  throw new Error(`${label} unexpectedly succeeded`);
}

class ProxyHTTPError extends Error {
  constructor(status, code, message) {
    super(`proxy HTTP error ${status}${code == null ? "" : ` (${code})`}: ${message}`);
    this.name = "ProxyHTTPError";
    this.status = status;
    this.code = code;
  }
}

function diagnosticFor(caseName, path) {
  const contract = DIAGNOSTIC_CONTRACTS.get(caseName);
  if (contract == null) throw new Error(`unknown diagnostic case ${caseName}`);
  return { case: caseName, path, stage: contract[0], code: contract[1] };
}
async function waitUntil(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("notification deadline exceeded");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}
async function delay(milliseconds, signal) {
  if (signal == null) {
    await new Promise((resolve) => setTimeout(resolve, milliseconds));
    return;
  }
  if (signal.aborted) throw signal.reason;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener("abort", () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
  });
}
async function withDeadline(milliseconds, promise) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("harness deadline exceeded")), milliseconds); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function closeWebSocketServer(server) {
  for (const client of server.clients) client.terminate();
  await new Promise((resolve, reject) => server.close((error) => error == null ? resolve() : reject(error)));
}

await main();
