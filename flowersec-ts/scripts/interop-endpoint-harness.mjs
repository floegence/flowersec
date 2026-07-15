import crypto from "node:crypto";
import http from "node:http";
import { WebSocketServer } from "ws";

import {
  acceptDirectNode,
  AllowPlaintextForLoopback,
  connectTunnelEndpointNode,
  serveProxyStream,
} from "../dist/node/index.js";
import { PROXY_KIND_HTTP1, PROXY_KIND_WS } from "../dist/proxy/constants.js";
import { RpcRouter, RpcServer } from "../dist/rpc/server.js";
import { createByteReader } from "../dist/streamio/index.js";

const psk = crypto.randomBytes(32);
const channelId = "typescript-interop-endpoint";
const expires = Math.floor(Date.now() / 1000) + 300;

const upstream = http.createServer((_request, response) => {
  response.writeHead(200, { "content-type": "text/plain" });
  response.end("flowersec-typescript-proxy-ok");
});
const upstreamWebSocket = new WebSocketServer({ server: upstream });
upstreamWebSocket.on("connection", (websocket) => {
  websocket.on("message", (payload, binary) => {
    websocket.send(payload, { binary });
  });
});
await listen(upstream);
const upstreamAddress = upstream.address();
if (upstreamAddress == null || typeof upstreamAddress === "string") throw new Error("missing upstream address");
const upstreamURL = `http://127.0.0.1:${upstreamAddress.port}`;

const tunnelGrant = argument("--tunnel-grant-json");
if (tunnelGrant != null) {
  process.stdout.write(`${JSON.stringify({ v: 1, event: "attaching" })}\n`);
  const session = await connectTunnelEndpointNode(JSON.parse(tunnelGrant), {
    origin: "https://app.redeven.com",
    transportSecurityPolicy: AllowPlaintextForLoopback,
  });
  await serveSession(session);
} else {
  const direct = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  await new Promise((resolve, reject) => {
    direct.once("listening", resolve);
    direct.once("error", reject);
  });
  const directAddress = direct.address();
  if (typeof directAddress === "string") throw new Error("missing direct address");

  direct.on("connection", (websocket) => {
    void serveConnection(websocket).catch((error) => {
      if (!String(error).includes("websocket closed")) {
        process.stderr.write(`TypeScript interop session failed: ${String(error)}\n`);
      }
      websocket.close();
    });
  });

  process.stdout.write(`${JSON.stringify({
    v: 1,
    event: "ready",
    direct_info: {
      ws_url: `ws://127.0.0.1:${directAddress.port}/flowersec`,
      channel_id: channelId,
      e2ee_psk_b64u: psk.toString("base64url"),
      channel_init_expire_at_unix_s: expires,
      default_suite: 1,
    },
  })}\n`);
}

async function serveConnection(websocket) {
  const session = await acceptDirectNode(websocket, {
    channelId,
    suite: 1,
    psk,
    initExpireAtUnixS: expires,
  }, { secureTransport: false, transportSecurityPolicy: AllowPlaintextForLoopback });

  await serveSession(session);
}

async function serveSession(session) {
  const accepted = await session.acceptStream();
  if (accepted.kind !== "rpc") throw new Error("first stream is not RPC");
  const reader = createByteReader(accepted.stream);
  const router = new RpcRouter();
  const rpc = new RpcServer({
    readExactly: (length) => reader.readExactly(length),
    write: (bytes) => accepted.stream.write(bytes),
    close: (error) => { void accepted.stream.reset(asError(error)); },
  }, {}, router);
  router.register(1, async () => {
    await rpc.notify(2, { hello: "world" });
    return { payload: { ok: true } };
  });
  void rpc.serve().catch(() => {});

  while (true) {
    const next = await session.acceptStream();
    if (next.kind === "echo") {
      void echo(next.stream);
      continue;
    }
    if (next.kind === PROXY_KIND_HTTP1 || next.kind === PROXY_KIND_WS) {
      void serveProxyStream(next.kind, next.stream, {
        upstream: upstreamURL,
        upstreamOrigin: upstreamURL,
      });
      continue;
    }
    await next.stream.reset(new Error(`unsupported stream kind ${next.kind}`));
  }
}

function argument(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1] ?? null;
}

async function echo(stream) {
  try {
    while (true) {
      const payload = await stream.read();
      if (payload == null) break;
      await stream.write(payload);
    }
    await stream.close();
  } catch {
    try { await stream.reset(new Error("echo failed")); } catch {}
  }
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function asError(error) {
  return error instanceof Error ? error : new Error(String(error));
}
