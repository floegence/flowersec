import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { WebSocketServer } from "ws";
import { afterEach, describe, expect, test } from "vitest";

import { AllowPlaintextForLoopback } from "../client-connect/transportSecurity.js";
import { acceptDirectNode } from "../endpoint/node.js";
import { readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { connectDirectNode } from "../node/connect.js";
import { createByteReader } from "../streamio/index.js";
import { base64urlEncode } from "../utils/base64url.js";
import { readU32be, u32be } from "../utils/bin.js";
import { PROXY_KIND_HTTP1, PROXY_KIND_WS } from "./constants.js";
import { serveProxySession } from "./server.js";
import type { HttpResponseMetaV1 } from "./types.js";

describe("Node proxy server", () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  });

  test("proxies HTTP over a direct Flowersec endpoint", async () => {
    const upstream = createServer((request, response) => {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ method: request.method, url: request.url }));
    });
    const upstreamPort = await listen(upstream);
    cleanups.push(() => closeHTTP(upstream));

    const directHTTP = createServer();
    const directWS = new WebSocketServer({ server: directHTTP, perMessageDeflate: false });
    const directPort = await listen(directHTTP);
    cleanups.push(async () => {
      await closeWebSocketServer(directWS);
      await closeHTTP(directHTTP);
    });

    const psk = crypto.getRandomValues(new Uint8Array(32));
    const expiresAt = Math.floor(Date.now() / 1000) + 60;
    directWS.on("connection", (websocket) => {
      void acceptDirectNode(
        websocket,
        { channelId: "proxy-direct", suite: 1, psk, initExpireAtUnixS: expiresAt },
        { secureTransport: false, transportSecurityPolicy: AllowPlaintextForLoopback },
      ).then((session) => serveProxySession(session, {
        upstream: `http://127.0.0.1:${upstreamPort}`,
        allowedUpstreamHosts: ["127.0.0.1"],
      })).catch(() => {});
    });

    const client = await connectDirectNode(
      {
        ws_url: `ws://127.0.0.1:${directPort}`,
        channel_id: "proxy-direct",
        e2ee_psk_b64u: base64urlEncode(psk),
        channel_init_expire_at_unix_s: expiresAt,
        default_suite: 1,
      },
      { origin: "http://127.0.0.1", transportSecurityPolicy: AllowPlaintextForLoopback },
    );
    const stream = await client.openStream(PROXY_KIND_HTTP1);
    const reader = createByteReader(stream);
    await writeJsonFrame(stream, {
      v: 1,
      request_id: "request-1",
      method: "GET",
      path: "/health?full=1",
      headers: [{ name: "accept", value: "application/json" }],
    });
    await stream.write(u32be(0));

    const meta = await readJsonFrame(reader, 1024 * 1024) as HttpResponseMetaV1;
    expect(meta.ok).toBe(true);
    expect(meta.status).toBe(200);
    const length = readU32be(await reader.readExactly(4), 0);
    const body = JSON.parse(new TextDecoder().decode(await reader.readExactly(length)));
    expect(body).toEqual({ method: "GET", url: "/health?full=1" });
    expect(readU32be(await reader.readExactly(4), 0)).toBe(0);
    client.close();
  });

  test("proxies WebSocket frames over a direct Flowersec endpoint", async () => {
    const upstreamHTTP = createServer();
    const upstreamWS = new WebSocketServer({ server: upstreamHTTP, perMessageDeflate: false });
    const greeting = new TextEncoder().encode("server greeting");
    upstreamWS.on("connection", (websocket) => {
      websocket.send(greeting, { binary: true });
      websocket.on("message", (data, isBinary) => websocket.send(data, { binary: isBinary }));
    });
    const upstreamPort = await listen(upstreamHTTP);
    cleanups.push(async () => {
      await closeWebSocketServer(upstreamWS);
      await closeHTTP(upstreamHTTP);
    });

    const directHTTP = createServer();
    const directWS = new WebSocketServer({ server: directHTTP, perMessageDeflate: false });
    const directPort = await listen(directHTTP);
    cleanups.push(async () => {
      await closeWebSocketServer(directWS);
      await closeHTTP(directHTTP);
    });

    const psk = crypto.getRandomValues(new Uint8Array(32));
    const expiresAt = Math.floor(Date.now() / 1000) + 60;
    directWS.on("connection", (websocket) => {
      void acceptDirectNode(
        websocket,
        { channelId: "proxy-ws-direct", suite: 1, psk, initExpireAtUnixS: expiresAt },
        { secureTransport: false, transportSecurityPolicy: AllowPlaintextForLoopback },
      ).then((session) => serveProxySession(session, {
        upstream: `http://127.0.0.1:${upstreamPort}`,
        allowedUpstreamHosts: ["127.0.0.1"],
      })).catch(() => {});
    });

    const client = await connectDirectNode(
      {
        ws_url: `ws://127.0.0.1:${directPort}`,
        channel_id: "proxy-ws-direct",
        e2ee_psk_b64u: base64urlEncode(psk),
        channel_init_expire_at_unix_s: expiresAt,
        default_suite: 1,
      },
      { origin: "http://127.0.0.1", transportSecurityPolicy: AllowPlaintextForLoopback },
    );
    const stream = await client.openStream(PROXY_KIND_WS);
    const reader = createByteReader(stream);
    await writeJsonFrame(stream, { v: 1, conn_id: "ws-1", path: "/echo", headers: [] });
    expect(await readJsonFrame(reader, 1024 * 1024)).toMatchObject({ v: 1, conn_id: "ws-1", ok: true });

    const greetingHeader = await reader.readExactly(5);
    expect(greetingHeader[0]).toBe(2);
    const greetingLength = readU32be(greetingHeader, 1);
    expect(await reader.readExactly(greetingLength)).toEqual(greeting);

    const payload = new TextEncoder().encode("hello websocket");
    const frame = new Uint8Array(5 + payload.length);
    frame[0] = 2;
    frame.set(u32be(payload.length), 1);
    frame.set(payload, 5);
    await stream.write(frame);
    const responseHeader = await reader.readExactly(5);
    expect(responseHeader[0]).toBe(2);
    const responseLength = readU32be(responseHeader, 1);
    expect(new TextDecoder().decode(await reader.readExactly(responseLength))).toBe("hello websocket");

    const closeReason = new TextEncoder().encode("done");
    const closePayload = new Uint8Array(2 + closeReason.length);
    closePayload[0] = 0x03;
    closePayload[1] = 0xe8;
    closePayload.set(closeReason, 2);
    const closeFrame = new Uint8Array(5 + closePayload.length);
    closeFrame[0] = 8;
    closeFrame.set(u32be(closePayload.length), 1);
    closeFrame.set(closePayload, 5);
    await stream.write(closeFrame);

    const closeResponseHeader = await reader.readExactly(5);
    expect(closeResponseHeader[0]).toBe(8);
    const closeResponseLength = readU32be(closeResponseHeader, 1);
    const closeResponse = await reader.readExactly(closeResponseLength);
    expect((closeResponse[0]! << 8) | closeResponse[1]!).toBe(1000);
    expect(new TextDecoder().decode(closeResponse.subarray(2))).toBe("done");
    client.close();
  });
});

async function listen(server: Server): Promise<number> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address == null || typeof address === "string") throw new Error("missing listen address");
  return address.port;
}

function closeHTTP(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function closeWebSocketServer(server: WebSocketServer): Promise<void> {
  for (const client of server.clients) client.terminate();
  return new Promise((resolve) => server.close(() => resolve()));
}
