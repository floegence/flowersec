import { createRequire } from "node:module";
import { once } from "node:events";
import { createServer } from "node:http";

import { describe, expect, test } from "vitest";

import { createNodeWsFactory } from "./wsFactory.js";

const require = createRequire(import.meta.url);
const wsMod = require("ws") as any;
const WebSocketServerCtor = wsMod?.WebSocketServer ?? wsMod?.Server;

describe("createNodeWsFactory", () => {
  test.each(["flowersec.direct.v2", "flowersec.tunnel.v2"])("negotiates the %s subprotocol", async (subprotocol) => {
    const server = createServer();
    const wss = new WebSocketServerCtor({ server, handleProtocols: (protocols: Set<string>) => protocols.has(subprotocol) ? subprotocol : false });
    server.listen(0);
    await once(server, "listening");
    const addr = server.address();
    const port = typeof addr === "object" && addr != null ? addr.port : 0;
    if (!port) throw new Error("http server did not start");
    const accepted = new Promise<string>((resolve) => wss.once("connection", (socket: any) => resolve(socket.protocol)));

    const ws = createNodeWsFactory()(`ws://127.0.0.1:${port}`, "https://app.example", subprotocol);
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", resolve);
      ws.addEventListener("error", reject);
    });
    expect(await accepted).toBe(subprotocol);

    ws.close();
    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("sets Origin header", async () => {
    const origin = "http://example.com";
    const server = createServer();
    const wss = new WebSocketServerCtor({ server });
    server.listen(0);
    await once(server, "listening");
    const addr = server.address();
    const port = typeof addr === "object" && addr != null ? addr.port : 0;
    if (!port) throw new Error("http server did not start");

    const gotOrigin = new Promise<string | undefined>((resolve) => {
      wss.once("connection", (_ws: any, req: any) => {
        resolve(req?.headers?.origin as string | undefined);
      });
    });

    const wsFactory = createNodeWsFactory();
    const ws = wsFactory(`ws://127.0.0.1:${port}`, origin);

    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => resolve());
      ws.addEventListener("error", (e) => reject(e));
    });

    expect(await gotOrigin).toBe(origin);

    ws.close();
    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("disables perMessageDeflate by default", async () => {
    const origin = "http://example.com";
    const server = createServer();
    const wss = new WebSocketServerCtor({ server });
    server.listen(0);
    await once(server, "listening");
    const addr = server.address();
    const port = typeof addr === "object" && addr != null ? addr.port : 0;
    if (!port) throw new Error("http server did not start");

    const gotExt = new Promise<string | undefined>((resolve) => {
      wss.once("connection", (_ws: any, req: any) => {
        resolve(req?.headers?.["sec-websocket-extensions"] as string | undefined);
      });
    });

    const wsFactory = createNodeWsFactory();
    const ws = wsFactory(`ws://127.0.0.1:${port}`, origin);

    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => resolve());
      ws.addEventListener("error", (e) => reject(e));
    });

    expect(await gotExt).toBeUndefined();

    ws.close();
    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("enforces maxPayload by default (defense-in-depth)", async () => {
    const origin = "http://example.com";
    const server = createServer();
    const wss = new WebSocketServerCtor({ server });
    server.listen(0);
    await once(server, "listening");
    const addr = server.address();
    const port = typeof addr === "object" && addr != null ? addr.port : 0;
    if (!port) throw new Error("http server did not start");

    wss.once("connection", (sock: any) => {
      sock.send(Buffer.alloc(2 * 1024 * 1024));
    });

    const wsFactory = createNodeWsFactory();
    const ws = wsFactory(`ws://127.0.0.1:${port}`, origin);

    const closedPromise = new Promise<{ code?: number }>((resolve) => {
      ws.addEventListener("close", (e: any) => resolve(e));
    });
    // Protocol rejection can emit an error before or alongside close.
    ws.addEventListener("error", () => {});
    const closed = await closedPromise;
    // "ws" may terminate the connection rather than completing a clean close handshake.
    // Accept both normal "message too big" and abnormal closure codes.
    expect([1006, 1009]).toContain(closed.code);

    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  test("enforces maxPayload", async () => {
    const origin = "http://example.com";
    const server = createServer();
    const wss = new WebSocketServerCtor({ server });
    server.listen(0);
    await once(server, "listening");
    const addr = server.address();
    const port = typeof addr === "object" && addr != null ? addr.port : 0;
    if (!port) throw new Error("http server did not start");

    wss.once("connection", (sock: any) => {
      sock.send(Buffer.alloc(64));
    });

    const wsFactory = createNodeWsFactory({ maxPayload: 32 });
    const ws = wsFactory(`ws://127.0.0.1:${port}`, origin);

    const closedPromise = new Promise<{ code?: number }>((resolve) => {
      ws.addEventListener("close", (e: any) => resolve(e));
    });
    // Protocol rejection can emit an error before or alongside close.
    ws.addEventListener("error", () => {});
    const closed = await closedPromise;
    // "ws" may terminate the connection rather than completing a clean close handshake.
    // Accept both normal "message too big" and abnormal closure codes.
    expect([1006, 1009]).toContain(closed.code);

    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});
