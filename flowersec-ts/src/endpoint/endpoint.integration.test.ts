import { createServer } from "node:http";
import { once } from "node:events";
import { WebSocketServer } from "ws";
import { afterEach, describe, expect, test } from "vitest";

import { AllowPlaintextForLoopback } from "../client-connect/transportSecurity.js";
import { connectDirectNode } from "../node/connect.js";
import { RpcRouter } from "../rpc/server.js";
import { base64urlEncode } from "../utils/base64url.js";
import { acceptDirectResolvedNode } from "./node.js";

describe("Node endpoint", () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  });

  test("accepts a resolved direct session and serves RPC", async () => {
    const psk = crypto.getRandomValues(new Uint8Array(32));
    const channelId = "endpoint-direct-integration";
    const expiresAt = Math.floor(Date.now() / 1000) + 60;
    const httpServer = createServer();
    const websocketServer = new WebSocketServer({ server: httpServer, perMessageDeflate: false });
    httpServer.listen(0, "127.0.0.1");
    await once(httpServer, "listening");
    const address = httpServer.address();
    if (address == null || typeof address === "string") throw new Error("missing listen address");

    cleanups.push(async () => {
      websocketServer.close();
      httpServer.close();
      await Promise.allSettled([once(websocketServer, "close"), once(httpServer, "close")]);
    });

    let committed = false;
    const serverReady = new Promise<void>((resolve, reject) => {
      websocketServer.once("connection", (websocket) => {
        void (async () => {
          const session = await acceptDirectResolvedNode(
            websocket,
            async (init) => {
              expect(init.channelId).toBe(channelId);
              expect(init.suite).toBe(1);
              return {
                psk,
                initExpireAtUnixS: expiresAt,
                commitAuthenticated: () => { committed = true; },
              };
            },
            { secureTransport: false, transportSecurityPolicy: AllowPlaintextForLoopback },
          );
          expect(committed).toBe(true);
          const router = new RpcRouter();
          router.register(41, async (payload) => ({ payload: { ...(payload as object), ok: true } }));
          resolve();
          await session.serveRPC(router);
        })().catch(reject);
      });
    });

    const client = await connectDirectNode(
      {
        ws_url: `ws://127.0.0.1:${address.port}`,
        channel_id: channelId,
        e2ee_psk_b64u: base64urlEncode(psk),
        channel_init_expire_at_unix_s: expiresAt,
        default_suite: 1,
      },
      { origin: "http://127.0.0.1", transportSecurityPolicy: AllowPlaintextForLoopback },
    );
    await serverReady;
    const response = await client.rpc.call(41, { value: "hello" });
    expect(response).toEqual({ payload: { value: "hello", ok: true } });
    client.close();
  });
});
