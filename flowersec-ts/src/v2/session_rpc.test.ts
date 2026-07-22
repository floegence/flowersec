import { describe, expect, test } from "vitest";

import { RpcRouter } from "../rpc/server.js";
import { createMemoryCarrierPairV2 } from "./carrier.js";
import { CipherSuiteV2 } from "./protocol.js";
import { establishSessionV2, type SessionConfigV2 } from "./session.js";

function config(role: "client" | "server", rpcRouter: RpcRouter, maxInboundStreams = 4): SessionConfigV2 {
  return {
    role,
    path: "direct",
    channelID: "session-v2-rpc",
    sessionContractHash: new Uint8Array(32).fill(1),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(2),
    maxInboundStreams,
    localAdmissionBinding: new Uint8Array(32).fill(3),
    peerAdmissionBinding: new Uint8Array(32).fill(3),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    rpcRouter,
  };
}

describe("SessionV2 reserved RPC stream", () => {
  test("lets both peers actively call and notify with numeric type IDs", async () => {
    const clientRouter = new RpcRouter();
    const serverRouter = new RpcRouter();
    clientRouter.register(8, async (payload) => ({ payload: { from: "client", payload } }));
    serverRouter.register(7, async (payload) => ({ payload: { from: "server", payload } }));
    let notified: unknown;
    const notification = new Promise<void>((resolve) => {
      serverRouter.register(9, async (payload) => {
        notified = payload;
        resolve();
        return { payload: null };
      });
    });

    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "websocket", path: "direct", inboundBidirectionalStreamCapacity: 6 });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", clientRouter)),
      establishSessionV2(serverCarrier, config("server", serverRouter)),
    ]);

    await expect(client.rpc.call(7, { value: 1 })).resolves.toEqual({
      payload: { from: "server", payload: { value: 1 } },
    });
    await expect(server.rpc.call(8, { value: 2 })).resolves.toEqual({
      payload: { from: "client", payload: { value: 2 } },
    });
    await client.rpc.notify(9, { event: "ready" });
    await notification;
    expect(notified).toEqual({ event: "ready" });
    await client.close();
  });

  test("keeps the role-owned control slot and both RPC directions usable when N=1", async () => {
    const clientRouter = new RpcRouter();
    const serverRouter = new RpcRouter();
    clientRouter.register(8, async (payload) => ({ payload }));
    serverRouter.register(7, async (payload) => ({ payload }));
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 3 });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client", clientRouter, 1)),
      establishSessionV2(serverCarrier, config("server", serverRouter, 1)),
    ]);

    const opening = client.openStream("only-application-slot");
    const incoming = await server.acceptStream();
    const stream = await opening;
    await expect(client.rpc.call(7, { side: "client" })).resolves.toEqual({ payload: { side: "client" } });
    await expect(server.rpc.call(8, { side: "server" })).resolves.toEqual({ payload: { side: "server" } });
    await stream.write(Uint8Array.of(1));
    expect(await incoming.stream.read()).toEqual(Uint8Array.of(1));
    expect(await client.probeLiveness()).toBeGreaterThanOrEqual(0);
    await client.close();
  });
});
