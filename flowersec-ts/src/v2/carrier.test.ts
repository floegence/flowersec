import { describe, expect, test } from "vitest";

import {
  createMemoryCarrierPairV2,
  createWebSocketCarrierSessionV2,
  type WebSocketBinaryTransportV2,
} from "./carrier.js";

describe("transport v2 carrier contract", () => {
  test("opens independent bidirectional streams with half-close and isolated reset", async () => {
    const [client, server] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 3 });
    const firstClient = await client.openStream();
    const secondClient = await client.openStream();
    const firstServer = await server.acceptStream();
    const secondServer = await server.acceptStream();

    await firstClient.write(Uint8Array.of(1, 2, 3));
    expect(await firstServer.read()).toEqual(Uint8Array.of(1, 2, 3));
    await firstClient.closeWrite();
    expect(await firstServer.read()).toBeNull();
    await firstServer.write(Uint8Array.of(4));
    expect(await firstClient.read()).toEqual(Uint8Array.of(4));

    await firstClient.reset();
    await expect(firstServer.read()).rejects.toThrow("reset");
    await secondClient.write(Uint8Array.of(9));
    expect(await secondServer.read()).toEqual(Uint8Array.of(9));
    await client.close();
    await expect(server.acceptStream()).rejects.toThrow("closed");
  });

  test("canceled accepts do not consume the next stream", async () => {
    const [client, server] = createMemoryCarrierPairV2({ kind: "websocket", path: "tunnel", inboundBidirectionalStreamCapacity: 3 });
    const controller = new AbortController();
    const canceled = server.acceptStream({ signal: controller.signal });
    controller.abort();
    await expect(canceled).rejects.toThrow("aborted");

    const opened = await client.openStream();
    const accepted = await server.acceptStream();
    await opened.write(Uint8Array.of(7));
    expect(await accepted.read()).toEqual(Uint8Array.of(7));
    await server.close();
  });

  test("binds WSS Yamux to the exact three physical N=1 slots and releases capacity after reset", async () => {
    const [clientBinary, serverBinary] = binaryPair();
    const client = createWebSocketCarrierSessionV2(clientBinary, {
      path: "direct",
      client: true,
      inboundBidirectionalStreamCapacity: 3,
      resourcePolicy: { maxConcurrentStreams: 8 },
    });
    const server = createWebSocketCarrierSessionV2(serverBinary, {
      path: "direct",
      client: false,
      inboundBidirectionalStreamCapacity: 3,
      resourcePolicy: { maxConcurrentStreams: 8 },
    });
    const first = await client.openStream();
    const second = await client.openStream();
    const third = await client.openStream();
    const accepted = await server.acceptStream();
    await server.acceptStream();
    await server.acceptStream();
    const rejected = await client.openStream();
    await expect(rejected.write(Uint8Array.of(2))).rejects.toThrow();
    await first.reset();
    await accepted.reset();
    const replacement = await client.openStream();
    const replacementAccepted = await server.acceptStream();
    await replacement.write(Uint8Array.of(4));
    expect(await replacementAccepted.read()).toEqual(Uint8Array.of(4));
    await second.reset();
    await third.reset();
    await client.close();
  });
});

class BinaryEndpoint implements WebSocketBinaryTransportV2 {
  peer: BinaryEndpoint | undefined;
  private readonly values: Uint8Array[] = [];
  private readonly waiters: Array<(value: Uint8Array) => void> = [];
  private error: Error | undefined;

  async readBinary(): Promise<Uint8Array> {
    if (this.error !== undefined) throw this.error;
    const value = this.values.shift();
    return value ?? await new Promise<Uint8Array>((resolve) => this.waiters.push(resolve));
  }

  async writeBinary(data: Uint8Array): Promise<void> {
    if (this.error !== undefined) throw this.error;
    this.peer?.push(data.slice());
  }

  close(): void {
    this.error = new Error("binary transport closed");
    if (this.peer !== undefined) this.peer.error = new Error("binary transport closed by peer");
  }

  private push(value: Uint8Array): void {
    const waiter = this.waiters.shift();
    if (waiter !== undefined) waiter(value);
    else this.values.push(value);
  }
}

function binaryPair(): readonly [BinaryEndpoint, BinaryEndpoint] {
  const left = new BinaryEndpoint();
  const right = new BinaryEndpoint();
  left.peer = right;
  right.peer = left;
  return [left, right];
}
