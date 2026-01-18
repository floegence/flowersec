import { describe, expect, test } from "vitest";
import { clientHandshake, serverHandshake, ServerHandshakeCache, type HandshakeClientOptions, type HandshakeServerOptions } from "./handshake.js";

type BinaryTransport = {
  readBinary(): Promise<Uint8Array>;
  writeBinary(frame: Uint8Array): Promise<void>;
  close(): void;
};

function createBinaryTransportPair(): { client: BinaryTransport; server: BinaryTransport } {
  type Waiter = { resolve: (b: Uint8Array) => void; reject: (e: unknown) => void };
  const left: { q: Uint8Array[]; waiters: Waiter[]; closed: boolean } = {
    q: [],
    waiters: [],
    closed: false
  };
  const right: { q: Uint8Array[]; waiters: Waiter[]; closed: boolean } = {
    q: [],
    waiters: [],
    closed: false
  };

  const make = (self: typeof left, peer: typeof right): BinaryTransport => ({
    async readBinary() {
      if (self.closed) throw new Error("closed");
      const b = self.q.shift();
      if (b != null) return b;
      return await new Promise<Uint8Array>((resolve, reject) => {
        if (self.closed) {
          reject(new Error("closed"));
          return;
        }
        self.waiters.push({ resolve, reject });
      });
    },
    async writeBinary(frame: Uint8Array) {
      if (self.closed) throw new Error("closed");
      if (peer.closed) throw new Error("peer closed");
      const w = peer.waiters.shift();
      if (w != null) {
        w.resolve(frame);
        return;
      }
      peer.q.push(frame);
    },
    close() {
      if (self.closed) return;
      self.closed = true;
      const ws = self.waiters;
      self.waiters = [];
      for (const w of ws) w.reject(new Error("closed"));
    }
  });

  return { client: make(left, right), server: make(right, left) };
}

describe("handshake server-finished ping", () => {
  test("aligns post-handshake record sequences", async () => {
    const pair = createBinaryTransportPair();
    const channelId = "chan_finished_test";
    const suite = 1 as const;
    const psk = new Uint8Array(32).fill(7);
    const now = Math.floor(Date.now() / 1000);

    const clientOpts: HandshakeClientOptions = {
      channelId,
      suite,
      psk,
      clientFeatures: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    };
    const serverOpts: HandshakeServerOptions = {
      channelId,
      suite,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: now + 60,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    };

    const cache = new ServerHandshakeCache();
    const serverPromise = serverHandshake(pair.server, cache, serverOpts);
    const client = await clientHandshake(pair.client, clientOpts);
    const server = await serverPromise;

    try {
      const serverMsg = new Uint8Array([1, 2, 3, 4]);
      await server.write(serverMsg);
      const gotServer = await client.read();
      expect(Array.from(gotServer)).toEqual(Array.from(serverMsg));

      const clientMsg = new Uint8Array([9, 8, 7]);
      await client.write(clientMsg);
      const gotClient = await server.read();
      expect(Array.from(gotClient)).toEqual(Array.from(clientMsg));
    } finally {
      client.close();
      server.close();
    }
  });
});
