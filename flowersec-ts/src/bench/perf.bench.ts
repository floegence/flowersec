import { bench, describe } from "vitest";
import { clientHandshake, serverHandshake, ServerHandshakeCache } from "../e2ee/handshake.js";
import { encryptRecord, decryptRecord } from "../e2ee/record.js";
import { RECORD_FLAG_APP } from "../e2ee/constants.js";
import { YamuxSession, type ByteDuplex } from "../yamux/session.js";

type BinaryTransport = {
  readBinary(): Promise<Uint8Array>;
  writeBinary(frame: Uint8Array): Promise<void>;
  close(): void;
};

type InMemoryLink = {
  read(): Promise<Uint8Array>;
  write(chunk: Uint8Array): Promise<void>;
  close(): void;
  attach(peer: InMemoryLink): void;
  enqueue(chunk: Uint8Array): void;
  isClosed(): boolean;
};

function createInMemoryLink(): InMemoryLink {
  let peer: InMemoryLink | null = null;
  let closed = false;
  let error: Error | null = null;
  const queue: Uint8Array[] = [];
  const waiters: Array<{ resolve: (b: Uint8Array) => void; reject: (e: Error) => void }> = [];

  const fail = (err: Error) => {
    if (error != null) return;
    error = err;
    closed = true;
    const ws = waiters.splice(0, waiters.length);
    for (const w of ws) w.reject(err);
  };

  return {
    attach(next: InMemoryLink) {
      peer = next;
    },
    isClosed() {
      return closed;
    },
    enqueue(chunk: Uint8Array) {
      if (closed) return;
      const w = waiters.shift();
      if (w != null) {
        w.resolve(chunk);
        return;
      }
      queue.push(chunk);
    },
    read() {
      if (error != null) return Promise.reject(error);
      const next = queue.shift();
      if (next != null) return Promise.resolve(next);
      return new Promise<Uint8Array>((resolve, reject) => {
        if (error != null) {
          reject(error);
          return;
        }
        waiters.push({ resolve, reject });
      });
    },
    async write(chunk: Uint8Array): Promise<void> {
      if (error != null) throw error;
      if (peer == null) throw new Error("missing peer");
      if (peer.isClosed()) throw new Error("peer closed");
      peer.enqueue(chunk.slice());
    },
    close() {
      if (closed) return;
      fail(new Error("closed"));
      if (peer != null && !peer.isClosed()) {
        peer.close();
      }
    }
  };
}

function createBinaryTransportPair(): { client: BinaryTransport; server: BinaryTransport; close: () => void } {
  const left = createInMemoryLink();
  const right = createInMemoryLink();
  left.attach(right);
  right.attach(left);
  return {
    client: {
      readBinary: () => left.read(),
      writeBinary: (frame) => left.write(frame),
      close: () => left.close()
    },
    server: {
      readBinary: () => right.read(),
      writeBinary: (frame) => right.write(frame),
      close: () => right.close()
    },
    close: () => {
      left.close();
      right.close();
    }
  };
}

function createDuplexPair(): { client: ByteDuplex; server: ByteDuplex; close: () => void } {
  const left = createInMemoryLink();
  const right = createInMemoryLink();
  left.attach(right);
  right.attach(left);
  return {
    client: {
      read: () => left.read(),
      write: (chunk) => left.write(chunk),
      close: () => left.close()
    },
    server: {
      read: () => right.read(),
      write: (chunk) => right.write(chunk),
      close: () => right.close()
    },
    close: () => {
      left.close();
      right.close();
    }
  };
}

async function runHandshake(suite: 1 | 2): Promise<void> {
  const pair = createBinaryTransportPair();
  const psk = new Uint8Array(32).fill(7);
  const now = Math.floor(Date.now() / 1000);
  const cache = new ServerHandshakeCache();
  const serverPromise = serverHandshake(pair.server, cache, {
    channelId: "bench",
    suite,
    psk,
    serverFeatures: 0,
    initExpireAtUnixS: now + 60,
    clockSkewSeconds: 30,
    maxHandshakePayload: 8 * 1024,
    maxRecordBytes: 1 << 20
  });
  const client = await clientHandshake(pair.client, {
    channelId: "bench",
    suite,
    psk,
    clientFeatures: 0,
    maxHandshakePayload: 8 * 1024,
    maxRecordBytes: 1 << 20
  });
  const server = await serverPromise;
  client.close();
  server.close();
  pair.close();
}

describe("e2ee handshake", () => {
  bench("handshake_x25519", async () => {
    await runHandshake(1);
  });

  bench("handshake_p256", async () => {
    await runHandshake(2);
  });
});

describe("e2ee record", () => {
  const sizes = [256, 1024, 8 * 1024, 64 * 1024, 1 << 20];
  for (const size of sizes) {
    const key = new Uint8Array(32).fill(1);
    const nonce = new Uint8Array(4).fill(2);
    const payload = new Uint8Array(size);
    const maxRecordBytes = size + 64;
    const frame = encryptRecord(key, nonce, RECORD_FLAG_APP, 1n, payload, maxRecordBytes);
    bench(`encrypt_${size}B`, () => {
      encryptRecord(key, nonce, RECORD_FLAG_APP, 1n, payload, maxRecordBytes);
    });

    bench(`decrypt_${size}B`, () => {
      decryptRecord(key, nonce, frame, 1n, maxRecordBytes);
    });
  }
});

describe("yamux", () => {
  bench("open_stream", async () => {
    const pair = createDuplexPair();
    const server = new YamuxSession(pair.server, {
      client: false,
      onIncomingStream: (stream) => {
        stream.reset(new Error("bench"));
      }
    });
    const client = new YamuxSession(pair.client, { client: true });
    const stream = await client.openStream();
    stream.reset(new Error("bench"));
    client.close();
    server.close();
    pair.close();
  });
});
