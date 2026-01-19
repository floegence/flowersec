import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { once } from "node:events";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { describe, expect, test } from "vitest";

import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role as TunnelRole, type Attach } from "../gen/flowersec/tunnel/v1.gen.js";
import { createExitPromise } from "./harnessProcess.js";
import { createLineReader, createTextBuffer, delay, readJsonLine, withTimeout, type LineReader } from "./interopUtils.js";
import {
  ServerHandshakeCache,
  clientHandshake,
  serverHandshake,
  type HandshakeClientOptions,
  type HandshakeServerOptions
} from "../e2ee/handshake.js";
import type { BinaryTransport, SecureChannel } from "../e2ee/secureChannel.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { concatBytes } from "../utils/bin.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import { FLAG_FIN, FLAG_RST } from "../yamux/constants.js";
import { decodeHeader, HEADER_LEN } from "../yamux/header.js";
import { YamuxSession, type ByteDuplex } from "../yamux/session.js";

const require = createRequire(import.meta.url);
const WS = require("ws");

const enableInterop = process.env.YAMUX_INTEROP === "1";
const enableDebug = process.env.YAMUX_INTEROP_DEBUG === "1";
const describeInterop = enableInterop ? describe : describe.skip;
const describeDebug = enableInterop && enableDebug ? describe : describe.skip;
const trace = enableDebug
  ? (msg: string) => {
      process.stderr.write(`[yamux-interop-debug] ${msg}\n`);
    }
  : () => {};

describeInterop("yamux interop (layers: in-memory)", () => {
  test("session close wakes writers waiting on flow control", { timeout: 5000 }, async () => {
      const { a, b } = createByteDuplexPair();
      const server = new YamuxSession(b, {
        client: false,
        onIncomingStream: () => {}
      });
      const client = new YamuxSession(a, { client: true });
      const stream = await client.openStream();
      const payload = new Uint8Array(512 * 1024);
      const writeTask = stream.write(payload);
      await delay(50);
      client.close();
      await expect(writeTask).rejects.toThrow(/session closed|stream/);
      server.close();
    });

  test("secure channel delivers FIN/RST when server closes early", { timeout: 8000 }, async () => {
      const { client, server, close } = await createSecureChannelPair();
      const probe = new FrameProbe();
      const clientMux = new YamuxSession(tapDuplex(secureToDuplex(client), probe), { client: true });
      const serverDone = trackServerClose(server, 32 * 1024);

      const stream = await clientMux.openStream();
      await writeUntilError(stream, 128 * 1024, 16 * 1024, 0, 1000);
      const control = await probe.waitForFlags(FLAG_FIN | FLAG_RST, 2000);

      expect(control.flags & (FLAG_FIN | FLAG_RST)).toBeGreaterThan(0);
      await expect(serverDone).resolves.toBeUndefined();

      clientMux.close();
      close();
    });
});

describeInterop("yamux interop (layers: websocket)", () => {
  test("websocket transport preserves FIN/RST delivery", { timeout: 15000 }, async () => {
      const { clientWs, serverWs, close } = await openWebSocketPair();
      const { client, server } = await createSecureChannelPair({
        clientTransport: new WebSocketBinaryTransport(clientWs),
        serverTransport: new WebSocketBinaryTransport(serverWs)
      });

      const probe = new FrameProbe();
      const clientMux = new YamuxSession(tapDuplex(secureToDuplex(client), probe), { client: true });
      const serverDone = trackServerClose(server, 32 * 1024);

      const stream = await clientMux.openStream();
      await writeUntilError(stream, 128 * 1024, 16 * 1024, 0, 1000);
      const control = await probe.waitForFlags(FLAG_FIN | FLAG_RST, 2000);

      expect(control.flags & (FLAG_FIN | FLAG_RST)).toBeGreaterThan(0);
      await expect(serverDone).resolves.toBeUndefined();

      clientMux.close();
      client.close();
      server.close();
      await close();
    });
});

describeDebug("yamux interop (full chain probe)", () => {
  test("full chain receives FIN/RST on rst_mid_write_go", { timeout: 30000 }, async () => {
      const scenario: Scenario = {
        scenario: "rst_mid_write_go",
        streams: 3,
        bytes_per_stream: 512 * 1024,
        chunk_bytes: 16 * 1024,
        direction: "ts_to_go",
        rst_after_bytes: 64 * 1024,
        deadline_ms: 6000,
        seed: 7
      };
      const { stdout, stderr, exitPromise } = spawnGoHarness(scenario);
      trace("spawned go harness");
      try {
        const ready = await withTimeout(
          "harness ready",
          10000,
          readJsonLine<{ grant_client: ChannelInitGrant }>(stdout, 20000)
        );
        trace("received harness grant");
        const probe = new FrameProbe();
        const client = await withTimeout(
          "connect tunnel client",
          10000,
          connectTunnelClientYamuxWithProbe(ready.grant_client, probe)
        );
        trace("connected tunnel client");
        const streams: YamuxStream[] = [];
        for (let i = 0; i < scenario.streams; i += 1) {
          streams.push(await withTimeout("openStream", 2000, client.mux.openStream()));
        }
        trace("opened streams");
        const streamIds = streams.map((s) => s.id);
        const control = withTimeout(
          "control frames",
          5000,
          probe.waitForStreams(FLAG_FIN | FLAG_RST, streamIds, 3000)
        );
        await withTimeout(
          "client writes",
          10000,
          Promise.all(
            streams.map((stream) =>
              writeUntilError(stream, scenario.bytes_per_stream, scenario.chunk_bytes, 0, 1000)
            )
          )
        );
        trace("writes completed");
        await expect(control).resolves.toBeUndefined();
        trace("received control frames");

        client.close();
        const server = await withTimeout(
          "harness result",
          10000,
          readJsonLine<ServerRun>(stdout, 20000)
        );
        trace("received harness result");
        if (server.error) throw new Error(`harness error: ${server.error}; stderr=${stderr()}`);
      } finally {
        await withTimeout("harness exit", 5000, exitPromise);
      }
    });
});

type Scenario = {
  scenario: "rst_mid_write_go";
  streams: number;
  bytes_per_stream: number;
  chunk_bytes: number;
  direction: "ts_to_go";
  deadline_ms: number;
  rst_after_bytes: number;
  seed?: number;
};

type ServerRun = {
  result: {
    streams_accepted: number;
    streams_handled: number;
    bytes_read: number;
    bytes_written: number;
    resets: number;
    errors: number;
    first_error?: string;
  };
  error?: string;
};

type YamuxStream = {
  read(): Promise<Uint8Array>;
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  reset(err: Error): void;
  id: number;
};

type FrameEvent = {
  flags: number;
  streamId: number;
  length: number;
};

class FrameProbe {
  private buf = new Uint8Array();
  private readonly events: FrameEvent[] = [];
  private readonly waiters: Array<{
    predicate: (ev: FrameEvent) => boolean;
    resolve: (ev: FrameEvent) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];
  private readonly streamWaiters: Array<{
    mask: number;
    pending: Set<number>;
    resolve: () => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  push(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    this.buf = concatBytes([this.buf, chunk]);
    this.parse();
  }

  waitForFlags(mask: number, timeoutMs: number): Promise<FrameEvent> {
    const predicate = (ev: FrameEvent) => (ev.flags & mask) !== 0;
    for (const ev of this.events) {
      if (predicate(ev)) return Promise.resolve(ev);
    }
    return new Promise<FrameEvent>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("timeout waiting for control frame"));
      }, timeoutMs);
      this.waiters.push({ predicate, resolve, reject, timer });
    });
  }

  waitForStreams(mask: number, streamIds: number[], timeoutMs: number): Promise<void> {
    const pending = new Set(streamIds);
    for (const ev of this.events) {
      if ((ev.flags & mask) !== 0) pending.delete(ev.streamId);
    }
    if (pending.size === 0) return Promise.resolve();
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("timeout waiting for control frames per stream"));
      }, timeoutMs);
      this.streamWaiters.push({ mask, pending, resolve, reject, timer });
    });
  }

  private parse(): void {
    while (this.buf.length >= HEADER_LEN) {
      const header = decodeHeader(this.buf, 0);
      const total = HEADER_LEN + header.length;
      if (this.buf.length < total) return;
      const ev: FrameEvent = { flags: header.flags, streamId: header.streamId, length: header.length };
      this.events.push(ev);
      this.dispatch(ev);
      this.buf = this.buf.slice(total);
    }
  }

  private dispatch(ev: FrameEvent): void {
    if (this.waiters.length > 0) {
      const pending: typeof this.waiters = [];
      for (const w of this.waiters) {
        if (w.predicate(ev)) {
          clearTimeout(w.timer);
          w.resolve(ev);
        } else {
          pending.push(w);
        }
      }
      this.waiters.length = 0;
      this.waiters.push(...pending);
    }

    if (this.streamWaiters.length > 0) {
      const streamPending: typeof this.streamWaiters = [];
      for (const w of this.streamWaiters) {
        if ((ev.flags & w.mask) !== 0) {
          w.pending.delete(ev.streamId);
        }
        if (w.pending.size === 0) {
          clearTimeout(w.timer);
          w.resolve();
        } else {
          streamPending.push(w);
        }
      }
      this.streamWaiters.length = 0;
      this.streamWaiters.push(...streamPending);
    }
  }
}

function tapDuplex(conn: ByteDuplex, probe: FrameProbe): ByteDuplex {
  return {
    read: async () => {
      const chunk = await conn.read();
      probe.push(chunk);
      return chunk;
    },
    write: (chunk) => conn.write(chunk),
    close: () => conn.close()
  };
}

function secureToDuplex(sc: SecureChannel): ByteDuplex {
  return {
    read: () => sc.read(),
    write: (chunk) => sc.write(chunk),
    close: () => sc.close()
  };
}

async function trackServerClose(secure: SecureChannel, readBytes: number): Promise<void> {
  return await new Promise<void>((resolve, reject) => {
    const serverMux = new YamuxSession(secureToDuplex(secure), {
      client: false,
      onIncomingStream: (stream) => {
        void (async () => {
          try {
            await readExactly(stream, readBytes);
            await stream.close();
            resolve();
          } catch (err) {
            reject(err instanceof Error ? err : new Error(String(err)));
          } finally {
            serverMux.close();
          }
        })();
      }
    });
  });
}

async function readExactly(stream: YamuxStream, total: number): Promise<void> {
  let remaining = total;
  while (remaining > 0) {
    const chunk = await stream.read();
    remaining -= chunk.length;
  }
}

type WriteResult = { bytes: number; error: unknown | null };

async function writeUntilError(
  stream: YamuxStream,
  total: number,
  chunkBytes: number,
  delayMs: number,
  writeTimeoutMs?: number
): Promise<WriteResult> {
  let remaining = total;
  let written = 0;
  const chunk = new Uint8Array(Math.max(1, chunkBytes));
  while (remaining > 0) {
    const size = Math.min(remaining, chunk.length);
    try {
      const writeTask = stream.write(chunk.subarray(0, size));
      if (writeTimeoutMs != null && writeTimeoutMs > 0) {
        await withTimeout("stream.write", writeTimeoutMs, writeTask);
      } else {
        await writeTask;
      }
      written += size;
    } catch (error) {
      const isTimeout = error instanceof Error && error.message.startsWith("timeout waiting for");
      if (isTimeout) {
        stream.reset(new Error("write timeout"));
      }
      return { bytes: written, error };
    }
    remaining -= size;
    if (delayMs > 0) {
      await delay(delayMs);
    }
  }
  return { bytes: written, error: null };
}

function createByteDuplexPair(): { a: ByteDuplex; b: ByteDuplex } {
  const left = createInMemoryLink();
  const right = createInMemoryLink();
  left.attach(right);
  right.attach(left);
  return {
    a: {
      read: () => left.read(),
      write: (chunk) => left.write(chunk),
      close: () => left.close()
    },
    b: {
      read: () => right.read(),
      write: (chunk) => right.write(chunk),
      close: () => right.close()
    }
  };
}

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

async function createSecureChannelPair(
  transports?: Readonly<{ clientTransport: BinaryTransport; serverTransport: BinaryTransport }>
): Promise<{ client: SecureChannel; server: SecureChannel; close: () => void }> {
  const channelId = "chan_test";
  const suite = 1 as const;
  const psk = new Uint8Array(32).fill(7);
  const now = Math.floor(Date.now() / 1000);
  let clientTransport: BinaryTransport;
  let serverTransport: BinaryTransport;
  if (transports == null) {
    const pair = createBinaryTransportPair();
    clientTransport = pair.client;
    serverTransport = pair.server;
  } else {
    clientTransport = transports.clientTransport;
    serverTransport = transports.serverTransport;
  }

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
  const serverPromise = serverHandshake(serverTransport, cache, serverOpts);
  const client = await clientHandshake(clientTransport, clientOpts);
  const server = await serverPromise;

  return {
    client,
    server,
    close: () => {
      client.close();
      server.close();
    }
  };
}

function createBinaryTransportPair(): { client: BinaryTransport; server: BinaryTransport } {
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
    }
  };
}

async function openWebSocketPair(): Promise<{
  clientWs: WebSocketLike;
  serverWs: WebSocketLike;
  close: () => Promise<void>;
}> {
  const wss = new WS.WebSocketServer({ port: 0 });
  const addr = wss.address();
  const port = typeof addr === "string" ? Number(addr.split(":").pop()) : addr?.port;
  if (!port) throw new Error("failed to allocate websocket port");
  const url = `ws://127.0.0.1:${port}`;
  const clientWs = new WS(url) as WebSocketLike;
  // Attach handlers before awaiting the server-side connection to avoid missing a fast "open"/"error" event.
  const openPromise = waitOpen(clientWs);
  const [serverWs] = (await once(wss, "connection")) as [WebSocketLike];
  await openPromise;
  return {
    clientWs,
    serverWs,
    close: () =>
      new Promise((resolve) => {
        clientWs.close();
        serverWs.close();
        wss.close(() => resolve());
      })
  };
}

async function connectTunnelClientYamuxWithProbe(
  grant: ChannelInitGrant,
  probe: FrameProbe
): Promise<{ mux: YamuxSession; close: () => void }> {
  const ws = new WS(grant.tunnel_url, { headers: { Origin: "https://app.redeven.com" } }) as WebSocketLike;
  await waitOpen(ws);

  const attach: Attach = {
    v: 1,
    channel_id: grant.channel_id,
    role: TunnelRole.Role_client,
    token: grant.token,
    endpoint_instance_id: base64urlEncode(randomBytes(24))
  };
  ws.send(JSON.stringify(attach));

  const transport = new WebSocketBinaryTransport(ws);
  const psk = base64urlDecode(grant.e2ee_psk_b64u);
  const suite = grant.default_suite as unknown as 1 | 2;
  const secure = await clientHandshake(transport, {
    channelId: grant.channel_id,
    suite,
    psk,
    clientFeatures: 0,
    maxHandshakePayload: 8 * 1024,
    maxRecordBytes: 1 << 20
  });
  const conn = tapDuplex(secureToDuplex(secure), probe);
  const mux = new YamuxSession(conn, { client: true });
  return {
    mux,
    close: () => {
      mux.close();
      secure.close();
      ws.close();
    }
  };
}

function spawnGoHarness(scenario: Scenario): {
  stdout: LineReader;
  stderr: () => string;
  exitPromise: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
} {
  const goCwd = path.join(process.cwd(), "..", "flowersec-go");
  const proc = spawn("go", ["run", "./internal/cmd/flowersec-e2e-harness", "-scenario", JSON.stringify(scenario)], {
    cwd: goCwd,
    stdio: ["ignore", "pipe", "pipe"]
  });
  return {
    stdout: createLineReader(proc.stdout),
    stderr: createTextBuffer(proc.stderr),
    exitPromise: createExitPromise(proc)
  };
}

function waitOpen(ws: WebSocketLike): Promise<void> {
  if (ws.readyState === 1) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const onOpen = () => {
      cleanup();
      resolve();
    };
    const onErr = () => {
      cleanup();
      reject(new Error("websocket error"));
    };
    const onClose = () => {
      cleanup();
      reject(new Error("websocket closed"));
    };
    const cleanup = () => {
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onErr);
      ws.removeEventListener("close", onClose);
    };
    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onErr);
    ws.addEventListener("close", onClose);
  });
}
