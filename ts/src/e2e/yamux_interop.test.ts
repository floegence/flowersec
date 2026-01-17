import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { describe, expect, test } from "vitest";

import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role as TunnelRole, type Attach } from "../gen/flowersec/tunnel/v1.gen.js";
import { createExitPromise } from "./harnessProcess.js";
import { createLineReader, createTextBuffer, delay, readJsonLine, withTimeout } from "./interopUtils.js";
import { clientHandshake } from "../e2ee/handshake.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import { YamuxSession, type ByteDuplex } from "../yamux/session.js";

const require = createRequire(import.meta.url);
const WS = require("ws");

const interopScale = parseScale(process.env.YAMUX_INTEROP_SCALE);
const enableInterop = process.env.YAMUX_INTEROP === "1";

type Scenario = {
  scenario: "window_update_race" | "rst_mid_write_ts" | "rst_mid_write_go" | "concurrent_open_close" | "session_close";
  streams: number;
  bytes_per_stream: number;
  chunk_bytes: number;
  direction: "ts_to_go" | "bidi";
  read_delay_ms?: number;
  write_delay_ms?: number;
  deadline_ms: number;
  seed?: number;
  rst_after_bytes?: number;
  close_immediately_ratio?: number;
  close_after_bytes?: number;
  session_close_delay_ms?: number;
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

type ClientRun = {
  bytesWritten: number;
  bytesRead: number;
  writeErrors: number;
  readErrors: number;
  afterResetErrors: number;
};

const minimalStreams = 10 * interopScale;
const minimalBytesPerStream = 512 * 1024 * interopScale;
const minimalRstAfterBytes = 64 * 1024 * interopScale;
const minimalCloseAfterBytes = 64 * 1024 * interopScale;
const windowRaceStreams = Math.max(2, 2 * interopScale);
const windowRaceBytesPerStream = 512 * 1024 * interopScale;

const fullChainStreams = 5 * interopScale;
const fullChainBytesPerStream = 256 * 1024 * interopScale;
const fullChainRstAfterBytes = 32 * 1024 * interopScale;
const fullChainCloseAfterBytes = 32 * 1024 * interopScale;
const fullChainWindowRaceStreams = Math.max(2, 2 * interopScale);
const fullChainWindowRaceBytesPerStream = 512 * 1024 * interopScale;
const fullChainSessionCloseBytesPerStream = 512 * 1024 * interopScale;

const enableClientRst = process.env.YAMUX_INTEROP_CLIENT_RST === "1";
const enableStress = process.env.YAMUX_INTEROP_STRESS === "1";

const minimalScenarios: Scenario[] = [
  ...(enableStress
    ? [
        {
          scenario: "window_update_race" as const,
          streams: windowRaceStreams,
          bytes_per_stream: windowRaceBytesPerStream,
          chunk_bytes: 16 * 1024,
          direction: "ts_to_go" as const,
          read_delay_ms: 2,
          write_delay_ms: 0,
          deadline_ms: 8000,
          seed: 1
        }
      ]
    : []),
  ...(enableClientRst
    ? [
        {
          scenario: "rst_mid_write_ts" as const,
          streams: minimalStreams,
          bytes_per_stream: minimalBytesPerStream,
          chunk_bytes: 16 * 1024,
          direction: "ts_to_go" as const,
          rst_after_bytes: minimalRstAfterBytes,
          deadline_ms: 6000,
          seed: 2
        }
      ]
    : []),
  {
    scenario: "rst_mid_write_go",
    streams: minimalStreams,
    bytes_per_stream: minimalBytesPerStream,
    chunk_bytes: 16 * 1024,
    direction: "ts_to_go",
    rst_after_bytes: minimalRstAfterBytes,
    write_delay_ms: 5,
    deadline_ms: 6000,
    seed: 3
  },
  ...(enableStress
    ? [
        {
          scenario: "concurrent_open_close" as const,
          streams: minimalStreams,
          bytes_per_stream: minimalBytesPerStream,
          chunk_bytes: 16 * 1024,
          direction: "ts_to_go" as const,
          close_immediately_ratio: 0.3,
          close_after_bytes: minimalCloseAfterBytes,
          deadline_ms: 8000,
          seed: 4
        }
      ]
    : []),
  {
    scenario: "session_close",
    streams: Math.max(3, Math.floor(minimalStreams / 4)),
    bytes_per_stream: minimalBytesPerStream,
    chunk_bytes: 16 * 1024,
    direction: "ts_to_go",
    write_delay_ms: 5,
    session_close_delay_ms: 150,
    deadline_ms: 6000,
    seed: 5
  }
];

const fullChainScenarios: Scenario[] = [
  ...(enableStress
    ? [
        {
          scenario: "window_update_race" as const,
          streams: fullChainWindowRaceStreams,
          bytes_per_stream: fullChainWindowRaceBytesPerStream,
          chunk_bytes: 16 * 1024,
          direction: "ts_to_go" as const,
          read_delay_ms: 2,
          write_delay_ms: 0,
          deadline_ms: 8000,
          seed: 1
        }
      ]
    : []),
  ...(enableClientRst
    ? [
        {
          scenario: "rst_mid_write_ts" as const,
          streams: fullChainStreams,
          bytes_per_stream: fullChainBytesPerStream,
          chunk_bytes: 16 * 1024,
          direction: "ts_to_go" as const,
          rst_after_bytes: fullChainRstAfterBytes,
          deadline_ms: 6000,
          seed: 2
        }
      ]
    : []),
  {
    scenario: "rst_mid_write_go",
    streams: fullChainStreams,
    bytes_per_stream: fullChainBytesPerStream,
    chunk_bytes: 16 * 1024,
    direction: "ts_to_go",
    rst_after_bytes: fullChainRstAfterBytes,
    write_delay_ms: 5,
    deadline_ms: 6000,
    seed: 3
  },
  ...(enableStress
    ? [
        {
          scenario: "concurrent_open_close" as const,
          streams: fullChainStreams,
          bytes_per_stream: fullChainBytesPerStream,
          chunk_bytes: 16 * 1024,
          direction: "ts_to_go" as const,
          close_immediately_ratio: 0.3,
          close_after_bytes: fullChainCloseAfterBytes,
          deadline_ms: 8000,
          seed: 4
        }
      ]
    : []),
  {
    scenario: "session_close",
    streams: Math.max(2, Math.floor(fullChainStreams / 2)),
    bytes_per_stream: fullChainSessionCloseBytesPerStream,
    chunk_bytes: 16 * 1024,
    direction: "ts_to_go",
    write_delay_ms: 10,
    session_close_delay_ms: 100,
    deadline_ms: 6000,
    seed: 5
  }
];

// Note: these tests only exercise client-initiated streams.
const describeInterop = enableInterop ? describe : describe.skip;

describeInterop("yamux interop (minimal tcp)", () => {
  for (const scenario of minimalScenarios) {
    test(scenario.scenario, { timeout: scenario.deadline_ms + 20000 }, async () => {
        const { client, server } = await runMinimalScenario(scenario);
        assertScenario(scenario, client, server);
      });
  }
});

describeInterop("yamux interop (full chain)", () => {
  for (const scenario of fullChainScenarios) {
    test(scenario.scenario, { timeout: scenario.deadline_ms + 30000 }, async () => {
        const { client, server } = await runFullScenario(scenario);
        assertScenario(scenario, client, server);
      });
  }
});

async function runMinimalScenario(scenario: Scenario): Promise<{ client: ClientRun; server: ServerRun }> {
  const goCwd = path.join(process.cwd(), "..", "go");
  const proc = spawn("go", ["run", "./cmd/flowersec-yamux-harness", "-scenario", JSON.stringify(scenario)], {
    cwd: goCwd,
    stdio: ["ignore", "pipe", "pipe"]
  });
  const exitPromise = createExitPromise(proc);
  const stdout = createLineReader(proc.stdout);
  const stderr = createTextBuffer(proc.stderr);
  let socket: net.Socket | null = null;
  let mux: TestYamuxSession | null = null;
  try {
    const ready = await readJsonLine<{ tcp_addr: string }>(stdout, 20000);
    socket = await connectTcp(ready.tcp_addr);
    const conn = socketToDuplex(socket);
    mux = new TestYamuxSession(conn, { client: true });

    let client: ClientRun;
    try {
      client = await runClientScenario(mux, scenario);
    } catch (error) {
      throw new Error(`client scenario failed: ${error instanceof Error ? error.message : String(error)}; stderr=${stderr()}`);
    }
    mux.close();
    mux = null;
    socket.destroy();
    socket = null;

    const server = await readJsonLine<ServerRun>(stdout, 20000);
    if (server.error) {
      throw new Error(`harness error: ${server.error}; stderr=${stderr()}`);
    }
    return { client, server };
  } finally {
    mux?.close();
    socket?.destroy();
    await withTimeout("harness exit", 5000, exitPromise);
  }
}

async function runFullScenario(scenario: Scenario): Promise<{ client: ClientRun; server: ServerRun }> {
  const goCwd = path.join(process.cwd(), "..", "go");
  const proc = spawn("go", ["run", "./cmd/flowersec-e2e-harness", "-scenario", JSON.stringify(scenario)], {
    cwd: goCwd,
    stdio: ["ignore", "pipe", "pipe"]
  });
  const exitPromise = createExitPromise(proc);
  const stdout = createLineReader(proc.stdout);
  const stderr = createTextBuffer(proc.stderr);
  let clientSession: { mux: YamuxSession; close: () => void } | null = null;
  try {
    const ready = await readJsonLine<{ grant_client: ChannelInitGrant }>(stdout, 20000);
    clientSession = await connectTunnelClientYamux(ready.grant_client);
    let client: ClientRun;
    try {
      client = await runClientScenario(clientSession.mux, scenario);
    } catch (error) {
      throw new Error(`client scenario failed: ${error instanceof Error ? error.message : String(error)}; stderr=${stderr()}`);
    }
    clientSession.close();
    clientSession = null;
    const server = await readJsonLine<ServerRun>(stdout, 20000);
    if (server.error) {
      throw new Error(`harness error: ${server.error}; stderr=${stderr()}`);
    }
    return { client, server };
  } finally {
    clientSession?.close();
    await withTimeout("harness exit", 5000, exitPromise);
  }
}

async function runClientScenario(mux: YamuxSession, scenario: Scenario): Promise<ClientRun> {
  const streams: YamuxStream[] = [];
  for (let i = 0; i < scenario.streams; i += 1) {
    const stream = await withTimeout("openStream", 2000, mux.openStream());
    if (mux instanceof TestYamuxSession) {
      await withTimeout("stream ACK", 2000, mux.waitForEstablished(stream.id, 2000));
    }
    streams.push(stream);
  }
  switch (scenario.scenario) {
    case "window_update_race":
      return runWindowUpdateRace(streams, scenario);
    case "rst_mid_write_ts":
      return runRstMidWriteTs(streams, scenario);
    case "rst_mid_write_go":
      return runRstMidWriteGo(streams, scenario);
    case "concurrent_open_close":
      return runConcurrentOpenClose(streams, scenario);
    case "session_close":
      return runSessionClose(streams, scenario);
    default:
      throw new Error(`unknown scenario: ${scenario.scenario}`);
  }
}

function assertScenario(scenario: Scenario, client: ClientRun, server: ServerRun): void {
  if (scenario.scenario === "window_update_race") {
    const total = scenario.streams * scenario.bytes_per_stream;
    expect(client.writeErrors).toBe(0);
    expect(client.readErrors).toBe(0);
    expect(client.bytesWritten).toBe(total);
    if (scenario.direction === "bidi") {
      expect(client.bytesRead).toBe(total);
    } else {
      expect(client.bytesRead).toBe(0);
    }
    expect(server.result.errors).toBe(0);
    expect(server.result.bytes_read).toBe(total);
    if (scenario.direction === "bidi") {
      expect(server.result.bytes_written).toBe(total);
    }
    return;
  }
  if (scenario.scenario === "rst_mid_write_ts") {
    expect(client.afterResetErrors).toBe(scenario.streams);
    expect(server.result.resets).toBe(scenario.streams);
    expect(server.result.errors).toBe(0);
    return;
  }
  if (scenario.scenario === "rst_mid_write_go") {
    expect(client.writeErrors).toBe(scenario.streams);
    expect(server.result.errors).toBe(0);
    return;
  }
  if (scenario.scenario === "concurrent_open_close") {
    expect(client.writeErrors).toBe(0);
    expect(server.result.errors).toBe(0);
    return;
  }
  if (scenario.scenario === "session_close") {
    expect(client.writeErrors).toBeGreaterThan(0);
    expect(server.result.errors).toBe(0);
    return;
  }
}

async function runWindowUpdateRace(streams: YamuxStream[], scenario: Scenario): Promise<ClientRun> {
  const batchSize = Math.min(5, streams.length);
  const results = await runInBatches(streams, batchSize, async (stream) => {
    if (scenario.direction === "ts_to_go") {
      const writeRes = await writeExactly(stream, scenario.bytes_per_stream, scenario.chunk_bytes, scenario.write_delay_ms ?? 0);
      await stream.close();
      return { writeRes, readRes: { bytes: 0, error: null } };
    }
    const [writeRes, readRes] = await Promise.all([
      writeExactly(stream, scenario.bytes_per_stream, scenario.chunk_bytes, scenario.write_delay_ms ?? 0),
      readExactly(stream, scenario.bytes_per_stream, scenario.read_delay_ms ?? 0)
    ]);
    await stream.close();
    return { writeRes, readRes };
  });
  return collectClientRun(results);
}

async function runRstMidWriteTs(streams: YamuxStream[], scenario: Scenario): Promise<ClientRun> {
  const batchSize = Math.min(5, streams.length);
  const rstAfter = Math.max(1, Math.min(scenario.rst_after_bytes ?? 0, scenario.bytes_per_stream));
  const results = await runInBatches(streams, batchSize, async (stream) => {
    const writeRes = await writeExactly(stream, rstAfter, scenario.chunk_bytes, scenario.write_delay_ms ?? 0);
    stream.reset(new Error("test reset"));
    const afterReset = await writeOnce(stream, new Uint8Array([0]));
    return { writeRes, readRes: { bytes: 0, error: null }, afterReset };
  });
  return collectClientRun(results);
}

async function runRstMidWriteGo(streams: YamuxStream[], scenario: Scenario): Promise<ClientRun> {
  const batchSize = Math.min(5, streams.length);
  const writeTimeoutMs = Math.min(1000, scenario.deadline_ms);
  const results = await runInBatches(streams, batchSize, async (stream) => {
    const writeRes = await writeUntilError(
      stream,
      scenario.bytes_per_stream,
      scenario.chunk_bytes,
      scenario.write_delay_ms ?? 0,
      writeTimeoutMs
    );
    return { writeRes, readRes: { bytes: 0, error: null }, afterReset: { error: null } };
  });
  return collectClientRun(results);
}

async function runConcurrentOpenClose(streams: YamuxStream[], scenario: Scenario): Promise<ClientRun> {
  const rand = mulberry32(scenario.seed ?? 1);
  const batchSize = Math.min(5, streams.length);
  const results = await runInBatches(streams, batchSize, async (stream) => {
    if ((scenario.close_immediately_ratio ?? 0) > 0 && rand() < (scenario.close_immediately_ratio ?? 0)) {
      await stream.close();
      return { writeRes: { bytes: 0, error: null }, readRes: { bytes: 0, error: null }, afterReset: { error: null } };
    }
    const writeRes = await writeExactly(stream, scenario.close_after_bytes ?? 0, scenario.chunk_bytes, scenario.write_delay_ms ?? 0);
    await stream.close();
    return { writeRes, readRes: { bytes: 0, error: null }, afterReset: { error: null } };
  });
  return collectClientRun(results);
}

async function runSessionClose(streams: YamuxStream[], scenario: Scenario): Promise<ClientRun> {
  const batchSize = Math.min(5, streams.length);
  const writeTimeoutMs = Math.min(1000, scenario.deadline_ms);
  const results = await runInBatches(streams, batchSize, async (stream) => {
    const writeRes = await writeUntilError(
      stream,
      scenario.bytes_per_stream,
      scenario.chunk_bytes,
      scenario.write_delay_ms ?? 0,
      writeTimeoutMs
    );
    return { writeRes, readRes: { bytes: 0, error: null }, afterReset: { error: null } };
  });
  return collectClientRun(results);
}

type YamuxStream = {
  read(): Promise<Uint8Array>;
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  reset(err: Error): void;
  id: number;
};

type WriteResult = { bytes: number; error: unknown | null };
type ReadResult = { bytes: number; error: unknown | null };

class TestYamuxSession extends YamuxSession {
  private readonly established = new Map<number, () => void>();
  private readonly establishedIds = new Set<number>();

  waitForEstablished(streamId: number, timeoutMs: number): Promise<void> {
    if (this.establishedIds.has(streamId)) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.established.delete(streamId);
        reject(new Error("timeout waiting for stream ACK"));
      }, timeoutMs);
      this.established.set(streamId, () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  override onStreamEstablished(streamId: number): void {
    this.establishedIds.add(streamId);
    const done = this.established.get(streamId);
    if (done != null) {
      this.established.delete(streamId);
      done();
    }
  }
}

async function writeExactly(stream: YamuxStream, total: number, chunkBytes: number, delayMs: number): Promise<WriteResult> {
  let remaining = total;
  let written = 0;
  const chunk = new Uint8Array(Math.max(1, chunkBytes));
  while (remaining > 0) {
    const size = Math.min(remaining, chunk.length);
    try {
      await stream.write(chunk.subarray(0, size));
      written += size;
    } catch (error) {
      return { bytes: written, error };
    }
    remaining -= size;
    if (delayMs > 0) {
      await delay(delayMs);
    }
  }
  return { bytes: written, error: null };
}

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

async function writeOnce(stream: YamuxStream, chunk: Uint8Array): Promise<{ error: unknown | null }> {
  try {
    await stream.write(chunk);
    return { error: null };
  } catch (error) {
    return { error };
  }
}

async function readExactly(stream: YamuxStream, total: number, delayMs: number): Promise<ReadResult> {
  let remaining = total;
  let read = 0;
  while (remaining > 0) {
    try {
      const chunk = await stream.read();
      read += chunk.length;
      remaining -= chunk.length;
    } catch (error) {
      return { bytes: read, error };
    }
    if (delayMs > 0) {
      await delay(delayMs);
    }
  }
  return { bytes: read, error: null };
}

function collectClientRun(results: Array<{ writeRes: WriteResult; readRes: ReadResult; afterReset?: { error: unknown | null } }>): ClientRun {
  let bytesWritten = 0;
  let bytesRead = 0;
  let writeErrors = 0;
  let readErrors = 0;
  let afterResetErrors = 0;
  for (const r of results) {
    bytesWritten += r.writeRes.bytes;
    bytesRead += r.readRes.bytes;
    if (r.writeRes.error != null) writeErrors += 1;
    if (r.readRes.error != null) readErrors += 1;
    if (r.afterReset?.error != null) afterResetErrors += 1;
  }
  return { bytesWritten, bytesRead, writeErrors, readErrors, afterResetErrors };
}

function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let x = t;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

function parseScale(raw: string | undefined): number {
  if (raw == null || raw === "") return 1;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return 1;
  return Math.max(1, Math.floor(n));
}

async function runInBatches<T, R>(items: T[], batchSize: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map((item) => fn(item)));
    out.push(...batchResults);
  }
  return out;
}

function socketToDuplex(socket: net.Socket): ByteDuplex {
  const queue: Uint8Array[] = [];
  let closed = false;
  let err: Error | null = null;
  let waiter: ((chunk: Uint8Array) => void) | null = null;
  let waiterErr: ((error: Error) => void) | null = null;

  const closeWithError = (error: Error) => {
    if (closed) return;
    closed = true;
    err = error;
    if (waiterErr) {
      waiterErr(error);
      waiter = null;
      waiterErr = null;
    }
  };

  socket.on("data", (chunk) => {
    if (waiter) {
      const resolve = waiter;
      waiter = null;
      waiterErr = null;
      resolve(chunk);
      return;
    }
    queue.push(chunk);
  });
  socket.on("error", (error) => closeWithError(error));
  socket.on("end", () => closeWithError(new Error("eof")));
  socket.on("close", () => closeWithError(new Error("closed")));

  return {
    read: () => {
      if (queue.length > 0) return Promise.resolve(queue.shift()!);
      if (closed) return Promise.reject(err ?? new Error("closed"));
      return new Promise<Uint8Array>((resolve, reject) => {
        waiter = resolve;
        waiterErr = reject;
      });
    },
    write: (chunk) => new Promise<void>((resolve, reject) => {
      socket.write(chunk, (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    }),
    close: () => socket.destroy()
  };
}

async function connectTcp(addr: string): Promise<net.Socket> {
  return await new Promise((resolve, reject) => {
    const idx = addr.lastIndexOf(":");
    if (idx <= 0) {
      reject(new Error(`invalid tcp address: ${addr}`));
      return;
    }
    const host = addr.slice(0, idx);
    const port = Number(addr.slice(idx + 1));
    if (!Number.isFinite(port)) {
      reject(new Error(`invalid tcp port: ${addr}`));
      return;
    }
    const socket = net.connect({ host, port });
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onConnect = () => {
      cleanup();
      socket.setNoDelay(true);
      resolve(socket);
    };
    const cleanup = () => {
      socket.off("error", onError);
      socket.off("connect", onConnect);
    };
    socket.once("error", onError);
    socket.once("connect", onConnect);
  });
}

async function connectTunnelClientYamux(grant: ChannelInitGrant): Promise<{ mux: YamuxSession; close: () => void }> {
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
  const conn = {
    read: () => secure.read(),
    write: (b: Uint8Array) => secure.write(b),
    close: () => secure.close()
  };
  const mux = new TestYamuxSession(conn, { client: true });
  return {
    mux,
    close: () => {
      mux.close();
      secure.close();
      ws.close();
    }
  };
}

function waitOpen(ws: WebSocketLike): Promise<void> {
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
