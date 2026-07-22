import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { connect, type Socket } from "node:net";
import { describe, expect, test } from "vitest";

import type { CarrierSessionV2, CarrierStreamV2 } from "./carrier.js";
import { establishAdmittedNativeSessionV2 } from "./admittedSession.js";
import type { SessionContractV2 } from "./artifact.js";
import { CipherSuiteV2 } from "./protocol.js";
import type { SessionConfigV2 } from "./session.js";

const frameOpen = 1;
const frameData = 2;
const frameFIN = 3;
const frameReset = 4;
const frameClose = 5;
const artifactFixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{
  positive: readonly Readonly<{
    id: string;
    artifact_json: string;
    winners: readonly Readonly<{
      candidate_id: string;
      fsb2_hex: string;
      admission_binding_hex: string;
    }>[];
  }>[];
}>;
const admissionVector = artifactFixture.positive
  .find((entry) => entry.id === "direct-three-carriers")!
  .winners.find((winner) => winner.candidate_id === "q1")!;
const rawFSB2 = Uint8Array.from(Buffer.from(admissionVector.fsb2_hex, "hex"));
const sessionContract = (JSON.parse(
  artifactFixture.positive.find((entry) => entry.id === "direct-three-carriers")!.artifact_json,
) as Readonly<{ session: SessionContractV2 }>).session;

describe("TypeScript-Go SessionV2 interop", () => {
  test("runs handshake, logical stream, liveness, and bilateral rekey over a byte-stream carrier fixture", async () => {
    const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));
    const peer = spawn("go", ["run", "./flowersec-ts/src/v2/interop/go_session_peer.go"], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stderr: string[] = [];
    let phase = "spawn";
    peer.stderr.setEncoding("utf8");
    peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
    try {
      const address = await firstLine(peer.stdout);
      phase = "connect";
      const [host, portText] = address.split(":");
      const socket = await connectSocket(host!, Number(portText));
      const carrier = new TCPFramedCarrier(socket);
      const session = await establishAdmittedNativeSessionV2(carrier, rawFSB2, new Set(), config());
      phase = "liveness";
      expect(session.chosenCarrier).toBe("raw_quic");
      expect(await session.probeLiveness()).toBeGreaterThanOrEqual(0);

      const stream = await session.openStream("interop.echo");
      phase = "first-data";
      await stream.write(new TextEncoder().encode("hello-go"));
      expect(new TextDecoder().decode((await stream.read())!)).toBe("hello-ts");
      phase = "go-rekey";
      expect(new TextDecoder().decode((await stream.read())!)).toBe("go-rekey-ok");

      phase = "ts-rekey";
      await session.rekey();
      await stream.write(new TextEncoder().encode("ts-rekey-ok"));
      await stream.closeWrite();
      expect(new TextDecoder().decode((await stream.read())!)).toBe("done");
      expect(await stream.read()).toBeNull();
      phase = "close";
      await session.close();

      const exit = await processExit(peer);
      expect(exit, stderr.join("")).toBe(0);
    } catch (error) {
      await Promise.race([processExit(peer), new Promise((resolve) => setTimeout(resolve, 250))]);
      throw new Error(`interop failed during ${phase}: ${error instanceof Error ? error.message : String(error)}\n${stderr.join("")}`);
    } finally {
      if (peer.exitCode === null) peer.kill("SIGKILL");
    }
  }, 30_000);
});

function config(): SessionConfigV2 {
  return {
    role: "client",
    path: "direct",
    channelID: "channel-1",
    sessionContractHash: Uint8Array.from(Buffer.from("ioBJP5DPhg471caMR-huV5I9RlNKY2Pr9fs2GkP8CmA", "base64url")),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    maxInboundStreams: 64,
    sessionContract,
    localAdmissionBinding: Uint8Array.from(Buffer.from(admissionVector.admission_binding_hex, "hex")),
    peerAdmissionBinding: Uint8Array.from(Buffer.from(admissionVector.admission_binding_hex, "hex")),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
  };
}

class TCPFramedCarrier implements CarrierSessionV2 {
  readonly kind = "raw_quic" as const;
  readonly path = "direct" as const;
  readonly inboundBidirectionalStreamCapacity = 66;

  private nextID = 1;
  private buffer = new Uint8Array();
  private readonly streams = new Map<number, TCPFramedStream>();
  private readonly incoming = new Queue<CarrierStreamV2>();
  private writeTail: Promise<void> = Promise.resolve();
  private error: Error | undefined;

  constructor(private readonly socket: Socket) {
    socket.on("data", (chunk: Buffer) => {
      this.buffer = concat(this.buffer, new Uint8Array(chunk));
      this.parse();
    });
    socket.on("error", (error) => this.fail(error));
    socket.on("close", () => this.fail(new Error("TCP framed carrier closed")));
  }

  async openStream(): Promise<CarrierStreamV2> {
    this.assertOpen();
    const id = this.nextID;
    this.nextID += 2;
    const stream = new TCPFramedStream(this, id);
    this.streams.set(id, stream);
    await this.writeFrame(frameOpen, id, new Uint8Array());
    return stream;
  }

  async acceptStream(): Promise<CarrierStreamV2> {
    this.assertOpen();
    return await this.incoming.shift();
  }

  async close(): Promise<void> {
    if (this.error !== undefined) return;
    await this.writeFrame(frameClose, 0, new Uint8Array()).catch(() => undefined);
    this.socket.end();
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    const failure = new Error(error?.reason ?? "TCP framed carrier aborted");
    this.fail(failure);
    this.socket.destroy(failure);
  }

  writeFrame(type: number, id: number, payload: Uint8Array): Promise<void> {
    const header = new Uint8Array(9);
    header[0] = type;
    const view = new DataView(header.buffer);
    view.setUint32(1, id, false);
    view.setUint32(5, payload.length, false);
    const raw = concat(header, payload);
    const task = this.writeTail.then(async () => await socketWrite(this.socket, raw));
    this.writeTail = task.catch(() => undefined);
    return task;
  }

  private parse(): void {
    while (this.buffer.length >= 9) {
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
      const type = this.buffer[0]!;
      const id = view.getUint32(1, false);
      const length = view.getUint32(5, false);
      if (length > 1 << 20) return this.fail(new Error("oversized framed carrier payload"));
      if (this.buffer.length < 9 + length) return;
      const payload = this.buffer.slice(9, 9 + length);
      this.buffer = this.buffer.slice(9 + length);
      if (type === frameClose) return this.fail(new Error("peer closed framed carrier"));
      let stream = this.streams.get(id);
      if (type === frameOpen) {
        if (stream !== undefined) return this.fail(new Error("duplicate framed carrier stream"));
        stream = new TCPFramedStream(this, id);
        this.streams.set(id, stream);
        this.incoming.push(stream);
        continue;
      }
      if (stream === undefined) return this.fail(new Error("unknown framed carrier stream"));
      if (type === frameData) stream.push(payload);
      else if (type === frameFIN) stream.peerFIN();
      else if (type === frameReset) stream.peerReset(new Error("carrier stream reset"));
      else return this.fail(new Error("unknown framed carrier frame"));
    }
  }

  private fail(error: Error): void {
    if (this.error !== undefined) return;
    this.error = error;
    this.incoming.fail(error);
    for (const stream of this.streams.values()) stream.peerReset(error);
  }

  private assertOpen(): void {
    if (this.error !== undefined) throw this.error;
  }
}

class TCPFramedStream implements CarrierStreamV2 {
  private readonly chunks = new Queue<Uint8Array | null>();
  private error: Error | undefined;
  private localFIN = false;

  constructor(private readonly session: TCPFramedCarrier, private readonly id: number) {}

  async read(): Promise<Uint8Array | null> {
    if (this.error !== undefined) throw this.error;
    return await this.chunks.shift();
  }

  async write(data: Uint8Array): Promise<number> {
    if (this.error !== undefined || this.localFIN) throw this.error ?? new Error("carrier write closed");
    await this.session.writeFrame(frameData, this.id, data);
    return data.length;
  }

  async closeWrite(): Promise<void> {
    if (this.localFIN) return;
    this.localFIN = true;
    await this.session.writeFrame(frameFIN, this.id, new Uint8Array());
  }

  async reset(): Promise<void> {
    if (this.error !== undefined) return;
    await this.session.writeFrame(frameReset, this.id, new Uint8Array()).catch(() => undefined);
    this.peerReset(new Error("carrier stream reset"));
  }

  abort(error?: Error): void {
    this.peerReset(error ?? new Error("carrier stream aborted"));
  }

  push(payload: Uint8Array): void { this.chunks.push(payload); }
  peerFIN(): void { this.chunks.push(null); }
  peerReset(error: Error): void {
    if (this.error !== undefined) return;
    this.error = error;
    this.chunks.fail(error);
  }
}

class Queue<T> {
  private readonly values: T[] = [];
  private readonly waiters: Array<{ resolve: (value: T) => void; reject: (error: Error) => void }> = [];
  private error: Error | undefined;

  push(value: T): void {
    const waiter = this.waiters.shift();
    if (waiter !== undefined) waiter.resolve(value);
    else this.values.push(value);
  }

  async shift(): Promise<T> {
    if (this.error !== undefined) throw this.error;
    if (this.values.length !== 0) return this.values.shift()!;
    return await new Promise<T>((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  fail(error: Error): void {
    if (this.error !== undefined) return;
    this.error = error;
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
  }
}

async function firstLine(stream: NodeJS.ReadableStream): Promise<string> {
  stream.setEncoding("utf8");
  return await new Promise<string>((resolve, reject) => {
    let buffered = "";
    const data = (chunk: string) => {
      buffered += chunk;
      const index = buffered.indexOf("\n");
      if (index < 0) return;
      cleanup();
      resolve(buffered.slice(0, index).trim());
    };
    const end = () => { cleanup(); reject(new Error("Go peer exited before publishing address")); };
    const cleanup = () => { stream.removeListener("data", data); stream.removeListener("end", end); };
    stream.on("data", data);
    stream.on("end", end);
  });
}

async function connectSocket(host: string, port: number): Promise<Socket> {
  return await new Promise<Socket>((resolve, reject) => {
    const socket = connect({ host, port });
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

async function socketWrite(socket: Socket, payload: Uint8Array): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.write(payload, (error) => error === null || error === undefined ? resolve() : reject(error));
  });
}

async function processExit(process: ReturnType<typeof spawn>): Promise<number | null> {
  if (process.exitCode !== null) return process.exitCode;
  return await new Promise((resolve) => process.once("exit", (code) => resolve(code)));
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const out = new Uint8Array(left.length + right.length);
  out.set(left);
  out.set(right, left.length);
  return out;
}
