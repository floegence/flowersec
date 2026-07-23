import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { RpcRouter } from "../rpc/server.js";
import {
  AdmissionStatusV2,
  computeSessionContractHashV2,
  decodeFSB2RequestV2,
  encodeFSA2ResponseV2,
  encodeFSB2RequestV2,
  type SessionContractV2,
} from "./artifact.js";
import {
  adaptNativeCarrierSessionV2,
  createMemoryCarrierPairV2,
  createWebSocketCarrierSessionV2,
  type NativeCarrierSessionV2,
  type NativeCarrierStreamV2,
  type WebSocketBinaryTransportV2,
} from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import {
  establishAdmittedNativeSessionV2,
  establishAdmittedWebSocketSessionV2,
} from "./admittedSession.js";
import { CipherSuiteV2 } from "./protocol.js";
import { establishSessionV2, type SessionConfigV2 } from "./session.js";
import { base64urlDecode } from "../utils/base64url.js";

type ArtifactFixture = Readonly<{
  positive: readonly Readonly<{
    path_kind: "direct" | "tunnel";
    artifact_json: string;
    winners: readonly Readonly<{ candidate_id: string; fsb2_hex: string }>[];
  }>[];
}>;

const artifactFixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as ArtifactFixture;
const rawWebSocketFSB2 = fsb2Fixture("direct", "w1", 8);
const rawWebSocketFSB2N1 = fsb2Fixture("direct", "w1", 1);
const rawWebTransportFSB2 = fsb2Fixture("direct", "t1", 8);
const rawWebTransportFSB2N1 = fsb2Fixture("direct", "t1", 1);
const rawQUICFSB2 = fsb2Fixture("direct", "q1", 8);
const rawTunnelWebTransportFSB2 = fsb2Fixture("tunnel", "t1", 8);
const rawFSA2 = encodeFSA2ResponseV2({ status: AdmissionStatusV2.Success, reason: "" }, new Set());

function config(
  role: "client" | "server",
  maxInboundStreams = 8,
  rpcRouter?: RpcRouter,
  rawFSB2 = rawWebSocketFSB2,
  path?: "direct" | "tunnel",
): SessionConfigV2 {
  const decoded = decodeFSB2RequestV2(rawFSB2);
  const sessionContract = fixtureSessionContract(maxInboundStreams);
  return {
    role,
    path: path ?? decoded.request.pathKind,
    channelID: decoded.request.channel_id,
    sessionContractHash: base64urlDecode(decoded.request.session_contract_hash_b64u),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: base64urlDecode(sessionContract.e2ee_psk_b64u),
    maxInboundStreams,
    sessionContract,
    localAdmissionBinding: decoded.localAdmissionBinding,
    peerAdmissionBinding: decoded.request.pathKind === "direct" ? decoded.localAdmissionBinding : new Uint8Array(32),
    localEndpointInstanceID: decoded.request.pathKind === "tunnel" ? decoded.request.endpoint_instance_id : "",
    expectedPeerEndpointInstanceID: "",
    ...(rpcRouter === undefined ? {} : { rpcRouter }),
  };
}

describe("admitted production carrier adapters", () => {
  test("switches WSS binary messages to existing Yamux only after FSA2", async () => {
    const [clientBinary, serverBinary] = binaryPair();
    const server = (async () => {
      expect(await serverBinary.readBinary()).toEqual(rawWebSocketFSB2);
      await serverBinary.writeBinary(rawFSA2);
      const carrier = createWebSocketCarrierSessionV2(serverBinary, {
        path: "direct",
        client: false,
        inboundBidirectionalStreamCapacity: 10,
      });
      return await establishSessionV2(carrier, config("server"));
    })();
    const client = establishAdmittedWebSocketSessionV2(clientBinary, rawWebSocketFSB2, new Set(), config("client"));
    const [clientSession, serverSession] = await Promise.all([client, server]);

    const opening = clientSession.openStream("wss-yamux");
    const incoming = await serverSession.acceptStream();
    const outgoing = await opening;
    await outgoing.write(Uint8Array.of(1, 2, 3));
    expect(await incoming.stream.read()).toEqual(Uint8Array.of(1, 2, 3));
    await clientSession.close();
  });

  test("gives WSS control, RPC, and N=1 application streams independent physical slots", async () => {
    const [clientBinary, serverBinary] = binaryPair();
    const clientRouter = new RpcRouter();
    const serverRouter = new RpcRouter();
    clientRouter.register(8, async (payload) => ({ payload }));
    const server = (async () => {
      expect(await serverBinary.readBinary()).toEqual(rawWebSocketFSB2N1);
      await serverBinary.writeBinary(rawFSA2);
      const carrier = createWebSocketCarrierSessionV2(serverBinary, {
        path: "direct",
        client: false,
        inboundBidirectionalStreamCapacity: 3,
        resourcePolicy: { maxConcurrentStreams: 3 },
      });
      return await establishSessionV2(carrier, config("server", 1, serverRouter, rawWebSocketFSB2N1));
    })();
    const client = establishAdmittedWebSocketSessionV2(
      clientBinary,
      rawWebSocketFSB2N1,
      new Set(),
      config("client", 1, clientRouter, rawWebSocketFSB2N1),
      { resourcePolicy: { maxConcurrentStreams: 3 } },
    );
    const [clientSession, serverSession] = await Promise.all([client, server]);

    await expect(serverSession.rpc.call(8, { reserved: true })).resolves.toEqual({ payload: { reserved: true } });
    const opening = serverSession.openStream("only-application-slot");
    const incoming = await clientSession.acceptStream();
    const outgoing = await opening;
    await outgoing.write(Uint8Array.of(4, 2));
    expect(await incoming.stream.read()).toEqual(Uint8Array.of(4, 2));
    expect(await clientSession.probeLiveness()).toBeGreaterThanOrEqual(0);
    await clientSession.close();
  });

  test("uses a native WebTransport bidi stream for FSA2 and never inserts Yamux", async () => {
    const [clientNative, serverNative] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const server = (async () => {
      const admission = await serverNative.acceptStream();
      expect(await admission.read()).toEqual(rawWebTransportFSB2);
      expect(await admission.read()).toBeNull();
      await admission.write(rawFSA2);
      await admission.closeWrite();
      return await establishSessionV2(adaptNativeCarrierSessionV2(serverNative), config("server", 8, undefined, rawWebTransportFSB2));
    })();
    const client = establishAdmittedNativeSessionV2(
      clientNative,
      rawWebTransportFSB2,
      new Set(),
      config("client", 8, undefined, rawWebTransportFSB2),
    );
    const [clientSession, serverSession] = await Promise.all([client, server]);

    const opening = clientSession.openStream("wt-native");
    const incoming = await serverSession.acceptStream();
    const outgoing = await opening;
    await incoming.stream.write(Uint8Array.of(9, 8));
    expect(await outgoing.read()).toEqual(Uint8Array.of(9, 8));
    await clientSession.close();
  });

  test("rejects a native N=1 physical-capacity mismatch before credential bytes or stream open", async () => {
    const native = new CapacityMismatchNativeCarrier(4);
    await expect(establishAdmittedNativeSessionV2(
      native,
      rawWebTransportFSB2N1,
      new Set(),
      config("client", 1, undefined, rawWebTransportFSB2N1),
    )).rejects.toMatchObject({ reason: "stream_capacity_mismatch" });
    expect(native.opens).toBe(0);
    expect(native.writtenBytes).toBe(0);
  });

  test("rejects an invalid WSS logical capacity before writing FSB2 credentials", async () => {
    const [clientBinary] = binaryPair();
    const invalidConfig = config("client");
    invalidConfig.maxInboundStreams = 0;
    await expect(establishAdmittedWebSocketSessionV2(
      clientBinary,
      rawWebSocketFSB2,
      new Set(),
      invalidConfig,
    )).rejects.toMatchObject({ reason: "stream_capacity_mismatch" });
    expect(clientBinary.writtenBytes).toBe(0);
  });

  test("rejects trailing bytes after an otherwise valid native FSA2", async () => {
    const [clientNative, serverNative] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const server = (async () => {
      const admission = await serverNative.acceptStream();
      expect(await admission.read()).toEqual(rawWebTransportFSB2);
      expect(await admission.read()).toBeNull();
      const trailing = new Uint8Array(rawFSA2.length + 1);
      trailing.set(rawFSA2);
      trailing[trailing.length - 1] = 1;
      await admission.write(trailing);
      await admission.closeWrite();
    })();

    await expect(establishAdmittedNativeSessionV2(
      clientNative,
      rawWebTransportFSB2,
      new Set(),
      config("client", 8, undefined, rawWebTransportFSB2),
    )).rejects.toMatchObject({ reason: "invalid_fsa2" });
    await server;
  });

  test("aborts and resets a native admission stream whose FSB2 write is blocked", async () => {
    const [clientNative] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const blocked = new BlockingAdmissionWriteCarrier(clientNative);
    const controller = new AbortController();
    const connecting = establishAdmittedNativeSessionV2(
      blocked,
      rawWebTransportFSB2,
      new Set(),
      config("client", 8, undefined, rawWebTransportFSB2),
      { signal: controller.signal },
    );
    await blocked.writeEntered.promise;
    controller.abort(new Error("admission deadline"));
    const outcome = await Promise.race([
      connecting.then(() => "connected", (error: unknown) => error instanceof Error ? error.message : String(error)),
      new Promise<string>((resolve) => setTimeout(() => resolve("blocked"), 50)),
    ]);
    blocked.releaseWrite.resolve();
    await connecting.catch(() => undefined);
    expect(outcome).toBe("admission deadline");
    expect(blocked.streamAborts).toBe(1);
    expect(blocked.sessionAborts).toBe(1);
  });

  test("does not retain hanging reset or close work after admission is aborted", async () => {
    const [clientNative] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: 10 });
    const blocked = new BlockingAdmissionWriteCarrier(clientNative, true);
    const controller = new AbortController();
    const connecting = establishAdmittedNativeSessionV2(
      blocked,
      rawWebTransportFSB2,
      new Set(),
      config("client", 8, undefined, rawWebTransportFSB2),
      { signal: controller.signal },
    );
    await blocked.writeEntered.promise;
    controller.abort(new Error("admission deadline"));

    let outcome: string;
    try {
      outcome = await Promise.race([
        connecting.then(() => "connected", (error: unknown) => error instanceof Error ? error.message : String(error)),
        new Promise<string>((resolve) => setTimeout(() => resolve("blocked"), 50)),
      ]);
      expect(outcome).toBe("admission deadline");
      expect(blocked.activeResets).toBe(0);
      expect(blocked.activeCloses).toBe(0);
      expect(blocked.streamAborts).toBe(1);
      expect(blocked.sessionAborts).toBe(1);
    } finally {
      blocked.releaseCleanup.resolve();
      blocked.releaseWrite.resolve();
      await connecting.catch(() => undefined);
    }
  });

  test("rejects malformed WSS FSB2 before writing credential bytes", async () => {
    const transport = new FailingReadBinaryTransport();
    await expect(establishAdmittedWebSocketSessionV2(
      transport,
      new TextEncoder().encode("FSB2-invalid"),
      new Set(),
      config("client"),
    )).rejects.toMatchObject({ reason: "invalid_fsb2" });
    expect(transport.writtenBytes).toBe(0);
  });

  test("rejects a WSS admission binding mismatch before writing credential bytes", async () => {
    const transport = new FailingReadBinaryTransport();
    const mismatched = config("client");
    mismatched.localAdmissionBinding = mismatched.localAdmissionBinding.slice();
    mismatched.localAdmissionBinding[0] ^= 0xff;
    await expect(establishAdmittedWebSocketSessionV2(
      transport,
      rawWebSocketFSB2,
      new Set(),
      mismatched,
    )).rejects.toMatchObject({ reason: "admission_binding_mismatch" });
    expect(transport.writtenBytes).toBe(0);
  });

  test("rejects a direct peer admission binding mismatch before writing credential bytes", async () => {
    const transport = new FailingReadBinaryTransport();
    const mismatched = config("client");
    mismatched.peerAdmissionBinding = new Uint8Array(32).fill(0x77);
    await expect(establishAdmittedWebSocketSessionV2(
      transport,
      rawWebSocketFSB2,
      new Set(),
      mismatched,
    )).rejects.toMatchObject({ reason: "peer_admission_binding_mismatch" });
    expect(transport.writtenBytes).toBe(0);
  });

  test("rejects a stale session contract hash field before writing credential bytes", async () => {
    const transport = new FailingReadBinaryTransport();
    const valid = config("client");
    const mismatched: SessionConfigV2 = {
      ...valid,
      sessionContract: { ...valid.sessionContract!, contract_hash_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
    };
    await expect(establishAdmittedWebSocketSessionV2(
      transport,
      rawWebSocketFSB2,
      new Set(),
      mismatched,
    )).rejects.toMatchObject({ reason: "session_config_mismatch" });
    expect(transport.writtenBytes).toBe(0);
  });

  test("closes WSS transport when FSA2 read fails after credential write", async () => {
    const transport = new FailingAdmissionResponseTransport();
    await expect(establishAdmittedWebSocketSessionV2(
      transport,
      rawWebSocketFSB2,
      new Set(),
      config("client"),
    )).rejects.toThrow("weak network read failure");
    expect(transport.writtenBytes).toBe(rawWebSocketFSB2.length);
    expect(transport.closeCount).toBe(1);
  });

  test("rejects a chosen-candidate carrier mismatch before writing credential bytes", async () => {
    const transport = new FailingReadBinaryTransport();
    await expect(establishAdmittedWebSocketSessionV2(
      transport,
      rawQUICFSB2,
      new Set(),
      config("client", 8, undefined, rawQUICFSB2),
    )).rejects.toMatchObject({ reason: "carrier_mismatch" });
    expect(transport.writtenBytes).toBe(0);
  });

  test("rejects native FSB2 path drift before stream open or credential bytes", async () => {
    const native = new CapacityMismatchNativeCarrier(10);
    await expect(establishAdmittedNativeSessionV2(
      native,
      rawTunnelWebTransportFSB2,
      new Set(),
      config("client", 8, undefined, rawTunnelWebTransportFSB2, "direct"),
    )).rejects.toMatchObject({ reason: "path_mismatch" });
    expect(native.opens).toBe(0);
    expect(native.writtenBytes).toBe(0);
  });
});

class BlockingAdmissionWriteCarrier implements NativeCarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity;
  readonly writeEntered = deferred<void>();
  readonly releaseWrite = deferred<void>();
  readonly releaseCleanup = deferred<void>();
  resets = 0;
  closes = 0;
  activeResets = 0;
  activeCloses = 0;
  streamAborts = 0;
  sessionAborts = 0;
  private opens = 0;

  constructor(
    private readonly inner: NativeCarrierSessionV2,
    private readonly hangCleanup = false,
  ) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<NativeCarrierStreamV2> {
    const stream = await this.inner.openStream(options);
    this.opens++;
    if (this.opens !== 1) return stream;
    return {
      read: async () => await stream.read(),
      write: async (data) => {
        this.writeEntered.resolve();
        await this.releaseWrite.promise;
        return await stream.write(data);
      },
      closeWrite: async () => await stream.closeWrite(),
      reset: async () => {
        this.resets++;
        if (this.hangCleanup) {
          this.activeResets++;
          try {
            await this.releaseCleanup.promise;
          } finally {
            this.activeResets--;
          }
        }
        await stream.reset();
      },
      abort: () => {
        this.streamAborts++;
        this.activeResets = 0;
        stream.abort();
      },
    };
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<NativeCarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(): Promise<void> {
    this.closes++;
    if (this.hangCleanup) {
      this.activeCloses++;
      try {
        await this.releaseCleanup.promise;
      } finally {
        this.activeCloses--;
      }
    }
    await this.inner.close();
  }

  abort(): void {
    this.sessionAborts++;
    this.activeResets = 0;
    this.activeCloses = 0;
    this.inner.abort();
  }
}

class CapacityMismatchNativeCarrier implements NativeCarrierSessionV2 {
  readonly kind = "webtransport" as const;
  readonly path = "direct" as const;
  opens = 0;
  writtenBytes = 0;

  constructor(readonly inboundBidirectionalStreamCapacity: number) {}

  async openStream(): Promise<NativeCarrierStreamV2> {
    this.opens++;
    return {
      read: async () => null,
      write: async (data) => {
        this.writtenBytes += data.length;
        return data.length;
      },
      closeWrite: async () => undefined,
      reset: async () => undefined,
      abort: () => undefined,
    };
  }

  async acceptStream(): Promise<NativeCarrierStreamV2> {
    return await this.openStream();
  }

  async close(): Promise<void> {}
  abort(): void {}
}

class BinaryEndpoint implements WebSocketBinaryTransportV2 {
  peer: BinaryEndpoint | undefined;
  writtenBytes = 0;
  private readonly queued: Uint8Array[] = [];
  private readonly waiters: Array<(value: Uint8Array) => void> = [];
  private error: Error | undefined;

  async readBinary(): Promise<Uint8Array> {
    if (this.error !== undefined) throw this.error;
    const value = this.queued.shift();
    if (value !== undefined) return value;
    return await new Promise<Uint8Array>((resolve) => this.waiters.push(resolve));
  }

  async writeBinary(data: Uint8Array): Promise<void> {
    if (this.error !== undefined) throw this.error;
    this.writtenBytes += data.length;
    this.peer?.push(data.slice());
  }

  close(): void {
    this.fail(new Error("binary transport closed"));
    this.peer?.fail(new Error("binary transport closed by peer"));
  }

  private push(value: Uint8Array): void {
    const waiter = this.waiters.shift();
    if (waiter !== undefined) waiter(value);
    else this.queued.push(value);
  }

  private fail(error: Error): void {
    if (this.error !== undefined) return;
    this.error = error;
  }
}

class FailingReadBinaryTransport implements WebSocketBinaryTransportV2 {
  writtenBytes = 0;

  async readBinary(): Promise<Uint8Array> {
    throw new Error("read must not be reached");
  }

  async writeBinary(data: Uint8Array): Promise<void> {
    this.writtenBytes += data.length;
  }

  close(): void {}
}

class FailingAdmissionResponseTransport implements WebSocketBinaryTransportV2 {
  writtenBytes = 0;
  closeCount = 0;

  async readBinary(): Promise<Uint8Array> {
    throw new Error("weak network read failure");
  }

  async writeBinary(data: Uint8Array): Promise<void> {
    this.writtenBytes += data.length;
  }

  close(): void {
    this.closeCount++;
  }
}

function binaryPair(): readonly [BinaryEndpoint, BinaryEndpoint] {
  const left = new BinaryEndpoint();
  const right = new BinaryEndpoint();
  left.peer = right;
  right.peer = left;
  return [left, right];
}

function fixtureSessionContract(maxInboundStreams: number): SessionContractV2 {
  const positive = artifactFixture.positive.find((entry) => entry.path_kind === "direct")!;
  const artifact = JSON.parse(positive.artifact_json) as Readonly<{ session: SessionContractV2 }>;
  const session = { ...artifact.session, max_inbound_streams: maxInboundStreams };
  return { ...session, contract_hash_b64u: computeSessionContractHashV2(session).hashBase64URL };
}

function fsb2Fixture(path: "direct" | "tunnel", candidateID: string, maxInboundStreams = 8): Uint8Array {
  const positive = artifactFixture.positive.find((entry) => entry.path_kind === path)!;
  const winner = positive.winners.find((entry) => entry.candidate_id === candidateID)!;
  const decoded = decodeFSB2RequestV2(Uint8Array.from(Buffer.from(winner.fsb2_hex, "hex")));
  return encodeFSB2RequestV2({
    ...decoded.request,
    session_contract_hash_b64u: fixtureSessionContract(maxInboundStreams).contract_hash_b64u,
  });
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}>;

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}
