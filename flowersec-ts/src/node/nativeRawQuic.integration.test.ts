import { createRequire } from "node:module";

import { describe, expect, test, vi } from "vitest";
import * as currentNativeTransport from "./nativeTransportCurrent.js";

import {
  nativeTransportContractVersion,
  type NativeOperation,
  type NativeRawListener,
  type NativeRawSession,
  type NativeRawStream,
  type NativeSubmission,
  type NativeTransportBinding,
} from "./nativeTransportCurrent.js";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MethodDefinition, ServiceDefinition, bytesMessageCodec, connect, createHandlerPlan,
  type AcceptedSession, type HandlerPlan, type Session, type Stream,
} from "./index.js";
import {
  configureCurrentPeerRawQUIC, configureCurrentPeerWSS, createCurrentPeerClient, installCurrentPoolServerAllow, peerJSONBytes, peerJSONValue,
  peerRequirements, peerServices, type CurrentPeerClient,
} from "../interop/currentPeer.js";
import { createCurrentPeerServer } from "../interop/currentServer.js";
import { createCurrentNativeTunnel } from "../interop/currentNativeTunnel.js";
import { startInvalidProofPeer } from "../interop/invalidProofPeer.js";
import { array, bytes, encode, fill, map, text, u } from "../v4/testSupport/credentials.js";
import { inspectEnvelopePrefix } from "../v4/runtime/envelope.js";
import { wire } from "../v4/runtime/wireRegistry.js";
import { NodeWSSCarrier } from "./wssV4.js";
import type { RelayHopByteMeter, RelayNativePairPreparation } from "./relayNativePair.js";

type RelayBufferWrite = Readonly<{ position: number; side: 0 | 1; scope: bigint; sequence: bigint; frameType: number; buffer: Uint8Array }>;
type RelayMeterSettlement = Readonly<{ meter: number; requested: number; actual: number | undefined; charged: number }>;
const relayTestObservation = vi.hoisted(() => ({
  nextPosition: 0,
  positions: new WeakMap<object, number>(),
  buffers: new WeakMap<Uint8Array, Readonly<{ position: number; side: 0 | 1 }>>(),
  writes: [] as RelayBufferWrite[],
  returnedPositions: [] as number[],
  meters: [] as RelayMeterSettlement[],
  nextMeter: 0,
}));
vi.mock("./relayNativePair.js", async importOriginal => {
  type OriginalPreparation = typeof RelayNativePairPreparation;
  type OriginalMeter = typeof RelayHopByteMeter;
  type RelayPairModule = { RelayNativePairPreparation: OriginalPreparation; RelayHopByteMeter: OriginalMeter };
  const original = await importOriginal<RelayPairModule>();
  class ObservedPreparation extends original.RelayNativePairPreparation {
    override take(config: Parameters<InstanceType<OriginalPreparation>["take"]>[0]): ReturnType<InstanceType<OriginalPreparation>["take"]> {
      const result = super.take(config);
      for (const [positionIndex, position] of result.positions.entries()) {
        let positionID = relayTestObservation.positions.get(position);
        if (positionID === undefined) { positionID = relayTestObservation.nextPosition++; relayTestObservation.positions.set(position, positionID); }
        for (const [side, buffer] of position.buffers.entries()) {
          relayTestObservation.buffers.set(buffer, { position: positionID, side: side as 0 | 1 });
          const set = buffer.set.bind(buffer);
          Object.defineProperty(buffer, "set", { configurable: true, value: (source: ArrayLike<number>, offset?: number): void => {
            set(source, offset);
            const start = offset ?? 0, end = start + source.length;
            if (end < 8 || buffer[5] !== 0 || buffer[6] !== 0 || buffer[7] !== 0) return;
            const expected = 8 + new DataView(buffer.buffer, buffer.byteOffset, 8).getUint32(0);
            if (expected !== end) return;
            const identity = nativeRecordIdentity(buffer.subarray(0, end));
            const frameType = buffer[4];
            if (identity !== undefined && frameType !== undefined) relayTestObservation.writes.push({ position: positionID!, side: side as 0 | 1, scope: identity.scope, sequence: identity.sequence, frameType, buffer });
          } });
        }
        void positionIndex;
      }
      const push = result.positions.push.bind(result.positions);
      Object.defineProperty(result.positions, "push", { configurable: true, value: (...positions: Parameters<typeof push>): number => {
        const length = push(...positions);
        for (const position of positions) {
          const id = relayTestObservation.positions.get(position);
          if (id === undefined) throw new Error("returned relay position was not originally observed");
          relayTestObservation.returnedPositions.push(id);
        }
        return length;
      } });
      return result;
    }
  }
  class ObservedMeter extends original.RelayHopByteMeter {
    constructor(...args: ConstructorParameters<OriginalMeter>) {
      super(...args);
      const meterID = relayTestObservation.nextMeter++;
      const reserve = this.reserve.bind(this);
      Object.defineProperty(this, "reserve", { configurable: true, value: async (bytes: number): Promise<(actual: number | undefined) => void> => {
        const settle = await reserve(bytes);
        return actual => {
          relayTestObservation.meters.push({ meter: meterID, requested: bytes, actual, charged: actual === undefined ? bytes : actual });
          settle(actual);
        };
      } });
    }
  }
  return { ...original, RelayNativePairPreparation: ObservedPreparation, RelayHopByteMeter: ObservedMeter };
});

const CERTIFICATE_DER = Buffer.from("MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==", "base64");
const PRIVATE_KEY_DER = Buffer.from("MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6", "base64");
describe("Node native raw QUIC driver", () => {
  test("runs the current addon contract with isolated ALPN and original TLS evidence", async () => {
    const pair = await openPair(4);
    try {
      expect(pair.client.wireVersion).toBe(4);
      expect(pair.server.wireVersion).toBe(4);
      expect(pair.client.path).toBe("direct");
      expect(pair.server.path).toBe("direct");
      const tls = pair.client.tls();
      expect(tls.version).toBe("TLSv1.3");
      expect(tls.alpn).toBe("flowersec-direct/4");
      expect(tls.earlyDataAccepted).toBe(false);
      expect(tls.dedicatedConnection).toBe(true);
      expect(tls.certificateVerified).toBe(true);
      expect(tls.peerLeafDER).toEqual(new Uint8Array(CERTIFICATE_DER));
      const outgoing = await pair.client.openStream().result();
      await writeNative(outgoing, new Uint8Array([3]));
      const incoming = await pair.server.acceptStream().result();
      expect(Array.from((await incoming.read(16).result())!)).toEqual([3]);
    } finally {
      await pair.cleanup();
    }
  }, 20_000);

  test("enforces a short-lived P-256 leaf pin without CA fallback", async () => {
    const directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-node-raw-pin-v4-"));
    const binding = loadBinding();
    let listener: NativeRawListener | undefined;
    let client: NativeRawSession | undefined;
    let server: NativeRawSession | undefined;
    let accepting: Promise<NativeRawSession> | undefined;
    let rejecting: Promise<void | undefined> | undefined;
    try {
      const certificatePath = join(directory, "leaf.pem");
      const certificateDERPath = join(directory, "leaf.der");
      const keyPath = join(directory, "leaf.key");
      const keyDERPath = join(directory, "leaf-key.der");
      runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keyPath]);
      runOpenSSL([
        "req", "-x509", "-new", "-key", keyPath, "-sha256", "-days", "2",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
        "-out", certificatePath,
      ]);
      runOpenSSL(["x509", "-in", certificatePath, "-outform", "DER", "-out", certificateDERPath]);
      runOpenSSL(["pkcs8", "-topk8", "-nocrypt", "-in", keyPath, "-outform", "DER", "-out", keyDERPath]);
      const certificateDER = readFileSync(certificateDERPath);
      const keyDER = readFileSync(keyDERPath);
      const pin = createHash("sha256").update(certificateDER).digest();
      listener = await binding.bindRawQuic({
        ...nativeLimits,
        host: "127.0.0.1", port: 0, path: "direct",
        certificateChainDer: [certificateDER], privateKeyDer: keyDER,
        inboundBidirectionalStreamCapacity: 4, pendingConnections: 8,
      });
      const address = listener.address();
      accepting = listener.accept().result();
      void accepting.catch(() => undefined);
      client = await binding.connectRawQuic({
        ...nativeLimits,
        host: address.host, port: address.port, serverName: "localhost", path: "direct",
        tlsMode: "pin", activeLeafDerSha256: [pin], inboundBidirectionalStreamCapacity: 4,
      }).result();
      server = await accepting;
      expect(client.tls().certificateVerified).toBe(true);
      expect(client.tls().peerLeafDER).toEqual(new Uint8Array(certificateDER));
      expect(client.tls().alpn).toBe("flowersec-direct/4");
      client.abort();
      server.abort();
      await Promise.all([client.waitTermination(), server.waitTermination()]);

      const wrong = Buffer.from(pin);
      wrong[0] = (wrong[0] ?? 0) ^ 0xff;
      rejecting = listener.accept().result().then(
        async accepted => { accepted.abort(); await accepted.waitTermination(); },
        () => undefined,
      );
      await expect(binding.connectRawQuic({
        ...nativeLimits,
        host: address.host, port: address.port, serverName: "localhost", path: "direct",
        tlsMode: "pin", activeLeafDerSha256: [wrong], inboundBidirectionalStreamCapacity: 4,
      }).result()).rejects.toThrow(/^pin_mismatch$/u);
      await rejecting;
      // The current native ABI rejects a mixed pin/CA policy before dialing;
      // trusted roots cannot provide a fallback for the failed signed pin.
      expect(() => binding.connectRawQuic({
        ...nativeLimits,
        host: address.host, port: address.port, serverName: "localhost", path: "direct",
        tlsMode: "pin", activeLeafDerSha256: [wrong], trustRootsDer: [certificateDER],
        inboundBidirectionalStreamCapacity: 4,
      })).toThrow(/^invalid_tls_policy$/u);
    } finally {
      client?.abort();
      server?.abort();
      await listener?.close();
      const lateServer = await accepting?.catch(() => undefined);
      lateServer?.abort();
      await Promise.all([client?.waitTermination(), server?.waitTermination(), lateServer?.waitTermination(), rejecting, listener?.waitTermination()]);
      rmSync(directory, { recursive: true, force: true });
    }
  }, 20_000);

  test("rejects a hash-matched leaf with an invalid TLS proof before current admission or durable spend", async () => {
    const peer = await startInvalidProofPeer("raw_quic");
    const endpoint = new URL(`quic://${peer.address}`);
    const now = BigInt(Date.now());
    const digest = new Uint8Array(createHash("sha256").update(peer.leafDER).digest());
    const leg = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(0),
      6: text(endpoint.hostname), 7: u(Number(endpoint.port)), 8: text(""), 9: text("flowersec-direct/4"), 10: text(""),
      11: map({ 0: u(1), 1: { kind: "bool", value: true }, 2: u(0), 3: array(map({
        0: bytes(digest), 1: u(now - 60000n), 2: u(now + 3600000n), 3: text("x509v3-p256-14d"),
      })) }) });
    let authority: Awaited<ReturnType<typeof createCurrentPeerServer>> | undefined;
    let fixture: CurrentPeerClient | undefined;
    try {
      authority = await createCurrentPeerServer(environment => createHandlerPlan(environment, { applicationBytes: 16384n,
        services: { ...peerServices, profile: "services" }, streams: [] }), "https://app.example", { applicationProfile: "services", carrier: "raw-quic", routeLeg: leg });
      fixture = await createCurrentPeerClient(authority.artifactJSON, { trustPEM: authority.trustPEM });
      const owner = configureCurrentPeerRawQUIC(fixture, authority.trustPEM);
      await expect(connect(fixture.environment, fixture.registerSource(owner), peerRequirements, { signal: AbortSignal.timeout(3000) }))
        .rejects.toMatchObject({ code: "authentication_failed", connection: { spendState: "unspent", networkReady: "not_started" } });
      expect(fixture.spentCount()).toBe(0);
      await peer.wait();
    } finally {
      await fixture?.close();
      await authority?.close();
      await peer.stop();
      digest.fill(0); peer.leafDER.fill(0);
    }
  }, 45000);

  test("runs stream, FIN, datagram, cancellation, and cleanup through N-API", async () => {
    const binding = loadBinding();
    // The current provider admits the bounded 4096 application positions plus
    // its fixed maintenance stream. Reject the first value beyond that bound.
    expect(() => bindListener(binding, 4098)).toThrow(/^invalid_limits$/u);
    expect(() => bindListener(binding, 0)).toThrow(/^invalid_limits$/u);
    expect(() => binding.bindRawQuic({
      ...nativeLimits,
      host: "127.0.0.1", port: 0, path: "invalid" as "direct",
      certificateChainDer: [CERTIFICATE_DER], privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 3, pendingConnections: 8,
    })).toThrow(/^invalid_path$/u);

    const pair = await openPair(10);
    try {
      const outbound = await pair.client.openStream().result();
      await writeNative(outbound, new Uint8Array([1, 2, 3]));
      const inbound = await pair.server.acceptStream().result();
      await outbound.closeWrite();
      expect(Array.from((await inbound.read(16).result())!)).toEqual([1, 2, 3]);
      expect(await inbound.read(16).result()).toBeNull();
      await inbound.closeWrite();
      expect(await outbound.read(16).result()).toBeNull();
      await Promise.all([outbound.waitTermination(), inbound.waitTermination()]);

      const resetOutbound = await pair.client.openStream().result();
      await writeNative(resetOutbound, new Uint8Array([9]));
      const resetInbound = await pair.server.acceptStream().result();
      expect(Array.from((await resetInbound.read(16).result())!)).toEqual([9]);
      await resetOutbound.resetWrite();
      await expect(resetInbound.read(16).result()).rejects.toThrow(/^direction_reset$/u);
      resetOutbound.abort();
      resetInbound.abort();
      await Promise.all([resetOutbound.waitTermination(), resetInbound.waitTermination()]);

      expect(pair.client.maxDatagramBytes()).toBeGreaterThanOrEqual(2);
      expect(pair.server.maxDatagramBytes()).toBeGreaterThanOrEqual(2);
      await completeSubmission(pair.client.submitDatagram(new Uint8Array([4, 5])));
      expect(Array.from(await pair.server.receiveDatagram(16).result())).toEqual([4, 5]);
      // Direct N-API Option<T> exports use null; the package facade normalizes
      // the same unavailable submission to undefined for SDK callers.
      expect(pair.client.submitDatagram(new Uint8Array(65_000))).toBeNull();

      const address = pair.listener.address();
      const acceptOperation = pair.listener.accept();
      const pendingAccept = acceptOperation.result();
      acceptOperation.cancel();
      await expect(pendingAccept).rejects.toThrow(/^canceled$/u);
      expect(pair.listener.address().port).toBe(address.port);

      const receiveOperation = pair.client.receiveDatagram(16);
      const pendingReceive = receiveOperation.result();
      receiveOperation.cancel();
      await expect(pendingReceive).rejects.toThrow(/^canceled$/u);

      pair.client.abort();
      pair.client.abort();
      await pair.server.waitTermination();
    } finally {
      await pair.cleanup();
      await pair.listener.close();
      await pair.listener.waitTermination();
    }
  });

  test("propagates STOP_SENDING to the peer send direction", async () => {
    const pair = await openPair(3);
    try {
      const outbound = await pair.client.openStream().result();
      await writeNative(outbound, new Uint8Array([7]));
      const inbound = await pair.server.acceptStream().result();

      await inbound.stopSending();
      await completeSubmission(pair.server.submitDatagram(new Uint8Array([8])));
      expect(Array.from(await pair.client.receiveDatagram(16).result())).toEqual([8]);
      await expect(writeNative(outbound, new Uint8Array([9]))).rejects.toThrow(/^direction_reset$/u);
    } finally {
      await pair.cleanup();
    }
  });

  test("enforces runtime stream capacity and cancels an in-flight open", async () => {
    const pair = await openPair(1);
    try {
      expect(pair.client.inboundBidirectionalStreamCapacity).toBe(1);
      expect(pair.server.inboundBidirectionalStreamCapacity).toBe(1);
      const heldOutbound = await pair.client.openStream().result();
      await writeNative(heldOutbound, new Uint8Array([1]));
      const heldInbound = await pair.server.acceptStream().result();
      let settled = false;
      const operation = pair.client.openStream();
      const pendingOpen = operation.result();
      void pendingOpen.then(
        () => { settled = true; },
        () => { settled = true; },
      );

      await new Promise<void>((resolve) => { setImmediate(resolve); });
      expect(settled).toBe(false);
      operation.cancel();
      await expect(pendingOpen).rejects.toThrow(/^canceled$/u);
      heldOutbound.abort();
      heldInbound.abort();
      await Promise.all([heldOutbound.waitTermination(), heldInbound.waitTermination()]);
    } finally {
      await pair.cleanup();
    }
  });

  test("reports peer abort for pending native operations", async () => {
    const pair = await openPair(3);
    try {
      const pendingAccept = pair.server.acceptStream().result();
      const pendingReceive = pair.server.receiveDatagram(16).result();
      const accepted = expect(pendingAccept).rejects.toThrow(/^closed$/u);
      const received = expect(pendingReceive).rejects.toThrow(/^closed$/u);

      pair.client.abort();

      await Promise.all([accepted, received]);
      await pair.server.waitTermination();
    } finally {
      await pair.cleanup();
    }
  });
});

describe("Node current production raw QUIC runtime", () => {
  test("pairs raw QUIC tunnel roles through original registered B and releases active-pair quota", async () => {
    let resolvePayload!: (bytes: Uint8Array) => void;
    let rejectPayload!: (reason: unknown) => void;
    const payload = new Promise<Uint8Array>((resolve, reject) => { resolvePayload = resolve; rejectPayload = reject; });
    void payload.catch(() => undefined);
    const tunnel = await createCurrentNativeTunnel("node-v4-raw-tunnel", async (stream, signal) => {
      try {
        const value = await readCurrentNativePayload(stream, signal);
        await stream.closeWrite({ signal }); resolvePayload(value);
        const result = await stream.finish({ signal }); if (!result.send_drained) throw new Error("native tunnel FIN did not drain");
      } catch (error) { rejectPayload(error); throw error; }
    });
    let fixture: CurrentPeerClient | undefined, client: Session | undefined, accepted: AcceptedSession | undefined, outgoing: Stream | undefined;
    let poolServerAllow: ReturnType<typeof installCurrentPoolServerAllow> | undefined;
    const signal = AbortSignal.timeout(15000);
    try {
      fixture = await createCurrentPeerClient(tunnel.relay.endpointAArtifactJSON, { trustPEM: tunnel.trustPEM });
      poolServerAllow = installCurrentPoolServerAllow(fixture, tunnel.poolClientInstallation, tunnel.serverAllow);
      const connector = configureCurrentPeerRawQUIC(fixture, tunnel.trustPEM, undefined, tunnel.listenerTLS, poolServerAllow);
      const acceptor = tunnel.acceptor;
      if (acceptor === null || typeof acceptor !== "object" || !("accept" in acceptor) || typeof acceptor.accept !== "function") throw new Error("original tunnel acceptor unavailable");
      const accepting = acceptor.accept({ signal }) as Promise<AcceptedSession>; void accepting.catch(() => undefined);
      tunnel.relay.start();
      client = await connect(fixture.environment, fixture.registerSource(connector), peerRequirements, { signal });
      accepted = await accepting;
      expect(fixture.spentCount()).toBe(1);
      outgoing = await client.openStream("node-v4-raw-tunnel", { signal });
      const progress = await outgoing.write(new Uint8Array([3, 2, 1]), { signal });
      expect(progress.terminal_reason).toBe("complete"); expect(progress.accepted_bytes).toBe(3n);
      await outgoing.closeWrite({ signal });
      await expect(payload).resolves.toEqual(new Uint8Array([3, 2, 1]));
      const end = await outgoing.read(16n, { signal }); expect(end.stream_status).toBe("eof");
      await outgoing.close({ signal }); outgoing = undefined;
      await Promise.all([client.close(), accepted.close()]);
      expect((await client.waitCleanup()).status).toBe("complete"); expect((await accepted.waitCleanup()).status).toBe("complete");
      await tunnel.relay.runtime.close();
      expect(tunnel.relay.runtime.status().activePairs).toBe(0);
    } finally {
      await outgoing?.close(); await client?.close(); await accepted?.close(); await poolServerAllow?.close(); await fixture?.close(); await tunnel.close();
    }
  }, 30000);

  test("retires native tunnel mappings across successive sibling streams", async () => {
    const handled: Uint8Array[] = [];
    let resolveHandled!: () => void;
    const handledTwice = new Promise<void>(resolve => { resolveHandled = resolve; });
    const tunnel = await createCurrentNativeTunnel("node-v4-raw-tunnel-slot-reuse", async (stream, signal) => {
      try {
        handled.push(await readCurrentNativePayload(stream, signal));
        await stream.closeWrite({ signal });
        const result = await stream.finish({ signal });
        if (!result.send_drained) throw new Error("native tunnel FIN did not drain");
        if (handled.length === 2) resolveHandled();
      } catch (error) {
        resolveHandled();
        throw error;
      }
    });
    let fixture: CurrentPeerClient | undefined;
    let client: Session | undefined;
    let accepted: AcceptedSession | undefined;
    let poolServerAllow: ReturnType<typeof installCurrentPoolServerAllow> | undefined;
    const signal = AbortSignal.timeout(15000);
    try {
      fixture = await createCurrentPeerClient(tunnel.relay.endpointAArtifactJSON, { trustPEM: tunnel.trustPEM });
      poolServerAllow = installCurrentPoolServerAllow(fixture, tunnel.poolClientInstallation, tunnel.serverAllow);
      const connector = configureCurrentPeerRawQUIC(fixture, tunnel.trustPEM, undefined, tunnel.listenerTLS, poolServerAllow);
      const acceptor = tunnel.acceptor;
      if (acceptor === null || typeof acceptor !== "object" || !("accept" in acceptor) || typeof acceptor.accept !== "function") throw new Error("original tunnel acceptor unavailable");
      const accepting = acceptor.accept({ signal }) as Promise<AcceptedSession>;
      void accepting.catch(() => undefined);
      tunnel.relay.start();
      client = await connect(fixture.environment, fixture.registerSource(connector), peerRequirements, { signal });
      accepted = await accepting;
      const payloads = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])] as const;
      for (const [index, payload] of payloads.entries()) {
        const outgoing = await client.openStream("node-v4-raw-tunnel-slot-reuse", { signal });
        try {
          const progress = await outgoing.write(payload, { signal });
          expect(progress.terminal_reason).toBe("complete");
          expect(progress.accepted_bytes).toBe(BigInt(payload.length));
          await outgoing.closeWrite({ signal });
          const end = await outgoing.read(16n, { signal });
          expect(end.stream_status).toBe("eof");
          expect(end.data.length).toBe(0);
          const finish = await outgoing.finish({ signal });
          expect(finish.send_drained).toBe(true);
        } finally {
          await outgoing.close().catch(() => undefined);
        }
        expect(handled[index]).toEqual(payload);
      }
      await handledTwice;
      expect(handled).toHaveLength(2);
      await client.close();
      await accepted.close();
      expect((await client.waitCleanup()).status).toBe("complete");
      expect((await accepted.waitCleanup()).status).toBe("complete");
      await tunnel.relay.runtime.close();
      expect(tunnel.relay.runtime.status().activePairs).toBe(0);
      expect(fixture.spentCount()).toBe(1);
    } finally {
      await client?.close().catch(() => undefined);
      await accepted?.close().catch(() => undefined);
      await poolServerAllow?.close();
      await fixture?.close();
      await tunnel.close();
    }
  }, 30000);

  test("retires native WSS/native mappings across successive sibling streams", async () => {
    const installation = process.env.FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION;
    if (installation === undefined) throw new Error("FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION is required");
    const handled: Uint8Array[] = [];
    let entered!: () => void, releaseRead!: () => void;
    const enteredFirst = new Promise<void>(resolve => { entered = resolve; });
    const releaseFirst = new Promise<void>(resolve => { releaseRead = resolve; });
    let resolveHandled!: () => void;
    const handledTwice = new Promise<void>(resolve => { resolveHandled = resolve; });
    const tunnel = await createCurrentNativeTunnel("node-v4-wss-tunnel-slot-reuse", async (stream, signal) => {
      try {
        if (handled.length === 0) { entered(); await releaseFirst; }
        handled.push(await readCurrentNativePayload(stream, signal));
        await stream.closeWrite({ signal });
        const result = await stream.finish({ signal });
        if (!result.send_drained) throw new Error("native tunnel FIN did not drain");
        if (handled.length === 2) resolveHandled();
      } catch (error) {
        resolveHandled();
        throw error;
      }
    }, installation);
    let fixture: CurrentPeerClient | undefined;
    let client: Session | undefined;
    let accepted: AcceptedSession | undefined;
    let poolServerAllow: ReturnType<typeof installCurrentPoolServerAllow> | undefined;
    const signal = AbortSignal.timeout(15000);
    try {
      fixture = await createCurrentPeerClient(tunnel.relay.endpointAArtifactJSON, { trustPEM: tunnel.trustPEM });
      poolServerAllow = installCurrentPoolServerAllow(fixture, tunnel.poolClientInstallation, tunnel.serverAllow);
      const connector = configureCurrentPeerWSS(fixture, tunnel.origin, tunnel.trustPEM, undefined, tunnel.listenerTLS, poolServerAllow);
      const acceptor = tunnel.acceptor;
      if (acceptor === null || typeof acceptor !== "object" || !("accept" in acceptor) || typeof acceptor.accept !== "function") throw new Error("original tunnel acceptor unavailable");
      const accepting = acceptor.accept({ signal }) as Promise<AcceptedSession>;
      void accepting.catch(() => undefined);
      tunnel.relay.start();
      client = await connect(fixture.environment, fixture.registerSource(connector), peerRequirements, { signal });
      accepted = await accepting;
      const payloads = [[new Uint8Array([1, 2]), new Uint8Array([3])], [new Uint8Array([4, 5]), new Uint8Array([6])]] as const;
      for (const [index, parts] of payloads.entries()) {
        const outgoing = await client.openStream("node-v4-wss-tunnel-slot-reuse", { signal });
        try {
          if (index === 0) await enteredFirst;
          const first = await outgoing.write(parts[0], { signal });
          expect(first.terminal_reason).toBe("complete");
          const second = await outgoing.write(parts[1], { signal });
          expect(second.terminal_reason).toBe("complete");
          releaseRead();
          await outgoing.closeWrite({ signal });
          const end = await outgoing.read(16n, { signal });
          expect(end.stream_status).toBe("eof");
          expect(end.data.length).toBe(0);
          const finish = await outgoing.finish({ signal });
          expect(finish.send_drained).toBe(true);
        } finally {
          await outgoing.close().catch(() => undefined);
        }
        expect(handled[index]).toEqual(new Uint8Array([...parts[0], ...parts[1]]));
      }
      await handledTwice;
      expect(handled).toHaveLength(2);
      await client.close();
      await accepted.close();
      expect((await client.waitCleanup()).status).toBe("complete");
      expect((await accepted.waitCleanup()).status).toBe("complete");
      await tunnel.relay.runtime.close();
      expect(tunnel.relay.runtime.status().activePairs).toBe(0);
      expect(fixture.spentCount()).toBe(1);
    } finally {
      releaseRead();
      await client?.close().catch(() => undefined);
      await accepted?.close().catch(() => undefined);
      await poolServerAllow?.close();
      await fixture?.close();
      await tunnel.close();
    }
  }, 30000);

  test("drops buffered WSS DATA after native direction retirement and keeps sibling mappings alive", async () => {
    const installation = process.env.FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION;
    if (installation === undefined) throw new Error("FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION is required");
    const rawStreams: Array<{ stream: NativeRawStream; local: Readonly<{ host: string; port: number }>; peer: Readonly<{ host: string; port: number }>; action: string }> = [];
    const rawStreamIds = new WeakMap<object, number>();
    const nativeFrames: Array<{ id: number; action: string; phase: "read" | "submit"; frameType: number; scope: bigint | undefined; sequence: bigint | undefined; bytes: number }> = [];
    let nextRawStreamId = 0;
    let provider: NativeRawStream | undefined;
    const acceptedStreams = new Map<bigint, NativeRawStream>();
    const wssFrames: Array<{ frameType: number; scope: bigint | undefined; sequence: bigint | undefined; bytes: number }> = [];
    const relayWSSReads: Array<{ maximum: number; bytes: number; frames: readonly number[] }> = [];
    let retiredScopeForObservation: bigint | undefined;
    let resolveTailObserved!: () => void;
    const tailObserved = new Promise<void>(resolve => { resolveTailObserved = resolve; });
    const nativeBinding = currentNativeTransport.loadCurrentNativeTransport();
    const nativeObservation = vi.spyOn(currentNativeTransport, "loadCurrentNativeTransport").mockReturnValue(observeNativeRawStreams(nativeBinding, (stream, session, action, frameType, phase, bytes) => {
      let id = rawStreamIds.get(stream);
      if (id === undefined) { id = nextRawStreamId++; rawStreamIds.set(stream, id); }
      rawStreams.push({ stream, local: session.localAddress(), peer: session.peerAddress(), action });
      const identity = bytes === undefined ? undefined : nativeRecordIdentity(bytes);
      if (phase !== undefined && frameType !== undefined) nativeFrames.push({ id, action, phase, frameType, scope: identity?.scope, sequence: identity?.sequence, bytes: bytes?.length ?? 0 });
      if (action === "accept" && phase === "read" && frameType === wire.frame_types.OPEN_STREAM && identity?.scope !== undefined) acceptedStreams.set(identity.scope, stream);
    }));
    const originalWSSRead = NodeWSSCarrier.prototype.read;
    const wssStates = new WeakMap<NodeWSSCarrier, { applicationReads: number; held: boolean }>();
    let releaseRead!: () => void;
    const readRelease = new Promise<void>(resolve => { releaseRead = resolve; });
    let resolveHeld!: () => void;
    const readHeld = new Promise<void>(resolve => { resolveHeld = resolve; });
    const wssObservation = vi.spyOn(NodeWSSCarrier.prototype, "read").mockImplementation(async function (this: NodeWSSCarrier, maximum, options) {
      const carrier = this;
      const metadata = this as unknown as { readonly role?: string; readonly path?: string };
      const state = wssStates.get(carrier) ?? { applicationReads: 0, held: false };
      wssStates.set(carrier, state);
      if (metadata.role === "server" && metadata.path === "tunnel" && state.applicationReads === 3 && !state.held) {
        state.held = true;
        resolveHeld();
        await readRelease;
      }
      const bytes = await originalWSSRead.call(this, maximum, options);
      if (bytes !== null) {
        const frames = nativeEnvelopeFrames(bytes);
        if (metadata.role === "server" && metadata.path === "tunnel") relayWSSReads.push({ maximum, bytes: bytes.length, frames: frames.map(frame => frame.bytes.length) });
        for (const frame of frames) {
          if (frame.frameType !== wire.frame_types.OPEN_STREAM && frame.frameType !== wire.frame_types.STREAM_DATA) continue;
          const identity = nativeRecordIdentity(frame.bytes);
          wssFrames.push({ frameType: frame.frameType, scope: identity?.scope, sequence: identity?.sequence, bytes: frame.bytes.length });
          state.applicationReads++;
          if (frame.frameType === wire.frame_types.STREAM_DATA && retiredScopeForObservation !== undefined && identity?.scope === retiredScopeForObservation && (identity.sequence ?? 0n) >= 2n && wssFrames.filter(value => value.frameType === wire.frame_types.STREAM_DATA && value.scope === retiredScopeForObservation && (value.sequence ?? 0n) >= 2n).length === 3) resolveTailObserved();
        }
      }
      return bytes;
    });
    const handled: Uint8Array[] = [];
    let resolveHandlerEntered!: () => void;
    const handlerEntered = new Promise<void>(resolve => { resolveHandlerEntered = resolve; });
    let resolveHandlerDone!: () => void;
    const handlerDone = new Promise<void>(resolve => { resolveHandlerDone = resolve; });
    const tunnel = await createCurrentNativeTunnel("node-v4-wss-native-retirement-tail", async (stream, signal) => {
      resolveHandlerEntered();
      try {
        handled.push(await readCurrentNativePayload(stream, signal));
        await stream.closeWrite({ signal });
        await stream.finish({ signal });
      } catch {
        // The first stream is intentionally stopped by the provider while its
        // buffered WSS DATA is still waiting in the real carrier.
      } finally { resolveHandlerDone(); }
    }, installation);
    let fixture: CurrentPeerClient | undefined;
    let client: Session | undefined;
    let accepted: AcceptedSession | undefined;
    let poolServerAllow: ReturnType<typeof installCurrentPoolServerAllow> | undefined;
    let first: Stream | undefined;
    let sibling: Stream | undefined;
    const signal = AbortSignal.timeout(15000);
    try {
      fixture = await createCurrentPeerClient(tunnel.relay.endpointAArtifactJSON, { trustPEM: tunnel.trustPEM });
      poolServerAllow = installCurrentPoolServerAllow(fixture, tunnel.poolClientInstallation, tunnel.serverAllow);
      const connector = configureCurrentPeerWSS(fixture, tunnel.origin, tunnel.trustPEM, undefined, tunnel.listenerTLS, poolServerAllow);
      const acceptor = tunnel.acceptor;
      if (acceptor === null || typeof acceptor !== "object" || !("accept" in acceptor) || typeof acceptor.accept !== "function") throw new Error("original tunnel acceptor unavailable");
      const accepting = acceptor.accept({ signal }) as Promise<AcceptedSession>;
      void accepting.catch(() => undefined);
      tunnel.relay.start();
      client = await connect(fixture.environment, fixture.registerSource(connector), peerRequirements, { signal });
      accepted = await accepting;
      first = await client.openStream("node-v4-wss-native-retirement-tail", { signal });
      await first.waitPeerAuthenticated(0n, { signal });
      await withinNativeEvent(handlerEntered);
      await first.write(new Uint8Array([1, 2]), { signal });
      await withinNativeEvent(readHeld);
      const appOpenIndex = wssFrames.findIndex((value, index) => value.frameType === wire.frame_types.OPEN_STREAM && wssFrames[index + 1]?.frameType === wire.frame_types.STREAM_DATA);
      const retiredScope = appOpenIndex < 0 ? undefined : wssFrames[appOpenIndex]?.scope;
      if (retiredScope === undefined) throw new Error(`WSS application DATA was not observed: ${wssFrames.map(value => `${value.frameType}:${value.scope?.toString() ?? "-"}:${value.sequence?.toString() ?? "-"}`).join(",")}`);
      retiredScopeForObservation = retiredScope;
      provider = acceptedStreams.get(retiredScope);
      if (provider === undefined) throw new Error(`native provider stream was not observed for scope ${retiredScope}`);
      const tailOne = first.write(new Uint8Array([3]), { signal });
      const tailTwo = tailOne.then(() => first!.write(new Uint8Array([4]), { signal }));
      const tailThree = tailTwo.then(() => first!.write(new Uint8Array([5]), { signal }));
      const streamsBeforeSibling = nextRawStreamId;
      const meterBeforeTail = relayTestObservation.meters.length;
      const relayWSSReadBeforeTail = relayWSSReads.length;
      const returnedPositionsBeforeStop = relayTestObservation.returnedPositions.length;
      await provider.stopSending("normal_drained");
      await provider.closeWrite();
      await withinNativeEvent(provider.waitTermination());
      expect(tunnel.relay.runtime.status().activePairs).toBe(1);
      releaseRead();
      await tailOne;
      await tailTwo;
      await tailThree;
      await withinNativeEvent(tailObserved);
      const tailFrames = wssFrames.filter(value => value.frameType === wire.frame_types.STREAM_DATA && value.scope === retiredScope && (value.sequence ?? 0n) >= 2n);
      const tailBytes = tailFrames.reduce((total, value) => total + value.bytes, 0);
      const relayWSSIngressReads = relayWSSReads.slice(relayWSSReadBeforeTail);
      const relayWSSIngressChunks = relayWSSIngressReads.map(value => value.bytes);
      const relayWSSIngressBytes = relayWSSIngressChunks.reduce((total, value) => total + value, 0);
      const ingressMaximum = relayWSSIngressReads[0]?.maximum;
      if (ingressMaximum === undefined || relayWSSIngressReads.some(value => value.maximum !== ingressMaximum)) throw new Error("WSS ingress read bounds changed during tail");
      const hasIngressSettlements = (settlements: readonly RelayMeterSettlement[]): boolean => {
        const byMeter = new Map<number, number[]>();
        for (const settlement of settlements) {
          if (settlement.actual === undefined || settlement.requested !== ingressMaximum) continue;
          const charges = byMeter.get(settlement.meter) ?? [];
          charges.push(settlement.charged); byMeter.set(settlement.meter, charges);
        }
        return [...byMeter.values()].some(charges => charges.length === relayWSSIngressChunks.length && charges.every((charged, index) => charged === relayWSSIngressChunks[index]));
      };
      // A message-hop read reserves its destination bound before WSS.read and
      // settles its actual bytes afterward. Match that exact bound, meter,
      // count, and order so unrelated same-sized work cannot satisfy the check.
      await waitForNativeCondition(() => hasIngressSettlements(relayTestObservation.meters.slice(meterBeforeTail)));
      const meterTailSettlements = relayTestObservation.meters.slice(meterBeforeTail);
      expect(tailBytes).toBe(180);
      expect(relayWSSIngressBytes).toBeGreaterThanOrEqual(tailBytes);
      expect(hasIngressSettlements(meterTailSettlements)).toBe(true);
      expect(meterTailSettlements.filter(value => value.actual === undefined)).toHaveLength(0);
      await withinNativeEvent(handlerDone);
      const retiredPositions = new Set(relayTestObservation.writes.filter(value => value.frameType === wire.frame_types.OPEN_STREAM && value.scope === retiredScope).map(value => value.position));
      // Endpoint callback exit precedes the relay's own native retirement join.
      // Require that exact original position to return before testing reuse.
      await waitForNativeCondition(() => relayTestObservation.returnedPositions.slice(returnedPositionsBeforeStop).some(position => retiredPositions.has(position)));
      const siblingOpening = client.openStream("node-v4-wss-native-retirement-tail", { signal });
      sibling = await siblingOpening;
      await sibling.write(new Uint8Array([6, 7, 8]), { signal });
      await sibling.closeWrite({ signal });
      const end = await sibling.read(16n, { signal });
      expect(end.stream_status).toBe("eof");
      expect(end.data.length).toBe(0);
      expect((await sibling.finish({ signal })).send_drained).toBe(true);
      expect(handled.some(value => Buffer.from(value).equals(Buffer.from([6, 7, 8])))).toBe(true);
      expect(nextRawStreamId).toBeGreaterThan(streamsBeforeSibling);
      const nativeBeforeLiveness = nativeFrames.length;
      const liveness = await client.probeLiveness({ signal });
      expect(liveness.submitted).toBe(true);
      expect(liveness.complete).toBe(true);
      expect(nativeFrames.slice(nativeBeforeLiveness).some(value => value.phase === "submit" && value.bytes > 0 && value.frameType !== wire.frame_types.OPEN_STREAM && value.frameType !== wire.frame_types.STREAM_DATA)).toBe(true);
      expect(tailFrames).toHaveLength(3);
      expect(nativeFrames.some(value => value.phase === "submit" && value.frameType === wire.frame_types.STREAM_DATA && value.scope === retiredScope && (value.sequence ?? 0n) >= 2n)).toBe(false);
      const applicationOpenScopes = [...new Set(wssFrames.filter(value => value.frameType === wire.frame_types.OPEN_STREAM && value.scope !== undefined).map(value => value.scope!))];
      const siblingScope = applicationOpenScopes.at(-1);
      if (siblingScope === undefined) throw new Error("sibling application OPEN was not observed");
      expect(siblingScope).not.toBe(retiredScope);
      const siblingPositions = new Set(relayTestObservation.writes.filter(value => value.frameType === wire.frame_types.OPEN_STREAM && value.scope === siblingScope).map(value => value.position));
      expect([...retiredPositions].some(position => siblingPositions.has(position))).toBe(true);
      const retiredBuffers = relayTestObservation.writes.filter(value => value.frameType === wire.frame_types.OPEN_STREAM && value.scope === retiredScope).map(value => value.buffer);
      const siblingBuffers = relayTestObservation.writes.filter(value => value.frameType === wire.frame_types.OPEN_STREAM && value.scope === siblingScope).map(value => value.buffer);
      expect(retiredBuffers.some(buffer => siblingBuffers.includes(buffer))).toBe(true);
      await first.close().catch(() => undefined);
      await sibling.close().catch(() => undefined);
      await client.close();
      await accepted.close();
      expect((await client.waitCleanup()).status).toBe("complete");
      expect((await accepted.waitCleanup()).status).toBe("complete");
      await tunnel.relay.runtime.close();
      expect(tunnel.relay.runtime.status().activePairs).toBe(0);
      expect(tunnel.relay.runtime.status().forwardedBytes).toBeGreaterThan(0n);
      expect(fixture.spentCount()).toBe(1);
    } finally {
      releaseRead();
      await first?.close().catch(() => undefined);
      await sibling?.close().catch(() => undefined);
      await client?.close().catch(() => undefined);
      await accepted?.close().catch(() => undefined);
      await poolServerAllow?.close();
      await fixture?.close();
      await tunnel.close();
      wssObservation.mockRestore();
      nativeObservation.mockRestore();
    }
  }, 30000);

  test.each(["unknown DATA", "duplicate OPEN"] as const)("rejects %s on the authenticated WSS hop", async variant => {
    const installation = process.env.FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION;
    if (installation === undefined) throw new Error("FLOWERSEC_NATIVE_WSS_TUNNEL_INSTALLATION is required");
    let mode: "unknown" | "duplicate" | undefined;
    let injected = false;
    let firstScope: bigint | undefined;
    const openScopes: bigint[] = [];
    let resolveFirstOpen!: () => void;
    const firstOpen = new Promise<void>(resolve => { resolveFirstOpen = resolve; });
    let resolveInjected!: () => void;
    const injectedEvent = new Promise<void>(resolve => { resolveInjected = resolve; });
    const originalWSSRead = NodeWSSCarrier.prototype.read;
    const wssObservation = vi.spyOn(NodeWSSCarrier.prototype, "read").mockImplementation(async function (this: NodeWSSCarrier, maximum, options) {
      const bytes = await originalWSSRead.call(this, maximum, options);
      if (bytes === null) return bytes;
      const metadata = this as unknown as { readonly role?: string; readonly path?: string };
      if (metadata.role !== "server" || metadata.path !== "tunnel") return bytes;
      const frames = nativeEnvelopeFrames(bytes);
      for (const frame of frames) {
        if (frame.frameType !== wire.frame_types.OPEN_STREAM || !nativeRecordIdentity(frame.bytes)?.scope) continue;
        const scope = nativeRecordIdentity(frame.bytes)!.scope;
        if (!openScopes.includes(scope)) openScopes.push(scope);
        if (openScopes.length === 2 && firstScope === undefined) { firstScope = scope; resolveFirstOpen(); }
      }
      if (mode === undefined || firstScope === undefined || injected) return bytes;
      const copy = new Uint8Array(bytes);
      let offset = 0;
      for (const frame of frames) {
        const identity = nativeRecordIdentity(frame.bytes);
        const mutate = mode === "unknown" ? frame.frameType === wire.frame_types.STREAM_DATA && identity?.scope === firstScope : frame.frameType === wire.frame_types.OPEN_STREAM && identity?.scope !== undefined && identity.scope !== firstScope;
        if (mutate) {
          const view = new DataView(copy.buffer, copy.byteOffset + offset, frame.bytes.length);
          view.setBigUint64(12, mode === "unknown" ? firstScope ^ 0x1000000000000000n : firstScope);
          injected = true;
          resolveInjected();
          return copy;
        }
        offset += frame.bytes.length;
      }
      return bytes;
    });
    const tunnel = await createCurrentNativeTunnel(`node-v4-wss-protocol-rejection-${variant}`, async (stream, signal) => {
      await readCurrentNativePayload(stream, signal).catch(() => undefined);
    }, installation);
    let fixture: CurrentPeerClient | undefined;
    let client: Session | undefined;
    let accepted: AcceptedSession | undefined;
    let poolServerAllow: ReturnType<typeof installCurrentPoolServerAllow> | undefined;
    let first: Stream | undefined;
    try {
      fixture = await createCurrentPeerClient(tunnel.relay.endpointAArtifactJSON, { trustPEM: tunnel.trustPEM });
      poolServerAllow = installCurrentPoolServerAllow(fixture, tunnel.poolClientInstallation, tunnel.serverAllow);
      const connector = configureCurrentPeerWSS(fixture, tunnel.origin, tunnel.trustPEM, undefined, tunnel.listenerTLS, poolServerAllow);
      const acceptor = tunnel.acceptor;
      if (acceptor === null || typeof acceptor !== "object" || !("accept" in acceptor) || typeof acceptor.accept !== "function") throw new Error("original tunnel acceptor unavailable");
      const signal = AbortSignal.timeout(15000);
      const accepting = acceptor.accept({ signal }) as Promise<AcceptedSession>;
      void accepting.catch(() => undefined);
      tunnel.relay.start();
      client = await connect(fixture.environment, fixture.registerSource(connector), peerRequirements, { signal });
      accepted = await accepting;
      first = await client.openStream(`node-v4-wss-protocol-rejection-${variant}`, { signal });
      await first.waitPeerAuthenticated(0n, { signal });
      await withinNativeEvent(firstOpen);
      mode = variant === "unknown DATA" ? "unknown" : "duplicate";
      if (mode === "unknown") {
        const writing = first.write(new Uint8Array([9]), { signal });
        void writing.catch(() => undefined);
        await withinNativeEvent(injectedEvent);
        await waitForNativeCondition(() => tunnel.relay.runtime.status().activePairs === 0);
        await writing.catch(() => undefined);
        await expect(client.probeLiveness({ signal })).rejects.toThrow();
      } else {
        const duplicate = client.openStream(`node-v4-wss-protocol-rejection-${variant}`, { signal }).then(async stream => {
          try { await stream.waitPeerAuthenticated(0n, { signal }); }
          finally { await stream.close().catch(() => undefined); }
        });
        void duplicate.catch(() => undefined);
        await withinNativeEvent(injectedEvent);
        await waitForNativeCondition(() => tunnel.relay.runtime.status().activePairs === 0);
        await expect(duplicate).rejects.toThrow();
      }
      expect(injected).toBe(true);
    } finally {
      await first?.close().catch(() => undefined);
      await client?.close().catch(() => undefined);
      await accepted?.close().catch(() => undefined);
      await poolServerAllow?.close();
      await fixture?.close();
      await tunnel.close();
      wssObservation.mockRestore();
    }
  }, 30000);

  test.each([false, true])("admits direct raw QUIC with original stores, typed RPC, stream FIN, and cleanup (hold DRAINED: %s)", async (holdDrained) => {
    const codec = bytesMessageCodec({ schemaDigest: new Uint8Array(32), revision: "1", maxMessageBytes: 4096 });
    const method = new MethodDefinition({ typeID: 9_106, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 4096, minResponseLimitBytes: 0, maxResponseBytes: 4096, restartFlush: false });
    const definition = new ServiceDefinition({ namespace: "flowersec.native", methods: { raw: method } });
    const contract = encode(map({
      0: text(definition.namespace), 1: u(method.typeID), 2: u(0), 3: u(0),
      6: text("1"), 7: text("1"), 8: u(1), 9: u(0), 10: u(4096), 11: u(30000), 12: u(30000),
      21: { kind: "bool", value: false }, 23: u(4096), 27: array(),
    }));
    const services = { ...peerServices, definitions: [definition], maxMethods: 1, notificationMethods: [],
      queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" as const }] };
    let resolveStream!: (value: Uint8Array) => void;
    let rejectStream!: (reason: unknown) => void;
    const handledStream = new Promise<Uint8Array>((resolve, reject) => { resolveStream = resolve; rejectStream = reject; });
    void handledStream.catch(() => undefined);
    let expectedClientIdentity: string | undefined;
    const server = await createCurrentPeerServer(environment => createHandlerPlan(environment, {
      applicationBytes: 16384n,
      services: { ...services, profile: "services", unaryHandlers: [{ namespace: definition.namespace, method, contract,
        handler: async (_context, payload: Uint8Array) => peerJSONBytes({ raw: peerJSONValue(payload) }),
        options: { workClass: "short", maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" } }] },
      streams: [{ kind: "node-v4-raw-direct", authorize: () => true,
        options: { workClass: "resident", applicationBytes: 16384n, maxConcurrentStreams: 2, maxAuthorizing: 2, applicationTimeoutMS: 10000n },
        handler: async (stream, context) => {
          try {
            const value = await readCurrentNativePayload(stream, context.signal);
            await stream.closeWrite({ signal: context.signal });
            resolveStream(value);
            const finished = await stream.finish({ signal: context.signal });
            if (!finished.send_drained) throw new Error("raw QUIC handler FIN did not drain");
          } catch (error) { rejectStream(error); throw error; }
        } }],
    }), "https://app.example", { applicationProfile: "services", carrier: "raw-quic", onAuthenticated: context => {
      expect(Object.keys(context.invocation)).toEqual([]);
      expect(Object.isFrozen(context.invocation)).toBe(true);
      expect(context.authentication.peerIdentityDigest).toHaveLength(64);
      expect(context.authentication.peerIdentityDigest).toBe(expectedClientIdentity);
      expect(context.authentication).toMatchObject({ tenant: "tenant", audience: "service", localRole: "server", localSubject: "server", peerSubject: "client" });
    } });
    expectedClientIdentity = server.clientIdentity;
    let fixture: CurrentPeerClient | undefined;
    let clientPlan: HandlerPlan | undefined;
    let client: Session | undefined;
    let accepted: AcceptedSession | undefined;
    let outgoing: Stream | undefined;
    let releaseService: (() => void) | undefined;
    let captureNextStream = false, holdFIN = false, finSubmitted = false, finAborted = false, nativeFIN = false;
    let releaseFIN!: () => void;
    const finTail = new Promise<void>(resolve => { releaseFIN = resolve; });
    let releaseControl!: () => void, controlHeld!: () => void;
    const controlTail = new Promise<void>(resolve => { releaseControl = resolve; });
    const controlPending = new Promise<void>(resolve => { controlHeld = resolve; });
    let holdControl = false, opened = 0, physicalEnd: Promise<void> | undefined, physicalEnded = false;
    const nativeBinding = currentNativeTransport.loadCurrentNativeTransport();
    // Preserve the actual installed native connection, stream, TLS and bytes.
    // Only delay observation of one original FIN submission's completion so
    // authenticated peer DRAINED can overtake its JavaScript continuation.
    const nativeObservation = vi.spyOn(currentNativeTransport, "loadCurrentNativeTransport").mockReturnValue({
      ...nativeBinding,
      connectRawQuic: options => {
        const connection = nativeBinding.connectRawQuic(options);
        const result = connection.result().then(session => ({
          ...session,
          openStream: () => {
            const target = captureNextStream, maintenance = opened++ === 0; captureNextStream = false;
            const opening = session.openStream();
            const stream = opening.result().then(original => {
              let ownsFIN = false;
              if (target) physicalEnd = original.waitTermination().then(() => { physicalEnded = true; });
              return {
                ...original,
                read: (maximum: number) => {
                  const reading = original.read(maximum);
                  const result = reading.result().then(async bytes => {
                    if (maintenance && holdControl && bytes !== null) { controlHeld(); await controlTail; }
                    return bytes;
                  });
                  return { result: () => result, cancel: () => reading.cancel() };
                },
                submit: (bytes: Uint8Array) => {
                  const submission = original.submit(bytes);
                  if (submission === undefined || !target || !holdFIN || inspectEnvelopePrefix(bytes, 65536).frameType !== wire.frame_types.STREAM_DATA) return submission;
                  holdFIN = false; ownsFIN = true; finSubmitted = true;
                  const completion = submission.completion().then(() => finTail);
                  return { completion: () => completion };
                },
                closeWrite: () => { if (ownsFIN) nativeFIN = true; return original.closeWrite(); },
                abort: () => { if (ownsFIN) finAborted = true; original.abort(); },
              };
            });
            return { result: () => stream, cancel: () => opening.cancel() };
          },
        }));
        return { result: () => result, cancel: () => connection.cancel() };
      },
    });
    try {
      fixture = await createCurrentPeerClient(server.artifactJSON, { trustPEM: server.trustPEM });
      clientPlan = createHandlerPlan(fixture.environment, { applicationBytes: 16384n, services: { ...services, profile: "services" }, streams: [] });
      const owner = configureCurrentPeerRawQUIC(fixture, server.trustPEM, clientPlan);
      const accepting = server.acceptor.accept();
      void accepting.catch(() => undefined);
      client = await connect(fixture.environment, fixture.registerSource(owner), peerRequirements);
      accepted = await accepting;
      expect(fixture.spentCount()).toBe(1);
      const serving = accepted.serve();
      void serving.catch(() => undefined);
      const service = await client.bindService(definition, { target: { authority: fixture.policy.authorities[0]!,
        tenant: fixture.policy.tenant, audience: fixture.policy.audience, localSubject: fixture.policy.clientSubject,
        peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity }] }, maximumOfferWindowMS: 10000n });
      releaseService = () => service.close();
      const response = await service.call(method, peerJSONBytes({ carrier: "raw_quic" }), { responseLimitBytes: 4096 });
      expect(response.kind).toBe("value");
      if (response.kind !== "value" || response.encoding !== "typed") throw new Error("raw QUIC RPC did not return typed bytes");
      try { expect(peerJSONValue(response.value)).toEqual({ raw: { carrier: "raw_quic" } }); }
      finally { response.release(); }
      service.close();
      releaseService = undefined;
      captureNextStream = true;
      outgoing = await client.openStream("node-v4-raw-direct");
      const progress = await outgoing.write(new Uint8Array([3, 0, 3]));
      expect(progress.phase).toBe("terminal");
      expect(progress.terminal_reason).toBe("complete");
      expect(progress.accepted_bytes).toBe(3n);
      holdControl = holdDrained;
      holdFIN = true;
      const closing = outgoing.closeWrite();
      void closing.catch(() => undefined);
      await expect(handledStream).resolves.toEqual(new Uint8Array([3, 0, 3]));
      const end = await outgoing.read(16n);
      expect(end.wait_status).toBe("ready");
      expect(end.stream_status).toBe("eof");
      expect(end.data.length).toBe(0);
      let finished = false;
      const finishing = outgoing.finish().then(result => { finished = true; return result; });
      void finishing.catch(() => undefined);
      if (holdDrained) {
        // Hold only the original maintenance read result. Native application
        // traffic and STOP_SENDING still run, without fabricating any frames.
        await withinNativeEvent(controlPending);
        await withinNativeEvent(physicalEnd!);
        expect(finished).toBe(false);
        expect((await outgoing.closeWrite()).send_drained).toBe(false);
        expect(outgoing.cleanupStatus().status).toBe("pending");
        expect(outgoing.cleanupStatus().core_cleanup).toBe("pending");
        expect(fixture.spentCount()).toBe(1);
      } else {
        // Authenticated DRAINED can overtake the retained publication tail.
        expect((await finishing).send_drained).toBe(true);
      }
      expect(finSubmitted).toBe(true);
      expect(nativeFIN).toBe(false);
      expect(finAborted).toBe(false);
      expect(outgoing.cleanupStatus().status).toBe("pending");
      releaseFIN();
      await closing;
      holdControl = false; releaseControl();
      expect((await finishing).send_drained).toBe(true);
      await client.probeLiveness();
      await outgoing.close();
      expect(nativeFIN || physicalEnded).toBe(true);
      if (holdDrained) expect(nativeFIN).toBe(false);
      outgoing = undefined;
      await accepted.close();
      await expect(serving).resolves.toBeUndefined();
      expect((await accepted.waitCleanup()).status).toBe("complete");
      await client.close();
      expect((await client.waitCleanup()).status).toBe("complete");
      expect(fixture.spentCount()).toBe(1);
    } finally {
      releaseFIN(); releaseControl();
      nativeObservation.mockRestore();
      releaseService?.();
      await outgoing?.close().catch(() => undefined);
      await client?.close().catch(() => undefined);
      await accepted?.close().catch(() => undefined);
      clientPlan?.close();
      await fixture?.close();
      await server.close();
      contract.fill(0);
    }
  }, 20_000);
});

function wrapNativeOperation<T>(operation: NativeOperation<T>, transform: (value: T) => T): NativeOperation<T> {
  return { result: () => operation.result().then(transform), cancel: () => operation.cancel() };
}

function observeNativeRawStreams(binding: NativeTransportBinding, onStream: (stream: NativeRawStream, session: NativeRawSession, action: string, frameType?: number, phase?: "read" | "submit", bytes?: Uint8Array) => void): NativeTransportBinding {
  const stream = (original: NativeRawStream, session: NativeRawSession, action: string): NativeRawStream => {
    let wrapped: NativeRawStream;
    let readRemainder = new Uint8Array(0);
    wrapped = { ...original,
      read: maximum => wrapNativeOperation(original.read(maximum), value => {
        if (value === null) { onStream(wrapped, session, action, undefined, "read"); return value; }
        const combined = new Uint8Array(readRemainder.length + value.length);
        combined.set(readRemainder); combined.set(value, readRemainder.length);
        const frames = nativeEnvelopeFrames(combined);
        const consumed = frames.reduce((total, frame) => total + frame.bytes.length, 0);
        readRemainder = combined.slice(consumed);
        if (frames.length === 0) onStream(wrapped, session, action, undefined, "read", value);
        else for (const frame of frames) onStream(wrapped, session, action, frame.frameType, "read", frame.bytes);
        return value;
      }),
      submit: data => {
        const frames = nativeEnvelopeFrames(data);
        if (frames.length === 0) onStream(wrapped, session, action, undefined, "submit", data);
        else for (const frame of frames) onStream(wrapped, session, action, frame.frameType, "submit", frame.bytes);
        return original.submit(data);
      },
    };
    onStream(wrapped, session, action);
    return wrapped;
  };
  const session = (original: NativeRawSession): NativeRawSession => ({
    ...original,
    openStream: () => wrapNativeOperation(original.openStream(), value => stream(value, original, "open")),
    acceptStream: () => wrapNativeOperation(original.acceptStream(), value => stream(value, original, "accept")),
  });
  const listener = (original: NativeRawListener): NativeRawListener => ({
    ...original,
    accept: () => wrapNativeOperation(original.accept(), value => session(value)),
  });
  return {
    ...binding,
    connectRawQuic: options => wrapNativeOperation(binding.connectRawQuic(options), value => session(value)),
    bindRawQuic: async options => listener(await binding.bindRawQuic(options)),
  };
}

function nativeEnvelopeFrames(bytes: Uint8Array): readonly { frameType: number; bytes: Uint8Array }[] {
  const frames: Array<{ frameType: number; bytes: Uint8Array }> = [];
  for (let offset = 0; offset < bytes.length;) {
    let prefix: Readonly<{ frameType: number; payloadBytes: number }>;
    try { prefix = inspectEnvelopePrefix(bytes.subarray(offset), 65536); } catch { break; }
    const length = 8 + prefix.payloadBytes;
    if (length > bytes.length - offset) break;
    frames.push({ frameType: prefix.frameType, bytes: bytes.subarray(offset, offset + length) });
    offset += length;
  }
  return frames;
}

function nativeRecordIdentity(bytes: Uint8Array): Readonly<{ scope: bigint; sequence: bigint }> | undefined {
  if (bytes.length < 28) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { scope: view.getBigUint64(12), sequence: view.getBigUint64(20) };
}

async function withinNativeEvent(event: Promise<void>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([event, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("native event did not complete")), 3000); })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

async function waitForNativeCondition(condition: () => boolean): Promise<void> {
  const limit = Date.now() + 3000;
  while (!condition()) {
    if (Date.now() >= limit) throw new Error("native condition did not complete");
    await new Promise<void>(resolve => { setTimeout(resolve, 5); });
  }
}

const nativeLimits = Object.freeze({ readBufferBytes: 16_384, datagramQueueBytes: 65_536, handshakeTimeoutMs: 2_000 });

type NativePair = Readonly<{
  client: NativeRawSession;
  server: NativeRawSession;
  listener: NativeRawListener;
  cleanup(): Promise<void>;
}>;

async function openPair(capacity: number): Promise<NativePair> {
  const binding = loadBinding();
  const listener = await bindListener(binding, capacity);
  let client: NativeRawSession | undefined;
  let server: NativeRawSession | undefined;
  const accepting = listener.accept().result();
  // Preserve the original accept task even when the client's handshake fails.
  void accepting.catch(() => undefined);
  try {
    const address = listener.address();
    client = await binding.connectRawQuic({
      ...nativeLimits,
      host: address.host, port: address.port, serverName: "localhost", path: "direct",
      tlsMode: "ca", trustRootsDer: [CERTIFICATE_DER], inboundBidirectionalStreamCapacity: capacity,
    }).result();
    server = await accepting;
    const connectedClient = client;
    const connectedServer = server;
    return {
      client: connectedClient,
      server: connectedServer,
      listener,
      async cleanup() {
        connectedClient.abort();
        connectedServer.abort();
        await Promise.all([connectedClient.waitTermination(), connectedServer.waitTermination()]);
        await listener.close();
        await listener.waitTermination();
      },
    };
  } catch (error) {
    client?.abort();
    server?.abort();
    await listener.close();
    const lateServer = await accepting.catch(() => undefined);
    lateServer?.abort();
    await Promise.all([client?.waitTermination(), server?.waitTermination(), lateServer?.waitTermination(), listener.waitTermination()]);
    throw error;
  }
}

function loadBinding(): NativeTransportBinding {
  const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
  if (addonPath === undefined) throw new Error("FLOWERSEC_NATIVE_ADDON_PATH is required");
  const binding = createRequire(import.meta.url)(addonPath) as NativeTransportBinding;
  if (binding.contractVersion() !== nativeTransportContractVersion) throw new Error("native ABI4 is required");
  return binding;
}

function bindListener(binding: NativeTransportBinding, capacity: number): Promise<NativeRawListener> {
  return binding.bindRawQuic({
    ...nativeLimits,
    host: "127.0.0.1", port: 0, path: "direct",
    certificateChainDer: [CERTIFICATE_DER], privateKeyDer: PRIVATE_KEY_DER,
    inboundBidirectionalStreamCapacity: capacity, pendingConnections: 8,
  });
}

async function completeSubmission(submission: NativeSubmission | undefined): Promise<void> {
  if (submission === undefined) throw new Error("native submission refused");
  await submission.completion();
}

async function writeNative(stream: NativeRawStream, bytes: Uint8Array): Promise<void> {
  await completeSubmission(stream.submit(bytes));
}

async function readCurrentNativePayload(stream: Stream, signal: AbortSignal): Promise<Uint8Array> {
  const output = new Uint8Array(16);
  let length = 0;
  for (;;) {
    const result = await stream.read(16n, { signal });
    if (result.wait_status !== "ready" || result.stream_status === "aborted" || result.stream_status === "error") throw new Error("raw QUIC handler read failed");
    if (result.data.length > output.length - length) throw new Error("raw QUIC handler input exceeds its bound");
    output.set(result.data, length);
    length += result.data.length;
    if (result.stream_status === "eof") return output.slice(0, length);
    if (result.data.length === 0) throw new Error("empty open raw QUIC handler read");
  }
}

function runOpenSSL(args: readonly string[]): void {
  execFileSync("openssl", [...args], { stdio: "ignore" });
}
