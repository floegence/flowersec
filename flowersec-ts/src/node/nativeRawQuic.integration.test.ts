import { createRequire } from "node:module";

import { afterAll, beforeAll, describe, expect, test, vi } from "vitest";

import {
  createNativeRawQuicDriver,
  createNativeWebTransportDriver,
  type NativeRawQuicDriver,
  type NativeRawQuicListener,
  type NativeTransportAddonBinding,
} from "./nativeTransportAddon.js";
import { adaptNativeCarrierSessionV3, type NativeCarrierSessionV3 } from "../v3/carrier.js";
import { SessionHandlersV3 } from "./acceptor.js";
import {
  decodeArtifactV3JSON,
  encodeArtifactV3JSON,
  type ArtifactCandidateV3,
  type ArtifactV3,
} from "../v3/artifact.js";
import { createArtifactLeaseV3Internal } from "../v3/artifactLease.js";
import { parseArtifactV3 } from "../v3/publicApi.js";
import { connectV3 } from "./connectSessionV3.js";
import { createAcceptorV3 } from "./acceptorV3.js";
import { bridgeTunnelPairV3, createTunnelRuntimeV3 } from "./tunnelRuntimeV3.js";
import {
  createTunnelVerificationRecord,
  verifyTunnelAuthorizationGrantV3,
  type TunnelVerificationRecord,
} from "./runtimeAuthorizationV3.js";
import { readFileSync } from "node:fs";
import { createHash, X509Certificate } from "node:crypto";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createNodeRawQuicClientV3 } from "./rawQuicAdapterV3.js";

const CERTIFICATE_DER = Buffer.from("MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==", "base64");
const PRIVATE_KEY_DER = Buffer.from("MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6", "base64");
const CERTIFICATE_PEM = pem("CERTIFICATE", CERTIFICATE_DER);
const PRIVATE_KEY_PEM = pem("PRIVATE KEY", PRIVATE_KEY_DER);
const v3Fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v5/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const V3_DIRECT_BASE = decodeArtifactV3JSON(v3Fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "direct")!.artifact_json);
const V3_TUNNEL_BASE = decodeArtifactV3JSON(v3Fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "tunnel")!.artifact_json);
let previousServerParityPeer: string | undefined;

beforeAll(() => {
  previousServerParityPeer = process.env.FLOWERSEC_SERVER_PARITY_PEER;
  process.env.FLOWERSEC_SERVER_PARITY_PEER = "1";
});

afterAll(() => {
  if (previousServerParityPeer === undefined) delete process.env.FLOWERSEC_SERVER_PARITY_PEER;
  else process.env.FLOWERSEC_SERVER_PARITY_PEER = previousServerParityPeer;
});

describe("Node native raw QUIC driver", () => {
  test("runs the Flowersec/5 addon entries with isolated ALPN", async () => {
    const v3 = loadDriver();
    const listener = await v3.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 4,
      handshakeTimeoutMs: 2_000,
    });
    let client: Awaited<ReturnType<typeof v3.connectRawQuic>> | undefined;
    let server: Awaited<ReturnType<typeof listener.accept>> | undefined;
    try {
      const accepting = listener.accept();
      const address = listener.address();
      client = await v3.connectRawQuic({
        host: address.host,
        port: address.port,
        serverName: "localhost",
        path: "direct",
        tlsMode: "ca",
        trustRootsDer: [CERTIFICATE_DER],
        inboundBidirectionalStreamCapacity: 4,
        handshakeTimeoutMs: 2_000,
      });
      server = await accepting;
      const outgoing = await client.openStream();
      await outgoing.write(new Uint8Array([3]));
      const incoming = await server.acceptStream();
      expect(Array.from((await incoming.read())!)).toEqual([3]);
    } finally {
      client?.abort();
      server?.abort();
      await listener.close();
    }
  }, 20_000);

  test("enforces a short-lived P-256 leaf pin without CA fallback", async () => {
    const directory = mkdtempSync(join(tmpdir(), "flowersec-node-raw-pin-v3-"));
    const driver = loadDriver();
    let listener: Awaited<ReturnType<typeof driver.bindRawQuic>> | undefined;
    try {
      const certificatePath = join(directory, "leaf.pem");
      const certificateDERPath = join(directory, "leaf.der");
      const keyPath = join(directory, "leaf.key");
      const keyDERPath = join(directory, "leaf-key.der");
      runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keyPath]);
      runOpenSSL([
        "req", "-x509", "-new", "-key", keyPath, "-sha256", "-days", "2",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
        "-out", certificatePath,
      ]);
      runOpenSSL(["x509", "-in", certificatePath, "-outform", "DER", "-out", certificateDERPath]);
      runOpenSSL(["pkcs8", "-topk8", "-nocrypt", "-in", keyPath, "-outform", "DER", "-out", keyDERPath]);
      const certificateDER = readFileSync(certificateDERPath);
      const keyDER = readFileSync(keyDERPath);
      const pin = createHash("sha256").update(certificateDER).digest();
      listener = await driver.bindRawQuic({
        host: "127.0.0.1",
        port: 0,
        path: "direct",
        certificateChainDer: [certificateDER],
        privateKeyDer: keyDER,
        inboundBidirectionalStreamCapacity: 4,
        handshakeTimeoutMs: 2_000,
      });
      const address = listener.address();
      const artifact = {
        path: { kind: "direct" },
        session: { max_inbound_streams: 2 },
      } as ArtifactV3;
      const expires = Math.floor(Date.now() / 1_000) + 3_600;
      const accepting = listener.accept();
      const client = await createNodeRawQuicClientV3(driver, {
        carrier: "raw_quic",
        id: "q-pin",
        normalized_url: `quic://${address.host}:${address.port}`,
        tls: {
          mode: "pin",
          pins: [{ algorithm: "sha-256", value_b64u: pin.toString("base64url"), not_after_unix_s: expires }],
        },
        wire_profile: "flowersec-direct/5",
      }, artifact, Math.floor(Date.now() / 1_000));
      const server = await accepting;
      client.abort();
      server.abort();

      const wrong = Buffer.from(pin);
      wrong[0] = (wrong[0] ?? 0) ^ 0xff;
      const rejectedServer = listener.accept().catch(() => undefined);
      await expect(createNodeRawQuicClientV3(driver, {
        carrier: "raw_quic",
        id: "q-pin",
        normalized_url: `quic://${address.host}:${address.port}`,
        tls: {
          mode: "pin",
          pins: [{ algorithm: "sha-256", value_b64u: wrong.toString("base64url"), not_after_unix_s: expires }],
        },
        wire_profile: "flowersec-direct/5",
      }, artifact, Math.floor(Date.now() / 1_000), {
        roots: certificateDER,
      })).rejects.toMatchObject({ code: "tls_failed", detail: "pin_mismatch" });
      await rejectedServer;
    } finally {
      await listener?.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }, 20_000);

  test("rejects a hash-matched leaf with an invalid TLS proof before FSB5 or lease spend", async () => {
    const peer = await startInvalidProofPeer();
    let spends = 0;
    const digest = createHash("sha256").update(peer.leafDER).digest("base64url");
    const artifact = {
      ...V3_DIRECT_BASE,
      path: {
        ...V3_DIRECT_BASE.path,
        candidates: [{
          carrier: "raw_quic",
          id: "q-invalid-proof",
          // The peer binds IPv4; target that listener so this TLS proof test
          // does not spend its handshake budget probing an absent IPv6 server.
          url: `quic://${peer.address}`,
          tls: {
            mode: "pin",
            pins: [{
              algorithm: "sha-256",
              value_b64u: digest,
              not_after_unix_s: Math.floor(Date.now() / 1_000) + 3_600,
            }],
          },
          wire_profile: "flowersec-direct/5",
        } satisfies ArtifactCandidateV3],
      },
    } as ArtifactV3;
    try {
      await expect(connectV3(createArtifactLeaseV3Internal(
        artifact,
        async () => { spends += 1; },
      ), {
        connectTimeoutMs: 3_000,
      })).rejects.toMatchObject({
        code: "transport_security_failed",
        retryDisposition: { kind: "terminal" },
      });
      expect(spends).toBe(0);
      await peer.wait();
    } finally {
      peer.stop();
    }
  }, 20_000);
  test("runs stream, FIN, datagram, cancellation, and cleanup through N-API", async () => {
    const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
    if (addonPath === undefined) throw new Error("FLOWERSEC_NATIVE_ADDON_PATH is required");
    const addon = createRequire(import.meta.url)(addonPath) as NativeTransportAddonBinding;
    const driver = createNativeRawQuicDriver(addon);
    await expect(driver.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 131,
      handshakeTimeoutMs: 2_000,
    })).rejects.toThrow(/invalid_limits/u);
    await expect(driver.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "invalid" as "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 3,
      handshakeTimeoutMs: 2_000,
    })).rejects.toThrow(/invalid_path/u);

    const listener = await driver.bindRawQuic({
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      certificateChainDer: [CERTIFICATE_DER],
      privateKeyDer: PRIVATE_KEY_DER,
      inboundBidirectionalStreamCapacity: 10,
      handshakeTimeoutMs: 2_000,
    });
    let client: Awaited<ReturnType<typeof driver.connectRawQuic>> | undefined;
    let server: Awaited<ReturnType<typeof listener.accept>> | undefined;
    try {
      const accepting = listener.accept();
      const address = listener.address();
      client = await driver.connectRawQuic({
        host: address.host,
        port: address.port,
        serverName: "localhost",
        path: "direct",
        tlsMode: "ca",
        trustRootsDer: [CERTIFICATE_DER],
        inboundBidirectionalStreamCapacity: 10,
        handshakeTimeoutMs: 2_000,
      });
      server = await accepting;

      const outbound = await client.openStream();
      expect(await outbound.write(new Uint8Array([1, 2, 3]))).toBe(3);
      const inbound = await server.acceptStream();
      await outbound.closeWrite();
      expect(Array.from((await inbound.read())!)).toEqual([1, 2, 3]);
      expect(await inbound.read()).toBeNull();
      await inbound.closeWrite();
      expect(await outbound.read()).toBeNull();

      const resetOutbound = await client.openStream();
      await resetOutbound.write(new Uint8Array([9]));
      const resetInbound = await server.acceptStream();
      expect(Array.from((await resetInbound.read())!)).toEqual([9]);
      await resetOutbound.reset();
      await expect(resetInbound.read()).rejects.toMatchObject({ code: "reset" });

      expect(client.unreliableDatagrams).toBeDefined();
      expect(server.unreliableDatagrams).toBeDefined();
      await expect(client.unreliableDatagrams!.send(new Uint8Array([4, 5]))).resolves.toBe("accepted");
      expect(Array.from(await server.unreliableDatagrams!.receive())).toEqual([4, 5]);
      await expect(client.unreliableDatagrams!.send(new Uint8Array(65_000)))
        .rejects.toMatchObject({ code: "datagram_unavailable" });

      const controller = new AbortController();
      const pendingAccept = listener.accept({ signal: controller.signal });
      controller.abort();
      await expect(pendingAccept).rejects.toMatchObject({ code: "aborted" });
      expect(listener.address().port).toBe(address.port);

      const receiveController = new AbortController();
      const pendingReceive = client.unreliableDatagrams!.receive({ signal: receiveController.signal });
      receiveController.abort();
      await expect(pendingReceive).rejects.toMatchObject({ code: "aborted" });

      client.abort();
      client.abort();
      await server.waitTermination();
    } finally {
      client?.abort();
      server?.abort();
      await listener.close();
      await listener.close();
    }
  });

  test("propagates STOP_SENDING to the peer send direction", async () => {
    const pair = await openPair(3);
    try {
      const outbound = await pair.client.openStream();
      await outbound.write(new Uint8Array([7]));
      const inbound = await pair.server.acceptStream();

      await inbound.stopSending();
      await pair.server.unreliableDatagrams!.send(new Uint8Array([8]));
      expect(Array.from(await pair.client.unreliableDatagrams!.receive())).toEqual([8]);
      await expect(outbound.write(new Uint8Array([9]))).rejects.toMatchObject({ code: "reset" });
    } finally {
      await pair.cleanup();
    }
  });

  test("enforces runtime stream capacity and cancels an in-flight open", async () => {
    const pair = await openPair(1);
    try {
      expect(pair.client.inboundBidirectionalStreamCapacity).toBe(1);
      expect(pair.server.inboundBidirectionalStreamCapacity).toBe(1);
      const heldOutbound = await pair.client.openStream();
      await heldOutbound.write(new Uint8Array([1]));
      const heldInbound = await pair.server.acceptStream();
      const controller = new AbortController();
      let settled = false;
      const pendingOpen = pair.client.openStream({ signal: controller.signal });
      void pendingOpen.then(
        () => { settled = true; },
        () => { settled = true; },
      );

      await new Promise<void>((resolve) => { setImmediate(resolve); });
      expect(settled).toBe(false);
      controller.abort();
      await expect(pendingOpen).rejects.toMatchObject({ code: "aborted" });
      await Promise.all([heldOutbound.reset(), heldInbound.reset()]);
    } finally {
      await pair.cleanup();
    }
  });

  test("maps peer abort into portable errors for pending operations", async () => {
    const pair = await openPair(3);
    try {
      const pendingAccept = pair.server.acceptStream();
      const pendingReceive = pair.server.unreliableDatagrams!.receive();
      const accepted = expect(pendingAccept).rejects.toMatchObject({ code: "closed" });
      const received = expect(pendingReceive).rejects.toMatchObject({ code: "closed" });

      pair.client.abort();

      await Promise.all([accepted, received]);
      await pair.server.waitTermination();
    } finally {
      await pair.cleanup();
    }
  });
});

describe("Node production raw QUIC Flowersec/5 runtime", () => {
  test("connects and accepts direct raw QUIC through FSB3 and FSH3", async () => {
    let artifact: ArtifactV3;
    let resolveStream!: (value: Uint8Array) => void;
    const handledStream = new Promise<Uint8Array>((resolve) => { resolveStream = resolve; });
    const handlers = new SessionHandlersV3();
    handlers.handleRPC(9_106, async (payload) => ({ payload: { raw: payload } }));
    handlers.handleStream("node-v3-raw-direct", async (incoming) => {
      const value = await incoming.stream.read();
      if (value === null) throw new Error("missing raw QUIC handler payload");
      resolveStream(value);
    });
    const acceptor = await createAcceptorV3({
      listeners: [{
        carrier: "raw_quic",
        path: "direct",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: CERTIFICATE_PEM, privateKey: PRIVATE_KEY_PEM },
      }],
      maxInboundStreams: V3_DIRECT_BASE.session.max_inbound_streams,
      authorize: async (received) => {
        expect(received.lookupKey()).toHaveLength(43);
        expect(Object.keys(received)).toEqual([]);
        return { accepted: true, artifact: parseArtifactV3(encodeArtifactV3JSON(artifact)) };
      },
      resolveHandlers: () => handlers,
    });
    const port = acceptor.addresses()[0]!.port;
    artifact = v3DirectRawQuicArtifact(port);
    let accepted;
    try {
      const established = await Promise.all([
        connectV3(v3Lease(artifact), { roots: CERTIFICATE_DER }),
        acceptor.accept(),
      ]);
      const client = established[0];
      accepted = established[1];
      const serving = accepted.serve().catch((error: unknown) => error);
      expect(await client.rpc.call(9_106, { carrier: "raw_quic" }, (payload) => payload))
        .toEqual({ ok: true, payload: { raw: { carrier: "raw_quic" } } });
      const outgoing = await client.openStream("node-v3-raw-direct");
      await outgoing.write(new Uint8Array([3, 0, 3]));
      await outgoing.closeWrite();
      await expect(handledStream).resolves.toEqual(new Uint8Array([3, 0, 3]));
      await client.close();
      await expect(serving).resolves.toMatchObject({ code: "closed" });
      await accepted.close();
    } finally {
      await accepted?.close().catch(() => undefined);
      await acceptor.close();
    }
  }, 20_000);

  test("pairs raw QUIC tunnel roles through production v3 listeners", async () => {
    const records = new Map<string, TunnelVerificationRecord>();
    const runtime = createTunnelRuntimeV3({
      listeners: [{
        carrier: "raw_quic",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: CERTIFICATE_PEM, privateKey: PRIVATE_KEY_PEM },
      }],
      maxInboundStreams: V3_TUNNEL_BASE.session.max_inbound_streams,
      authorize: async (request) => {
        const record = records.get(request.lookupKey());
        if (record === undefined) {
          return { decision: "reject" as const, reason: "not_authorized" };
        }
        return {
          decision: "allow" as const,
          grant: verifyTunnelAuthorizationGrantV3(request, record, { leaseId: `raw-lease-${record.credentialId}` }),
        };
      },
    });
    await runtime.start();
    const port = runtime.addresses()[0]!.port;
    const first = v3TunnelRawQuicArtifact(port, 1);
    const second = v3TunnelRawQuicArtifact(port, 2);
    for (const artifact of [first, second]) {
      const record = createTunnelVerificationRecord(parseArtifactV3(encodeArtifactV3JSON(artifact)), "node-raw-quic");
      records.set(record.credentialId, record);
    }
    try {
      const [client, server] = await Promise.all([
        connectV3(v3Lease(first), {
          roots: CERTIFICATE_DER,
        }),
        connectV3(v3Lease(second), {
          roots: CERTIFICATE_DER,
        }),
      ]);
      const opened = client.openStream("node-v3-raw-tunnel");
      const incoming = await server.acceptStream();
      const outgoing = await opened;
      await outgoing.write(new Uint8Array([3, 2, 1]));
      expect(await incoming.stream.read()).toEqual(new Uint8Array([3, 2, 1]));
      await Promise.all([client.close(), server.close()]);
    } finally {
      await runtime.close();
    }
  }, 20_000);
});

type NativePair = Readonly<{
  client: NativeCarrierSessionV3;
  server: NativeCarrierSessionV3;
  listener: NativeRawQuicListener;
  cleanup(): Promise<void>;
}>;

test("native H3 relay delivers the client control tail before closing its carrier", async () => {
  const addon = createRequire(import.meta.url)(process.env.FLOWERSEC_NATIVE_ADDON_PATH!) as NativeTransportAddonBinding;
  const driver = createNativeWebTransportDriver(addon, "native_h3")!;
  const origin = "https://app.example";
  const common = { host: "127.0.0.1", path: "tunnel", inboundBidirectionalStreamCapacity: 4, handshakeTimeoutMs: 2_000 } as const;
  const listener = await driver.bind({ ...common, port: 0, authorityHost: common.host, allowedOrigins: [origin],
    certificateChainDer: [CERTIFICATE_DER], privateKeyDer: PRIVATE_KEY_DER });
  const { port } = listener.address();
  const connect = () => driver.connect({ ...common, port, origin, serverName: common.host, tlsMode: "ca", trustRootsDer: [CERTIFICATE_DER],
    url: `https://${common.host}:${port}/flowersec/webtransport/v5/tunnel` });
  const sessions: NativeCarrierSessionV3[] = [];
  const controller = new AbortController();
  let bridge: Promise<void> | undefined;
  try {
    const [first, inbound] = await Promise.all([connect(), listener.accept()]);
    sessions.push(first, inbound);
    const [second, outbound] = await Promise.all([connect(), listener.accept()]);
    sessions.push(second, outbound);
    const firstLeg = adaptNativeCarrierSessionV3(inbound);
    const secondLeg = adaptNativeCarrierSessionV3(outbound);
    const firstAbort = vi.spyOn(firstLeg, "abort");
    const secondAbort = vi.spyOn(secondLeg, "abort");
    bridge = bridgeTunnelPairV3(firstLeg, secondLeg, controller.signal,
      { maxConcurrentStreams: 2, admissionTimeoutMs: 2_000, cleanupTimeoutMs: 2_000 });
    void bridge.catch(() => {});
    const request = await first.openStream();
    await request.write(Uint8Array.of(1));
    const response = await second.acceptStream();
    expect(Array.from((await response.read())!)).toEqual([1]);
    await response.write(Uint8Array.of(2));
    await response.closeWrite();
    expect(Array.from((await request.read())!)).toEqual([2]);
    expect(await request.read()).toBeNull();
    await request.write(Uint8Array.of(3));
    await request.closeWrite();
    expect(Array.from((await response.read())!)).toEqual([3]);
    expect(await response.read()).toBeNull();
    await second.close({ code: 1, reason: "session closed" });
    expect(await first.waitRemoteSessionClose!()).toBe(true);
    await bridge;
    expect(firstAbort).not.toHaveBeenCalled();
    expect(secondAbort).not.toHaveBeenCalled();
  } finally {
    controller.abort();
    for (const session of sessions) session.abort();
    await bridge?.catch(() => {});
    await listener.close();
  }
}, 10_000);

describe.each(["draft02", "native_h3"] as const)("Node native WebTransport %s", (profile) => {
  const origin = "https://app.example";
  const config = { carrier: "webtransport", profile, host: "127.0.0.1", port: 0,
    tls: { certificate: CERTIFICATE_PEM, privateKey: PRIVATE_KEY_PEM }, allowedOrigins: [origin] } as const;
  const clientOptions = { webTransportProfile: profile, origin, roots: CERTIFICATE_DER, connectTimeoutMs: 4_000 } as const;
  function candidate(port: number, path: "direct" | "tunnel"): ArtifactCandidateV3 {
    return { carrier: "webtransport", id: "wt-ca", url: `https://127.0.0.1:${port}/flowersec/webtransport/v5/${path}`, tls: { mode: "ca" }, wire_profile: `flowersec-${path}/5` };
  }

  test("establishes an authorized direct session, exchanges encrypted DATAGRAMs and rejects untrusted origins before spend", async () => {
    let artifact: ArtifactV3;
    let authorizations = 0, spends = 0;
    const acceptor = await createAcceptorV3({ listeners: [{ ...config, path: "direct" }], maxInboundStreams: V3_DIRECT_BASE.session.max_inbound_streams,
      authorize: async () => { authorizations++; return { accepted: true, artifact: parseArtifactV3(encodeArtifactV3JSON(artifact)) }; } });
    artifact = { ...V3_DIRECT_BASE, path: { ...V3_DIRECT_BASE.path, candidates: [candidate(acceptor.addresses()[0]!.port, "direct")] } };
    try {
      await expect(connectV3(createArtifactLeaseV3Internal(artifact, async () => { spends++; }), { ...clientOptions, origin: "https://denied.example" })).rejects.toThrow();
      expect([authorizations, spends]).toEqual([0, 0]);
      const [client, accepted] = await Promise.all([connectV3(v3Lease(artifact), clientOptions), acceptor.accept({ signal: AbortSignal.timeout(5_000) })]);
      try {
        expect(authorizations).toBe(1);
        await exchangeMessages(client, accepted.session);
      } finally { await Promise.all([client.close(), accepted.close()]); }
    } finally { await acceptor.close(); }
  }, 15_000);

  test.each(["webtransport", "raw_quic"] as const)("pairs a WebTransport leg with %s and relays encrypted streams and DATAGRAMs", async (otherCarrier) => {
    const records = new Map<string, TunnelVerificationRecord>();
    const secondConfig = { carrier: "raw_quic", host: config.host, port: 0, tls: config.tls } as const;
    const tunnel = createTunnelRuntimeV3({ listeners: otherCarrier === "raw_quic" ? [config, secondConfig] : [config], maxInboundStreams: V3_TUNNEL_BASE.session.max_inbound_streams,
      authorize: async (request) => ({ decision: "allow", grant: verifyTunnelAuthorizationGrantV3(request, records.get(request.lookupKey())!, { leaseId: `wt-${request.lookupKey()}` }) }) });
    await tunnel.start();
    try {
      const port = tunnel.addresses()[0]!.port;
      const firstCandidate = candidate(port, "tunnel");
      const secondCandidate = otherCarrier === "raw_quic" ? v3RawQuicCandidate(tunnel.addresses()[1]!.port, "tunnel") : firstCandidate;
      const artifacts = ([1, 2] as const).map(role => {
        const base = v3TunnelRawQuicArtifact(port, role);
        const artifact = { ...base, path: { ...base.path, candidates: otherCarrier === "raw_quic" ? [firstCandidate, secondCandidate] : [firstCandidate] } };
        const record = createTunnelVerificationRecord(parseArtifactV3(encodeArtifactV3JSON(artifact)), "node-wt");
        records.set(record.credentialId, record); return artifact;
      });
      const [first, second] = await Promise.all([connectV3(v3Lease(artifacts[0]!), { ...clientOptions, tunnelIngressURL: firstCandidate.url }), connectV3(v3Lease(artifacts[1]!), { ...clientOptions, tunnelIngressURL: secondCandidate.url })]);
      try {
        const [outgoing, incoming] = await Promise.all([first.openStream("wt-tunnel"), second.acceptStream({ signal: AbortSignal.timeout(3_000) })]);
        await outgoing.write(Uint8Array.of(1, 2, 3));
        expect(await incoming.stream.read()).toEqual(Uint8Array.of(1, 2, 3));
        await exchangeMessages(first, second);
      } finally { await Promise.all([first.close(), second.close()]); }
    } finally { await tunnel.close(); }
  }, 15_000);
  test("enforces active leaf pins without a CA fallback", async () => {
    const directory = mkdtempSync(join(tmpdir(), "flowersec-node-wt-pin-"));
    try {
      const key = join(directory, "key.pem"), cert = join(directory, "cert.pem");
      runOpenSSL(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-keyout", key, "-out", cert]);
      const certificate = readFileSync(cert, "utf8"), privateKey = readFileSync(key, "utf8");
      const fingerprint = createHash("sha256").update(new X509Certificate(certificate).raw).digest();
      let artifact: ArtifactV3, authorizations = 0, spends = 0;
      const acceptor = await createAcceptorV3({ listeners: [{ ...config, path: "direct", tls: { certificate, privateKey } }], maxInboundStreams: V3_DIRECT_BASE.session.max_inbound_streams,
        authorize: async () => { authorizations++; return { accepted: true, artifact: parseArtifactV3(encodeArtifactV3JSON(artifact)) }; } });
      const pinned = (pin: Uint8Array): ArtifactV3 => ({ ...V3_DIRECT_BASE, path: { ...V3_DIRECT_BASE.path, candidates: [{ ...candidate(acceptor.addresses()[0]!.port, "direct"), tls: { mode: "pin", pins: [
        { algorithm: "sha-256", value_b64u: Buffer.from(pin).toString("base64url"), not_after_unix_s: Math.floor(Date.now() / 1000) + 60 },
      ] } }] } });
      try {
        await expect(connectV3(createArtifactLeaseV3Internal(pinned(Buffer.alloc(32)), async () => { spends++; }), { ...clientOptions, roots: certificate })).rejects.toMatchObject({ code: "transport_security_failed" });
        expect([authorizations, spends]).toEqual([0, 0]);
        artifact = pinned(fingerprint);
        const [client, peer] = await Promise.all([connectV3(v3Lease(artifact), { ...clientOptions, roots: "ignored in pin mode" }), acceptor.accept({ signal: AbortSignal.timeout(5_000) })]);
        await Promise.all([client.close(), peer.close()]);
        expect(authorizations).toBe(1);
      } finally { await acceptor.close(); }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }, 15_000);
});

async function exchangeMessages(first: Awaited<ReturnType<typeof connectV3>>, second: Awaited<ReturnType<typeof connectV3>>) {
  for (const [sender, receiver] of [[first, second], [second, first]] as const) {
    expect(await sender.unreliableMessages!.send(Uint8Array.of(5, 7), { expiresAtUnixMs: Date.now() + 3_000 })).toBe("accepted");
    expect(await receiver.unreliableMessages!.receive({ signal: AbortSignal.timeout(3_000) })).toEqual(Uint8Array.of(5, 7));
  }
}

async function openPair(capacity: number): Promise<NativePair> {
  const driver = loadDriver();
  const listener = await bindListener(driver, capacity);
  let client: NativeCarrierSessionV3 | undefined;
  let server: NativeCarrierSessionV3 | undefined;
  try {
    const accepting = listener.accept();
    const address = listener.address();
    client = await driver.connectRawQuic({
      host: address.host,
      port: address.port,
      serverName: "localhost",
      path: "direct",
      tlsMode: "ca",
      trustRootsDer: [CERTIFICATE_DER],
      inboundBidirectionalStreamCapacity: capacity,
      handshakeTimeoutMs: 2_000,
    });
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
        await listener.close();
      },
    };
  } catch (error) {
    client?.abort();
    server?.abort();
    await listener.close();
    throw error;
  }
}

function loadDriver(): NativeRawQuicDriver {
  const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
  if (addonPath === undefined) throw new Error("FLOWERSEC_NATIVE_ADDON_PATH is required");
  const addon = createRequire(import.meta.url)(addonPath) as NativeTransportAddonBinding;
  return createNativeRawQuicDriver(addon);
}

async function bindListener(driver: NativeRawQuicDriver, capacity: number): Promise<NativeRawQuicListener> {
  return await driver.bindRawQuic({
    host: "127.0.0.1",
    port: 0,
    path: "direct",
    certificateChainDer: [CERTIFICATE_DER],
    privateKeyDer: PRIVATE_KEY_DER,
    inboundBidirectionalStreamCapacity: capacity,
    handshakeTimeoutMs: 2_000,
  });
}

function pem(label: string, der: Uint8Array): string {
  const base64 = Buffer.from(der).toString("base64");
  const lines = base64.match(/.{1,64}/gu) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function runOpenSSL(args: readonly string[]): void {
  execFileSync("openssl", [...args], { stdio: "ignore" });
}

function v3DirectRawQuicArtifact(port: number): ArtifactV3 {
  return {
    ...V3_DIRECT_BASE,
    path: {
      ...V3_DIRECT_BASE.path,
      candidates: [v3RawQuicCandidate(port, "direct")],
    },
  } as ArtifactV3;
}

function v3TunnelRawQuicArtifact(port: number, role: 1 | 2): ArtifactV3 {
  if (V3_TUNNEL_BASE.path.kind !== "tunnel") throw new Error("invalid tunnel fixture");
  return {
    ...V3_TUNNEL_BASE,
    path: {
      ...V3_TUNNEL_BASE.path,
      role,
      local_endpoint_instance_id: role === 1 ? "endpoint-client" : "endpoint-server",
      expected_peer_endpoint_instance_id: role === 1 ? "endpoint-server" : "endpoint-client",
      token: role === 1 ? "raw-attach-client-v3" : "raw-attach-server-v3",
      candidates: [v3RawQuicCandidate(port, "tunnel")],
    },
  };
}

function v3RawQuicCandidate(port: number, path: "direct" | "tunnel"): ArtifactCandidateV3 {
  return {
    carrier: "raw_quic",
    id: "q-ca",
    url: `quic://127.0.0.1:${port}`,
    tls: { mode: "ca" },
    wire_profile: path === "direct" ? "flowersec-direct/5" : "flowersec-tunnel/5",
  };
}

function v3Lease(artifact: ArtifactV3) {
  return createArtifactLeaseV3Internal(artifact, async () => undefined);
}

async function startInvalidProofPeer() {
  const child = spawn("go", [
    "run", "./internal/cmd/invalid-proof-peer", "--carrier", "raw_quic",
  ], {
    cwd: new URL("../../../flowersec-go/", import.meta.url),
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.end();
  const stderr: string[] = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => { stderr.push(chunk); });
  const finished = new Promise<number | null>((resolve) => child.once("close", resolve));
  const line = await firstJSONLine(child, stderr);
  const ready = JSON.parse(line) as Readonly<{ address: string; leaf_der_base64: string }>;
  return {
    address: ready.address,
    leafDER: Buffer.from(ready.leaf_der_base64, "base64"),
    wait: async () => expect(await finished, stderr.join("")).toBe(0),
    stop: () => { if (child.exitCode === null) child.kill(); },
  };
}

async function firstJSONLine(child: ChildProcessWithoutNullStreams, stderr: string[]): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    let stdout = "";
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    child.once("error", fail);
    child.once("exit", (code) => {
      if (!settled) fail(new Error(`invalid-proof peer exited ${String(code)}: ${stderr.join("")}`));
    });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      if (settled) return;
      stdout += chunk;
      const newline = stdout.indexOf("\n");
      if (newline >= 0) {
        settled = true;
        resolve(stdout.slice(0, newline));
      }
    });
  });
}
