import { createRequire } from "node:module";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import {
  createNativeRawQuicDriver,
  createNativeRawQuicDriverV3,
  type NativeRawQuicDriver,
  type NativeRawQuicDriverV3,
  type NativeRawQuicListener,
  type NativeTransportAddonBinding,
} from "./nativeTransportAddon.js";
import type { NativeCarrierSessionV2 } from "../v2/carrier.js";
import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import { parseArtifact, type Artifact } from "../v2/opaqueArtifact.js";
import { connect, createConnectionController } from "./connectSession.js";
import { createAcceptor, SessionHandlersV3 } from "./acceptor.js";
import { createEndpointSet, Issuer } from "./controlplane.js";
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
import { createTunnelRuntimeV3 } from "./tunnelRuntimeV3.js";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
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
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
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
  test("runs the explicit v3 addon entries with isolated ALPN", async () => {
    const v3 = loadDriverV3();
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

    const v2Listener = await bindListener(loadDriver(), 4);
    try {
      const address = v2Listener.address();
      await expect(v3.connectRawQuic({
        host: address.host,
        port: address.port,
        serverName: "localhost",
        path: "direct",
        tlsMode: "ca",
        trustRootsDer: [CERTIFICATE_DER],
        inboundBidirectionalStreamCapacity: 4,
        handshakeTimeoutMs: 2_000,
      })).rejects.toThrow();
    } finally {
      await v2Listener.close();
    }
  }, 20_000);

  test("enforces a short-lived P-256 leaf pin without CA fallback", async () => {
    const directory = mkdtempSync(join(tmpdir(), "flowersec-node-raw-pin-v3-"));
    const driver = loadDriverV3();
    let listener: Awaited<ReturnType<typeof driver.bindRawQuic>> | undefined;
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
        normalized_url: `quic://localhost:${address.port}`,
        tls: {
          mode: "pin",
          pins: [{ algorithm: "sha-256", value_b64u: pin.toString("base64url"), not_after_unix_s: expires }],
        },
        wire_profile: "flowersec-direct/3",
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
        normalized_url: `quic://localhost:${address.port}`,
        tls: {
          mode: "pin",
          pins: [{ algorithm: "sha-256", value_b64u: wrong.toString("base64url"), not_after_unix_s: expires }],
        },
        wire_profile: "flowersec-direct/3",
      }, artifact, Math.floor(Date.now() / 1_000), {
        roots: certificateDER,
      })).rejects.toMatchObject({ code: "tls_failed", detail: "pin_mismatch" });
      await rejectedServer;
    } finally {
      await listener?.close();
      rmSync(directory, { recursive: true, force: true });
    }
  }, 20_000);

  test("rejects a hash-matched leaf with an invalid TLS proof before FSB3 or lease spend", async () => {
    const peer = await startInvalidProofPeer();
    let spends = 0;
    const port = Number(peer.address.slice(peer.address.lastIndexOf(":") + 1));
    const digest = createHash("sha256").update(peer.leafDER).digest("base64url");
    const artifact = {
      ...V3_DIRECT_BASE,
      path: {
        ...V3_DIRECT_BASE.path,
        candidates: [{
          carrier: "raw_quic",
          id: "q-invalid-proof",
          url: `quic://localhost:${port}`,
          tls: {
            mode: "pin",
            pins: [{
              algorithm: "sha-256",
              value_b64u: digest,
              not_after_unix_s: Math.floor(Date.now() / 1_000) + 3_600,
            }],
          },
          wire_profile: "flowersec-direct/3",
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
        disposition: { kind: "terminal" },
      });
      expect(spends).toBe(0);
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

describe("Node production raw QUIC runtime v3", () => {
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
    const artifacts = new Map<string, ArtifactV3>();
    const runtime = createTunnelRuntimeV3({
      listeners: [{
        carrier: "raw_quic",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: CERTIFICATE_PEM, privateKey: PRIVATE_KEY_PEM },
      }],
      maxInboundStreams: V3_TUNNEL_BASE.session.max_inbound_streams,
      authorize: async (request) => {
        const artifact = artifacts.get(request.lookupKey());
        if (artifact === undefined || artifact.path.kind !== "tunnel") {
          return { decision: "reject" as const, reason: "not_authorized" };
        }
        return v3TunnelAuthorization(artifact, `raw-lease-${artifact.path.role}`);
      },
    });
    await runtime.start();
    const port = runtime.addresses()[0]!.port;
    const first = v3TunnelRawQuicArtifact(port, 1);
    const second = v3TunnelRawQuicArtifact(port, 2);
    artifacts.set(v3TunnelLookupKey(first), first);
    artifacts.set(v3TunnelLookupKey(second), second);
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

describe("Node public raw QUIC connector", () => {
  test("connects a raw-QUIC-only artifact without origin", async () => {
    const authorized = new Map<string, Artifact>();
    const acceptor = await rawQuicAcceptor(authorized);
    try {
      const address = acceptor.addresses()[0]!;
      const issued = issueDirect(`quic://127.0.0.1:${address.port}`, "node-no-origin-oneshot");
      authorized.set(issued.authorizationRecord().lookupKey(), parseArtifact(issued.artifactJSON()));
      let spends = 0;
      const acceptedPromise = acceptor.accept();
      const clientPromise = connect(
        createArtifactLeaseV2(parseArtifact(issued.artifactJSON()), async () => { spends += 1; }),
        { tls: { ca: CERTIFICATE_DER } },
      );
      const [client, accepted] = await Promise.all([clientPromise, acceptedPromise]);
      expect(spends).toBe(1);
      await Promise.all([client.close(), accepted.close()]);
    } finally {
      await acceptor.close();
    }
  }, 20_000);

  test("uses only raw QUIC from a mixed artifact when origin is absent", async () => {
    const { createServer } = await import("node:http");
    const { once } = await import("node:events");
    const websocketProbe = createServer();
    let upgrades = 0;
    websocketProbe.on("upgrade", (_request, socket) => {
      upgrades += 1;
      socket.destroy();
    });
    websocketProbe.listen(0, "127.0.0.1");
    await once(websocketProbe, "listening");
    const websocketAddress = websocketProbe.address();
    if (typeof websocketAddress !== "object" || websocketAddress === null) throw new Error("probe did not bind");

    const authorized = new Map<string, Artifact>();
    const acceptor = await rawQuicAcceptor(authorized);
    try {
      const address = acceptor.addresses()[0]!;
      const issued = issueDirect(
        `ws://127.0.0.1:${websocketAddress.port}/flowersec/v2/direct`,
        "node-no-origin-mixed",
        `quic://127.0.0.1:${address.port}`,
      );
      authorized.set(issued.authorizationRecord().lookupKey(), parseArtifact(issued.artifactJSON()));
      const [client, accepted] = await Promise.all([
        connect(
          createArtifactLeaseV2(parseArtifact(issued.artifactJSON()), async () => undefined),
          { tls: { ca: CERTIFICATE_DER } },
        ),
        acceptor.accept(),
      ]);
      expect(upgrades).toBe(0);
      await Promise.all([client.close(), accepted.close()]);
    } finally {
      await acceptor.close();
      await new Promise<void>((resolve) => websocketProbe.close(() => resolve()));
    }
  }, 20_000);

  test("keeps no-origin semantics across ConnectionController generations", async () => {
    const authorized = new Map<string, Artifact>();
    const acceptor = await rawQuicAcceptor(authorized);
    let acquisitions = 0;
    let spends = 0;
    const address = acceptor.addresses()[0]!;
    const source = {
      acquire: async () => {
        acquisitions += 1;
        const issued = issueDirect(`quic://127.0.0.1:${address.port}`, `node-no-origin-controller-${acquisitions}`);
        const artifact = parseArtifact(issued.artifactJSON());
        authorized.set(issued.authorizationRecord().lookupKey(), artifact);
        return {
          kind: "lease" as const,
          lease: createArtifactLeaseV2(artifact, async () => { spends += 1; }),
        };
      },
    };
    const controller = createConnectionController(source, { tls: { ca: CERTIFICATE_DER }, maximumAttempts: 3 });
    try {
      const firstAcceptedPromise = acceptor.accept();
      controller.start();
      const first = await controller.waitForSession();
      const firstAccepted = await firstAcceptedPromise;
      expect(acquisitions).toBe(1);
      expect(spends).toBe(1);

      const replacementPromise = waitForReplacement(controller, first);
      const secondAcceptedPromise = acceptor.accept();
      await firstAccepted.close();
      const replacement = await replacementPromise;
      const secondAccepted = await secondAcceptedPromise;
      expect(replacement).not.toBe(first);
      expect(acquisitions).toBe(2);
      expect(spends).toBe(2);
      await secondAccepted.close();
    } finally {
      await controller.close();
      await acceptor.close();
    }
  }, 20_000);
});

type NativePair = Readonly<{
  client: NativeCarrierSessionV2;
  server: NativeCarrierSessionV2;
  listener: NativeRawQuicListener;
  cleanup(): Promise<void>;
}>;

async function openPair(capacity: number): Promise<NativePair> {
  const driver = loadDriver();
  const listener = await bindListener(driver, capacity);
  let client: NativeCarrierSessionV2 | undefined;
  let server: NativeCarrierSessionV2 | undefined;
  try {
    const accepting = listener.accept();
    const address = listener.address();
    client = await driver.connectRawQuic({
      host: address.host,
      port: address.port,
      serverName: "localhost",
      path: "direct",
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

function loadDriverV3(): NativeRawQuicDriverV3 {
  const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
  if (addonPath === undefined) throw new Error("FLOWERSEC_NATIVE_ADDON_PATH is required");
  const addon = createRequire(import.meta.url)(addonPath) as NativeTransportAddonBinding;
  return createNativeRawQuicDriverV3(addon);
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

async function rawQuicAcceptor(authorized: Map<string, Artifact>) {
  return await createAcceptor({
    listeners: [{
      carrier: "raw_quic",
      path: "direct",
      host: "127.0.0.1",
      port: 0,
      tls: { certificate: CERTIFICATE_PEM, privateKey: PRIVATE_KEY_PEM },
    }],
    maxInboundStreams: 10,
    authorize: async (request) => {
      const artifact = authorized.get(request.lookupKey());
      return artifact === undefined
        ? { decision: "reject" as const, reason: "unknown_credential" }
        : { decision: "allow" as const, artifact };
    },
  });
}

function issueDirect(firstUrl: string, channelId: string, ...additionalUrls: string[]) {
  return new Issuer().issueDirect({
    session: { channelId, maxInboundStreams: 10 },
    endpoints: createEndpointSet(firstUrl, ...additionalUrls),
    rendezvousGroupId: `${channelId}-group`,
    listenerAudience: "node-native-listener",
    upstreamAddress: "127.0.0.1:9000",
  });
}

async function waitForReplacement(
  controller: ReturnType<typeof createConnectionController>,
  previous: Awaited<ReturnType<typeof connect>>,
) {
  return await new Promise<Awaited<ReturnType<typeof connect>>>((resolve, reject) => {
    let unsubscribe: () => void = () => undefined;
    unsubscribe = controller.subscribe((snapshot) => {
      if (snapshot.state === "connected" && snapshot.currentSession !== undefined && snapshot.currentSession !== previous) {
        unsubscribe();
        resolve(snapshot.currentSession);
      } else if (snapshot.state === "failed" || snapshot.state === "closed") {
        unsubscribe();
        reject(new Error(`controller stopped in ${snapshot.state}`));
      }
    });
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

function v3TunnelLookupKey(artifact: ArtifactV3): string {
  if (artifact.path.kind !== "tunnel") throw new Error("expected tunnel artifact");
  return createHash("sha256").update(artifact.path.token).digest("base64url");
}

function v3TunnelAuthorization(artifact: ArtifactV3, leaseId: string) {
  if (artifact.path.kind !== "tunnel") throw new Error("expected tunnel artifact");
  return {
    decision: "allow" as const,
    artifact: parseArtifactV3(encodeArtifactV3JSON(artifact)),
    credentialId: v3TunnelLookupKey(artifact),
    leaseId,
    expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
    expectedPeerEndpointInstanceId: artifact.path.expected_peer_endpoint_instance_id,
  };
}

function v3RawQuicCandidate(port: number, path: "direct" | "tunnel"): ArtifactCandidateV3 {
  return {
    carrier: "raw_quic",
    id: "q-ca",
    url: `quic://localhost:${port}`,
    tls: { mode: "ca" },
    wire_profile: path === "direct" ? "flowersec-direct/3" : "flowersec-tunnel/3",
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
  const line = await firstJSONLine(child, stderr);
  const ready = JSON.parse(line) as Readonly<{ address: string; leaf_der_base64: string }>;
  return {
    address: ready.address,
    leafDER: Buffer.from(ready.leaf_der_base64, "base64"),
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
