import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { decodeArtifactV3JSON, type ArtifactV3, type ArtifactCandidateV3 } from "../v3/artifact.js";
import { createArtifactLeaseV3Internal } from "../v3/artifactLease.js";
import type { Session } from "../public/contract.js";
import { connectV3, createConnectionControllerV3 } from "./connectSessionV3.js";
import { RPCHandlers } from "./acceptor.js";
import { createAcceptorV3 } from "./acceptorV3.js";
import { createTunnelRuntimeV3 } from "./tunnelRuntimeV3.js";
import { startNodeWebSocketListenerV3 } from "./webSocketServerV3.js";

const opensslAvailable = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;
const networkDescribe = opensslAvailable ? describe : describe.skip;
const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const directBase = decodeArtifactV3JSON(fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "direct")!.artifact_json);
const tunnelBase = decodeArtifactV3JSON(fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "tunnel")!.artifact_json);

let directory = "";
let rootCertificate = "";
let leafCertificate = "";
let leafKey = "";
let leafDigest = "";

networkDescribe("Node production server runtime v3", () => {
  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), "flowersec-node-server-v3-"));
    generateCertificates(directory);
    rootCertificate = readFileSync(join(directory, "root.pem"), "utf8");
    leafCertificate = readFileSync(join(directory, "leaf.pem"), "utf8");
    leafKey = readFileSync(join(directory, "leaf.key"), "utf8");
    leafDigest = createHash("sha256").update(readFileSync(join(directory, "leaf.der"))).digest("base64url");
  });

  afterAll(() => {
    if (directory !== "") rmSync(directory, { recursive: true, force: true });
  });

  test("filters WebSocket candidates before dialing when no origin is composed", async () => {
    await expect(connectV3(lease(directArtifact(443)), {
      roots: rootCertificate,
      connectTimeoutMs: 100,
    })).rejects.toMatchObject({
      code: "transport_security_unsupported",
      disposition: { kind: "terminal" },
    });
  });

  test("accepts a production v3 WSS direct session through FSB3 and FSH3", async () => {
    let artifact: ArtifactV3;
    const rpcHandlers = new RPCHandlers();
    rpcHandlers.handleRPC(9_100, async (payload) => ({ payload: { handled: payload } }));
    const acceptor = await createAcceptorV3({
      listeners: [{
        carrier: "websocket",
        path: "direct",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: leafCertificate, privateKey: leafKey },
        allowedOrigins: ["https://app.example"],
      }],
      maxInboundStreams: directBase.session.max_inbound_streams,
      authorize: async (received) => {
        expect(Buffer.from(received.raw.subarray(0, 4)).toString("ascii")).toBe("FSB3");
        return { accepted: true, artifact };
      },
    });
    const port = acceptor.addresses()[0]!.port;
    artifact = directArtifact(port);
    try {
      const accepting = acceptor.accept();
      const connecting = connectV3(lease(artifact), {
        origin: "https://app.example",
        roots: rootCertificate,
        connectTimeoutMs: 3_000,
        rpcHandlers,
      });
      const [accepted, client] = await Promise.all([accepting, connecting]);
      expect(await accepted.session.rpc.call(9_100, { mode: "one-shot" }, (payload) => payload))
        .toEqual({ ok: true, payload: { handled: { mode: "one-shot" } } });
      const opened = client.openStream("node-v3-direct");
      const incoming = await accepted.session.acceptStream();
      const outgoing = await opened;
      await outgoing.write(new Uint8Array([3, 0, 0]));
      expect(await incoming.stream.read()).toEqual(new Uint8Array([3, 0, 0]));
      await Promise.all([client.close(), accepted.close()]);
    } finally {
      await acceptor.close();
    }
  });

  test("fails over from a real refused candidate to a production WSS candidate", async () => {
    let artifact!: ArtifactV3;
    let spends = 0;
    const acceptor = await createAcceptorV3({
      listeners: [{
        carrier: "websocket",
        path: "direct",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: leafCertificate, privateKey: leafKey },
        allowedOrigins: ["https://app.example"],
      }],
      maxInboundStreams: directBase.session.max_inbound_streams,
      authorize: async () => ({ accepted: true, artifact }),
    });
    artifact = directFailoverArtifact(acceptor.addresses()[0]!.port);
    try {
      const accepting = acceptor.accept();
      const connecting = connectV3(createArtifactLeaseV3Internal(
        artifact,
        async () => { spends += 1; },
      ), {
        origin: "https://app.example",
        roots: rootCertificate,
        connectTimeoutMs: 3_000,
      });
      const [accepted, client] = await Promise.all([accepting, connecting]);
      expect(spends).toBe(1);
      expect(await client.probeLiveness()).toBeGreaterThanOrEqual(0);
      await Promise.all([client.close(), accepted.close()]);
    } finally {
      await acceptor.close();
    }
  });

  test("keeps an established production WSS Session alive after its pin policy expires", async () => {
    let artifact!: ArtifactV3;
    const acceptor = await createAcceptorV3({
      listeners: [{
        carrier: "websocket",
        path: "direct",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: leafCertificate, privateKey: leafKey },
        allowedOrigins: ["https://app.example"],
      }],
      maxInboundStreams: directBase.session.max_inbound_streams,
      authorize: async () => ({ accepted: true, artifact }),
    });
    const pinExpiry = Math.floor(Date.now() / 1_000) + 3;
    artifact = directPinArtifact(acceptor.addresses()[0]!.port, pinExpiry);
    try {
      const accepting = acceptor.accept();
      const connecting = connectV3(lease(artifact), {
        origin: "https://app.example",
        connectTimeoutMs: 3_000,
      });
      const [accepted, client] = await Promise.all([accepting, connecting]);
      await new Promise<void>((resolve) => setTimeout(resolve, Math.max(1, pinExpiry * 1_000 - Date.now() + 50)));

      const opened = client.openStream("pin-expiry-does-not-close");
      const incoming = await accepted.session.acceptStream();
      const outgoing = await opened;
      await outgoing.write(new Uint8Array([3, 3, 0, 0]));
      expect(await incoming.stream.read()).toEqual(new Uint8Array([3, 3, 0, 0]));
      await Promise.all([client.close(), accepted.close()]);
    } finally {
      await acceptor.close();
    }
  }, 15_000);

  test("reuses frozen client RPC handlers with a fresh router across v3 controller generations", async () => {
    let authorizedArtifact!: ArtifactV3;
    let acquisitions = 0;
    let spends = 0;
    let rpcCalls = 0;
    let notifications = 0;
    const rpcHandlers = new RPCHandlers();
    rpcHandlers.handleRPC(9_101, async (payload) => ({
      payload: { invocation: ++rpcCalls, request: payload },
    }));
    rpcHandlers.handleNotification(9_102, () => { notifications += 1; });
    const acceptor = await createAcceptorV3({
      listeners: [{
        carrier: "websocket",
        path: "direct",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: leafCertificate, privateKey: leafKey },
        allowedOrigins: ["https://app.example"],
      }],
      maxInboundStreams: directBase.session.max_inbound_streams,
      authorize: async () => ({ accepted: true, artifact: authorizedArtifact }),
    });
    const port = acceptor.addresses()[0]!.port;
    const source = {
      acquire: async () => {
        acquisitions += 1;
        authorizedArtifact = directArtifactGeneration(port, acquisitions);
        return {
          kind: "lease" as const,
          lease: createArtifactLeaseV3Internal(authorizedArtifact, async () => { spends += 1; }),
        };
      },
    };
    const controller = createConnectionControllerV3(source, {
      origin: "https://app.example",
      roots: rootCertificate,
      rpcHandlers,
      maximumAttempts: 3,
    });
    const accepted: Array<Awaited<ReturnType<typeof acceptor.accept>>> = [];
    try {
      const firstAccepted = acceptor.accept();
      controller.start();
      const first = await controller.waitForSession();
      accepted.push(await firstAccepted);
      expect(await accepted[0]!.session.rpc.call(9_101, { phase: "first" }, (payload) => payload))
        .toEqual({ ok: true, payload: { invocation: 1, request: { phase: "first" } } });
      await accepted[0]!.session.rpc.notify(9_102, { phase: "first" });
      await waitFor(() => notifications === 1);

      const replacement = waitForReplacement(controller, first);
      const secondAccepted = acceptor.accept();
      await first.close();
      const second = await replacement;
      accepted.push(await secondAccepted);
      expect(await accepted[1]!.session.rpc.call(9_101, { phase: "second" }, (payload) => payload))
        .toEqual({ ok: true, payload: { invocation: 2, request: { phase: "second" } } });
      await accepted[1]!.session.rpc.notify(9_102, { phase: "second" });
      await waitFor(() => notifications === 2);
      expect({ acquisitions, spends, rpcCalls, notifications }).toEqual({
        acquisitions: 2,
        spends: 2,
        rpcCalls: 2,
        notifications: 2,
      });
      await second.close();
    } finally {
      await controller.close().catch(() => undefined);
      await Promise.allSettled(accepted.map(async (value) => await value.close()));
      await acceptor.close();
    }
  }, 15_000);

  test("rejects v2 WebSocket path and subprotocol before carrier acceptance", async () => {
    const listener = await startNodeWebSocketListenerV3({
      host: "127.0.0.1",
      port: 0,
      path: "direct",
      tls: { certificate: leafCertificate, privateKey: leafKey },
      allowedOrigins: ["https://app.example"],
      inboundBidirectionalStreamCapacity: 3,
    });
    let accepted = false;
    const accepting = listener.accept().then(() => { accepted = true; }, () => undefined);
    const require = createRequire(import.meta.url);
    const wsModule = require("ws") as { WebSocket: new (...args: unknown[]) => any };
    const port = listener.address().port;
    const socket = new wsModule.WebSocket(
      `wss://localhost:${port}/flowersec/v2/direct`,
      ["flowersec.direct.v2"],
      { ca: rootCertificate, origin: "https://app.example" },
    );
    try {
      const status = await new Promise<number>((resolve) => {
        socket.once("unexpected-response", (_request: unknown, response: { statusCode: number }) => resolve(response.statusCode));
        socket.once("error", () => resolve(0));
      });
      expect(status).toBe(403);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(accepted).toBe(false);
    } finally {
      socket.terminate();
      await listener.close();
      await accepting;
    }
  });

  test("pairs production v3 WSS tunnel roles without exposing the encrypted session", async () => {
    const runtime = createTunnelRuntimeV3({
      listeners: [{
        carrier: "websocket",
        host: "127.0.0.1",
        port: 0,
        tls: { certificate: leafCertificate, privateKey: leafKey },
        allowedOrigins: ["https://app.example"],
      }],
      maxInboundStreams: tunnelBase.session.max_inbound_streams,
      authorize: async ({ request }) => ({
        decision: "allow",
        credentialId: createHash("sha256").update(request.pathKind === "tunnel" ? request.attach_token : "").digest("base64url"),
        leaseId: `lease-${request.pathKind === "tunnel" ? request.role : 0}`,
        expiresAtUnixSeconds: Math.floor(Date.now() / 1_000) + 60,
        expectedPeerEndpointInstanceId: request.pathKind === "tunnel" && request.role === 1
          ? "endpoint-server"
          : "endpoint-client",
      }),
    });
    await runtime.start();
    const port = runtime.addresses()[0]!.port;
    const first = tunnelArtifact(port, 1);
    const second = tunnelArtifact(port, 2);
    try {
      const [client, server] = await Promise.all([
        connectV3(lease(first), {
          origin: "https://app.example",
          roots: rootCertificate,
          connectTimeoutMs: 3_000,
        }),
        connectV3(lease(second), {
          origin: "https://app.example",
          roots: rootCertificate,
          connectTimeoutMs: 3_000,
        }),
      ]);
      const opened = client.openStream("node-v3-tunnel");
      const incoming = await server.acceptStream();
      const outgoing = await opened;
      await outgoing.write(new Uint8Array([3, 1, 2, 3]));
      expect(await incoming.stream.read()).toEqual(new Uint8Array([3, 1, 2, 3]));
      await Promise.all([client.close(), server.close()]);
    } finally {
      await runtime.close();
    }
  });
});

function directArtifact(port: number): ArtifactV3 {
  return {
    ...directBase,
    path: {
      ...directBase.path,
      candidates: [candidate(port, "direct")],
    },
  } as ArtifactV3;
}

function directFailoverArtifact(port: number): ArtifactV3 {
  const reachable = candidate(port, "direct");
  return {
    ...directBase,
    path: {
      ...directBase.path,
      candidates: [{
        ...reachable,
        id: "a-refused",
        url: "wss://127.0.0.1:1/flowersec/v3/direct",
      }, reachable],
    },
  } as ArtifactV3;
}

function directPinArtifact(port: number, notAfterUnixSeconds: number): ArtifactV3 {
  return {
    ...directBase,
    path: {
      ...directBase.path,
      candidates: [{
        ...candidate(port, "direct"),
        id: "w-pin",
        tls: {
          mode: "pin",
          pins: [{
            algorithm: "sha-256",
            value_b64u: leafDigest,
            not_after_unix_s: notAfterUnixSeconds,
          }],
        },
      }],
    },
  } as ArtifactV3;
}

function directArtifactGeneration(port: number, generation: number): ArtifactV3 {
  const artifact = directArtifact(port);
  if (artifact.path.kind !== "direct") throw new Error("invalid direct artifact fixture");
  return {
    ...artifact,
    path: {
      ...artifact.path,
      routing_token: `routing-token-v3-${generation}`,
    },
  };
}

function tunnelArtifact(port: number, role: 1 | 2): ArtifactV3 {
  if (tunnelBase.path.kind !== "tunnel") throw new Error("invalid tunnel fixture");
  return {
    ...tunnelBase,
    path: {
      ...tunnelBase.path,
      role,
      local_endpoint_instance_id: role === 1 ? "endpoint-client" : "endpoint-server",
      expected_peer_endpoint_instance_id: role === 1 ? "endpoint-server" : "endpoint-client",
      token: role === 1 ? "attach-token-client-v3" : "attach-token-server-v3",
      candidates: [candidate(port, "tunnel")],
    },
  };
}

function candidate(port: number, path: "direct" | "tunnel"): ArtifactCandidateV3 {
  return {
    carrier: "websocket",
    id: "w-ca",
    url: `wss://localhost:${port}/flowersec/v3/${path}`,
    tls: { mode: "ca" },
    wire_profile: path === "direct" ? "flowersec-direct/3" : "flowersec-tunnel/3",
  };
}

function lease(artifact: ArtifactV3) {
  return createArtifactLeaseV3Internal(artifact, async () => undefined);
}

async function waitForReplacement(
  controller: ReturnType<typeof createConnectionControllerV3>,
  previous: Session,
): Promise<Session> {
  return await new Promise<Session>((resolve, reject) => {
    let unsubscribe: () => void = () => undefined;
    unsubscribe = controller.subscribe((snapshot) => {
      if (snapshot.state === "connected" && snapshot.currentSession !== undefined &&
          snapshot.currentSession !== previous) {
        unsubscribe();
        resolve(snapshot.currentSession);
      } else if (snapshot.state === "failed" || snapshot.state === "closed") {
        unsubscribe();
        reject(new Error(`v3 controller stopped in ${snapshot.state}`));
      }
    });
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for v3 RPC handler");
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
}

function generateCertificates(target: string): void {
  runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", join(target, "root.key")]);
  runOpenSSL([
    "req", "-x509", "-new", "-key", join(target, "root.key"), "-sha256", "-days", "2",
    "-subj", "/CN=Flowersec v3 Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", join(target, "root.pem"),
  ]);
  runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", join(target, "leaf.key")]);
  runOpenSSL(["req", "-new", "-key", join(target, "leaf.key"), "-subj", "/CN=localhost", "-out", join(target, "leaf.csr")]);
  writeFileSync(join(target, "leaf.ext"), [
    "subjectAltName=DNS:localhost",
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature",
    "extendedKeyUsage=serverAuth",
    "",
  ].join("\n"));
  runOpenSSL([
    "x509", "-req", "-in", join(target, "leaf.csr"), "-CA", join(target, "root.pem"),
    "-CAkey", join(target, "root.key"), "-CAcreateserial", "-days", "2", "-sha256",
    "-extfile", join(target, "leaf.ext"), "-out", join(target, "leaf.pem"),
  ]);
  runOpenSSL(["x509", "-in", join(target, "leaf.pem"), "-outform", "DER", "-out", join(target, "leaf.der")]);
}

function runOpenSSL(args: readonly string[]): void {
  execFileSync("openssl", [...args], { stdio: "ignore" });
}
