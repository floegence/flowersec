import { execFileSync } from "node:child_process";
import { createServer } from "node:https";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";

import { afterAll, describe, expect, test } from "vitest";
import type * as WS from "ws";

import { createConnectionController } from "./connectSession.js";
import { RPCHandlers } from "./acceptor.js";
import { RpcRouter } from "../rpc/server.js";
import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import {
  AdmissionStatusV2,
  decodeArtifactV2JSON,
  decodeFSB2RequestV2,
  encodeFSA2ResponseV2,
  type ArtifactV2,
} from "../v2/artifact.js";
import { parseArtifact } from "../v2/opaqueArtifact.js";
import { createWebSocketCarrierSessionV2 } from "../transport/webSocketAdapter.js";
import type { CipherSuiteV2 } from "../v2/protocol.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "../v2/session.js";
import { WebSocketBinaryTransport } from "../ws-client/binaryTransport.js";
import { base64urlDecode } from "../utils/base64url.js";
import { nodeSessionRuntimeV2 } from "./sessionRuntime.js";
import { SessionError } from "../v2/contract.js";

type Fixture = Readonly<{
  positive: readonly Readonly<{ id: string; artifact_json: string }>[];
}>;

type Peer = Readonly<{
  port: number;
  session(): Promise<SessionV2>;
  waitForPendingRPC(): Promise<void>;
  stop(): Promise<void>;
}>;

const CLIENT_RPC = 901;
const CLIENT_NOTIFICATION = 902;
const PENDING_SERVER_RPC = 903;

const require = createRequire(import.meta.url);
const { WebSocketServer } = require("ws") as typeof WS;
const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Fixture;

let certificateDirectory = "";
let certificate = "";
let privateKey = "";

afterAll(() => {
  if (certificateDirectory !== "") rmSync(certificateDirectory, { recursive: true, force: true });
});

describe("Node ConnectionController real-network replacement", () => {
  test("restarts a WSS peer with a fresh lease and does not replay old operations", async () => {
    await createCertificate();
    const sourceFixture = fixture.positive.find((entry) => entry.id === "direct-three-carriers");
    if (sourceFixture === undefined) throw new Error("direct WSS artifact fixture is missing");

    let peer: Peer | undefined;
    let acquisitions = 0;
    let spendCount = 0;
    let rpcCalls = 0;
    let notifications = 0;
    const rpcHandlers = new RPCHandlers();
    rpcHandlers.handleRPC(CLIENT_RPC, async (payload) => {
      rpcCalls += 1;
      return { payload: { generation: rpcCalls, request: payload } };
    });
    rpcHandlers.handleNotification(CLIENT_NOTIFICATION, () => {
      notifications += 1;
    });
    const source = {
      acquire: async () => {
        peer = await startPeer();
        const artifact = localArtifact(sourceFixture.artifact_json, `wss://localhost:${peer.port}/flowersec/v2/direct`);
        acquisitions += 1;
        return {
          kind: "lease" as const,
          lease: createArtifactLeaseV2(parseArtifact(artifact), async () => { spendCount += 1; }),
        };
      },
    };
    const controller = createConnectionController(source, {
      origin: "https://client.example",
      tls: { ca: certificate },
      rpcHandlers,
    });
    try {
      controller.start();
      const first = await controller.waitForSession();
      expect(acquisitions).toBe(1);
      expect(spendCount).toBe(1);
      if (peer === undefined) throw new Error("controller connected without a live peer");
      const firstPeer = peer;
      const firstServerSession = await firstPeer.session();
      await expect(firstServerSession.rpc.call(CLIENT_RPC, { phase: "first" }))
        .resolves.toEqual({ payload: { generation: 1, request: { phase: "first" } } });
      await firstServerSession.rpc.notify(CLIENT_NOTIFICATION, { phase: "first" });
      await waitFor(() => notifications === 1);

      const oldStream = await first.openStream("restart-old");
      const pendingRead = oldStream.read().then(() => undefined, (error: unknown) => error);
      const pendingRPC = first.rpc.call(PENDING_SERVER_RPC, { phase: "first" }, (payload) => payload);
      await firstPeer.waitForPendingRPC();

      const oldTermination = first.waitTermination();
      await firstPeer.stop();
      await expect(oldTermination).resolves.toMatchObject({ error: { code: "closed" } });
      expect(await pendingRead).toMatchObject({ code: "closed" });
      await expect(pendingRPC).rejects.toBeInstanceOf(SessionError);
      await expect(oldStream.write(Uint8Array.of(1))).rejects.toMatchObject({ code: "closed" });
      await expect(first.rpc.call(91, { request: "after-close" }, (payload) => payload))
        .rejects.toBeInstanceOf(SessionError);
      await expect(first.rpc.notify(92, { request: "after-close" })).rejects.toBeInstanceOf(SessionError);

      const replacement = await controller.waitForSession();
      expect(replacement).not.toBe(first);
      expect(acquisitions).toBe(2);
      expect(spendCount).toBe(2);
      if (peer === undefined) throw new Error("controller replaced session without a live peer");
      const secondServerSession = await peer.session();
      await expect(secondServerSession.rpc.call(CLIENT_RPC, { phase: "second" }))
        .resolves.toEqual({ payload: { generation: 2, request: { phase: "second" } } });
      await secondServerSession.rpc.notify(CLIENT_NOTIFICATION, { phase: "second" });
      await waitFor(() => notifications === 2);
      expect(rpcCalls).toBe(2);

      const freshStream = await replacement.openStream("restart-new");
      await freshStream.write(Uint8Array.of(2));
      await freshStream.closeWrite();
      await freshStream.close();
    } finally {
      await controller.close().catch(() => undefined);
      await peer?.stop().catch(() => undefined);
      peer = undefined;
    }
  }, 30_000);
});

async function createCertificate(): Promise<void> {
  if (certificate !== "") return;
  certificateDirectory = mkdtempSync(join(tmpdir(), "flowersec-controller-restart-"));
  const keyPath = join(certificateDirectory, "localhost.key");
  const certPath = join(certificateDirectory, "localhost.crt");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    "-keyout", keyPath, "-out", certPath,
  ], { stdio: "ignore" });
  privateKey = readFileSync(keyPath, "utf8");
  certificate = readFileSync(certPath, "utf8");
}

async function startPeer(): Promise<Peer> {
  const httpsServer = createServer({ key: privateKey, cert: certificate });
  const wss = new WebSocketServer({
    server: httpsServer,
    perMessageDeflate: false,
    handleProtocols(protocols) {
      return protocols.has("flowersec.direct.v2") ? "flowersec.direct.v2" : false;
    },
  });
  const sessions = new Set<SessionV2>();
  let resolveSession!: (session: SessionV2) => void;
  const sessionReady = new Promise<SessionV2>((resolve) => { resolveSession = resolve; });
  let resolvePendingRPC!: () => void;
  const pendingRPCStarted = new Promise<void>((resolve) => { resolvePendingRPC = resolve; });
  let releasePendingRPC!: () => void;
  const pendingRPCRelease = new Promise<void>((resolve) => { releasePendingRPC = resolve; });
  wss.on("connection", (socket) => {
    void servePeer(
      socket as never,
      sessions,
      resolveSession,
      resolvePendingRPC,
      pendingRPCRelease,
    ).catch(() => undefined);
  });
  httpsServer.listen(0, "127.0.0.1");
  await once(httpsServer, "listening");
  const address = httpsServer.address();
  if (typeof address !== "object" || address === null) throw new Error("WSS peer did not bind TCP");

  let stopped = false;
  return {
    port: address.port,
    async session() { return await sessionReady; },
    async waitForPendingRPC() { await pendingRPCStarted; },
    async stop() {
      if (stopped) return;
      stopped = true;
      for (const socket of wss.clients) socket.terminate();
      for (const session of sessions) await session.close().catch(() => undefined);
      releasePendingRPC();
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    },
  };
}

async function servePeer(
  socket: WS.WebSocket,
  sessions: Set<SessionV2>,
  resolveSession: (session: SessionV2) => void,
  resolvePendingRPC: () => void,
  pendingRPCRelease: Promise<void>,
): Promise<void> {
  const transport = new WebSocketBinaryTransport(socket as never);
  const request = decodeFSB2RequestV2(await transport.readBinary());
  await transport.writeBinary(encodeFSA2ResponseV2({ status: AdmissionStatusV2.Success, reason: "" }));
  const artifact = decodeArtifactV2JSON(fixture.positive.find((entry) => entry.id === "direct-three-carriers")!.artifact_json);
  const router = new RpcRouter();
  router.register(PENDING_SERVER_RPC, async () => {
    resolvePendingRPC();
    await pendingRPCRelease;
    return { payload: { late: true } };
  });
  const session = await establishSessionV2(
    createWebSocketCarrierSessionV2(transport, {
      path: "direct",
      client: false,
      inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
    }),
    serverConfig(artifact, request, router),
  );
  sessions.add(session);
  resolveSession(session);
  try {
    await session.waitTermination();
  } finally {
    sessions.delete(session);
  }
}

function localArtifact(rawArtifact: string, url: string): string {
  const value = JSON.parse(rawArtifact) as { path: { candidates: Array<{ id: string; url: string }> } };
  value.path.candidates = value.path.candidates.filter((candidate) => candidate.id === "w1");
  value.path.candidates[0]!.url = url;
  return JSON.stringify(value);
}

function serverConfig(
  artifact: ArtifactV2,
  fsb2: ReturnType<typeof decodeFSB2RequestV2>,
  rpcRouter: RpcRouter,
): SessionConfigV2 {
  return {
    role: "server",
    path: "direct",
    channelID: artifact.session.channel_id,
    sessionContractHash: base64urlDecode(artifact.session.contract_hash_b64u),
    suite: artifact.session.default_suite as CipherSuiteV2,
    psk: base64urlDecode(artifact.session.e2ee_psk_b64u),
    maxInboundStreams: artifact.session.max_inbound_streams,
    sessionContract: artifact.session,
    idleTimeoutMs: artifact.session.idle_timeout_seconds * 1_000,
    localAdmissionBinding: fsb2.localAdmissionBinding,
    peerAdmissionBinding: fsb2.localAdmissionBinding,
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    rpcRouter,
    runtime: nodeSessionRuntimeV2,
    deadlines: {
      establishTimeoutMs: artifact.session.establish_timeout_seconds * 1_000,
      rekeyPrepareTimeoutMs: artifact.session.rekey_prepare_timeout_seconds * 1_000,
      rekeyCompletionTimeoutMs: artifact.session.rekey_completion_timeout_seconds * 1_000,
    },
  };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for handler invocation");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
