import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { createRequire } from "node:module";

import { afterAll, beforeAll, describe, expect, test } from "vitest";
import type * as WS from "ws";

import { connectNodeSessionV2 } from "./connectV2.js";
import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import {
  AdmissionStatusV2,
  admissionBindingV2,
  decodeArtifactV2JSON,
  decodeFSB2RequestV2,
  encodeFSA2ResponseV2,
  encodeFSB2RequestV2,
  type ArtifactV2,
} from "../v2/artifact.js";
import { createWebSocketCarrierSessionV2 } from "../v2/carrier.js";
import type { CipherSuiteV2 } from "../v2/protocol.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "../v2/session.js";
import { WebSocketBinaryTransport } from "../ws-client/binaryTransport.js";
import { base64urlDecode } from "../utils/base64url.js";

type Fixture = Readonly<{ positive: readonly Readonly<{ path_kind: "direct" | "tunnel"; artifact_json: string }>[] }>;
const fixture = JSON.parse(readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8")) as Fixture;
const require = createRequire(import.meta.url);
const { WebSocketServer } = require("ws") as typeof WS;

let certificateDirectory = "";
let certificate = "";
let privateKey = "";

beforeAll(() => {
  certificateDirectory = mkdtempSync(join(tmpdir(), "flowersec-node-wss-v2-"));
  const keyPath = join(certificateDirectory, "localhost.key");
  const certPath = join(certificateDirectory, "localhost.crt");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    "-keyout", keyPath, "-out", certPath,
  ], { stdio: "ignore" });
  privateKey = readFileSync(keyPath, "utf8");
  certificate = readFileSync(certPath, "utf8");
});

afterAll(() => {
  if (certificateDirectory !== "") rmSync(certificateDirectory, { recursive: true, force: true });
});

describe("Node Transport v2 WSS production connector", () => {
  test.each(["direct", "tunnel"] as const)("establishes a complete %s session over localhost TLS", async (path) => {
    const source = fixture.positive.find((entry) => entry.path_kind === path);
    if (source === undefined) throw new Error(`missing ${path} artifact fixture`);
    const protocol = path === "direct" ? "flowersec.direct.v2" : "flowersec.tunnel.v2";
    const httpsServer = createServer({ key: privateKey, cert: certificate });
    let upgradeProtocol = "";
    const wss = new WebSocketServer({
      server: httpsServer,
      perMessageDeflate: false,
      handleProtocols(protocols) { return protocols.has(protocol) ? protocol : false; },
    });
    wss.on("headers", (_headers, request) => { upgradeProtocol = request.headers["sec-websocket-protocol"] ?? ""; });
    httpsServer.listen(0, "localhost");
    await once(httpsServer, "listening");
    const address = httpsServer.address();
    if (typeof address !== "object" || address === null) throw new Error("TLS server did not bind TCP");
    const localArtifact = withLocalWSS(source.artifact_json, `wss://localhost:${address.port}/flowersec/v2/${path}`);
    const artifact = localArtifact.artifact;

    let observedFSB2: ReturnType<typeof decodeFSB2RequestV2> | undefined;
    const serverSessionPromise = new Promise<SessionV2>((resolve, reject) => {
      wss.once("connection", (socket) => {
        void (async () => {
          expect(socket.protocol).toBe(protocol);
          const transport = new WebSocketBinaryTransport(socket as never);
          const rawFSB2 = await transport.readBinary();
          observedFSB2 = decodeFSB2RequestV2(rawFSB2);
          expect(observedFSB2.request.pathKind).toBe(path);
          expect(observedFSB2.request.chosen_candidate_id).toBe("w1");
          await transport.writeBinary(encodeFSA2ResponseV2({ status: AdmissionStatusV2.Success, reason: "" }, new Set()));
          const carrier = createWebSocketCarrierSessionV2(transport, {
            path,
            client: false,
            inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
          });
          resolve(await establishSessionV2(carrier, serverConfig(artifact, observedFSB2)));
        })().catch(reject);
      });
    });

    let spendCount = 0;
    const lease = createArtifactLeaseV2(localArtifact.raw, async () => { spendCount++; });
    const clientSessionPromise = connectNodeSessionV2(lease, {
      origin: "https://app.example",
      webSocket: { ca: certificate },
    });
    const [client, server] = await Promise.all([clientSessionPromise, serverSessionPromise]);
    expect(upgradeProtocol).toBe(protocol);
    expect(spendCount).toBe(1);

    const clientOpening = client.openStream(`${path}-client`);
    const serverIncoming = await server.acceptStream();
    const clientStream = await clientOpening;
    await clientStream.write(Uint8Array.of(1, 2, 3));
    await clientStream.closeWrite();
    expect(await serverIncoming.stream.read()).toEqual(Uint8Array.of(1, 2, 3));
    expect(await serverIncoming.stream.read()).toBeNull();

    const serverOpening = server.openStream(`${path}-server`);
    const clientIncoming = await client.acceptStream();
    const serverStream = await serverOpening;
    await serverStream.write(Uint8Array.of(4, 5, 6));
    await serverStream.closeWrite();
    expect(await clientIncoming.stream.read()).toEqual(Uint8Array.of(4, 5, 6));
    expect(await clientIncoming.stream.read()).toBeNull();

    await client.close();
    await server.close();
    expect(spendCount).toBe(1);
    await new Promise<void>((resolve) => wss.close(() => resolve()));
    await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
  }, 20_000);
});

function withLocalWSS(rawArtifact: string, url: string): Readonly<{ raw: string; artifact: ArtifactV2 }> {
  const value = JSON.parse(rawArtifact) as { path: { candidates: Array<{ id: string; url: string }> } };
  value.path.candidates = value.path.candidates.filter((candidate) => candidate.id === "w1");
  value.path.candidates[0]!.url = url;
  const raw = JSON.stringify(value);
  return { raw, artifact: decodeArtifactV2JSON(raw) };
}

function serverConfig(artifact: ArtifactV2, fsb2: ReturnType<typeof decodeFSB2RequestV2>): SessionConfigV2 {
  const tunnel = artifact.path.kind === "tunnel" ? artifact.path : undefined;
  const localBinding = tunnel === undefined
    ? fsb2.localAdmissionBinding
    : admissionBindingV2(encodeFSB2RequestV2({
        ...fsb2.request,
        role: 2,
        endpoint_instance_id: tunnel.expected_peer_endpoint_instance_id,
      }));
  return {
    role: "server",
    path: artifact.path.kind,
    channelID: artifact.session.channel_id,
    sessionContractHash: base64urlDecode(artifact.session.contract_hash_b64u),
    suite: artifact.session.default_suite as CipherSuiteV2,
    psk: base64urlDecode(artifact.session.e2ee_psk_b64u),
    maxInboundStreams: artifact.session.max_inbound_streams,
    sessionContract: artifact.session,
    idleTimeoutMs: artifact.session.idle_timeout_seconds * 1_000,
    localAdmissionBinding: localBinding,
    peerAdmissionBinding: fsb2.localAdmissionBinding,
    localEndpointInstanceID: tunnel?.expected_peer_endpoint_instance_id ?? "",
    expectedPeerEndpointInstanceID: tunnel?.local_endpoint_instance_id ?? "",
    deadlines: {
      establishTimeoutMs: artifact.session.establish_timeout_seconds * 1_000,
      rekeyPrepareTimeoutMs: artifact.session.rekey_prepare_timeout_seconds * 1_000,
      rekeyCompletionTimeoutMs: artifact.session.rekey_completion_timeout_seconds * 1_000,
    },
  };
}
