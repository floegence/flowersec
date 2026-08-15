import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { StreamHandlers } from "../facade.js";
import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import { parseArtifact } from "../v2/opaqueArtifact.js";
import { createAcceptor, SessionHandlers } from "./acceptor.js";
import { connect } from "./connectSession.js";
import { createEndpointSet, Issuer } from "./controlplane.js";

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));

describe("Node WebSocket Acceptor", () => {
  test("serves a complete direct WSS Session", async () => {
    const carrierPath = "direct" as const;
    const temporary = mkdtempSync(path.join(os.tmpdir(), "flowersec-node-wss-acceptor-"));
    const certificatePath = path.join(temporary, "certificate.pem");
    const privateKeyPath = path.join(temporary, "private-key.pem");
    const certificateDER = path.join(temporary, "certificate.der");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-nodes", "-days", "1", "-sha256", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
      "-keyout", privateKeyPath, "-out", certificatePath,
    ], { stdio: "ignore" });
    execFileSync("openssl", ["x509", "-in", certificatePath, "-outform", "DER", "-out", certificateDER]);

    const fixture = JSON.parse(readFileSync(
      path.join(repositoryRoot, "testdata/transport_v2/artifact_vectors.json"),
      "utf8",
    )) as Readonly<{ positive: readonly Readonly<{ path_kind: string; artifact_json: string }>[] }>;
    const source = fixture.positive.find((entry) => entry.path_kind === "direct");
    if (source === undefined) throw new Error("missing direct artifact fixture");
    const directArtifact = JSON.parse(source.artifact_json) as {
      session: { max_inbound_streams: number };
      path: {
        kind: "direct" | "tunnel";
        routing_token?: string;
        token?: string;
        candidates: Array<{ id: string; carrier: string; url: string }>;
      };
    };
    directArtifact.path.candidates = directArtifact.path.candidates.filter((candidate) => candidate.carrier === "websocket");
    const artifacts = carrierPath === "direct"
      ? [directArtifact]
      : (() => {
          const pair = new Issuer().issueTunnelPair({
            session: { channelId: "node-wss-tunnel", maxInboundStreams: directArtifact.session.max_inbound_streams },
            endpoints: createEndpointSet("wss://localhost/flowersec/v2/tunnel"),
            rendezvousGroupId: "node-wss-group",
            listenerAudience: "node-wss-listener",
            firstEndpointId: "endpoint-a",
            secondEndpointId: "endpoint-b",
          });
          return [pair.first, pair.second].map((issued) => JSON.parse(new TextDecoder().decode(issued.artifactJSON())) as typeof directArtifact);
        })();
    const artifactsByLookup = new Map<string, ReturnType<typeof parseArtifact>>();

    let resolveNotification!: (value: unknown) => void;
    const notification = new Promise<unknown>((resolve) => { resolveNotification = resolve; });
    const acceptor = await createAcceptor({
      listeners: [{
        carrier: "websocket",
        path: carrierPath,
        host: "127.0.0.1",
        port: 0,
        tls: {
          certificate: readFileSync(certificatePath, "utf8"),
          privateKey: readFileSync(privateKeyPath, "utf8"),
        },
        allowedOrigins: ["https://app.example"],
      }],
      maxInboundStreams: directArtifact.session.max_inbound_streams,
      authorize: async (request) => {
        const matched = artifactsByLookup.get(request.lookupKey());
        return matched === undefined
          ? { decision: "reject" as const, reason: "credential_unknown" }
          : { decision: "allow" as const, artifact: matched };
      },
      resolveHandlers: () => {
        const handlers = new SessionHandlers();
        handlers.handleRPC(17, async (payload) => ({ payload }));
        handlers.handleNotification(18, (payload) => resolveNotification(payload));
        handlers.handleStream("node-wss", async (incoming) => {
          const payload = await incoming.stream.read();
          await incoming.stream.write(payload ?? new Uint8Array());
          await incoming.stream.closeWrite();
        });
        return handlers;
      },
    });
    try {
      const address = acceptor.addresses()[0];
      if (address === undefined) throw new Error("WebSocket listener did not bind");
      for (const artifact of artifacts) {
        artifact.path.candidates[0]!.url = "wss://localhost:" + address.port + "/flowersec/v2/" + carrierPath;
        const credential = artifact.path.kind === "direct" ? artifact.path.routing_token : artifact.path.token;
        if (credential === undefined) throw new Error("artifact credential is missing");
        artifactsByLookup.set(new IssuerLookup(credential).value, parseArtifact(JSON.stringify(artifact)));
      }
      const acceptedPromises = artifacts.map(async () => await acceptor.accept());
      const clients = await Promise.all(artifacts.map(async (artifact) => await connect(
        createArtifactLeaseV2(parseArtifact(JSON.stringify(artifact)), async () => undefined), {
          origin: "https://app.example",
          tls: { ca: readFileSync(certificatePath, "utf8") },
        }),
      ));
      const accepted = await Promise.all(acceptedPromises);
      const serving = accepted.map((session) => session.serve().catch((error: unknown) => error));
      const clientHandlers = new StreamHandlers();
      clientHandlers.handleStream("node-client-inbound", async (incoming) => {
        const payload = await incoming.stream.read();
        if (payload === null) throw new Error("server stream ended before its payload");
        await incoming.stream.write(payload);
      });
      const clientServing = clientHandlers.serve(clients[0]!).catch((error: unknown) => error);
      const serverStream = await accepted[0]!.session.openStream("node-client-inbound");
      await serverStream.write(new TextEncoder().encode("server-payload"));
      await serverStream.closeWrite();
      const clientEcho = await serverStream.read();
      if (clientEcho === null) throw new Error("client stream ended before its payload");
      expect(new TextDecoder().decode(clientEcho)).toBe("server-payload");
      expect(await serverStream.read()).toBeNull();
      expect(await clients[0]!.rpc.call(17, { path: carrierPath }, (payload) => payload))
        .toEqual({ ok: true, payload: { path: carrierPath } });
      await clients[0]!.rpc.notify(18, { ready: true });
      await expect(notification).resolves.toEqual({ ready: true });
      const stream = await clients[0]!.openStream("node-wss");
      await stream.write(new TextEncoder().encode("payload"));
      await stream.closeWrite();
      const echoed = await stream.read();
      if (echoed === null) throw new Error("echo stream ended before its payload");
      expect(new TextDecoder().decode(echoed)).toBe("payload");
      expect(await stream.read()).toBeNull();
      await Promise.all(clients.map(async (client) => await client.close()));
      await expect(clientServing).resolves.toMatchObject({ code: "closed" });
      for (const task of serving) await expect(task).resolves.toMatchObject({ code: "closed" });
      await Promise.all(accepted.map(async (session) => await session.close().catch(() => undefined)));
    } finally {
      await acceptor.close();
      rmSync(temporary, { recursive: true, force: true });
    }
  }, 30_000);
});

class IssuerLookup {
  readonly value: string;
  constructor(token: string) {
    this.value = createHash("sha256").update(token).digest("base64url");
  }
}
