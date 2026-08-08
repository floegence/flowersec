import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import { parseArtifact } from "../v2/opaqueArtifact.js";
import { connect } from "./connectSession.js";
import {
  createAcceptor,
  SessionHandlers,
  type RuntimeAuthorizationRequest,
} from "./acceptor.js";

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));

describe("Node Acceptor", () => {
  test("freezes handlers before direct WebTransport establishment", async () => {
    const temporary = mkdtempSync(path.join(os.tmpdir(), "flowersec-node-acceptor-"));
    const certificate = path.join(temporary, "certificate.pem");
    const privateKey = path.join(temporary, "private-key.pem");
    const certificateDER = path.join(temporary, "certificate.der");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-nodes", "-days", "1", "-sha256", "-subj", "/CN=127.0.0.1",
      "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", privateKey, "-out", certificate,
    ], { stdio: "ignore" });
    execFileSync("openssl", ["x509", "-in", certificate, "-outform", "DER", "-out", certificateDER]);
    const certificateHash = createHash("sha256").update(readFileSync(certificateDER)).digest();
    const fixture = JSON.parse(readFileSync(
      path.join(repositoryRoot, "testdata/transport_v2/artifact_vectors.json"),
      "utf8",
    )) as Readonly<{ positive: readonly Readonly<{ id: string; artifact_json: string }>[] }>;
    const source = fixture.positive.find((entry) => entry.id === "direct-three-carriers");
    if (source === undefined) throw new Error("missing direct artifact fixture");
    const raw = JSON.parse(source.artifact_json) as {
      session: { max_inbound_streams: number };
      path: { candidates: Array<{ id: string; carrier: string; url: string }> };
    };
    raw.path.candidates = raw.path.candidates.filter((candidate) => candidate.id === "t1");
    if (raw.path.candidates[0] === undefined || raw.path.candidates[0].carrier !== "webtransport") {
      throw new Error("direct WebTransport candidate is missing");
    }
    const acceptor = await createAcceptor({
      host: "127.0.0.1",
      port: 0,
      path: "/flowersec/webtransport/v2/direct",
      certificate: readFileSync(certificate, "utf8"),
      privateKey: readFileSync(privateKey, "utf8"),
      maxInboundStreams: raw.session.max_inbound_streams,
      authorize: async (_request: RuntimeAuthorizationRequest) => ({
        decision: "allow" as const,
        artifact: parseArtifact(JSON.stringify(raw)),
      }),
      resolveHandlers: () => {
        const handlers = new SessionHandlers({ maxConcurrentStreams: 2 });
        handlers.handleRPC(17, async (payload) => ({ payload }));
        handlers.handleStream("accepted-handler", async (incoming) => {
          expect(new TextDecoder().decode(await incoming.stream.read())).toBe("handled");
        });
        return handlers;
      },
    });
    const address = acceptor.address();
    raw.path.candidates[0]!.url = `https://127.0.0.1:${address.port}/flowersec/webtransport/v2/direct`;
    const lease = createArtifactLeaseV2(parseArtifact(JSON.stringify(raw)), async () => undefined);
    let accepted;
    try {
      const acceptedPromise = acceptor.accept();
      const client = await connect(lease, {
        origin: "https://app.example",
        tls: { serverCertificateHash: certificateHash },
      });
      accepted = await acceptedPromise;
      const serving = accepted.serve().then(
        () => undefined,
        (error: unknown) => error,
      );
      const response = await client.rpc.call(17, { value: "rpc" }, (payload) => payload);
      expect(response).toEqual({ ok: true, payload: { value: "rpc" } });
      const stream = await client.openStream("accepted-handler");
      await stream.write(new TextEncoder().encode("handled"));
      await stream.closeWrite();
      await client.close();
      await expect(serving).resolves.toMatchObject({ code: "closed" });
    } finally {
      await accepted?.close().catch(() => undefined);
      await acceptor.close();
      rmSync(temporary, { recursive: true, force: true });
    }
  }, 30_000);
});
