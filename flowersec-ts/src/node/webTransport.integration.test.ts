import { createHash } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import { parseArtifact } from "../v2/opaqueArtifact.js";
import { connectNodeSession } from "./connectSession.js";
import { createNodeWebTransportClientV2 } from "./webTransportClient.js";
import { startNodeWebTransportServerV2 } from "./webTransportServer.js";

const text = (value: string): Uint8Array => new TextEncoder().encode(value);
const decode = (value: Uint8Array | null): string => value === null ? "" : new TextDecoder().decode(value);
const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));
const artifactFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  positive: readonly Readonly<{ id: string; artifact_json: string }>[];
}>;

describe("Node WebTransport runtime adapter", () => {
  test("carries native stream FIN and DATAGRAM without a browser", async () => {
    const temporary = mkdtempSync(path.join(os.tmpdir(), "flowersec-node-webtransport-"));
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
    const server = await startNodeWebTransportServerV2({
      host: "127.0.0.1",
      port: 0,
      path: "/flowersec/webtransport/v2/direct",
      certificate: readFileSync(certificate, "utf8"),
      privateKey: readFileSync(privateKey, "utf8"),
      carrierPath: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    let client;
    let accepted;
    try {
      const address = server.address();
      [client, accepted] = await Promise.all([
        createNodeWebTransportClientV2(
          `https://127.0.0.1:${address.port}/flowersec/webtransport/v2/direct`,
          {
            path: "direct",
            inboundBidirectionalStreamCapacity: 10,
            serverCertificateHash: certificateHash,
          },
        ),
        server.accept(),
      ]);
      const clientStream = await client.openStream();
      const serverStream = await accepted.acceptStream();
      await clientStream.write(text("FSC2"));
      await clientStream.closeWrite();
      expect(decode(await serverStream.read())).toBe("FSC2");
      expect(await serverStream.read()).toBeNull();

      expect(await client.unreliableDatagrams!.send(text("FSD2"))).toBe("accepted");
      expect(decode(await accepted.unreliableDatagrams!.receive())).toBe("FSD2");
    } finally {
      await Promise.all([client?.close(), accepted?.close()]);
      await server.close();
      rmSync(temporary, { recursive: true, force: true });
    }
  }, 30_000);

  test("runs direct Go admission and Session semantics over WebTransport", async () => {
    await runGoWebTransportSession("direct");
  }, 30_000);

  test("runs tunnel Go admission and Session semantics over WebTransport", async () => {
    await runGoWebTransportSession("tunnel");
  }, 30_000);
});

async function runGoWebTransportSession(sessionPath: "direct" | "tunnel"): Promise<void> {
  const peer = spawn(
    "go",
    ["run", "./internal/cmd/node-webtransport-peer", "--path", sessionPath],
    { cwd: path.join(repositoryRoot, "flowersec-go"), stdio: ["ignore", "pipe", "pipe"] },
  );
  const stderr: string[] = [];
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
  let phase = "peer-start";
  try {
    const endpoint = JSON.parse(await firstLine(peer.stdout)) as Readonly<{
      url: string;
      certificate_hash: string;
    }>;
    const fixture = artifactFixture.positive.find((entry) => entry.id === `${sessionPath}-three-carriers`);
    if (fixture === undefined) throw new Error(`${sessionPath} artifact fixture is missing`);
    const raw = JSON.parse(fixture.artifact_json) as {
      path: { candidates: Array<{ id: string; url: string }> };
    };
    const candidate = raw.path.candidates.find((entry) => entry.id === "t1");
    if (candidate === undefined) throw new Error(`${sessionPath} WebTransport candidate is missing`);
    candidate.url = endpoint.url;
    raw.path.candidates = [candidate];

    phase = "admission-and-handshake";
    const session = await connectNodeSession(
      createArtifactLeaseV2(parseArtifact(JSON.stringify(raw)), async () => undefined),
      {
        origin: "http://127.0.0.1:1",
        tls: { serverCertificateHash: Uint8Array.from(Buffer.from(endpoint.certificate_hash, "base64")) },
      },
    );
    if (session.unreliableMessages === undefined) throw new Error("WebTransport DATAGRAM was not negotiated");

    phase = "datagram";
    expect(await session.unreliableMessages.send(text("node-datagram"), {
      expiresAtUnixMs: Date.now() + 5_000,
    })).toBe("accepted");
    expect(decode(await session.unreliableMessages.receive())).toBe("go-datagram");

    phase = "stream-and-rekey";
    expect(await session.probeLiveness()).toBeGreaterThanOrEqual(0);
    const stream = await session.openStream("interop.echo");
    await stream.write(text("hello-go"));
    expect(decode(await stream.read())).toBe("hello-ts");
    expect(decode(await stream.read())).toBe("go-rekey-ok");
    await session.rekey();
    await stream.write(text("ts-rekey-ok"));
    await stream.closeWrite();
    expect(decode(await stream.read())).toBe("done");
    expect(await stream.read()).toBeNull();

    phase = "close";
    await session.close();
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } catch (error) {
    throw new Error(
      `Node-Go WebTransport ${sessionPath} failed during ${phase}: ${error instanceof Error ? error.message : String(error)}\n${stderr.join("")}`,
    );
  } finally {
    if (peer.exitCode === null) peer.kill("SIGKILL");
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
    const end = () => { cleanup(); reject(new Error("Go peer exited before publishing endpoint")); };
    const cleanup = () => { stream.removeListener("data", data); stream.removeListener("end", end); };
    stream.on("data", data);
    stream.on("end", end);
  });
}

async function processExit(process: ReturnType<typeof spawn>): Promise<number | null> {
  if (process.exitCode !== null) return process.exitCode;
  return await new Promise((resolve) => process.once("exit", (code) => resolve(code)));
}
