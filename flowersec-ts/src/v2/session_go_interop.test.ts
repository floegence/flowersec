import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

import { createNodeWsFactory } from "../node/wsFactory.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import { establishAdmittedWebSocketSessionV2 } from "./admittedSession.js";
import type { SessionContractV2 } from "./artifact.js";
import { CipherSuiteV2 } from "./protocol.js";
import type { SessionConfigV2 } from "./session.js";

const artifactFixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{
  positive: readonly Readonly<{
    id: string;
    artifact_json: string;
    winners: readonly Readonly<{
      candidate_id: string;
      fsb2_hex: string;
      admission_binding_hex: string;
    }>[];
  }>[];
}>;
const directFixture = artifactFixture.positive.find((entry) => entry.id === "direct-three-carriers")!;
const admissionVector = directFixture.winners.find((winner) => winner.candidate_id === "w1")!;
const rawFSB2 = Uint8Array.from(Buffer.from(admissionVector.fsb2_hex, "hex"));
const sessionContract = (JSON.parse(directFixture.artifact_json) as Readonly<{ session: SessionContractV2 }>).session;

describe("TypeScript-Go SessionV2 interop", () => {
  test("runs admission, handshake, streams, liveness, rekey, and FIN over production WSS", async () => {
    const goRoot = fileURLToPath(new URL("../../../flowersec-go", import.meta.url));
    const peer = spawn("go", ["run", "./internal/cmd/ts-session-peer"], {
      cwd: goRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stderr: string[] = [];
    let phase = "spawn";
    peer.stderr.setEncoding("utf8");
    peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
    try {
      const endpoint = JSON.parse(await firstLine(peer.stdout)) as Readonly<{ url: string; ca_pem: string }>;
      phase = "connect";
      const socket = createNodeWsFactory({ ca: endpoint.ca_pem })(
        endpoint.url,
        "https://client.example",
        "flowersec.direct.v2",
      );
      await waitForWebSocketOpen(socket);
      const transport = new WebSocketBinaryTransport(socket);
      const session = await establishAdmittedWebSocketSessionV2(transport, rawFSB2, new Set(), config());
      phase = "liveness";
      expect(await session.probeLiveness()).toBeGreaterThanOrEqual(0);

      const stream = await session.openStream("interop.echo");
      phase = "first-data";
      await stream.write(new TextEncoder().encode("hello-go"));
      expect(new TextDecoder().decode((await stream.read())!)).toBe("hello-ts");
      phase = "go-rekey";
      expect(new TextDecoder().decode((await stream.read())!)).toBe("go-rekey-ok");

      phase = "ts-rekey";
      await session.rekey();
      await stream.write(new TextEncoder().encode("ts-rekey-ok"));
      await stream.closeWrite();
      expect(new TextDecoder().decode((await stream.read())!)).toBe("done");
      expect(await stream.read()).toBeNull();
      phase = "close";
      await session.close();

      const exit = await processExit(peer);
      expect(exit, stderr.join("")).toBe(0);
    } catch (error) {
      await Promise.race([processExit(peer), new Promise((resolve) => setTimeout(resolve, 250))]);
      throw new Error(`interop failed during ${phase}: ${error instanceof Error ? error.message : String(error)}\n${stderr.join("")}`);
    } finally {
      if (peer.exitCode === null) peer.kill("SIGKILL");
    }
  }, 30_000);
});

function config(): SessionConfigV2 {
  return {
    role: "client",
    path: "direct",
    channelID: "channel-1",
    sessionContractHash: Uint8Array.from(Buffer.from("ioBJP5DPhg471caMR-huV5I9RlNKY2Pr9fs2GkP8CmA", "base64url")),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    maxInboundStreams: 64,
    sessionContract,
    localAdmissionBinding: Uint8Array.from(Buffer.from(admissionVector.admission_binding_hex, "hex")),
    peerAdmissionBinding: Uint8Array.from(Buffer.from(admissionVector.admission_binding_hex, "hex")),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
  };
}

async function waitForWebSocketOpen(socket: WebSocketLike): Promise<void> {
  if (socket.readyState === 1) return;
  await new Promise<void>((resolve, reject) => {
    const open = () => { cleanup(); resolve(); };
    const error = () => { cleanup(); reject(new Error("WSS connection failed before open")); };
    const close = () => { cleanup(); reject(new Error("WSS connection closed before open")); };
    const cleanup = () => {
      socket.removeEventListener("open", open);
      socket.removeEventListener("error", error);
      socket.removeEventListener("close", close);
    };
    socket.addEventListener("open", open);
    socket.addEventListener("error", error);
    socket.addEventListener("close", close);
  });
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
