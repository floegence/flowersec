import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  connect,
  createArtifactLease,
  parseArtifact,
} from "../node/index.js";

const artifactFixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{
  positive: readonly Readonly<{ id: string; artifact_json: string }>[];
}>;

describe("TypeScript-Go v3 production interoperability", () => {
  test("runs direct FSB3/FSH3 and Session semantics over Go WSS", async () => {
    await runGoWSSSessionV3("direct");
  }, 30_000);

  test("runs tunnel-role FSB3/FSH3 and Session semantics over Go WSS", async () => {
    await runGoWSSSessionV3("tunnel");
  }, 30_000);
});

async function runGoWSSSessionV3(sessionPath: "direct" | "tunnel"): Promise<void> {
  const goRoot = fileURLToPath(new URL("../../../flowersec-go", import.meta.url));
  const peer = spawn("go", [
    "run", "./internal/cmd/ts-session-peer-v3", "--path", sessionPath, "--server-notify",
  ], {
    cwd: goRoot,
    env: { ...process.env, FLOWERSEC_SERVER_PARITY_PEER: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stderr: string[] = [];
  let phase = "spawn";
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
  try {
    const endpoint = JSON.parse(await firstLine(peer.stdout)) as Readonly<{ url: string; ca_pem: string }>;
    const fixture = artifactFixture.positive.find((entry) => entry.id === `${sessionPath}-mixed-security`);
    if (fixture === undefined) throw new Error(`${sessionPath} v3 artifact fixture is missing`);
    const raw = JSON.parse(fixture.artifact_json) as {
      path: {
        role?: 1 | 2;
        candidates: Array<{ carrier: string; url: string; tls: unknown; wire_profile: string }>;
      };
    };
    const webSocket = raw.path.candidates.find((candidate) => candidate.carrier === "websocket" &&
      candidate.tls !== undefined && (candidate.tls as { mode?: unknown }).mode === "ca");
    if (webSocket === undefined) throw new Error(`${sessionPath} v3 CA WebSocket candidate is missing`);
    webSocket.url = endpoint.url;
    raw.path.candidates = [webSocket];

    phase = "connect";
    const session = await connect(
      createArtifactLease(parseArtifact(JSON.stringify(raw)), async () => undefined),
      { origin: "https://client.example", roots: endpoint.ca_pem },
    );
    phase = "liveness";
    expect(await session.probeLiveness()).toBeGreaterThanOrEqual(0);

    phase = "server-notify";
    const serverNotification = new Promise<Readonly<{ state: string }>>((resolve) => {
      const unsubscribe = session.rpc.onNotify(9_002, decodeStateNotification, (payload) => {
        unsubscribe();
        resolve(payload);
      });
    });
    await session.rpc.notify(9_001, { state: "ready" });
    expect(await Promise.race([
      serverNotification,
      new Promise((_, reject) => setTimeout(() => reject(new Error("Go v3 server notification timed out")), 5_000)),
    ])).toEqual({ state: "accepted" });

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

    expect(await processExit(peer), stderr.join("")).toBe(0);
  } catch (error) {
    await Promise.race([processExit(peer), new Promise((resolve) => setTimeout(resolve, 250))]);
    throw new Error(`v3 interop failed during ${phase}: ${error instanceof Error ? error.message : String(error)}\n${stderr.join("")}`);
  } finally {
    if (peer.exitCode === null) peer.kill("SIGKILL");
  }
}

function decodeStateNotification(payload: unknown): Readonly<{ state: string }> {
  if (typeof payload !== "object" || payload === null || !("state" in payload) ||
      typeof payload.state !== "string") throw new TypeError("invalid state notification");
  return Object.freeze({ state: payload.state });
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
    const end = () => { cleanup(); reject(new Error("Go v3 peer exited before publishing endpoint")); };
    const cleanup = () => { stream.removeListener("data", data); stream.removeListener("end", end); };
    stream.on("data", data);
    stream.on("end", end);
  });
}

async function processExit(process: ReturnType<typeof spawn>): Promise<number | null> {
  if (process.exitCode !== null) return process.exitCode;
  return await new Promise((resolve) => process.once("exit", (code) => resolve(code)));
}
