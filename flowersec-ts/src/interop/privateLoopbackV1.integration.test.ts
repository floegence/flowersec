import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test, vi } from "vitest";
import { WebSocket as NodeWebSocket } from "ws";

import {
  connectPrivateLoopbackV1,
  createPrivateLoopbackArtifactLeaseV1,
  parsePrivateLoopbackArtifactV1,
} from "../browser/index.js";

describe("private loopback v1 TypeScript-Go interoperability", () => {
  afterEach(() => vi.unstubAllGlobals());

  test("establishes a real Session, performs RPC, spends once, and releases once", async () => {
    const goRoot = fileURLToPath(new URL("../../../flowersec-go", import.meta.url));
    const peer = spawn("go", ["run", "./internal/cmd/private-loopback-peer-v1"], {
      cwd: goRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stderr: string[] = [];
    peer.stderr.setEncoding("utf8");
    peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
    try {
      const endpoint = JSON.parse(await firstLine(peer.stdout)) as Readonly<{
        artifact_json: string;
        bridge_token: string;
        origin: string;
      }>;
      class PrivateWebSocket extends NodeWebSocket {
        constructor(url: string, protocols?: string | string[]) {
          super(url, protocols, {
            origin: endpoint.origin,
            headers: { "X-Flowersec-Private-Bridge-Token": endpoint.bridge_token },
          });
        }
      }
      vi.stubGlobal("WebSocket", PrivateWebSocket);
      vi.stubGlobal("WebTransport", undefined);

      let spends = 0;
      let retirements = 0;
      const session = await connectPrivateLoopbackV1(
        createPrivateLoopbackArtifactLeaseV1(
          parsePrivateLoopbackArtifactV1(endpoint.artifact_json),
          async () => { spends += 1; },
          async () => { retirements += 1; },
        ),
        { origin: endpoint.origin },
      );
      expect(await session.probeLiveness()).toBeGreaterThanOrEqual(0);
      expect(await session.rpc.call(7001, { message: "ping" }, (payload) => payload)).toEqual({
        ok: true,
        payload: { server: "private-loopback" },
      });
      expect(spends).toBe(1);
      expect(retirements).toBe(0);
      await session.close();
      expect(await processExit(peer), stderr.join("")).toBe(0);
    } finally {
      if (peer.exitCode === null) peer.kill("SIGKILL");
    }
  }, 30_000);
});

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
    const end = () => { cleanup(); reject(new Error("Go private peer exited before publishing its endpoint")); };
    const cleanup = () => { stream.removeListener("data", data); stream.removeListener("end", end); };
    stream.on("data", data);
    stream.on("end", end);
  });
}

async function processExit(process: ReturnType<typeof spawn>): Promise<number | null> {
  if (process.exitCode !== null) return process.exitCode;
  return await new Promise((resolve) => process.once("exit", (code) => resolve(code)));
}
