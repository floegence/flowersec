import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test, vi } from "vitest";
import { WebSocket as NodeWebSocket } from "ws";
import { connectHTTPDirectV1, createHTTPDirectArtifactLeaseV1, parseHTTPDirectArtifactV1 } from "../browser/index.js";

describe("HTTP direct TypeScript-Go interoperability", () => {
  afterEach(() => vi.unstubAllGlobals());
  test("shares one application port and preserves two independent sessions", async () => {
    const peer = spawn("go", ["run", "./internal/cmd/http-direct-peer-v1"], {
      cwd: fileURLToPath(new URL("../../../flowersec-go", import.meta.url)), stdio: ["ignore", "pipe", "pipe"],
    });
    const stderr: string[] = [];
    peer.stderr.setEncoding("utf8");
    peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
    try {
      const {origin} = JSON.parse(await firstLine(peer.stdout)) as {origin: string};
      expect(await (await fetch(origin)).text()).toBe("application");
      class HTTPWebSocket extends NodeWebSocket {
        constructor(url: string, protocols?: string | string[]) { super(url, protocols, {origin}); }
      }
      vi.stubGlobal("WebSocket", HTTPWebSocket);
      vi.stubGlobal("WebTransport", undefined);
      // Ordinary HTTP pages expose CSPRNG bytes, but not SubtleCrypto or UUID.
      const randomBytes = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
      vi.stubGlobal("crypto", {getRandomValues: randomBytes});
      let spends = 0;
      const open = async () => connectHTTPDirectV1(createHTTPDirectArtifactLeaseV1(
        parseHTTPDirectArtifactV1(await (await fetch(origin + "/artifact")).text()),
        async () => {spends++;},
      ), {origin});
      const [first, second] = await Promise.all([open(), open()]);
      const response = {ok: true, payload: {server: "http-direct"}};
      expect(await first.rpc.call(7001, {message:"first"}, payload => payload)).toEqual(response);
      expect(await second.rpc.call(7001, {message:"second"}, payload => payload)).toEqual(response);
      await first.close();
      expect(await second.probeLiveness()).toBeGreaterThanOrEqual(0);
      expect(await second.rpc.call(7001, {}, payload => payload)).toEqual(response);
      expect(spends).toBe(2);
      await second.close();
      expect(await processExit(peer), stderr.join("")).toBe(0);
    } finally { if (peer.exitCode === null) peer.kill("SIGKILL"); }
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
    const end = () => { cleanup(); reject(new Error("Go HTTP peer exited before publishing its endpoint")); };
    const cleanup = () => { stream.removeListener("data", data); stream.removeListener("end", end); };
    stream.on("data", data);
    stream.on("end", end);
  });
}

async function processExit(process: ReturnType<typeof spawn>): Promise<number | null> {
  if (process.exitCode !== null) return process.exitCode;
  return await new Promise((resolve) => process.once("exit", (code) => resolve(code)));
}
