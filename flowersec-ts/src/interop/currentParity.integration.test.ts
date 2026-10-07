import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { CurrentParityReady } from "./currentParity.js";

const peerPath = fileURLToPath(new URL("./serverParityPeer.ts", import.meta.url));
const packagePath = fileURLToPath(new URL("../..", import.meta.url));
function peer(role: "server" | "client") {
  const child = spawn(process.execPath, ["--import", "tsx", peerPath, role, "--carrier", "websocket"], { cwd: packagePath, stdio: ["pipe", "pipe", "pipe"] });
  const reader = createInterface({ input: child.stdout }), lines = reader[Symbol.asyncIterator]();
  let diagnostics = "";
  child.stderr.on("data", (bytes: Buffer) => { if (diagnostics.length < 65536) diagnostics += bytes.toString("utf8").slice(0, 65536 - diagnostics.length); });
  const exit = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => code === 0 ? resolve() : reject(new Error(`parity ${role} exited ${code ?? signal}: ${diagnostics}`)));
  });
  void exit.catch(() => undefined);
  return { child, exit, async next<T>(): Promise<T> {
    const item = await lines.next(); if (item.done || Buffer.byteLength(item.value) > 4194304) throw new Error(`parity ${role} omitted its bounded protocol output: ${diagnostics}`);
    return JSON.parse(item.value) as T;
  }, async close(): Promise<void> { reader.close(); if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); await exit.catch(() => undefined); } };
}

// Exercises the ordinary source, Acceptor, ServiceContract, stream and Noise
// owners through the same default entry point used by the parity driver.
describe("current parity direct READY", () => {
  it("runs the default V4 WSS client and accepted server through actual cleanup", async () => {
    const server = peer("server"); let client: ReturnType<typeof peer> | undefined;
    const stop = setTimeout(() => { server.child.kill("SIGKILL"); client?.child.kill("SIGKILL"); }, 40000);
    try {
      const ready = await server.next<CurrentParityReady>();
      expect(ready).toMatchObject({ type: "ready", runtime: "node-typescript", wire_revision: 4, path: "direct", carrier: "websocket", source: "preauthorized_pool" });
      expect(JSON.parse(ready.artifact_json)).toMatchObject({ wire_revision: 4, role: 0, source: "preauthorized_pool" });
      client = peer("client"); client.child.stdin.end(`${JSON.stringify(ready)}\n`);
      const clientResult = await client.next<{ type: string; wire_revision: number; cases: string[] }>();
      const serverResult = await server.next<{ type: string; wire_revision: number; cases: string[] }>();
      expect(clientResult).toMatchObject({ type: "client-result", wire_revision: 4 });
      expect(serverResult).toMatchObject({ type: "server-result", wire_revision: 4 });
      const cases = ["admission", "rpc", "notification", "stream-metadata", "stream-fin", "stream-reset", "cancel", "rekey", "liveness", "close", "cleanup"];
      expect(clientResult.cases).toEqual(expect.arrayContaining(cases)); expect(serverResult.cases).toEqual(expect.arrayContaining(cases));
      expect(clientResult.cases).not.toContain("datagram");
      await Promise.all([client.exit, server.exit]);
    } finally { clearTimeout(stop); await Promise.all([client?.close(), server.close()]); }
  }, 45000);
});
