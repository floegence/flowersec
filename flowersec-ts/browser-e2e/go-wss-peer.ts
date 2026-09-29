import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { expect } from "@playwright/test";
import { createV4WSSPeerFixture } from "./v4-wss-peer.js";
import type { NoiseProfile } from "../src/v4/runtime/noiseHandshake.js";
import { encode } from "../src/v4/testSupport/credentials.js";
import { wire } from "../src/v4/runtime/wireRegistry.js";

export function buildGoWSSPeer() {
  const directory = mkdtempSync(join(tmpdir(), "flowersec-browser-go-")), binary = join(directory, "peer");
  try {
    execFileSync("go", ["test", "-c", "-o", binary, "./internal/sessionv4"], {
      cwd: fileURLToPath(new URL("../../flowersec-go/", import.meta.url)), stdio: "pipe", timeout: 60000,
    });
    return { binary, close: () => rmSync(directory, { recursive: true, force: true }) };
  } catch (error) { rmSync(directory, { recursive: true, force: true }); throw error; }
}

interface PeerEvent { readonly event: string; readonly port?: number; readonly streams?: number; readonly reservations?: number; readonly frames?: number[] }

export async function startGoWSSPeer(binary: string, certificate: Buffer, key: Buffer, origin: string, profile: NoiseProfile) {
  const process = spawn(binary, ["-test.run=^TestBrowserWSSInteropPeer$", "-test.v", "-test.timeout=40s"], {
    cwd: fileURLToPath(new URL("../../flowersec-go/internal/sessionv4/", import.meta.url)),
    env: { ...globalThis.process.env, FLOWERSEC_BROWSER_WSS_INTEROP: "1" }, stdio: ["pipe", "pipe", "pipe"],
  });
  const events = new Map<string, PeerEvent>(), waiters = new Map<string, { resolve(value: PeerEvent): void; reject(error: Error): void }>();
  let output = "", failure: Error | undefined;
  const fail = (error: Error) => { failure ??= error; for (const waiter of waiters.values()) waiter.reject(error); waiters.clear(); };
  process.on("error", fail);
  process.stdin.on("error", fail);
  process.stderr.setEncoding("utf8"); process.stderr.on("data", (value: string) => { output = (output + value).slice(-32768); });
  const lines = createInterface({ input: process.stdout });
  lines.on("line", (line: string) => {
    output = (output + line + "\n").slice(-32768);
    if (!line.startsWith("FLOWERSEC_INTEROP ")) return;
    try {
      const value = JSON.parse(line.slice("FLOWERSEC_INTEROP ".length)) as PeerEvent;
      events.set(value.event, value); waiters.get(value.event)?.resolve(value); waiters.delete(value.event);
    } catch { fail(new Error("invalid Go peer result")); }
  });
  const ended = new Promise<number | null>(resolve => process.once("close", code => {
    if (code !== 0 || waiters.size !== 0) fail(new Error(`Go WSS peer exited (${code}):\n${output}`));
    resolve(code);
  }));
  const wait = (event: string): Promise<PeerEvent> => {
    const value = events.get(event);
    if (value !== undefined) return Promise.resolve(value);
    if (failure !== undefined) return Promise.reject(failure);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { waiters.delete(event); reject(new Error(`Go peer did not publish ${event}:\n${output}`)); }, 20000);
      waiters.set(event, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
    });
  };
  const stop = async () => {
    process.stdin.end();
    const timer = setTimeout(() => process.kill("SIGKILL"), 7000);
    try { return await ended; } finally { clearTimeout(timer); lines.close(); }
  };
  let fixtureOwner: ReturnType<typeof createV4WSSPeerFixture> | undefined;
  try {
    process.stdin.write(JSON.stringify({ certificate: certificate.toString("base64"), key: key.toString("base64"), origin, profile }) + "\n");
    const ready = await wait("listening");
    if (!Number.isSafeInteger(ready.port) || ready.port! <= 0) throw new Error("invalid Go peer port");
    const { timeOrigin, env, fixture } = fixtureOwner = createV4WSSPeerFixture(origin, ready.port!, profile);
    const input = fixture.input();
    process.stdin.write(JSON.stringify({
      artifact: Buffer.from(input.artifact).toString("base64"), clientCertificate: Buffer.from(input.clientCertificate).toString("base64"),
      serverCertificate: Buffer.from(input.serverCertificate).toString("base64"), activation: Buffer.from(input.activation).toString("base64"), timeOrigin: Number(timeOrigin),
    }) + "\n");
    return {
      endpoint: `wss://localhost:${ready.port}/flowersec/v4/direct`, timeOrigin: timeOrigin.toString(), profile, route: Array.from(fixture.route),
      input: { artifact: Array.from(input.artifact), clientCertificate: Array.from(input.clientCertificate), serverCertificate: Array.from(input.serverCertificate), activation: Array.from(input.activation), candidateIndex: 0 },
      bootstrap: (nonce: number[]) => ({ response: Array.from(fixture.response(new Uint8Array(nonce))), state: Array.from(encode(fixture.state)) }),
      served: () => wait("served"),
      close: async () => {
        const code = await stop(); await env.publicOwner.close();
        expect(code, output).toBe(0); expect(failure, output).toBeUndefined();
        expect(events.get("cleanup"), output).toMatchObject({ reservations: 0 });
        const frames = events.get("cleanup")!.frames;
        for (const name of ["NEGOTIATE", "ADMISSION_RESULT", "HANDSHAKE", "READY"] as const) expect(frames?.[wire.frame_types[name]!], name).toBe(1);
        expect(frames?.[wire.frame_types.PONG!], "Go authenticated PONG publication").toBeGreaterThan(0);
        expect((await env.publicOwner.waitCleanup()).status).toBe("complete"); expect(env.root.snapshot().reservations).toBe(0);
      },
    };
  } catch (error) {
    await stop(); await fixtureOwner?.env.publicOwner.close(); throw error;
  }
}
