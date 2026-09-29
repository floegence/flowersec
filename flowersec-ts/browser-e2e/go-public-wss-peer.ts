import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { expect } from "@playwright/test";
import type { NoiseProfile } from "../src/v4/runtime/noiseHandshake.js";

interface Event { event: string; value: Record<string, unknown> }
const unpack = (value: unknown): number[] => Array.from(Buffer.from(String(value), "base64"));

export async function startGoPublicWSSPeer(binary: string, origin: string, profile: NoiseProfile, source: "preauthorized_pool" | "live_authority" = "preauthorized_pool", controlFailure: "credential" | "signature" | "" = "") {
  const child = spawn(binary, ["-test.run=^TestPublicWebSocketBrowserInterop$", "-test.v", "-test.timeout=60s"], {
    cwd: fileURLToPath(new URL("../../flowersec-go/internal/sessionv4/", import.meta.url)),
    env: { ...process.env, FLOWERSEC_BROWSER_PUBLIC_WSS: "1" }, stdio: ["pipe", "pipe", "pipe"],
  });
  const events = new Map<string, Event>(), waiters = new Map<string, { resolve(value: Event): void; reject(error: Error): void }>();
  let output = "", failure: Error | undefined;
  const fail = (error: Error) => { failure ??= error; for (const waiter of waiters.values()) waiter.reject(error); waiters.clear(); };
  child.on("error", fail); child.stdin.on("error", fail);
  child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk: string) => { output = (output + chunk).slice(-32768); });
  const lines = createInterface({ input: child.stdout });
  lines.on("line", line => {
    if (!line.startsWith("FLOWERSEC_PUBLIC ")) { output = (output + line + "\n").slice(-32768); return; }
    try {
      const event = JSON.parse(line.slice("FLOWERSEC_PUBLIC ".length)) as Event;
      output = (output + `FLOWERSEC_PUBLIC ${event.event}\n`).slice(-32768);
      events.set(event.event, event); waiters.get(event.event)?.resolve(event); waiters.delete(event.event);
    } catch { fail(new Error("invalid Go public WSS event")); }
  });
  const ended = new Promise<number | null>(resolve => child.once("close", code => {
    if (code !== 0 || waiters.size !== 0) fail(new Error(`Go public WSS peer exited (${code}):\n${output}`));
    resolve(code);
  }));
  const wait = (name: string): Promise<Event> => {
    const event = events.get(name);
    if (event !== undefined) return Promise.resolve(event);
    if (failure !== undefined) return Promise.reject(failure);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { waiters.delete(name); reject(new Error(`Go public WSS peer did not publish ${name}:\n${output}`)); }, 25000);
      waiters.set(name, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
    });
  };
  const stop = async () => {
    if (child.exitCode === null && child.signalCode === null && !child.stdin.destroyed) {
      child.stdin.end(JSON.stringify({ Finish: true }) + "\n");
    }
    const timer = setTimeout(() => child.kill("SIGKILL"), 10000);
    try { return await ended; }
    finally { clearTimeout(timer); lines.close(); }
  };
  try {
    child.stdin.write(JSON.stringify({ Origin: origin, Profile: profile, Source: source, ControlFailure: controlFailure }) + "\n");
    const fixture = (await wait("fixture")).value;
    const port = Number(fixture.port);
    if (!Number.isSafeInteger(port) || port <= 0) throw new Error("invalid Go public WSS port");
    const input = {
      artifact: unpack(fixture.artifact), activation: fixture.activation == null ? [] : unpack(fixture.activation), clientCertificate: unpack(fixture.clientCertificate),
      serverCertificate: unpack(fixture.serverCertificate), candidateIndex: 0,
    };
    return {
      endpoint: `wss://localhost:${port}/flowersec/v4/direct`, profile, timeOrigin: "1200", route: unpack(fixture.routeDigest), input,
      public: {
        rootKeyID: unpack(fixture.rootKeyID), rootPublicKey: unpack(fixture.rootPublicKey), identitySeed: unpack(fixture.identitySeed),
        dhSeed: unpack(fixture.dhSeed), tenant: String(fixture.tenant), authority: String(fixture.authority),
        audience: String(fixture.audience), clientSubject: String(fixture.clientSubject), serverSubject: String(fixture.serverSubject),
        onceAuthority: String(fixture.onceAuthority), issuerKeyID: unpack(fixture.issuerKeyID),
        liveControl: source === "live_authority" ? { baseURL: String(fixture.liveControlBaseURL), bearerToken: controlFailure === "credential" ? "flowersec-browser-refused" : "flowersec-browser-live-test" } : undefined,
      },
      bootstrap: async (nonce: number[]) => {
        child.stdin.write(JSON.stringify({ Nonce: Buffer.from(nonce).toString("base64") }) + "\n");
        const value = (await wait("bootstrap")).value;
        return { response: unpack(value.response), state: unpack(value.state) };
      },
      served: () => wait("served"),
      refused: () => wait("refused"),
      close: async () => {
        expect(await stop(), output).toBe(0);
        expect(failure, output).toBeUndefined();
        const sessions = controlFailure === "" ? 1 : 0;
        expect(events.get("cleanup")?.value, output).toMatchObject({ reservations: 0, authorized: [0, sessions], released: [0, sessions] });
      },
    };
  } catch (error) { await stop(); throw error; }
}
