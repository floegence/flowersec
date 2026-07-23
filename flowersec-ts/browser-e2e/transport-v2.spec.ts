import { expect, test } from "@playwright/test";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..");

test("real browser exposes only opaque Transport v2 artifacts and connector entrypoints", async ({ page }) => {
  const fixture = JSON.parse(await readFile(
    path.join(repositoryRoot, "testdata", "transport_v2", "artifact_vectors.json"),
    "utf8",
  )) as { positive: Array<{ artifact_json: string }> };
  const site = await startBrowserModuleSite();
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      const artifact = sdk.parseArtifact(artifactJSON);
      return {
        artifactKeys: Object.keys(artifact),
        artifactJSON: JSON.stringify(artifact),
        frozen: Object.isFrozen(artifact),
        connectorType: typeof sdk.connectBrowserSessionV2,
        capabilityExported: "detectBrowserRuntimeCapabilityV2" in sdk,
      };
    }, fixture.positive[0]!.artifact_json);

    expect(result.artifactKeys).toEqual([]);
    expect(result.artifactJSON).toBe("{}");
    expect(result.frozen).toBe(true);
    expect(result.connectorType).toBe("function");
    expect(result.capabilityExported).toBe(false);
  } finally {
    await site.close();
  }
});

test("real browser runs a complete public SessionV2 over production Go WSS", async ({ page }) => {
  const fixture = JSON.parse(await readFile(
    path.join(repositoryRoot, "testdata", "transport_v2", "artifact_vectors.json"),
    "utf8",
  )) as { positive: Array<{ id: string; artifact_json: string }> };
  const source = JSON.parse(
    fixture.positive.find((entry) => entry.id === "direct-three-carriers")!.artifact_json,
  ) as { path: { candidates: Array<{ id: string; carrier: string; url: string }> } };
  const peer = spawn("go", ["run", "./internal/cmd/ts-session-peer"], {
    cwd: path.join(repositoryRoot, "flowersec-go"),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stderr: string[] = [];
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
  const site = await startBrowserModuleSite();
  try {
    const endpoint = JSON.parse(await firstLine(peer.stdout)) as { url: string };
    const webSocket = source.path.candidates.find((candidate) => candidate.id === "w1")!;
    webSocket.url = endpoint.url;
    source.path.candidates = [webSocket];

    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      const artifact = sdk.parseArtifact(artifactJSON);
      const lease = sdk.createArtifactLeaseV2(artifact, async () => undefined);
      const session = await sdk.connectBrowserSessionV2(lease);
      const liveness = await session.probeLiveness();
      const stream = await session.openStream("interop.echo");
      await stream.write(new TextEncoder().encode("hello-go"));
      const first = new TextDecoder().decode(await stream.read());
      const afterGoRekey = new TextDecoder().decode(await stream.read());
      await session.rekey();
      await stream.write(new TextEncoder().encode("ts-rekey-ok"));
      await stream.closeWrite();
      const done = new TextDecoder().decode(await stream.read());
      const eof = await stream.read();
      await session.close();
      return { liveness, first, afterGoRekey, done, eof };
    }, JSON.stringify(source));

    expect(result.liveness).toBeGreaterThanOrEqual(0);
    expect(result.first).toBe("hello-ts");
    expect(result.afterGoRekey).toBe("go-rekey-ok");
    expect(result.done).toBe("done");
    expect(result.eof).toBeNull();
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } finally {
    await site.close();
    if (peer.exitCode === null) peer.kill("SIGKILL");
  }
});

test("Chromium runs native encrypted DATAGRAM and SessionV2 over production Go WebTransport", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "WebKit has no production WebTransport capability");
  const fixture = JSON.parse(await readFile(
    path.join(repositoryRoot, "testdata", "transport_v2", "artifact_vectors.json"),
    "utf8",
  )) as { positive: Array<{ id: string; artifact_json: string }> };
  const source = JSON.parse(
    fixture.positive.find((entry) => entry.id === "direct-three-carriers")!.artifact_json,
  ) as { path: { candidates: Array<{ id: string; carrier: string; url: string }> } };
  const peer = spawn("go", ["run", "./internal/cmd/browser-webtransport-peer"], {
    cwd: path.join(repositoryRoot, "flowersec-go"),
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stderr: string[] = [];
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
  const site = await startBrowserModuleSite();
  try {
    const endpoint = JSON.parse(await firstLine(peer.stdout)) as { url: string; certificate_hash: string };
    const webTransport = source.path.candidates.find((candidate) => candidate.id === "t1")!;
    webTransport.url = endpoint.url;
    source.path.candidates = [webTransport];

    await page.addInitScript((certificateHash) => {
      const NativeWebTransport = globalThis.WebTransport;
      const hash = Uint8Array.from(atob(certificateHash), (character) => character.charCodeAt(0));
      globalThis.WebTransport = class extends NativeWebTransport {
        constructor(url: string | URL, options?: WebTransportOptions) {
          super(url, {
            ...options,
            serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
          });
        }
      };
    }, endpoint.certificate_hash);
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      const artifact = sdk.parseArtifact(artifactJSON);
      const lease = sdk.createArtifactLeaseV2(artifact, async () => undefined);
      const session = await sdk.connectBrowserSessionV2(lease);
      if (session.unreliableMessages === undefined) throw new Error("WebTransport DATAGRAM was not negotiated");
      const sent = await session.unreliableMessages.send(
        sdk.createUnreliableMessageV2(new TextEncoder().encode("browser-datagram")),
        { expiresAtUnixMs: Date.now() + 5_000 },
      );
      const received = new TextDecoder().decode((await session.unreliableMessages.receive()).data);
      const stream = await session.openStream("interop.echo");
      await stream.write(new TextEncoder().encode("hello-go"));
      const first = new TextDecoder().decode(await stream.read());
      const afterGoRekey = new TextDecoder().decode(await stream.read());
      await session.rekey();
      await stream.write(new TextEncoder().encode("ts-rekey-ok"));
      await stream.closeWrite();
      const done = new TextDecoder().decode(await stream.read());
      const eof = await stream.read();
      await session.close();
      return { sent, received, first, afterGoRekey, done, eof };
    }, JSON.stringify(source)).catch((error: unknown) => {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo WebTransport peer:\n${stderr.join("")}`);
    });

    expect(result.sent).toBe("accepted");
    expect(result.received).toBe("go-datagram");
    expect(result.first).toBe("hello-ts");
    expect(result.afterGoRekey).toBe("go-rekey-ok");
    expect(result.done).toBe("done");
    expect(result.eof).toBeNull();
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } finally {
    await site.close();
    if (peer.exitCode === null) peer.kill("SIGKILL");
  }
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
