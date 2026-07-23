import { expect, test, type Page } from "@playwright/test";
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

for (const sessionPath of ["direct", "tunnel"] as const) {
  test(`real browser runs a complete public SessionV2 over production Go WSS (${sessionPath})`, async ({ page }) => {
    test.setTimeout(45_000);
    const source = await artifactFor(sessionPath, "w1");
    const peer = startPeer("ts-session-peer", sessionPath);
    const stderr = captureStderr(peer);
    const site = await startBrowserModuleSite();
    try {
      const endpoint = JSON.parse(await firstLine(peer.stdout)) as { url: string };
      source.path.candidates[0]!.url = endpoint.url;
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

  test(`Chromium runs native DATAGRAM and SessionV2 over production Go WebTransport (${sessionPath})`, async ({ page, browserName }) => {
    test.skip(browserName !== "chromium", "WebKit has no production WebTransport capability");
    test.setTimeout(45_000);
    const source = await artifactFor(sessionPath, "t1");
    const peer = startPeer("browser-webtransport-peer", sessionPath);
    const stderr = captureStderr(peer);
    const site = await startBrowserModuleSite();
    try {
      const endpoint = JSON.parse(await firstLine(peer.stdout)) as { url: string; certificate_hash: string };
      source.path.candidates[0]!.url = endpoint.url;
      await installWebTransportCertificateHash(page, endpoint.certificate_hash);
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
        return { sent, received, liveness, first, afterGoRekey, done, eof };
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
}

for (const opposite of ["wss", "raw_quic"] as const) {
  test(`Chromium WebTransport tunnel bridges to production Go ${opposite}`, async ({ page, browserName }) => {
    test.skip(browserName !== "chromium", "WebKit has no production WebTransport capability");
    test.setTimeout(45_000);
    const peer = spawn(
      "go",
      ["run", "./internal/cmd/browser-webtransport-peer", "--opposite", opposite],
      { cwd: path.join(repositoryRoot, "flowersec-go"), stdio: ["ignore", "pipe", "pipe"] },
    );
    const stderr = captureStderr(peer);
    const site = await startBrowserModuleSite();
    try {
      const endpoint = JSON.parse(await firstLine(peer.stdout)) as {
        artifact_json: string;
        certificate_hash: string;
      };
      await installWebTransportCertificateHash(page, endpoint.certificate_hash, opposite === "wss");
      await page.goto(site.origin, { waitUntil: "networkidle" });
      const result = await page.evaluate(async (artifactJSON) => {
        const sdk = await import("/dist/browser/index.js");
        const artifact = sdk.parseArtifact(artifactJSON);
        const lease = sdk.createArtifactLeaseV2(artifact, async () => undefined);
        const session = await sdk.connectBrowserSessionV2(lease);
        const stream = await session.openStream("mixed.echo");
        await stream.write(new TextEncoder().encode("browser-mixed"));
        await stream.closeWrite();
        const response = new TextDecoder().decode(await stream.read());
        const eof = await stream.read();
        await session.close();
        return { response, eof };
      }, endpoint.artifact_json).catch((error: unknown) => {
        throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo mixed peer:\n${stderr.join("")}`);
      });

      expect(result.response).toBe(`go-${opposite.replace("_", "-")}`);
      expect(result.eof).toBeNull();
      expect(await processExit(peer), stderr.join("")).toBe(0);
    } finally {
      await site.close();
      if (peer.exitCode === null) peer.kill("SIGKILL");
    }
  });
}

type MutableArtifact = { path: { candidates: Array<{ id: string; carrier: string; url: string }> } };

async function artifactFor(sessionPath: "direct" | "tunnel", candidateID: "w1" | "t1"): Promise<MutableArtifact> {
  const fixture = JSON.parse(await readFile(
    path.join(repositoryRoot, "testdata", "transport_v2", "artifact_vectors.json"),
    "utf8",
  )) as { positive: Array<{ id: string; artifact_json: string }> };
  const source = JSON.parse(
    fixture.positive.find((entry) => entry.id === `${sessionPath}-three-carriers`)!.artifact_json,
  ) as MutableArtifact;
  source.path.candidates = source.path.candidates.filter((candidate) => candidate.id === candidateID);
  return source;
}

function startPeer(name: string, sessionPath: "direct" | "tunnel"): ReturnType<typeof spawn> {
  return spawn("go", ["run", `./internal/cmd/${name}`, "--path", sessionPath], {
    cwd: path.join(repositoryRoot, "flowersec-go"),
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function captureStderr(peer: ReturnType<typeof spawn>): string[] {
  const stderr: string[] = [];
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
  return stderr;
}

async function installWebTransportCertificateHash(
  page: Page,
  certificateHash: string,
  disableWebSocket = false,
): Promise<void> {
  await page.addInitScript(({ encodedHash, removeWebSocket }) => {
    const NativeWebTransport = globalThis.WebTransport;
    const hash = Uint8Array.from(atob(encodedHash), (character) => character.charCodeAt(0));
    globalThis.WebTransport = class extends NativeWebTransport {
      constructor(url: string | URL, options?: WebTransportOptions) {
        super(url, {
          ...options,
          serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
        });
      }
    };
    if (removeWebSocket) {
      Object.defineProperty(globalThis, "WebSocket", { value: undefined, configurable: true });
    }
  }, { encodedHash: certificateHash, removeWebSocket: disableWebSocket });
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
