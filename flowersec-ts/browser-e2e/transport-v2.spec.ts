import { expect, test, type Page } from "@playwright/test";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..");

test("Chromium runs the WebSocket client profile", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium");
  const encoded = process.env.FLOWERSEC_PARITY_READY_BASE64;
  if (encoded === undefined) return;
  test.setTimeout(60_000);
  const ready = JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as {
    artifact_json: string; trust_pem: string; origin: string; path: "direct" | "tunnel";
  };
  const site = await startBrowserModuleSite(Number(process.env.FLOWERSEC_BROWSER_SITE_PORT));
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      const artifact = sdk.parseArtifact(artifactJSON);
      const session = await sdk.connect(sdk.createArtifactLease(artifact, async () => undefined));
      const echo = await session.rpc.call(7001, { value: "ping" }, (payload) => payload);
      if (!echo.ok || echo.payload.value !== "ping") throw new Error("RPC echo failed");
      await session.rpc.notify(7002, { value: "notify" });
      const stream = await session.openStream("parity.echo", { metadata: sdk.createStreamMetadata({ cell: "direct" }) });
      await stream.write(new TextEncoder().encode("hello"));
      await stream.closeWrite();
      if (new TextDecoder().decode(await stream.read()) !== "world") throw new Error("stream FIN failed");
      const reset = await session.openStream("parity.reset");
      await reset.write(new TextEncoder().encode("reset"));
      await reset.closeWrite();
      let resetObserved = false;
      try { await reset.read(); } catch { resetObserved = true; }
      if (!resetObserved) throw new Error("stream reset failed");
      await session.rekey();
      await session.probeLiveness();
      await session.close();
      return true;
    }, ready.artifact_json);
    expect(result).toBe(true);
  } finally {
    await site.close();
  }
});

test("Chromium runs the direct WebTransport topology", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium");
  test.setTimeout(45_000);
  await runDirectWebTransport(page);
});

for (const opposite of ["wss", "raw_quic"] as const) {
  test(`Chromium WebTransport tunnel bridges to production Go ${opposite}`, async ({ page, browserName }) => {
    test.skip(browserName !== "chromium", "requires Chromium");
    test.setTimeout(45_000);
    await runTunnelWebTransport(page, opposite);
  });
}

test("Firefox reports unsupported native WebTransport connection", async ({ page, browserName }) => {
  test.skip(browserName !== "firefox", "requires Firefox");
  test.setTimeout(45_000);
  await expect(runDirectWebTransport(page)).rejects.toThrow(/dial_failed.*WebTransport connection rejected/);
});

test("WebKit reports unsupported native WebTransport DATAGRAM surface", async ({ page, browserName }) => {
  test.skip(browserName !== "webkit", "requires WebKit");
  test.setTimeout(45_000);
  await expect(runDirectWebTransport(page)).rejects.toThrow(/dial_failed.*outgoing DATAGRAMs/);
});

async function runDirectWebTransport(page: Page): Promise<void> {
  const source = await artifactFor("direct", "t1");
  const peer = startPeer("browser-webtransport-peer", "direct");
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
      const lease = sdk.createArtifactLease(artifact, async () => undefined);
      const session = await sdk.connect(lease).catch(async (error: unknown) => {
        const internal = await import("/dist/utils/errors.js");
        if (!(error instanceof internal.ConnectError)) throw error;
        const details = internal.connectErrorDetailsInternal(error);
        throw new Error(JSON.stringify({
          publicCode: error.code,
          internalCode: details.code,
          stage: details.stage,
          candidates: details.diagnostics,
        }));
      });
      if (session.unreliableMessages === undefined) throw new Error("WebTransport DATAGRAM was not negotiated");
      const sent = await session.unreliableMessages.send(
        new TextEncoder().encode("browser-datagram"),
        { expiresAtUnixMs: Date.now() + 5_000 },
      );
      const received = new TextDecoder().decode(await session.unreliableMessages.receive());
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
    expect(result.liveness).toBeGreaterThanOrEqual(0);
    expect(result.first).toBe("hello-ts");
    expect(result.afterGoRekey).toBe("go-rekey-ok");
    expect(result.done).toBe("done");
    expect(result.eof).toBeNull();
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } finally {
    await site.close();
    await stopPeer(peer);
  }
}

async function runTunnelWebTransport(page: Page, opposite: "wss" | "raw_quic"): Promise<void> {
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
      const lease = sdk.createArtifactLease(artifact, async () => undefined);
      const session = await sdk.connect(lease).catch(async (error: unknown) => {
        const internal = await import("/dist/utils/errors.js");
        if (!(error instanceof internal.ConnectError)) throw error;
        const details = internal.connectErrorDetailsInternal(error);
        throw new Error(JSON.stringify({
          publicCode: error.code,
          internalCode: details.code,
          stage: details.stage,
          candidates: details.diagnostics,
        }));
      });
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
    await stopPeer(peer);
  }
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

function startPeer(name: string, sessionPath: "direct" | "tunnel", ...args: string[]): ReturnType<typeof spawn> {
  return spawn("go", ["run", `./internal/cmd/${name}`, "--path", sessionPath, ...args], {
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

async function stopPeer(peer: ReturnType<typeof spawn>): Promise<void> {
  if (peer.exitCode !== null) return;
  peer.kill("SIGTERM");
  const stopped = await Promise.race([
    processExit(peer).then(() => true),
    new Promise<false>((resolve) => setTimeout(() => resolve(false), 1_000)),
  ]);
  if (stopped || peer.exitCode !== null) return;
  peer.kill("SIGKILL");
  await processExit(peer);
}
