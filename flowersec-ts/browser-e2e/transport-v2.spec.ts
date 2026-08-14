import { expect, test, type Page } from "@playwright/test";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..");

test("Portable browsers run the self-contained WebSocket client contract", async ({ page, browserName }) => {
  test.setTimeout(60_000);
  const site = await startBrowserModuleSite();
  const peer = spawn(
    "go",
    ["run", "./internal/cmd/server-parity-peer", "server", "--carrier", "websocket"],
    {
      cwd: path.join(repositoryRoot, "flowersec-go"),
      env: {
        ...process.env,
        FLOWERSEC_SERVER_PARITY_PEER: "1",
        FLOWERSEC_PARITY_CLIENT_PROFILE: "browser",
        FLOWERSEC_PARITY_ORIGIN: site.origin,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const stderr = captureStderr(peer);
  try {
    const ready = JSON.parse(await firstLine(peer.stdout)) as { artifact_json: string };
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async ({ artifactJSON, browser }) => {
      const sdk = await import("/dist/browser/index.js");
      const artifact = sdk.parseArtifact(artifactJSON);
      const proxy = await import("/dist/proxy/index.js");
      const handle = await proxy.connectProxyBrowser(sdk.createArtifactLease(artifact, async () => undefined));
      const session = handle.session;
      const echo = await session.rpc.call(7001, { value: "ping" }, (payload) => payload);
      if (!echo.ok || echo.payload.value !== "ping") throw new Error("RPC echo failed");
      await session.rpc.notify(7002, { value: "notify" });
      const stream = await session.openStream("parity.echo", {
        metadata: sdk.createStreamMetadata({ cell: "direct", browser }),
      });
      await stream.write(new TextEncoder().encode("hello"));
      await stream.closeWrite();
      const response = new TextDecoder().decode(await stream.read());
      const eof = await stream.read();
      const reset = await session.openStream("parity.reset");
      await reset.write(new TextEncoder().encode("reset"));
      await reset.closeWrite();
      let resetObserved = false;
      try { await reset.read(); } catch { resetObserved = true; }
      await session.rekey();
      const liveness = await session.probeLiveness();
      await handle.dispose();
      return { response, eof, resetObserved, liveness };
    }, { artifactJSON: ready.artifact_json, browser: browserName }).catch((error: unknown) => {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo WSS peer:\n${stderr.join("")}`);
    });
    expect(result).toMatchObject({ response: "world", eof: null, resetObserved: true });
    expect(result.liveness).toBeGreaterThanOrEqual(0);
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } finally {
    await site.close();
    await stopPeer(peer);
  }
});

test("Chromium runs the direct WebTransport topology", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium");
  test.setTimeout(45_000);
  await runDirectWebTransport(page);
});

test("Chromium WebTransport closes bounded concurrent streams after peer termination", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport coverage");
  test.setTimeout(45_000);
  const source = await artifactFor("direct", "t1");
  const peer = startPeer("browser-webtransport-peer", "direct", "--drop-transport-after-streams", "3");
  const stderr = captureStderr(peer);
  const site = await startBrowserModuleSite();
  try {
    const endpoint = JSON.parse(await firstLine(peer.stdout)) as { url: string; certificate_hash: string };
    source.path.candidates[0]!.url = endpoint.url;
    await installWebTransportCertificateHash(page, endpoint.certificate_hash);
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      const session = await sdk.connect(sdk.createArtifactLease(sdk.parseArtifact(artifactJSON), async () => undefined));
      const streams = await Promise.all([
        session.openStream("bounded-1"),
        session.openStream("bounded-2"),
        session.openStream("bounded-3"),
      ]);
      const pendingReads = streams.map(async (stream) => {
        try {
          await stream.read();
          throw new Error("pending stream read completed without transport failure");
        } catch (error) {
          if (!(error instanceof sdk.SessionError)) throw error;
          return error.code;
        }
      });
      await Promise.all(streams.map(async (stream) => {
        const written = await stream.write(Uint8Array.of(1));
        if (written !== 1) throw new Error("stream drop barrier was not written exactly once");
      }));
      const [streamErrors, termination] = await Promise.all([
        Promise.all(pendingReads),
        session.waitTermination(),
      ]);
      return { streamErrors, terminationCode: termination.error.code };
    }, JSON.stringify(source));
    expect(result.streamErrors).toHaveLength(3);
    expect(result.streamErrors).toEqual([
      result.terminationCode,
      result.terminationCode,
      result.terminationCode,
    ]);
    expect(["closed", "operation_failed"]).toContain(result.terminationCode);
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo WebTransport peer:\n${stderr.join("")}`);
  } finally {
    await site.close();
    await stopPeer(peer);
  }
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
  await expect(runDirectWebTransport(page)).rejects.toThrow(/publicCode.*connection_failed.*internalCode.*dial_failed/);
});

test("WebKit reports unsupported native WebTransport DATAGRAM surface", async ({ page, browserName }) => {
  test.skip(browserName !== "webkit", "requires WebKit");
  test.setTimeout(45_000);
  await expect(runDirectWebTransport(page)).rejects.toThrow(/publicCode.*connection_failed.*internalCode.*dial_failed/);
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
        if (!(error instanceof sdk.ConnectError)) throw error;
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
        if (!(error instanceof sdk.ConnectError)) throw error;
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
