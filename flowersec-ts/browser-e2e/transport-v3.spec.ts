import { expect, test, type Page } from "@playwright/test";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startBrowserModuleSite } from "./browser-module-site.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..");
const fixture = JSON.parse(readFileSync(
  path.join(repositoryRoot, "testdata/transport_v3/artifact_vectors.json"),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ id: string; artifact_json: string }>[] }>;
const urlFixture = JSON.parse(readFileSync(
  path.join(repositoryRoot, "testdata/transport_v3/idna_vectors.json"),
  "utf8",
)) as Readonly<{
  url_normalization: Readonly<{
    positive: readonly Readonly<{
      carrier: "raw_quic" | "websocket" | "webtransport";
      path_kind: "direct" | "tunnel";
      input: string;
      normalized: string;
      whatwg_roundtrip: boolean;
    }>[];
  }>;
}>;
const publicCAInputs = [
  process.env.FLOWERSEC_BROWSER_PUBLIC_CA_CERT,
  process.env.FLOWERSEC_BROWSER_PUBLIC_CA_KEY,
  process.env.FLOWERSEC_BROWSER_PUBLIC_CA_HOST,
];
const publicCAConfigured = publicCAInputs.every((value) => value !== undefined && value !== "");
if (!publicCAConfigured && publicCAInputs.some((value) => value !== undefined && value !== "")) {
  throw new Error("public-CA browser validation requires certificate, key, and host inputs together");
}

test("Chromium runs production v3 WebTransport with the artifact TLS pin", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport certificate hashes");
  test.setTimeout(60_000);

  const site = await startBrowserModuleSite();
  const peer = spawn(
    "go",
    [
      "run",
      "./internal/cmd/browser-webtransport-peer",
      "--v3-product-direct",
      "--origin",
      site.origin,
    ],
    { cwd: path.join(repositoryRoot, "flowersec-go"), stdio: ["ignore", "pipe", "pipe"] },
  );
  const stderr = captureStderr(peer);
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    const ready = JSON.parse(await firstLine(peer.stdout)) as {
      artifact_json: string;
      certificate_hash: string;
    };
    const artifact = JSON.parse(ready.artifact_json) as {
      path: { candidates: Array<{ tls: { mode: string; pins?: Array<{ value_b64u: string }> } }> };
    };
    expect(artifact.path.candidates).toHaveLength(1);
    expect(artifact.path.candidates[0]?.tls).toMatchObject({
      mode: "pin",
      pins: [{ value_b64u: ready.certificate_hash }],
    });

    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      let spendCount = 0;
      const artifact = sdk.parseArtifact(artifactJSON);
      const lease = sdk.createArtifactLease(artifact, async () => { spendCount += 1; });
      const session = await sdk.connect(lease);
      const surface = {
        acceptStream: typeof session.acceptStream,
        openStream: typeof session.openStream,
        waitTermination: typeof session.waitTermination,
      };
      await session.close().catch(() => undefined);
      return { spendCount, surface };
    }, ready.artifact_json).catch((error: unknown) => {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo v3 WebTransport peer:\n${stderr.join("")}`);
    });

    expect(result).toEqual({
      spendCount: 1,
      surface: { acceptStream: "function", openStream: "function", waitTermination: "function" },
    });
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } finally {
    await context.close();
    await site.close();
    await stopPeer(peer);
  }
});

test("Chromium WebTransport rejects an unknown v3 pin before durable spend", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport certificate hashes");
  test.setTimeout(60_000);

  const site = await startBrowserModuleSite();
  const peer = spawn(
    "go",
    [
      "run",
      "./internal/cmd/browser-webtransport-peer",
      "--v3-product-direct",
      "--origin",
      site.origin,
    ],
    { cwd: path.join(repositoryRoot, "flowersec-go"), stdio: ["ignore", "pipe", "pipe"] },
  );
  const stderr = captureStderr(peer);
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    const ready = JSON.parse(await firstLine(peer.stdout)) as {
      artifact_json: string;
      certificate_hash: string;
    };
    const artifact = JSON.parse(ready.artifact_json) as {
      path: { candidates: Array<{ tls: { mode: string; pins: Array<{ value_b64u: string }> } }> };
    };
    const unknownPin = Buffer.alloc(32).toString("base64url");
    expect(unknownPin).not.toBe(ready.certificate_hash);
    artifact.path.candidates[0]!.tls.pins[0]!.value_b64u = unknownPin;

    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      let spendCount = 0;
      try {
        const artifact = sdk.parseArtifact(artifactJSON);
        const lease = sdk.createArtifactLease(artifact, async () => { spendCount += 1; });
        const session = await sdk.connect(lease);
        await session.close().catch(() => undefined);
        return { connected: true, spendCount };
      } catch (error) {
        if (!(error instanceof sdk.ConnectError)) throw error;
        return {
          connected: false,
          spendCount,
          error: { code: error.code, disposition: error.disposition.kind },
        };
      }
    }, JSON.stringify(artifact)).catch((error: unknown) => {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo v3 WebTransport peer:\n${stderr.join("")}`);
    });

    expect(result).toEqual({
      connected: false,
      spendCount: 0,
      error: { code: "connection_failed", disposition: "terminal" },
    });
  } finally {
    await context.close();
    await site.close();
    await stopPeer(peer);
  }
});

test("Chromium WebTransport production adapter accepts a public-CA certificate in CA mode", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport");
  requirePublicCAConfiguration();
  test.setTimeout(60_000);

  const site = await startBrowserModuleSite();
  const peer = spawn(
    "go",
    [
      "run",
      "./internal/cmd/browser-webtransport-peer",
      "--v3-product-direct",
      "--v3-public-ca",
      "--origin",
      site.origin,
    ],
    { cwd: path.join(repositoryRoot, "flowersec-go"), stdio: ["ignore", "pipe", "pipe"] },
  );
  const stderr = captureStderr(peer);
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    const ready = JSON.parse(await firstLine(peer.stdout)) as {
      artifact_json: string;
      certificate_hash: string;
    };
    const artifact = JSON.parse(ready.artifact_json) as {
      path: { candidates: Array<{ tls: unknown }> };
    };
    expect(artifact.path.candidates).toHaveLength(1);
    expect(artifact.path.candidates[0]?.tls).toEqual({ mode: "ca" });

    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      let spendCount = 0;
      const session = await sdk.connect(sdk.createArtifactLease(
        sdk.parseArtifact(artifactJSON),
        async () => { spendCount += 1; },
      ));
      await session.close().catch(() => undefined);
      return { spendCount };
    }, ready.artifact_json).catch((error: unknown) => {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo public-CA WebTransport peer:\n${stderr.join("")}`);
    });

    expect(result).toEqual({ spendCount: 1 });
    expect(await processExit(peer), stderr.join("")).toBe(0);
  } finally {
    await context.close();
    await site.close();
    await stopPeer(peer);
  }
});

test("Chromium runs the WebSocket open failure as retryable before durable spend", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium browser WebSocket coverage");
  test.setTimeout(30_000);
  const site = await startBrowserModuleSite();
  try {
    const source = fixture.positive.find(({ id }) => id === "direct-mixed-security");
    if (source === undefined) throw new Error("direct mixed-security artifact fixture is missing");
    const artifact = JSON.parse(source.artifact_json) as {
      path: { candidates: Array<{ carrier: string; tls: unknown; url: string }> };
    };
    const candidate = artifact.path.candidates.find(({ carrier }) => carrier === "websocket");
    if (candidate === undefined) throw new Error("WebSocket v3 candidate is missing");
    candidate.tls = { mode: "ca" };
    candidate.url = "wss://127.0.0.1:1/flowersec/v3/direct";
    artifact.path.candidates = [candidate];
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      let spendCount = 0;
      try {
        const session = await sdk.connect(sdk.createArtifactLease(
          sdk.parseArtifact(artifactJSON),
          async () => { spendCount += 1; },
        ));
        await session.close().catch(() => undefined);
        return { connected: true, spendCount };
      } catch (error) {
        if (!(error instanceof sdk.ConnectError)) throw error;
        return {
          connected: false,
          spendCount,
          error: { code: error.code, disposition: error.disposition.kind },
        };
      }
    }, JSON.stringify(artifact));
    expect(result).toEqual({
      connected: false,
      spendCount: 0,
      error: { code: "connection_failed", disposition: "retryable" },
    });
  } finally {
    await site.close();
  }
});

test("Chromium WebTransport production adapter rejects a wrong pin for a public-CA certificate without CA fallback", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport certificate hashes");
  requirePublicCAConfiguration();
  test.setTimeout(60_000);

  const site = await startBrowserModuleSite();
  const peer = spawn(
    "go",
    [
      "run",
      "./internal/cmd/browser-webtransport-peer",
      "--v3-product-direct",
      "--v3-public-ca",
      "--origin",
      site.origin,
    ],
    { cwd: path.join(repositoryRoot, "flowersec-go"), stdio: ["ignore", "pipe", "pipe"] },
  );
  const stderr = captureStderr(peer);
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    const ready = JSON.parse(await firstLine(peer.stdout)) as {
      artifact_json: string;
      certificate_hash: string;
      certificate_not_after_unix_s: number;
    };
    const artifact = JSON.parse(ready.artifact_json) as {
      path: { candidates: Array<{ tls: unknown }> };
    };
    const unknownPin = Buffer.alloc(32, 0xa5).toString("base64url");
    expect(unknownPin).not.toBe(ready.certificate_hash);
    artifact.path.candidates[0]!.tls = {
      mode: "pin",
      pins: [{
        algorithm: "sha-256",
        not_after_unix_s: ready.certificate_not_after_unix_s,
        value_b64u: unknownPin,
      }],
    };

    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      let spendCount = 0;
      try {
        const session = await sdk.connect(sdk.createArtifactLease(
          sdk.parseArtifact(artifactJSON),
          async () => { spendCount += 1; },
        ));
        await session.close().catch(() => undefined);
        return { connected: true, spendCount };
      } catch (error) {
        if (!(error instanceof sdk.ConnectError)) throw error;
        return {
          connected: false,
          spendCount,
          error: { code: error.code, disposition: error.disposition.kind },
        };
      }
    }, JSON.stringify(artifact)).catch((error: unknown) => {
      throw new Error(`${error instanceof Error ? error.message : String(error)}\nGo public-CA WebTransport peer:\n${stderr.join("")}`);
    });

    expect(result).toEqual({
      connected: false,
      spendCount: 0,
      error: { code: "connection_failed", disposition: "terminal" },
    });
  } finally {
    await context.close();
    await site.close();
    await stopPeer(peer);
  }
});

test("Chromium WebTransport fails closed when certificate hashes are unsupported", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport certificate hashes");
  const site = await startBrowserModuleSite();
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      Object.defineProperty(globalThis, "WebSocket", { configurable: true, value: undefined });
      Object.defineProperty(globalThis, "WebTransport", {
        configurable: true,
        value: class {
          constructor() {
            throw new DOMException("certificate hashes unavailable", "NotSupportedError");
          }
        },
      });
      const sdk = await import("/dist/browser/index.js");
      let spendCount = 0;
      try {
        await sdk.connect(sdk.createArtifactLease(
          sdk.parseArtifact(artifactJSON),
          async () => { spendCount += 1; },
        ));
        return { connected: true, spendCount };
      } catch (error) {
        if (!(error instanceof sdk.ConnectError)) throw error;
        return {
          connected: false,
          spendCount,
          error: { code: error.code, disposition: error.disposition.kind },
        };
      }
    }, singleWebTransportArtifact("pin"));

    expect(result).toEqual({
      connected: false,
      spendCount: 0,
      error: { code: "transport_security_unsupported", disposition: "terminal" },
    });
  } finally {
    await site.close();
  }
});

test("Chromium WebTransport delegates CA trust without certificate hashes", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport");
  const site = await startBrowserModuleSite();
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const normalizedURLs = urlFixture.url_normalization.positive
      .filter(({ whatwg_roundtrip }) => whatwg_roundtrip)
      .map(({ normalized }) => normalized);
    const result = await page.evaluate(async ({ artifactJSON, normalizedURLs }) => {
      const calls: unknown[][] = [];
      Object.defineProperty(globalThis, "WebSocket", { configurable: true, value: undefined });
      Object.defineProperty(globalThis, "WebTransport", {
        configurable: true,
        value: class {
          readonly ready = Promise.reject(new Error("test endpoint intentionally unavailable"));
          constructor(...args: unknown[]) { calls.push(args); }
          close() {}
        },
      });
      const sdk = await import("/dist/browser/index.js");
      let spendCount = 0;
      let code = "";
      try {
        await sdk.connect(sdk.createArtifactLease(
          sdk.parseArtifact(artifactJSON),
          async () => { spendCount += 1; },
        ));
      } catch (error) {
        if (!(error instanceof sdk.ConnectError)) throw error;
        code = `${error.code}:${error.disposition.kind}`;
      }
      const constructorURL = calls[0]?.[0];
      return {
        argumentCount: calls[0]?.length,
        code,
        constructorURL,
        roundtrips: normalizedURLs.map((value) => new URL(value).href),
        roundtripURL: typeof constructorURL === "string" ? new URL(constructorURL).href : undefined,
        spendCount,
      };
    }, { artifactJSON: sharedBrowserURLArtifact(), normalizedURLs });

    const vector = sharedBrowserURLVector();
    expect(vector.whatwg_roundtrip).toBe(true);
    expect(result).toEqual({
      argumentCount: 1,
      code: "connection_failed:retryable",
      constructorURL: vector.normalized,
      roundtrips: normalizedURLs,
      roundtripURL: vector.normalized,
      spendCount: 0,
    });
  } finally {
    await site.close();
  }
});

test("Firefox reports explicit v3 WebTransport pin capability as unsupported", async ({ page, browserName }) => {
  expect(browserName).toBe("firefox");
  await verifyProductionWebTransportUnsupported(page);
});

test("WebKit reports explicit v3 WebTransport pin capability as unsupported", async ({ page, browserName }) => {
  expect(browserName).toBe("webkit");
  await verifyProductionWebTransportUnsupported(page);
});

async function verifyProductionWebTransportUnsupported(page: Page): Promise<void> {
  const site = await startBrowserModuleSite();
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async (artifactJSON) => {
      const sdk = await import("/dist/browser/index.js");
      const runtime = await import("/dist/v3/browserRuntime.js");
      const capability = (await runtime.BrowserRuntimeCapabilityRegistryV3.create()).snapshot();
      const publicCodes = [
        "artifact_invalid",
        "expired_artifact",
        "transport_security_unsupported",
        "transport_security_failed",
        "connection_failed",
      ];
      let spendCount = 0;
      try {
        const session = await sdk.connect(sdk.createArtifactLease(
          sdk.parseArtifact(artifactJSON),
          async () => { spendCount += 1; },
        ));
        await session.close().catch(() => undefined);
        return { connected: true, spendCount };
      } catch (error) {
        if (!(error instanceof sdk.ConnectError)) throw error;
        return {
          connected: false,
          spendCount,
          capability: {
            webTransportSecurityModes: capability.tuples
              .filter(({ carrier }) => carrier === "webtransport")
              .map(({ securityModes }) => securityModes),
            unsupported: capability.unsupported,
          },
          error: {
            code: error.code,
            disposition: error.disposition.kind,
            belongsToFixedPublicSet: publicCodes.includes(error.code),
          },
        };
      }
    }, singleWebTransportArtifact("pin"));

    expect(result).toEqual({
      connected: false,
      spendCount: 0,
      capability: {
        webTransportSecurityModes: [["ca"], ["ca"], ["ca"]],
        unsupported: [{ carrier: "raw_quic", reason: "browser_no_raw_udp" }],
      },
      error: {
        code: "transport_security_unsupported",
        disposition: "terminal",
        belongsToFixedPublicSet: true,
      },
    });
  } finally {
    await site.close();
  }
}

function captureStderr(peer: ReturnType<typeof spawn>): string[] {
  const stderr: string[] = [];
  peer.stderr.setEncoding("utf8");
  peer.stderr.on("data", (chunk: string) => stderr.push(chunk));
  return stderr;
}

function requirePublicCAConfiguration(): void {
  if (!publicCAConfigured) {
    throw new Error(
      "public-CA browser validation requires FLOWERSEC_BROWSER_PUBLIC_CA_CERT, " +
      "FLOWERSEC_BROWSER_PUBLIC_CA_KEY, and FLOWERSEC_BROWSER_PUBLIC_CA_HOST",
    );
  }
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
    const end = () => { cleanup(); reject(new Error("Go v3 peer exited before publishing its artifact")); };
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

function singleWebTransportArtifact(mode: "ca" | "pin"): string {
  const source = fixture.positive.find(({ id }) => id === "direct-mixed-security");
  if (source === undefined) throw new Error("direct v3 artifact fixture is missing");
  const artifact = JSON.parse(source.artifact_json) as {
    path: { candidates: Array<{ carrier: string; tls: unknown }> };
  };
  const candidate = artifact.path.candidates.find(({ carrier }) => carrier === "webtransport");
  if (candidate === undefined) throw new Error("WebTransport v3 candidate is missing");
  if (mode === "ca") candidate.tls = { mode: "ca" };
  artifact.path.candidates = [candidate];
  return JSON.stringify(artifact);
}

function sharedBrowserURLVector() {
  const vector = urlFixture.url_normalization.positive.find(({ carrier }) => carrier === "webtransport");
  if (vector === undefined) throw new Error("shared WebTransport URL normalization vector is missing");
  return vector;
}

function sharedBrowserURLArtifact(): string {
  const vector = sharedBrowserURLVector();
  const source = fixture.positive.find(({ artifact_json }) =>
    (JSON.parse(artifact_json) as { path: { kind: string } }).path.kind === vector.path_kind);
  if (source === undefined) throw new Error(`shared ${vector.path_kind} artifact vector is missing`);
  const artifact = JSON.parse(source.artifact_json) as {
    path: { candidates: Array<{ carrier: string; tls: unknown; url: string }> };
  };
  const candidate = artifact.path.candidates.find(({ carrier }) => carrier === "webtransport");
  if (candidate === undefined) throw new Error("shared WebTransport artifact candidate is missing");
  candidate.tls = { mode: "ca" };
  candidate.url = vector.input;
  artifact.path.candidates = [candidate];
  return JSON.stringify(artifact);
}
