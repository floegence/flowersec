import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startBrowserModuleSite } from "./browser-module-site.js";
import { startGoWebTransportPeer } from "./go-webtransport-peer.js";
import { startV4WSSPeer } from "./v4-wss-peer.js";
import { createCurrentWTPolicyFixture, currentWSSBrowserFixture } from "./current-browser-credentials.js";
import { installCurrentBrowserClient, currentBrowserSpendCount, closeCurrentBrowserClient } from "./current-browser-client.js";

const publicCAInputs = [process.env.FLOWERSEC_BROWSER_PUBLIC_CA_CERT, process.env.FLOWERSEC_BROWSER_PUBLIC_CA_KEY, process.env.FLOWERSEC_BROWSER_PUBLIC_CA_HOST];
const publicCAConfigured = publicCAInputs.every(value => value !== undefined && value !== "");
if (!publicCAConfigured && publicCAInputs.some(value => value !== undefined && value !== "")) throw new Error("public-CA browser validation requires certificate, key, and host inputs together");
function requirePublicCA(): void { if (!publicCAConfigured) throw new Error("public-CA browser validation requires FLOWERSEC_BROWSER_PUBLIC_CA_CERT, FLOWERSEC_BROWSER_PUBLIC_CA_KEY, and FLOWERSEC_BROWSER_PUBLIC_CA_HOST"); }
async function recordConstructors(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const globals = globalThis as unknown as { WebTransport?: new (...args: unknown[]) => unknown };
    const Native = globals.WebTransport; if (Native === undefined) return;
    window.wtConstructorCalls = [];
    globals.WebTransport = new Proxy(Native, { construct(target, args, newTarget) { window.wtConstructorCalls!.push(args); return Reflect.construct(target, args, newTarget); } });
  });
}
async function constructorCalls(page: Page) {
  return page.evaluate(() => (window.wtConstructorCalls ?? []).map(args => ({ endpoint: args[0], arguments: args.length,
    keys: args[1] === undefined ? [] : Object.keys(args[1] as object), hashes: ((args[1] as { serverCertificateHashes?: unknown[] } | undefined)?.serverCertificateHashes ?? []).length })));
}
async function connect(page: Page, exercise: "connect" | "stream" | "echo_datagram" = "connect") {
  return page.evaluate(async exercise => {
    const owner = window.currentBrowser, fixture = owner.fixture, bytes = (value: readonly number[]) => new Uint8Array(value);
    if (owner.client === undefined) throw new Error("current client configuration unavailable");
    const material = owner.client.verifyPoolMaterial({ ...fixture.policy, authorities: [...fixture.policy.authorities], cryptoProfiles: [...fixture.policy.cryptoProfiles] },
      { artifact: bytes(fixture.input.artifact), activation: bytes(fixture.input.activation), clientCertificate: bytes(fixture.input.clientCertificate), serverCertificate: bytes(fixture.input.serverCertificate), candidateIndex: fixture.input.candidateIndex });
    let session: Awaited<ReturnType<typeof owner.environment.connectMaterial>> | undefined;
    try {
      const signal = AbortSignal.timeout(10000); session = await owner.environment.connectMaterial(material, { signal });
      const surface = { acceptStream: typeof session.acceptStream, openStream: typeof session.openStream, waitTermination: typeof session.waitTermination };
      let echo: number[] | undefined, datagram: string | undefined, submission: string | undefined;
      if (exercise === "stream") {
        const stream = await session.openStream("example/websocket", { signal }), payload = bytes([1, 3, 5, 7]);
        try { await stream.write(payload, { signal }); const reply = await stream.read(4n, { signal }); echo = Array.from(reply.data); }
        finally { await stream.close(); }
      } else if (exercise === "echo_datagram") {
        if (owner.definition === undefined || owner.method === undefined) throw new Error("original echo declaration unavailable");
        const service = await session.bindService(owner.definition, { target: { authority: fixture.policy.authorities[0]!, tenant: fixture.policy.tenant, audience: fixture.policy.audience,
          localSubject: fixture.policy.clientSubject, peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity.map(value => value.toString(16).padStart(2, "0")).join("") }] }, maximumOfferWindowMS: 10000n, signal });
        try { const reply = await service.call(owner.method, bytes([1, 3, 5, 7]), { responseLimitBytes: 1024, signal });
          if (reply.kind !== "value" || reply.encoding !== "typed") throw new Error("current Go echo did not return a typed value");
          try { echo = Array.from(reply.value); } finally { reply.release(); }
        } finally { service.close(); }
        const channel = session.unreliableMessages(), encoder = new TextEncoder();
        submission = await channel.send(encoder.encode("browser-webtransport-datagram-request"), { expiresAtMS: BigInt(Date.now()) + 5000n, signal });
        datagram = new TextDecoder().decode(await channel.receive({ signal }));
      }
      return { connected: true, surface, echo, datagram, submission, error: undefined };
    } catch (error) { return { connected: false, surface: undefined, echo: undefined, datagram: undefined, submission: undefined, error: error instanceof Error ? error.message : String(error) }; }
    finally { await session?.close(); await material.close(); }
  }, exercise);
}
async function closeIfInstalled(page: Page): Promise<void> { if (await page.evaluate(() => window.currentBrowser !== undefined)) await closeCurrentBrowserClient(page); }

test("Chromium runs current WebTransport with a signed pin, reliable echo and datagram", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires the installed Chromium WebTransport tuple"); test.setTimeout(60000);
  const site = await startBrowserModuleSite(), context = await browser.newContext({ ignoreHTTPSErrors: false }), page = await context.newPage();
  let peer: Awaited<ReturnType<typeof startGoWebTransportPeer>> | undefined;
  try {
    peer = await startGoWebTransportPeer(site.origin, { datagram: true }); expect(peer.tlsMode).toBe("pin"); expect(peer.pins).toEqual([peer.certificateHash]);
    await recordConstructors(page); await page.goto(site.origin); await installCurrentBrowserClient(page, peer);
    const result = await connect(page, "echo_datagram"); expect(result.error, peer.diagnostics()).toBeUndefined(); expect(result.connected).toBe(true);
    expect(result.echo).toEqual([1, 3, 5, 7]); expect(result.submission).toBe("accepted"); expect(result.datagram).toBe("browser-webtransport-datagram-response");
    expect(result.surface).toEqual({ acceptStream: "function", openStream: "function", waitTermination: "function" }); expect(await currentBrowserSpendCount(page)).toBe(1);
    expect(await constructorCalls(page)).toEqual([{ endpoint: peer.endpoint, arguments: 2, keys: ["serverCertificateHashes"], hashes: 1 }]);
    await peer.finished(); expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer?.close(); await site.close(); }
});

test("Chromium WebTransport rejects a signed unknown pin before durable spend", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium certificate hashes"); test.setTimeout(60000);
  const site = await startBrowserModuleSite(), context = await browser.newContext({ ignoreHTTPSErrors: false }), page = await context.newPage();
  let peer: Awaited<ReturnType<typeof startGoWebTransportPeer>> | undefined;
  try {
    peer = await startGoWebTransportPeer(site.origin, { wrongPin: true }); expect(peer.tlsMode).toBe("pin"); expect(peer.pins).not.toContain(peer.certificateHash);
    await recordConstructors(page); await page.goto(site.origin); await installCurrentBrowserClient(page, peer); const result = await connect(page);
    expect(result.connected).toBe(false); expect(result.error).toBeTruthy(); expect(await currentBrowserSpendCount(page)).toBe(0);
    expect(await constructorCalls(page)).toEqual([{ endpoint: peer.endpoint, arguments: 2, keys: ["serverCertificateHashes"], hashes: 1 }]);
    expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer?.close(); await site.close(); }
});

test("Chromium WebTransport accepts an actual public-CA deployment", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires the installed Chromium tuple"); requirePublicCA(); test.setTimeout(60000);
  const site = await startBrowserModuleSite(), context = await browser.newContext({ ignoreHTTPSErrors: false }), page = await context.newPage();
  let peer: Awaited<ReturnType<typeof startGoWebTransportPeer>> | undefined;
  try {
    peer = await startGoWebTransportPeer(site.origin, { publicCA: true }); expect(peer.tlsMode).toBe("ca"); expect(peer.pins).toEqual([]);
    await recordConstructors(page); await page.goto(site.origin); await installCurrentBrowserClient(page, peer); const result = await connect(page);
    expect(result.error, peer.diagnostics()).toBeUndefined(); expect(result.connected).toBe(true); expect(await currentBrowserSpendCount(page)).toBe(1);
    expect(await constructorCalls(page)).toEqual([{ endpoint: peer.endpoint, arguments: 1, keys: [], hashes: 0 }]);
    await peer.finished(); expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer?.close(); await site.close(); }
});

test("Chromium WebTransport rejects a wrong pin on a public-CA endpoint without CA fallback", async ({ browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium certificate hashes"); requirePublicCA(); test.setTimeout(60000);
  const site = await startBrowserModuleSite(), context = await browser.newContext({ ignoreHTTPSErrors: false }), page = await context.newPage();
  let peer: Awaited<ReturnType<typeof startGoWebTransportPeer>> | undefined;
  try {
    peer = await startGoWebTransportPeer(site.origin, { publicCA: true, wrongPin: true }); expect(peer.tlsMode).toBe("pin"); expect(peer.pins).not.toContain(peer.certificateHash);
    await recordConstructors(page); await page.goto(site.origin); await installCurrentBrowserClient(page, peer); expect((await connect(page)).connected).toBe(false);
    expect(await currentBrowserSpendCount(page)).toBe(0); expect(await constructorCalls(page)).toEqual([{ endpoint: peer.endpoint, arguments: 2, keys: ["serverCertificateHashes"], hashes: 1 }]);
    expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer?.close(); await site.close(); }
});

test("Chromium WebTransport fails closed when certificate hashes are unsupported", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport"); const site = await startBrowserModuleSite(), fixture = createCurrentWTPolicyFixture(site.origin, "pin");
  try {
    await page.addInitScript(() => { window.wtConstructorCalls = []; Object.defineProperty(globalThis, "WebTransport", { configurable: true, value: class {
      constructor(...args: unknown[]) { window.wtConstructorCalls!.push(args); throw new DOMException("certificate hashes unavailable", "NotSupportedError"); }
    } }); });
    await page.goto(site.origin); await installCurrentBrowserClient(page, fixture); const result = await connect(page);
    expect(result.connected).toBe(false); expect(result.error).toBeTruthy(); expect(await currentBrowserSpendCount(page)).toBe(0);
    expect(await constructorCalls(page)).toEqual([{ endpoint: fixture.endpoint, arguments: 2, keys: ["serverCertificateHashes"], hashes: 1 }]);
    expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await fixture.close(); await site.close(); }
});

test("Chromium WebTransport delegates CA trust without hashes and retains normalized deployment URLs", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium WebTransport"); const site = await startBrowserModuleSite(), fixture = createCurrentWTPolicyFixture(site.origin, "ca");
  try {
    await page.addInitScript(() => {
      window.wtConstructorCalls = [];
      Object.defineProperty(globalThis, "WebTransport", { configurable: true, value: class {
        readonly ready = Promise.reject(new Error("test endpoint intentionally unavailable")); readonly closed: Promise<void>; readonly end: () => void;
        constructor(...args: unknown[]) { window.wtConstructorCalls!.push(args); let end!: () => void; this.closed = new Promise<void>(resolve => { end = resolve; }); this.end = end; }
        close() { this.end(); }
      } });
    });
    await page.goto(site.origin); await installCurrentBrowserClient(page, fixture); const outcome = await connect(page); expect(outcome.connected).toBe(false); expect(await currentBrowserSpendCount(page)).toBe(0);
    const calls = await constructorCalls(page); expect(calls).toEqual([{ endpoint: fixture.endpoint, arguments: 1, keys: [], hashes: 0 }]); expect(new URL(String(calls[0]!.endpoint)).href).toBe(fixture.endpoint);
    expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
    // A second page has a fresh module capture and refuses a noncanonical
    // trusted deployment before entering native construction or durable spend.
    await page.reload(); await expect(installCurrentBrowserClient(page, fixture, fixture.endpoint.replace("localhost", "LOCALHOST"))).rejects.toThrow();
    expect(await constructorCalls(page)).toEqual([]); expect(await currentBrowserSpendCount(page)).toBe(0); expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await closeIfInstalled(page); await fixture.close(); await site.close(); }
});

for (const name of ["Firefox", "WebKit"] as const) test(`${name} reports the current WebTransport pin deployment as unsupported`, async ({ page, browserName }) => {
  expect(browserName).toBe(name === "Firefox" ? "firefox" : "webkit"); const site = await startBrowserModuleSite(), fixture = createCurrentWTPolicyFixture(site.origin, "pin");
  try {
    await page.goto(site.origin); await expect(installCurrentBrowserClient(page, fixture)).rejects.toThrow("configuration_capacity");
    expect(await currentBrowserSpendCount(page)).toBe(0); expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await fixture.close(); await site.close(); }
});

test("Portable browsers run the ordinary WebSocket client contract", async ({ page }) => {
  const artifactParent = resolve(process.env.FLOWERSEC_TASK_ARTIFACT_DIR ?? join(dirname(fileURLToPath(new URL("../..", import.meta.url))), "flowersec-browser-artifacts"));
  const { mkdirSync } = await import("node:fs"); mkdirSync(artifactParent, { recursive: true }); const directory = mkdtempSync(join(artifactParent, "current-portable-wss-"));
  let site: Awaited<ReturnType<typeof startBrowserModuleSite>> | undefined, peer: Awaited<ReturnType<typeof startV4WSSPeer>> | undefined;
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(directory, "key.pem"), "-out", join(directory, "cert.pem"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth"], { stdio: "ignore" });
    site = await startBrowserModuleSite(); peer = await startV4WSSPeer(readFileSync(join(directory, "cert.pem")), readFileSync(join(directory, "key.pem")), site.origin, "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1");
    await page.goto(site.origin); await installCurrentBrowserClient(page, currentWSSBrowserFixture(peer)); const result = await connect(page, "stream");
    expect(result.error).toBeUndefined(); expect(result.connected).toBe(true); expect(result.echo).toEqual([1, 3, 5, 7]); expect(await currentBrowserSpendCount(page)).toBe(1);
    expect(await closeCurrentBrowserClient(page)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await closeIfInstalled(page); await peer?.close(); await site?.close(); rmSync(directory, { recursive: true, force: true }); }
});
