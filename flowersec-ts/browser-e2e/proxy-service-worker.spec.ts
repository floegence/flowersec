import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";

import { WebSocketServer, type WebSocket } from "ws";

import { createProxyServiceWorkerScript } from "../src/proxy/serviceWorker.js";
import { startBrowserModuleSite } from "./browser-module-site.js";
import { startV4WSSPeer } from "./v4-wss-peer.js";
import { p256 } from "@noble/curves/nist.js";

const profiles = ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"] as const;
let directory: string, certificate: Buffer, key: Buffer;
test.beforeAll(() => {
  directory = mkdtempSync(path.join(realpathSync(tmpdir()), "flowersec-ts-proxy-browser-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", path.join(directory, "key.pem"), "-out", path.join(directory, "cert.pem"),
    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth"], { stdio: "ignore" });
  certificate = readFileSync(path.join(directory, "cert.pem")); key = readFileSync(path.join(directory, "key.pem"));
});
test.afterAll(() => rmSync(directory, { recursive: true, force: true }));

for (const profile of profiles) test(`Chromium runs the Service Worker proxy product chain with ${profile}`, async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium Service Worker coverage");
  test.setTimeout(60_000);
  const script = createProxyServiceWorkerScript({
    maxRequestBodyBytes: 4,
    passthrough: { paths: ["/", "/proxy-sw.js"], prefixes: ["/dist/", "/node_modules/"] },
    proxyPathPrefix: "/proxy/",
    stripProxyPathPrefix: true,
    injectHTML: {
      mode: "external_module",
      scriptUrl: "/dist/proxy/index.js",
      runtimeGlobal: "__flowersecProxyRuntime",
      excludePathPrefixes: ["/proxy/no-inject"],
    },
  });
  const upstream = await startProxyUpstream();
  const site = await startBrowserModuleSite({ serviceWorkerScript: script });
  const primaryPeer = await startV4WSSPeer(certificate, key, site.origin, profile, false, upstream.origin);
  let recoveryPeer: Awaited<ReturnType<typeof startV4WSSPeer>> | undefined;
  let appPage: Page | undefined;
  let recoveryPage: Page | undefined;
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    await installRuntimePage(page, primaryPeer, site.origin, "flowersec-proxy-browser-primary");
    const direct = await page.evaluate(async () => {
      const holder = globalThis as typeof globalThis & { __flowersecProxyRuntime?: { fetch(path: string): Promise<Response> } };
      let response: Response;
      try { response = await holder.__flowersecProxyRuntime!.fetch("/echo"); }
      catch (error) { return { stage: "fetch", error: String(error) }; }
      try { return { status: response.status, body: await response.text() }; }
      catch (error) { return { stage: "body", status: response.status, error: String(error) }; }
    });
    expect(direct, JSON.stringify(primaryPeer.proxyErrors().map(error => error instanceof Error ? error.stack : String(error)))).toEqual({ status: 200, body: "proxied" });
    appPage = await context.newPage();
    await appPage.goto(site.origin, { waitUntil: "networkidle" });

    for (const encoding of ["gzip", "deflate", "br", "chain"]) {
      const decoded = await appPage.evaluate(async (coding) => {
        const response = await fetch(`/proxy/encoded/${coding}`);
        return { body: await response.text(), encoding: response.headers.get("content-encoding"), etag: response.headers.get("etag") };
      }, encoding);
      expect(decoded).toEqual({ body: "compressed browser payload", encoding: encoding === "chain" ? "gzip, br" : encoding, etag: '"coded-origin"' });
    }

    const firstChunk = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/stream");
      const reader = response.body!.getReader();
      (globalThis as typeof globalThis & { __flowersecStreamReader?: ReadableStreamDefaultReader<Uint8Array> })
        .__flowersecStreamReader = reader;
      const first = await reader.read();
      return new TextDecoder().decode(first.value);
    });
    expect(firstChunk).toBe("alpha-");
    upstream.releaseStream();
    await expect(appPage.evaluate(async () => {
      const holder = globalThis as typeof globalThis & { __flowersecStreamReader?: ReadableStreamDefaultReader<Uint8Array> };
      const reader = holder.__flowersecStreamReader;
      if (reader === undefined) throw new Error("stream reader was not retained");
      let result = "";
      for (;;) {
        const value = await reader.read();
        if (value.done) break;
        result += new TextDecoder().decode(value.value);
      }
      delete holder.__flowersecStreamReader;
      return result;
    })).resolves.toBe("beta");

    await appPage.reload({ waitUntil: "networkidle" });
    await expect(appPage.evaluate(async () => await (await fetch("/proxy/echo")).text()))
      .resolves.toBe("proxied");

    await appPage.evaluate(async () => {
      const response = await fetch("/proxy/abort");
      const reader = response.body!.getReader();
      await reader.read();
      await reader.cancel();
    });
    await Promise.race([
      upstream.canceled,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("upstream cancel was not propagated")), 5_000)),
    ]);

    const oversized = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/upload", { method: "POST", body: "12345" });
      return { status: response.status, body: await response.text() };
    });
    expect(oversized).toEqual({ status: 413, body: "proxy request too large" });
    const failed = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/error");
      return { status: response.status, body: await response.text() };
    });
    expect(failed).toEqual({ status: 502, body: "proxy request failed" });

    const html = await appPage.evaluate(async () => await (await fetch("/proxy/html")).text());
    expect(html).toContain("data-flowersec-runtime-global=\"__flowersecProxyRuntime\"");
    const excluded = await appPage.evaluate(async () => await (await fetch("/proxy/no-inject")).text());
    expect(excluded).not.toContain("data-flowersec-runtime-global");

    await expect(page.evaluate(runWebSocketPatchContract)).resolves.toEqual({
      echoed: "patched-echo",
      restored: true,
    });

    await disposeRuntimePage(page);
    await page.close();
    await primaryPeer.close();
    expect(primaryPeer.failure()).toBeUndefined();
    expect(primaryPeer.proxyActiveCount()).toBe(0);
    const unavailable = await appPage.evaluate(async () => {
      const response = await fetch("/proxy/echo");
      return { status: response.status, body: await response.text() };
    });
    expect(unavailable).toEqual({ status: 503, body: "proxy runtime unavailable" });

    recoveryPeer = await startV4WSSPeer(certificate, key, site.origin, profile, false, upstream.origin);
    recoveryPage = await context.newPage();
    await recoveryPage.goto(site.origin, { waitUntil: "networkidle" });
    await installRuntimePage(recoveryPage, recoveryPeer, site.origin, "flowersec-proxy-browser-recovery");
    await expect(appPage.evaluate(async () => await (await fetch("/proxy/echo")).text()))
      .resolves.toBe("proxied");
    await disposeRuntimePage(recoveryPage);
    await recoveryPeer.close();
    expect(recoveryPeer.failure()).toBeUndefined();
    expect(recoveryPeer.proxyActiveCount()).toBe(0);
  } finally {
    const cleanupPage = recoveryPage ?? appPage;
    if (cleanupPage !== undefined && !cleanupPage.isClosed()) {
      await cleanupPage.evaluate(async () => {
        for (const registration of await navigator.serviceWorker.getRegistrations()) await registration.unregister();
      }).catch(() => undefined);
    }
    await recoveryPage?.close().catch(() => undefined);
    await appPage?.close().catch(() => undefined);
    if (!page.isClosed()) await page.close().catch(() => undefined);
    await recoveryPeer?.close().catch(() => undefined);
    await primaryPeer.close().catch(() => undefined);
    await site.close();
    await upstream.close();
  }
});

test("Chromium runs the authenticated controller window proxy bridge", async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium window bridge coverage");
  test.setTimeout(45_000);
  const upstream = await startProxyUpstream();
  const site = await startBrowserModuleSite();
  const peer = await startV4WSSPeer(certificate, key, site.origin, profiles[0], false, upstream.origin);
  let appPage: Page | undefined;
  try {
    await page.goto(site.origin);
    [appPage] = await Promise.all([
      context.waitForEvent("page"),
      page.evaluate(() => {
        const app = window.open("/", "_blank");
        if (app === null) throw new Error("app window was blocked");
        (window as typeof window & { __flowersecAppWindow?: Window }).__flowersecAppWindow = app;
      }),
    ]);
    await appPage.waitForLoadState();
    await installRuntimePage(page, peer, site.origin, "flowersec-proxy-browser-controller", "controller");

    const result = await appPage.evaluate(async origin => {
      const proxy = await import("/dist/proxy/index.js");
      const app = proxy.registerProxyAppWindow({ controllerOrigin: origin, controllerWindow: window.opener,
        capabilityNonce: "proxy-browser-bridge" });
      const patch = proxy.installWebSocketPatch({ runtime: app.runtime, shouldProxy: () => true });
      try {
        const response = await app.runtime.fetch("/echo");
        const body = await response.text();
        const socket = new globalThis.WebSocket("ws://proxy.invalid/socket", "chat");
        const outcome = await new Promise<{ echoed: string; closeCode: number }>((resolve, reject) => {
          let echoed: string | undefined;
          socket.onerror = () => reject(new Error("window bridge WebSocket failed"));
          socket.onopen = () => socket.send("bridge-echo");
          socket.onmessage = event => { echoed = String(event.data); socket.close(1000, "done"); };
          socket.onclose = event => echoed === undefined
            ? reject(new Error("window bridge WebSocket closed before echo"))
            : resolve({ echoed, closeCode: event.code });
        });
        return { status: response.status, body, ...outcome };
      } finally { patch.uninstall(); app.dispose(); }
    }, site.origin);
    expect(result).toEqual({ status: 200, body: "proxied", echoed: "bridge-echo", closeCode: 1000 });
    expect(peer.proxyActiveCount()).toBe(0);
    expect(peer.failure()).toBeUndefined();

    const [otherPage] = await Promise.all([
      context.waitForEvent("page"),
      page.evaluate(() => {
        if (window.open("/", "_blank") === null) throw new Error("untrusted window was blocked");
      }),
    ]);
    try {
      await otherPage.waitForLoadState();
      const answered = await otherPage.evaluate(async origin => {
        if (window.opener === null) throw new Error("untrusted window has no controller opener");
        const channel = new MessageChannel();
        const reply = new Promise<boolean>(resolve => {
          channel.port1.onmessage = () => resolve(true);
          setTimeout(() => resolve(false), 150);
        });
        window.opener.postMessage({ type: "flowersec-proxy:window_fetch_v2", version: 2,
          capabilityNonce: "proxy-browser-bridge", request: { id: "untrusted", method: "GET", path: "/echo", headers: [] } }, origin, [channel.port2]);
        const result = await reply;
        channel.port1.close();
        return result;
      }, site.origin);
      expect(answered).toBe(false);
      expect(peer.proxyActiveCount()).toBe(0);
    } finally { await otherPage.close(); }

    const authorized = await appPage.evaluate(async origin => {
      const proxy = await import("/dist/proxy/index.js");
      const app = proxy.registerProxyAppWindow({ controllerOrigin: origin, controllerWindow: window.opener,
        capabilityNonce: "proxy-browser-bridge" });
      try {
        const response = await app.runtime.fetch("/echo");
        return { status: response.status, body: await response.text() };
      } finally { app.dispose(); }
    }, site.origin);
    expect(authorized).toEqual({ status: 200, body: "proxied" });
    expect(peer.proxyActiveCount()).toBe(0);

    await disposeRuntimePage(page);
    await peer.close();
    expect(peer.failure()).toBeUndefined();
  } finally {
    await appPage?.close().catch(() => undefined);
    if (!page.isClosed()) await page.close().catch(() => undefined);
    await peer.close().catch(() => undefined);
    await site.close();
    await upstream.close();
  }
});

type Peer = Awaited<ReturnType<typeof startV4WSSPeer>>;
async function installRuntimePage(page: Page, peer: Peer, externalOrigin: string, databaseName: string,
  mode: "service_worker" | "controller" = "service_worker"): Promise<void> {
  await page.exposeFunction("bootstrapProxyV4", peer.bootstrap);
  await page.evaluate(async ({ peer: input, externalOrigin: origin, databaseName: database, p256Public, mode: connectionMode }) => {
    const proxy = await import("/dist/proxy/index.js");
    const sdk = await import("/dist/browser/index.js");
    const noble = await import("/node_modules/@noble/curves/ed25519.js");
    const bytes = (value: number, count = 32) => new Uint8Array(count).fill(value);
    const value = (data: number[]) => new Uint8Array(data);
    const limit = new sdk.V4ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 2000n, 2000n, 2000n, 2000n, 2000n, 2000n]);
    const root = new sdk.V4ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 32, reservations: 256, references: 512,
      rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
    const start = performance.now(), now = BigInt(Date.now());
    const environment = sdk.createV4TransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
      namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 100,
      clock: { profile: { rate: new sdk.V4ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
        tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - start)), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: now, upperMS: now }) },
      random: (destination: Uint8Array) => { const sample = new Uint8Array(destination.byteLength); crypto.getRandomValues(sample); destination.set(sample); } });
    const backing = sdk.createV4IndexedDBPoolBacking(environment, database, { maxRecords: 4, maxRecordBytes: 16384, transactionMS: 10000n,
      runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, storageBytes: 1048576n });
    const store = await sdk.openV4IndexedDBPoolStore(backing, { create: true, identity: { authority: "spend", storeID: bytes(9), generation: 1n },
      continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: bytes(5, 16) }] });
    const prefix = (hex: string) => Uint8Array.from(hex.match(/../g)!, byte => Number.parseInt(byte, 16));
    const combine = (a: Uint8Array, b: Uint8Array) => { const result = new Uint8Array(a.length + b.length); result.set(a); result.set(b, a.length); return result; };
    const b64 = (data: number[]) => btoa(String.fromCharCode(...data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const identityKey = await crypto.subtle.importKey("pkcs8", combine(prefix("302e020100300506032b657004220420"), bytes(14)), "Ed25519", true, ["sign"]);
    const noiseKey = input.profile.includes("x25519")
      ? await crypto.subtle.importKey("pkcs8", combine(prefix("302e020100300506032b656e04220420"), bytes(16)), "X25519", true, ["deriveBits"])
      : await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", d: b64(Array.from(bytes(16))), x: b64(p256Public.slice(1, 33)), y: b64(p256Public.slice(33)) }, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const client = await sdk.configureV4BrowserWSS(environment, { identityKey, noiseKey, poolStore: store,
      carrier: { deployment: { deploymentID: "browser-proxy-test", revision: "one", endpoint: input.endpoint, applicationOrigin: location.origin, routeDigest: value(input.route),
        notBeforeMS: BigInt(input.timeOrigin), notAfterMS: BigInt(input.timeOrigin) + 50000n,
        terminatorProfile: "tls13-no-early-data-http11-exact-origin-no-extensions", evidenceReference: "test:https-server-tls13-and-upgrade-policy" },
        queueMessages: 8, sendBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n },
      limits: { maxFrame: 65536, maxStreams: 8, receiveQueueBytes: 256, maxDataBytes: 128, maxCursorBytes: 1024, maxWriteBytes: 1024,
        writeDeadlineMS: 1000n, operationDeadlineMS: 1000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n, cryptoKeys: 100 } });
    const namespace = client.namespace({ tenant: "tenant", authority: "authority", rootKeyID: bytes(1, 16), rootPublicKey: noble.ed25519.getPublicKey(bytes(7)),
      maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
    const bootstrap = await (window as typeof window & { bootstrapProxyV4(nonce: number[]): Promise<{response: number[]; state: number[]}> }).bootstrapProxyV4(Array.from(namespace.bootstrapNonce()));
    namespace.bootstrap(value(bootstrap.response), value(bootstrap.state));
    const material = { artifact: value(input.input.artifact), clientCertificate: value(input.input.clientCertificate), serverCertificate: value(input.input.serverCertificate),
      activation: value(input.input.activation), candidateIndex: 0 };
    const policy = { tenant: "tenant", audience: "service", clientSubject: "client", serverSubject: "server", cryptoProfiles: [input.profile], authorities: ["authority"] };
    const source = client.registerPoolSource(policy, async (_request, destination) => {
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(material[name]);
      return { artifact: material.artifact.length, clientCertificate: material.clientCertificate.length,
        serverCertificate: material.serverCertificate.length, activation: material.activation.length, candidateIndex: 0 };
    });
    const runtimeOptions = { externalOrigin: origin, maxBodyBytes: 4096, maxChunkBytes: 64, maxJsonFrameBytes: 4096, maxWsFrameBytes: 32 };
    const appWindow = (window as typeof window & { __flowersecAppWindow?: Window }).__flowersecAppWindow;
    if (connectionMode === "controller" && appWindow === undefined) throw new Error("app window is unavailable");
    const handle = connectionMode === "controller"
      ? await proxy.connectProxyControllerBrowser(environment, source, { runtime: runtimeOptions, controller: {
        allowedOrigins: [origin], expectedSource: appWindow ?? null,
        capabilityNonce: "proxy-browser-bridge",
      } })
      : await proxy.connectProxyBrowser(environment, source, { runtime: runtimeOptions,
        serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/", controllerTimeoutMs: 5_000 } });
    const holder = globalThis as typeof globalThis & {
      __flowersecProxyHandle?: typeof handle;
      __flowersecProxyRuntime?: typeof handle.runtime;
      __flowersecProxyOwners?: { environment: typeof environment; store: typeof store; backing: typeof backing; root: typeof root; database: string };
    };
    holder.__flowersecProxyHandle = handle;
    holder.__flowersecProxyRuntime = handle.runtime;
    holder.__flowersecProxyOwners = { environment, store, backing, root, database };
    if (connectionMode === "service_worker") await proxy.ensureServiceWorkerRuntimeRegistered();
  }, { peer: { endpoint: peer.endpoint, timeOrigin: peer.timeOrigin, route: peer.route, profile: peer.profile, input: peer.input },
    externalOrigin, databaseName, mode, p256Public: Array.from(p256.getPublicKey(new Uint8Array(32).fill(16), false)) });
}

async function disposeRuntimePage(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const holder = globalThis as typeof globalThis & {
      __flowersecProxyHandle?: { dispose(): Promise<void> };
      __flowersecProxyRuntime?: unknown;
      __flowersecProxyOwners?: { environment: { close(): Promise<void>; waitCleanup(): Promise<{ status: string }> }; store: { close(): void };
        backing: { releaseRemoved(): Promise<void> }; root: { snapshot(): { reservations: number } }; database: string };
    };
    await holder.__flowersecProxyHandle?.dispose();
    const owners = holder.__flowersecProxyOwners;
    if (owners !== undefined) {
      await owners.environment.close(); owners.store.close();
      await new Promise<void>((resolve, reject) => { const request = indexedDB.deleteDatabase(owners.database);
        request.onsuccess = () => resolve(); request.onerror = () => reject(request.error); });
      await owners.backing.releaseRemoved();
      if ((await owners.environment.waitCleanup()).status !== "complete" || owners.root.snapshot().reservations !== 0) throw new Error("proxy browser resources remain");
    }
    delete holder.__flowersecProxyHandle;
    delete holder.__flowersecProxyRuntime;
    delete holder.__flowersecProxyOwners;
  });
}

async function runWebSocketPatchContract(): Promise<Readonly<{ echoed: string; restored: boolean }>> {
  const proxy = await import("/dist/proxy/index.js");
  const holder = globalThis as typeof globalThis & { __flowersecProxyRuntime?: Parameters<typeof proxy.installWebSocketPatch>[0]["runtime"] };
  if (holder.__flowersecProxyRuntime === undefined) throw new Error("production proxy runtime was not retained");
  const NativeWebSocket = globalThis.WebSocket;
  const patch = proxy.installWebSocketPatch({ runtime: holder.__flowersecProxyRuntime, shouldProxy: () => true });
  let echoed = "";
  try {
    const socket = new globalThis.WebSocket("ws://proxy.invalid/echo", "chat");
    echoed = await new Promise<string>((resolve, reject) => {
      socket.onerror = () => reject(new Error("patched WebSocket failed"));
      socket.onopen = () => socket.send("patched-echo");
      socket.onmessage = (event) => resolve(String(event.data));
    });
    socket.close(1000, "done");
  } finally {
    patch.uninstall();
  }
  return { echoed, restored: globalThis.WebSocket === NativeWebSocket };
}

async function startProxyUpstream(): Promise<Readonly<{
  origin: string;
  canceled: Promise<void>;
  releaseStream(): void;
  close(): Promise<void>;
}>> {
  let releaseStream!: () => void;
  const streamReleased = new Promise<void>((resolve) => { releaseStream = resolve; });
  let markCanceled!: () => void;
  const canceled = new Promise<void>((resolve) => { markCanceled = resolve; });
  const server = createServer(async (request, response) => {
    if (request.url?.startsWith("/encoded/")) {
      const content = Buffer.from("compressed browser payload");
      const coding = request.url.slice("/encoded/".length);
      const body = coding === "gzip" ? gzipSync(content) : coding === "deflate" ? deflateSync(content) : coding === "br" ? brotliCompressSync(content) : brotliCompressSync(gzipSync(content));
      response.writeHead(200, { "content-type": "text/plain", "content-encoding": coding === "chain" ? "gzip, br" : coding, "content-length": body.length, etag: '"coded-origin"' });
      response.end(body);
      return;
    }
    if (request.url === "/stream") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.write("alpha-");
      await streamReleased;
      response.end("beta");
      return;
    }
    if (request.url === "/abort") {
      let settled = false;
      const observeCancel = () => {
        if (settled) return;
        settled = true;
        markCanceled();
      };
      request.once("aborted", observeCancel);
      response.once("close", observeCancel);
      response.writeHead(200, { "content-type": "text/plain" });
      response.write("first");
      return;
    }
    if (request.url === "/error") {
      request.socket.destroy();
      return;
    }
    if (request.url === "/html" || request.url === "/no-inject") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("<!doctype html><html><head><title>proxied</title></head><body>ok</body></html>");
      return;
    }
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("proxied");
  });
  const sockets = new Set<WebSocket>();
  const webSockets = new WebSocketServer({ server, perMessageDeflate: false, maxPayload: 32 });
  webSockets.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("message", (data, isBinary) => socket.send(data, { binary: isBinary }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("proxy upstream did not bind");
  return Object.freeze({
    origin: `http://127.0.0.1:${address.port}`,
    canceled,
    releaseStream,
    close: async () => {
      for (const socket of sockets) socket.terminate();
      await new Promise<void>((resolve) => webSockets.close(() => resolve()));
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  });
}
