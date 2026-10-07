import { test, expect, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { startBrowserModuleSite } from "./browser-module-site.js";
import { startV4WSSPeer } from "./v4-wss-peer.js";
import { buildGoWSSPeer, startGoWSSPeer } from "./go-wss-peer.js";
import { startGoPublicWSSPeer } from "./go-public-wss-peer.js";
import type * as BrowserSDK from "../src/browser/index.js";

const profiles = ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"] as const;
let directory: string, certificate: Buffer, key: Buffer;
test.beforeAll(() => {
  directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-browser-v4-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(directory, "key.pem"), "-out", join(directory, "cert.pem"),
    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth"], { stdio: "ignore" });
  certificate = readFileSync(join(directory, "cert.pem")); key = readFileSync(join(directory, "key.pem"));
});
test.afterAll(() => rmSync(directory, { recursive: true, force: true }));

type Peer = Awaited<ReturnType<typeof startV4WSSPeer>>;
type PublicPeer = Awaited<ReturnType<typeof startGoPublicWSSPeer>>;
type PeerMaterial = Pick<Peer, "endpoint" | "timeOrigin" | "route" | "profile" | "input" | "bootstrap"> |
  Pick<PublicPeer, "endpoint" | "timeOrigin" | "route" | "profile" | "input" | "bootstrap" | "public">;
type BrowserClient = Awaited<ReturnType<typeof BrowserSDK.configureBrowserWSS>>;
declare global {
  interface Window {
    bootstrapV4: (...args: Parameters<Peer["bootstrap"]>) => Promise<Awaited<ReturnType<Peer["bootstrap"]>>>;
    v4: {
      sdk: typeof BrowserSDK;
      environment: ReturnType<typeof BrowserSDK.createTransportEnvironment>;
      backing: ReturnType<typeof BrowserSDK.createIndexedDBPoolBacking> | undefined;
      store: Awaited<ReturnType<typeof BrowserSDK.openIndexedDBPoolStore>> | undefined;
      root: InstanceType<typeof BrowserSDK.ResourceRoot>;
      client: BrowserClient;
      materialInput: Parameters<BrowserClient["verifyPoolMaterial"]>[1];
      policy: Parameters<BrowserClient["verifyPoolMaterial"]>[0];
      refuseContinuity(): void;
      cleanupMaterial(): void;
    };
  }
}
// Tenant, Environment, Session send, and the admitted 8+8+1 direction pool.
const browserAccountSlots = 2 + 1 + 8 + 8 + 1;
async function install(page: Page, peer: PeerMaterial, create: boolean, accounts = browserAccountSlots) {
  await page.exposeFunction("bootstrapV4", peer.bootstrap);
  return page.evaluate(async input => {
    const sdk = await import("/dist/browser/index.js"), runtime = await import("/dist/v4/runtime/environment.js"), noble = await import("/node_modules/@noble/curves/ed25519.js");
    const bytes = (n: number, count = 32) => new Uint8Array(count).fill(n), value = (data: number[]) => new Uint8Array(data);
    const limit = new sdk.ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 2000n, 2000n, 2000n, 2000n, 2000n, 2000n]);
    // Tenant/Environment accounts and the original protected Stream send
    // accounts coexist before consume; the scalar byte budget cannot replace them.
    const root = new sdk.ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: input.accounts, reservations: 256, references: 512, rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
    // Go's signed authority fixture uses a short logical-time window. A scaled
    // test clock keeps it valid through real I/O; this is not a latency or
    // real-world freshness qualification. The TLS listener uses current time.
    const start = performance.now(), now = input.public === undefined ? BigInt(Date.now()) : 1200n, environment = sdk.createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
      namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 100,
      clock: { profile: { rate: new sdk.ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
        tick: () => ({ milliseconds: BigInt(Math.floor((performance.now() - start) / (input.public === undefined ? 1 : 100))), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: now, upperMS: input.public === undefined ? now : 1250n }) }, random: (destination: Uint8Array) => {
        if (!(destination.buffer instanceof ArrayBuffer)) throw new Error("random destination must own an ArrayBuffer");
        crypto.getRandomValues(new Uint8Array(destination.buffer, destination.byteOffset, destination.byteLength));
      } });
    const liveControl = input.public?.liveControl;
    const backing = liveControl === undefined ? sdk.createIndexedDBPoolBacking(environment, "flowersec-browser-v4-once", { maxRecords: 4, maxRecordBytes: 16384, transactionMS: 10000n, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, storageBytes: 1048576n }) : undefined;
    // Test host trust boundary only. Real deployments provide an independent
    // continuity authority; this fixture does not qualify rollback resistance.
    let continuity = true;
    const store = backing === undefined ? undefined : await sdk.openIndexedDBPoolStore(backing, { create: input.create, identity: { authority: input.public?.onceAuthority ?? "spend", storeID: bytes(9), generation: 1n },
      continuity: { check: () => { if (!continuity) throw new Error("history_unknown"); } }, bindings: [{ tenant: input.public?.tenant ?? "tenant", issuer: input.public === undefined ? bytes(5, 16) : value(input.public.issuerKeyID) }] });
    const prefix = (hex: string) => Uint8Array.from(hex.match(/../g)!, v => Number.parseInt(v, 16)), combine = (a: Uint8Array, b: Uint8Array) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; };
    const identitySeed = input.public === undefined ? bytes(14) : value(input.public.identitySeed);
    const dhSeed = input.public === undefined ? bytes(16) : value(input.public.dhSeed);
    const identityKey = await crypto.subtle.importKey("pkcs8", combine(prefix("302e020100300506032b657004220420"), identitySeed), "Ed25519", true, ["sign"]);
    const b64 = (data: number[]) => btoa(String.fromCharCode(...data)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const noiseKey = input.profile.includes("x25519") ? await crypto.subtle.importKey("pkcs8", combine(prefix("302e020100300506032b656e04220420"), dhSeed), "X25519", true, ["deriveBits"]) :
      await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", d: b64(Array.from(dhSeed)), x: b64(input.p256.slice(1, 33)), y: b64(input.p256.slice(33)) }, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const liveAuthority = liveControl === undefined ? undefined : sdk.createBrowserLiveHTTPS(environment, {
      deployment: { deploymentID: "browser-test-control", revision: "one", baseURL: liveControl.baseURL, applicationOrigin: location.origin,
        notBeforeMS: 1000n, notAfterMS: 4000n, terminatorProfile: "tls13-no-early-data-authenticated-control", evidenceReference: "test:go-tls13-bearer-origin-and-framing" },
      authority: input.public!.onceAuthority, tenant: input.public!.tenant, audience: input.public!.audience,
      bearerToken: liveControl.bearerToken, credentialNotAfterMS: 4000n, maxConcurrentRequests: 1,
      timeoutMS: 1000n, headerBytes: 8192, runtimeBytes: 1024n, providerBytes: 1048576n,
    });
    const client = await sdk.configureBrowserWSS(environment, { identityKey, noiseKey,
      ...(liveAuthority === undefined ? { poolStore: store! } : { liveAuthority }),
      carrier: { deployment: { deploymentID: "browser-test-terminator", revision: "one", endpoint: input.endpoint, applicationOrigin: location.origin, routeDigest: value(input.route),
        notBeforeMS: BigInt(input.timeOrigin), notAfterMS: BigInt(input.timeOrigin) + 50000n, terminatorProfile: "tls13-no-early-data-http11-exact-origin-no-extensions", evidenceReference: "test:https-server-tls13-and-upgrade-policy" },
        queueMessages: 8, sendBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n },
      limits: { maxFrame: 65536, maxStreams: 8, receiveQueueBytes: 256, maxDataBytes: 128, maxCursorBytes: 1024, maxWriteBytes: 1024, writeDeadlineMS: 1000n, operationDeadlineMS: 1000n,
        rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n, cryptoKeys: 100 } });
    const namespace = client.namespace({ tenant: input.public?.tenant ?? "tenant", authority: input.public?.authority ?? "authority", rootKeyID: input.public === undefined ? bytes(1, 16) : value(input.public.rootKeyID),
      rootPublicKey: input.public === undefined ? noble.ed25519.getPublicKey(bytes(7)) : value(input.public.rootPublicKey), maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
    await namespace.fetchBootstrap(async (request, response, state) => {
      const bootstrap = await window.bootstrapV4(Array.from(request.nonce));
      const signed = value(bootstrap.response), content = value(bootstrap.state);
      try { response.set(signed); state.set(content); return { responseBytes: signed.length, stateBytes: content.length }; }
      finally { signed.fill(0); content.fill(0); }
    });
    const materialInput = { artifact: value(input.input.artifact), clientCertificate: value(input.input.clientCertificate), serverCertificate: value(input.input.serverCertificate), activation: value(input.input.activation), candidateIndex: 0 };
    const policy = { tenant: input.public?.tenant ?? "tenant", audience: input.public?.audience ?? "service", clientSubject: input.public?.clientSubject ?? "client", serverSubject: input.public?.serverSubject ?? "server",
      cryptoProfiles: [input.profile], authorities: [input.public?.authority ?? "authority"] };
    window.v4 = { sdk, environment, backing, store, root, client, materialInput, policy,
      refuseContinuity: () => { continuity = false; }, cleanupMaterial: () => runtime.originalEnvironment(environment).cleanupStatus() };
    return true;
  }, { endpoint: peer.endpoint, timeOrigin: peer.timeOrigin, route: peer.route, profile: peer.profile, input: peer.input, create, accounts,
    public: "public" in peer ? peer.public : undefined,
    p256: Array.from(p256.getPublicKey(new Uint8Array("public" in peer ? peer.public.dhSeed : new Array(32).fill(16)), false)) });
}
async function close(page: Page, remove: boolean) {
  return page.evaluate(async remove => {
    const { environment, backing, store, root } = window.v4; await environment.close(); store?.close();
    if (remove && backing !== undefined) { await new Promise<void>((resolve, reject) => { const r = indexedDB.deleteDatabase("flowersec-browser-v4-once"); r.onsuccess = () => resolve(); r.onerror = () => reject(r.error); }); await backing.releaseRemoved(); }
    return { cleanup: (await environment.waitCleanup()).status, reservations: root.snapshot().reservations };
  }, remove);
}

async function connectionRefusal(page: Page, loseContinuity = false) {
  return page.evaluate(async loseContinuity => {
    const v = window.v4;
    if (loseContinuity) v.refuseContinuity();
    try { await v.environment.connectMaterial(v.client.verifyPoolMaterial(v.policy, v.materialInput)); }
    catch (error) {
      if (!(error instanceof v.sdk.ConnectionError)) throw error;
      return { code: error.code, connection: error.connection, cleanup: error.cleanup };
    }
    throw new Error("refused material unexpectedly connected");
  }, loseContinuity);
}
function expectUnspentRefusal(refusal: Awaited<ReturnType<typeof connectionRefusal>>, code = "controller_failed") {
  // Connect exposes a closed public projection; store and credential errors
  // remain internal. Assert original spend/admission facts and physical cleanup.
  expect(refusal.code).toBe(code);
  expect(refusal.connection).toMatchObject({ spendState: "unspent", admissionState: "not_started",
    networkReady: "not_started", applicationPublish: "not_started", queryAvailability: "unavailable" });
  expect(refusal.cleanup).toEqual({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
}
async function spendCount(page: Page): Promise<number> {
  return page.evaluate(() => new Promise<number>((resolve, reject) => {
    const open = indexedDB.open("flowersec-browser-v4-once");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const database = open.result, transaction = database.transaction("spend", "readonly");
      const count = transaction.objectStore("spend").count();
      transaction.oncomplete = () => { database.close(); resolve(count.result); };
      transaction.onabort = () => { database.close(); reject(transaction.error); };
    };
  }));
}

for (const profile of profiles) test(`Chromium runs v4 WSS and strict IndexedDB consume with ${profile}`, async ({ browser }) => {
  const site = await startBrowserModuleSite(), peer = await startV4WSSPeer(certificate, key, site.origin, profile);
  // Functional WSS/IDB test only. Self-signed test trust is enabled explicitly;
  // public-CA browser acceptance remains a separate deployment qualification.
  const context = await browser.newContext({ ignoreHTTPSErrors: true }), first = await context.newPage();
  try {
    await first.goto(site.origin); await install(first, peer, true);
    const result = await first.evaluate(async () => {
      const v = window.v4, session = await v.environment.connectMaterial(v.client.verifyPoolMaterial(v.policy, v.materialInput));
      const stream = await session.openStream("example/browser-v4"), payload = new Uint8Array([1, 3, 5, 7]); await stream.write(payload);
      const echoed = await stream.read(4n); await session.rekey(); const liveness = await session.probeLiveness(), info = session.info(); await session.close(); v.cleanupMaterial();
      return { echoed: Array.from(echoed.data), guarantee: info.guarantees.local_consumer_tls13_verification, liveness };
    });
    expect(result.echoed).toEqual([1, 3, 5, 7]); expect(result.guarantee).toBe("controlled_terminator");
    expect(result.liveness.submitted).toBe(true); expect(result.liveness.elapsedMS).toBeGreaterThanOrEqual(0n);
    expect((await close(first, false)).cleanup).toBe("complete"); await first.close();
    const second = await context.newPage(); await second.goto(site.origin); await install(second, peer, false);
    const refusal = await connectionRefusal(second);
    expectUnspentRefusal(refusal); expect(await spendCount(second)).toBe(1); expect(peer.counts().hellos).toBe(1); expect(peer.failure()).toBeUndefined();
    expect(await close(second, true)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer.close(); await site.close(); }
});

test.describe("Go and browser current-core interoperability", () => {
  let go: ReturnType<typeof buildGoWSSPeer>;
  test.beforeAll(() => { go = buildGoWSSPeer(); });
  test.afterAll(() => go?.close());
  for (const profile of profiles) test(`Chromium runs Go WSS authentication, streams and rekey with ${profile}`, async ({ browser }) => {
    const site = await startBrowserModuleSite();
    const peer = await startGoWSSPeer(go.binary, certificate, key, site.origin, profile);
    const context = await browser.newContext({ ignoreHTTPSErrors: true }), page = await context.newPage();
    const errors: unknown[] = [];
    try {
      await page.goto(site.origin); await install(page, peer, true);
      const result = await page.evaluate(async () => {
        const v = window.v4;
        const activation = v.materialInput.activation;
        if (activation === undefined) throw new Error("pool fixture requires its signed activation");
        const input = { ...v.materialInput, activation };
        const source = v.client.registerPoolSource(v.policy, async (_request, buffers) => {
          for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) buffers[name].set(input[name]);
          return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length,
            serverCertificate: input.serverCertificate.length, activation: input.activation.length, candidateIndex: 0 };
        });
        const session = await v.environment.connect(source);
        const echoes: number[][] = [];
        for (let round = 0; round < 2; round++) {
          const stream = await session.openStream("example/browser-go");
          const payload = new Uint8Array([round, 3, 5, 7]);
          const written = await stream.write(payload);
          if (written.accepted_bytes !== BigInt(payload.length) || written.terminal_reason !== "complete") throw new Error("incomplete write");
          await stream.closeWrite();
          const output: number[] = [];
          for (;;) {
            const read = await stream.read(64n);
            output.push(...read.data);
            if (read.stream_status === "eof") break;
            if (read.wait_status !== "ready" || read.stream_status !== "open") throw new Error("incomplete read");
          }
          const finished = await stream.finish();
          if (!finished.send_drained || finished.read_terminal !== "eof") throw new Error("stream did not finish normally");
          echoes.push(output);
          if (round === 0) await session.rekey();
        }
        const liveness = await session.probeLiveness(), info = session.info();
        await session.close(); v.cleanupMaterial();
        return { echoes, liveness, info };
      });
      expect(result.echoes).toEqual([[0, 3, 5, 7], [1, 3, 5, 7]]);
      // An authenticated PONG can win the browser provider's completion
      // callback. `complete` describes that local send tail, not peer liveness.
      expect(result.liveness.submitted).toBe(true);
      expect(result.liveness.elapsedMS).toBeGreaterThanOrEqual(0n);
      expect(result.info.guarantees.local_consumer_tls13_verification).toBe("controlled_terminator");
      expect((await peer.served()).streams).toBe(2);
      expect(await close(page, true)).toEqual({ cleanup: "complete", reservations: 0 });
    } catch (error) { errors.push(error); }
    finally {
      const cleanup = await Promise.allSettled([context.close(), peer.close(), site.close()]);
      for (const result of cleanup) if (result.status === "rejected") errors.push(result.reason);
    }
    if (errors.length !== 0) throw new AggregateError(errors, "Go/browser WSS interoperability or cleanup failed");
  });
});

test.describe("Go public Serve and browser WSS interoperability", () => {
  let go: ReturnType<typeof buildGoWSSPeer>;
  test.beforeAll(() => { go = buildGoWSSPeer(); });
  test.afterAll(() => go?.close());
  for (const source of ["preauthorized_pool", "live_authority"] as const) for (const profile of profiles) test(`Chromium runs public Go Serve with ${profile} (${source})`, async ({ browser }) => {
    const site = await startBrowserModuleSite(source === "live_authority" ? { tls: { cert: certificate, key } } : undefined);
    const peer = await startGoPublicWSSPeer(go.binary, site.origin, profile, source).catch(async error => { await site.close(); throw error; });
    const context = await browser.newContext({ ignoreHTTPSErrors: true }), page = await context.newPage();
    const errors: unknown[] = [];
    try {
      await page.goto(site.origin); await install(page, peer, true);
      const result = await page.evaluate(async sourceKind => {
        const v = window.v4;
        let acquisitions = 0;
        const provider: BrowserSDK.CredentialProvider = async (_request, buffers) => {
          acquisitions++;
          const input = v.materialInput;
          if (input.activation === undefined) throw new Error("pool activation is required");
          const activation = input.activation;
          for (const name of ["artifact", "clientCertificate", "serverCertificate"] as const) buffers[name].set(input[name]);
          buffers.activation.set(activation);
          return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length,
            serverCertificate: input.serverCertificate.length, activation: activation.length, candidateIndex: 0 };
        };
        const source = sourceKind === "live_authority" ? v.client.registerLiveSource(v.policy, provider) : v.client.registerPoolSource(v.policy, provider);
        const session = await v.environment.connect(source);
        const echoes: number[][] = [];
        for (let round = 0; round < 2; round++) {
          const stream = await session.openStream("example/websocket");
          const payload = new Uint8Array([round, 7, 11, 15]);
          const written = await stream.write(payload);
          if (written.accepted_bytes !== 4n || written.terminal_reason !== "complete") throw new Error("public Go stream write incomplete");
          await stream.closeWrite();
          const output: number[] = [];
          for (;;) {
            const read = await stream.read(64n); output.push(...read.data);
            if (read.stream_status === "eof") break;
            if (read.wait_status !== "ready" || read.stream_status !== "open") throw new Error("public Go stream read incomplete");
          }
          const finished = await stream.finish();
          if (!finished.send_drained || finished.read_terminal !== "eof") throw new Error("public Go stream did not drain");
          echoes.push(output);
          if (round === 0) await session.rekey();
        }
        const liveness = await session.probeLiveness(), info = session.info();
        await session.close(); v.cleanupMaterial();
        return { echoes, liveness, guarantee: info.guarantees.local_consumer_tls13_verification, acquisitions, hasPoolStore: v.store !== undefined };
      }, source);
      expect(result.echoes).toEqual([[0, 7, 11, 15], [1, 7, 11, 15]]);
      expect(result.guarantee).toBe("controlled_terminator");
      expect(result.liveness.submitted).toBe(true);
      expect(result.acquisitions).toBe(1);
      expect(result.hasPoolStore).toBe(source === "preauthorized_pool");
      expect((await peer.served()).value).toMatchObject({ streams: 2, materialLookups: 1,
        liveAuthorizations: source === "live_authority" ? 1 : 0, liveRequests: source === "live_authority" ? 1 : 0 });
      expect(await close(page, true)).toEqual({ cleanup: "complete", reservations: 0 });
    } catch (error) { errors.push(error); }
    finally {
      const cleanup = await Promise.allSettled([context.close(), peer.close(), site.close()]);
      for (const result of cleanup) if (result.status === "rejected") errors.push(result.reason);
    }
    if (errors.length !== 0) throw new AggregateError(errors, "public Go Serve/browser WSS interoperability or cleanup failed");
  });

  for (const failure of ["credential", "signature"] as const) test(`Chromium runs live_authority ${failure} refusal before Go admission`, async ({ browser }) => {
    const site = await startBrowserModuleSite({ tls: { cert: certificate, key } });
    const peer = await startGoPublicWSSPeer(go.binary, site.origin, profiles[0], "live_authority", failure).catch(async error => { await site.close(); throw error; });
    const context = await browser.newContext({ ignoreHTTPSErrors: true }), page = await context.newPage();
    const errors: unknown[] = [];
    try {
      await page.goto(site.origin); await install(page, peer, true);
      const result = await page.evaluate(async () => {
        const v = window.v4;
        let acquisitions = 0;
        const source = v.client.registerLiveSource(v.policy, async (_request, buffers) => {
          acquisitions++;
          const input = v.materialInput;
          for (const name of ["artifact", "clientCertificate", "serverCertificate"] as const) buffers[name].set(input[name]);
          return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length,
            serverCertificate: input.serverCertificate.length, activation: 0, candidateIndex: 0 };
        });
        try { await v.environment.connect(source); return { error: "unexpected_success", acquisitions }; }
        catch (error) { return { error: (error as Error).message, acquisitions }; }
      });
      expect(result).toEqual({ error: "live_authorization_failed", acquisitions: 1 });
      expect((await peer.refused()).value).toEqual({ liveRequests: 1, liveAuthorizations: failure === "signature" ? 1 : 0, materialLookups: 0 });
      expect(await close(page, true)).toEqual({ cleanup: "complete", reservations: 0 });
    } catch (error) { errors.push(error); }
    finally {
      const cleanup = await Promise.allSettled([context.close(), peer.close(), site.close()]);
      for (const result of cleanup) if (result.status === "rejected") errors.push(result.reason);
    }
    if (errors.length !== 0) throw new AggregateError(errors, "browser live authority refusal or cleanup failed");
  });
});

test("Chromium runs v4 account capacity rejection before consume or network I/O", async ({ browser }) => {
  const site = await startBrowserModuleSite(), peer = await startV4WSSPeer(certificate, key, site.origin, profiles[0]), context = await browser.newContext({ ignoreHTTPSErrors: true }), page = await context.newPage();
  try {
    await page.goto(site.origin); await install(page, peer, true, browserAccountSlots - 1);
    const refusal = await page.evaluate(async () => {
      const v = window.v4;
      const material = v.client.verifyPoolMaterial(v.policy, v.materialInput);
      try { await v.environment.connectMaterial(material); return "unexpected_success"; }
      catch (error) { return (error as Error).message; }
      finally { await material.close(); }
    });
    expect(refusal).toBe("resource_exhausted"); expect(peer.counts()).toEqual({ connections: 0, hellos: 0 });
    expect(await close(page, true)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer.close(); await site.close(); }
});

test("Chromium runs v4 browser TLS requirement rejection before consume", async ({ browser }) => {
  const site = await startBrowserModuleSite(), peer = await startV4WSSPeer(certificate, key, site.origin, profiles[0], true), context = await browser.newContext({ ignoreHTTPSErrors: true }), page = await context.newPage();
  try {
    await page.goto(site.origin); await install(page, peer, true);
    const refusal = await connectionRefusal(page);
    expectUnspentRefusal(refusal); expect(await spendCount(page)).toBe(0); expect(peer.counts()).toEqual({ connections: 0, hellos: 0 });
    expect(await close(page, true)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer.close(); await site.close(); }
});

test("Chromium runs v4 browser continuity loss refusal before HELLO", async ({ browser }) => {
  const site = await startBrowserModuleSite(), peer = await startV4WSSPeer(certificate, key, site.origin, profiles[0]), context = await browser.newContext({ ignoreHTTPSErrors: true }), page = await context.newPage();
  try {
    await page.goto(site.origin); await install(page, peer, true);
    const refusal = await connectionRefusal(page, true);
    expectUnspentRefusal(refusal); expect(await spendCount(page)).toBe(0); expect(peer.counts().hellos).toBe(0);
    expect(await close(page, true)).toEqual({ cleanup: "complete", reservations: 0 });
  } finally { await context.close(); await peer.close(); await site.close(); }
});

test("Chromium runs v4 browser cross-tab fencing before one unique lease consume", async ({ browser }) => {
  const site = await startBrowserModuleSite(), peer = await startV4WSSPeer(certificate, key, site.origin, profiles[0]), context = await browser.newContext({ ignoreHTTPSErrors: true });
  const first = await context.newPage(), second = await context.newPage();
  try {
    await first.goto(site.origin); await install(first, peer, true);
    await second.goto(site.origin); await install(second, peer, false);
    const [stale, current] = await Promise.all([
      connectionRefusal(first),
      second.evaluate(async () => {
        const v = window.v4, session = await v.environment.connectMaterial(v.client.verifyPoolMaterial(v.policy, v.materialInput));
        const stream = await session.openStream("example/browser-v4"); await stream.write(new Uint8Array([9]));
        const read = await stream.read(1n); await session.close(); v.cleanupMaterial(); return Array.from(read.data);
      }),
    ]);
    expectUnspentRefusal(stale, "closed"); expect(await spendCount(second)).toBe(1); expect(current).toEqual([9]); expect(peer.counts().hellos).toBe(1); expect(peer.failure()).toBeUndefined();
    expect((await close(first, false)).cleanup).toBe("complete"); expect(await close(second, true)).toEqual({ cleanup: "complete", reservations: 0 });
    expect(await first.evaluate(async () => { await window.v4.backing!.releaseRemoved(); return window.v4.root.snapshot().reservations; })).toBe(0);
  } finally { await context.close(); await peer.close(); await site.close(); }
});
