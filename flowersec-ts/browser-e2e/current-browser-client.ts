import type { Page } from "@playwright/test";
import type * as BrowserSDK from "../src/browser/index.js";
import type { CurrentBrowserFixture } from "./go-webtransport-peer.js";

interface BrowserFixtureOwner {
  readonly environment: ReturnType<typeof BrowserSDK.createTransportEnvironment>;
  readonly root: InstanceType<typeof BrowserSDK.ResourceRoot>;
  readonly backing: ReturnType<typeof BrowserSDK.createIndexedDBPoolBacking>;
  readonly store: Awaited<ReturnType<typeof BrowserSDK.openIndexedDBPoolStore>>;
  readonly databaseName: string;
  client?: BrowserSDK.BrowserWSSClient;
  method?: BrowserSDK.MethodDefinition<Uint8Array, Uint8Array, "unary">;
  definition?: BrowserSDK.ServiceDefinition<{ echo: BrowserSDK.MethodDefinition<Uint8Array, Uint8Array, "unary"> }>;
  readonly fixture: Omit<CurrentBrowserFixture, "bootstrap">;
}
declare global { interface Window { currentBootstrap(index: number, nonce: readonly number[]): Promise<Readonly<{ response: readonly number[]; state: readonly number[] }>>; currentBrowser: BrowserFixtureOwner; wtConstructorCalls?: unknown[][] } }
const bootstrapOwners = new WeakMap<Page, { fixture: CurrentBrowserFixture; ready: Promise<void> }>();

export async function installCurrentBrowserClient(page: Page, fixture: CurrentBrowserFixture, deploymentEndpoint = fixture.endpoint): Promise<void> {
  let binding = bootstrapOwners.get(page);
  if (binding === undefined) {
    const owner = { fixture, ready: Promise.resolve() };
    owner.ready = page.exposeFunction("currentBootstrap", (index: number, nonce: number[]) => owner.fixture.bootstrap(index, nonce));
    bootstrapOwners.set(page, owner);
    binding = owner;
  }
  binding.fixture = fixture;
  await binding.ready;
  const { carrier, endpoint, timeOrigin, profile, route, issuer, serverIdentity, tlsMode, pins,
    services, spendAuthority, identitySeed, noiseSeed, namespaces, policy, input } = fixture;
  const material: Omit<CurrentBrowserFixture, "bootstrap"> = { carrier, endpoint, timeOrigin, profile, route,
    issuer, serverIdentity, tlsMode, pins, services, spendAuthority, identitySeed, noiseSeed, namespaces, policy, input };
  await page.evaluate(async ({ fixture, deploymentEndpoint }) => {
    const sdk = await import("/dist/browser/index.js"), registry = await import("/dist/generated/transportV4Registry.js");
    const bytes = (value: readonly number[]) => new Uint8Array(value), start = performance.now(), now = BigInt(Date.now());
    const limit = new sdk.ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 5000n, 5000n, 5000n, 5000n, 5000n, 5000n]);
    const root = new sdk.ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 2048, reservations: 4096, references: 8192,
      rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
    const environment = sdk.createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
      namespaces: fixture.namespaces.length, sources: 1, acquisitions: 1, materials: 4, sessions: 1, dependencies: 16, acquireMS: 10000n, cleanupMS: 10000,
      clock: { profile: { rate: new sdk.ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
        tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - start)), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: now, upperMS: now }) },
      random: output => { if (!(output.buffer instanceof ArrayBuffer)) throw new Error("random owner unavailable"); crypto.getRandomValues(new Uint8Array(output.buffer, output.byteOffset, output.byteLength)); } });
    const databaseName = "flowersec-current-browser-once", backing = sdk.createIndexedDBPoolBacking(environment, databaseName, { maxRecords: 4, maxRecordBytes: 65536, transactionMS: 10000n,
      runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, storageBytes: 1048576n });
    // This is the engineering host's explicit continuity trust boundary.
    const store = await sdk.openIndexedDBPoolStore(backing, { create: true, identity: { authority: fixture.spendAuthority, storeID: new Uint8Array(32).fill(9), generation: 1n }, continuity: { check: () => undefined },
      bindings: [{ tenant: fixture.policy.tenant, issuer: bytes(fixture.issuer) }] });
    const owner = window.currentBrowser = { environment, root, backing, store, databaseName, fixture } as BrowserFixtureOwner;
    const identityKey = await crypto.subtle.importKey("pkcs8", bytes([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, ...fixture.identitySeed]), "Ed25519", true, ["sign"]);
    const noble = await import("/node_modules/@noble/curves/ed25519.js"), noisePrivate = bytes(fixture.noiseSeed), noisePublic = noble.x25519.getPublicKey(noisePrivate);
    const b64 = (wire: Uint8Array) => btoa(String.fromCharCode(...wire)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    const noiseKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "X25519", x: b64(noisePublic), d: b64(noisePrivate), ext: true }, "X25519", true, ["deriveBits"]); noisePrivate.fill(0);
    let services: BrowserSDK.BrowserWSSClientConfig["services"];
    if (fixture.services) {
      const codec = sdk.bytesMessageCodec({ schemaDigest: new Uint8Array(32), revision: "1", maxMessageBytes: 1048576 });
      owner.method = new sdk.MethodDefinition({ typeID: 1, shape: "unary", unarySemantics: "transient", request: codec, response: codec, requestMaxBytes: 1048576, minResponseLimitBytes: 0, maxResponseBytes: 1048576, restartFlush: false });
      owner.definition = new sdk.ServiceDefinition({ namespace: "flowersec.engineering.release", methods: { echo: owner.method } });
      const digest = new Uint8Array(32); digest[0] = 9; services = { query: { typeID: 7, contractDigest: digest }, definitions: [owner.definition], maxMethods: 1, maxCaptureBytes: 1048576 };
    }
    const common = { identityKey, noiseKey, poolStore: store, ...(services === undefined ? {} : { services }),
      limits: { maxFrame: 65536, maxStreams: fixture.services ? 32 : 8, receiveQueueBytes: 16384, maxDataBytes: 4096, maxCursorBytes: 65536, maxWriteBytes: 65536, maxGeneralOutstanding: 32,
        writeDeadlineMS: 10000n, operationDeadlineMS: 10000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n, cryptoKeys: 100 } };
    const deployment = { deploymentID: "current-browser-test", revision: "one", endpoint: deploymentEndpoint, applicationOrigin: location.origin, routeDigest: bytes(fixture.route),
      notBeforeMS: BigInt(fixture.timeOrigin), notAfterMS: BigInt(fixture.timeOrigin) + 120000n, evidenceReference: "engineering:unverified-current-browser-provider" };
    if (fixture.carrier === "wss") owner.client = await sdk.configureBrowserWSS(environment, { ...common, carrier: { deployment: { ...deployment, terminatorProfile: "tls13-no-early-data-http11-exact-origin-no-extensions" }, queueMessages: 8, sendBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n } });
    else {
      const tuple = registry.transportV4CarrierProviderRegistry.webtransport.tuples.find(value => value.id === "chromium_h3_draft02")!;
      owner.client = await sdk.configureBrowserWebTransport(environment, { ...common, carrier: { deployment: { ...deployment, providerTuple: "chromium_h3_draft02", implementation: tuple.implementation, quicImplementation: tuple.quic_implementation,
        buildID: "engineering-unverified", userAgent: navigator.userAgent, terminatorProfile: "tls13-no-early-data-h3-dedicated-exact-origin-no-wt-session-flow-control" }, applicationStreams: fixture.services ? 65 : 32,
        streamBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n } });
    }
    for (const [index, record] of fixture.namespaces.entries()) {
      const namespace = owner.client.namespace({ tenant: record.tenant, authority: record.authority, rootKeyID: bytes(record.rootKeyID), rootPublicKey: bytes(record.rootPublicKey), maxTrustLifetimeMS: 30000000n, bootstrapMS: 10000n, stateBytes: 65536, stateNodes: 131072 });
      await namespace.fetchBootstrap(async (request, response, state) => {
        const reply = await window.currentBootstrap(index, Array.from(request.nonce));
        const signed = bytes(reply.response), content = bytes(reply.state);
        try { response.set(signed); state.set(content); return { responseBytes: signed.length, stateBytes: content.length }; }
        finally { signed.fill(0); content.fill(0); }
      });
      if (namespace.activeVersion()[0] !== BigInt(record.generation)) throw new Error("current namespace generation mismatch");
    }
  }, { fixture: material, deploymentEndpoint });
}
/** Inspect the actual original store's durable spend count. An application
 * callback is never substituted for the configured built-in store. */
export async function currentBrowserSpendCount(page: Page): Promise<number> {
  return page.evaluate(() => new Promise<number>((resolve, reject) => {
    const request = indexedDB.open(window.currentBrowser.databaseName);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => { const database = request.result, transaction = database.transaction("spend", "readonly"), count = transaction.objectStore("spend").count(); let value = 0;
      count.onsuccess = () => { value = count.result; }; transaction.oncomplete = () => { database.close(); resolve(value); }; transaction.onabort = () => { database.close(); reject(transaction.error); }; };
  }));
}
export async function closeCurrentBrowserClient(page: Page): Promise<Readonly<{ cleanup: string; reservations: number }>> {
  return page.evaluate(async () => {
    const owner = window.currentBrowser; await owner.environment.close(); owner.store.close();
    await new Promise<void>((resolve, reject) => { const request = indexedDB.deleteDatabase(owner.databaseName); request.onsuccess = () => resolve(); request.onerror = () => reject(request.error); });
    await owner.backing.releaseRemoved(); const result = { cleanup: (await owner.environment.waitCleanup()).status, reservations: owner.root.snapshot().reservations };
    Reflect.deleteProperty(window, "currentBrowser"); return result;
  });
}
