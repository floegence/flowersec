import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { wrapCredentialSource, V4EnvironmentRuntime, createV4TransportEnvironment, type V4EnvironmentConfig, type V4CredentialBuffers, type V4CredentialLengths, type EnvironmentClientConnector } from "./runtime/environment.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { V4ConnectionMaterial } from "./public.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { credentialFixture, fill } from "./testSupport/credentials.js";

const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
const requirements = { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false };
const policy = { tenant: "tenant", audience: "service", clientSubject: "client", serverSubject: "server", cryptoProfiles: [profile], authorities: ["authority"] };
const namespaceOptions = () => ({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)), maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
function fixtureRoot(work = 5000000n) {
  const limit = new ResourceVector([512n * 1024n * 1024n, 0n, 0n, 5000000n, work, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  return { root, limit };
}
function config(shared = fixtureRoot(), id = "2", tick = () => 0n): V4EnvironmentConfig {
  return { ...shared, tenantID: "1".repeat(32), environmentID: id.repeat(32), tenantLimit: shared.limit, runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, acquireMS: 10000n, cleanupMS: 25,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: tick(), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1000n }) },
    random: bytes => { crypto.getRandomValues(bytes); } };
}
function credentials(environment: V4EnvironmentRuntime) {
  const namespace = environment.namespace(namespaceOptions());
  const fixture = credentialFixture(environment.resources, environment.clock, () => { throw new Error("Environment owns reservations"); }, "live_authority", profile, namespace);
  fixture.bootstrap(); return fixture;
}
function install(buffers: V4CredentialBuffers, input: ReturnType<ReturnType<typeof credentials>["input"]>): V4CredentialLengths {
  for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) buffers[name].set(input[name]);
  return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, activation: input.activation.length, candidateIndex: input.candidateIndex };
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(yes => { resolve = yes; }); return { promise, resolve }; }

describe("v4 original Environment ownership", () => {
  it("charges every Environment to the same root without multiplying its bound", async () => {
    const shared = fixtureRoot(65n), one = new V4EnvironmentRuntime(config(shared));
    expect(() => new V4EnvironmentRuntime(config(shared, "4"))).toThrow("resource_exhausted");
    expect(one.clock.sample().requireInterval().lowerMS).toBe(1000n);
    await one.close(); expect(shared.root.snapshot().reservations).toBe(0); expect(shared.root.snapshot().closed).toBe(false);
  });
  it("does not close the borrowed root or shared tenant when one Environment closes", async () => {
    const shared = fixtureRoot(), one = new V4EnvironmentRuntime(config(shared)), two = new V4EnvironmentRuntime(config(shared, "4"));
    await one.close(); expect(one.cleanupStatus().status).toBe("complete");
    expect(two.clock.sample().requireInterval().lowerMS).toBe(1000n); expect(shared.root.snapshot().reservations).toBe(3);
    await two.close(); expect(shared.root.snapshot().reservations).toBe(0);
  });
  it("reuses one namespace owner and rejects conflicting roots and excess names", async () => {
    const environment = new V4EnvironmentRuntime(config());
    try {
      const one = environment.namespace(namespaceOptions()); expect(environment.namespace(namespaceOptions())).toBe(one);
      expect(() => environment.namespace({ ...namespaceOptions(), rootPublicKey: ed25519.getPublicKey(fill(8)) })).toThrow("credential_binding");
      expect(() => environment.namespace({ ...namespaceOptions(), authority: "other" })).toThrow("resource_exhausted");
    } finally { await environment.close(); }
  });
  it("acquires a genuine verified snapshot and keeps one finite material slot", async () => {
    const configuration = config(), environment = new V4EnvironmentRuntime(configuration), fixture = credentials(environment);
    const provider = vi.fn(async (request, buffers: V4CredentialBuffers) => {
      expect(request.requirements).toEqual(requirements);
      expect(Object.isFrozen(request.requirements)).toBe(true);
      return install(buffers, fixture.input());
    });
    const source = environment.registerSource(policy, "live_authority", provider);
    try {
      const material = await source.acquire(requirements);
      await expect(source.acquire(requirements)).rejects.toThrow("resource_exhausted"); expect(provider).toHaveBeenCalledTimes(1);
      const other = new V4EnvironmentRuntime(config({ root: configuration.root, limit: configuration.limit }, "4"));
      await expect(other.establishVerified(material, {} as never, new Uint8Array())).rejects.toThrow("material_unavailable"); await other.close();
      await material.closeMaterial(); const next = await source.acquire(requirements); await next.closeMaterial();
    } finally { await environment.close(); }
    expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it("reserves the Session position before invoking a concurrent material source", async () => {
    const configuration = { ...config(), acquisitions: 2, materials: 2 };
    const environment = new V4EnvironmentRuntime(configuration), fixture = credentials(environment), returned = deferred<V4CredentialLengths>();
    let destination!: V4CredentialBuffers;
    const provider = vi.fn(async (_request, buffers: V4CredentialBuffers) => { destination = buffers; return returned.promise; });
    const source = wrapCredentialSource(environment.registerSource(policy, "live_authority", provider));
    const connect = vi.fn(async () => { throw new Error("carrier_unavailable"); });
    environment.installClientConnector({ applicationProfile: "transport", checkRequirements: () => undefined, connect });
    const first = environment.connect(source, requirements), failed = expect(first).rejects.toThrow("carrier_unavailable");
    await expect(environment.connect(source, requirements)).rejects.toThrow("resource_exhausted");
    expect(provider).toHaveBeenCalledTimes(1); expect(connect).not.toHaveBeenCalled();
    returned.resolve(install(destination, fixture.input())); await failed;
    await environment.close(); expect((await environment.waitCleanup()).status).toBe("complete");
    expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it.each(["services", "execution"] as const)("keeps the local %s profile fixed and rejects wrong source material before connect", async applicationProfile => {
    const configuration = config(), environment = new V4EnvironmentRuntime(configuration), fixture = credentials(environment);
    const provider = vi.fn(async (request, buffers: V4CredentialBuffers) => {
      expect(request.requirements.application_profile).toBe(applicationProfile);
      return install(buffers, fixture.input());
    });
    const source = wrapCredentialSource(environment.registerSource(policy, "live_authority", provider));
    const connect = vi.fn(async () => { throw new Error("must not connect or spend"); });
    const connector: { -readonly [K in keyof EnvironmentClientConnector]: EnvironmentClientConnector[K] } = {
      applicationProfile, checkRequirements: () => undefined, connect,
    };
    environment.installClientConnector(connector); connector.applicationProfile = "transport";
    try {
      await expect(environment.connect(source, requirements)).rejects.toThrow("connection_requirement_unavailable");
      expect(provider).toHaveBeenCalledTimes(1); expect(connect).not.toHaveBeenCalled();
    } finally { await environment.close(); }
    expect((await environment.waitCleanup()).status).toBe("complete");
    expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it("fences canceled acquisition immediately but retains its actual callback and buffers", async () => {
    const configuration = config(fixtureRoot(), "2", () => BigInt(Math.floor(performance.now()))), environment = new V4EnvironmentRuntime(configuration), fixture = credentials(environment), returned = deferred<V4CredentialLengths>();
    let buffers!: V4CredentialBuffers, requestSignal!: AbortSignal;
    const source = environment.registerSource(policy, "live_authority", (request, destination) => { buffers = destination; requestSignal = request.signal; install(buffers, fixture.input()); return returned.promise; });
    const abort = new AbortController(), acquisition = source.acquire(requirements, { signal: abort.signal });
    const canceled = expect(acquisition).rejects.toThrow("canceled"); abort.abort(); await canceled;
    expect(requestSignal.aborted).toBe(true); expect(buffers.artifact.some(byte => byte !== 0)).toBe(true);
    await expect(source.acquire(requirements)).rejects.toThrow("resource_exhausted");
    await environment.close(); expect(environment.cleanupStatus().status).toBe("cleanup_incomplete"); expect(configuration.root.snapshot().reservations).toBeGreaterThan(0);
    const cleaned = deferred<void>(); environment.onCleanup(() => cleaned.resolve());
    returned.resolve(install(buffers, fixture.input())); await cleaned.promise;
    expect((await environment.waitCleanup()).status).toBe("complete"); expect(buffers.artifact.every(byte => byte === 0)).toBe(true);
    expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it("Environment Close cancels an acquisition wait without erasing its original tail", async () => {
    const configuration = config(fixtureRoot(), "2", () => BigInt(Math.floor(performance.now()))), environment = new V4EnvironmentRuntime(configuration), fixture = credentials(environment), returned = deferred<V4CredentialLengths>();
    let lengths!: V4CredentialLengths;
    const source = environment.registerSource(policy, "live_authority", (_request, destination) => { lengths = install(destination, fixture.input()); return returned.promise; });
    const acquisition = source.acquire(requirements), closed = expect(acquisition).rejects.toThrow("closed");
    const close = environment.close(); expect(environment.close()).toBe(close); await closed; await close;
    expect(environment.cleanupStatus().pending_callbacks).toBe(1n);
    const cleaned = deferred<void>(); environment.onCleanup(() => cleaned.resolve());
    returned.resolve(lengths); await cleaned.promise;
    expect((await environment.waitCleanup()).status).toBe("complete"); expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it("rejects unavailable Connect before issuing or removing any material", async () => {
    const configuration = config(), environment = createV4TransportEnvironment(configuration), acquire = vi.fn(async () => { throw new Error("must not acquire"); });
    await expect(environment.connect({ acquire }, requirements)).rejects.toThrow("runtime_unavailable"); expect(acquire).not.toHaveBeenCalled();
    const closeMaterial = vi.fn(async () => undefined), material = new V4ConnectionMaterial({ closeMaterial });
    await expect(environment.connectMaterial(material)).rejects.toThrow("runtime_unavailable"); expect(closeMaterial).not.toHaveBeenCalled();
    await material.close(); expect(closeMaterial).toHaveBeenCalledTimes(1);
    await environment.close(); expect((await environment.waitCleanup()).status).toBe("complete"); expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it("rejects malformed optional requirements before source acquisition", async () => {
    const configuration = config(), environment = createV4TransportEnvironment(configuration);
    const acquire = vi.fn(async () => { throw new Error("must not acquire"); });
    for (const request of [null, { datagram: 1 }, { local_consumer_tls13_verification: null }, { application_profile: "auto" }]) {
      await expect(environment.connect({ acquire }, request as never)).rejects.toThrow("invalid_argument");
    }
    expect(acquire).not.toHaveBeenCalled();
    await environment.close(); expect((await environment.waitCleanup()).status).toBe("complete");
    expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it("keeps synchronous namespace construction owned during a reentrant close", async () => {
    const configuration = config(); let environment!: V4EnvironmentRuntime;
    environment = new V4EnvironmentRuntime({ ...configuration, random: bytes => {
      void environment.close(); expect(environment.cleanupStatus().status).toBe("cleanup_incomplete"); bytes.fill(1);
    } });
    expect(() => environment.namespace(namespaceOptions())).toThrow();
    expect((await environment.waitCleanup()).status).toBe("complete"); await environment.close();
    expect(configuration.root.snapshot().reservations).toBe(0);
  });
  it("fences the original Environment when its configured CSPRNG fails", async () => {
    const configuration = config(), environment = new V4EnvironmentRuntime({ ...configuration, random: () => { throw new Error("entropy failure"); } });
    expect(() => environment.namespace(namespaceOptions())).toThrow("random_unavailable");
    await environment.close(); expect((await environment.waitCleanup()).status).toBe("complete"); expect(configuration.root.snapshot().reservations).toBe(0);
  });
});
