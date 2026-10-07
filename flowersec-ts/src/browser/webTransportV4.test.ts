import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { BrowserWebTransportCarrier } from "./webTransportV4.js";
import { V4EnvironmentRuntime, type V4EnvironmentConfig, type V4CredentialBuffers, type V4CredentialLengths, type EnvironmentClientConnector } from "../v4/runtime/environment.js";
import { ResourceRoot, ResourceVector } from "../v4/runtime/resources.js";
import { TrustedClock } from "../v4/runtime/clock.js";
import { ClockRate } from "../v4/runtime/timeArithmetic.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { registerPoolSpendStore, type PoolSpendStore } from "../v4/runtime/poolSpend.js";
import { bytes, credentialFixture, fill, map, text, u } from "../v4/testSupport/credentials.js";

const settle = async () => { for (let index = 0; index < 8; index++) await Promise.resolve(); };
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

function harness() {
  let tick = 0n, resolveClosed!: (value: unknown) => void, rejectReady!: (error: Error) => void;
  const reservation = { take: () => ({ check: () => undefined, release: () => undefined }) };
  const clock = new TrustedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1_000_000n, maxRoundTripMS: 100n },
    () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), 128n, reservation as never);
  clock.installTrusted(clock.monotonic(), { lowerMS: 1000n, upperMS: 1000n });
  const ready = new Promise<void>((_resolve, reject) => { rejectReady = reject; });
  const closed = new Promise<unknown>(resolve => { resolveClosed = resolve; });
  const native = { ready, closed, close: vi.fn(() => resolveClosed(undefined)) };
  const Native = function() { return native; } as unknown as ConstructorParameters<typeof BrowserWebTransportCarrier>[3]["constructor"];
  const deployment = { endpoint: "https://127.0.0.1:19443/flowersec/webtransport/v4/direct", applicationOrigin: "https://127.0.0.1:19443",
    notBeforeMS: 0n, notAfterMS: 100_000n, userAgent: "Chrome/151.0.7922.34" };
  const options = { deployment, applicationStreams: 2, streamBufferBytes: 65544, runtimeBytes: 128n, providerRuntimeBytes: 128n, providerStreamBytes: 128n, constructor: Native } as unknown as ConstructorParameters<typeof BrowserWebTransportCarrier>[3];
  const retire = vi.fn();
  const dependency = { check: () => undefined, release: retire, onClose: () => undefined };
  const positions = { close: vi.fn(), cleanupComplete: () => true };
  const makeDeadline = (duration: bigint) => new TrustedDeadline(clock, 1000n + duration);
  const makeCarrier = (deadline: TrustedDeadline) => new BrowserWebTransportCarrier(
    { clock } as never, dependency as never, positions as never, options, 65544, deadline, []);
  vi.stubGlobal("navigator", { userAgent: deployment.userAgent });
  vi.stubGlobal("location", { origin: deployment.applicationOrigin });
  vi.stubGlobal("isSecureContext", true);
  return { makeCarrier, native, retire, positions, rejectReady, setTick: (value: bigint) => { tick = value; }, makeDeadline };
}

const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
const requirements = { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false };
const policy = { tenant: "tenant", audience: "service", clientSubject: "client", serverSubject: "server", cryptoProfiles: [profile], authorities: ["authority"] };
function environmentConfiguration(tick: () => bigint): V4EnvironmentConfig {
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 5000n, 5000n, 5000n, 5000n, 5000n, 5000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 64, reservations: 512, references: 1024,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  return { root, limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), tenantLimit: limit, runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 2, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 10000,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 60000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: tick(), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1000n }) },
    random: bytes => { crypto.getRandomValues(bytes); } };
}
function installFixture(buffers: V4CredentialBuffers, input: ReturnType<ReturnType<typeof credentialFixture>["input"]>): V4CredentialLengths {
  for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) buffers[name].set(input[name]);
  return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
    activation: input.activation.length, candidateIndex: 0 };
}
function pendingCarrier(environment: V4EnvironmentRuntime, deadline: TrustedDeadline) {
  let resolveClosed!: (value: unknown) => void, rejectReady!: (error: Error) => void;
  const ready = new Promise<void>((_resolve, reject) => { rejectReady = reject; });
  const closed = new Promise<unknown>(resolve => { resolveClosed = resolve; });
  const native = { ready, closed, close: vi.fn(() => resolveClosed(undefined)) };
  const Native = function() { return native; } as unknown as ConstructorParameters<typeof BrowserWebTransportCarrier>[3]["constructor"];
  const deployment = { endpoint: "https://127.0.0.1:19443/flowersec/webtransport/v4/direct", applicationOrigin: "https://127.0.0.1:19443",
    notBeforeMS: 0n, notAfterMS: 100_000n, userAgent: "Chrome/151.0.7922.34" };
  const options = { deployment, applicationStreams: 2, streamBufferBytes: 65544, runtimeBytes: 128n, providerRuntimeBytes: 128n, providerStreamBytes: 128n, constructor: Native } as unknown as ConstructorParameters<typeof BrowserWebTransportCarrier>[3];
  const retire = vi.fn(), dependency = { check: () => undefined, release: retire, onClose: () => undefined };
  const positions = { close: vi.fn(), cleanupComplete: () => true };
  vi.stubGlobal("navigator", { userAgent: deployment.userAgent });
  vi.stubGlobal("location", { origin: deployment.applicationOrigin });
  vi.stubGlobal("isSecureContext", true);
  return { carrier: new BrowserWebTransportCarrier({ clock: environment.clock } as never, dependency as never, positions as never, options,
    65544, deadline, []), native, rejectReady, retire, positions };
}

describe("current browser WebTransport readiness lifecycle", () => {
  it("bounds a pending native ready signal by the trusted preparation deadline", async () => {
    vi.useFakeTimers();
    const f = harness(), carrier = f.makeCarrier(f.makeDeadline(25n));
    const preparing = carrier.prepare();
    const rejected = expect(preparing).rejects.toMatchObject({ code: "time_expired" });
    await settle();

    f.setTick(25n);
    await vi.advanceTimersByTimeAsync(25);
    await rejected;
    expect(f.native.close).toHaveBeenCalledOnce();
    expect(f.retire).not.toHaveBeenCalled();

    f.rejectReady(new Error("late readiness failure"));
    await carrier.waitTermination();
    expect(f.retire).toHaveBeenCalledOnce();
    expect(f.positions.close).toHaveBeenCalledOnce();
  });

  it("cancels pending readiness and retires once after its late native failure", async () => {
    const f = harness(), carrier = f.makeCarrier(f.makeDeadline(10_000n)), controller = new AbortController();
    const preparing = carrier.prepare(controller.signal);
    await settle();
    controller.abort(new Error("private cancellation detail"));
    await expect(preparing).rejects.toThrow("canceled");
    expect(f.native.close).toHaveBeenCalledOnce();
    expect(f.retire).not.toHaveBeenCalled();

    f.rejectReady(new Error("late provider failure"));
    await carrier.waitTermination();
    expect(f.retire).toHaveBeenCalledOnce();
    expect(f.positions.close).toHaveBeenCalledOnce();
  });

  it("cancels current client acquisition before pool spend when native readiness fails late", async () => {
    let tick = 0n;
    const configuration = environmentConfiguration(() => tick), environment = new V4EnvironmentRuntime(configuration);
    const namespace = environment.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
      maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
    const browserLeg = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(2), 6: text("127.0.0.1"), 7: u(19443),
      8: text("/flowersec/webtransport/v4/direct"), 9: text("h3"), 10: text(""), 11: map({ 0: u(0), 1: { kind: "bool", value: false } }),
      12: map({ 0: { kind: "array", value: [text("https://127.0.0.1:19443")] }, 1: { kind: "bool", value: false } }) });
    const credentials = credentialFixture(environment.resources, environment.clock, () => { throw new Error("Environment owns reservations"); }, "preauthorized_pool", profile, namespace, { leg: browserLeg });
    credentials.bootstrap();
    const source = environment.registerSource(policy, "preauthorized_pool", async (_request, destination) => installFixture(destination, credentials.input()));
    const spend = vi.fn<PoolSpendStore["consume"]>();
    const store = { consume: spend } as PoolSpendStore;
    registerPoolSpendStore(store);
    let pending: ReturnType<typeof pendingCarrier> | undefined;
    environment.installClientConnector({ applicationProfile: "transport", checkRequirements: () => undefined,
      connect: (material, options) => environment.establishPoolClient(material, store, async (fields, signal) => {
        pending = pendingCarrier(environment, fields.preparationDeadline);
        await pending.carrier.prepare(signal);
        throw new Error("unexpected native readiness success");
      }, options) } satisfies EnvironmentClientConnector);

    try {
      const material = await source.acquire(requirements);
      const controller = new AbortController();
      const connecting = environment.connectMaterial(material, { signal: controller.signal });
      const canceled = expect(connecting).rejects.toThrow("canceled");
      await settle();
      expect(pending?.native.close).not.toHaveBeenCalled();
      controller.abort(new Error("private cancellation detail"));
      await settle();
      expect(pending?.native.close).toHaveBeenCalledOnce();
      expect(spend).not.toHaveBeenCalled();
      expect(pending?.retire).not.toHaveBeenCalled();

      pending!.rejectReady(new Error("late native readiness failure"));
      await pending!.carrier.waitTermination();
      await canceled;
      expect(spend).not.toHaveBeenCalled();
      expect(pending!.retire).toHaveBeenCalledOnce();
      expect(pending!.positions.close).toHaveBeenCalledOnce();
    } finally {
      source.close();
      await environment.close();
      expect((await environment.waitCleanup()).status).toBe("complete");
      expect(configuration.root.snapshot().reservations).toBe(0);
    }
  });
});
