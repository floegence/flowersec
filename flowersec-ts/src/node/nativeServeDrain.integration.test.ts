import { X509Certificate } from "node:crypto";
import { expect, test, vi } from "vitest";
import { MethodDefinition, ServiceDefinition, bytesMessageCodec, configureNodeWebTransport, connect, createHandlerPlan,
  type AcceptedSession, type HandlerPlan, type ServiceClient, type Session, type Stream } from "./index.js";
import { createCurrentPeerServer } from "../interop/currentServer.js";
import { configureCurrentPeerRawQUIC, createCurrentPeerClient, peerLimits, peerRawQUICCapacity, peerRequirements, peerServices,
  type CurrentPeerClient } from "../interop/currentPeer.js";
import { array, encode, map, text, u } from "../v4/testSupport/credentials.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { loadCurrentNativeTransport } from "./nativeTransportCurrent.js";
import * as nativeTransport from "./nativeTransportCurrent.js";
import type { NativeRawListener, NativeRawSession } from "./nativeTransportCurrent.js";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
const complete = { status: "complete", core_cleanup: "complete", pending_callbacks: 0n } as const;
const carriers = ["raw-quic", "webtransport"] as const;
function connector(fixture: CurrentPeerClient, trustPEM: string, plan: HandlerPlan) {
  return fixture.carrierKind === "raw-quic" ? configureCurrentPeerRawQUIC(fixture, trustPEM, plan) :
    configureNodeWebTransport(fixture.environment, { identityKey: fixture.identityKey, noiseKey: fixture.noiseKey,
      poolStore: fixture.poolStore, limits: peerLimits, handlerPlan: plan, candidateAttemptLimit: fixture.candidateAttempts,
      carrier: { applicationStreams: peerRawQUICCapacity, streamBufferBytes: 65544, runtimeBytes: 1024n,
        providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n, trustRootsDER: [new Uint8Array(new X509Certificate(trustPEM).raw)],
        headerBytes: 16384, controlBytes: 65536, tuples: ["native_h3"], allowedOrigins: [], allowAbsentOrigin: true } });
}

for (const carrier of carriers) {
  test(`public native ${carrier} Drain preserves multiple Sessions, replies, streams and maintenance`, async () => {
    const codec = bytesMessageCodec({ schemaDigest: new Uint8Array(32), revision: "1", maxMessageBytes: 4096 });
    const method = new MethodDefinition({ typeID: 9110, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 4096, minResponseLimitBytes: 0, maxResponseBytes: 4096, restartFlush: false });
    const definition = new ServiceDefinition({ namespace: "flowersec.native.drain", methods: { echo: method } });
    const contract = encode(map({ 0: text(definition.namespace), 1: u(method.typeID), 2: u(0), 3: u(0), 6: text("1"), 7: text("1"),
      8: u(1), 9: u(0), 10: u(4096), 11: u(30000), 12: u(30000), 21: { kind: "bool", value: false }, 23: u(4096), 27: array() }));
    const services = { ...peerServices, definitions: [definition], maxMethods: 1, notificationMethods: [],
      queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" as const }] };
    const release = [deferred<void>(), deferred<void>()], rpcEntered = [deferred<void>(), deferred<void>()];
    const streamEntered = [deferred<void>(), deferred<void>()], streamDone = [deferred<void>(), deferred<void>()];
    const signals: AbortSignal[] = [];
    let streams = 0;
    const peer = await createCurrentPeerServer(environment => createHandlerPlan(environment, { applicationBytes: 16384n,
      services: { ...services, profile: "services", unaryHandlers: [{ namespace: definition.namespace, method, contract,
        handler: async (context, payload: Uint8Array) => {
          const index = payload[0]!; signals.push(context.signal); rpcEntered[index]!.resolve(); await release[index]!.promise;
          expect(context.signal.aborted).toBe(false); return new Uint8Array(payload);
        }, options: { workClass: "short", maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" } }] },
      streams: [{ kind: "native-drain", authorize: () => true,
        options: { workClass: "resident", applicationBytes: 16384n, maxConcurrentStreams: 2, maxAuthorizing: 2, applicationTimeoutMS: 10000n },
        handler: async (stream, context) => {
          const index = streams++; signals.push(context.signal); streamEntered[index]!.resolve(); await release[index]!.promise;
          expect(context.signal.aborted).toBe(false);
          const request = await stream.read(16n, { signal: context.signal });
          expect(request.data).toEqual(new Uint8Array([index, 42]));
          await stream.write(request.data, { signal: context.signal });
          expect((await stream.read(16n, { signal: context.signal })).stream_status).toBe("eof");
          await stream.closeWrite({ signal: context.signal });
          expect((await stream.finish({ signal: context.signal })).send_drained).toBe(true); streamDone[index]!.resolve();
        } }],
    }), "https://app.example", { applicationProfile: "services", carrier, serverName: "127.0.0.1", materialCount: 2 });
    const fixtures: CurrentPeerClient[] = [], plans: HandlerPlan[] = [], clients: Session[] = [], accepted: AcceptedSession[] = [], outgoing: Stream[] = [];
    const bound: ServiceClient<{ echo: typeof method }>[] = [];
    const replies: ReturnType<(typeof bound)[number]["call"]>[] = [];
    const cancellation = new AbortController(), signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(15000)]);
    try {
      for (const material of peer.artifactJSONs) fixtures.push(await createCurrentPeerClient(material, { trustPEM: peer.trustPEM }));
      for (let i = 0; i < 2; i++) {
        const fixture = fixtures[i]!;
        const plan = createHandlerPlan(fixture.environment, { applicationBytes: 16384n, services: { ...services, profile: "services" }, streams: [] }); plans.push(plan);
        const accepting = peer.acceptor.accept({ signal }); void accepting.catch(() => undefined);
        const client = await connect(fixture.environment, fixture.registerSource(connector(fixture, peer.trustPEM, plan)), peerRequirements, { signal })
          .catch(cause => { throw new Error(`original Session ${i} did not connect`, { cause }); }); clients.push(client);
        accepted.push(await accepting);
        const service = await client.bindService(definition, { target: { authority: fixture.policy.authorities[0]!, tenant: fixture.policy.tenant,
          audience: fixture.policy.audience, localSubject: fixture.policy.clientSubject,
          peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity }] }, maximumOfferWindowMS: 10000n, signal }); bound.push(service);
        const reply = service.call(method, new Uint8Array([i, 7]), { responseLimitBytes: 4096, signal }); replies.push(reply); void reply.catch(() => undefined);
        await rpcEntered[i]!.promise;
        outgoing.push(await client.openStream("native-drain", { signal })); await streamEntered[i]!.promise;
      }
      const queued = peer.acceptor.accept({ signal }), rejected = expect(queued).rejects.toMatchObject({ code: "closed" });
      const drains = peer.acceptor.drain(); await rejected;
      expect(drains).toHaveLength(1); expect(drains[0]!.status().outcome).toBe("pending");
      await expect(peer.acceptor.accept({ signal })).rejects.toMatchObject({ code: "closed" });
      const native = loadCurrentNativeTransport(), address = peer.acceptor.addresses()[0]!;
      const options = { ...address, serverName: "localhost", path: "direct" as const, tlsMode: "ca" as const,
        trustRootsDer: [new Uint8Array(new X509Certificate(peer.trustPEM).raw)], inboundBidirectionalStreamCapacity: 4,
        readBufferBytes: 16384, datagramQueueBytes: 65536, handshakeTimeoutMs: 500 };
      const ingress = carrier === "raw-quic" ? native.connectRawQuic(options) : native.connectWebTransport({ ...options,
        connectPath: "/flowersec/webtransport/v4/direct", tuple: "native_h3", headerBytes: 16384, controlBytes: 65536 });
      await expect(ingress.result()).rejects.toThrow();
      for (const session of accepted) {
        await session.session.rekey({ signal });
        expect((await session.session.probeLiveness({ signal })).complete).toBe(true);
      }
      expect(signals).toHaveLength(4); expect(signals.every(value => !value.aborted)).toBe(true);
      for (let i = 0; i < 2; i++) {
        release[i]!.resolve();
        const reply = await replies[i]!;
        expect(reply.kind).toBe("value");
        if (reply.kind !== "value" || reply.encoding !== "typed") throw new Error("original RPC reply missing");
        try { expect(reply.value).toEqual(new Uint8Array([i, 7])); } finally { reply.release(); }
        await outgoing[i]!.write(new Uint8Array([i, 42]), { signal }); await outgoing[i]!.closeWrite({ signal });
        expect((await outgoing[i]!.read(16n, { signal })).data).toEqual(new Uint8Array([i, 42]));
        expect((await outgoing[i]!.read(16n, { signal })).stream_status).toBe("eof");
        expect((await outgoing[i]!.finish({ signal })).send_drained).toBe(true); await streamDone[i]!.promise;
        if (i === 0) { expect(drains[0]!.status().outcome).toBe("pending"); expect(signals.slice(2).every(value => !value.aborted)).toBe(true); }
      }
      expect((await drains[0]!.wait({ signal })).outcome).toBe("drained");
      await expect.poll(() => peer.acceptor.cleanupStatus(), { timeout: 5000 }).toEqual(complete);
    } finally {
      release.forEach(value => value.resolve()); cancellation.abort();
      bound.forEach(service => service.close());
      await Promise.all(outgoing.map(stream => stream.close().catch(() => undefined)));
      await Promise.all(clients.map(client => client.close())); await Promise.all(accepted.map(session => session.close()));
      await Promise.all(replies.map(reply => reply.then(value => { if (value.kind === "value") value.release(); }, () => undefined)));
      plans.forEach(plan => plan.close()); await Promise.all(fixtures.map(fixture => fixture.close())); await peer.close(); contract.fill(0);
    }
  }, 25000);

  for (const end of ["Close", "deadline"] as const) {
    test(`public native ${carrier} Drain ${end} aborts original work but retains its callback charge`, async () => {
      const entered = deferred<AbortSignal>(), release = deferred<void>();
      const peer = await createCurrentPeerServer(environment => createHandlerPlan(environment, { applicationBytes: 16384n,
        services: { ...peerServices, profile: "services" }, streams: [{ kind: "native-drain-held", authorize: () => true,
          options: { workClass: "resident", applicationBytes: 16384n, maxConcurrentStreams: 1, maxAuthorizing: 1, applicationTimeoutMS: 10000n },
          handler: async (_stream, context) => { entered.resolve(context.signal); await release.promise; } }],
      }), "https://app.example", { applicationProfile: "services", carrier, serverName: "127.0.0.1",
        ingress: { positions: 2, handshakeMS: 5000n, drainMS: 5000n, cleanupMS: 200n }, acceptorCleanupMS: 200n });
      let fixture: CurrentPeerClient | undefined, plan: HandlerPlan | undefined, client: Session | undefined, accepted: AcceptedSession | undefined, stream: Stream | undefined;
      try {
        fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
        plan = createHandlerPlan(fixture.environment, { applicationBytes: 16384n, services: { ...peerServices, profile: "services" }, streams: [] });
        const accepting = peer.acceptor.accept(); void accepting.catch(() => undefined);
        client = await connect(fixture.environment, fixture.registerSource(connector(fixture, peer.trustPEM, plan)), peerRequirements);
        accepted = await accepting; stream = await client.openStream("native-drain-held"); const signal = await entered.promise;
        const drains = peer.acceptor.drain({ timeoutMS: end === "Close" ? 5000n : 50n });
        expect(signal.aborted).toBe(false);
        if (end === "Close") void peer.acceptor.close();
        else {
          const observation = new AbortController(); observation.abort();
          await expect(drains[0]!.wait({ signal: observation.signal })).rejects.toThrow();
          expect(peer.acceptor.drain({ timeoutMS: 5000n })[0]).toBe(drains[0]);
        }
        expect((await drains[0]!.wait()).outcome).toBe(end === "Close" ? "failed" : "deadline_aborted");
        await expect.poll(() => signal.aborted).toBe(true);
        await expect.poll(() => peer.acceptor.cleanupStatus().core_cleanup, { timeout: 5000 }).toBe("complete");
        expect(peer.acceptor.cleanupStatus().pending_callbacks).toBeGreaterThan(0n);
        expect((await peer.acceptor.waitCleanup()).status).toBe("cleanup_incomplete");
        const root = originalEnvironment(peer.environment).resources.root, held = root.snapshot().reservations;
        release.resolve(); await expect.poll(() => peer.acceptor.cleanupStatus(), { timeout: 5000 }).toEqual(complete);
        expect(root.snapshot().reservations).toBeLessThan(held);
      } finally {
        // Close/deadline has already aborted the peer. Join the original
        // Session before observing its detached Stream cleanup; a fresh reset
        // cannot obtain termination proofs from that destroyed peer.
        release.resolve(); await client?.close(); await accepted?.close(); await stream?.close(); plan?.close(); await fixture?.close(); await peer.close();
      }
    }, 20000);
  }

  for (const boundary of ["pending accept", "late result"] as const) {
    test(`public native ${carrier} Drain retains ${boundary} until original physical exit without publication`, async () => {
      const originalBind = nativeTransport.bindCurrentNativeListener, entered = deferred<void>(), release = deferred<void>();
      const physicalExit = deferred<void>(), releasePhysicalExit = deferred<void>();
      let published = 0, accepts = 0, rawAborts = 0, native: NativeRawListener | undefined, client: NativeRawSession | undefined;
      const binding = vi.spyOn(nativeTransport, "bindCurrentNativeListener").mockImplementation(async (...args) => {
        native = await originalBind(...args);
        const listener = native, terminated = listener.waitTermination();
        return { ...listener, waitTermination: () => terminated,
          accept: () => {
            accepts++; const operation = listener.accept();
            const result = operation.result().then(async raw => {
              entered.resolve(); await release.promise;
              const termination = raw.waitTermination().then(async () => { physicalExit.resolve(); await releasePhysicalExit.promise; });
              return { ...raw, abort: () => { rawAborts++; raw.abort(); }, waitTermination: () => termination };
            }, async error => { entered.resolve(); await release.promise; throw error; });
            return { cancel: () => operation.cancel(), result: () => result };
          } };
      });
      const peer = await createCurrentPeerServer(environment => createHandlerPlan(environment, { applicationBytes: 16384n,
        services: { ...peerServices, profile: "services" }, streams: [] }), "https://app.example", {
        applicationProfile: "services", carrier, serverName: "127.0.0.1", onAuthenticated: () => { published++; },
      });
      try {
        if (boundary === "late result") {
          const options = { ...peer.acceptor.addresses()[0]!, serverName: "127.0.0.1", path: "direct" as const, tlsMode: "ca" as const,
            trustRootsDer: [new Uint8Array(new X509Certificate(peer.trustPEM).raw)], inboundBidirectionalStreamCapacity: peerRawQUICCapacity + 1,
            readBufferBytes: 16384, datagramQueueBytes: 65536, handshakeTimeoutMs: 3000 };
          const driver = loadCurrentNativeTransport();
          client = await (carrier === "raw-quic" ? driver.connectRawQuic(options) : driver.connectWebTransport({ ...options,
            connectPath: "/flowersec/webtransport/v4/direct", tuple: "native_h3", headerBytes: 16384, controlBytes: 65536 })).result();
          await entered.promise;
        }
        const queued = peer.acceptor.accept(), rejected = expect(queued).rejects.toMatchObject({ code: "closed" });
        const drain = peer.acceptor.drain()[0]!; await rejected; await entered.promise;
        expect((await drain.wait()).outcome).toBe("drained");
        expect(peer.acceptor.cleanupStatus().core_cleanup).toBe("pending");
        const root = originalEnvironment(peer.environment).resources.root, held = root.snapshot().reservations;
        expect(accepts).toBe(1); expect(published).toBe(0);
        release.resolve();
        if (boundary === "late result") {
          await physicalExit.promise;
          expect(rawAborts).toBe(1); expect(peer.acceptor.cleanupStatus().core_cleanup).toBe("pending");
          expect(root.snapshot().reservations).toBe(held); releasePhysicalExit.resolve();
        }
        await expect.poll(() => peer.acceptor.cleanupStatus(), { timeout: 5000 }).toEqual(complete);
        expect(root.snapshot().reservations).toBeLessThan(held); expect(published).toBe(0); expect(accepts).toBe(1);
      } finally {
        release.resolve(); releasePhysicalExit.resolve(); client?.abort(); native?.abort();
        await client?.waitTermination(); await peer.close(); binding.mockRestore();
      }
    }, 15000);
  }

  test(`public native ${carrier} Close owns a late bind until physical termination`, async () => {
    const bound = deferred<void>(), release = deferred<void>(), terminated = deferred<void>(), releaseTermination = deferred<void>();
    const originalBind = nativeTransport.bindCurrentNativeListener;
    let environment: Parameters<typeof createHandlerPlan>[0] | undefined, native: NativeRawListener | undefined, aborts = 0, accepts = 0;
    const binding = vi.spyOn(nativeTransport, "bindCurrentNativeListener").mockImplementation(async (...args) => {
      native = await originalBind(...args); const listener = native;
      const termination = listener.waitTermination().then(async () => { terminated.resolve(); await releaseTermination.promise; });
      bound.resolve(); await release.promise;
      return { ...listener, abort: () => { aborts++; listener.abort(); }, waitTermination: () => termination,
        accept: () => { accepts++; return listener.accept(); } };
    });
    const starting = createCurrentPeerServer(owner => { environment = owner; return createHandlerPlan(owner, {
      applicationBytes: 16384n, services: { ...peerServices, profile: "services" }, streams: [],
    }); }, "https://app.example", { applicationProfile: "services", carrier, serverName: "127.0.0.1" });
    const rejected = expect(starting).rejects.toThrow();
    try {
      await bound.promise;
      const closing = environment!.close(); void closing.catch(() => undefined);
      release.resolve(); await terminated.promise;
      expect(aborts).toBe(1); expect(accepts).toBe(0);
      expect(environment!.cleanupStatus().status).not.toBe("complete");
      releaseTermination.resolve(); await rejected; await closing;
      expect(environment!.cleanupStatus()).toEqual(complete);
    } finally {
      release.resolve(); releaseTermination.resolve(); native?.abort();
      await starting.then(peer => peer.close(), () => undefined); binding.mockRestore();
    }
  }, 15000);
}
