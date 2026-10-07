import { expect } from "@playwright/test";
import { createPrivateKey } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  ResourceRoot, ResourceVector, ClockRate, createTransportEnvironment, createAcceptor,
  createHandlerPlan, createSQLitePoolBacking, openSQLiteAdmissionStore, ProxyServer,
  type Acceptor, type AcceptorOptions, type HandlerPlan, type SQLiteAdmissionStore, type SQLitePoolBacking,
} from "../src/node/index.js";
import { originalEnvironment } from "../src/v4/runtime/environment.js";
import { credentialFixture, fill, map, bytes, text, u, array, encode, digest } from "../src/v4/testSupport/credentials.js";
import type { Value } from "../src/v4/testSupport/cbor.js";
import type { NoiseProfile } from "../src/v4/runtime/noiseHandshake.js";
import { peerLimits } from "../src/interop/currentPeer.js";

function environment(timeOrigin: bigint) {
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 2000n, 2000n, 2000n, 2000n, 2000n, 2000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 256, reservations: 1024, references: 2048,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n }), start = performance.now();
  const publicOwner = createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 4, sessions: 4, dependencies: 24, acquireMS: 10000n, cleanupMS: 10000,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - start)), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: timeOrigin + 1000n, upperMS: timeOrigin + 1000n }) },
    random: bytes => { crypto.getRandomValues(bytes); } });
  return { root, publicOwner, owner: originalEnvironment(publicOwner) };
}
function credentials(env: ReturnType<typeof environment>, profile: NoiseProfile, leg: Value, timeOrigin: bigint) {
  const ns = env.owner.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)), maxTrustLifetimeMS: 120000n,
    bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
  const result = credentialFixture(env.owner.resources, env.owner.clock, () => { throw new Error("original Environment only"); }, "preauthorized_pool", profile, ns, { timeOrigin, leg });
  result.bootstrap(); return result;
}
export function createV4WSSPeerFixture(origin: string, port: number, profile: NoiseProfile, requireConsumer = false) {
  const timeOrigin = BigInt(Date.now()) - 1000n, env = environment(timeOrigin);
  const leg = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("localhost"), 7: u(port), 8: text("/flowersec/v4/direct"), 9: text("http/1.1"),
    10: text("flowersec.direct.v4"), 11: map({ 0: u(0), 1: { kind: "bool", value: requireConsumer } }), 12: map({ 0: array(text(origin)), 1: { kind: "bool", value: false } }) });
  return { timeOrigin, env, fixture: credentials(env, profile, leg, timeOrigin) };
}

/** Browser fixtures use the same current listener, durable admission and
 * handler owners as ordinary Node applications. Only signed test credentials
 * and bootstrap state are supplied by this engineering authority. */
export async function startV4WSSPeer(certificate: Buffer, key: Buffer, origin: string, profile: NoiseProfile, requireConsumer = false, proxyUpstream?: string) {
  const { timeOrigin, env, fixture: authority } = createV4WSSPeerFixture(origin, 1, profile, requireConsumer);
  const directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../..", import.meta.url))), "flowersec-browser-current-peer-"));
  const stores: SQLiteAdmissionStore[] = [], backings: SQLitePoolBacking[] = [], jobs: Promise<void>[] = [];
  const abort = new AbortController(), proxyErrors: unknown[] = [];
  let acceptor: Acceptor | undefined, plan: HandlerPlan | undefined, failure: unknown, connections = 0, hellos = 0, closing: Promise<void> | undefined;
  const proxy = proxyUpstream === undefined ? undefined : new ProxyServer({ upstream: proxyUpstream, upstreamOrigin: proxyUpstream,
    allowedOrigins: [origin], maxConcurrentStreams: 4, maxBodyBytes: 4096, maxChunkBytes: 64, maxJsonFrameBytes: 4096, maxWebSocketFrameBytes: 32,
    onError: error => proxyErrors.push(error) });
  const close = (): Promise<void> => closing ??= (async () => {
    abort.abort(); await acceptor?.close(); await Promise.allSettled(jobs); plan?.close(); await proxy?.close();
    await env.publicOwner.close(); for (const store of stores) store.close(); await Promise.all(stores.map(store => store.waitCleanup()));
    const cleanup = await env.publicOwner.waitCleanup(); rmSync(directory, { recursive: true, force: true }); for (const backing of backings) backing.releaseRemoved();
    expect(cleanup.status).toBe("complete"); expect(env.root.snapshot().reservations).toBe(0); env.root.close();
  })();
  try {
    const openBacking = (name: string): SQLitePoolBacking => {
      const backing = createSQLitePoolBacking(env.publicOwner, join(directory, `${name}.sqlite`), { maxPages: 128, maxRecords: 16, maxRecordBytes: 65536,
        runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n }); backings.push(backing); return backing;
    };
    const binding = { tenant: "tenant", issuer: fill(5, 16), audience: "service", serverIdentity: digest("certificate_digest", authority.server) };
    const winner = await openSQLiteAdmissionStore(openBacking("winner"), { create: true, identity: { authority: "winner", storeID: fill(10), generation: 1n }, continuity: { check: () => undefined }, bindings: [binding] }); stores.push(winner);
    const admission = await openSQLiteAdmissionStore(openBacking("service"), { create: true, identity: { authority: "service", storeID: fill(11), generation: 1n }, continuity: { check: () => undefined }, bindings: [binding], parentWinnerStore: winner }); stores.push(admission);
    plan = proxy === undefined ? createHandlerPlan(env.publicOwner, { applicationBytes: 1024n, streams: ["example/browser-v4", "example/websocket"].map(kind => ({ kind, options: { applicationBytes: 1024n },
      handler: async (stream, context) => { try { const received = await stream.read(32n, { signal: context.signal }); await stream.write(received.data, { signal: context.signal }); } catch (error) { if (!context.signal.aborted) failure = error; throw error; } } })) })
      : proxy.register(env.publicOwner, { applicationBytes: 1024n, authorize: (_context, metadata) => metadata.values.version === 2 && ["flowersec.proxy.http", "flowersec.proxy.websocket"].includes(String(metadata.values.protocol)) });
    const handlers = plan;
    const identityKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), fill(15)]), format: "der", type: "pkcs8" });
    const noiseKey = profile.includes("x25519") ? createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), fill(17)]), format: "der", type: "pkcs8" })
      : createPrivateKey({ key: Buffer.concat([Buffer.from("30310201010420", "hex"), fill(17), Buffer.from("a00a06082a8648ce3d030107", "hex")]), format: "der", type: "sec1" });
    let material: ReturnType<typeof credentials> | undefined;
    const listener: AcceptorOptions["listeners"][number] = { host: "127.0.0.1", port: 0, serverName: "localhost", tls: { certificate: certificate.toString(), privateKey: key.toString() }, identityKey, noiseKey,
      admissionStore: admission, limits: { ...peerLimits, maxDataBytes: 128, receiveQueueBytes: 256, maxWriteBytes: 1024, maxCursorBytes: 1024 },
      ingress: { positions: 4, callbackBytes: 16384n, handshakeMS: 10000n, drainMS: 10000n, cleanupMS: 10000n }, carrier: { queueMessages: 8, nativeBytes: 1048576n, prepareBytes: 262144, runtimeBytes: 1024n },
      credentials: { source: "preauthorized_pool", policy: { tenant: "tenant", audience: "service", clientSubject: "client", serverSubject: "server", authorities: ["authority"], cryptoProfiles: [profile] },
        resolve: async (request, buffers) => {
          if (request.signal.aborted || material === undefined) throw new Error("material_unavailable"); hellos++;
          const input = material.input(); try { for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) buffers[name].set(input[name]);
            return { artifact: input.artifact.length, activation: input.activation.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, candidateIndex: 0 };
          } finally { for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) input[name].fill(0); }
        } } };
    const cleaned = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
    acceptor = await createAcceptor({ environment: env.publicOwner, listeners: [listener], maxPendingSessions: 4, maxPendingAccepts: 4, cleanupMS: 10000n,
      authorizeRequest: context => { if (context.origin !== origin) return { allowed: false }; connections++; return { allowed: true }; }, resolveHandlers: () => handlers,
      authorizeApplication: (_context, declared) => ({ decision: "authorized", handlers: declared, lease: { close: () => undefined, waitCleanup: async () => cleaned } }), release: () => cleaned });
    const address = acceptor.addresses()[0]; if (address === undefined) throw new Error("listener_unavailable");
    const leg = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("localhost"), 7: u(address.port), 8: text("/flowersec/v4/direct"), 9: text("http/1.1"),
      10: text("flowersec.direct.v4"), 11: map({ 0: u(0), 1: { kind: "bool", value: requireConsumer } }), 12: map({ 0: array(text(origin)), 1: { kind: "bool", value: false } }) });
    material = credentialFixture(env.owner.resources, env.owner.clock, () => { throw new Error("original Environment only"); }, "preauthorized_pool", profile, authority.namespace, { timeOrigin, leg });
    const original = acceptor;
    const accepting = (async () => { while (!abort.signal.aborted) {
      const accepted = await original.accept({ signal: abort.signal });
      const job = accepted.serve({ signal: abort.signal }).catch(error => { if (!abort.signal.aborted) failure = error; }).finally(async () => { await accepted.close(); }); jobs.push(job);
    } })().catch(error => { if (!abort.signal.aborted) failure = error; }); jobs.push(accepting);
    const fixture = material, input = fixture.input();
    const result = { endpoint: `wss://localhost:${address.port}/flowersec/v4/direct`, timeOrigin: timeOrigin.toString(), route: Array.from(fixture.route), profile,
      input: { artifact: Array.from(input.artifact), clientCertificate: Array.from(input.clientCertificate), serverCertificate: Array.from(input.serverCertificate), activation: Array.from(input.activation), candidateIndex: 0 },
      bootstrap: (nonce: number[]) => ({ response: Array.from(fixture.response(new Uint8Array(nonce))), state: Array.from(encode(fixture.state)) }),
      counts: () => ({ connections, hellos }), proxyActiveCount: () => proxy?.activeCount ?? 0, proxyErrors: () => proxyErrors, failure: () => failure, close };
    for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) input[name].fill(0);
    return result;
  } catch (error) { await close(); throw error; }
}
