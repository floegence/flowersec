import { createPrivateKey, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ClockRate, ResourceRoot, ResourceVector, configureNodeWSS, connect, createAcceptor,
  createSQLitePoolBacking, createTransportEnvironment, openSQLiteAdmissionStore, openSQLitePoolStore,
  type Acceptor, type HandlerPlan, type SQLiteAdmissionStore, type SQLitePoolBacking, type SQLitePoolStore,
  type TransportEnvironment,
} from "../../node/index.js";
import { originalEnvironment } from "../runtime/environment.js";
import { credentialFixture, fill, map, text, u, bytes, digest, array, type CredentialFixture } from "./credentials.js";
import { testCertificatePEM, testPrivateKeyPEM } from "../../testSupport/tlsFixture.js";

const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
const cleaned = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
const limits = Object.freeze({ maxFrame: 65536, maxStreams: 18, receiveQueueBytes: 16384, maxDataBytes: 4096, maxCursorBytes: 65536, maxWriteBytes: 65536,
  writeDeadlineMS: 10000n, operationDeadlineMS: 10000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n, cryptoKeys: 100 });
function environment(timeOrigin: bigint) {
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 5000n, 5000n, 5000n, 5000n, 5000n, 5000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 2048, reservations: 4096, references: 8192,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const beginning = performance.now();
  const publicOwner = createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: randomBytes(16).toString("hex"),
    runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 4, sessions: 4, dependencies: 16, acquireMS: 10000n, cleanupMS: 10000,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 60000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - beginning)), incarnation: "3".repeat(32) }),
      initial: () => ({ lowerMS: timeOrigin + 1000n, upperMS: timeOrigin + 1000n }) }, random: bytes => { crypto.getRandomValues(bytes); } });
  return { root, publicOwner, owner: originalEnvironment(publicOwner) };
}
function fixture(env: ReturnType<typeof environment>, timeOrigin: bigint) {
  const result = credentialFixture(env.owner.resources, env.owner.clock, (name, charge) => env.owner.reserveConnectionWork(name, charge), "preauthorized_pool", profile,
    env.owner.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: publicRoot,
      maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 }), { timeOrigin });
  result.bootstrap(); return result;
}
// Independent engineering authority/root; never configured from peer messages.
import { ed25519 } from "@noble/curves/ed25519.js";
const publicRoot = ed25519.getPublicKey(fill(7));
const key = (seed: number, algorithm: "identity" | "noise") => createPrivateKey({ key: Buffer.concat([
  Buffer.from(algorithm === "identity" ? "302e020100300506032b657004220420" : "302e020100300506032b656e04220420", "hex"), fill(seed),
]), format: "der", type: "pkcs8" });

/** Real ordinary default Session/Acceptor owners and stores. The fixture's
 * fresh physical databases live outside the repository and platform tmp roots. */
export async function createCurrentNodeSession(buildPlan: (environment: TransportEnvironment) => HandlerPlan, origin = "https://app.example",
  options: Readonly<{ clientPlan?: (environment: TransportEnvironment) => HandlerPlan; closeClientPlanAfterConfigure?: boolean; applicationProfile?: "services"; onSourceAcquire?: () => void }> = {}) {
  const timeOrigin = BigInt(Date.now()) - 1000n, a = environment(timeOrigin), b = environment(timeOrigin);
  const directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../../..", import.meta.url))), "flowersec-node-session-"));
  const backings: SQLitePoolBacking[] = [], stores: (SQLitePoolStore | SQLiteAdmissionStore)[] = [];
  let acceptor: Acceptor | undefined, plan: HandlerPlan | undefined, clientPlan: HandlerPlan | undefined;
  const close = async () => {
    await acceptor?.close(); plan?.close(); clientPlan?.close();
    await Promise.all([a.publicOwner.close(), b.publicOwner.close()]);
    for (const store of stores) store.close(); await Promise.all(stores.map(store => store.waitCleanup()));
    await Promise.all([a.publicOwner.waitCleanup(), b.publicOwner.waitCleanup()]);
    rmSync(directory, { recursive: true, force: true }); for (const backing of backings) backing.releaseRemoved();
    a.root.close(); b.root.close();
  };
  try {
    const first = fixture(a, timeOrigin), second = fixture(b, timeOrigin);
    const policy = { tenant: "tenant", audience: "service", clientSubject: "client", serverSubject: "server", authorities: ["authority"], cryptoProfiles: [profile] };
    const openBacking = (name: string) => {
      const backing = createSQLitePoolBacking(name === "spend" ? a.publicOwner : b.publicOwner, join(directory, `${name}.sqlite`),
        { maxPages: 64, maxRecords: 4, maxRecordBytes: 65536, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
      backings.push(backing); return backing;
    };
    const pool = await openSQLitePoolStore(openBacking("spend"), { create: true, identity: { authority: "spend", storeID: fill(9), generation: 1n },
      continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16) }] }); stores.push(pool);
    const binding = { tenant: "tenant", issuer: fill(5, 16), audience: "service", serverIdentity: digest("certificate_digest", second.server) };
    const winner = await openSQLiteAdmissionStore(openBacking("winner"), { create: true, identity: { authority: "winner", storeID: fill(10), generation: 1n },
      continuity: { check: () => undefined }, bindings: [binding] }); stores.push(winner);
    const service = await openSQLiteAdmissionStore(openBacking("service"), { create: true, identity: { authority: "service", storeID: fill(11), generation: 1n },
      continuity: { check: () => undefined }, bindings: [binding], parentWinnerStore: winner }); stores.push(service);
    let serverCredentials: CredentialFixture | undefined;
    plan = buildPlan(b.publicOwner); const declaredPlan = plan;
    acceptor = await createAcceptor({ environment: b.publicOwner, maxPendingSessions: 4, maxPendingAccepts: 4, cleanupMS: 10000n,
      listeners: [{ host: "127.0.0.1", port: 0, serverName: "localhost", tls: { certificate: testCertificatePEM, privateKey: testPrivateKeyPEM },
        identityKey: key(15, "identity"), noiseKey: key(17, "noise"), admissionStore: service, limits,
        ingress: { positions: 4, callbackBytes: 16384n, handshakeMS: 10000n, drainMS: 10000n, cleanupMS: 10000n },
        carrier: { queueMessages: 8, nativeBytes: 1048576n, prepareBytes: 262144 }, credentials: { source: "preauthorized_pool", policy,
          async resolve(request, destination) {
            if (request.signal.aborted || serverCredentials === undefined) throw new Error("material unavailable");
            const input = serverCredentials.input();
            for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) destination[name].set(input[name]);
            return { artifact: input.artifact.length, activation: input.activation.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, candidateIndex: 0 };
          },
        },
      }], authorizeRequest: context => ({ allowed: context.origin === origin }), resolveHandlers: () => declaredPlan,
      authorizeApplication: (_context, handlers) => ({ decision: "authorized", handlers, lease: { close: () => undefined, waitCleanup: async () => cleaned } }),
      release: () => cleaned,
    });
    const address = acceptor.addresses()[0]!;
    const leg = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("localhost"), 7: u(address.port),
      8: text("/flowersec/v4/direct"), 9: text("http/1.1"), 10: text("flowersec.direct.v4"), 11: map({ 0: u(0), 1: { kind: "bool", value: true } }),
      12: map({ 0: array(text(origin)), 1: { kind: "bool", value: false } }) });
    const clientCredentials = credentialFixture(a.owner.resources, a.owner.clock, () => { throw new Error("original Environment only"); }, "preauthorized_pool", profile, first.namespace, { timeOrigin, leg, ...(options.applicationProfile === undefined ? {} : { applicationProfile: options.applicationProfile }) });
    serverCredentials = credentialFixture(b.owner.resources, b.owner.clock, () => { throw new Error("original Environment only"); }, "preauthorized_pool", profile, second.namespace, { timeOrigin, leg, ...(options.applicationProfile === undefined ? {} : { applicationProfile: options.applicationProfile }) });
    clientPlan = options.clientPlan?.(a.publicOwner);
    const connector = configureNodeWSS(a.publicOwner, { identityKey: key(14, "identity"), noiseKey: key(16, "noise"), poolStore: pool, limits,
      carrier: { remoteAddress: "127.0.0.1", origin, ca: [testCertificatePEM], queueMessages: 8, runtimeBytes: 1024n, nativeBytes: 1048576n, prepareBytes: 262144 },
      ...(clientPlan === undefined ? {} : { handlerPlan: clientPlan }) });
    if (options.closeClientPlanAfterConfigure) clientPlan?.close();
    const source = connector.registerPoolSource(policy, async (request, destination) => {
      if (request.signal.aborted) throw new Error("canceled"); options.onSourceAcquire?.(); const input = clientCredentials.input();
      for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, activation: input.activation.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, candidateIndex: 0 };
    });
    const acceptedPromise = acceptor.accept();
    void acceptedPromise.catch(() => undefined);
    const session = await connect(a.publicOwner, source, { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: true });
    const accepted = await acceptedPromise;
    let closing: Promise<void> | undefined;
    return Object.freeze({ session, accepted, acceptor, poolStore: pool, clientEnvironment: a.publicOwner, serverEnvironment: b.publicOwner,
      close: () => closing ??= close() });
  } catch (error) { await close(); throw error; }
}
