import { createPrivateKey, randomBytes, X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHTTPSServer } from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Socket } from "node:net";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  ClockRate, ResourceRoot, ResourceVector, createAcceptor, createSQLitePoolBacking,
  createTransportEnvironment, openSQLiteAdmissionStore,
  type Acceptor, type AcceptorOptions, type AuthenticatedRequestContext, type HandlerPlan, type SQLiteAdmissionStore, type SQLitePoolBacking, type TransportEnvironment,
} from "../node/index.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { CredentialWork, credentialWorkCharge, equalCredential } from "../v4/runtime/credentialSupport.js";
import { credentialFixture, fill, map, text, u, bytes, digest, array, encode, get, type CredentialFixture } from "../v4/testSupport/credentials.js";
import { testCertificatePEM, testPrivateKeyPEM } from "../testSupport/tlsFixture.js";
import { peerBytes, peerLimits, peerRawQUICCapacity, type CurrentPeerMaterial } from "./currentPeer.js";
import type { Value } from "../v4/testSupport/cbor.js";

const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
const cleaned = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64");
const configuredKey = (seed: number, noise = false) => createPrivateKey({ key: Buffer.concat([
  Buffer.from(noise ? "302e020100300506032b656e04220420" : "302e020100300506032b657004220420", "hex"), fill(seed),
]), format: "der", type: "pkcs8" });

/** Independently configured engineering authority. This module is never an SDK
 * package entry, a key locator, or an application-supplied spend implementation. */
export interface CurrentPeerServerOptions {
  readonly applicationProfile?: "services";
  readonly carrier?: "websocket" | "raw-quic" | "webtransport";
  readonly serverName?: "localhost" | "127.0.0.1";
  readonly routeLeg?: Value | ((address: Readonly<{ host: string; port: number }>, materialIndex: number) => Value);
  readonly candidateLegs?: readonly Value[] | ((address: Readonly<{ host: string; port: number }>) => readonly Value[]);
  readonly materialCount?: number;
  readonly listenerTLS?: Readonly<{ certificatePEM: string; privateKeyPEM: string }>;
  readonly onAuthenticated?: (context: AuthenticatedRequestContext) => void;
  readonly authorizeRequest?: AcceptorOptions["authorizeRequest"];
  readonly resolveHandlers?: AcceptorOptions["resolveHandlers"];
  readonly authorizeApplication?: AcceptorOptions["authorizeApplication"];
  readonly release?: AcceptorOptions["release"];
  readonly ingress?: Readonly<{ positions: number; handshakeMS: bigint; drainMS: bigint; cleanupMS: bigint }>;
  readonly acceptorCleanupMS?: bigint;
}
export async function createCurrentPeerServer(buildPlan: (environment: TransportEnvironment) => HandlerPlan,
  origin = "https://app.example", options: CurrentPeerServerOptions = {}) {
  const timeOrigin = BigInt(Date.now()) - 1000n, beginning = performance.now();
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 5000n, 5000n, 5000n, 5000n, 5000n, 5000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 2048, reservations: 4096, references: 8192,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const environment = createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: randomBytes(16).toString("hex"),
    runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 4, sessions: 4, dependencies: 16, acquireMS: 10000n, cleanupMS: 10000,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 60000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - beginning)), incarnation: "3".repeat(32) }),
      initial: () => ({ lowerMS: timeOrigin + 1000n, upperMS: timeOrigin + 1000n }) }, random: output => { crypto.getRandomValues(output); } });
  const owner = originalEnvironment(environment), publicRoot = ed25519.getPublicKey(fill(7));
  const directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-ts-peer-server-"));
  const stores: SQLiteAdmissionStore[] = [], backings: SQLitePoolBacking[] = [];
  let acceptor: Acceptor | undefined, plan: HandlerPlan | undefined;
  let control: Awaited<ReturnType<typeof bootstrapServer>> | undefined;
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    await acceptor?.close(); plan?.close(); await control?.close(); await environment.close();
    for (const store of stores) store.close(); await Promise.all(stores.map(store => store.waitCleanup()));
    await environment.waitCleanup(); rmSync(directory, { recursive: true, force: true });
    for (const backing of backings) backing.releaseRemoved(); root.close();
  })();
  try {
    const namespace = owner.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: publicRoot,
      maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
    const authority = credentialFixture(owner.resources, owner.clock, (name, charge) => owner.reserveConnectionWork(name, charge),
      "preauthorized_pool", profile, namespace, { timeOrigin });
    authority.bootstrap();
    control = await bootstrapServer(environment, authority);
    const openBacking = (name: string) => {
      const backing = createSQLitePoolBacking(environment, join(directory, `${name}.sqlite`), { maxPages: 64, maxRecords: 4,
        maxRecordBytes: 65536, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
      backings.push(backing); return backing;
    };
    const binding = { tenant: "tenant", issuer: fill(5, 16), audience: "service", serverIdentity: digest("certificate_digest", authority.server) };
    const winner = await openSQLiteAdmissionStore(openBacking("winner"), { create: true, identity: { authority: "winner", storeID: fill(10), generation: 1n },
      continuity: { check: () => undefined }, bindings: [binding] }); stores.push(winner);
    const service = await openSQLiteAdmissionStore(openBacking("service"), { create: true, identity: { authority: "service", storeID: fill(11), generation: 1n },
      continuity: { check: () => undefined }, bindings: [binding], parentWinnerStore: winner }); stores.push(service);
    let materials: readonly CredentialFixture[] = [];
    const materialCount = options.materialCount ?? 1;
    if (!Number.isSafeInteger(materialCount) || materialCount < 1 || materialCount > 4) throw new Error("engineering material count exceeds its original store capacity");
    plan = buildPlan(environment); const declaredPlan = plan;
    const webTransport = options.carrier === "webtransport", raw = options.carrier === "raw-quic" || webTransport;
    const listenerTLS = options.listenerTLS ?? { certificatePEM: testCertificatePEM, privateKeyPEM: testPrivateKeyPEM };
    const credentials: AcceptorOptions["listeners"][number]["credentials"] = { source: "preauthorized_pool",
      policy: { tenant: "tenant", audience: "service", clientSubject: "client", serverSubject: "server", authorities: ["authority"], cryptoProfiles: [profile] },
      async resolve(request, destination) {
        if (request.signal.aborted || materials.length === 0) throw new Error("material unavailable");
        const reference = owner.reserveConnectionWork("engineering_material_selector", credentialWorkCharge(16384, owner.resources.runtimeBytes));
        let work: CredentialWork | undefined, selected: CredentialFixture | undefined, selectedCandidateIndex = -1;
        try {
          work = new CredentialWork(owner.resources, 16384, reference);
          const hello = work.parse(request.hello, "ClientHello", 16384);
          try {
            const expected = hello.bytes("artifact_digest"), candidateID = hello.bytes("candidate_id");
            try {
              selected = materials.find(entry => {
                const actual = digest("artifact_digest", entry.artifact);
                try {
                  if (!equalCredential(actual, expected)) return false;
                  const list = get(entry.artifact, 12); if (list.kind !== "array") return false;
                  const index = list.value.findIndex(candidate => { const id = get(candidate, 0); return id.kind === "bytes" && equalCredential(id.value, candidateID); });
                  if (index < 0) return false; selectedCandidateIndex = index; return true;
                } finally { actual.fill(0); }
              });
            } finally { expected.fill(0); candidateID.fill(0); }
          } finally { hello.close(); }
        } finally { work?.close(); reference.release(); }
        if (request.signal.aborted || selected === undefined) throw new Error("original issuer has no material for this selector");
        const input = selected.input();
        try {
          for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) destination[name].set(input[name]);
          return { artifact: input.artifact.length, activation: input.activation.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, candidateIndex: selectedCandidateIndex };
        } finally { for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) input[name].fill(0); }
      },
    };
    const serverName = options.serverName ?? "localhost";
    const common = { host: "127.0.0.1", port: 0, serverName, identityKey: configuredKey(15), noiseKey: configuredKey(17, true),
      admissionStore: service, limits: peerLimits, ingress: { callbackBytes: 16384n, ...(options.ingress ?? { positions: 4, handshakeMS: 10000n, drainMS: 10000n, cleanupMS: 10000n }) }, credentials };
    const nativeListener = {
      ...common, tls: { certificateChainDER: [new Uint8Array(new X509Certificate(listenerTLS.certificatePEM).raw)],
        privateKeyDER: new Uint8Array(createPrivateKey(listenerTLS.privateKeyPEM).export({ format: "der", type: "pkcs8" })) },
      carrier: { applicationStreams: peerRawQUICCapacity, streamBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n },
    };
    const listener: AcceptorOptions["listeners"][number] = webTransport ? {
      ...nativeListener, carrierKind: "webtransport", carrier: { ...nativeListener.carrier, headerBytes: 16384, controlBytes: 65536,
        tuples: ["native_h3"], allowedOrigins: [origin], allowAbsentOrigin: true },
    } : raw ? { ...nativeListener, carrierKind: "raw_quic" } : { ...common, tls: { certificate: listenerTLS.certificatePEM, privateKey: listenerTLS.privateKeyPEM },
      carrier: { queueMessages: 8, nativeBytes: 1048576n, prepareBytes: 262144 } };
    acceptor = await createAcceptor({ environment, maxPendingSessions: 4, maxPendingAccepts: 4, cleanupMS: options.acceptorCleanupMS ?? 10000n,
      listeners: [listener], authorizeRequest: options.authorizeRequest ?? (context => ({ allowed: raw ? context.origin === undefined || context.origin === "" : context.origin === origin })),
      resolveHandlers: context => { options.onAuthenticated?.(context); return options.resolveHandlers?.(context) ?? declaredPlan; },
      authorizeApplication: options.authorizeApplication ?? ((_context, handlers) => ({ decision: "authorized", handlers, lease: { close: () => undefined, waitCleanup: async () => cleaned } })),
      release: options.release ?? (() => cleaned),
    });
    const address = acceptor.addresses()[0]; if (address === undefined) throw new Error("engineering listener did not bind");
    const artifactJSONs: string[] = [], issued: CredentialFixture[] = [];
    for (let materialIndex = 0; materialIndex < materialCount; materialIndex++) {
      const installedLeg = typeof options.routeLeg === "function" ? options.routeLeg(Object.freeze({ ...address }), materialIndex) : options.routeLeg;
      const candidateLegs = typeof options.candidateLegs === "function" ? options.candidateLegs(Object.freeze({ ...address })) : options.candidateLegs;
      const leg = installedLeg ?? map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(webTransport ? 2 : raw ? 0 : 1), 6: text(serverName), 7: u(address.port),
        8: text(webTransport ? "/flowersec/webtransport/v4/direct" : raw ? "" : "/flowersec/v4/direct"), 9: text(webTransport ? "h3" : raw ? "flowersec-direct/4" : "http/1.1"), 10: text(raw ? "" : "flowersec.direct.v4"),
        11: map({ 0: u(0), 1: { kind: "bool", value: true } }),
        ...(raw && !webTransport ? {} : { 12: map({ 0: array(text(origin)), 1: { kind: "bool", value: webTransport } }) }) });
      const material = credentialFixture(owner.resources, owner.clock, () => { throw new Error("original Environment only"); },
        "preauthorized_pool", profile, namespace, { timeOrigin, leg, ...(candidateLegs === undefined ? {} : { candidateLegs }),
          connectionSeed: 22 + materialIndex * 4, datagram: raw, ...(options.applicationProfile === undefined ? {} : { applicationProfile: options.applicationProfile }) });
      issued.push(material);
      const route = encode(map({ 0: u(0), 1: bytes(fill(20, 16)), 2: candidateLegs?.[0] ?? leg })), input = material.input();
      try {
        const exported: CurrentPeerMaterial = {
          wire_revision: 4, profile, source: "preauthorized_pool", generation: { source: b64(randomBytes(16)), generation: materialIndex + 1 }, role: 0,
          artifact: b64(input.artifact), activation: b64(input.activation), client_certificate: b64(input.clientCertificate), server_certificate: b64(input.serverCertificate),
          route: b64(route), route_digest: b64(material.route), activation_signing_key_id: "activate-1", identity_seed: b64(fill(14)), dh_seed: b64(fill(16)),
          namespaces: [{ tenant: "tenant", authority: "authority", generation: 1, root_key_id: b64(fill(1, 16)), root_public_key: b64(publicRoot),
            bootstrap_url: control.url, state_url: control.url }], tunnels: [],
        };
        artifactJSONs.push(JSON.stringify(exported));
      } finally { for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) input[name].fill(0); route.fill(0); }
    }
    materials = Object.freeze(issued);
    return Object.freeze({ environment, acceptor, artifactJSON: artifactJSONs[0]!, artifactJSONs: Object.freeze(artifactJSONs),
      clientIdentity: Buffer.from(digest("certificate_digest", materials[0]!.client)).toString("hex"), trustPEM: testCertificatePEM, origin, close });
  } catch (error) { await close(); throw error; }
}

/** One dedicated finite HTTPS authority owner. Every bootstrap signs the
 * caller's fresh nonce; there are no static response blobs or nonce reuse. */
async function bootstrapServer(environment: TransportEnvironment, authority: CredentialFixture) {
  const owner = originalEnvironment(environment), dependency = owner.admitDependency("engineering_bootstrap_server",
    new ResourceVector([2097152n, 4n << 20n, 0n, 64n, 16n, 16n, 1n, 1n, 1n, 0n, 8n]));
  const sockets = new Set<Socket>(), writes = new Set<Promise<void>>();
  const server = createHTTPSServer({ key: testPrivateKeyPEM, cert: testCertificatePEM, minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
    maxHeaderSize: 4096, handshakeTimeout: 5000, requestTimeout: 5000, headersTimeout: 5000 }, (request, response) => {
    if (request.method !== "POST" || request.url !== "/flowersec/v4/trust/bootstrap" || request.headers["content-encoding"] !== undefined) {
      response.writeHead(400, { connection: "close" }); response.end(); return;
    }
    const input = Buffer.alloc(1024); let count = 0;
    request.on("error", () => { input.fill(0); response.destroy(); });
    request.on("data", (chunk: Buffer) => {
      if (chunk.length > input.length - count) { input.fill(0); request.destroy(); return; }
      input.set(chunk, count); count += chunk.length;
    });
    request.once("end", () => {
      let nonce: Uint8Array | undefined;
      try {
        dependency.check(); if (!request.complete) throw new Error("truncated bootstrap request");
        const record = JSON.parse(input.subarray(0, count).toString("utf8")) as { tenant?: unknown; authority?: unknown; nonce?: unknown };
        if (record.tenant !== "tenant" || record.authority !== "authority" || typeof record.nonce !== "string") throw new Error("unknown bootstrap namespace");
        nonce = peerBytes(record.nonce, 32, 32);
        const signed = authority.response(nonce), state = encode(authority.state);
        const output = Buffer.from(JSON.stringify({ response: b64(signed), state: b64(state) })); signed.fill(0); state.fill(0);
        if (output.length > 131072) { output.fill(0); throw new Error("bootstrap response exceeds declared capacity"); }
        response.writeHead(200, { "content-type": "application/json", "content-length": String(output.length), connection: "close" });
        let done!: () => void;
        const actual = new Promise<void>(resolve => { done = resolve; }); writes.add(actual);
        void actual.then(() => writes.delete(actual));
        const finished = () => { output.fill(0); done(); };
        response.once("close", finished);
        try { response.end(output, finished); }
        catch (error) { finished(); throw error; }
      } catch { response.destroy(); }
      finally { input.fill(0); nonce?.fill(0); }
    });
  });
  server.maxConnections = 4; server.maxHeadersCount = 16; server.maxRequestsPerSocket = 1; server.setTimeout(5000, socket => socket.destroy());
  server.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  let closing: Promise<void> | undefined;
  const close = () => closing ??= (async () => {
    const actual = new Promise<void>(resolve => server.close(() => resolve()));
    for (const socket of sockets) socket.destroy(); await actual; await Promise.all(writes); dependency.release();
  })();
  dependency.onClose(() => { void close(); });
  try {
    await new Promise<void>((resolve, reject) => {
      const failed = (error: Error) => { server.removeListener("listening", ready); reject(error); };
      const ready = () => { server.removeListener("error", failed); resolve(); };
      server.once("error", failed); server.once("listening", ready); server.listen(0, "127.0.0.1");
    });
    const address = server.address(); if (address === null || typeof address === "string") throw new Error("bootstrap listener did not bind");
    dependency.check();
    return Object.freeze({ url: `https://localhost:${address.port}/flowersec/v4/trust/bootstrap`, close });
  } catch (error) { await close(); throw error; }
}
