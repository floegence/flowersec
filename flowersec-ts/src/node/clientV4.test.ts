import { MethodDefinition as V4MethodDefinition, ServiceDefinition as V4ServiceDefinition, utf8MessageCodec as v4UTF8MessageCodec, createNodeWSSListener, createHandlerPlan, type ServeHandle, type Session as V4Session, type ServeCallbacks, type HandlerPlan, type TransportEnvironment as V4TransportEnvironment, type RawStreamHandler as V4RawStreamHandler, type StreamOpenAuthorizer as V4StreamOpenAuthorizer } from "./index.js";
import { DatabaseSync } from "node:sqlite";
import { SQLiteWorkerDatabase, SQLiteWorkerError } from "./sqliteWorkerV4.js";
import { openSQLiteAdmissionStore, type SQLiteAdmissionStore } from "./sqliteAdmission.js";
import { ServeIngress } from "../v4/runtime/serveGroup.js";
import { ServerAdmissionExchange, serverAdmissionCharge } from "../v4/runtime/serverAdmission.js";
import { reliableServerSpec } from "../v4/runtime/serverSessionSpec.js";
import { NodeWSSCarrier, nodeWSSAdmissionCosts } from "./wssV4.js";
import { configureNodeRawQUIC } from "./clientV4.js";
import * as nativeBinding from "./nativeTransportCurrent.js";
import type { NativePreparationLimits, NativeOperation, NativeRawStream, NativeWebTransportSession, NativeTransportBinding } from "./nativeTransportCurrent.js";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createHash, createPrivateKey, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createServer } from "node:https";
import { createServer as createHTTPServer } from "node:http";
import { once } from "node:events";
import { promiseHooks } from "node:v8";
import { TLSSocket, type ConnectionOptions } from "node:tls";
import WebSocket, { WebSocketServer } from "ws";
import { ed25519 } from "@noble/curves/ed25519.js";
import type { OperationOptions } from "../public/contract.js";
import { configureNodeWSS as configureV4NodeWSS, connect, connectMaterial } from "./index.js";
import { createV4SQLitePoolBacking, openV4SQLitePoolStore } from "./sqlitePoolV4.js";
import { createV4TransportEnvironment, originalEnvironment, type V4EnvironmentSessionSpec } from "../v4/runtime/environment.js";
import { ResourceRoot, ResourceVector, type ResourceAccount, type ResourceReference } from "../v4/runtime/resources.js";
import { ClockRate } from "../v4/runtime/timeArithmetic.js";
import { credentialFixture, fill, map, bytes, text, u, array, get, encode, digest, sign } from "../v4/testSupport/credentials.js";
import { Reference, type Value } from "../v4/testSupport/cbor.js";
import { wire } from "../v4/runtime/wireRegistry.js";
import { wireDomains } from "../v4/runtime/schemaRegistry.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import type { NoiseProfile } from "../v4/runtime/noiseHandshake.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { ProxyServer } from "./proxyServer.js";
import { connectProxyBrowser, type ProxyBrowserHandle } from "../proxy/index.js";
import { currentProxyStream } from "../proxy/currentStream.js";
import { ProxyByteReader, writeAll } from "../proxy/stream.js";
import { readProxyFrame, writeProxyFrame } from "../proxy/wire.js";
import { u32be, readU32be } from "../utils/bin.js";
import { createStreamMetadata } from "../public/streamMetadata.js";

const profileX = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", profileP = "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1";
const request = { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: true };
const transportLimits = {
  maxFrame: 65536, maxStreams: 8, receiveQueueBytes: 256, maxDataBytes: 128, maxCursorBytes: 1024, maxWriteBytes: 1024,
  writeDeadlineMS: 1000n, operationDeadlineMS: 1000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n, cryptoKeys: 100
};
const reference = new Reference();
const buffer = (value: Value): Uint8Array => { if (value.kind !== "bytes") throw new Error("expected bytes"); return value.value; };
function decode(bytes: Uint8Array): Value { const result = reference.decode(bytes, "", {}, 65536n); if (!result.ok) throw new Error(result.error); return result.value; }
function envelope(name: string, payload: Uint8Array): Uint8Array { const out = new Uint8Array(payload.length + 8); new DataView(out.buffer).setUint32(0, payload.length); out[4] = wire.frame_types[name]!; out.set(payload, 8); return out; }
function parseMessage(bytes: Uint8Array, name: string): Uint8Array {
  expect(bytes.length).toBeGreaterThanOrEqual(8); expect(bytes[4]).toBe(wire.frame_types[name]); expect(bytes.subarray(5, 8)).toEqual(new Uint8Array(3));
  expect(new DataView(bytes.buffer, bytes.byteOffset).getUint32(0)).toBe(bytes.length - 8); return bytes.subarray(8);
}
class ServerTransport implements V4AuthenticatedTransport {
  readonly role = "server" as const; readonly mode = "message" as const;
  readonly queue: Uint8Array[] = []; waiter: ((value: Uint8Array | null) => void) | undefined;
  readonly done: Promise<void>; closed = false;
  constructor(readonly ws: WebSocket) {
    this.done = new Promise(resolve => ws.once("close", () => { this.closed = true; this.waiter?.(null); this.waiter = undefined; resolve(); }));
    ws.on("error", () => undefined); ws.on("message", (value, binary) => {
      expect(binary).toBe(true); if (!Buffer.isBuffer(value)) throw new Error("native binary"); const bytes = new Uint8Array(value), waiter = this.waiter;
      if (waiter !== undefined) { this.waiter = undefined; waiter(bytes); } else this.queue.push(bytes);
    });
  }
  read(_max: number, _options?: OperationOptions): Promise<Uint8Array | null> { if (this.queue.length) return Promise.resolve(this.queue.shift()!); if (this.closed) return Promise.resolve(null); return new Promise(resolve => { this.waiter = resolve; }); }
  async write(data: Uint8Array): Promise<number> { const result = this.submit(data, () => undefined); if (result === undefined) throw new Error("closed"); await result.completion; return data.length; }
  submit(data: Uint8Array, admitted: () => void): { completion: Promise<void> } | undefined {
    if (this.ws.readyState !== WebSocket.OPEN) return undefined; admitted(); return { completion: new Promise((resolve, reject) => this.ws.send(data, error => error ? reject(error) : resolve())) };
  }
  close(): Promise<void> { this.ws.terminate(); return this.done; }
  waitTermination(): Promise<void> { return this.done; }
}
function environment(timeOrigin: bigint, services = false) {
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 2000n, 2000n, 2000n, 2000n, 2000n, 2000n]);
  const root = new ResourceRoot({
    profileRevision: "1".repeat(64), limit, accounts: services ? 2048 : 32, reservations: services ? 4096 : 256, references: services ? 8192 : 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n
  }), start = performance.now();
  const publicOwner = createV4TransportEnvironment({
    root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 50,
    clock: {
      profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - start)), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: timeOrigin + 1000n, upperMS: timeOrigin + 1000n })
    },
    random: bytes => { crypto.getRandomValues(bytes); }
  });
  return { root, publicOwner, owner: originalEnvironment(publicOwner) };
}
function credentials(env: ReturnType<typeof environment>, profile: NoiseProfile, leg: Value, timeOrigin: bigint, services = false) {
  const ns = env.owner.namespace({
    tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)), maxTrustLifetimeMS: 120000n,
    bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384
  });
  const result = credentialFixture(env.owner.resources, env.owner.clock, () => { throw new Error("original Environment only"); }, "preauthorized_pool", profile, ns, { timeOrigin, leg, ...(services ? { applicationProfile: "services" as const } : {}) });
  result.bootstrap(); return result;
}
function noiseKey(profile: NoiseProfile) {
  if (profile === profileX) return createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), fill(16)]), format: "der", type: "pkcs8" });
  // SEC1 uses the same deterministic scalar as the signed test certificate.
  return createPrivateKey({ key: Buffer.concat([Buffer.from("30310201010420", "hex"), fill(16), Buffer.from("a00a06082a8648ce3d030107", "hex")]), format: "der", type: "sec1" });
}
function serverSpec(env: ReturnType<typeof environment>, fixture: ReturnType<typeof credentials>, transport: ServerTransport, profile: NoiseProfile, fsb: Uint8Array, fsa: Value, context: Value, timeOrigin: bigint): V4EnvironmentSessionSpec {
  const c = digest("certificate_digest", fixture.client), s = digest("certificate_digest", fixture.server), contextDigest = digest("transport_context_digest", context), binding = digest("admission_binding", decode(fsb));
  return {
    transport, maxFrame: 65536, maxReceiveDirections: 8, signer: { publicKey: ed25519.getPublicKey(fill(15)), sign: bytes => ed25519.sign(bytes, fill(15)) }, peerReadyPublicKey: ed25519.getPublicKey(fill(14)),
    noise: {
      role: "server", profile, localStaticPrivate: fill(17), localStaticPublic: fixture.publicNoise(1), peerStaticPublic: fixture.publicNoise(0), psk: fill(24),
      contextDigest, fsb, fsa: encode(fsa), authorizationDeadline: new TrustedDeadline(env.owner.clock, timeOrigin + 30000n), preparationDeadline: new TrustedDeadline(env.owner.clock, timeOrigin + 10000n)
    },
    ready: { localCertificateDigest: s, peerCertificateDigest: c, fsbDigest: digest("fsb_digest", decode(fsb)), fsaDigest: digest("fsa_digest", fsa), admissionBinding: binding, transportContextDigest: contextDigest, selectedFeatures: 0n },
    crypto: { keys: 100, maintenance: { calls: 64n, blocks: 8192n, bytes: 1048576n } },
    streams: {
      limits: {
        direction: 1, maxActive: 8, maxPending: 8, ingressItems: 8, ingressBytes: 65536, terminalCapacity: 32, rejectionReserve: 8, runtimeBytes: 1024n,
        perClass: [8, 0, 0], perOpener: [[8, 0, 0], [8, 0, 0]], protected: [[0, 0, 0], [0, 0, 0]]
      },
      receive: { maxDataBytes: 128, queueBytes: 256, maxCursorBytes: 1024, receiveLimit: 256n, runtimeBytes: 1024n, cursorRuntimeBytes: 1024n, decoderRuntimeBytes: 1024n },
      maxWriteBytes: 1024, writeDeadlineMS: 1000n, operationDeadlineMS: 1000n, rekeyBurst: 10n, rekeyRefillMS: 1000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n
    },
    info: {
      application_profile: "transport", selected_features: 0n, guarantees: {
        reliable_progress: "shared_ordered", bound_stream_input_isolation: "shared_failure_scope", datagram: false,
        local_consumer_tls13_verification: "not_applicable", scope: "complete_direct_path", assumptions: "authenticated_peer_within_transport_profile"
      }
    }
  };
}

describe("Node v4 original WSS pool connection", () => {
  let directory: string, certificate: Buffer, key: Buffer, cert: X509Certificate;
  beforeAll(() => {
    directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-wss-"));
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(directory, "key.pem"), "-out", join(directory, "cert.pem"),
      "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth"], { stdio: "ignore" });
    certificate = readFileSync(join(directory, "cert.pem")); key = readFileSync(join(directory, "key.pem")); cert = new X509Certificate(certificate);
  });
  afterAll(() => rmSync(directory, { recursive: true, force: true }));
  let serial = 0;
  async function setup(profile: NoiseProfile, mode: "ca" | "pin", behavior: "ready" | "reject" | "bad_echo" | "pause" | "bad_exporter" | "downgrade" | "production" | "production_cancel_sign" | "production_bad_endpoint" | "production_pressure" | "production_public" = "ready", origin = "https://app.example.com", badPin = false,
    bindingMode: "direct_exporter" | "authenticated_context" = "authenticated_context", publicCallbacks: Partial<ServeCallbacks<HandlerPlan>> = {}, publicSignal?: AbortSignal, rpc = false, hooks: { startup?: (environment: V4TransportEnvironment) => void; stream?: V4RawStreamHandler; authorize?: V4StreamOpenAuthorizer } = {}) {
    let startupFailure: unknown;
    const limits = rpc ? { ...transportLimits, maxStreams: 18, receiveQueueBytes: 16384, maxWriteBytes: 16384, maxGeneralOutstanding: 4 } : transportLimits;
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({
      typeID: 42, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false
    });
    const definition = new V4ServiceDefinition({ namespace: "example.serve", methods: { echo: method } });
    const services = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const server = createServer({ key, cert: certificate, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"] });
    const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, handleProtocols: () => "flowersec.direct.v4" });
    server.on("upgrade", (request, socket, head) => {
      expect(request.url).toBe("/flowersec/v4/direct"); expect(request.headers.origin).toBe("https://app.example.com");
      wss.handleUpgrade(request, socket, head, ws => wss.emit("connection", ws, request));
    });
    server.listen(0, "127.0.0.1"); await once(server, "listening"); const address = server.address(); if (address === null || typeof address === "string") throw new Error("listen");
    const timeOrigin = BigInt(Date.now()) - 1000n, a = environment(timeOrigin, rpc), b = environment(timeOrigin, rpc);
    const tls = mode === "ca" ? map({ 0: u(0), 1: { kind: "bool", value: true } }) : map({
      0: u(1), 1: { kind: "bool", value: true }, 2: u(0), 3: array(map({
        0: bytes(badPin ? fill(99) : createHash("sha256").update(cert.raw).digest()), 1: u(BigInt(cert.validFromDate.getTime())), 2: u(BigInt(cert.validToDate.getTime())), 3: text("x509v3-p256-14d")
      }))
    });
    const leg = map({
      0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("localhost"), 7: u(address.port), 8: text("/flowersec/v4/direct"), 9: text("http/1.1"),
      10: text("flowersec.direct.v4"), 11: tls, 12: map({ 0: array(text("https://app.example.com")), 1: { kind: "bool", value: false } })
    });
    const fixture = credentials(a, profile, leg, timeOrigin, rpc), peer = credentials(b, profile, leg, timeOrigin, rpc), policy = { ...fixture.config, authorities: ["authority"] };
    const path = join(directory, `once-${++serial}.sqlite`), backing = createV4SQLitePoolBacking(a.publicOwner, path, { maxPages: 64, maxRecords: 4, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
    const store = await openV4SQLitePoolStore(backing, { create: true, identity: { authority: "spend", storeID: fill(9), generation: 1n }, continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16) }] });
    const client = configureV4NodeWSS(a.publicOwner, {
      identityKey: createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), fill(14)]), format: "der", type: "pkcs8" }),
      noiseKey: noiseKey(profile), poolStore: store, carrier: { remoteAddress: "127.0.0.1", origin, ca: [certificate], queueMessages: 8, runtimeBytes: 1024n, nativeBytes: 1048576n, prepareBytes: 262144 }, limits, bindingMode, ...(rpc ? { services } : {})
    });
    const serverStores: SQLiteAdmissionStore[] = [], serverBackings: ReturnType<typeof createV4SQLitePoolBacking>[] = [], serverPaths: string[] = [];
    let serverStore: SQLiteAdmissionStore | undefined;
    if (behavior.startsWith("production")) {
      const openServerStore = async (authority: string, parentWinnerStore?: SQLiteAdmissionStore) => {
        const path = join(directory, `${authority}-${++serial}.sqlite`), backing = createV4SQLitePoolBacking(b.publicOwner, path,
          { maxPages: 64, maxRecords: 4, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
        serverBackings.push(backing); serverPaths.push(path);
        const value = await openSQLiteAdmissionStore(backing, {
          create: true, identity: { authority, storeID: fill(10), generation: 1n }, continuity: { check: () => undefined },
          bindings: [{ tenant: "tenant", issuer: fill(5, 16), audience: "service", serverIdentity: digest("certificate_digest", peer.server) }],
          ...(parentWinnerStore === undefined ? {} : { parentWinnerStore })
        });
        serverStores.push(value); return value;
      };
      serverStore = await openServerStore("service", await openServerStore("winner"));
    }
    let serveHandle: ServeHandle | undefined;
    const serveEvents: string[] = []; let leaseCloses = 0;
    let acquisitions = 0, helloCount = 0, connections = 0, serverFailure: unknown;
    let established!: (value: (Awaited<ReturnType<typeof b.owner.establishVerified>> | V4Session)) => void;
    const accepted = new Promise<(Awaited<ReturnType<typeof b.owner.establishVerified>> | V4Session)>(resolve => { established = resolve; });
    let sawHello!: () => void; const helloObserved = new Promise<void>(resolve => { sawHello = resolve; });
    const jobs: Promise<void>[] = [];
    wss.on("connection", (ws, request) => {
      if (behavior.startsWith("production")) {
        connections++;
        const charge = nodeWSSAdmissionCosts(limits.maxFrame, { remoteAddress: "127.0.0.1", queueMessages: 8, runtimeBytes: 1024n, nativeBytes: 1048576n, prepareBytes: 262144 }, 1024n)[0]![1];
        const dependency = b.owner.admitDependency("accepted_wss", charge), transport = new NodeWSSCarrier(b.owner, dependency, 65544, 8, "server");
        const job = (async () => {
          if (!(request.socket instanceof TLSSocket)) throw new Error("TLS socket required"); transport.accept(ws, request, { host: "localhost", port: behavior === "production_bad_endpoint" ? address.port + 1 : address.port });
          const deadline = new TrustedDeadline(b.owner.clock, timeOrigin + 10000n), stop = new AbortController();
          const timer = setTimeout(() => { stop.abort(); void transport.close(); }, Number(deadline.remainingMS()));
          const work = b.owner.reserveConnectionWork("server_admission", serverAdmissionCharge(1024n));
          let exchange: ServerAdmissionExchange | undefined, pressure: ResourceReference | undefined;
          const signingCancellation = new AbortController();
          try {
            const signer = { publicKey: ed25519.getPublicKey(fill(15)), sign: (message: Uint8Array) => { if (behavior === "production_cancel_sign") signingCancellation.abort(); return ed25519.sign(message, fill(15)); } };
            exchange = new ServerAdmissionExchange(b.owner.resources, transport, signer, value => { crypto.getRandomValues(value); }, work,
              () => { deadline.check(); if (stop.signal.aborted) throw new Error("canceled"); }, bindingMode);
            await exchange.readHello({ signal: stop.signal }); helloCount++; sawHello();
            const material = b.owner.verify({ ...peer.config, authorities: ["authority"] }, peer.input());
            const session = await b.owner.establishServer(material, fields => {
              if (behavior === "production_pressure") {
                const snapshot = b.root.snapshot(), resources = b.owner.resources;
                pressure = b.root.reserve({
                  owner: { ...resources.owner, kind: "server_admission_pressure" }, accounts: resources.accounts,
                  charge: new ResourceVector([snapshot.limit.values()[0]! - snapshot.charged.values()[0]! - 1024n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])
                });
              }
              return reliableServerSpec(fields, transport, signer, fill(17), limits, 1024n);
            },
              exchange, serverStore!, { acceptor: fill(71, 16), invocation: fill(72, 16), carrier: fill(73, 16), generation: 1n }, { signal: AbortSignal.any([stop.signal, signingCancellation.signal]) });
            established(session);
          } finally { clearTimeout(timer); exchange?.close(); work.release(); pressure?.release(); }
        })().catch(error => { serverFailure = error; void transport.close(); }); jobs.push(job); return;
      }
      connections++; const transport = new ServerTransport(ws);
      const job = (async () => {
        const message = await transport.read(65544); if (message === null) return;
        const clientBytes = parseMessage(message, "NEGOTIATE"), hello = decode(clientBytes); helloCount++; sawHello(); if (behavior === "pause") { await transport.waitTermination(); return; }
        const fields = Object.fromEntries(Array.from({ length: 8 }, (_, id) => [id, get(hello, id)]));
        const selectedBinding = bindingMode === "direct_exporter" && behavior !== "downgrade" ? 0 : 1;
        expect(get(hello, 9)).toEqual(u(bindingMode === "direct_exporter" ? 1 : 2));
        const response = map({ ...fields, ...(behavior === "bad_echo" ? { 6: bytes(fill(88, 16)) } : {}), 8: bytes(fill(31)), 9: u(0), 10: u(0), 11: u(selectedBinding), 12: bytes(new Uint8Array()) }), serverBytes = encode(response);
        await transport.write(envelope("NEGOTIATE", serverBytes)); if (behavior === "bad_echo") { await transport.waitTermination(); return; }
        const label = Buffer.from(wireDomains.find(d => d.name === "hello_transcript_digest")!.label_bytes, "hex"), size1 = Buffer.alloc(4), size2 = Buffer.alloc(4);
        size1.writeUInt32BE(clientBytes.length); size2.writeUInt32BE(serverBytes.length); const transcript = createHash("sha256").update(label).update(size1).update(clientBytes).update(size2).update(serverBytes).digest();
        const admission = await transport.read(65544); if (admission === null) return; const fsb = parseMessage(admission, "ADMISSION"), parsed = decode(fsb);
        expect(buffer(get(parsed, 9))).toEqual(new Uint8Array(transcript));
        if (!(request.socket instanceof TLSSocket)) throw new Error("original TLS socket missing");
        const exporter = selectedBinding === 0 ? request.socket.exportKeyingMaterial(32, "EXPORTER-flowersec-v4", Buffer.from(buffer(get(hello, 3)))) : new Uint8Array();
        if (behavior === "bad_exporter") exporter[0] = exporter[0]! ^ 1;
        const context = map({ 0: text("4"), 1: text(profile), 2: u(0), 3: u(0), 4: get(hello, 3), 5: get(hello, 5), 6: get(hello, 6), 7: get(hello, 7), 8: bytes(transcript), 9: u(0), 10: u(selectedBinding), 11: u(selectedBinding === 0 ? 1 : 0), 12: bytes(exporter) });
        const rejecting = behavior === "reject", zero = new Uint8Array(32);
        const fsa = sign("FSA4", map({
          0: u(rejecting ? 1 : 0), 1: u(rejecting ? 1 : 0), 2: u(rejecting ? 0 : 1), 3: bytes(rejecting ? zero : fill(27)),
          4: bytes(rejecting ? zero : digest("admission_binding", parsed)), 5: get(hello, 5), 6: bytes(transcript), 7: u(0), 8: u(selectedBinding), 9: bytes(rejecting ? zero : digest("transport_context_digest", context)),
          10: bytes(rejecting ? zero : digest("certificate_digest", peer.client)), 11: bytes(rejecting ? zero : digest("certificate_digest", peer.server)), 12: bytes(encode(peer.server))
        }), 15);
        await transport.write(envelope("ADMISSION_RESULT", encode(fsa))); if (rejecting || behavior === "bad_exporter") { await transport.waitTermination(); return; }
        const material = b.owner.verify({ ...peer.config, authorities: ["authority"] }, peer.input()), session = await b.owner.establishVerified(material, serverSpec(b, peer, transport, profile, fsb, fsa, context, timeOrigin), encode(context)); established(session);
      })().catch(error => { serverFailure = error; ws.terminate(); }); jobs.push(job);
    });
    if (behavior === "production_public") {
      await new Promise<void>(resolve => server.close(() => resolve()));
      const handlerPlan = createHandlerPlan(b.publicOwner, {
        applicationBytes: 1024n,
        ...(rpc ? {
          services: {
            ...services, profile: "services" as const, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" as const }],
            unaryHandlers: [{
              namespace: definition.namespace, method,
              contract: encode(map({
                0: text(definition.namespace), 1: u(42), 2: u(0), 3: u(0), 6: text("text-v1"), 7: text("text-v1"),
                8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000), 21: { kind: "bool", value: false }, 23: u(128), 27: array()
              })),
              handler: (_context: unknown, value: string) => `served:${value}`, options: { workClass: "short" as const, maxConcurrentCalls: 1, applicationBytes: 1024n, authorization: "authenticated" as const }
            }]
          }
        } : {}),
        streams: [{
          kind: "example/served", ...(hooks.authorize === undefined ? {} : { authorize: hooks.authorize }), options: { applicationBytes: 1024n, maxConcurrentStreams: 1, maxAuthorizing: 1 },
          handler: hooks.stream ?? (async stream => { const request = await stream.read(128n); await stream.write(request.data); await stream.closeWrite(); await stream.finish(); })
        }]
      });
      const listener = createNodeWSSListener(b.publicOwner, {
        host: "127.0.0.1", serverName: "localhost", port: address.port, tls: { certificate: certificate.toString(), privateKey: key.toString() },
        identityKey: createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), fill(15)]), format: "der", type: "pkcs8" }),
        noiseKey: profile === profileX ? createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), fill(17)]), format: "der", type: "pkcs8" })
          : createPrivateKey({ key: Buffer.concat([Buffer.from("30310201010420", "hex"), fill(17), Buffer.from("a00a06082a8648ce3d030107", "hex")]), format: "der", type: "sec1" }),
        admissionStore: serverStore!, credentials: {
          source: "preauthorized_pool", policy: { ...peer.config, authorities: ["authority"] }, resolve: async (_request, destination) => {
            const input = peer.input(); for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
            return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, activation: input.activation.length, candidateIndex: 0 };
          }
        }, limits, ingress: { positions: 2, callbackBytes: 1024n, handshakeMS: 5000n, drainMS: 5000n, cleanupMS: 1000n },
        carrier: { queueMessages: 8, nativeBytes: 1048576n, prepareBytes: 262144 }, bindingMode,
      });
      const cleaned = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n } as const);
      const starting = b.publicOwner.serve({
        listener: listener.listener, carrier: "wss", authorizeRequest: context => { serveEvents.push("request"); return publicCallbacks.authorizeRequest?.(context) ?? { allowed: true }; },
        resolveHandlers: context => { serveEvents.push("handlers"); expect(context.authentication.peerSubject).toBe("client"); return publicCallbacks.resolveHandlers?.(context) ?? handlerPlan; },
        authorizeApplication: (context, handlers) => { serveEvents.push("authorize"); return publicCallbacks.authorizeApplication?.(context, handlers) ?? { decision: "authorized", handlers, lease: { close: () => { leaseCloses++; }, waitCleanup: async () => cleaned } }; },
        onSession: (session, context) => { serveEvents.push("session"); established(session); return publicCallbacks.onSession?.(session, context) ?? { accepted: true }; },
        release: context => { serveEvents.push("release"); return publicCallbacks.release?.(context) ?? cleaned; }
      }, publicSignal === undefined ? undefined : { signal: publicSignal });
      hooks.startup?.(b.publicOwner);
      try { serveHandle = await starting; } catch (error) { if (hooks.startup === undefined) throw error; startupFailure = error; }
    }
    const source = client.registerPoolSource(policy, async (request, destination) => {
      expect(request.requirements.application_profile).toBe(rpc ? "services" : "transport");
      acquisitions++;
      const input = fixture.input(); for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, activation: input.activation.length, candidateIndex: 0 };
    });
    const replay = async () => {
      const other = environment(timeOrigin), otherFixture = credentials(other, profile, leg, timeOrigin);
      const replayPath = join(directory, `replay-${++serial}.sqlite`), replayBacking = createV4SQLitePoolBacking(other.publicOwner, replayPath,
        { maxPages: 64, maxRecords: 4, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
      const replayStore = await openV4SQLitePoolStore(replayBacking, { create: true, identity: { authority: "spend", storeID: fill(9), generation: 1n }, continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16) }] });
      const connector = configureV4NodeWSS(other.publicOwner, {
        identityKey: createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), fill(14)]), format: "der", type: "pkcs8" }),
        noiseKey: noiseKey(profile), poolStore: replayStore, carrier: { remoteAddress: "127.0.0.1", origin, ca: [certificate], queueMessages: 8, runtimeBytes: 1024n, nativeBytes: 1048576n, prepareBytes: 262144 }, limits, bindingMode
      });
      try { return await other.publicOwner.connectMaterial(connector.verifyPoolMaterial({ ...otherFixture.config, authorities: ["authority"] }, otherFixture.input())); }
      finally {
        await other.publicOwner.close(); replayStore.close(); await replayStore.waitCleanup(); for (const suffix of ["", "-wal", "-shm", "-journal"]) rmSync(replayPath + suffix, { force: true }); replayBacking.releaseRemoved();
        expect((await other.publicOwner.waitCleanup()).status).toBe("complete"); expect(other.root.snapshot().reservations).toBe(0);
      }
    };
    return {
      a, b, address, startupFailure, replay, client, source, policy, fixture, accepted, helloObserved, serveEvents, serveHandle, method, definition, peerIdentity: Buffer.from(digest("certificate_digest", peer.server)).toString("hex"), leaseCloses: () => leaseCloses, counts: () => ({ acquisitions, helloCount, connections }), failure: () => serverFailure,
      close: async () => {
        serveHandle?.close();
        const serveCleanup = await serveHandle?.waitCleanup();
        await Promise.all([a.publicOwner.close(), b.publicOwner.close()]); for (const ws of wss.clients) ws.terminate(); await Promise.all(jobs);
        await new Promise<void>(resolve => wss.close(() => resolve())); await new Promise<void>(resolve => server.close(() => resolve())); store.close(); await store.waitCleanup();
        for (const suffix of ["", "-wal", "-shm", "-journal"]) rmSync(path + suffix, { force: true }); backing.releaseRemoved();
        for (const value of serverStores) value.close(); await Promise.all(serverStores.map(value => value.waitCleanup()));
        for (const path of serverPaths) for (const suffix of ["", "-wal", "-shm", "-journal"]) rmSync(path + suffix, { force: true });
        for (const value of serverBackings) value.releaseRemoved();
        expect((await a.publicOwner.waitCleanup()).status).toBe("complete"); expect((await b.publicOwner.waitCleanup()).status).toBe("complete");
        expect(a.root.snapshot().reservations).toBe(0); expect(b.root.snapshot().reservations).toBe(0); if (serveCleanup !== undefined) expect(serveCleanup.status).toBe("complete");
      }
    };
  }
  it("commits the actual native fallback candidate acquired through the production connector", async () => {
    const timeOrigin = BigInt(Date.now()) - 1000n, env = environment(timeOrigin, true), calls: string[] = [];
    const namespace = env.owner.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
      maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
    const leg = (index: number, carrier: 0 | 2): Value => map({ 0: u(0), 1: bytes(fill(21 + index, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(carrier),
      6: text("localhost"), 7: u(30000), 8: text(carrier === 2 ? "/flowersec/webtransport/v4/direct" : ""),
      9: text(carrier === 2 ? "h3" : "flowersec-direct/4"), 10: text(""), 11: map({ 0: u(0), 1: { kind: "bool", value: true } }),
      ...(carrier === 2 ? { 12: map({ 0: array(text("https://localhost")), 1: { kind: "bool", value: true } }) } : {}) });
    const legs = [leg(0, 0), leg(1, 2)], material = credentialFixture(env.owner.resources, env.owner.clock, () => { throw new Error("original Environment only"); },
      "preauthorized_pool", profileX, namespace, { timeOrigin, candidateLegs: legs }); material.bootstrap();
    const policy = { ...material.config, authorities: ["authority"] }, poolPath = join(directory, `native-candidates-${++serial}.sqlite`);
    const backing = createV4SQLitePoolBacking(env.publicOwner, poolPath, { maxPages: 64, maxRecords: 4, maxRecordBytes: 16384, runtimeBytes: 1024n,
      providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
    let store: Awaited<ReturnType<typeof openV4SQLitePoolStore>> | undefined;
    const sourceLengthReads: Record<string, number> = {};
    let acquisitions = 0, writes = 0, nativeClosed = false, budgetCreated = 0, budgetClosed = 0, finishStream!: () => void, finishSession!: () => void;
    const budgetLimits: NativePreparationLimits[] = [];
    const streamEnded = new Promise<void>(resolve => { finishStream = resolve; }), sessionEnded = new Promise<void>(resolve => { finishSession = resolve; });
    const operation = <T>(result: Promise<T>): NativeOperation<T> => ({ result: () => result, cancel: () => undefined });
    const stream: NativeRawStream = { read: () => operation(Promise.resolve(null)), submit: () => { writes++; return { completion: () => Promise.resolve() }; },
      closeWrite: async () => undefined, stopSending: async () => undefined, resetWrite: async () => undefined,
      onWriteFailure: () => () => undefined, waitTermination: () => streamEnded, abort: () => { finishStream(); } };
    const native: NativeWebTransportSession = { kind: "webtransport", wireVersion: 4, path: "direct", inboundBidirectionalStreamCapacity: 21,
      completePreparation: () => undefined,
      tls: () => ({ version: "TLSv1.3", alpn: "h3", earlyDataAccepted: false, dedicatedConnection: true, peerLeafDER: new Uint8Array(cert.raw), certificateVerified: true }),
      request: () => Object.freeze({ scheme: "https", authority: "localhost:30000", path: "/flowersec/webtransport/v4/direct", tuple: "native_h3",
        protocol: "webtransport-h3", sessionFlowControl: false, streamPrefixes: "rfc_webtransport", datagramContext: "rfc_h3_quarter_stream_id" }),
      exportKeyingMaterial: length => fill(60, length), maxDatagramBytes: () => 1400,
      receiveDatagram: () => operation(Promise.reject(new Error("unused datagram read"))), submitDatagram: () => undefined,
      openStream: () => operation(Promise.resolve(stream)), acceptStream: () => operation(Promise.reject(new Error("unused peer stream"))),
      localAddress: () => ({ host: "127.0.0.1", port: 20000 }), peerAddress: () => ({ host: "127.0.0.1", port: 30000 }),
      close: async () => { nativeClosed = true; finishStream(); finishSession(); }, waitTermination: () => sessionEnded,
      abort: () => { nativeClosed = true; finishStream(); finishSession(); } };
    const driver: NativeTransportBinding = { contractVersion: () => 4,
      createPreparationBudget: () => { expect(acquisitions).toBe(0); budgetCreated++; let configured = false, closed = false;
        return { configure: limits => { expect(configured).toBe(false); configured = true; budgetLimits.push(limits); },
          beginCandidate: limits => { expect(configured && !closed).toBe(true); budgetLimits.push(limits); return Object.freeze({}); },
          usage: () => ({ preauthInputBytes: 0, addressAttempts: 0, workUnits: 0 }), close: () => { if (!closed) { closed = true; budgetClosed++; } } };
      },
      connectRawQuic: () => { expect(acquisitions).toBe(1); calls.push("raw-quic"); throw new Error("native refused"); },
      connectWebTransport: () => { expect(acquisitions).toBe(1); calls.push("webtransport"); return operation(Promise.resolve(native)); },
      bindRawQuic: async () => { throw new Error("unused listener"); }, bindWebTransport: async () => { throw new Error("unused listener"); } };
    const rawBinding = vi.spyOn(nativeBinding, "loadCurrentNativeTransport").mockReturnValue(driver);
    const webBinding = vi.spyOn(nativeBinding, "loadCurrentNativeWebTransport").mockReturnValue(driver);
    try {
      store = await openV4SQLitePoolStore(backing, { create: true, identity: { authority: "spend", storeID: fill(9), generation: 1n },
        continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16) }] });
      const carrier = { applicationStreams: 20, streamBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n,
        providerStreamBytes: 65536n, trustRootsDER: [new Uint8Array(cert.raw)] };
      const client = configureNodeRawQUIC(env.publicOwner, { identityKey: createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), fill(14)]), format: "der", type: "pkcs8" }),
        noiseKey: noiseKey(profileX), poolStore: store, carrier, carrierAlternatives: [{ ...carrier, nativeCarrier: "webtransport",
          webTransport: { headerBytes: 1024, controlBytes: 16384, tuples: ["native_h3"], allowedOrigins: [], allowAbsentOrigin: true } }], limits: transportLimits, candidateAttemptLimit: 2 });
      const source = client.registerPoolSource(policy, async (_request, destination) => {
        expect(budgetCreated).toBe(1); expect(budgetClosed).toBe(0); acquisitions++; const input = material.input();
        for (const key of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[key].set(input[key]);
        const returned = { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
          activation: input.activation.length, candidateIndex: 0 };
        for (const key of Object.keys(returned) as (keyof typeof returned)[]) {
          const length = returned[key]; Object.defineProperty(returned, key, { get: () => { sourceLengthReads[key] = (sourceLengthReads[key] ?? 0) + 1; return length; } });
        }
        return returned;
      });
      {
        // The prepared native peer ends Admission after HELLO. TxA must already
        // contain the actual selected route even though READY is never reached.
        await expect(env.owner.connect(source, request)).rejects.toThrow();
        expect(calls).toEqual(["raw-quic", "webtransport"]); expect(writes).toBeGreaterThan(0); expect(nativeClosed).toBe(true);
        expect(budgetCreated).toBe(1); expect(budgetClosed).toBe(1); expect(budgetLimits).toHaveLength(3);
        await sessionEnded;
        store?.close(); await store?.waitCleanup();
        expect(budgetLimits[0]!.addressAttempts).toBeGreaterThanOrEqual(budgetLimits[1]!.addressAttempts);
        expect(sourceLengthReads).toEqual({ artifact: 1, clientCertificate: 1, serverCertificate: 1, activation: 1, candidateIndex: 1 });
        const database = new DatabaseSync(poolPath, { readOnly: true, timeout: 1000 });
        try {
          const rows = database.prepare("SELECT projection FROM spend").all(); expect(rows).toHaveLength(1);
          const row = rows[0]!; if (!(row.projection instanceof Uint8Array)) throw new Error("pool projection missing");
          const spent = decode(new Uint8Array(row.projection)), route = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: legs[1]! });
          expect(get(spent, 11)).toEqual(u(1)); expect(buffer(get(spent, 10))).toEqual(fill(21, 16));
          expect(buffer(get(spent, 12))).toEqual(digest("route_digest", route)); expect(buffer(get(spent, 19))).toEqual(encode(legs[1]!));
        } finally { database.close(); }
      }
    } finally {
      rawBinding.mockRestore(); webBinding.mockRestore(); native.abort();
      await env.publicOwner.close(); store?.close(); await store?.waitCleanup();
      for (const suffix of ["", "-wal", "-shm", "-journal"]) rmSync(poolPath + suffix, { force: true }); backing.releaseRemoved();
      expect((await env.publicOwner.waitCleanup()).status).toBe("complete"); expect(env.root.snapshot().reservations).toBe(0);
    }
  }, 15000);

  for (const cancel of ["parent", "environment"] as const) {
    it(`settles Serve startup after immediate ${cancel} cancellation`, async () => {
      const controller = new AbortController();
      const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {}, controller.signal, false,
        { startup: env => { if (cancel === "parent") controller.abort(); else void env.close(); } });
      try { expect(f.startupFailure).toMatchObject({ name: "ServeError", code: cancel === "parent" ? "canceled" : "serve_failed", cleanup: { status: "complete" } }); }
      finally { await f.close(); }
    }, 15000);
  }
  for (const ending of ["none", "drain", "close"] as const) {
    it(`claims Serve publication before a queued OPEN authorizer (${ending})`, async () => {
      let releaseReady!: () => void, queued = false;
      const readyGate = new Promise<void>(resolve => { releaseReady = resolve; });
      let claimed = false, authorized = false;
      let drain: ReturnType<ServeHandle["drain"]> | undefined;
      const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {}, undefined, false,
        { authorize: () => { expect(claimed).toBe(true); authorized = true; if (ending === "drain") drain = f.serveHandle!.drain(); else if (ending === "close") f.serveHandle!.close(); return true; } });
      const accept = NodeWSSCarrier.prototype.accept, submit = NodeWSSCarrier.prototype.submit, originalClaim = ServeIngress.prototype.claim;
      const acceptance = vi.spyOn(NodeWSSCarrier.prototype, "accept").mockImplementation(function (this: NodeWSSCarrier, socket, request, endpoint) {
        accept.call(this, socket, request, endpoint);
        socket.on("message", data => { if (Buffer.isBuffer(data) && data[4] === wire.frame_types.OPEN_STREAM) queued = true; });
      });
      const sending = vi.spyOn(NodeWSSCarrier.prototype, "submit").mockImplementation(function (this: NodeWSSCarrier, data, admitted) {
        const result = submit.call(this, data, admitted);
        return result !== undefined && this.role === "server" && data[4] === wire.frame_types.READY
          ? { completion: result.completion.then(() => readyGate) } : result;
      });
      const claiming = vi.spyOn(ServeIngress.prototype, "claim").mockImplementation(function (this: ServeIngress<object>, session) {
        originalClaim.call(this, session); claimed = true;
      });
      try {
        const session = await connect(f.a.publicOwner, f.source, request), opening = session.openStream("example/served");
        void opening.catch(() => undefined);
        await expect.poll(() => queued).toBe(true); expect(claimed).toBe(false); expect(authorized).toBe(false); releaseReady();
        if (ending !== "none") {
          await expect(opening).rejects.toThrow(); await f.accepted;
          expect(f.serveEvents.filter(event => event === "session")).toHaveLength(1);
          if (drain !== undefined) expect((await drain.wait()).outcome).toBe("drained");
        } else {
          const stream = await opening; expect(authorized).toBe(true);
          const payload = fill(21, 4); await stream.write(payload); await stream.closeWrite();
          expect((await stream.read(128n)).data).toEqual(payload); await stream.finish();
        }
        await session.close();
      } finally { releaseReady(); acceptance.mockRestore(); sending.mockRestore(); claiming.mockRestore(); await f.close(); }
    }, 15000);
  }
  for (const boundary of ["before", "after"] as const) {
    it(`keeps the original handoff when Close occurs ${boundary} the Serve claim`, async () => {
      let invoked = false;
      const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {}, undefined, false,
        { stream: async () => { invoked = true; } });
      const original = ServeIngress.prototype.claim;
      let claimed = false;
      const claim = vi.spyOn(ServeIngress.prototype, "claim").mockImplementation(function (this: ServeIngress<object>, session) {
        claimed = true; if (boundary === "before") f.serveHandle!.close();
        original.call(this, session); if (boundary === "after") f.serveHandle!.close();
      });
      try {
        const connecting = connect(f.a.publicOwner, f.source, request).then(async session => {
          try { await session.openStream("example/served"); } catch { /* The original publication was canceled. */ }
          finally { await session.close(); }
        }).catch(() => undefined);
        await connecting;
        await expect.poll(() => f.serveHandle!.cleanupStatus().status).toBe("complete");
        expect(claimed).toBe(true); expect(invoked).toBe(false);
        expect(f.serveEvents.filter(event => event === "session")).toHaveLength(boundary === "after" ? 1 : 0);
        expect(f.serveEvents.filter(event => event === "release")).toHaveLength(1);
      } finally { claim.mockRestore(); await f.close(); }
    }, 15000);
  }
  it("accepts browser compression offers while negotiating no extensions", async () => {
    const f = await setup(profileX, "ca", "production_public");
    const configuration: WebSocket.ClientOptions & ConnectionOptions = {
      ca: certificate, servername: "localhost", ALPNProtocols: ["http/1.1"], perMessageDeflate: true,
      headers: { host: `localhost:${f.address.port}`, origin: "https://app.example.com" },
    };
    const socket = new WebSocket(`wss://127.0.0.1:${f.address.port}/flowersec/v4/direct`, "flowersec.direct.v4", configuration);
    try { await once(socket, "open"); expect(socket.extensions).toBe(""); expect(f.serveEvents).toEqual(["request"]); }
    finally { const closed = once(socket, "close"); socket.terminate(); await closed; await f.close(); }
  }, 15000);
  it("projects native cleanup separately from a real Release tail", async () => {
    let release!: () => void, entered!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; }), called = new Promise<void>(resolve => { entered = resolve; });
    const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {
      release: async () => { entered(); await gate; return { status: "complete", core_cleanup: "complete", pending_callbacks: 0n }; },
    });
    try {
      const session = await connect(f.a.publicOwner, f.source, request), peer = await f.accepted;
      expect((await peer.drain().wait()).outcome).toBe("drained");
      await called; await session.close();
      const drain = f.serveHandle!.drain();
      expect((await drain.wait()).outcome).toBe("drained");
      await expect.poll(() => f.serveHandle!.cleanupStatus().core_cleanup).toBe("complete");
      expect(f.serveHandle!.cleanupStatus().pending_callbacks).toBe(1n);
      expect((await f.serveHandle!.waitCleanup()).status).toBe("cleanup_incomplete");
      expect(drain.status().cleanup_status).toEqual(f.serveHandle!.cleanupStatus());
      expect((await drain.wait()).cleanup_status.status).toBe("cleanup_incomplete");
      expect(f.b.root.snapshot().reservations).toBeGreaterThan(3);
      release(); await expect.poll(() => f.serveHandle!.cleanupStatus().status).toBe("complete");
    } finally { release(); await f.close(); }
  }, 15000);
  for (const end of ["close", "drain_deadline"] as const) {
    it(`keeps a real raw callback visible through ${end} and eventual cleanup`, async () => {
      let release!: () => void, entered!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), called = new Promise<void>(resolve => { entered = resolve; });
      const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {}, undefined, false,
        { stream: async () => { entered(); await gate; } });
      try {
        const session = await connect(f.a.publicOwner, f.source, request), stream = await session.openStream("example/served"); await called;
        const drain = f.serveHandle!.drain({ timeoutMS: end === "close" ? 1000n : 30n });
        if (end === "close") f.serveHandle!.close();
        expect((await drain.wait()).outcome).toBe(end === "close" ? "failed" : "deadline_aborted");
        await expect.poll(() => f.serveHandle!.cleanupStatus().core_cleanup).toBe("complete");
        expect(f.serveHandle!.cleanupStatus().pending_callbacks).toBeGreaterThan(0n);
        release(); await stream.close(); await session.close();
        await expect.poll(() => f.serveHandle!.cleanupStatus().status).toBe("complete");
      } finally { release(); await f.close(); }
    }, 15000);
  }
  it("rejects an authenticated replay at the public server even from another consumer store", async () => {
    const f = await setup(profileX, "ca", "production_public");
    try {
      const session = await connect(f.a.publicOwner, f.source, request), peer = await f.accepted;
      await Promise.all([session.close(), peer.close()]); await expect.poll(() => f.serveEvents.filter(event => event === "release").length).toBe(1);
      await expect(f.replay()).rejects.toThrow(); await expect.poll(() => f.serveEvents.filter(event => event === "release").length).toBe(2);
      expect(f.serveEvents.filter(event => event === "authorize")).toHaveLength(2); expect(f.serveEvents.filter(event => event === "session")).toHaveLength(1);
      expect((await f.serveHandle!.drain().wait()).outcome).toBe("drained");
    } finally { await f.close(); }
    expect(f.leaseCloses()).toBe(2);
  }, 15000);
  it("keeps a real authorization callback and its late lease owned after Close", async () => {
    let release!: () => void, entered!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; }), called = new Promise<void>(resolve => { entered = resolve; });
    let closed = 0;
    const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {
      authorizeApplication: async (_context, handlers) => {
        entered(); await gate; return {
          decision: "authorized", handlers,
          lease: { close: () => { closed++; }, waitCleanup: async () => ({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n }) }
        };
      },
    });
    const connecting = connect(f.a.publicOwner, f.source, request), rejected = expect(connecting).rejects.toThrow();
    try {
      await called; f.serveHandle!.close(); await rejected;
      expect(f.serveHandle!.cleanupStatus().pending_callbacks).toBe(1n); expect(f.serveEvents).not.toContain("session");
      expect((await f.serveHandle!.waitCleanup()).status).toBe("cleanup_incomplete");
      expect(f.serveHandle!.cleanupStatus().core_cleanup).toBe("complete"); release();
      await expect.poll(() => f.serveHandle!.cleanupStatus().status).toBe("complete"); expect(closed).toBe(1);
    } finally { release(); await f.close(); }
  }, 15000);
  it("calls a typed service through public Serve and the real client", async () => {
    const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {}, undefined, true);
    try {
      const session = await connect(f.a.publicOwner, f.source, { ...request, application_profile: "services" });
      const service = await session.bindService(f.definition, {
        target: {
          authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
          peers: [{ subject: "server", identityDigest: f.peerIdentity }]
        }, maximumOfferWindowMS: 10000n
      });
      try { const result = await service.call(f.method, "hello"); expect(result).toMatchObject({ kind: "value", value: "served:hello" }); if ("release" in result) result.release(); }
      finally { service.close(); }
      await session.close();
    } finally { await f.close(); }
    expect(f.leaseCloses()).toBe(1); expect(f.serveEvents.filter(event => event === "release")).toHaveLength(1);
  }, 15000);
  it("serves a registered application stream through the public Environment entry", async () => {
    const f = await setup(profileX, "ca", "production_public");
    try {
      const session = await connect(f.a.publicOwner, f.source, request), stream = await session.openStream("example/served");
      const payload = fill(71, 23); await stream.write(payload); await stream.closeWrite();
      expect((await stream.read(128n)).data).toEqual(payload); expect((await stream.read(1n)).stream_status).toBe("eof");
      await stream.finish(); await session.close();
      expect(f.serveEvents.slice(0, 4)).toEqual(["request", "handlers", "authorize", "session"]);
    } finally { await f.close(); }
    expect(f.serveEvents.filter(event => event === "release")).toHaveLength(1); expect(f.leaseCloses()).toBe(1);
  }, 15000);
  for (const denial of ["request", "application", "unknown", "canceled"] as const) {
    it(`does not admit or publish public Serve ${denial}`, async () => {
      const stop = new AbortController();
      const callbacks: Partial<ServeCallbacks<HandlerPlan>> = denial === "request" ? { authorizeRequest: () => ({ allowed: false }) }
        : {
          authorizeApplication: (_context, handlers) => {
            if (denial === "unknown") throw new Error("private authorization failure");
            if (denial === "canceled") { stop.abort(); return { decision: "authorized", handlers, lease: { close: () => undefined, waitCleanup: async () => ({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n }) } }; }
            return { decision: "rejected" };
          }
        };
      const f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", callbacks, stop.signal);
      const prepare = DatabaseSync.prototype.prepare; let writes = 0;
      const spy = vi.spyOn(DatabaseSync.prototype, "prepare").mockImplementation(function (this: DatabaseSync, sql) {
        if (sql.startsWith("INSERT INTO admission")) writes++; return prepare.call(this, sql);
      });
      try { await expect(connect(f.a.publicOwner, f.source, request)).rejects.toThrow(); expect(writes).toBe(0); expect(f.serveEvents).not.toContain("session"); }
      finally { spy.mockRestore(); await f.close(); }
      expect(f.serveEvents.filter(event => event === "release")).toHaveLength(1);
    }, 15000);
  }
  for (const receipt of ["reserve_unknown", "admit_confirmed", "admit_not_committed", "cancel_after_admit"] as const) {
    it(`keeps public Serve on its original commit continuation: ${receipt}`, async () => {
      const stop = new AbortController(), f = await setup(profileX, "ca", "production_public", "https://app.example.com", false, "authenticated_context", {}, stop.signal);
      const exec = SQLiteWorkerDatabase.prototype.exec; let injected = false;
      const spy = vi.spyOn(SQLiteWorkerDatabase.prototype, "exec").mockImplementation(async function (this: SQLiteWorkerDatabase, sql) {
        let hit = false;
        if (sql === "COMMIT" && !injected) {
          try { hit = (await this.all("SELECT state FROM admission"))[0]?.state === (receipt === "reserve_unknown" ? 0 : 1); } catch { /* Consumer and parent stores are separate authorities. */ }
        }
        if (hit) { injected = true; if (receipt === "admit_not_committed") throw new SQLiteWorkerError("storage_unavailable", "not_submitted"); }
        const result = await exec.call(this, sql);
        if (hit) { if (receipt === "cancel_after_admit") stop.abort(); throw new SQLiteWorkerError("storage_unavailable", "unknown"); } return result;
      });
      try {
        if (receipt === "admit_confirmed") {
          const session = await connect(f.a.publicOwner, f.source, request), peer = await f.accepted;
          expect(f.serveEvents.filter(event => event === "session")).toHaveLength(1); await Promise.all([session.close(), peer.close()]);
        } else { await expect(connect(f.a.publicOwner, f.source, request)).rejects.toThrow(); expect(f.serveEvents).not.toContain("session"); }
        expect(injected).toBe(true);
      } finally { spy.mockRestore(); await f.close(); }
      expect(f.serveEvents.filter(event => event === "release")).toHaveLength(1); expect(f.leaseCloses()).toBe(1);
    }, 15000);
  }
  for (const behavior of ["production_cancel_sign", "production_bad_endpoint", "production_pressure"] as const) {
    it(`rejects ${behavior} without FSA publication and cleans native ownership`, async () => {
      const f = await setup(profileX, "ca", behavior);
      const submit = NodeWSSCarrier.prototype.submit, execute = SQLiteWorkerDatabase.prototype.run;
      let responses = 0, admissionWrites = 0;
      const sends = vi.spyOn(NodeWSSCarrier.prototype, "submit").mockImplementation(function (this: NodeWSSCarrier, data, admitted) {
        if (this.role === "server" && data[4] === wire.frame_types.ADMISSION_RESULT) responses++; return submit.call(this, data, admitted);
      });
      const writes = vi.spyOn(SQLiteWorkerDatabase.prototype, "run").mockImplementation(function (this: SQLiteWorkerDatabase, sql, ...args) {
        if (sql.startsWith("INSERT INTO admission")) admissionWrites++; return execute.call(this, sql, ...args);
      });
      try {
        await expect(connect(f.a.publicOwner, f.source, request)).rejects.toThrow(); expect(responses).toBe(0);
        expect(admissionWrites).toBe(behavior === "production_cancel_sign" ? 1 : 0);
      } finally { sends.mockRestore(); writes.mockRestore(); await f.close(); }
    }, 15000);
  }
  for (const serverBehavior of ["production", "production_public"] as const) for (const profile of [profileX, profileP] as const) for (const binding of ["authenticated_context", "direct_exporter"] as const) for (const tls of ["ca", "pin"] as const) {
    it(`establishes ${serverBehavior} server admission chain: ${profile} ${binding} ${tls}`, async () => {
      const f = await setup(profile, tls, serverBehavior, "https://app.example.com", false, binding);
      try {
        const session = await connect(f.a.publicOwner, f.source, request), peer = await f.accepted;
        expect(peer.info().guarantees.local_consumer_tls13_verification).toBe("not_applicable");
        if (serverBehavior === "production_public") {
          const stream = await session.openStream("example/served"), payload = fill(76, 19);
          await stream.write(payload); await stream.closeWrite(); expect((await stream.read(128n)).data).toEqual(payload);
          expect((await stream.read(1n)).stream_status).toBe("eof"); await stream.finish();
          await session.rekey(); await session.probeLiveness(); await Promise.all([session.close(), peer.close()]); return;
        }
        const opening = session.openStream("example/production-server"), incoming = await peer.acceptStream(), stream = await opening;
        const payload = fill(76, 19); expect((await stream.write(payload)).accepted_bytes).toBe(19n); await stream.closeWrite();
        expect((await incoming.stream.read(19n)).data).toEqual(payload); expect((await incoming.stream.read(1n)).stream_status).toBe("eof");
        expect((await incoming.stream.write(payload)).accepted_bytes).toBe(19n); await incoming.stream.closeWrite();
        expect((await stream.read(19n)).data).toEqual(payload); expect((await stream.read(1n)).stream_status).toBe("eof");
        await Promise.all([stream.finish(), incoming.stream.finish()]); await session.rekey(); await session.probeLiveness();
        await Promise.all([session.close(), peer.close()]); expect(f.failure()).toBeUndefined();
      } finally { await f.close(); }
    }, 15000);
  }
  for (const profile of [profileX, profileP] as const) it(`preserves untransferred material across native Promise cancellation: ${profile}`, async () => {
    const f = await setup(profile, "ca");
    try {
      const material = f.client.verifyPoolMaterial(f.policy, f.fixture.input());
      for (const entry of ["source", "material"] as const) {
        const abort = new AbortController(); let entered = false;
        const stop = promiseHooks.createHook({
          init() {
            if (entered) return;
            entered = true; abort.abort();
          }
        });
        let pending;
        try { pending = entry === "source" ? connect(f.a.publicOwner, f.source, request, { signal: abort.signal }) : connectMaterial(f.a.publicOwner, material, { signal: abort.signal }); }
        finally { stop(); }
        await expect(pending).rejects.toThrow("canceled");
        expect(entered).toBe(true);
        expect(f.counts()).toEqual({ acquisitions: 0, helloCount: 0, connections: 0 });
      }
      const session = await connectMaterial(f.a.publicOwner, material), peer = await f.accepted;
      await session.rekey();
      const opening = session.openStream("example/cancel-before-transfer"), incoming = await peer.acceptStream(), stream = await opening;
      const payload = fill(76, 19);
      expect((await stream.write(payload)).accepted_bytes).toBe(19n); await stream.closeWrite();
      expect((await incoming.stream.read(19n)).data).toEqual(payload);
      expect((await incoming.stream.read(1n)).stream_status).toBe("eof");
      expect((await incoming.stream.write(payload)).accepted_bytes).toBe(19n); await incoming.stream.closeWrite();
      expect((await stream.read(19n)).data).toEqual(payload);
      expect((await stream.read(1n)).stream_status).toBe("eof");
      await Promise.all([stream.finish(), incoming.stream.finish()]);
      expect((await session.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      expect(f.counts()).toEqual({ acquisitions: 0, helloCount: 1, connections: 1 });
      await Promise.all([session.close(), peer.close()]); expect(f.failure()).toBeUndefined();
    } finally { await f.close(); }
  }, 15000);

  it("releases transferred material when Session admission fails before the native carrier", async () => {
    const f = await setup(profileX, "ca");
    try {
      const resources = f.a.owner.resources, before = f.a.root.snapshot();
      const material = f.client.verifyPoolMaterial(f.policy, f.fixture.input());
      const snapshot = f.a.root.snapshot();
      const pressure = f.a.root.reserve({
        accounts: resources.accounts, owner: { ...resources.owner, kind: "test_material_admission_pressure" },
        charge: new ResourceVector([snapshot.limit.values()[0]! - snapshot.charged.values()[0]! - (1n << 20n), 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])
      });
      try {
        await expect(connectMaterial(f.a.publicOwner, material)).rejects.toThrow("resource_exhausted");
        expect(f.counts()).toEqual({ acquisitions: 0, helloCount: 0, connections: 0 });
      } finally { pressure.release(); }
      await material.close();
      // No Environment.Close is needed to retire a failed static attempt.
      expect(f.a.root.snapshot().charged.values()).toEqual(before.charged.values());
      expect(f.a.root.snapshot().reservations).toBe(before.reservations);
      expect(f.a.root.snapshot().references).toBe(before.references);
      await expect(connectMaterial(f.a.publicOwner, material)).rejects.toThrow("material_unavailable");
      const session = await connect(f.a.publicOwner, f.source, request), peer = await f.accepted;
      await Promise.all([session.close(), peer.close()]); expect(f.failure()).toBeUndefined();
    } finally { await f.close(); }
  }, 15000);

  for (const profile of [profileX, profileP] as const) for (const mode of ["ca", "pin"] as const) it(`connects through durable consume, HELLO and dual READY: ${profile}, ${mode}`, async () => {
    const f = await setup(profile, mode);
    try {
      if (mode === "ca") {
        const resources = f.a.owner.resources, snapshot = f.a.root.snapshot();
        const pressure = f.a.root.reserve({
          accounts: resources.accounts, owner: { ...resources.owner, kind: "test_headroom_pressure" },
          charge: new ResourceVector([snapshot.limit.values()[0]! - snapshot.charged.values()[0]! - (1n << 20n), 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])
        });
        try {
          await expect(connect(f.a.publicOwner, f.source, request)).rejects.toThrow("resource_exhausted");
          expect(f.counts()).toEqual({ acquisitions: 0, helloCount: 0, connections: 0 });
        } finally { pressure.release(); }
        // Free bytes alone cannot promise admission when root account slots
        // are occupied. Failure must precede source acquisition as well.
        const held: ResourceAccount[] = [];
        try {
          for (let index = 1; index <= 32; index++) {
            try { held.push(f.a.root.account("pool", index.toString(16).padStart(32, "f"), snapshot.limit)); }
            catch (error) { expect(error).toMatchObject({ message: "resource_exhausted" }); break; }
          }
          await expect(connect(f.a.publicOwner, f.source, request)).rejects.toThrow("resource_exhausted");
          expect(f.counts()).toEqual({ acquisitions: 0, helloCount: 0, connections: 0 });
        } finally { for (const account of held) account.close(); }
      }
      await expect(connect(f.a.publicOwner, f.source, { application_profile: "services" })).rejects.toThrow("connection_requirement_unavailable");
      await expect(connect(f.a.publicOwner, f.source, { independent_reliable_read_progress: true })).rejects.toThrow("required_guarantee_unavailable");
      expect(f.counts()).toEqual({ acquisitions: 0, helloCount: 0, connections: 0 });
      const session = mode === "pin" ? await connectMaterial(f.a.publicOwner, f.client.verifyPoolMaterial(f.policy, f.fixture.input())) : await connect(f.a.publicOwner, f.source), peer = await f.accepted;
      expect(session.info().guarantees.local_consumer_tls13_verification).toBe("consumer_enforced");
      const opening = session.openStream("example/node-wss"), incoming = await peer.acceptStream(), outgoing = await opening;
      expect((await outgoing.write(fill(89, 12))).accepted_bytes).toBe(12n); expect((await incoming.stream.read(12n)).data).toEqual(fill(89, 12));
      await session.rekey(); expect((await session.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      await Promise.all([session.close(), peer.close()]); f.a.owner.cleanupStatus();
      await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed", connection: { networkReady: "not_started" } }); expect(f.counts().helloCount).toBe(1); expect(f.failure()).toBeUndefined();
    } finally { await f.close(); }
  }, 15000);
  for (const profile of [profileX, profileP] as const) it(`binds actual TLS exporter through Noise and READY: ${profile}`, async () => {
    const f = await setup(profile, "pin", "ready", "https://app.example.com", false, "direct_exporter");
    try {
      const session = await connect(f.a.publicOwner, f.source, request), peer = await f.accepted;
      const opening = session.openStream("example/exporter"), incoming = await peer.acceptStream(), outgoing = await opening;
      expect((await outgoing.write(fill(51, 17))).accepted_bytes).toBe(17n); expect((await incoming.stream.read(17n)).data).toEqual(fill(51, 17));
      await Promise.all([session.close(), peer.close()]); expect(f.failure()).toBeUndefined();
    } finally { await f.close(); }
  }, 15000);
  for (const profile of [profileX, profileP] as const) it(`serves the proxy through current authenticated WSS Streams: ${profile}`, async () => {
    const body = new Uint8Array(2300).fill(97), observed: Uint8Array[] = [];
    let idleStarted = false, idleClosed = false;
    const upstream = createHTTPServer(async (request, response) => {
      for await (const chunk of request) observed.push(new Uint8Array(chunk as Buffer));
      if (request.url === "/idle") {
        response.on("close", () => { idleClosed = true; });
        response.writeHead(200, { "content-type": "text/event-stream" }); response.flushHeaders();
        idleStarted = true; return;
      }
      response.writeHead(200, { "content-type": "application/octet-stream" });
      response.end(body);
    });
    const sockets = new WebSocketServer({ server: upstream });
    sockets.on("connection", socket => socket.on("message", (payload, binary) => socket.send(payload, { binary })));
    upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
    const address = upstream.address(); if (address === null || typeof address === "string") throw new Error("listen");
    const origin = `http://127.0.0.1:${address.port}`, failures: unknown[] = [];
    const proxy = new ProxyServer({
      upstream: origin, upstreamOrigin: origin, maxBodyBytes: 4096,
      maxChunkBytes: 2048, maxWebSocketFrameBytes: 4096, onError: error => failures.push(error)
    });
    const f = await setup(profile, "pin");
    let io: ReturnType<typeof currentProxyStream> | undefined;
    let handle: ProxyBrowserHandle | undefined;
    const registrations: Array<ReturnType<Awaited<typeof f.accepted>["registerStream"]>> = [];
    try {
      handle = await connectProxyBrowser(f.a.publicOwner, f.source, {
        surface: {
          mode: "trusted", hostOrigin: origin, contentOrigin: origin,
          requestPolicy: { methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], paths: {}, allowWebSocket: true },
        },
        runtime: {
          maxBodyBytes: 4096, maxChunkBytes: 2048, maxMetadataBytes: 4096, maxWsFrameBytes: 4096,
        }
      });
      const session = handle.session, runtime = handle.runtime, peer = await f.accepted;
      let authorizations = 0;
      for (const declaration of proxy.streamHandlers((context, metadata) => {
        expect(context.authentication.localRole).toBe("server");
        expect(context.authentication.peerIdentityDigest).toBe(Buffer.from(digest("certificate_digest", f.fixture.client)).toString("hex"));
        expect(metadata.values.version).toBe(2);
        if (!["flowersec.proxy.http", "flowersec.proxy.websocket"].includes(String(metadata.values.protocol))) return false;
        authorizations++; return true;
      }, { applicationBytes: 1024n })) {
        registrations.push(peer.registerStream(declaration.kind, declaration.authorize, declaration.handler, declaration.options));
      }
      const stream = await session.openStream("flowersec-proxy/http1", { metadata: createStreamMetadata({ protocol: "flowersec.proxy.http", version: 2 }) });
      io = currentProxyStream(stream, { readBytes: 128, inputBackingBytes: 8192, finishTimeoutMS: 1000, cleanupTimeoutMS: 100 });
      const writer = { write: (bytes: Uint8Array) => writeAll(io!, bytes) };
      await writeProxyFrame(writer, "ProxyHTTPRequest", { v: 2, request_id: "current-wss", method: "POST", path: "/echo", headers: [] });
      for (let offset = 0; offset < body.length; offset += 1536) {
        const chunk = body.subarray(offset, offset + 1536);
        await writeAll(io, u32be(chunk.length)); await writeAll(io, chunk);
      }
      await writeAll(io, u32be(0)); await writeProxyFrame(writer, "ProxyBodyEnd", { v: 2, trailers: [] });
      await io.closeWrite();
      const reader = new ProxyByteReader(io), response = await readProxyFrame(reader, "ProxyHTTPResponse", 4096);
      expect(response).toMatchObject({ v: 2, request_id: "current-wss", ok: true, status: 200 });
      const chunks: Uint8Array[] = [];
      for (; ;) { const size = readU32be(await reader.readExactly(4), 0); if (size === 0) break; chunks.push(await reader.readExactly(size)); }
      expect(await readProxyFrame(reader, "ProxyBodyEnd", 4096)).toEqual({ v: 2, trailers: [] });
      expect(Buffer.concat(chunks)).toEqual(Buffer.from(body)); expect(Buffer.concat(observed)).toEqual(Buffer.from(body));
      expect(await io.read()).toBeNull(); await io.finish(); io.dispose();
      await expect.poll(() => io!.cleanupStatus().status).toBe("complete");
      await expect.poll(() => proxy.activeCount).toBe(0);
      expect(authorizations).toBe(1); expect(failures).toEqual([]);
      await expect(session.openStream("flowersec-proxy/http1", { metadata: createStreamMetadata({ protocol: "denied", version: 2 }) })).rejects.toThrow();
      const fetched = await runtime.fetch("/echo", { method: "POST", body: body.slice() });
      expect(fetched.status).toBe(200); expect(new Uint8Array(await fetched.arrayBuffer())).toEqual(body);
      const websocket = await runtime.openWebSocketStream("/socket");
      const wsio = websocket.stream, wsReader = new ProxyByteReader(wsio);
      expect(websocket.protocol).toBe("");
      const frame = new Uint8Array([2, 0, 0, 0, 3, 7, 8, 9]);
      await writeAll(wsio, frame); expect(await wsReader.readExactly(frame.length)).toEqual(frame);
      const close = new Uint8Array([8, 0, 0, 0, 2, 3, 232]);
      await writeAll(wsio, close); await wsio.closeWrite();
      expect(await wsReader.readExactly(close.length)).toEqual(close);
      expect(await wsio.read()).toBeNull(); await wsio.finish!(); wsio.dispose?.();
      await expect.poll(() => proxy.activeCount).toBe(0);
      expect(authorizations).toBe(3); expect(failures).toEqual([]);
      const idle = await runtime.fetch("/idle", { headers: { accept: "text/event-stream" } });
      expect(idle.status).toBe(200); expect(idleStarted).toBe(true);
      await idle.body!.cancel();
      // Request FIN has already completed the post-body reader. Peer STOP
      // must still cancel the real upstream without waiting for another event.
      await expect.poll(() => idleClosed, { timeout: 1000 }).toBe(true);
      await expect.poll(() => proxy.activeCount).toBe(0);
      await expect.poll(() => io!.cleanupStatus().status).toBe("complete");
      expect(authorizations).toBe(4);
      await session.rekey(); expect((await session.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      for (const registration of registrations) registration.close();
      await Promise.all(registrations.map(registration => registration.waitCleanup()));
      await Promise.all([session.close(), peer.close()]);
    } finally {
      await handle?.dispose(); io?.dispose(); for (const registration of registrations) registration.close();
      await proxy.close(); await f.close();
      for (const socket of sockets.clients) socket.terminate();
      await new Promise<void>(resolve => sockets.close(() => resolve()));
      upstream.closeAllConnections(); await new Promise<void>(resolve => upstream.close(() => resolve()));
    }
  }, 15000);
  for (const behavior of ["bad_exporter", "downgrade"] as const) it(`refuses ${behavior} without another handshake`, async () => {
    const f = await setup(profileX, "pin", behavior, "https://app.example.com", false, "direct_exporter");
    try {
      await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed" });
      expect(f.counts().helloCount).toBe(1);
      await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed", connection: { networkReady: "not_started" } });
      expect(f.counts().helloCount).toBe(1); expect(f.failure()).toBeUndefined();
    } finally { await f.close(); }
  });
  it("authenticates a signed rejection with zero identity sentinels and leaves the lease spent", async () => {
    const f = await setup(profileX, "pin", "reject");
    try { await expect(connect(f.a.publicOwner, f.source, request)).rejects.toThrow("admission_rejected"); await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed", connection: { networkReady: "not_started" } }); expect(f.counts().helloCount).toBe(1); expect(f.failure()).toBeUndefined(); }
    finally { await f.close(); }
  });
  it("rejects an echoed attempt mismatch before FSB and does not reuse the consumed lease", async () => {
    const f = await setup(profileX, "pin", "bad_echo");
    try { await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed" }); await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed", connection: { networkReady: "not_started" } }); expect(f.counts().helloCount).toBe(1); }
    finally { await f.close(); }
  });
  it("checks the exact Origin before creating a native carrier or consuming a lease", async () => {
    const f = await setup(profileX, "pin", "ready", "https://other.example.com");
    try { await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed" }); expect(f.counts()).toEqual({ acquisitions: 1, connections: 0, helloCount: 0 }); }
    finally { await f.close(); }
  });
  it("rejects a signed DER pin mismatch before WebSocket or HELLO", async () => {
    const f = await setup(profileX, "pin", "ready", "https://app.example.com", true);
    try { await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "authentication_failed" }); expect(f.counts()).toEqual({ acquisitions: 1, connections: 0, helloCount: 0 }); }
    finally { await f.close(); }
  });
  it("cancels the original live HELLO read and closes its actual socket tail", async () => {
    const f = await setup(profileX, "pin", "pause"), abort = new AbortController();
    try {
      const connecting = connect(f.a.publicOwner, f.source, request, { signal: abort.signal }), failed = expect(connecting).rejects.toThrow("canceled");
      await f.helloObserved; abort.abort(); await failed; expect(f.counts().helloCount).toBe(1);
      await expect(connect(f.a.publicOwner, f.source, request)).rejects.toMatchObject({ name: "ConnectionError", code: "controller_failed", connection: { networkReady: "not_started" } });
    } finally { await f.close(); }
  });
});
