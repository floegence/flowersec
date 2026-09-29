import { expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { createServer } from "node:https";
import { once } from "node:events";
import WebSocket, { WebSocketServer } from "ws";
import { ed25519 } from "@noble/curves/ed25519.js";
import type { OperationOptions } from "../src/public/contract.js";
import { createV4TransportEnvironment, originalEnvironment, type V4EnvironmentSessionSpec } from "../src/v4/runtime/environment.js";
import { ResourceRoot, ResourceVector } from "../src/v4/runtime/resources.js";
import { ClockRate } from "../src/v4/runtime/timeArithmetic.js";
import { credentialFixture, fill, map, bytes, text, u, array, get, encode, digest, sign } from "../src/v4/testSupport/credentials.js";
import { Reference, type Value } from "../src/v4/testSupport/cbor.js";
import { wire } from "../src/v4/runtime/wireRegistry.js";
import { wireDomains } from "../src/v4/runtime/schemaRegistry.js";
import type { V4AuthenticatedTransport } from "../src/v4/runtime/session.js";
import type { NoiseProfile } from "../src/v4/runtime/noiseHandshake.js";
import { TrustedDeadline } from "../src/v4/runtime/deadline.js";
import { ProxyServer } from "../src/node/proxyServer.js";
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
function environment(timeOrigin: bigint) {
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 2000n, 2000n, 2000n, 2000n, 2000n, 2000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 32, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n }), start = performance.now();
  const publicOwner = createV4TransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 50,
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
function serverSpec(env: ReturnType<typeof environment>, fixture: ReturnType<typeof credentials>, transport: ServerTransport, profile: NoiseProfile, fsb: Uint8Array, fsa: Value, context: Value, timeOrigin: bigint): V4EnvironmentSessionSpec {
  const c = digest("certificate_digest", fixture.client), s = digest("certificate_digest", fixture.server), contextDigest = digest("transport_context_digest", context), binding = digest("admission_binding", decode(fsb));
  return { transport, maxFrame: 65536, maxReceiveDirections: 8, signer: { publicKey: ed25519.getPublicKey(fill(15)), sign: bytes => ed25519.sign(bytes, fill(15)) }, peerReadyPublicKey: ed25519.getPublicKey(fill(14)),
    noise: { role: "server", profile, localStaticPrivate: fill(17), localStaticPublic: fixture.publicNoise(1), peerStaticPublic: fixture.publicNoise(0), psk: fill(24),
      contextDigest, fsb, fsa: encode(fsa), authorizationDeadline: new TrustedDeadline(env.owner.clock, timeOrigin + 30000n), preparationDeadline: new TrustedDeadline(env.owner.clock, timeOrigin + 10000n) },
    ready: { localCertificateDigest: s, peerCertificateDigest: c, fsbDigest: digest("fsb_digest", decode(fsb)), fsaDigest: digest("fsa_digest", fsa), admissionBinding: binding, transportContextDigest: contextDigest, selectedFeatures: 0n },
    crypto: { keys: 100, maintenance: { calls: 64n, blocks: 8192n, bytes: 1048576n } },
    streams: { limits: { direction: 1, maxActive: 8, maxPending: 8, ingressItems: 8, ingressBytes: 65536, terminalCapacity: 32, rejectionReserve: 8, runtimeBytes: 1024n,
      perClass: [8, 0, 0], perOpener: [[8, 0, 0], [8, 0, 0]], protected: [[0, 0, 0], [0, 0, 0]] },
      receive: { maxDataBytes: 128, queueBytes: 256, maxCursorBytes: 1024, receiveLimit: 256n, runtimeBytes: 1024n, cursorRuntimeBytes: 1024n, decoderRuntimeBytes: 1024n },
      maxWriteBytes: 1024, writeDeadlineMS: 1000n, operationDeadlineMS: 1000n, rekeyBurst: 10n, rekeyRefillMS: 1000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n },
    info: { application_profile: "transport", selected_features: 0n, guarantees: { reliable_progress: "shared_ordered", bound_stream_input_isolation: "shared_failure_scope", datagram: false,
      local_consumer_tls13_verification: "not_applicable", scope: "complete_direct_path", assumptions: "authenticated_peer_within_transport_profile" } } };
}

export function createV4WSSPeerFixture(origin: string, port: number, profile: NoiseProfile, requireConsumer = false) {
  const timeOrigin = BigInt(Date.now()) - 1000n, env = environment(timeOrigin);
  const leg = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("localhost"), 7: u(port), 8: text("/flowersec/v4/direct"), 9: text("http/1.1"),
    10: text("flowersec.direct.v4"), 11: map({ 0: u(0), 1: { kind: "bool", value: requireConsumer } }), 12: map({ 0: array(text(origin)), 1: { kind: "bool", value: false } }) });
  return { timeOrigin, env, fixture: credentials(env, profile, leg, timeOrigin) };
}

export async function startV4WSSPeer(certificate: Buffer, key: Buffer, origin: string, profile: NoiseProfile, requireConsumer = false, proxyUpstream?: string) {
  const server = createServer({ key, cert: certificate, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"] });
  const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, handleProtocols: () => "flowersec.direct.v4" });
  server.on("upgrade", (request, socket, head) => {
    if (request.url !== "/flowersec/v4/direct" || request.headers.origin !== origin) { socket.destroy(); return; }
    wss.handleUpgrade(request, socket, head, ws => wss.emit("connection", ws, request));
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening"); const address = server.address(); if (address === null || typeof address === "string") throw new Error("listen");
  const { timeOrigin, env, fixture } = createV4WSSPeerFixture(origin, address.port, profile, requireConsumer), jobs: Promise<void>[] = []; let failure: unknown, connections = 0, hellos = 0;
  const proxyErrors: unknown[] = [];
  const proxy = proxyUpstream === undefined ? undefined : new ProxyServer({ upstream: proxyUpstream, upstreamOrigin: proxyUpstream,
    allowedOrigins: [origin], maxBodyBytes: 4096, maxChunkBytes: 64, maxJsonFrameBytes: 4096, maxWebSocketFrameBytes: 32,
    onError: error => proxyErrors.push(error) });
  wss.on("connection", ws => {
    connections++; const transport = new ServerTransport(ws);
    jobs.push((async () => {
      const first = await transport.read(65544); if (first === null) return; hellos++;
      const clientBytes = parseMessage(first, "NEGOTIATE"), hello = decode(clientBytes), fields = Object.fromEntries(Array.from({ length: 8 }, (_, id) => [id, get(hello, id)]));
      const response = map({ ...fields, 8: bytes(fill(31)), 9: u(0), 10: u(0), 11: u(1), 12: bytes(new Uint8Array()) }), serverBytes = encode(response);
      await transport.write(envelope("NEGOTIATE", serverBytes));
      const label = Buffer.from(wireDomains.find(d => d.name === "hello_transcript_digest")!.label_bytes, "hex"), size1 = Buffer.alloc(4), size2 = Buffer.alloc(4);
      size1.writeUInt32BE(clientBytes.length); size2.writeUInt32BE(serverBytes.length); const transcript = createHash("sha256").update(label).update(size1).update(clientBytes).update(size2).update(serverBytes).digest();
      const message = await transport.read(65544); if (message === null) return; const fsb = parseMessage(message, "ADMISSION"), parsed = decode(fsb);
      expect(buffer(get(parsed, 9))).toEqual(new Uint8Array(transcript));
      const context = map({ 0: text("4"), 1: text(profile), 2: u(0), 3: u(0), 4: get(hello, 3), 5: get(hello, 5), 6: get(hello, 6), 7: get(hello, 7), 8: bytes(transcript), 9: u(0), 10: u(1), 11: u(0), 12: bytes(new Uint8Array()) });
      const fsa = sign("FSA4", map({ 0: u(0), 1: u(0), 2: u(1), 3: bytes(fill(27)), 4: bytes(digest("admission_binding", parsed)), 5: get(hello, 5), 6: bytes(transcript), 7: u(0), 8: u(1),
        9: bytes(digest("transport_context_digest", context)), 10: bytes(digest("certificate_digest", fixture.client)), 11: bytes(digest("certificate_digest", fixture.server)), 12: bytes(encode(fixture.server)) }), 15);
      await transport.write(envelope("ADMISSION_RESULT", encode(fsa)));
      const material = env.owner.verify({ ...fixture.config, authorities: ["authority"] }, fixture.input());
      const session = await env.owner.establishVerified(material, serverSpec(env, fixture, transport, profile, fsb, fsa, context, timeOrigin), encode(context));
      if (proxy !== undefined) {
        const registrations = proxy.streamHandlers((_context, metadata) =>
          metadata.values.version === 2 && ["flowersec.proxy.http", "flowersec.proxy.websocket"].includes(String(metadata.values.protocol)),
        { applicationBytes: 1024n }).map(declaration => session.registerStream(declaration.kind, declaration.authorize, declaration.handler, declaration.options));
        try { await session.waitTermination(); }
        finally {
          for (const registration of registrations) registration.close();
          await Promise.all(registrations.map(registration => registration.waitCleanup()));
        }
      } else {
        const incoming = await session.acceptStream(), received = await incoming.stream.read(32n); await incoming.stream.write(received.data); await session.waitTermination();
      }
    })().catch(error => { failure = error; ws.terminate(); }));
  });
  const input = fixture.input();
  return { endpoint: `wss://localhost:${address.port}/flowersec/v4/direct`, timeOrigin: timeOrigin.toString(), route: Array.from(fixture.route), profile,
    input: { artifact: Array.from(input.artifact), clientCertificate: Array.from(input.clientCertificate), serverCertificate: Array.from(input.serverCertificate), activation: Array.from(input.activation), candidateIndex: 0 },
    bootstrap: (nonce: number[]) => ({ response: Array.from(fixture.response(new Uint8Array(nonce))), state: Array.from(encode(fixture.state)) }),
    counts: () => ({ connections, hellos }), proxyActiveCount: () => proxy?.activeCount ?? 0, proxyErrors: () => proxyErrors, failure: () => failure,
    close: async () => {
      await env.publicOwner.close(); for (const socket of wss.clients) socket.terminate(); await Promise.all(jobs); await proxy?.close();
      await new Promise<void>(resolve => wss.close(() => resolve())); await new Promise<void>(resolve => server.close(() => resolve()));
      expect((await env.publicOwner.waitCleanup()).status).toBe("complete"); expect(env.root.snapshot().reservations).toBe(0);
    } };
}
