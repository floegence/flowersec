import { createServer as createNetServer, isIP, type Socket } from "node:net";
import { createServer as createHTTPSServer } from "node:https";
import type { IncomingMessage } from "node:http";
import { type TLSSocket } from "node:tls";
import { KeyObject, createPublicKey, sign, constants } from "node:crypto";
import { WebSocketServer } from "ws";
import type { V4TransportEnvironment } from "../v4/public.js";
import { ServeError, createServeListener, createServeHandle, type ServeListener } from "../v4/serve.js";
import { type HandlerPlan, captureHandlerPlan } from "../v4/handlerPlan.js";
import { ServeGroup, type ServeGroupLimits, type ServeIngress } from "../v4/runtime/serveGroup.js";
import { originalEnvironment, type V4CredentialPolicy, type V4CredentialBuffers, type V4CredentialLengths, type EnvironmentDependency, type V4EnvironmentMaterial } from "../v4/runtime/environment.js";
import { captureReliableClientLimits, type ReliableClientLimits } from "../v4/runtime/clientSessionSpec.js";
import { reliableServerSpec } from "../v4/runtime/serverSessionSpec.js";
import { ServerAdmissionExchange, serverAdmissionCharge } from "../v4/runtime/serverAdmission.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { wire } from "../v4/runtime/wireRegistry.js";
import { requireCredential } from "../v4/runtime/credentialSupport.js";
import { NodeWSSCarrier, nodeWSSAdmissionCosts } from "./wssV4.js";
import { SQLiteAdmissionStore } from "./sqliteAdmission.js";

export interface NodeWSSListenerOptions {
  readonly path?: "direct" | "tunnel";
  readonly host: string;
  readonly port: number;
  readonly serverName: string;
  readonly tls: Readonly<{ certificate: string; privateKey: string }>;
  readonly identityKey: KeyObject;
  readonly noiseKey: KeyObject;
  readonly admissionStore: SQLiteAdmissionStore;
  readonly credentials: Readonly<{
    source: "preauthorized_pool" | "live_authority";
    policy: V4CredentialPolicy;
    /** Trusted bounded material lookup. HELLO is only an unverified selector.
     * Resolution ends every buffer borrow, including on cancellation. */
    resolve(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, buffers: V4CredentialBuffers): Promise<V4CredentialLengths>;
    /** Transfers the exact server-local original prepared material once. */
    takePreparedHop?(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>): Promise<V4EnvironmentMaterial>;
    resolveHop?(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, buffers: V4CredentialBuffers): Promise<V4CredentialLengths>;
  }>;
  readonly limits: ReliableClientLimits;
  readonly ingress: ServeGroupLimits;
  readonly carrier: Readonly<{ queueMessages: number; nativeBytes: bigint; prepareBytes: number }>;
  readonly bindingMode?: "direct_exporter" | "authenticated_context";
}
export interface NodeWSSListener {
  readonly listener: ServeListener<HandlerPlan>;
  address(): Readonly<{ host: string; port: number }>;
}
interface Connection {
  readonly key: string;
  readonly raw: Socket;
  readonly dependency: EnvironmentDependency;
  readonly ingress: ServeIngress<HandlerPlan>;
  readonly nativeDone: Promise<void>; readonly preparation?: TrustedDeadline;
  running: boolean;
  nativeEnded: boolean;
  transport?: NodeWSSCarrier;
}
/** Owns TCP admission before TLS parsing, one bounded HTTP upgrade, and the
 * original WSS/Session lifetime. It never closes the borrowed Environment. */
export function createNodeWSSListener(environment: V4TransportEnvironment, input: NodeWSSListenerOptions): NodeWSSListener {
  const runtime = originalEnvironment(environment), runtimeBytes = runtime.resources.runtimeBytes;
  const host = input.host, port = input.port, serverName = input.serverName;
  const certificate = input.tls.certificate, privateKeyPEM = input.tls.privateKey;
  const identityKey = input.identityKey, noiseKey = input.noiseKey, store = input.admissionStore;
  const limits = captureReliableClientLimits(input.limits), ingress = Object.freeze({ ...input.ingress });
  const provider = input.credentials.resolve, hopProvider = input.credentials.resolveHop, preparedProvider = input.credentials.takePreparedHop, source = input.credentials.source, p = input.credentials.policy, path = input.path ?? (p.tunnel === undefined ? "direct" : "tunnel");
  const policy = Object.freeze({ tenant: p.tenant, audience: p.audience, clientSubject: p.clientSubject, serverSubject: p.serverSubject, ...(p.tunnel === undefined ? {} : { tunnel: Object.freeze({ ...p.tunnel }) }),
    authorities: Object.freeze([...p.authorities]), cryptoProfiles: Object.freeze([...p.cryptoProfiles]) });
  const carrier = Object.freeze({ ...input.carrier, remoteAddress: host, runtimeBytes });
  const bindingMode = input.bindingMode ?? "authenticated_context", handshakeMS = ingress.handshakeMS;
  requireCredential(path === "direct" || path === "tunnel" && policy.tunnel?.role === 1 && (typeof hopProvider === "function" || typeof preparedProvider === "function") && bindingMode === "authenticated_context", "configuration_capacity");
  requireCredential(isIP(host) !== 0 && Number.isSafeInteger(port) && port >= 0 && port <= 65535 && typeof serverName === "string" && serverName.length > 0 && serverName.length <= 253 &&
    typeof certificate === "string" && certificate.length > 0 && certificate.length <= 65536 && typeof privateKeyPEM === "string" && privateKeyPEM.length > 0 && privateKeyPEM.length <= 65536 &&
    identityKey instanceof KeyObject && identityKey.type === "private" && identityKey.asymmetricKeyType === "ed25519" && noiseKey instanceof KeyObject && noiseKey.type === "private" &&
    ["x25519", "ec"].includes(noiseKey.asymmetricKeyType ?? "") && store instanceof SQLiteAdmissionStore && typeof provider === "function" &&
    (source === "preauthorized_pool" || source === "live_authority") && (bindingMode === "authenticated_context" || bindingMode === "direct_exporter"), "configuration_capacity");
  for (const value of [limits.maxFrame, limits.maxStreams, limits.receiveQueueBytes, limits.maxDataBytes, limits.maxCursorBytes, limits.maxWriteBytes, limits.cryptoKeys])
    requireCredential(Number.isSafeInteger(value) && value > 0 && value <= 16777216, "configuration_capacity");
  for (const value of [limits.writeDeadlineMS, limits.operationDeadlineMS, limits.rekeyPrepareMS, limits.rekeyProtocolMS, limits.rekeyConfirmationMS])
    requireCredential(typeof value === "bigint" && value > 0n && value <= 0xffffffffffffffffn, "configuration_capacity");
  requireCredential(limits.receiveQueueBytes >= limits.maxDataBytes && limits.cryptoKeys <= 65536, "configuration_capacity");
  const nativeCharge = nodeWSSAdmissionCosts(limits.maxFrame, carrier, runtimeBytes)[0]![1];
  let address: Readonly<{ host: string; port: number }> | undefined;
  const listener = createServeListener<HandlerPlan>({ environment, async start(callbacks, maintenanceOwner, signal) {
    const group = new ServeGroup(runtime, ingress, callbacks, signal);
    let infrastructure: EnvironmentDependency | undefined;
    let boundListener = false;
    let privateKey = new Uint8Array(), publicKey = new Uint8Array();
    try {
      infrastructure = runtime.admitDependency("wss_listener", new ResourceVector([524288n + runtimeBytes, carrier.nativeBytes, 0n, 8n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
      const identityJWK = createPublicKey(identityKey).export({ format: "jwk" }), noiseJWK = noiseKey.export({ format: "jwk" });
      requireCredential(identityJWK.crv === "Ed25519" && typeof identityJWK.x === "string" && typeof noiseJWK.d === "string" && ["X25519", "P-256"].includes(noiseJWK.crv ?? ""), "configuration_capacity");
      publicKey = new Uint8Array(Buffer.from(identityJWK.x, "base64url")); privateKey = new Uint8Array(Buffer.from(noiseJWK.d, "base64url")); noiseJWK.d = "";
      const signer = Object.freeze({ publicKey, sign: (bytes: Uint8Array) => { infrastructure!.check(); return new Uint8Array(sign(null, bytes, identityKey)); } });
      const acceptor = new Uint8Array(16); runtime.fillRandom(acceptor);
      const connections = new Map<string, Connection>();
      const network = createNetServer({ pauseOnConnect: true }), https = createHTTPSServer({ key: privateKeyPEM, cert: certificate,
        minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], secureOptions: constants.SSL_OP_NO_TICKET,
        maxHeaderSize: 16384, highWaterMark: 16384, handshakeTimeout: Number(ingress.handshakeMS), requestTimeout: Number(ingress.handshakeMS), headersTimeout: Number(ingress.handshakeMS) });
      https.maxHeadersCount = 32; https.maxRequestsPerSocket = 1; network.maxConnections = ingress.positions;
      const wss = new WebSocketServer({ noServer: true, clientTracking: false, perMessageDeflate: false, maxPayload: Math.max(limits.maxFrame, 65536) + 8,
        handleProtocols: protocols => { const protocol = path === "direct" ? "flowersec.direct.v4" : "flowersec.tunnel.v4"; return protocols.size === 1 && protocols.has(protocol) ? protocol : false; } });
      let sealing = false, networkEnded = false, websocketEnded = false, nativeReleased = false;
      const collect = (): void => {
        if (nativeReleased || !sealing || !networkEnded || !websocketEnded || [...connections.values()].some(entry => !entry.nativeEnded)) return;
        group.listenerCoreEnded();
        if (connections.size !== 0) return;
        nativeReleased = true;
        privateKey.fill(0); publicKey.fill(0); acceptor.fill(0); infrastructure!.release(); infrastructure = undefined;
        group.listenerEnded();
      };
      const key = (socket: Socket): string => `${socket.remoteAddress ?? ""}/${socket.remotePort ?? 0}/${socket.localPort ?? 0}`;
      const retire = async (entry: Connection): Promise<void> => {
        try {
          entry.raw.destroy(); await entry.nativeDone;
          if (entry.transport !== undefined) await entry.transport.close(); else entry.dependency.release();
          await entry.ingress.finish();
        } finally { connections.delete(entry.key); collect(); }
      };
      const seal = (): void => {
        if (sealing) return; sealing = true;
        network.close(() => { networkEnded = true; collect(); }); wss.close(() => { websocketEnded = true; collect(); });
      };
      group.bindListener(seal, () => { for (const entry of connections.values()) entry.ingress.abort(); });
      boundListener = true; infrastructure.onClose(() => group.close());
      network.on("error", () => group.close()); https.on("error", () => group.close()); wss.on("error", () => group.close());
      network.on("connection", raw => {
        let dependency: EnvironmentDependency | undefined;
        try {
          group.checkIngress(); dependency = runtime.admitDependency("accepted_wss", nativeCharge);
          const ingress = group.begin(() => raw.destroy()), connectionKey = key(raw);
          let ended!: () => void; const nativeDone = new Promise<void>(resolve => { ended = resolve; });
          const entry: Connection = { key: connectionKey, raw, dependency, ingress, nativeDone, running: false, nativeEnded: false, ...(path === "direct" ? {} : { preparation: TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), handshakeMS, 0xffffffffffffffffn) }) }; connections.set(connectionKey, entry);
          raw.on("error", () => ingress.abort()); raw.once("close", () => {
            ended(); ingress.abort();
            void (entry.transport?.waitTermination() ?? nativeDone).then(() => { entry.nativeEnded = true; ingress.nativeEnded(); collect(); });
            if (!entry.running) { entry.running = true; void retire(entry); }
          });
          https.emit("connection", raw); raw.resume();
        } catch { raw.destroy(); if (dependency !== undefined) { if (raw.closed) dependency.release(); else raw.once("close", () => dependency!.release()); } }
      });
      https.on("request", (request, response) => { response.destroy(); request.socket.destroy(); });
      https.on("clientError", (_error, socket) => socket.destroy()); https.on("tlsClientError", (_error, socket) => socket.destroy());
      https.on("upgrade", (request, socket, head) => {
        const entry = connections.get(key(request.socket));
        if (entry === undefined || entry.running) { socket.destroy(); return; } entry.running = true;
        const run = async (): Promise<void> => {
          let exchange: ServerAdmissionExchange | undefined, material: V4EnvironmentMaterial | undefined;
          let planCapture: ReturnType<typeof captureHandlerPlan> | undefined, prepared: ReturnType<typeof runtime.prepareTunnelCredentials> | undefined;
          const work = runtime.reserveConnectionWork("server_material_input", new ResourceVector([(path === "direct" ? 278528n : 344080n) + runtimeBytes, 0n, 0n, 8n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
          const buffers = { artifact: new Uint8Array(65536), clientCertificate: new Uint8Array(16384), serverCertificate: new Uint8Array(16384), activation: new Uint8Array(65536), tunnelGrant: new Uint8Array(65536), relayCertificate: new Uint8Array(16384) };
          try {
            entry.ingress.check();
            checkUpgrade(request, head, serverName, address!.port, path);
            await entry.ingress.authorizeRequest(request.headers.origin ?? ""); entry.ingress.check();
            // handleUpgrade synchronously transfers the original native socket.
            wss.handleUpgrade(request, socket, head, websocket => {
              const transport = entry.transport = new NodeWSSCarrier(runtime, entry.dependency, Math.max(limits.maxFrame, 65536) + 8, carrier.queueMessages, "server", path, entry.preparation);
              transport.accept(websocket, request, { host: serverName, port: address!.port });
            });
            const transport = entry.transport; requireCredential(transport !== undefined, "credential_closed");
            if (path === "tunnel" && preparedProvider === undefined) prepared = runtime.prepareTunnelCredentials(policy);
            const verifyMaterial = (lengths: V4CredentialLengths): V4EnvironmentMaterial => {
              for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation", "tunnelGrant", "relayCertificate"] as const) {
                const length = lengths[name] ?? 0; requireCredential(Number.isSafeInteger(length) && length >= 0 && length <= buffers[name].length, "credential_binding");
              }
              return runtime.verify(policy, { source, artifact: buffers.artifact.subarray(0, lengths.artifact), clientCertificate: buffers.clientCertificate.subarray(0, lengths.clientCertificate),
                serverCertificate: buffers.serverCertificate.subarray(0, lengths.serverCertificate), activation: buffers.activation.subarray(0, lengths.activation), candidateIndex: lengths.candidateIndex,
                ...(path === "direct" ? {} : { tunnel: { grant: buffers.tunnelGrant.subarray(0, lengths.tunnelGrant ?? 0), relayCertificate: buffers.relayCertificate.subarray(0, lengths.relayCertificate ?? 0) } }) }, prepared);
            };
            if (path === "tunnel") {
              const routing = await transport.read(65544, { signal: entry.ingress.signal });
              try {
                entry.ingress.check(); requireCredential(routing !== null && routing.length >= 8 && routing[4] === wire.frame_types.HOP_AUTH && routing[5] === 0 && routing[6] === 0 && routing[7] === 0 && new DataView(routing.buffer, routing.byteOffset, 8).getUint32(0) === routing.length - 8);
                const hello = routing.subarray(8), request = Object.freeze({ signal: entry.ingress.signal, hello });
                if (preparedProvider === undefined) { const lengths = await entry.ingress.resolveMaterial(() => hopProvider!(request, buffers)); material = verifyMaterial(lengths); }
                else {
                  // Capture custody before the ingress checks cancellation again.
                  material = await entry.ingress.resolveMaterial(async () => {
                    const original = await preparedProvider(request); material = original; return original;
                  });
                  runtime.checkOriginalServerPublication(material, work);
                }
                await runtime.authenticateAcceptedHop(material, transport, signer, hello, { signal: entry.ingress.signal });
              } finally { routing?.fill(0); }
            }
            const ref = runtime.reserveConnectionWork("server_admission", serverAdmissionCharge(runtimeBytes));
            try { exchange = new ServerAdmissionExchange(runtime.resources, transport, signer, bytes => runtime.fillRandom(bytes), ref, () => entry.ingress.check(), bindingMode); }
            finally { ref.release(); }
            const hello = await exchange.readHello({ signal: entry.ingress.signal });
            if (path === "direct") { const lengths = await entry.ingress.resolveMaterial(() => provider(Object.freeze({ signal: entry.ingress.signal, hello }), buffers)); material = verifyMaterial(lengths); }
            requireCredential(material !== undefined);
            const invocation = new Uint8Array(16), carrierID = new Uint8Array(16); runtime.fillRandom(invocation); runtime.fillRandom(carrierID);
            try {
              const session = await runtime.establishServer(material, async fields => {
                const authentication = exchange!.requestContext(), selected = await entry.ingress.authorize(authentication);
                const plan = planCapture = captureHandlerPlan(selected, runtime, maintenanceOwner); entry.ingress.check();
                requireCredential(fields.maxFrame <= limits.maxFrame && fields.rpcMaxGeneralOutstanding <= (limits.maxGeneralOutstanding ?? 1024) &&
                  limits.maxDataBytes + 41 <= fields.maxFrame && BigInt(limits.receiveQueueBytes) <= fields.maxCredit &&
                  (fields.profile.includes("x25519") ? noiseJWK.crv === "X25519" : noiseJWK.crv === "P-256"), "configuration_capacity");
                return { ...reliableServerSpec(fields, transport, signer, privateKey, limits, runtimeBytes, plan.application, plan.profile === "transport" ? "services" : plan.profile), initialRawStreams: plan.raw, claimReadySession: session => entry.ingress.claim(session) };
              }, exchange, store, { acceptor, invocation, carrier: carrierID, generation: 1n, signal: entry.ingress.signal }, { signal: entry.ingress.signal }).finally(() => entry.ingress.publishClaimed());
              await session.waitTermination();
            } finally { invocation.fill(0); carrierID.fill(0); }
          } finally { prepared?.close(); planCapture?.release(); exchange?.close(); await material?.closeMaterial(); for (const bytes of Object.values(buffers)) bytes.fill(0); work.release(); }
        };
        void run().catch(() => entry.ingress.abort()).finally(() => retire(entry));
      });
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const cleanup = (): void => { network.removeListener("listening", listening); network.removeListener("error", failed); network.removeListener("close", closed); };
        const failed = (): void => { if (settled) return; settled = true; cleanup(); reject(group.failure(signal?.aborted ? "canceled" : "serve_failed")); };
        const closed = (): void => failed();
        const listening = (): void => { if (settled) return; settled = true; cleanup(); resolve(); };
        network.once("error", failed); network.once("listening", listening); network.once("close", closed);
        try { group.checkIngress(); network.listen(port, host); } catch { failed(); }
      });
      const bound = network.address(); requireCredential(bound !== null && typeof bound !== "string"); address = Object.freeze({ host: bound.address, port: bound.port });
      group.checkIngress(); return createServeHandle(group);
    } catch {
      group.close();
      if (!boundListener) { infrastructure?.release(); infrastructure = undefined; privateKey.fill(0); publicKey.fill(0); group.listenerEnded(); }
      else await group.waitCleanup();
      throw new ServeError(signal?.aborted ? "canceled" : "serve_failed", group.cleanupStatus());
    }
  } });
  return Object.freeze({ listener, address: () => { if (address === undefined) throw new Error("not_listening"); return address; } });
}
function checkUpgrade(request: IncomingMessage, head: Buffer, host: string, port: number, path: "direct" | "tunnel"): void {
  const socket = request.socket as TLSSocket;
  requireCredential(head.length === 0 && request.method === "GET" && request.httpVersion === "1.1" && request.url === (path === "direct" ? "/flowersec/v4/direct" : "/flowersec/v4/tunnel") &&
    request.headers.host === `${isIP(host) === 6 ? `[${host}]` : host}${port === 443 ? "" : `:${port}`}` && request.headers["sec-websocket-protocol"] === (path === "direct" ? "flowersec.direct.v4" : "flowersec.tunnel.v4") &&
    request.headers["content-length"] === undefined && request.headers["transfer-encoding"] === undefined &&
    socket.getProtocol() === "TLSv1.3" && socket.alpnProtocol === "http/1.1" && !socket.isSessionReused() && request.rawHeaders.length <= 64 &&
    (request.headers.origin === undefined || typeof request.headers.origin === "string" && request.headers.origin.length <= 2048));
  const headers = new Set<string>();
  for (let i = 0; i < request.rawHeaders.length; i += 2) { const name = request.rawHeaders[i]!.toLowerCase(); requireCredential(!headers.has(name)); headers.add(name); }
}
