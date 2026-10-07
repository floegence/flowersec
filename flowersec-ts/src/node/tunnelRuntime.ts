import { prepareRegisteredCarrier, type RegisteredCarrierPreparation } from "../v4/runtime/registeredCarrierPreparation.js";
import type { CredentialInput } from "../v4/runtime/credentialVerifier.js";
import { observeTask } from "../v4/runtime/taskObservation.js";
import { createPublicKey, createPrivateKey, constants, sign, X509Certificate, type KeyObject } from "node:crypto";
import { createServer as createNetServer, type Server as NetServer, type Socket, isIP } from "node:net";
import { createServer as createHTTPSServer } from "node:https";
import { WebSocketServer } from "ws";
import { captureNodeWSS, nodeWSSAdmissionCosts, nodeWSSRelayDialPolicy, prepareNodeWSS, NodeWSSCarrier, type V4NodeWSSOptions } from "./wssV4.js";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency } from "../v4/runtime/environment.js";
import { TrustedDeadline, timerChunk } from "../v4/runtime/deadline.js";
import { CredentialWork, credentialWorkCharge, credentialOwner, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { verifyRelayCredentials, relayCredentialCharge, type RelayCredentialConfig, type VerifiedRelayCredentials, type VerifiedRelayClaim, type RelayCredentialInput } from "../v4/runtime/relayCredentials.js";
import { HopAuthentication, hopAuthenticationCharge } from "../v4/runtime/hopAuthentication.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { NativeProviderPositions } from "../v4/runtime/nativeProviderPositions.js";
import { loadCurrentNativeTransport, loadCurrentNativeWebTransport, bindCurrentNativeListener, type NativeOperation, type NativeRawListener, type NativeRawSession } from "./nativeTransportCurrent.js";
import { captureNodeRawQUIC, nodeRawQUICAdmissionCosts, nativeRawQUICQueueBytes, rawQUICRelayDialPolicy, prepareNodeRawQUIC, NodeRawQUICCarrier, type NodeRawQUICOptions } from "./rawQUICCurrent.js";
import { SQLiteAdmissionStore, type RelayActivationOwner } from "./sqliteAdmission.js";
import { RelayNativePair, RelayNativePairPreparation, relayNativePairCharge, RelayHopByteMeter, readRelayEnvelope, type RelayNativePairLimits } from "./relayNativePair.js";
import { isTunnelListenerPreparation, type TunnelListenerPreparation } from "./tunnelListenerPreparation.js";
import { wire } from "../v4/runtime/wireRegistry.js";

export type TunnelCarrierOptions = NodeRawQUICOptions | (V4NodeWSSOptions & Readonly<{ nativeCarrier: "wss" }>);
type TunnelHopCarrier = NodeRawQUICCarrier | NodeWSSCarrier;
function isWSS(options: TunnelCarrierOptions): options is V4NodeWSSOptions & Readonly<{ nativeCarrier: "wss" }> { return options.nativeCarrier === "wss"; }
function closeCarrierRoots(options: TunnelCarrierOptions | undefined): void {
  if (options === undefined) return;
  if (isWSS(options)) { for (const root of options.ca ?? []) if (root instanceof Uint8Array) root.fill(0); }
  else for (const root of options.trustRootsDER ?? []) root.fill(0);
}
function carrierRootBytes(options: TunnelCarrierOptions): number {
  if (isWSS(options)) return (options.ca ?? []).reduce((total, root) => total + (typeof root === "string" ? Buffer.byteLength(root) : root.length), 0);
  return (options.trustRootsDER ?? []).reduce((total, root) => total + root.length, 0);
}
export interface TunnelRuntimeListenerOptions {
  readonly host: string; readonly port: number; readonly serverName: string;
  readonly tls: Readonly<{ certificateChainDER: readonly Uint8Array[]; privateKeyDER: Uint8Array }>;
  readonly preparedListener?: TunnelListenerPreparation;
}
export interface TunnelRuntimeOptions {
  readonly environment: V4TransportEnvironment;
  readonly host: string; readonly port: number; readonly serverName: string;
  readonly tls: Readonly<{ certificateChainDER: readonly Uint8Array[]; privateKeyDER: Uint8Array }>;
  readonly preparedListener?: TunnelListenerPreparation;
  readonly identityKey: KeyObject;
  readonly relayCertificate: Uint8Array;
  readonly credentials: Omit<RelayCredentialConfig, "resources" | "clock" | "endpointSubject"> & Readonly<{ clientSubject: string; serverSubject: string }>;
  readonly activationStore: SQLiteAdmissionStore;
  readonly carrier: TunnelCarrierOptions;
  /** Additional trusted native choices for relay-initiated client legs. */
  readonly carrierAlternatives?: readonly NodeRawQUICOptions[];
  /** Logical endpoint accepted on the primary physical listener. */
  readonly ingressRole?: 0 | 1;
  /** A second original physical listener when both endpoints dial the relay. */
  readonly oppositeListener?: TunnelRuntimeListenerOptions;
  /** Independently configured server endpoint leg, captured before claims. */
  readonly serverCarrier?: TunnelCarrierOptions;
  /** Additional trusted native choices for relay-initiated server legs. */
  readonly serverCarrierAlternatives?: readonly NodeRawQUICOptions[];
  readonly forwarding: RelayNativePairLimits;
  /** Bind the original listener before acknowledging the fixed deployment. */
  readonly deferForwarding?: boolean;
  readonly maxPairs: number; readonly handshakeMS: bigint;
}
export interface TunnelRuntimeStatus { readonly listening: boolean; readonly activePairs: number; readonly rejectedHops: bigint; readonly authenticatedPairs: bigint; readonly forwardedBytes: bigint; readonly forwardedDatagrams: bigint; readonly lastFailure?: string; }
interface Entry {
  readonly raw?: NativeRawSession; readonly incoming?: NodeWSSCarrier; readonly rawSocket?: Socket; readonly nativeDone?: Promise<void>;
  readonly preparation?: TrustedDeadline; readonly finishIngress?: () => void; readonly abort: AbortController; promise: Promise<void> | undefined; close: () => void;
}
interface PreparedRelayIngress {
  readonly entry: Entry; readonly carrier: TunnelHopCarrier; readonly credentials: VerifiedRelayCredentials;
  readonly hello: Uint8Array; readonly key: string; readonly preparation: TrustedDeadline; readonly finishHandshake: () => void; readonly complete: () => void;
  taken: boolean;
}
interface RelayIngressWaiter { readonly take: (ingress: PreparedRelayIngress) => void; readonly cancel: () => void; }
interface RelayIngressDelegate { readonly accept: (entry: Entry, listener: TunnelRuntime) => Promise<void>; }
interface OriginalLivePreparedCarrier { readonly registry: RegisteredCarrierPreparation; readonly abort: AbortController; prepared: Promise<void>; carrier?: TunnelHopCarrier; timer: ReturnType<typeof setTimeout> | undefined; taken: boolean; closed: boolean; closing?: Promise<void>; }
const runtimeOwners = new WeakSet<TunnelRuntime>();
const runtimeCapability = Symbol("current native tunnel runtime");
/** Owns an ordinary current relay deployment. It authenticates only hop
 * possession, original issuance and durable per-leg claims. It has no endpoint
 * Session, handler plan, Noise keys, PSK, application dispatch or READY API. */
export class TunnelRuntime {
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #options: TunnelRuntimeOptions; readonly #carrier: TunnelCarrierOptions; readonly #serverCarrier: TunnelCarrierOptions;
  readonly #carrierAlternatives: readonly NodeRawQUICOptions[]; readonly #serverCarrierAlternatives: readonly NodeRawQUICOptions[];
  readonly #certificateChain: readonly Uint8Array[]; readonly #privateKey: Uint8Array; readonly #relayCertificate: Uint8Array; readonly #relayID = new Uint8Array(16); readonly #publicKey: Uint8Array;
  readonly #ingressRole: 0 | 1; readonly #ingressDelegate: RelayIngressDelegate | undefined;
  readonly #oppositeOwner: TunnelRuntime | undefined; #oppositeEnded = true;
  readonly #livePreparedRoles = new Set<0 | 1>(); readonly #liveInboundPrepared = new Map<0 | 1, RegisteredCarrierPreparation>();
  readonly #livePrepared = new Map<0 | 1, OriginalLivePreparedCarrier>();
  readonly #pendingIngress = new Map<string, PreparedRelayIngress>(); readonly #ingressWaiters = new Map<string, RelayIngressWaiter>();
  readonly #routeWaiters = new Set<() => void>(); #routeEnabled: boolean;
  readonly #entries = new Set<Entry>(); readonly #retiring = new Set<NativeRawSession>(); readonly #closedWait: Promise<void>; #resolve!: () => void;
  #dependency: EnvironmentDependency | undefined; #listener: NativeRawListener | undefined; #accept: NativeOperation<NativeRawSession> | undefined; #accepting: Promise<void> | undefined; #binding: Promise<NativeRawListener> | undefined;
  #network: NetServer | undefined; #websockets: WebSocketServer | undefined; #wssEnded = true;
  #address: Readonly<{ host: string; port: number }> | undefined; #outbound = false; #closed = false; #started = false; #listenerEnded = false; #released = false; #rejected = 0n; #authenticatedPairs = 0n; #forwardedBytes = 0n; #forwardedDatagrams = 0n; #failure: string | undefined;
  constructor(token: symbol, options: TunnelRuntimeOptions, ingressDelegate?: RelayIngressDelegate) {
    requireCredential(token === runtimeCapability); runtimeOwners.add(this); this.#runtime = originalEnvironment(options.environment);
    requireCredential(options.ingressRole === undefined || options.ingressRole === 0 || options.ingressRole === 1, "configuration_capacity");
    this.#ingressRole = options.ingressRole ?? 0; this.#ingressDelegate = ingressDelegate;
    requireCredential(options.deferForwarding === undefined || typeof options.deferForwarding === "boolean", "configuration_capacity"); this.#routeEnabled = options.deferForwarding !== true;
    relayNativePairCharge(options.forwarding); requireCredential(options.preparedListener === undefined || isTunnelListenerPreparation(options.preparedListener), "configuration_capacity");
    requireCredential(typeof options.host === "string" && options.host.length > 0 && Number.isSafeInteger(options.port) && options.port >= 0 && options.port <= 65535 && typeof options.serverName === "string" && options.serverName.length > 0 &&
      Number.isSafeInteger(options.maxPairs) && options.maxPairs >= 1 && options.maxPairs <= 4096 && typeof options.handshakeMS === "bigint" && options.handshakeMS > 0n && options.handshakeMS <= 60000n &&
      options.activationStore instanceof SQLiteAdmissionStore && options.credentials.namespaces.length > 0 && options.credentials.namespaces.length <= 8 &&
      Array.isArray(options.tls.certificateChainDER) && options.tls.certificateChainDER.length > 0 && options.tls.certificateChainDER.length <= 16 && options.tls.certificateChainDER.every(bytes => bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 65536) &&
      options.tls.privateKeyDER instanceof Uint8Array && options.tls.privateKeyDER.length > 0 && options.tls.privateKeyDER.length <= 65536 && options.relayCertificate instanceof Uint8Array && options.relayCertificate.length > 0 && options.relayCertificate.length <= 8192, "configuration_capacity");
    let carrier: TunnelCarrierOptions | undefined, serverCarrier: TunnelCarrierOptions | undefined, carrierAlternatives: readonly NodeRawQUICOptions[] = [], serverCarrierAlternatives: readonly NodeRawQUICOptions[] = [], certificateChain: readonly Uint8Array[] = [], privateKey: Uint8Array | undefined, relayCertificate: Uint8Array | undefined, publicKeyBytes: Uint8Array | undefined;
    try {
      carrier = isWSS(options.carrier) ? Object.freeze({ ...captureNodeWSS(options.carrier), nativeCarrier: "wss" as const }) : captureNodeRawQUIC(options.carrier);
      const outgoingInput = options.serverCarrier ?? options.carrier;
      serverCarrier = isWSS(outgoingInput) ? Object.freeze({ ...captureNodeWSS(outgoingInput), nativeCarrier: "wss" as const }) : captureNodeRawQUIC(outgoingInput);
      const alternatives = (primary: TunnelCarrierOptions, inputs: readonly NodeRawQUICOptions[] | undefined): readonly NodeRawQUICOptions[] => {
        requireCredential(inputs === undefined || inputs.length === 0 || inputs.length <= 1 && !isWSS(primary), "configuration_capacity");
        const captured: NodeRawQUICOptions[] = [];
        try { for (const value of inputs ?? []) captured.push(captureNodeRawQUIC(value)); requireCredential(captured.every(value => value.nativeCarrier !== primary.nativeCarrier), "configuration_capacity"); return Object.freeze(captured); }
        catch (error) { for (const value of captured) closeCarrierRoots(value); throw error; }
      };
      carrierAlternatives = alternatives(carrier, options.carrierAlternatives);
      serverCarrierAlternatives = alternatives(serverCarrier, options.serverCarrierAlternatives);
      for (const configured of [carrier, serverCarrier, ...carrierAlternatives, ...serverCarrierAlternatives]) {
        if (isWSS(configured)) {
          nodeWSSAdmissionCosts(Math.max(65536, options.forwarding.maxEnvelopeBytes - 8), configured, this.#runtime.resources.runtimeBytes);
          requireCredential(options.forwarding.maxDatagramBytes === 0, "configuration_capacity");
        } else requireCredential(configured.applicationStreams >= options.forwarding.maxResidentNativeMappings + options.forwarding.maxPendingNativeMappings && configured.streamBufferBytes >= Math.max(65544, options.forwarding.maxEnvelopeBytes), "configuration_capacity");
      }
      const listenerCarrier = this.#ingressRole === 0 ? carrier : serverCarrier;
      requireCredential(!isWSS(listenerCarrier) || options.preparedListener === undefined, "configuration_capacity");
      const tlsBytes = BigInt(options.tls.certificateChainDER.reduce((total, bytes) => total + bytes.length, 0) + options.tls.privateKeyDER.length);
      const configurationBytes = tlsBytes + BigInt(options.relayCertificate.length + [carrier, serverCarrier, ...carrierAlternatives, ...serverCarrierAlternatives].reduce((total, configured) => total + carrierRootBytes(configured), 0));
      this.#dependency = this.#runtime.admitDependency("tunnel_listener", new ResourceVector([262144n + configurationBytes + this.#runtime.resources.runtimeBytes + BigInt(options.maxPairs) * 512n,
        options.preparedListener !== undefined ? 0n : isWSS(listenerCarrier) ? tlsBytes + listenerCarrier.nativeBytes : tlsBytes + listenerCarrier.providerRuntimeBytes * BigInt(options.maxPairs + 1) + nativeRawQUICQueueBytes(listenerCarrier) * BigInt(options.maxPairs),
        0n, BigInt(options.maxPairs * 4 + 16), 4n, 4n, 1n, 0n, 0n, 0n, 1n]));
      const publicKey = createPublicKey(options.identityKey).export({ format: "jwk" }); requireCredential(options.identityKey.type === "private" && publicKey.crv === "Ed25519" && typeof publicKey.x === "string", "configuration_capacity");
      publicKeyBytes = new Uint8Array(Buffer.from(publicKey.x, "base64url")); requireCredential(publicKeyBytes.length === 32, "configuration_capacity");
      certificateChain = Object.freeze(options.tls.certificateChainDER.map(bytes => new Uint8Array(bytes))); privateKey = new Uint8Array(options.tls.privateKeyDER); relayCertificate = new Uint8Array(options.relayCertificate);
      const credentials = Object.freeze({ ...options.credentials, namespaces: Object.freeze([...options.credentials.namespaces]), cryptoProfiles: Object.freeze([...options.credentials.cryptoProfiles]) });
      this.#carrier = carrier; this.#serverCarrier = serverCarrier!; this.#carrierAlternatives = carrierAlternatives; this.#serverCarrierAlternatives = serverCarrierAlternatives; this.#certificateChain = certificateChain; this.#privateKey = privateKey; this.#relayCertificate = relayCertificate; this.#publicKey = publicKeyBytes;
      this.#options = Object.freeze({ ...options, credentials, tls: Object.freeze({ certificateChainDER: certificateChain, privateKeyDER: privateKey }), relayCertificate, carrier, serverCarrier: this.#serverCarrier, carrierAlternatives, serverCarrierAlternatives, forwarding: Object.freeze({ ...options.forwarding }) });
      if (options.oppositeListener !== undefined) {
        requireCredential(ingressDelegate === undefined, "configuration_capacity");
        const { oppositeListener: _oppositeListener, preparedListener: _primaryPreparation, ...shared } = this.#options; void _oppositeListener; void _primaryPreparation;
        const { preparedListener: oppositePreparation, ...oppositeOptions } = options.oppositeListener;
        this.#oppositeOwner = new TunnelRuntime(runtimeCapability, { ...shared, ...oppositeOptions, ...(oppositePreparation === undefined ? {} : { preparedListener: oppositePreparation }), ingressRole: this.#ingressRole === 0 ? 1 : 0 },
          { accept: (entry, listener) => this.#queueIngress(entry, listener) });
        this.#oppositeEnded = false;
        void this.#oppositeOwner.#closedWait.then(() => { this.#oppositeEnded = true; if (!this.#closed) { this.#failure = this.#oppositeOwner!.#failure ?? "opposite_listener_closed"; void this.close(); } this.#cleanup(); });
      }
      this.#runtime.fillRandom(this.#relayID); this.#closedWait = new Promise(resolve => { this.#resolve = resolve; });
      this.#dependency!.onClose(() => { void this.close(); }); this.#check(); Object.freeze(this);
    } catch (error) {
      void this.#oppositeOwner?.close(); for (const bytes of certificateChain) bytes.fill(0); closeCarrierRoots(carrier); closeCarrierRoots(serverCarrier); for (const configured of [...carrierAlternatives, ...serverCarrierAlternatives]) closeCarrierRoots(configured); privateKey?.fill(0); relayCertificate?.fill(0); publicKeyBytes?.fill(0); this.#relayID.fill(0); this.#dependency?.release(); throw error;
    }
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency?.check(); }
  /** Releases only the original prepared deployment; no received record or
   * acknowledgement creates a Grant or a durable relay claim. */
  activateRoute(): void {
    this.#check(); requireCredential(this.#started && (this.#address !== undefined || this.#outbound));
    if (this.#routeEnabled) return;
    this.#routeEnabled = true; this.#oppositeOwner?.activateRoute(); for (const resume of this.#routeWaiters) resume(); this.#routeWaiters.clear();
  }
  async #waitRoute(entry: Entry, guard: () => void): Promise<void> {
    guard(); if (this.#routeEnabled) return;
    await new Promise<void>(resolve => {
      const resume = (): void => { entry.abort.signal.removeEventListener("abort", resume); this.#routeWaiters.delete(resume); resolve(); };
      requireCredential(this.#routeWaiters.size < this.#options.maxPairs, "configuration_capacity");
      this.#routeWaiters.add(resume); entry.abort.signal.addEventListener("abort", resume, { once: true });
      if (entry.abort.signal.aborted || this.#routeEnabled) resume();
    });
    guard(); requireCredential(this.#routeEnabled);
  }
  async listen(): Promise<Readonly<{ host: string; port: number }>> {
    this.#check(); requireCredential(!this.#started); this.#started = true; const options = this.#options, runtime = this.#runtime, listenerCarrier = this.#ingressRole === 0 ? this.#carrier : this.#serverCarrier;
    try {
      const reference = runtime.reserveConnectionWork("relay_listener_identity", credentialWorkCharge(16384, runtime.resources.runtimeBytes)); let work: CredentialWork | undefined;
      try {
        work = new CredentialWork(runtime.resources, 16384, reference); const certificate = work.parse(this.#relayCertificate, "IdentityCertificate", 8192);
        try {
          requireCredential(certificate.uint("role") === 2n && certificate.text("tenant_id") === options.credentials.tenant && certificate.text("audience") === options.credentials.audience && certificate.text("subject_id") === options.credentials.relaySubject && equalCredential(certificate.bytes("ed25519_public_key"), this.#publicKey));
          const namespace = options.credentials.namespaces.find(value => value.matches(certificate)); requireCredential(namespace !== undefined, "credential_untrusted"); namespace.verifyCredential(certificate, 0, work);
        } finally { certificate.close(); }
      } finally { work?.close(); reference.release(); }
      this.#check();
      await this.#oppositeOwner?.listen();
      if (isWSS(listenerCarrier)) return await this.#listenWSS(listenerCarrier);
      const driver = listenerCarrier.nativeCarrier === "webtransport" ? loadCurrentNativeWebTransport() : loadCurrentNativeTransport();
      if (options.preparedListener !== undefined) this.#listener = options.preparedListener.adopt({ ...options, carrier: listenerCarrier }, this.#dependency!.reference);
      else {
        this.#binding = bindCurrentNativeListener(driver, { host: options.host, port: options.port, path: "tunnel", certificateChainDer: this.#certificateChain, privateKeyDer: this.#privateKey, inboundBidirectionalStreamCapacity: listenerCarrier.applicationStreams + 1,
          readBufferBytes: Math.min(16384, listenerCarrier.streamBufferBytes), datagramQueueBytes: 65536, handshakeTimeoutMs: Number(options.handshakeMS), pendingConnections: options.maxPairs }, options.serverName, listenerCarrier.webTransport);
        this.#listener = await this.#binding;
      }
      void this.#listener.waitTermination().then(() => { this.#listenerEnded = true; void this.close(); this.#cleanup(); }, () => { this.#failure = "physical_termination_unknown"; void this.close(); });
      this.#check(); this.#address = this.#listener.address(); this.#accepting = this.#acceptLoop(); return this.#address;
    } catch (error) { if (this.#listener === undefined && this.#network === undefined) this.#listenerEnded = true; this.#failure = error instanceof Error ? error.message : "carrier_failed"; void this.close(); throw error; }
  }
  async #listenWSS(configured: V4NodeWSSOptions): Promise<Readonly<{ host: string; port: number }>> {
    const options = this.#options, runtime = this.#runtime, maximum = Math.max(65544, options.forwarding.maxEnvelopeBytes);
    const certificate = this.#certificateChain.map(bytes => new X509Certificate(bytes).toString()).join("\n");
    const key = createPrivateKey({ key: Buffer.from(this.#privateKey), format: "der", type: "pkcs8" }).export({ format: "pem", type: "pkcs8" });
    const network = this.#network = createNetServer({ pauseOnConnect: true });
    const https = createHTTPSServer({ key, cert: certificate, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], secureOptions: constants.SSL_OP_NO_TICKET,
      maxHeaderSize: 16384, highWaterMark: 16384, handshakeTimeout: Number(options.handshakeMS), requestTimeout: Number(options.handshakeMS), headersTimeout: Number(options.handshakeMS) });
    https.maxHeadersCount = 32; https.maxRequestsPerSocket = 1; network.maxConnections = options.maxPairs;
    const websockets = this.#websockets = new WebSocketServer({ noServer: true, clientTracking: false, perMessageDeflate: false, autoPong: false,
      maxPayload: maximum, handleProtocols: protocols => protocols.size === 1 && protocols.has("flowersec.tunnel.v4") ? "flowersec.tunnel.v4" : false });
    this.#listenerEnded = false; this.#wssEnded = false;
    network.once("close", () => { this.#listenerEnded = true; this.#cleanup(); }); websockets.once("close", () => { this.#wssEnded = true; this.#cleanup(); });
    const connections = new Map<string, Entry>();
    const socketKey = (socket: Socket): string => `${socket.remoteAddress ?? ""}/${socket.remotePort ?? 0}/${socket.localPort ?? 0}`;
    const retire = async (entry: Entry): Promise<void> => {
      entry.close(); await entry.incoming!.waitTermination(); await entry.nativeDone;
      connections.delete(socketKey(entry.rawSocket!)); this.#entries.delete(entry); this.#cleanup();
    };
    const failure = (error: Error): void => { this.#failure = error.message; void this.close(); };
    network.on("error", failure); https.on("error", failure); websockets.on("error", failure);
    network.on("connection", raw => {
      let carrier: NodeWSSCarrier | undefined;
      try {
        this.#check(); requireCredential(this.#entries.size < options.maxPairs, "configuration_capacity");
        const costs = nodeWSSAdmissionCosts(Math.max(65536, options.forwarding.maxEnvelopeBytes - 8), configured, runtime.resources.runtimeBytes), dependency = runtime.admitDependency("relay_wss_ingress", costs[0]![1]);
        const preparation = TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), options.handshakeMS, 0xffffffffffffffffn);
        try { carrier = new NodeWSSCarrier(runtime, dependency, maximum, configured.queueMessages, "server", "tunnel", preparation); carrier.ownPendingSocket(raw); }
        catch (error) { dependency.release(); throw error; }
        let ended!: () => void; const nativeDone = new Promise<void>(resolve => { ended = resolve; });
        let timer: ReturnType<typeof setTimeout> | undefined;
        const entry: Entry = { rawSocket: raw, incoming: carrier, nativeDone, preparation, finishIngress: () => { if (timer !== undefined) { clearTimeout(timer); timer = undefined; } }, abort: new AbortController(), promise: undefined, close: () => { entry.abort.abort(); void carrier!.close(); raw.destroy(); } };
        connections.set(socketKey(raw), entry); this.#entries.add(entry);
        const tick = (): void => { try { this.#check(); preparation.check(); timer = setTimeout(tick, timerChunk(preparation.remainingMS())); } catch { entry.close(); } }; tick();
        raw.once("close", () => {
          ended(); if (timer !== undefined) clearTimeout(timer); entry.abort.abort();
          if (entry.promise === undefined) entry.promise = retire(entry).catch(() => { this.#failure = "physical_termination_unknown"; void this.close(); });
        });
        https.emit("connection", raw); raw.resume();
      } catch { this.#rejected++; raw.destroy(); void carrier?.close(); }
    });
    https.on("request", (request, response) => { response.destroy(); request.socket.destroy(); });
    https.on("upgrade", (request, socket, head) => {
      const entry = connections.get(socketKey(socket as Socket));
      try {
        this.#check(); requireCredential(entry !== undefined && entry.promise === undefined && !entry.abort.signal.aborted && head.length <= maximum, "credential_binding"); entry.preparation!.check();
        const port = this.#address!.port, expectedHost = `${isIP(options.serverName) === 6 ? `[${options.serverName}]` : options.serverName}${port === 443 ? "" : `:${port}`}`;
        requireCredential(request.method === "GET" && request.httpVersion === "1.1" && request.url === "/flowersec/v4/tunnel" && request.headers.host === expectedHost &&
          request.headers["sec-websocket-protocol"] === "flowersec.tunnel.v4" && request.headers["sec-websocket-version"] === "13" && request.headers["content-length"] === undefined &&
          request.headers["transfer-encoding"] === undefined && request.headers.expect === undefined && request.headers["sec-websocket-extensions"] === undefined && request.rawHeaders.length <= 64, "credential_binding");
        const names = new Set<string>(); for (let index = 0; index < request.rawHeaders.length; index += 2) { const name = request.rawHeaders[index]!.toLowerCase(); requireCredential(!names.has(name), "credential_binding"); names.add(name); }
        websockets.handleUpgrade(request, socket, head, websocket => {
          try {
            entry.incoming!.accept(websocket, request, { host: options.serverName, port }); entry.finishIngress!();
            entry.promise = this.#dispatchIngress(entry).catch(error => { this.#rejected++; this.#failure = error instanceof Error ? error.message : "carrier_failed"; return retire(entry); }).finally(() => { connections.delete(socketKey(entry.rawSocket!)); });
          } catch { this.#rejected++; websocket.terminate(); entry.close(); }
        });
      } catch { this.#rejected++; entry?.close(); socket.destroy(); }
    });
    try {
      await new Promise<void>((resolve, reject) => { network.once("error", reject); network.listen({ host: options.host, port: options.port }, () => { network.removeListener("error", reject); resolve(); }); });
      this.#check(); const address = network.address(); requireCredential(address !== null && typeof address !== "string");
      this.#address = Object.freeze({ host: address.address, port: address.port }); return this.#address;
    } catch (error) { void this.close(); throw error; }
  }
  async #acceptLoop(): Promise<void> {
    try {
      for (;;) { this.#check(); this.#accept = this.#listener!.accept(); const raw = await this.#accept.result(); this.#accept = undefined;
        if (this.#closed || this.#entries.size >= this.#options.maxPairs) { this.#rejected++; this.#retireRaw(raw); continue; }
        const entry: Entry = { raw, abort: new AbortController(), promise: undefined, close: () => { entry.abort.abort(); raw.abort(); } }; this.#entries.add(entry);
        entry.promise = this.#dispatchIngress(entry).catch(async error => { entry.close(); this.#rejected++; this.#failure = error instanceof Error ? error.message : "carrier_failed";
          try { await raw.waitTermination(); this.#entries.delete(entry); this.#cleanup(); } catch { this.#failure = "physical_termination_unknown"; void this.close(); }
        });
      }
    } catch (error) { if (!this.#closed) { this.#failure = error instanceof Error ? error.message : "carrier_failed"; void this.close(); } }
    finally { this.#accept = undefined; this.#accepting = undefined; this.#cleanup(); }
  }
  #retireRaw(raw: NativeRawSession): void { this.#retiring.add(raw); raw.abort(); void raw.waitTermination().then(() => { this.#retiring.delete(raw); this.#cleanup(); }, () => { this.#failure = "physical_termination_unknown"; void this.close(); }); }
  belongsTo(environment: ReturnType<typeof originalEnvironment>, store: SQLiteAdmissionStore): boolean { return runtimeOwners.has(this) && !this.#closed && this.#runtime === environment && this.#options.activationStore === store; }
  /** Signed registry facts prepare only TLS/native custody. The same carrier
   * is later bound to original TxB Grants before any hop claim or dispatch. */
  async prepareOriginalLiveCarrier(role: 0 | 1, input: Omit<CredentialInput, "source" | "activation" | "tunnel"> & Readonly<{ relayCertificate: Uint8Array; applicationAudience: string }>, signal?: AbortSignal): Promise<void> {
    this.#check(); requireCredential((role === 0 || role === 1) && !this.#livePreparedRoles.has(role) && !this.#liveInboundPrepared.has(role) && equalCredential(input.relayCertificate, this.#relayCertificate), "credential_binding");
    let configuration = role === 0 ? this.#carrier : this.#serverCarrier; const credentials = this.#options.credentials;
    const registry = prepareRegisteredCarrier({ ...credentials, audience: input.applicationAudience, resources: this.#runtime.resources, clock: this.#runtime.clock, tunnel: { role, audience: credentials.audience, service: credentials.service, relaySubject: credentials.relaySubject } }, { ...input, source: "live_authority", tunnel: { relayCertificate: input.relayCertificate } }, this.#options.handshakeMS);
    let ref: ResourceReference | undefined, work: CredentialWork | undefined;
    try { ref = this.#runtime.reserveConnectionWork("original_live_relay_direction", credentialWorkCharge(16384, this.#runtime.resources.runtimeBytes)); work = new CredentialWork(this.#runtime.resources, 16384, ref); const route = work.parse(registry.fields().route, "Route", 16384);
      try { const leg = route.field(role === 0 ? "client_leg" : "server_leg"), dialer = route.uint("dialer_role", leg, "Leg"), listener = route.uint("listener_role", leg, "Leg");
        if (dialer !== 2n) { const owner = role === this.#ingressRole ? this : this.#oppositeOwner; requireCredential(dialer === BigInt(role) && listener === 2n && owner !== undefined && owner.#started && owner.#address !== undefined && route.text("host", leg, "Leg") === owner.#options.serverName && route.uint("port", leg, "Leg") === BigInt(owner.#address.port) && route.uint("carrier", leg, "Leg") === (isWSS(configuration) ? 1n : configuration.nativeCarrier === "webtransport" ? 2n : 0n), "credential_binding"); this.#liveInboundPrepared.set(role, registry); return; }
        requireCredential(listener === BigInt(role), "credential_binding");
        const kind = route.uint("carrier", leg, "Leg"), selected = this.#configurations(role).find(value => kind === (isWSS(value) ? 1n : value.nativeCarrier === "webtransport" ? 2n : 0n));
        requireCredential(selected !== undefined, "connection_requirement_unavailable"); configuration = selected;
      } finally { route.close(); }
    } catch (error) { registry.close(); throw error; } finally { work?.close(); ref?.release(); }
    const slot: OriginalLivePreparedCarrier = { registry, abort: new AbortController(), prepared: Promise.resolve(), timer: undefined, taken: false, closed: false }; this.#livePreparedRoles.add(role); this.#livePrepared.set(role, slot);
    const canceled = (): void => { slot.abort.abort(); }; signal?.addEventListener("abort", canceled, { once: true }); if (signal?.aborted) canceled();
    slot.prepared = (async () => {
      try {
        const guard = (): void => { this.#check(); registry.check(); requireCredential(!slot.abort.signal.aborted && !slot.closed); };
        const tick = (): void => { try { guard(); slot.timer = setTimeout(tick, timerChunk(registry.fields().preparationDeadline.remainingMS())); } catch { void this.#closeOriginalLiveCarrier(role, slot); } }; tick(); guard();
        slot.carrier = isWSS(configuration) ? await prepareNodeWSS(this.#runtime, registry.fields(), configuration, slot.abort.signal, undefined, role, 2) : await prepareNodeRawQUIC(this.#runtime, registry.fields(), configuration, configuration.nativeCarrier === "webtransport" ? loadCurrentNativeWebTransport() : loadCurrentNativeTransport(), slot.abort.signal, undefined, role, 2);
        guard(); const original = slot.carrier; void original.waitTermination().then(() => this.#closeOriginalLiveCarrier(role, slot), () => this.#closeOriginalLiveCarrier(role, slot)).catch(() => undefined);
      } finally { signal?.removeEventListener("abort", canceled); }
    })();
    void slot.prepared.catch(() => { void this.#closeOriginalLiveCarrier(role, slot); }); await slot.prepared;
  }
  checkOriginalLiveCarrierPreparation(role: 0 | 1): void {
    this.#check(); const inbound = this.#liveInboundPrepared.get(role); if (inbound !== undefined) { inbound.check(); const owner = role === this.#ingressRole ? this : this.#oppositeOwner; requireCredential(owner !== undefined && owner.#address !== undefined && !owner.#closed, "credential_binding"); return; }
    const slot = this.#livePrepared.get(role); requireCredential(slot !== undefined && !slot.closed && !slot.taken && slot.carrier !== undefined, "credential_closed"); slot.registry.check(); slot.carrier.checkPreparation();
  }
  continueOriginalLivePair(inputs: readonly [RelayCredentialInput, RelayCredentialInput]): void {
    this.#check(); this.checkOriginalLiveCarrierPreparation(0); this.checkOriginalLiveCarrierPreparation(1); this.activateRoute();
    if (this.#livePreparedRoles.has(0) && this.#livePreparedRoles.has(1)) { const original = this.connectOriginalPair(inputs); void original.catch(() => undefined); }
  }
  async #closeOriginalLiveCarrier(role: 0 | 1, slot: OriginalLivePreparedCarrier): Promise<void> {
    if (slot.closing !== undefined) return slot.closing; slot.closed = true; slot.abort.abort(); if (slot.timer !== undefined) clearTimeout(slot.timer);
    return slot.closing = (async () => { await Promise.allSettled([slot.prepared]); await slot.carrier?.close(); await slot.carrier?.waitTermination(); slot.registry.close(); if (this.#livePrepared.get(role) === slot) this.#livePrepared.delete(role); this.#cleanup(); })();
  }
  async #takeOriginalLiveCarrier(role: 0 | 1, credentials: VerifiedRelayCredentials, reference: ResourceReference, signal: AbortSignal): Promise<TunnelHopCarrier | undefined> {
    const slot = this.#livePrepared.get(role); if (slot === undefined) { requireCredential(!this.#livePreparedRoles.has(role), "credential_closed"); return undefined; }
    requireCredential(!slot.taken && !slot.closed, "credential_binding"); await observeTask(slot.prepared, signal); this.#check(); slot.registry.checkOriginalGrant(credentials, reference); requireCredential(slot.carrier !== undefined && !slot.closed && !signal.aborted, "credential_binding");
    slot.taken = true; if (slot.timer !== undefined) clearTimeout(slot.timer); slot.timer = undefined; if (slot.carrier instanceof NodeRawQUICCarrier) slot.carrier.activate(); return slot.carrier;
  }
  /** Starts both relay-initiated physical legs using the original signed
   * issuance pair. Each durable claim still resolves through the same ledger;
   * supplying bytes does not install issuance or ParentWinner rights. */
  connectOriginalPair(input: readonly [RelayCredentialInput, RelayCredentialInput]): Promise<void> {
    this.#check(); requireCredential(!this.#started && this.#oppositeOwner === undefined && this.#options.preparedListener === undefined, "credential_binding");
    for (const leg of input) requireCredential(leg.grant instanceof Uint8Array && leg.grant.length > 0 && leg.grant.length <= 65536 &&
      leg.endpointCertificate instanceof Uint8Array && leg.endpointCertificate.length > 0 && leg.endpointCertificate.length <= 8192 &&
      leg.relayCertificate instanceof Uint8Array && equalCredential(leg.relayCertificate, this.#relayCertificate), "configuration_capacity");
    this.#started = true; this.#outbound = true; this.#listenerEnded = true;
    const entry: Entry = { abort: new AbortController(), promise: undefined, close: () => { entry.abort.abort(); } };
    this.#entries.add(entry); entry.promise = this.#runOutgoingPair(input, entry).catch(error => { this.#rejected++; this.#failure = error instanceof Error ? error.message : "carrier_failed"; throw error; });
    return entry.promise;
  }
  #configurations(role: 0 | 1): readonly TunnelCarrierOptions[] {
    return role === 0 ? [this.#carrier, ...this.#carrierAlternatives] : [this.#serverCarrier, ...this.#serverCarrierAlternatives];
  }
  #selectRelayConfiguration(role: 0 | 1, credentials: VerifiedRelayCredentials, reference: ResourceReference): TunnelCarrierOptions {
    credentials.check(reference); requireCredential(credentials.role === role, "credential_binding");
    const bytes = credentials.descriptor(reference), ref = this.#runtime.reserveConnectionWork("relay_carrier_selection", credentialWorkCharge(16384, this.#runtime.resources.runtimeBytes));
    let work: CredentialWork | undefined;
    try {
      work = new CredentialWork(this.#runtime.resources, 16384, ref); const leg = work.parse(bytes, "Leg", 16384, 16384, { selectors: { path_kind: "tunnel" } });
      try {
        const kind = leg.uint("carrier");
        requireCredential(leg.uint("endpoint_role") === BigInt(role), "credential_binding");
        const selected = this.#configurations(role).find(value => kind === (isWSS(value) ? 1n : value.nativeCarrier === "webtransport" ? 2n : 0n));
        requireCredential(selected !== undefined, "connection_requirement_unavailable"); return selected;
      } finally { leg.close(); }
    } finally { bytes.fill(0); work?.close(); ref.release(); }
  }
  async #prepareRelayDial(carrier: TunnelHopCarrier, configured: TunnelCarrierOptions, credentials: VerifiedRelayCredentials,
    preparation: TrustedDeadline, entry: Entry, reference: ResourceReference): Promise<void> {
    const runtime = this.#runtime;
    if (isWSS(configured)) {
      requireCredential(carrier instanceof NodeWSSCarrier);
      const policy = nodeWSSRelayDialPolicy(runtime, credentials, configured, reference);
      try { await carrier.prepare({ pathKind: 1, preparationDeadline: preparation }, configured, policy, entry.abort.signal); }
      finally { for (const pin of policy.pins) pin.digest.fill(0); }
    } else {
      requireCredential(carrier instanceof NodeRawQUICCarrier);
      const policy = rawQUICRelayDialPolicy(runtime, credentials, configured, reference);
      await carrier.prepare(configured.nativeCarrier === "webtransport" ? loadCurrentNativeWebTransport() : loadCurrentNativeTransport(), policy.endpoint, policy.expectation, entry.abort.signal); carrier.activate();
    }
  }
  #requireForwardingPair(credentials: readonly (VerifiedRelayCredentials | undefined)[], carriers: readonly (TunnelHopCarrier | undefined)[], reference: ResourceReference): void {
    const limits = this.#options.forwarding;
    for (const role of [0, 1]) {
      const signed = credentials[role]!.limits(reference), carrier = carriers[role]!;
      requireCredential(signed.envelopeBytes === BigInt(limits.maxEnvelopeBytes) && signed.pendingMappings >= BigInt(limits.maxPendingNativeMappings) &&
        signed.residentMappings >= BigInt(limits.maxResidentNativeMappings) && signed.totalMappings >= BigInt(limits.maxTotalNativeMappings) &&
        signed.queueItems >= BigInt(limits.maxQueueItems) && signed.queueBytes >= BigInt(limits.maxQueueBytes) && signed.datagramBytes === BigInt(limits.maxDatagramBytes));
      if (limits.maxDatagramBytes > 0) requireCredential(carrier instanceof NodeRawQUICCarrier && carrier.maxDatagramBytes() >= limits.maxDatagramBytes);
      requireCredential(signed.rateBytesPerSecond >= BigInt(Math.max(65544, limits.maxEnvelopeBytes)));
    }
  }
  async #runOutgoingPair(input: readonly [RelayCredentialInput, RelayCredentialInput], entry: Entry): Promise<void> {
    const runtime = this.#runtime, options = this.#options, configurations: TunnelCarrierOptions[] = [];
    const preparation = TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), options.handshakeMS, 0xffffffffffffffffn);
    const references: ResourceReference[] = [], inputs: RelayCredentialInput[] = [], credentials: VerifiedRelayCredentials[] = [], carriers: TunnelHopCarrier[] = [], claims: VerifiedRelayClaim[] = [], hops: HopAuthentication[] = [], meters: RelayHopByteMeter[] = [];
    let reference: ResourceReference | undefined, pair: RelayNativePair | undefined, pairPreparation: RelayNativePairPreparation | undefined, timer: ReturnType<typeof setTimeout> | undefined;
    const incarnation = new Uint8Array(16), invocation = new Uint8Array(16), carrierID = new Uint8Array(16);
    const cancel = (): void => { entry.abort.abort(); pair?.close(); for (const carrier of carriers) void carrier.close(); };
    entry.close = cancel;
    const guard = (): void => { this.#check(); reference!.check(); requireCredential(!entry.abort.signal.aborted); for (const credential of credentials) credential.check(reference!); };
    try {
      reference = runtime.reserveConnectionWork("relay_outgoing_entry", new ResourceVector([262144n + runtime.resources.runtimeBytes, 0n, 0n, 16n, 2n, 0n, 0n, 0n, 0n, 0n, 0n]));
      for (const leg of input) inputs.push(Object.freeze({ grant: new Uint8Array(leg.grant), endpointCertificate: new Uint8Array(leg.endpointCertificate), relayCertificate: new Uint8Array(leg.relayCertificate) }));
      const ledgerCharge = options.activationStore.relayCharge();
      references.push(...runtime.resources.root.reserveBatch([relayNativePairCharge(options.forwarding), ...[0, 1].map(() => relayCredentialCharge(runtime.resources.runtimeBytes)), ...[0, 1].map(() => hopAuthenticationCharge(runtime.resources.runtimeBytes)), ledgerCharge, ledgerCharge, ledgerCharge].map((charge, index) => ({ owner: credentialOwner(runtime.resources, `relay_outgoing_${index}`), accounts: runtime.resources.accounts, charge }))));
      pairPreparation = new RelayNativePairPreparation(options.forwarding, references[0]!);
      for (const role of [0, 1] as const) {
        credentials.push(verifyRelayCredentials({ ...options.credentials, endpointSubject: role === 0 ? options.credentials.clientSubject : options.credentials.serverSubject, resources: runtime.resources, clock: runtime.clock }, inputs[role]!, references[1 + role]!));
        requireCredential(credentials[role]!.role === role); credentials[role]!.onRevoked(cancel);
        configurations[role] = this.#selectRelayConfiguration(role, credentials[role]!, reference);
        carriers.push(await this.#takeOriginalLiveCarrier(role, credentials[role]!, reference, entry.abort.signal) ?? this.#allocateCarrier(configurations[role]!, false, preparation));
      }
      const tick = (): void => { try { guard(); preparation.check(); timer = setTimeout(tick, timerChunk(preparation.remainingMS())); } catch { cancel(); } }; tick();
      await this.#waitRoute(entry, guard);
      for (const role of [0, 1] as const) if (this.#livePrepared.get(role)?.taken !== true) await this.#prepareRelayDial(carriers[role]!, configurations[role]!, credentials[role]!, preparation, entry, reference);
      guard(); this.#requireForwardingPair(credentials, carriers, reference);
      runtime.fillRandom(incarnation); runtime.fillRandom(invocation); runtime.fillRandom(carrierID);
      const signer = Object.freeze({ publicKey: this.#publicKey, sign: (bytes: Uint8Array): Uint8Array => { guard(); return new Uint8Array(sign(null, bytes, options.identityKey)); } });
      const owner = (): RelayActivationOwner => ({ relay: this.#relayID, invocation, carrier: carrierID, generation: 1n, signal: entry.abort.signal });
      for (const role of [0, 1] as const) {
        meters.push(new RelayHopByteMeter(credentials[role]!.limits(reference), runtime.clock, guard, entry.abort.signal));
        hops.push(new HopAuthentication({ resources: runtime.resources, transport: carriers[role]!, credentials: credentials[role]!, localRole: 2, localIncarnation: incarnation, random: bytes => runtime.fillRandom(bytes), signer, deadline: preparation, guard, meter: meters[role]! }, references[3 + role]!));
      }
      for (const role of [0, 1] as const) {
        runtime.fillRandom(invocation); runtime.fillRandom(carrierID);
        claims.push(await hops[role]!.authenticateRelay(async (claim, publish) => {
          // Both roles must be the exact same original issuance, even when the
          // caller supplies two individually valid and correctly scoped Grants.
          if (role === 0) {
            const counterpart = await options.activationStore.relayCounterpart(claim, references[7]!, preparation), other = inputs[1]!;
            try { requireCredential(equalCredential(counterpart.grant, other.grant) && equalCredential(counterpart.endpointCertificate, other.endpointCertificate) && equalCredential(counterpart.relayCertificate, other.relayCertificate), "credential_binding"); }
            finally { counterpart.grant.fill(0); counterpart.endpointCertificate.fill(0); counterpart.relayCertificate.fill(0); }
          }
          meters[role]!.requireRemaining(BigInt(Math.max(65544, options.forwarding.maxEnvelopeBytes)) * 8n);
          await options.activationStore.claimRelay(claim, owner(), preparation, references[5 + role]!, guard, publish);
        }, { signal: entry.abort.signal })); hops[role]!.close();
      }
      // Both original hop proofs and durable claims precede this handoff.
      // TLS pin windows constrain admission; the admitted opaque forwarding
      // pair keeps the same sockets and Grant deadlines afterward.
      for (const carrier of carriers) { requireCredential(carrier !== undefined); carrier.checkPreparation(); }
      guard();
      for (const carrier of carriers) if (carrier instanceof NodeWSSCarrier) carrier.completePreparation();
      pair = new RelayNativePair(options.forwarding, [{ transport: carriers[0]!, credentials: credentials[0]!, claim: claims[0]!, meter: meters[0]! }, { transport: carriers[1]!, credentials: credentials[1]!, claim: claims[1]!, meter: meters[1]! }], pairPreparation); this.#authenticatedPairs++;
      if (timer !== undefined) clearTimeout(timer);
      const forwardTick = (): void => { try { guard(); const remaining = credentials[0]!.deadline.remainingMS() < credentials[1]!.deadline.remainingMS() ? credentials[0]!.deadline.remainingMS() : credentials[1]!.deadline.remainingMS(); timer = setTimeout(forwardTick, timerChunk(remaining)); } catch { cancel(); } }; forwardTick(); pair.start(); await pair.waitTermination();
    } finally {
      cancel(); if (timer !== undefined) clearTimeout(timer);
      if (pair !== undefined) { await pair.waitTermination(); const observed = pair.forwardingObservations(); this.#forwardedBytes += observed.bytes; this.#forwardedDatagrams += observed.datagrams; }
      for (const hop of hops) hop.close();
      await Promise.all(carriers.flatMap(carrier => [carrier.close(), carrier.waitTermination()]));
      for (const claim of claims) claim.close(); for (const credential of credentials) credential.close(); pairPreparation?.close();
      for (const leg of inputs) { leg.grant.fill(0); leg.endpointCertificate.fill(0); leg.relayCertificate.fill(0); }
      for (const held of references) held.release(); reference?.release(); incarnation.fill(0); invocation.fill(0); carrierID.fill(0); this.#entries.delete(entry); this.#cleanup();
    }
  }
  #dispatchIngress(entry: Entry): Promise<void> {
    if (this.#ingressDelegate === undefined) return this.#run(entry);
    return this.#ingressDelegate.accept(entry, this).finally(() => { this.#entries.delete(entry); this.#cleanup(); });
  }
  #allocateCarrier(configured: TunnelCarrierOptions, listener: boolean, preparation: TrustedDeadline): TunnelHopCarrier {
    const runtime = this.#runtime, maximum = Math.max(65544, this.#options.forwarding.maxEnvelopeBytes);
    if (isWSS(configured)) {
      const costs = nodeWSSAdmissionCosts(maximum - 8, configured, runtime.resources.runtimeBytes);
      const dependency = runtime.admitDependency("relay_wss_hop", costs[0]![1]);
      try { return new NodeWSSCarrier(runtime, dependency, maximum, configured.queueMessages, listener ? "server" : "client", "tunnel", preparation); }
      catch (error) { dependency.release(); throw error; }
    }
    const costs = nodeRawQUICAdmissionCosts(maximum - 8, configured, runtime.resources.runtimeBytes);
    const position = runtime.admitDependencyPositions("relay_quic_hop", costs[0]![1], costs[1]![1], configured.applicationStreams + 1);
    let nativePositions: NativeProviderPositions | undefined;
    try { nativePositions = new NativeProviderPositions(position.positions); return new NodeRawQUICCarrier(runtime, position.dependency, nativePositions, configured, preparation, listener ? "server" : "client", "tunnel"); }
    catch (error) { if (nativePositions === undefined) for (const slot of position.positions) slot.closeAfterUse(); else nativePositions.close(); position.dependency.release(); throw error; }
  }
  #ingressKey(credentials: VerifiedRelayCredentials, reference: ResourceReference): string {
    const digest = credentials.grantDigest(reference);
    try { return Buffer.from(digest).toString("hex"); } finally { digest.fill(0); }
  }
  /** Every queued physical ingress owns its decoder, credential preparation,
   * provider positions and original deadline until the paired run terminates. */
  async #queueIngress(entry: Entry, listener: TunnelRuntime): Promise<void> {
    const runtime = this.#runtime, role = listener.#ingressRole, configured = role === 0 ? this.#carrier : this.#serverCarrier;
    const preparation = entry.preparation ?? TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), this.#options.handshakeMS, 0xffffffffffffffffn);
    const references: ResourceReference[] = []; let routing: Uint8Array | undefined; let forwarding = false;
    let carrier: TunnelHopCarrier | undefined, credentials: VerifiedRelayCredentials | undefined, work: CredentialWork | undefined;
    let record: PreparedRelayIngress | undefined, timer: ReturnType<typeof setTimeout> | undefined;
    let abortObserver: (() => void) | undefined;
    const originalClose = entry.close;
    const cancel = (): void => { originalClose(); void carrier?.close(); };
    entry.close = cancel;
    const guard = (): void => { this.#check(); listener.#check(); references[0]!.check(); if (!forwarding) preparation.check(); requireCredential(!entry.abort.signal.aborted); credentials?.check(references[0]!); };
    try {
      references.push(...runtime.resources.root.reserveBatch([new ResourceVector([262144n + runtime.resources.runtimeBytes, 0n, 0n, 16n, 2n, 0n, 0n, 0n, 0n, 0n, 0n]),
        relayCredentialCharge(runtime.resources.runtimeBytes), credentialWorkCharge(65536, runtime.resources.runtimeBytes)].map((charge, index) => ({ owner: credentialOwner(runtime.resources, `relay_ingress_${role}_${index}`), accounts: runtime.resources.accounts, charge }))));
      routing = new Uint8Array(65544); carrier = entry.incoming ?? this.#allocateCarrier(configured, true, preparation);
      const tick = (): void => { try { guard(); timer = setTimeout(tick, timerChunk(preparation.remainingMS())); } catch { cancel(); } }; tick();
      if (entry.raw !== undefined) {
        requireCredential(carrier instanceof NodeRawQUICCarrier);
        await carrier.accept(entry.raw, { host: listener.#options.serverName, port: listener.#address!.port, leaf: new X509Certificate(listener.#certificateChain[0]!) }, entry.abort.signal);
      } else requireCredential(carrier === entry.incoming);
      await listener.#waitRoute(entry, guard);
      const count = await readRelayEnvelope(carrier, routing, guard, entry.abort.signal);
      requireCredential(count !== null && routing[4] === wire.frame_types.HOP_AUTH);
      work = new CredentialWork(runtime.resources, 65536, references[2]!);
      const hello = work.parse(routing.subarray(8, count), "HOP_AUTH_HELLO", 65536, 16384, { selectors: { hop_sender_role: "endpoint" } });
      try {
        const grant = hello.bytes("grant"), endpointCertificate = hello.bytes("identity_certificate");
        try { credentials = verifyRelayCredentials({ ...this.#options.credentials, endpointSubject: role === 0 ? this.#options.credentials.clientSubject : this.#options.credentials.serverSubject, resources: runtime.resources, clock: runtime.clock }, { grant, endpointCertificate, relayCertificate: this.#relayCertificate }, references[1]!); }
        finally { grant.fill(0); endpointCertificate.fill(0); }
      } finally { hello.close(); }
      requireCredential(credentials.role === role); credentials.onRevoked(cancel); carrier.checkAcceptedHopRoute(credentials, references[0]!);
      const key = this.#ingressKey(credentials, references[0]!);
      guard(); requireCredential(!this.#pendingIngress.has(key), "credential_binding");
      let complete!: () => void; const completed = new Promise<void>(resolve => { complete = resolve; });
      record = { entry, carrier, credentials, hello: new Uint8Array(routing.subarray(8, count)), key, preparation, finishHandshake: () => { forwarding = true; if (timer !== undefined) clearTimeout(timer); timer = undefined; }, taken: false, complete };
      abortObserver = (): void => {
        if (record!.taken) return;
        if (this.#pendingIngress.get(key) === record) this.#pendingIngress.delete(key);
        record!.complete();
      };
      entry.abort.signal.addEventListener("abort", abortObserver, { once: true });
      const waiter = this.#ingressWaiters.get(key);
      if (waiter !== undefined) { this.#ingressWaiters.delete(key); record.taken = true; waiter.take(record); }
      else { requireCredential(this.#pendingIngress.size < this.#options.maxPairs, "configuration_capacity"); this.#pendingIngress.set(key, record); }
      if (entry.abort.signal.aborted) abortObserver();
      await completed;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (abortObserver !== undefined) entry.abort.signal.removeEventListener("abort", abortObserver);
      if (record !== undefined) { if (this.#pendingIngress.get(record.key) === record) this.#pendingIngress.delete(record.key); record.hello.fill(0); }
      cancel();
      if (carrier !== undefined) await Promise.all([carrier.close(), carrier.waitTermination()]);
      await (entry.raw?.waitTermination() ?? entry.nativeDone); credentials?.close(); work?.close(); routing?.fill(0); for (const reference of references) reference.release();
    }
  }
  #takeIngress(credentials: VerifiedRelayCredentials, reference: ResourceReference, entry: Entry): Promise<PreparedRelayIngress> {
    this.#check(); requireCredential(!entry.abort.signal.aborted);
    const key = this.#ingressKey(credentials, reference), pending = this.#pendingIngress.get(key);
    if (pending !== undefined) { this.#pendingIngress.delete(key); requireCredential(!pending.entry.abort.signal.aborted); pending.taken = true; return Promise.resolve(pending); }
    requireCredential(!this.#ingressWaiters.has(key) && this.#ingressWaiters.size < this.#options.maxPairs, "configuration_capacity");
    return new Promise<PreparedRelayIngress>((resolve, reject) => {
      const remove = (): void => { entry.abort.signal.removeEventListener("abort", cancel); if (this.#ingressWaiters.get(key) === waiter) this.#ingressWaiters.delete(key); };
      const cancel = (): void => { remove(); reject(new Error("carrier_closed")); };
      const waiter: RelayIngressWaiter = { take: ingress => { remove(); resolve(ingress); }, cancel };
      this.#ingressWaiters.set(key, waiter); entry.abort.signal.addEventListener("abort", cancel, { once: true });
      if (entry.abort.signal.aborted) cancel();
    });
  }
  async #run(entry: Entry): Promise<void> {
    const runtime = this.#runtime, options = this.#options, first = this.#ingressRole, second = first === 0 ? 1 : 0;
    const preparation = entry.preparation ?? TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), options.handshakeMS, 0xffffffffffffffffn), configurations: TunnelCarrierOptions[] = [this.#carrier, this.#serverCarrier];
    const outgoingCandidates: { configuration: TunnelCarrierOptions; carrier: TunnelHopCarrier }[] = [];
    const refs: ResourceReference[] = [], carriers: (TunnelHopCarrier | undefined)[] = [undefined, undefined], credentials: (VerifiedRelayCredentials | undefined)[] = [undefined, undefined];
    const claims: (VerifiedRelayClaim | undefined)[] = [undefined, undefined], hops: (HopAuthentication | undefined)[] = [undefined, undefined], meters: (RelayHopByteMeter | undefined)[] = [undefined, undefined];
    let pair: RelayNativePair | undefined, pairPreparation: RelayNativePairPreparation | undefined, timer: ReturnType<typeof setTimeout> | undefined, entryRef: ResourceReference | undefined, routingWork: CredentialWork | undefined;
    let opposite: PreparedRelayIngress | undefined; let handshake = true;
    const incarnation = new Uint8Array(16), invocation = new Uint8Array(16), carrierID = new Uint8Array(16), routing = new Uint8Array(65544);
    const cancel = (): void => { entry.abort.abort(); entry.raw?.abort(); entry.rawSocket?.destroy(); opposite?.entry.close(); pair?.close(); for (const carrier of carriers) void carrier?.close(); for (const candidate of outgoingCandidates) void candidate.carrier.close(); };
    entry.close = cancel;
    const guard = (): void => { this.#check(); entryRef!.check(); requireCredential(!entry.abort.signal.aborted); for (const owner of credentials) owner?.check(entryRef!); if (opposite !== undefined) { requireCredential(!opposite.entry.abort.signal.aborted); if (handshake) opposite.preparation.check(); } };
    try {
      entryRef = runtime.reserveConnectionWork("relay_entry", new ResourceVector([262144n + runtime.resources.runtimeBytes, 0n, 0n, 16n, 2n, 0n, 0n, 0n, 0n, 0n, 0n]));
      carriers[first] = entry.incoming ?? this.#allocateCarrier(configurations[first]!, true, preparation);
      // A second inbound listener owns its provider and finite ingress position
      // from listen. Otherwise reserve the outgoing owner before either claim.
      if (this.#oppositeOwner === undefined && !this.#livePreparedRoles.has(second)) for (const configuration of this.#configurations(second)) outgoingCandidates.push({ configuration, carrier: this.#allocateCarrier(configuration, false, preparation) });
      const ledgerCharge = options.activationStore.relayCharge();
      refs.push(...runtime.resources.root.reserveBatch([relayNativePairCharge(options.forwarding), ...[0, 1].map(() => relayCredentialCharge(runtime.resources.runtimeBytes)), ...[0, 1].map(() => hopAuthenticationCharge(runtime.resources.runtimeBytes)), ledgerCharge, ledgerCharge, ledgerCharge, credentialWorkCharge(65536, runtime.resources.runtimeBytes)].map((charge, index) => ({ owner: credentialOwner(runtime.resources, `relay_entry_${index}`), accounts: runtime.resources.accounts, charge }))));
      pairPreparation = new RelayNativePairPreparation(options.forwarding, refs[0]!);
      const tick = (): void => { try { guard(); preparation.check(); timer = setTimeout(tick, timerChunk(preparation.remainingMS())); } catch { cancel(); } }; tick();
      if (entry.raw !== undefined) {
        requireCredential(carriers[first] instanceof NodeRawQUICCarrier);
        await carriers[first].accept(entry.raw, { host: options.serverName, port: this.#address!.port, leaf: new X509Certificate(this.#certificateChain[0]!) }, entry.abort.signal);
      } else requireCredential(carriers[first] === entry.incoming);
      guard(); await this.#waitRoute(entry, guard);
      const count = await readRelayEnvelope(carriers[first]!, routing, () => { guard(); preparation.check(); }, entry.abort.signal);
      requireCredential(count !== null && routing[4] === wire.frame_types.HOP_AUTH);
      routingWork = new CredentialWork(runtime.resources, 65536, refs[8]!);
      const hello = routingWork.parse(routing.subarray(8, count), "HOP_AUTH_HELLO", 65536, 16384, { selectors: { hop_sender_role: "endpoint" } });
      try {
        const grant = hello.bytes("grant"), endpointCertificate = hello.bytes("identity_certificate");
        try { credentials[first] = verifyRelayCredentials({ ...options.credentials, endpointSubject: first === 0 ? options.credentials.clientSubject : options.credentials.serverSubject, resources: runtime.resources, clock: runtime.clock }, { grant, endpointCertificate, relayCertificate: this.#relayCertificate }, refs[1 + first]!); }
        finally { grant.fill(0); endpointCertificate.fill(0); }
      } finally { hello.close(); }
      credentials[first]!.onRevoked(cancel); requireCredential(credentials[first]!.role === first); carriers[first]!.checkAcceptedHopRoute(credentials[first]!, entryRef);
      runtime.fillRandom(incarnation); runtime.fillRandom(invocation); runtime.fillRandom(carrierID);
      const signer = Object.freeze({ publicKey: this.#publicKey, sign: (bytes: Uint8Array): Uint8Array => { guard(); return new Uint8Array(sign(null, bytes, options.identityKey)); } });
      const owner = (): RelayActivationOwner => ({ relay: this.#relayID, invocation, carrier: carrierID, generation: 1n, signal: entry.abort.signal });
      meters[first] = new RelayHopByteMeter(credentials[first]!.limits(entryRef), runtime.clock, guard, entry.abort.signal);
      const received = await meters[first]!.reserve(count); received(count);
      hops[first] = new HopAuthentication({ resources: runtime.resources, transport: carriers[first]!, credentials: credentials[first]!, localRole: 2, localIncarnation: incarnation, random: bytes => runtime.fillRandom(bytes), signer, deadline: preparation, guard, acceptedHello: routing.subarray(8, count), meter: meters[first]! }, refs[3 + first]!);
      claims[first] = await hops[first]!.authenticateRelay(async (claim, publish) => {
        const counterpart = await options.activationStore.relayCounterpart(claim, refs[7]!, preparation);
        try {
          credentials[second] = verifyRelayCredentials({ ...options.credentials, endpointSubject: second === 0 ? options.credentials.clientSubject : options.credentials.serverSubject, resources: runtime.resources, clock: runtime.clock }, counterpart, refs[1 + second]!);
          configurations[second] = this.#selectRelayConfiguration(second, credentials[second]!, entryRef!);
          if (outgoingCandidates.length > 0) {
            const selected = outgoingCandidates.find(value => value.configuration === configurations[second]); requireCredential(selected !== undefined, "credential_binding");
            carriers[second] = selected.carrier;
            await Promise.all(outgoingCandidates.filter(value => value !== selected).flatMap(value => [value.carrier.close(), value.carrier.waitTermination()]));
          }
          if (this.#oppositeOwner === undefined && this.#livePreparedRoles.has(second)) carriers[second] = await this.#takeOriginalLiveCarrier(second, credentials[second]!, entryRef!, entry.abort.signal);
          if (this.#oppositeOwner !== undefined) {
            opposite = await this.#takeIngress(credentials[second]!, entryRef!, entry);
            const suppliedGrant = opposite.credentials.grant(entryRef!), suppliedCertificate = opposite.credentials.certificate("endpoint", entryRef!), suppliedRelay = opposite.credentials.certificate("relay", entryRef!);
            try { requireCredential(opposite.credentials.role === second && equalCredential(suppliedGrant, counterpart.grant) && equalCredential(suppliedCertificate, counterpart.endpointCertificate) && equalCredential(suppliedRelay, counterpart.relayCertificate), "credential_binding"); }
            finally { suppliedGrant.fill(0); suppliedCertificate.fill(0); suppliedRelay.fill(0); }
            carriers[second] = opposite.carrier; opposite.entry.abort.signal.addEventListener("abort", cancel, { once: true });
          }
        } finally { counterpart.grant.fill(0); counterpart.endpointCertificate.fill(0); counterpart.relayCertificate.fill(0); }
        credentials[second]!.onRevoked(cancel); requireCredential(credentials[second]!.role === second);
        if (opposite === undefined && this.#livePrepared.get(second)?.taken !== true) await this.#prepareRelayDial(carriers[second]!, configurations[second]!, credentials[second]!, preparation, entry, entryRef!);
        guard(); this.#requireForwardingPair(credentials, carriers, entryRef!);
        meters[second] = new RelayHopByteMeter(credentials[second]!.limits(entryRef!), runtime.clock, guard, entry.abort.signal);
        if (opposite !== undefined) { const incoming = await meters[second]!.reserve(opposite.hello.length + 8); incoming(opposite.hello.length + 8); }
        hops[second] = new HopAuthentication({ resources: runtime.resources, transport: carriers[second]!, credentials: credentials[second]!, localRole: 2, localIncarnation: incarnation, random: bytes => runtime.fillRandom(bytes), signer, deadline: preparation, guard, ...(opposite === undefined ? {} : { acceptedHello: opposite.hello }), meter: meters[second]! }, refs[3 + second]!);
        meters[first]!.requireRemaining(BigInt(Math.max(65544, options.forwarding.maxEnvelopeBytes)) * 8n);
        await options.activationStore.claimRelay(claim, owner(), preparation, refs[5 + first]!, guard, publish);
      }, { signal: entry.abort.signal });
      hops[first]!.close(); runtime.fillRandom(invocation); runtime.fillRandom(carrierID);
      claims[second] = await hops[second]!.authenticateRelay(async (claim, publish) => { meters[second]!.requireRemaining(BigInt(Math.max(65544, options.forwarding.maxEnvelopeBytes)) * 8n); await options.activationStore.claimRelay(claim, owner(), preparation, refs[5 + second]!, guard, publish); }, { signal: entry.abort.signal });
      hops[second]!.close(); handshake = false; opposite?.finishHandshake();
      // Both original hop proofs and durable claims precede this handoff.
      // TLS pin windows constrain admission; the admitted opaque forwarding
      // pair keeps the same sockets and Grant deadlines afterward.
      for (const carrier of carriers) { requireCredential(carrier !== undefined); carrier.checkPreparation(); }
      guard();
      for (const carrier of carriers) if (carrier instanceof NodeWSSCarrier) carrier.completePreparation();
      pair = new RelayNativePair(options.forwarding, [{ transport: carriers[0]!, credentials: credentials[0]!, claim: claims[0]!, meter: meters[0]! }, { transport: carriers[1]!, credentials: credentials[1]!, claim: claims[1]!, meter: meters[1]! }], pairPreparation);
      this.#authenticatedPairs++;
      if (timer !== undefined) { clearTimeout(timer); timer = undefined; }
      const forwardTick = (): void => { try { guard(); const remaining = credentials[0]!.deadline.remainingMS() < credentials[1]!.deadline.remainingMS() ? credentials[0]!.deadline.remainingMS() : credentials[1]!.deadline.remainingMS(); timer = setTimeout(forwardTick, timerChunk(remaining)); } catch { cancel(); } }; forwardTick(); pair.start(); await pair.waitTermination();
    } finally {
      if (opposite !== undefined) opposite.entry.abort.signal.removeEventListener("abort", cancel);
      cancel(); if (timer !== undefined) clearTimeout(timer);
      if (pair !== undefined) { await pair.waitTermination(); const observed = pair.forwardingObservations(); this.#forwardedBytes += observed.bytes; this.#forwardedDatagrams += observed.datagrams; }
      for (const hop of hops) hop?.close();
      await Promise.all([...carriers.flatMap(carrier => carrier === undefined ? [] : [carrier.close(), carrier.waitTermination()]), ...outgoingCandidates.flatMap(value => [value.carrier.close(), value.carrier.waitTermination()])]);
      entry.raw?.abort(); entry.rawSocket?.destroy(); await (entry.raw?.waitTermination() ?? entry.nativeDone); await entry.incoming?.waitTermination();
      opposite?.complete(); pairPreparation?.close(); for (const claim of claims) claim?.close(); for (const credential of credentials) credential?.close(); routingWork?.close(); for (const reference of refs) reference.release();
      incarnation.fill(0); invocation.fill(0); carrierID.fill(0); routing.fill(0); entryRef?.release(); this.#entries.delete(entry); this.#cleanup();
    }
  }
  listenerAddresses(): readonly Readonly<{ endpointRole: 0 | 1; host: string; port: number }>[] {
    this.#check(); requireCredential(this.#address !== undefined);
    return Object.freeze([{ endpointRole: this.#ingressRole, ...this.#address }, ...(this.#oppositeOwner === undefined ? [] : [{ endpointRole: this.#oppositeOwner.#ingressRole, ...this.#oppositeOwner.address() }])].map(address => Object.freeze(address)));
  }
  status(): TunnelRuntimeStatus { return Object.freeze({ listening: this.#address !== undefined && !this.#closed, activePairs: this.#entries.size, rejectedHops: this.#rejected, authenticatedPairs: this.#authenticatedPairs, forwardedBytes: this.#forwardedBytes, forwardedDatagrams: this.#forwardedDatagrams, ...(this.#failure === undefined ? {} : { lastFailure: this.#failure }) }); }
  address(): Readonly<{ host: string; port: number }> { this.#check(); requireCredential(this.#address !== undefined); return this.#address; }
  close(): Promise<void> { if (!this.#closed) { this.#closed = true; this.#accept?.cancel(); for (const registry of this.#liveInboundPrepared.values()) registry.close(); this.#liveInboundPrepared.clear(); for (const [role, slot] of this.#livePrepared) void this.#closeOriginalLiveCarrier(role, slot);
      for (const waiter of this.#ingressWaiters.values()) waiter.cancel();
      for (const ingress of this.#pendingIngress.values()) ingress.entry.close();
      if (this.#oppositeOwner !== undefined) void this.#oppositeOwner.close().then(() => { this.#oppositeEnded = true; this.#cleanup(); }); for (const entry of this.#entries) entry.close(); if (!this.#started) this.#listenerEnded = true; if (this.#listener === undefined && this.#binding === undefined && this.#network === undefined) this.#listenerEnded = true; this.#cleanup(); } this.#listener?.abort(); this.#network?.close(() => { this.#listenerEnded = true; this.#cleanup(); }); this.#websockets?.close(() => { this.#wssEnded = true; this.#cleanup(); }); return this.#closedWait; }
  #cleanup(): void { if (!this.#closed || !this.#listenerEnded || this.#accepting !== undefined || this.#entries.size !== 0 || this.#livePrepared.size !== 0 || this.#retiring.size !== 0 || !this.#wssEnded || this.#released || !this.#oppositeEnded) return; this.#released = true;
    for (const bytes of this.#certificateChain) bytes.fill(0); for (const configured of [this.#carrier, this.#serverCarrier, ...this.#carrierAlternatives, ...this.#serverCarrierAlternatives]) closeCarrierRoots(configured); this.#privateKey.fill(0); this.#relayCertificate.fill(0); this.#publicKey.fill(0); this.#relayID.fill(0); this.#dependency?.release(); this.#resolve(); }
}
export function isOriginalTunnelRuntime(value: unknown, environment: ReturnType<typeof originalEnvironment>, store: SQLiteAdmissionStore): value is TunnelRuntime { return value instanceof TunnelRuntime && runtimeOwners.has(value) && value.belongsTo(environment, store); }
export function createTunnelRuntime(options: TunnelRuntimeOptions): TunnelRuntime { return new TunnelRuntime(runtimeCapability, options); }
for (const constructor of [TunnelRuntime]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
