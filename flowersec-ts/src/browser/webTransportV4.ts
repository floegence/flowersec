import { authenticateEndpointHop } from "../v4/runtime/endpointHop.js";
import type { HopAuthenticationPreparation } from "../v4/runtime/hopAuthentication.js";
import type { VerifiedRelayCredentials } from "../v4/runtime/relayCredentials.js";
import type { ReadyIdentitySigner } from "../v4/runtime/noiseHandshake.js";
import type { RandomFill } from "../v4/runtime/random.js";
import type { CredentialResources } from "../v4/runtime/credentialSupport.js";
import type { ResourceReference } from "../v4/runtime/resources.js";
import type { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import type { OperationOptions } from "../public/contract.js";
import type { V4AuthenticatedTransport, V4NativeStreamProvider } from "../v4/runtime/session.js";
import type { V4EnvironmentRuntime, EnvironmentDependency } from "../v4/runtime/environment.js";
import { CredentialWork, credentialWorkCharge, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import type { ClientPreparationFields } from "../v4/runtime/credentialVerifier.js";
import { ResourceError, ResourceVector } from "../v4/runtime/resources.js";
import { timerChunk, TrustedDeadline } from "../v4/runtime/deadline.js";
import { transportV4CarrierProviderRegistry } from "../generated/transportV4Registry.js";
import { BrowserWebTransportStream, browserStreamSignalsAvailable, observeNative, type BrowserNativeBidi } from "./webTransportStreamV4.js";
import type { NativeDatagrams } from "../v4/runtime/unreliable.js";
import { BrowserWebTransportPositions, browserNativeStreamCharge } from "./webTransportPositionsV4.js";

interface BrowserNativeWebTransport {
  readonly ready: Promise<void>;
  readonly closed: Promise<unknown>;
  readonly incomingBidirectionalStreams: ReadableStream<BrowserNativeBidi>;
  readonly incomingUnidirectionalStreams: ReadableStream<ReadableStream<Uint8Array>>;
  readonly datagrams: { readonly readable: ReadableStream<Uint8Array>; readonly writable: WritableStream<Uint8Array>; readonly maxDatagramSize: number; incomingHighWaterMark: number; outgoingHighWaterMark: number };
  readonly reliability?: string;
  createBidirectionalStream(): Promise<BrowserNativeBidi>;
  close(info?: Readonly<{ closeCode: number; reason: string }>): void;
}
type NativeConstructor = new (url: string, options?: Readonly<{ serverCertificateHashes: readonly Readonly<{ algorithm: "sha-256"; value: ArrayBuffer }>[] }>) => BrowserNativeWebTransport;
// Capture the host implementation once; a later global replacement cannot
// silently replace the provider selected by Environment configuration.
const NativeWebTransport = (globalThis as unknown as { WebTransport?: NativeConstructor }).WebTransport;
const tuple = transportV4CarrierProviderRegistry.webtransport.tuples.find(value => value.id === "chromium_h3_draft02")!;

/** Trusted operator input, independent of peer messages and credential content.
 * Source/build, dedicated H3, no early data, Origin enforcement, RFC H3 DATAGRAM,
 * absent extra WT session flow control, and maintenance progress are deployment
 * obligations. JS cannot inspect TLS/SETTINGS/CONNECT stream ID or prove them.
 * An evidence reference documents this trust; it is not a runtime receipt. */
export interface V4BrowserWebTransportDeployment {
  readonly deploymentID: string;
  readonly revision: string;
  readonly endpoint: string;
  readonly applicationOrigin: string;
  readonly routeDigest: Uint8Array;
  readonly notBeforeMS: bigint;
  readonly notAfterMS: bigint;
  readonly providerTuple: "chromium_h3_draft02";
  readonly implementation: string;
  readonly quicImplementation: string;
  readonly buildID: string;
  readonly userAgent: string;
  readonly terminatorProfile: "tls13-no-early-data-h3-dedicated-exact-origin-no-wt-session-flow-control";
  readonly evidenceReference: string;
}
export interface V4BrowserWebTransportOptions {
  readonly deployment: V4BrowserWebTransportDeployment;
  /** Includes opening, accepted, unbound and physically cleaning application streams. */
  readonly applicationStreams: number;
  readonly streamBufferBytes: number;
  readonly runtimeBytes: bigint;
  /** Qualified native connection/HTTP3 queues, including streams not yet exposed to JS. */
  readonly providerRuntimeBytes: bigint;
  /** Additional native per-stream peak allowance. */
  readonly providerStreamBytes: bigint;
}
interface CapturedOptions extends V4BrowserWebTransportOptions { readonly constructor: NativeConstructor }
const captured = new WeakMap<V4BrowserWebTransportOptions, CapturedOptions>();
const positive = (value: bigint): boolean => typeof value === "bigint" && value > 0n && value <= 0xffffffffffffffffn;
const identifier = (value: string): boolean => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u.test(value);


/** Called by trusted Environment setup, before starting Prepare. The opaque
 * captured key exposes no mutable route-digest backing used by admission. */
export function captureBrowserWebTransport(input: V4BrowserWebTransportOptions): V4BrowserWebTransportOptions {
  const source = input.deployment;
  requireCredential(source.routeDigest instanceof Uint8Array && typeof source.endpoint === "string" && typeof source.applicationOrigin === "string", "configuration_capacity");
  const d: V4BrowserWebTransportDeployment = { deploymentID: source.deploymentID, revision: source.revision, endpoint: source.endpoint,
    applicationOrigin: source.applicationOrigin, routeDigest: new Uint8Array(source.routeDigest), notBeforeMS: source.notBeforeMS, notAfterMS: source.notAfterMS,
    providerTuple: source.providerTuple, implementation: source.implementation, quicImplementation: source.quicImplementation,
    buildID: source.buildID, userAgent: source.userAgent, terminatorProfile: source.terminatorProfile, evidenceReference: source.evidenceReference };
  const applicationStreams = input.applicationStreams, streamBufferBytes = input.streamBufferBytes, runtimeBytes = input.runtimeBytes,
    providerRuntimeBytes = input.providerRuntimeBytes, providerStreamBytes = input.providerStreamBytes;
  // The only browser tuple installed by this provider is Chromium. Checking
  // the engine family rejects an incompatible deployment claim; it does not
  // qualify the source/build, TLS, or HTTP/3 behavior of that deployment.
  requireCredential(/\b(?:Chrome|Chromium|HeadlessChrome)\/\d+/u.test(globalThis.navigator?.userAgent ?? ""), "configuration_capacity");
  requireCredential(typeof NativeWebTransport === "function" && browserStreamSignalsAvailable() && globalThis.isSecureContext && typeof globalThis.location?.origin === "string", "configuration_capacity");
  requireCredential(typeof globalThis.navigator?.userAgent === "string" && d.providerTuple === tuple.id && d.implementation === tuple.implementation && d.quicImplementation === tuple.quic_implementation &&
    d.terminatorProfile === "tls13-no-early-data-h3-dedicated-exact-origin-no-wt-session-flow-control" && identifier(d.deploymentID) && identifier(d.revision) && identifier(d.buildID) &&
    typeof d.userAgent === "string" && d.userAgent.length > 0 && d.userAgent.length <= 1024 && d.userAgent === globalThis.navigator.userAgent &&
    typeof d.evidenceReference === "string" && d.evidenceReference.length > 0 && d.evidenceReference.length <= 1024 && d.routeDigest.length === 32 &&
    typeof d.notBeforeMS === "bigint" && d.notBeforeMS >= 0n && d.notBeforeMS <= 0xffffffffffffffffn && positive(d.notAfterMS) && d.notAfterMS > d.notBeforeMS &&
    Number.isSafeInteger(applicationStreams) && applicationStreams >= 1 && applicationStreams <= 4096 &&
    Number.isSafeInteger(streamBufferBytes) && streamBufferBytes >= 65544 && streamBufferBytes <= 16777224 &&
    positive(runtimeBytes) && positive(providerRuntimeBytes) && positive(providerStreamBytes), "configuration_capacity");
  let endpoint: URL, origin: URL;
  try { endpoint = new URL(d.endpoint); origin = new URL(d.applicationOrigin); }
  catch { requireCredential(false, "configuration_capacity"); }
  requireCredential(endpoint.href === d.endpoint && endpoint.protocol === "https:" && endpoint.username === "" && endpoint.password === "" && endpoint.search === "" && endpoint.hash === "" &&
    (endpoint.pathname === "/flowersec/webtransport/v4/direct" || endpoint.pathname === "/flowersec/webtransport/v4/tunnel") && origin.origin === d.applicationOrigin && origin.origin === globalThis.location.origin, "configuration_capacity");
  const value = Object.freeze({ deployment: Object.freeze(d), applicationStreams, streamBufferBytes, runtimeBytes, providerRuntimeBytes, providerStreamBytes, constructor: NativeWebTransport });
  const key = Object.freeze({ deployment: Object.freeze({ ...d, routeDigest: new Uint8Array(d.routeDigest) }),
    applicationStreams, streamBufferBytes, runtimeBytes, providerRuntimeBytes, providerStreamBytes });
  captured.set(key, value); return key;
}
interface Pin { readonly digest: Uint8Array<ArrayBuffer>; readonly from: bigint; readonly until: bigint }

/** One original dedicated native H3 connection. This layer owns native
 * associations; logical scope binding and independent record scheduling belong
 * to Session and must be assembled before this provider is publicly exposed. */
export class BrowserWebTransportCarrier implements V4AuthenticatedTransport {
  readonly role = "client" as const;
  readonly mode = "stream" as const;
  readonly nativeStreams: V4NativeStreamProvider;
  readonly nativeDatagrams: NativeDatagrams;
  #datagramReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  #datagramWriter: WritableStreamDefaultWriter<Uint8Array> | undefined;
  #datagramReading = false;
  #datagramWrites = 0;
  #datagramClosed = true;
  #datagramCancel: Promise<void> | undefined;
  readonly #done: Promise<void>;
  #resolve!: () => void;
  readonly #abort = new AbortController();
  readonly #streams = new Set<BrowserWebTransportStream>();
  readonly #deadline: TrustedDeadline;
  #maintenance: BrowserWebTransportStream | undefined;
  #native: BrowserNativeWebTransport | undefined;
  #incoming: ReadableStreamDefaultReader<BrowserNativeBidi> | undefined;
  #incomingClosed = true;
  #incomingCancel: Promise<void> | undefined;
  #incomingUni: ReadableStreamDefaultReader<ReadableStream<Uint8Array>> | undefined;
  #incomingUniClosed = true;
  #incomingUniCancel: Promise<void> | undefined;
  #unsupportedInput: Promise<void> | undefined;
  #accepting = false;
  #nativeEnded = false;
  #readyPending = false;
  #closed = false;
  #released = false;
  #activated = false;
  #applications = false;
  #applicationCount = 0;
  #prepared = false;
  #prepareStarted = false;
  #constructing = false;
  #pins: readonly Pin[];
  #maximumDatagram = 0;
  constructor(private readonly environment: V4EnvironmentRuntime, private readonly dependency: EnvironmentDependency,
    private readonly positions: BrowserWebTransportPositions, private readonly options: CapturedOptions, private readonly maximum: number, private readonly preparation: TrustedDeadline, pins: readonly Pin[]) {
    this.#done = new Promise(resolve => { this.#resolve = resolve; }); this.#pins = pins;
    this.nativeStreams = Object.freeze({ capacity: options.applicationStreams, enable: () => this.enableApplicationStreams(),
      open: (operation?: OperationOptions) => this.openApplicationStream(operation), accept: (operation?: OperationOptions) => this.acceptApplicationStream(operation) });
    this.#deadline = new TrustedDeadline(environment.clock, options.deployment.notAfterMS);
    this.nativeDatagrams = Object.freeze({ maxDatagramBytes: () => this.maxDatagramBytes(),
      receive: (maximum: number, operation?: OperationOptions) => this.receiveDatagram(maximum, operation),
      submit: (bytes: Uint8Array, admitted: () => void) => this.submitDatagram(bytes, admitted) });
    dependency.onClose(() => { void this.close(); });
  }
  #checkBinding(): void {
    this.dependency.check(); this.#deadline.check();
    if (this.#closed || this.#nativeEnded) throw new Error("carrier_closed");
    const d = this.options.deployment, now = this.environment.clock.sample().requireInterval();
    requireCredential(now.lowerMS >= d.notBeforeMS && globalThis.isSecureContext && globalThis.location.origin === d.applicationOrigin && globalThis.navigator.userAgent === d.userAgent, "credential_untrusted");
    // Browser APIs cannot identify which hash matched. The original entire
    // active set must remain authorized; never remove an expired entry locally.
    for (const pin of this.#pins) requireCredential(now.lowerMS >= pin.from && now.upperMS < pin.until, "credential_expired");
  }
  authenticateHop(credentials: VerifiedRelayCredentials, signer: ReadyIdentitySigner, random: RandomFill, resources: CredentialResources, reference: ResourceReference,
    options?: OperationOptions, acceptedHello?: Uint8Array, prepared?: HopAuthenticationPreparation): Promise<void> {
    return authenticateEndpointHop(this, credentials, signer, random, resources, reference, this.preparation, options, acceptedHello, prepared);
  }
  checkPreparation(): void {
    this.#checkBinding(); this.preparation.check();
    requireCredential(this.#prepared && this.#maintenance !== undefined && !this.#maintenance.cleanupComplete(), "credential_closed");
  }
  activate(): void {
    this.checkPreparation();
    if (this.#activated) throw new Error("activation_already_started");
    this.#activated = true;
  }
  /** Internal Session calls this only after original admission, Noise and READY. */
  enableApplicationStreams(): void {
    this.#checkBinding();
    if (!this.#activated || this.#applications) throw new Error("activation_required");
    this.#applications = true;
  }
  #checkIO(): void { this.#checkBinding(); if (!this.#activated) throw new Error("activation_required"); }
  #position(origin: "maintenance" | "local" | "peer"): BrowserWebTransportStream {
    this.#checkBinding();
    if (origin !== "maintenance" && this.#applicationCount >= this.options.applicationStreams) throw new ResourceError("resource_exhausted");
    const position = this.positions.acquire(origin === "maintenance");
    try {
      const stream = new BrowserWebTransportStream(position, origin, this.maximum, () => this.#checkIO(), () => {
        this.#streams.delete(stream); if (origin !== "maintenance") this.#applicationCount--; this.#finish();
      });
      this.#streams.add(stream); if (origin !== "maintenance") this.#applicationCount++; return stream;
    } catch (error) { position.release(); throw error; }
  }
  #create(origin: "maintenance" | "local", signal?: AbortSignal): Promise<BrowserWebTransportStream> {
    const stream = this.#position(origin);
    let pending: Promise<BrowserNativeBidi>;
    try { pending = this.#native!.createBidirectionalStream(); }
    catch (error) { stream.creationFailed(); throw error; }
    const actual = pending.then(raw => {
      try {
        stream.attach(raw);
        if (this.#closed || signal?.aborted) { void stream.close(); throw new Error("canceled"); }
        this.#checkBinding(); return stream;
      } catch (error) { void stream.close(); throw error; }
    }, () => { stream.creationFailed(); throw new Error("carrier_failed"); });
    return observeNative(actual, signal, late => { void late.close(); });
  }
  async prepare(signal?: AbortSignal): Promise<void> {
    if (this.#prepareStarted) throw new Error("invalid_resource_owner");
    this.#prepareStarted = true;
    const abort = (): void => { void this.close(); };
    const operation = AbortSignal.any(signal === undefined ? [this.#abort.signal] : [signal, this.#abort.signal]);
    signal?.addEventListener("abort", abort, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined, preparationFailure: unknown;
    try {
      if (operation.aborted) throw new Error("canceled");
      this.preparation.check(); this.#checkBinding();
      // Chromium exposes neither allowPooling nor requireUnreliable. The
      // fixed trusted tuple supplies dedicated H3; pass no fictitious options.
      this.#constructing = true;
      let native: BrowserNativeWebTransport;
      try {
        native = this.#native = this.#pins.length === 0 ? new this.options.constructor(this.options.deployment.endpoint)
          : new this.options.constructor(this.options.deployment.endpoint, { serverCertificateHashes: this.#pins.map(pin => ({ algorithm: "sha-256", value: pin.digest.buffer })) });
        this.#nativeEnded = false;
      } finally { this.#constructing = false; }
      const ended = (): void => { this.#nativeEnded = true; void this.close(); this.#finish(); };
      void native.closed.then(ended, ended);
      this.#readyPending = true;
      const readiness = native.ready.finally(() => { this.#readyPending = false; this.#finish(); });
      if (this.#closed) try { native.close({ closeCode: 0, reason: "" }); } catch { /* Retain the original native closed observation. */ }
      const tick = (): void => {
        try { this.preparation.check(); this.#checkBinding(); timer = setTimeout(tick, timerChunk(this.preparation.remainingMS())); }
        catch (error) { preparationFailure = error; void this.close(); }
      };
      tick();
      try { await observeNative(readiness, operation); }
      catch (error) { throw preparationFailure ?? error; }
      this.preparation.check(); this.#checkBinding();
      requireCredential(native.reliability === undefined || native.reliability === "supports-unreliable", "credential_untrusted");
      const maximum = native.datagrams.maxDatagramSize;
      requireCredential(Number.isSafeInteger(maximum) && maximum > 0 && typeof native.datagrams.readable.getReader === "function" && typeof native.datagrams.writable.getWriter === "function", "credential_untrusted");
      this.#maximumDatagram = maximum;
      native.datagrams.incomingHighWaterMark = 64; native.datagrams.outgoingHighWaterMark = 1;
      this.#datagramReader = native.datagrams.readable.getReader(); this.#datagramWriter = native.datagrams.writable.getWriter(); this.#datagramClosed = false;
      const datagramsEnded = () => { this.#datagramClosed = true; this.#finish(); };
      void this.#datagramReader.closed.then(datagramsEnded, datagramsEnded);
      void this.#datagramWriter.closed.catch(() => undefined);
      this.#incoming = native.incomingBidirectionalStreams.getReader(); this.#incomingClosed = false;
      const incomingEnded = (): void => { this.#incomingClosed = true; if (!this.#closed) void this.close(); this.#finish(); };
      void this.#incoming.closed.then(incomingEnded, incomingEnded);
      this.#incomingUni = native.incomingUnidirectionalStreams.getReader(); this.#incomingUniClosed = false;
      const uniEnded = (): void => { this.#incomingUniClosed = true; if (!this.#closed) void this.close(); this.#finish(); };
      void this.#incomingUni.closed.then(uniEnded, uniEnded);
      // Flowersec's selected reliable profile assigns only native bidi streams.
      // Observe one unsupported uni association without reading its body or
      // growing a discard queue. Its actual cancel tail remains connection-paid.
      this.#unsupportedInput = this.#incomingUni.read().then(async result => {
        void this.close();
        if (!result.done) await result.value.cancel();
      }, () => { void this.close(); }).catch(() => undefined).finally(() => {
        this.#unsupportedInput = undefined; this.#finish();
      });
      this.#maintenance = await this.#create("maintenance", operation);
      this.#prepared = true; this.checkPreparation();
    } catch (error) { void this.close(); throw error; }
    finally { if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", abort); }
  }
  openApplicationStream(options?: OperationOptions): Promise<BrowserWebTransportStream> {
    try {
      this.#checkIO(); if (!this.#applications) throw new Error("session_not_ready");
      if (options?.signal?.aborted) throw new Error("canceled");
      const signal = AbortSignal.any(options?.signal === undefined ? [this.#abort.signal] : [options.signal, this.#abort.signal]);
      return this.#create("local", signal);
    } catch (error) { return Promise.reject(error); }
  }
  acceptApplicationStream(options?: OperationOptions): Promise<BrowserWebTransportStream> {
    let stream: BrowserWebTransportStream;
    try {
      this.#checkIO(); if (!this.#applications) throw new Error("session_not_ready");
      if (options?.signal?.aborted) throw new Error("canceled");
      if (this.#accepting) throw new Error("busy");
      stream = this.#position("peer");
    } catch (error) { return Promise.reject(error); }
    this.#accepting = true;
    const actual = (async () => {
      try {
        const result = await this.#incoming!.read();
        if (result.done) { stream.creationFailed(); throw new Error("carrier_closed"); }
        stream.attach(result.value);
        this.#checkIO(); if (options?.signal?.aborted) throw new Error("canceled");
        return stream;
      } catch (error) { stream.creationFailed(); void stream.close(); throw error; }
      finally { this.#accepting = false; this.#finish(); }
    })();
    const signal = AbortSignal.any(options?.signal === undefined ? [this.#abort.signal] : [options.signal, this.#abort.signal]);
    return observeNative(actual, signal, late => { void late.close(); });
  }
  /** Complete Flowersec envelope MTU supplied by the native browser API. This
   * observation alone does not enable the Flowersec datagram feature. */
  maxDatagramBytes(): number {
    this.#checkBinding(); const actual = this.#native!.datagrams.maxDatagramSize;
    if (!Number.isSafeInteger(actual) || actual < 1) throw new Error("carrier_failed");
    return Math.min(actual, this.#maximumDatagram);
  }
  async receiveDatagram(maximum: number, options?: OperationOptions): Promise<Uint8Array> {
    this.#checkIO(); if (!this.#applications || this.#datagramReading || this.#datagramReader === undefined || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024) throw new Error("carrier_closed");
    if (options?.signal?.aborted) throw new Error("canceled");
    this.#datagramReading = true;
    const cancel = () => { void this.#cancelDatagrams(); };
    options?.signal?.addEventListener("abort", cancel, { once: true }); if (options?.signal?.aborted) cancel();
    try { for (;;) {
      const result = await this.#datagramReader.read();
      this.#checkIO(); if (options?.signal?.aborted) { result.value?.fill(0); throw new Error("canceled"); }
      if (result.done) throw new Error("carrier_closed");
      try {
        if (!(result.value instanceof Uint8Array)) throw new Error("carrier_failed");
        if (result.value.length > maximum) continue;
        return new Uint8Array(result.value);
      } finally { result.value.fill(0); }
    } } finally { options?.signal?.removeEventListener("abort", cancel); this.#datagramReading = false; this.#finish(); }
  }
  submitDatagram(bytes: Uint8Array, admitted: () => void): Readonly<{ completion: Promise<void> }> | undefined {
    this.#checkIO(); const writer = this.#datagramWriter;
    if (!this.#applications || writer === undefined || bytes.length > this.maxDatagramBytes() || writer.desiredSize === null || writer.desiredSize <= 0) return undefined;
    const actual = writer.write(bytes); this.#datagramWrites++;
    let failure: unknown;
    try { admitted(); } catch (error) { failure = error; }
    const completion = (async () => { try { await actual; if (failure !== undefined) throw failure; }
      finally { this.#datagramWrites--; this.#finish(); } })();
    return Object.freeze({ completion });
  }
  #cancelDatagrams(): Promise<void> {
    if (this.#datagramCancel !== undefined) return this.#datagramCancel;
    if (this.#datagramReader === undefined) return Promise.resolve();
    let actual: Promise<void>;
    try { actual = this.#datagramReader.cancel(); } catch { actual = Promise.reject(new Error("carrier_failed")); }
    return this.#datagramCancel = actual.catch(() => undefined).then(() => { this.#datagramCancel = undefined; this.#finish(); });
  }
  read(maxBytes: number, options?: OperationOptions): Promise<Uint8Array | null> {
    try {
      this.#checkIO();
      const signal = AbortSignal.any(options?.signal === undefined ? [this.#abort.signal] : [options.signal, this.#abort.signal]);
      return this.#maintenance!.read(maxBytes, { ...options, signal });
    } catch (error) { return Promise.reject(error); }
  }
  write(data: Uint8Array, options?: OperationOptions): Promise<number> {
    try { this.#checkIO(); return this.#maintenance!.write(data, options); } catch (error) { return Promise.reject(error); }
  }
  submit(data: Uint8Array, admitted: () => void, beforeSubmit?: () => void): { completion: Promise<void> } | undefined {
    try { this.#checkIO(); } catch { return undefined; }
    return this.#maintenance!.submit(data, admitted, beforeSubmit);
  }
  close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true; this.#abort.abort(); void this.#cancelDatagrams();
      this.positions.close();
      for (const stream of this.#streams) void stream.close();
      if (this.#incoming !== undefined) {
        let tail: Promise<void>;
        try { tail = this.#incoming.cancel(); } catch { tail = Promise.reject(new Error("carrier_failed")); }
        this.#incomingCancel = tail.catch(() => undefined).then(() => { this.#incomingCancel = undefined; this.#finish(); });
      }
      if (this.#incomingUni !== undefined) {
        let tail: Promise<void>;
        try { tail = this.#incomingUni.cancel(); } catch { tail = Promise.reject(new Error("carrier_failed")); }
        this.#incomingUniCancel = tail.catch(() => undefined).then(() => { this.#incomingUniCancel = undefined; this.#finish(); });
      }
      if (this.#native === undefined) this.#nativeEnded = true;
      else try { this.#native.close({ closeCode: 0, reason: "" }); } catch { /* Only the original closed promise proves native exit. */ }
    }
    this.#finish(); return this.#done;
  }
  waitTermination(): Promise<void> { return this.#done; }
  #finish(): void {
    if (!this.#closed || this.#constructing || !this.#nativeEnded || this.#readyPending || this.#released || this.#streams.size !== 0 || this.#accepting || this.#incomingCancel !== undefined || !this.#incomingClosed ||
        this.#datagramReading || this.#datagramWrites !== 0 || !this.#datagramClosed || this.#datagramCancel !== undefined || this.#unsupportedInput !== undefined || this.#incomingUniCancel !== undefined || !this.#incomingUniClosed || !this.positions.cleanupComplete()) return;
    this.#released = true; this.#datagramReader?.releaseLock(); this.#datagramWriter?.releaseLock(); this.#datagramReader = undefined; this.#datagramWriter = undefined; this.#incoming?.releaseLock(); this.#incomingUni?.releaseLock();
    this.#incoming = undefined; this.#incomingUni = undefined; this.#native = undefined; this.#maintenance = undefined;
    for (const pin of this.#pins) pin.digest.fill(0); this.#pins = [];
    this.dependency.release(); this.#resolve();
  }
}

export function browserWebTransportAdmissionCosts(maxFrame: number, configuration: V4BrowserWebTransportOptions, runtimeBytes: bigint): readonly (readonly [string, ResourceVector])[] {
  const options = captured.get(configuration); requireCredential(options !== undefined, "configuration_capacity");
  const maximum = Math.max(maxFrame, 65536) + 8; requireCredential(maximum <= options.streamBufferBytes, "configuration_capacity");
  const charge = new ResourceVector([options.runtimeBytes + 16384n + 65536n + BigInt(options.applicationStreams + 1) * 128n,
    options.providerRuntimeBytes + options.providerStreamBytes + 4194304n, 0n, BigInt(options.applicationStreams + 20), 4n, 8n, 1n, 1n, 1n, 0n, 5n]);
  const position = browserNativeStreamCharge(maximum, options.runtimeBytes, options.providerStreamBytes);
  return [["browser_webtransport", charge], ...Array.from({ length: options.applicationStreams + 1 }, () => ["carrier_stream_position", position] as const),
    ["browser_webtransport_policy", credentialWorkCharge(16384, runtimeBytes)]];
}

export async function prepareBrowserWebTransport(environment: V4EnvironmentRuntime, fields: ClientPreparationFields,
  configuration: V4BrowserWebTransportOptions, signal?: AbortSignal, admission?: ClientSessionAdmission): Promise<BrowserWebTransportCarrier> {
  const options = captured.get(configuration); requireCredential(options !== undefined, "configuration_capacity");
  const d = options.deployment, now = environment.clock.sample().requireInterval();
  requireCredential(equalCredential(fields.routeDigest, d.routeDigest) && now.lowerMS >= d.notBeforeMS && now.upperMS < d.notAfterMS && globalThis.location.origin === d.applicationOrigin);
  const maximum = Math.max(fields.maxFrame, 65536) + 8; requireCredential(maximum <= options.streamBufferBytes, "configuration_capacity");
  const costs = browserWebTransportAdmissionCosts(fields.maxFrame, configuration, environment.resources.runtimeBytes);
  const references = admission?.take(costs.slice(0, -1));
  let reserved: ReturnType<V4EnvironmentRuntime["admitDependencyPositions"]>;
  try { reserved = environment.admitDependencyPositions("browser_webtransport", costs[0]![1], costs[1]![1], options.applicationStreams + 1, references, admission); }
  finally { for (const reference of references ?? []) reference.release(); }
  const { dependency, positions: prepaid } = reserved;
  const pins: Pin[] = [];
  let positions: BrowserWebTransportPositions | undefined, work: CredentialWork | undefined, carrier: BrowserWebTransportCarrier | undefined;
  try {
    positions = new BrowserWebTransportPositions(prepaid);
    const r = environment.resources, ref = environment.reserveConnectionWork("browser_webtransport_policy", costs[costs.length - 1]![1], admission);
    try { work = new CredentialWork(r, 16384, ref); } finally { ref.release(); }
    const route = work.parse(fields.route, "Route", 16384);
    try {
      const leg = route.field(fields.pathKind === 0 ? "direct_leg" : "client_leg"), tls = route.field("tls_policy", leg, "Leg"), origin = route.field("origin_policy", leg, "Leg"), url = new URL(d.endpoint);
      requireCredential(route.uint("path_kind") === BigInt(fields.pathKind) && route.uint("access_class", leg, "Leg") === 0n && route.uint("carrier", leg, "Leg") === 2n &&
        route.uint("dialer_role", leg, "Leg") === 0n && route.uint("listener_role", leg, "Leg") === (fields.pathKind === 0 ? 1n : 2n) && route.text("path", leg, "Leg") === url.pathname &&
        route.text("alpn", leg, "Leg") === "h3" && route.text("subprotocol", leg, "Leg") === "" &&
        route.text("host", leg, "Leg") === url.hostname.replace(/^\[|\]$/gu, "") && route.uint("port", leg, "Leg") === BigInt(url.port === "" ? 443 : Number(url.port)) &&
        [...route.items("origins", origin, "OriginPolicy")].some(node => route.doc.text(node) === d.applicationOrigin), "credential_untrusted");
      requireCredential(!route.doc.boolean(route.field("require_consumer_tls13_verification", tls, "TLSPolicy")), "credential_untrusted");
      const mode = route.uint("mode", tls, "TLSPolicy");
      if (mode === 1n) {
        requireCredential(route.uint("pin_kind", tls, "TLSPolicy") === 0n, "credential_untrusted");
        for (const pin of route.items("pins", tls, "TLSPolicy")) {
          const from = route.uint("not_before_ms", pin, "TLSPin"), until = route.uint("not_after_ms", pin, "TLSPin");
          requireCredential(route.text("certificate_profile", pin, "TLSPin") === "x509v3-p256-14d" && until > from && until - from <= 1209600000n, "credential_untrusted");
          if (now.lowerMS >= from && now.upperMS < until) pins.push(Object.freeze({ from, until, digest: new Uint8Array(route.bytes("leaf_der_sha256", pin, "TLSPin")) }));
        }
        requireCredential(pins.length > 0 && pins.length <= 16, "credential_expired");
      } else requireCredential(mode === 0n, "credential_untrusted");
    } finally { route.close(); work.close(); work = undefined; }
    carrier = new BrowserWebTransportCarrier(environment, dependency, positions, options, maximum, fields.preparationDeadline, Object.freeze(pins));
    await carrier.prepare(signal); requireCredential((fields.required & 1n) === 0n || carrier.maxDatagramBytes() >= 76, "required_guarantee_unavailable"); return carrier;
  } catch (error) {
    work?.close();
    if (carrier !== undefined) await Promise.allSettled([carrier.close(), carrier.waitTermination()]);
    else {
      for (const pin of pins) pin.digest.fill(0);
      if (positions !== undefined) positions.close(); else for (const position of prepaid) position.close();
      dependency.release();
    }
    throw error;
  }
}
