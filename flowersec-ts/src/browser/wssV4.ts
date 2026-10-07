import { authenticateEndpointHop } from "../v4/runtime/endpointHop.js";
import type { HopAuthenticationPreparation } from "../v4/runtime/hopAuthentication.js";
import type { VerifiedRelayCredentials } from "../v4/runtime/relayCredentials.js";
import type { ReadyIdentitySigner } from "../v4/runtime/noiseHandshake.js";
import type { RandomFill } from "../v4/runtime/random.js";
import type { CredentialResources } from "../v4/runtime/credentialSupport.js";
import type { ResourceReference } from "../v4/runtime/resources.js";
import type { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import type { OperationOptions } from "../public/contract.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import type { V4EnvironmentRuntime, EnvironmentDependency } from "../v4/runtime/environment.js";
import { CredentialWork, credentialWorkCharge, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import type { ClientPreparationFields } from "../v4/runtime/credentialVerifier.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { timerChunk, TrustedDeadline } from "../v4/runtime/deadline.js";

const NativeWebSocket = globalThis.WebSocket;
/** Trusted host deployment input, captured independently of peer messages.
 * The configured operator is responsible for the browser-facing terminator,
 * including any LB/proxy. JS does not observe TLS version, early data or ALPN.
 * This binding cannot satisfy consumer-enforced TLS verification. */
export interface V4BrowserWSSDeployment {
  readonly deploymentID: string;
  readonly revision: string;
  readonly endpoint: string;
  readonly applicationOrigin: string;
  readonly routeDigest: Uint8Array;
  readonly notBeforeMS: bigint;
  readonly notAfterMS: bigint;
  readonly terminatorProfile: "tls13-no-early-data-http11-exact-origin-no-extensions";
  /** Reference to the operator's independently established configuration evidence. */
  readonly evidenceReference: string;
}
export interface V4BrowserWSSOptions {
  readonly deployment: V4BrowserWSSDeployment;
  readonly queueMessages: number;
  readonly sendBufferBytes: number;
  readonly runtimeBytes: bigint;
  /** Observed/qualified host allocation budget; browser native queues are not JS-controllable. */
  readonly providerRuntimeBytes: bigint;
}
export function captureBrowserWSS(options: V4BrowserWSSOptions): V4BrowserWSSOptions {
  const d = options.deployment;
  requireCredential(typeof NativeWebSocket === "function" && globalThis.isSecureContext && typeof globalThis.location?.origin === "string", "configuration_capacity");
  requireCredential(d.terminatorProfile === "tls13-no-early-data-http11-exact-origin-no-extensions" && /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u.test(d.deploymentID) &&
    /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u.test(d.revision) && typeof d.evidenceReference === "string" && d.evidenceReference.length > 0 && d.evidenceReference.length <= 1024 &&
    d.routeDigest instanceof Uint8Array && d.routeDigest.length === 32 && typeof d.notBeforeMS === "bigint" && d.notBeforeMS >= 0n && d.notBeforeMS <= 0xffffffffffffffffn &&
    typeof d.notAfterMS === "bigint" && d.notAfterMS > d.notBeforeMS && d.notAfterMS <= 0xffffffffffffffffn &&
    Number.isSafeInteger(options.queueMessages) && options.queueMessages >= 1 && options.queueMessages <= 64 && Number.isSafeInteger(options.sendBufferBytes) && options.sendBufferBytes >= 65544 && options.sendBufferBytes <= 16777224 &&
    typeof options.runtimeBytes === "bigint" && options.runtimeBytes > 0n && options.runtimeBytes <= 0xffffffffffffffffn &&
    typeof options.providerRuntimeBytes === "bigint" && options.providerRuntimeBytes > 0n && options.providerRuntimeBytes <= 0xffffffffffffffffn &&
    typeof d.endpoint === "string" && typeof d.applicationOrigin === "string", "configuration_capacity");
  let endpoint: URL, origin: URL;
  try { endpoint = new URL(d.endpoint); origin = new URL(d.applicationOrigin); }
  catch { requireCredential(false, "configuration_capacity"); }
  requireCredential(endpoint.href === d.endpoint && endpoint.protocol === "wss:" && endpoint.username === "" && endpoint.password === "" && endpoint.search === "" && endpoint.hash === "" &&
    (endpoint.pathname === "/flowersec/v4/direct" || endpoint.pathname === "/flowersec/v4/tunnel") && origin.origin === d.applicationOrigin && origin.origin === globalThis.location.origin);
  return Object.freeze({ deployment: Object.freeze({ deploymentID: d.deploymentID, revision: d.revision, endpoint: d.endpoint, applicationOrigin: d.applicationOrigin,
    routeDigest: new Uint8Array(d.routeDigest), notBeforeMS: d.notBeforeMS, notAfterMS: d.notAfterMS, terminatorProfile: d.terminatorProfile, evidenceReference: d.evidenceReference }),
    queueMessages: options.queueMessages, sendBufferBytes: options.sendBufferBytes, runtimeBytes: options.runtimeBytes, providerRuntimeBytes: options.providerRuntimeBytes });
}

/** Internal queue/deadline contract shared by network and dedicated local
 * adapters. Each adapter separately validates its signed access class. */
export type BrowserWebSocketOptions = Pick<V4BrowserWSSOptions, "queueMessages" | "sendBufferBytes" | "runtimeBytes" | "providerRuntimeBytes"> & {
  readonly deployment: Pick<V4BrowserWSSDeployment, "endpoint" | "applicationOrigin" | "notBeforeMS" | "notAfterMS">;
};

/** One original browser WebSocket. Each message is one envelope. Browser
 * internal allocation before message delivery is an observed host boundary. */
export class BrowserWSSCarrier implements V4AuthenticatedTransport {
  readonly role = "client" as const; readonly mode = "message" as const;
  readonly #done: Promise<void>; #resolve!: () => void;
  #socket: WebSocket | undefined; #closed = false; #nativeEnded = false; #released = false;
  #started = false;
  #queue: Uint8Array[] = [];
  #read: { max: number; resolve: (value: Uint8Array | null) => void; reject: (error: unknown) => void; signal: AbortSignal | undefined; abort: () => void } | undefined;
  #output: { resolve: () => void; reject: (error: unknown) => void; timer: ReturnType<typeof setTimeout> | undefined; deadline: TrustedDeadline } | undefined;
  readonly #deadline: TrustedDeadline;
  constructor(private readonly environment: V4EnvironmentRuntime, private readonly dependency: EnvironmentDependency, private readonly options: BrowserWebSocketOptions,
    private readonly maximum: number, private readonly preparation: TrustedDeadline, private readonly subprotocol = "flowersec.direct.v4") {
    this.#done = new Promise(resolve => { this.#resolve = resolve; }); this.#deadline = new TrustedDeadline(environment.clock, options.deployment.notAfterMS);
    dependency.onClose(() => { void this.close(); });
  }
  authenticateHop(credentials: VerifiedRelayCredentials, signer: ReadyIdentitySigner, random: RandomFill, resources: CredentialResources, reference: ResourceReference,
    options?: OperationOptions, acceptedHello?: Uint8Array, prepared?: HopAuthenticationPreparation): Promise<void> {
    return authenticateEndpointHop(this, credentials, signer, random, resources, reference, this.preparation, options, acceptedHello, prepared);
  }
  checkPreparation(): void {
    this.dependency.check(); this.#deadline.check(); const now = this.environment.clock.sample().requireInterval();
    requireCredential(!this.#closed && now.lowerMS >= this.options.deployment.notBeforeMS && globalThis.location.origin === this.options.deployment.applicationOrigin &&
      this.#socket?.readyState === NativeWebSocket.OPEN && this.#socket.protocol === this.subprotocol && this.#socket.extensions === "", "credential_closed");
  }
  async prepare(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) throw new Error("canceled"); this.preparation.check(); this.dependency.check();
    let timer: ReturnType<typeof setTimeout> | undefined, failure: unknown;
    try {
      const socket = this.#socket = new NativeWebSocket(this.options.deployment.endpoint, this.subprotocol); socket.binaryType = "arraybuffer";
      socket.addEventListener("close", () => { this.#nativeEnded = true; void this.close(); this.#finish(); });
      socket.addEventListener("error", () => { failure ??= new Error("carrier_failed"); void this.close(); });
      socket.addEventListener("message", event => {
        try {
          this.checkPreparation(); requireCredential(this.#started && event.data instanceof ArrayBuffer && event.data.byteLength <= this.maximum && this.#queue.length < this.options.queueMessages);
          this.#queue.push(new Uint8Array(event.data)); this.#deliver();
        } catch { void this.close(); }
      });
      await new Promise<void>((resolve, reject) => {
        let done = false;
        const finish = (error?: unknown): void => { if (done) return; done = true; if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", abort);
          socket.removeEventListener("open", opened); socket.removeEventListener("close", closed); error === undefined ? resolve() : reject(error); };
        const abort = (): void => { failure = new Error("canceled"); void this.close(); finish(failure); };
        const opened = (): void => { try { this.preparation.check(); this.checkPreparation(); finish(); } catch (error) { failure = error; void this.close(); finish(error); } };
        const closed = (): void => finish(failure ?? new Error("carrier_closed"));
        const tick = (): void => { try { this.preparation.check(); this.#deadline.check(); timer = setTimeout(tick, timerChunk(this.preparation.remainingMS())); } catch (error) { failure = error; void this.close(); finish(error); } };
        socket.addEventListener("open", opened); socket.addEventListener("close", closed); signal?.addEventListener("abort", abort, { once: true }); tick(); if (signal?.aborted) abort();
      });
    } catch (error) { if (this.#socket === undefined) this.#nativeEnded = true; await this.close(); throw error; }
    finally { if (timer !== undefined) clearTimeout(timer); }
  }
  #deliver(): void {
    const w = this.#read; if (w === undefined) return; const bytes = this.#queue.shift(); if (!this.#closed && bytes === undefined) return;
    this.#read = undefined; w.signal?.removeEventListener("abort", w.abort);
    if (this.#closed) w.resolve(null);
    else if (bytes!.length > w.max) { bytes!.fill(0); w.reject(new Error("frame_boundary")); void this.close(); } else w.resolve(bytes!);
  }
  read(maxBytes: number, options?: OperationOptions): Promise<Uint8Array | null> {
    if (this.#closed) return Promise.resolve(null);
    try { this.checkPreparation(); requireCredential(Number.isSafeInteger(maxBytes) && maxBytes > 0 && this.#read === undefined); if (options?.signal?.aborted) throw new Error("canceled"); }
    catch (error) { return Promise.reject(error); }
    return new Promise((resolve, reject) => {
      const abort = (): void => { if (this.#read?.abort !== abort) return; this.#read = undefined; options?.signal?.removeEventListener("abort", abort); reject(new Error("canceled")); };
      this.#read = { max: maxBytes, resolve, reject, signal: options?.signal, abort }; options?.signal?.addEventListener("abort", abort, { once: true }); this.#deliver();
    });
  }
  submit(data: Uint8Array, admitted: () => void, beforeSubmit?: () => void): { completion: Promise<void> } | undefined {
    try { this.checkPreparation(); } catch { return undefined; }
    const socket = this.#socket!;
    if (this.#output !== undefined || socket.bufferedAmount !== 0 || data.length > this.maximum || data.length > this.options.sendBufferBytes) return undefined;
    let deadline: TrustedDeadline; try { deadline = new TrustedDeadline(this.environment.clock, this.#deadline.cap); } catch { return undefined; }
    let resolve!: () => void, reject!: (error: unknown) => void; const completion = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    // WebSocket.send copies the message before returning. Its actual native
    // queued output stays charged until bufferedAmount is zero or close fires.
    beforeSubmit?.();
    try { socket.send(data as Uint8Array<ArrayBuffer>); this.#started = true; } catch { return undefined; }
    this.#output = { resolve, reject, timer: undefined, deadline };
    try { admitted(); } catch { void this.close(); }
    this.#pollOutput(); return { completion };
  }
  #pollOutput(): void {
    const output = this.#output; if (output === undefined) return;
    if (this.#nativeEnded || !this.#closed && this.#socket!.bufferedAmount === 0) {
      this.#output = undefined; if (output.timer !== undefined) clearTimeout(output.timer); this.#closed ? output.reject(new Error("carrier_closed")) : output.resolve(); this.#finish(); return;
    }
    if (!this.#closed) { try { output.deadline.check(); } catch { void this.close(); } }
    output.timer = setTimeout(() => this.#pollOutput(), 10);
  }
  async write(data: Uint8Array, options?: OperationOptions): Promise<number> {
    if (options?.signal?.aborted) throw new Error("canceled"); const output = this.submit(data, () => undefined); if (output === undefined) throw new Error("carrier_closed"); await output.completion; return data.length;
  }
  close(): Promise<void> {
    if (!this.#closed) { this.#closed = true; for (const bytes of this.#queue) bytes.fill(0); this.#queue = []; this.#deliver();
      if (this.#socket !== undefined && this.#socket.readyState !== NativeWebSocket.CLOSED) this.#socket.close();
      else this.#nativeEnded = true;
    }
    if (this.#nativeEnded) this.#pollOutput(); this.#finish(); return this.#done;
  }
  #finish(): void { if (!this.#released && this.#closed && this.#nativeEnded && this.#output === undefined) { this.#released = true; this.dependency.release(); this.#resolve(); } }
  waitTermination(): Promise<void> { return this.#done; }
}

export function browserWSSAdmissionCosts(maxFrame: number, options: BrowserWebSocketOptions, runtimeBytes: bigint): readonly (readonly [string, ResourceVector])[] {
  const maximum = Math.max(maxFrame, 65536) + 8;
  requireCredential(maximum <= options.sendBufferBytes, "configuration_capacity");
  return [["browser_wss", new ResourceVector([BigInt(maximum * (options.queueMessages + 2)) + options.runtimeBytes, options.providerRuntimeBytes, 0n,
    BigInt(options.queueMessages + 8), 2n, 2n, 3n, 1n, 0n, 0n, 0n])], ["browser_wss_policy", credentialWorkCharge(16384, runtimeBytes)]];
}

export async function prepareBrowserWSS(environment: V4EnvironmentRuntime, fields: ClientPreparationFields, options: V4BrowserWSSOptions, signal?: AbortSignal, admission?: ClientSessionAdmission): Promise<BrowserWSSCarrier> {
  const d = options.deployment, now = environment.clock.sample().requireInterval();
  requireCredential(equalCredential(fields.routeDigest, d.routeDigest) && now.lowerMS >= d.notBeforeMS && now.upperMS < d.notAfterMS && globalThis.location.origin === d.applicationOrigin);
  const maximum = Math.max(fields.maxFrame, 65536) + 8;
  requireCredential(maximum <= options.sendBufferBytes, "configuration_capacity");
  const costs = browserWSSAdmissionCosts(fields.maxFrame, options, environment.resources.runtimeBytes);
  const reference = admission?.take([costs[0]!])[0];
  let dependency: EnvironmentDependency;
  try { dependency = environment.admitDependency("browser_wss", costs[0]![1], reference, admission); } finally { reference?.release(); }
  let carrier: BrowserWSSCarrier | undefined, work: CredentialWork | undefined;
  try {
    const r = environment.resources, ref = environment.reserveConnectionWork("browser_wss_policy", costs[1]![1], admission);
    try { work = new CredentialWork(r, 16384, ref); } finally { ref.release(); }
    const route = work.parse(fields.route, "Route", 16384);
    try {
      const leg = route.field(fields.pathKind === 0 ? "direct_leg" : "client_leg"), tls = route.field("tls_policy", leg, "Leg"), origin = route.field("origin_policy", leg, "Leg"), url = new URL(d.endpoint);
      requireCredential(route.uint("path_kind") === BigInt(fields.pathKind) && route.uint("access_class", leg, "Leg") === 0n && route.uint("carrier", leg, "Leg") === 1n &&
        route.uint("dialer_role", leg, "Leg") === 0n && route.uint("listener_role", leg, "Leg") === (fields.pathKind === 0 ? 1n : 2n) && route.text("host", leg, "Leg") === url.hostname.replace(/^\[|\]$/gu, "") &&
        route.uint("port", leg, "Leg") === BigInt(url.port === "" ? 443 : Number(url.port)) && route.text("path", leg, "Leg") === url.pathname && route.text("alpn", leg, "Leg") === "http/1.1" &&
        route.text("subprotocol", leg, "Leg") === (fields.pathKind === 0 ? "flowersec.direct.v4" : "flowersec.tunnel.v4") && [...route.items("origins", origin, "OriginPolicy")].some(node => route.doc.text(node) === d.applicationOrigin));
      // A standard browser cannot inspect peer DER or the actual TLS version.
      requireCredential(route.uint("mode", tls, "TLSPolicy") === 0n && !route.doc.boolean(route.field("require_consumer_tls13_verification", tls, "TLSPolicy")), "credential_untrusted");
    } finally { route.close(); work.close(); work = undefined; }
    carrier = new BrowserWSSCarrier(environment, dependency, options, maximum, fields.preparationDeadline, fields.pathKind === 0 ? "flowersec.direct.v4" : "flowersec.tunnel.v4"); await carrier.prepare(signal); return carrier;
  } catch (error) { work?.close(); if (carrier !== undefined) await carrier.close(); else dependency.release(); throw error; }
}
