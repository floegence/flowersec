import type { IncomingMessage } from "node:http";
import type { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import { createHash, constants, type X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import { connect as tlsConnect, checkServerIdentity, type TLSSocket, type ConnectionOptions } from "node:tls";
import WebSocket from "ws";
import type { OperationOptions } from "../public/contract.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import type { V4EnvironmentRuntime, EnvironmentDependency } from "../v4/runtime/environment.js";
import { CredentialWork, credentialWorkCharge, requireCredential, equalCredential } from "../v4/runtime/credentialSupport.js";
import type { ClientPreparationFields } from "../v4/runtime/credentialVerifier.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { timerChunk } from "../v4/runtime/deadline.js";
import type { TimeInterval } from "../v4/runtime/timeArithmetic.js";

export interface V4NodeWSSOptions {
  /** One numeric address, captured before preparation. No resolver or retry. */
  readonly remoteAddress: string;
  readonly origin?: string;
  /** Immutable trust anchors for CA mode; pin mode uses only signed leaf DER. */
  readonly ca?: readonly (string | Uint8Array)[];
  readonly queueMessages: number;
  readonly runtimeBytes: bigint;
  readonly nativeBytes: bigint;
  readonly prepareBytes: number;
}
export interface AcceptedWSSEndpoint { readonly host: string; readonly port: number; }
interface Pin { digest: Uint8Array; from: bigint; until: bigint }
interface Policy { host: string; port: number; path: string; subprotocol: string; origin: string; mode: bigint; pins: Pin[] }
function validity(certificate: X509Certificate, now: TimeInterval): { from: bigint; until: bigint } {
  const a = certificate.validFromDate.getTime(), b = certificate.validToDate.getTime();
  requireCredential(Number.isSafeInteger(a) && Number.isSafeInteger(b) && a >= 0 && b > a);
  const from = BigInt(a), until = BigInt(b); requireCredential(now.lowerMS >= from && now.upperMS < until, "credential_expired"); return { from, until };
}
interface DER { tag: number; body: Uint8Array; next: number }
function der(bytes: Uint8Array, at: number, tag?: number): DER {
  requireCredential(at + 2 <= bytes.length); const actual = bytes[at++]!; if (tag !== undefined) requireCredential(actual === tag);
  let length = bytes[at++]!;
  if (length & 128) {
    const count = length & 127; requireCredential(count > 0 && count <= 4 && at + count <= bytes.length && bytes[at] !== 0); length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[at++]!; requireCredential(length >= 128);
  }
  requireCredential(at + length <= bytes.length); return { tag: actual, body: bytes.subarray(at, at + length), next: at + length };
}
function hex(bytes: Uint8Array): string { return Buffer.from(bytes).toString("hex"); }
function pinProfile(certificate: X509Certificate, now: TimeInterval): { from: bigint; until: bigint } {
  const window = validity(certificate, now), key = certificate.publicKey;
  requireCredential(window.until - window.from <= 1209600000n && key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1");
  const outer = der(certificate.raw, 0, 0x30); requireCredential(outer.next === certificate.raw.length);
  const tbs = der(outer.body, 0, 0x30), version = der(tbs.body, 0, 0xa0), value = der(version.body, 0, 2);
  requireCredential(value.next === version.body.length && value.body.length === 1 && value.body[0] === 2);
  let cursor = version.next;
  // serial, signature, issuer, validity, subject and SubjectPublicKeyInfo.
  for (let n = 0; n < 6; n++) cursor = der(tbs.body, cursor).next;
  const seen = new Set<string>();
  while (cursor < tbs.body.length) {
    const item = der(tbs.body, cursor); cursor = item.next;
    if (item.tag !== 0xa3) { requireCredential(item.tag === 0x81 || item.tag === 0x82); continue; }
    const extensions = der(item.body, 0, 0x30); requireCredential(extensions.next === item.body.length);
    for (let at = 0; at < extensions.body.length;) {
      const ext = der(extensions.body, at, 0x30); at = ext.next;
      const oid = der(ext.body, 0, 6), name = hex(oid.body); requireCredential(!seen.has(name)); seen.add(name);
      let position = oid.next, critical = false;
      if (ext.body[position] === 1) { const flag = der(ext.body, position, 1); requireCredential(flag.body.length === 1 && flag.body[0] === 255); critical = true; position = flag.next; }
      const payload = der(ext.body, position, 4); requireCredential(payload.next === ext.body.length);
      if (name === "551d0f") {
        const usage = der(payload.body, 0, 3); requireCredential(usage.next === payload.body.length && usage.body.length >= 2 && usage.body[0]! <= 7 && (usage.body[1]! & 128) !== 0);
      } else if (name === "551d25") {
        const usage = der(payload.body, 0, 0x30); requireCredential(usage.next === payload.body.length); let server = false;
        for (let index = 0; index < usage.body.length;) { const purpose = der(usage.body, index, 6); index = purpose.next; server ||= ["2b06010505070301", "551d2500"].includes(hex(purpose.body)); }
        requireCredential(server);
      } else if (critical) {
        // Recognize only constraints interpreted by this pin profile. Other
        // critical extensions cannot be silently ignored by a pin callback.
        requireCredential(name === "551d13" || name === "551d11");
        const sequence = der(payload.body, 0, 0x30); requireCredential(sequence.next === payload.body.length);
      }
    }
  }
  return window;
}

/** One native WebSocket, with finite native/SDK queues and original send tails. */
export class NodeWSSCarrier implements V4AuthenticatedTransport {
  readonly mode = "message" as const;
  exportBinding(artifactDigest: Uint8Array): Uint8Array {
    this.checkPreparation();
    const socket = this.#socket;
    if (socket === undefined || socket.destroyed || socket.isSessionReused() || socket.getProtocol() !== "TLSv1.3" ||
      artifactDigest.length !== 32 || !artifactDigest.some(byte => byte !== 0)) throw new Error("required_guarantee_unavailable");
    // Node accepts the complete TLS label. This returns a new owned buffer;
    // the admission reservation retains and clears it before durable consume.
    const value = socket.exportKeyingMaterial(32, "EXPORTER-flowersec-v4", Buffer.from(artifactDigest));
    try { this.checkPreparation(); if (value.length !== 32) throw new Error("required_guarantee_unavailable"); return new Uint8Array(value); }
    finally { value.fill(0); }
  }
  readonly #done: Promise<void>;
  #resolve!: () => void;
  #socket: TLSSocket | undefined;
  #websocket: WebSocket | undefined;
  #socketEnded = true;
  #websocketEnded = true;
  #closing = false;
  #cleaned = false;
  #sending = false;
  #queue: Uint8Array[] = [];
  #read: { max: number; resolve: (value: Uint8Array | null) => void; reject: (reason: unknown) => void; signal: AbortSignal | undefined; abort: () => void } | undefined;
  #validity: { from: bigint; until: bigint } | undefined;
  #accepted: { host: string; port: number; origin: string; leaf: X509Certificate } | undefined;
  constructor(private readonly environment: V4EnvironmentRuntime, private readonly dependency: EnvironmentDependency,
    private readonly maximum: number, private readonly queueMessages: number, readonly role: "client" | "server" = "client") {
    this.#done = new Promise(resolve => { this.#resolve = resolve; }); dependency.onClose(() => { void this.close(); });
  }
  check(): void {
    this.dependency.check(); requireCredential(!this.#closing && this.#validity !== undefined, "credential_closed");
    const now = this.environment.clock.sample().requireInterval(); requireCredential(now.lowerMS >= this.#validity.from && now.upperMS < this.#validity.until, "credential_expired");
  }
  checkPreparation(): void { this.check(); }
  /** Called only by the controlled HTTPS listener, immediately after upgrade.
   * The accepted socket and native send tails keep the same lifecycle owner. */
  accept(websocket: WebSocket, request: IncomingMessage, endpoint: AcceptedWSSEndpoint): void {
    const socket = request.socket as TLSSocket;
    this.dependency.check(); requireCredential(this.role === "server" && this.#socket === undefined && this.#websocket === undefined, "credential_binding");
    this.#socket = socket; this.#socketEnded = socket.closed; this.#websocket = websocket; this.#websocketEnded = websocket.readyState === WebSocket.CLOSED;
    socket.on("error", () => { void this.close(); }); socket.once("close", () => { this.#socketEnded = true; void this.close(); this.#finish(); });
    websocket.on("error", () => { void this.close(); }); websocket.once("close", () => { this.#websocketEnded = true; void this.close(); this.#finish(); });
    try {
        requireCredential(
        socket.getProtocol() === "TLSv1.3" && socket.alpnProtocol === "http/1.1" && !socket.isSessionReused() && websocket.readyState === WebSocket.OPEN &&
        websocket.protocol === "flowersec.direct.v4" && websocket.extensions === "", "credential_binding");
      const leaf = socket.getX509Certificate(); requireCredential(leaf !== undefined && leaf.raw.length <= 65536);
      const host = endpoint.host, port = endpoint.port, expectedHost = `${isIP(host) === 6 ? `[${host}]` : host}${port === 443 ? "" : `:${port}`}`;
      requireCredential(typeof host === "string" && host.length > 0 && host.length <= 253 && Number.isSafeInteger(port) && port > 0 && port <= 65535 &&
        request.method === "GET" && request.httpVersion === "1.1" && request.url === "/flowersec/v4/direct" && request.headers.host === expectedHost &&
        request.headers["sec-websocket-protocol"] === "flowersec.direct.v4" && request.headers["sec-websocket-version"] === "13" &&
        request.headers["content-length"] === undefined && request.headers["transfer-encoding"] === undefined &&
        request.headers["expect"] === undefined && socket.localPort === port && (isIP(host) ? !socket.servername : socket.servername === host) &&
        (isIP(host) ? leaf.checkIP(host) === host : leaf.checkHost(host, { subject: "never" }) !== undefined), "credential_binding");
      const headerNames = new Set<string>();
      requireCredential(request.rawHeaders.length <= 128, "configuration_capacity");
      for (let index = 0; index < request.rawHeaders.length; index += 2) {
        const name = request.rawHeaders[index]!.toLowerCase(); requireCredential(!headerNames.has(name), "credential_binding"); headerNames.add(name);
      }
      const origin = request.headers.origin ?? ""; requireCredential(typeof origin === "string" && origin.length <= 2048);
      this.#accepted = { host, port, origin, leaf };
      this.#validity = validity(leaf, this.environment.clock.sample().requireInterval());
      websocket.on("ping", () => { void this.close(); }); websocket.on("pong", () => { void this.close(); });
      websocket.on("message", (data, binary) => {
        try {
          this.check(); requireCredential(binary && Buffer.isBuffer(data) && data.length <= this.maximum && this.#queue.length < this.queueMessages);
          this.#queue.push(new Uint8Array(data)); this.#deliver();
        } catch { void this.close(); }
      });
    } catch (error) { void this.close(); throw error; }
  }
  /** Compare the signed route with this original accepted TLS/HTTP endpoint.
   * No forwarded header or peer-selected authority can replace local facts. */
  checkAcceptedRoute(fields: ClientPreparationFields): void {
    this.check(); const actual = this.#accepted; requireCredential(this.role === "server" && actual !== undefined, "credential_binding");
    const ref = this.environment.reserveConnectionWork("accepted_wss_route", credentialWorkCharge(16384, this.environment.resources.runtimeBytes));
    let work: CredentialWork | undefined;
    try {
      work = new CredentialWork(this.environment.resources, 16384, ref); const route = work.parse(fields.route, "Route", 16384);
      try {
        const leg = route.field("direct_leg"), tls = route.field("tls_policy", leg, "Leg");
        requireCredential(route.uint("path_kind") === 0n && route.uint("access_class", leg, "Leg") === 0n && route.uint("carrier", leg, "Leg") === 1n &&
          route.uint("dialer_role", leg, "Leg") === 0n && route.uint("listener_role", leg, "Leg") === 1n && route.text("alpn", leg, "Leg") === "http/1.1" &&
          route.text("path", leg, "Leg") === "/flowersec/v4/direct" && route.text("subprotocol", leg, "Leg") === "flowersec.direct.v4" &&
          route.text("host", leg, "Leg") === actual.host && route.uint("port", leg, "Leg") === BigInt(actual.port));
        const origin = route.optional("origin_policy", leg, "Leg");
        if (origin < 0) requireCredential(actual.origin === "");
        else if (actual.origin === "") requireCredential(route.doc.boolean(route.field("allow_absent", origin, "OriginPolicy")));
        else requireCredential([...route.items("origins", origin, "OriginPolicy")].some(node => route.doc.text(node) === actual.origin));
        if (route.uint("mode", tls, "TLSPolicy") === 1n) {
          const now = this.environment.clock.sample().requireInterval(), window = pinProfile(actual.leaf, now), hash = createHash("sha256").update(actual.leaf.raw).digest();
          try {
            requireCredential([...route.items("pins", tls, "TLSPolicy")].some(pin => {
              const from = route.uint("not_before_ms", pin, "TLSPin"), until = route.uint("not_after_ms", pin, "TLSPin");
              return now.lowerMS >= from && now.upperMS < until && from >= window.from && until <= window.until && equalCredential(hash, route.bytes("leaf_der_sha256", pin, "TLSPin"));
            }));
          } finally { hash.fill(0); }
        }
      } finally { route.close(); }
      this.check();
    } finally { work?.close(); ref.release(); }
  }
  async prepare(fields: ClientPreparationFields, options: V4NodeWSSOptions, policy: Policy, signal?: AbortSignal): Promise<void> {
    this.dependency.check(); requireCredential(this.role === "client" && !this.#closing, "credential_closed");
    let failure: unknown, timer: ReturnType<typeof setTimeout> | undefined;
    const guard = (): void => { this.dependency.check(); if (failure !== undefined) throw failure; if (signal?.aborted || this.#closing) throw new Error("canceled"); fields.preparationDeadline.check(); };
    const stop = (error: unknown): void => { failure ??= error; void this.close(); };
    const abort = (): void => stop(new Error("canceled"));
    const tick = (): void => { try { guard(); timer = setTimeout(tick, timerChunk(fields.preparationDeadline.remainingMS())); } catch (error) { stop(error); } };
    signal?.addEventListener("abort", abort, { once: true }); tick();
    try {
      guard();
      const tlsOptions: ConnectionOptions & { highWaterMark: number; allowHalfOpen: boolean } = { host: options.remoteAddress, port: policy.port,
        minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], secureOptions: constants.SSL_OP_NO_TICKET,
        servername: isIP(policy.host) ? "" : policy.host, rejectUnauthorized: policy.mode === 0n,
        ...(policy.mode === 0n ? { ca: options.ca!.map(value => typeof value === "string" ? value : Buffer.from(value)) } : {}),
        checkServerIdentity: (_name, certificate) => checkServerIdentity(policy.host, certificate),
        highWaterMark: this.maximum, allowHalfOpen: false };
      const socket = this.#socket = tlsConnect(tlsOptions);
      this.#socketEnded = false;
      socket.on("error", error => stop(error)); socket.once("close", () => { this.#socketEnded = true; void this.close(); this.#finish(); });
      await new Promise<void>((resolve, reject) => {
        const finish = (error?: unknown): void => { socket.removeListener("secureConnect", secure); socket.removeListener("error", failed); socket.removeListener("close", closed); error === undefined ? resolve() : reject(error); };
        const secure = (): void => finish(), failed = (error: Error): void => finish(error), closed = (): void => finish(failure ?? new Error("carrier_closed"));
        socket.once("secureConnect", secure); socket.once("error", failed); socket.once("close", closed);
      });
      guard(); requireCredential(socket.getProtocol() === "TLSv1.3" && socket.alpnProtocol === "http/1.1" && socket.bytesRead <= options.prepareBytes);
      const now = this.environment.clock.sample().requireInterval(), leaf = socket.getPeerX509Certificate(); requireCredential(leaf !== undefined && leaf.raw.length <= 65536);
      if (policy.mode === 1n) {
        const actual = pinProfile(leaf, now), hash = createHash("sha256").update(leaf.raw).digest();
        const matched = policy.pins.find(pin => equalCredential(pin.digest, hash)); requireCredential(matched !== undefined && matched.from >= actual.from && matched.until <= actual.until && now.lowerMS >= matched.from && now.upperMS < matched.until);
        this.#validity = { from: matched.from, until: matched.until };
      } else {
        requireCredential(socket.authorized && leaf.subjectAltName !== undefined);
        requireCredential(isIP(policy.host) ? leaf.checkIP(policy.host) === policy.host : leaf.checkHost(policy.host, { subject: "never" }) !== undefined);
        let peer: X509Certificate | undefined = leaf, total = 0, count = 0, from = 0n, until = 0xffffffffffffffffn; const seen = new Set<string>();
        while (peer !== undefined) {
          const fingerprint = hex(createHash("sha256").update(peer.raw).digest()); if (seen.has(fingerprint)) break; seen.add(fingerprint);
          total += peer.raw.length; requireCredential(++count <= 16 && total <= options.prepareBytes);
          const times = validity(peer, now); if (times.from > from) from = times.from; if (times.until < until) until = times.until;
          peer = peer.issuerCertificate;
        }
        requireCredential(count > 0); this.#validity = { from, until };
      }
      guard();
      const host = isIP(policy.host) === 6 ? `[${policy.host}]` : policy.host, url = `wss://${host}:${policy.port}${policy.path}`;
      let connectionUsed = false;
      const configuration = { createConnection: () => { requireCredential(!connectionUsed); connectionUsed = true; guard(); return socket; },
        followRedirects: false, perMessageDeflate: false, autoPong: false, maxPayload: this.maximum,
        maxFragments: 128, maxBufferedChunks: 256, maxHeaderSize: 16384, handshakeTimeout: Math.min(30000, Number(fields.preparationDeadline.remainingMS())),
        ...(policy.origin === "" ? {} : { origin: policy.origin }) };
      const websocket = this.#websocket = new WebSocket(url, policy.subprotocol, configuration); this.#websocketEnded = false;
      websocket.on("error", error => stop(error)); websocket.once("close", () => { this.#websocketEnded = true; void this.close(); this.#finish(); });
      websocket.on("ping", () => stop(new Error("unexpected_native_control")));
      websocket.on("pong", () => stop(new Error("unexpected_native_control")));
      websocket.on("message", (data, binary) => {
        try {
          this.check(); requireCredential(binary && Buffer.isBuffer(data) && data.length <= this.maximum && this.#queue.length < this.queueMessages);
          const copy = new Uint8Array(data); this.#queue.push(copy); this.#deliver();
        } catch (error) { stop(error); }
      });
      await new Promise<void>((resolve, reject) => {
        const finish = (error?: unknown): void => { websocket.removeListener("open", opened); websocket.removeListener("error", failed); websocket.removeListener("close", closed); error === undefined ? resolve() : reject(error); };
        const opened = (): void => finish(), failed = (error: Error): void => finish(error), closed = (): void => finish(failure ?? new Error("carrier_closed"));
        websocket.once("open", opened); websocket.once("error", failed); websocket.once("close", closed);
      });
      guard(); requireCredential(websocket.protocol === policy.subprotocol && websocket.extensions === "" && socket.bytesRead <= options.prepareBytes); this.check();
    } catch (error) { await this.close(); throw error; }
    finally { if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", abort); }
  }
  #deliver(): void {
    const waiter = this.#read; if (waiter === undefined) return;
    if (this.#closing) { this.#read = undefined; waiter.signal?.removeEventListener("abort", waiter.abort); waiter.resolve(null); return; }
    const bytes = this.#queue.shift(); if (bytes === undefined) return;
    this.#read = undefined; waiter.signal?.removeEventListener("abort", waiter.abort);
    if (bytes.length > waiter.max) { bytes.fill(0); waiter.reject(new Error("frame_boundary")); void this.close(); } else waiter.resolve(bytes);
  }
  read(maxBytes: number, options?: OperationOptions): Promise<Uint8Array | null> {
    if (this.#closing) return Promise.resolve(null);
    try { this.check(); requireCredential(Number.isSafeInteger(maxBytes) && maxBytes > 0 && this.#read === undefined); if (options?.signal?.aborted) throw new Error("canceled"); }
    catch (error) { return Promise.reject(error); }
    return new Promise((resolve, reject) => {
      const abort = (): void => { if (this.#read?.abort !== abort) return; this.#read = undefined; options?.signal?.removeEventListener("abort", abort); reject(new Error("canceled")); };
      this.#read = { max: maxBytes, resolve, reject, signal: options?.signal, abort }; options?.signal?.addEventListener("abort", abort, { once: true }); this.#deliver();
    });
  }
  submit(data: Uint8Array, admitted: () => void): { completion: Promise<void> } | undefined {
    try { this.check(); } catch { return undefined; }
    const ws = this.#websocket; if (this.#sending || ws?.readyState !== WebSocket.OPEN || data.length > this.maximum || ws.bufferedAmount !== 0) return undefined;
    this.#sending = true;
    let resolve!: () => void, reject!: (error: unknown) => void; const completion = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    let entered = false, returned = false, callback = false, failure: Error | undefined;
    const finish = (): void => {
      if (!entered || !returned || !callback) return;
      this.#sending = false; if (failure !== undefined) { reject(failure); void this.close(); } else resolve(); this.#finish();
    };
    try {
      // ws.send synchronously accepts one original message into its finite
      // native sender. The callback, including failure, ends the byte borrow.
      ws.send(data, { binary: true, compress: false, fin: true }, error => { callback = true; failure = error ?? undefined; finish(); });
      entered = true; admitted(); returned = true; finish();
    } catch (error) {
      if (!entered) { this.#sending = false; void this.close(); this.#finish(); return undefined; }
      returned = true; failure = error instanceof Error ? error : new Error("carrier_failed"); finish(); void this.close();
    }
    return { completion };
  }
  async write(data: Uint8Array, options?: OperationOptions): Promise<number> {
    if (options?.signal?.aborted) throw new Error("canceled"); const result = this.submit(data, () => undefined); if (result === undefined) throw new Error("carrier_closed"); await result.completion; return data.length;
  }
  close(): Promise<void> {
    if (!this.#closing) { this.#closing = true; for (const bytes of this.#queue) bytes.fill(0); this.#queue = []; this.#deliver(); this.#websocket?.terminate(); this.#socket?.destroy(); }
    this.#finish(); return this.#done;
  }
  #finish(): void {
    if (this.#cleaned || !this.#closing || !this.#socketEnded || !this.#websocketEnded || this.#sending) return;
    this.#cleaned = true; this.#validity = undefined; this.#accepted = undefined; this.dependency.release(); this.#resolve();
  }
  waitTermination(): Promise<void> { return this.#done; }
}

export function nodeWSSAdmissionCosts(maxFrame: number, options: V4NodeWSSOptions, runtimeBytes: bigint): readonly (readonly [string, ResourceVector])[] {
  requireCredential(typeof runtimeBytes === "bigint" && runtimeBytes > 0n && runtimeBytes <= 0xffffffffffffffffn, "configuration_capacity");
  requireCredential(isIP(options.remoteAddress) !== 0 && Number.isSafeInteger(options.queueMessages) && options.queueMessages >= 1 && options.queueMessages <= 64 &&
    typeof options.runtimeBytes === "bigint" && options.runtimeBytes > 0n && options.runtimeBytes <= 0xffffffffffffffffn &&
    typeof options.nativeBytes === "bigint" && options.nativeBytes >= 1048576n && options.nativeBytes <= 0xffffffffffffffffn &&
    Number.isSafeInteger(options.prepareBytes) && options.prepareBytes >= 16384 && options.prepareBytes <= 262144, "configuration_capacity");
  const maximum = Math.max(maxFrame, 65536) + 8;
  requireCredential(options.nativeBytes >= BigInt(maximum * 2 + options.prepareBytes + 256 * 256 + 131072), "configuration_capacity");
  const charge = new ResourceVector([BigInt(maximum * (options.queueMessages + 3)) + options.runtimeBytes, options.nativeBytes, 0n, BigInt(options.queueMessages + 8), 4n, 4n, 2n, 1n, 0n, 0n, 0n]);
  return [["node_wss", charge], ["node_wss_policy", credentialWorkCharge(16384, runtimeBytes)]];
}

export async function prepareNodeWSS(environment: V4EnvironmentRuntime, fields: ClientPreparationFields, options: V4NodeWSSOptions, signal?: AbortSignal, admission?: ClientSessionAdmission): Promise<NodeWSSCarrier> {
  const maximum = Math.max(fields.maxFrame, 65536) + 8;
  if (fields.source === "preauthorized_pool") requireCredential(fields.preparationBytes >= options.prepareBytes && fields.preparationWork >= 1, "configuration_capacity");
  const costs = nodeWSSAdmissionCosts(fields.maxFrame, options, environment.resources.runtimeBytes), charge = costs[0]![1];
  const reference = admission?.take([costs[0]!])[0];
  let dependency: EnvironmentDependency;
  try { dependency = environment.admitDependency("node_wss", charge, reference, admission); } finally { reference?.release(); }
  let carrier: NodeWSSCarrier | undefined, work: CredentialWork | undefined;
  try {
    const resources = environment.resources, ref = environment.reserveConnectionWork("node_wss_policy", costs[1]![1], admission);
    try { work = new CredentialWork(resources, 16384, ref); } finally { ref.release(); }
    const route = work.parse(fields.route, "Route", 16384);
    let policy: Policy;
    try {
      const leg = route.field("direct_leg"), tls = route.field("tls_policy", leg, "Leg");
      requireCredential(route.uint("path_kind") === 0n && route.uint("access_class", leg, "Leg") === 0n && route.uint("carrier", leg, "Leg") === 1n &&
        route.uint("dialer_role", leg, "Leg") === 0n && route.uint("listener_role", leg, "Leg") === 1n && route.text("alpn", leg, "Leg") === "http/1.1" &&
        route.text("path", leg, "Leg") === "/flowersec/v4/direct" && route.text("subprotocol", leg, "Leg") === "flowersec.direct.v4");
      const host = route.text("host", leg, "Leg"), origin = options.origin ?? "", originNode = route.optional("origin_policy", leg, "Leg");
      requireCredential(!isIP(host) || host === options.remoteAddress);
      if (originNode < 0) requireCredential(origin === "");
      else if (origin === "") requireCredential(route.doc.boolean(route.field("allow_absent", originNode, "OriginPolicy")));
      else requireCredential([...route.items("origins", originNode, "OriginPolicy")].some(node => route.doc.text(node) === origin));
      const mode = route.uint("mode", tls, "TLSPolicy"), pins: Pin[] = [], now = environment.clock.sample().requireInterval();
      if (mode === 0n) requireCredential(options.ca !== undefined && options.ca.length > 0 && options.ca.length <= 64, "configuration_capacity");
      else for (const pin of route.items("pins", tls, "TLSPolicy")) {
        const from = route.uint("not_before_ms", pin, "TLSPin"), until = route.uint("not_after_ms", pin, "TLSPin");
        if (now.lowerMS >= from && now.upperMS < until) pins.push({ from, until, digest: route.bytes("leaf_der_sha256", pin, "TLSPin") });
      }
      requireCredential(mode === 0n || pins.length > 0, "credential_expired");
      policy = { host, port: Number(route.uint("port", leg, "Leg")), path: route.text("path", leg, "Leg"), subprotocol: route.text("subprotocol", leg, "Leg"), origin, mode, pins };
    } finally { route.close(); work.close(); work = undefined; }
    carrier = new NodeWSSCarrier(environment, dependency, maximum, options.queueMessages);
    await carrier.prepare(fields, options, policy, signal); return carrier;
  } catch (error) { work?.close(); if (carrier !== undefined) await carrier.close(); else dependency.release(); throw error; }
}
