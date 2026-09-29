import { constants, X509Certificate } from "node:crypto";
import { Agent, request as httpsRequest } from "node:https";
import type { ClientRequest, IncomingMessage } from "node:http";
import { isIP } from "node:net";
import { checkServerIdentity, connect, createSecureContext, type ConnectionOptions, type SecureContext, type TLSSocket } from "node:tls";
import type { V4TransportEnvironment } from "../v4/public.js";
import type { V4LiveAuthorizationConfig, V4LiveAuthorizationProvider } from "../v4/runtime/liveAuthorization.js";
import { bindLiveAuthorizationConfig } from "../v4/runtime/liveAuthorization.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { TrustedWindow, timerChunk } from "../v4/runtime/deadline.js";
import { encodeLiveAuthorizationRequest } from "../v4/runtime/liveAuthorizationWire.js";

export interface V4NodeLiveHTTPSOptions {
  /** Independently trusted control origin; requests append /live/authorize. */
  readonly baseURL: string;
  /** Host-resolved numeric address for that origin; no resolver is invoked. */
  readonly remoteAddress: string;
  readonly authority: string;
  readonly tenant: string;
  readonly audience: string;
  readonly ca: readonly (string | Uint8Array)[];
  /** PEM client chain and private key for mandatory independent mutual TLS. */
  readonly clientCertificate: string | Uint8Array;
  readonly clientPrivateKey: Uint8Array;
  readonly maxConcurrentRequests: number;
  readonly timeoutMS: bigint;
  readonly headerBytes: number;
  readonly handshakeBytes: number;
  readonly runtimeBytes: bigint;
  readonly providerBytes: bigint;
}

function requireControl(condition: unknown, code = "control_configuration"): asserts condition {
  if (!condition) throw new Error(code);
}
function byteSize(value: string | Uint8Array): number {
  requireControl(typeof value === "string" || value instanceof Uint8Array);
  return typeof value === "string" ? Buffer.byteLength(value) : value.byteLength;
}
function certificateInterval(certificate: X509Certificate): { from: bigint; until: bigint } {
  const from = certificate.validFromDate.getTime(), until = certificate.validToDate.getTime();
  requireControl(Number.isSafeInteger(from) && from >= 0 && Number.isSafeInteger(until) && until > from, "control_tls_invalid");
  return { from: BigInt(from), until: BigInt(until) };
}
function responseSize(response: IncomingMessage, maximum: number): number {
  requireControl(response.httpVersion === "1.1" && response.statusCode === 200 && response.rawHeaders.length <= 512, "control_response_invalid");
  const fields = new Map<string, string>();
  for (let index = 0; index < response.rawHeaders.length; index += 2) {
    const name = response.rawHeaders[index]!.toLowerCase(), value = response.rawHeaders[index + 1]!;
    requireControl(!fields.has(name), "control_response_invalid"); fields.set(name, value);
  }
  const length = fields.get("content-length");
  requireControl(fields.get("content-type") === "application/cbor" && !fields.has("content-encoding") && !fields.has("transfer-encoding") &&
    !fields.has("trailer") && length !== undefined && /^[1-9][0-9]{0,9}$/u.test(length), "control_response_invalid");
  const size = Number(length); requireControl(size <= maximum, "control_response_invalid"); return size;
}

/** Creates an Environment-owned, bounded control transport. A request is sent
 * only after actual TLS 1.3, hostname/CA, certificate-time and client-identity
 * checks. Success is still untrusted bytes until the original credential owner
 * verifies the signed ActivationAuthorization against its selected winner. */
export function createV4NodeLiveHTTPS(environment: V4TransportEnvironment, options: V4NodeLiveHTTPSOptions): V4LiveAuthorizationConfig {
  const owner = originalEnvironment(environment);
  const input = options.baseURL;
  requireControl(typeof input === "string" && input.length > 0 && input.length <= 2048 && !/[\s%\\?#]/u.test(input));
  let url: URL;
  try { url = new URL(input); } catch { throw new Error("control_configuration"); }
  const host = url.hostname.replace(/^\[|\]$/gu, ""), remoteAddress = options.remoteAddress;
  requireControl(url.protocol === "https:" && url.username === "" && url.password === "" && url.search === "" && url.hash === "" &&
    host.length > 0 && isIP(remoteAddress) !== 0 && (!isIP(host) || host === remoteAddress) &&
    input.replace(/\/$/u, "") === url.href.replace(/\/$/u, ""));
  const authority = options.authority, tenant = options.tenant, audience = options.audience, identifier = /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u;
  requireControl(identifier.test(authority) && identifier.test(tenant) && identifier.test(audience));
  const maxConcurrentRequests = options.maxConcurrentRequests, timeoutMS = options.timeoutMS, headerBytes = options.headerBytes,
    handshakeBytes = options.handshakeBytes, runtimeBytes = options.runtimeBytes, providerBytes = options.providerBytes;
  requireControl(Number.isSafeInteger(maxConcurrentRequests) && maxConcurrentRequests >= 1 && maxConcurrentRequests <= 64 &&
    typeof timeoutMS === "bigint" && timeoutMS > owner.clock.profile.rate.elapsed(0n).upperMS && timeoutMS <= 90000n &&
    Number.isSafeInteger(headerBytes) && headerBytes >= 1024 && headerBytes <= 65536 && Number.isSafeInteger(handshakeBytes) && handshakeBytes >= 16384 && handshakeBytes <= 262144 &&
    typeof runtimeBytes === "bigint" && runtimeBytes > 0n && typeof providerBytes === "bigint" && providerBytes >= 1048576n + BigInt(64 * headerBytes + handshakeBytes));
  requireControl(Array.isArray(options.ca) && options.ca.length >= 1 && options.ca.length <= 64 && options.clientPrivateKey instanceof Uint8Array);
  const caBytes = options.ca.reduce((total, value) => total + byteSize(value), 0), certBytes = byteSize(options.clientCertificate), keyBytes = byteSize(options.clientPrivateKey);
  requireControl(caBytes > 0 && caBytes <= 1048576 && certBytes > 0 && certBytes <= 262144 && keyBytes > 0 && keyBytes <= 65536);
  const dependency = owner.admitDependency("node_live_https", new ResourceVector([BigInt(4 * (caBytes + certBytes + keyBytes) + 16384) + runtimeBytes,
    BigInt(4 * (caBytes + certBytes + keyBytes)) + providerBytes, 0n, 8n, 1n, 0n, 0n, 0n, 0n, 0n, 1n]));
  const active = new Set<AbortController>();
  let context: SecureContext | undefined, closed = false;
  const cleanup = (): void => { if (closed && active.size === 0) { context = undefined; dependency.release(); } };
  dependency.onClose(() => { closed = true; for (const controller of active) controller.abort(); cleanup(); });
  let clientWindow: { from: bigint; until: bigint };
  try {
    const key = Buffer.from(options.clientPrivateKey), cert = Buffer.from(options.clientCertificate), ca = options.ca.map(value => Buffer.from(value));
    try {
      clientWindow = certificateInterval(new X509Certificate(cert));
      context = createSecureContext({ ca, cert, key, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", secureOptions: constants.SSL_OP_NO_TICKET });
    } finally { key.fill(0); cert.fill(0); for (const value of ca) value.fill(0); }
    dependency.check();
  } catch { dependency.close(); throw new Error("control_configuration"); }
  const port = Number(url.port || "443"), path = url.pathname.replace(/\/$/u, "") + "/live/authorize", hostHeader = url.host;
  const charge = new ResourceVector([BigInt(headerBytes * 4 + 32768) + runtimeBytes, providerBytes, 0n, 16n, 2n, 3n, 1n, 1n, 1n, 0n, 2n]);
  const requestAuthorization: V4LiveAuthorizationProvider = async (request, destination, call) => {
    dependency.check(); call.check();
    requireControl(!closed && context !== undefined && !call.signal.aborted, "closed");
    requireControl(request.authority === authority && request.tenant === tenant && request.audience === audience, "control_request_binding");
    requireControl(destination instanceof Uint8Array && destination.byteLength >= 1 && destination.byteLength <= 4096, "control_response_capacity");
    requireControl(active.size < maxConcurrentRequests, "resource_exhausted");
    const resources = owner.resources, reservation = resources.root.reserve({ owner: { ...resources.owner, kind: "node_live_https_request" }, accounts: resources.accounts, charge });
    const controller = new AbortController(); active.add(controller);
    let socket: TLSSocket | undefined, agent: Agent | undefined, http: ClientRequest | undefined, response: IncomingMessage | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined, body: Uint8Array | undefined, success = false, responseComplete = false;
    let socketDone = Promise.resolve(), requestDone = Promise.resolve(), responseDone = Promise.resolve(), writeDone = Promise.resolve();
    let failed: Error | undefined, rejectPending: ((error: Error) => void) | undefined;
    const stop = (code: string): void => {
      failed ??= new Error(code); rejectPending?.(failed); http?.destroy(); response?.destroy(); socket?.destroy(); agent?.destroy();
    };
    const abort = (): void => { controller.abort(); }, aborted = (): void => stop("canceled");
    call.signal.addEventListener("abort", abort, { once: true }); controller.signal.addEventListener("abort", aborted, { once: true });
    try {
      const window = new TrustedWindow(owner.clock, timeoutMS);
      let serverWindow: { from: bigint; until: bigint } | undefined;
      const guard = (): void => {
        if (failed !== undefined) throw failed;
        dependency.check(); reservation.check(); call.check(); window.check();
        requireControl(!closed && !controller.signal.aborted && !call.signal.aborted, "canceled");
        const time = owner.clock.sample().requireInterval();
        for (const validity of [clientWindow, serverWindow]) if (validity !== undefined) requireControl(time.lowerMS >= validity.from && time.upperMS < validity.until, "control_tls_expired");
      };
      const tick = (): void => {
        try { guard(); timer = setTimeout(tick, timerChunk(window.remainingMS())); }
        catch { stop("control_deadline"); }
      };
      tick(); guard();
      body = new Uint8Array(1024); const encoded = encodeLiveAuthorizationRequest(request, body);
      const tlsOptions: ConnectionOptions & { highWaterMark: number; allowHalfOpen: boolean } = { host: remoteAddress, port, secureContext: context, minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
        servername: isIP(host) ? "" : host, rejectUnauthorized: true, ALPNProtocols: ["http/1.1"],
        checkServerIdentity: (_name, certificate) => checkServerIdentity(host, certificate), highWaterMark: 16384, allowHalfOpen: false };
      socket = connect(tlsOptions);
      const connection = socket;
      socketDone = new Promise(resolve => connection.once("close", () => { if (!responseComplete) stop("control_closed"); resolve(); }));
      connection.on("error", () => stop("control_transport_failed"));
      await new Promise<void>((resolve, reject) => { rejectPending = reject; connection.once("secureConnect", resolve); });
      rejectPending = undefined; guard();
      requireControl(connection.authorized && connection.getProtocol() === "TLSv1.3" && !connection.isSessionReused() &&
        (connection.alpnProtocol === "http/1.1" || connection.alpnProtocol === false) && connection.bytesRead <= handshakeBytes, "control_tls_invalid");
      const leaf = connection.getPeerX509Certificate(), local = connection.getX509Certificate();
      requireControl(leaf !== undefined && local !== undefined && local.raw.length > 0 && leaf.subjectAltName !== undefined, "control_tls_invalid");
      requireControl(isIP(host) ? leaf.checkIP(host) === host : leaf.checkHost(host, { subject: "never" }) !== undefined, "control_tls_invalid");
      const seen = new Set<string>(); let peer: X509Certificate | undefined = leaf, total = 0, from = 0n, until = 0xffffffffffffffffn;
      while (peer !== undefined) {
        if (seen.has(peer.fingerprint256)) break; seen.add(peer.fingerprint256);
        total += peer.raw.length; requireControl(seen.size <= 16 && total <= handshakeBytes, "control_tls_invalid");
        const validity = certificateInterval(peer); if (validity.from > from) from = validity.from; if (validity.until < until) until = validity.until;
        peer = peer.issuerCertificate;
      }
      serverWindow = { from, until }; guard();
      agent = new Agent({ keepAlive: false, maxSockets: 1, maxTotalSockets: 1, maxFreeSockets: 0, maxCachedSessions: 0, proxyEnv: {} });
      let connectionUsed = false;
      agent.createConnection = () => { guard(); requireControl(!connectionUsed, "control_transport_failed"); connectionUsed = true; return connection; };
      const completed = new Promise<number>((resolve, reject) => {
        rejectPending = reject;
        guard();
        http = httpsRequest({ hostname: host, port, path, method: "POST", agent, maxHeaderSize: headerBytes, insecureHTTPParser: false,
          joinDuplicateHeaders: true, headers: { Host: hostHeader, Accept: "application/cbor", "Content-Type": "application/cbor",
            "Content-Length": String(encoded.length), "Cache-Control": "no-store", Connection: "close" } });
        const outgoing = http;
        requestDone = new Promise(done => outgoing.once("close", () => { if (response === undefined || !response.complete) stop("control_closed"); done(); }));
        outgoing.maxHeadersCount = 256;
        outgoing.on("error", () => stop("control_transport_failed"));
        outgoing.on("information", () => stop("control_response_invalid"));
        outgoing.on("upgrade", (_reply, upgraded) => { upgraded.destroy(); stop("control_response_invalid"); });
        outgoing.once("response", incoming => {
          response = incoming;
          responseDone = new Promise(done => incoming.once("close", done));
          incoming.on("error", () => stop("control_transport_failed"));
          incoming.once("aborted", () => stop("control_response_invalid"));
          try {
            guard(); const size = responseSize(incoming, destination.length); let received = 0;
            incoming.on("data", (chunk: Buffer) => {
              try { guard(); requireControl(Buffer.isBuffer(chunk) && chunk.length <= size - received, "control_response_invalid"); destination.set(chunk, received); received += chunk.length; }
              catch { stop("control_response_invalid"); }
            });
            incoming.once("end", () => {
              try { guard(); requireControl(incoming.complete && received === size && incoming.rawTrailers.length === 0, "control_response_invalid"); responseComplete = true; resolve(received); }
              catch { stop("control_response_invalid"); }
            });
          } catch { stop("control_response_invalid"); }
        });
        guard();
        writeDone = new Promise(done => {
          try {
            outgoing.write(encoded, error => { if (error !== null && error !== undefined) stop("control_transport_failed"); done(); });
          } catch { done(); stop("control_transport_failed"); }
        });
        outgoing.end();
      });
      const count = await completed; rejectPending = undefined;
      await writeDone; guard(); success = true; return count;
    } catch { throw new Error(call.signal.aborted || controller.signal.aborted ? "canceled" : "live_authorization_failed"); }
    finally {
      if (timer !== undefined) clearTimeout(timer);
      call.signal.removeEventListener("abort", abort); controller.signal.removeEventListener("abort", aborted);
      rejectPending = undefined; http?.destroy(); response?.destroy(); socket?.destroy(); agent?.destroy();
      // An aborted await is not native cleanup. Retain both byte buffers and
      // the original reservation through real write/request/socket callbacks.
      await Promise.all([writeDone, requestDone, responseDone, socketDone]);
      body?.fill(0); if (!success) destination.fill(0);
      reservation.release(); active.delete(controller); cleanup();
    }
  };
  return bindLiveAuthorizationConfig(owner, Object.freeze({ requestAuthorization, maxConcurrentRequests, runtimeBytes, providerBytes }));
}
