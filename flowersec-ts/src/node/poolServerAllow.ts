import { constants } from "node:crypto";
import { createServer, type Server } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { isIP, type Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency } from "../v4/runtime/environment.js";
import { CBORDecoder, cborDecoderCharge } from "../v4/runtime/cbor.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { TrustedWindow } from "../v4/runtime/deadline.js";
import { equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { capturePoolServerAllowConfiguration, clearPoolServerAllowConfiguration, poolServerAllowConfigurationCharge, encodeTunnelServerAllow, type PoolServerAllowPublication, type PoolServerAllowConfiguration, type PoolServerAllowRecipient, type TunnelServerAllowRequest } from "../v4/runtime/poolServerAllow.js";
import { callRegisteredRelayControl, listenRegisteredControlServer, registeredControlTLSText } from "./registeredTunnelControl.js";

export interface NodePoolServerAllowOptions {
  readonly endpoint: string;
  readonly tls: Readonly<{ certificatePEM: string; privateKeyPEM: string; trustPEM: string }>;
  readonly workMS: bigint;
}
export interface NodePoolServerAllowReceiverOptions extends NodePoolServerAllowOptions {
  readonly clientCertificateDER: Uint8Array;
}
export interface PoolServerAllowBinding { readonly endpoint: string; readonly recipient: string; readonly incarnation: string; }
function captureOptions(input: NodePoolServerAllowOptions): NodePoolServerAllowOptions {
  const endpoint = new URL(input.endpoint), host = endpoint.hostname.replace(/^\[|\]$/gu, "");
  requireCredential(endpoint.protocol === "https:" && endpoint.pathname === "/tunnel/server-allow" && endpoint.search === "" && endpoint.hash === "" &&
    endpoint.username === "" && endpoint.password === "" && isIP(host) !== 0 && endpoint.port !== "" &&
    typeof input.workMS === "bigint" && input.workMS > 0n && input.workMS <= 2000n, "configuration_capacity");
  return Object.freeze({ endpoint: endpoint.href, workMS: input.workMS, tls: Object.freeze({ certificatePEM: registeredControlTLSText(input.tls.certificatePEM),
    privateKeyPEM: registeredControlTLSText(input.tls.privateKeyPEM), trustPEM: registeredControlTLSText(input.tls.trustPEM) }) });
}
/** One installed authenticated control adapter. It publishes only when called
 * by the original Connect success continuation and joins physical socket exit. */
export function createNodePoolServerAllow(environment: V4TransportEnvironment, options: NodePoolServerAllowOptions,
  recipients: readonly PoolServerAllowRecipient[]): PoolServerAllowConfiguration & { close(): Promise<void> } {
  const runtime = originalEnvironment(environment), installed = captureOptions(options);
  const input: PoolServerAllowConfiguration = { recipients, prepare: () => { throw new Error("owner_unavailable"); } };
  const dependency = runtime.admitDependency("pool_server_allow_transport", new ResourceVector([8388608n + runtime.resources.runtimeBytes, 4194304n, 0n, 32n, 2n, 2n, 0n, 0n, 0n, 0n, 0n]).add(poolServerAllowConfigurationCharge(input)));
  let captured: PoolServerAllowConfiguration | undefined, closing: Promise<void> | undefined, reserved = false;
  let slotDone: Promise<void> | undefined, releaseSlot: (() => void) | undefined;
  const endpoint = new URL(installed.endpoint);
  const state = { reference: dependency.reference, abort: new AbortController(), closed: false, busy: false, pending: undefined as Promise<void> | undefined,
    deployment: { relayControl: { endpoint: endpoint.origin + "/", authority: "pool-server-allow", tls: installed.tls, workMS: installed.workMS } } };
  const close = (): Promise<void> => {
    state.closed = true; state.abort.abort(); releaseSlot?.();
    return closing ??= (async () => { await slotDone; await state.pending; clearPoolServerAllowConfiguration(captured); dependency.release(); })();
  };
  try {
    captured = capturePoolServerAllowConfiguration(input); dependency.onClose(() => { void close(); });
    return Object.freeze({ recipients: captured.recipients, close, prepare: (request: TunnelServerAllowRequest, grant: Uint8Array) => {
      dependency.check(); requireCredential(!state.closed && !state.busy && !reserved, "credential_closed");
      const original = captured!.recipients.find(item => item.candidateIndex === request.candidateIndex);
      requireCredential(original !== undefined && equalCredential(original.recipient, request.recipient) && equalCredential(original.incarnation, request.incarnation) && equalCredential(original.grant, grant), "credential_binding");
      const custody = dependency.reference.borrow();
      let allocated: Uint8Array | undefined, encoded: Uint8Array;
      try { allocated = new Uint8Array(66560); encoded = encodeTunnelServerAllow(request, grant, allocated); }
      catch (error) { allocated?.fill(0); custody.release(); throw error; }
      const backing = allocated!;
      reserved = true; let entered = false, released = false, physical = false;
      let resolveSlot!: () => void; slotDone = new Promise(resolve => { resolveSlot = resolve; });
      const release = (): void => { if (released || physical) return; released = true; backing.fill(0); custody.release(); reserved = false; releaseSlot = undefined; slotDone = undefined; resolveSlot(); };
      releaseSlot = release;
      return Object.freeze({ close: release, publish: async (operation: Parameters<PoolServerAllowPublication["publish"]>[0]): Promise<void> => {
        dependency.check(); operation.check(); requireCredential(!state.closed && !entered && !released && reserved, "credential_closed"); entered = true; physical = true;
        try { await callRegisteredRelayControl(state, "/tunnel/server-allow", encoded, operation, custody); }
        finally { physical = false; release(); }
      } });
    } });
  } catch (error) { clearPoolServerAllowConfiguration(captured); dependency.release(); throw error; }
}

/** The receiver's callback atomically validates and unlocks only its original
 * B preparation. Installation and Grant issuance never call this callback. */
export class NodePoolServerAllowReceiver {
  readonly #dependency: EnvironmentDependency;
  readonly #runtime: ReturnType<typeof originalEnvironment>;
  readonly #installed: NodePoolServerAllowOptions;
  readonly #pin: Uint8Array; readonly #recipient = new Uint8Array(16); readonly #incarnation = new Uint8Array(16);
  readonly #server: Server; readonly #decoder: CBORDecoder;
  readonly #sockets = new Set<Socket>(); readonly #jobs = new Set<Promise<void>>(); readonly #ends = new Map<Socket, Promise<void>>();
  readonly #receive: (request: TunnelServerAllowRequest, grant: Uint8Array) => void;
  #closed = false; #delivered = false; #busy = false; #starting: Promise<void> | undefined; #closing: Promise<void> | undefined;
  constructor(environment: V4TransportEnvironment, options: NodePoolServerAllowReceiverOptions, receive: (request: TunnelServerAllowRequest, grant: Uint8Array) => void) {
    this.#installed = captureOptions(options); requireCredential(options.clientCertificateDER instanceof Uint8Array && options.clientCertificateDER.length > 0 && options.clientCertificateDER.length <= 65536, "configuration_capacity");
    const runtime = this.#runtime = originalEnvironment(environment), config = { bytes: 66560, nodes: 18, textBytes: 128, arrayItems: 14, runtimeBytes: runtime.resources.runtimeBytes };
    this.#dependency = runtime.admitDependency("pool_server_allow_receiver", new ResourceVector([8388608n + runtime.resources.runtimeBytes, 4194304n, 0n, 32n, 4n, 4n, 0n, 0n, 0n, 0n, 1n]));
    let pin: Uint8Array | undefined, decoder: CBORDecoder | undefined;
    try {
      this.#pin = pin = new Uint8Array(options.clientCertificateDER); this.#receive = receive;
      runtime.fillRandom(this.#recipient); runtime.fillRandom(this.#incarnation);
      const decoderReference = runtime.reserveConnectionWork("pool_server_allow_decoder", cborDecoderCharge(config));
      try { this.#decoder = decoder = new CBORDecoder(config, decoderReference); } finally { decoderReference.release(); }
      this.#server = createServer({ cert: this.#installed.tls.certificatePEM, key: this.#installed.tls.privateKeyPEM, ca: this.#installed.tls.trustPEM,
        requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], secureOptions: constants.SSL_OP_NO_TICKET,
        maxHeaderSize: 8192, highWaterMark: 16384, handshakeTimeout: Number(this.#installed.workMS), headersTimeout: Number(this.#installed.workMS), requestTimeout: Number(this.#installed.workMS) }, (request, response) => {
        const job = this.#handle(request, response); this.#jobs.add(job); void job.finally(() => { this.#jobs.delete(job); }).catch(() => { request.destroy(); });
      });
      this.#server.maxConnections = 2; this.#server.maxHeadersCount = 16; this.#server.maxRequestsPerSocket = 1;
      this.#server.on("connection", socket => {
        this.#sockets.add(socket);
        const timer = setTimeout(() => { socket.destroy(); }, Number(this.#installed.workMS));
        this.#ends.set(socket, new Promise(resolve => { socket.once("close", () => { clearTimeout(timer); this.#sockets.delete(socket); this.#ends.delete(socket); resolve(); }); }));
        if (this.#closed) socket.destroy();
      });
      this.#server.on("error", () => { void this.close(); }); this.#dependency.onClose(() => { void this.close(); });
    } catch (error) { decoder?.close(); pin?.fill(0); this.#recipient.fill(0); this.#incarnation.fill(0); this.#dependency.release(); throw error; }
  }
  async listen(): Promise<void> {
    this.#check(); requireCredential(this.#starting === undefined, "credential_closed"); const endpoint = new URL(this.#installed.endpoint);
    this.#starting = listenRegisteredControlServer(this.#server, endpoint.hostname.replace(/^\[|\]$/gu, ""), Number(endpoint.port));
    try { await this.#starting; this.#check(); } catch (error) { await this.close(); throw error; }
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); }
  binding(): PoolServerAllowBinding { this.#check(); return Object.freeze({ endpoint: this.#installed.endpoint, recipient: Buffer.from(this.#recipient).toString("base64"), incarnation: Buffer.from(this.#incarnation).toString("base64") }); }
  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    let entered = false, backing: Uint8Array | undefined; const copies: Uint8Array[] = [];
    // HTTPS exposes a TLSSocket while the connection event owns its raw
    // socket. Join this actual request socket instead of looking it up by the
    // other object's identity and refunding the request before TLS exits.
    const end = new Promise<void>(resolve => { if (request.socket.closed) resolve(); else request.socket.once("close", () => { resolve(); }); });
    const timer = setTimeout(() => { request.destroy(); response.destroy(); }, Number(this.#installed.workMS));
    try {
      this.#check(); requireCredential(!this.#busy && !this.#delivered && request.method === "POST" && request.url === "/tunnel/server-allow" && request.headers["content-type"] === "application/cbor", "credential_binding");
      const socket = request.socket as TLSSocket, peer = socket.getPeerCertificate(true);
      requireCredential(socket.authorized && socket.getProtocol() === "TLSv1.3" && peer.raw instanceof Uint8Array && equalCredential(peer.raw, this.#pin), "credential_binding");
      let contentType = false, contentLength = false;
      requireCredential(request.rawHeaders.length <= 32 && request.rawHeaders.length % 2 === 0, "credential_binding");
      for (let index = 0; index < request.rawHeaders.length; index += 2) {
        const name = request.rawHeaders[index]!.toLowerCase(), value = request.rawHeaders[index + 1]!;
        if (name === "content-type") { requireCredential(!contentType && value === "application/cbor", "credential_binding"); contentType = true; }
        else if (name === "content-length") { requireCredential(!contentLength && /^[1-9][0-9]{0,4}$/u.test(value) && Number(value) <= 66560, "credential_binding"); contentLength = true; }
        else requireCredential(name !== "content-encoding" && name !== "transfer-encoding" && name !== "trailer", "credential_binding");
      }
      requireCredential(contentType && contentLength, "credential_binding");
      const window = new TrustedWindow(this.#runtime.clock, this.#installed.workMS);
      const check = (): void => { this.#check(); window.check(); requireCredential(!request.aborted && !response.destroyed, "credential_closed"); };
      this.#busy = true; entered = true; backing = new Uint8Array(66560); let length = 0;
      for await (const chunk of request) { check(); requireCredential(chunk instanceof Uint8Array && length + chunk.length <= backing.length, "configuration_capacity"); backing.set(chunk, length); length += chunk.length; }
      check(); requireCredential(request.complete && length === Number(request.headers["content-length"]) && !this.#delivered, "credential_closed");
      const doc = this.#decoder.decode(backing.subarray(0, length));
      try {
        const items = (node: number, count: number): number[] => { requireCredential(doc.kind(node) === "array" && doc.size(node) === count, "credential_binding"); const values: number[] = []; for (let child = doc.firstChild(node); child >= 0; child = doc.nextSibling(child)) values.push(child); requireCredential(values.length === count); return values; };
        const bytes = (node: number, exact?: number): Uint8Array => { requireCredential(doc.kind(node) === "bytes" && (exact === undefined ? doc.size(node) > 0 && doc.size(node) <= 65536 : doc.size(node) === exact), "credential_binding"); const value = new Uint8Array(doc.size(node)); copies.push(value); doc.copyPayload(node, value); return value; };
        const fields = items(0, 14); requireCredential(doc.text(fields[0]!) === "tunnel-server-allow-1", "credential_binding"); const selected = items(fields[11]!, 3), index = doc.uint(selected[0]!);
        requireCredential(index < 16n, "credential_binding");
        const value: TunnelServerAllowRequest = Object.freeze({ tenant: doc.text(fields[1]!), audience: doc.text(fields[2]!), artifact: bytes(fields[3]!, 32), grant: bytes(fields[4]!, 32), relayIdentity: bytes(fields[5]!, 32),
          attempt: bytes(fields[6]!, 16), pairing: bytes(fields[7]!, 16), leg: bytes(fields[8]!, 16), recipient: bytes(fields[9]!, 16), incarnation: bytes(fields[10]!, 16),
          candidateIndex: Number(index), candidateID: bytes(selected[1]!, 16), routeDigest: bytes(selected[2]!, 32), notAfterMS: doc.uint(fields[12]!) });
        requireCredential(equalCredential(value.recipient, this.#recipient) && equalCredential(value.incarnation, this.#incarnation), "credential_binding");
        const grant = bytes(fields[13]!); check(); this.#receive(value, grant); this.#delivered = true;
      } finally { doc.release(); }
      response.writeHead(200, { "content-type": "application/cbor", "content-length": "1", "connection": "close", "cache-control": "no-store" }); response.end(Buffer.from([0xf5]));
    } catch { if (!response.headersSent && !response.destroyed) { response.writeHead(409, { "connection": "close", "content-length": "0" }); response.end(); } else response.destroy(); }
    finally { await end; clearTimeout(timer); backing?.fill(0); for (const value of copies) value.fill(0); if (entered) this.#busy = false; }
  }
  close(): Promise<void> {
    this.#closed = true;
    return this.#closing ??= (async () => {
      // A pending bind still owns the listener. Closing it before listen has
      // settled can report "not running" and then leave a late listener alive.
      await this.#starting?.catch(() => undefined);
      const stopped = new Promise<void>(resolve => { this.#server.close(() => { resolve(); }); });
      for (const socket of this.#sockets) socket.destroy(); await stopped; await Promise.all([...this.#ends.values()]);
      await Promise.allSettled([...this.#jobs]); this.#decoder.close(); this.#pin.fill(0); this.#recipient.fill(0); this.#incarnation.fill(0); this.#dependency.release(); })();
  }
}
Object.freeze(NodePoolServerAllowReceiver.prototype); Object.freeze(NodePoolServerAllowReceiver);
