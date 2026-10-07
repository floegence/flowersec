import { PreparedGrantDigest } from "../v4/runtime/grantDigest.js";
import { NodePoolServerAllowReceiver, type NodePoolServerAllowReceiverOptions, type PoolServerAllowBinding } from "./poolServerAllow.js";
import { prepareTunnelEndpointDialer, type TunnelEndpointDialerPreparation } from "./endpointDialer.js";
import type { NodeWSSListenerOptions } from "./serveWSS.js";
import type { NodeRawQUICListenerOptions } from "./serveRawQUIC.js";
import { observeTask } from "../v4/runtime/taskObservation.js";
import { createPublicKey, sign, verify, constants, KeyObject } from "node:crypto";
import { createServer, request as httpsRequest, type RequestOptions, type Server } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { checkServerIdentity, type ConnectionOptions, type TLSSocket } from "node:tls";
import { isIP, type LookupFunction, type Socket } from "node:net";
import { FixedCBORWriter } from "../v4/runtime/cborWriter.js";
import { candidateRouteDigest } from "../v4/runtime/credentialVerifier.js";
import { encodeLiveTunnelMaterial } from "../v4/runtime/liveAuthorizationWire.js";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency, type V4CredentialPolicy, type V4EnvironmentMaterial } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { TrustedDeadline, timerChunk } from "../v4/runtime/deadline.js";
import { CredentialWork, credentialWorkCharge, credentialDigest, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { createGrantIssuer, type GrantIssuer, type GrantIssuerOptions, type GrantIssuanceInput, type OriginalGrantIssuance } from "./grantIssuerCurrent.js";
import { createAcceptor, type Acceptor, type AcceptorOptions } from "./acceptorCurrent.js";
import { openSQLiteAdmissionStore, SQLiteAdmissionStore, type SQLiteAdmissionOpenOptions } from "./sqliteAdmission.js";
import type { V4SQLitePoolBacking } from "./sqliteV4.js";
import { captureOriginalRegisteredWinner, type OriginalRegisteredWinnerContinuation } from "./registeredWinnerContinuation.js";

const capability = Symbol("original registered tunnel control");
const remoteWinners = new WeakSet<RegisteredTunnelParentWinner>(), originalPublications = new WeakSet<RegisteredTunnelControlAuthority>();
const maximumBody = 262144, domain = Buffer.from("flowersec/original-tunnel-control/1\0");
export const registeredControlCharge = (runtimeBytes: bigint) => new ResourceVector([8388608n + runtimeBytes, 4194304n, 0n, 32n, 8n, 8n, 4n, 0n, 0n, 0n, 1n]);
export const registeredControlBase64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
export function registeredControlBytes(value: unknown, limit: number, exact?: number): Uint8Array {
  requireCredential(typeof value === "string" && value.length <= Math.ceil(limit / 3) * 4 && /^[A-Za-z0-9+/]*={0,2}$/u.test(value), "credential_binding");
  const result = new Uint8Array(Buffer.from(value, "base64"));
  if (result.length > limit || exact !== undefined && result.length !== exact || registeredControlBase64(result) !== value) { result.fill(0); throw new Error("credential_binding"); }
  return result;
}
export function registeredControlTLSText(value: string): string { requireCredential(typeof value === "string" && value.length > 0 && Buffer.byteLength(value) <= 262144, "configuration_capacity"); return value; }
function copyMaterial(input: GrantIssuanceInput): GrantIssuanceInput {
  requireCredential((input.source === "preauthorized_pool" || input.source === "live_authority") && Number.isSafeInteger(input.candidateIndex) && input.candidateIndex >= 0 && input.candidateIndex < 16, "configuration_capacity");
  for (const [value, limit] of [[input.artifact, 65536], [input.activation, 4096], [input.clientCertificate, 8192], [input.serverCertificate, 8192], [input.relayCertificate, 8192]] as const)
    requireCredential(value instanceof Uint8Array && (value.length > 0 || value === input.activation && input.source === "live_authority") && value.length <= limit, "configuration_capacity");
  return Object.freeze({ source: input.source, candidateIndex: input.candidateIndex, artifact: new Uint8Array(input.artifact), activation: new Uint8Array(input.activation), clientCertificate: new Uint8Array(input.clientCertificate), serverCertificate: new Uint8Array(input.serverCertificate), relayCertificate: new Uint8Array(input.relayCertificate) });
}
function clearMaterial(material: GrantIssuanceInput): void { for (const value of Object.values(material)) if (value instanceof Uint8Array) value.fill(0); }
export async function readRegisteredControlBody(message: IncomingMessage, signal: AbortSignal, check: () => void): Promise<Uint8Array> {
  const backing = new Uint8Array(maximumBody); let length = 0;
  const stop = (): void => { message.destroy(); }; signal.addEventListener("abort", stop, { once: true });
  try {
    check(); for await (const chunk of message) { check(); requireCredential(chunk instanceof Uint8Array && length + chunk.length <= backing.length, "configuration_capacity"); backing.set(chunk, length); length += chunk.length; }
    check(); requireCredential(length > 0); return new Uint8Array(backing.subarray(0, length));
  } finally { signal.removeEventListener("abort", stop); backing.fill(0); }
}
export interface RegisteredControlPayload { readonly kind: "prepare" | "prepared_ack" | "winner_continue" | "live_register" | "live_reservation" | "live_reserved" | "live_receive" | "live_allow_ack" | "live_authorize" | "live_client_prepared"; readonly incarnation: string; readonly parent: string; readonly candidate: number; readonly grant?: string; readonly continuation?: string; readonly recipient?: string; readonly attempt?: string; readonly activation?: string; readonly authentication?: string; readonly signature?: string; readonly request?: Readonly<Record<string, string | number>>; }
export interface RegisteredControlReply { readonly incarnation: string; readonly authority: string; readonly clientGrant?: string; readonly serverGrant?: string; readonly delivered?: true; readonly matched?: true; readonly prepared?: true; readonly registered?: true; readonly reserved?: true; readonly attempt?: string; readonly activation?: string; readonly grant?: string; readonly continuation?: string; readonly lease?: string; readonly projection?: string; }
export interface RegisteredRelayControlOptions {
  readonly endpoint: string; readonly authority: string;
  readonly tls: Readonly<{ certificatePEM: string; privateKeyPEM: string; trustPEM: string }>;
  readonly workMS: bigint;
}
/** Capture only an independently installed root HTTPS relay control endpoint. */
export function captureRegisteredRelayControl(input: RegisteredRelayControlOptions | undefined, identity: RegisteredRelayControlOptions["tls"]): RegisteredRelayControlOptions | undefined {
  if (input === undefined) return undefined;
  requireCredential(input !== null && typeof input === "object" && typeof input.authority === "string" && /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(input.authority) &&
    typeof input.workMS === "bigint" && input.workMS > 0n && input.workMS <= 60000n, "configuration_capacity");
  requireCredential(input.tls !== null && typeof input.tls === "object" && input.tls.certificatePEM === identity.certificatePEM && input.tls.privateKeyPEM === identity.privateKeyPEM, "configuration_capacity");
  const endpoint = new URL(input.endpoint);
  const host = endpoint.hostname.startsWith("[") ? endpoint.hostname.slice(1, -1) : endpoint.hostname;
  requireCredential(endpoint.protocol === "https:" && endpoint.pathname === "/" && endpoint.search === "" && endpoint.hash === "" && endpoint.username === "" && endpoint.password === "" &&
    (host === "localhost" || isIP(host) !== 0) && endpoint.port !== "" && Number.isSafeInteger(Number(endpoint.port)) && Number(endpoint.port) > 0 && Number(endpoint.port) <= 65535, "configuration_capacity");
  return Object.freeze({ endpoint: endpoint.href, authority: input.authority, workMS: input.workMS,
    tls: Object.freeze({ certificatePEM: registeredControlTLSText(input.tls.certificatePEM), privateKeyPEM: registeredControlTLSText(input.tls.privateKeyPEM), trustPEM: registeredControlTLSText(input.tls.trustPEM) }) });
}
/** Only localhost needs a lookup callback. Its installed hostname remains
 * unchanged for HTTP authority and TLS, while TCP always uses this address. */
const registeredRelayLocalhostLookup: LookupFunction = (hostname, options, callback): void => {
  if (hostname !== "localhost") { callback(new Error("configuration_capacity"), "", 4); return; }
  if (options.all) callback(null, [{ address: "127.0.0.1", family: 4 }]);
  else callback(null, "127.0.0.1", 4);
};
export function encodeRegisteredRelayReady(artifact: Uint8Array, candidate: Uint8Array, route: Uint8Array, role: 0 | 1, output: Uint8Array): Uint8Array {
  requireCredential(artifact.length === 32 && candidate.length === 16 && route.length === 32 && (role === 0 || role === 1), "credential_binding");
  return new FixedCBORWriter(output).array(5).data(new TextEncoder().encode("tunnel-relay-ready-1"), true).data(artifact).data(candidate).data(route).uint(role).result();
}
export interface RegisteredTunnelControlClientOptions {
  readonly endpoint: string; readonly authority: string;
  readonly tls: Readonly<{ certificatePEM: string; privateKeyPEM: string; trustPEM: string }>;
  readonly identityKey: KeyObject;
  readonly workMS: bigint;
  /** Optional independent relay process, using this endpoint's own mTLS identity. */
  readonly relayControl?: RegisteredRelayControlOptions;
}
export interface RegisteredTunnelControlAuthorityOptions {
  readonly issuer: GrantIssuerOptions; readonly material: GrantIssuanceInput;
  readonly host: string; readonly port: number;
  readonly tls: Readonly<{ certificatePEM: string; privateKeyPEM: string; clientTrustPEM: string }>;
  /** Independently installed B control certificate; mTLS also verifies its chain. */
  readonly serverControlCertificateDER: Uint8Array;
  readonly workMS: bigint;
}
/** One original pool registration in the authority process. The authenticated
 * B Prepare precedes signing/COMMIT, and material release waits for B's verified
 * installation. Only A's original TxA-P can subsequently publish B's Allow. */
export class RegisteredTunnelControlAuthority {
  #grantDigest: PreparedGrantDigest | undefined;
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #dependency: EnvironmentDependency;
  readonly #material: GrantIssuanceInput; readonly #issuer: GrantIssuer; readonly #store: SQLiteAdmissionStore;
  readonly #parent: string; readonly #serverKey: KeyObject; readonly #controlCertificate: Uint8Array;
  readonly #server: Server; readonly #sockets = new Set<Socket>(); readonly #jobs = new Set<Promise<void>>(); readonly #nativeEnds = new Map<Socket, Promise<void>>();
  readonly #workMS: bigint; readonly #publicationDeadline: TrustedDeadline;
  readonly #publication: Promise<void>; #resolvePublication!: () => void; #rejectPublication!: (error: unknown) => void;
  #winner: OriginalRegisteredWinnerContinuation | undefined;
  #incarnation: string | undefined; #grants: Readonly<{ clientGrant: Uint8Array; serverGrant: Uint8Array }> | undefined;
  #address: Readonly<{ host: string; port: number }> | undefined; #prepared = false; #publicationTaken = false; #busy = false; #closed = false;
  #timer: ReturnType<typeof setTimeout> | undefined; #starting: Promise<void> | undefined; #closing: Promise<void> | undefined;
  constructor(token: symbol, options: RegisteredTunnelControlAuthorityOptions) {
    requireCredential(token === capability && options.issuer.activationStore instanceof SQLiteAdmissionStore && typeof options.workMS === "bigint" && options.workMS > 0n && options.workMS <= 60000n && Number.isSafeInteger(options.port) && options.port >= 1 && options.port <= 65535 && options.serverControlCertificateDER instanceof Uint8Array && options.serverControlCertificateDER.length > 0 && options.serverControlCertificateDER.length <= 65536, "configuration_capacity");
    this.#runtime = originalEnvironment(options.issuer.environment); this.#dependency = this.#runtime.admitDependency("registered_tunnel_control_authority", registeredControlCharge(this.#runtime.resources.runtimeBytes));
    let material: GrantIssuanceInput | undefined, issuer: GrantIssuer | undefined;
    try {
      this.#grantDigest = new PreparedGrantDigest(this.#runtime.resources);
      this.#material = material = copyMaterial(options.material); this.#issuer = issuer = createGrantIssuer(options.issuer); this.#store = options.issuer.activationStore;
      const digest = credentialDigest("artifact_digest", material.artifact); try { this.#parent = registeredControlBase64(digest); } finally { digest.fill(0); }
      const ref = this.#runtime.reserveConnectionWork("registered_control_identity", credentialWorkCharge(16384, this.#runtime.resources.runtimeBytes)); let work: CredentialWork | undefined;
      try { work = new CredentialWork(this.#runtime.resources, 16384, ref); const certificate = work.parse(material.serverCertificate, "IdentityCertificate", 8192);
        try { const key = certificate.bytes("ed25519_public_key"); try { this.#serverKey = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), key]), format: "der", type: "spki" }); } finally { key.fill(0); } } finally { certificate.close(); }
      } finally { work?.close(); ref.release(); }
      this.#controlCertificate = new Uint8Array(options.serverControlCertificateDER);
      this.#workMS = options.workMS; this.#publicationDeadline = TrustedDeadline.ageAt(this.#runtime.clock, this.#runtime.clock.sample(), options.workMS, 0xffffffffffffffffn);
      this.#publication = new Promise((resolve, reject) => { this.#resolvePublication = resolve; this.#rejectPublication = reject; }); void this.#publication.catch(() => undefined);
      this.#server = createServer({ cert: registeredControlTLSText(options.tls.certificatePEM), key: registeredControlTLSText(options.tls.privateKeyPEM), ca: registeredControlTLSText(options.tls.clientTrustPEM), requestCert: true, rejectUnauthorized: true,
        minVersion: "TLSv1.3", maxVersion: "TLSv1.3", secureOptions: constants.SSL_OP_NO_TICKET, maxHeaderSize: 8192, highWaterMark: 16384, handshakeTimeout: Number(options.workMS), headersTimeout: Number(options.workMS), requestTimeout: Number(options.workMS) }, (request, response) => {
        const job = this.#handle(request, response); this.#jobs.add(job); void job.finally(() => { this.#jobs.delete(job); }).catch(() => { request.destroy(); });
      });
      this.#server.maxConnections = 4; this.#server.maxHeadersCount = 16; this.#server.maxRequestsPerSocket = 1;
      this.#server.on("connection", socket => {
        this.#sockets.add(socket); this.#nativeEnds.set(socket, new Promise(resolve => { socket.once("close", () => { this.#sockets.delete(socket); this.#nativeEnds.delete(socket); resolve(); }); }));
        if (this.#closed) socket.destroy();
      });
      this.#server.on("error", error => { this.#rejectPublication(error); void this.close(); });
      this.#dependency.onClose(() => { void this.close(); }); originalPublications.add(this); Object.freeze(this);
    } catch (error) { this.#grantDigest?.close(); issuer?.close(); if (material !== undefined) clearMaterial(material); this.#dependency.release(); throw error; }
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); }
  /** @internal */
  ownsOriginalIssuer(issuer: GrantIssuer): boolean { return originalPublications.has(this) && !this.#closed && this.#busy && this.#incarnation !== undefined && this.#winner === undefined && issuer === this.#issuer; }
  /** @internal */
  captureOriginalWinner(issuer: GrantIssuer, issuance: OriginalGrantIssuance, reference: ResourceReference): void {
    this.#check(); requireCredential(this.ownsOriginalIssuer(issuer) && this.#dependency.reference.sameEnvironment(reference), "credential_binding");
    this.#winner = captureOriginalRegisteredWinner(issuance, this.#dependency.reference, this.#store, nonce => this.#runtime.fillRandom(nonce as Uint8Array<ArrayBuffer>));
  }
  async listen(host: string, port: number): Promise<void> {
    this.#check(); requireCredential(this.#starting === undefined, "credential_closed");
    this.#starting = listenRegisteredControlServer(this.#server, host, port);
    try { await this.#starting; this.#check(); } catch (error) { await this.close(); throw error; }
    const address = this.#server.address(); requireCredential(address !== null && typeof address !== "string"); this.#address = Object.freeze({ host: address.address, port: address.port });
    const tick = (): void => { if (this.#prepared || this.#closed) return; try { this.#check(); this.#publicationDeadline.check(); this.#timer = setTimeout(tick, timerChunk(this.#publicationDeadline.remainingMS())); } catch (error) { this.#rejectPublication(error); void this.close(); } }; tick();
  }
  address(): Readonly<{ host: string; port: number }> { this.#check(); requireCredential(this.#address !== undefined); return this.#address; }
  async takeOriginalPublication(): Promise<Readonly<{ clientGrant: Uint8Array; serverGrant: Uint8Array }>> {
    this.#check(); requireCredential(!this.#publicationTaken, "credential_binding"); this.#publicationTaken = true;
    await this.#publication; this.#check(); requireCredential(this.#prepared && this.#grants !== undefined, "credential_binding");
    return Object.freeze({ clientGrant: new Uint8Array(this.#grants.clientGrant), serverGrant: new Uint8Array(this.#grants.serverGrant) });
  }
  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const abort = new AbortController(), stop = (): void => { abort.abort(); }; response.once("close", stop);
    let reference: ResourceReference | undefined, body: Uint8Array | undefined, payloadBytes: Uint8Array | undefined, proof: Uint8Array | undefined;
    let deadline: TrustedDeadline | undefined, releaseBusy = false, acknowledge = false, timer: ReturnType<typeof setTimeout> | undefined;
    const nativeEnd = this.#nativeEnds.get(request.socket) ?? (request.socket.closed ? Promise.resolve() : new Promise<void>(resolve => { request.socket.once("close", () => { resolve(); }); }));
    timer = setTimeout(() => { abort.abort(); request.destroy(); response.destroy(); }, Number(this.#workMS));
    const check = (): void => { this.#check(); reference!.check(); deadline!.check(); requireCredential(!abort.signal.aborted); };
    try {
      this.#check(); requireCredential(!this.#busy && request.method === "POST" && request.url === "/flowersec/control/tunnel" && request.headers["content-type"] === "application/json", "credential_binding"); this.#busy = true; releaseBusy = true;
      reference = this.#runtime.reserveConnectionWork("registered_tunnel_control_request", registeredControlCharge(this.#runtime.resources.runtimeBytes)); deadline = TrustedDeadline.ageAt(this.#runtime.clock, this.#runtime.clock.sample(), this.#workMS, 0xffffffffffffffffn);
      const socket = request.socket as TLSSocket, peer = socket.getPeerCertificate(true);
      requireCredential(socket.authorized && socket.getProtocol() === "TLSv1.3" && peer.raw instanceof Uint8Array && equalCredential(peer.raw, this.#controlCertificate), "credential_binding");
      body = await readRegisteredControlBody(request, abort.signal, check); const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as { payload: unknown; proof: unknown };
      requireCredential(Object.keys(envelope).length === 2 && typeof envelope.payload === "string" && Buffer.byteLength(envelope.payload) <= 131072, "credential_binding");
      payloadBytes = new TextEncoder().encode(envelope.payload); proof = registeredControlBytes(envelope.proof, 64, 64);
      requireCredential(verify(null, Buffer.concat([domain, payloadBytes]), this.#serverKey, proof), "credential_binding");
      const payload = JSON.parse(envelope.payload) as RegisteredControlPayload;
      requireCredential(payload.parent === this.#parent && payload.candidate === this.#material.candidateIndex && typeof payload.incarnation === "string", "credential_binding");
      const incarnation = registeredControlBytes(payload.incarnation, 32, 32); try { requireCredential(incarnation.some(value => value !== 0)); } finally { incarnation.fill(0); }
      let reply: RegisteredControlReply;
      if (payload.kind === "prepare") {
        this.#publicationDeadline.check(); requireCredential(this.#incarnation === undefined && Object.keys(payload).length === 4, "credential_binding");
        this.#incarnation = payload.incarnation;
        // The once-only original issuer owns the durable COMMIT. An interrupted
        // response does not authorize another registration or material replay.
        this.#grants = await this.#issuer.issueOriginalRegistered(this.#material, this); check();
        requireCredential(this.#winner !== undefined); const winner = this.#winner.publication();
        reply = { incarnation: payload.incarnation, authority: this.#store.authorityID(), clientGrant: registeredControlBase64(this.#grants.clientGrant), serverGrant: registeredControlBase64(this.#grants.serverGrant), continuation: registeredControlBase64(winner.continuation), lease: registeredControlBase64(winner.lease), projection: registeredControlBase64(winner.projection) };
      } else if (payload.kind === "prepared_ack") {
        this.#publicationDeadline.check(); requireCredential(payload.incarnation === this.#incarnation && !this.#prepared && this.#grants !== undefined && this.#winner !== undefined && Object.keys(payload).length === 6, "credential_binding");
        const actual = registeredControlBytes(payload.grant, 32, 32), expected = this.#grantDigest!.digest(this.#grants.serverGrant);
        try { requireCredential(equalCredential(actual, expected), "credential_binding"); const nonce = registeredControlBytes(payload.continuation, 32, 32); try { this.#winner.acknowledge(nonce); } finally { nonce.fill(0); } } finally { actual.fill(0); expected.fill(0); }
        this.#prepared = true; if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
        reply = { incarnation: payload.incarnation, authority: this.#store.authorityID(), prepared: true }; acknowledge = true;
      } else {
        requireCredential(payload.kind === "winner_continue" && this.#prepared && payload.incarnation === this.#incarnation && this.#winner !== undefined && Object.keys(payload).length === 5, "credential_binding");
        const nonce = registeredControlBytes(payload.continuation, 32, 32), winner = this.#winner; this.#winner = undefined;
        try { await winner.continue(nonce, reference, { signal: abort.signal, check, remainingMS: () => deadline!.remainingMS() }); check(); }
        finally { nonce.fill(0); winner.close(); }
        reply = { incarnation: payload.incarnation, authority: this.#store.authorityID(), matched: true };
      }
      check(); response.writeHead(200, { "content-type": "application/json", "connection": "close", "cache-control": "no-store" }); response.end(JSON.stringify(reply));
    } catch { if (!response.headersSent) { response.writeHead(409, { "connection": "close", "cache-control": "no-store" }); response.end(); } else response.destroy(); }
    finally {
      response.removeListener("close", stop);
      await nativeEnd; if (timer !== undefined) clearTimeout(timer); body?.fill(0); payloadBytes?.fill(0); proof?.fill(0); reference?.release(); if (releaseBusy) this.#busy = false; if (acknowledge && !this.#closed) this.#resolvePublication();
    }
  }
  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing;
    this.#closed = true; if (this.#timer !== undefined) clearTimeout(this.#timer); this.#rejectPublication(new Error("credential_closed")); this.#issuer.close();
    return this.#closing = (async () => { await this.#starting?.catch(() => undefined); const stopped = new Promise<void>(resolve => { this.#server.close(() => { resolve(); }); }); for (const socket of this.#sockets) socket.destroy(); await stopped; await Promise.all([...this.#nativeEnds.values()]); await Promise.allSettled([...this.#jobs]);
      this.#winner?.close(); this.#winner = undefined; this.#grants?.clientGrant.fill(0); this.#grants?.serverGrant.fill(0); clearMaterial(this.#material); this.#controlCertificate.fill(0); this.#grantDigest?.close(); this.#dependency.release(); })();
  }
}
/** The owner retains this promise so Close cannot outrun a pending bind. */
export function listenRegisteredControlServer(server: Server, host: string, port: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const failed = (error: Error): void => { server.removeListener("error", failed); reject(error); };
    server.once("error", failed);
    try { server.listen(port, host, () => { server.removeListener("error", failed); resolve(); }); }
    catch (error) { server.removeListener("error", failed); reject(error); }
  });
}
export function isOriginalRegisteredGrantPublication(value: unknown, issuer: GrantIssuer): value is RegisteredTunnelControlAuthority { return value instanceof RegisteredTunnelControlAuthority && originalPublications.has(value) && value.ownsOriginalIssuer(issuer); }
export async function createRegisteredTunnelControlAuthority(options: RegisteredTunnelControlAuthorityOptions): Promise<RegisteredTunnelControlAuthority> {
  const authority = new RegisteredTunnelControlAuthority(capability, options);
  try { await authority.listen(options.host, options.port); return authority; } catch (error) { await authority.close(); throw error; }
}

export interface RegisteredControlClientState { readonly runtime: ReturnType<typeof originalEnvironment>; readonly reference: ResourceReference; readonly deployment: RegisteredTunnelControlClientOptions; readonly endpoint: URL; readonly parent: string; readonly candidate: number; readonly incarnation: string; readonly abort: AbortController; delivered: boolean; busy: boolean; closed: boolean; pending: Promise<void> | undefined; }
/** One physical relay request under the original registered owner. Cancellation
 * keeps body/native socket custody until actual termination; never retry. */
export async function callRegisteredRelayControl(state: Pick<RegisteredControlClientState, "reference" | "abort" | "closed" | "busy" | "pending"> & { readonly deployment: { readonly relayControl?: RegisteredRelayControlOptions } }, path: "/tunnel/relay-ready" | "/tunnel/relay-prepare" | "/tunnel/relay-activate-client" | "/tunnel/server-allow", input: Uint8Array,
  operation: Readonly<{ signal?: AbortSignal; check(): void; remainingMS(): bigint }>, preparedCustody?: ResourceReference): Promise<void> {
  const installed = state.deployment.relayControl;
  requireCredential(installed !== undefined && !state.closed && !state.busy && input.length > 0 && input.length <= maximumBody, "credential_closed");
  const custody = preparedCustody ?? state.reference.borrow(); custody.check(); state.busy = true;
  let body: Uint8Array | undefined, nativeEnd: Promise<void> | undefined, bodyRead: Promise<void> | undefined, timer: ReturnType<typeof setTimeout> | undefined;
  let resolvePending!: () => void; state.pending = new Promise(resolve => { resolvePending = resolve; });
  const abort = new AbortController(), stop = (): void => { abort.abort(); }, check = (): void => { state.reference.check(); operation.check(); requireCredential(!state.closed && !abort.signal.aborted, "credential_closed"); };
  operation.signal?.addEventListener("abort", stop, { once: true }); state.abort.signal.addEventListener("abort", stop, { once: true }); if (operation.signal?.aborted || state.abort.signal.aborted) stop();
  try {
    check(); body = new Uint8Array(input);
    const available = operation.remainingMS(), remaining = available < installed.workMS ? available : installed.workMS; requireCredential(remaining > 0n && remaining <= 60000n);
    timer = setTimeout(stop, Number(remaining));
    const endpoint = new URL(path, installed.endpoint);
    await new Promise<void>((resolve, reject) => {
      const options: RequestOptions & ConnectionOptions = { method: "POST", agent: false, maxHeaderSize: 8192,
        ...(endpoint.hostname === "localhost" ? { lookup: registeredRelayLocalhostLookup, family: 4, servername: "localhost" } : {}), cert: installed.tls.certificatePEM, key: installed.tls.privateKeyPEM, ca: installed.tls.trustPEM,
        minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], rejectUnauthorized: true, secureOptions: constants.SSL_OP_NO_TICKET, checkServerIdentity, signal: abort.signal,
        headers: { "content-type": "application/cbor", "content-length": body!.length, "connection": "close" } };
      const request = httpsRequest(endpoint, options, response => {
        const socket = response.socket as TLSSocket;
        try {
          check(); requireCredential(socket.authorized && socket.getProtocol() === "TLSv1.3" && response.statusCode === 200, "credential_binding");
          requireCredential(response.rawHeaders.length % 2 === 0, "credential_binding");
          let contentType = false, contentLength = false;
          // Inspect physical header occurrences before Node's normalized map
          // can discard or combine duplicate framing and content metadata.
          for (let index = 0; index < response.rawHeaders.length; index += 2) {
            const name = response.rawHeaders[index]!.toLowerCase(), value = response.rawHeaders[index + 1]!;
            if (name === "content-type") {
              requireCredential(!contentType && value === "application/cbor", "credential_binding"); contentType = true;
            } else if (name === "content-length") {
              requireCredential(!contentLength && value === "1", "credential_binding"); contentLength = true;
            } else requireCredential(name !== "content-encoding" && name !== "transfer-encoding" && name !== "trailer", "credential_binding");
          }
          requireCredential(contentType && contentLength, "credential_binding");
        } catch (error) { response.destroy(); reject(error); return; }
        // The installed stage protocol acknowledges exactly canonical CBOR
        // true; a receipt, JSON fact or extra body cannot authorize handoff.
        bodyRead = (async () => {
          let count = 0;
          for await (const chunk of response) { check(); requireCredential(chunk instanceof Uint8Array && chunk.length <= 1 - count && (chunk.length === 0 || chunk[0] === 0xf5), "credential_binding"); count += chunk.length; }
          check(); requireCredential(count === 1, "credential_binding");
        })();
        void bodyRead.then(resolve, error => { response.destroy(); reject(error); });
      });
      nativeEnd = new Promise<void>(ended => { let socketAssigned = false;
        request.once("socket", socket => { socketAssigned = true; socket.once("close", () => { ended(); }); });
        request.once("close", () => { if (!socketAssigned) ended(); }); });
      request.once("error", reject); check(); request.end(body);
    });
    check();
  } finally {
    operation.signal?.removeEventListener("abort", stop); state.abort.signal.removeEventListener("abort", stop); if (timer !== undefined) clearTimeout(timer);
    abort.abort(); await nativeEnd; await bodyRead?.catch(() => undefined); body?.fill(0); custody.release(); state.busy = false; state.pending = undefined; resolvePending();
  }
}
export async function callRegisteredControl(state: RegisteredControlClientState, payload: RegisteredControlPayload, operation: Readonly<{ signal?: AbortSignal; check(): void; remainingMS(): bigint }>): Promise<RegisteredControlReply> {
  requireCredential(!state.closed && !state.busy, "credential_closed"); const custody = state.reference.borrow(); state.busy = true;
  let body: Uint8Array | undefined, signature: Uint8Array | undefined, answer: Uint8Array | undefined, nativeEnd: Promise<void> | undefined, bodyRead: Promise<Uint8Array> | undefined, timer: ReturnType<typeof setTimeout> | undefined;
  let resolvePending!: () => void; state.pending = new Promise(resolve => { resolvePending = resolve; });
  const abort = new AbortController(), stop = (): void => { abort.abort(); }, check = (): void => { state.reference.check(); operation.check(); requireCredential(!state.closed && !abort.signal.aborted); };
  operation.signal?.addEventListener("abort", stop, { once: true }); state.abort.signal.addEventListener("abort", stop, { once: true }); if (operation.signal?.aborted || state.abort.signal.aborted) stop();
  try {
    check(); const content = JSON.stringify(payload), encoded = new TextEncoder().encode(content);
    try { signature = new Uint8Array(sign(null, Buffer.concat([domain, encoded]), state.deployment.identityKey)); } finally { encoded.fill(0); }
    body = new TextEncoder().encode(JSON.stringify({ payload: content, proof: registeredControlBase64(signature) })); requireCredential(body.length <= maximumBody);
    const configured = state.deployment, tls = configured.tls, remaining = operation.remainingMS(); requireCredential(remaining > 0n && remaining <= 60000n);
    timer = setTimeout(() => { abort.abort(); }, Number(remaining));
    answer = await new Promise<Uint8Array>((resolve, reject) => {
      const request = httpsRequest(state.endpoint, { method: "POST", agent: false, cert: tls.certificatePEM, key: tls.privateKeyPEM, ca: tls.trustPEM, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", rejectUnauthorized: true,
        secureOptions: constants.SSL_OP_NO_TICKET, checkServerIdentity, signal: abort.signal, headers: { "content-type": "application/json", "content-length": body!.length, "connection": "close" } }, response => {
        const socket = response.socket as TLSSocket;
        try { check(); requireCredential(socket.authorized && socket.getProtocol() === "TLSv1.3" && response.statusCode === 200, "credential_binding"); }
        catch (error) { response.destroy(); reject(error); return; }
        bodyRead = readRegisteredControlBody(response, abort.signal, check);
        void bodyRead.then(resolve, reject);
      });
      nativeEnd = new Promise<void>(ended => {
        let socketAssigned = false;
        request.once("socket", socket => { socketAssigned = true; socket.once("close", () => { ended(); }); });
        request.once("close", () => { if (!socketAssigned) ended(); });
      });
      request.once("error", reject); request.end(body);
    });
    check(); const reply = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(answer)) as RegisteredControlReply;
    requireCredential(reply.incarnation === state.incarnation && reply.authority === configured.authority, "credential_binding"); return reply;
  } finally {
    operation.signal?.removeEventListener("abort", stop); state.abort.signal.removeEventListener("abort", stop); if (timer !== undefined) clearTimeout(timer);
    abort.abort(); await nativeEnd;
    const received = await bodyRead?.catch(() => undefined); if (received !== answer) received?.fill(0);
    body?.fill(0); signature?.fill(0); answer?.fill(0); custody.release(); state.busy = false; state.pending = undefined; resolvePending();
  }
}
/** Only B's original verified publication installs this private continuation.
 * It matches the local service projection before continuing the same ledger's
 * exact match once. The reply cannot publish or authorize a Session. */
export class RegisteredTunnelParentWinner {
  readonly #state: RegisteredControlClientState;
  #nonce: Uint8Array | undefined; #lease: Uint8Array | undefined; #projection: Uint8Array | undefined; #attempted = false;
  constructor(token: symbol, state: RegisteredControlClientState) { requireCredential(token === capability); this.#state = state; remoteWinners.add(this); Object.freeze(this); }
  check(reference: ResourceReference): void { requireCredential(remoteWinners.has(this) && !this.#state.closed && this.#state.reference.sameEnvironment(reference), "credential_binding"); this.#state.reference.check(); }
  install(token: symbol, reply: RegisteredControlReply): string {
    requireCredential(token === capability && !this.#state.closed && !this.#state.delivered && this.#nonce === undefined && !this.#attempted, "credential_binding");
    let nonce: Uint8Array | undefined, lease: Uint8Array | undefined, projection: Uint8Array | undefined;
    try {
      nonce = registeredControlBytes(reply.continuation, 32, 32); lease = registeredControlBytes(reply.lease, 161); projection = registeredControlBytes(reply.projection, 8192);
      requireCredential(nonce.some(value => value !== 0) && lease.length >= 34 && projection.length > 0, "credential_binding");
      this.#nonce = nonce; this.#lease = lease; this.#projection = projection; return registeredControlBase64(nonce);
    } catch (error) { nonce?.fill(0); lease?.fill(0); projection?.fill(0); throw error; }
  }
  async match(authority: string, lease: Uint8Array, projection: Uint8Array, reference: ResourceReference, operation: Readonly<{ signal?: AbortSignal; check(): void; remainingMS(): bigint }>): Promise<void> {
    this.check(reference); requireCredential(this.#state.delivered && !this.#attempted && this.#nonce !== undefined && this.#lease !== undefined && this.#projection !== undefined, "credential_binding");
    this.#attempted = true;
    try {
      operation.check(); requireCredential(authority === this.#state.deployment.authority && equalCredential(lease, this.#lease) && equalCredential(projection, this.#projection), "credential_binding");
      const reply = await callRegisteredControl(this.#state, { kind: "winner_continue", incarnation: this.#state.incarnation, parent: this.#state.parent, candidate: this.#state.candidate, continuation: registeredControlBase64(this.#nonce) }, operation);
      this.check(reference); operation.check(); requireCredential(reply.matched === true, "credential_binding");
    } finally { this.close(); }
  }
  close(): void { this.#attempted = true; this.#nonce?.fill(0); this.#lease?.fill(0); this.#projection?.fill(0); this.#nonce = undefined; this.#lease = undefined; this.#projection = undefined; }
}
export function isRegisteredTunnelParentWinner(value: unknown, reference: ResourceReference): value is RegisteredTunnelParentWinner {
  if (!(value instanceof RegisteredTunnelParentWinner) || !remoteWinners.has(value)) return false;
  value.check(reference); return true;
}

type Listener = AcceptorOptions["listeners"][number];
type ServerListener<L> = L extends Listener ? Omit<L, "credentials" | "admissionStore" | "preparation"> : never;
export interface RegisteredPoolTunnelServerOptions {
  readonly environment: V4TransportEnvironment; readonly material: GrantIssuanceInput; readonly policy: V4CredentialPolicy;
  readonly control: RegisteredTunnelControlClientOptions;
  readonly serverAllow?: NodePoolServerAllowReceiverOptions;
  readonly serviceBacking: V4SQLitePoolBacking; readonly serviceStore: Omit<SQLiteAdmissionOpenOptions, "parentWinnerStore" | "parentWinnerAuthority">;
  readonly server: Omit<AcceptorOptions, "environment" | "listeners"> & Readonly<{ listener: ServerListener<Listener> }>;
}
/** B owns the physical Prepare and the original received allow in its own
 * Environment. Its AdmissionLedger matches the authority's existing winner
 * over the same authenticated registration, never an empty local winner DB. */
export interface RegisteredLiveTunnelServerOptions extends Omit<RegisteredPoolTunnelServerOptions, "material"> {
  readonly material: Omit<GrantIssuanceInput, "activation" | "source">;
}
export class RegisteredTunnelServer {
  #grantDigest: PreparedGrantDigest | undefined;
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #dependency: EnvironmentDependency; readonly #material: GrantIssuanceInput;
  readonly #options: RegisteredPoolTunnelServerOptions; readonly #live: boolean; readonly #recipient = new Uint8Array(16); readonly #ownedConfiguration: Uint8Array[] = [];
  readonly #state: RegisteredControlClientState; readonly #winner: RegisteredTunnelParentWinner; readonly #policy: V4CredentialPolicy;
  readonly #deadline: TrustedDeadline; #preparation: ReturnType<ReturnType<typeof originalEnvironment>["prepareTunnelCredentials"]> | undefined;
  #dialer: TunnelEndpointDialerPreparation | undefined;
  #allowReceiver: NodePoolServerAllowReceiver | undefined;
  readonly #publicationReady: Promise<void>; #resolvePublication!: () => void; #rejectPublication!: (error: unknown) => void;
  #acceptor: Acceptor | undefined; #store: SQLiteAdmissionStore | undefined; #prepared: V4EnvironmentMaterial | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined; #closed = false; #consumed = false; #prepareDone: Promise<void> | undefined; #delivery: Promise<void> | undefined; #closing: Promise<void> | undefined;
  constructor(token: symbol, options: RegisteredPoolTunnelServerOptions, live = false) {
    requireCredential(token === capability && options.policy.tunnel?.role === 1 && options.server.listener.path === "tunnel" && typeof options.control.workMS === "bigint" && options.control.workMS > 0n && options.control.workMS <= 60000n && options.control.identityKey instanceof KeyObject && options.control.identityKey.type === "private" && options.control.identityKey.asymmetricKeyType === "ed25519", "configuration_capacity");
    this.#live = live; requireCredential(live ? options.policy.tunnel?.liveGrant !== undefined : options.serverAllow !== undefined, "configuration_capacity");
    this.#runtime = originalEnvironment(options.environment); this.#dependency = this.#runtime.admitDependency("registered_tunnel_server", registeredControlCharge(this.#runtime.resources.runtimeBytes));
    this.#publicationReady = new Promise((resolve, reject) => { this.#resolvePublication = resolve; this.#rejectPublication = reject; }); void this.#publicationReady.catch(() => undefined);
    let material: GrantIssuanceInput | undefined;
    try {
      this.#grantDigest = new PreparedGrantDigest(this.#runtime.resources);
      this.#material = material = copyMaterial(options.material);
      const listener = options.server.listener;
      requireCredential(!("physicalDirection" in listener) || listener.physicalDirection === "dialer", "configuration_capacity");
      const copy = (value: Uint8Array, limit: number): Uint8Array => { requireCredential(value instanceof Uint8Array && value.length > 0 && value.length <= limit, "configuration_capacity"); const captured = new Uint8Array(value); this.#ownedConfiguration.push(captured); return captured; };
      let tls: NodeWSSListenerOptions["tls"] | NodeRawQUICListenerOptions["tls"] | undefined;
      if ("tls" in listener && "certificateChainDER" in listener.tls) {
        requireCredential(Array.isArray(listener.tls.certificateChainDER) && listener.tls.certificateChainDER.length > 0 && listener.tls.certificateChainDER.length <= 16, "configuration_capacity");
        tls = Object.freeze({ certificateChainDER: Object.freeze(listener.tls.certificateChainDER.map(value => copy(value, 65536))), privateKeyDER: copy(listener.tls.privateKeyDER, 65536) });
      } else if ("tls" in listener) {
        const tlsOptions = listener.tls;
        requireCredential("certificate" in tlsOptions && "privateKey" in tlsOptions, "configuration_capacity");
        tls = Object.freeze({ certificate: registeredControlTLSText(tlsOptions.certificate), privateKey: registeredControlTLSText(tlsOptions.privateKey) });
      }
      requireCredential(options.serviceStore.bindings.length > 0 && options.serviceStore.bindings.length <= 64, "configuration_capacity");
      const bindings = Object.freeze(options.serviceStore.bindings.map(binding => Object.freeze({ ...binding, issuer: copy(binding.issuer, 16), serverIdentity: copy(binding.serverIdentity, 32) })));
      const carrier = listener.carrier;
      if ("trustRootsDER" in carrier && carrier.trustRootsDER !== undefined) requireCredential(carrier.trustRootsDER.length <= 16, "configuration_capacity");
      const capturedCarrier = "trustRootsDER" in carrier && carrier.trustRootsDER !== undefined ? Object.freeze({ ...carrier, trustRootsDER: Object.freeze(carrier.trustRootsDER.map(value => copy(value, 65536))) }) : "ca" in carrier && carrier.ca !== undefined ? Object.freeze({ ...carrier, ca: Object.freeze(carrier.ca.map(value => typeof value === "string" ? registeredControlTLSText(value) : copy(value, 65536))) }) : Object.freeze({ ...carrier });
      // Capture callback identities, TLS backing and the route tuple before
      // the first store or native bind await exposes this original owner.
      this.#options = Object.freeze({ ...options, serviceStore: Object.freeze({ ...options.serviceStore, bindings, identity: Object.freeze({ ...options.serviceStore.identity, storeID: copy(options.serviceStore.identity.storeID, 32) }), continuity: Object.freeze({ check: options.serviceStore.continuity.check.bind(options.serviceStore.continuity) }) }),
        server: Object.freeze({ ...options.server, listener: Object.freeze({ ...listener, ...(tls === undefined ? {} : { tls }), carrier: capturedCarrier, limits: Object.freeze({ ...listener.limits }), ingress: Object.freeze({ ...listener.ingress }) }) }) }) as RegisteredPoolTunnelServerOptions;
      const digest = credentialDigest("artifact_digest", material.artifact), incarnation = new Uint8Array(live ? 16 : 32);
      try { this.#runtime.fillRandom(incarnation); this.#runtime.fillRandom(this.#recipient); const endpoint = new URL(options.control.endpoint); requireCredential(endpoint.protocol === "https:" && endpoint.pathname === (live ? "/flowersec/control/live" : "/flowersec/control/tunnel") && endpoint.search === "" && endpoint.hash === "" && endpoint.username === "" && endpoint.password === "", "configuration_capacity");
        const relayControl = captureRegisteredRelayControl(options.control.relayControl, options.control.tls);
        const deployment = Object.freeze({ ...options.control, ...(relayControl === undefined ? {} : { relayControl }), tls: Object.freeze({ certificatePEM: registeredControlTLSText(options.control.tls.certificatePEM), privateKeyPEM: registeredControlTLSText(options.control.tls.privateKeyPEM), trustPEM: registeredControlTLSText(options.control.tls.trustPEM) }) });
        this.#state = { runtime: this.#runtime, reference: this.#dependency.reference, deployment, endpoint, parent: registeredControlBase64(digest), candidate: material.candidateIndex, incarnation: registeredControlBase64(incarnation), abort: new AbortController(), delivered: false, busy: false, closed: false, pending: undefined };
      } finally { digest.fill(0); incarnation.fill(0); }
      this.#winner = new RegisteredTunnelParentWinner(capability, this.#state);
      this.#policy = Object.freeze({ ...options.policy, authorities: Object.freeze([...options.policy.authorities]), cryptoProfiles: Object.freeze([...options.policy.cryptoProfiles]), tunnel: Object.freeze({ ...options.policy.tunnel }) });
      this.#deadline = TrustedDeadline.ageAt(this.#runtime.clock, this.#runtime.clock.sample(), options.control.workMS, 0xffffffffffffffffn);
      this.#preparation = this.#runtime.prepareTunnelCredentials(this.#policy);
      if (!live) this.#allowReceiver = new NodePoolServerAllowReceiver(options.environment, options.serverAllow!, (request, grant) => {
        this.#check(); this.#deadline.check(); requireCredential(!this.#state.delivered && !this.#consumed && this.#prepared !== undefined, "credential_binding");
        this.#runtime.acceptOriginalPoolServerAllow(this.#prepared, request, grant, this.#dependency.reference);
        this.#state.delivered = true; this.#resolvePublication();
      });
      this.#dependency.onClose(() => { void this.close(); }); Object.freeze(this);
    } catch (error) { this.#grantDigest?.close(); this.#preparation?.close(); for (const value of this.#ownedConfiguration) value.fill(0); if (material !== undefined) clearMaterial(material); this.#dependency.release(); throw error; }
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); }
  async prepare(token: symbol): Promise<void> {
    requireCredential(token === capability); const options = this.#options;
    this.#check(); this.#deadline.check(); requireCredential(this.#prepareDone === undefined, "credential_binding");
    let resolvePreparation!: () => void; this.#prepareDone = new Promise(resolve => { resolvePreparation = resolve; });
    let reference: ResourceReference | undefined, work: CredentialWork | undefined, originalServerListens = false;
    try {
      reference = this.#runtime.reserveConnectionWork("registered_server_prepare_route", credentialWorkCharge(131072, this.#runtime.resources.runtimeBytes));
      work = new CredentialWork(this.#runtime.resources, 131072, reference); const artifact = work.parse(this.#material.artifact, "Artifact", 65536, 16384), certificate = work.parse(this.#material.serverCertificate, "IdentityCertificate", 8192);
      try { const candidate = [...artifact.items("candidates")][this.#material.candidateIndex]!;
        const leg = artifact.field("server_leg", candidate, "Candidate"), listener = options.server.listener, carrier = "carrierKind" in listener ? listener.carrierKind ?? "wss" : "wss";
        const dialerRole = artifact.uint("dialer_role", leg, "Leg"), listenerRole = artifact.uint("listener_role", leg, "Leg");
        requireCredential(artifact.uint("endpoint_role", leg, "Leg") === 1n && (dialerRole === 2n && listenerRole === 1n || dialerRole === 1n && listenerRole === 2n), "credential_binding");
        originalServerListens = listenerRole === 1n;
        requireCredential(("physicalDirection" in listener) === !originalServerListens && artifact.text("host", leg, "Leg") === listener.serverName && artifact.uint("port", leg, "Leg") === BigInt(listener.port) && artifact.uint("carrier", leg, "Leg") === (carrier === "wss" ? 1n : carrier === "raw_quic" ? 0n : 2n), "credential_binding");
        const expected = certificate.bytes("ed25519_public_key"), key = createPublicKey(listener.identityKey).export({ format: "jwk" }), controlKey = createPublicKey(this.#state.deployment.identityKey).export({ format: "jwk" });
        try { requireCredential(key.crv === "Ed25519" && typeof key.x === "string" && key.x === controlKey.x && equalCredential(new Uint8Array(Buffer.from(key.x, "base64url")), expected), "credential_binding"); } finally { expected.fill(0); }
      } finally { artifact.close(); certificate.close(); }
      this.#store = await openSQLiteAdmissionStore(options.serviceBacking, { ...options.serviceStore, ...(this.#live ? {} : { parentWinnerAuthority: this.#winner }) });
      if (this.#live) {
        this.#prepared = this.#runtime.verify(this.#policy, { artifact: this.#material.artifact, clientCertificate: this.#material.clientCertificate, serverCertificate: this.#material.serverCertificate,
          source: "live_authority", candidateIndex: this.#material.candidateIndex, tunnel: { relayCertificate: this.#material.relayCertificate } }, this.#preparation);
        this.#preparation!.close(); this.#preparation = undefined;
      }
      const endpoint = options.server.listener;
      if (!originalServerListens) {
        requireCredential("physicalDirection" in endpoint && endpoint.physicalDirection === "dialer", "credential_binding");
        this.#dialer = await prepareTunnelEndpointDialer({ environment: options.environment, policy: this.#policy, material: { ...this.#material, tunnel: { relayCertificate: this.#material.relayCertificate } }, workMS: options.control.workMS, carrierKind: endpoint.carrierKind, carrier: endpoint.carrier } as Parameters<typeof prepareTunnelEndpointDialer>[0], this.#state.abort.signal);
      }
      const unavailable = async (): Promise<never> => { throw new Error("original_prepared_server_material_required"); };
      this.#acceptor = await createAcceptor({ ...options.server, environment: options.environment, listeners: [{ ...options.server.listener, ...(this.#dialer === undefined ? {} : { preparation: this.#dialer }), admissionStore: this.#store, credentials: { source: this.#live ? "live_authority" : "preauthorized_pool", policy: this.#policy, resolve: unavailable, resolveHop: unavailable, takePreparedHop: request => this.#take(request) } } as Listener] });
      this.#check(); this.#deadline.check(); requireCredential(this.#acceptor.addresses().length === 1 && this.#acceptor.addresses()[0]!.port === options.server.listener.port, "credential_binding");
      await this.#allowReceiver?.listen();
      const operation = { check: (): void => { this.#check(); this.#deadline.check(); }, remainingMS: (): bigint => this.#deadline.remainingMS() };
      if (this.#live) {
        if (this.#state.deployment.relayControl !== undefined && originalServerListens) {
          const artifact = work.parse(this.#material.artifact, "Artifact", 65536, 16384), backing = new Uint8Array(192);
          let candidateID: Uint8Array | undefined, routeDigest: Uint8Array | undefined, parent: Uint8Array | undefined;
          try {
            const candidate = [...artifact.items("candidates")][this.#material.candidateIndex]!;
            candidateID = artifact.bytes("candidate_id", candidate, "Candidate"); routeDigest = candidateRouteDigest(artifact, candidate); parent = credentialDigest("artifact_digest", this.#material.artifact);
            await callRegisteredRelayControl(this.#state, "/tunnel/relay-ready", encodeRegisteredRelayReady(parent, candidateID, routeDigest, 1, backing), operation);
          } finally { artifact.close(); backing.fill(0); candidateID?.fill(0); routeDigest?.fill(0); parent?.fill(0); }
        }
        const registered = await callRegisteredControl(this.#state, { kind: "live_register", incarnation: this.#state.incarnation, parent: this.#state.parent, candidate: this.#state.candidate, recipient: registeredControlBase64(this.#recipient) }, operation);
        requireCredential(registered.registered === true, "credential_binding");
        this.#delivery = this.#installLive(); void this.#delivery.catch(() => { void this.close(); }); return;
      }
      const reply = await callRegisteredControl(this.#state, { kind: "prepare", incarnation: this.#state.incarnation, parent: this.#state.parent, candidate: this.#state.candidate }, operation);
      const grant = registeredControlBytes(reply.serverGrant, 65536); let clientGrant: Uint8Array | undefined;
      try {
        // Issuance installs the verified closure only. The separate original
        // A success continuation must still deliver Allow to this receiver.
        clientGrant = registeredControlBytes(reply.clientGrant, 65536);
        this.#prepared = this.#runtime.verify(this.#policy, { ...this.#material, tunnel: { grant, relayCertificate: this.#material.relayCertificate } }, this.#preparation);
        this.#preparation!.close(); this.#preparation = undefined; this.#runtime.checkOriginalServerPublication(this.#prepared, this.#dependency.reference);
        const continuation = this.#winner.install(capability, reply);
        const digest = this.#grantDigest!.digest(grant);
        try { const ack = await callRegisteredControl(this.#state, { kind: "prepared_ack", incarnation: this.#state.incarnation, parent: this.#state.parent, candidate: this.#state.candidate, grant: registeredControlBase64(digest), continuation }, operation); requireCredential(ack.prepared === true, "credential_binding"); }
        finally { digest.fill(0); }
        this.#check();
      } finally { grant.fill(0); clientGrant?.fill(0); }
      const tick = (): void => { if (this.#closed || this.#consumed) return; try { this.#check(); this.#runtime.checkOriginalServerPublication(this.#prepared!, this.#dependency.reference); this.#timer = setTimeout(tick, 1000); } catch { void this.close(); } }; tick();
    } finally { work?.close(); reference?.release(); resolvePreparation(); }
  }
  async #installLive(): Promise<void> {
    const operation = { check: (): void => { this.#check(); this.#deadline.check(); }, remainingMS: (): bigint => this.#deadline.remainingMS() };
    const common = { incarnation: this.#state.incarnation, parent: this.#state.parent, candidate: this.#state.candidate };
    let attempt: Uint8Array | undefined, activation: Uint8Array | undefined, grant: Uint8Array | undefined;
    const response = new Uint8Array(73728);
    try {
      const reservation = await callRegisteredControl(this.#state, { kind: "live_reservation", ...common }, operation); attempt = registeredControlBytes(reservation.attempt, 16, 16);
      this.#check(); this.#runtime.beginOriginalLivePublication(this.#prepared!, attempt, this.#dependency.reference);
      const reserved = await callRegisteredControl(this.#state, { kind: "live_reserved", ...common, attempt: registeredControlBase64(attempt) }, operation); requireCredential(reserved.reserved === true, "credential_binding");
      const publication = await callRegisteredControl(this.#state, { kind: "live_receive", ...common }, operation);
      const receivedAttempt = registeredControlBytes(publication.attempt, 16, 16); try { requireCredential(equalCredential(receivedAttempt, attempt), "credential_binding"); } finally { receivedAttempt.fill(0); }
      activation = registeredControlBytes(publication.activation, 4096); grant = registeredControlBytes(publication.grant, 65536);
      const encoded = encodeLiveTunnelMaterial(activation, grant, response); this.#runtime.installOriginalLivePublication(this.#prepared!, encoded, this.#dependency.reference);
      this.#state.delivered = true;
      const activationDigest = credentialDigest("activation_digest", activation), grantDigest = this.#grantDigest!.digest(grant);
      try { const ack = await callRegisteredControl(this.#state, { kind: "live_allow_ack", ...common, attempt: registeredControlBase64(attempt), activation: registeredControlBase64(activationDigest), grant: registeredControlBase64(grantDigest) }, operation); requireCredential(ack.delivered === true, "credential_binding"); }
      finally { activationDigest.fill(0); grantDigest.fill(0); }
      this.#check();
      this.#resolvePublication();
      const tick = (): void => { if (this.#closed || this.#consumed) return; try { this.#check(); this.#runtime.checkOriginalLivePublication(this.#prepared!, this.#dependency.reference); this.#timer = setTimeout(tick, 1000); } catch { void this.close(); } }; tick();
    } finally { attempt?.fill(0); activation?.fill(0); grant?.fill(0); response.fill(0); }
  }
  /** Native Prepare and authenticated registration are already complete. This
   * wait observes only this receiver's original Allow delivery. */
  async waitPublication(): Promise<void> { this.#check(); await this.#publicationReady; this.#check(); requireCredential(this.#state.delivered, "credential_binding"); }
  poolServerAllowBinding(): PoolServerAllowBinding { this.#check(); requireCredential(!this.#live && this.#allowReceiver !== undefined, "credential_binding"); return this.#allowReceiver.binding(); }
  preparedAcceptor(): Acceptor { this.#check(); requireCredential(this.#acceptor !== undefined); return this.#acceptor; }
  async #take(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>): Promise<V4EnvironmentMaterial> {
    this.#check(); await observeTask(this.#publicationReady, request.signal); this.#check(); requireCredential(this.#state.delivered && !this.#consumed && this.#prepared !== undefined && !request.signal.aborted, "credential_binding");
    this.#runtime.checkOriginalServerPublication(this.#prepared, this.#dependency.reference);
    const reference = this.#runtime.reserveConnectionWork("registered_server_original_hello", credentialWorkCharge(65536, this.#runtime.resources.runtimeBytes)); let work: CredentialWork | undefined;
    try { if ("physicalDirection" in this.#options.server.listener && this.#options.server.listener.physicalDirection === "dialer") requireCredential(request.hello.length === 0, "credential_binding");
      else { work = new CredentialWork(this.#runtime.resources, 65536, reference); const hello = work.parse(request.hello, "HOP_AUTH_HELLO", 65536, 16384, { selectors: { hop_sender_role: "relay" } });
      try { const certificate = hello.bytes("identity_certificate"); try { requireCredential(equalCredential(certificate, this.#material.relayCertificate), "credential_binding"); } finally { certificate.fill(0); } } finally { hello.close(); } }
      this.#check(); requireCredential(!request.signal.aborted); this.#runtime.checkOriginalServerPublication(this.#prepared, this.#dependency.reference);
      const original = this.#prepared; this.#prepared = undefined; this.#consumed = true; if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; return original;
    } finally { work?.close(); reference.release(); }
  }
  acceptor(): Acceptor { this.#check(); requireCredential(this.#acceptor !== undefined, "credential_binding"); return this.#acceptor; }
  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing; this.#closed = true; this.#state.closed = true; this.#state.abort.abort(); this.#rejectPublication(new Error("credential_closed"));
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#preparation?.close(); this.#preparation = undefined;
    return this.#closing = (async () => { await this.#allowReceiver?.close(); await this.#prepareDone; await Promise.allSettled(this.#delivery === undefined ? [] : [this.#delivery]); await this.#state.pending; await this.#acceptor?.close(); await this.#dialer?.close(); const prepared = this.#prepared; this.#prepared = undefined; await prepared?.closeMaterial(); this.#store?.close(); await this.#store?.waitCleanup(); this.#winner.close(); clearMaterial(this.#material); this.#recipient.fill(0); for (const value of this.#ownedConfiguration) value.fill(0); this.#grantDigest?.close(); this.#dependency.release(); })();
  }
}
export async function createRegisteredPoolTunnelServer(options: RegisteredPoolTunnelServerOptions): Promise<RegisteredTunnelServer> {
  const server = new RegisteredTunnelServer(capability, options);
  try { await server.prepare(capability); return server; } catch (error) { await server.close(); throw error; }
}
export async function createRegisteredLiveTunnelServer(options: RegisteredLiveTunnelServerOptions): Promise<RegisteredTunnelServer> {
  const server = new RegisteredTunnelServer(capability, { ...options, material: { ...options.material, source: "live_authority", activation: new Uint8Array() } }, true);
  try { await server.prepare(capability); return server; } catch (error) { await server.close(); throw error; }
}
for (const owner of [RegisteredTunnelControlAuthority, RegisteredTunnelParentWinner, RegisteredTunnelServer]) { Object.freeze(owner.prototype); Object.freeze(owner); }
