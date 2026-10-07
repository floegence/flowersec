import { PreparedGrantDigest } from "../v4/runtime/grantDigest.js";
import { observeTask } from "../v4/runtime/taskObservation.js";
import type { ClientPreparationFields } from "../v4/runtime/credentialVerifier.js";
import { isOriginalTunnelRuntime, type TunnelRuntime } from "./tunnelRuntime.js";
import { bindOriginalLiveCarrierPreparation } from "../v4/runtime/liveCarrierPreparation.js";
import { createPublicKey, constants, sign, verify, KeyObject } from "node:crypto";
import { createServer, type Server } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { isIP, type Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { TrustedDeadline, timerChunk } from "../v4/runtime/deadline.js";
import { CredentialWork, credentialWorkCharge, credentialDigest, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { observeOriginalLiveSpend, bindLiveAuthorizationConfig, type V4LiveAuthorizationConfig, type V4LiveAuthorizationRequest } from "../v4/runtime/liveAuthorization.js";
import { CBORDecoder, cborDecoderCharge } from "../v4/runtime/cbor.js";
import { FixedCBORWriter } from "../v4/runtime/cborWriter.js";
import { encodeLiveAuthorizationRequest } from "../v4/runtime/liveAuthorizationWire.js";
import { createLiveTunnelAuthority, isOriginalLiveControlCapability, type LiveTunnelAuthority, type LiveTunnelAuthorityOptions, type OriginalLiveServerPublication } from "./liveTunnelAuthorityCurrent.js";
import type { GrantIssuanceInput } from "./grantIssuerCurrent.js";
import { callRegisteredControl, callRegisteredRelayControl, captureRegisteredRelayControl, encodeRegisteredRelayReady, listenRegisteredControlServer, readRegisteredControlBody, registeredControlBase64 as b64, registeredControlBytes as bytes, registeredControlCharge as charge, registeredControlTLSText as tlsText,
  type RegisteredControlClientState, type RegisteredControlPayload, type RegisteredControlReply, type RegisteredTunnelControlClientOptions } from "./registeredTunnelControl.js";

const capability = Symbol("original remote live tunnel registration"), controls = new WeakSet<RegisteredLiveTunnelControlAuthority>();
const domain = Buffer.from("flowersec/original-tunnel-control/1\0");
interface Deferred<T> { readonly promise: Promise<T>; resolve(value: T): void; reject(error: unknown): void; }
function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  const promise = new Promise<T>((accept, refuse) => { resolve = accept; reject = refuse; }); void promise.catch(() => undefined); return { promise, resolve, reject };
}
function sameInput(left: GrantIssuanceInput, right: GrantIssuanceInput): boolean {
  return left.source === "live_authority" && right.source === "live_authority" && left.candidateIndex === right.candidateIndex &&
    (["artifact", "clientCertificate", "serverCertificate", "relayCertificate"] as const).every(field => equalCredential(left[field], right[field]));
}
/** This publication belongs to a live authority invocation, never a row read.
 * The remote receiver's original pending material and actual listener existed
 * before registration. Its attempt confirmation gates the original TxA. */
class OriginalRemoteLivePublication implements OriginalLiveServerPublication {
  readonly #grantDigest: PreparedGrantDigest;
  readonly #owner: RegisteredLiveTunnelControlAuthority; readonly #reference: ResourceReference; readonly #input: GrantIssuanceInput;
  readonly #recipient: Uint8Array; readonly #incarnation: Uint8Array; readonly #attempt: Uint8Array;
  readonly #reserved = deferred<void>(); readonly #available = deferred<void>(); readonly #delivered = deferred<void>();
  readonly #activation = new Uint8Array(4096); readonly #clientGrant = new Uint8Array(65536); readonly #grant = new Uint8Array(65536); readonly #deadline: TrustedDeadline;
  #activationLength = 0; #grantLength = 0; #reservationTaken = false; #reservedConfirmed = false; #materialTaken = false; #published = false; #acknowledged = false; #closed = false;
  constructor(token: symbol, owner: RegisteredLiveTunnelControlAuthority, input: GrantIssuanceInput, attempt: Uint8Array, recipient: Uint8Array, incarnation: Uint8Array, reference: ResourceReference, deadline: TrustedDeadline, resources: ReturnType<typeof originalEnvironment>["resources"]) {
    requireCredential(token === capability); this.#grantDigest = new PreparedGrantDigest(resources); this.#owner = owner; this.#input = input; this.#attempt = new Uint8Array(attempt); this.#recipient = new Uint8Array(recipient); this.#incarnation = new Uint8Array(incarnation); this.#reference = reference; this.#deadline = deadline; Object.freeze(this);
  }
  check(): void { requireCredential(!this.#closed, "credential_closed"); this.#owner.checkPublication(capability, this); this.#reference.check(); this.#deadline.check(); }
  recipient(): Uint8Array { this.check(); return new Uint8Array(this.#recipient); }
  incarnation(): Uint8Array { this.check(); return new Uint8Array(this.#incarnation); }
  async #wait<T>(pending: Promise<T>, guard: () => void): Promise<T> {
    this.check(); guard(); const canceled = deferred<never>(); let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = (): void => { try { this.check(); guard(); timer = setTimeout(tick, timerChunk(this.#deadline.remainingMS() < 1000n ? this.#deadline.remainingMS() : 1000n)); } catch (error) { canceled.reject(error); } }; tick();
    try { const result = await Promise.race([pending, canceled.promise]); this.check(); guard(); return result; } finally { if (timer !== undefined) clearTimeout(timer); }
  }
  async prepare(input: GrantIssuanceInput, attempt: Uint8Array, guard: () => void): Promise<void> {
    this.check(); requireCredential(sameInput(input, this.#input) && equalCredential(attempt, this.#attempt), "credential_binding");
    this.#owner.checkOriginalPreparedCarriers(capability, input, attempt);
    await this.#wait(this.#reserved.promise, guard); this.#owner.checkOriginalPreparedCarriers(capability, input, attempt); requireCredential(this.#reservedConfirmed, "credential_binding");
  }
  takeReservation(token: symbol): Uint8Array { this.check(); requireCredential(token === capability && !this.#reservationTaken); this.#reservationTaken = true; return new Uint8Array(this.#attempt); }
  confirmReservation(token: symbol, attempt: Uint8Array): void {
    this.check(); requireCredential(token === capability && this.#reservationTaken && !this.#reservedConfirmed && equalCredential(attempt, this.#attempt), "credential_binding"); this.#reservedConfirmed = true; this.#reserved.resolve();
  }
  async publish(input: GrantIssuanceInput, activation: Uint8Array, grant: Uint8Array, guard: () => void, clientGrant?: Uint8Array): Promise<void> {
    this.check(); guard(); requireCredential(sameInput(input, this.#input) && this.#reservedConfirmed && !this.#published && activation.length > 0 && activation.length <= 4096 && grant.length > 0 && grant.length <= 65536, "credential_binding");
    // These fixed publication buffers and their owner were prepaid before TxA.
    // Only the original invocation calls this after the original durable TxB.
    requireCredential(clientGrant !== undefined && clientGrant.length > 0 && clientGrant.length <= this.#clientGrant.length, "credential_binding"); this.#clientGrant.set(clientGrant);
    this.#activation.set(activation); this.#grant.set(grant); this.#activationLength = activation.length; this.#grantLength = grant.length; this.#published = true; this.#available.resolve();
    await this.#wait(this.#delivered.promise, guard); requireCredential(this.#acknowledged, "credential_binding"); this.#owner.continueOriginalPreparedPair(capability, this.#input, this.#clientGrant.subarray(0, clientGrant.length), this.#grant.subarray(0, this.#grantLength));
  }
  async takeMaterial(token: symbol, check: () => void): Promise<Readonly<{ activation: string; grant: string; attempt: string }>> {
    this.check(); requireCredential(token === capability && !this.#materialTaken, "credential_binding");
    await this.#wait(this.#available.promise, check); requireCredential(!this.#materialTaken && this.#published, "credential_binding"); this.#materialTaken = true;
    return Object.freeze({ activation: b64(this.#activation.subarray(0, this.#activationLength)), grant: b64(this.#grant.subarray(0, this.#grantLength)), attempt: b64(this.#attempt) });
  }
  acknowledge(token: symbol, attempt: Uint8Array, proofDigest: Uint8Array, grantDigest: Uint8Array): void {
    this.check(); requireCredential(token === capability && this.#materialTaken && this.#published && !this.#acknowledged && equalCredential(attempt, this.#attempt), "credential_binding");
    const expectedProof = credentialDigest("activation_digest", this.#activation.subarray(0, this.#activationLength)), expectedGrant = this.#grantDigest.digest(this.#grant.subarray(0, this.#grantLength));
    try { requireCredential(equalCredential(proofDigest, expectedProof) && equalCredential(grantDigest, expectedGrant), "credential_binding"); } finally { expectedProof.fill(0); expectedGrant.fill(0); }
    this.#acknowledged = true; this.#delivered.resolve();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; const error = new Error("original_publication_closed"); this.#reserved.reject(error); this.#available.reject(error); this.#delivered.reject(error);
    this.#activation.fill(0); this.#clientGrant.fill(0); this.#grant.fill(0); this.#attempt.fill(0); this.#recipient.fill(0); this.#incarnation.fill(0); this.#grantDigest.close(); this.#reference.release(); this.#owner.finishPublication(capability, this);
  }
}
export interface RegisteredLiveTunnelControlAuthorityOptions {
  readonly live: Omit<LiveTunnelAuthorityOptions, "serverControl">;
  readonly relayRuntime?: TunnelRuntime;
  readonly host: string; readonly port: number;
  readonly tls: Readonly<{ certificatePEM: string; privateKeyPEM: string; clientTrustPEM: string }>;
  readonly clientControlCertificateDER: Uint8Array;
  readonly serverControlCertificateDER: Uint8Array;
}
/** The authority process owns the original journal, policy, signers and TxB.
 * B's control registration identifies its actual SDK receiver incarnation;
 * neither receipt lookup nor a second process can reconstruct this owner. */
export class RegisteredLiveTunnelControlAuthority {
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #dependency: EnvironmentDependency;
  readonly #authority!: LiveTunnelAuthority; readonly #server!: Server; readonly #parent!: string; readonly #candidate!: number; readonly #authorityID!: string;
  readonly #clientKey!: KeyObject; readonly #serverKey!: KeyObject; readonly #clientTLS!: Uint8Array; readonly #serverTLS!: Uint8Array;
  readonly #relay!: TunnelRuntime | undefined; readonly #applicationAudience!: string;
  #preparedClient: Readonly<{ attempt: Uint8Array; incarnation: string }> | undefined; #preparedServer = false;
  readonly #workMS!: bigint; readonly #material!: LiveTunnelAuthorityOptions["material"];
  readonly #sockets = new Set<Socket>(); readonly #nativeEnds = new Map<Socket, Promise<void>>(); readonly #jobs = new Set<Promise<void>>();
  readonly #reservation = deferred<OriginalRemoteLivePublication>();
  #registration: Readonly<{ recipient: Uint8Array; incarnation: Uint8Array; encodedIncarnation: string }> | undefined;
  #publication: OriginalRemoteLivePublication | undefined; #used = false; #clientBusy = false; #serverBusy = false; #closed = false; #starting: Promise<void> | undefined; #closing: Promise<void> | undefined;
  #address: Readonly<{ host: string; port: number }> | undefined;
  constructor(token: symbol, options: RegisteredLiveTunnelControlAuthorityOptions) {
    requireCredential(token === capability && isIP(options.host) !== 0 && typeof options.live.workMS === "bigint" && options.live.workMS > 0n && options.live.workMS <= 60000n && Number.isSafeInteger(options.port) && options.port > 0 && options.port <= 65535, "configuration_capacity");
    this.#runtime = originalEnvironment(options.live.issuer.environment); this.#dependency = this.#runtime.admitDependency("registered_live_tunnel_control", charge(this.#runtime.resources.runtimeBytes));
    let authority: LiveTunnelAuthority | undefined;
    try {
      requireCredential(options.relayRuntime === undefined || isOriginalTunnelRuntime(options.relayRuntime, this.#runtime, options.live.issuer.activationStore), "credential_binding"); this.#relay = options.relayRuntime; this.#applicationAudience = options.live.issuer.credentials.audience;
      this.#workMS = options.live.workMS; this.#authorityID = options.live.authority; this.#candidate = options.live.material.candidateIndex;
      this.#material = Object.freeze({ candidateIndex: this.#candidate, artifact: new Uint8Array(options.live.material.artifact), clientCertificate: new Uint8Array(options.live.material.clientCertificate), serverCertificate: new Uint8Array(options.live.material.serverCertificate), relayCertificate: new Uint8Array(options.live.material.relayCertificate) });
      const digest = credentialDigest("artifact_digest", this.#material.artifact); try { this.#parent = b64(digest); } finally { digest.fill(0); }
      for (const certificate of [options.clientControlCertificateDER, options.serverControlCertificateDER]) requireCredential(certificate instanceof Uint8Array && certificate.length > 0 && certificate.length <= 65536, "configuration_capacity");
      this.#clientTLS = new Uint8Array(options.clientControlCertificateDER); this.#serverTLS = new Uint8Array(options.serverControlCertificateDER); requireCredential(!equalCredential(this.#clientTLS, this.#serverTLS), "configuration_capacity");
      const reference = this.#runtime.reserveConnectionWork("registered_live_identities", credentialWorkCharge(32768, this.#runtime.resources.runtimeBytes)); let work: CredentialWork | undefined;
      try {
        work = new CredentialWork(this.#runtime.resources, 32768, reference);
        const identityKey = (input: Uint8Array): KeyObject => { const certificate = work!.parse(input, "IdentityCertificate", 8192); try { const publicKey = certificate.bytes("ed25519_public_key"); try { return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]), format: "der", type: "spki" }); } finally { publicKey.fill(0); } } finally { certificate.close(); } };
        this.#clientKey = identityKey(this.#material.clientCertificate); this.#serverKey = identityKey(this.#material.serverCertificate);
      } finally { work?.close(); reference.release(); }
      controls.add(this); this.#authority = authority = createLiveTunnelAuthority({ ...options.live, serverControl: this });
      this.#server = createServer({ cert: tlsText(options.tls.certificatePEM), key: tlsText(options.tls.privateKeyPEM), ca: tlsText(options.tls.clientTrustPEM), requestCert: true, rejectUnauthorized: true,
        minVersion: "TLSv1.3", maxVersion: "TLSv1.3", secureOptions: constants.SSL_OP_NO_TICKET, maxHeaderSize: 8192, highWaterMark: 16384, handshakeTimeout: Number(this.#workMS), headersTimeout: Number(this.#workMS), requestTimeout: Number(this.#workMS) }, (request, response) => {
        const job = this.#handle(request, response); this.#jobs.add(job); void job.finally(() => { this.#jobs.delete(job); }).catch(() => { request.destroy(); });
      });
      this.#server.maxConnections = 4; this.#server.maxHeadersCount = 16; this.#server.maxRequestsPerSocket = 1;
      this.#server.on("connection", socket => { this.#sockets.add(socket); this.#nativeEnds.set(socket, new Promise(resolve => { socket.once("close", () => { this.#sockets.delete(socket); this.#nativeEnds.delete(socket); resolve(); }); })); if (this.#closed) socket.destroy(); });
      this.#server.on("error", () => { void this.close(); }); this.#dependency.onClose(() => { void this.close(); }); Object.freeze(this);
    } catch (error) { controls.delete(this); authority?.close(); this.#server?.close(); this.#clientTLS?.fill(0); this.#serverTLS?.fill(0); for (const value of Object.values(this.#material ?? {})) if (value instanceof Uint8Array) value.fill(0); this.#dependency.release(); throw error; }
  }
  belongsTo(runtime: ReturnType<typeof originalEnvironment>): boolean { return controls.has(this) && !this.#closed && this.#runtime === runtime; }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); }
  async listen(host: string, port: number): Promise<void> {
    this.#check(); requireCredential(this.#starting === undefined, "credential_closed");
    this.#starting = listenRegisteredControlServer(this.#server, host, port);
    try { await this.#starting; this.#check(); } catch (error) { await this.close(); throw error; }
    const address = this.#server.address(); requireCredential(address !== null && typeof address !== "string"); this.#address = Object.freeze({ host: address.address, port: address.port });
  }
  address(): Readonly<{ host: string; port: number }> { this.#check(); requireCredential(this.#address !== undefined); return this.#address; }
  recipient(): Uint8Array { this.#check(); requireCredential(this.#registration !== undefined); return new Uint8Array(this.#registration.recipient); }
  incarnation(): Uint8Array { this.#check(); requireCredential(this.#registration !== undefined); return new Uint8Array(this.#registration.incarnation); }
  reserve(token: symbol, input: GrantIssuanceInput, attempt: Uint8Array): OriginalLiveServerPublication {
    this.#check(); requireCredential(isOriginalLiveControlCapability(token) && !this.#used && this.#registration !== undefined && input.source === "live_authority" && attempt.length === 16, "credential_binding");
    const expected = { ...this.#material, source: "live_authority" as const, activation: input.activation }; requireCredential(sameInput(input, expected), "credential_binding");
    const reference = this.#runtime.reserveConnectionWork("original_remote_live_publication", new ResourceVector([262144n + this.#runtime.resources.runtimeBytes, 0n, 0n, 8n, 4n, 0n, 0n, 0n, 0n, 0n, 0n]));
    try { this.#publication = new OriginalRemoteLivePublication(capability, this, input, attempt, this.#registration.recipient, this.#registration.incarnation, reference, TrustedDeadline.ageAt(this.#runtime.clock, this.#runtime.clock.sample(), this.#workMS, 0xffffffffffffffffn), this.#runtime.resources); this.#used = true; this.#reservation.resolve(this.#publication); return this.#publication; }
    catch (error) { reference.release(); throw error; }
  }
  async #prepareOriginalCarrier(role: 0 | 1, signal: AbortSignal): Promise<void> {
    if (this.#relay !== undefined) { await this.#relay.prepareOriginalLiveCarrier(role, { ...this.#material, applicationAudience: this.#applicationAudience }, signal); return; }
    const reference = this.#runtime.reserveConnectionWork("registered_live_physical_direction", credentialWorkCharge(65536, this.#runtime.resources.runtimeBytes)); let work: CredentialWork | undefined;
    try { work = new CredentialWork(this.#runtime.resources, 65536, reference); const artifact = work.parse(this.#material.artifact, "Artifact", 65536); try { const candidate = [...artifact.items("candidates")][this.#candidate]!; const leg = artifact.field(role === 0 ? "client_leg" : "server_leg", candidate, "Candidate"); requireCredential(role === 1 || artifact.uint("dialer_role", leg, "Leg") === 0n && artifact.uint("listener_role", leg, "Leg") === 2n, "original_relay_preparation_required"); } finally { artifact.close(); } } finally { work?.close(); reference.release(); }
  }
  checkOriginalPreparedCarriers(token: symbol, input: GrantIssuanceInput, attempt: Uint8Array): void {
    this.#check(); requireCredential(token === capability && this.#preparedClient !== undefined && this.#preparedServer && equalCredential(this.#preparedClient.attempt, attempt) && sameInput(input, { ...this.#material, source: "live_authority", activation: input.activation }), "credential_binding");
    this.#relay?.checkOriginalLiveCarrierPreparation(0); this.#relay?.checkOriginalLiveCarrierPreparation(1);
  }
  continueOriginalPreparedPair(token: symbol, input: GrantIssuanceInput, clientGrant: Uint8Array, serverGrant: Uint8Array): void {
    this.#check(); requireCredential(token === capability && this.#preparedClient !== undefined); this.checkOriginalPreparedCarriers(token, input, this.#preparedClient.attempt);
    this.#relay?.continueOriginalLivePair([{ grant: clientGrant, endpointCertificate: input.clientCertificate, relayCertificate: input.relayCertificate }, { grant: serverGrant, endpointCertificate: input.serverCertificate, relayCertificate: input.relayCertificate }]);
  }
  checkPublication(token: symbol, publication: OriginalRemoteLivePublication): void { this.#check(); requireCredential(token === capability && publication === this.#publication, "credential_binding"); }
  finishPublication(token: symbol, publication: OriginalRemoteLivePublication): void { requireCredential(token === capability); if (this.#publication === publication) this.#publication = undefined; }
  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const abort = new AbortController(), stopped = (): void => { abort.abort(); }; response.once("close", stopped);
    const nativeEnd = this.#nativeEnds.get(request.socket) ?? (request.socket.closed ? Promise.resolve() : new Promise<void>(resolve => { request.socket.once("close", () => { resolve(); }); }));
    const timer = setTimeout(() => { abort.abort(); request.destroy(); response.destroy(); }, Number(this.#workMS));
    let reference: ResourceReference | undefined, body: Uint8Array | undefined, encoded: Uint8Array | undefined, proof: Uint8Array | undefined, role: "client" | "server" | undefined;
    const deadline = TrustedDeadline.ageAt(this.#runtime.clock, this.#runtime.clock.sample(), this.#workMS, 0xffffffffffffffffn);
    const check = (): void => { this.#check(); reference!.check(); deadline.check(); requireCredential(!abort.signal.aborted); };
    try {
      this.#check(); requireCredential(request.method === "POST" && request.url === "/flowersec/control/live" && request.headers["content-type"] === "application/json", "credential_binding");
      reference = this.#runtime.reserveConnectionWork("registered_live_control_request", charge(this.#runtime.resources.runtimeBytes)); body = await readRegisteredControlBody(request, abort.signal, check);
      const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)) as { payload: unknown; proof: unknown };
      requireCredential(Object.keys(envelope).length === 2 && typeof envelope.payload === "string" && Buffer.byteLength(envelope.payload) <= 131072, "credential_binding");
      encoded = new TextEncoder().encode(envelope.payload); proof = bytes(envelope.proof, 64, 64); const payload = JSON.parse(envelope.payload) as RegisteredControlPayload;
      requireCredential(payload.parent === this.#parent && payload.candidate === this.#candidate, "credential_binding");
      const client = payload.kind === "live_authorize" || payload.kind === "live_client_prepared", socket = request.socket as TLSSocket, peer = socket.getPeerCertificate(true);
      requireCredential(socket.authorized && socket.getProtocol() === "TLSv1.3" && peer.raw instanceof Uint8Array && equalCredential(peer.raw, client ? this.#clientTLS : this.#serverTLS) && verify(null, Buffer.concat([domain, encoded]), client ? this.#clientKey : this.#serverKey, proof), "credential_binding");
      requireCredential(client ? !this.#clientBusy : !this.#serverBusy, "credential_busy"); role = client ? "client" : "server"; if (client) this.#clientBusy = true; else this.#serverBusy = true;
      const incarnation = bytes(payload.incarnation, client ? 32 : 16, client ? 32 : 16); try { requireCredential(incarnation.some(value => value !== 0)); } finally { incarnation.fill(0); }
      let reply: RegisteredControlReply;
      if (payload.kind === "live_client_prepared") {
        requireCredential(Object.keys(payload).length === 5 && this.#preparedClient === undefined && !this.#used, "credential_binding");
        const attempt = bytes(payload.attempt, 16, 16);
        try {
          requireCredential(attempt.some(value => value !== 0), "credential_binding"); await this.#prepareOriginalCarrier(0, abort.signal); check();
          this.#preparedClient = Object.freeze({ attempt: new Uint8Array(attempt), incarnation: payload.incarnation });
          reply = { incarnation: payload.incarnation, authority: this.#authorityID, prepared: true };
        } finally { attempt.fill(0); }
      } else if (payload.kind === "live_authorize") {
        requireCredential(Object.keys(payload).length === 7 && payload.request !== undefined && this.#registration !== undefined && this.#preparedClient !== undefined && payload.incarnation === this.#preparedClient.incarnation, "credential_binding");
        const requestFields = decodeRequest(payload.request);
        let authentication: Uint8Array | undefined, signature: Uint8Array | undefined;
        const output = new Uint8Array(73728);
        try {
          requireCredential(equalCredential(requestFields.attempt, this.#preparedClient.attempt), "credential_binding");
          authentication = bytes(payload.authentication, 1152); signature = bytes(payload.signature, 64, 64);
          const count = await this.#authority.authorizeOriginalControlRequest(requestFields, authentication, signature, output, abort.signal, check); check(); reply = { incarnation: payload.incarnation, authority: this.#authorityID, grant: b64(output.subarray(0, count)) };
        } finally { authentication?.fill(0); signature?.fill(0); output.fill(0); clearRequest(requestFields); }
      } else if (payload.kind === "live_register") {
        requireCredential(Object.keys(payload).length === 5 && this.#registration === undefined && !this.#used, "credential_binding");
        let recipient: Uint8Array | undefined, originalIncarnation: Uint8Array | undefined, retained = false;
        try {
          recipient = bytes(payload.recipient, 16, 16); originalIncarnation = bytes(payload.incarnation, 16, 16); requireCredential(recipient.some(value => value !== 0));
          this.#registration = Object.freeze({ recipient, incarnation: originalIncarnation, encodedIncarnation: payload.incarnation }); retained = true;
          await this.#prepareOriginalCarrier(1, abort.signal); check(); this.#preparedServer = true; reply = { incarnation: payload.incarnation, authority: this.#authorityID, registered: true };
        } finally { if (!retained) { recipient?.fill(0); originalIncarnation?.fill(0); } }
      } else {
        requireCredential(this.#registration !== undefined && payload.incarnation === this.#registration.encodedIncarnation, "credential_binding");
        if (payload.kind === "live_reservation") {
          requireCredential(Object.keys(payload).length === 4, "credential_binding");
          const publication = await this.#waitReservation(abort.signal, check, deadline); const attempt = publication.takeReservation(capability);
          try { reply = { incarnation: payload.incarnation, authority: this.#authorityID, attempt: b64(attempt) }; } finally { attempt.fill(0); }
        } else if (payload.kind === "live_reserved") {
          requireCredential(Object.keys(payload).length === 5 && this.#publication !== undefined, "credential_binding"); const attempt = bytes(payload.attempt, 16, 16);
          try { this.#publication.confirmReservation(capability, attempt); } finally { attempt.fill(0); } reply = { incarnation: payload.incarnation, authority: this.#authorityID, reserved: true };
        } else if (payload.kind === "live_receive") {
          requireCredential(Object.keys(payload).length === 4 && this.#publication !== undefined, "credential_binding");
          reply = { incarnation: payload.incarnation, authority: this.#authorityID, ...await this.#publication.takeMaterial(capability, check) };
        } else {
          requireCredential(payload.kind === "live_allow_ack" && Object.keys(payload).length === 7 && this.#publication !== undefined, "credential_binding");
          let attempt: Uint8Array | undefined, activation: Uint8Array | undefined, grant: Uint8Array | undefined;
          try { attempt = bytes(payload.attempt, 16, 16); activation = bytes(payload.activation, 32, 32); grant = bytes(payload.grant, 32, 32);
            this.#publication.acknowledge(capability, attempt, activation, grant);
          } finally { attempt?.fill(0); activation?.fill(0); grant?.fill(0); } reply = { incarnation: payload.incarnation, authority: this.#authorityID, delivered: true };
        }
      }
      check(); response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store", "connection": "close" }); response.end(JSON.stringify(reply));
    } catch { if (!response.headersSent) { response.writeHead(409, { "connection": "close", "cache-control": "no-store" }); response.end(); } else response.destroy(); }
    finally { response.removeListener("close", stopped); await nativeEnd; if (role === "client") this.#clientBusy = false; else if (role === "server") this.#serverBusy = false; clearTimeout(timer); body?.fill(0); encoded?.fill(0); proof?.fill(0); reference?.release(); }
  }
  async #waitReservation(signal: AbortSignal, check: () => void, deadline: TrustedDeadline): Promise<OriginalRemoteLivePublication> {
    const canceled = deferred<never>(); const stop = (): void => { canceled.reject(new Error("canceled")); }; signal.addEventListener("abort", stop, { once: true });
    try { check(); deadline.check(); const publication = await Promise.race([this.#reservation.promise, canceled.promise]); check(); return publication; } finally { signal.removeEventListener("abort", stop); }
  }
  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing; this.#closed = true; this.#authority.close(); this.#publication?.close(); this.#reservation.reject(new Error("credential_closed"));
    return this.#closing = (async () => { await this.#starting?.catch(() => undefined); const stopped = new Promise<void>(resolve => { this.#server.close(() => { resolve(); }); }); for (const socket of this.#sockets) socket.destroy(); await stopped; await Promise.all([...this.#nativeEnds.values()]); await Promise.allSettled([...this.#jobs]);
      for (const value of Object.values(this.#material)) if (value instanceof Uint8Array) value.fill(0); this.#preparedClient?.attempt.fill(0); this.#registration?.recipient.fill(0); this.#registration?.incarnation.fill(0); this.#clientTLS.fill(0); this.#serverTLS.fill(0); this.#dependency.release(); })();
  }
}
export function isRegisteredLiveTunnelServerControl(value: unknown, runtime: ReturnType<typeof originalEnvironment>): value is RegisteredLiveTunnelControlAuthority { return value instanceof RegisteredLiveTunnelControlAuthority && controls.has(value) && value.belongsTo(runtime); }
export async function createRegisteredLiveTunnelControlAuthority(options: RegisteredLiveTunnelControlAuthorityOptions): Promise<RegisteredLiveTunnelControlAuthority> {
  const authority = new RegisteredLiveTunnelControlAuthority(capability, options); try { await authority.listen(options.host, options.port); return authority; } catch (error) { await authority.close(); throw error; }
}
function encodeRequest(request: V4LiveAuthorizationRequest, authority: string): Readonly<Record<string, string | number>> {
  const result: Record<string, string | number> = { authority, tenant: request.tenant, audience: request.audience, cryptoProfile: request.cryptoProfile, candidateIndex: request.candidateIndex, activationNotAfterMS: request.activationNotAfterMS.toString(), attemptNo: request.attemptNo };
  for (const field of ["issuer", "lease", "attempt", "artifact", "clientIdentity", "serverIdentity", "candidateID", "routeDigest"] as const) result[field] = b64(request[field]); return Object.freeze(result);
}
function decodeRequest(input: Readonly<Record<string, string | number>>): V4LiveAuthorizationRequest {
  requireCredential(Object.keys(input).length === 15 && typeof input.authority === "string" && typeof input.tenant === "string" && typeof input.audience === "string" && typeof input.cryptoProfile === "string" && typeof input.activationNotAfterMS === "string" && /^(?:0|[1-9][0-9]{0,19})$/u.test(input.activationNotAfterMS) && typeof input.candidateIndex === "number" && input.attemptNo === 1, "credential_binding");
  requireCredential(Number.isSafeInteger(input.candidateIndex) && input.candidateIndex >= 0 && input.candidateIndex < 16 && BigInt(input.activationNotAfterMS) > 0n && BigInt(input.activationNotAfterMS) <= 0xffffffffffffffffn, "credential_binding");
  const owned: Uint8Array[] = []; const decode = (value: unknown, size: number): Uint8Array => { const result = bytes(value, size, size); owned.push(result); return result; };
  try { return Object.freeze({ authority: input.authority, tenant: input.tenant, audience: input.audience, cryptoProfile: input.cryptoProfile, candidateIndex: input.candidateIndex, activationNotAfterMS: BigInt(input.activationNotAfterMS), attemptNo: 1,
    issuer: decode(input.issuer, 16), lease: decode(input.lease, 16), attempt: decode(input.attempt, 16), artifact: decode(input.artifact, 32), clientIdentity: decode(input.clientIdentity, 32), serverIdentity: decode(input.serverIdentity, 32), candidateID: decode(input.candidateID, 16), routeDigest: decode(input.routeDigest, 32) }); } catch (error) { for (const value of owned) value.fill(0); throw error; }
}
function clearRequest(request: V4LiveAuthorizationRequest): void { for (const value of Object.values(request)) if (value instanceof Uint8Array) value.fill(0); }
export interface RegisteredLiveTunnelClientOptions {
  readonly control: RegisteredTunnelControlClientOptions;
  readonly material: LiveTunnelAuthorityOptions["material"];
}
/** A's ordinary live provider submits one original identity-proof request over
 * mTLS. The signed response is installed only by the original client exchange. */
export function createRegisteredLiveTunnelClientAuthorization(environment: V4TransportEnvironment, options: RegisteredLiveTunnelClientOptions): V4LiveAuthorizationConfig {
  const runtime = originalEnvironment(environment), dependency = runtime.admitDependency("registered_live_client_control", charge(runtime.resources.runtimeBytes));
  let state: RegisteredControlClientState | undefined, decoder: CBORDecoder | undefined, relayWork: CredentialWork | undefined, used = false, closed = false;
  let providerDone: Promise<void> | undefined, preparationAck: Promise<void> | undefined, closing: Promise<void> | undefined;
  let acquiredReference: ResourceReference | undefined;
  let phase: "unbound" | "bound" | "preparing" | "prepared" | "authorizing" | "delivered" | "handed_off" | "failed" = "unbound";
  let preparedProjection: Readonly<{ attempt: Uint8Array; candidateID: Uint8Array; routeDigest: Uint8Array; candidateIndex: number }> | undefined;
  try {
    requireCredential(options.control.identityKey instanceof KeyObject && options.control.identityKey.type === "private" && options.control.identityKey.asymmetricKeyType === "ed25519" && typeof options.control.workMS === "bigint" && options.control.workMS > 0n && options.control.workMS <= 60000n && Number.isSafeInteger(options.material.candidateIndex) && options.material.candidateIndex >= 0 && options.material.candidateIndex < 16, "configuration_capacity");
    const digest = credentialDigest("artifact_digest", options.material.artifact), incarnation = new Uint8Array(32);
    try { runtime.fillRandom(incarnation); const endpoint = new URL(options.control.endpoint); requireCredential(endpoint.protocol === "https:" && endpoint.pathname === "/flowersec/control/live" && endpoint.search === "" && endpoint.hash === "" && endpoint.username === "" && endpoint.password === "", "configuration_capacity");
      const relayControl = captureRegisteredRelayControl(options.control.relayControl, options.control.tls);
      const control = Object.freeze({ ...options.control, ...(relayControl === undefined ? {} : { relayControl }), tls: Object.freeze({ certificatePEM: tlsText(options.control.tls.certificatePEM), privateKeyPEM: tlsText(options.control.tls.privateKeyPEM), trustPEM: tlsText(options.control.tls.trustPEM) }) });
      state = { runtime, reference: dependency.reference, deployment: control, endpoint, parent: b64(digest), candidate: options.material.candidateIndex, incarnation: b64(incarnation), abort: new AbortController(), delivered: false, busy: false, closed: false, pending: undefined };
    } finally { digest.fill(0); incarnation.fill(0); }
    requireCredential(state !== undefined, "credential_binding");
    const original = state;
    if (original.deployment.relayControl !== undefined) {
      const config = Object.freeze({ bytes: 73728, nodes: 8, textBytes: 32, arrayItems: 3, runtimeBytes: runtime.resources.runtimeBytes });
      const reference = runtime.reserveConnectionWork("registered_live_client_relay_response", cborDecoderCharge(config));
      try { decoder = new CBORDecoder(config, reference); } finally { reference.release(); }
      const grantReference = runtime.reserveConnectionWork("registered_live_client_relay_grant", credentialWorkCharge(65536, runtime.resources.runtimeBytes));
      try { relayWork = new CredentialWork(runtime.resources, 65536, grantReference); relayWork.prepayParsers(65536, 16384, 1); } finally { grantReference.release(); }
    }
    const cleanup = (): Promise<void> => {
      if (closing !== undefined) return closing;
      closed = true; original.closed = true; original.abort.abort();
      // Withdrawal fences publication immediately; the original material Account
      // and position remain borrowed through every physical writer/reader tail.
      return closing = (async () => {
        await Promise.allSettled([original.pending, providerDone, preparationAck].filter((value): value is Promise<void> => value !== undefined));
        decoder?.close(); relayWork?.close(); preparedProjection?.attempt.fill(0); preparedProjection?.candidateID.fill(0); preparedProjection?.routeDigest.fill(0);
        acquiredReference?.release(); acquiredReference = undefined;
      })();
    };
    const withdraw = (): void => { if (phase !== "handed_off") phase = "failed"; void cleanup(); };
    dependency.onClose(() => {
      withdraw();
      // The installed control/TLS graph remains Environment-owned after phase
      // retirement; only its actual owner shutdown releases that fixed charge.
      void cleanup().finally(() => { dependency.release(); });
    });
    const config = bindLiveAuthorizationConfig(runtime, Object.freeze({ maxConcurrentRequests: 1, runtimeBytes: runtime.resources.runtimeBytes, providerBytes: 4194304n,
      requestAuthorization: async (request: V4LiveAuthorizationRequest, destination: Uint8Array, operation: Readonly<{ signal: AbortSignal; check(): void }>): Promise<number> => {
        requireCredential(!closed && !used && phase === "prepared", "credential_closed"); used = true; phase = "authorizing"; dependency.check(); operation.check();
        const deadline = TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), original.deployment.workMS, request.activationNotAfterMS), backing = new Uint8Array(1152);
        // The acquired material borrow belongs to cleanup(), which joins
        // providerDone before releasing it. A borrow cannot be borrowed again.
        const relayBacking = original.deployment.relayControl === undefined ? undefined : new Uint8Array(75008), custody = acquiredReference!;
        let resolveProvider!: () => void; providerDone = new Promise(resolve => { resolveProvider = resolve; });
        const invocation = { signal: operation.signal, check: (): void => { custody.check(); dependency.check(); operation.check(); deadline.check(); requireCredential(!closed && !original.closed, "credential_closed"); }, remainingMS: (): bigint => deadline.remainingMS() };
        let signature: Uint8Array | undefined, response: Uint8Array | undefined, proof: Uint8Array | undefined, grant: Uint8Array | undefined;
        try {
          runtime.fillRandom(backing.subarray(0, 32)); const encoded = encodeLiveAuthorizationRequest(request, backing.subarray(32));
          if (relayBacking !== undefined) {
            requireCredential(request.candidateIndex === 0 && request.candidateIndex === original.candidate && request.attemptNo === 1 && b64(request.artifact) === original.parent && preparedProjection !== undefined &&
              preparedProjection.candidateIndex === request.candidateIndex && equalCredential(preparedProjection.attempt, request.attempt) && equalCredential(preparedProjection.candidateID, request.candidateID) && equalCredential(preparedProjection.routeDigest, request.routeDigest), "credential_binding");
            await preparationAck; invocation.check();
            // The SDK invokes this provider only after physical network Prepare.
            // The original request bytes survive every stage through handoff.
            await callRegisteredRelayControl(original, "/tunnel/relay-prepare", encoded, invocation);
          }
          const authentication = backing.subarray(0, encoded.length + 32); signature = new Uint8Array(sign(null, authentication, original.deployment.identityKey));
          // The registered control endpoint has its own installed authority;
          // the verified Artifact retains the original spend authority.
          const reply = await callRegisteredControl(original, { kind: "live_authorize", incarnation: original.incarnation, parent: original.parent, candidate: original.candidate, authentication: b64(authentication), signature: b64(signature), request: encodeRequest(request, original.deployment.authority) }, invocation);
          response = bytes(reply.grant, 73728); requireCredential(response.length > 0 && response.length <= destination.length, "configuration_capacity");
          if (relayBacking !== undefined) {
            const doc = decoder!.decode(response);
            try {
              requireCredential(doc.sameEnvironment(custody) && doc.kind() === "array" && doc.size() === 3, "control_response_invalid");
              const label = doc.firstChild(), activation = doc.nextSibling(label), localGrant = doc.nextSibling(activation);
              requireCredential(doc.kind(label) === "text" && doc.text(label) === "live-tunnel-material-1" && doc.kind(activation) === "bytes" && doc.size(activation) > 0 && doc.size(activation) <= 4096 &&
                doc.kind(localGrant) === "bytes" && doc.size(localGrant) > 0 && doc.size(localGrant) <= 9302 && doc.nextSibling(localGrant) < 0, "control_response_invalid");
              proof = new Uint8Array(doc.size(activation)); grant = new Uint8Array(doc.size(localGrant)); doc.copyPayload(activation, proof); doc.copyPayload(localGrant, grant);
            } finally { doc.release(); }
            // Preserve verified TxA independently of the subsequent relay handoff.
            observeOriginalLiveSpend(operation, proof!);
            const local = relayWork!.parse(grant!, "Grant", 65536);
            let attempt: Uint8Array | undefined, route: Uint8Array | undefined, parent: Uint8Array | undefined;
            try {
              const namespace = local.field("namespace"), parentRef = local.field("parent_ref");
              attempt = local.bytes("attempt_id"); route = local.bytes("route_digest"); parent = local.bytes("artifact_digest", parentRef, "GrantParentRef");
              // Refuse any server-role projection before crossing A's boundary.
              // Relay and original SDK still independently verify all signatures.
              requireCredential(local.uint("role_mask", namespace, "GrantNamespace") === 5n && equalCredential(attempt, request.attempt) && equalCredential(route, request.routeDigest) && equalCredential(parent, request.artifact), "credential_binding");
            } finally { local.close(); attempt?.fill(0); route?.fill(0); parent?.fill(0); }
            const envelope = new FixedCBORWriter(relayBacking).array(4).data(new TextEncoder().encode("tunnel-relay-activate-client-1"), true).data(encoded).data(proof!).data(grant!).result();
            // Only A's own signed local Grant crosses this control boundary.
            // Exact CBOR true precedes the original SDK response installation.
            await callRegisteredRelayControl(original, "/tunnel/relay-activate-client", envelope, invocation);
          }
          invocation.check(); destination.set(response); operation.check(); phase = "delivered"; return response.length;
        } catch (error) { withdraw(); throw error; } finally { backing.fill(0); relayBacking?.fill(0); signature?.fill(0); response?.fill(0); proof?.fill(0); grant?.fill(0); resolveProvider(); }
      } }), (input, reference) => {
        requireCredential(!closed && phase === "unbound" && input.source === "live_authority" && (input.candidateIndex ?? 0) === original.candidate && reference.sameEnvironment(dependency.reference), "credential_binding");
        const parent = credentialDigest("artifact_digest", input.artifact);
        try { requireCredential(b64(parent) === original.parent, "credential_binding"); } finally { parent.fill(0); }
        acquiredReference = reference.borrow(); phase = "bound";
        return Object.freeze({ withdraw, handoff: (): void => {
          requireCredential(!closed && phase === "delivered", "credential_binding");
          // The SDK's original verified response installation is terminal.
          phase = "handed_off"; void cleanup();
        } });
      }, () => { if (phase === "unbound") withdraw(); });
    const announce = async (fields: ClientPreparationFields, signal: AbortSignal): Promise<void> => {
      // cleanup() retains the original material through preparationAck.
      const custody = acquiredReference!;
      const deadline = TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), original.deployment.workMS, 0xffffffffffffffffn);
      const invocation = { signal, check: (): void => { custody.check(); dependency.check(); fields.preparationDeadline.check(); deadline.check(); requireCredential(!closed && !original.closed && !signal.aborted); }, remainingMS: (): bigint => deadline.remainingMS() };
      if (original.deployment.relayControl !== undefined) {
        const reference = runtime.reserveConnectionWork("registered_live_client_relay_route", credentialWorkCharge(16384, runtime.resources.runtimeBytes));
        let work: CredentialWork | undefined, listens = false;
        try {
          work = new CredentialWork(runtime.resources, 16384, reference); const route = work.parse(fields.route, "Route", 16384);
          try {
            const leg = route.field("client_leg"), listener = route.uint("listener_role", leg, "Leg");
            requireCredential(route.uint("path_kind") === 1n && route.uint("endpoint_role", leg, "Leg") === 0n && (listener === 0n || listener === 2n), "credential_binding"); listens = listener === 0n;
          } finally { route.close(); }
        } finally { work?.close(); reference.release(); }
        if (listens) {
          const backing = new Uint8Array(192);
          try { await callRegisteredRelayControl(original, "/tunnel/relay-ready", encodeRegisteredRelayReady(fields.artifactDigest, fields.candidateID, fields.routeDigest, 0, backing), invocation); }
          finally { backing.fill(0); }
        }
      }
      const reply = await callRegisteredControl(original, { kind: "live_client_prepared", incarnation: original.incarnation, parent: original.parent, candidate: original.candidate, attempt: b64(fields.attempt) }, invocation);
      requireCredential(reply.prepared === true, "credential_binding");
    };
    return bindOriginalLiveCarrierPreparation(runtime, config, async (fields, signal) => {
      requireCredential(!closed && !used && fields.source === "live_authority" && fields.pathKind === 1 && b64(fields.artifactDigest) === original.parent, "credential_binding");
      // Bind-before-accept and the later selected SDK projection observe one
      // original readiness continuation, never a second physical notification.
      try {
        if (preparedProjection === undefined) {
          requireCredential(phase === "bound", "credential_binding"); phase = "preparing";
          preparedProjection = Object.freeze({ attempt: new Uint8Array(fields.attempt), candidateID: new Uint8Array(fields.candidateID), routeDigest: new Uint8Array(fields.routeDigest), candidateIndex: fields.candidateIndex });
          preparationAck = (async () => {
            try { await announce(fields, signal); requireCredential(!closed && !signal.aborted, "credential_closed"); phase = "prepared"; }
            catch (error) { withdraw(); throw error; }
          })(); void preparationAck.catch(() => undefined);
        } else requireCredential(preparedProjection.candidateIndex === fields.candidateIndex && equalCredential(preparedProjection.attempt, fields.attempt) && equalCredential(preparedProjection.candidateID, fields.candidateID) && equalCredential(preparedProjection.routeDigest, fields.routeDigest), "credential_binding");
        await observeTask(preparationAck!, signal); fields.preparationDeadline.check(); requireCredential(!closed && !signal.aborted, "credential_closed");
      } catch (error) { withdraw(); throw error; }
    });
  } catch (error) { if (state !== undefined) { state.closed = true; state.abort.abort(); } decoder?.close(); relayWork?.close(); dependency.release(); throw error; }
}
for (const owner of [OriginalRemoteLivePublication, RegisteredLiveTunnelControlAuthority]) { Object.freeze(owner.prototype); Object.freeze(owner); }
