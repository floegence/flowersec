import { applicationResumeFeature } from "./checkpointToken.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { OperationOptions } from "../../public/contract.js";
import { CredentialWork, credentialWorkCharge, credentialDigest, equalCredential, requireCredential, type CredentialResources, type OwnedCredentialMap } from "./credentialSupport.js";
import type { ClientPreparationFields, VerifiedCredentialClosure } from "./credentialVerifier.js";
import { EnvelopeDecoder, envelopeDecoderCharge, type EnvelopeFrame } from "./envelope.js";
import { FixedCBORWriter } from "./openAdmission.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { table, wireDomains } from "./schemaRegistry.js";
import type { ReadyIdentitySigner } from "./noiseHandshake.js";
import type { V4AuthenticatedTransport } from "./session.js";
import type { ClientAdmissionResult } from "./clientAdmission.js";
import { isServerAdmissionAuthority, type ServerAdmissionAuthority, type ServerAdmissionOwner } from "./serverAdmissionAuthority.js";
import type { RandomFill } from "./random.js";
import { wire } from "./wireRegistry.js";

export interface ServerAdmissionTransport extends V4AuthenticatedTransport {
  checkAcceptedRoute(fields: ClientPreparationFields): void;
}
export function serverAdmissionCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([524288n + runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
function input(name: string, parts: readonly Uint8Array[]): Uint8Array {
  const domain = wireDomains.find(d => d.name === name);
  requireCredential(domain !== undefined && domain.input_schema.parts.length === parts.length && domain.input_schema.parts.every(p => p.encoding === "lp-map"));
  const label = Uint8Array.from(domain.label_bytes.match(/../gu)!.map(b => Number.parseInt(b, 16)));
  const output = new Uint8Array(label.length + parts.reduce((n, p) => n + 4 + p.length, 0)); output.set(label); let at = label.length;
  for (const p of parts) { new DataView(output.buffer).setUint32(at, p.length); at += 4; output.set(p, at); at += p.length; } return output;
}
function text(w: FixedCBORWriter, value: string): FixedCBORWriter { return w.data(new TextEncoder().encode(value), true); }
/** Owns the original bounded ingress and handshake bytes. The listener keeps
 * its finite handshake deadline and actual carrier checks alive throughout
 * resolution, authentication, admission, Noise and READY. */
export class ServerAdmissionExchange {
  readonly #reference: ResourceReference;
  readonly #work: CredentialWork;
  readonly #decoder: EnvelopeDecoder;
  readonly #buffer: Uint8Array;
  readonly #output: Uint8Array;
  readonly #retained: Uint8Array[] = [];
  #hello: OwnedCredentialMap | undefined;
  #reading = false;
  readonly #signals: AbortSignal[] = [];
  #started = false;
  #admitting = false;
  #authenticated: { closure: VerifiedCredentialClosure; fields: ClientPreparationFields; context: Uint8Array; contextDigest: Uint8Array; fsb: Uint8Array; transcript: Uint8Array; mode: bigint; selected: bigint } | undefined;
  #running = false;
  #closed = false;
  constructor(readonly resources: CredentialResources, private readonly transport: ServerAdmissionTransport,
    private readonly signer: ReadyIdentitySigner, private readonly random: RandomFill, reference: ResourceReference,
    private readonly guard: () => void, private readonly bindingMode: "direct_exporter" | "authenticated_context") {
    requireCredential(transport.role === "server" && (transport.mode === "message" || transport.mode === "stream"), "configuration_capacity");
    this.#reference = reference.take(serverAdmissionCharge(resources.runtimeBytes));
    let work: CredentialWork | undefined, decoder: EnvelopeDecoder | undefined;
    try {
      this.#buffer = new Uint8Array(65536); this.#output = new Uint8Array(65544);
      const request = (kind: string, charge: ResourceVector) => ({ owner: { ...resources.owner, kind }, accounts: resources.accounts, charge });
      const refs = resources.root.reserveBatch([request("server_admission_work", credentialWorkCharge(65536, resources.runtimeBytes)),
      request("server_admission_envelope", envelopeDecoderCharge({ maxFrame: 65536, mode: transport.mode, runtimeBytes: resources.runtimeBytes }))]);
      try {
        this.#work = work = new CredentialWork(resources, 65536, refs[0]!);
        this.#decoder = decoder = new EnvelopeDecoder({ maxFrame: 65536, mode: transport.mode, runtimeBytes: resources.runtimeBytes }, refs[1]!);
        work.prepaySignatures(65536, 16384); work.prepayParsers(65536, 16384, 3);
      } finally { for (const ref of refs) ref.release(); }
    } catch (error) { decoder?.close(); work?.close(); this.#reference.release(); throw error; }
  }
  #check(): void {
    if (this.#signals.some(signal => signal.aborted)) throw new Error("canceled");
    if (this.#closed) throw new Error("closed"); this.#reference.check(); this.guard(); this.transport.checkPreparation?.();
    if (this.#signals.some(signal => signal.aborted)) throw new Error("canceled");
    if (this.#closed) throw new Error("closed"); this.#reference.check();
  }
  #keep<T extends Uint8Array>(value: T): T { this.#retained.push(value); return value; }
  #encode(build: (w: FixedCBORWriter) => void): Uint8Array {
    this.#buffer.fill(0); const w = new FixedCBORWriter(this.#buffer); build(w); return this.#keep(new Uint8Array(w.result()));
  }
  async #read(name: string, schema: string, cap: number, options?: OperationOptions, source?: string): Promise<OwnedCredentialMap> {
    this.#check();
    let frame: EnvelopeFrame;
    if (this.transport.mode === "message") {
      const bytes = await this.transport.read(65544, options); this.#check(); requireCredential(bytes !== null, "credential_closed");
      frame = this.#decoder.message(bytes);
    } else {
      // Do not read ahead beyond the original admission envelope. The next
      // owner must receive the first Noise byte from the same maintenance bidi.
      const prefix = new Uint8Array(8);
      let read = 0, expected = 8, candidate: EnvelopeFrame | undefined;
      try {
        while (candidate === undefined) {
          const bytes = await this.transport.read(expected - read, options); this.#check();
          requireCredential(bytes !== null && bytes.length > 0 && bytes.length <= expected - read, "credential_closed");
          if (read < 8) prefix.set(bytes, read);
          const progress = this.#decoder.push(bytes);
          requireCredential(progress.consumed === bytes.length, "credential_binding");
          read += progress.consumed; candidate = progress.frame;
          if (read === 8) expected = 8 + new DataView(prefix.buffer).getUint32(0);
        }
        frame = candidate;
      } finally { prefix.fill(0); }
    }
    try {
      requireCredential(frame.frameType() === wire.frame_types[name] && frame.payloadBytes() <= cap);
      const size = frame.copyPayload(this.#buffer);
      return this.#work.parse(this.#buffer.subarray(0, size), schema, cap, 16384, source === undefined ? {} : { selectors: { activation_source_profile: source } });
    } finally { frame.release(); this.#buffer.fill(0); }
  }
  async #send(name: string, payload: Uint8Array): Promise<void> {
    this.#check(); const output = this.#output.subarray(0, payload.length + 8); output.fill(0);
    new DataView(output.buffer).setUint32(0, payload.length); output[4] = wire.frame_types[name]!; output.set(payload, 8);
    let accepted = false;
    const submission = this.transport.submit(output, () => { this.#check(); requireCredential(!accepted); accepted = true; });
    requireCredential(submission !== undefined && accepted, "credential_closed"); await submission.completion; output.fill(0); this.#check();
  }
  /** Borrowed unauthenticated routing input; never application authorization. */
  async readHello(options?: OperationOptions): Promise<Uint8Array> {
    requireCredential(!this.#reading && this.#hello === undefined && !this.#started); this.#reading = true;
    try { this.#hello = await this.#read("NEGOTIATE", "ClientHello", 16384, options); return this.#keep(this.#hello.encoded()); }
    finally { this.#reading = false; this.#cleanup(); }
  }
  prepareClosure(closure: VerifiedCredentialClosure): void {
    this.#check(); requireCredential(!this.#started && this.#hello !== undefined, "credential_binding");
    const hello = this.#hello.encoded();
    try { closure.bindAcceptedLiveAttempt(hello, this.#reference); } finally { hello.fill(0); }
    this.#check();
  }
  async authenticate(closure: VerifiedCredentialClosure, f: ClientPreparationFields, options?: OperationOptions, applicationFeatures = 0n): Promise<void> {
    requireCredential(!this.#started && this.#hello !== undefined);
    if (options?.signal !== undefined) this.#signals.push(options.signal); this.#started = true; this.#running = true;
    let request: OwnedCredentialMap | undefined;
    try {
      this.#check(); this.transport.checkAcceptedRoute(f); closure.checkPreparation(this.#reference); closure.prepayHandshakeChecks(this.#reference);
      requireCredential(equalCredential(this.signer.publicKey, f.identityKeys[1]!));
      const client = this.#hello;
      for (const [name, expected] of [["artifact_digest", f.artifactDigest], ["candidate_id", f.candidateID], ["route_digest", f.routeDigest], ["attempt_id", f.attempt], ["client_nonce", f.nonce]] as const)
        requireCredential(equalCredential(client.bytes(name), expected));
      requireCredential(client.text("crypto_profile_id") === f.profile);
      const mode = this.bindingMode === "direct_exporter" ? 0n : 1n, offered = ((this.transport.nativeDatagrams?.maxDatagramBytes() ?? 0) < 76 ? 0n : 1n) | (f.resume ? applicationFeatures & applicationResumeFeature() : 0n), selected = offered & client.uint("offered_features") & f.allowed;
      requireCredential((selected & f.required) === f.required && (client.uint("supported_binding_modes") & (1n << mode)) !== 0n);
      const nonce = this.#keep(new Uint8Array(32)); this.random(nonce); this.#check(); requireCredential(nonce.some(n => n !== 0));
      const server = this.#encode(w => {
        w.map(13).uint(0); text(w, table<string>("protocol_id")!); w.uint(1); text(w, table<string>("profile_revision")!); w.uint(2); text(w, f.profile);
        w.uint(3).data(f.artifactDigest).uint(4).data(f.candidateID).uint(5).data(f.routeDigest).uint(6).data(f.attempt).uint(7).data(f.nonce)
          .uint(8).data(nonce).uint(9).uint(offered).uint(10).uint(selected).uint(11).uint(mode).uint(12).data(new Uint8Array());
      });
      const parsed = this.#work.parse(server, "ServerHello", 16384); parsed.close();
      const transcriptInput = input("hello_transcript_digest", [client.encoded(), server]), transcript = this.#keep(sha256(transcriptInput)); transcriptInput.fill(0);
      let exporter: Uint8Array = new Uint8Array();
      if (mode === 0n) {
        requireCredential(typeof this.transport.exportBinding === "function", "credential_binding");
        exporter = this.transport.exportBinding(f.artifactDigest); this.#keep(exporter); requireCredential(exporter.length === 32);
      }
      const context = this.#encode(w => {
        w.map(13).uint(0); text(w, table<string>("profile_revision")!); w.uint(1); text(w, f.profile);
        w.uint(2).uint(f.accessClass).uint(3).uint(f.pathKind).uint(4).data(f.artifactDigest).uint(5).data(f.routeDigest).uint(6).data(f.attempt).uint(7).data(f.nonce)
          .uint(8).data(transcript).uint(9).uint(selected).uint(10).uint(mode).uint(11).uint(mode === 0n ? 1 : 0).uint(12).data(exporter);
      });
      const contextDigest = this.#keep(credentialDigest("transport_context_digest", context));
      await this.#send("NEGOTIATE", server); request = await this.#read("ADMISSION", "FSB4", 65536, options, f.source);
      const fsb = this.#keep(request.encoded()); request.close(); request = undefined;
      const binding = closure.authenticateClientAdmission(fsb, context, this.#reference); binding.fill(0);
      this.#check(); this.#authenticated = { closure, fields: f, context, contextDigest, fsb, transcript, mode, selected };
    } finally { request?.close(); this.#running = false; this.#cleanup(); }
  }
  requestContext() {
    this.#check(); const value = this.#authenticated;
    requireCredential(value !== undefined, "credential_binding");
    return value.closure.serverRequestContext(value.fsb, value.context, this.#reference);
  }
  async run(closure: VerifiedCredentialClosure, f: ClientPreparationFields, authority: ServerAdmissionAuthority, owner: ServerAdmissionOwner,
    work: ResourceReference, options?: OperationOptions): Promise<ClientAdmissionResult> {
    requireCredential(!this.#admitting && isServerAdmissionAuthority(authority)); this.#admitting = true;
    if (this.#authenticated === undefined) await this.authenticate(closure, f, options);
    if (options?.signal !== undefined && !this.#signals.includes(options.signal)) this.#signals.push(options.signal);
    const original = this.#authenticated;
    requireCredential(original !== undefined && original.closure === closure && original.fields === f); this.#running = true;
    const { context, contextDigest, fsb, transcript, mode, selected } = original;
    try {
      this.#check(); closure.checkPreparation(this.#reference);
      let fsa: Uint8Array | undefined, binding: Uint8Array | undefined;
      await authority.admit(closure, fsb, context, owner, f.preparationDeadline, work, () => { this.#check(); if (options?.signal?.aborted) throw new Error("canceled"); }, response => {
        binding = this.#keep(new Uint8Array(response.admissionBinding));
        const fields = (w: FixedCBORWriter): void => {
          w.uint(0).uint(0).uint(1).uint(0).uint(2).uint(response.serverEpoch).uint(3).data(response.reservationKey).uint(4).data(response.admissionBinding)
            .uint(5).data(f.routeDigest).uint(6).data(transcript).uint(7).uint(selected).uint(8).uint(mode).uint(9).data(contextDigest)
            .uint(10).data(f.identities[0]!).uint(11).data(f.identities[1]!).uint(12).data(f.serverCertificate);
        };
        const unsigned = this.#encode(w => { w.map(13); fields(w); }), signingInput = input("fsa_signature", [unsigned]);
        let signature: Uint8Array;
        try { signature = this.#keep(this.signer.sign(signingInput)); requireCredential(signature.length === 64); } finally { signingInput.fill(0); }
        this.#check(); closure.checkPreparation(this.#reference);
        fsa = this.#encode(w => { w.map(14); fields(w); w.uint(13).data(signature); });
      });
      requireCredential(fsa !== undefined && binding !== undefined);
      const accepted = this.#work.parse(fsa, "FSA4", 16384);
      try { this.#work.verify(accepted, f.identityKeys[1]!); } finally { accepted.close(); }
      await this.#send("ADMISSION_RESULT", fsa);
      return Object.freeze({
        context, contextDigest, fsb, fsa, selected, ready: Object.freeze({
          localCertificateDigest: f.identities[1]!, peerCertificateDigest: f.identities[0]!,
          fsbDigest: this.#keep(credentialDigest("fsb_digest", fsb)), fsaDigest: this.#keep(credentialDigest("fsa_digest", fsa)), admissionBinding: binding, transportContextDigest: contextDigest, selectedFeatures: selected
        })
      });
    } finally { this.#running = false; this.#cleanup(); }
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#running || this.#reading) return;
    this.#signals.length = 0; this.#authenticated = undefined; this.#hello?.close(); this.#hello = undefined; this.#work.close(); this.#decoder.close();
    this.#buffer.fill(0); this.#output.fill(0); for (const value of this.#retained) value.fill(0); this.#retained.length = 0; this.#reference.release();
  }
}
Object.freeze(ServerAdmissionExchange.prototype); Object.freeze(ServerAdmissionExchange);
