import { sha256 } from "@noble/hashes/sha2.js";
import type { OperationOptions } from "../../public/contract.js";
import { CredentialWork, credentialWorkCharge, credentialDigest, equalCredential, requireCredential, type CredentialResources, type OwnedCredentialMap } from "./credentialSupport.js";
import type { ClientPreparationFields, VerifiedCredentialClosure } from "./credentialVerifier.js";
import { EnvelopeDecoder, envelopeDecoderCharge, type EnvelopeFrame } from "./envelope.js";
import { FixedCBORWriter } from "./openAdmission.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { table, wireDomains } from "./schemaRegistry.js";
import type { ReadyIdentitySigner, ReadyConfig } from "./noiseHandshake.js";
import type { V4AuthenticatedTransport } from "./session.js";
import { timerChunk } from "./deadline.js";
import { wire } from "./wireRegistry.js";
import type { RandomFill } from "./random.js";
import { observeTask } from "./taskObservation.js";

export interface ClientAdmissionResult {
  readonly context: Uint8Array; readonly contextDigest: Uint8Array; readonly fsb: Uint8Array; readonly fsa: Uint8Array;
  readonly selected: bigint; readonly ready: ReadyConfig;
}
export class V4AdmissionRejected extends Error {
  constructor(readonly rejectionCode: bigint) { super("admission_rejected"); this.name = "V4AdmissionRejected"; }
}
export function clientAdmissionCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([524288n + runtimeBytes, 0n, 0n, 16n, 1n, 2n, 1n, 0n, 0n, 0n, 0n]);
}
export function clearClientPreparation(fields: ClientPreparationFields): void {
  for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0);
  for (const values of [fields.identities, fields.noiseKeys, fields.identityKeys]) for (const value of values) value.fill(0);
}
function input(name: string, parts: readonly Uint8Array[]): Uint8Array {
  const domain = wireDomains.find(d => d.name === name);
  requireCredential(domain !== undefined && domain.input_schema.parts.length === parts.length && domain.input_schema.parts.every(p => p.encoding === "lp-map"));
  const label = Uint8Array.from(domain.label_bytes.match(/../gu)!.map(b => Number.parseInt(b, 16)));
  const output = new Uint8Array(label.length + parts.reduce((n, p) => n + 4 + p.length, 0)); output.set(label); let at = label.length;
  for (const p of parts) { new DataView(output.buffer).setUint32(at, p.length); at += 4; output.set(p, at); at += p.length; }
  return output;
}
function text(writer: FixedCBORWriter, value: string): FixedCBORWriter { return writer.data(new TextEncoder().encode(value), true); }

/** The original once-invoked admission exchange, owned before durable consume.
 * Only its Environment invokes run after definite TxA-P success. */
export class ClientAdmissionExchange {
  readonly #reference: ResourceReference;
  readonly #work: CredentialWork;
  readonly #decoder: EnvelopeDecoder;
  readonly #buffer = new Uint8Array(65536);
  readonly #output = new Uint8Array(65544);
  readonly #payload = new Uint8Array(65536);
  readonly #retained: Uint8Array[] = [];
  #started = false;
  #closed = false;
  #running = false;
  readonly #cancellation = new AbortController();
  readonly #bindingMode: bigint;
  readonly #exporter = new Uint8Array(32);
  #activation: Uint8Array;
  constructor(readonly resources: CredentialResources, readonly closure: VerifiedCredentialClosure, readonly fields: ClientPreparationFields,
    private readonly signer: ReadyIdentitySigner, private readonly random: RandomFill, reservation: ResourceReference,
    private readonly transport: V4AuthenticatedTransport, bindingMode: "direct_exporter" | "authenticated_context" = "authenticated_context") {
    requireCredential(equalCredential(signer.publicKey, fields.identityKeys[0]!));
    requireCredential(bindingMode === "direct_exporter" || bindingMode === "authenticated_context", "configuration_capacity");
    this.#bindingMode = bindingMode === "direct_exporter" ? 0n : 1n;
    this.#reference = reservation.take(clientAdmissionCharge(resources.runtimeBytes));
    this.#activation = new Uint8Array(fields.activation);
    let work: CredentialWork | undefined, decoder: EnvelopeDecoder | undefined;
    try {
      const request = (kind: string, charge: ResourceVector) => ({ owner: { ...resources.owner, kind }, accounts: resources.accounts, charge });
      const refs = resources.root.reserveBatch([request("client_admission_work", credentialWorkCharge(65536, resources.runtimeBytes)),
        request("client_admission_envelope", envelopeDecoderCharge({ maxFrame: 65536, mode: transport.mode, runtimeBytes: resources.runtimeBytes }))]);
      try {
        this.#work = work = new CredentialWork(resources, 65536, refs[0]!);
        this.#decoder = decoder = new EnvelopeDecoder({ maxFrame: 65536, mode: transport.mode, runtimeBytes: resources.runtimeBytes }, refs[1]!);
        work.prepaySignatures(65536, 16384);
        work.prepayParsers(65536, 16384, 3);
        closure.prepayHandshakeChecks(this.#reference);
      } finally { for (const ref of refs) ref.release(); }
      closure.checkPreparation(this.#reference);
      if (this.#bindingMode === 0n) {
        if (transport.role !== "client" || typeof transport.exportBinding !== "function") throw new Error("required_guarantee_unavailable");
        transport.checkPreparation?.();
        const value = transport.exportBinding(fields.artifactDigest);
        try { if (value.length !== 32) throw new Error("required_guarantee_unavailable"); this.#exporter.set(value); }
        finally { value.fill(0); }
        transport.checkPreparation?.(); closure.checkPreparation(this.#reference);
      }
    } catch (error) { this.#exporter.fill(0); this.#activation.fill(0); work?.close(); decoder?.close(); this.#reference.release(); throw error; }
  }
  #keep(value: Uint8Array): Uint8Array { this.#retained.push(value); return value; }
  installLiveAuthorization(bytes: Uint8Array): void {
    requireCredential(!this.#closed && !this.#started && this.fields.source === "live_authority" && this.#activation.length === 0, "credential_binding");
    this.closure.installLiveAuthorization(bytes, this.#reference);
    this.#activation = new Uint8Array(bytes);
  }
  #encode(build: (writer: FixedCBORWriter) => void): Uint8Array {
    this.#buffer.fill(0); const writer = new FixedCBORWriter(this.#buffer); build(writer); return this.#keep(new Uint8Array(writer.result()));
  }
  run(transport: V4AuthenticatedTransport, options?: OperationOptions): Promise<ClientAdmissionResult> {
    requireCredential(!this.#closed && !this.#started && this.#activation.length > 0 && transport === this.transport && transport.role === "client" &&
    (transport.mode === "message" || transport.mode === "stream")); this.#started = true;
    this.#running = true;
    const actual = this.#run(transport, options).finally(() => { this.#running = false; this.#cleanup(); });
    return observeTask(actual, this.#cancellation.signal, () => this.#cancellation.signal.reason);
  }
  async #run(transport: V4AuthenticatedTransport, options?: OperationOptions): Promise<ClientAdmissionResult> {
    const f = this.fields, work = this.#work;
    let timer: ReturnType<typeof setTimeout> | undefined, failure: unknown;
    const guard = (): void => { if (failure !== undefined) throw failure; if (this.#closed || options?.signal?.aborted) throw new Error("canceled"); this.closure.checkPreparation(this.#reference); };
    const abort = (): void => { failure ??= new Error("canceled"); this.#cancellation.abort(failure); void transport.close(); };
    const tick = (): void => {
      try { guard(); timer = setTimeout(tick, timerChunk(f.preparationDeadline.remainingMS())); }
      catch (error) { failure = error; this.#cancellation.abort(error); void transport.close(); }
    };
    const send = async (name: string, payload: Uint8Array): Promise<void> => {
      guard(); const output = this.#output.subarray(0, payload.length + 8); output.fill(0); new DataView(output.buffer).setUint32(0, payload.length);
      output[4] = wire.frame_types[name]!; output.set(payload, 8);
      let accepted = false;
      const submission = transport.submit(output, () => { guard(); requireCredential(!accepted); accepted = true; });
      requireCredential(submission !== undefined && accepted, "credential_closed"); await submission.completion; output.fill(0); guard();
    };
    const read = async (name: string, schema: string, cap: number): Promise<OwnedCredentialMap> => {
      guard();
      let frame: EnvelopeFrame;
      if (transport.mode === "message") {
        const bytes = await transport.read(65544, options); guard(); requireCredential(bytes !== null, "credential_closed");
        frame = this.#decoder.message(bytes);
      } else {
        // Read exactly this envelope. No admission-owned read-ahead may steal
        // the first Noise bytes when the stream passes to the handshake owner.
        const prefix = new Uint8Array(8);
        let read = 0, expected = 8, candidate: EnvelopeFrame | undefined;
        try {
          while (candidate === undefined) {
            const bytes = await transport.read(expected - read, options); guard();
            requireCredential(bytes !== null && bytes.byteLength > 0 && bytes.byteLength <= expected - read, "credential_closed");
            if (read < 8) prefix.set(bytes, read);
            const progress = this.#decoder.push(bytes);
            requireCredential(progress.consumed === bytes.byteLength);
            read += progress.consumed; candidate = progress.frame;
            if (read === 8) expected = 8 + new DataView(prefix.buffer).getUint32(0);
          }
          frame = candidate;
        } finally { prefix.fill(0); }
      }
      try { requireCredential(frame.frameType() === wire.frame_types[name] && frame.payloadBytes() <= cap); const size = frame.copyPayload(this.#payload); return work.parse(this.#payload.subarray(0, size), schema, cap); }
      finally { frame.release(); this.#payload.fill(0); }
    };
    options?.signal?.addEventListener("abort", abort, { once: true }); tick();
    let server: OwnedCredentialMap | undefined, admission: OwnedCredentialMap | undefined;
    try {
      guard();
      transport.checkPreparation?.(); transport.activate?.(); guard();
      const offered = 0n; requireCredential(f.required === 0n, "credential_untrusted");
      const hello = this.#encode(w => {
        w.map(11).uint(0); text(w, table<string>("protocol_id")!); w.uint(1); text(w, table<string>("profile_revision")!); w.uint(2); text(w, f.profile);
        w.uint(3).data(f.artifactDigest).uint(4).data(f.candidateID).uint(5).data(f.routeDigest).uint(6).data(f.attempt).uint(7).data(f.nonce)
          .uint(8).uint(offered).uint(9).uint(1n << this.#bindingMode).uint(10).data(new Uint8Array());
      });
      const client = work.parse(hello, "ClientHello", 16384); client.close();
      await send("NEGOTIATE", hello); server = await read("NEGOTIATE", "ServerHello", 16384);
      for (const [name, expected] of [["artifact_digest", f.artifactDigest], ["candidate_id", f.candidateID], ["route_digest", f.routeDigest], ["attempt_id", f.attempt], ["client_nonce", f.nonce]] as const)
        requireCredential(equalCredential(server.bytes(name), expected));
      requireCredential(server.text("crypto_profile_id") === f.profile && server.bytes("server_nonce").some(n => n !== 0) && server.uint("binding_mode") === this.#bindingMode);
      const selected = f.allowed & offered & server.uint("server_offered_features"); requireCredential(server.uint("selected_features") === selected && (selected & f.required) === f.required);
      const transcriptInput = input("hello_transcript_digest", [hello, server.encoded()]), transcript = this.#keep(sha256(transcriptInput)); transcriptInput.fill(0);
      const context = this.#encode(w => {
        w.map(13).uint(0); text(w, table<string>("profile_revision")!); w.uint(1); text(w, f.profile);
        w.uint(2).uint(0).uint(3).uint(0).uint(4).data(f.artifactDigest).uint(5).data(f.routeDigest).uint(6).data(f.attempt).uint(7).data(f.nonce)
          .uint(8).data(transcript).uint(9).uint(selected).uint(10).uint(this.#bindingMode).uint(11).uint(this.#bindingMode === 0n ? 1 : 0).uint(12).data(this.#exporter.subarray(0, this.#bindingMode === 0n ? 32 : 0));
      });
      const contextMap = work.parse(context, "TransportContext", 2048); contextMap.close(); const contextDigest = this.#keep(credentialDigest("transport_context_digest", context));
      const nonce = new Uint8Array(32); this.#keep(nonce); this.random(nonce); requireCredential(nonce.some(n => n !== 0));
      const fsbFields = (w: FixedCBORWriter): void => {
        w.uint(0).data(f.artifactDigest).uint(1); text(w, f.tenant); w.uint(2).data(f.issuer).uint(3).data(f.lease).uint(4).data(f.nonce)
          .uint(5).data(f.candidateID).uint(6).data(f.routeDigest).uint(7).data(f.attempt).uint(8).data(nonce).uint(9).data(transcript)
          .uint(10).uint(selected).uint(11).uint(this.#bindingMode).uint(12).data(contextDigest).uint(13).data(this.#activation).uint(14).data(f.clientCertificate);
      };
      const unsigned = this.#encode(w => { w.map(15); fsbFields(w); }), signingInput = input("fsb_signature", [unsigned]);
      let signature: Uint8Array;
      try { signature = this.#keep(this.signer.sign(signingInput)); requireCredential(signature.length === 64); } finally { signingInput.fill(0); }
      const fsb = this.#encode(w => { w.map(16); fsbFields(w); w.uint(15).data(signature); });
      const signed = work.parse(fsb, "FSB4", 65536, 16384, { selectors: { activation_source_profile: f.source } });
      try { work.verify(signed, f.identityKeys[0]!, { selectors: { activation_source_profile: f.source } }); } finally { signed.close(); }
      const binding = this.#keep(credentialDigest("admission_binding", fsb));
      await send("ADMISSION", fsb); admission = await read("ADMISSION_RESULT", "FSA4", 16384);
      this.closure.authenticateAdmission(admission, work, this.#reference);
      requireCredential(equalCredential(admission.bytes("route_digest"), f.routeDigest) && equalCredential(admission.bytes("hello_transcript_digest"), transcript) &&
        admission.uint("selected_features") === selected && admission.uint("binding_mode") === this.#bindingMode);
      if (admission.uint("status") !== 0n) throw new V4AdmissionRejected(admission.uint("code"));
      requireCredential(admission.uint("code") === 0n && equalCredential(admission.bytes("transport_context_digest"), contextDigest) && equalCredential(admission.bytes("admission_binding"), binding) &&
        equalCredential(admission.bytes("client_identity_digest"), f.identities[0]!) && equalCredential(admission.bytes("server_identity_digest"), f.identities[1]!));
      const fsa = this.#keep(admission.encoded()); guard();
      return Object.freeze({ context, contextDigest, fsb, fsa, selected, ready: Object.freeze({ localCertificateDigest: f.identities[0]!, peerCertificateDigest: f.identities[1]!,
        fsbDigest: this.#keep(credentialDigest("fsb_digest", fsb)), fsaDigest: this.#keep(credentialDigest("fsa_digest", fsa)), admissionBinding: binding, transportContextDigest: contextDigest, selectedFeatures: selected }) });
    } finally { server?.close(); admission?.close(); if (timer !== undefined) clearTimeout(timer); options?.signal?.removeEventListener("abort", abort); }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#cancellation.abort(new Error("canceled")); this.#cleanup();
  }
  #cleanup(): void {
    if (!this.#closed || this.#running) return;
    for (const bytes of this.#retained) bytes.fill(0); this.#retained.length = 0;
    this.#buffer.fill(0); this.#output.fill(0); this.#payload.fill(0); this.#exporter.fill(0); this.#activation.fill(0); this.#decoder.close(); this.#work.close(); this.#reference.release();
  }
}
