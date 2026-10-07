import type { OperationOptions } from "../../public/contract.js";
import type { V4AuthenticatedTransport } from "./session.js";
import type { CredentialResources, OwnedCredentialMap } from "./credentialSupport.js";
import { CredentialWork, credentialWorkCharge, credentialOwner, requireCredential, equalCredential } from "./credentialSupport.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { EnvelopeDecoder, envelopeDecoderCharge, type EnvelopeFrame } from "./envelope.js";
import { FixedCBORWriter } from "./openAdmission.js";
import type { TrustedDeadline } from "./deadline.js";
import { timerChunk } from "./deadline.js";
import type { RandomFill } from "./random.js";
import type { ReadyIdentitySigner } from "./noiseHandshake.js";
import { wire } from "./wireRegistry.js";
import { isVerifiedRelayCredentials, isVerifiedRelayClaim, type VerifiedRelayCredentials, type VerifiedRelayClaim } from "./relayCredentials.js";

export function hopAuthenticationCharge(runtimeBytes: bigint): ResourceVector {
  requireCredential(runtimeBytes > 0n, "configuration_capacity");
  return new ResourceVector([262144n + runtimeBytes, 0n, 0n, 8n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
/** Parser, envelope and exchange positions owned before credential acquisition.
 * The envelope has the same bounded backing for stream and message ingress. */
export class HopAuthenticationPreparation {
  #reference: ResourceReference | undefined; #work: CredentialWork | undefined; #envelope: ResourceReference | undefined;
  constructor(resources: CredentialResources) {
    const charges = [hopAuthenticationCharge(resources.runtimeBytes), credentialWorkCharge(65536, resources.runtimeBytes), envelopeDecoderCharge({ maxFrame: 65536, mode: "stream", runtimeBytes: resources.runtimeBytes })];
    const refs = resources.root.reserveBatch(charges.map((charge, index) => ({ owner: credentialOwner(resources, `hop_preparation_${index}`), accounts: resources.accounts, charge })));
    try {
      this.#reference = refs[0]!.take(charges[0]!); this.#work = new CredentialWork(resources, 65536, refs[1]!); this.#work.prepayParsers(65536, 32768, 2); this.#envelope = refs[2]!.take(charges[2]!); Object.freeze(this);
    } catch (error) { this.close(); throw error; } finally { for (const ref of refs) ref.release(); }
  }
  take(reference: ResourceReference): Readonly<{ reference: ResourceReference; work: CredentialWork; envelope: ResourceReference }> {
    requireCredential(this.#reference !== undefined && this.#work !== undefined && this.#envelope !== undefined && this.#reference.sameEnvironment(reference));
    this.#reference.check(); this.#work.check(); this.#envelope.check(); const result = { reference: this.#reference, work: this.#work, envelope: this.#envelope };
    this.#reference = undefined; this.#work = undefined; this.#envelope = undefined; return Object.freeze(result);
  }
  close(): void { this.#work?.close(); this.#work = undefined; this.#envelope?.release(); this.#envelope = undefined; this.#reference?.release(); this.#reference = undefined; }
}
export interface HopAuthenticationConfig {
  readonly resources: CredentialResources;
  readonly transport: V4AuthenticatedTransport;
  readonly credentials: VerifiedRelayCredentials;
  readonly localRole: 0 | 1 | 2;
  readonly localIncarnation: Uint8Array;
  readonly random: RandomFill;
  readonly signer: ReadyIdentitySigner;
  readonly deadline: TrustedDeadline;
  readonly guard: () => void;
  readonly acceptedHello?: Uint8Array;
  readonly meter?: Readonly<{ reserve(bytes: number): Promise<(actual: number | undefined) => void> }>;
}
/** One four-flight exchange over the actual maintenance carrier. The physical
 * dialer sends HELLO first. End-to-end admission receives the very next byte;
 * no hop reader reads ahead or grants an endpoint Session. */
export class HopAuthentication {
  readonly #config: HopAuthenticationConfig;
  readonly #reference: ResourceReference;
  readonly #work: CredentialWork;
  readonly #decoder: EnvelopeDecoder;
  readonly #input = new Uint8Array(65536);
  readonly #output = new Uint8Array(65544);
  readonly #incarnation: Uint8Array;
  readonly #challenge = new Uint8Array(32);
  #acceptedHello: Uint8Array | undefined;
  #context: Uint8Array | undefined;
  #remoteIncarnation: Uint8Array | undefined;
  #remoteChallenge: Uint8Array | undefined;
  #running = false; #started = false; #closed = false; #cleaned = false;
  constructor(config: HopAuthenticationConfig, reservation: ResourceReference | HopAuthenticationPreparation, environmentReference?: ResourceReference) {
    requireCredential(isVerifiedRelayCredentials(config.credentials) && (config.localRole === 2 || config.localRole === config.credentials.role) && config.localIncarnation.length === 16 && config.localIncarnation.some(value => value !== 0), "configuration_capacity");
    this.#config = Object.freeze({ ...config, ...(config.acceptedHello === undefined ? {} : { acceptedHello: config.acceptedHello }) }); this.#acceptedHello = config.acceptedHello === undefined ? undefined : new Uint8Array(config.acceptedHello); this.#incarnation = new Uint8Array(config.localIncarnation);
    const backing = reservation instanceof HopAuthenticationPreparation ? reservation.take(environmentReference!) : undefined;
    this.#reference = (backing?.reference ?? reservation as ResourceReference).take(hopAuthenticationCharge(config.resources.runtimeBytes)); let work: CredentialWork | undefined = backing?.work, decoder: EnvelopeDecoder | undefined;
    try {
      this.#check(); config.random(this.#challenge); requireCredential(this.#challenge.some(value => value !== 0));
      if (backing !== undefined) {
        this.#work = backing.work; requireCredential(this.#work.sameEnvironment(this.#reference));
        this.#decoder = decoder = new EnvelopeDecoder({ maxFrame: 65536, mode: config.transport.mode, runtimeBytes: config.resources.runtimeBytes }, backing.envelope);
      } else {
        const request = (kind: string, charge: ResourceVector) => ({ owner: credentialOwner(config.resources, kind), accounts: config.resources.accounts, charge });
        const references = config.resources.root.reserveBatch([request("hop_authentication_work", credentialWorkCharge(65536, config.resources.runtimeBytes)), request("hop_authentication_envelope", envelopeDecoderCharge({ maxFrame: 65536, mode: config.transport.mode, runtimeBytes: config.resources.runtimeBytes }))]);
        try { this.#work = work = new CredentialWork(config.resources, 65536, references[0]!); work.prepayParsers(65536, 32768, 2); this.#decoder = decoder = new EnvelopeDecoder({ maxFrame: 65536, mode: config.transport.mode, runtimeBytes: config.resources.runtimeBytes }, references[1]!); }
        finally { for (const reference of references) reference.release(); }
      }
    } catch (error) { decoder?.close(); work?.close(); this.#incarnation.fill(0); this.#challenge.fill(0); this.#acceptedHello?.fill(0); this.#input.fill(0); this.#output.fill(0); this.#reference.release(); throw error; }
    finally { backing?.envelope.release(); backing?.reference.release(); }
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#reference.check(); this.#config.deadline.check(); this.#config.credentials.check(this.#reference); this.#config.guard(); this.#config.transport.checkPreparation?.(); requireCredential(!this.#closed, "credential_closed"); }
  #encode(build: (writer: FixedCBORWriter) => void): Uint8Array { this.#input.fill(0); const writer = new FixedCBORWriter(this.#input); build(writer); const output = new Uint8Array(writer.result()); this.#input.fill(0); return output; }
  async #send(payload: Uint8Array): Promise<void> {
    this.#check(); const output = this.#output.subarray(0, payload.length + 8); output.fill(0); new DataView(output.buffer).setUint32(0, payload.length); output[4] = wire.frame_types.HOP_AUTH!; output.set(payload, 8);
    const settle = await this.#config.meter?.reserve(output.length);
    let charged = false, admitted = false, receipt: Readonly<{ completion: Promise<void> }> | undefined;
    try {
      receipt = this.#config.transport.submit(output, () => { this.#check(); requireCredential(!admitted); admitted = true; });
      if (receipt !== undefined) await receipt.completion;
      requireCredential(receipt !== undefined && admitted, "credential_closed"); settle?.(output.length); charged = true; this.#check();
    } catch (error) { if (!charged) { if (!admitted || receipt === undefined) settle?.(0); else settle?.(undefined); } throw error; } finally { output.fill(0); }
  }
  async #read(schema: string, options: OperationOptions | undefined, senderRole?: "endpoint" | "relay"): Promise<OwnedCredentialMap> {
    this.#check(); const transport = this.#config.transport; let frame: EnvelopeFrame;
    if (transport.mode === "message") { const settle = await this.#config.meter?.reserve(65544); let bytes: Uint8Array | null; try { bytes = await transport.read(65544, options); settle?.(bytes?.length ?? 0); } catch (error) { settle?.(undefined); throw error; } this.#check(); requireCredential(bytes !== null); frame = this.#decoder.message(bytes); }
    else {
      const prefix = new Uint8Array(8); let count = 0, expected = 8, result: EnvelopeFrame | undefined;
      try {
        while (result === undefined) {
          const maximum = Math.min(16384, expected - count), settle = await this.#config.meter?.reserve(maximum); let bytes: Uint8Array | null; try { bytes = await transport.read(maximum, options); settle?.(bytes?.length ?? 0); } catch (error) { settle?.(undefined); throw error; } this.#check(); requireCredential(bytes !== null && bytes.length > 0 && bytes.length <= expected - count);
          if (count < 8) prefix.set(bytes, count); const progress = this.#decoder.push(bytes); requireCredential(progress.consumed === bytes.length); count += progress.consumed; result = progress.frame;
          if (count === 8) expected = 8 + new DataView(prefix.buffer).getUint32(0);
        }
        frame = result;
      } finally { prefix.fill(0); }
    }
    try { requireCredential(frame.frameType() === wire.frame_types.HOP_AUTH); const count = frame.copyPayload(this.#input); return this.#work.parse(this.#input.subarray(0, count), schema, 65536, 16384, senderRole === undefined ? {} : { selectors: { hop_sender_role: senderRole } }); }
    finally { frame.release(); this.#input.fill(0); }
  }
  #hello(): Uint8Array {
    const config = this.#config, endpoint = config.localRole !== 2, certificate = config.credentials.certificate(endpoint ? "endpoint" : "relay", this.#reference), grant = endpoint ? config.credentials.grant(this.#reference) : undefined;
    try { return this.#encode(writer => { writer.map(endpoint ? 5 : 4).uint(0).uint(0).uint(1).data(this.#incarnation).uint(2).data(this.#challenge); if (grant !== undefined) writer.uint(3).data(grant); writer.uint(4).data(certificate); }); }
    finally { grant?.fill(0); certificate.fill(0); }
  }
  async #exchangeHello(options?: OperationOptions): Promise<void> {
    const config = this.#config, descriptor = config.credentials.descriptor(this.#reference), leg = this.#work.parse(descriptor, "Leg", 16384, 16384, { selectors: { path_kind: "tunnel" } }); descriptor.fill(0);
    let hello: OwnedCredentialMap | undefined, payload: Uint8Array | undefined;
    try {
      const dialerRole = Number(leg.uint("dialer_role")), listenerRole = Number(leg.uint("listener_role")); requireCredential(dialerRole === config.localRole || listenerRole === config.localRole);
      const localDialer = dialerRole === config.localRole, remoteIsRelay = config.localRole !== 2;
      if (localDialer) { payload = this.#hello(); await this.#send(payload); payload.fill(0); payload = undefined; }
      if (this.#acceptedHello !== undefined) {
        requireCredential(!localDialer); const bytes = this.#acceptedHello; this.#acceptedHello = undefined;
        try { hello = this.#work.parse(bytes, "HOP_AUTH_HELLO", 65536, 16384, { selectors: { hop_sender_role: remoteIsRelay ? "relay" : "endpoint" } }); } finally { bytes.fill(0); }
      } else hello = await this.#read("HOP_AUTH_HELLO", options, remoteIsRelay ? "relay" : "endpoint");
      const expectedCertificate = config.credentials.certificate(remoteIsRelay ? "relay" : "endpoint", this.#reference);
      try { requireCredential(equalCredential(hello.bytes("identity_certificate"), expectedCertificate)); }
      finally { expectedCertificate.fill(0); }
      if (!remoteIsRelay) { const expectedGrant = config.credentials.grant(this.#reference); try { requireCredential(equalCredential(hello.bytes("grant"), expectedGrant)); } finally { expectedGrant.fill(0); } }
      this.#remoteIncarnation = hello.bytes("local_incarnation"); this.#remoteChallenge = hello.bytes("local_challenge");
      requireCredential(!equalCredential(this.#remoteIncarnation, this.#incarnation) && !equalCredential(this.#remoteChallenge, this.#challenge));
      if (!localDialer) { payload = this.#hello(); await this.#send(payload); payload.fill(0); payload = undefined; }
      this.#context = this.#encode(writer => writer.map(7).uint(0).data(localDialer ? this.#incarnation : this.#remoteIncarnation!).uint(1).data(localDialer ? this.#remoteIncarnation! : this.#incarnation)
        .uint(2).data(leg.bytes("leg_id")).uint(3).uint(dialerRole).uint(4).uint(listenerRole).uint(5).data(localDialer ? this.#challenge : this.#remoteChallenge!).uint(6).data(localDialer ? this.#remoteChallenge! : this.#challenge));
    } finally { payload?.fill(0); hello?.close(); leg.close(); }
  }
  async #run<T>(operation: () => Promise<T>, options?: OperationOptions): Promise<T> {
    this.#check(); requireCredential(!this.#started); this.#started = true; this.#running = true; const config = this.#config; let timer: ReturnType<typeof setTimeout> | undefined;
    const cancel = (): void => { this.close(); void config.transport.close(); };
    const tick = (): void => { try { this.#check(); timer = setTimeout(tick, timerChunk(config.deadline.remainingMS())); } catch { cancel(); } };
    options?.signal?.addEventListener("abort", cancel, { once: true }); tick(); if (options?.signal?.aborted) cancel();
    try {
      this.#check(); const result = await operation();
      try { this.#check(); return result; } catch (error) { if (isVerifiedRelayClaim(result)) result.close(); throw error; }
    }
    catch (error) { cancel(); throw error; }
    finally { if (timer !== undefined) clearTimeout(timer); options?.signal?.removeEventListener("abort", cancel); this.#running = false; this.#cleanup(); }
  }
  authenticateEndpoint(options?: OperationOptions): Promise<void> {
    requireCredential(this.#config.localRole !== 2);
    return this.#run(async () => {
      await this.#exchangeHello(options); const proof = this.#config.credentials.signPossession(this.#context!, this.#config.localRole, this.#config.signer, this.#reference);
      let reply: OwnedCredentialMap | undefined; const payload = this.#encode(writer => writer.map(2).uint(0).uint(1).uint(1).data(proof));
      try { await this.#send(payload); reply = await this.#read("HOP_AUTH_RELAY_PROOF", options); this.#config.credentials.verifyPossession(this.#context!, 2, reply.bytes("proof"), this.#reference); }
      finally { proof.fill(0); payload.fill(0); reply?.close(); }
    }, options);
  }
  /** Dispatch is supplied by the SDK's original durable claim owner. The
   * owner must commit claimed before invoking publish exactly once. A duplicate
   * claim/readback/reopen never receives this original signing continuation. */
  authenticateRelay(dispatch: (claim: VerifiedRelayClaim, publish: () => Promise<void>) => Promise<void>, options?: OperationOptions): Promise<VerifiedRelayClaim> {
    requireCredential(this.#config.localRole === 2 && typeof dispatch === "function");
    return this.#run(async () => {
      await this.#exchangeHello(options); const proof = await this.#read("HOP_AUTH_ENDPOINT_PROOF", options); let claim: VerifiedRelayClaim | undefined;
      try {
        claim = this.#config.credentials.bindClaim(this.#context!, proof.bytes("proof"), this.#reference); let published = false;
        await dispatch(claim, async () => {
          this.#check(); requireCredential(!published); published = true;
          const signature = this.#config.credentials.signPossession(this.#context!, 2, this.#config.signer, this.#reference), payload = this.#encode(writer => writer.map(2).uint(0).uint(2).uint(1).data(signature));
          try { await this.#send(payload); } finally { signature.fill(0); payload.fill(0); }
        });
        requireCredential(published); this.#check(); return claim;
      } catch (error) { claim?.close(); throw error; } finally { proof.close(); }
    }, options);
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void { if (!this.#closed || this.#running || this.#cleaned) return; this.#cleaned = true; this.#input.fill(0); this.#output.fill(0); this.#incarnation.fill(0); this.#challenge.fill(0); this.#acceptedHello?.fill(0); this.#context?.fill(0); this.#remoteChallenge?.fill(0); this.#remoteIncarnation?.fill(0); this.#decoder.close(); this.#work.close(); this.#reference.release(); }
  cleanupComplete(): boolean { return this.#cleaned; }
}

for (const constructor of [HopAuthentication, HopAuthenticationPreparation]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
