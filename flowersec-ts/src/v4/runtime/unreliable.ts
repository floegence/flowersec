import type { OperationOptions } from "../../public/contract.js";
import { V4UnreliableMessageError, type V4UnreliableMessages, type V4UnreliableMessage, type V4UnreliableSendOptions, type V4UnreliableSendResult } from "../unreliable.js";
import { CBORDecoder, cborDecoderCharge, byteLength } from "./cbor.js";
import { EnvelopeDecoder, envelopeDecoderCharge, type EnvelopeFrame } from "./envelope.js";
import { DirectionKeyPositions, directionKeyCharge } from "./maintenancePositions.js";
import { FixedCBORWriter } from "./openAdmission.js";
import { RecordCryptoError, type CryptoUsageLedger } from "./cryptoUsage.js";
import type { RecordCipher, RecordCipherConfig, RecordEpoch, RecordPacket, RecordAuthorization } from "./recordCrypto.js";
import { ResourceVector, type ResourceRoot, type ResourceReference } from "./resources.js";
import type { TrustedClock } from "./clock.js";
import { TrustedDeadline } from "./deadline.js";
import { TimeError } from "./timeArithmetic.js";
import { observeTask } from "./taskObservation.js";
import { datagramScope, wire } from "./wireRegistry.js";

export interface NativeDatagrams {
  maxDatagramBytes(): number;
  /** The actual read owns its native position until return, including cancel. */
  receive(maxBytes: number, options?: OperationOptions): Promise<Uint8Array>;
  /** Returned completion alone ends the original ciphertext borrow. */
  submit(bytes: Uint8Array, admitted: () => void): Readonly<{ completion: Promise<void> }> | undefined;
}
const envelopeBytes = wire.resource_caps.max_datagram_envelope, pending = wire.resource_caps.max_pending_datagrams;
const payloadBytes = wire.resource_caps.max_datagram_payload;
const datagramFrameType = (() => {
  const value = wire.frame_types.DATAGRAM;
  if (value === undefined || !Number.isSafeInteger(value)) throw new Error("wire_registry");
  return value;
})();
const decoderConfig = (runtimeBytes: bigint) => ({ bytes: envelopeBytes, nodes: 32, textBytes: 0, arrayItems: 4, runtimeBytes });
export function unreliableCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  const cipher = { maxFrame: envelopeBytes - 8, runtimeBytes };
  return [new ResourceVector([runtimeBytes + BigInt(pending * (2 * payloadBytes + 512) + 4 * envelopeBytes + 2048), 0n, 0n,
    BigInt(2 * pending + 8), 1n, BigInt(pending + 2), 2n, 0n, 0n, 0n, 1n]),
    envelopeDecoderCharge({ ...cipher, mode: "message" }), cborDecoderCharge(decoderConfig(runtimeBytes)),
    directionKeyCharge(cipher), directionKeyCharge(cipher), directionKeyCharge(cipher), directionKeyCharge(cipher)];
}
/** Original pre-acquisition key positions, parsers and bounded buffers. READY
 * activates this owner without allocating replacement headroom. */
export class UnreliablePreparation {
  reference: ResourceReference | undefined;
  envelope: EnvelopeDecoder | undefined;
  decoder: CBORDecoder | undefined;
  sendKeys: DirectionKeyPositions | undefined;
  receiveKeys: DirectionKeyPositions | undefined;
  readonly sendStorage = Array.from({ length: pending }, () => new Uint8Array(payloadBytes));
  readonly receiveStorage = Array.from({ length: pending }, () => new Uint8Array(payloadBytes));
  readonly encode = new Uint8Array(envelopeBytes);
  readonly output = new Uint8Array(envelopeBytes);
  readonly plain = new Uint8Array(envelopeBytes);
  readonly decoded = new Uint8Array(payloadBytes);
  #closed = false;
  #claimed = false;
  constructor(root: ResourceRoot, runtimeBytes: bigint, references: readonly ResourceReference[], ledger: CryptoUsageLedger) {
    const costs = unreliableCharges(runtimeBytes), cipher = { maxFrame: envelopeBytes - 8, runtimeBytes };
    if (references.length !== costs.length) throw new Error("configuration_capacity");
    try {
      this.reference = references[0]!.take(costs[0]!);
      this.envelope = new EnvelopeDecoder({ ...cipher, mode: "message" }, references[1]!);
      this.decoder = new CBORDecoder(decoderConfig(runtimeBytes), references[2]!);
      this.sendKeys = new DirectionKeyPositions(root, cipher, references.slice(3, 5), ledger, datagramScope, ledger.sendDirection);
      this.receiveKeys = new DirectionKeyPositions(root, cipher, references.slice(5, 7), ledger, datagramScope, ledger.sendDirection === 0 ? 1 : 0);
    } catch (error) { this.close(); throw error; }
  }
  claim(reference: ResourceReference): void {
    if (this.#closed || this.#claimed || this.reference?.sameEnvironment(reference) !== true) throw new Error("owner_unavailable");
    this.#claimed = true;
  }
  retire(): void { this.#claimed = false; this.close(); }
  close(): void {
    if (this.#claimed) return;
    this.#closed = true; this.envelope?.close(); this.decoder?.close(); this.sendKeys?.close(); this.receiveKeys?.close();
    if (this.sendKeys?.cleanupComplete() === false || this.receiveKeys?.cleanupComplete() === false) return;
    for (const bytes of [...this.sendStorage, ...this.receiveStorage, this.encode, this.output, this.plain, this.decoded]) bytes.fill(0);
    const reference = this.reference; this.reference = undefined; reference?.release();
  }
  cleanupComplete(): boolean { return this.#closed && this.reference === undefined && this.sendKeys?.cleanupComplete() !== false && this.receiveKeys?.cleanupComplete() !== false; }
}
interface Host {
  readonly clock: TrustedClock;
  readonly runtimeBytes: bigint;
  readonly ledger: CryptoUsageLedger;
  readonly profile: string;
  check(): void;
  available(): boolean;
  recordCheck: RecordAuthorization["check"];
  changed(): void;
  failed(): void;
  dropped?(epoch: "current" | "old" | "future"): void;
}
interface SendJob {
  readonly slot: number; readonly size: number; readonly deadline: TrustedDeadline; readonly signal?: AbortSignal;
  readonly promise: Promise<V4UnreliableSendResult>;
  resolve(value: V4UnreliableSendResult): void; reject(error: Error): void;
}
interface QueuedMessage { readonly slot: number; readonly size: number; readonly epoch: number; readonly sequence: bigint }
export class UnreliableRuntime implements V4UnreliableMessages {
  readonly #abort = new AbortController();
  readonly #jobs: SendJob[] = [];
  readonly #messages: QueuedMessage[] = [];
  readonly #freeSend = Array.from({ length: pending }, (_, index) => index);
  readonly #freeReceive = Array.from({ length: pending }, (_, index) => index);
  #send: RecordCipher | undefined;
  #receive: RecordCipher | undefined;
  #epoch = -1;
  #reading = false;
  #writing = false;
  #reader: Promise<void> | undefined;
  #writer: Promise<void> | undefined;
  #waiter: (() => void) | undefined;
  #receiveActive = false;
  #closed = false;
  #frozen = false;
  #retired = false;
  #maximum = 0;
  constructor(private readonly prepared: UnreliablePreparation, private readonly provider: NativeDatagrams,
    private readonly host: Host, epoch: RecordEpoch, number: number, reference: ResourceReference) {
    prepared.claim(reference);
    try {
      const actual = provider.maxDatagramBytes();
      if (!Number.isSafeInteger(actual) || actual < 76) throw new V4UnreliableMessageError("unavailable");
      this.#maximum = Math.min(payloadBytes, Math.min(actual, envelopeBytes) - 75); this.replaceEpoch(epoch, number);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void {
    if (this.#closed) throw new V4UnreliableMessageError("closed");
    try { this.prepared.reference!.check(); this.host.check(); }
    catch { throw new V4UnreliableMessageError(this.#closed ? "closed" : "operation_failed"); }
    if (this.#closed) throw new V4UnreliableMessageError("closed");
  }
  #currentMaximum(): number {
    let actual: number;
    try { actual = this.provider.maxDatagramBytes(); } catch { return 0; }
    return Number.isSafeInteger(actual) && actual >= 76 ? Math.min(payloadBytes, Math.min(actual, envelopeBytes) - 75) : 0;
  }
  maxMessageBytes() { this.#check(); this.#maximum = this.#currentMaximum(); return Object.freeze({ bytes: BigInt(this.#maximum), scope: "local_submission" as const }); }
  receiveStatus() { this.#check(); return this.host.ledger.datagramReceiveStatus(); }
  start(): void {
    this.#check(); if (this.#reader !== undefined) throw new Error("owner_unavailable");
    this.#reading = true; this.#reader = this.#readLoop();
    void this.#reader.finally(() => { this.#reader = undefined; this.#reading = false; this.#finish(); }).catch(() => this.host.failed());
  }
  replaceEpoch(epoch: RecordEpoch, number: number): void {
    if (this.#writing) throw new Error("configuration_capacity");
    const config: RecordCipherConfig = { maxFrame: envelopeBytes - 8, runtimeBytes: this.host.runtimeBytes };
    const authorization: RecordAuthorization = { check: (frame, header, direction) => {
      this.#check();
      if (frame !== datagramFrameType || header.scope !== datagramScope || header.epoch !== this.#epoch || this.#frozen || !this.host.available()) throw new Error("datagram_unavailable");
      this.host.recordCheck(frame, header, direction); this.#check();
      if (header.epoch !== this.#epoch || this.#frozen || !this.host.available()) throw new Error("datagram_unavailable");
    } };
    const refs: ResourceReference[] = [];
    let send: RecordCipher | undefined, receive: RecordCipher | undefined;
    try {
      const sendRef = this.prepared.sendKeys!.checkout(); refs.push(sendRef);
      const receiveRef = this.prepared.receiveKeys!.checkout(); refs.push(receiveRef);
      send = epoch.derive(datagramScope, this.host.ledger.sendDirection, config, authorization, sendRef, this.prepared.sendKeys!.usage);
      receive = epoch.derive(datagramScope, this.host.ledger.sendDirection === 0 ? 1 : 0, config, authorization, receiveRef, this.prepared.receiveKeys!.usage);
      this.#send?.close(); this.#receive?.close(); this.#send = send; this.#receive = receive; send = receive = undefined;
      this.#epoch = number; this.#frozen = false; this.#clearMessages(); this.host.changed();
    } finally { send?.close(); receive?.close(); for (const ref of refs) ref.release(); }
  }
  freeze(): void {
    this.#frozen = true;
    for (const job of this.#jobs.splice(0)) this.#settle(job, "dropped_budget");
    this.#clearMessages(); this.#waiter?.(); this.host.changed();
  }
  pendingOutput(): boolean { return this.#writing; }
  async send(message: Uint8Array, options: V4UnreliableSendOptions): Promise<V4UnreliableSendResult> {
    const signal = options?.signal, expiry = options?.expiresAtMS;
    this.#check(); if (signal?.aborted) throw new V4UnreliableMessageError("canceled");
    this.#check();
    let size: number; try { size = byteLength(message); } catch { throw new V4UnreliableMessageError("invalid_message"); }
    this.#maximum = this.#currentMaximum();
    if (size > this.#maximum) throw new V4UnreliableMessageError("too_large");
    if (typeof expiry !== "bigint" || expiry < 0n || expiry > 0xffffffffffffffffn) throw new V4UnreliableMessageError("invalid_message");
    let deadline: TrustedDeadline;
    try { deadline = new TrustedDeadline(this.host.clock, expiry); deadline.check(); }
    catch (error) { if (error instanceof TimeError && error.code === "time_expired") return "dropped_expired"; throw new V4UnreliableMessageError("operation_failed"); }
    if (this.#frozen || !this.host.available() || this.#freeSend.length === 0) return "dropped_budget";
    const slot = this.#freeSend.shift()!;
    let resolve!: SendJob["resolve"], reject!: SendJob["reject"];
    const promise = new Promise<V4UnreliableSendResult>((yes, no) => { resolve = yes; reject = no; });
    const job: SendJob = { slot, size, deadline, ...(signal === undefined ? {} : { signal }), promise, resolve, reject };
    this.prepared.sendStorage[slot]!.set(message); this.#jobs.push(job); this.#drive();
    return observeTask(promise, signal, () => new V4UnreliableMessageError("canceled"));
  }
  #settle(job: SendJob, result: V4UnreliableSendResult | Error): void {
    this.prepared.sendStorage[job.slot]!.fill(0); this.#freeSend.push(job.slot);
    if (result instanceof Error) job.reject(result); else job.resolve(result);
  }
  #drive(): void {
    if (this.#writing || this.#closed || this.#jobs.length === 0) return;
    this.#writing = true; this.#writer = this.#writeLoop();
    void this.#writer.then(() => { this.#writer = undefined; this.#writing = false; this.host.changed(); this.#drive(); this.#finish(); }, () => {
      this.#writer = undefined; this.#writing = false; this.host.failed(); this.#finish();
    });
  }
  async #writeLoop(): Promise<void> {
    while (!this.#closed && this.#jobs.length !== 0) {
      const job = this.#jobs.shift()!; let packet: RecordPacket | undefined;
      let result: V4UnreliableSendResult | Error = "dropped_carrier";
      try {
        this.#check(); if (job.signal?.aborted) throw new V4UnreliableMessageError("canceled");
        try { job.deadline.check(); } catch (error) { if (!(error instanceof TimeError) || error.code !== "time_expired") throw error; result = "dropped_expired"; continue; }
        if (this.#frozen || !this.host.available()) { result = "dropped_budget"; continue; }
        if (job.size > this.#currentMaximum()) { result = "dropped_carrier"; continue; }
        const cipher = this.#send!, frontier = cipher.frontier();
        const body = new FixedCBORWriter(this.prepared.encode).map(4).uint(0).uint(frontier.epoch).uint(1).uint(frontier.next)
          .uint(2).uint(datagramScope).uint(3).data(this.prepared.sendStorage[job.slot]!.subarray(0, job.size)).result();
        packet = cipher.seal(datagramFrameType, body); this.prepared.encode.fill(0);
        // Sealing irreversibly charges this key even if native submission
        // drops the packet. Wake safety while this writer still owns its tail.
        this.host.changed();
        const count = packet.copyBytes(this.prepared.output);
        let admitted = false;
        const submission = this.provider.submit(this.prepared.output.subarray(0, count), () => {
          this.#check(); job.deadline.check();
          if (job.size > this.#currentMaximum()) throw new Error("datagram_mtu_changed");
          if (admitted || this.#send !== cipher || this.#epoch !== frontier.epoch || this.#frozen || !this.host.available()) throw new Error("datagram_unavailable");
          admitted = true;
        });
        if (submission === undefined) { if (admitted) throw new Error("invalid_native_submission"); result = "dropped_carrier"; }
        else {
          // Even a broken provider must retain the original output borrow
          // through its actual completion before the fixed buffer is reused.
          await submission.completion;
          if (!admitted) throw new Error("invalid_native_submission");
          result = "accepted";
        }
      } catch (error) { result = error instanceof V4UnreliableMessageError ? error : error instanceof TimeError && error.code === "time_expired" ? "dropped_expired" : error instanceof RecordCryptoError && (error.code === "crypto_usage_exhausted" || error.code === "datagram_key_budget") ? "dropped_budget" : "dropped_carrier"; }
      finally { packet?.release(); this.prepared.encode.fill(0); this.prepared.output.fill(0); if (typeof result === "string" && result !== "accepted") this.host.dropped?.("current"); this.#settle(job, result); }
    }
  }
  async #readLoop(): Promise<void> {
    try {
      while (!this.#closed) {
        const bytes = await this.provider.receive(envelopeBytes, { signal: this.#abort.signal });
        try { this.#accept(bytes); } finally { bytes.fill(0); }
      }
    } catch { if (!this.#closed) this.host.failed(); }
  }
  #accept(bytes: Uint8Array): void {
    let frame: EnvelopeFrame | undefined, packet: RecordPacket | undefined;
    let accepted = false;
    let delivered = false, dropEpoch: "current" | "old" | "future" = "current";
    let document: ReturnType<CBORDecoder["decodeMap"]> | undefined;
    try {
      this.#check(); if (this.#frozen || !this.host.available()) return;
      if (this.host.ledger.datagramReceiveStatus().state !== "available") { this.#waiter?.(); return; }
      frame = this.prepared.envelope!.message(bytes);
      const header = frame.recordHeader(this.host.profile), cipher = this.#receive!;
      dropEpoch = header.epoch < this.#epoch ? "old" : header.epoch > this.#epoch ? "future" : "current";
      if (header.frameType !== datagramFrameType || header.scope !== datagramScope || header.epoch !== this.#epoch) return;
      packet = cipher.open(frame);
      const count = packet.copyBytes(this.prepared.plain);
      document = this.prepared.decoder!.decodeMap(this.prepared.plain.subarray(0, count), "DATAGRAM");
      if (document.uint(document.field(0, 0)) !== BigInt(header.epoch) || document.uint(document.field(0, 1)) !== header.sequence ||
          document.uint(document.field(0, 2)) !== datagramScope) throw new Error("invalid_datagram");
      const size = document.copyPayload(document.field(0, 3), this.prepared.decoded);
      packet.observeValidation(() => {
        this.#check(); if (this.#receive !== cipher || this.#epoch !== header.epoch || this.#frozen || !this.host.available()) throw new Error("datagram_unavailable");
      });
      // Replay/good-use and finite queue choice share this synchronous owner
      // turn. A full queue consumes replay eligibility and drops the result.
      packet.commitValidated();
      accepted = true;
      const slot = this.#freeReceive.shift();
      if (slot !== undefined) {
        this.prepared.receiveStorage[slot]!.set(this.prepared.decoded.subarray(0, size));
        this.#messages.push({ slot, size, epoch: header.epoch, sequence: header.sequence }); delivered = true; this.#waiter?.();
      }
    } catch { this.#waiter?.(); }
    finally {
      document?.release(); packet?.release(); frame?.release(); this.prepared.plain.fill(0); this.prepared.decoded.fill(0);
      this.prepared.envelope?.discardUnpublished();
      // Wake after the synchronous acceptance/queue turn is complete, so a
      // rekey freeze cannot be followed by another old-epoch queue insertion.
      if (accepted) this.host.changed();
      if (!delivered) this.host.dropped?.(dropEpoch);
    }
  }
  async receive(options?: OperationOptions): Promise<V4UnreliableMessage> {
    const signal = options?.signal;
    if (this.#receiveActive) throw new V4UnreliableMessageError("operation_failed");
    this.#receiveActive = true;
    try { for (;;) {
      this.#check(); if (signal?.aborted) throw new V4UnreliableMessageError("canceled");
      const status = this.host.ledger.datagramReceiveStatus();
      if (status.state !== "available") throw new V4UnreliableMessageError(status.state, status.retryAfterMS);
      const message = this.#messages.shift();
      if (message !== undefined) {
        const data = this.prepared.receiveStorage[message.slot]!.slice(0, message.size);
        this.prepared.receiveStorage[message.slot]!.fill(0); this.#freeReceive.push(message.slot);
        return data;
      }
      await new Promise<void>((resolve, reject) => {
        const cancel = () => { this.#waiter = undefined; signal?.removeEventListener("abort", cancel); reject(new V4UnreliableMessageError("canceled")); };
        this.#waiter = () => { this.#waiter = undefined; signal?.removeEventListener("abort", cancel); resolve(); };
        signal?.addEventListener("abort", cancel, { once: true }); if (signal?.aborted) cancel();
      });
    } } finally { this.#receiveActive = false; this.#finish(); }
  }
  #clearMessages(): void {
    for (const message of this.#messages.splice(0)) { this.prepared.receiveStorage[message.slot]!.fill(0); this.#freeReceive.push(message.slot); }
  }
  close(): void {
    if (!this.#closed) {
      this.#closed = true; this.#abort.abort(); this.#send?.close(); this.#receive?.close(); this.#clearMessages();
      for (const job of this.#jobs.splice(0)) this.#settle(job, new V4UnreliableMessageError("closed"));
      this.#waiter?.();
    }
    this.#finish();
  }
  #finish(): void {
    if (this.#retired || !this.#closed || this.#reading || this.#writing || this.#receiveActive || this.#send?.cleanupComplete() === false || this.#receive?.cleanupComplete() === false) return;
    this.#retired = true; this.prepared.retire(); this.host.changed();
  }
  cleanupComplete(): boolean { return this.#closed && !this.#reading && !this.#writing && !this.#receiveActive && this.prepared.cleanupComplete(); }
}
