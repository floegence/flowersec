import { transportV4ApplicationHeaders } from "../../generated/transportV4Registry.js";
import type { V4StreamOwner } from "../public.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge, type ApplicationHeader } from "./applicationHeader.js";
import { applicationGroupCharge, type ApplicationGroup } from "./applicationExecutor.js";
import type { NotificationMessage } from "./notifyDispatch.js";
import type { NotifyPreparation, NotifyStartResult } from "./notifyPreparation.js";
import { ResourceVector, type ProtectedResourceReservation, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { acquireRPCStream, type RPCStreamOwner } from "./rpcStream.js";
import { writeRequestCharge, type ReliableWriteRequest } from "./writeRequest.js";

export const notifySpec = transportV4ApplicationHeaders.notify;
export function notifyChannelCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  return [new ResourceVector([4096n + 514n + runtimeBytes * 3n, 0n, 0n, 8n, 2n, 4n, 1n, 0n, 0n, 0n, 0n]),
    new ResourceVector([50304n + runtimeBytes, 0n, 0n, 5n, 6n, 6n, 4n, 0n, 0n, 1n, 0n]), applicationGroupCharge(runtimeBytes),
    applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes), writeRequestCharge(16384, runtimeBytes)];
}
/** Exactly one parser and publisher per admitted notification channel. The
 * framing is uint16 header length, canonical header, then declared payload. */
export class NotifyChannel {
  #reference: ResourceReference | undefined;
  #stream: RPCStreamOwner | undefined;
  #codec: ApplicationHeaderCodec | undefined;
  #position: ProtectedResourceReservation | undefined;
  readonly #abort = new AbortController();
  #headerBuffer = new Uint8Array(514);
  #have = 0;
  #need = 2;
  #header: ApplicationHeader | undefined;
  #offset = 0;
  #input: NotificationMessage | undefined;
  #admit: ((header: ApplicationHeader) => NotificationMessage | undefined) | undefined;
  #operation: NotifyPreparation | undefined;
  #write: ReliableWriteRequest | undefined;
  #closed = false;
  #reading = false;
  #publishing = false;
  #physical = false;
  #collecting = false;
  #changed: (() => void) | undefined;
  constructor(stream: V4StreamOwner, runtimeBytes: bigint, references: readonly ResourceReference[], group: ApplicationGroup,
    position: ProtectedResourceReservation, admit: (header: ApplicationHeader) => NotificationMessage | undefined, changed: () => void) {
    const costs = notifyChannelCharges(runtimeBytes); this.#reference = references[0]!.take(costs[0]!); this.#admit = admit; this.#changed = changed;
    try {
      this.#codec = new ApplicationHeaderCodec(runtimeBytes, references[3]!, references[4]!); this.#position = position;
      this.#stream = acquireRPCStream(stream, { kind: "message", readBytes: 16384, inputBackingBytes: 1, inputEntries: 1,
        gracefulFinishMS: 30000, cleanupMS: 5000, prepaid: references[1]!, application: group });
      if (this.#stream.kind !== notifySpec.kind) throw new RPCProtocolError("notify_kind");
      this.#stream.invalidateWith(() => this.close()); this.#stream.ioEndedWith(() => this.close());
      this.#stream.cleanupWith(() => { this.#physical = true; this.#collect(); });
    } catch (error) { this.#codec?.close(); this.#stream?.rollback(); this.#stream = undefined; this.#reference.release(); this.#reference = undefined; throw error; }
  }
  start(): void { if (this.#reading || this.#closed) return; this.#reading = true; void this.#read(); }
  #feed(bytes: Uint8Array): number {
    let at = 0;
    while (at < bytes.length) {
      if (this.#header === undefined) {
        const n = Math.min(this.#need - this.#have, bytes.length - at);
        this.#headerBuffer.set(bytes.subarray(at, at + n), this.#have); this.#have += n; at += n;
        if (this.#have < this.#need) break;
        if (this.#need === 2) {
          const size = this.#headerBuffer[0]! * 256 + this.#headerBuffer[1]!;
          if (size < 1 || size > 512) throw new RPCProtocolError("notify_header_length"); this.#need += size; continue;
        }
        this.#header = this.#codec!.decode(this.#headerBuffer.subarray(2, this.#need));
        if (this.#header.kind !== "observation_notify" && this.#header.kind !== "execution_notify") throw new RPCProtocolError("notify_kind");
        // Admission failures consume the remaining declared body without
        // allocating another payload and preserve the next framing boundary.
        this.#input = this.#admit!(this.#header); this.#offset = 0;
      }
      const n = Math.min(bytes.length - at, this.#header.payloadBytes - this.#offset);
      if (n !== 0) { this.#input?.write(this.#offset, bytes.subarray(at, at + n)); at += n; this.#offset += n; }
      if (this.#offset === this.#header.payloadBytes) {
        const input = this.#input; this.#input = undefined; this.#header = undefined; this.#have = 0; this.#need = 2; this.#headerBuffer.fill(0); input?.finish();
      }
    }
    return at;
  }
  async #read(): Promise<void> {
    try {
      while (!this.#closed) {
        await this.#stream!.readInto(16384, bytes => this.#feed(bytes), this.#abort.signal);
        if (this.#closed) break;
        if (this.#stream!.readState().stream_status !== "open") { this.close(); break; }
      }
    } catch { this.close(); }
    finally { this.#reading = false; this.#stream?.releaseReader(); this.#collect(); }
  }
  ready(): boolean { return !this.#closed && this.#reading && this.#operation === undefined && this.#position?.available() === true; }
  submit(operation: NotifyPreparation): NotifyStartResult {
    if (!this.ready()) return Object.freeze({ status: "not_admitted", submission: "not_submitted", reason: this.#closed ? "not_ready" : "resource_exhausted" });
    operation.checkStart(); this.#stream!.check();
    if (!this.ready() || !operation.current()) return Object.freeze({ status: "not_admitted", submission: "not_submitted", reason: "not_ready" });
    operation.admit(() => this.#write?.cancel()); this.#operation = operation; this.#publishing = true; void this.#publish(operation);
    return Object.freeze({ status: "admitted" });
  }
  async #publish(operation: NotifyPreparation): Promise<void> {
    let begun = false, submitted = false, borrow: ReturnType<NotifyPreparation["borrow"]> | undefined;
    const prefix = new Uint8Array(514);
    try {
      borrow = operation.borrow(); const length = operation.header().encode(prefix.subarray(2)); prefix[0] = length >>> 8; prefix[1] = length & 255;
      const publish = async (bytes: Uint8Array): Promise<void> => {
        operation.checkStart(); this.#stream!.check(); const reference = this.#position!.checkout();
        try { this.#write = this.#stream!.prepareFragment(bytes, reference); } finally { reference.release(); }
        this.#write.checkProtocolAdmission(); operation.checkStart();
        if (this.#closed || !operation.current() || !this.#write.admitProtocol()) throw new RPCProtocolError("notify_closed");
        if (!begun) { begun = true; operation.begun(); }
        this.#write.start(); await this.#write.waitCleanup();
        const progress = this.#write.progress();
        if (progress.accepted_bytes !== BigInt(bytes.length) || progress.terminal_reason !== "complete") throw new RPCProtocolError("notify_incomplete");
        this.#write = undefined;
      };
      await publish(prefix.subarray(0, length + 2));
      for (let offset = 0; offset < borrow.bytes.length; offset += 16384) await publish(borrow.bytes.subarray(offset, Math.min(offset + 16384, borrow.bytes.length)));
      submitted = true;
    } catch { if (begun) this.close(); }
    finally {
      if (this.#write !== undefined) { this.#write.terminate(); await this.#write.waitCleanup(); this.#write = undefined; }
      prefix.fill(0); borrow?.release(); this.#operation = undefined; operation.publicationFinished(submitted); this.#publishing = false; this.#collect();
    }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#abort.abort(); this.#input?.close(); this.#input = undefined; this.#admit = undefined;
    this.#write?.terminate(); this.#operation?.close(); this.#position?.closeAfterUse(); const stream = this.#stream;
    if (stream !== undefined) { stream.releaseDelivery(); void stream.reset().catch(() => undefined).finally(() => { this.#physical = stream.cleanupStatus().core_cleanup === "complete"; this.#collect(); }); }
    this.#collect();
  }
  #collect(): void {
    if (this.#collecting || !this.#closed || this.#reading || this.#publishing || !this.#physical || this.#position?.cleanupComplete() === false) return; this.#collecting = true;
    try {
      this.#codec?.close(); this.#codec = undefined; this.#headerBuffer.fill(0); this.#headerBuffer = new Uint8Array(); this.#header = undefined;
      this.#stream?.application.close(); this.#stream?.release(); this.#stream = undefined; this.#position = undefined;
      this.#reference?.release(); this.#reference = undefined; const changed = this.#changed; this.#changed = undefined; changed?.();
    } finally { this.#collecting = false; }
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
