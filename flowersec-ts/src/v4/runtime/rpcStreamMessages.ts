import { acquireResumeStream, type ResumeStreamOwner } from "./resumeStream.js";
import { V4ReadMethodError, type V4StreamOwner } from "../public.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge, type ApplicationHeader } from "./applicationHeader.js";
import { applicationGroupCharge, type ApplicationGroup } from "./applicationExecutor.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCNetwork, RPCNetworkTicket } from "./rpcNetwork.js";
import { ResourceVector, type ResourceReference, type ProtectedResourceReservation } from "./resources.js";
import { acquireRPCStream, type RPCStreamOwner } from "./rpcStream.js";
import { writeRequestCharge, type ReliableWriteRequest } from "./writeRequest.js";
import { timerChunk } from "./deadline.js";
import { TimeError } from "./timeArithmetic.js";

export interface RPCStreamInput {
  write(offset: number, bytes: Uint8Array): void;
  finish(): void;
}
export function rpcStreamMessagesCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  return [new ResourceVector([8192n + runtimeBytes * 8n, 0n, 0n, 16n, 2n, 5n, 2n, 0n, 0n, 0n, 0n]),
    new ResourceVector([50304n + runtimeBytes, 0n, 0n, 5n, 6n, 6n, 4n, 0n, 0n, 1n, 0n]),
    applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes), writeRequestCharge(16384, runtimeBytes), applicationGroupCharge(runtimeBytes)];
}
/** Framing for exactly one dedicated reliable application Stream. There is
 * one persistent input cursor, no prefetch and no per-item transport scope.
 * Both the adapter floor and the original general RPC association are owned
 * before OPEN/ACCEPT. The association survives every physical I/O tail. */
export class RPCStreamMessages {
  #reference: ResourceReference | undefined;
  #stream: RPCStreamOwner | undefined;
  #resume: ResumeStreamOwner | undefined;
  #sentMessages = 0;
  #readMessages = 0;
  #codec: ApplicationHeaderCodec | undefined;
  #position: ProtectedResourceReservation | undefined;
  #network: RPCNetwork | undefined;
  #ticket: RPCNetworkTicket | undefined;
  #releaseNetwork: (() => void) | undefined;
  readonly #abort = new AbortController();
  #prefix = new Uint8Array(514);
  #have = 0;
  #need = 2;
  #header: ApplicationHeader | undefined;
  #input: RPCStreamInput | undefined;
  #offset = 0;
  #candidate = false;
  #reading = false;
  #writing = false;
  #finishing = false;
  #write: ReliableWriteRequest | undefined;
  #closed = false;
  #collecting = false;
  #physical = false;
  #outputClosed = false;
  #inputEOF = false;
  #ioEnded = false;
  #failure: unknown;
  #changed: (() => void) | undefined;
  #group: ApplicationGroup | undefined;
  constructor(runtimeBytes: bigint, references: readonly ResourceReference[], position: ProtectedResourceReservation,
    group: ApplicationGroup) {
    const charges = rpcStreamMessagesCharges(runtimeBytes);
    this.#reference = references[0]!.take(charges[0]!); this.#position = position; this.#group = group;
    try { this.#codec = new ApplicationHeaderCodec(runtimeBytes, references[2]!, references[3]!); }
    catch (error) { this.close(); throw error; }
  }
  bind(network: RPCNetwork, ticket: RPCNetworkTicket): void {
    if (this.#network !== undefined || this.#closed) throw new RPCProtocolError("rpc_stream_owner");
    network.checkStream(ticket, this); this.#releaseNetwork = network.retainStream(ticket, this); this.#network = network; this.#ticket = ticket;
  }
  attach(stream: V4StreamOwner, adapter: ResourceReference): void {
    if (this.#stream !== undefined || this.#closed) throw new RPCProtocolError("rpc_stream_owner");
    this.#stream = acquireRPCStream(stream, { kind: "message", readBytes: 16384, inputBackingBytes: 1, inputEntries: 1,
      gracefulFinishMS: 30000, cleanupMS: 5000, prepaid: adapter, application: this.#group!, preaccepted: true });
    this.#observeStream();
  }
  attachResume(stream: V4StreamOwner, session: object, kind: string, adapter: ResourceReference): ResumeStreamOwner {
    if (this.#stream !== undefined || this.#closed) throw new RPCProtocolError("rpc_stream_owner");
    this.#resume = acquireResumeStream(stream, session, kind, { kind: "message", readBytes: 16384, inputBackingBytes: 1, inputEntries: 1,
      gracefulFinishMS: 30000, cleanupMS: 5000, prepaid: adapter, application: this.#group! });
    this.#stream = this.#resume; this.#observeStream(); return this.#resume;
  }
  #observeStream(): void {
    this.#stream!.invalidateWith(() => this.close());
    this.#stream!.ioEndedWith(() => { this.#ioEnded = true; this.#observeEOF(); this.#changed?.(); });
    this.#stream!.inputChangedWith?.(() => { this.#observeEOF(); this.#changed?.(); });
    this.#stream!.cleanupWith(() => { this.#physical = true; this.#collect(); this.#changed?.(); });
  }
  onChange(changed: () => void): void { if (this.#changed !== undefined) throw new RPCProtocolError("rpc_stream_owner"); this.#changed = changed; }
  clearChange(changed: () => void): void { if (this.#changed !== changed) throw new RPCProtocolError("rpc_stream_owner"); this.#changed = undefined; }
  unused(): boolean { return !this.#closed && this.#network === undefined && !this.#reading && !this.#writing && this.#stream?.unused() === true; }
  codec(): ApplicationHeaderCodec { this.check(); return this.#codec!; }
  check(): void {
    if (this.#closed) throw this.#failure ?? new RPCProtocolError("rpc_stream_closed");
    this.#reference!.checkRetained(); this.#stream?.check();
    if (this.#network !== undefined) this.#network.checkStream(this.#ticket!, this);
  }
  get eof(): boolean { this.#observeEOF(); return this.#inputEOF; }
  get outputClosed(): boolean { return this.#outputClosed; }
  get ioEnded(): boolean { return this.#ioEnded; }
  get physicalComplete(): boolean { return this.#physical; }
  get closed(): boolean { return this.#closed; }
  #observeEOF(): void {
    // ReadState only reports EOF after all authenticated bytes were consumed.
    if (this.#stream?.readState().stream_status === "eof") {
      if (!this.#candidate && (this.#have !== 0 || this.#header !== undefined)) this.#fail(new RPCProtocolError("rpc_stream_truncated"));
      else this.#inputEOF = true;
    }
  }
  #feed(bytes: Uint8Array, admit: (header: ApplicationHeader) => RPCStreamInput): number {
    let at = 0;
    while (at < bytes.length && !this.#candidate) {
      if (this.#header === undefined) {
        const n = Math.min(this.#need - this.#have, bytes.length - at);
        this.#prefix.set(bytes.subarray(at, at + n), this.#have); this.#have += n; at += n;
        if (this.#have < this.#need) break;
        if (this.#need === 2) {
          const size = this.#prefix[0]! * 256 + this.#prefix[1]!;
          if (size < 1 || size > 512) throw new RPCProtocolError("application_header_length"); this.#need = size + 2; continue;
        }
        this.#header = this.#codec!.decode(this.#prefix.subarray(2, this.#need));
        this.#input = admit(this.#header); this.#offset = 0;
      }
      const count = Math.min(bytes.length - at, this.#header.payloadBytes - this.#offset);
      if (count !== 0) { this.#input!.write(this.#offset, bytes.subarray(at, at + count)); at += count; this.#offset += count; }
      if (this.#offset === this.#header.payloadBytes) { this.#input!.finish(); this.#candidate = true; }
    }
    return at;
  }
  /** Cancellation detaches only this wait. The same parser, payload sink and
   * partial offset remain owned by this Stream for the next read. */
  async read(admit: (header: ApplicationHeader) => RPCStreamInput, signal?: AbortSignal): Promise<ApplicationHeader | undefined> {
    this.check(); if (this.#reading) throw new RPCProtocolError("read_in_progress");
    this.#reading = true;
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    try {
      while (!this.#candidate) {
        this.check(); if (cancellation.aborted) throw new RPCProtocolError("wait_canceled"); this.#observeEOF();
        if (this.#inputEOF) return;
        await this.#stream!.readInto(16384, bytes => this.#feed(bytes, admit), cancellation);
        this.#observeEOF();
        if (!this.#candidate && !this.#inputEOF && this.#stream!.readState().stream_status !== "open") throw new RPCProtocolError("rpc_stream_incomplete");
      }
      this.check(); if (cancellation.aborted) throw new RPCProtocolError("wait_canceled"); return this.#header!;
    } catch (error) {
      const suspended = error instanceof TimeError && ["time_pending", "time_unavailable", "time_continuity"].includes(error.code) ||
        error instanceof V4ReadMethodError && ["time_pending", "time_unavailable"].includes(error.reason);
      if (!cancellation.aborted && !suspended) this.#fail(error); throw error;
    }
    finally { this.#reading = false; if (this.#inputEOF) this.#stream?.releaseReader(); this.#collect(); }
  }
  consume(): void {
    this.check(); if (!this.#candidate || this.#reading) throw new RPCProtocolError("rpc_stream_candidate");
    this.#readMessages++; this.#candidate = false; this.#header = undefined; this.#input = undefined; this.#have = 0; this.#need = 2; this.#offset = 0; this.#prefix.fill(0);
    this.#observeEOF(); this.#changed?.();
  }
  async requireEOF(signal?: AbortSignal): Promise<void> {
    const extra = await this.read(() => { throw new RPCProtocolError("rpc_stream_extra_input"); }, signal);
    if (extra !== undefined) throw new RPCProtocolError("rpc_stream_extra_input");
  }
  /** A complete terminal error ends item production. Its only remaining
   * input is FIN, under the existing adapter's finite finish deadline. */
  async finishTerminal(): Promise<void> {
    this.check(); const deadline = this.#stream!.deadline(30000n), abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = (): void => {
      timer = undefined;
      try { deadline.check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
      catch { abort.abort(); }
    };
    tick();
    try { await this.requireEOF(abort.signal); await this.finish(); }
    finally { if (timer !== undefined) clearTimeout(timer); this.close(); }
  }
  async send(header: ApplicationHeader, bytes: Uint8Array, check: () => void, admitted?: () => void): Promise<void> {
    this.check(); if (this.#writing || this.#outputClosed || bytes.length !== header.payloadBytes) throw new RPCProtocolError("rpc_stream_output");
    this.#writing = true; const prefix = new Uint8Array(514); let begun = false;
    try {
      const size = header.encode(prefix.subarray(2)); prefix[0] = size >>> 8; prefix[1] = size & 255;
      const publish = async (part: Uint8Array): Promise<void> => {
        check(); this.check(); const reference = this.#position!.checkout();
        try { this.#write = this.#stream!.prepareFragment(part, reference); } finally { reference.release(); }
        this.#write.checkProtocolAdmission(); check(); this.check();
        if (!this.#write.admitProtocol()) throw new RPCProtocolError("rpc_stream_output");
        if (!begun) { begun = true; admitted?.(); }
        this.#write.start(); await this.#write.waitCleanup();
        const progress = this.#write.progress();
        if (progress.accepted_bytes !== BigInt(part.length) || progress.terminal_reason !== "complete") throw new RPCProtocolError("rpc_stream_incomplete");
        this.#write = undefined;
      };
      await publish(prefix.subarray(0, size + 2));
      for (let offset = 0; offset < bytes.length; offset += 16384) await publish(bytes.subarray(offset, Math.min(bytes.length, offset + 16384)));
      this.#sentMessages++;
    } catch (error) { this.#fail(error); throw error; }
    finally {
      if (this.#write !== undefined) { this.#write.terminate(); await this.#write.waitCleanup(); this.#write = undefined; }
      prefix.fill(0); this.#writing = false; this.#collect();
    }
  }
  async closeWrite(): Promise<void> {
    this.check(); if (this.#writing) throw new RPCProtocolError("rpc_stream_output"); if (this.#outputClosed) return;
    this.#writing = true;
    try { await this.#stream!.closeWrite(); this.#outputClosed = true; }
    catch (error) { this.#fail(error); throw error; }
    finally { this.#writing = false; this.#changed?.(); this.#collect(); }
  }
  /** Normal terminal I/O releases transport ownership but leaves the compact
   * complete candidate/authorization owner to its result handoff. */
  async finish(): Promise<void> {
    this.check(); if (!this.#outputClosed || !this.#inputEOF || this.#finishing) throw new RPCProtocolError("rpc_stream_incomplete");
    this.#finishing = true;
    try { this.#stream!.releaseReader(); await this.#stream!.finish(); }
    finally { this.#finishing = false; this.#collect(); }
  }
  /** Release only this temporary framing owner. The caller's accepted Stream
   * stays live; unread following bytes remain in its original receive queue. */
  returnResumeBoundary(): void {
    this.check();
    if (this.#resume === undefined || this.#reading || this.#writing || this.#finishing || this.#write !== undefined ||
        this.#candidate || this.#have !== 0 || this.#header !== undefined || this.#input !== undefined || this.#outputClosed ||
        this.#sentMessages !== 1 || this.#readMessages !== 1) throw new RPCProtocolError("rpc_stream_incomplete");
    this.#resume.returnAtBoundary(); this.#resume = undefined; this.#stream = undefined; this.#physical = true;
    this.#closed = true; this.#position!.closeAfterUse(); this.#changed?.(); this.#collect();
  }
  /** Preparation cancellation before any frame is admitted returns the same
   * target's unused qualification without terminating caller-owned I/O. */
  releaseUnusedResume(): void {
    this.check();
    if (this.#resume === undefined || this.#reading || this.#writing || this.#finishing || this.#write !== undefined ||
        this.#candidate || this.#have !== 0 || this.#sentMessages !== 0 || this.#readMessages !== 0) throw new RPCProtocolError("rpc_stream_incomplete");
    this.#resume.rollback(); this.#resume = undefined; this.#stream = undefined; this.#physical = true;
    this.#closed = true; this.#position!.closeAfterUse(); this.#changed?.(); this.#collect();
  }
  #fail(error: unknown): void { this.#failure ??= error; this.close(); }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#abort.abort(); this.#write?.terminate(); this.#position?.closeAfterUse();
    const stream = this.#stream;
    if (stream === undefined) this.#physical = true;
    else { stream.releaseDelivery(); void stream.reset().catch(() => undefined).finally(() => { this.#physical = stream.cleanupStatus().core_cleanup === "complete"; this.#collect(); }); }
    this.#changed?.(); this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#collecting) return;
    this.#collecting = true;
    try {
      // The cursor owns receive backing. Release it after its actual read exits,
      // before waiting for core cleanup, which includes that same backing.
      if (!this.#reading) this.#stream?.releaseReader();
      if (this.#reading || this.#writing || this.#finishing || !this.#physical || this.#position?.cleanupComplete() === false) return;
      this.#stream?.release(); this.#stream = undefined; this.#resume = undefined; this.#group?.close(); this.#group = undefined;
      this.#codec?.close(); this.#codec = undefined; this.#prefix.fill(0); this.#prefix = new Uint8Array(); this.#input = undefined; this.#header = undefined;
      this.#network?.closeStream(this.#ticket!, this); this.#releaseNetwork?.(); this.#releaseNetwork = undefined; this.#network = undefined; this.#ticket = undefined;
      this.#position = undefined; this.#reference?.release(); this.#reference = undefined; const changed = this.#changed; this.#changed = undefined; changed?.();
    } finally { this.#collecting = false; }
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
