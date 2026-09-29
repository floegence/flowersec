import type { V4StreamOwner } from "../public.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge, type ApplicationHeader } from "./applicationHeader.js";
import { applicationGroupCharge, type ApplicationGroup } from "./applicationExecutor.js";
import { acquireRPCStream, type RPCStreamOwner } from "./rpcStream.js";
import { ExecutionManagementCodec, executionManagementDecoderCharge, managementBinding, managementHeader, type ExecutionTarget, type ExecutionManagementResult } from "./executionManagementCodec.js";
import { TrustedDeadline } from "./deadline.js";
import type { TrustedClock } from "./clock.js";
import { ResourceVector, type ResourceReference, type ProtectedResourceReservation } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { writeRequestCharge, type ReliableWriteRequest } from "./writeRequest.js";

const NativePromise = Promise, maximum = (1n << 64n) - 1n;
const add = EventTarget.prototype.addEventListener, remove = EventTarget.prototype.removeEventListener;
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const isAborted = (signal?: AbortSignal): boolean => signal !== undefined && signalAborted.call(signal) as boolean;
interface Pending {
  readonly target: ExecutionTarget; readonly cancel: boolean; readonly deadline: TrustedDeadline;
  readonly signal: AbortSignal | undefined; readonly abort: () => void;
  resolve: ((result: ExecutionManagementResult) => void) | undefined;
  reject: ((error: unknown) => void) | undefined;
  serial: bigint; header: ApplicationHeader | undefined;
}
interface Reply { readonly header: ApplicationHeader; readonly target: ExecutionTarget; readonly cancel: boolean; readonly deadline: TrustedDeadline | undefined; readonly result: ExecutionManagementResult }
class Wake {
  #resolve: (() => void) | undefined;
  signal(): void { const resolve = this.#resolve; this.#resolve = undefined; resolve?.(); }
  wait(): Promise<void> { return new NativePromise<void>(resolve => { this.#resolve = resolve; }); }
}
export function executionManagementCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  return [new ResourceVector([65536n + 8n * runtimeBytes, 0n, 0n, 48n, 4n, 4n, 2n, 0n, 0n, 0n, 0n]),
    // Original message adapter owns its cursor, metadata and delivery lease.
    new ResourceVector([50304n + runtimeBytes, 0n, 0n, 5n, 6n, 6n, 4n, 0n, 0n, 1n, 0n]), applicationGroupCharge(runtimeBytes),
    applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes), executionManagementDecoderCharge(runtimeBytes),
    writeRequestCharge(1538, runtimeBytes)];
}
/** One generation of the fixed bidirectional M channel. Two original outgoing
 * matches and two short SDK replies use one parser and one publisher. Neither
 * path enters the application executor or allocates a task per incoming call. */
export class ExecutionManagementChannel {
  #reference: ResourceReference | undefined;
  #stream: RPCStreamOwner | undefined;
  #headers: ApplicationHeaderCodec | undefined;
  #bodies: ExecutionManagementCodec | undefined;
  readonly #abort = new AbortController();
  readonly #wake = new Wake();
  readonly #readWake = new Wake();
  readonly #pending: Pending[] = [];
  readonly #replies: Reply[] = [];
  #highwater = 0n;
  #inbound = 0n;
  #filled = 0;
  #needed = 2;
  #header: ApplicationHeader | undefined;
  #inputDeadline: TrustedDeadline | undefined;
  #wire = new Uint8Array(1538);
  #input = new Uint8Array(1538);
  #body = new Uint8Array(1024);
  #timer: ReturnType<typeof setTimeout> | undefined;
  #yieldTimer: ReturnType<typeof setTimeout> | undefined;
  #yieldResolve: (() => void) | undefined;
  #write: ReliableWriteRequest | undefined;
  #reading = false;
  #publishing = false;
  #physical = false;
  #closed = false;
  #collecting = false;
  #lastReply = false;
  #resolve: ((target: ExecutionTarget, cancel: boolean) => ExecutionManagementResult) | undefined;
  #authorize: ((target: ExecutionTarget, cancel: boolean, outgoing: boolean) => void) | undefined;
  constructor(stream: V4StreamOwner, readonly clock: TrustedClock, readonly deadline: TrustedDeadline,
    readonly position: ProtectedResourceReservation, runtimeBytes: bigint, references: readonly ResourceReference[], group: ApplicationGroup,
    resolve: (target: ExecutionTarget, cancel: boolean) => ExecutionManagementResult,
    authorize: (target: ExecutionTarget, cancel: boolean, outgoing: boolean) => void, readonly cleaned: () => void) {
    const costs = executionManagementCharges(runtimeBytes);
    if (references.length !== 5 || !references.every(reference => references[0]!.sameEnvironment(reference))) throw new RPCProtocolError("management_owner");
    this.#reference = references[0]!.take(costs[0]!); this.#resolve = resolve; this.#authorize = authorize;
    try {
      this.#headers = new ApplicationHeaderCodec(runtimeBytes, references[2]!, references[3]!);
      this.#bodies = new ExecutionManagementCodec(runtimeBytes, references[4]!);
      this.#stream = acquireRPCStream(stream, { kind: "message", readBytes: 16384, inputBackingBytes: 1, inputEntries: 1,
        gracefulFinishMS: 30000, cleanupMS: 5000, prepaid: references[1]!, application: group });
      this.#stream.invalidateWith(() => this.close()); this.#stream.ioEndedWith(() => this.close());
      this.#stream.cleanupWith(() => { this.#physical = true; this.#collect(); });
    } catch (error) { this.#stream?.rollback(); this.#physical = true; this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("management_unavailable"); this.#reference!.check(); this.#stream!.check(); }
  get closed(): boolean { return this.#closed; }
  start(): void {
    this.#check(); if (this.#reading || this.#publishing) return;
    this.#reading = this.#publishing = true; this.#tick(); void this.#read(); void this.#publish();
  }
  request(target: ExecutionTarget, cancel: boolean, deadline: TrustedDeadline, signal?: AbortSignal): Promise<ExecutionManagementResult> {
    this.#check(); this.#authorize!(target, cancel, true); deadline.check(); this.#check();
    if (!deadline.belongsTo(this.clock) || this.#pending.length === 2 || this.#highwater === maximum) throw new RPCProtocolError("resource_exhausted");
    if (isAborted(signal)) return NativePromise.reject(new RPCProtocolError("canceled"));
    return new NativePromise<ExecutionManagementResult>((resolve, reject) => {
      const pending: Pending = { target, cancel, deadline, signal, resolve, reject, serial: 0n, header: undefined,
        abort: () => this.#abandon(pending, new RPCProtocolError("canceled")) };
      this.#pending.push(pending);
      if (signal !== undefined) add.call(signal, "abort", pending.abort, { once: true });
      if (isAborted(signal)) pending.abort(); this.#wake.signal();
    });
  }
  #remove(pending: Pending): void {
    const index = this.#pending.indexOf(pending); if (index >= 0) this.#pending.splice(index, 1);
    if (pending.signal !== undefined) remove.call(pending.signal, "abort", pending.abort);
  }
  #abandon(pending: Pending, error: unknown): void {
    const reject = pending.reject; pending.reject = pending.resolve = undefined;
    if (pending.signal !== undefined) remove.call(pending.signal, "abort", pending.abort);
    if (pending.serial === 0n) this.#remove(pending);
    reject?.(error); this.#wake.signal();
  }
  readonly #tick = (): void => {
    this.#timer = undefined; if (this.#closed) return;
    try {
      this.#check(); this.deadline.check(); this.#inputDeadline?.check();
      for (const pending of [...this.#pending]) {
        try { pending.deadline.check(); } catch (error) { this.#abandon(pending, error); }
      }
      this.#timer = setTimeout(this.#tick, 50);
    } catch { this.close(); }
  };
  #feed(bytes: Uint8Array): number {
    let consumed = 0;
    // Stop at one complete envelope. The reader yields between bounded SDK jobs.
    while (consumed < bytes.length) {
      const length = Math.min(bytes.length - consumed, this.#needed - this.#filled);
      this.#input.set(bytes.subarray(consumed, consumed + length), this.#filled); consumed += length; this.#filled += length;
      if (this.#filled !== this.#needed) break;
      if (this.#needed === 2) {
        const n = (this.#input[0]! << 8) | this.#input[1]!;
        if (n < 1 || n > 512) throw new RPCProtocolError("management_framing"); this.#needed = 2 + n;
        this.#inputDeadline = this.deadline.forkAgeAt(this.clock.sample(), 30000n);
      } else if (this.#header === undefined) {
        this.#header = this.#headers!.decode(this.#input.subarray(2, this.#needed)); managementBinding(this.#header);
        this.#needed += this.#header.payloadBytes;
        if (this.#filled !== this.#needed) continue;
      }
      if (this.#header !== undefined && this.#filled === this.#needed) {
        const header = this.#header, n = (this.#input[0]! << 8) | this.#input[1]!;
        this.#accept(header, this.#input.subarray(2 + n, this.#needed));
        this.#filled = 0; this.#needed = 2; this.#header = undefined; this.#inputDeadline = undefined; this.#input.fill(0); break;
      }
    }
    return consumed;
  }
  #accept(header: ApplicationHeader, bytes: Uint8Array): void {
    this.#check(); const cancel = managementBinding(header), serial = header.uint(9);
    if (header.isResponse()) {
      if (serial > this.#highwater) throw new RPCProtocolError("management_serial");
      const pending = this.#pending.find(entry => entry.serial === serial);
      const result = this.#bodies!.result(bytes, cancel);
      if (pending === undefined) return; // Bounded high-water classification of an old response.
      header.checkResponse(pending.header!);
      if (pending.resolve !== undefined) {
        try { pending.deadline.check(); this.#authorize!(pending.target, pending.cancel, true); this.#check(); }
        catch (error) { this.#abandon(pending, error); }
      }
      this.#remove(pending); const resolve = pending.resolve; pending.resolve = pending.reject = undefined; resolve?.(result); return;
    }
    if (serial !== this.#inbound + 1n || serial === maximum || this.#replies.length === 2) throw new RPCProtocolError("management_serial");
    const target = this.#bodies!.target(bytes); this.#inbound = serial;
    let result: ExecutionManagementResult, deadline: TrustedDeadline | undefined;
    try {
      const sample = this.clock.sample(), now = sample.requireInterval();
      if (header.uint(5) > now.lowerMS + 30000n) throw new RPCProtocolError("deadline_exceeded");
      deadline = new TrustedDeadline(this.clock, header.uint(5) < this.deadline.cap ? header.uint(5) : this.deadline.cap, sample); deadline.tightenFrom(this.deadline);
      this.#authorize!(target, cancel, false); this.#check(); result = this.#resolve!(target, cancel); deadline.check(); this.#check();
    } catch (error) { result = { status: error instanceof RPCProtocolError && error.code === "permission_denied" ? "unauthorized" : error instanceof RPCProtocolError && error.code === "operation_conflict" ? "operation_conflict" : error instanceof Error && (error.message.startsWith("time_") || error.message === "deadline_exceeded") ? "deadline_exceeded" : "unavailable" }; }
    this.#replies.push({ header, target, cancel, deadline, result }); this.#wake.signal();
  }
  async #read(): Promise<void> {
    try {
      let quantum = 0;
      while (!this.#closed) {
        if (this.#replies.length === 2) { await this.#readWake.wait(); continue; }
        await this.#stream!.readInto(16384, bytes => this.#feed(bytes), this.#abort.signal);
        if (++quantum === 8) {
          quantum = 0;
          await new NativePromise<void>(resolve => { this.#yieldResolve = resolve; this.#yieldTimer = setTimeout(() => {
            this.#yieldTimer = undefined; this.#yieldResolve = undefined; resolve();
          }, 0); });
        }
        if (!this.#closed && this.#stream!.readState().stream_status !== "open") throw new RPCProtocolError("management_closed");
      }
    } catch { this.close(); }
    finally { this.#reading = false; this.#stream?.releaseReader(); this.#collect(); }
  }
  async #publish(): Promise<void> {
    try {
      while (!this.#closed) {
        const pending = this.#pending.find(value => value.serial === 0n), reply = this.#replies[0];
        if (pending === undefined && reply === undefined) { await this.#wake.wait(); continue; }
        const responding = reply !== undefined && (pending === undefined || !this.#lastReply);
        let header: ApplicationHeader, body: Uint8Array;
        if (responding) {
          let result = reply!.result;
          if (result.observation !== undefined) {
            try { reply!.deadline!.check(); this.#authorize!(reply!.target, reply!.cancel, false); this.#check(); }
            catch { result = { status: "unavailable" }; }
          }
          body = this.#bodies!.encodeResult(result, reply!.cancel, this.#body);
          header = this.#headers!.response(reply!.header, reply!.cancel ? "request_cancel_response" : "query_operation_response", body.length);
        } else {
          try { pending!.deadline.check(); this.#authorize!(pending!.target, pending!.cancel, true); this.#check(); }
          catch (error) { this.#abandon(pending!, error); continue; }
          body = this.#bodies!.encodeTarget(pending!.target, this.#body);
          header = managementHeader(this.#headers!, pending!.cancel, false, this.#highwater + 1n, body.length, pending!.deadline.cap);
        }
        const n = header.encode(this.#wire.subarray(2, 514)); this.#wire[0] = n >> 8; this.#wire[1] = n & 255; this.#wire.set(body, 2 + n);
        const reference = this.position.checkout();
        try { this.#write = this.#stream!.prepareFragment(this.#wire.subarray(0, 2 + n + body.length), reference); } finally { reference.release(); }
        this.#write.checkProtocolAdmission(); this.#check();
        if (!responding) {
          pending!.deadline.check(); this.#authorize!(pending!.target, pending!.cancel, true); this.#check();
          if (pending!.resolve === undefined) { this.#write.cancel(); await this.#write.waitCleanup(); this.#write = undefined; continue; }
        }
        if (responding && reply!.result.observation !== undefined) {
          try { reply!.deadline!.check(); this.#authorize!(reply!.target, reply!.cancel, false); this.#check(); }
          catch {
            this.#write.cancel(); await this.#write.waitCleanup(); this.#write = undefined;
            this.#replies[0] = { ...reply!, result: { status: "unavailable" } }; continue;
          }
        }
        if (!this.#write.admitProtocol()) throw new RPCProtocolError("management_unavailable");
        if (!responding) { pending!.serial = ++this.#highwater; pending!.header = header; }
        this.#lastReply = responding; this.#write.start(); await this.#write.waitCleanup();
        if (this.#write.progress().terminal_reason !== "complete") throw new RPCProtocolError("management_unavailable");
        this.#write = undefined; if (responding) { this.#replies.shift(); this.#readWake.signal(); }
        this.#wire.fill(0); this.#body.fill(0);
      }
    } catch { this.close(); }
    finally { this.#publishing = false; this.#collect(); }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#abort.abort(); this.#wake.signal(); this.#readWake.signal();
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    if (this.#yieldTimer !== undefined) clearTimeout(this.#yieldTimer); this.#yieldTimer = undefined;
    const resolveYield = this.#yieldResolve; this.#yieldResolve = undefined; resolveYield?.();
    for (const pending of [...this.#pending]) { this.#abandon(pending, new RPCProtocolError("management_unavailable")); this.#remove(pending); }
    this.#resolve = this.#authorize = undefined; this.#write?.terminate();
    const stream = this.#stream;
    if (stream !== undefined) { stream.releaseDelivery(); void stream.reset().catch(() => undefined).finally(() => { this.#physical = stream.cleanupStatus().core_cleanup === "complete"; this.#collect(); }); }
    else this.#physical = true;
    this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#reading || this.#publishing || !this.#physical || this.#reference === undefined || this.#collecting) return;
    // Returning a protected checkout synchronously wakes its Session owner.
    // Keep this generation unavailable until all of its releases have exited.
    this.#collecting = true;
    try {
      this.#stream?.application.close(); this.#stream?.release(); this.#stream = undefined;
      this.#headers?.close(); this.#bodies?.close(); this.#headers = undefined; this.#bodies = undefined;
      this.#replies.length = 0; this.#wire.fill(0); this.#body.fill(0); this.#input.fill(0);
      this.#wire = this.#body = this.#input = new Uint8Array(); this.#header = undefined; this.#inputDeadline = undefined;
      this.#reference.release(); this.#reference = undefined;
    } finally { this.#collecting = false; }
    this.cleaned();
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
Object.freeze(ExecutionManagementChannel.prototype);
