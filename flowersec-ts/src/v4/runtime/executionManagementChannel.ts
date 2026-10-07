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
import { DiagnosticActivity, type DiagnosticObserver } from "./diagnosticObservation.js";
import { diagnosticFailure, type DiagnosticFailure } from "./diagnosticCounters.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { ManagementPermit } from "./fixedManagementExecutor.js";
const NativePromise = Promise, maximum = (1n << 64n) - 1n;
const add = EventTarget.prototype.addEventListener, remove = EventTarget.prototype.removeEventListener;
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const isAborted = (signal?: AbortSignal): boolean => signal !== undefined && signalAborted.call(signal) as boolean;
interface Pending {
  readonly diagnostic: DiagnosticActivity;
  // Physical tails retain finite diagnostic facts, never the provider exception.
  diagnosticOutcome: DiagnosticFailure | undefined; result: ExecutionManagementResult | undefined;
  publishing: boolean; retired: boolean; diagnosticFinished: boolean;
  readonly target: ExecutionTarget; readonly cancel: boolean; readonly deadline: TrustedDeadline;
  readonly signal: AbortSignal | undefined; readonly abort: () => void;
  resolve: ((result: ExecutionManagementResult) => void) | undefined;
  reject: ((error: unknown) => void) | undefined;
  serial: bigint; header: ApplicationHeader | undefined;
}
interface Reply { readonly owner: ManagementPermit; readonly diagnostic: DiagnosticActivity; diagnosticOutcome: DiagnosticFailure | undefined; readonly header: ApplicationHeader; readonly target: ExecutionTarget; readonly cancel: boolean; readonly deadline: TrustedDeadline | undefined; readonly result: ExecutionManagementResult }
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
  #resolvingDeadline: TrustedDeadline | undefined;
  #wire = new Uint8Array(1538);
  #input = new Uint8Array(1538);
  #body = new Uint8Array(1024);
  #timer: ReturnType<typeof setTimeout> | undefined;
  #yieldTimer: ReturnType<typeof setTimeout> | undefined;
  #yieldResolve: (() => void) | undefined;
  #write: ReliableWriteRequest | undefined;
  #reading = false;
  #publishing = false;
  #publishingPending: Pending | undefined;
  #publishingPermit: ManagementPermit | undefined;
  #physical = false;
  #closed = false;
  #collecting = false;
  #lastReply = false;
  #drainDeadline: TrustedDeadline | undefined;
  #resolve: ((target: ExecutionTarget, cancel: boolean, access: RPCPublicationGuard) => ExecutionManagementResult | Promise<ExecutionManagementResult>) | undefined;
  #authorize: ((target: ExecutionTarget, cancel: boolean, outgoing: boolean) => void) | undefined;
  #diagnostics: DiagnosticObserver | undefined;
  constructor(stream: V4StreamOwner, readonly clock: TrustedClock, readonly deadline: TrustedDeadline, readonly position: ProtectedResourceReservation, runtimeBytes: bigint, references: readonly ResourceReference[], private readonly group: ApplicationGroup, resolve: (target: ExecutionTarget, cancel: boolean, access: RPCPublicationGuard) => ExecutionManagementResult | Promise<ExecutionManagementResult>, authorize: (target: ExecutionTarget, cancel: boolean, outgoing: boolean) => void, readonly cleaned: () => void, diagnostics?: DiagnosticObserver) {
    const costs = executionManagementCharges(runtimeBytes);
    if (references.length !== 5 || !references.every(reference => references[0]!.sameEnvironment(reference))) throw new RPCProtocolError("management_owner");
    this.#reference = references[0]!.take(costs[0]!); this.#resolve = resolve; this.#authorize = authorize; this.#diagnostics = diagnostics;
    try {
      this.#headers = new ApplicationHeaderCodec(runtimeBytes, references[2]!, references[3]!);
      this.#bodies = new ExecutionManagementCodec(runtimeBytes, references[4]!);
      this.#stream = acquireRPCStream(stream, {
        kind: "message", readBytes: 16384, inputBackingBytes: 1, inputEntries: 1,
        gracefulFinishMS: 30000, cleanupMS: 5000, prepaid: references[1]!, application: group
      });
      this.#stream.invalidateWith(() => this.close()); this.#stream.ioEndedWith(() => this.close());
      this.#stream.cleanupWith(() => { this.#physical = true; this.#collect(); });
    } catch (error) { this.#stream?.rollback(); this.#physical = true; this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("management_unavailable"); this.#reference!.check(); this.#stream!.check(); this.#drainDeadline?.check(); }
  get closed(): boolean { return this.#closed; }
  drain(deadline: TrustedDeadline): void {
    if (this.#closed) return;
    this.#check();
    if (!deadline.belongsTo(this.clock)) throw new RPCProtocolError("time_owner");
    if (this.#drainDeadline === undefined) this.#drainDeadline = deadline.fork(deadline.cap);
    else this.#drainDeadline.tightenFrom(deadline);
    for (const pending of [...this.#pending]) {
      try { pending.deadline.tightenFrom(this.#drainDeadline); }
      catch (error) { this.#abandon(pending, error); }
    }
    for (const reply of this.#replies) {
      try { reply.deadline?.tightenFrom(this.#drainDeadline); }
      catch (error) { reply.diagnosticOutcome ??= diagnosticFailure(error); }
    }
    try {
      this.#inputDeadline?.tightenFrom(this.#drainDeadline);
      this.#resolvingDeadline?.tightenFrom(this.#drainDeadline);
    } catch { this.close(); }
    this.#wake.signal(); this.#readWake.signal();
  }
  start(): void {
    this.#check(); if (this.#reading || this.#publishing) return;
    this.#reading = this.#publishing = true; this.#tick(); void this.#read(); void this.#publish();
  }
  request(target: ExecutionTarget, cancel: boolean, deadline: TrustedDeadline, signal?: AbortSignal, originalDiagnostic?: DiagnosticActivity): Promise<ExecutionManagementResult> {
    const diagnostic = originalDiagnostic ?? new DiagnosticActivity(this.#diagnostics, "application");
    try {
      this.#check(); this.#authorize!(target, cancel, true);
      if (!deadline.belongsTo(this.clock)) throw new RPCProtocolError("time_owner");
      deadline.check();
      // A request inherits the fixed Drain cap; it cannot change that cap for
      // other work or shorten the original Session Drain owner.
      if (this.#drainDeadline !== undefined) deadline.tightenFrom(this.#drainDeadline);
      this.#check();
      if (this.#pending.length === 2 || this.#highwater === maximum) throw new RPCProtocolError("resource_exhausted");
      if (isAborted(signal)) {
        const error = new RPCProtocolError("canceled"); diagnostic.failure(error); return NativePromise.reject(error);
      }
    } catch (error) { diagnostic.failure(error); throw error; }
    return new NativePromise<ExecutionManagementResult>((resolve, reject) => {
      const pending: Pending = {
        diagnostic, diagnosticOutcome: undefined, result: undefined, publishing: false, retired: false, diagnosticFinished: false,
        target, cancel, deadline, signal, resolve, reject, serial: 0n, header: undefined,
        abort: () => this.#abandon(pending, new RPCProtocolError("canceled"))
      };
      this.#pending.push(pending);
      if (signal !== undefined) add.call(signal, "abort", pending.abort, { once: true });
      if (isAborted(signal)) pending.abort(); this.#wake.signal();
    });
  }
  #remove(pending: Pending): void {
    pending.retired = true;
    const index = this.#pending.indexOf(pending); if (index >= 0) this.#pending.splice(index, 1);
    if (pending.signal !== undefined) remove.call(pending.signal, "abort", pending.abort);
  }
  #abandon(pending: Pending, error: unknown): void {
    pending.diagnosticOutcome ??= diagnosticFailure(error);
    const reject = pending.reject; pending.reject = pending.resolve = undefined;
    if (pending.signal !== undefined) remove.call(pending.signal, "abort", pending.abort);
    if (pending.serial === 0n && this.#publishingPending === pending) this.#write?.cancel();
    if (pending.serial === 0n && !pending.publishing) this.#remove(pending);
    this.#finishPendingDiagnostic(pending);
    reject?.(error); this.#wake.signal();
  }
  #finishPendingDiagnostic(pending: Pending): void {
    if (!pending.retired || pending.publishing || pending.diagnosticFinished) return;
    pending.diagnosticFinished = true;
    if (pending.diagnosticOutcome !== undefined) pending.diagnostic.failureFacts(pending.diagnosticOutcome);
    else if (pending.result !== undefined) this.#diagnosticResult(pending.diagnostic, pending.result);
    else pending.diagnostic.failure(new RPCProtocolError("management_unavailable"));
  }
  readonly #tick = (): void => {
    this.#timer = undefined; if (this.#closed) return;
    try {
      this.#check(); this.deadline.check(); this.#inputDeadline?.check(); this.#resolvingDeadline?.check();
      for (const pending of [...this.#pending]) {
        try { pending.deadline.check(); } catch (error) { this.#abandon(pending, error); }
      }
      this.#timer = setTimeout(this.#tick, 50);
    } catch { this.close(); }
  };
  #feed(bytes: Uint8Array): number {
    let consumed = 0;
    if (bytes.length !== 0 && this.#filled === 0) {
      this.#inputDeadline = this.deadline.forkAgeAt(this.clock.sample(), 30000n);
      if (this.#drainDeadline !== undefined) this.#inputDeadline.tightenFrom(this.#drainDeadline);
    }
    this.#inputDeadline?.check();
    // Stop at one complete envelope. The reader yields between bounded SDK jobs.
    while (consumed < bytes.length) {
      const length = Math.min(bytes.length - consumed, this.#needed - this.#filled);
      this.#input.set(bytes.subarray(consumed, consumed + length), this.#filled);
      consumed += length;
      this.#filled += length;
      if (this.#filled !== this.#needed) break;
      if (this.#needed === 2) {
        const n = (this.#input[0]! << 8) | this.#input[1]!;
        if (n < 1 || n > 512) throw new RPCProtocolError("management_framing"); this.#needed = 2 + n;
      } else if (this.#header === undefined) {
        this.#header = this.#headers!.decode(this.#input.subarray(2, this.#needed)); managementBinding(this.#header);
        if (this.#header.isResponse()) {
          const pending = this.#pending.find(entry => entry.serial === this.#header!.uint(9));
          if (pending !== undefined) this.#header.checkResponse(pending.header!);
          // Expiry ends caller delivery. The original response still owns
          // bounded matching and assembly until its complete envelope exits.
        } else {
          const requestDeadline = this.#inputDeadline!.fork(this.#header.uint(5) < this.#inputDeadline!.cap ? this.#header.uint(5) : this.#inputDeadline!.cap);
          this.#inputDeadline!.tightenFrom(requestDeadline);
        }
        this.#needed += this.#header.payloadBytes;
        if (this.#filled !== this.#needed) continue;
      }
      if (this.#header !== undefined && this.#filled === this.#needed) {
        break;
      }
    }
    return consumed;
  }
  async #accept(header: ApplicationHeader, bytes: Uint8Array, owner?: ManagementPermit): Promise<boolean> {
    this.#check();
    const cancel = managementBinding(header), serial = header.uint(9);
    if (header.isResponse()) {
      if (serial > this.#highwater) throw new RPCProtocolError("management_serial");
      const pending = this.#pending.find(entry => entry.serial === serial);
      const result = this.#bodies!.result(bytes, cancel);
      if (pending === undefined) return false; // Bounded high-water classification of an old response.
      header.checkResponse(pending.header!);
      if (pending.resolve !== undefined) {
        try { pending.deadline.check(); this.#authorize!(pending.target, pending.cancel, true); this.#check(); }
        catch (error) { this.#abandon(pending, error); }
      }
      this.#remove(pending); const resolve = pending.resolve; pending.resolve = pending.reject = undefined;
      pending.result = result; this.#finishPendingDiagnostic(pending);
      resolve?.(result); return false;
    }
    if (owner === undefined) throw new RPCProtocolError("management_owner");
    if (this.#inbound === maximum || serial !== this.#inbound + 1n || this.#replies.length === 2) throw new RPCProtocolError("management_serial");
    const target = this.#bodies!.target(bytes);
    const diagnostic = new DiagnosticActivity(this.#diagnostics, "application");
    this.#inbound = serial;
    let result: ExecutionManagementResult, deadline: TrustedDeadline | undefined, diagnosticOutcome: DiagnosticFailure | undefined;
    try {
      const sample = this.clock.sample(), now = sample.requireInterval();
      if (header.uint(5) > now.lowerMS + 30000n) throw new RPCProtocolError("deadline_exceeded");
      deadline = new TrustedDeadline(this.clock, header.uint(5) < this.deadline.cap ? header.uint(5) : this.deadline.cap, sample);
      deadline.tightenFrom(this.deadline);
      if (this.#inputDeadline !== undefined) deadline.tightenFrom(this.#inputDeadline);
      if (this.#drainDeadline !== undefined) deadline.tightenFrom(this.#drainDeadline);
      this.#authorize!(target, cancel, false);
      this.#check();
      this.#resolvingDeadline = deadline;
      const originalDeadline = deadline;
      const access: RPCPublicationGuard = Object.freeze({
        check: () => {
          this.#check(); originalDeadline.check(); this.#authorize!(target, cancel, false);
          this.#check(); originalDeadline.check();
        },
        current: () => !this.#closed,
      });
      result = await this.#resolve!(target, cancel, access);
      deadline.check();
      this.#check();
    }
    catch (error) {
      diagnosticOutcome = diagnosticFailure(error);
      result = { status: diagnosticOutcome.code === "timeout" ? "deadline_exceeded" : "unavailable" };
      // An application resolver may throw an arbitrary exception. Failure
      // classification must not strand the original diagnostic before its
      // reply is registered, even if inspecting that exception throws.
      try {
        if (error instanceof RPCProtocolError && error.code === "permission_denied") result = { status: "unauthorized" };
        else if (error instanceof RPCProtocolError && error.code === "operation_conflict") result = { status: "operation_conflict" };
        else if (error instanceof Error && error.message.startsWith("time_")) result = { status: "deadline_exceeded" };
      } catch { /* Preserve the finite unavailable/timeout response. */ }
    }
    finally { this.#resolvingDeadline = undefined; }
    if (this.#closed) diagnosticOutcome ??= diagnosticFailure(new RPCProtocolError("management_unavailable"));
    this.#replies.push({ owner, diagnostic, diagnosticOutcome, header, target, cancel, deadline, result });
    this.#wake.signal();
    return true;
  }
  async #read(): Promise<void> {
    try {
      let quantum = 0;
      while (!this.#closed) {
        if (this.#replies.length === 2) { await this.#readWake.wait(); continue; }
        await this.#stream!.readInto(16384, bytes => this.#feed(bytes), this.#abort.signal);
        if (this.#header !== undefined && this.#filled === this.#needed) {
          const header = this.#header, n = (this.#input[0]! << 8) | this.#input[1]!;
          try {
            const check = (): void => { this.#check(); this.#inputDeadline!.check(); };
            if (header.isResponse()) {
              check(); await this.#accept(header, this.#input.subarray(2 + n, this.#needed));
            } else {
              const permit = await this.group.management(this.#abort.signal, check);
              let transferred = false;
              try { check(); transferred = await this.#accept(header, this.#input.subarray(2 + n, this.#needed), permit); }
              finally { if (!transferred) permit.release(); }
            }
          }
          finally { this.#filled = 0; this.#needed = 2; this.#header = undefined; this.#inputDeadline = undefined; this.#input.fill(0); }
        }
        if (++quantum === 8) {
          quantum = 0;
          await new NativePromise<void>(resolve => {
            this.#yieldResolve = resolve; this.#yieldTimer = setTimeout(() => {
              this.#yieldTimer = undefined; this.#yieldResolve = undefined; resolve();
            }, 0);
          });
        }
        if (!this.#closed && this.#stream!.readState().stream_status !== "open") throw new RPCProtocolError("management_closed");
      }
    }
    catch { this.close(); }
    finally { this.#reading = false; this.#stream?.releaseReader(); this.#collect(); }
  }
  async #publish(): Promise<void> {
    try {
      while (!this.#closed) {
        const pending = this.#pending.find(value => value.serial === 0n), reply = this.#replies[0];
        if (pending === undefined && reply === undefined) { await this.#wake.wait(); continue; }
        const responding = reply !== undefined && (pending === undefined || !this.#lastReply);
        if (!responding) { this.#publishingPending = pending; pending!.publishing = true; }
        // The preinstalled publisher owns request encoding. Replies retain
        // their admitted store owner; publication never waits for a second
        // permit while both original incoming replies already hold the lane.
        const permit = responding ? reply!.owner : undefined;
        this.#publishingPermit = permit;
        try {
        let header: ApplicationHeader, body: Uint8Array, publishesObservation = false;
        if (responding) {
          if (reply!.deadline === undefined) throw new RPCProtocolError("deadline_exceeded");
          reply!.deadline.check();
          let result = reply!.result;
          if (result.observation !== undefined) {
            try { reply!.deadline!.check(); this.#authorize!(reply!.target, reply!.cancel, false); this.#check(); }
            catch (error) { reply!.diagnosticOutcome ??= diagnosticFailure(error); result = { status: "unavailable" }; }
          }
          publishesObservation = result.observation !== undefined;
          body = this.#bodies!.encodeResult(result, reply!.cancel, this.#body);
          header = this.#headers!.response(reply!.header, reply!.cancel ? "request_cancel_response" : "query_operation_response", body.length);
        } else {
          try { pending!.deadline.check(); this.#authorize!(pending!.target, pending!.cancel, true); this.#check(); }
          catch (error) { this.#abandon(pending!, error); this.#releasePublishingPending(); continue; }
          if (this.#highwater === maximum) {
            this.#abandon(pending!, new RPCProtocolError("resource_exhausted")); this.#releasePublishingPending(); continue;
          }
          body = this.#bodies!.encodeTarget(pending!.target, this.#body);
          header = managementHeader(this.#headers!, pending!.cancel, false, this.#highwater + 1n, body.length, pending!.deadline.cap);
        }
        const n = header.encode(this.#wire.subarray(2, 514)); this.#wire[0] = n >> 8; this.#wire[1] = n & 255; this.#wire.set(body, 2 + n);
        // Keep this exact target authority attached to the original write.
        // Credit, rekey and output waits can outlive the delegation even while
        // the request and Session deadlines remain valid. The Stream repeats
        // this guard at every actual native admission, including later records.
        const originalDeadline = responding ? reply!.deadline! : pending!.deadline;
        const publication: RPCPublicationGuard = Object.freeze({
          check: () => {
            try {
              this.#check(); originalDeadline.check();
              if (!responding) {
                if (pending!.serial === 0n && pending!.resolve === undefined) throw new RPCProtocolError("canceled");
                this.#authorize!(pending!.target, pending!.cancel, true);
              } else if (publishesObservation) this.#authorize!(reply!.target, reply!.cancel, false);
              this.#check(); originalDeadline.check();
            } catch (error) {
              // Preserve the original authorization failure for the caller.
              // Abandon cancels only an unsubmitted request; committed serials
              // retain their matching position until response or physical exit.
              if (!responding) this.#abandon(pending!, error);
              else reply!.diagnosticOutcome ??= diagnosticFailure(error);
              throw error;
            }
          },
          current: () => !this.#closed,
        });
        const reference = this.position.checkout();
        try { this.#write = this.#stream!.prepareFragment(this.#wire.subarray(0, 2 + n + body.length), reference, originalDeadline, publication); } finally { reference.release(); }
        this.#write.checkProtocolAdmission(); this.#check();
        if (!responding) {
          pending!.deadline.check(); this.#authorize!(pending!.target, pending!.cancel, true); this.#check();
          if (pending!.resolve === undefined) { this.#write.cancel(); await this.#write.waitCleanup(); this.#write = undefined; this.#releasePublishingPending(); continue; }
        }
        if (responding) reply!.deadline!.check();
        if (responding && reply!.result.observation !== undefined) {
          try { reply!.deadline!.check(); this.#authorize!(reply!.target, reply!.cancel, false); this.#check(); }
          catch (error) {
            reply!.diagnosticOutcome ??= diagnosticFailure(error);
            this.#write.cancel(); await this.#write.waitCleanup(); this.#write = undefined;
            this.#replies[0] = { ...reply!, result: { status: "unavailable" } }; continue;
          }
        }
        if (responding) {
          if (!this.#write.admitProtocol()) throw new RPCProtocolError("management_unavailable");
        } else {
          this.#write.observeFirstNativeAdmission(() => {
            pending!.serial = ++this.#highwater; pending!.header = header;
          });
        }
        this.#lastReply = responding; this.#write.start();
        } finally {
          // The same incoming request owner spans store execution, queued
          // response, and actual write exit. It cannot be lent between stages.
          if (this.#write === undefined) {
            this.#publishingPermit = undefined;
          }
        }
        await this.#write!.waitCleanup();
        const progress = this.#write.progress();
        if (!responding && pending!.serial === 0n && progress.accepted_bytes === 0n &&
            (progress.terminal_reason === "canceled" || progress.terminal_reason === "deadline_exceeded")) {
          this.#write = undefined;
          this.#abandon(pending!, new RPCProtocolError(progress.terminal_reason)); this.#releasePublishingPending();
          this.#wire.fill(0); this.#body.fill(0); continue;
        }
        if (progress.terminal_reason !== "complete") throw new RPCProtocolError("management_unavailable");
        this.#write = undefined;
        this.#publishingPermit?.release(); this.#publishingPermit = undefined;
        if (responding) {
          if (reply!.diagnosticOutcome !== undefined) reply!.diagnostic.failureFacts(reply!.diagnosticOutcome);
          else this.#diagnosticResult(reply!.diagnostic, reply!.result);
          this.#replies.shift(); this.#readWake.signal();
        } else this.#releasePublishingPending();
        this.#wire.fill(0); this.#body.fill(0);
      }
    } catch { this.close(); }
    finally {
      if (this.#write !== undefined) { this.#write.terminate(); await this.#write.waitCleanup(); this.#write = undefined; }
      this.#publishingPermit?.release(); this.#publishingPermit = undefined;
      this.#releasePublishingPending(); this.#publishing = false; this.#collect();
    }
  }
  #releasePublishingPending(): void {
    const pending = this.#publishingPending; this.#publishingPending = undefined;
    if (pending === undefined) return;
    pending.publishing = false;
    if (pending.serial === 0n && pending.resolve === undefined) this.#remove(pending);
    this.#finishPendingDiagnostic(pending);
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#abort.abort(); this.#wake.signal(); this.#readWake.signal();
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    if (this.#yieldTimer !== undefined) clearTimeout(this.#yieldTimer); this.#yieldTimer = undefined;
    const resolveYield = this.#yieldResolve; this.#yieldResolve = undefined; resolveYield?.();
    for (const pending of [...this.#pending]) this.#abandon(pending, new RPCProtocolError("management_unavailable"));
    for (const reply of this.#replies) reply.diagnosticOutcome ??= diagnosticFailure(new RPCProtocolError("management_unavailable"));
    this.#diagnostics = undefined;
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
      for (const pending of [...this.#pending]) { this.#remove(pending); this.#finishPendingDiagnostic(pending); }
      for (const reply of this.#replies) {
        reply.diagnostic.failureFacts(reply.diagnosticOutcome ?? diagnosticFailure(new RPCProtocolError("management_unavailable")));
        reply.owner.release();
      }
      this.#replies.length = 0; this.#wire.fill(0); this.#body.fill(0); this.#input.fill(0);
      this.#wire = this.#body = this.#input = new Uint8Array(); this.#header = undefined; this.#inputDeadline = undefined;
      this.#reference.release(); this.#reference = undefined;
    } finally { this.#collecting = false; }
    this.cleaned();
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
  #diagnosticResult(diagnostic: DiagnosticActivity, result: ExecutionManagementResult): void {
    if (result.status === "ok" || result.status === "not_found" || result.status === "history_unknown" || result.status === "result_expired") {
      diagnostic.event({ state: "ready", code: "ok" }); diagnostic.close();
    } else { diagnostic.failure(new RPCProtocolError(result.status === "deadline_exceeded" ? "deadline_exceeded" : "management_unavailable")); }
  }
}
Object.freeze(ExecutionManagementChannel.prototype);
