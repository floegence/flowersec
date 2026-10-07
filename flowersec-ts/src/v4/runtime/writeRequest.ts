import type { OperationOptions } from "../../public/contract.js";
import type { V4CleanupStatus, V4WriteProgress, V4WriteTerminalReason } from "../../generated/transportV4APIResults.js";
import type { V4WriteRequestOwner } from "../public.js";
import { byteLength, byteSlice } from "./cbor.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { DiagnosticActivity } from "./diagnosticObservation.js";
import { diagnosticFailure } from "./diagnosticCounters.js";

const NativePromise = Promise;
const empty = new Uint8Array();
const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const pending: V4CleanupStatus = Object.freeze({ status: "pending", core_cleanup: "pending", pending_callbacks: 0n });
export function writeRequestCharge(bytes: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > 1048576 || runtimeBytes <= 0n) throw new Error("configuration_capacity");
  return new ResourceVector([BigInt(bytes) + runtimeBytes, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 1n, 0n]);
}
export interface WriteRequestTarget {
  readonly maxChunk: number;
  readyBytes(): number;
  waitReady(signal: AbortSignal): Promise<void>;
  send(bytes: Uint8Array, admitted: (bytes: number) => void, signal: AbortSignal): Promise<void>;
  release(request: ReliableWriteRequest): void;
}
interface Waiter {
  readonly resolve: (progress: V4WriteProgress) => void; readonly reject: (error: unknown) => void;
  readonly signal: AbortSignal | undefined; readonly canceled: () => void;
  armed: boolean; queued: boolean;
}

/** Exactly one prepaid immutable request per direction. Cancellation fences
 * future native admission; accepted bytes never decrease, and the private copy
 * stays charged until every admitted output callback has actually returned. */
export class ReliableWriteRequest implements V4WriteRequestOwner {
  readonly #requested: bigint;
  readonly #abort = new AbortController();
  #payload: Uint8Array = empty;
  #reservation: ResourceReference | undefined;
  #phase: V4WriteProgress["phase"] = "prepared";
  #reason: V4WriteTerminalReason = "none";
  #accepted = 0n;
  #running = false;
  #operation: Promise<void> | undefined;
  #released = false;
  #protocolAdmitted = false;
  #firstNativeAdmission: (() => void) | undefined;
  #handoff: (() => void) | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #waiter: Waiter | undefined;
  constructor(private readonly target: WriteRequestTarget, payload: Uint8Array, private readonly deadline: TrustedDeadline,
    runtimeBytes: bigint, reservation: ResourceReference, private readonly diagnostic?: DiagnosticActivity) {
    const size = byteLength(payload); this.#requested = BigInt(size);
    this.#reservation = reservation.take(writeRequestCharge(size, runtimeBytes));
    try {
      this.#payload = new Uint8Array(size); Uint8Array.prototype.set.call(this.#payload, payload); deadline.check();
      // Construction cannot notify the target before it has installed this
      // request. The first expiration check runs from the original timer.
      this.#timer = setTimeout(() => { this.#timer = undefined; this.#arm(); }, timerChunk(deadline.remainingMS()));
    }
    catch (error) { this.#payload.fill(0); this.#reservation.release(); this.#reservation = undefined; throw error; }
    Object.defineProperty(this, "then", { value: undefined });
  }
  #arm(): void {
    try {
      this.deadline.check();
      this.#timer = setTimeout(() => { this.#timer = undefined; this.#arm(); }, timerChunk(this.deadline.remainingMS()));
    } catch { this.#finish("deadline_exceeded"); }
  }
  start(): void {
    if (this.#phase !== "prepared") return;
    if (this.#abort.signal.aborted) { this.#finish("canceled"); return; }
    try { this.deadline.check(); this.#reservation!.check(); }
    catch { this.#finish("deadline_exceeded"); return; }
    this.#phase = "running"; this.#running = true;
    this.#operation = this.#run();
  }
  /** Private protocol preparation samples time before its synchronous commit
   * gate. The prepared immutable copy already belongs to this Stream. */
  checkProtocolAdmission(): void {
    if (this.#phase !== "prepared" || this.#protocolAdmitted) throw new Error("write_owner");
    this.deadline.check(); this.#reservation!.check();
  }
  /** SDK-only all-or-zero transfer of the prepared fragment responsibility.
   * No timer/provider/application operation runs at this linearization point.
   * Public accepted_bytes still reports the actual native accepted prefix. */
  admitProtocol(): boolean {
    if (this.#phase !== "prepared" || this.#protocolAdmitted || this.#abort.signal.aborted) return false;
    this.#protocolAdmitted = true; return true;
  }
  /** Fixed M framing commits its serial at the first accepted native record. */
  observeFirstNativeAdmission(callback: () => void): void {
    if (this.#phase !== "prepared" || this.#protocolAdmitted || this.#firstNativeAdmission !== undefined) throw new Error("write_owner");
    this.#firstNativeAdmission = callback;
  }
  /** Original SDK observer; no application callback is accepted here. */
  observeProtocolHandoff(callback: () => void): void {
    if (this.#phase !== "prepared" || !this.#protocolAdmitted || this.#handoff !== undefined) throw new Error("write_owner");
    this.#handoff = callback;
  }
  async #run(): Promise<void> {
    try {
      while (this.#accepted < this.#requested) {
        this.#check();
        const ready = this.target.readyBytes();
        if (ready === 0) { await this.target.waitReady(this.#abort.signal); continue; }
        const at = Number(this.#accepted), n = Math.min(ready, this.target.maxChunk, this.#payload.length - at);
        await this.target.send(byteSlice(this.#payload, at, at + n), count => {
          if (count !== n || this.#accepted !== BigInt(at)) throw new Error("write_owner");
          if (this.#firstNativeAdmission !== undefined) {
            const first = this.#firstNativeAdmission; this.#firstNativeAdmission = undefined;
            this.#protocolAdmitted = true;
            first();
          }
          this.#accepted += BigInt(count);
          if (this.#accepted === this.#requested) { const handoff = this.#handoff; this.#handoff = undefined; handoff?.(); }
          this.#wake();
        }, this.#abort.signal);
      }
      this.#finish("complete");
    } catch {
      if (this.#reason === "none") {
        try { this.deadline.check(); this.#finish(this.#abort.signal.aborted ? "canceled" : "failed"); }
        catch { this.#finish("deadline_exceeded"); }
      }
    } finally { this.#running = false; this.#cleanup(); this.#wake(); }
  }
  #check(): void {
    if (this.#abort.signal.aborted || this.#phase === "terminal") throw new Error("canceled");
    this.#reservation!.check(); this.deadline.check();
  }
  cancel(): void { if (!this.#protocolAdmitted && this.#phase !== "terminal") this.#finish("canceled"); }
  terminate(): void { if (this.#phase !== "terminal") this.#finish("stream_terminated"); }
  #finish(reason: V4WriteTerminalReason): void {
    if (this.#phase === "terminal") return;
    this.#reason = reason; this.#phase = "terminal"; this.#abort.abort();
    this.diagnostic?.event(reason === "complete" ? { state: "ready", code: "ok" } : {
      state: "failed", code: diagnosticFailure(new Error(reason)).code, retry_disposition: "preserve_facts",
    });
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.#cleanup(); this.#wake();
  }
  #cleanup(): void {
    if (this.#phase !== "terminal" || this.#running || this.#released) return;
    this.#released = true; this.#handoff = undefined; this.#firstNativeAdmission = undefined; this.#payload.fill(0); this.#payload = empty;
    this.#reservation?.release(); this.#reservation = undefined; this.target.release(this);
    this.diagnostic?.close();
  }
  progress(): V4WriteProgress {
    const result = { requested_bytes: this.#requested, accepted_bytes: this.#accepted, phase: this.#phase,
      terminal_reason: this.#reason, cleanup_status: this.cleanupStatus() };
    Object.defineProperty(result, "then", { value: undefined }); return Object.freeze(result);
  }
  cleanupStatus(): V4CleanupStatus { return this.#reservation === undefined ? complete : pending; }
  waitCleanup(): Promise<void> { return this.#operation ?? NativePromise.resolve(); }
  wait(options?: OperationOptions): Promise<V4WriteProgress> {
    let resolve!: (progress: V4WriteProgress) => void, reject!: (error: unknown) => void;
    const promise = new NativePromise<V4WriteProgress>((yes, no) => { resolve = yes; reject = no; });
    if (this.#waiter !== undefined) { reject(new Error("write_wait_in_progress")); return promise; }
    const waiter: Waiter = { resolve, reject, signal: options?.signal, canceled: () => this.#wake(), armed: false, queued: false };
    this.#waiter = waiter; waiter.signal?.addEventListener("abort", waiter.canceled, { once: true });
    this.#wake(); waiter.armed = true; return promise;
  }
  #wake(): void {
    const waiter = this.#waiter; if (waiter === undefined || waiter.queued) return;
    waiter.queued = true;
    queueMicrotask(() => {
      waiter.queued = false;
      if (!waiter.armed || this.#waiter !== waiter || this.#phase !== "terminal" && !waiter.signal?.aborted) return;
      this.#waiter = undefined; waiter.signal?.removeEventListener("abort", waiter.canceled);
      waiter.resolve(this.progress());
    });
  }
}
