import type { CapturedByteEventSource, V4ByteEventPublisher, V4EventPublishResult, V4EventSourceDisposer } from "../eventSource.js";
import type { ApplicationGroup, ApplicationPermit, ApplicationWorkClass } from "./applicationExecutor.js";
import { byteLength, byteSlice } from "./cbor.js";
import type { TrustedClock } from "./clock.js";
import { TrustedWindow, timerChunk } from "./deadline.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { SessionCleanup } from "./sessionCleanup.js";

const copy = Uint8Array.prototype.set, wipe = Uint8Array.prototype.fill;
interface Input { readonly bytes: Uint8Array; readonly reference: ResourceReference; readonly charge: bigint; }
export function eventInputCharge(bytes: number, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([BigInt(bytes) + 512n + 2n * runtimeBytes, 0n, 0n, 3n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function eventSourceCharge(source: CapturedByteEventSource, runtimeBytes: bigint): ResourceVector {
  const maximum = eventInputCharge(source.maxEventInputBytes, runtimeBytes).values()[0]!;
  if (source.maxPendingBytes !== undefined && source.maxPendingBytes < maximum) throw new RPCProtocolError("configuration_capacity");
  // Queue indices, one pump/wakeup, setup/cleanup descriptors and the original
  // fixed close timer. Variable event bytes are acquired at each publication.
  return new ResourceVector([8192n + runtimeBytes * 6n + BigInt(source.maxPendingItems) * 128n, 0n, 0n,
    BigInt(source.maxPendingItems + 8), 1n, 3n, 2n, 0n, 0n, 0n, 0n]);
}
/** One original subscription. A wake carries no application input; ownership
 * stays in the bounded queue until the single pump takes it synchronously. */
export class RPCEventSource {
  #source: CapturedByteEventSource | undefined;
  #reference: ResourceReference | undefined;
  #reserve: ((charge: ResourceVector) => ResourceReference) | undefined;
  #check: (() => void) | undefined;
  #clock: TrustedClock | undefined;
  readonly #queue: Input[] = [];
  #current: Input | undefined;
  #bytes = 0n;
  readonly #maxBytes: bigint;
  #wake: (() => void) | undefined;
  #sealed = false;
  #closed = false;
  #setupDone = false;
  #disposer: V4EventSourceDisposer | undefined;
  #disposing = false;
  #disposed = false;
  #window: TrustedWindow | undefined;
  #failure: "source_overflow" | undefined;
  readonly publisher: V4ByteEventPublisher;
  constructor(source: CapturedByteEventSource, readonly runtimeBytes: bigint, reference: ResourceReference,
    clock: TrustedClock, reserve: (charge: ResourceVector) => ResourceReference, check: () => void) {
    this.#source = source; this.#reference = reference.take(eventSourceCharge(source, runtimeBytes)); this.#clock = clock; this.#reserve = reserve; this.#check = check;
    const maximum = eventInputCharge(source.maxEventInputBytes, runtimeBytes).values()[0]!;
    this.#maxBytes = source.maxPendingBytes ?? (maximum > 262144n ? maximum : 262144n);
    this.publisher = Object.freeze({ tryPublish: (input: Uint8Array) => this.#publish(input), complete: () => this.#complete() });
    Object.freeze(this);
  }
  get source(): CapturedByteEventSource { if (this.#source === undefined) throw new RPCProtocolError("event_source_closed"); return this.#source; }
  #publish(input: Uint8Array): V4EventPublishResult {
    if (this.#sealed || this.#closed) return "closed";
    try { this.#check!(); } catch { this.close(); return "closed"; }
    const length = byteLength(input), charge = eventInputCharge(length, this.runtimeBytes), amount = charge.values()[0]!;
    if (length > this.source.maxEventInputBytes || this.#queue.length + (this.#current === undefined ? 0 : 1) >= this.source.maxPendingItems || amount > this.#maxBytes - this.#bytes) return this.#overflow();
    let reference: ResourceReference | undefined;
    try {
      reference = this.#reserve!(charge);
      const snapshot = new Uint8Array(length); copy.call(snapshot, byteSlice(input, 0, length));
      // No application getter, callback or asynchronous step occurs between
      // the original safety gate, complete reservation and snapshot transfer.
      this.#queue.push({ bytes: snapshot, reference, charge: amount }); this.#bytes += amount; reference = undefined;
      this.#signal(); return "accepted";
    } catch { return this.#overflow(); }
    finally { reference?.release(); }
  }
  #overflow(): "overflow" { this.#failure = "source_overflow"; this.close(); return "overflow"; }
  #complete(): void { if (this.#sealed || this.#closed) return; this.#sealed = true; this.#signal(); }
  get failure(): "source_overflow" | undefined { return this.#failure; }
  get ended(): boolean { return this.#closed || this.#sealed && this.#queue.length === 0 && this.#current === undefined; }
  setupFinished(disposer: void | V4EventSourceDisposer): void {
    if (this.#setupDone) throw new RPCProtocolError("event_source_owner");
    this.#setupDone = true;
    if (disposer !== undefined && typeof disposer !== "function") throw new RPCProtocolError("service_failed");
    this.#disposer = disposer ?? undefined;
  }
  take(): Uint8Array | undefined {
    if (!this.#setupDone || this.#current !== undefined) throw new RPCProtocolError("event_source_owner");
    if (this.#closed) return;
    this.#current = this.#queue.shift(); return this.#current?.bytes;
  }
  releaseCurrent(): void {
    const input = this.#current; this.#current = undefined;
    if (input !== undefined) { wipe.call(input.bytes, 0); input.reference.release(); this.#bytes -= input.charge; }
  }
  wait(): Promise<void> {
    if (this.#wake !== undefined) return Promise.reject(new RPCProtocolError("event_source_owner"));
    if (this.#queue.length !== 0 || this.ended) return Promise.resolve();
    return new Promise<void>(resolve => { this.#wake = resolve; });
  }
  #signal(): void { const wake = this.#wake; this.#wake = undefined; wake?.(); }
  close(): void {
    if (this.#closed) return; this.#closed = this.#sealed = true;
    try { this.#window = new TrustedWindow(this.#clock!, 5000n); } catch { /* Cleanup reports the unavailable original close window. */ }
    for (const input of this.#queue) { wipe.call(input.bytes, 0); input.reference.release(); this.#bytes -= input.charge; }
    this.#queue.length = 0; this.#signal();
  }
  /** Only the original cleanup duty may acquire ordinary service after the
   * business door closes. It receives no invocation or business capability. */
  async dispose(group: ApplicationGroup, workClass: ApplicationWorkClass, cleanup: SessionCleanup): Promise<void> {
    if (this.#disposing || this.#disposed) return;
    this.close(); this.#disposing = true;
    let permit: ApplicationPermit | undefined, running = false, timer: ReturnType<typeof setTimeout> | undefined;
    const abort = new AbortController();
    try {
      const disposer = this.#disposer;
      if (disposer !== undefined) {
        const check = (): void => { this.#reference!.checkRetained(); if (this.#window === undefined) throw new Error("cleanup_incomplete"); this.#window.check(); };
        const tick = (): void => { timer = undefined; try { check(); timer = setTimeout(tick, timerChunk(this.#window!.remainingMS())); } catch { abort.abort(); } };
        tick(); permit = await group.acquire(workClass, abort.signal, check); check();
        if (timer !== undefined) clearTimeout(timer); timer = undefined;
        cleanup.enterCallback(); running = true;
        await disposer(); this.#disposer = undefined;
      }
      this.#disposed = true;
    } catch {
      // Failed or never-entered cleanup retains its subscription responsibility;
      // it cannot report complete or silently refund an external listener.
      cleanup.markIncomplete();
    } finally {
      if (timer !== undefined) clearTimeout(timer); if (running) cleanup.exitCallback(); permit?.release(); this.#disposing = false;
      if (this.#disposed && this.#current === undefined) {
        this.#reference?.release(); this.#reference = undefined; this.#reserve = this.#check = undefined; this.#clock = undefined; this.#window = undefined; this.#source = undefined;
      }
    }
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
Object.freeze(RPCEventSource.prototype); Object.freeze(RPCEventSource);
