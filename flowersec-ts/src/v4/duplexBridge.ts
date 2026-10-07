import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus, V4DuplexDirectionResult, V4DuplexResult, V4StreamStatus, V4TypedError } from "../generated/transportV4APIResults.js";
import type { V4StreamOwner } from "./public.js";
import { byteLength, byteSlice } from "./runtime/cbor.js";
import {
  acquireBridgeStreamAdapter, acquireNativeBridgeDuplexAdapter, hasBridgeStreamAdapter, hasNativeBridgeDuplexAdapter,
  type BridgeStreamAdapterOwner, type NativeBridgeDuplexAdapterOwner,
} from "./runtime/streamAdapter.js";
import { ResourceError, type ResourceReference } from "./runtime/resources.js";
import { cleanupResult } from "./runtime/lifecycle.js";

export interface V4DuplexBridgeOptions {
  readonly readChunkBytes?: number;
  /** Bounds the complete operation, including time before Start. */
  readonly timeoutMS?: number;
  /** Explicit operation cancellation; Wait signals remain passive. */
  readonly signal?: AbortSignal;
  readonly gracefulFinishTimeoutMS?: number;
  readonly cleanupTimeoutMS?: number;
}
export type V4DuplexBridgeFailure = "invalid_endpoint" | "configuration_capacity" | "resource_exhausted" | "deadline_exceeded" | "stream_owned" | "owner_unavailable" | "read_failed" | "write_failed" | "finish_failed" | "wait_canceled" | "wait_in_progress";
export interface V4DuplexBridgeDirectionProgress {
  readonly source_read_bytes: bigint;
  readonly destination_accepted_bytes: bigint;
  readonly unaccepted_tail_bytes: bigint;
  readonly source_status: V4StreamStatus;
  readonly send_drained?: boolean;
  readonly native_send_finished?: boolean;
}
export interface V4DuplexBridgeProgress {
  readonly state: "prepared" | "running" | "terminal";
  readonly outcome: "normal" | "failed" | "aborted";
  readonly a_to_b: V4DuplexBridgeDirectionProgress;
  readonly b_to_a: V4DuplexBridgeDirectionProgress;
  readonly cleanup_status: V4CleanupStatus;
  readonly failure?: V4DuplexBridgeFailure;
  readonly first_error?: V4TypedError;
}
/** One caller-owned result. Release only returns its detached tail backing;
 * it neither closes Streams nor changes the immutable progress snapshot. */
export interface V4DuplexBridgeResult extends V4DuplexResult {
  readonly failure?: V4DuplexBridgeFailure;
  release(): void;
}
export class V4DuplexBridgeError extends Error {
  constructor(readonly code: V4DuplexBridgeFailure, readonly progress?: V4DuplexBridgeProgress) {
    super(code); this.name = "DuplexBridgeError"; Object.freeze(this);
  }
}
interface Direction {
  read: bigint;
  accepted: bigint;
  tail: Uint8Array;
  filled: number;
  status: V4StreamStatus;
  drained: boolean;
  backing: ResourceReference | undefined;
  endpointKind: "flowersec_stream" | "native_duplex";
  sendEndpointKind: "flowersec_stream" | "native_duplex";
}
interface Waiter<T> {
  readonly signal: AbortSignal | undefined;
  readonly canceled: () => void;
  readonly resolve: (value: T) => void;
  readonly reject: (error: V4DuplexBridgeError) => void;
}
const NativePromise = Promise;
const complete = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const empty = (): Uint8Array => new Uint8Array();
function bound(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new V4DuplexBridgeError("configuration_capacity");
  return value;
}
type BridgeEndpointOwner = BridgeStreamAdapterOwner | NativeBridgeDuplexAdapterOwner;
function direction(owner: BridgeEndpointOwner, destination: BridgeEndpointOwner): Direction {
  return { read: 0n, accepted: 0n, tail: new Uint8Array(owner.readBytes), filled: 0, status: owner.readState().stream_status,
    drained: false, backing: owner.resultBacking, endpointKind: owner.endpointKind, sendEndpointKind: destination.endpointKind };
}
function snapshot(value: Direction): V4DuplexBridgeDirectionProgress {
  return Object.freeze({ source_read_bytes: value.read, destination_accepted_bytes: value.accepted,
    unaccepted_tail_bytes: BigInt(value.filled), source_status: value.status,
    ...(value.sendEndpointKind === "native_duplex" ? { native_send_finished: value.drained } : { send_drained: value.drained }) });
}
/** Owns a pair of accepted Flowersec Streams or one Flowersec Stream and one
 * registered Node native byte Duplex. Every endpoint stays behind its original owner. */
export class V4DuplexBridge {
  #a: BridgeEndpointOwner | undefined;
  #b: BridgeEndpointOwner | undefined;
  readonly #ab: Direction;
  readonly #ba: Direction;
  readonly #operations = new AbortController();
  readonly #cleanupMS: number;
  #started = false;
  #running = false;
  #terminal = false;
  #aborting = false;
  #outcome: "normal" | "failed" | "aborted" = "normal";
  #failure: V4DuplexBridgeFailure | undefined;
  #firstError: V4TypedError | undefined;
  #tails = 0;
  #cleaned = false;
  #cleanupExpired = false;
  #cleanupTimer: ReturnType<typeof setTimeout> | undefined;
  #operationTimer: ReturnType<typeof setTimeout> | undefined;
  #operationSignal: AbortSignal | undefined;
  readonly #operationCanceled = (): void => this.#abort("aborted");
  #waiter: Waiter<V4DuplexBridgeResult> | undefined;
  #cleanupWaiter: Waiter<V4CleanupStatus> | undefined;
  #result: V4DuplexBridgeResult | undefined;
  #queued = false;
  #constructing = true;

  constructor(a: V4StreamOwner, b: V4StreamOwner, options: V4DuplexBridgeOptions = {}) {
    if (a === b) throw new V4DuplexBridgeError("invalid_endpoint");
    const readBytes = bound(options.readChunkBytes ?? 16384, 1048576);
    const timeoutMS = bound(options.timeoutMS ?? 90000, 90000);
    const operationSignal = options.signal;
    const gracefulFinishMS = bound(options.gracefulFinishTimeoutMS ?? 30000, 90000);
    this.#cleanupMS = bound(options.cleanupTimeoutMS ?? 5000, 90000);
    const nativePair = hasNativeBridgeDuplexAdapter(a) || hasNativeBridgeDuplexAdapter(b);
    if (nativePair && readBytes > 65536) throw new V4DuplexBridgeError("configuration_capacity");
    const profile = { kind: "bridge" as const, readBytes, inputBackingBytes: readBytes * (nativePair ? 4 : 1), inputEntries: 1,
      gracefulFinishMS, cleanupMS: this.#cleanupMS, ...(nativePair ? { nativeEndpoint: true } : {}) };
    let left: BridgeEndpointOwner | undefined, right: BridgeEndpointOwner | undefined;
    try {
      if (a === b) throw new V4DuplexBridgeError("invalid_endpoint");
      if (nativePair) {
        if (hasNativeBridgeDuplexAdapter(a) === hasNativeBridgeDuplexAdapter(b)) throw new V4DuplexBridgeError("invalid_endpoint");
        const stream = hasBridgeStreamAdapter(a) ? a : hasBridgeStreamAdapter(b) ? b : undefined;
        const native = stream === a ? b : a;
        if (stream === undefined || !hasNativeBridgeDuplexAdapter(native)) throw new V4DuplexBridgeError("invalid_endpoint");
        const streamOwner = acquireBridgeStreamAdapter(stream, profile);
        if (stream === a) left = streamOwner; else right = streamOwner;
        const nativeBacking = streamOwner.nativeResultBacking, nativeIOBacking = streamOwner.nativeIOBacking;
        if (nativeBacking === undefined || nativeIOBacking === undefined) throw new V4DuplexBridgeError("owner_unavailable");
        const nativeOwner = acquireNativeBridgeDuplexAdapter(native, profile, nativeBacking, nativeIOBacking);
        if (stream === a) right = nativeOwner; else left = nativeOwner;
      } else {
        if (!hasBridgeStreamAdapter(a) || !hasBridgeStreamAdapter(b)) throw new V4DuplexBridgeError("invalid_endpoint");
        left = acquireBridgeStreamAdapter(a, profile); right = acquireBridgeStreamAdapter(b, profile);
      }
      if (left === undefined || right === undefined) throw new V4DuplexBridgeError("owner_unavailable");
      const leftOwner = left, rightOwner = right;
      this.#ab = direction(leftOwner, rightOwner); this.#ba = direction(rightOwner, leftOwner);
      this.#a = leftOwner; this.#b = rightOwner;
      leftOwner.invalidateWith(() => this.#invalidated()); rightOwner.invalidateWith(() => this.#invalidated());
      leftOwner.sendStoppedWith(() => this.#stopped()); rightOwner.sendStoppedWith(() => this.#stopped());
      leftOwner.cleanupWith(() => this.#schedule()); rightOwner.cleanupWith(() => this.#schedule());
      leftOwner.check(); rightOwner.check();
      Object.defineProperty(this, "then", { value: undefined });
      this.#constructing = false;
      this.#operationSignal = operationSignal;
      operationSignal?.addEventListener("abort", this.#operationCanceled, { once: true });
      this.#operationTimer = setTimeout(() => this.#abort("aborted", "deadline_exceeded"), timeoutMS);
      if (operationSignal?.aborted) this.#abort("aborted");
    } catch (error) {
      left?.resultBacking.release(); right?.resultBacking.release(); left?.rollback(); right?.rollback();
      this.#stopOperationDeadline();
      const reason = error instanceof ResourceError && (error.code === "resource_exhausted" || error.code === "configuration_capacity") ? error.code :
        error instanceof Error && error.message === "stream_owned" ? "stream_owned" : "owner_unavailable";
      throw error instanceof V4DuplexBridgeError ? error : new V4DuplexBridgeError(reason);
    }
  }
  start(): void {
    if (this.#started || this.#terminal) return;
    this.#started = true; this.#running = true;
    // Starting chooses the two original I/O owners once, before any pump job.
    void this.#run();
  }
  abort(): void { this.#abort("aborted"); }
  progress(): V4DuplexBridgeProgress {
    const value = { state: this.#terminal ? "terminal" as const : this.#started ? "running" as const : "prepared" as const,
      outcome: this.#outcome, a_to_b: snapshot(this.#ab), b_to_a: snapshot(this.#ba), cleanup_status: this.cleanupStatus(),
      ...(this.#failure === undefined ? {} : { failure: this.#failure }), ...(this.#firstError === undefined ? {} : { first_error: this.#firstError }) };
    Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
  }
  wait(options?: OperationOptions): Promise<V4DuplexBridgeResult> {
    return new NativePromise((resolve, reject) => {
      if (this.#waiter !== undefined) { reject(new V4DuplexBridgeError("wait_in_progress", this.progress())); return; }
      const waiter: Waiter<V4DuplexBridgeResult> = { resolve, reject, signal: options?.signal, canceled: () => this.#schedule() };
      this.#waiter = waiter; waiter.signal?.addEventListener("abort", waiter.canceled, { once: true }); this.#schedule();
    });
  }
  cleanupStatus(): V4CleanupStatus {
    if (this.#cleaned) return complete;
    return cleanupResult({ status: this.#cleanupExpired ? "cleanup_incomplete" : "pending", core_cleanup: "pending",
      pending_callbacks: BigInt((this.#running ? 2 : 0) + this.#tails) });
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    return new NativePromise((resolve, reject) => {
      if (this.#cleanupWaiter !== undefined) { reject(new V4DuplexBridgeError("wait_in_progress", this.progress())); return; }
      const waiter: Waiter<V4CleanupStatus> = { resolve, reject, signal: options?.signal, canceled: () => this.#schedule() };
      this.#cleanupWaiter = waiter; waiter.signal?.addEventListener("abort", waiter.canceled, { once: true });
      this.#observeCleanupDeadline(); this.#schedule();
    });
  }
  #invalidated(): void {
    if (this.#constructing || this.#terminal && this.#outcome === "normal") return;
    this.#abort("failed", "owner_unavailable");
  }
  #stopped(): void {
    if (!this.#constructing && !this.#terminal) this.#abort("failed", "write_failed");
  }
  #abort(outcome: "failed" | "aborted", failure?: V4DuplexBridgeFailure, error?: V4TypedError): void {
    if (this.#terminal && this.#outcome === "normal" || this.#aborting || this.#cleaned) return;
    this.#aborting = true; this.#outcome = outcome; this.#failure = failure;
    this.#rememberError(error);
    for (const owner of [this.#a, this.#b]) {
      try { this.#rememberError(owner?.readState().error); } catch { /* Keep the last original error observation. */ }
    }
    this.#operations.abort();
    // The abort gate is chosen before either reset can synchronously invalidate
    // an adapter. Each original physical tail continues after a timed wait.
    for (const owner of [this.#a, this.#b]) {
      if (owner === undefined) continue;
      this.#tails++;
      try { void owner.reset().then(() => undefined, () => undefined).finally(() => { this.#tails--; this.#schedule(); }); }
      catch { this.#tails--; }
    }
    if (!this.#started) {
      this.#terminal = true;
      for (const [owner, state] of [[this.#a, this.#ab], [this.#b, this.#ba]] as const) {
        try { state.status = owner?.readState().stream_status ?? state.status; } catch { /* Preserve the last original observation. */ }
      }
    }
    this.#stopOperationDeadline(); this.#observeCleanupDeadline(); this.#schedule();
  }
  async #run(): Promise<void> {
    try {
      await NativePromise.all([this.#copy(this.#a!, this.#b!, this.#ab), this.#copy(this.#b!, this.#a!, this.#ba)]);
      if (!this.#aborting) {
        await NativePromise.all([this.#finish(this.#a!, this.#ba), this.#finish(this.#b!, this.#ab)]);
      }
    } catch { if (!this.#aborting) this.#abort("failed", "owner_unavailable"); }
    finally {
      this.#running = false; this.#terminal = true;
      this.#stopOperationDeadline(); this.#observeCleanupDeadline(); this.#schedule();
    }
  }
  async #copy(source: BridgeEndpointOwner, destination: BridgeEndpointOwner, state: Direction): Promise<void> {
    let stage: "read_failed" | "write_failed" | "finish_failed" = "read_failed";
    try {
      while (!this.#aborting) {
        stage = "read_failed";
        // Reserve room for the largest next source chunk before advancing its
        // non-seekable owner. Accepted bytes cannot exceed this guarded count.
        if (state.read > 0xffffffffffffffffn - BigInt(source.readBytes)) throw new Error("read_failed");
        const result = await source.read({ signal: this.#operations.signal });
        const count = byteLength(result.data);
        if (count > source.readBytes) throw new Error("read_failed");
        state.read += BigInt(count); state.status = result.stream_status;
        // Save the source-owned prefix before a destination host operation.
        // At most this direction's one read chunk is ever outstanding.
        state.tail.set(result.data); state.filled = count;
        if (result.error !== undefined) { this.#rememberError(result.error); this.#abort("failed", "read_failed", result.error); return; }
        while (state.filled !== 0 && !this.#aborting) {
          stage = "write_failed";
          const offered = state.filled;
          const written = await destination.write(byteSlice(state.tail, 0, offered), { signal: this.#operations.signal });
          if (written.accepted_bytes < 0n || written.accepted_bytes > BigInt(offered)) throw new Error("write_failed");
          const accepted = Number(written.accepted_bytes); state.accepted += written.accepted_bytes;
          state.tail.copyWithin(0, accepted, offered); state.tail.fill(0, offered - accepted); state.filled = offered - accepted;
          if (accepted === 0 || written.terminal_reason !== "complete") throw new Error("write_failed");
          this.#schedule();
          if (destination.endpointKind === "native_duplex") await destination.waitProducerExit({ signal: this.#operations.signal });
        }
        if (this.#aborting) return;
        if (result.stream_status === "eof") {
          stage = "finish_failed";
          const closed = await destination.closeWrite({ signal: this.#operations.signal });
          if (closed.first_error !== undefined) { this.#abort("failed", stage, closed.first_error); return; }
          return;
        }
        if (result.stream_status !== "open" || result.wait_status === "wait_canceled" || count === 0) throw new Error("read_failed");
        this.#schedule();
      }
    } catch { if (!this.#aborting) this.#abort("failed", stage); }
    finally {
      try {
        const observed = source.readState();
        if (state.status === "open" && observed.stream_status !== "open") state.status = observed.stream_status;
        this.#rememberError(observed.error);
        if (!this.#aborting && observed.error !== undefined) this.#abort("failed", "read_failed", observed.error);
      } catch { if (!this.#aborting) this.#abort("failed", "owner_unavailable"); }
    }
  }
  async #finish(owner: BridgeEndpointOwner, direction: Direction): Promise<void> {
    try {
      const result = await owner.finish({ signal: this.#operations.signal }); direction.drained = result.send_drained;
      if (result.first_error !== undefined) this.#abort("failed", "finish_failed", result.first_error);
      else if (!result.send_drained || result.read_terminal !== "eof") this.#abort("failed", "finish_failed");
    } catch { if (!this.#aborting) this.#abort("failed", "finish_failed"); }
  }
  #rememberError(error: V4TypedError | undefined): void {
    if (error !== undefined && this.#firstError === undefined && !this.#terminal) this.#firstError = Object.freeze({
      code: error.code, scope: error.scope, retry_disposition: error.retry_disposition,
    });
  }
  #stopOperationDeadline(): void {
    if (this.#operationTimer !== undefined) clearTimeout(this.#operationTimer); this.#operationTimer = undefined;
    this.#operationSignal?.removeEventListener("abort", this.#operationCanceled); this.#operationSignal = undefined;
  }
  #observeCleanupDeadline(): void {
    if (this.#cleaned || this.#cleanupExpired || this.#cleanupTimer !== undefined) return;
    this.#cleanupTimer = setTimeout(() => { this.#cleanupTimer = undefined; this.#cleanupExpired = true; this.#schedule(); }, this.#cleanupMS);
  }
  #schedule(): void {
    if (this.#queued || this.#constructing) return;
    this.#queued = true; queueMicrotask(() => { this.#queued = false; this.#collect(); this.#wake(); });
  }
  #collect(): void {
    if (this.#cleaned || !this.#terminal || this.#running || this.#tails !== 0) return;
    if (this.#a?.cleanupStatus().status !== "complete" || this.#b?.cleanupStatus().status !== "complete") return;
    this.#a.release(); this.#b.release(); this.#a = this.#b = undefined; this.#cleaned = true;
    if (this.#cleanupTimer !== undefined) clearTimeout(this.#cleanupTimer); this.#cleanupTimer = undefined;
    // Empty final results need no retained backing after protocol retirement.
    for (const state of [this.#ab, this.#ba]) if (state.filled === 0) { state.tail = empty(); state.backing?.release(); state.backing = undefined; }
  }
  #wake(): void {
    const waiter = this.#waiter;
    if (waiter !== undefined && (waiter.signal?.aborted || this.#terminal)) {
      this.#waiter = undefined; waiter.signal?.removeEventListener("abort", waiter.canceled);
      if (waiter.signal?.aborted) waiter.reject(new V4DuplexBridgeError("wait_canceled", this.progress()));
      else { this.#result ??= this.#takeResult(); waiter.resolve(this.#result); }
    }
    const cleanup = this.#cleanupWaiter;
    if (cleanup !== undefined && (cleanup.signal?.aborted || this.#cleaned || this.#cleanupExpired)) {
      this.#cleanupWaiter = undefined; cleanup.signal?.removeEventListener("abort", cleanup.canceled);
      if (cleanup.signal?.aborted) cleanup.reject(new V4DuplexBridgeError("wait_canceled", this.progress())); else cleanup.resolve(this.cleanupStatus());
    }
  }
  #takeResult(): V4DuplexBridgeResult {
    const resultDirection = (state: Direction): V4DuplexDirectionResult => Object.freeze({
      progress: Object.freeze({ source_read_bytes: state.read, destination_accepted_bytes: state.accepted,
        unaccepted_tail: state.filled === 0 ? empty() : byteSlice(state.tail, 0, state.filled) }),
      source_status: state.status, send_result: Object.freeze({ endpoint_kind: state.sendEndpointKind,
        ...(state.sendEndpointKind === "native_duplex" ? { native_send_finished: state.drained } : { send_drained: state.drained }) }),
    });
    const buffers: Uint8Array[] = [], references: ResourceReference[] = [];
    for (const state of [this.#ab, this.#ba]) {
      if (state.filled !== 0) { buffers.push(state.tail); if (state.backing !== undefined) references.push(state.backing); }
      else { state.tail.fill(0); state.backing?.release(); state.backing = undefined; }
    }
    const value = { a_to_b: resultDirection(this.#ab), b_to_a: resultDirection(this.#ba), outcome: this.#outcome, cleanup_status: this.cleanupStatus(),
      ...(this.#failure === undefined ? {} : { failure: this.#failure }), ...(this.#firstError === undefined ? {} : { first_error: this.#firstError }),
      release: () => { if (released) return; released = true; for (const bytes of buffers) bytes.fill(0); for (const reference of references) reference.release(); } };
    let released = false;
    for (const state of [this.#ab, this.#ba]) { state.tail = empty(); state.backing = undefined; }
    Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
  }
}
Object.freeze(V4DuplexBridge.prototype); Object.freeze(V4DuplexBridge);
