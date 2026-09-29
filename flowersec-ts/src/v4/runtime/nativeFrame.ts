import type { OperationOptions } from "../../public/contract.js";
import type { V4NativeApplicationStream } from "./session.js";
import type { NativeReceiveClaim, ReliableReceiveDirection } from "./receiveDirection.js";
import { inspectEnvelopePrefix, inspectRecordPrefix, type ParsedRecord } from "./envelope.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { StreamDataBounds } from "./streamData.js";
import { envelopePrefixBytes, recordHeaderBytes, wire } from "./wireRegistry.js";
import type { NativeCandidatePermit, NativeCandidatePool } from "./nativeCandidates.js";

const openingBytes = 4480 + envelopePrefixBytes;
const fixedPrefixBytes = envelopePrefixBytes + recordHeaderBytes;
const quantum = 16384;
export function nativeFrameCharge(runtimeBytes: bigint, headerBytes = openingBytes): ResourceVector {
  if (runtimeBytes <= 0n || !Number.isSafeInteger(headerBytes) || headerBytes < envelopePrefixBytes || headerBytes > openingBytes) throw new Error("configuration_capacity");
  // Includes the bounded replacement overlap when OPEN staging becomes H_DATA.
  return new ResourceVector([BigInt(headerBytes) + 128n + 512n + runtimeBytes, 0n, 0n, 1n, 1n, 2n, 1n, 0n, 0n, 0n, 0n]);
}
export function nativeOpeningCharge(): ResourceVector {
  return new ResourceVector([BigInt(openingBytes) + 128n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export interface NativeFramePromise {
  readonly direction: ReliableReceiveDirection;
  readonly bounds: StreamDataBounds;
  readonly remaining: bigint;
}
export interface NativeFrameCandidate {
  readonly header: ParsedRecord;
  readonly segments: readonly Uint8Array[];
  release(): void;
}
export interface NativeFramePrefetch {
  readonly pool: NativeCandidatePool;
  /** Only original, accepted, unsealed DATA authority; no raw next header
   * participates in this decision or chooses a key. */
  preview(): NativeFramePromise | undefined;
}
interface CandidateState {
  head: Uint8Array;
  parts: Uint8Array[];
  claim?: NativeReceiveClaim;
  permit?: NativeCandidatePermit;
  filled: number;
  length: number;
  headBytes: number;
  eof: boolean;
  complete: boolean;
  promoted: boolean;
  authenticationStarted: boolean;
  failed: boolean;
  error?: unknown;
}
function state(head: Uint8Array): CandidateState {
  return { head, parts: [], filled: 0, length: 0, headBytes: 0, eof: false, complete: false, promoted: false, authenticationStarted: false, failed: false };
}

/** Native DATA uses the original promise plus fixed H_DATA. Optional next
 * assembly owns one Session permit, never an authentication slot or a key.
 * One actual read and one promoted authentication can run per direction. */
export class NativeFrameReader {
  #reference: ResourceReference | undefined;
  #opening: ResourceReference | undefined;
  readonly #prepaid: boolean;
  #head = new Uint8Array();
  #current: CandidateState | undefined;
  #next: CandidateState | undefined;
  #candidate: NativeFrameCandidate | undefined;
  #prefetchTask: Promise<void> | undefined;
  #cancelRequest: (() => void) | undefined;
  readonly #abort = new AbortController();
  #options: OperationOptions | undefined;
  #busy = false;
  #closed = false;
  #readBytes = 0;
  constructor(private readonly transport: V4NativeApplicationStream, private readonly maxFrame: number,
    private readonly profile: string, private readonly runtimeBytes: bigint, reference: ResourceReference,
    private readonly preflight: (type: number, payload: number) => NativeFramePromise | undefined,
    private readonly prefetch?: NativeFramePrefetch, private readonly changed?: () => void, opening?: ResourceReference) {
    this.#prepaid = opening !== undefined;
    this.#reference = reference.take(nativeFrameCharge(runtimeBytes, this.#prepaid ? 128 : openingBytes));
    try { this.#opening = opening?.take(nativeOpeningCharge()); this.#head = new Uint8Array(openingBytes); }
    catch (error) { this.close(); throw error; }
  }
  bindData(bounds: StreamDataBounds): void {
    if (this.#closed || this.#busy || this.#candidate !== undefined || this.#next !== undefined) throw new Error("busy");
    const overhead = bounds.overhead();
    if (overhead > 128) throw new Error("configuration_capacity");
    if (this.#head.length === overhead) return;
    this.#reference!.check();
    const next = new Uint8Array(overhead);
    this.#head.fill(0); this.#head = next;
    if (this.#prepaid) { this.#opening?.release(); this.#opening = undefined; }
    else this.#reference!.shrink(nativeFrameCharge(this.runtimeBytes, overhead));
  }
  #check(options?: OperationOptions): void {
    if (this.#closed || options?.signal?.aborted) throw new Error("closed");
    this.#reference!.check();
  }
  async #readTo(s: CandidateState, parts: readonly Uint8Array[], target: number, options: OperationOptions,
    allowed: () => boolean): Promise<boolean> {
    while (s.filled < target) {
      this.#check(options); s.claim?.check();
      if (!allowed()) return false;
      let offset = s.filled, part: Uint8Array | undefined;
      for (const candidate of parts) {
        if (offset < candidate.length) { part = candidate; break; }
        offset -= candidate.length;
      }
      if (part === undefined) throw new Error("invalid_resource_owner");
      const allowance = Math.min(quantum, target - s.filled, part.length - offset);
      const bytes = await this.transport.read(allowance, options);
      this.#check(options); s.claim?.check();
      if (bytes === null) {
        if (s.filled === 0) { s.eof = true; return false; }
        throw new Error("truncated");
      }
      if (bytes.length < 1 || bytes.length > allowance) throw new Error("carrier_failed");
      part.set(bytes, offset); s.filled += bytes.length;
      if (s === this.#current) this.#readBytes = s.filled;
      // Short completions return a host turn before another read, so other
      // directions and maintenance do not wait for this complete body.
      if (s.filled < target) await new Promise<void>(resolve => { setTimeout(resolve, 0); });
    }
    return true;
  }
  async #assemble(s: CandidateState, next: boolean, options: OperationOptions): Promise<void> {
    const mayReadPrefix = (): boolean => !next || this.prefetch?.preview() !== undefined;
    if (!await this.#readTo(s, [s.head.subarray(0, envelopePrefixBytes)], envelopePrefixBytes, options, mayReadPrefix)) return;
    const prefix = inspectEnvelopePrefix(s.head, this.maxFrame);
    s.length = envelopePrefixBytes + prefix.payloadBytes;
    if (next) {
      if (prefix.frameType !== wire.frame_types.STREAM_DATA || s.length < fixedPrefixBytes + 16) throw new Error("protocol_violation");
      // No record semantics are inspected until promotion. A next with no
      // complete body claim retains only this envelope/fixed-header prefix.
      if (!await this.#readTo(s, [s.head.subarray(0, fixedPrefixBytes)], fixedPrefixBytes, options, mayReadPrefix)) return;
    }
    const promise = next ? this.prefetch?.preview() : this.preflight(prefix.frameType, prefix.payloadBytes);
    if (next && promise === undefined) return;
    s.headBytes = promise === undefined ? s.length : Math.min(s.length, promise.bounds.overhead());
    if (s.headBytes > s.head.length) throw new Error("configuration_capacity");
    if (promise !== undefined) {
      if (!next && s.length > promise.bounds.maximumEnvelope(promise.remaining)) throw new Error("receive_credit");
      if (s.claim === undefined) {
        const upper = promise.bounds.payloadUpper(s.length);
        if (next && upper > promise.remaining) return;
        const amount = next || upper < promise.remaining ? upper : promise.remaining;
        const claim = promise.direction.claimNative(s.length - s.headBytes, amount, next);
        if (claim === undefined) return;
        s.claim = claim;
      }
    }
    s.parts = [s.head.subarray(0, s.headBytes), ...(s.claim?.segments ?? [])];
    const allowed = (): boolean => {
      if (!next) { this.preflight(prefix.frameType, prefix.payloadBytes); return true; }
      const current = this.prefetch?.preview();
      // Rekey/FIN/STOPPED stop new overlap. Real input already in flight keeps
      // its storage; a smaller final frontier is rechecked in original order.
      return current !== undefined && s.claim !== undefined && current.direction.nativePrefetchFits(s.claim, current.remaining);
    };
    s.complete = await this.#readTo(s, s.parts, s.length, options, allowed);
  }
  #requestNext(s: CandidateState): void {
    if (this.#closed || this.prefetch === undefined || s.claim === undefined || this.#cancelRequest !== undefined || this.#next !== undefined ||
        this.#prefetchTask !== undefined || this.prefetch.preview() === undefined) return;
    this.#cancelRequest = this.prefetch.pool.request(this, permit => {
      this.#cancelRequest = undefined;
      if (this.#closed || this.#current !== s || this.#candidate === undefined || this.prefetch!.preview() === undefined) { permit.release(); return; }
      const following = state(permit.head); following.permit = permit; this.#next = following;
      if (!s.promoted || s.authenticationStarted) this.#startNext(following);
    });
  }
  #startNext(following: CandidateState): void {
    if (this.#closed || this.#prefetchTask !== undefined || following.filled !== 0 || following.failed || following.eof) return;
    this.#prefetchTask = this.#assemble(following, true, this.#options!).catch(error => {
      // Store the first next error without publishing it ahead of current.
      following.failed = true; following.error = error;
    }).finally(() => {
      this.#prefetchTask = undefined; this.#cleanup(); this.changed?.();
    });
  }
  /** The original AEAD job is the earliest point at which a promoted current
   * may start reading a third physical frame. */
  beginAuthentication(): void {
    const current = this.#current;
    if (this.#candidate === undefined || current === undefined) throw new Error("invalid_resource_owner");
    current.authenticationStarted = true;
    if (this.#next !== undefined) this.#startNext(this.#next);
    this.#requestNext(current);
  }
  async next(options?: OperationOptions): Promise<NativeFrameCandidate | null> {
    this.#check(options);
    if (this.#busy || this.#candidate !== undefined) throw new Error("busy");
    this.#busy = true; this.#readBytes = 0;
    this.#options = { signal: options?.signal === undefined ? this.#abort.signal : AbortSignal.any([options.signal, this.#abort.signal]) };
    try {
      if (this.#prefetchTask !== undefined) await this.#prefetchTask;
      this.#check(this.#options);
      let current = this.#next; this.#next = undefined;
      if (current === undefined) current = state(this.#head);
      else {
        // The sole read task has exited or paused. Move only fixed overhead;
        // ciphertext remains in its original promise, including any paid gap.
        this.#head.set(current.head.subarray(0, Math.min(current.filled, this.#head.length)));
        current.parts.length = 0;
        current.head = this.#head; current.promoted = true;
        current.permit!.release(); delete current.permit;
      }
      this.#current = current; this.#readBytes = current.filled;
      if (current.failed) throw current.error;
      if (current.eof) return null;
      await this.#assemble(current, false, this.#options);
      if (current.eof) return null;
      if (!current.complete) throw new Error("invalid_resource_owner");
      const prefix = inspectEnvelopePrefix(current.head, this.maxFrame), header = inspectRecordPrefix(current.head, prefix.payloadBytes, this.profile);
      let released = false;
      const candidate: NativeFrameCandidate = {
        header,
        get segments() { if (released) throw new Error("closed"); return current.parts; },
        release: () => {
          if (released) return; released = true;
          this.#cancelRequest?.(); this.#cancelRequest = undefined;
          this.#release(current); this.#current = undefined; this.#candidate = undefined; this.#cleanup();
        },
      };
      this.#candidate = candidate;
      this.#requestNext(current);
      return candidate;
    } finally {
      this.#busy = false;
      if (this.#candidate === undefined && this.#current !== undefined) { this.#release(this.#current); this.#current = undefined; }
      this.#cleanup();
    }
  }
  #release(s: CandidateState): void {
    s.parts.length = 0; s.claim?.release(); delete s.claim;
    s.head.fill(0); s.permit?.release(); delete s.permit;
  }
  atFrameBoundary(): boolean { return this.#readBytes === 0; }
  close(): void {
    this.#closed = true; this.#abort.abort(); this.#cancelRequest?.(); this.#cancelRequest = undefined; this.#cleanup();
  }
  #cleanup(): void {
    if (!this.#closed || this.#busy || this.#candidate !== undefined || this.#prefetchTask !== undefined) return;
    if (this.#next !== undefined) { this.#release(this.#next); this.#next = undefined; }
    if (this.#current !== undefined) { this.#release(this.#current); this.#current = undefined; }
    this.#head.fill(0); this.#head = new Uint8Array(); this.#options = undefined;
    this.#opening?.release(); this.#opening = undefined;
    this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
