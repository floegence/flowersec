import type { OperationOptions } from "../../public/contract.js";
import type { V4CleanupStatus, V4ReadResult, V4TypedError } from "../../generated/transportV4APIResults.js";
import { V4ReadMethodError, type V4CursorReadOwner, type V4ReaderSource, type V4ReadState } from "../public.js";
import { CBORDecoder, CBORWireError, cborDecoderCharge, byteSlice, type CBORDocument, type CBORDecoderConfig } from "./cbor.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import type { RecordCipher, RecordPacket} from "./recordCrypto.js";
import { type ReceiveRecordBinding } from "./recordCrypto.js";
import type { ProtectedResourceReservation, ResourceReference, ResourceRoot} from "./resources.js";
import { ResourceError, ResourceVector } from "./resources.js";
import { SchemaValidationError } from "./schema.js";
import { TimeError } from "./timeArithmetic.js";
import { wire } from "./wireRegistry.js";
import { ReceiveWorkspace } from "./receiveWorkspace.js";

const token = Symbol("receive direction owner");
const empty = new Uint8Array();
const copy = Uint8Array.prototype.set;
const reverse = Uint8Array.prototype.reverse;
const NativeBytes = Uint8Array;
const NativePromise = Promise;
const enqueueReadJob = queueMicrotask;
const uint64Max = (1n << 64n) - 1n;
const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const pending: V4CleanupStatus = Object.freeze({ status: "pending", core_cleanup: "pending", pending_callbacks: 0n });

export type ReceiveFailure = "configuration_capacity" | "receive_closed" | "receive_busy" | "receive_owner" | "receive_credit" | "receive_sequence" | "receive_data";
export class ReceiveError extends Error {
  constructor(readonly code: ReceiveFailure) { super(code); this.name = "ReceiveError"; }
}
function fail(code: ReceiveFailure): never { throw new ReceiveError(code); }
function quantity(n: bigint): bigint {
  if (typeof n !== "bigint" || n < 0n || n > uint64Max) fail("configuration_capacity");
  return n;
}
function size(n: number): number {
  if (!Number.isSafeInteger(n) || n < 1 || n > 0x7fffffff) fail("configuration_capacity");
  return n;
}
function vector(bytes: bigint, items = 1n, work = 1n, tasks = 0n): ResourceVector {
  return new ResourceVector([bytes, 0n, 0n, items, work, tasks, 0n, 0n, 0n, 0n, 0n]);
}

export function receiveDeliveryCharge(runtimeBytes: bigint): ResourceVector {
  if (quantity(runtimeBytes) === 0n) fail("configuration_capacity");
  return new ResourceVector([runtimeBytes, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]);
}

/**
 * Original result authorization, separate from normal Session I/O shutdown.
 * The admission/security owner supplies the captured trusted deadline and closes
 * this gate on revocation, authorization termination or Environment.Close.
 * Its reservation must belong to that safety lifetime, not a short I/O scope.
 */
export class ReceiveDeliveryGate {
  #deadline: TrustedDeadline | undefined;
  #reservation: ResourceReference | undefined;
  #reason: "closed" | "authorization_denied" | undefined;
  #authorization: (() => void) | undefined;
  #authorizationRelease: (() => void) | undefined;
  #authorizationRemaining: (() => bigint) | undefined;
  #authorizationObserver: (() => void) | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #retiring = false;
  #closing = false;
  #cleaned: (() => void) | undefined;
  readonly #leases = new Set<ReceiveDeliveryLease>();

  constructor(deadline: TrustedDeadline, runtimeBytes: bigint, reservation: ResourceReference) {
    deadline.check();
    this.#deadline = deadline;
    this.#reservation = reservation.take(receiveDeliveryCharge(runtimeBytes));
    Object.freeze(this);
  }
  constrainAuthorization(check: () => void, original: ResourceReference, release?: () => void, remainingMS?: () => bigint, observe?: (changed: () => void) => () => void): void {
    this.check(token);
    if (this.#authorization !== undefined || !this.#reservation!.sameEnvironment(original)) fail("receive_owner");
    check(); this.#authorization = check; this.#authorizationRelease = release; this.#authorizationRemaining = remainingMS;
    this.#authorizationObserver = observe?.(() => {
      if (!this.#retiring || this.#reason !== undefined) return;
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#armAuthorization();
    });
  }
  retain(directionReservation: ResourceReference, closed: () => void): ReceiveDeliveryLease {
    this.check(token);
    if (this.#retiring) throw new V4ReadMethodError("closed");
    if (!this.#reservation!.sameEnvironment(directionReservation)) fail("receive_owner");
    const reservation = this.#reservation!.borrow();
    const lease = new ReceiveDeliveryLease(token, this, reservation, closed);
    this.#leases.add(lease);
    return lease;
  }
  check(capability: symbol): void {
    if (capability !== token) fail("receive_owner");
    if (this.#reason !== undefined) throw new V4ReadMethodError(this.#reason);
    try { this.#reservation!.check(); }
    catch { this.close(); throw new V4ReadMethodError("closed"); }
    try { this.#deadline!.check(); this.#authorization?.(); }
    catch (error) {
      if (error instanceof TimeError && ["time_unavailable", "time_pending", "time_continuity"].includes(error.code)) {
        throw new V4ReadMethodError(error.code === "time_pending" ? "time_pending" : "time_unavailable");
      }
      this.close("authorization_denied");
      throw new V4ReadMethodError("authorization_denied");
    }
    if (this.#reason !== undefined) throw new V4ReadMethodError(this.#reason);
  }
  release(capability: symbol, lease: ReceiveDeliveryLease): void {
    if (capability !== token || !this.#leases.delete(lease)) fail("receive_owner");
    if (this.#retiring && this.#leases.size === 0) this.close();
    this.#notifyCleanup();
  }
  onCleanup(callback: () => void): void { if (this.#cleaned !== undefined) fail("receive_owner"); this.#cleaned = callback; this.#notifyCleanup(); }
  #notifyCleanup(): void {
    if (this.#closing || this.#reason === undefined || this.#leases.size !== 0) return;
    const callback = this.#cleaned; this.#cleaned = undefined; callback?.();
  }
  /** Normal I/O shutdown leaves existing complete candidates authorized. */
  retire(): void {
    if (this.#retiring || this.#reason !== undefined) return;
    this.#retiring = true;
    if (this.#leases.size === 0) this.close(); else this.#armAuthorization();
  }
  #armAuthorization(): void {
    if (this.#reason !== undefined) return;
    let remaining: bigint;
    try {
      this.check(token);
      const session = this.#deadline!.remainingMS(), authorization = this.#authorizationRemaining?.() ?? session;
      remaining = authorization < session ? authorization : session;
    } catch (error) {
      if (this.#reason !== undefined) return;
      // Loss of a usable clock suspends delivery. A wake retries the original
      // deadlines; it neither expires a result speculatively nor renews it.
      if (error instanceof V4ReadMethodError && ["time_pending", "time_unavailable"].includes(error.reason) ||
          error instanceof TimeError && ["time_pending", "time_unavailable", "time_continuity"].includes(error.code)) remaining = 1000n;
      else { this.close("authorization_denied"); return; }
    }
    if (this.#reason === undefined) this.#timer = setTimeout(() => { this.#timer = undefined; this.#armAuthorization(); }, timerChunk(remaining));
  }
  close(reason: "closed" | "authorization_denied" = "closed"): void {
    if (this.#reason !== undefined) return;
    this.#reason = reason; this.#closing = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.#reservation?.seal();
    for (const lease of this.#leases) lease.notifyClosed();
    this.#reservation?.release(); this.#reservation = undefined;
    this.#deadline = undefined; this.#authorization = undefined; this.#authorizationRemaining = undefined;
    this.#authorizationObserver?.(); this.#authorizationObserver = undefined;
    const release = this.#authorizationRelease; this.#authorizationRelease = undefined; release?.(); this.#closing = false;
    this.#notifyCleanup();
  }
  cleanupStatus(): V4CleanupStatus { return !this.#closing && this.#reason !== undefined && this.#leases.size === 0 ? complete : pending; }
}
class ReceiveDeliveryLease {
  #gate: ReceiveDeliveryGate | undefined;
  #reservation: ResourceReference | undefined;
  #closed: (() => void) | undefined;
  constructor(capability: symbol, gate: ReceiveDeliveryGate, reservation: ResourceReference, closed: () => void) {
    if (capability !== token) fail("receive_owner");
    this.#gate = gate; this.#reservation = reservation; this.#closed = closed;
  }
  check(): void {
    if (this.#gate === undefined) throw new V4ReadMethodError("closed");
    this.#reservation!.checkRetained(); this.#gate.check(token);
  }
  notifyClosed(): void { this.#closed?.(); }
  release(): void {
    if (this.#gate === undefined) return;
    this.#reservation!.release(); this.#gate.release(token, this); this.#gate = undefined; this.#reservation = undefined; this.#closed = undefined;
  }
}

export interface ReceiveDirectionConfig {
  readonly workspace?: ReceiveWorkspace;
  readonly maxDataBytes: number;
  readonly queueBytes: number;
  readonly maxCursorBytes: number;
  /** Initial absolute credit already authorized by the original stream owner. */
  readonly receiveLimit: bigint;
  readonly runtimeBytes: bigint;
  readonly cursorRuntimeBytes: bigint;
  readonly decoderRuntimeBytes: bigint;
}
interface Config extends ReceiveDirectionConfig { readonly plaintextBytes: number }
function capture(c: ReceiveDirectionConfig): Config {
  const maxDataBytes = size(c.maxDataBytes), queueBytes = size(c.queueBytes), maxCursorBytes = size(c.maxCursorBytes);
  const receiveLimit = quantity(c.receiveLimit), runtimeBytes = quantity(c.runtimeBytes);
  const cursorRuntimeBytes = quantity(c.cursorRuntimeBytes), decoderRuntimeBytes = quantity(c.decoderRuntimeBytes);
  if (maxDataBytes > wire.resource_caps.max_payload_length - 100 || receiveLimit > BigInt(queueBytes) ||
      runtimeBytes === 0n || cursorRuntimeBytes === 0n || decoderRuntimeBytes === 0n) fail("configuration_capacity");
  const workspace = c.workspace;
  if (workspace !== undefined && !(workspace instanceof ReceiveWorkspace)) fail("configuration_capacity");
  return Object.freeze({ maxDataBytes, queueBytes, maxCursorBytes, receiveLimit, runtimeBytes,
    cursorRuntimeBytes, decoderRuntimeBytes, plaintextBytes: workspace?.maxPlainBytes ?? maxDataBytes + 64,
    ...(workspace === undefined ? {} : { workspace }) });
}
function decoderConfig(c: Config): CBORDecoderConfig {
  return { bytes: c.plaintextBytes, nodes: 15, textBytes: 0, arrayItems: 1, runtimeBytes: c.decoderRuntimeBytes };
}
export function receiveDirectionCharge(config: ReceiveDirectionConfig): ResourceVector {
  const c = capture(config);
  return vector(BigInt(c.queueBytes + (c.workspace === undefined ? c.plaintextBytes : 0)) + c.runtimeBytes, 1n, 1n, 1n);
}
export function receiveCursorCharge(config: ReceiveDirectionConfig): ResourceVector {
  const c = capture(config);
  return vector(BigInt(c.maxCursorBytes) + c.cursorRuntimeBytes, 1n, 1n, 1n);
}
export function receiveDecoderCharge(config: ReceiveDirectionConfig): ResourceVector {
  const c = capture(config);
  return c.workspace === undefined ? cborDecoderCharge(decoderConfig(c)) : vector(64n + c.decoderRuntimeBytes, 1n, 0n);
}

export interface ReceiveReservations {
  readonly root: ResourceRoot;
  readonly direction: ResourceReference;
  readonly decoder: ResourceReference;
  readonly cursor: ResourceReference;
  /** A Session-owned future position, reused only after this direction exits. */
  readonly cursorPosition?: ProtectedResourceReservation;
}
export interface ReceiveProgress {
  readonly ack_offset: bigint;
  readonly released_offset: bigint;
  readonly receive_limit: bigint;
  readonly queued_bytes: bigint;
  readonly fin_offset?: bigint;
}
export interface MessageReceiveBody {
  readonly bytes: Uint8Array;
  readonly reference: ResourceReference;
}
/** Private ciphertext claim in the original, not-yet-authenticated promise. */
export interface NativeReceiveClaim {
  readonly segments: readonly Uint8Array[];
  check(): void;
  release(): void;
}
interface NativeClaimState {
  readonly claim: NativeReceiveClaim;
  readonly reference: ResourceReference;
  readonly end: bigint;
  readonly logicalBytes: bigint;
  readonly clear: () => void;
  detached: boolean;
  validated: boolean;
}
type BodyReserve = (name: string, charge: ResourceVector) => ResourceReference;
interface CursorWait {
  readonly kind: "cursor";
  readonly owner: ReceiveCursorOwner;
  readonly maximum: number;
  readonly transfer: (bytes: Uint8Array) => number;
  readonly resolve: () => void;
  readonly reject: (error: unknown) => void;
  readonly signal: AbortSignal;
  readonly canceled: () => void;
}
interface RawWait {
  armed: boolean;
  readonly kind: "raw";
  readonly owner: ReceiveCursorOwner;
  readonly maximum: number;
  readonly resolve: (result: V4ReadResult) => void;
  readonly reject: (error: unknown) => void;
  readonly signal: AbortSignal | undefined;
  readonly canceled: () => void;
}
type ReadWait = CursorWait | RawWait;

/**
 * One real authenticated receive queue. Ordinary reads and public ReaderCursor
 * share its direction claim, bytes, resource root and result authorization.
 * This component does not establish OPEN/READY or publish maintenance credit.
 * The configured limit is fixed until that Session machinery supplies a real
 * authenticated credit publication path; consumed bytes are never self-granted.
 */
export class ReliableReceiveDirection implements V4ReaderSource {
  readonly #config: Config;
  #cipher: RecordCipher | undefined;
  #binding: ReceiveRecordBinding;
  #reservation: ResourceReference | undefined;
  #cursorReservation: ProtectedResourceReservation | undefined;
  #borrowedCursor = false;
  #decoder: CBORDecoder | undefined;
  #workspaceReference: ResourceReference | undefined;
  #workspaceRelease: (() => void) | undefined;
  #delivery: ReceiveDeliveryLease | undefined;
  #ring: Uint8Array = empty;
  #queueReference: ResourceReference | undefined;
  #bodyQueue: { start: bigint; end: bigint; bytes: Uint8Array; reference: ResourceReference } | undefined;
  #scratch: Uint8Array = empty;
  #head = 0;
  #queued = 0;
  #ack = 0n;
  #receiveLimit = 0n;
  #released = 0n;
  #creditPaused = false;
  #fin: bigint | undefined;
  #terminal: V4ReadState | undefined;
  #active: ReceiveCursorOwner | undefined;
  #wait: ReadWait | undefined;
  #working = false;
  #pumpQueued = false;
  #abandoned = false;
  #closed = false;
  readonly #nativeClaims: NativeClaimState[] = [];

  constructor(config: ReceiveDirectionConfig, cipher: RecordCipher, delivery: ReceiveDeliveryGate, reservations: ReceiveReservations,
    private readonly released?: () => void, private readonly settled?: () => void) {
    const c = capture(config);
    const { root, direction, decoder, cursor } = reservations;
    if (!direction.sameEnvironment(decoder) || !direction.sameEnvironment(cursor)) fail("receive_owner");
    this.#binding = cipher.receiveBinding(direction);
    this.#config = c; this.#receiveLimit = c.receiveLimit; this.#cipher = cipher;
    this.#reservation = direction.take(receiveDirectionCharge(c));
    try {
      this.#delivery = delivery.retain(this.#reservation, () => this.close());
      if (reservations.cursorPosition === undefined) this.#cursorReservation = root.protect(cursor, receiveCursorCharge(c));
      else {
        if (!reservations.cursorPosition.sameEnvironment(cursor)) fail("receive_owner");
        this.#cursorReservation = reservations.cursorPosition; this.#borrowedCursor = true; cursor.release();
      }
      if (c.workspace === undefined) {
        this.#decoder = new CBORDecoder(decoderConfig(c), decoder); this.#scratch = new Uint8Array(c.plaintextBytes);
      } else {
        this.#workspaceReference = decoder.take(receiveDecoderCharge(c)); this.#workspaceRelease = c.workspace.retain(this.#workspaceReference);
      }
      this.#ring = new Uint8Array(c.queueBytes);
    } catch (error) { this.close(); throw error; }
    Object.freeze(this);
  }

  progress(): ReceiveProgress {
    return Object.freeze({ ack_offset: this.#ack, released_offset: this.#released,
      receive_limit: this.#receiveLimit, queued_bytes: BigInt(this.#queued),
      ...(this.#fin === undefined ? {} : { fin_offset: this.#fin }) });
  }
  claimNative(bytes: number, payloadClaim: bigint, prefetch = false): NativeReceiveClaim | undefined {
    this.#checkIngress();
    if (this.#nativeClaims.length >= 2 || !prefetch && this.#nativeClaims.some(value => !value.validated) ||
        this.#fin !== undefined || !Number.isSafeInteger(bytes) || bytes < 0 || payloadClaim < BigInt(bytes)) fail("receive_credit");
    let start = this.#ack;
    for (const state of this.#nativeClaims) if (!state.validated && state.end > start) start = state.end;
    // Conservative gaps left by a preceding claim stay in the original paid
    // ring. Lack of space disables overlap; it never rejects a legal next frame.
    if (start > this.#receiveLimit || payloadClaim > this.#receiveLimit - start) {
      if (prefetch) return undefined;
      fail("receive_credit");
    }
    const body = this.#bodyQueue;
    let segments: Uint8Array[];
    if (body !== undefined) {
      const offset = start - body.start;
      if (offset < 0n || BigInt(bytes) > body.end - start) fail("receive_credit");
      segments = [byteSlice(body.bytes, Number(offset), Number(offset) + bytes)];
    } else {
      if (start < this.#released || start - this.#released + BigInt(bytes) > BigInt(this.#ring.length)) fail("receive_credit");
      const at = this.#ring.length === 0 ? 0 : (this.#head + Number(start - this.#released)) % this.#ring.length;
      const first = Math.min(bytes, this.#ring.length - at);
      segments = [byteSlice(this.#ring, at, at + first), byteSlice(this.#ring, 0, bytes - first)];
    }
    // The direction already owns this exact backing reference before granting
    // credit, including the retained alias of a transferred message body. Lend
    // that owner to its bounded native claims; do not allocate a fresh
    // root alias under memory pressure after the promise has been published.
    const reference = body?.reference ?? this.#queueReference ?? this.#reservation!;
    reference.checkRetained();
    let released = false;
    const claim: NativeReceiveClaim = {
      get segments() { if (released) fail("receive_owner"); return segments; },
      check: () => { if (released || !this.#nativeClaims.includes(state)) fail("receive_owner"); reference.checkRetained(); this.#checkIngress(); },
      release: () => {
        if (released) return; released = true;
        if (!state.validated) state.clear(); segments = [];
        const at = this.#nativeClaims.indexOf(state); if (at < 0) fail("receive_owner");
        this.#nativeClaims.splice(at, 1);
        if (state.detached && !this.#nativeClaims.some(value => value.reference === reference)) reference.release();
        this.#cleanup();
      },
    };
    const state: NativeClaimState = { claim, reference, end: start + payloadClaim, logicalBytes: payloadClaim,
      detached: false, validated: false, clear: () => { for (const part of segments) part.fill(0); } };
    this.#nativeClaims.push(state); return claim;
  }
  nativePrefetchFits(claim: NativeReceiveClaim, remaining: bigint): boolean {
    this.#checkIngress();
    if (!this.#nativeClaims.some(state => state.claim === claim)) fail("receive_owner");
    return this.#nativeClaims.reduce((total, state) => total + (state.validated ? 0n : state.logicalBytes), 0n) <= remaining;
  }
  #validateNative(length: number): void {
    const state = this.#nativeClaims.find(value => !value.validated);
    if (state === undefined) return;
    if (BigInt(length) > state.logicalBytes) fail("receive_credit");
    // Coalescing and schema validation have ended their ciphertext borrow.
    // Keep the original claim/reference until its actual candidate exits, but
    // allow this exact storage to receive the authenticated plaintext below.
    state.clear(); state.validated = true;
  }
  #releaseBacking(reference: ResourceReference): void {
    let retained = false;
    for (const state of this.#nativeClaims) if (state.reference === reference) { state.detached = true; retained = true; }
    if (!retained) reference.release();
  }
  /** Original fixed queue capacity backs the new absolute promise. Publication
   * calls commitCredit in the same record ticket gate, never after completion. */
  nextCredit(): bigint {
    if (this.#abandoned || this.#fin !== undefined || this.#creditPaused) return this.#receiveLimit;
    if (this.#bodyQueue !== undefined) {
      const end = this.#bodyQueue.end, window = this.#released + BigInt(this.#config.queueBytes);
      return window < end ? window : end;
    }
    if (this.#ring.length === 0) return this.#receiveLimit;
    const remaining = uint64Max - this.#released;
    return this.#released + (remaining < BigInt(this.#config.queueBytes) ? remaining : BigInt(this.#config.queueBytes));
  }
  commitCredit(limit: bigint): void {
    this.#checkIngress();
    if (limit < this.#receiveLimit || limit > this.nextCredit()) fail("receive_credit");
    this.#receiveLimit = limit;
  }
  state(): V4ReadState {
    return this.#terminal ?? Object.freeze({ stream_status: this.#fin !== undefined && this.#queued === 0 ? "eof" : "open" });
  }
  checkAdapterClaim(): void {
    if (this.#active !== undefined || this.#closed) throw new V4ReadMethodError("read_in_progress");
    this.#delivery!.check();
  }
  setAdapterCreditPaused(paused: boolean): void {
    this.#creditPaused = paused;
    if (!paused && !this.#closed) this.released?.();
  }

  /** A single authenticated message interval can take the queue's real
   * backing. Cross-boundary promises keep their ring and full overlap charge. */
  admitMessageBody(length: number, structure: ResourceVector, reserve: BodyReserve): MessageReceiveBody {
    if (!Number.isSafeInteger(length) || length < 0 || BigInt(length) > uint64Max - this.#released ||
        this.#closed || this.#working || this.#wait !== undefined || this.#bodyQueue !== undefined) fail("receive_owner");
    this.#delivery!.check();
    const direct = this.#nativeClaims.length === 0 && length > 0 && this.#ring.length > 0 && this.#receiveLimit - this.#released <= BigInt(length) && this.#queued <= length;
    const reuse = direct && length <= this.#ring.length;
    const charge = structure.add(vector(reuse ? 0n : BigInt(length), 0n, 0n));
    const reference = reserve("v4_message_body", charge);
    let retained: ResourceReference | undefined;
    try {
      // Take the actual I/O alias before changing any backing or accounting.
      // A canceled message cannot refund storage still held by this direction.
      if (direct) retained = reference.borrow();
      const bytes = reuse ? byteSlice(this.#ring, 0, length) : new NativeBytes(length);
      if (!direct) return { bytes, reference };
      const capacity = this.#ring.length, original = this.#queueReference ?? this.#reservation!;
      // New allocation overlaps the old ring until its bytes are copied and
      // all aliases below have exited. Reuse performs an in-place rotation.
      if (!reuse) {
        const first = Math.min(this.#queued, capacity - this.#head);
        copy.call(bytes, byteSlice(this.#ring, this.#head, this.#head + first));
        if (first < this.#queued) copy.call(bytes, byteSlice(this.#ring, 0, this.#queued - first), first);
      }
      original.moveBytesTo(reference, BigInt(capacity));
      if (reuse && this.#head !== 0) {
        reverse.call(byteSlice(this.#ring, 0, this.#head));
        reverse.call(byteSlice(this.#ring, this.#head, capacity));
        reverse.call(this.#ring);
      }
      if (!reuse) this.#ring.fill(0);
      this.#bodyQueue = { start: this.#released, end: this.#released + BigInt(length), bytes, reference: retained! };
      this.#ring = empty; this.#head = 0;
      this.#queueReference?.release(); this.#queueReference = undefined;
      if (!reuse) reference.shrink(charge, [retained!]);
      return { bytes, reference };
    } catch (error) { retained?.release(); reference.release(); throw error; }
  }

  /** A consumed message still owns its backing. New credit needs a different
   * paid queue; restoring it cannot reuse the private result's memory. */
  ensureMessageQueue(reserve: BodyReserve): void {
    if (this.#closed || this.#working || this.#wait !== undefined) fail("receive_owner");
    if (this.#ring.length !== 0 || this.#fin !== undefined && this.#queued === 0) return;
    if (this.#bodyQueue !== undefined && this.#released !== this.#bodyQueue.end) fail("receive_owner");
    const reference = reserve("v4_message_queue", vector(BigInt(this.#config.queueBytes), 0n, 0n));
    try {
      const bytes = new NativeBytes(this.#config.queueBytes);
      this.#delivery!.check();
      const previous = this.#bodyQueue; this.#bodyQueue = undefined; if (previous !== undefined) this.#releaseBacking(previous.reference);
      this.#ring = bytes; this.#head = 0; this.#queueReference = reference;
    } catch (error) { reference.release(); throw error; }
    this.released?.();
  }

  /** Consumes this exact key's packet on success or authenticated input failure. */
  accept(packet: RecordPacket, finalOffset?: bigint): void {
    this.#checkIngress();
    // A packet from another queue is an integration error, not a peer input
    // violation. Do not consume it or damage either direction on that path.
    const info = this.#cipher!.inspectIncoming(packet);
    if (info.frameType !== wire.frame_types.STREAM_DATA) fail("receive_owner");
    this.#working = true;
    let document: CBORDocument | undefined;
    let scratch = this.#scratch, decoder = this.#decoder, shared = false, scratchUsed = 0;
    try {
      if (this.#config.workspace !== undefined) {
        const position = this.#config.workspace.acquire(this); scratch = position.scratch; decoder = position.decoder; shared = true;
      }
      if (info.plaintextBytes > scratch.length) fail("receive_data");
      scratchUsed = info.plaintextBytes;
      const count = packet.copyBytes(scratch);
      document = decoder!.decodeMap(byteSlice(scratch, 0, count), "STREAM_DATA", { limits: {
        max_data_payload_bytes: shared ? Math.min(this.#config.queueBytes, this.#config.plaintextBytes) : this.#config.maxDataBytes,
      } });
      if (document.uint(document.field(0, 0)) !== info.scope || document.uint(document.field(0, 1)) !== BigInt(info.direction) ||
          document.uint(document.field(0, 2)) !== BigInt(info.epoch) || document.uint(document.field(0, 3)) !== info.sequence) fail("receive_data");
      const offset = document.uint(document.field(0, 4)), fin = document.boolean(document.field(0, 5));
      const node = document.field(0, 6), length = document.size(node);
      if (offset !== this.#ack || this.#fin !== undefined || BigInt(length) > uint64Max - offset) fail("receive_sequence");
      if (finalOffset !== undefined && (finalOffset < this.#ack || finalOffset > this.#receiveLimit || offset + BigInt(length) > finalOffset)) fail("receive_credit");
      const body = this.#bodyQueue;
      if (offset + BigInt(length) > this.#receiveLimit ||
          (body === undefined ? length > this.#ring.length - this.#queued : offset < body.start || offset + BigInt(length) > body.end)) fail("receive_credit");
      this.#delivery!.check();
      if (this.#closed) fail("receive_closed");
      this.#validateNative(length);
      // All storage is prepaid. The hidden tail is not visible to readers until
      // both full schema/association validation and crypto commit succeed.
      if (!this.#abandoned && body !== undefined) {
        document.copyRange(node, 0, byteSlice(body.bytes, Number(offset - body.start), Number(offset - body.start) + length), true);
      } else if (!this.#abandoned && length > 0) {
        const tail = (this.#head + this.#queued) % this.#ring.length;
        const first = Math.min(length, this.#ring.length - tail);
        document.copyRange(node, 0, byteSlice(this.#ring, tail, tail + first), true);
        if (first < length) document.copyRange(node, first, byteSlice(this.#ring, 0, length - first), true);
      }
      packet.commitValidated();
      if (!this.#abandoned) this.#queued += length;
      this.#ack += BigInt(length);
      if (fin) this.#fin = this.#ack;
    } catch (error) {
      if (!this.#closed) {
        if (error instanceof SchemaValidationError || error instanceof CBORWireError || error instanceof ReceiveError &&
            ["receive_data", "receive_sequence", "receive_credit"].includes(error.code)) {
          this.#terminate({ stream_status: "error", error: { code: "stream_data_invalid", scope: "stream", retry_disposition: "preserve_facts" } });
        } else if (error instanceof ResourceError && error.code === "resource_exhausted") {
          this.#terminate({ stream_status: "error", error: { code: "resource_exhausted", scope: "stream", retry_disposition: "preserve_facts" } });
        } else this.close();
      }
      throw error;
    } finally {
      document?.release(); packet.release();
      if (shared) this.#config.workspace!.release(this, scratchUsed);
      else scratch.fill(0, 0, scratchUsed);
      this.#working = false;
      this.#pump(); this.#cleanup();
    }
  }

  /** Called by the original rekey owner before retiring its old receive key. */
  replaceCipher(next: RecordCipher): void {
    this.#checkIngress();
    const binding = next.receiveBinding(this.#reservation!);
    if (!next.sharesReceiveDirection(this.#cipher!) || binding.epoch !== this.#binding.epoch + 1) fail("receive_owner");
    this.#cipher = next; this.#binding = binding;
  }

  /** Seal application delivery at the original direction, while retaining the
   * decoder and credit promise needed to authenticate/discard in-flight DATA.
   * Discarded bytes advance only the authenticated frontier, never consumption. */
  abandonDelivery(): void {
    if (this.#closed || this.#abandoned) return;
    this.#abandoned = true;
    this.#terminate({ stream_status: "aborted" }); this.#pump();
  }

  acquireCursor(target: bigint): V4CursorReadOwner { return this.#acquire(target); }
  #acquire(target: bigint): ReceiveCursorOwner {
    if (typeof target !== "bigint" || target < 0n || target > BigInt(this.#config.maxCursorBytes) || target > uint64Max - this.#released) {
      throw new V4ReadMethodError("invalid_argument");
    }
    if (this.#closed) throw new V4ReadMethodError("closed");
    if (this.#active !== undefined) throw new V4ReadMethodError("read_in_progress");
    this.#reservation!.check(); this.#delivery!.check();
    if (this.#closed) throw new V4ReadMethodError("closed");
    const reservation = this.#cursorReservation!.checkout();
    try {
      const owner = new ReceiveCursorOwner(token, this, this.#released, Number(target), reservation);
      this.#active = owner;
      return owner;
    } catch (error) { reservation.release(); throw error; }
  }

  read(maxBytes: bigint, options?: OperationOptions): Promise<V4ReadResult> {
    let resolve!: (result: V4ReadResult) => void, reject!: (error: unknown) => void;
    const promise = new NativePromise<V4ReadResult>((yes, no) => { resolve = yes; reject = no; });
    if (typeof maxBytes !== "bigint" || maxBytes <= 0n || maxBytes > BigInt(this.#config.maxCursorBytes)) {
      reject(new V4ReadMethodError("invalid_argument")); return promise;
    }
    if (this.#closed && this.state().stream_status === "eof") {
      resolve(readResult(new Uint8Array(), this.#released, "ready", this.state())); return promise;
    }
    const signal = options?.signal;
    let owner: ReceiveCursorOwner;
    try { owner = this.#acquire(maxBytes); }
    catch (error) { reject(error); return promise; }
    const canceled = () => this.#pump();
    const wait: RawWait = { kind: "raw", owner, maximum: Number(maxBytes), resolve, reject, signal, canceled, armed: false };
    this.#wait = wait;
    signal?.addEventListener("abort", canceled, { once: true });
    this.#pump();
    wait.armed = true;
    return promise;
  }

  cursorRead(capability: symbol, owner: ReceiveCursorOwner, maximum: number, transfer: (bytes: Uint8Array) => number, signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      if (capability !== token || this.#active !== owner) { reject(new V4ReadMethodError("owner_unavailable")); return; }
      if (this.#wait !== undefined) { reject(new V4ReadMethodError("read_in_progress")); return; }
      if (!Number.isSafeInteger(maximum) || maximum <= 0 || maximum > owner.storage.length) { reject(new V4ReadMethodError("invalid_argument")); return; }
      const canceled = () => {
        const wait = this.#wait;
        if (wait?.owner !== owner) return;
        this.#detach(wait); reject(new V4ReadMethodError("prefix_frozen"));
      };
      this.#wait = { kind: "cursor", owner, maximum, transfer, resolve, reject, signal, canceled };
      signal.addEventListener("abort", canceled, { once: true });
      if (signal.aborted) canceled();
      this.#pump();
    });
  }

  claimDelivery(capability: symbol, owner: ReceiveCursorOwner): void {
    if (capability !== token || this.#active !== owner) throw new V4ReadMethodError("owner_unavailable");
    // Normal I/O close does not close the independently captured safety gate.
    this.#delivery!.check();
  }
  releaseCursor(capability: symbol, owner: ReceiveCursorOwner): void {
    if (capability !== token || this.#active !== owner || this.#wait?.owner === owner) fail("receive_owner");
    this.#active = undefined;
    if (this.#bodyQueue !== undefined && this.#released === this.#bodyQueue.end) {
      const body = this.#bodyQueue; this.#bodyQueue = undefined; this.#releaseBacking(body.reference);
    }
    this.#cleanup();
    this.settled?.();
  }

  #checkIngress(): void {
    if (this.#closed || this.#terminal !== undefined && !this.#abandoned) fail("receive_closed");
    if (this.#working) fail("receive_busy");
    this.#reservation!.check(); this.#delivery!.check();
    if (this.#closed) fail("receive_closed");
  }
  #detach(wait: ReadWait): void {
    if (this.#wait === wait) this.#wait = undefined;
    wait.signal?.removeEventListener("abort", wait.canceled);
  }
  #pump(): void {
    if (this.#pumpQueued || this.#wait === undefined || this.#working) return;
    this.#pumpQueued = true;
    enqueueReadJob(() => { this.#pumpQueued = false; this.#runPump(); });
  }
  #runPump(): void {
    const wait = this.#wait;
    if (wait === undefined || this.#working || wait.kind === "raw" && !wait.armed) return;
    if (this.#queued === 0 && this.state().stream_status === "open" && !(wait.kind === "raw" && wait.signal?.aborted)) return;
    this.#detach(wait);
    let handoff = false;
    try {
      if (wait.kind === "raw") {
        if (wait.signal?.aborted && this.state().stream_status === "open") {
          const result = readResult(new Uint8Array(), this.#released, "wait_canceled", this.state());
          wait.resolve(result); wait.owner.release(); return;
        }
      } else if (this.#queued > 0) {
        this.#delivery!.check();
      }
      const body = this.#bodyQueue;
      const maximum = Math.min(wait.maximum, this.#queued, body === undefined ? this.#ring.length - this.#head : Number(body.end - this.#released), this.#config.maxDataBytes);
      let count = 0;
      if (maximum > 0) {
        const bytes = body === undefined ? byteSlice(this.#ring, this.#head, this.#head + maximum) :
          byteSlice(body.bytes, Number(this.#released - body.start), Number(this.#released - body.start) + maximum);
        if (wait.kind === "raw") { copy.call(wait.owner.storage, bytes); count = maximum; }
        else count = wait.transfer(bytes);
        if (!Number.isSafeInteger(count) || count < 0 || count > maximum) fail("receive_owner");
      }
      let result: V4ReadResult | undefined;
      if (wait.kind === "raw") {
        const state = this.#terminal ?? { stream_status: this.#fin !== undefined && this.#queued === count ? "eof" as const : "open" as const };
        result = readResult(byteSlice(wait.owner.storage, 0, count), this.#released + BigInt(count), "ready", state);
        // All backing, result shape and the final capability exist before the
        // irreversible claim. Retain the reservation through resolver exit.
        wait.owner.claimDelivery();
        handoff = true;
      }
      if (count > 0) {
        if (body === undefined) {
          this.#ring.fill(0, this.#head, this.#head + count);
          this.#head = (this.#head + count) % this.#ring.length;
        }
        this.#queued -= count; this.#released += BigInt(count);
      }
      if (wait.kind === "cursor") wait.resolve();
      else { wait.resolve(result!); wait.owner.release(); }
      // The original final resolver remains the caller's capability. Credit
      // publication observes the committed transfer without chaining payload
      // through a private intermediate promise or invoking host code in it.
      if (count > 0) this.released?.();
    } catch (error) {
      if (handoff) return;
      if (wait.kind === "raw") wait.owner.release();
      wait.reject(error);
    }
  }
  #terminate(state: V4ReadState): void {
    this.#terminal ??= Object.freeze({ ...state, ...(state.error === undefined ? {} : { error: Object.freeze({ ...state.error }) }) });
    if (this.#nativeClaims.length === 0) this.#ring.fill(0);
    else {
      // An intentional delivery stop cannot corrupt an in-flight ciphertext
      // which still belongs to the original authentication/termination path.
      const first = Math.min(this.#queued, this.#ring.length - this.#head);
      this.#ring.fill(0, this.#head, this.#head + first); this.#ring.fill(0, 0, this.#queued - first);
    }
    this.#queued = 0;
  }
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.state().stream_status === "open") this.#terminate({ stream_status: "aborted" });
    if (!this.#borrowedCursor) this.#cursorReservation?.closeAfterUse();
    this.#pump(); this.#cleanup();
  }
  #cleanup(): void {
    if (this.#closed && !this.#working) {
      // Retained cursors/claims need their real bytes and safety gate, but no
      // future parser access. They do not retain the shared full workspace.
      this.#workspaceRelease?.(); this.#workspaceRelease = undefined;
      this.#workspaceReference?.release(); this.#workspaceReference = undefined;
    }
    if (!this.#closed || this.#working || this.#nativeClaims.length !== 0 || this.#active !== undefined || this.#wait !== undefined) return;
    this.#ring.fill(0); this.#scratch.fill(0); this.#ring = empty; this.#scratch = empty;
    // The independent message owner clears or delivers its body. This I/O
    // alias neither zeros a completed result nor refunds its transferred charge.
    const body = this.#bodyQueue; this.#bodyQueue = undefined; body?.reference.release();
    this.#queueReference?.release(); this.#queueReference = undefined;
    this.#decoder?.close(); this.#decoder = undefined; this.#cipher = undefined;
    this.#delivery?.release(); this.#delivery = undefined;
    this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupStatus(): V4CleanupStatus {
    return this.#closed && this.#reservation === undefined && (this.#borrowedCursor || this.#cursorReservation?.cleanupComplete() !== false) ? complete : pending;
  }
}

class ReceiveCursorOwner implements V4CursorReadOwner {
  #direction: ReliableReceiveDirection | undefined;
  #reservation: ResourceReference | undefined;
  #storage: Uint8Array;
  #claimed = false;
  #state: V4ReadState = { stream_status: "open" };
  readonly startOffset: bigint;
  constructor(capability: symbol, direction: ReliableReceiveDirection, offset: bigint, size: number, reservation: ResourceReference) {
    if (capability !== token) fail("receive_owner");
    this.#direction = direction; this.#reservation = reservation; this.startOffset = offset;
    this.#storage = new Uint8Array(size);
  }
  get storage(): Uint8Array { return this.#storage; }
  state(): V4ReadState { return this.#direction?.state() ?? this.#state; }
  read(maximum: number, transfer: (bytes: Uint8Array) => number, signal: AbortSignal): Promise<void> {
    if (this.#direction === undefined) return Promise.reject(new V4ReadMethodError("closed"));
    return this.#direction.cursorRead(token, this, maximum, transfer, signal);
  }
  claimDelivery(): void {
    if (this.#claimed) throw new V4ReadMethodError("already_delivered");
    if (this.#direction === undefined) throw new V4ReadMethodError("closed");
    this.#reservation!.checkRetained(); this.#direction.claimDelivery(token, this); this.#claimed = true;
  }
  release(): void {
    if (this.#direction === undefined) return;
    const direction = this.#direction;
    this.#state = direction.state(); this.#direction = undefined;
    if (!this.#claimed) this.#storage.fill(0);
    this.#storage = empty;
    this.#reservation!.release(); this.#reservation = undefined;
    direction.releaseCursor(token, this);
  }
}
function readResult(data: Uint8Array, offset: bigint, waitStatus: "ready" | "wait_canceled", state: V4ReadState): V4ReadResult {
  const error: V4TypedError | undefined = state.error;
  const result: V4ReadResult = { data, progress: Object.freeze({ offset, filled: BigInt(data.length) }), wait_status: waitStatus,
    stream_status: state.stream_status, ...(error === undefined ? {} : { error }) };
  Object.defineProperty(result, "then", { value: undefined });
  return Object.freeze(result);
}
for (const owner of [ReceiveDeliveryGate, ReliableReceiveDirection, ReceiveCursorOwner]) { Object.freeze(owner.prototype); Object.freeze(owner); }
