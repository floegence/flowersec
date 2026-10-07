import { ConnectionError, controllerFailureCode } from "./connectionDiagnostic.js";
import { diagnosticDimensions, diagnosticMetrics, type DiagnosticCounts, type DiagnosticMetric, type DiagnosticSink } from "./diagnostics.js";
import { ConnectionFacts, observedConnectionFacts, unknownConnectionFacts } from "./runtime/connectionFacts.js";
import type { V4UnreliableMessages } from "./unreliable.js";
import { V4UnreliableMessageError } from "./unreliable.js";
import type * as OperationReferenceTypes from "./operationReference.js";
import type * as OperationResultReadTypes from "./operationResultRead.js";
import type * as ServiceDefinitionTypes from "./serviceDefinition.js";
import type * as ServiceClientTypes from "./serviceClient.js";
import type * as MessageDefinitionTypes from "./messageDefinition.js";
import type * as MessageStreamTypes from "./messageStream.js";
import type * as StreamHandlersTypes from "./streamHandlers.js";
import type * as DrainTypes from "./drain.js";
import { ServeError, startServe, type ServeOptions, type ServeHandle } from "./serve.js";
import type { V4Notifications } from "./notificationSubscription.js";
import { V4LivenessError, type V4LivenessResult } from "./liveness.js";
import { captureConnectionRequirements } from "./connectionRequirements.js";
import { cleanupResult } from "./runtime/lifecycle.js";
import type { OperationOptions } from "../public/contract.js";
import type { StreamMetadata } from "../public/streamMetadata.js";
import { byteSlice } from "./runtime/cbor.js";
import type {
  V4CleanupStatus,
  V4LifecycleResult,
  V4CloseResult,
  V4ConnectionRequirements,
  V4ReadCause,
  V4ReadMethodFailureReason,
  V4ReadResult,
  V4ReaderCursorSnapshot,
  V4SessionInfo,
  V4StreamStatus,
  V4TypedError,
  V4WriteProgress,
} from "../generated/transportV4APIResults.js";

export type { V4CleanupStatus, V4LifecycleObjectKind, V4LifecycleState, V4LifecycleReason, V4LifecycleResult, V4ReadProgress, V4ReadResult, V4WriteProgress } from "../generated/transportV4APIResults.js";

const uint64Max = (1n << 64n) - 1n;
const empty = new Uint8Array();
const copyBytes = Uint8Array.prototype.set;
const NativePromise = Promise;
const completeCleanup = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const enqueueReadJob = queueMicrotask;
interface CursorWaiter {
  readonly prefix: boolean;
  readonly signal: AbortSignal | undefined;
  readonly resolve: (result: V4ReadResult) => void;
  readonly reject: (error: unknown) => void;
  readonly canceled: () => void;
  armed: boolean;
  queued: boolean;
  settled: boolean;
}

export class V4ReadMethodError extends Error {
  constructor(readonly reason: V4ReadMethodFailureReason, readonly cursor?: V4ReaderCursorSnapshot) {
    super(reason);
    this.name = "V4ReadMethodError";
  }
}

/** Runtime integration: A committed state from the original authenticated read direction. */
export type V4ReadState = Readonly<{ stream_status: V4StreamStatus; error?: V4TypedError }>;

/**
 * Runtime integration: Implemented by the v4 stream's existing queue and resource owner.
 * A generic ByteStream cannot supply this capability: it has no bounded dequeue,
 * exclusive direction claim, result authorization gate or cursor reservation.
 */
export interface V4ReaderSource {
  acquireCursor(target: bigint): V4CursorReadOwner;
}

/** Runtime integration: All methods run in the original stream owner, not a second queue. */
export interface V4CursorReadOwner {
  readonly startOffset: bigint;
  /** Private reserved backing; never reused after result ownership is transferred. */
  readonly storage: Uint8Array;
  state(): V4ReadState;
  /**
   * Offer an authenticated queue prefix under the direction's transfer gate.
   * Commit exactly the synchronous callback's returned byte count, updating
   * released_offset once. Leave the suffix in that same source queue. A rejected
   * read must preserve transfers already committed by the callback. Abort stops
   * pending work but never undoes a committed transfer.
   */
  read(maxBytes: number, transfer: (bytes: Uint8Array) => number, signal: AbortSignal): Promise<void>;
  /** Check the original result authorization/lifecycle gate before handoff. */
  claimDelivery(): void;
  /** Relinquish the direction and backing references after all reads exit. */
  release(): void;
}

export type V4CursorTarget =
  | Readonly<{ exact: bigint; delimiter?: never; maxBytes?: never }>
  | Readonly<{ exact?: never; delimiter: Uint8Array; maxBytes: bigint }>;

/** A single target, persistent partial prefix and one payload handoff. */
export class V4ReaderCursor {
  #owner: V4CursorReadOwner | undefined;
  #storage: Uint8Array;
  readonly #target: bigint;
  readonly #delimiter: Uint8Array | undefined;
  readonly #prefixTable: readonly number[];
  #match = 0;
  #filled = 0;
  #offset: bigint;
  #matched = false;
  #closed = false;
  #frozen = false;
  #delivered = false;
  #waiter: CursorWaiter | undefined;
  #prefixWaiter: CursorWaiter | undefined;
  #handoff = false;
  #state: V4ReadState;
  #pending: true | undefined;
  #readAbort: AbortController | undefined;
  #readFailure: V4ReadMethodFailureReason | undefined;

  constructor(source: V4ReaderSource, options: V4CursorTarget) {
    const exact = options.exact;
    const delimiter = options.delimiter;
    if (exact !== undefined) {
      if (!isUint64(exact) || delimiter !== undefined || options.maxBytes !== undefined) {
        throw new V4ReadMethodError("invalid_argument");
      }
      this.#target = exact;
      this.#delimiter = undefined;
    } else {
      const maxBytes = options.maxBytes;
      if (!(delimiter instanceof Uint8Array) || delimiter.length < 1 || delimiter.length > 32 ||
          !isUint64(maxBytes) || maxBytes < BigInt(delimiter.length)) {
        throw new V4ReadMethodError("invalid_argument");
      }
      this.#target = maxBytes;
      this.#delimiter = new Uint8Array(delimiter);
    }
    if (this.#target > BigInt(Number.MAX_SAFE_INTEGER)) throw new V4ReadMethodError("invalid_argument");
    if (typeof source?.acquireCursor !== "function") throw new V4ReadMethodError("owner_unavailable");
    const owner = source.acquireCursor(this.#target);
    if (!isUint64(owner.startOffset) || this.#target > uint64Max - owner.startOffset ||
        owner.storage.length !== Number(this.#target)) {
      owner.release();
      throw new V4ReadMethodError("owner_unavailable");
    }
    this.#owner = owner;
    this.#storage = owner.storage;
    this.#offset = owner.startOffset;
    try { this.#state = snapshotReadState(owner.state()); }
    catch (error) { owner.release(); throw error; }
    this.#prefixTable = delimiterTable(this.#delimiter);
  }

  progress(): V4ReaderCursorSnapshot {
    this.#refreshState();
    const cause = this.#cause();
    return Object.freeze({
      offset: this.#offset,
      transferred_bytes: BigInt(this.#filled),
      target: this.#target,
      stream_status: this.#state.stream_status,
      ...(cause === undefined ? {} : { target_cause: cause }),
      ...(this.#state.error === undefined ? {} : { stream_error: this.#state.error }),
      complete: this.#complete(),
      frozen: this.#frozen,
      delivered: this.#delivered,
      closed: this.#closed,
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#readAbort?.abort();
    this.#releaseIfFinished();
    this.#wake();
  }

  readExactly(options?: OperationOptions): Promise<V4ReadResult> { return this.#wait("exact", options?.signal); }
  readUntil(options?: OperationOptions): Promise<V4ReadResult> { return this.#wait("until", options?.signal); }
  readLine(options?: OperationOptions): Promise<V4ReadResult> { return this.#wait("line", options?.signal); }
  takePrefix(options?: OperationOptions): Promise<V4ReadResult> { return this.#wait("prefix", options?.signal); }

  #failure(reason: V4ReadMethodFailureReason): V4ReadMethodError { return new V4ReadMethodError(reason, this.progress()); }

  #wait(method: "exact" | "until" | "line" | "prefix", signal?: AbortSignal): Promise<V4ReadResult> {
    let resolve!: (result: V4ReadResult) => void, reject!: (error: unknown) => void;
    // Construct the final capability before installing any waiter. Native init
    // hooks may close this cursor, which the installation checks below observe.
    const promise = new NativePromise<V4ReadResult>((yes, no) => { resolve = yes; reject = no; });
    let reason: V4ReadMethodFailureReason | undefined;
    if ((method === "exact" && this.#delimiter !== undefined) ||
        ((method === "until" || method === "line") && this.#delimiter === undefined) ||
        (method === "line" && (this.#delimiter?.length !== 1 || this.#delimiter[0] !== 10))) reason = "target_mismatch";
    else if (this.#delivered) reason = "already_delivered";
    else if (this.#closed) reason = "closed";
    else if (method !== "prefix" && this.#frozen) reason = "prefix_frozen";
    else if (this.#handoff || this.#prefixWaiter !== undefined || method !== "prefix" && this.#waiter !== undefined) reason = "read_in_progress";
    if (reason !== undefined) { reject(this.#failure(reason)); return promise; }
    const waiter: CursorWaiter = {
      prefix: method === "prefix", signal, resolve, reject,
      canceled: () => this.#schedule(waiter), armed: false, queued: false, settled: false,
    };
    if (waiter.prefix) {
      this.#prefixWaiter = waiter;
      this.#frozen = true;
      this.#readAbort?.abort();
    } else this.#waiter = waiter;
    signal?.addEventListener("abort", waiter.canceled, { once: true });
    this.#wake();
    // No host operation is allowed between arming and returning this exact
    // capability. A ready result is delivered by the registered job afterward.
    waiter.armed = true;
    return promise;
  }

  #wake(): void {
    if (this.#waiter !== undefined) this.#schedule(this.#waiter);
    if (this.#prefixWaiter !== undefined) this.#schedule(this.#prefixWaiter);
  }

  #schedule(waiter: CursorWaiter): void {
    if (waiter.queued || waiter.settled) return;
    waiter.queued = true;
    enqueueReadJob(() => {
      waiter.queued = false;
      if (!waiter.armed || waiter.settled) return;
      try { this.#drive(waiter); }
      catch (error) {
        // A claimed host action is never republished as rejection. Supported
        // native resolvers return normally; an exceptional tail stays owned.
        if (this.#handoff) return;
        this.#finishWait(waiter);
        waiter.reject(error);
      }
    });
  }

  #finishWait(waiter: CursorWaiter): void {
    waiter.settled = true;
    if (this.#waiter === waiter) this.#waiter = undefined;
    if (this.#prefixWaiter === waiter) this.#prefixWaiter = undefined;
    waiter.signal?.removeEventListener("abort", waiter.canceled);
  }

  #drive(waiter: CursorWaiter): void {
    if (this.#closed) throw this.#failure("closed");
    if (!waiter.prefix && this.#frozen) throw this.#failure("prefix_frozen");
    this.#refreshState();
    if (waiter.signal?.aborted && this.#state.stream_status === "open") {
      const result = this.#result(false);
      this.#finishWait(waiter); waiter.resolve(result); return;
    }
    if (this.#pending === undefined && (waiter.prefix || this.#complete())) {
      const result = this.#result(true);
      this.#owner!.claimDelivery();
      this.#handoff = true;
      waiter.resolve(result);
      // Reentrant Close/cancel can fence future work, but cannot erase or refund
      // this claimed action while the native resolver is still running.
      this.#delivered = true;
      this.#handoff = false;
      this.#finishWait(waiter);
      this.#releaseIfFinished();
      return;
    }
    if (this.#readFailure !== undefined) throw this.#failure(this.#readFailure);
    if (this.#pending === undefined) this.#startRead();
  }

  #startRead(): void {
    const owner = this.#owner!;
    const controller = new AbortController();
    this.#readAbort = controller;
    const remaining = Number(this.#target) - this.#filled;
    let transferred = 0;
    this.#pending = true;
    void NativePromise.resolve().then(async () => {
      if (controller.signal.aborted || this.#closed || this.#frozen) return;
      await owner.read(remaining, bytes => {
        if (this.#closed || this.#frozen) return 0;
        const count = this.#transfer(bytes);
        transferred += count;
        return count;
      }, controller.signal);
    }).catch(error => {
      if (!controller.signal.aborted) this.#readFailure = error instanceof V4ReadMethodError ? error.reason : "owner_unavailable";
    }).then(() => {
      try { this.#refreshState(); }
      catch { this.#readFailure = "owner_unavailable"; }
      // Empty successful reads on an open positive target cannot busy-loop.
      if (transferred === 0 && !controller.signal.aborted && this.#state.stream_status === "open") this.#readFailure ??= "owner_unavailable";
      this.#pending = undefined;
      this.#readAbort = undefined;
      this.#releaseIfFinished();
      this.#wake();
    });
  }

  #transfer(bytes: Uint8Array): number {
    const maximum = Math.min(bytes.length, Number(this.#target) - this.#filled);
    let count = maximum;
    if (this.#delimiter !== undefined) {
      count = 0;
      while (count < maximum && !this.#matched) {
        const byte = bytes[count]!;
        while (this.#match > 0 && byte !== this.#delimiter[this.#match]) this.#match = this.#prefixTable[this.#match - 1]!;
        if (byte === this.#delimiter[this.#match]) this.#match++;
        count++;
        if (this.#match === this.#delimiter.length) this.#matched = true;
      }
    }
    copyBytes.call(this.#storage, byteSlice(bytes, 0, count), this.#filled);
    this.#filled += count;
    this.#offset += BigInt(count);
    return count;
  }

  #refreshState(): void {
    if (this.#owner !== undefined) this.#state = snapshotReadState(this.#owner.state());
  }

  #complete(): boolean { return this.#matched || BigInt(this.#filled) === this.#target || this.#state.stream_status !== "open"; }

  #cause(): V4ReadCause | undefined {
    if (this.#delimiter !== undefined && !this.#matched && BigInt(this.#filled) === this.#target) return "delimiter_not_found";
    if (this.#state.stream_status === "eof" && !this.#matched && BigInt(this.#filled) < this.#target) return "unexpected_eof";
    return undefined;
  }

  #result(deliver: boolean): V4ReadResult {
    const cause = this.#cause();
    const result: V4ReadResult = {
      data: deliver ? byteSlice(this.#storage, 0, this.#filled) : new Uint8Array(),
      progress: Object.freeze({ offset: this.#offset, filled: deliver ? BigInt(this.#filled) : 0n, target: this.#target }),
      wait_status: deliver ? "ready" : "wait_canceled",
      stream_status: this.#state.stream_status,
      ...(cause === undefined ? {} : { cause }),
      ...(this.#state.error === undefined ? {} : { error: this.#state.error }),
    };
    // Prevent inherited thenables from intercepting the public handoff.
    Object.defineProperty(result, "then", { value: undefined });
    return Object.freeze(result);
  }

  #releaseIfFinished(): void {
    if (this.#handoff || this.#pending !== undefined || (!this.#closed && !this.#delivered)) return;
    const owner = this.#owner;
    this.#owner = undefined;
    this.#storage = empty;
    owner?.release();
  }
}

/** Runtime integration: Supplied by the v4 WriteRequest admission and resource owner. */
export interface V4WriteRequestOwner {
  start(): void;
  cancel(): void;
  wait(options?: OperationOptions): Promise<V4WriteProgress>;
  progress(): V4WriteProgress;
  cleanupStatus(): V4CleanupStatus;
}

/** Runtime integration: Preparation reserves/copies bytes and fixes a finite deadline. */
export interface V4WriteSource {
  prepareWrite(payload: Uint8Array, options?: Readonly<{ deadlineMilliseconds?: bigint }>): V4WriteRequestOwner;
}

/** A projection of one real WriteRequest, including its partial acceptance. */
export class V4WriteOperation {
  readonly #owner: V4WriteRequestOwner;
  #started = false;

  constructor(source: V4WriteSource, payload: Uint8Array, options?: Readonly<{ deadlineMilliseconds?: bigint }>) {
    if (typeof source?.prepareWrite !== "function") throw new Error("owner_unavailable");
    this.#owner = source.prepareWrite(payload, options);
  }

  start(): void {
    if (this.#started) return;
    this.#started = true;
    this.#owner.start();
  }
  cancel(): void { this.#owner.cancel(); }
  wait(options?: OperationOptions): Promise<V4WriteProgress> { return this.#owner.wait(options).then(freezeWriteProgress); }
  progress(): V4WriteProgress { return freezeWriteProgress(this.#owner.progress()); }
  cleanupStatus(): V4CleanupStatus { return freezeCleanup(this.#owner.cleanupStatus()); }
}

export type V4OperationStatus = "pending" | "accepted" | "executing" | "completed" | "failed" | "unknown";
/** Runtime integration: Execution owners alone supply operation status and cancellation. */
export interface V4OperationOwner {
  start(): void;
  status(): V4OperationStatus;
  requestCancel(): void;
  waitStatus(options?: OperationOptions): Promise<V4OperationStatus>;
  cleanupStatus(): V4CleanupStatus;
}

export class V4OperationHandle {
  readonly #owner: V4OperationOwner;
  constructor(owner: V4OperationOwner) {
    if (typeof owner?.waitStatus !== "function" || typeof owner.cleanupStatus !== "function") throw new Error("owner_unavailable");
    this.#owner = owner;
  }
  start(): void { this.#owner.start(); }
  status(): V4OperationStatus { return this.#owner.status(); }
  requestCancel(): void { this.#owner.requestCancel(); }
  waitStatus(options?: OperationOptions): Promise<V4OperationStatus> { return this.#owner.waitStatus(options); }
  cleanupStatus(): V4CleanupStatus { return freezeCleanup(this.#owner.cleanupStatus()); }
}

/** Runtime integration: An accepted v4 stream supplies these capabilities from one owner. */
export interface V4StreamOwner extends V4ReaderSource, V4WriteSource {
  read(maxBytes: bigint, options?: OperationOptions): Promise<V4ReadResult>;
  write(payload: Uint8Array, options?: OperationOptions): Promise<V4WriteProgress>;
  closeWrite(options?: OperationOptions): Promise<V4CloseResult>;
  finish(options?: OperationOptions): Promise<V4CloseResult>;
  reset(options?: OperationOptions): Promise<V4CloseResult>;
  close(options?: OperationOptions): Promise<V4CloseResult>;
  waitPeerAuthenticated(offset: bigint, options?: OperationOptions): Promise<void>;
  cleanupStatus(): V4CleanupStatus;
}

/** Runtime integration: Created only after the actual v4 admission/READY path succeeds. */
export interface V4SessionOwner {
  unreliableMessages?(): V4UnreliableMessages;
  subscribeNotification?: V4Notifications["subscribe"];
  readOperationResult?(reference: OperationReferenceTypes.V4OperationReference, options?: OperationResultReadTypes.V4OperationResultReadOptions): OperationResultReadTypes.V4OperationResultRead;
  queryOperation?(reference: OperationReferenceTypes.V4OperationReference, options?: OperationOptions): Promise<OperationReferenceTypes.V4ExecutionManagementResult>;
  requestCancel?(reference: OperationReferenceTypes.V4OperationReference, options?: OperationOptions): Promise<OperationReferenceTypes.V4ExecutionManagementResult>;
  bindService?<Methods extends ServiceDefinitionTypes.V4ServiceMethods>(definition: ServiceDefinitionTypes.V4ServiceDefinition<Methods>,
    options: ServiceClientTypes.V4ServiceBindOptions): Promise<ServiceClientTypes.V4ServiceClient<Methods>>;
  info(): V4SessionInfo;
  openStream(kind: string, options?: OperationOptions & Readonly<{ metadata?: StreamMetadata }>): Promise<V4StreamOwner>;
  acceptStream(options?: OperationOptions): Promise<Readonly<{ kind: string; metadata: StreamMetadata; stream: V4StreamOwner }>>;
  openMessageStream<A, B>(definition: MessageDefinitionTypes.V4MessageStreamDefinition<A, B>, options?: OperationOptions & MessageStreamTypes.V4MessageStreamOptions & Readonly<{ metadata?: StreamMetadata }>): Promise<MessageStreamTypes.V4TypedMessageStream<B, A>>;
  acceptMessageStream<A, B>(definition: MessageDefinitionTypes.V4MessageStreamDefinition<A, B>, options?: OperationOptions & MessageStreamTypes.V4MessageStreamOptions): Promise<MessageStreamTypes.V4TypedMessageStream<A, B>>;
  registerMessageStream<A, B>(definition: MessageDefinitionTypes.V4MessageStreamDefinition<A, B>, authorize: StreamHandlersTypes.V4StreamOpenAuthorizer | undefined,
    handler: StreamHandlersTypes.V4MessageStreamHandler<A, B>, options: StreamHandlersTypes.V4StreamRegistrationOptions): StreamHandlersTypes.V4StreamRegistration;
  registerStream(kind: string, authorize: StreamHandlersTypes.V4StreamOpenAuthorizer | undefined,
    handler: StreamHandlersTypes.V4RawStreamHandler, options: StreamHandlersTypes.V4StreamRegistrationOptions): StreamHandlersTypes.V4StreamRegistration;
  rekey(options?: OperationOptions): Promise<void>;
  probeLiveness(options?: OperationOptions): Promise<V4LivenessResult>;
  drain(options?: DrainTypes.V4DrainOptions): DrainTypes.V4DrainOperation;
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus>;
  waitTermination(options?: OperationOptions): Promise<void>;
  close(): Promise<V4LifecycleResult>;
  lifecycleResult(): V4LifecycleResult;
  onCleanup?(callback: () => void): void;
  cleanupStatus(): V4CleanupStatus;
}

export class V4Session {
  readonly notifications: V4Notifications;
  #owner: V4SessionOwner | undefined;
  #close: Promise<V4LifecycleResult> | undefined;
  #closing = false;
  #info: V4SessionInfo | undefined;
  #final: V4LifecycleResult | undefined;
  #termination: Promise<void> | undefined;
  #drain: DrainTypes.V4DrainOperation | undefined;
  constructor(owner: V4SessionOwner) {
    this.notifications = Object.freeze({ subscribe: (method, handler, options) => {
      if (this.#closing || this.#owner?.subscribeNotification === undefined) throw new Error("notification_unavailable");
      return this.#owner.subscribeNotification(method, handler, options);
    } } satisfies V4Notifications);
    if (typeof owner?.info !== "function" || typeof owner.cleanupStatus !== "function") throw new Error("owner_unavailable");
    this.#owner = owner;
    Object.defineProperty(this, "then", { value: undefined });
    owner.onCleanup?.(() => {
      this.#info = owner.info(); this.#final = owner.lifecycleResult(); this.#closing = true;
      this.#termination = owner.waitTermination(); void this.#termination.catch(() => undefined);
      this.#owner = undefined;
    });
  }
  unreliableMessages(): V4UnreliableMessages {
    if (this.#closing || this.#owner?.unreliableMessages === undefined) throw new V4UnreliableMessageError(this.#closing ? "closed" : "unavailable");
    return this.#owner.unreliableMessages();
  }
  queryOperation(reference: OperationReferenceTypes.V4OperationReference, options?: OperationOptions): Promise<OperationReferenceTypes.V4ExecutionManagementResult> {
    if (this.#owner?.queryOperation === undefined) return NativePromise.reject(new Error("configuration_capacity")); return this.#owner.queryOperation(reference, options);
  }
  readOperationResult(reference: OperationReferenceTypes.V4OperationReference, options?: OperationResultReadTypes.V4OperationResultReadOptions): OperationResultReadTypes.V4OperationResultRead {
    if (this.#closing) throw new Error("closed");
    if (this.#owner?.readOperationResult === undefined) throw new Error("configuration_capacity"); return this.#owner.readOperationResult(reference, options);
  }
  requestCancel(reference: OperationReferenceTypes.V4OperationReference, options?: OperationOptions): Promise<OperationReferenceTypes.V4ExecutionManagementResult> {
    if (this.#owner?.requestCancel === undefined) return NativePromise.reject(new Error("configuration_capacity")); return this.#owner.requestCancel(reference, options);
  }
  bindService<Methods extends ServiceDefinitionTypes.V4ServiceMethods>(definition: ServiceDefinitionTypes.V4ServiceDefinition<Methods>,
    options: ServiceClientTypes.V4ServiceBindOptions): Promise<ServiceClientTypes.V4ServiceClient<Methods>> {
    if (this.#closing) return NativePromise.reject(new Error("closed"));
    if (this.#owner?.bindService === undefined) return NativePromise.reject(new Error("configuration_capacity"));
    return this.#owner.bindService(definition, options);
  }
  info(): V4SessionInfo { return this.#info ?? this.#owner!.info(); }
  openStream(kind: string, options?: OperationOptions & Readonly<{ metadata?: StreamMetadata }>): Promise<V4StreamOwner> {
    if (this.#closing) return Promise.reject(new Error("closed"));
    return this.#owner!.openStream(kind, options);
  }
  acceptStream(options?: OperationOptions): ReturnType<V4SessionOwner["acceptStream"]> {
    if (this.#closing) return Promise.reject(new Error("closed"));
    return this.#owner!.acceptStream(options);
  }
  openMessageStream<A, B>(definition: MessageDefinitionTypes.V4MessageStreamDefinition<A, B>, options?: OperationOptions & MessageStreamTypes.V4MessageStreamOptions & Readonly<{ metadata?: StreamMetadata }>): Promise<MessageStreamTypes.V4TypedMessageStream<B, A>> {
    if (this.#closing) return Promise.reject(new Error("closed")); return this.#owner!.openMessageStream(definition, options);
  }
  acceptMessageStream<A, B>(definition: MessageDefinitionTypes.V4MessageStreamDefinition<A, B>, options?: OperationOptions & MessageStreamTypes.V4MessageStreamOptions): Promise<MessageStreamTypes.V4TypedMessageStream<A, B>> {
    if (this.#closing) return Promise.reject(new Error("closed")); return this.#owner!.acceptMessageStream(definition, options);
  }
  registerMessageStream<A, B>(definition: MessageDefinitionTypes.V4MessageStreamDefinition<A, B>, authorize: StreamHandlersTypes.V4StreamOpenAuthorizer | undefined,
    handler: StreamHandlersTypes.V4MessageStreamHandler<A, B>, options: StreamHandlersTypes.V4StreamRegistrationOptions): StreamHandlersTypes.V4StreamRegistration {
    if (this.#closing) throw new Error("closed"); return this.#owner!.registerMessageStream(definition, authorize, handler, options);
  }
  registerStream(kind: string, authorize: StreamHandlersTypes.V4StreamOpenAuthorizer | undefined,
    handler: StreamHandlersTypes.V4RawStreamHandler, options: StreamHandlersTypes.V4StreamRegistrationOptions): StreamHandlersTypes.V4StreamRegistration {
    if (this.#closing) throw new Error("closed"); return this.#owner!.registerStream(kind, authorize, handler, options);
  }
  rekey(options?: OperationOptions): Promise<void> {
    if (this.#closing) return Promise.reject(new Error("closed"));
    return this.#owner!.rekey(options);
  }
  probeLiveness(options?: OperationOptions): Promise<V4LivenessResult> {
    if (this.#closing) return Promise.reject(new V4LivenessError("closed", { submitted: false, complete: false, elapsedMS: null }));
    return this.#owner!.probeLiveness(options);
  }
  waitTermination(options?: OperationOptions): Promise<void> { return this.#termination ?? this.#owner!.waitTermination(options); }
  drain(options?: DrainTypes.V4DrainOptions): DrainTypes.V4DrainOperation {
    if (this.#drain !== undefined) return this.#drain;
    if (this.#closing) throw new Error("closed");
    this.#drain = this.#owner!.drain(options); return this.#drain;
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    return this.#owner === undefined ? NativePromise.resolve(this.#final!.cleanup_status) : this.#owner.waitCleanup(options);
  }
  close(): Promise<V4LifecycleResult> {
    if (this.#close !== undefined) return this.#close;
    if (this.#owner === undefined) return this.#close = NativePromise.resolve(this.#final!);
    this.#closing = true;
    // The owner seals its admission synchronously, including raw Stream handles.
    try { return this.#close = this.#owner.close(); } catch { return this.#close = NativePromise.reject(new Error("cleanup_failed")); }
  }
  lifecycleResult(): V4LifecycleResult { return this.#final ?? this.#owner!.lifecycleResult(); }
  cleanupStatus(): V4CleanupStatus { return this.#final?.cleanup_status ?? freezeCleanup(this.#owner!.cleanupStatus()); }
}

/** Runtime integration: The immutable lease/identity/key owner, never an existing Session. */
export interface V4MaterialOwner { closeMaterial(): Promise<void>; }
/** Runtime integration: The runtime owns source acquisition and prepare/spend/READY. */
export interface V4EnvironmentOwner {
  diagnosticCounts?(metric: DiagnosticMetric): DiagnosticCounts;
  diagnosticSink?(): DiagnosticSink | undefined;
  /** Required dependencies are checked before material ownership transfers. */
  assertConnectAvailable?(): void;
  connect(source: V4ConnectionMaterialSource, request: V4ConnectionRequirements, options?: OperationOptions): Promise<V4SessionOwner>;
  connectMaterial(material: V4MaterialOwner, options?: OperationOptions): Promise<V4SessionOwner>;
  close(): Promise<V4LifecycleResult>;
  lifecycleResult(): V4LifecycleResult;
  onCleanup?(callback: () => void): void;
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus>;
  /** Includes all child session, preparation and shared dependency references. */
  cleanupStatus(): V4CleanupStatus;
}
export interface V4ConnectionMaterialSource {
  acquire(request: V4ConnectionRequirements, options?: OperationOptions): Promise<V4ConnectionMaterial>;
}

const materialOwners = new WeakMap<V4ConnectionMaterial, V4MaterialOwner>();
const wrappedMaterials = new WeakSet<V4MaterialOwner>();
export class V4ConnectionMaterial {
  #close: Promise<void> | undefined;
  constructor(owner: V4MaterialOwner) {
    if (typeof owner?.closeMaterial !== "function") throw new Error("owner_unavailable");
    if (wrappedMaterials.has(owner)) throw new Error("material_unavailable");
    wrappedMaterials.add(owner);
    materialOwners.set(this, owner);
  }
  close(): Promise<void> {
    if (this.#close !== undefined) return this.#close;
    const owner = materialOwners.get(this);
    materialOwners.delete(this);
    this.#close = owner === undefined ? Promise.resolve() : Promise.resolve().then(() => owner.closeMaterial());
    return this.#close;
  }
}

const emptyDiagnosticCounts: DiagnosticCounts = Object.freeze({ total: 0n,
  state: Object.freeze(diagnosticDimensions.state.map(() => 0n)), phase: Object.freeze(diagnosticDimensions.phase.map(() => 0n)),
  code: Object.freeze(diagnosticDimensions.code.map(() => 0n)), duration_bucket: Object.freeze(diagnosticDimensions.duration_bucket.map(() => 0n)),
  attempt_bucket: Object.freeze(diagnosticDimensions.attempt_bucket.map(() => 0n)) });
/** Lifecycle projection; connection and cleanup evidence come from the runtime. */
export class V4TransportEnvironment {
  #diagnosticFinal: ReadonlyMap<DiagnosticMetric, DiagnosticCounts> | undefined;
  #diagnosticSink: DiagnosticSink | undefined;
  #owner: V4EnvironmentOwner | undefined;
  #closing = false;
  #final: V4LifecycleResult | undefined;
  #close: Promise<V4LifecycleResult> | undefined;
  constructor(owner: V4EnvironmentOwner) {
    if (typeof owner?.connectMaterial !== "function" || typeof owner.cleanupStatus !== "function") throw new Error("owner_unavailable");
    this.#owner = owner;
    this.#diagnosticSink = owner.diagnosticSink?.();
    Object.defineProperty(this, "then", { value: undefined });
    owner.onCleanup?.(() => {
      this.#diagnosticFinal = new Map(diagnosticMetrics.map(metric => [metric, owner.diagnosticCounts?.(metric) ?? emptyDiagnosticCounts]));
      this.#final = owner.lifecycleResult(); this.#closing = true; this.#owner = undefined;
    });
  }
  diagnosticCounts(metric: DiagnosticMetric): DiagnosticCounts {
    return this.#owner?.diagnosticCounts?.(metric) ?? this.#diagnosticFinal?.get(metric) ?? emptyDiagnosticCounts;
  }
  diagnosticSink(): DiagnosticSink | undefined { return this.#diagnosticSink; }
  async serve<Plan extends object>(options: ServeOptions<Plan>, operation?: OperationOptions): Promise<ServeHandle> {
    try { this.#checkConnect(operation?.signal); }
    catch { throw new ServeError(operation?.signal?.aborted ? "canceled" : "closed", { status: "complete", core_cleanup: "complete", pending_callbacks: 0n }); }
    return startServe(this, options, operation);
  }
  connect(source: V4ConnectionMaterialSource, request: Partial<V4ConnectionRequirements> = {}, options?: OperationOptions): Promise<V4Session> {
    return this.#connect(owner => {
      const requirements = captureConnectionRequirements(request);
      this.#checkConnect(options?.signal);
      return owner.connect(source, requirements, options);
    }, options?.signal);
  }
  connectMaterial(material: V4ConnectionMaterial, options?: OperationOptions): Promise<V4Session> {
    return this.#connect(owner => {
      owner.assertConnectAvailable?.();
      this.#checkConnect(options?.signal);
      const original = materialOwners.get(material);
      if (original === undefined) throw new Error("material_unavailable");
      // The final public capability already exists. Check the original map
      // after host initialization and dependency checks, which can reenter
      // Close, cancellation, or a competing ConnectMaterial on this handle.
      materialOwners.delete(material);
      // The runtime owns every outcome after this transfer, including failed
      // admission. Consumed material never returns to the public handle.
      return owner.connectMaterial(original, options);
    }, options?.signal);
  }
  #checkConnect(signal?: AbortSignal): void {
    if (this.#closing) throw new Error("closed");
    if (signal?.aborted) throw new Error("canceled");
  }
  #connect(connect: (owner: V4EnvironmentOwner) => Promise<V4SessionOwner>, signal?: AbortSignal): Promise<V4Session> {
    let resolve!: (session: V4Session) => void, reject!: (error: unknown) => void;
    // Native Promise initialization can synchronously reenter the SDK. Do not
    // transfer material or start source work until construction has returned.
    const pending = new NativePromise<V4Session>((yes, no) => { resolve = yes; reject = no; });
    try {
      this.#checkConnect(signal);
      // Enter the runtime synchronously after the gate, before returning the
      // capability; a later Close cannot be followed by queued source work.
      let connecting: Promise<V4SessionOwner>;
      connecting = connect(this.#owner!);
      void connecting.then(owner => {
        const session = new V4Session(owner);
        if (this.#closing || signal?.aborted) {
          void session.close().then(
            () => reject(new ConnectionError(this.#closing ? "closed" : "canceled", observedConnectionFacts(owner) ?? unknownConnectionFacts(), session.cleanupStatus())),
            () => reject(new ConnectionError("controller_failed", observedConnectionFacts(owner) ?? unknownConnectionFacts(), session.cleanupStatus())),
          );
          return;
        }
        resolve(session);
      }).catch(error => reject(error instanceof ConnectionError ? error : new ConnectionError(controllerFailureCode(error), new ConnectionFacts().snapshot(), completeCleanup)));
    } catch (error) { reject(error instanceof ConnectionError ? error : new ConnectionError(controllerFailureCode(error), new ConnectionFacts().snapshot(), completeCleanup)); }
    return pending;
  }
  close(): Promise<V4LifecycleResult> {
    if (this.#close !== undefined) return this.#close;
    if (this.#owner === undefined) return this.#close = NativePromise.resolve(this.#final!);
    this.#closing = true;
    // The Environment owns pending connections and Sessions. The facade does
    // not add an unbounded wait for its own convenience Promise reactions.
    try { return this.#close = this.#owner.close(); } catch { return this.#close = NativePromise.reject(new Error("cleanup_failed")); }
  }
  lifecycleResult(): V4LifecycleResult { return this.#final ?? this.#owner!.lifecycleResult(); }
  cleanupStatus(): V4CleanupStatus { return this.#final?.cleanup_status ?? freezeCleanup(this.#owner!.cleanupStatus()); }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    return this.#owner === undefined ? NativePromise.resolve(this.#final!.cleanup_status) : this.#owner.waitCleanup(options);
  }

}

function isUint64(value: unknown): value is bigint { return typeof value === "bigint" && value >= 0n && value <= uint64Max; }
function freezeCleanup(value: V4CleanupStatus): V4CleanupStatus {
  const result = { status: value.status, core_cleanup: value.core_cleanup, pending_callbacks: value.pending_callbacks };
  Object.defineProperty(result, "then", { value: undefined }); return Object.freeze(result);
}
function freezeWriteProgress(value: V4WriteProgress): V4WriteProgress { return Object.freeze({ ...value, cleanup_status: freezeCleanup(value.cleanup_status) }); }
function snapshotReadState(value: V4ReadState): V4ReadState {
  if ((value.stream_status === "error") !== (value.error !== undefined)) throw new V4ReadMethodError("owner_unavailable");
  return Object.freeze({ stream_status: value.stream_status, ...(value.error === undefined ? {} : { error: Object.freeze({ ...value.error }) }) });
}
function delimiterTable(delimiter: Uint8Array | undefined): readonly number[] {
  if (delimiter === undefined) return [];
  const table = Array<number>(delimiter.length).fill(0);
  for (let i = 1, prefix = 0; i < delimiter.length; i++) {
    while (prefix > 0 && delimiter[i] !== delimiter[prefix]) prefix = table[prefix - 1]!;
    if (delimiter[i] === delimiter[prefix]) prefix++;
    table[i] = prefix;
  }
  return table;
}
