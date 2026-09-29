import type * as OperationReferenceTypes from "./operationReference.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import type { V4UnaryStartResult } from "./unaryOperation.js";
import type { RPCUnaryPreparation, RPCUnaryPreparationOptions } from "./runtime/rpcUnaryPreparation.js";
import type { RPCStreamingAbandonResult, RPCStreamingExchange, RPCStreamingItem, RPCStreamingReadOptions, RPCStreamingStatus } from "./runtime/rpcStreamingExchange.js";
import { RPCProtocolError } from "./runtime/rpcFragment.js";

export interface V4StreamingOptions {
  readonly maxItemBytes?: number;
  readonly timeoutMS?: bigint;
  readonly deadlineAtMS?: bigint;
  readonly admission?: "queued" | "try_now";
  readonly admissionNotAfterMS?: bigint;
  readonly context?: V4ApplicationContext;
  readonly signal?: AbortSignal;
}
export type V4StreamingItem<Item> = Exclude<RPCStreamingItem, { kind: "value"; encoding: "typed" }> |
  (Omit<Extract<RPCStreamingItem, { kind: "value"; encoding: "typed" }>, "value"> & Readonly<{ value: Item }>);
export type V4StreamingStatus = RPCStreamingStatus | Readonly<{ state: "prepared" | "closed"; submission: "not_submitted"; deliveredItems: 0n; deliveredBytes: 0n;
  payloadStatus: "pending" | "payload_unavailable"; applicationInputDelivered: false }>;
export type V4StreamingAbandonResult = Omit<RPCStreamingAbandonResult, "status"> & Readonly<{ status: V4StreamingStatus }>;
const capability = Symbol("original streaming operation");
const preparations = new WeakMap<V4StreamingOperation<unknown>, RPCUnaryPreparation<RPCStreamingExchange>>();
const NativePromise = Promise;
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const addListener = EventTarget.prototype.addEventListener, removeListener = EventTarget.prototype.removeEventListener;
function doneResult(): IteratorReturnResult<undefined> {
  const result = { done: true as const, value: undefined }; Object.defineProperty(result, "then", { value: undefined }); return Object.freeze(result);
}
export function captureStreamingOptions(options: V4StreamingOptions = {}) {
  const { maxItemBytes, timeoutMS = 30000n, deadlineAtMS, admission, admissionNotAfterMS, context, signal } = options;
  const preparation: RPCUnaryPreparationOptions = Object.freeze({ defaultLifetimeMS: timeoutMS,
    ...(maxItemBytes === undefined ? {} : { responseLimitBytes: maxItemBytes }), ...(deadlineAtMS === undefined ? {} : { deadlineAtMS }),
    ...(admission === undefined ? {} : { admission }), ...(admissionNotAfterMS === undefined ? {} : { admissionNotAfterMS }) });
  return Object.freeze({ preparation, context, signal });
}
/** Explicit ownership of one prepared initial request and dedicated result
 * stream. Closing this handle never claims remote business cancellation. */
export class V4StreamingOperation<Item> {
  readonly #preparation: RPCUnaryPreparation<RPCStreamingExchange>;
  #exchange: RPCStreamingExchange | undefined;
  #closed = false;
  #iterating = false;
  #closeIterator: (() => void) | undefined;
  constructor(token: symbol, preparation: RPCUnaryPreparation<RPCStreamingExchange>) {
    if (token !== capability) throw new RPCProtocolError("rpc_stream_owner"); this.#preparation = preparation; preparations.set(this, preparation);
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  start(options: RPCStreamingReadOptions = {}): V4UnaryStartResult {
    if (this.#exchange !== undefined) return Object.freeze({ status: "admitted" });
    if (this.#closed) throw new RPCProtocolError("rpc_request_closed");
    const result = this.#preparation.start(options.context, options.signal);
    if (result.status === "not_admitted") return result;
    this.#exchange = result.exchange; return Object.freeze({ status: "admitted" });
  }
  status(): V4StreamingStatus {
    const closed = this.#closed || !this.#preparation.prepared;
    return this.#exchange?.status() ?? Object.freeze({ state: closed ? "closed" : "prepared", submission: "not_submitted", deliveredItems: 0n, deliveredBytes: 0n,
      payloadStatus: closed ? "payload_unavailable" : "pending", applicationInputDelivered: false });
  }
  waitStatus(options: RPCStreamingReadOptions = {}): Promise<V4StreamingStatus> { return this.#exchange?.waitStatus(options.signal) ?? Promise.resolve(this.status()); }
  readNext(options?: RPCStreamingReadOptions): Promise<V4StreamingItem<Item>> {
    if (this.#iterating && !this.#closed) throw new RPCProtocolError("read_in_progress");
    if (this.#exchange === undefined) throw new RPCProtocolError("rpc_not_started"); return this.#exchange.readNext(false, options) as Promise<V4StreamingItem<Item>>;
  }
  readNextEncoded(options?: RPCStreamingReadOptions): Promise<RPCStreamingItem> {
    if (this.#iterating && !this.#closed) throw new RPCProtocolError("read_in_progress");
    if (this.#exchange === undefined) throw new RPCProtocolError("rpc_not_started"); return this.#exchange.readNext(true, options);
  }
  items(options: RPCStreamingReadOptions = {}): AsyncIterableIterator<Exclude<V4StreamingItem<Item>, { kind: "end" }>, undefined> {
    if (this.#iterating) throw new RPCProtocolError("read_in_progress");
    const { signal, context } = options;
    if (signal !== undefined) signalAborted.call(signal);
    if (this.#exchange === undefined && !this.#closed) throw new RPCProtocolError("rpc_not_started");
    this.#exchange?.checkReaderAvailable();
    this.#iterating = true;
    let pending = false, ended = this.#closed;
    const captured = Object.freeze({ ...(signal === undefined ? {} : { signal }), ...(context === undefined ? {} : { context }) });
    const close = (): void => { ended = true; this.close(); };
    this.#closeIterator = () => { ended = true; if (signal !== undefined) removeListener.call(signal, "abort", close); };
    const settled = (terminal: boolean): void => { pending = false; if (terminal) close(); };
    type Iteration = IteratorResult<Exclude<V4StreamingItem<Item>, { kind: "end" }>, undefined>;
    const iterator: AsyncIterableIterator<Exclude<V4StreamingItem<Item>, { kind: "end" }>, undefined> = {
      next: (): Promise<Iteration> => {
        if (ended) return NativePromise.resolve(doneResult());
        if (pending) { close(); return NativePromise.reject(new RPCProtocolError("read_in_progress")); }
        pending = true;
        try { return this.#exchange!.readIteration(captured, settled) as Promise<Iteration>; }
        catch (error) { settled(true); return NativePromise.reject(error); }
      },
      return: (): Promise<Iteration> => { close(); return NativePromise.resolve(doneResult()); },
      throw: (reason?: unknown): Promise<Iteration> => { close(); return NativePromise.reject(reason); },
      [Symbol.asyncIterator](): AsyncIterableIterator<Exclude<V4StreamingItem<Item>, { kind: "end" }>, undefined> { return this; },
    };
    Object.defineProperty(iterator, "then", { value: undefined }); Object.freeze(iterator);
    if (signal !== undefined) { addListener.call(signal, "abort", close, { once: true }); if (signalAborted.call(signal)) close(); }
    return iterator;
  }
  abandonResult(): V4StreamingAbandonResult {
    return this.#exchange?.abandonResult() ?? Object.freeze({ outcome: "not_started", status: this.status(), cleanup: this.cleanupStatus() });
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    const closeIterator = this.#closeIterator; this.#closeIterator = undefined; closeIterator?.(); this.#preparation.close();
  }
  cleanupStatus(): V4CleanupStatus { return this.#preparation.cleanupStatus(); }
  waitCleanup(options: RPCStreamingReadOptions = {}): Promise<V4CleanupStatus> {
    return this.#exchange === undefined ? this.#preparation.waitPreparedCleanup(options.signal) : this.#exchange.waitCleanup(options);
  }
  toJSON(): object { return {}; }
}
/** Execution history is independent of the lifetime of the output stream. */
export class V4ExecutionStreamingOperation<Item> extends V4StreamingOperation<Item> {
  reference(): OperationReferenceTypes.V4OperationReference { return preparations.get(this)!.reference(); }
}
export function streamingOperation<Item>(preparation: RPCUnaryPreparation<RPCStreamingExchange>): V4StreamingOperation<Item> | V4ExecutionStreamingOperation<Item> {
  return preparation.execution ? new V4ExecutionStreamingOperation(capability, preparation) : new V4StreamingOperation(capability, preparation);
}
Object.freeze(V4ExecutionStreamingOperation.prototype); Object.freeze(V4ExecutionStreamingOperation);
Object.freeze(V4StreamingOperation.prototype); Object.freeze(V4StreamingOperation);
