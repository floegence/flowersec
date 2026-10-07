import type * as OperationReferenceTypes from "./operationReference.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import type { RPCUnaryPreparation, RPCUnaryPreparationOptions } from "./runtime/rpcUnaryPreparation.js";
import type { RPCUnaryExchange, RPCUnaryProgress, RPCUnaryTakeOptions, RPCUnaryTakeResult, RPCUnaryWaitResult } from "./runtime/rpcUnaryExchange.js";
import { RPCProtocolError } from "./runtime/rpcFragment.js";

export interface V4UnaryOptions extends Omit<RPCUnaryPreparationOptions, "defaultLifetimeMS" | "defaultResponseLimitBytes"> {
  readonly timeoutMS?: bigint;
  readonly signal?: AbortSignal;
  readonly context?: V4ApplicationContext;
}
export type V4UnaryResult<Value> = Exclude<RPCUnaryTakeResult, { kind: "value"; encoding: "typed" } | { kind: "retained_result" }> |
  (Omit<Extract<RPCUnaryTakeResult, { kind: "value"; encoding: "typed" }>, "value"> & Readonly<{ value: Value }>);
export type V4UnaryStatus = RPCUnaryProgress | Readonly<{ state: "prepared" | "closed"; submission: "not_submitted" }>;
export type V4UnaryStartResult = Readonly<{ status: "admitted" }> |
  Readonly<{ status: "not_admitted"; submission: "not_submitted"; reason: "not_ready" | "resource_exhausted" | "dependency_unavailable" }>;
const capability = Symbol("original unary operation view"), NativePromise = Promise;
const preparations = new WeakMap<V4UnaryOperation<unknown>, RPCUnaryPreparation>();
const dispatchOwners = new WeakMap<RPCUnaryPreparation, object>();

/** Internal provenance; a public handle cannot grant Controller ownership. */
export function controllerUnaryPreparation(preparation: RPCUnaryPreparation, owner: object): RPCUnaryPreparation {
  dispatchOwners.set(preparation, owner); return preparation;
}
export function dispatchControllerUnary<Value>(operation: V4UnaryOperation<Value>, owner: object, options: RPCUnaryTakeOptions): V4UnaryStartResult {
  const preparation = preparations.get(operation);
  if (preparation === undefined || dispatchOwners.get(preparation) !== owner) throw new RPCProtocolError("rpc_request_owner");
  return V4UnaryOperation.prototype.start.call(operation, options);
}

export function captureUnaryCallOptions(options: V4UnaryOptions = {}): Readonly<{
  preparation: RPCUnaryPreparationOptions; signal: AbortSignal | undefined; context: V4ApplicationContext | undefined;
}> {
  const { timeoutMS = 30000n, deadlineAtMS, admissionNotAfterMS, responseLimitBytes, admission, signal, context } = options;
  return Object.freeze({ preparation: Object.freeze({ defaultLifetimeMS: timeoutMS,
    ...(deadlineAtMS === undefined ? {} : { deadlineAtMS }), ...(admissionNotAfterMS === undefined ? {} : { admissionNotAfterMS }),
    ...(responseLimitBytes === undefined ? {} : { responseLimitBytes }), ...(admission === undefined ? {} : { admission }) }), signal, context });
}

/** One view of the original prepared unary operation. Methods never discover
 * a source, refresh a contract, implicitly Start, or replay a submitted call. */
export class V4UnaryOperation<Value> {
  readonly #preparation: RPCUnaryPreparation;
  #exchange: RPCUnaryExchange | undefined;
  #closed = false;
  constructor(token: symbol, preparation: RPCUnaryPreparation) {
    if (token !== capability) throw new RPCProtocolError("rpc_request_owner"); this.#preparation = preparation; preparations.set(this, preparation);
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  start(options: RPCUnaryTakeOptions = {}): V4UnaryStartResult {
    if (this.#exchange !== undefined) return Object.freeze({ status: "admitted" });
    if (this.#closed) throw new RPCProtocolError("rpc_request_closed");
    const started = this.#preparation.start(options.context, options.signal);
    if (started.status === "not_admitted") return started;
    this.#exchange = started.exchange; return Object.freeze({ status: "admitted" });
  }
  status(): V4UnaryStatus {
    if (this.#exchange !== undefined) return this.#exchange.progress();
    return Object.freeze({ state: this.#closed || !this.#preparation.prepared ? "closed" : "prepared", submission: "not_submitted" });
  }
  waitStatus(options: RPCUnaryTakeOptions = {}): Promise<V4UnaryStatus | RPCUnaryWaitResult> {
    return this.#exchange === undefined ? NativePromise.resolve(this.status()) : this.#exchange.waitStatus(options.signal);
  }
  takeResult(options?: RPCUnaryTakeOptions): Promise<V4UnaryResult<Value>> {
    if (this.#exchange === undefined) throw new RPCProtocolError("rpc_not_started");
    return this.#exchange.takeResult(options) as Promise<V4UnaryResult<Value>>;
  }
  takeEncodedResult(options?: RPCUnaryTakeOptions): Promise<RPCUnaryTakeResult> {
    if (this.#exchange === undefined) throw new RPCProtocolError("rpc_not_started"); return this.#exchange.takeEncodedResult(options);
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#preparation.close(); }
  cleanupStatus(): V4CleanupStatus { return this.#preparation.cleanupStatus(); }
  toJSON(): object { return {}; }
}
/** Only an execution operation exposes a remote-history reference. */
export class V4ExecutionUnaryOperation<Value> extends V4UnaryOperation<Value> {
  reference(): OperationReferenceTypes.V4OperationReference { return preparations.get(this)!.reference(); }
}
export function unaryOperation<Value>(preparation: RPCUnaryPreparation): V4UnaryOperation<Value> | V4ExecutionUnaryOperation<Value> {
  return preparation.execution ? new V4ExecutionUnaryOperation(capability, preparation) : new V4UnaryOperation(capability, preparation);
}
Object.freeze(V4ExecutionUnaryOperation.prototype); Object.freeze(V4ExecutionUnaryOperation);
Object.freeze(V4UnaryOperation.prototype); Object.freeze(V4UnaryOperation);
