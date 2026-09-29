import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import type { RPCUnaryExchange, RPCUnaryProgress, RPCUnaryTakeOptions, RPCUnaryTakeResult, RPCUnaryWaitResult } from "./runtime/rpcUnaryExchange.js";

export interface V4OperationResultReadOptions {
  readonly timeoutMS?: bigint;
  readonly signal?: AbortSignal;
  readonly context?: V4ApplicationContext;
}
export type V4OperationResultReadResult = Extract<RPCUnaryTakeResult, { kind: "retained_result" | "metadata" | "sdk_error" }>;
const capability = Symbol("original retained-result read");

/** One admitted fixed SDK read. Its typed value is Uint8Array: these are the
 * original encoded business-result bytes, whose success/error metadata comes
 * from QueryOperation. Reading neither dispatches nor resumes an operation. */
export class V4OperationResultRead {
  readonly #exchange: RPCUnaryExchange;
  constructor(token: symbol, exchange: RPCUnaryExchange) {
    if (token !== capability || exchange.header.kind !== "read_result_request") throw new Error("rpc_result_read_owner");
    this.#exchange = exchange; Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  status(): RPCUnaryProgress { return this.#exchange.progress(); }
  waitStatus(options: RPCUnaryTakeOptions = {}): Promise<RPCUnaryWaitResult> { return this.#exchange.waitStatus(options.signal); }
  takeResult(options?: RPCUnaryTakeOptions): Promise<V4OperationResultReadResult> { return this.#exchange.takeResult(options) as Promise<V4OperationResultReadResult>; }
  takeEncodedResult(options?: RPCUnaryTakeOptions): Promise<V4OperationResultReadResult> { return this.#exchange.takeEncodedResult(options) as Promise<V4OperationResultReadResult>; }
  close(): void { this.#exchange.close(); }
  cleanupStatus(): V4CleanupStatus { return this.#exchange.cleanupStatus(); }
  toJSON(): object { return {}; }
}
export function operationResultRead(exchange: RPCUnaryExchange): V4OperationResultRead { return new V4OperationResultRead(capability, exchange); }
Object.freeze(V4OperationResultRead.prototype); Object.freeze(V4OperationResultRead);
