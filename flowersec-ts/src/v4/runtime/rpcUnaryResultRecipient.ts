import type { V4ApplicationContext } from "../streamHandlers.js";
import type { RPCUnaryTakeOptions, RPCUnaryTakeResult } from "./rpcUnaryExchange.js";
import { RPCProtocolError } from "./rpcFragment.js";

const NativePromise = Promise;

/** The final recipient of one original convenience call. Its containing call
 * prepays construction and waiting before any application encoder runs. This
 * is not another result store: only the original exchange can supply payload. */
export class RPCUnaryResultRecipient {
  readonly promise: Promise<RPCUnaryTakeResult>;
  readonly signal: AbortSignal | undefined;
  readonly context: V4ApplicationContext | undefined;
  #resolve: ((result: RPCUnaryTakeResult) => void) | undefined;
  #reject: ((error: unknown) => void) | undefined;
  #settled: (() => void) | undefined;
  #claimed = false;
  #armed = false;
  #used = false;
  constructor(options: RPCUnaryTakeOptions) {
    this.signal = options.signal; this.context = options.context;
    this.promise = new NativePromise((resolve, reject) => { this.#resolve = resolve; this.#reject = reject; });
    Object.freeze(this);
  }
  get armed(): boolean { return this.#armed; }
  get done(): boolean { return this.#used; }
  arm(): void { this.#armed = true; }
  claim(): void {
    if (this.#claimed || this.#used) throw new RPCProtocolError("rpc_result_unavailable"); this.#claimed = true;
  }
  onSettled(callback: () => void): void {
    if (this.#settled !== undefined) throw new RPCProtocolError("rpc_request_owner"); this.#settled = callback;
  }
  resolve(result: RPCUnaryTakeResult): void {
    if (this.#used) return;
    this.#used = true; const resolve = this.#resolve!; this.#resolve = undefined; this.#reject = undefined;
    resolve(result);
  }
  reject(error: unknown): void {
    if (this.#used) return;
    this.#used = true; const reject = this.#reject!; this.#resolve = undefined; this.#reject = undefined;
    reject(error);
  }
  /** Called after the original resolver/rejector actually returns. */
  complete(): void { const settled = this.#settled; this.#settled = undefined; settled?.(); }
}
Object.freeze(RPCUnaryResultRecipient.prototype); Object.freeze(RPCUnaryResultRecipient);
