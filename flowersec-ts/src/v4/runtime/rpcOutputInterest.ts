import type * as ContractTypes from "../../public/contract.js";
import type { V4ApplicationContext } from "../streamHandlers.js";
import type { V4OutputInterest, V4OutputInterestProgress, V4OutputInterestReason } from "../serviceHandlers.js";
import { applicationHasPermit } from "./applicationExecutor.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { ResourceVector, type ResourceReference } from "./resources.js";

export function rpcOutputInterestCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([2048n + runtimeBytes, 0n, 0n, 4n, 0n, 1n, 0n, 0n, 0n, 0n, 0n]);
}

interface Waiter {
  readonly resolve: (progress: V4OutputInterestProgress) => void;
  readonly reject: (error: unknown) => void;
  readonly signal: AbortSignal | undefined;
  readonly cancel: () => void;
}
/** Prepaid by the accepted result owner. Scalar loss is separate from host
 * wakeups; this cell never follows a reused slot and holds no Session graph. */
export class RPCOutputInterest {
  #reason: V4OutputInterestReason | undefined;
  #context: V4ApplicationContext | undefined;
  #waiter: Waiter | undefined;
  #notify: (() => void) | undefined;
  #pending = false;
  #detached = false;
  #ended = false;
  #reference: ResourceReference | undefined;
  readonly view: V4OutputInterest;
  constructor(runtimeBytes: bigint, reference: ResourceReference) {
    this.#reference = reference.take(rpcOutputInterestCharge(runtimeBytes));
    const state = this;
    this.view = Object.freeze({ get interested() { return state.#reason === undefined; },
      progress: () => state.progress(), waitLost: (options?: ContractTypes.OperationOptions) => state.#wait(options?.signal) });
  }
  progress(): V4OutputInterestProgress {
    const value = { interested: this.#reason === undefined, ...(this.#reason === undefined ? {} : { reason: this.#reason }) };
    Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
  }
  sameEnvironment(reference: ResourceReference): boolean { return this.#reference !== undefined && this.#reference.sameEnvironment(reference); }
  lose(reason: V4OutputInterestReason, detached = false): void {
    this.#reason ??= reason; this.#detached ||= detached; this.#pending = true;
  }
  attach(context: V4ApplicationContext): void {
    if (this.#ended || this.#context !== undefined || !applicationHasPermit(context)) throw new RPCProtocolError("rpc_output_owner");
    this.#context = context; context.signal.addEventListener("abort", this.#contextAborted, { once: true });
  }
  readonly #contextAborted = (): void => { this.#take()?.reject(new RPCProtocolError("owner_unavailable")); };
  observe(callback: () => void): void {
    if (this.#notify !== undefined) throw new RPCProtocolError("rpc_output_owner"); this.#notify = callback;
  }
  unobserve(): void { this.#notify = undefined; }
  /** Called after the network/publication gate, never inside its mutation. */
  flush(): void {
    if (!this.#pending) return; this.#pending = false;
    this.#notify?.(); const waiter = this.#take(); waiter?.resolve(this.progress()); this.#collect();
  }
  endInvocation(): void {
    this.#ended = true; this.#context?.signal.removeEventListener("abort", this.#contextAborted); this.#context = undefined;
    this.#take()?.reject(new RPCProtocolError("owner_unavailable")); this.#collect();
  }
  #collect(): void {
    if (!this.#detached || !this.#ended || this.#pending) return;
    this.#notify = undefined; this.#reference?.release(); this.#reference = undefined;
  }
  #take(): Waiter | undefined {
    const waiter = this.#waiter; this.#waiter = undefined; waiter?.signal?.removeEventListener("abort", waiter.cancel); return waiter;
  }
  #wait(signal: AbortSignal | undefined): Promise<V4OutputInterestProgress> {
    try {
      if (this.#context === undefined || !applicationHasPermit(this.#context)) throw new RPCProtocolError("owner_unavailable");
      if (signal?.aborted) throw new RPCProtocolError("wait_canceled");
      if (this.#waiter !== undefined) throw new RPCProtocolError("rpc_wait_in_progress");
      if (this.#reason !== undefined) return Promise.resolve(this.progress());
      return new Promise((resolve, reject) => {
        const waiter: Waiter = { resolve, reject, signal, cancel: () => {
          if (this.#waiter === waiter) this.#take()?.reject(new RPCProtocolError("wait_canceled"));
        } };
        this.#waiter = waiter; signal?.addEventListener("abort", waiter.cancel, { once: true }); if (signal?.aborted) waiter.cancel();
      });
    } catch (error) { return Promise.reject(error); }
  }
}
Object.freeze(RPCOutputInterest.prototype); Object.freeze(RPCOutputInterest);
