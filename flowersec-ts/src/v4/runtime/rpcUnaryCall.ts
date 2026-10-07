import type { V4ApplicationContext } from "../streamHandlers.js";
import type { RPCUnaryPreparation } from "./rpcUnaryPreparation.js";
import type { RPCUnaryExchange, RPCUnaryTakeResult } from "./rpcUnaryExchange.js";
import { RPCUnaryResultRecipient } from "./rpcUnaryResultRecipient.js";
import { RPCProtocolError } from "./rpcFragment.js";

const promiseThen = Promise.prototype.then;
const callCleanup = new WeakMap<Promise<unknown>, Promise<void>>();
export function rpcUnaryCallCleanup(value: Promise<unknown>): Promise<void> { return callCleanup.get(value) ?? Promise.resolve(); }
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const addListener = EventTarget.prototype.addEventListener, removeListener = EventTarget.prototype.removeEventListener;
function aborted(signal?: AbortSignal): boolean { return signal !== undefined && signalAborted.call(signal) as boolean; }
function listen(signal: AbortSignal | undefined, callback: () => void): void { if (signal !== undefined) addListener.call(signal, "abort", callback, { once: true }); }
function unlisten(signal: AbortSignal | undefined, callback: () => void): void { if (signal !== undefined) removeListener.call(signal, "abort", callback); }

/** The convenience scope owns its one hidden preparation/exchange. Explicit
 * preparations never enter this scope. Closing it cannot close the borrowed
 * Session, create a second request, or request remote execution cancellation. */
export class RPCUnaryCall {
  readonly #recipient: RPCUnaryResultRecipient;
  readonly #abort = new AbortController();
  #preparation: RPCUnaryPreparation | undefined;
  #exchange: RPCUnaryExchange | undefined;
  #context: V4ApplicationContext | undefined;
  #finished: (() => void) | undefined;
  #cleanupResolve!: () => void;
  readonly #cleanupPromise = new Promise<void>(resolve => { this.#cleanupResolve = resolve; });
  #signal: AbortSignal | undefined;
  #preparing = false;
  #entering = false;
  #started = false;
  #closed = false;
  #done = false;
  constructor(context: V4ApplicationContext | undefined, signal: AbortSignal | undefined, finished: () => void) {
    this.#context = context; this.#signal = signal; this.#finished = finished;
    this.#recipient = new RPCUnaryResultRecipient({ signal: this.#abort.signal, ...(context === undefined ? {} : { context }) });
    this.#recipient.onSettled(() => this.#settled());
    callCleanup.set(this.#recipient.promise, this.#cleanupPromise);
    // Validate native signal brands before attaching either retained listener.
    aborted(signal); aborted(context?.signal);
    try { listen(signal, this.#cancel); listen(context?.signal, this.#cancel); }
    catch (error) { unlisten(signal, this.#cancel); unlisten(context?.signal, this.#cancel); throw error; }
    Object.freeze(this);
  }
  get promise(): Promise<RPCUnaryTakeResult> { return this.#recipient.promise; }
  arm(): void { this.#recipient.arm(); }
  begin(prepare: (signal: AbortSignal) => Promise<RPCUnaryPreparation>): void {
    if (this.#started) throw new RPCProtocolError("rpc_request_owner"); this.#started = true;
    if (aborted(this.#signal) || aborted(this.#context?.signal)) this.close();
    if (this.#closed) return;
    this.#preparing = true;
    try {
      const pending = prepare(this.#abort.signal);
      void promiseThen.call(pending, (preparation: RPCUnaryPreparation) => {
        this.#preparing = false; this.#entering = true;
        try {
          this.#preparation = preparation;
          if (this.#closed) { preparation.close(); return; }
          const started = preparation.start(this.#context, this.#abort.signal);
          if (started.status === "not_admitted") throw new RPCProtocolError(started.reason);
          this.#exchange = started.exchange;
          // The recipient may settle as soon as its result handoff commits, but
          // the real unary request/response/call tails still belong to this
          // convenience scope until the exchange releases its final owner.
          started.exchange.onCleanup(() => this.#collect());
          if (this.#closed) { started.exchange.close(); return; }
          started.exchange.receiveResult(this.#recipient);
        } catch (error) { this.fail(error); }
        finally { this.#entering = false; this.#collect(); }
      }, error => { this.#preparing = false; this.fail(error); this.#collect(); });
    } catch (error) { this.#preparing = false; this.fail(error); }
  }
  readonly #cancel = (): void => this.close();
  fail(error: unknown): void {
    if (!this.#recipient.done) { this.#recipient.reject(error); this.#recipient.complete(); }
    else this.#settled();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#abort.abort(); this.#preparation?.close();
    if (this.#exchange === undefined) this.fail(new RPCProtocolError("canceled"));
    // An attached original exchange decides the final metadata/payload race.
    // A committed payload is never replaced by a convenience-scope rejection.
    else this.#exchange.close();
    this.#collect();
  }
  #settled(): void {
    if (this.#done) return; this.#done = true; this.#closed = true;
    this.#abort.abort(); this.#preparation?.close(); this.#exchange?.close();
    unlisten(this.#signal, this.#cancel); this.#signal = undefined;
    unlisten(this.#context?.signal, this.#cancel); this.#context = undefined; this.#collect();
  }
  #collect(): void {
    if (!this.#done || this.#preparing || this.#entering || this.#exchange?.cleanupComplete() === false) return;
    this.#preparation = undefined; this.#exchange = undefined;
    const finished = this.#finished; this.#finished = undefined; finished?.();
    this.#cleanupResolve(); this.#cleanupResolve = () => undefined;
  }
}
Object.freeze(RPCUnaryCall.prototype); Object.freeze(RPCUnaryCall);
