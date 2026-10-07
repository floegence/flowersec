import type { OperationOptions } from "../public/contract.js";
import type { BrowserNativeStreamPosition } from "./webTransportPositionsV4.js";
import type { V4NativeApplicationStream } from "../v4/runtime/session.js";
import { NativeDirectionFailure } from "../v4/runtime/nativeFailure.js";
import { transportV4CarrierProviderRegistry } from "../generated/transportV4Registry.js";

interface NativeStreamError extends Error { readonly source: "stream" | "session"; readonly streamErrorCode: number | null }
type NativeErrorConstructor = new (options: { source: "stream"; streamErrorCode: number }) => NativeStreamError;
const NativeWebTransportError = (globalThis as unknown as { WebTransportError?: NativeErrorConstructor }).WebTransportError;
const normalDrainedCode = transportV4CarrierProviderRegistry.normal_drained.webtransport_application_code;
export function browserStreamSignalsAvailable(): boolean { return typeof NativeWebTransportError === "function"; }
function nativeFailure(error: unknown): Error {
  if (error instanceof NativeDirectionFailure) return error;
  if (NativeWebTransportError !== undefined && error instanceof NativeWebTransportError && error.source === "stream") {
    return new NativeDirectionFailure(error.streamErrorCode === normalDrainedCode ? "normal_drained" : "direction_reset");
  }
  return new Error("carrier_failed");
}

export interface BrowserNativeBidi {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
}

/** Cancellation ends the observer, never the actual native task. A late
 * handle is disposed by its original creator, using the original reservation. */
class NativeObservation<T> {
  #observer: { resolve(value: T): void; reject(error: unknown): void; signal: AbortSignal | undefined } | undefined;
  #discard: ((value: T) => void) | undefined;
  constructor(resolve: (value: T) => void, reject: (error: unknown) => void, signal: AbortSignal | undefined, discard: ((value: T) => void) | undefined) {
    this.#observer = { resolve, reject, signal }; this.#discard = discard;
    signal?.addEventListener("abort", this.abort, { once: true });
  }
  #take() {
    const observer = this.#observer; this.#observer = undefined;
    observer?.signal?.removeEventListener("abort", this.abort); return observer;
  }
  readonly abort = (): void => { this.#take()?.reject(new Error("canceled")); };
  succeed(value: T): void {
    if (this.#observer?.signal?.aborted) this.abort();
    const observer = this.#take(), discard = this.#discard; this.#discard = undefined;
    if (observer === undefined) discard?.(value); else observer.resolve(value);
  }
  fail(error: unknown): void {
    this.#discard = undefined; const observer = this.#take();
    if (observer !== undefined) observer.reject(nativeFailure(error));
  }
}
export function observeNative<T>(actual: Promise<T>, signal?: AbortSignal, discard?: (value: T) => void): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const observation = new NativeObservation(resolve, reject, signal, discard);
    attachNativeObservation(actual, observation);
    if (signal?.aborted) observation.abort();
  });
}
function attachNativeObservation<T>(actual: Promise<T>, observation: NativeObservation<T>): void {
  // After cancellation only the original late-result disposal duty remains;
  // the native Promise no longer retains the canceled workflow's resolvers.
  void actual.then(value => observation.succeed(value), error => observation.fail(error)).catch(() => undefined);
}

/** A position admitted BEFORE create/accept. It keeps a failed or canceled
 * create, BYOB input, and both actual direction tails until their real exit.
 * Native stream identity is this object, never a guessed QUIC stream number.
 * Returned bytes are borrowed until the next read/close on this position. */
export class BrowserWebTransportStream implements V4NativeApplicationStream {
  readonly role = "client" as const;
  readonly mode = "stream" as const;
  readonly #done: Promise<void>;
  #resolve!: () => void;
  #raw: BrowserNativeBidi | undefined;
  #position: BrowserNativeStreamPosition | undefined;
  #reader: ReadableStreamBYOBReader | undefined;
  #writer: WritableStreamDefaultWriter<Uint8Array> | undefined;
  #input: Uint8Array<ArrayBuffer>;
  #creating = true;
  #closed = false;
  #released = false;
  #reading = false;
  #borrowed = false;
  #writing = false;
  #readSealed = false;
  #writeSealed = false;
  #readEnded = false;
  #writeEnded = false;
  #readerClosedObserved = true;
  #writerClosedObserved = true;
  #readFailure: Error | undefined;
  #writeFailure: NativeDirectionFailure | undefined;
  #writeObserver: ((failure: NativeDirectionFailure) => void) | undefined;
  #tails = 0;
  #cancel: Promise<void> | undefined;
  #abort: Promise<void> | undefined;
  #fin: Promise<void> | undefined;
  #checking: (() => void) | undefined;
  #releasedCallback: (() => void) | undefined;
  readonly #inputCapacity: number;
  constructor(position: BrowserNativeStreamPosition, readonly origin: "maintenance" | "local" | "peer",
    private readonly maximum: number, check: () => void, released: () => void) {
    this.#position = position;
    this.#inputCapacity = Math.min(16384, maximum); this.#input = new Uint8Array(this.#inputCapacity);
    this.#done = new Promise(resolve => { this.#resolve = resolve; });
    this.#checking = check; this.#releasedCallback = released;
  }
  attach(raw: BrowserNativeBidi): void {
    if (!this.#creating) throw new Error("invalid_resource_owner");
    this.#raw = raw; this.#creating = false;
    try {
      this.#reader = raw.readable.getReader({ mode: "byob" });
      this.#readerClosedObserved = false;
      void this.#reader.closed.then(() => { this.#readerClosedObserved = true; this.#readEnded = true; this.#finish(); }, error => {
        this.#readerClosedObserved = true; this.#readFailure = nativeFailure(error); this.#readEnded = true; this.#finish();
      });
      this.#writer = raw.writable.getWriter(); this.#writerClosedObserved = false;
      // closed may settle before cancel/abort or a currently entered write;
      // those original tasks have their own outstanding counters below.
      void this.#writer.closed.then(() => { this.#writerClosedObserved = true; this.#writeEnded = true; this.#finish(); }, error => {
        this.#writerClosedObserved = true;
        this.#writeEnded = true; this.#writeSealed = true;
        const failure = nativeFailure(error);
        if (failure instanceof NativeDirectionFailure) { this.#writeFailure = failure; this.#writeObserver?.(failure); }
        this.#finish();
      });
    } catch (error) {
      // Any acquired half already has exactly one actual closed observation.
      void this.close(); throw error;
    }
    if (this.#closed) void this.close();
  }
  creationFailed(): void {
    if (!this.#creating) return;
    this.#creating = false; this.#readEnded = this.#writeEnded = true;
    void this.close();
  }
  observeWriteFailure(changed: (failure: NativeDirectionFailure) => void): () => void {
    if (this.#writeObserver !== undefined) throw new Error("busy");
    this.#writeObserver = changed;
    if (this.#writeFailure !== undefined) queueMicrotask(() => { if (this.#writeObserver === changed) changed(this.#writeFailure!); });
    return () => { if (this.#writeObserver === changed) this.#writeObserver = undefined; };
  }
  #check(): void {
    if (this.#closed || this.#creating || this.#released) throw new Error("carrier_closed");
    this.#position!.check(); this.#checking!();
  }
  async read(maxBytes: number, options?: OperationOptions): Promise<Uint8Array | null> {
    this.#check();
    if (options?.signal?.aborted) throw new Error("canceled");
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > this.maximum) throw new Error("configuration_capacity");
    if (this.#reading) throw new Error("busy");
    this.#borrowed = false;
    if (this.#readFailure !== undefined) throw this.#readFailure;
    if (this.#readSealed) throw new Error("read_closed");
    if (this.#readEnded) { this.#finish(); return null; }
    this.#reading = true;
    const cancel = (): void => { void this.stopSending().catch(() => undefined); };
    options?.signal?.addEventListener("abort", cancel, { once: true });
    const actual = (async () => {
      try {
        // BYOB bounds each native read before allocation and returns ownership
        // of the same full backing even when only a short view was requested.
        const result = await this.#reader!.read(this.#input.subarray(0, maxBytes)).catch(error => { throw nativeFailure(error); });
        if (result.value !== undefined) {
          const view = result.value;
          if (!(view.buffer instanceof ArrayBuffer) || view.buffer.byteLength !== this.#inputCapacity || view.byteLength > Math.min(maxBytes, this.#inputCapacity)) {
            void this.close(); throw new Error("carrier_contract_invalid");
          }
          this.#input = new Uint8Array(view.buffer);
          if (this.#closed || this.#readSealed || options?.signal?.aborted) { this.#input.fill(0); throw new Error("canceled"); }
          if (view.byteLength !== 0) { this.#borrowed = true; return view; }
        }
        if (!result.done) throw new Error("carrier_contract_invalid");
        this.#readEnded = true; return null;
      } finally { this.#reading = false; options?.signal?.removeEventListener("abort", cancel); this.#finish(); }
    })();
    if (options?.signal?.aborted) cancel();
    return await observeNative(actual, options?.signal, value => {
      // Cancellation can win after the actual read settled but before its
      // observer publishes. Do not leave an undisclosed borrowed input alive.
      if (value !== null) { this.#borrowed = false; this.#input.fill(0); }
      void this.stopSending().catch(() => undefined); this.#finish();
    });
  }
  submit(data: Uint8Array, admitted: () => void, beforeSubmit?: () => void): { completion: Promise<void> } | undefined {
    if (this.#writeFailure !== undefined) throw this.#writeFailure;
    try { this.#check(); } catch { return undefined; }
    if (this.#writeSealed || this.#writeEnded || this.#writing || data.byteLength < 1 || data.byteLength > this.maximum) return undefined;
    this.#writing = true;
    let tail: Promise<void>;
    try {
      // This callback is synchronous. A second outstanding write is forbidden;
      // native backpressure retains this exact buffer and position until exit.
      this.#check(); beforeSubmit?.(); tail = this.#writer!.write(data);
    } catch (error) { this.#writing = false; this.#finish(); throw error; }
    try { admitted(); } catch { void this.close(); }
    const completion = tail.then(() => { this.#writing = false; this.#finish(); }, error => {
      this.#writing = false; this.#finish(); throw nativeFailure(error);
    });
    void completion.catch(() => undefined);
    return { completion };
  }
  async write(data: Uint8Array, options?: OperationOptions): Promise<number> {
    if (options?.signal?.aborted) throw new Error("canceled");
    const length = data.byteLength, submission = this.submit(data, () => undefined);
    if (submission === undefined) throw new Error("carrier_closed");
    const abort = (): void => { void this.resetWrite().catch(() => undefined); };
    options?.signal?.addEventListener("abort", abort, { once: true });
    if (options?.signal?.aborted) abort();
    try { await submission.completion; return length; }
    finally { options?.signal?.removeEventListener("abort", abort); }
  }
  #tail(call: () => Promise<void>, ended: () => void): Promise<void> {
    this.#tails++;
    let actual: Promise<void>;
    try { actual = call(); } catch { actual = Promise.reject(new Error("carrier_failed")); }
    const completion = actual.then(() => { ended(); }, error => { throw nativeFailure(error); })
      .finally(() => { this.#tails--; this.#finish(); });
    void completion.catch(() => undefined); return completion;
  }
  closeWrite(): Promise<void> {
    if (this.#fin !== undefined) return this.#fin;
    if (this.#writeEnded) return Promise.resolve();
    this.#check();
    if (this.#writing || this.#writeSealed) throw new Error("busy");
    this.#writeSealed = true;
    return this.#fin = this.#tail(() => this.#writer!.close(), () => { this.#writeEnded = true; });
  }
  stopSending(reason?: "normal_drained"): Promise<void> {
    this.#readSealed = true;
    if (this.#cancel !== undefined) return this.#cancel;
    if (this.#creating || this.#raw === undefined || this.#readEnded) return Promise.resolve();
    const signal = reason === "normal_drained" ? new NativeWebTransportError!({ source: "stream", streamErrorCode: normalDrainedCode }) : undefined;
    return this.#cancel = this.#tail(() => this.#reader !== undefined ? this.#reader.cancel(signal) : this.#raw!.readable.cancel(signal), () => { this.#readEnded = true; });
  }
  resetWrite(): Promise<void> {
    this.#writeSealed = true;
    if (this.#abort !== undefined) return this.#abort;
    if (this.#creating || this.#raw === undefined || this.#writeEnded) return Promise.resolve();
    // An admitted FIN retains its original queued publication, even on cleanup.
    if (this.#fin !== undefined) return this.#fin;
    return this.#abort = this.#tail(() => this.#writer !== undefined ? this.#writer.abort() : this.#raw!.writable.abort(), () => { this.#writeEnded = true; });
  }
  close(): Promise<void> {
    this.#closed = true; this.#borrowed = false;
    void this.stopSending(); void this.resetWrite(); this.#finish(); return this.#done;
  }
  waitTermination(): Promise<void> { return this.#done; }
  cleanupComplete(): boolean { return this.#released; }
  #finish(): void {
    if (this.#released || this.#creating || this.#reading || this.#borrowed || this.#writing || this.#tails !== 0 || !this.#readEnded || !this.#writeEnded ||
        !this.#readerClosedObserved || !this.#writerClosedObserved) return;
    this.#released = true; this.#closed = true;
    // No entered read/write/control operation still borrows either handle.
    this.#reader?.releaseLock(); this.#writer?.releaseLock();
    if (this.#input.byteLength !== 0) this.#input.fill(0);
    this.#input = new Uint8Array(0); this.#reader = this.#writer = this.#raw = undefined;
    this.#checking = undefined; this.#writeObserver = undefined;
    const callback = this.#releasedCallback; this.#releasedCallback = undefined;
    const position = this.#position; this.#position = undefined;
    position?.release(); callback?.(); this.#resolve();
  }
}
