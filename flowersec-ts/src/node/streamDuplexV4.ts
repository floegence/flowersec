import { Duplex } from "node:stream";
import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus, V4CloseResult, V4WriteProgress } from "../generated/transportV4APIResults.js";
import type { V4StreamOwner } from "../v4/public.js";
import { acquireStreamAdapter } from "../v4/runtime/streamAdapter.js";
import { byteLength, byteSlice } from "../v4/runtime/cbor.js";

/** A deployment declaration for cooperative native producers, not a Node queue hard limit. */
export interface V4NodeProducerProfile {
  readonly maxChunkBytes: number;
  readonly maxBackingBytes: number;
  readonly maxPendingWrites: number;
  readonly maxQueuedBackingBytes: number;
}
export interface V4NodeDuplexOptions {
  readonly producer: V4NodeProducerProfile;
  readonly highWaterMark?: number;
  readonly gracefulFinishTimeoutMS?: number;
  readonly cleanupTimeoutMS?: number;
  readonly signal?: AbortSignal;
}
export type V4NodeDuplexFailure = "aborted" | "read_failed" | "write_failed" | "finish_failed" | "producer_profile" | "cleanup_incomplete";
/** Bounded SDK error; a partial write always retains its stable accepted prefix. */
export class V4NodeDuplexError extends Error {
  constructor(readonly code: V4NodeDuplexFailure, readonly progress?: V4WriteProgress) {
    super(code); this.name = "V4NodeDuplexError";
  }
}
export interface V4NodeDuplex extends Duplex {
  closeResult(): V4CloseResult | undefined;
  cleanupStatus(): V4CleanupStatus;
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus>;
}

const typed = Object.getPrototypeOf(Uint8Array.prototype) as object;
const getBuffer = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
const getBackingLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength")!.get!;
const getResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get;
const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const pending: V4CleanupStatus = Object.freeze({ status: "pending", core_cleanup: "pending", pending_callbacks: 0n });
const incomplete: V4CleanupStatus = Object.freeze({ status: "cleanup_incomplete", core_cleanup: "pending", pending_callbacks: 0n });
const originalDestroy = Duplex.prototype.destroy;
const originalPush = Duplex.prototype.push;
const originalPause = Duplex.prototype.pause;
const scheduleCheckpoint = setImmediate;
const flowersecDuplexes = new WeakSet<object>();
export function isFlowersecNodeDuplex(value: object): boolean { return flowersecDuplexes.has(value); }

function positive(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0x7fffffff) throw new Error("configuration_capacity");
  return value;
}

/** Owns both application directions of one accepted v4 Stream. */
export function asNodeDuplex(stream: V4StreamOwner, options: V4NodeDuplexOptions): V4NodeDuplex {
  const producer = Object.freeze({
    maxChunkBytes: positive(options.producer.maxChunkBytes), maxBackingBytes: positive(options.producer.maxBackingBytes),
    maxPendingWrites: positive(options.producer.maxPendingWrites), maxQueuedBackingBytes: positive(options.producer.maxQueuedBackingBytes),
  });
  if (producer.maxChunkBytes > producer.maxBackingBytes || producer.maxBackingBytes > producer.maxQueuedBackingBytes) throw new Error("configuration_capacity");
  const highWaterMark = positive(options.highWaterMark ?? 65536);
  const gracefulFinishMS = positive(options.gracefulFinishTimeoutMS ?? 30000), cleanupMS = positive(options.cleanupTimeoutMS ?? 5000);
  const signal = options.signal;
  if (signal?.aborted) throw new V4NodeDuplexError("aborted");
  const owner = acquireStreamAdapter(stream, {
    readBytes: highWaterMark, inputBackingBytes: positive(producer.maxQueuedBackingBytes + producer.maxBackingBytes),
    inputEntries: positive(producer.maxPendingWrites + 1), gracefulFinishMS, cleanupMS,
  });
  // Read admission, FIN and Reset stay with the original Stream. This owner
  // accounts only for native buffers, callbacks and their actual exit tails.
  const operations = new AbortController();
  let intent: "normal_auto_destroy" | "abort" | undefined;
  let firstError: V4NodeDuplexError | undefined;
  let result: V4CloseResult | undefined;
  let reading = false, readEOF = false, sendDrained = false, tasks = 0;
  let destroyStarted = false, nativeExited = false, released = false, cleanupExpired = false;
  let checkpoint: ReturnType<typeof setImmediate> | undefined;
  let cleanupTimer: ReturnType<typeof setTimeout> | undefined;
  let resetTail: Promise<void> | undefined;
  let destroyCallback: ((error?: Error | null) => void) | undefined;
  let cleanupResolve!: (status: V4CleanupStatus) => void;
  const cleanup = new Promise<V4CleanupStatus>(resolve => { cleanupResolve = resolve; });
  let cleanupWaiter: { finish(value: V4CleanupStatus): void } | undefined;
  let duplex!: V4NodeDuplex;

  function status(): V4CleanupStatus {
    if (released) return complete;
    return Object.freeze({ ...(cleanupExpired ? incomplete : pending), pending_callbacks: BigInt(tasks) });
  }
  function record(code: V4NodeDuplexFailure, progress?: V4WriteProgress): V4NodeDuplexError {
    firstError ??= new V4NodeDuplexError(code, progress);
    if (progress !== undefined && firstError.progress === undefined) firstError = new V4NodeDuplexError(firstError.code, progress);
    return firstError;
  }
  function settleCleanup(value: V4CleanupStatus): void { cleanupResolve(value); cleanupWaiter?.finish(value); }
  function checkpointCleanup(): void {
    if (checkpoint !== undefined || released || !destroyStarted) return;
    checkpoint = scheduleCheckpoint(() => {
      checkpoint = undefined;
      // The Node destroy callback's reactions have run. Public queue lengths
      // are used only for the private reader and the declared producer profile.
      if (tasks !== 0 || resetTail !== undefined) return;
      if (!nativeExited) {
        if (owner.cleanupStatus().status !== "complete") return;
        completeDestroy(); return;
      }
      if (duplex.readableLength !== 0 || duplex.writableLength !== 0) return;
      released = true; owner.release();
      signal?.removeEventListener("abort", abort);
      duplex.removeListener("end", normalEnd); duplex.removeListener("finish", normalEnd);
      duplex.removeListener("data", queueDrained);
      if (cleanupTimer !== undefined) clearTimeout(cleanupTimer); cleanupTimer = undefined;
      settleCleanup(complete);
    });
  }
  function completeDestroy(): void {
    const callback = destroyCallback;
    if (callback === undefined) return;
    destroyCallback = undefined;
    // This callback permits Node to settle queued native writes. Keep the
    // reservation through its return and the subsequent native reactions.
    try { callback(firstError); }
    finally { nativeExited = true; checkpointCleanup(); }
  }
  function beginAbort(code: V4NodeDuplexFailure, progress?: V4WriteProgress): V4NodeDuplexError {
    const error = record(code, progress);
    if (intent === undefined) intent = "abort";
    if (intent === "abort") operations.abort();
    return error;
  }
  function fail(code: V4NodeDuplexFailure, progress?: V4WriteProgress): void {
    const error = beginAbort(code, progress);
    if (!destroyStarted) originalDestroy.call(duplex, error);
  }
  function abort(): void { fail("aborted"); }
  function queueDrained(): void { checkpointCleanup(); }
  function normalEnd(): void {
    if (intent !== undefined || firstError !== undefined || !sendDrained || !duplex.readableEnded || !duplex.writableFinished || duplex.destroyed) return;
    // No host call, await or next job may intervene between selecting this
    // intent and invoking the captured native destroy implementation.
    intent = "normal_auto_destroy";
    originalDestroy.call(duplex);
  }
  function partial(requested: bigint, accepted: bigint, progress?: V4WriteProgress): V4WriteProgress {
    return Object.freeze({ requested_bytes: requested, accepted_bytes: accepted, phase: "terminal",
      terminal_reason: progress?.terminal_reason === "complete" ? "failed" : progress?.terminal_reason ?? "failed",
      cleanup_status: progress?.cleanup_status ?? owner.cleanupStatus() });
  }
  function checkInput(bytes: Uint8Array): number {
    const count = byteLength(bytes), backing: unknown = getBuffer.call(bytes);
    const backingLength = getBackingLength.call(backing) as number;
    if (getResizable?.call(backing) || count > producer.maxChunkBytes || backingLength > producer.maxBackingBytes) throw new Error("producer_profile");
    return count;
  }

  try {
    duplex = new Duplex({
      allowHalfOpen: true, autoDestroy: false, readableHighWaterMark: highWaterMark, writableHighWaterMark: highWaterMark,
      read() {
        if (reading || readEOF || intent !== undefined) return;
        reading = true; tasks++;
        void (async () => {
          try {
            while (intent === undefined) {
              const read = await owner.read({ signal: operations.signal });
              if (intent !== undefined) return;
              owner.check();
              const bytes = read.data, count = byteLength(bytes);
              // The result owns compact initialized backing. Handoff runs once
              // in this job; no SDK code touches its bytes after push begins.
              const keepReading = count === 0 || originalPush.call(duplex, bytes);
              if (intent !== undefined) return;
              if (read.stream_status === "eof") { readEOF = true; originalPush.call(duplex, null); return; }
              if (read.stream_status !== "open" || read.wait_status === "wait_canceled") { fail("read_failed"); return; }
              if (!keepReading) return;
              if (count === 0) throw new Error("read_failed");
            }
          } catch { if (intent === undefined) fail("read_failed"); }
          finally { reading = false; tasks--; checkpointCleanup(); }
        })();
      },
      write(chunk: Buffer, _encoding, callback) {
        tasks++;
        void (async () => {
          let error: V4NodeDuplexError | undefined, requested = 0n, accepted = 0n;
          let latest: V4WriteProgress | undefined;
          try {
            try { requested = BigInt(checkInput(chunk)); }
            catch { error = beginAbort("producer_profile"); throw error; }
            while (accepted < requested) {
              if (intent !== undefined) throw new Error("aborted");
              owner.check();
              latest = await owner.write(byteSlice(chunk, Number(accepted), Number(requested)), { signal: operations.signal });
              const n = latest.accepted_bytes;
              if (n < 0n || n > requested - accepted) throw new Error("write_failed");
              accepted += n;
              if (intent !== undefined || n === 0n || latest.terminal_reason !== "complete") throw new Error("write_failed");
            }
            if (intent !== undefined) throw new Error("aborted");
          } catch { error ??= beginAbort("write_failed", partial(requested, accepted, latest)); }
          // Callback reentrancy still belongs to this charged task. With
          // autoDestroy disabled every failure explicitly takes Reset ownership.
          try { callback(error); }
          finally { tasks--; if (error !== undefined && !destroyStarted) originalDestroy.call(duplex, error); checkpointCleanup(); }
        })();
      },
      final(callback) {
        tasks++;
        void (async () => {
          let error: V4NodeDuplexError | undefined;
          try {
            await owner.closeWrite({ signal: operations.signal });
            const finished = await owner.finish({ signal: operations.signal });
            if (intent !== undefined || !finished.send_drained) throw new Error("finish_failed");
            result = finished; sendDrained = true;
          } catch { error = beginAbort("finish_failed"); }
          try { callback(error); }
          finally { tasks--; if (error !== undefined && !destroyStarted) originalDestroy.call(duplex, error); checkpointCleanup(); }
        })();
      },
      destroy(error, callback) {
        destroyStarted = true; destroyCallback = callback;
        signal?.removeEventListener("abort", abort);
        // Only our own normalEnd can select normal_auto_destroy. A caller's
        // destroy(null), including an end listener, is an explicit abort.
        if (intent !== "normal_auto_destroy") {
          beginAbort(error === null ? "aborted" : firstError?.code ?? "aborted");
          resetTail = owner.reset().then(value => { result = value; }, () => undefined).finally(() => {
            resetTail = undefined; checkpointCleanup();
          });
        }
        cleanupTimer = setTimeout(() => {
          cleanupTimer = undefined; cleanupExpired = true;
          if (firstError === undefined && intent !== "normal_auto_destroy") record("cleanup_incomplete");
          completeDestroy(); settleCleanup(status());
        }, cleanupMS);
        checkpointCleanup();
      },
    }) as V4NodeDuplex;
    Object.defineProperties(duplex, {
      closeResult: { value: (): V4CloseResult | undefined => result === undefined ? undefined : Object.freeze({
        ...result, read_terminal: readEOF ? "eof" : result.read_terminal, cleanup_status: status(),
      }) },
      cleanupStatus: { value: status },
      waitCleanup: { value: (wait?: OperationOptions): Promise<V4CleanupStatus> => {
        if (released || cleanupExpired) return Promise.resolve(status());
        if (wait?.signal === undefined) return cleanup;
        if (wait.signal.aborted) return Promise.reject(new V4NodeDuplexError("aborted"));
        if (cleanupWaiter !== undefined) return Promise.reject(new Error("wait_in_progress"));
        return new Promise((resolve, reject) => {
          const canceled = (): void => {
            cleanupWaiter = undefined; wait.signal!.removeEventListener("abort", canceled);
            reject(new V4NodeDuplexError("aborted"));
          };
          cleanupWaiter = { finish(value) {
            cleanupWaiter = undefined; wait.signal!.removeEventListener("abort", canceled); resolve(value);
          } };
          wait.signal!.addEventListener("abort", canceled, { once: true });
        });
      } },
    });
    duplex.on("end", normalEnd); duplex.on("finish", normalEnd);
    // This listener is installed only after destroy; installing it here would
    // switch Node into flowing mode and consume before the caller attaches.
    duplex.once("close", () => {
      if (!released && duplex.readableLength !== 0) {
        // Destroy does not prove Node dropped unread chunks. Preserve their
        // original allowance until the caller actually consumes that queue.
        originalPause.call(duplex); duplex.on("data", queueDrained);
      }
      checkpointCleanup();
    });
    owner.cleanupWith(checkpointCleanup);
    owner.invalidateWith(() => {
      if (intent !== undefined) return;
      beginAbort("aborted"); queueMicrotask(() => { if (!destroyStarted) originalDestroy.call(duplex, firstError); });
    });
    owner.check();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    flowersecDuplexes.add(duplex);
    return duplex;
  } catch (error) {
    owner.rollback(); throw error;
  }
}
