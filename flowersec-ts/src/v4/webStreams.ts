import type { V4StreamOwner } from "./public.js";
import type { V4WriteProgress } from "../generated/transportV4APIResults.js";
import { byteLength, byteSlice } from "./runtime/cbor.js";
import { acquireStreamAdapter } from "./runtime/streamAdapter.js";

export interface V4WebStreamsOptions {
  readonly readChunkBytes?: number;
  readonly maxWriteChunkBytes?: number;
  readonly maxWriteBackingBytes?: number;
  readonly maxPendingWrites?: number;
  readonly maxQueuedWriteBytes?: number;
  readonly gracefulFinishTimeoutMS?: number;
  readonly cleanupTimeoutMS?: number;
}
export interface V4WebStreams {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
}
export type V4WebStreamFailure = "closed" | "aborted" | "invalid_chunk" | "write_capacity" | "read_failed" | "write_failed" | "finish_failed" | "cleanup_incomplete";
export class V4WebStreamError extends Error {
  constructor(readonly code: V4WebStreamFailure, readonly progress?: V4WriteProgress,
    readonly handoff?: Readonly<{ confirmed_bytes: bigint; unconfirmed_bytes: bigint }>) {
    super(code); this.name = "V4WebStreamError";
  }
}

// These standard primitives are captured once at trusted SDK initialization.
const NativeReadable = ReadableStream, NativeWritable = WritableStream, NativeChannel = MessageChannel;
const enqueue = ReadableStreamDefaultController.prototype.enqueue;
const closeReadable = ReadableStreamDefaultController.prototype.close;
const errorReadable = ReadableStreamDefaultController.prototype.error;
const errorWritable = WritableStreamDefaultController.prototype.error;
const post = MessagePort.prototype.postMessage, closePort = MessagePort.prototype.close;
const typed = Object.getPrototypeOf(Uint8Array.prototype) as object;
const getBuffer = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
const getOffset = Object.getOwnPropertyDescriptor(typed, "byteOffset")!.get!;
const getBackingBytes = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength")!.get!;
const getResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get;
const getDetached = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "detached")?.get;
interface InputEntry { readonly buffer: ArrayBuffer; readonly offset: number; readonly bytes: number; readonly backing: number }
function bound(n: number): number {
  if (!Number.isSafeInteger(n) || n < 1 || n > 0x7fffffff) throw new Error("configuration_capacity");
  return n;
}
function input(chunk: Uint8Array): InputEntry {
  try {
    const bytes = byteLength(chunk), buffer = getBuffer.call(chunk) as ArrayBuffer;
    const backing = getBackingBytes.call(buffer) as number, offset = getOffset.call(chunk) as number;
    if (getResizable?.call(buffer) || getDetached?.call(buffer)) throw new Error("invalid_chunk");
    // Constructing a view rejects detached zero-length input on older hosts.
    byteSlice(chunk, 0, bytes);
    return { buffer, offset, bytes, backing };
  } catch { throw new V4WebStreamError("invalid_chunk"); }
}

/** A native pair over one accepted v4 Stream, with independent directional termination. */
export function asWebStreams(stream: V4StreamOwner, options: V4WebStreamsOptions = {}): V4WebStreams {
  const readBytes = bound(options.readChunkBytes ?? 65536), maxChunk = bound(options.maxWriteChunkBytes ?? 262144);
  const maxBacking = bound(options.maxWriteBackingBytes ?? 262144), maxEntries = bound(options.maxPendingWrites ?? 4);
  const maxQueued = bound(options.maxQueuedWriteBytes ?? 1048576);
  const gracefulFinishMS = bound(options.gracefulFinishTimeoutMS ?? 30000), cleanupMS = bound(options.cleanupTimeoutMS ?? 5000);
  if (maxChunk > maxBacking || maxBacking > maxQueued || maxEntries > 65536) throw new Error("configuration_capacity");
  const owner = acquireStreamAdapter(stream, {
    readBytes, inputBackingBytes: bound(maxQueued + maxBacking), inputEntries: bound(maxEntries + 1),
    gracefulFinishMS, cleanupMS, kind: "web",
  });
  const readAbort = new AbortController(), writeAbort = new AbortController();
  const entries: InputEntry[] = [];
  let queuedBytes = 0, current: InputEntry | undefined, settledTail: InputEntry | undefined;
  let readableController!: ReadableStreamDefaultController<Uint8Array>, writableController!: WritableStreamDefaultController;
  let channel: MessageChannel | undefined;
  let installed = false, constructing = true, invalidated = false, released = false;
  let readDone = false, writeDone = false, readBusy = false, writeBusy = false, readHostActive = false;
  let readFailure: V4WebStreamError | undefined, writeFailure: V4WebStreamError | undefined;
  let readerErrorSent = false, writerErrorSent = false, scheduled = false, checkpointPending = false;
  let confirmed = 0n, unconfirmed = 0n;
  let readClosing: Promise<void> | undefined, writeClosing: Promise<void> | undefined;
  let readTail = false, writeTail = false;

  function cleanup(): void {
    if (released || !installed || !readDone || !writeDone || readBusy || writeBusy || readHostActive || readTail || writeTail || scheduled ||
        current !== undefined || entries.length !== 0 || settledTail !== undefined || checkpointPending || owner.cleanupStatus().status !== "complete") return;
    released = true;
    writableController.signal.removeEventListener("abort", writerCanceled);
    if (channel !== undefined) { closePort.call(channel.port1); closePort.call(channel.port2); channel = undefined; }
    owner.release();
  }
  function checkpoint(): void {
    if (checkpointPending || channel === undefined || released) return;
    checkpointPending = true; post.call(channel.port2, 0);
  }
  function afterCheckpoint(): void {
    checkpointPending = false;
    // A MessagePort task follows this agent's native Promise reactions. It is
    // a dequeue barrier for already-settled sink work, not a guessed delay.
    settledTail = undefined;
    if (writeFailure !== undefined && !writeBusy && writerErrorSent) { entries.length = 0; queuedBytes = 0; writeDone = true; }
    cleanup();
  }
  function schedule(): void {
    if (scheduled || released || constructing) return;
    scheduled = true;
    queueMicrotask(() => { scheduled = false; flush(); });
  }
  function flush(): void {
    if (!installed || released) return;
    if (readFailure !== undefined && !readHostActive && !readerErrorSent) {
      readerErrorSent = true; readHostActive = true;
      try { errorReadable.call(readableController, readFailure); }
      finally { readHostActive = false; readDone = true; }
    }
    if (writeFailure !== undefined && !writerErrorSent) {
      writerErrorSent = true; errorWritable.call(writableController, writeFailure); checkpoint();
    }
    cleanup();
  }
  function terminate(send: boolean): Promise<void> {
    const existing = send ? writeClosing : readClosing;
    if (existing !== undefined) return existing;
    if (send) writeTail = true; else readTail = true;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    // Exactly one finite wait per direction. The real protocol tail stays
    // charged and continues after this public cleanup wait times out.
    const operation = send ? owner.abortWrite() : owner.abortRead();
    const waiting = new Promise<void>((resolve, reject) => {
      timeout = setTimeout(() => { timeout = undefined; reject(new V4WebStreamError("cleanup_incomplete")); }, cleanupMS);
      void operation.then(() => resolve(), () => reject(new V4WebStreamError("cleanup_incomplete"))).finally(() => {
        if (timeout !== undefined) clearTimeout(timeout); timeout = undefined;
        if (send) writeTail = false; else readTail = false;
        cleanup();
      });
    });
    if (send) writeClosing = waiting; else readClosing = waiting;
    void waiting.catch(() => undefined);
    return waiting;
  }
  function failRead(code: V4WebStreamFailure): void {
    readFailure ??= new V4WebStreamError(code, undefined, Object.freeze({ confirmed_bytes: confirmed, unconfirmed_bytes: unconfirmed }));
    readAbort.abort();
    if (!constructing) void terminate(false).catch(() => undefined);
    schedule();
  }
  function failWrite(code: V4WebStreamFailure, progress?: V4WriteProgress): V4WebStreamError {
    writeFailure ??= new V4WebStreamError(code, progress);
    if (progress !== undefined && writeFailure.progress === undefined) writeFailure = new V4WebStreamError(writeFailure.code, progress);
    writeAbort.abort();
    if (!constructing) void terminate(true).catch(() => undefined);
    schedule(); return writeFailure;
  }
  function writerCanceled(): void { failWrite("aborted"); }
  function takeEntry(chunk: Uint8Array): InputEntry {
    // The previous native item must have been removed before the next sink
    // invocation. Keep no unbounded completion list between those points.
    settledTail = undefined;
    const entry = entries.shift(), actual = input(chunk);
    if (entry === undefined || actual.buffer !== entry.buffer || actual.offset !== entry.offset || actual.bytes !== entry.bytes || actual.backing !== entry.backing) {
      throw new V4WebStreamError("invalid_chunk");
    }
    return entry;
  }
  function partial(entry: InputEntry, accepted: bigint, progress?: V4WriteProgress): V4WriteProgress {
    return Object.freeze({ requested_bytes: BigInt(entry.bytes), accepted_bytes: accepted, phase: "terminal",
      terminal_reason: progress?.terminal_reason === "complete" ? "failed" : progress?.terminal_reason ?? "failed",
      cleanup_status: progress?.cleanup_status ?? owner.cleanupStatus() });
  }

  try {
    channel = new NativeChannel(); channel.port1.onmessage = afterCheckpoint;
    owner.invalidateWith(() => {
      invalidated = true;
      if (!constructing) { failRead("closed"); failWrite("closed"); }
    });
    owner.cleanupWith(cleanup);
    const readable = new NativeReadable<Uint8Array>({
      start(controller) { readableController = controller; },
      async pull() {
        if (!installed || readDone || readBusy || readFailure !== undefined) return;
        readBusy = true;
        try {
          const result = await owner.read({ signal: readAbort.signal });
          if (readDone || readFailure !== undefined) return;
          owner.check();
          const bytes = result.data, count = byteLength(bytes);
          if (count > owner.readBytes) throw new Error("read_failed");
          if (count !== 0) {
            // Claim a unique controller/chunk/count under the original gate.
            // The next action in this job is its one captured host call.
            const target = readableController, n = BigInt(count);
            readHostActive = true;
            try { enqueue.call(target, bytes); confirmed += n; }
            catch { unconfirmed += n; failRead("read_failed"); return; }
            finally { readHostActive = false; }
          }
          if (readFailure !== undefined || readDone) return;
          if (result.stream_status === "eof") {
            readHostActive = true;
            try { closeReadable.call(readableController); readDone = true; }
            finally { readHostActive = false; }
          } else if (result.stream_status !== "open" || result.wait_status === "wait_canceled" || count === 0) failRead("read_failed");
        } catch { failRead("read_failed"); }
        finally { readBusy = false; flush(); cleanup(); }
      },
      cancel() {
        // Native cancel owns its reason and has already discarded its queue.
        // Never inspect, stringify or retain the caller's arbitrary reason.
        readDone = true; readerErrorSent = true; readAbort.abort();
        return terminate(false).finally(cleanup);
      },
    }, { highWaterMark: 0 });
    const writable = new NativeWritable<Uint8Array>({
      start(controller) {
        writableController = controller; controller.signal.addEventListener("abort", writerCanceled);
      },
      async write(chunk) {
        if (!installed || writeFailure !== undefined || writeDone) throw writeFailure ?? new V4WebStreamError("closed");
        writeBusy = true;
        let accepted = 0n, progress: V4WriteProgress | undefined;
        try {
          current = takeEntry(chunk);
          while (accepted < BigInt(current.bytes)) {
            if (writeFailure !== undefined) throw writeFailure;
            owner.check();
            progress = await owner.write(byteSlice(chunk, Number(accepted), current.bytes), { signal: writeAbort.signal });
            if (progress.accepted_bytes < 0n || progress.accepted_bytes > BigInt(current.bytes) - accepted) throw new Error("write_failed");
            accepted += progress.accepted_bytes;
            if (writeFailure !== undefined || progress.accepted_bytes === 0n || progress.terminal_reason !== "complete") throw new Error("write_failed");
          }
          if (writeFailure !== undefined) throw writeFailure;
        } catch {
          throw failWrite("write_failed", current === undefined ? undefined : partial(current, accepted, progress));
        } finally {
          if (current !== undefined) { settledTail = current; queuedBytes -= current.backing; current = undefined; }
          writeBusy = false; checkpoint(); flush();
        }
      },
      async close() {
        settledTail = undefined;
        if (writeFailure !== undefined) throw writeFailure;
        writeBusy = true;
        try {
          await owner.closeWrite({ signal: writeAbort.signal });
          const result = await owner.finish({ signal: writeAbort.signal });
          if (writeFailure !== undefined || !result.send_drained) throw new Error("finish_failed");
          writeDone = true;
        } catch { throw failWrite("finish_failed"); }
        finally { writeBusy = false; checkpoint(); flush(); }
      },
      abort() {
        settledTail = undefined; failWrite("aborted");
        return terminate(true).finally(() => { checkpoint(); cleanup(); });
      },
    }, {
      highWaterMark: maxQueued,
      size(chunk) {
        if (!installed || writeDone || writeFailure !== undefined || invalidated) throw writeFailure ?? new V4WebStreamError("closed");
        try {
          owner.check();
          const entry = input(chunk);
          if (entry.bytes > maxChunk || entry.backing > maxBacking || entries.length + Number(current !== undefined) >= maxEntries ||
              entry.backing > maxQueued - queuedBytes) throw new V4WebStreamError("write_capacity");
          entries.push(entry); queuedBytes += entry.backing;
          return Math.max(1, entry.backing);
        } catch (error) {
          throw failWrite(error instanceof V4WebStreamError ? error.code : "closed");
        }
      },
    });
    owner.check(); if (invalidated) throw new V4WebStreamError("closed");
    // Both native endpoints exist, and no raw I/O has occurred. Publication is
    // one final owner-gate decision, never the return of a half-constructed pair.
    installed = true; constructing = false;
    const pair = { readable, writable }; Object.defineProperty(pair, "then", { value: undefined });
    return Object.freeze(pair);
  } catch (error) {
    constructing = false;
    writableController?.signal.removeEventListener("abort", writerCanceled);
    if (channel !== undefined) { closePort.call(channel.port1); closePort.call(channel.port2); }
    owner.rollback(); throw error;
  }
}
