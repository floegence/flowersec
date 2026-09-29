import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus, V4CloseResult, V4ReadResult, V4WriteProgress } from "../generated/transportV4APIResults.js";
import type { V4StreamOwner } from "../v4/public.js";
import { acquireStreamAdapter } from "../v4/runtime/streamAdapter.js";
import type { ProxyStream } from "./stream.js";

/** Keep the original progress when a framing operation fails after a prefix. */
export class ProxyStreamError extends Error {
  constructor(readonly code: "read_failed" | "write_failed" | "finish_failed" | "canceled" | "closed",
    readonly progress?: V4ReadResult | V4WriteProgress | V4CloseResult) {
    super(code); this.name = "ProxyStreamError";
  }
}

export interface CurrentProxyStream extends ProxyStream {
  readonly signal: AbortSignal;
  finish(options?: OperationOptions): Promise<void>;
  cleanupStatus(): V4CleanupStatus;
  /** The framing owner has dropped its final read/write aliases. */
  dispose(onCleanup?: () => void): void;
}

/** Project the original accepted Stream; never create another protocol owner. */
export function currentProxyStream(stream: V4StreamOwner, options: Readonly<{
  readBytes: number;
  inputBackingBytes: number;
  finishTimeoutMS: number;
  cleanupTimeoutMS: number;
}>): CurrentProxyStream {
  const owner = acquireStreamAdapter(stream, {
    kind: "proxy", readBytes: options.readBytes, inputBackingBytes: options.inputBackingBytes,
    inputEntries: 1, gracefulFinishMS: options.finishTimeoutMS, cleanupMS: options.cleanupTimeoutMS,
  });
  const lifetime = new AbortController();
  let eof = false, drained = false, aborted = false, invalidated = false, disposed = false, released = false, tasks = 0;
  let reading = false, writing = false;
  let cleanupCallback: (() => void) | undefined;
  const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
  const collect = (): void => {
    if (!released && disposed && tasks === 0 && owner.cleanupStatus().status === "complete") {
      released = true; owner.release();
      const callback = cleanupCallback; cleanupCallback = undefined; callback?.();
    }
  };
  const check = (signal?: AbortSignal): void => {
    if (aborted || disposed || released || invalidated || lifetime.signal.aborted) throw new ProxyStreamError("closed");
    if (signal?.aborted) throw new ProxyStreamError("canceled");
    owner.check();
  };
  const reset = async (): Promise<void> => {
    if (released) return;
    aborted = true; tasks++;
    try { await owner.reset(); }
    finally { tasks--; collect(); }
  };
  const result: CurrentProxyStream = {
    signal: lifetime.signal,
    async read(wait) {
      if (eof) return null;
      check(wait?.signal);
      if (reading) throw new Error("read_in_progress");
      reading = true; tasks++;
      try {
        const read = await owner.read(wait);
        if (read.wait_status !== "ready") throw new ProxyStreamError("canceled", read);
        if (read.stream_status === "aborted" || read.stream_status === "error") throw new ProxyStreamError("read_failed", read);
        eof = read.stream_status === "eof";
        if (read.data.length === 0 && !eof) throw new ProxyStreamError("read_failed", read);
        return read.data.length === 0 ? null : read.data;
      } finally { reading = false; tasks--; collect(); }
    },
    async write(data, wait) {
      check(wait?.signal);
      if (writing) throw new Error("write_in_progress");
      if (data.byteLength > options.inputBackingBytes || data.buffer.byteLength > options.inputBackingBytes) throw new Error("configuration_capacity");
      writing = true; tasks++;
      try {
        const progress = await owner.write(data, wait);
        if (progress.phase !== "terminal" || progress.terminal_reason !== "complete" ||
            progress.requested_bytes !== BigInt(data.length) || progress.accepted_bytes < 0n || progress.accepted_bytes > BigInt(data.length) ||
            data.length > 0 && progress.accepted_bytes === 0n) throw new ProxyStreamError("write_failed", progress);
        return Number(progress.accepted_bytes);
      } finally { writing = false; tasks--; collect(); }
    },
    async closeWrite(wait) {
      if (drained) return;
      check(wait?.signal); tasks++;
      try { await owner.closeWrite(wait); }
      finally { tasks--; collect(); }
    },
    async finish(wait) {
      if (drained) return;
      check(wait?.signal); tasks++;
      try {
        const closed = await owner.finish(wait);
        if (!closed.send_drained) throw new ProxyStreamError("finish_failed", closed);
        drained = true;
      } finally { tasks--; collect(); }
    },
    reset,
    close: reset,
    dispose(onCleanup) {
      if (onCleanup !== undefined) {
        if (released) { onCleanup(); return; }
        if (cleanupCallback !== undefined) throw new Error("cleanup_observer_in_use");
        cleanupCallback = onCleanup;
      }
      disposed = true; collect();
    },
    cleanupStatus() {
      if (released) return complete;
      const status = owner.cleanupStatus();
      return Object.freeze({ status: status.status === "cleanup_incomplete" ? "cleanup_incomplete" : "pending",
        core_cleanup: status.core_cleanup, pending_callbacks: status.pending_callbacks + BigInt(tasks) });
    },
  };
  owner.cleanupWith(collect);
  owner.invalidateWith(() => { invalidated = true; lifetime.abort(new ProxyStreamError("closed")); collect(); });
  owner.sendStoppedWith(() => { lifetime.abort(new ProxyStreamError("closed")); });
  return Object.freeze(result);
}
