import type { Duplex } from "node:stream";
import { Socket, isIP } from "node:net";
import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus, V4CloseResult, V4ReadResult, V4StreamStatus, V4WriteProgress } from "../generated/transportV4APIResults.js";
import type { V4ReadState, V4StreamOwner, V4TransportEnvironment } from "../v4/public.js";
import { V4DuplexBridge, V4DuplexBridgeError, type V4DuplexBridgeOptions } from "../v4/duplexBridge.js";
import { cleanupResult } from "../v4/runtime/lifecycle.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { registerNativeBridgeDuplexAdapter, hasBridgeStreamAdapter, type NativeBridgeDuplexAdapterOwner, type StreamAdapterProfile } from "../v4/runtime/streamAdapter.js";

const empty = new Uint8Array();
const done: V4CleanupStatus = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const pending: V4CleanupStatus = cleanupResult({ status: "pending", core_cleanup: "pending", pending_callbacks: 1n });
const terminalClose = (readTerminal: "eof" | "abandoned" | "open" | "unknown", sendDrained: boolean, cleanup: V4CleanupStatus): V4CloseResult =>
  Object.freeze({ direction: "c2s", send_drained: sendDrained, read_terminal: readTerminal, cleanup_status: cleanup });
const nativeCapability = Symbol("native TCP connection");
interface NativeTCPState {
  readonly socket: Socket;
  readonly state: { claimed: boolean };
  readonly check: (reference?: ResourceReference) => void;
  readonly cleanup: () => V4CleanupStatus;
  readonly releaseIfExited: () => void;
}
const nativeConnections = new WeakMap<V4NativeTCPConnection, NativeTCPState>();

export interface V4NativeTCPConnectOptions {
  /** Numeric IPv4 or IPv6; this factory performs no DNS or target discovery. */
  readonly host: string;
  readonly port: number;
  readonly readChunkBytes?: number;
  readonly timeoutMS?: number;
  readonly signal?: AbortSignal;
}

/** SDK-created byte TCP endpoint. No raw socket or descriptor escapes; aliases
 * share one complete owner. Native completion proves local shutdown only. */
export class V4NativeTCPConnection {
  constructor(capability: symbol, state: NativeTCPState) {
    if (capability !== nativeCapability) throw new V4DuplexBridgeError("owner_unavailable");
    nativeConnections.set(this,state); Object.freeze(this);
  }
  close(): void {
    const core = nativeConnections.get(this)!;
    if (core.state.claimed) throw new V4DuplexBridgeError("stream_owned");
    core.socket.destroy(); core.releaseIfExited();
  }
  cleanupStatus(): V4CleanupStatus { return nativeConnections.get(this)!.cleanup(); }
}
Object.freeze(V4NativeTCPConnection.prototype); Object.freeze(V4NativeTCPConnection);

/** Reserve the original Environment's native dependency before constructing a
 * socket. Environment Close keeps its charge until socket and adapter exit. */
export async function connectDuplexTCP(environment: V4TransportEnvironment, input: V4NativeTCPConnectOptions): Promise<V4NativeTCPConnection> {
  const host = input.host, port = input.port, chunk = input.readChunkBytes ?? 16384, timeout = input.timeoutMS ?? 90000, signal = input.signal;
  if (typeof host !== "string" || isIP(host) === 0 || host.includes("%") || !Number.isSafeInteger(port) || port < 1 || port > 65535 ||
      !Number.isSafeInteger(chunk) || chunk < 1 || chunk > 65536 || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 90000) throw new V4DuplexBridgeError("configuration_capacity");
  if (signal?.aborted) throw new V4DuplexBridgeError("owner_unavailable");
  const runtime = originalEnvironment(environment);
  const deadline = TrustedDeadline.ageAt(runtime.clock,runtime.clock.sample(),BigInt(timeout),0xffffffffffffffffn);
  const dependency = runtime.admitDependency("duplex_tcp",new ResourceVector([
    runtime.resources.runtimeBytes + BigInt(4 * chunk) + 4096n, 262144n, 0n, 8n, 2n, 2n, 1n, 1n, 0n, 0n, 1n,
  ]));
  const state = { claimed:false };
  let socket: Socket | undefined, physicallyClosed = false, dependencyReleased = false;
  const releaseIfExited = (): void => {
    if (!physicallyClosed || state.claimed || dependencyReleased) return;
    dependencyReleased = true; dependency.release();
  };
  try {
    dependency.check(); deadline.check();
    // Match native buffering to the admitted chunk budget before any IO.
    // Socket forwards these Duplex options; a local value also accommodates
    // Node declarations that omit them from SocketConstructorOpts.
    const socketOptions = { allowHalfOpen:true,readableHighWaterMark:chunk,writableHighWaterMark:chunk };
    socket = new Socket(socketOptions);
    const native = socket;
    const closed = (): void => { physicallyClosed = true; releaseIfExited(); };
    native.once("close",closed);
    // Keep an error observer through complete native retirement, including a
    // provider error after the connect promise has already settled.
    native.on("error",() => undefined);
    dependency.onClose(() => native.destroy());
    await new Promise<void>((resolve,reject) => {
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const remove = (): void => { if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort",aborted); native.removeListener("connect",connected); native.removeListener("error",failed); native.removeListener("close",earlyClose); };
      const finish = (cause?: unknown): void => { if (settled) return; settled = true; remove(); if (cause === undefined) resolve(); else { native.destroy(); reject(cause); } };
      const connected = (): void => { try { dependency.check(); deadline.check(); finish(); } catch (cause) { finish(cause); } };
      const failed = (): void => finish(new V4DuplexBridgeError("owner_unavailable"));
      const earlyClose = (): void => finish(new V4DuplexBridgeError("owner_unavailable"));
      const aborted = (): void => finish(new V4DuplexBridgeError("owner_unavailable"));
      native.once("connect",connected); native.once("error",failed); native.once("close",earlyClose); signal?.addEventListener("abort",aborted,{once:true});
      timer = setTimeout(() => finish(new V4DuplexBridgeError("deadline_exceeded")),timeout);
      try {
        if (signal?.aborted) { aborted(); return; }
        dependency.check(); deadline.check();
        native.connect({host,port});
      } catch (cause) { finish(cause); }
    });
    // Publication uses the original lifetime after the connect continuation.
    // Environment Close or cancellation can win after the provider event.
    dependency.check(); deadline.check();
    if (signal?.aborted) throw new V4DuplexBridgeError("owner_unavailable");
    const core: NativeTCPState = {
      socket:native,state,
      check(reference) { dependency.check(); if (reference !== undefined && !reference.sameEnvironment(dependency.reference)) throw new V4DuplexBridgeError("owner_unavailable"); },
      cleanup: () => physicallyClosed && !state.claimed ? done : pending,
      releaseIfExited,
    };
    const endpoint = new V4NativeTCPConnection(nativeCapability,core);
    registerNativeBridgeDuplexAdapter(endpoint,(profile,resultBacking,ioBacking) => {
      core.check(ioBacking);
      const scoped = dependency.reference.borrowInScopesOf(ioBacking);
      try { return claimNativeTCPBridge(native,state,profile,resultBacking,ioBacking,() => { scoped.release(); releaseIfExited(); }); }
      catch (cause) { scoped.release(); throw cause; }
    });
    return endpoint;
  } catch (cause) {
    if (socket === undefined) physicallyClosed = true; else socket.destroy();
    releaseIfExited(); throw cause;
  }
}

// Private SDK owner seam; package exports expose only the sealed factory.
export function claimNativeTCPBridge(duplex: Duplex, state: { claimed: boolean }, profile: StreamAdapterProfile,
  resultBacking: ResourceReference, ioBacking: ResourceReference, releasedNative: () => void): NativeBridgeDuplexAdapterOwner {
  if (state.claimed) throw new Error("stream_owned");
  const readBytes = profile.readBytes;
  if (!Number.isSafeInteger(duplex.readableHighWaterMark) || !Number.isSafeInteger(duplex.writableHighWaterMark) ||
      duplex.readableHighWaterMark < 1 || duplex.writableHighWaterMark < 1 ||
      duplex.readableHighWaterMark > readBytes || duplex.writableHighWaterMark > readBytes ||
      duplex.allowHalfOpen !== true || duplex.readableDidRead || duplex.readableObjectMode || duplex.writableObjectMode || duplex.readableEncoding !== null ||
      duplex.readableFlowing === true || duplex.listenerCount("data") !== 0 || duplex.writableLength !== 0 ||
      duplex.destroyed || duplex.readableEnded || duplex.writableEnded) {
    throw new Error("owner_unavailable");
  }
  resultBacking.check(); ioBacking.check();
  state.claimed = true;
  const scratch = new Uint8Array(readBytes);
  let released = false, closed = duplex.closed, readEnded = false, writeFinished = false, writeClosing = false;
  let readInFlight = false, error: unknown, waiter: { resolve(value: V4ReadResult): void; reject(reason: unknown): void; signal?: AbortSignal; canceled?: () => void } | undefined;
  let pendingWrite: Promise<void> | undefined, pendingProducer: Promise<void> | undefined;
  let invalidate: (() => void) | undefined, stopped: (() => void) | undefined, cleanup: (() => void) | undefined;
  let readOffset = 0n;

  const status = (): V4CleanupStatus => closed && !readInFlight && pendingWrite === undefined && pendingProducer === undefined ? done : pending;
  const streamStatus = (): V4StreamStatus => error !== undefined ? "error" : readEnded ? "eof" : duplex.destroyed ? "aborted" : "open";
  const readState = (): V4ReadState => Object.freeze({ stream_status: streamStatus() });
  const detachWaiter = (): void => {
    const current = waiter;
    if (current?.signal !== undefined && current.canceled !== undefined) current.signal.removeEventListener("abort", current.canceled);
    waiter = undefined;
  };
  const signalCleanup = (): void => { cleanup?.(); };
  const finishRead = (): void => {
    const current = waiter;
    if (current === undefined || released) return;
    if (error !== undefined) { detachWaiter(); current.reject(error); return; }
    try {
      // A byte stream may publish a short chunk and wait for a response before
      // producing more. read(Q) would wait for Q bytes despite available input.
      // Consume the current bounded prefix without requiring a full chunk.
      const available = Math.min(readBytes,duplex.readableLength);
      const chunk = (available > 0 ? duplex.read(available) : null) as Buffer | null;
      if (chunk !== null) {
        const length = chunk.byteLength;
        if (length < 1 || length > readBytes) throw new Error("read_failed");
        scratch.set(chunk);
        const result: V4ReadResult = Object.freeze({ data: scratch.subarray(0, length),
          progress: Object.freeze({ offset: readOffset, filled: BigInt(length) }), wait_status: "ready", stream_status: "open" });
        readOffset += BigInt(length); detachWaiter(); current.resolve(result); return;
      }
      if (readEnded || duplex.readableEnded) {
        readEnded = true;
        const result: V4ReadResult = Object.freeze({ data: empty, progress: Object.freeze({ offset: readOffset, filled: 0n }),
          wait_status: "ready", stream_status: "eof" });
        detachWaiter(); current.resolve(result); signalCleanup(); return;
      }
      if (closed || duplex.destroyed) { detachWaiter(); current.reject(new Error("read_failed")); }
    } catch (cause) { error = cause; detachWaiter(); current.reject(cause); invalidate?.(); }
  };
  const onReadable = (): void => finishRead();
  const onEnd = (): void => { readEnded = true; finishRead(); signalCleanup(); };
  const onFinish = (): void => { writeFinished = true; if (!writeClosing) stopped?.(); signalCleanup(); };
  const onError = (cause: Error): void => { error ??= cause; waiter?.reject(cause); detachWaiter(); invalidate?.(); signalCleanup(); };
  const onClose = (): void => {
    closed = true; readEnded ||= duplex.readableEnded; writeFinished ||= duplex.writableFinished; finishRead();
    if (!(readEnded && writeFinished)) invalidate?.();
    signalCleanup();
  };
  const onDrain = (): void => { signalCleanup(); };
  duplex.on("readable", onReadable); duplex.on("end", onEnd); duplex.on("finish", onFinish);
  duplex.on("error", onError); duplex.on("close", onClose); duplex.on("drain", onDrain);

  const removeListeners = (): void => {
    duplex.removeListener("readable", onReadable); duplex.removeListener("end", onEnd); duplex.removeListener("finish", onFinish);
    duplex.removeListener("error", onError); duplex.removeListener("close", onClose); duplex.removeListener("drain", onDrain);
  };
  const closePromise = (): Promise<void> => closed ? Promise.resolve() : new Promise(resolve => duplex.once("close", () => resolve()));
  const owner: NativeBridgeDuplexAdapterOwner = Object.freeze({
    endpointKind: "native_duplex" as const, readBytes, resultBacking, readState,
    check() { if (released || !state.claimed || error !== undefined || closed && !(readEnded && writeFinished) || duplex.destroyed && !(readEnded && writeFinished)) throw new Error("closed"); ioBacking.check(); },
    read(options?: OperationOptions): Promise<V4ReadResult> {
      try { owner.check(); if (readInFlight) throw new Error("read_in_progress"); }
      catch (cause) { return Promise.reject(cause); }
      readInFlight = true;
      return new Promise((resolve, reject) => {
        if (options?.signal?.aborted) { readInFlight = false; reject(new Error("aborted")); return; }
        const current: NonNullable<typeof waiter> = { resolve: value => { readInFlight = false; resolve(value); },
          reject: cause => { readInFlight = false; reject(cause); }, ...(options?.signal === undefined ? {} : { signal: options.signal }) };
        if (options?.signal !== undefined) {
          current.canceled = () => { if (waiter !== current) return; detachWaiter(); readInFlight = false; reject(new Error("aborted")); };
          options.signal.addEventListener("abort", current.canceled, { once: true });
        }
        waiter = current; finishRead();
      });
    },
    async write(bytes: Uint8Array, options?: OperationOptions): Promise<V4WriteProgress> {
      owner.check();
      if (options?.signal?.aborted || writeClosing || duplex.writableEnded || bytes.byteLength < 1 || bytes.byteLength > readBytes) throw new Error("write_failed");
      await owner.waitProducerExit(options);
      owner.check(); if (options?.signal?.aborted) throw new Error("aborted");
      const buffer = Buffer.from(bytes);
      let callbackExited!: () => void;
      const physical = new Promise<void>(resolve => { callbackExited = resolve; });
      pendingWrite = physical;
      let writeReturned = false, needsDrain = false, drained = false, callbackDone = false, callbackScheduled = false, producerSettled = false;
      let completeProducer!: () => void, failProducer!: (cause: unknown) => void;
      const producer = new Promise<void>((resolve, reject) => { completeProducer = resolve; failProducer = reject; });
      pendingProducer = producer;
      // Observe every producer handoff before write. A synchronous callback or
      // drain cannot be lost, and neither event alone permits another read.
      const removeProducerListeners = (): void => {
        duplex.removeListener("drain", onProducerDrain); duplex.removeListener("error", onProducerError); duplex.removeListener("close", onProducerClose);
      };
      const settleProducer = (cause?: unknown): void => {
        if (producerSettled || cause === undefined && (!writeReturned || !callbackDone || needsDrain && !drained)) return;
        producerSettled = true; removeProducerListeners();
        if (cause === undefined) completeProducer(); else { error ??= cause; failProducer(cause); }
      };
      const onProducerDrain = (): void => { drained = true; settleProducer(); };
      const onProducerError = (cause: Error): void => settleProducer(cause);
      const onProducerClose = (): void => settleProducer(new Error("closed"));
      duplex.on("drain", onProducerDrain); duplex.on("error", onProducerError); duplex.on("close", onProducerClose);
      void producer.then(() => {
        if (pendingProducer === producer) pendingProducer = undefined; signalCleanup();
      }, () => {
        if (pendingProducer === producer) pendingProducer = undefined; signalCleanup();
      });
      const exitCallback = (cause?: Error | null): void => {
        if (callbackScheduled) return;
        callbackScheduled = true;
        // The native callback still owns buffer until its invocation returns.
        queueMicrotask(() => {
          buffer.fill(0); callbackDone = true;
          if (pendingWrite === physical) pendingWrite = undefined;
          callbackExited(); settleProducer(cause ?? undefined); signalCleanup();
        });
      };
      try {
        needsDrain = !duplex.write(buffer, exitCallback); writeReturned = true; settleProducer();
      } catch (cause) {
        writeReturned = true; settleProducer(cause);
        // A standard Socket synchronous refusal retained no callback input.
        // The callback-exit microtask preserves any invocation already queued.
        if (!callbackDone) exitCallback();
        throw cause;
      }
      // Accepted means Node took the input. Callback/drain is a separate local
      // producer gate; it does not prove authenticated peer receipt.
      return Object.freeze({ requested_bytes: BigInt(bytes.byteLength), accepted_bytes: BigInt(bytes.byteLength),
        phase: "terminal", terminal_reason: "complete", cleanup_status: status() });
    },
    async waitProducerExit(options?: OperationOptions): Promise<void> {
      const producer = pendingProducer;
      if (options?.signal?.aborted) throw new Error("aborted");
      if (producer === undefined) { owner.check(); return; }
      if (options?.signal === undefined) { await producer; return; }
      const signal = options.signal;
      await new Promise<void>((resolve, reject) => {
        const remove = (): void => signal.removeEventListener("abort", canceled);
        const canceled = (): void => { remove(); reject(new Error("aborted")); };
        signal.addEventListener("abort", canceled, { once: true });
        void producer.then(() => { remove(); resolve(); }, cause => { remove(); reject(cause); });
        if (signal.aborted) canceled();
      });
    },
    async closeWrite(options?: OperationOptions): Promise<V4CloseResult> {
      owner.check(); await owner.waitProducerExit(options);
      owner.check(); if (options?.signal?.aborted) throw new Error("aborted");
      if (!writeClosing) { writeClosing = true; duplex.end(); }
      return terminalClose(readEnded ? "eof" : "open", false, status());
    },
    async finish(options?: OperationOptions): Promise<V4CloseResult> {
      owner.check(); await owner.waitProducerExit(options);
      owner.check(); if (options?.signal?.aborted) throw new Error("aborted");
      if (!writeFinished && !duplex.writableFinished) await new Promise<void>((resolve, reject) => {
        let settled = false;
        const cleanupWait = (): void => { duplex.removeListener("finish", onFinishWait); duplex.removeListener("error", onErrorWait); duplex.removeListener("close", onCloseWait); options?.signal?.removeEventListener("abort", onAbort); };
        const finishWait = (cause?: unknown): void => { if (settled) return; settled = true; cleanupWait(); if (cause === undefined) resolve(); else reject(cause); };
        const onFinishWait = (): void => finishWait();
        const onErrorWait = (cause: Error): void => finishWait(cause);
        const onCloseWait = (): void => finishWait(writeFinished || duplex.writableFinished ? undefined : new Error("closed"));
        const onAbort = (): void => finishWait(new Error("aborted"));
        // Install before end: synchronous native finish must not be lost.
        duplex.once("finish", onFinishWait); duplex.once("error", onErrorWait); duplex.once("close", onCloseWait); options?.signal?.addEventListener("abort", onAbort, { once: true });
        try {
          if (options?.signal?.aborted) { onAbort(); return; }
          if (!writeClosing) { writeClosing = true; duplex.end(); }
          if (writeFinished || duplex.writableFinished) finishWait();
          else if (closed || duplex.closed) onCloseWait();
        } catch (cause) { finishWait(cause); }
      });
      if (pendingWrite !== undefined) await pendingWrite;
      if (!readEnded && !duplex.readableEnded) throw new Error("finish_failed");
      readEnded = true; writeFinished = true; signalCleanup();
      return terminalClose("eof", true, status());
    },
    async reset(): Promise<V4CloseResult> {
      if (!duplex.destroyed) duplex.destroy();
      await closePromise(); closed = true; readEnded ||= duplex.readableEnded; writeFinished ||= duplex.writableFinished;
      detachWaiter();
      await Promise.allSettled([...(pendingWrite === undefined ? [] : [pendingWrite]), ...(pendingProducer === undefined ? [] : [pendingProducer])]);
      signalCleanup();
      return terminalClose(readEnded ? "eof" : "abandoned", false, status());
    },
    async abortRead(): Promise<V4CloseResult> { return owner.reset(); },
    async abortWrite(): Promise<V4CloseResult> { return owner.reset(); },
    cleanupStatus: status,
    invalidateWith(callback: () => void) { invalidate = callback; if (error !== undefined || closed && !readEnded) callback(); },
    sendStoppedWith(callback: () => void) { stopped = callback; if (writeFinished && !writeClosing) callback(); },
    cleanupWith(callback: () => void) { cleanup = callback; if (status().status === "complete") callback(); },
    rollback() { if (released) return; released = true; detachWaiter(); removeListeners(); scratch.fill(0); ioBacking.release(); state.claimed = false; releasedNative(); },
    release() { if (released) return; released = true; detachWaiter(); removeListeners(); scratch.fill(0); ioBacking.release(); state.claimed = false; releasedNative(); },
  });
  return owner;
}

export class V4NodeDuplexBridge extends V4DuplexBridge {
  constructor(a: V4StreamOwner | V4NativeTCPConnection, b: V4StreamOwner | V4NativeTCPConnection, options: V4DuplexBridgeOptions = {}) {
    for (const endpoint of [a,b]) {
      if (!hasBridgeStreamAdapter(endpoint) && !nativeConnections.has(endpoint as V4NativeTCPConnection)) throw new V4DuplexBridgeError("owner_unavailable");
    }
    super(a as V4StreamOwner, b as V4StreamOwner, options);
  }
}
