import type { OperationOptions } from "../public/contract.js";
import { streamMetadataFromDocument, type StreamMetadata } from "../public/streamMetadata.js";
import type { V4CleanupStatus, V4CloseResult } from "../generated/transportV4APIResults.js";
import type { V4StreamOwner } from "./public.js";
import { CBORDecoder, cborDecoderCharge, byteLength, byteSlice } from "./runtime/cbor.js";
import { ResourceError, ResourceVector, type ResourceReference } from "./runtime/resources.js";
import { timerChunk, type TrustedDeadline } from "./runtime/deadline.js";
import { acquireMessageStreamAdapter, type MessageStreamAdapterOwner } from "./runtime/streamAdapter.js";
import { MessageSegments, messageInputBytes, checkApplicationMessageOutput } from "./runtime/messageCodec.js";
import type { V4MessageStreamDefinition} from "./messageDefinition.js";
import { messageDefinition, sameMessageDigest, emptyMessageMetadata } from "./messageDefinition.js";
import { applicationHasPermit, type V4ApplicationContext, type V4ApplicationWaitOptions } from "./streamHandlers.js";
import { applicationHasCompletionAncestor, applicationDependsOn, type ApplicationPermit, type CompletionClaim, type CompletionReservation } from "./runtime/applicationExecutor.js";

export interface V4MessageStreamOptions {
  readonly assemblyTimeoutMS?: bigint;
  readonly sendTimeoutMS?: bigint;
  readonly cleanupTimeoutMS?: bigint;
}
export interface V4MessageSendOptions extends OperationOptions {
  readonly admission?: "queued" | "try_now";
  readonly timeoutMS?: bigint;
  readonly context?: V4ApplicationContext;
}
export interface V4MessageReceiveOptions extends OperationOptions { readonly context?: V4ApplicationContext; }
export interface V4MessageSendResult {
  readonly submission: "not_submitted" | "submitted";
  readonly stream_bytes_accepted_at_return: bigint;
  readonly publication_pending: boolean;
  readonly cleanup_status: V4CleanupStatus;
}
export type V4MessageReceiveResult<T = unknown> = Readonly<{ done: true }> | Readonly<{ done: false; value: T; application_input_delivered: boolean }>;
export type V4MessageFailure = "closed" | "canceled" | "deadline_exceeded" | "resource_exhausted" | "would_block" |
  "read_in_progress" | "encode_failed" | "decode_failed" | "framing_error" | "write_failed" | "definition_mismatch" |
  "dependency_unavailable" | "completion_dependency_unavailable" | "result_mode_conflict";
export class V4MessageStreamError extends Error {
  constructor(readonly code: V4MessageFailure, readonly progress?: V4MessageSendResult, readonly application_input_delivered = false) { super(code); this.name = "V4MessageStreamError"; }
}
const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const pending: V4CleanupStatus = Object.freeze({ status: "pending", core_cleanup: "pending", pending_callbacks: 0n });
const empty = new Uint8Array(), token = Symbol("original typed message owner"), copy = Uint8Array.prototype.set;
const NativePromise = Promise, enqueue = queueMicrotask, defineProperty = Object.defineProperty, freeze = Object.freeze;
const nativeDecode = TextDecoder.prototype.decode, utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const sendCap = 2 * 1024 * 1024 + 32;
function result<T extends object>(value: T): Readonly<T> { defineProperty(value, "then", { value: undefined }); return freeze(value); }
function duration(value: bigint | undefined, fallback: bigint, max = 90000n): bigint {
  const n = value ?? fallback; if (typeof n !== "bigint" || n < 1n || n > max) throw new Error("configuration_capacity"); return n;
}
export function captureMessageOptions(options: V4MessageStreamOptions = {}) {
  return Object.freeze({ assemblyTimeoutMS: duration(options.assemblyTimeoutMS, 30000n), sendTimeoutMS: duration(options.sendTimeoutMS, 30000n), cleanupTimeoutMS: duration(options.cleanupTimeoutMS, 5000n, 30000n) });
}
export function messageAdapterProfile(options: ReturnType<typeof captureMessageOptions>, prepaid?: ResourceReference) {
  return Object.freeze({ kind: "message" as const, readBytes: 4096, inputBackingBytes: 1, inputEntries: 1,
    gracefulFinishMS: Number(options.sendTimeoutMS), cleanupMS: Number(options.cleanupTimeoutMS), ...(prepaid === undefined ? {} : { prepaid }) });
}
export function messageAdapterCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([25728n + runtimeBytes, 0n, 0n, 5n, 6n, 6n, 4n, 0n, 0n, 1n, 0n]);
}
type WriteRequest = ReturnType<MessageStreamAdapterOwner["prepareWrite"]>;
interface Send {
  value: unknown; readonly reference: ResourceReference; readonly deadline: TrustedDeadline; readonly signal: AbortSignal | undefined;
  readonly canceled: () => void; readonly resolve: (value: V4MessageSendResult) => void; readonly reject: (error: V4MessageStreamError) => void;
  timer: ReturnType<typeof setTimeout> | undefined; segments: MessageSegments | undefined; request: WriteRequest | undefined;
  capacity: number; accepted: bigint; prefix: Uint8Array; running: boolean; done: boolean; delivered: boolean; revoked: boolean; reason: V4MessageFailure | undefined;
  readonly abort: AbortController; readonly context: V4ApplicationContext | undefined; permit: ApplicationPermit | undefined;
  payload: readonly Uint8Array[] | undefined;
  preparing: boolean; applicationContext: V4ApplicationContext | undefined;
}
interface ReceiveWait {
  readonly encoded: boolean; readonly signal: AbortSignal | undefined; readonly canceled: () => void;
  readonly resolve: (result: V4MessageReceiveResult<unknown>) => void; readonly reject: (error: V4MessageStreamError) => void;
  readonly context: V4ApplicationContext | undefined; claim: CompletionClaim | undefined;
}

/** One duplex owner, bounded FIFO and persistent message cursor. Complete
 * payloads are allocated only after validating the original four-byte prefix. */
export class V4TypedMessageStream<Inbound = unknown, Outbound = unknown> {
  #owner: MessageStreamAdapterOwner | undefined;
  #inbound: ReturnType<typeof messageDefinition>["directions"][number] | undefined;
  #outbound: ReturnType<typeof messageDefinition>["directions"][number] | undefined;
  #metadata: StreamMetadata = emptyMessageMetadata();
  #definition: object | undefined;
  #prepared: Readonly<{ localOpener: boolean; kind: string }> | undefined;
  readonly #options: ReturnType<typeof captureMessageOptions>;
  readonly #sends: Send[] = [];
  readonly #actualSends = new Set<Send>();
  #sendBytes = 0;
  #publishing = false;
  #publisher: Send | undefined;
  #sealed = false;
  #closed = false;
  #ioEnded = false;
  #ioDetached = false;
  #cleaning = false;
  #failure: V4MessageFailure | undefined;
  #closeResult: V4CloseResult | undefined;
  #direction: "c2s" | "s2c" = "c2s";
  #closeTail: Promise<void> | undefined;
  #closeRunning = false;
  #fin: Promise<V4CloseResult> | undefined;
  #finResolve: ((value: V4CloseResult) => void) | undefined;
  #finReject: ((error: V4MessageStreamError) => void) | undefined;
  #finDeadline: TrustedDeadline | undefined;
  #finTimer: ReturnType<typeof setTimeout> | undefined;
  #finStarted = false;
  #finResult: V4CloseResult | undefined;
  #finish: Promise<V4CloseResult> | undefined;
  #readWait: ReceiveWait | undefined;
  #readRunning = false;
  #handoff = false;
  #readAdmissionBlocked = false;
  #readScheduled = false;
  #readAbort: AbortController | undefined;
  #prefix = new Uint8Array(4);
  #prefixBytes = 0;
  #length: number | undefined;
  #body: Uint8Array = empty;
  #filled = 0;
  #bodyReference: ResourceReference | undefined;
  #typedReference: ResourceReference | undefined;
  #typedPrepaid = false;
  #completion: CompletionReservation | undefined;
  #value: unknown;
  #decoded = false;
  #decoding = false;
  #applicationInputDelivered = false;
  #decodeContext: V4ApplicationContext | undefined;
  #decodeAbort: AbortController | undefined;
  #decodeFailed = false;
  #eof = false;
  #assembly: TrustedDeadline | undefined;
  #assemblyTimer: ReturnType<typeof setTimeout> | undefined;
  #resourceObserver: (() => void) | undefined;
  #dependencyDeadline: TrustedDeadline | undefined;
  #dependencyTimer: ReturnType<typeof setTimeout> | undefined;
  #cleanupDeadline: TrustedDeadline | undefined;
  #cleanupTimer: ReturnType<typeof setTimeout> | undefined;
  #cleanupIncomplete = false;
  #waits = 0;
  #cleanupWaits = 0;
  readonly #observers = new Set<() => void>();

  constructor(capability: symbol, definition: object, options: V4MessageStreamOptions) {
    if (capability !== token) throw new Error("owner_unavailable");
    messageDefinition(definition); this.#definition = definition; this.#options = captureMessageOptions(options);
    Object.defineProperty(this, "then", { value: undefined });
  }
  get metadata(): StreamMetadata { return this.#metadata; }
  /** Internal pre-acceptance preparation has no byte I/O or delivery rights. */
  prepare(capability: symbol, context: Pick<MessageStreamAdapterOwner, "kind" | "localOpener" | "metadata" | "runtimeBytes" | "reserve">): void {
    if (capability !== token || this.#prepared !== undefined || this.#closed) throw new Error("owner_unavailable");
    const def = messageDefinition(this.#definition!);
    if (context.kind !== (this.#definition as { kind: string }).kind) throw new V4MessageStreamError("definition_mismatch");
    const config = { bytes: 4096, nodes: 272, textBytes: 128, arrayItems: 1, runtimeBytes: context.runtimeBytes };
    const reference = context.reserve("v4_message_metadata", cborDecoderCharge(config)); let decoder: CBORDecoder | undefined;
    try {
      decoder = new CBORDecoder(config, reference);
      const document = decoder.decodeMap(context.metadata, "TypedMessageMetadata");
      let application: Uint8Array;
      try {
        let digest = empty; application = empty;
        for (let k = document.firstChild(document.field(0, 2)); k >= 0;) {
          const v = document.nextSibling(k), bytes = new Uint8Array(document.size(v)); document.copyPayload(v, bytes);
          if (document.text(k) === "definition") digest = bytes; else application = bytes;
          k = document.nextSibling(v);
        }
        if (!sameMessageDigest(digest, def.digest)) throw new V4MessageStreamError("definition_mismatch");
      } finally { document.release(); }
      if (application.length !== 0) {
        const doc = decoder.decodeMap(application, "StreamMetadata"); try { this.#metadata = streamMetadataFromDocument(doc); } finally { doc.release(); application.fill(0); }
      }
      this.#inbound = def.directions[context.localOpener ? 1 : 0]; this.#outbound = def.directions[context.localOpener ? 0 : 1];
      this.#prepared = Object.freeze({ localOpener: context.localOpener, kind: context.kind });
    } finally { decoder?.close(); reference.release(); }
  }
  /** Internal one-time transfer after the same OPEN reaches accepted. */
  bind(capability: symbol, owner: MessageStreamAdapterOwner): void {
    if (capability !== token || this.#owner !== undefined || this.#closed) throw new Error("owner_unavailable");
    if (this.#prepared === undefined) this.prepare(token, owner);
    if (this.#prepared!.localOpener !== owner.localOpener || this.#prepared!.kind !== owner.kind) throw new V4MessageStreamError("definition_mismatch");
    owner.check(); this.#owner = owner; this.#direction = owner.direction;
    owner.cleanupWith(() => this.#cleanup()); owner.invalidateWith(() => { if (this.#applicationInputDelivered) this.#endIO(); else this.#fail("closed"); });
    owner.ioEndedWith(() => this.#endIO());
  }
  #check(): MessageStreamAdapterOwner {
    if (this.#closed || this.#owner === undefined) throw new V4MessageStreamError(this.#failure ?? "closed");
    this.#owner.check(); return this.#owner;
  }
  #checkRead(): MessageStreamAdapterOwner {
    if (!this.#applicationInputDelivered) return this.#check();
    if (this.#closed || this.#owner === undefined) throw new V4MessageStreamError(this.#failure ?? "closed", undefined, true);
    // The same application completion owns already-disclosed input. Revocation
    // still prevents all future I/O, but cannot recall that original input.
    return this.#owner;
  }
  #endIO(): void {
    if (this.#closed || this.#ioEnded) return;
    // A complete empty frame has no body read to provide another wake.
    if (this.#length === undefined && this.#prefixBytes === 4 && this.#prefix.every(byte => byte === 0)) {
      const owner = this.#owner!;
      try {
        this.#bodyReference = owner.reserve("v4_message_body", new ResourceVector([owner.runtimeBytes + 256n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
        this.#length = 0;
      } catch { this.#fail("resource_exhausted"); return; }
    }
    // Only a completely authenticated/assembled body can outlive transport.
    if (this.#length === undefined || this.#filled !== this.#length || this.#bodyReference === undefined) { this.#fail("closed"); return; }
    this.#ioEnded = true; this.#sealed = true; this.#stopAssembly();
    this.#resourceObserver?.(); this.#resourceObserver = undefined;
    for (const entry of this.#actualSends) {
      entry.revoked = true; entry.reason = "closed"; entry.abort.abort(); entry.request?.cancel(); this.#settleSend(entry, "closed");
      if (!entry.running) this.#releaseSend(entry);
    }
    this.#sends.length = 0;
    if (this.#finTimer !== undefined) clearTimeout(this.#finTimer); this.#finTimer = undefined;
    this.#finReject?.(new V4MessageStreamError("closed")); this.#finReject = this.#finResolve = undefined;
    if (!this.#readRunning) this.#owner?.releaseReader();
    this.#cleanup();
  }
  #snapshot(entry: Send): V4MessageSendResult {
    const accepted = entry.accepted + (entry.request?.progress().accepted_bytes ?? 0n);
    return result({ submission: accepted === 0n ? "not_submitted" : "submitted", stream_bytes_accepted_at_return: accepted,
      publication_pending: accepted > 0n && !entry.done, cleanup_status: entry.done ? complete : pending });
  }
  #settleSend(entry: Send, failure?: V4MessageFailure): void {
    if (entry.delivered) return; entry.delivered = true;
    entry.signal?.removeEventListener("abort", entry.canceled);
    if (failure === undefined) entry.resolve(this.#snapshot(entry)); else entry.reject(new V4MessageStreamError(failure, this.#snapshot(entry)));
  }
  send(value: Outbound, options: V4MessageSendOptions = {}): Promise<V4MessageSendResult> {
    let resolve!: (value: V4MessageSendResult) => void, reject!: (error: V4MessageStreamError) => void;
    const promise = new NativePromise<V4MessageSendResult>((yes, no) => { resolve = yes; reject = no; });
    let reference: ResourceReference | undefined, admitted: Send | undefined;
    try {
      const owner = this.#check();
      if (this.#sealed) throw new V4MessageStreamError("closed");
      if (options.signal?.aborted) throw new V4MessageStreamError("canceled");
      if (options.admission !== undefined && options.admission !== "queued" && options.admission !== "try_now") throw new V4MessageStreamError("encode_failed");
      if ((options.admission === "try_now" || applicationHasPermit(options.context)) && (this.#publishing || this.#sends.length !== 0)) throw new V4MessageStreamError("would_block");
      if (this.#actualSends.size === 8 || this.#sendBytes + 4 > sendCap) throw new V4MessageStreamError("resource_exhausted");
      const maximum = this.#outbound!.maximum, codec = this.#outbound!.application;
      const bytes = messageInputBytes(value, this.#outbound!.implementation, maximum), outputBytes = codec === undefined ? 0 : 2 * maximum;
      if (outputBytes + 4 > sendCap - this.#sendBytes) throw new V4MessageStreamError("resource_exhausted");
      const timeout = duration(options.timeoutMS, this.#options.sendTimeoutMS, this.#options.sendTimeoutMS), deadline = owner.deadline(timeout);
      reference = owner.reserveSend("v4_message_send", new ResourceVector([BigInt(bytes + outputBytes) + (codec?.applicationBytes ?? 0n) + owner.runtimeBytes + 512n, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]));
      const entry: Send = { value, reference, deadline, signal: options.signal, canceled: () => this.#cancelSend(entry), resolve, reject, timer: undefined,
        segments: undefined, request: undefined, capacity: outputBytes + 4, accepted: 0n, prefix: new Uint8Array(4), running: false, done: false, delivered: false, revoked: false, reason: undefined,
        abort: new AbortController(), context: options.context, permit: undefined, payload: undefined, preparing: false, applicationContext: undefined };
      this.#sendBytes += entry.capacity; this.#actualSends.add(entry); this.#sends.push(entry); reference = undefined;
      admitted = entry;
      const guard = (): void => { this.#check(); entry.deadline.check(); if (entry.signal?.aborted || entry.revoked) throw new V4MessageStreamError("canceled"); };
      if (applicationHasPermit(options.context)) {
        let used = false;
        if (codec?.execution !== "async") {
          entry.running = entry.preparing = true;
          try {
            const synchronous = owner.application.synchronous(options.context, guard, () => this.#encodeSend(entry, owner, guard, options.context));
            used = synchronous.used;
          } finally { entry.running = entry.preparing = false; }
        }
        if (!used) entry.permit = owner.application.tryOrdinary("short", options.context);
      } else if (options.admission === "try_now") entry.permit = owner.application.tryOrdinary("short");
      const expire = (): void => {
        try { entry.deadline.check(); entry.timer = setTimeout(expire, timerChunk(entry.deadline.remainingMS())); }
        catch { entry.timer = undefined; this.#cancelSend(entry, "deadline_exceeded"); }
      };
      entry.signal?.addEventListener("abort", entry.canceled, { once: true }); expire();
      enqueue(() => { if (entry.signal?.aborted) this.#cancelSend(entry); this.#publish(); });
    } catch (error) {
      reference?.release(); const code = error instanceof V4MessageStreamError ? error.code : error instanceof ResourceError ? "resource_exhausted" :
        error instanceof Error && (error.message === "dependency_unavailable" || error.message === "would_block") ? error.message : "encode_failed";
      if (admitted !== undefined) { this.#cancelSend(admitted, code); return promise; }
      reject(new V4MessageStreamError(code, result({ submission: "not_submitted", stream_bytes_accepted_at_return: 0n, publication_pending: false, cleanup_status: complete })));
    }
    return promise;
  }
  #cancelSend(entry: Send, reason: V4MessageFailure = "canceled"): void {
    if (entry.done) return;
    const submitted = entry.accepted + (entry.request?.progress().accepted_bytes ?? 0n) > 0n;
    if (!submitted) {
      entry.revoked = true; entry.reason = reason; entry.abort.abort(); entry.request?.cancel();
      const i = this.#sends.indexOf(entry); if (i >= 0) this.#sends.splice(i, 1);
      if (entry.preparing && this.#publisher === entry) { this.#publisher = undefined; this.#publishing = false; }
    } else if (reason !== "canceled") { entry.reason = reason; entry.request?.cancel(); this.#fail(reason); }
    this.#settleSend(entry, reason);
    if (!entry.running) this.#releaseSend(entry);
    this.#publish();
  }
  #publish(): void {
    if (this.#publishing || this.#closed || this.#ioEnded) return;
    const entry = this.#sends[0];
    if (entry === undefined) { this.#startFIN(); return; }
    this.#publishing = true; this.#publisher = entry;
    void this.#runSend(entry).finally(() => {
      if (this.#publisher === entry) { this.#publisher = undefined; this.#publishing = false; }
      this.#publish(); this.#cleanup();
    });
  }
  #encodeSend(entry: Send, owner: MessageStreamAdapterOwner, guard: () => void, context?: V4ApplicationContext): void {
    guard();
    const codec = this.#outbound!.application;
    if (codec !== undefined) {
      if (codec.execution !== "sync" || context === undefined) throw new V4MessageStreamError("encode_failed");
      entry.applicationContext = context;
      try {
        let output: Uint8Array | undefined;
        try { output = codec.encode(context, entry.value); } catch { throw new V4MessageStreamError("encode_failed"); }
        this.#sealApplicationOutput(entry, guard, output); output = undefined; this.#finishApplicationEncoding(entry, owner);
      }
      finally { entry.applicationContext = undefined; }
      return;
    }
    const segments = entry.segments = new MessageSegments(this.#outbound!.maximum, owner.runtimeBytes, (charge, capacity) => {
      guard(); if (capacity > sendCap - this.#sendBytes) throw new ResourceError("resource_exhausted");
      const ref = owner.reserveSend("v4_message_segment", charge); this.#sendBytes += capacity; entry.capacity += capacity; return ref;
    }, guard);
    if (this.#outbound!.implementation === "bytes") segments.append(entry.value as Uint8Array); else segments.utf8(entry.value as string);
    entry.payload = segments.finalize(); entry.value = undefined; new DataView(entry.prefix.buffer).setUint32(0, segments.length);
    entry.reference.shrink(new ResourceVector([owner.runtimeBytes + 512n, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]));
  }
  #sealApplicationOutput(entry: Send, guard: () => void, value: unknown): void {
    guard();
    let source: Uint8Array | undefined = checkApplicationMessageOutput(value, this.#outbound!.maximum);
    const length = byteLength(source), owned = new Uint8Array(length);
    copy.call(owned, source); source = undefined; value = undefined;
    entry.value = undefined; entry.payload = [owned]; new DataView(entry.prefix.buffer).setUint32(0, length);
  }
  #finishApplicationEncoding(entry: Send, owner: MessageStreamAdapterOwner): void {
    const length = byteLength(entry.payload![0]!);
    this.#sendBytes -= entry.capacity - length - 4; entry.capacity = length + 4;
    entry.reference.shrink(new ResourceVector([BigInt(length) + owner.runtimeBytes + 512n, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]));
  }
  async #runSend(entry: Send): Promise<void> {
    entry.running = true;
    let failure: V4MessageFailure | undefined;
    let applicationTail: ReturnType<MessageStreamAdapterOwner["sessionCleanup"]["startApplicationCallback"]> | undefined;
    try {
      const owner = this.#check();
      const guard = (): void => { this.#check(); entry.deadline.check(); if (entry.revoked) throw new V4MessageStreamError(entry.reason ?? "canceled"); };
      guard();
      if (entry.payload === undefined) {
        entry.preparing = true;
        let invocation: ReturnType<MessageStreamAdapterOwner["application"]["context"]> | undefined;
        try {
          entry.permit ??= await owner.application.acquire("short", entry.abort.signal, guard, entry.context);
          guard();
          const codec = this.#outbound!.application;
          if (codec !== undefined) {
            if (owner.authentication === undefined) throw new V4MessageStreamError("encode_failed");
            invocation = owner.application.context(entry.permit, owner.authentication, entry.abort.signal); entry.applicationContext = invocation.context;
            applicationTail = owner.sessionCleanup.startApplicationCallback();
            if (codec.execution === "async") {
              let output: Uint8Array | undefined;
              try { output = await codec.encode(invocation.context, entry.value); } catch { throw new V4MessageStreamError("encode_failed"); }
              this.#sealApplicationOutput(entry, guard, output); output = undefined; this.#finishApplicationEncoding(entry, owner);
            } else this.#encodeSend(entry, owner, guard, invocation.context);
          } else this.#encodeSend(entry, owner, guard);
        } finally {
          invocation?.release(); entry.applicationContext = undefined; entry.permit?.release(); entry.permit = undefined; entry.preparing = false;
          applicationTail?.callbackExited();
        }
      }
      const payload = entry.payload!;
      for (const bytes of [entry.prefix, ...payload]) {
        for (let at = 0; at < bytes.length;) {
          guard(); const count = Math.min(owner.maxWriteBytes, bytes.length - at);
          if (count > sendCap - this.#sendBytes) throw new ResourceError("resource_exhausted");
          const remaining = entry.deadline.remainingMS(), request = owner.prepareWrite(byteSlice(bytes, at, at + count), remaining < owner.maxWriteMilliseconds ? remaining : owner.maxWriteMilliseconds);
          entry.request = request; this.#sendBytes += count;
          try {
            if (entry.revoked) request.cancel(); request.start(); const progress = await request.wait();
            await request.waitCleanup();
            entry.accepted += progress.accepted_bytes; entry.request = undefined;
            if (progress.accepted_bytes !== BigInt(count) || progress.terminal_reason !== "complete") throw new V4MessageStreamError(entry.reason ?? "write_failed");
            at += count;
          } finally { this.#sendBytes -= count; }
        }
      }
    } catch (error) {
      failure = entry.reason ?? (error instanceof V4MessageStreamError ? error.code : error instanceof ResourceError ? "resource_exhausted" : "encode_failed");
      if (!this.#ioEnded && entry.accepted + (entry.request?.progress().accepted_bytes ?? 0n) > 0n) this.#fail(failure);
    } finally {
      const i = this.#sends.indexOf(entry); if (i >= 0) this.#sends.splice(i, 1);
      entry.running = false; this.#releaseSend(entry); this.#settleSend(entry, failure);
      applicationTail?.finish();
    }
  }
  #releaseSend(entry: Send): void {
    if (entry.done) return; entry.done = true;
    if (entry.timer !== undefined) clearTimeout(entry.timer); entry.timer = undefined;
    entry.signal?.removeEventListener("abort", entry.canceled); entry.value = undefined;
    entry.permit?.release(); entry.permit = undefined;
    if (entry.segments === undefined) for (const bytes of entry.payload ?? []) bytes.fill(0);
    entry.segments?.close(); entry.segments = undefined; entry.payload = undefined; entry.prefix.fill(0); entry.prefix = empty;
    this.#sendBytes -= entry.capacity; entry.capacity = 0; entry.reference.release(); this.#actualSends.delete(entry);
  }

  receive(options?: V4MessageReceiveOptions): Promise<V4MessageReceiveResult<Inbound>> { return this.#receive(false, options) as Promise<V4MessageReceiveResult<Inbound>>; }
  receiveEncoded(options?: V4MessageReceiveOptions): Promise<V4MessageReceiveResult<Uint8Array>> { return this.#receive(true, options) as Promise<V4MessageReceiveResult<Uint8Array>>; }
  #receive(encoded: boolean, options?: V4MessageReceiveOptions): Promise<V4MessageReceiveResult<unknown>> {
    let resolve!: ReceiveWait["resolve"], reject!: ReceiveWait["reject"];
    const promise = new NativePromise<V4MessageReceiveResult<unknown>>((yes, no) => { resolve = yes; reject = no; });
    try {
      this.#checkRead();
      if (applicationDependsOn(options?.context, this.#decodeContext)) throw new V4MessageStreamError("dependency_unavailable", undefined, this.#applicationInputDelivered);
      if (this.#readWait !== undefined) throw new V4MessageStreamError("read_in_progress");
      if (this.#ioEnded && this.#length === undefined) throw new V4MessageStreamError("closed");
      if (options?.signal?.aborted) throw new V4MessageStreamError("canceled");
      applicationHasPermit(options?.context);
      if (encoded && this.#applicationInputDelivered) throw new V4MessageStreamError("result_mode_conflict", undefined, true);
      const wait: ReceiveWait = { encoded, signal: options?.signal, context: options?.context, claim: undefined, resolve, reject, canceled: () => {
        if (this.#readWait !== wait || this.#handoff) return; this.#readWait = undefined; wait.signal?.removeEventListener("abort", wait.canceled);
        if (!this.#decoded && !this.#applicationInputDelivered && this.#typedPrepaid && this.#bodyReference !== undefined && this.#length !== undefined) {
          try {
            this.#bodyReference.shrink(new ResourceVector([BigInt(this.#body.buffer.byteLength) + this.#owner!.runtimeBytes + 256n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
            this.#typedPrepaid = false;
          } catch { /* Closed roots retain the original charge until cleanup. */ }
        }
        if (!this.#decoded && !this.#applicationInputDelivered) { this.#typedReference?.release(); this.#typedReference = undefined; this.#completion?.close(); this.#completion = undefined; }
        wait.claim?.release(); wait.claim = undefined;
        if (this.#dependencyTimer !== undefined) clearTimeout(this.#dependencyTimer); this.#dependencyTimer = undefined;
        this.#readAbort?.abort(); wait.reject(new V4MessageStreamError("canceled", undefined, this.#applicationInputDelivered));
      } };
      this.#readWait = wait; wait.signal?.addEventListener("abort", wait.canceled, { once: true }); this.#scheduleRead();
    } catch (error) { reject(error instanceof V4MessageStreamError ? error : new V4MessageStreamError(
      error instanceof Error && error.message === "dependency_unavailable" ? "dependency_unavailable" : "closed")); }
    return promise;
  }
  #scheduleRead(): void {
    if (this.#readScheduled || this.#readRunning || this.#closed || this.#readWait === undefined) return;
    this.#readScheduled = true; enqueue(() => { this.#readScheduled = false; if (!this.#closed && this.#readWait !== undefined) void this.#runRead(); });
  }
  #startAssembly(): void {
    if (this.#assembly !== undefined) return;
    this.#assembly = this.#owner!.deadline(this.#options.assemblyTimeoutMS);
    const tick = (): void => {
      try { this.#assembly!.check(); this.#assemblyTimer = setTimeout(tick, timerChunk(this.#assembly!.remainingMS())); }
      catch { this.#assemblyTimer = undefined; this.#fail("deadline_exceeded"); }
    }; tick();
  }
  #stopAssembly(): void { if (this.#assemblyTimer !== undefined) clearTimeout(this.#assemblyTimer); this.#assemblyTimer = undefined; this.#assembly = undefined; }
  #bodyAdmission(wait: ReceiveWait): boolean {
    const owner = this.#owner!, n = this.#length!, typed = !wait.encoded;
    const dependent = applicationHasCompletionAncestor(wait.context);
    let completion: CompletionReservation | undefined;
    try {
      if (dependent) {
        this.#dependencyDeadline ??= owner.deadline(30000n);
        this.#dependencyDeadline.check();
        if (typed && wait.claim?.active !== true) wait.claim = owner.application.claimCompletion(wait.context!);
        if (this.#dependencyTimer === undefined) {
          const tick = (): void => {
            try { this.#dependencyDeadline!.check(); this.#dependencyTimer = setTimeout(tick, timerChunk(this.#dependencyDeadline!.remainingMS())); }
            catch {
              this.#dependencyTimer = undefined;
              const current = this.#readWait;
              if (current !== undefined && current.context !== undefined) this.#rejectRead(current, "completion_dependency_unavailable");
            }
          }; tick();
        }
      }
      if (typed && this.#completion === undefined) completion = owner.application.reserveCompletion();
      if (this.#bodyReference === undefined) {
        const extra = typed ? (this.#inbound!.implementation === "utf8" ? BigInt(n) * 2n : 0n) + (this.#inbound!.application?.applicationBytes ?? 0n) + owner.runtimeBytes + 256n : 0n;
        const body = owner.admitBody(n, new ResourceVector([owner.runtimeBytes + 256n + extra, 0n, 0n, typed ? 2n : 1n, typed ? 1n : 0n, typed ? 1n : 0n, 0n, 0n, 0n, 0n, 0n]));
        this.#bodyReference = body.reference;
        this.#typedPrepaid = typed;
        this.#body = body.bytes;
      }
      if (typed && !this.#typedPrepaid && this.#typedReference === undefined) this.#typedReference = owner.reserve("v4_message_decode", new ResourceVector([
        (this.#inbound!.implementation === "utf8" ? BigInt(n) * 2n : 0n) + (this.#inbound!.application?.applicationBytes ?? 0n) + owner.runtimeBytes + 256n, 0n, 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n,
      ]));
      if (completion !== undefined) { this.#completion = completion; completion = undefined; }
      const observe = this.#resourceObserver; this.#resourceObserver = undefined; observe?.();
      this.#readAdmissionBlocked = false; owner.pauseCredit(false); return true;
    } catch (error) {
      completion?.close();
      wait.claim?.release(); wait.claim = undefined;
      if (dependent) { this.#rejectRead(wait, "completion_dependency_unavailable"); return false; }
      if (!(error instanceof ResourceError) || error.code !== "resource_exhausted") throw error;
      owner.pauseCredit(true);
      // No short cursor/borrow is held while waiting for a complete vector.
      owner.releaseReader();
      this.#readAdmissionBlocked = true;
      this.#resourceObserver ??= owner.observeResources(() => {
        if (this.#readRunning) { this.#readAdmissionBlocked = false; return; }
        this.#scheduleRead();
      }); return false;
    }
  }
  async #runRead(): Promise<void> {
    if (this.#readRunning) return; this.#readRunning = true;
    // A failed attempt's own temporary refunds are not new capacity. Subscribe
    // only after the attempt exits; subsequent owner transitions wake it once.
    const observe = this.#resourceObserver; this.#resourceObserver = undefined; observe?.();
    try {
      while (this.#readWait !== undefined && !this.#closed) {
        const owner = this.#checkRead();
        if (this.#readWait === undefined || this.#closed) break;
        if (this.#eof) { this.#deliverRead(); break; }
        if (this.#prefixBytes === 0 && this.#length === undefined) {
          try { owner.ensureReadQueue(); }
          catch (error) {
            if (!(error instanceof ResourceError) || error.code !== "resource_exhausted") throw error;
            owner.pauseCredit(true); owner.releaseReader(); this.#readAdmissionBlocked = true;
            this.#resourceObserver ??= owner.observeResources(() => {
              if (this.#readRunning) { this.#readAdmissionBlocked = false; return; }
              this.#scheduleRead();
            }); break;
          }
          this.#readAdmissionBlocked = false; owner.pauseCredit(false);
        }
        if (this.#prefixBytes === 4 && this.#length === undefined) {
          this.#length = new DataView(this.#prefix.buffer).getUint32(0);
          if (this.#length > this.#inbound!.maximum) { this.#fail("framing_error"); break; }
        }
        if (this.#length !== undefined && !this.#bodyAdmission(this.#readWait)) break;
        if (this.#length !== undefined && this.#filled === this.#length) {
          this.#stopAssembly(); owner.releaseReader();
          if (!this.#readWait.encoded && !this.#decoded) {
            const wait = this.#readWait, abort = this.#readAbort = new AbortController();
            let permit: ApplicationPermit | undefined;
            const check = (): void => {
              this.#check();
              if (this.#readWait !== wait || abort.signal.aborted) throw new Error("canceled");
              if (wait.context !== undefined) { applicationHasPermit(wait.context); if (applicationHasCompletionAncestor(wait.context)) this.#dependencyDeadline?.check(); }
            };
            try {
              permit = await this.#completion!.acquire(abort.signal, check, wait.context, wait.claim); wait.claim = undefined;
              check();
              const codec = this.#inbound!.application;
              if (codec === undefined) {
                try { this.#value = this.#inbound!.implementation === "bytes" ? this.#body : nativeDecode.call(utf8, this.#body); }
                catch { this.#fail("framing_error"); break; }
              } else {
                if (owner.authentication === undefined) throw new V4MessageStreamError("decode_failed");
                const decodeAbort = this.#decodeAbort = new AbortController();
                const invocation = owner.application.context(permit, owner.authentication, decodeAbort.signal);
                try {
                  check();
                  this.#decodeContext = invocation.context; this.#decoding = true;
                  this.#applicationInputDelivered = true; this.#readAbort = undefined;
                  try {
                    if (codec.execution === "sync") this.#value = codec.decode(invocation.context, this.#body);
                    else {
                      const output = codec.decode(invocation.context, this.#body);
                      this.#cleanup(); this.#value = await output;
                    }
                  } catch { this.#decodeFailed = true; }
                } finally {
                  invocation.release(); this.#decodeContext = undefined; this.#decodeAbort = undefined; this.#decoding = false;
                }
              }
              this.#decoded = true;
            } catch {
              if (this.#readWait === wait) this.#rejectRead(wait, "completion_dependency_unavailable");
              break;
            } finally { permit?.release(); if (this.#readAbort === abort) this.#readAbort = undefined; }
          }
          this.#deliverRead(); break;
        }
        const before = owner.readState();
        if (before.stream_status !== "open") {
          if (before.stream_status === "eof" && this.#prefixBytes === 0) { this.#eof = true; owner.releaseReader(); continue; }
          this.#fail("framing_error"); break;
        }
        const abort = this.#readAbort = new AbortController();
        await owner.readInto(this.#length === undefined ? 4 - this.#prefixBytes : this.#length - this.#filled, bytes => {
          if (this.#closed || abort.signal.aborted) return 0;
          if (this.#prefixBytes === 0) this.#startAssembly(); else this.#assembly?.check();
          const n = byteLength(bytes);
          if (this.#length === undefined) {
            copy.call(this.#prefix, bytes, this.#prefixBytes); this.#prefixBytes += n;
            if (this.#prefixBytes === 4) owner.pauseCredit(true);
          } else { copy.call(this.#body, bytes, this.#filled); this.#filled += n; if (this.#filled === this.#length) this.#stopAssembly(); }
          return n;
        }, abort.signal);
        this.#readAbort = undefined;
        const state = owner.readState();
        if (state.stream_status !== "open") {
          if (state.stream_status === "eof" && this.#prefixBytes === 0) { this.#eof = true; owner.releaseReader(); }
          else if (!(this.#ioEnded && this.#length !== undefined && this.#filled === this.#length) &&
              (state.stream_status !== "eof" || this.#prefixBytes < 4 || this.#length !== undefined && this.#filled < this.#length)) { this.#fail("framing_error"); break; }
          else if (this.#length === undefined && new DataView(this.#prefix.buffer).getUint32(0) !== 0) { this.#fail("framing_error"); break; }
        }
      }
    } catch {
      if (!this.#readAbort?.signal.aborted && !this.#closed) this.#fail("framing_error");
    } finally {
      this.#readAbort = undefined; this.#readRunning = false;
      if (this.#closed) { this.#owner?.releaseReader(); this.#clearBody(); }
      else if (this.#ioEnded) this.#owner?.releaseReader();
      this.#cleanup();
      // A replacement waiter may have arrived while the old native read exited.
      if (!this.#closed && this.#readWait !== undefined && !this.#readAdmissionBlocked) this.#scheduleRead();
    }
  }
  #deliverRead(): void {
    const wait = this.#readWait; if (wait === undefined || wait.signal?.aborted) return;
    this.#checkRead(); if (this.#readWait !== wait || wait.signal?.aborted || this.#closed) return;
    const value = this.#eof ? result({ done: true as const }) : result({ done: false as const, value: wait.encoded ? this.#body : this.#value, application_input_delivered: this.#applicationInputDelivered });
    wait.signal?.removeEventListener("abort", wait.canceled); wait.claim?.release(); wait.claim = undefined;
    const failed = this.#decodeFailed && !wait.encoded;
    this.#checkRead(); if (this.#readWait !== wait || wait.signal?.aborted || this.#closed) return;
    this.#handoff = true;
    try { if (failed) wait.reject(new V4MessageStreamError("decode_failed", undefined, this.#applicationInputDelivered)); else wait.resolve(value); }
    finally {
      // Reentrant host hooks cannot reclaim, zero, or deliver this same body.
      if (!this.#eof) this.#clearBody(!failed && (wait.encoded || this.#inbound!.implementation === "bytes"));
      this.#readWait = undefined; this.#handoff = false;
    }
  }
  #rejectRead(wait: ReceiveWait, reason: V4MessageFailure): void {
    if (this.#readWait !== wait) return;
    this.#readWait = undefined; wait.signal?.removeEventListener("abort", wait.canceled);
    wait.claim?.release(); wait.claim = undefined; this.#readAbort?.abort(); this.#owner?.releaseReader();
    if (this.#dependencyTimer !== undefined) clearTimeout(this.#dependencyTimer); this.#dependencyTimer = undefined;
    wait.reject(new V4MessageStreamError(reason, undefined, this.#applicationInputDelivered));
  }
  #clearBody(delivered = false): void {
    this.#stopAssembly();
    if (this.#dependencyTimer !== undefined) clearTimeout(this.#dependencyTimer); this.#dependencyTimer = undefined; this.#dependencyDeadline = undefined;
    if (!delivered && !this.#applicationInputDelivered) this.#body.fill(0);
    this.#body = empty; this.#value = undefined; this.#bodyReference?.release(); this.#bodyReference = undefined;
    this.#typedReference?.release(); this.#typedReference = undefined;
    this.#completion?.close(); this.#completion = undefined;
    this.#length = undefined; this.#filled = 0; this.#prefixBytes = 0; this.#prefix.fill(0); this.#decoded = this.#decodeFailed = this.#typedPrepaid = this.#applicationInputDelivered = false;
  }

  closeWrite(options?: OperationOptions): Promise<V4CloseResult> {
    if (this.#fin === undefined) {
      try {
        const owner = this.#check(); this.#sealed = true; this.#finDeadline = owner.deadline(this.#options.sendTimeoutMS);
        this.#fin = new NativePromise((resolve, reject) => { this.#finResolve = resolve; this.#finReject = reject; });
        void this.#fin.catch(() => undefined);
        const expire = (): void => {
          try { this.#finDeadline!.check(); this.#finTimer = setTimeout(expire, timerChunk(this.#finDeadline!.remainingMS())); }
          catch { this.#finTimer = undefined; this.#fail("deadline_exceeded"); }
        }; expire(); this.#publish();
      } catch { return Promise.reject(new V4MessageStreamError(this.#failure ?? "closed")); }
    }
    return this.#wait(this.#fin, options);
  }
  #startFIN(): void {
    if (this.#fin === undefined || this.#finStarted || this.#closed) return; this.#finStarted = true;
    void this.#owner!.closeWrite().then(value => {
      if (this.#finTimer !== undefined) clearTimeout(this.#finTimer); this.#finTimer = undefined;
      this.#finResult = value;
      this.#finResolve?.(value); this.#finResolve = this.#finReject = undefined; this.#cleanup();
    }, () => this.#fail("write_failed"));
  }
  finish(options?: OperationOptions): Promise<V4CloseResult> {
    if (this.#finish === undefined) {
      this.#finish = this.closeWrite().then(async () => {
        if (this.#owner === undefined && this.#failure === undefined && this.#finResult !== undefined) return result({ ...this.#finResult, send_drained: true, read_terminal: "eof" as const, cleanup_status: complete });
        this.#check(); const value = await this.#owner!.finish(); this.#finResult = value; return value;
      }); void this.#finish.catch(() => undefined);
    }
    return this.#wait(this.#finish, options);
  }
  close(options?: V4ApplicationWaitOptions): Promise<V4CloseResult> {
    this.#fail("closed");
    return this.waitCleanup(options).then(cleanup => result({ ...(this.#closeResult ?? { direction: this.#direction, send_drained: false, read_terminal: "abandoned" as const }), cleanup_status: cleanup }));
  }
  #fail(reason: V4MessageFailure): void {
    if (this.#closed) return; this.#closed = true; this.#sealed = true; this.#failure = reason;
    this.#stopAssembly(); this.#resourceObserver?.(); this.#resourceObserver = undefined;
    this.#readAbort?.abort(); this.#decodeAbort?.abort();
    const wait = this.#readWait;
    if (!this.#handoff) {
      this.#readWait = undefined;
      if (wait !== undefined) { wait.signal?.removeEventListener("abort", wait.canceled); wait.claim?.release(); wait.claim = undefined; wait.reject(new V4MessageStreamError(reason, undefined, this.#applicationInputDelivered)); }
    }
    for (const entry of this.#actualSends) {
      entry.revoked = true; entry.reason = reason; entry.abort.abort(); entry.request?.cancel(); this.#settleSend(entry, reason);
      if (!entry.running) this.#releaseSend(entry);
    }
    this.#sends.length = 0;
    if (this.#finTimer !== undefined) clearTimeout(this.#finTimer); this.#finTimer = undefined;
    this.#finReject?.(new V4MessageStreamError(reason)); this.#finReject = this.#finResolve = undefined;
    if (!this.#readRunning) { this.#owner?.releaseReader(); this.#clearBody(); }
    if (this.#owner !== undefined) {
      try { this.#cleanupDeadline = this.#owner.deadline(this.#options.cleanupTimeoutMS); } catch { this.#cleanupIncomplete = true; }
      this.#closeRunning = true;
      this.#closeTail = this.#owner.reset().then(value => { this.#closeResult = value; }, () => undefined).finally(() => { this.#closeRunning = false; this.#cleanup(); });
      const expire = (): void => {
        try { this.#cleanupDeadline!.check(); this.#cleanupTimer = setTimeout(expire, timerChunk(this.#cleanupDeadline!.remainingMS())); }
        catch { this.#cleanupTimer = undefined; this.#cleanupIncomplete = true; this.#notify(); }
      }; if (this.#cleanupDeadline !== undefined) expire();
    }
    this.#cleanup();
  }
  #cleanup(): void {
    if (this.#owner === undefined || this.#cleaning) return;
    this.#cleaning = true;
    try { this.#collect(); } finally { this.#cleaning = false; }
  }
  #collect(): void {
    if (this.#owner === undefined) return;
    if (this.#ioEnded && !this.#ioDetached && (!this.#readRunning || this.#decoding) && !this.#closeRunning &&
        [...this.#actualSends].every(entry => entry.preparing) && this.#owner.cleanupStatus().status === "complete") {
      this.#ioDetached = true; this.#owner.detachIO();
    }
    if (this.#ioDetached && this.#applicationInputDelivered) this.#owner.releaseDelivery();
    if (this.#ioEnded && this.#length === undefined && !this.#handoff) this.#closed = true;
    const natural = this.#eof && this.#finResult !== undefined && this.#sends.length === 0;
    if ((!this.#closed && !natural) || this.#handoff || this.#readRunning || this.#publishing || this.#closeRunning || this.#actualSends.size !== 0 || this.#waits !== 0 || this.#owner.cleanupStatus().status !== "complete") { this.#notify(); return; }
    this.#closed = true; this.#sealed = true;
    this.#resourceObserver?.(); this.#resourceObserver = undefined;
    if (this.#cleanupTimer !== undefined) clearTimeout(this.#cleanupTimer); this.#cleanupTimer = undefined;
    const owner = this.#owner; this.#owner = undefined; owner.release(); this.#definition = undefined; this.#prepared = undefined; this.#inbound = this.#outbound = undefined;
    this.#cleanupDeadline = this.#finDeadline = undefined; this.#notify();
  }
  #notify(): void { for (const wake of this.#observers) wake(); }
  cleanupStatus(): V4CleanupStatus {
    if (this.#owner === undefined) return complete;
    return result({ status: this.#cleanupIncomplete ? "cleanup_incomplete" : "pending", core_cleanup: this.#owner.cleanupStatus().core_cleanup,
      pending_callbacks: BigInt(this.#actualSends.size + Number(this.#readRunning) + Number(this.#publishing) + Number(this.#closeRunning)) });
  }
  #wait<T>(operation: Promise<T>, options?: OperationOptions): Promise<T> {
    if (options?.signal?.aborted) return Promise.reject(new V4MessageStreamError("canceled"));
    if (this.#owner === undefined) return operation;
    if (this.#waits >= 32) return Promise.reject(new V4MessageStreamError("resource_exhausted"));
    let reference: ResourceReference;
    try { reference = this.#owner.reserve("v4_message_wait", new ResourceVector([this.#owner.runtimeBytes + 128n, 0n, 0n, 1n, 0n, 1n, 0n, 0n, 0n, 0n, 0n])); }
    catch { return Promise.reject(new V4MessageStreamError("resource_exhausted")); }
    this.#waits++;
    return new NativePromise((resolve, reject) => {
      let done = false;
      const finish = (): boolean => { if (done) return false; done = true; options?.signal?.removeEventListener("abort", cancel); return true; };
      const release = (): void => { this.#waits--; reference.release(); this.#cleanup(); };
      const cancel = (): void => { if (finish()) reject(new V4MessageStreamError("canceled")); };
      options?.signal?.addEventListener("abort", cancel, { once: true });
      // An uncancelable native Promise reaction remains a real retained tail.
      // Cancel detaches only the public wait; its slot is refunded on reaction exit.
      void operation.then(value => { try { if (finish()) resolve(value); } finally { release(); } }, () => {
        try { if (finish()) reject(new V4MessageStreamError(this.#failure ?? "write_failed")); } finally { release(); }
      });
    });
  }
  waitCleanup(options?: V4ApplicationWaitOptions): Promise<V4CleanupStatus> {
    try {
      if (applicationDependsOn(options?.context, this.#decodeContext) || [...this.#actualSends].some(entry => applicationDependsOn(options?.context, entry.applicationContext))) {
        return Promise.reject(new V4MessageStreamError("dependency_unavailable", undefined, this.#applicationInputDelivered));
      }
    } catch { return Promise.reject(new V4MessageStreamError("dependency_unavailable", undefined, this.#applicationInputDelivered)); }
    const initial = this.cleanupStatus(); if (initial.status !== "pending") return Promise.resolve(initial);
    if (options?.signal?.aborted) return Promise.reject(new V4MessageStreamError("canceled"));
    if (this.#cleanupWaits >= 32) return Promise.reject(new V4MessageStreamError("resource_exhausted"));
    const owner = this.#owner!;
    let deadline: TrustedDeadline, reference: ResourceReference;
    try {
      deadline = owner.deadline(this.#options.cleanupTimeoutMS);
      reference = owner.reserve("v4_message_cleanup_wait", new ResourceVector([owner.runtimeBytes + 256n, 0n, 0n, 1n, 0n, 1n, 1n, 0n, 0n, 0n, 0n]));
    } catch { return Promise.reject(new V4MessageStreamError("resource_exhausted")); }
    this.#cleanupWaits++;
    return new NativePromise<V4CleanupStatus>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      let done = false;
      const finish = (canceled = false): void => {
        if (done) return; done = true;
        if (timer !== undefined) clearTimeout(timer); this.#observers.delete(wake); options?.signal?.removeEventListener("abort", cancel);
        this.#cleanupWaits--; reference.release();
        if (canceled) reject(new V4MessageStreamError("canceled")); else resolve(this.cleanupStatus());
      };
      const cancel = (): void => finish(true);
      const wake = (): void => { if (this.cleanupStatus().status !== "pending") finish(); };
      const tick = (): void => { try { deadline.check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); } catch { finish(); } };
      this.#observers.add(wake); options?.signal?.addEventListener("abort", cancel, { once: true });
      if (options?.signal?.aborted) cancel(); else { wake(); if (!done) tick(); }
    });
  }
}

/** Low-level conversion requires an untouched accepted Stream whose OPEN
 * already contains the exact definition binding. */
export function asTypedMessages<A, B>(stream: V4StreamOwner, definition: V4MessageStreamDefinition<A, B>, options: V4MessageStreamOptions = {}): V4TypedMessageStream<A | B, A | B> {
  messageDefinition(definition);
  const fixed = captureMessageOptions(options), owner = acquireMessageStreamAdapter(stream, messageAdapterProfile(fixed));
  try { const candidate = prepareTypedMessages(definition, fixed); candidate.bind(token, owner); return candidate as V4TypedMessageStream<A | B, A | B>; }
  catch (error) { owner.rollback(); throw error; }
}
/** Internal candidate construction occurs before OPEN and application delivery. */
export function prepareTypedMessages(definition: object, options: V4MessageStreamOptions): V4TypedMessageStream<unknown, unknown> {
  return new V4TypedMessageStream(token, definition, options);
}
export function prepareMessageBinding(candidate: V4TypedMessageStream<unknown, unknown>, context: Pick<MessageStreamAdapterOwner, "kind" | "localOpener" | "metadata" | "runtimeBytes" | "reserve">): void {
  candidate.prepare(token, context);
}
export function bindTypedMessages(candidate: V4TypedMessageStream<unknown, unknown>, stream: V4StreamOwner, options: V4MessageStreamOptions, prepaid: ResourceReference, preaccepted = false): void {
  const owner = acquireMessageStreamAdapter(stream, { ...messageAdapterProfile(captureMessageOptions(options), prepaid), preaccepted });
  try { candidate.bind(token, owner); } catch (error) { owner.rollback(); throw error; }
}
