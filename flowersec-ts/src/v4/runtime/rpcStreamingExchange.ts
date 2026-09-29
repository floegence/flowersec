import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { applicationDependsOn, applicationHasCompletionAncestor, applicationHasPermit, type ApplicationPermit, type CompletionClaim } from "./applicationExecutor.js";
import { V4ReadMethodError } from "../public.js";
import { TimeError } from "./timeArithmetic.js";
import { CBORDecoder, cborDecoderCharge } from "./cbor.js";
import { TrustedWindow, timerChunk } from "./deadline.js";
import type { TrustedClock } from "./clock.js";
import { cleanupResult } from "./lifecycle.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { RPCCompletion, type RPCSDKError } from "./rpcCompletion.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCNetwork, RPCNetworkTicket } from "./rpcNetwork.js";
import type { RPCPayloadBorrow } from "./rpcPayload.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { ResourceReference } from "./resources.js";
import { rpcUnaryExchangeCharges } from "./rpcUnaryExchange.js";
import type { RPCUnaryTransfer } from "./rpcUnaryPreparation.js";
import type { RPCStreamMessages } from "./rpcStreamMessages.js";

export interface RPCStreamingStatus {
  readonly state: "opening" | "streaming" | "complete" | "failed" | "closed";
  readonly submission: "not_submitted" | "submitted";
  readonly deliveredItems: bigint;
  readonly deliveredBytes: bigint;
  readonly payloadStatus: "pending" | "available" | "host_handoff_committed" | "already_delivered" | "result_abandoned" | "payload_unavailable";
  readonly applicationInputDelivered: boolean;
  readonly deliveryWait?: "time_pending" | "time_unavailable";
  readonly failure?: string;
}
export interface RPCStreamingAbandonResult {
  readonly outcome: "not_started" | "host_handoff_committed" | "already_delivered" | "result_abandoned";
  readonly status: RPCStreamingStatus;
  readonly cleanup: V4CleanupStatus;
}
export type RPCStreamingItem = Readonly<{ kind: "end"; status: RPCStreamingStatus }> |
  Readonly<{ kind: "sdk_error"; code: RPCSDKError; header: ApplicationHeader }> |
  Readonly<{ kind: "value" | "application_error"; header: ApplicationHeader; encoding: "encoded"; bytes: Uint8Array; schemaDigest: Uint8Array; codecRevision: string; release(): void }> |
  Readonly<{ kind: "value"; header: ApplicationHeader; encoding: "typed"; value: unknown; schemaDigest: Uint8Array; codecRevision: string; release(): void }> |
  Readonly<{ kind: "application_error"; header: ApplicationHeader; encoding: "typed"; error: unknown; schemaDigest: Uint8Array; codecRevision: string; release(): void }>;
export interface RPCStreamingReadOptions { readonly signal?: AbortSignal; readonly context?: V4ApplicationContext; }
export type RPCStreamingIteration = IteratorResult<Exclude<RPCStreamingItem, { kind: "end" }>, undefined>;
interface Recipient {
  readonly id: bigint; readonly iterator: boolean; readonly settled: ((terminal: boolean) => void) | undefined;
  readonly encoded: boolean; readonly signal: AbortSignal | undefined; readonly context: V4ApplicationContext | undefined;
  readonly resolve: (value: RPCStreamingItem | RPCStreamingIteration) => void; readonly reject: (error: unknown) => void; readonly cancel: () => void;
  claim: CompletionClaim | undefined;
  armed: boolean; committed: boolean;
}
const errorConfig = (runtimeBytes: bigint) => ({ bytes: 256, nodes: 8, textBytes: 0, arrayItems: 1, runtimeBytes });
export const rpcStreamingErrorCharge = (runtimeBytes: bigint) => cborDecoderCharge(errorConfig(runtimeBytes));
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const decodeUTF8 = TextDecoder.prototype.decode;
const NativePromise = Promise, enqueue = queueMicrotask;
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const addListener = EventTarget.prototype.addEventListener, removeListener = EventTarget.prototype.removeEventListener;
function aborted(signal?: AbortSignal): boolean { return signal !== undefined && signalAborted.call(signal) as boolean; }
function listen(signal: AbortSignal | undefined, callback: () => void): void { if (signal !== undefined) addListener.call(signal, "abort", callback, { once: true }); }
function unlisten(signal: AbortSignal | undefined, callback: () => void): void { if (signal !== undefined) removeListener.call(signal, "abort", callback); }
function shell<T extends object>(value: T): Readonly<T> { Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value); }
function timeSuspension(error: unknown): "time_pending" | "time_unavailable" | undefined {
  const code = error instanceof TimeError ? error.code : error instanceof V4ReadMethodError ? error.reason : undefined;
  return code === "time_pending" ? "time_pending" : code === "time_unavailable" || code === "time_continuity" ? "time_unavailable" : undefined;
}
function resultFor(wait: Recipient, value: RPCStreamingItem): RPCStreamingItem | RPCStreamingIteration {
  return !wait.iterator ? value : value.kind === "end" ? shell({ done: true as const, value: undefined }) : shell({ done: false as const, value });
}

/** One dedicated call and one current result candidate. Status observation
 * never advances the reader. The final native Promise recipient, not an
 * internal async helper, is the only application payload handoff. */
export class RPCStreamingExchange {
  #reference: ResourceReference | undefined;
  #transfer: Omit<RPCUnaryTransfer, "guard" | "references"> | undefined;
  #guard: RPCPublicationGuard | undefined;
  #messages: RPCStreamMessages | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #response: RPCCompletion | undefined;
  #errors: CBORDecoder | undefined;
  #reserveResult: (() => ResourceReference) | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #claim: CompletionClaim | undefined;
  #borrow: RPCPayloadBorrow | undefined;
  #value: unknown;
  #decoded = false;
  #entered = false;
  #decoding = false;
  #decodeAbort: AbortController | undefined;
  #decodeContext: V4ApplicationContext | undefined;
  #applicationInputDelivered = false;
  #delivering = false;
  #creatingRecipient = false;
  #nextRecipient = 0n;
  #reading = false;
  #opening = false;
  #finishing = false;
  #networkEnded = false;
  #detached = false;
  #collecting = false;
  #scheduled = false;
  #recipient: Recipient | undefined;
  #statusWait: Readonly<{ resolve: (status: RPCStreamingStatus) => void; signal?: AbortSignal; cancel: () => void }> | undefined;
  #creatingStatus = false;
  #readAbort: AbortController | undefined;
  readonly #abort = new AbortController();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #state: RPCStreamingStatus["state"] = "opening";
  #submitted = false;
  #terminal = false;
  #terminalDelivered = false;
  #closed = false;
  #abandoned = false;
  #abandonAfterDelivery = false;
  #failure: string | undefined;
  #receivedItems = 0n;
  #receivedBytes = 0n;
  #deliveredItems = 0n;
  #deliveredBytes = 0n;
  #cleaned: (() => void) | undefined;
  #networkCleaned: (() => void) | undefined;
  #clock: TrustedClock | undefined;
  #cleanupWindow: TrustedWindow | undefined;
  #cleanupIncomplete = false;
  #cleanupWait: (() => void) | undefined;
  #creatingCleanup = false;
  #deliveryWait: RPCStreamingStatus["deliveryWait"];
  #authorizationEnded = false;
  readonly #runtimeBytes: bigint;
  constructor(transfer: RPCUnaryTransfer, messages: RPCStreamMessages, runtimeBytes: bigint, errorReference: ResourceReference,
    delivery: ReceiveDeliveryGate, authentication: V4AuthenticatedContext, reserveResult: () => ResourceReference, claim: CompletionClaim | undefined,
    clock: TrustedClock, lease?: ReturnType<ReceiveDeliveryGate["retain"]>) {
    if (transfer.method.shape !== "server_streaming" || transfer.completionDeadline === undefined) throw new RPCProtocolError("rpc_request_binding");
    this.#runtimeBytes = runtimeBytes; this.#clock = clock;
    const { guard, references, ...resultTransfer } = transfer;
    this.#transfer = resultTransfer; this.#guard = guard; this.#messages = messages; this.#claim = claim;
    this.#reference = references[0]!.take(rpcUnaryExchangeCharges(transfer.header.payloadBytes, Number(transfer.header.uint(8)), runtimeBytes, transfer.method)[0]!);
    this.#authentication = authentication; this.#reserveResult = reserveResult;
    transfer.contract.retain();
    try {
      this.#response = new RPCCompletion(transfer.header, Number(transfer.header.uint(8)), runtimeBytes, references[1]!, transfer.contract);
      this.#errors = new CBORDecoder(errorConfig(runtimeBytes), errorReference);
      this.#lease = lease ?? delivery.retain(this.#reference, () => this.authorizationClosed());
      messages.onChange(() => { this.#observeTerminal(); this.#schedule(); this.#collect(); });
      this.#tick(); Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  start(network: RPCNetwork, ticket: RPCNetworkTicket, open: (signal: AbortSignal) => Promise<void>): void {
    if (this.#opening || this.#state !== "opening") throw new RPCProtocolError("rpc_stream_owner");
    this.#opening = true; void this.#open(network, ticket, open);
  }
  async #open(network: RPCNetwork, ticket: RPCNetworkTicket, open: (signal: AbortSignal) => Promise<void>): Promise<void> {
    let borrow: RPCPayloadBorrow | undefined;
    try {
      await open(this.#abort.signal); this.#check(); this.#guard!.check();
      borrow = this.#transfer!.request.borrow(this.#transfer!.header.payloadBytes);
      await this.#messages!.send(this.#transfer!.header, borrow.bytes, () => { this.#check(); this.#guard!.check(); }, () => {
        this.#submitted = true; this.#guard!.admitted?.();
      });
      await this.#messages!.closeWrite(); network.completeStreamRequest(ticket, this.#messages!);
      this.#state = "streaming";
    } catch (error) { if (!this.#closed) this.#fail(error instanceof Error ? error.message : "stream_failed"); }
    finally { borrow?.release(); this.#transfer?.request.close(); this.#guard = undefined; this.#opening = false; this.#observeTerminal(); this.#schedule(); this.#collect(); }
  }
  #check(): void {
    if (this.#closed || this.#reference === undefined) throw new RPCProtocolError(this.#failure ?? "rpc_stream_closed");
    this.#reference.checkRetained();
    if (!this.#entered) {
      if (this.#authorizationEnded) throw new RPCProtocolError("source_unavailable");
      this.#lease!.check();
    }
    if (!this.#terminal) (this.#submitted ? this.#transfer!.completionDeadline! : this.#transfer!.deadline).check();
    if (this.#closed) throw new RPCProtocolError("rpc_stream_closed");
  }
  readonly #tick = (): void => {
    this.#timer = undefined; if (this.#closed || this.#terminal && this.#deliveryWait === undefined) return;
    try {
      this.#observeTerminal(); if (this.#closed) return;
      this.#check(); this.#deliveryWait = undefined; this.#schedule();
      if (!this.#terminal) this.#timer = setTimeout(this.#tick, timerChunk((this.#submitted ? this.#transfer!.completionDeadline! : this.#transfer!.deadline).remainingMS()));
    } catch (error) {
      if (this.#suspend(error)) return;
      if (!this.#closed) { this.#abandoned = this.#submitted; this.#fail(this.#submitted ? "completion_deadline" : "deadline_exceeded"); }
    }
  };
  #suspend(error: unknown): boolean {
    const reason = timeSuspension(error); if (reason === undefined || this.#closed) return false;
    this.#deliveryWait = reason; this.#stopTimer(); this.#timer = setTimeout(this.#tick, 1000); return true;
  }
  #observeTerminal(): void {
    if (this.#closed || this.#messages === undefined || this.#state === "opening") return;
    if (!this.#terminal && this.#messages.eof) {
      this.#terminal = true; this.#state = "complete"; if (this.#deliveryWait === undefined) this.#stopTimer(); this.#notifyStatus();
    }
    if (this.#messages.ioEnded && !this.#networkEnded) this.networkClosed();
    if (this.#terminal && this.#messages.eof) this.#finishIO();
  }
  #finishIO(terminalError = false): void {
    if (this.#networkEnded || this.#finishing || this.#reading || this.#opening || this.#messages === undefined) return;
    this.#networkEnded = this.#finishing = true; this.#reserveResult = undefined;
    const messages = this.#messages;
    void (terminalError ? messages.finishTerminal() : messages.finish()).catch(() => undefined).finally(() => {
      messages.close(); this.#finishing = false; this.#collect(); this.#schedule();
    });
  }
  /** Normal Session I/O shutdown preserves a complete owned candidate. The
   * independent delivery lease still enforces authorization and Environment. */
  networkClosed(): void {
    if (this.#closed || this.#networkEnded) return;
    this.#networkEnded = true; this.#reserveResult = undefined;
    if (!this.#terminal && this.#response?.progress().done !== true) { this.#fail("stream_closed"); return; }
    if (!this.#terminal) { this.#terminal = true; this.#state = this.#messages?.eof ? "complete" : "failed"; if (this.#state === "failed") this.#failure ??= "stream_closed"; }
    this.#stopTimer(); this.#messages?.close(); this.#notifyStatus(); this.#schedule(); this.#collect();
  }
  status(): RPCStreamingStatus {
    this.#observeTerminal(); return shell({ state: this.#state, submission: this.#submitted ? "submitted" : "not_submitted",
      deliveredItems: this.#deliveredItems, deliveredBytes: this.#deliveredBytes,
      payloadStatus: this.#delivering ? "host_handoff_committed" : this.#terminalDelivered ? "already_delivered" : this.#abandoned ? "result_abandoned" :
        this.#closed ? "payload_unavailable" : this.#response?.progress().done ? "available" : "pending",
      ...(this.#deliveryWait === undefined ? {} : { deliveryWait: this.#deliveryWait }),
      applicationInputDelivered: this.#applicationInputDelivered, ...(this.#failure === undefined ? {} : { failure: this.#failure }) });
  }
  waitStatus(signal?: AbortSignal): Promise<RPCStreamingStatus> {
    if (this.#statusWait !== undefined || this.#creatingStatus) throw new RPCProtocolError("wait_in_progress");
    aborted(signal); this.#creatingStatus = true;
    try {
      let resolve!: (status: RPCStreamingStatus) => void, reject!: (error: unknown) => void;
      const promise = new NativePromise<RPCStreamingStatus>((yes, no) => { resolve = yes; reject = no; });
      const cancel = (): void => { if (this.#statusWait !== wait) return; this.#statusWait = undefined; unlisten(signal, cancel); reject(new RPCProtocolError("wait_canceled")); };
      const wait = { resolve, cancel, ...(signal === undefined ? {} : { signal }) }; this.#statusWait = wait;
      listen(signal, cancel);
      enqueue(() => { if (aborted(signal)) cancel(); else { this.#observeTerminal(); this.#notifyStatus(); } });
      return promise;
    } finally { this.#creatingStatus = false; }
  }
  #notifyStatus(): void {
    if (!this.#terminal && !this.#closed || this.#statusWait === undefined) return;
    if (this.#creatingStatus) return;
    const wait = this.#statusWait; this.#statusWait = undefined; unlisten(wait.signal, wait.cancel); wait.resolve(this.status());
  }
  readNext(encoded: boolean, options: RPCStreamingReadOptions = {}): Promise<RPCStreamingItem> {
    return this.#readRecipient(encoded, false, options) as Promise<RPCStreamingItem>;
  }
  /** The iterator passes its final native Promise recipient to this owner;
   * no helper Promise first consumes the item or awaits an application value. */
  readIteration(options: RPCStreamingReadOptions, settled: (terminal: boolean) => void): Promise<RPCStreamingIteration> {
    return this.#readRecipient(false, true, options, settled) as Promise<RPCStreamingIteration>;
  }
  checkReaderAvailable(): void {
    if (this.#recipient !== undefined || this.#creatingRecipient || this.#delivering) throw new RPCProtocolError("read_in_progress");
  }
  #readRecipient(encoded: boolean, iterator: boolean, options: RPCStreamingReadOptions, settled?: (terminal: boolean) => void): Promise<RPCStreamingItem | RPCStreamingIteration> {
    if (applicationDependsOn(options.context, this.#decodeContext)) throw new RPCProtocolError("dependency_unavailable");
    this.checkReaderAvailable(); this.#creatingRecipient = true;
    let claim: CompletionClaim | undefined;
    try {
    const { signal, context } = options; aborted(signal);
    if (!encoded && !this.#closed && !this.#terminalDelivered && !this.#entered && !this.#claim?.active && applicationHasCompletionAncestor(context)) {
      claim = this.#transfer!.completion.group.claimCompletion(context!);
    }
    let resolve!: Recipient["resolve"], reject!: Recipient["reject"];
    const promise = new NativePromise<RPCStreamingItem | RPCStreamingIteration>((yes, no) => { resolve = yes; reject = no; });
    const recipient: Recipient = { id: ++this.#nextRecipient, iterator, settled, encoded, signal, context, resolve, reject, claim, armed: false, committed: false,
      cancel: () => { if (recipient.committed || this.#recipient !== recipient) return;
        this.#finishWait(undefined, new RPCProtocolError("wait_canceled")); if (!this.#entered) { this.#readAbort?.abort(); this.#decodeAbort?.abort(); } } };
    this.#recipient = recipient; claim = undefined;
    listen(signal, recipient.cancel);
    this.#schedule(); recipient.armed = true; return promise;
    } finally { claim?.release(); this.#creatingRecipient = false; }
  }
  #schedule(): void {
    if (this.#scheduled) return; this.#scheduled = true;
    enqueue(() => { this.#scheduled = false; this.#pump(); });
  }
  #finishWait(value?: RPCStreamingItem, error?: unknown): void {
    const wait = this.#recipient; if (wait === undefined || wait.committed) return;
    const result = value === undefined ? undefined : resultFor(wait, value);
    this.#recipient = undefined; unlisten(wait.signal, wait.cancel); wait.claim?.release(); wait.claim = undefined;
    if (error !== undefined) wait.reject(error); else wait.resolve(result!);
    wait.settled?.(true); this.#collect();
  }
  #pump(): void {
    const wait = this.#recipient; if (wait === undefined || !wait.armed || wait.committed) { this.#collect(); return; }
    if (aborted(wait.signal)) { wait.cancel(); return; }
    if (this.#closed || this.#terminalDelivered) { this.#finishWait(shell({ kind: "end", status: this.status() })); return; }
    if (this.#terminal && !this.#response?.progress().done) {
      this.#terminalDelivered = true; this.#finishWait(shell({ kind: "end", status: this.status() })); this.close(); return;
    }
    if (this.#deliveryWait !== undefined) return;
    if (this.#opening || this.#state === "opening") return;
    try {
      this.#check(); if (wait.context !== undefined) applicationHasPermit(wait.context);
      if (wait.encoded && this.#entered) { this.#finishWait(undefined, new RPCProtocolError("result_mode_conflict")); return; }
      if (wait.encoded && this.#decoding) { this.#decodeAbort?.abort(); return; }
      if (this.#reading || this.#decoding) return;
      const progress = this.#response?.progress();
      if (!progress?.done) {
        if (this.#terminal) { this.#terminalDelivered = true; this.#finishWait(shell({ kind: "end", status: this.status() })); this.close(); return; }
        void this.#read(); return;
      }
      if (progress.sdkError === undefined && !wait.encoded && !this.#decoded) { void this.#decode(wait.id, wait.signal, wait.context); return; }
      this.#deliver(wait);
    } catch (error) { if (!this.#suspend(error)) this.#finishWait(undefined, error); }
  }
  async #read(): Promise<void> {
    this.#reading = true; this.#readAbort = new AbortController();
    try {
      if (this.#response === undefined) {
        const reference = this.#reserveResult!();
        try { this.#response = new RPCCompletion(this.#transfer!.header, Number(this.#transfer!.header.uint(8)), this.#runtimeBytes, reference, this.#transfer!.contract); }
        finally { reference.release(); }
      }
      const response = this.#response;
      const header = await this.#messages!.read(value => {
        response.begin(value);
        if (!value.isSDKError() && !value.isApplicationError() &&
            (this.#receivedItems >= this.#transfer!.contract.uint(24) || BigInt(value.payloadBytes) > this.#transfer!.contract.uint(25) - this.#receivedBytes)) throw new RPCProtocolError("application_stream_limit");
        return { write: (offset, bytes) => response.write(offset, bytes), finish: () => response.finish(this.#errors!, { requestAborted: false, stopSent: false }) };
      }, this.#readAbort.signal);
      if (header === undefined) { this.#terminal = true; this.#state = "complete"; this.#stopTimer(); this.#notifyStatus(); }
      else if (header.isSDKError() || header.isApplicationError()) { this.#terminal = true; this.#state = "complete"; this.#stopTimer(); this.#notifyStatus(); }
    } catch (error) {
      if (!this.#readAbort.signal.aborted && !this.#closed && !this.#suspend(error)) this.#fail(error instanceof Error ? error.message : "stream_failed");
    } finally {
      this.#readAbort = undefined; this.#reading = false;
      const header = this.#response?.progress().header;
      if (!this.#closed && this.#terminal && header !== undefined && (header.isSDKError() || header.isApplicationError()) && !this.#networkEnded) {
        this.#messages!.consume(); this.#finishIO(true);
      } else this.#observeTerminal();
      this.#schedule(); this.#collect();
    }
  }
  async #decode(id: bigint, signal: AbortSignal | undefined, context: V4ApplicationContext | undefined): Promise<void> {
    this.#decoding = true; let permit: ApplicationPermit | undefined;
    const abort = this.#decodeAbort = new AbortController(); let entered = false;
    try {
      const check = (): void => { this.#check(); if (abort.signal.aborted) throw new RPCProtocolError("wait_canceled"); if (context !== undefined) applicationHasPermit(context); };
      const recipient = this.#recipient, claim = this.#claim?.active ? this.#claim : recipient?.claim;
      permit = await this.#transfer!.completion.acquire(signal === undefined ? abort.signal : AbortSignal.any([signal, abort.signal]), check, context, claim?.active ? claim : undefined);
      if (recipient !== undefined) { recipient.claim?.release(); recipient.claim = undefined; }
      this.#claim = undefined; check();
      if (aborted(signal) || this.#recipient?.id !== id || this.#recipient.encoded) return;
      const header = this.#response!.progress().header!, method = this.#transfer!.method;
      const codec = header.isApplicationError() ? method.errors.find(error => BigInt(error.code) === header.uint(10))?.codec : method.response;
      if (codec === undefined) throw new RPCProtocolError("application_error_code");
      this.#borrow = this.#response!.borrow(); const bytes = this.#borrow.bytes;
      context = undefined; signal = undefined;
      if (codec.application === undefined) { entered = true; this.#value = codec.implementation === "bytes" ? bytes : decodeUTF8.call(utf8, bytes); }
      else {
        const invocation = this.#transfer!.completion.group.context(permit, this.#authentication!, abort.signal);
        try {
          check(); this.#decodeContext = invocation.context; entered = this.#entered = this.#applicationInputDelivered = true;
          this.#value = codec.application.execution === "sync" ? codec.application.decode(invocation.context, bytes) : await codec.application.decode(invocation.context, bytes);
        } finally { this.#decodeContext = undefined; invocation.release(); }
      }
      this.#decoded = true;
    } catch (error) {
      if (entered && !this.#closed) this.#fail("decode_failed");
      else if (!abort.signal.aborted && this.#recipient?.id === id && !this.#suspend(error)) this.#finishWait(undefined, error);
    } finally {
      permit?.release(); this.#decodeAbort = undefined; this.#decoding = false;
      if (!this.#decoded || this.#closed) { this.#value = undefined; this.#borrow?.release(); this.#borrow = undefined; }
      this.#schedule(); this.#collect();
    }
  }
  #deliver(wait: Recipient): void {
    const header = this.#response!.progress().header!, code = this.#response!.progress().sdkError;
    let result: RPCStreamingItem;
    if (code !== undefined) result = shell({ kind: "sdk_error", code, header });
    else {
      const method = this.#transfer!.method, codec = header.isApplicationError() ? method.errors.find(error => BigInt(error.code) === header.uint(10))!.codec : method.response!;
      this.#borrow ??= this.#response!.borrow(); const { bytes, release } = this.#borrow;
      const shared = { header, schemaDigest: new Uint8Array(codec.schema), codecRevision: codec.revision, release };
      result = wait.encoded ? shell({ ...shared, kind: header.isApplicationError() ? "application_error" : "value", encoding: "encoded" as const, bytes })
        : header.isApplicationError() ? shell({ ...shared, kind: "application_error" as const, encoding: "typed" as const, error: this.#value })
        : shell({ ...shared, kind: "value" as const, encoding: "typed" as const, value: this.#value });
    }
    const finalResult = resultFor(wait, result);
    unlisten(wait.signal, wait.cancel); this.#check(); if (wait.context !== undefined) applicationHasPermit(wait.context);
    if (this.#closed || this.#recipient !== wait || aborted(wait.signal)) { this.#schedule(); return; }
    wait.committed = true; this.#delivering = true;
    wait.resolve(finalResult);
    if (!header.isSDKError() && !header.isApplicationError()) {
      this.#deliveredItems++; this.#deliveredBytes += BigInt(header.payloadBytes); this.#receivedItems++; this.#receivedBytes += BigInt(header.payloadBytes);
    } else this.#terminalDelivered = true;
    this.#recipient = undefined;
    this.#claim?.release(); this.#claim = undefined; wait.claim?.release(); wait.claim = undefined;
    this.#borrow = undefined; this.#value = undefined; this.#decoded = this.#entered = false; this.#response!.close(); this.#response = undefined;
    if (!this.#closed && !this.#networkEnded) { this.#messages!.consume(); this.#observeTerminal(); }
    this.#delivering = false; wait.settled?.(this.#terminalDelivered);
    if (this.#terminalDelivered || this.#abandonAfterDelivery) this.close(); this.#collect();
  }
  #stopTimer(): void { if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; }
  #fail(reason: string): void { this.#failure ??= reason; this.#state = "failed"; this.close(); }
  authorizationClosed(): void {
    if (this.#closed || this.#authorizationEnded) return; this.#authorizationEnded = true;
    this.#lease?.release(); this.#lease = undefined;
    if (!this.#entered && !this.#delivering) {
      this.#failure ??= "source_unavailable"; if (!this.#terminal) this.#state = "failed"; this.close(); return;
    }
    // This exact application input or host action already crossed its final
    // gate. Stop future I/O; retain only its existing output and real tail.
    if (!this.#terminal) { this.#terminal = true; this.#state = "failed"; this.#failure ??= "source_unavailable"; }
    this.#networkEnded = true; this.#deliveryWait = undefined; this.#stopTimer(); this.#reserveResult = undefined;
    this.#messages?.close(); this.#notifyStatus(); this.#schedule(); this.#collect();
  }
  abandonResult(): RPCStreamingAbandonResult {
    let outcome: RPCStreamingAbandonResult["outcome"];
    if (this.#delivering) { outcome = "host_handoff_committed"; this.#abandonAfterDelivery = true; }
    else if (this.#terminalDelivered) outcome = "already_delivered";
    else if (!this.#submitted) outcome = "not_started";
    else { outcome = "result_abandoned"; this.#abandoned = true; this.close(); }
    return shell({ outcome, status: this.status(), cleanup: this.cleanupStatus() });
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; if (!this.#terminal && this.#state !== "failed") this.#state = "closed";
    this.#deliveryWait = undefined;
    if (this.#submitted && !this.#terminalDelivered && this.#failure === undefined) this.#abandoned = true;
    try { this.#cleanupWindow = new TrustedWindow(this.#clock!, 5000n); } catch { this.#cleanupIncomplete = true; }
    this.#stopTimer(); this.#abort.abort(); this.#readAbort?.abort(); this.#decodeAbort?.abort(); this.#messages?.close(); this.#claim?.release(); this.#claim = undefined;
    this.#lease?.release(); this.#lease = undefined; this.#reserveResult = undefined; this.#notifyStatus(); this.#schedule(); this.#collect();
  }
  onCleanup(callback: () => void): void { if (this.#cleaned !== undefined) throw new RPCProtocolError("rpc_stream_owner"); this.#cleaned = callback; this.#collect(); }
  onNetworkCleanup(callback: () => void): void { if (this.#networkCleaned !== undefined) throw new RPCProtocolError("rpc_stream_owner"); this.#networkCleaned = callback; this.#collect(); }
  #collect(): void {
    if (this.#collecting || this.#opening || this.#reading || this.#finishing) return;
    this.#collecting = true;
    try {
    if (!this.#detached && this.#messages?.cleanupComplete() !== false) {
      this.#messages = undefined; this.#detached = true; this.#reserveResult = undefined;
      const cleaned = this.#networkCleaned; this.#networkCleaned = undefined; cleaned?.();
    }
    if (!this.#closed || this.#decoding || this.#delivering || this.#recipient !== undefined || !this.#detached) return;
    this.#borrow?.release(); this.#borrow = undefined; this.#value = undefined; this.#response?.close(); this.#response = undefined;
    const transfer = this.#transfer; transfer?.request.close(); transfer?.call.close(); transfer?.completion.close();
    if (transfer?.call.cleanupComplete() === false || transfer?.completion.cleanupComplete() === false) return;
    transfer?.contract.release(); this.#transfer = undefined; this.#messages = undefined; this.#errors?.close(); this.#errors = undefined; this.#authentication = undefined;
    this.#reference?.release(); this.#reference = undefined; this.#clock = undefined; this.#cleanupWindow = undefined;
    const cleaned = this.#cleaned; this.#cleaned = undefined; cleaned?.();
    } finally { this.#cleanupWait?.(); this.#collecting = false; }
  }
  cleanupStatus(): V4CleanupStatus {
    this.#collect(); return this.#cleanupProjection();
  }
  #cleanupProjection(): V4CleanupStatus {
    const complete = this.#reference === undefined;
    if (!complete && this.#cleanupWindow !== undefined) try { this.#cleanupWindow.check(); } catch { this.#cleanupIncomplete = true; }
    return cleanupResult({ status: complete ? "complete" : this.#cleanupIncomplete ? "cleanup_incomplete" : "pending",
      core_cleanup: complete || this.#detached ? "complete" : "pending", pending_callbacks: this.#decoding && this.#entered ? 1n : 0n });
  }
  waitCleanup(options: RPCStreamingReadOptions = {}): Promise<V4CleanupStatus> {
    if (this.#cleanupWait !== undefined || this.#creatingCleanup) throw new RPCProtocolError("wait_in_progress");
    this.#creatingCleanup = true;
    try {
      const { signal, context } = options; aborted(signal);
      if (applicationDependsOn(context, this.#decodeContext)) throw new RPCProtocolError("dependency_unavailable");
      const initial = this.cleanupStatus(); if (initial.status !== "pending") return NativePromise.resolve(initial);
      if (aborted(signal)) return NativePromise.reject(new RPCProtocolError("wait_canceled"));
      const clock = this.#clock!, reference = this.#reference!.borrow();
      // One original prepaid waiter; no new task, repeated Close deadline,
      // or reaction attached to the potentially uncooperative decoder.
      return new NativePromise<V4CleanupStatus>((resolve, reject) => {
        let done = false, timer: ReturnType<typeof setTimeout> | undefined, window: TrustedWindow | undefined;
        const finish = (canceled = false, expired = false): void => {
          if (done) return; done = true; this.#cleanupWait = undefined;
          if (timer !== undefined) clearTimeout(timer); unlisten(signal, cancel);
          const status = this.#cleanupProjection(); reference.release();
          if (canceled) reject(new RPCProtocolError("wait_canceled"));
          else resolve(expired && status.status === "pending" ? cleanupResult({ ...status, status: "cleanup_incomplete" }) : status);
        };
        const cancel = (): void => finish(true);
        const wake = (): void => { if (this.#cleanupProjection().status !== "pending") finish(); };
        const tick = (): void => {
          timer = undefined; wake(); if (done) return;
          try { window!.check(); timer = setTimeout(tick, timerChunk(window!.remainingMS())); } catch { finish(false, true); }
        };
        this.#cleanupWait = wake; listen(signal, cancel);
        try { window = this.#cleanupWindow ?? new TrustedWindow(clock, 5000n); if (aborted(signal)) cancel(); else tick(); }
        catch { finish(false, true); }
      });
    } finally { this.#creatingCleanup = false; }
  }
}
