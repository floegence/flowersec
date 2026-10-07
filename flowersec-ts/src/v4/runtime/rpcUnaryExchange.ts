import type { DiagnosticActivity } from "./diagnosticObservation.js";
import type { ControllerUnaryRoute } from "./controllerUnaryRoute.js";
import type { RPCStreamMessages } from "./rpcStreamMessages.js";
import type { RPCNetwork } from "./rpcNetwork.js";
import type { ResumeCodec } from "./resumeCodec.js";
import { cleanupResult } from "./lifecycle.js";
import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { applicationHasPermit, type ApplicationPermit, type CompletionClaim, type CompletionReservation } from "./applicationExecutor.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import type { RPCCallReservation } from "./rpcCallCapacity.js";
import type { RPCChannelRuntime } from "./rpcChannel.js";
import { RPCCompletion, rpcCompletionCharge, type RPCSDKError } from "./rpcCompletion.js";
import { RPCUnaryResultRecipient } from "./rpcUnaryResultRecipient.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCNetworkTicket } from "./rpcNetwork.js";
import type { RPCPayload} from "./rpcPayload.js";
import { rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import { ResourceVector, type ResourceReference, type ResourceRoot } from "./resources.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";
import { TimeError } from "./timeArithmetic.js";

const NativePromise = Promise, enqueue = queueMicrotask, defineProperty = Object.defineProperty, freeze = Object.freeze;
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const addListener = EventTarget.prototype.addEventListener, removeListener = EventTarget.prototype.removeEventListener;
const promiseThen = NativePromise.prototype.then;
function aborted(signal?: AbortSignal): boolean { return signal !== undefined && signalAborted.call(signal) as boolean; }
function listen(signal: AbortSignal | undefined, callback: () => void): void { if (signal !== undefined) addListener.call(signal, "abort", callback, { once: true }); }
function unlisten(signal: AbortSignal | undefined, callback: () => void): void { if (signal !== undefined) removeListener.call(signal, "abort", callback); }
function resultShell<T extends object>(value: T): Readonly<T> { defineProperty(value, "then", { value: undefined }); return freeze(value); }
const resultCleanup = new WeakMap<object, Promise<void>>();
/** Internal bridge for transports that must retain a real unary provider until
 * the original exchange has released its request/response/call tail. */
export function rpcUnaryResultCleanup(result: object): Promise<void> { return resultCleanup.get(result) ?? Promise.resolve(); }
export type RPCUnaryPayloadStatus = "pending" | "available" | "host_handoff_committed" | "already_delivered" | "explicitly_abandoned" | "unavailable";
export interface RPCUnaryTakeOptions { readonly signal?: AbortSignal; readonly context?: V4ApplicationContext; }
export type RPCUnaryTakeResult = Readonly<{ kind: "metadata"; progress: RPCUnaryProgress; error?: "result_mode_conflict"; cause?: "decoder_started" }> |
  Readonly<{ kind: "sdk_error"; header: ApplicationHeader; code: RPCSDKError }> |
  Readonly<{ kind: "retained_result"; header: ApplicationHeader; encoding: "typed"; value: Uint8Array; release(): void }> |
  Readonly<{ kind: "retained_result"; header: ApplicationHeader; encoding: "encoded"; bytes: Uint8Array; release(): void }> |
  Readonly<{ kind: "value"; header: ApplicationHeader; encoding: "typed"; value: unknown;
    schemaDigest: Uint8Array; codecRevision: string; release(): void }> |
  Readonly<{ kind: "application_error"; header: ApplicationHeader; encoding: "typed"; error: unknown;
    schemaDigest: Uint8Array; codecRevision: string; release(): void }> |
  Readonly<{ kind: "value" | "application_error"; header: ApplicationHeader; encoding: "encoded"; bytes: Uint8Array;
    schemaDigest: Uint8Array; codecRevision: string; release(): void }>;
interface ResultWaiter {
  readonly recipient?: RPCUnaryResultRecipient;
  readonly id: bigint;
  readonly encoded: boolean;
  readonly signal: AbortSignal | undefined;
  readonly context: V4ApplicationContext | undefined;
  readonly resolve: (result: RPCUnaryTakeResult) => void;
  readonly reject: (error: unknown) => void;
  readonly cancel: () => void;
  armed: boolean;
  done: boolean;
  committed: boolean;
}
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }), decodeUTF8 = TextDecoder.prototype.decode;
export type RPCUnaryFailure = "closed" | "deadline_exceeded" | "source_unavailable" | "channel_closed" | "response_aborted" | "decode_failed";
export interface RPCUnaryProgress {
  readonly state: "admitted" | "waiting" | "ready" | "taken" | "failed";
  readonly submission: "not_submitted" | "submitted";
  readonly payloadStatus: RPCUnaryPayloadStatus;
  readonly applicationInputDelivered: boolean;
  readonly failure?: RPCUnaryFailure;
  readonly sdkError?: RPCSDKError;
}
export interface RPCUnaryWaitResult extends RPCUnaryProgress { readonly waitStatus: "ready" | "wait_canceled" }
interface Waiter {
  readonly resolve: (result: RPCUnaryWaitResult) => void;
  readonly signal: AbortSignal | undefined;
  readonly cancel: () => void;
}
export function rpcUnaryExchangeCharges(requestBytes: number, responseLimit: number, runtimeBytes: bigint,
  method?: CapturedMethodDefinition): readonly ResourceVector[] {
  // One response variant is decoded at a time. Retain the largest complete
  // codec/object allowance, including the fixed error catalog, before BEGIN.
  if (method !== undefined && (method.shape !== "unary" && method.shape !== "server_streaming" || method.response === undefined)) throw new RPCProtocolError("rpc_request_binding");
  let allowance = 0n;
  for (const codec of method === undefined ? [] : [method.response!, ...method.errors.map(error => error.codec)]) {
    const current = codec.implementation === "utf8" ? BigInt(responseLimit) * 3n : codec.application?.applicationBytes ?? 0n;
    if (current > allowance) allowance = current;
  }
  return [new ResourceVector([7168n + BigInt(requestBytes) + 20n * runtimeBytes + allowance, 0n, 0n, 24n, 1n, 5n, method?.shape === "server_streaming" ? 2n : 1n, 0n, 0n, 0n, 0n]),
    rpcPayloadCharge(requestBytes, runtimeBytes), rpcCompletionCharge(responseLimit, runtimeBytes)];
}

/** One original, fully admitted encoded unary request. Preparation and the
 * trusted method/target binding precede this owner. It consumes no new ID or
 * encoder and never restores Start authority after local admission. Network
 * matching, full result delivery and actual publication tails share its K and
 * Completion reservations. It is the same engine for both unary variants. */
export class RPCUnaryExchange implements RPCPublicationGuard {
  readonly header: ApplicationHeader;
  #reference: ResourceReference | undefined;
  #request: RPCPayload | undefined;
  #response: RPCCompletion | undefined;
  #contract: ServiceContractSnapshot | undefined;
  #call: RPCCallReservation | undefined;
  #completion: CompletionReservation | undefined;
  #claim: CompletionClaim | undefined;
  #method: CapturedMethodDefinition | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #decode: Promise<void> | undefined;
  #decodeBorrow: RPCPayloadBorrow | undefined;
  #decodeAbort: AbortController | undefined;
  #decoding = false;
  #decodeYieldedToEncoded = false;
  #decoded = false;
  #taking = false;
  #value: unknown;
  #channel: RPCChannelRuntime | undefined;
  #ticket: RPCNetworkTicket | undefined;
  #source: RPCPublicationGuard | undefined;
  #deadline: TrustedDeadline | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #observer: (() => void) | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #state: RPCUnaryProgress["state"] = "admitted";
  #submitted = false;
  #queued = false;
  #closed = false;
  #working = false;
  #collecting = false;
  #failure: RPCUnaryFailure | undefined;
  #sdkError: RPCSDKError | undefined;
  #waiter: Waiter | undefined;
  #constructingStatus = false;
  #resultHeld = false;
  readonly #resultWaiters = new Set<ResultWaiter>();
  #constructingResult = 0;
  #nextResultWaiter = 0n;
  #resultScheduled = false;
  #handoff: "none" | "committed" | "complete" = "none";
  #applicationInputDelivered = false;
  #cleaned: (() => void) | undefined;
  #networkCleaned: (() => void) | undefined;
  #cleanupResolve!: () => void;
  readonly #cleanupPromise = new Promise<void>(resolve => { this.#cleanupResolve = resolve; });
  #detached = false;
  #cancelSignal: AbortSignal | undefined;
  #resumeCodec: ResumeCodec | undefined;
  #resumeMessages: RPCStreamMessages | undefined;
  #resumeWorking = false;
  #diagnostic: DiagnosticActivity | undefined;
  #route: ControllerUnaryRoute | undefined;
  #routeObserver: (() => void) | undefined;
  #routeBytes: Uint8Array | undefined;
  #delegate: RPCUnaryExchange | undefined;
  #routing = false;
  #routeSealed = false;
  #routingAllowed = false;
  #routeStopReason: "closed" | "deadline_exceeded" | undefined;
  constructor(header: ApplicationHeader, contract: ServiceContractSnapshot | undefined, request: RPCPayload, deadline: TrustedDeadline,
    source: RPCPublicationGuard, delivery: ReceiveDeliveryGate, root: ResourceRoot, runtimeBytes: bigint,
    references: readonly ResourceReference[], call: RPCCallReservation, completion: CompletionReservation,
    method: CapturedMethodDefinition | undefined, authentication: V4AuthenticatedContext, claim?: CompletionClaim, readLimit?: number, route?: ControllerUnaryRoute, diagnostic?: DiagnosticActivity) {
    const read = header.kind === "read_result_request";
    if (read ? contract !== undefined || method !== undefined || readLimit === undefined :
        header.kind !== "transient_unary_request" && header.kind !== "execution_unary_request" && header.kind !== "resume_request" || contract?.shape !== "unary" || method === undefined || readLimit !== undefined) throw new RPCProtocolError("rpc_request_binding");
    if (header.uint(5) < deadline.cap) throw new RPCProtocolError("rpc_request_binding");
    const limit = read ? readLimit! : Number(header.uint(8));
    const costs = rpcUnaryExchangeCharges(header.payloadBytes, limit, runtimeBytes, method);
    if (references.length !== 2 || !references.every(reference => references[0]!.sameEnvironment(reference)) || !request.sameEnvironment(references[0]!) ||
        contract !== undefined && !contract.sameEnvironment(references[0]!) || !completion.group.sameEnvironment(references[0]!)) throw new RPCProtocolError("rpc_request_owner");
    if (contract !== undefined) { contract.checkRequest(header); contract.checkMethod(contract.namespace, method!); } call.check();
    this.header = header; this.#source = source; this.#deadline = deadline; this.#call = call; this.#completion = completion;
    this.#reference = references[0]!.take(costs[0]!);
    this.#method = method; this.#authentication = Object.freeze({ ...authentication }); this.#claim = claim;
    this.#working = true; this.#diagnostic = diagnostic;
    try {
      this.#contract = contract?.retain(); this.#request = request;
      if (route !== undefined) {
        if (read || header.kind === "resume_request" || header.uint(7) !== 0n || claim !== undefined) throw new RPCProtocolError("rpc_request_binding");
        const original = request.borrow(header.payloadBytes);
        try { this.#routeBytes = new Uint8Array(original.bytes); } finally { original.release(); }
        this.#route = route;
      }
      this.#response = new RPCCompletion(header, limit, runtimeBytes, references[1]!, contract);
      // The hash binds the immutable captured copy, not a retained caller view.
      if (header.has(1)) {
        const borrow = this.#request.borrow(header.payloadBytes);
        try { contract!.verifyExecution(header, borrow.bytes); } finally { borrow.release(); }
      }
      this.#lease = delivery.retain(this.#reference, () => this.#fail("source_unavailable"));
      this.#observer = root.observeAvailability(this.#reference, () => this.#collect());
      this.#response.observe(() => this.#arrived()); Object.freeze(this);
    } catch (error) { this.#fail("source_unavailable"); throw error; }
    finally { this.#working = false; this.#collect(); }
  }
  #checkOwner(): void {
    if (this.#closed || this.#routeSealed || this.#reference === undefined) throw new RPCProtocolError("rpc_request_closed");
    this.#reference.checkRetained();
  }
  #checkSafety(): void { this.#checkOwner(); this.#lease!.check(); this.#checkOwner(); }
  check(): void {
    this.#checkOwner(); if (this.#working) throw new RPCProtocolError("rpc_request_busy");
    if (this.#state !== "admitted" && this.#state !== "waiting") throw new RPCProtocolError("rpc_result_unavailable");
    this.#working = true;
    try {
      const deadline = this.#deadline!, lease = this.#lease!, source = this.#source!;
      deadline.check(); this.#checkOwner(); lease.check(); this.#checkOwner();
      if (!this.#submitted) { this.#route?.check(); if (this.#route?.current() === false) throw new RPCProtocolError("source_unavailable"); }
      source.check(); this.#checkOwner();
    }
    catch (error) {
      this.#fail(error instanceof TimeError && error.code === "time_expired" ? "deadline_exceeded" : "source_unavailable"); throw error;
    } finally { this.#working = false; this.#collect(); }
    this.#checkOwner();
  }
  current(): boolean { return !this.#closed && !this.#routeSealed && this.#queued && this.#reference !== undefined && this.#source?.current() === true && (this.#submitted || this.#route?.current() !== false); }
  admitted(): void {
    // The publisher's scalar BEGIN gate and route revocation use this exact
    // owner. An old publisher can never admit on behalf of its delegate.
    if (this.#routeSealed || this.#closed) throw new RPCProtocolError("rpc_request_closed");
    this.#submitted = true; this.#source?.admitted?.();
    this.#routeObserver?.(); this.#routeObserver = undefined; this.#route = undefined;
    this.#routeBytes?.fill(0); this.#routeBytes = undefined;
  }
  /** An explicit fixed read can be canceled without canceling its execution.
   * Completed private bytes then follow the independent result safety lease. */
  cancelWith(signal: AbortSignal | undefined): void {
    this.#checkOwner(); aborted(signal);
    if (this.#queued || this.#cancelSignal !== undefined) throw new RPCProtocolError("rpc_request_owner");
    this.#cancelSignal = signal; listen(signal, this.#cancelRead);
    if (aborted(signal)) this.close();
  }
  readonly #cancelRead = (): void => this.close();
  #releaseCancellation(): void { unlisten(this.#cancelSignal, this.#cancelRead); this.#cancelSignal = undefined; }
  submit(channel: RPCChannelRuntime): void {
    this.#routingAllowed = true;
    try { this.check(); } catch (error) { if (this.#delegate !== undefined) return; throw error; }
    if (this.#queued) throw new RPCProtocolError("rpc_already_submitted");
    const borrow = this.#request!.borrow(this.header.payloadBytes);
    this.#working = true;
    try {
      this.#channel = channel;
      this.#ticket = channel.queueRequest(this.header, this.#response!, borrow, this, this.#call!);
      this.#queued = true; this.#state = "waiting";
      this.#call!.onNetworkCleanup(() => this.#collect());
      // The publisher now owns the only payload borrow. Return this backing
      // as soon as its actual send tail exits, independently of result arrival.
      this.#request!.close();
    } catch (error) { borrow.release(); this.#fail("source_unavailable"); if (this.#delegate !== undefined) return; throw error; }
    finally { this.#working = false; this.#collect(); }
    if (this.#route !== undefined && !this.#closed && !this.#submitted) {
      this.#routeObserver = this.#route.observe(this.#reference!, () => this.#routeChanged());
      this.#routeChanged();
    }
    this.#tick();
  }
  /** The original K and Completion are shared with a temporary recovery
   * framing owner. Public Close cannot cut a submitted frame or hand its
   * cursor to raw I/O; this finite task settles the actual boundary first. */
  submitResume(messages: RPCStreamMessages, network: RPCNetwork, ticket: RPCNetworkTicket, codec: ResumeCodec): void {
    this.check();
    if (this.#queued || this.header.kind !== "resume_request") throw new RPCProtocolError("resume_binding");
    this.#resumeCodec = codec; this.#resumeMessages = messages; this.#resumeWorking = true;
    this.#ticket = ticket; this.#queued = true; this.#state = "waiting";
    this.#call!.onNetworkCleanup(() => this.#collect());
    messages.onChange(() => this.#collect());
    const deadline = this.#deadline!, source = this.#source!, response = this.#response!;
    const borrow = this.#request!.borrow(this.header.payloadBytes); this.#request!.close();
    void this.#runResume(messages, network, ticket, response, borrow, deadline, source);
  }
  async #runResume(messages: RPCStreamMessages, network: RPCNetwork, ticket: RPCNetworkTicket, response: RPCCompletion,
    borrow: RPCPayloadBorrow, deadline: TrustedDeadline, source: RPCPublicationGuard): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined, begun = false;
    const check = (): void => { deadline.check(); source.check(); messages.check(); if (!begun) this.check(); };
    const tick = (): void => {
      timer = undefined;
      try { check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
      catch { messages.close(); }
    };
    try {
      tick();
      await messages.send(this.header, borrow.bytes, check, () => { begun = true; this.admitted(); });
      borrow.release(); network.completeStreamRequest(ticket, messages);
      const header = await messages.read(incoming => {
        check(); if (incoming.kind !== "resume_response") throw new RPCProtocolError("resume_binding");
        response.begin(incoming); return { write: (offset, bytes) => response.write(offset, bytes), finish: () => undefined };
      });
      if (header === undefined) throw new RPCProtocolError("rpc_stream_incomplete");
      check(); response.validateBody(bytes => { const result = this.#resumeCodec!.result(bytes); result.checkpoint?.position.fill(0); });
      messages.consume(); messages.returnResumeBoundary();
      // The complete response becomes visible only after the actual reader
      // and sender have exited and the same Stream accepts application I/O.
      response.finish(undefined, { requestAborted: false, stopSent: false });
      if (this.#closed) response.close();
    } catch {
      response.channelClosed(); this.#fail("channel_closed");
      if (!begun && messages.unused()) { try { messages.releaseUnusedResume(); } catch { messages.close(); } }
      else messages.close();
    } finally {
      if (timer !== undefined) clearTimeout(timer); borrow.release();
      this.#resumeWorking = false; this.#collect();
    }
  }
  readonly #tick = (): void => {
    this.#timer = undefined;
    if (this.#closed || this.#state !== "waiting") return;
    try {
      this.check();
      if (this.#closed || this.#state !== "waiting") return;
      const remaining = this.#deadline!.remainingMS(), source = this.#source?.publicationRemainingMS?.();
      const delay = timerChunk(source !== undefined && source < remaining ? source : remaining);
      if (!this.#closed && this.#state === "waiting") this.#timer = setTimeout(this.#tick, delay);
    }
    catch (error) { this.#fail(error instanceof TimeError && error.code === "time_expired" ? "deadline_exceeded" : "source_unavailable"); }
  };
  #arrived(): void {
    if (this.#routing || this.#delegate !== undefined) { this.#collect(); return; }
    const progress = this.#response!.progress();
    if (!this.#closed && progress.done) {
      if (progress.failure !== undefined) this.#fail(progress.failure);
      else if (progress.abandoned) this.#fail("closed");
      else {
        // Complete authenticated input wins over a later message deadline.
        // Retained delivery still uses the original independent safety lease.
        this.#diagnostic?.event({ state: "ready", phase: "application", code: "ok" });
        this.#state = "ready"; this.#sdkError = progress.sdkError;
        this.#releaseCancellation();
        this.#stopTimer(); this.#deadline = undefined; this.#source = undefined;
        this.#request?.close(); this.#notify();
      }
    }
    this.#collect();
  }
  progress(): RPCUnaryProgress {
    if (this.#delegate !== undefined) return this.#delegate.progress();
    const payloadStatus: RPCUnaryPayloadStatus = this.#handoff === "complete" ? "already_delivered" :
      this.#handoff === "committed" ? "host_handoff_committed" : this.#closed ? (this.#failure === "closed" ? "explicitly_abandoned" : "unavailable") :
        this.#state === "ready" ? (this.#sdkError === undefined ? "available" : "unavailable") : "pending";
    return resultShell({ state: this.#state, submission: this.#submitted ? "submitted" : "not_submitted", payloadStatus,
      applicationInputDelivered: this.#applicationInputDelivered,
      ...(this.#failure === undefined ? {} : { failure: this.#failure }), ...(this.#sdkError === undefined ? {} : { sdkError: this.#sdkError }) });
  }
  waitStatus(signal?: AbortSignal): Promise<RPCUnaryWaitResult> {
    if (this.#delegate !== undefined) return this.#delegate.waitStatus(signal);
    aborted(signal);
    if (this.#waiter !== undefined || this.#constructingStatus) throw new RPCProtocolError("rpc_wait_in_progress");
    this.#constructingStatus = true;
    let resolve!: Waiter["resolve"], promise: Promise<RPCUnaryWaitResult>;
    try { promise = new NativePromise(done => { resolve = done; }); }
    catch (error) { this.#constructingStatus = false; this.#collect(); throw error; }
    const waiter: Waiter = { resolve, signal, cancel: () => this.#cancelStatus(waiter) };
    this.#waiter = waiter; this.#constructingStatus = false;
    listen(signal, waiter.cancel);
    // Promise construction may have reentered Close before installation.
    if (aborted(signal)) waiter.cancel(); else this.#notify();
    this.#collect(); return promise;
  }
  #cancelStatus(waiter: Waiter): void {
    if (this.#delegate !== undefined) { this.#delegate.#cancelStatus(waiter); return; }
    if (this.#waiter === waiter) this.#notify(true);
  }
  #terminal(): boolean { return this.#state === "ready" || this.#state === "taken" || this.#state === "failed"; }
  #waitResult(cancelled: boolean): RPCUnaryWaitResult { return resultShell({ ...this.progress(), waitStatus: cancelled ? "wait_canceled" : "ready" }); }
  #notify(cancelled = false): void {
    if (this.#delegate !== undefined) { this.#delegate.#notify(cancelled); return; }
    this.#scheduleResults();
    const waiter = this.#waiter; if (waiter === undefined || !cancelled && !this.#terminal()) return;
    this.#waiter = undefined; unlisten(waiter.signal, waiter.cancel); waiter.resolve(this.#waitResult(cancelled));
  }
  /** Synchronous narrow wrappers return the final recipient's exact native
   * capability. No private Promise ever receives the application payload. */
  takeResult(options?: RPCUnaryTakeOptions): Promise<RPCUnaryTakeResult> { return this.#takeResult(false, options); }
  takeEncodedResult(options?: RPCUnaryTakeOptions): Promise<RPCUnaryTakeResult> { return this.#takeResult(true, options); }
  /** A convenience scope transfers its already-returned final capability.
   * This method neither creates a helper Promise nor receives payload itself. */
  receiveResult(recipient: RPCUnaryResultRecipient): void {
    if (this.#delegate !== undefined) { this.#delegate.receiveResult(recipient); return; }
    if (!(recipient instanceof RPCUnaryResultRecipient) || !recipient.armed) throw new RPCProtocolError("rpc_request_owner");
    if (this.#resultWaiters.size + this.#constructingResult >= 4 || this.#nextResultWaiter === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
    const { signal, context } = recipient; aborted(signal); recipient.claim();
    const wait: ResultWaiter = { id: ++this.#nextResultWaiter, encoded: false, signal, context, recipient,
      resolve: result => recipient.resolve(result), reject: error => recipient.reject(error), armed: true, done: false, committed: false,
      cancel: () => { if (!wait.committed && !wait.done) this.#scheduleResults(); } };
    this.#resultWaiters.add(wait); listen(signal, wait.cancel); this.#scheduleResults();
  }
  #takeResult(encoded: boolean, options: RPCUnaryTakeOptions | undefined): Promise<RPCUnaryTakeResult> {
    if (this.#delegate !== undefined) return this.#delegate.#takeResult(encoded, options);
    const signal = options?.signal, context = options?.context;
    aborted(signal); // Validate the native signal before reserving a recipient.
    if (this.#resultWaiters.size + this.#constructingResult >= 4 || this.#nextResultWaiter === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
    // Construction has its own original finite position. A Promise init hook
    // can close the owner, but cannot install or arm this unfinished waiter.
    this.#constructingResult++; const id = ++this.#nextResultWaiter;
    let resolve!: ResultWaiter["resolve"], reject!: ResultWaiter["reject"];
    let promise: Promise<RPCUnaryTakeResult>;
    try { promise = new NativePromise((yes, no) => { resolve = yes; reject = no; }); }
    catch (error) { this.#constructingResult--; this.#collect(); throw error; }
    const wait: ResultWaiter = { id, encoded, signal, context, resolve, reject, armed: false, done: false, committed: false,
      cancel: () => { if (!wait.committed && !wait.done) this.#scheduleResults(); } };
    try {
      this.#resultWaiters.add(wait); this.#constructingResult--;
      listen(signal, wait.cancel);
      this.#scheduleResults();
    } catch (error) {
      wait.done = true; this.#resultWaiters.delete(wait); unlisten(signal, wait.cancel); reject(error); this.#collect();
    }
    // Nothing that invokes the host may occur between arming and return.
    wait.armed = true;
    return promise;
  }
  #scheduleResults(): void {
    if (this.#delegate !== undefined) { this.#delegate.#scheduleResults(); return; }
    if (this.#resultScheduled || this.#resultWaiters.size === 0) return;
    this.#resultScheduled = true;
    try { enqueue(() => { this.#resultScheduled = false; this.#pumpResults(); }); }
    catch (error) { this.#resultScheduled = false; throw error; }
  }
  #finishWait(wait: ResultWaiter, value: RPCUnaryTakeResult | undefined, error?: unknown): void {
    if (wait.done || wait.committed) return;
    wait.done = true; this.#resultWaiters.delete(wait); unlisten(wait.signal, wait.cancel);
    if (error !== undefined) wait.reject(error); else wait.resolve(value!);
    wait.recipient?.complete();
  }
  #metadata(cause?: "decoder_started"): RPCUnaryTakeResult {
    return resultShell({ kind: "metadata" as const, progress: this.progress(), ...(cause === undefined ? {} : { error: "result_mode_conflict" as const, cause }) });
  }
  #pumpResults(): void {
    if (this.#delegate !== undefined) { this.#delegate.#scheduleResults(); this.#collect(); return; }
    if (this.#taking) return; this.#taking = true;
    try {
      // An encoded recipient can win while a typed task only waits for a
      // permit. Application decoder entry, rather than task selection, seals
      // that choice. The fixed four-position set never duplicates a payload.
      const waits = [...this.#resultWaiters].sort((a, b) => Number(b.encoded) - Number(a.encoded));
      for (const wait of waits) {
        if (!wait.armed || wait.done || wait.committed || !this.#resultWaiters.has(wait)) continue;
        if (this.#handoff !== "none" || this.#closed) { this.#finishWait(wait, this.#metadata()); continue; }
        if (aborted(wait.signal)) { this.#finishWait(wait, undefined, new RPCProtocolError("wait_canceled")); continue; }
        if (this.#state !== "ready") continue;
        try {
          this.#checkSafety();
          if (wait.context !== undefined) applicationHasPermit(wait.context);
          if (this.#closed || aborted(wait.signal) || wait.done || this.#handoff !== "none") { this.#scheduleResults(); continue; }
          if (wait.encoded && this.#applicationInputDelivered) { this.#finishWait(wait, this.#metadata("decoder_started")); continue; }
          if (wait.encoded && this.#decoding) { this.#decodeYieldedToEncoded = true; this.#decodeAbort?.abort(); continue; }
          if (this.#method !== undefined && !wait.encoded && this.#sdkError === undefined && !this.#decoded) {
            if (this.#decode === undefined) this.#startDecode(wait);
            continue;
          }
          this.#deliverResult(wait);
        } catch (error) {
          // Time suspension does not turn a complete private candidate into
          // a permanent failure; the caller can wait again on this same owner.
          if (!wait.committed) this.#finishWait(wait, undefined, error);
        }
      }
    } finally { this.#taking = false; this.#collect(); }
  }
  #startDecode(wait: ResultWaiter): void {
    this.#decodeYieldedToEncoded = false;
    const original = this.#decodeResult(wait.signal, wait.context); this.#decode = original;
    this.#observeDecode(original, wait.id);
  }
  #observeDecode(original: Promise<void>, recipient: bigint): void {
    // A canceled recipient's resolver, signal and invocation are not retained
    // by an uncooperative decoder's completion reaction.
    void promiseThen.call(original, () => { if (this.#decode === original) this.#decode = undefined; this.#scheduleResults(); }, error => {
      if (this.#decode === original) this.#decode = undefined;
      const wait = [...this.#resultWaiters].find(candidate => candidate.id === recipient);
      // A pre-entry cancellation/conflict leaves the original encoded bytes
      // available. A genuine decoder failure is already recorded by its owner.
      if (wait !== undefined && !this.#closed && !wait.done && !wait.committed && !this.#decodeYieldedToEncoded &&
          !(error instanceof RPCProtocolError && error.code === "rpc_result_unavailable")) this.#finishWait(wait, undefined, error);
      this.#scheduleResults();
    });
  }
  #deliverResult(wait: ResultWaiter): void {
    const header = this.#response!.progress().header!, sdk = this.#sdkError;
    if (header === undefined) throw new RPCProtocolError("rpc_result_unavailable");
    let borrow: RPCPayloadBorrow | undefined, shell: RPCUnaryTakeResult, acquired = false;
    try {
      if (sdk !== undefined) shell = resultShell({ kind: "sdk_error" as const, header, code: sdk });
      else if (this.#method === undefined) {
        // ReadOperationResult's fixed SDK result is the original encoded
        // payload. Its wire variant has no business error discriminant; only
        // QueryOperation supplies that metadata. Never infer an application
        // success/error codec from the bytes or the current advertisement.
        borrow = this.#response!.borrow(); acquired = true;
        shell = wait.encoded ? resultShell({ kind: "retained_result" as const, header, encoding: "encoded" as const, bytes: borrow.bytes, release: borrow.release })
          : resultShell({ kind: "retained_result" as const, header, encoding: "typed" as const, value: borrow.bytes, release: borrow.release });
      } else {
        const method = this.#method!, codec = header.isApplicationError()
          ? method.errors.find(error => BigInt(error.code) === header.uint(10))?.codec : method.response;
        if (codec === undefined) throw new RPCProtocolError("application_error_code");
        borrow = this.#decodeBorrow;
        if (borrow === undefined && wait.encoded) { borrow = this.#response!.borrow(); acquired = true; }
        if (borrow === undefined) throw new RPCProtocolError("rpc_result_unavailable");
        // The release closure retains only the compact original payload; it
        // cannot retain this exchange, its Session, codec or verification graph.
        const release = borrow.release, schemaDigest = new Uint8Array(codec.schema), codecRevision = codec.revision;
        const kind = header.isApplicationError() ? "application_error" as const : "value" as const;
        shell = wait.encoded ? resultShell({ kind, header, encoding: "encoded" as const, bytes: borrow.bytes, schemaDigest, codecRevision, release })
          : kind === "application_error" ? resultShell({ kind, header, encoding: "typed" as const, error: this.#value, schemaDigest, codecRevision, release })
          : resultShell({ kind, header, encoding: "typed" as const, value: this.#value, schemaDigest, codecRevision, release });
      }
      // Listener removal and safety/ctx sampling precede the scalar commit.
      resultCleanup.set(shell, this.#cleanupPromise);
      unlisten(wait.signal, wait.cancel); this.#checkSafety();
      if (wait.context !== undefined) applicationHasPermit(wait.context);
      if (this.#closed || wait.done || aborted(wait.signal) || this.#handoff !== "none" || !this.#resultWaiters.has(wait)) {
        if (acquired) borrow?.release(); this.#scheduleResults(); return;
      }
      wait.committed = true; this.#handoff = "committed"; this.#state = "taken"; this.#resultHeld = true;
      // No await, task registration, getter or authorization between commit
      // and this one use of the original final native Promise resolver.
      wait.resolve(shell);
      this.#handoff = "complete"; wait.done = true; this.#resultWaiters.delete(wait);
      this.#decodeBorrow = undefined; this.#value = undefined; this.#resultHeld = false;
      this.#claim?.release(); this.#claim = undefined; this.#lease?.release(); this.#lease = undefined;
      this.close(); this.#completion?.close(); this.#response?.close(); this.#notify(); wait.recipient?.complete();
    } catch (error) {
      if (wait.committed) {
        // Completion could not be confirmed. Never restore consumption or
        // resolve/reject again; retained backing records the unfinished handoff.
        this.#resultWaiters.delete(wait); this.#source = undefined; this.#deadline = undefined;
        this.#lease?.release(); this.#lease = undefined;
      } else { if (acquired) borrow?.release(); throw error; }
    }
  }
  async #decodeResult(signal: AbortSignal | undefined, context: V4ApplicationContext | undefined): Promise<void> {
    this.#decoding = true;
    const abort = this.#decodeAbort = new AbortController();
    let permit: ApplicationPermit | undefined, entered = false;
    try {
      const check = (): void => {
        this.#checkSafety();
        if (this.#state !== "ready" || abort.signal.aborted) throw new RPCProtocolError("rpc_result_unavailable");
        if (context !== undefined) applicationHasPermit(context);
      };
      const claim = this.#claim?.active ? this.#claim : undefined;
      permit = await this.#completion!.acquire(signal === undefined ? abort.signal : AbortSignal.any([signal, abort.signal]), check, context, claim);
      this.#claim = undefined; check();
      if (aborted(signal)) throw new RPCProtocolError("wait_canceled");
      const header = this.#response!.progress().header!, method = this.#method!;
      const codec = header.isApplicationError() ? method.errors.find(error => BigInt(error.code) === header.uint(10))?.codec : method.response;
      if (codec === undefined) throw new RPCProtocolError("application_error_code");
      this.#decodeBorrow = this.#response!.borrow();
      const bytes = this.#decodeBorrow.bytes, application = codec.application;
      // Only the compact authenticated projection enters application code.
      // Parent wait cancellation is no longer a callback termination proof.
      context = undefined; signal = undefined;
      if (application === undefined) { entered = true; this.#value = this.#resumeCodec !== undefined ? this.#resumeCodec.result(bytes) : codec.implementation === "bytes" ? bytes : decodeUTF8.call(utf8, bytes); }
      else {
        const invocation = this.#completion!.group.context(permit, this.#authentication!, abort.signal);
        try {
          check(); entered = true; this.#applicationInputDelivered = true;
          this.#value = application.execution === "sync" ? application.decode(invocation.context, bytes) : await application.decode(invocation.context, bytes);
        } finally { invocation.release(); }
      }
      this.#decoded = true;
    } catch (error) {
      if (entered) this.#fail("decode_failed"); throw error;
    } finally {
      permit?.release(); this.#decodeAbort = undefined; this.#decoding = false;
      if (!this.#decoded || this.#closed) { this.#value = undefined; this.#decodeBorrow?.release(); this.#decodeBorrow = undefined; }
      this.#collect();
    }
  }
  onCleanup(callback: () => void): void {
    if (this.#cleaned !== undefined) throw new RPCProtocolError("rpc_request_owner");
    if (this.#reference === undefined) callback(); else this.#cleaned = callback;
  }
  /** The original Session stops owning this job after actual network cleanup;
   * a complete independent result can remain privately retained afterwards. */
  onNetworkCleanup(callback: () => void): void {
    if (this.#networkCleaned !== undefined) throw new RPCProtocolError("rpc_request_owner");
    if (this.#detached) callback(); else this.#networkCleaned = callback;
  }
  endSession(): void {
    if (this.#state !== "ready" && this.#state !== "taken") this.#fail("channel_closed");
  }
  #routeChanged(): void {
    if (this.#closed || this.#routing || this.#submitted || this.#delegate !== undefined || this.#route === undefined) return;
    try { if (this.#route.current()) return; } catch { /* Published-current selection is checked again below. */ }
    if (!this.#reselect()) this.#fail("source_unavailable");
  }
  #reselect(): boolean {
    const route = this.#route;
    if (route === undefined || this.#closed || this.#routing || this.#submitted || !this.#routingAllowed || this.#claim !== undefined ||
        this.#constructingResult !== 0 || this.#constructingStatus || this.#routeBytes === undefined || route.selections >= 3 || aborted(this.#cancelSignal)) return false;
    // Scalar revocation precedes clocks, observers and new resource allocation.
    // The old publisher's current() is permanently false from this point.
    this.#routing = true; this.#routeSealed = true;
    this.#routeObserver?.(); this.#routeObserver = undefined;
    let candidate: RPCUnaryExchange | undefined;
    try {
      this.#deadline!.check(); route.check();
      candidate = route.reserve({ header: this.header, contract: this.#contract!, method: this.#method!, bytes: this.#routeBytes,
        authentication: this.#authentication!, deadline: this.#deadline!, publication: this.#source! });
      if (candidate === undefined) return false;
      this.#delegate = candidate;
      candidate.#diagnostic = this.#diagnostic; this.#diagnostic = undefined;
      // Transfer the final result capabilities themselves. No intermediate
      // Promise receives an application result or claims its recipient twice.
      let recipientOwner = candidate;
      while (recipientOwner.#delegate !== undefined) recipientOwner = recipientOwner.#delegate;
      for (const wait of this.#resultWaiters) recipientOwner.#resultWaiters.add(wait);
      this.#resultWaiters.clear(); recipientOwner.#nextResultWaiter = this.#nextResultWaiter;
      recipientOwner.#waiter = this.#waiter; this.#waiter = undefined;
      candidate.onCleanup(() => this.#collect());
      this.#closed = true; this.#stopTimer(); this.#source = undefined; this.#deadline = undefined; this.#route = undefined;
      try { this.#channel?.stop(this.#ticket!); } catch { /* Original physical tails retain their paid association. */ }
      if (this.#queued) this.#response?.abandon(); else this.#response?.close();
      this.#request?.close(); this.#completion?.close(); this.#call?.close(); this.#lease?.release(); this.#lease = undefined;
      if (this.#routeStopReason !== undefined) candidate.#fail(this.#routeStopReason);
      else if (aborted(this.#cancelSignal)) candidate.close();
      candidate.#notify(); return true;
    } catch { candidate?.close(); return false; }
    finally { this.#routing = false; this.#collect(); }
  }
  #stopTimer(): void { if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; }
  #fail(failure: RPCUnaryFailure): void {
    if (this.#delegate !== undefined) {
      // Session retirement only concerns its revoked original route. Public
      // Close and deadline cancellation still reach the operation's new owner.
      if (failure === "closed" || failure === "deadline_exceeded") this.#delegate.#fail(failure);
      this.#collect(); return;
    }
    if (this.#routing) {
      if (failure === "closed" || failure === "deadline_exceeded") this.#routeStopReason ??= failure;
      return;
    }
    if (this.#closed) return;
    if ((failure === "source_unavailable" || failure === "channel_closed") && this.#reselect()) return;
    // A Close/deadline winner during allocation remains the operation's final
    // cause even if allocation itself subsequently fails or returns no route.
    if (this.#routeStopReason !== undefined) failure = this.#routeStopReason;
    const complete = this.#state === "ready" || this.#state === "taken";
    if (!complete) this.#diagnostic?.failure(new Error(failure));
    this.#closed = true;
    this.#routeObserver?.(); this.#routeObserver = undefined; this.#route = undefined;
    this.#releaseCancellation();
    if (this.#state !== "taken") { this.#state = "failed"; this.#failure = failure; }
    this.#stopTimer(); this.#source = undefined; this.#deadline = undefined;
    this.#decodeAbort?.abort();
    if (this.#handoff !== "committed") { this.#claim?.release(); this.#claim = undefined; }
    if (!this.#decoding && !this.#resultHeld) { this.#value = undefined; this.#decodeBorrow?.release(); this.#decodeBorrow = undefined; }
    if (this.#handoff !== "committed") { this.#lease?.release(); this.#lease = undefined; }
    if (this.#resumeWorking) {
      // The original finite recovery task retains the complete response sink.
    } else if (this.#queued && !complete) {
      try { this.#channel?.stop(this.#ticket!); } catch { /* Original channel cleanup owns any remaining association. */ }
      this.#response?.abandon();
    } else this.#response?.close();
    this.#request?.close(); if (this.#handoff !== "committed") this.#completion?.close(); this.#notify(); this.#collect();
  }
  #collect(): void {
    if (this.#working || this.#routing || this.#resumeWorking || this.#resumeMessages?.cleanupComplete() === false || this.#collecting || this.#reference === undefined) return;
    this.#collecting = true;
    try {
      // The public result owns no Session graph after the original request and
      // network work has ended. Its compact K/Completion owners retain safety.
      if (!this.#detached && (this.#closed || this.#response?.progress().done) && this.#request?.cleanupComplete() !== false &&
          this.#call?.networkComplete() !== false) {
        this.#channel = undefined; this.#ticket = undefined; this.#detached = true;
        const cleaned = this.#networkCleaned; this.#networkCleaned = undefined; cleaned?.();
      }
      if (this.#delegate?.cleanupComplete() === false) return;
      if (!this.#closed || this.#resultHeld || this.#decoding || this.#taking || this.#constructingResult !== 0 || this.#constructingStatus || this.#resultScheduled || this.#resultWaiters.size !== 0 || this.#request?.cleanupComplete() === false || this.#response?.cleanupComplete() === false ||
          this.#completion?.cleanupComplete() === false) return;
      this.#call?.close(); if (this.#call?.cleanupComplete() === false) return;
      this.#diagnostic?.close(); this.#diagnostic = undefined;
      this.#resumeMessages = undefined; this.#resumeCodec?.close(); this.#resumeCodec = undefined;
      this.#call = undefined; this.#completion = undefined; this.#contract?.release(); this.#contract = undefined;
      this.#request = undefined; this.#response = undefined; this.#channel = undefined; this.#ticket = undefined;
      this.#releaseCancellation(); this.#method = undefined; this.#authentication = undefined;
      this.#routeObserver?.(); this.#routeObserver = undefined; this.#route = undefined;
      this.#routeBytes?.fill(0); this.#routeBytes = undefined;
      this.#observer?.(); this.#observer = undefined; this.#reference.release(); this.#reference = undefined;
      const cleaned = this.#cleaned; this.#cleaned = undefined; cleaned?.();
      this.#cleanupResolve(); this.#cleanupResolve = () => undefined;
    } finally { this.#collecting = false; }
  }
  close(): void { this.#fail("closed"); }
  cleanupStatus(): V4CleanupStatus {
    this.#collect();
    return cleanupResult({ status: this.#handoff === "committed" && this.#closed ? "cleanup_incomplete" : this.#reference === undefined ? "complete" : "pending",
      core_cleanup: this.#reference === undefined ? "complete" : "pending", pending_callbacks: this.#decoding && this.#applicationInputDelivered ? 1n : 0n });
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
  toJSON(): object { return {}; }
}
Object.freeze(RPCUnaryExchange.prototype); Object.freeze(RPCUnaryExchange);
