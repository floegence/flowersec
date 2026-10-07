import { DiagnosticActivity, type DiagnosticObserver } from "./diagnosticObservation.js";
import { beginReferenceSave, referenceStoreRetention, referenceSaveFailure, referenceSaveReport, type V4OperationReferenceStore, type ReferenceSaveReport } from "../operationReferenceStore.js";
import type { ServiceBindingTarget } from "./serviceBindingConfig.js";
import { operationReference, type V4OperationReference } from "../operationReference.js";
import { hex } from "./executionManagementCodec.js";
import { cleanupResult } from "./lifecycle.js";
import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge, type ApplicationHeader, type ApplicationHeaderInput } from "./applicationHeader.js";
import { applicationHasCompletionAncestor, applicationHasPermit, applicationWorkClass, type ApplicationGroup, type ApplicationPermit, type ApplicationWorkClass, type CompletionClaim, type CompletionReservation } from "./applicationExecutor.js";
import { byteLength } from "./cbor.js";
import type { TrustedClock } from "./clock.js";
import { TrustedDeadline, TrustedWindow, timerChunk } from "./deadline.js";
import { checkApplicationMessageOutput, messageInputBytes } from "./messageCodec.js";
import type { RandomFill } from "./random.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { ResourceError, ResourceVector, type ResourceReference } from "./resources.js";
import type { RPCCallReservation } from "./rpcCallCapacity.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCPayload } from "./rpcPayload.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import { rpcUnaryExchangeCharges, type RPCUnaryExchange } from "./rpcUnaryExchange.js";
import type { AdmissionOffer, ServiceContractSnapshot } from "./serviceContract.js";
import type { SessionCleanup } from "./sessionCleanup.js";
import { observeTask } from "./taskObservation.js";
import { TimeError, timeAdd } from "./timeArithmetic.js";

const maximum = (1n << 64n) - 1n, utf8 = new TextEncoder(), encodeUTF8 = TextEncoder.prototype.encode;
const min = (a: bigint, b: bigint): bigint => a < b ? a : b;
const codeUnit = String.prototype.charCodeAt;
export function encodeText(value: string, maximumBytes: number): Uint8Array {
  let length = 0;
  for (let index = 0; index < value.length; index++) {
    const cp = codeUnit.call(value, index);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const next = codeUnit.call(value, ++index);
      if (!Number.isFinite(next) || next < 0xdc00 || next > 0xdfff) throw new RPCProtocolError("encode_failed");
      length += 4;
    } else if (cp >= 0xdc00 && cp <= 0xdfff) throw new RPCProtocolError("encode_failed");
    else length += cp < 0x80 ? 1 : cp < 0x800 ? 2 : 3;
    if (length > maximumBytes) throw new RPCProtocolError("application_request_limit");
  }
  return encodeUTF8.call(utf8, value);
}
export interface RPCUnaryPreparationOptions {
  readonly deadlineAtMS?: bigint;
  readonly defaultLifetimeMS: bigint;
  readonly admissionNotAfterMS?: bigint;
  readonly responseLimitBytes?: number;
  readonly defaultResponseLimitBytes?: number;
  readonly admission?: "queued" | "try_now";
}
export interface RPCUnaryTransfer {
  readonly diagnostic?: DiagnosticActivity | undefined;
  readonly header: ApplicationHeader;
  readonly contract: ServiceContractSnapshot;
  readonly request: RPCPayload;
  readonly deadline: TrustedDeadline;
  readonly completionDeadline?: TrustedDeadline;
  readonly guard: RPCPublicationGuard;
  readonly references: readonly ResourceReference[];
  readonly call: RPCCallReservation;
  readonly completion: CompletionReservation;
  readonly method: CapturedMethodDefinition;
}
/** SDK-only target. check may sample host state; current is a scalar gate.
 * Neither preflight can create a Stream, serial, publisher or async task. */
export interface RPCPreparedExchange {
  close(): void;
  cleanupStatus(): V4CleanupStatus;
  waitCleanup?(options?: { readonly signal?: AbortSignal }): Promise<V4CleanupStatus>;
}
export interface RPCPreparedStart<Exchange extends RPCPreparedExchange> {
  current(): boolean;
  start(transfer: RPCUnaryTransfer, claim: CompletionClaim | undefined): Exchange;
  release(): void;
}
export interface RPCUnaryStartTarget<Exchange extends RPCPreparedExchange = RPCUnaryExchange> {
  check(header: ApplicationHeader, call: RPCCallReservation): void;
  current(header: ApplicationHeader, call: RPCCallReservation): boolean;
  start(transfer: RPCUnaryTransfer, claim: CompletionClaim | undefined): Exchange;
  releaseUnused?(): void;
  reserve?(header: ApplicationHeader, call: RPCCallReservation): RPCPreparedStart<Exchange> | undefined;
}
export type RPCUnaryStartResult<Exchange extends RPCPreparedExchange = RPCUnaryExchange> = Readonly<{ status: "admitted"; exchange: Exchange }> |
  Readonly<{ status: "not_admitted"; submission: "not_submitted"; reason: "not_ready" | "resource_exhausted" | "dependency_unavailable" }>;

/** The publisher keeps the original preparation/cutoff until actual BEGIN
 * admission, including time spent behind an existing rekey gate. */
class UnaryPublication implements RPCPublicationGuard {
  #submitted = false;
  #closed = false;
  constructor(readonly source: RPCPublicationGuard, readonly deadline: TrustedDeadline,
    readonly preparation: TrustedDeadline, readonly cutoff: TrustedDeadline | undefined, readonly notBefore: bigint | undefined) {}
  checkPrepared(): void {
    if (this.#closed) throw new RPCProtocolError("rpc_request_closed");
    if (!this.#submitted) { this.preparation.check(); this.cutoff?.check(); }
    this.deadline.check(); this.source.check();
  }
  check(): void {
    this.checkPrepared();
    if (!this.#submitted && this.notBefore !== undefined && this.deadline.sample().requireInterval().lowerMS < this.notBefore) throw new TimeError("time_pending");
  }
  current(): boolean { return !this.#closed && this.source.current(); }
  close(): void { this.#closed = true; }
  admitted(): void { this.#submitted = true; this.source.admitted?.(); }
  reroute(source: RPCPublicationGuard): RPCPublicationGuard {
    if (this.#closed || this.#submitted) throw new RPCProtocolError("rpc_request_owner");
    // The original preparation, execution deadline, Offer cutoff and not-before
    // remain exact. No route selection creates another age window.
    this.preparation.check(); this.cutoff?.check(); this.deadline.check();
    return new UnaryPublication(source, this.deadline, this.preparation, this.cutoff, this.notBefore);
  }
  publicationRemainingMS(): bigint {
    let remaining = this.deadline.remainingMS();
    if (!this.#submitted) {
      remaining = min(remaining, this.preparation.remainingMS());
      if (this.cutoff !== undefined) remaining = min(remaining, this.cutoff.remainingMS());
    }
    return remaining;
  }
}

export function captureUnaryOptions(input: RPCUnaryPreparationOptions, context?: V4ApplicationContext): RPCUnaryPreparationOptions {
  const { deadlineAtMS, defaultLifetimeMS, admissionNotAfterMS, responseLimitBytes, defaultResponseLimitBytes, admission } = input;
  const nested = applicationHasPermit(context);
  if (admission !== undefined && admission !== "queued" && admission !== "try_now") throw new RPCProtocolError("rpc_request_binding");
  if (nested && admission === "queued") throw new RPCProtocolError("admission_mode_incompatible");
  if (typeof defaultLifetimeMS !== "bigint" || defaultLifetimeMS < 1n || defaultLifetimeMS > maximum) throw new RPCProtocolError("rpc_request_binding");
  for (const time of [deadlineAtMS, admissionNotAfterMS]) if (time !== undefined && (typeof time !== "bigint" || time < 1n || time > maximum)) throw new RPCProtocolError("rpc_request_binding");
  for (const limit of [responseLimitBytes, defaultResponseLimitBytes]) if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 0 || limit > 1048576)) throw new RPCProtocolError("response_limit_unsupported");
  return Object.freeze({ defaultLifetimeMS, admission: admission ?? (nested ? "try_now" : "queued"),
    ...(deadlineAtMS === undefined ? {} : { deadlineAtMS }), ...(admissionNotAfterMS === undefined ? {} : { admissionNotAfterMS }),
    ...(responseLimitBytes === undefined ? {} : { responseLimitBytes }), ...(defaultResponseLimitBytes === undefined ? {} : { defaultResponseLimitBytes }) });
}
export function unaryResponseLimit(contract: ServiceContractSnapshot, options: RPCUnaryPreparationOptions): number {
  const limit = options.responseLimitBytes ?? options.defaultResponseLimitBytes ?? contract.maxResponseBytes;
  if (!Number.isSafeInteger(limit) || limit < contract.minResponseBytes || limit > contract.maxResponseBytes) throw new RPCProtocolError("response_limit_unsupported");
  return limit;
}
/** Includes both the callback's maximum output and the distinct immutable
 * request backing. Complete future result/codec responsibility is paid now. */
export function rpcUnaryPreparationCharges(contract: Pick<ServiceContractSnapshot, "requestMaxBytes">, method: CapturedMethodDefinition,
  limit: number, inputBytes: number, runtimeBytes: bigint): readonly ResourceVector[] {
  if (!Number.isSafeInteger(inputBytes) || inputBytes < 0) throw new RPCProtocolError("configuration_capacity");
  return [...rpcUnaryExchangeCharges(contract.requestMaxBytes, limit, runtimeBytes, method),
    new ResourceVector([8192n + 8n * runtimeBytes + BigInt(inputBytes) + BigInt(method.request.maximum) +
      (method.request.application?.applicationBytes ?? 0n), 0n, 0n, 16n, 1n, 4n, 2n, 0n, 0n, 0n, 0n]),
    applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes)];
}

/** One immutable preparation and its original once-only transfer. It holds no
 * wire ID for transient calls and never discovers, connects, opens or retries.
 * An application encoder may outlive cancellation; only its actual exit frees
 * its input/output allowance and permit. */
export class RPCUnaryPreparation<Exchange extends RPCPreparedExchange = RPCUnaryExchange> {
  #diagnostic: DiagnosticActivity | undefined;
  #operationReference: V4OperationReference | undefined;
  readonly #localAuthority: string | undefined;
  readonly #namespace: string;
  readonly #destination: ServiceBindingTarget | undefined;
  #reference: ResourceReference | undefined;
  #exchangeReference: ResourceReference | undefined;
  #responseReference: ResourceReference | undefined;
  #codec: ApplicationHeaderCodec | undefined;
  #request: RPCPayload | undefined;
  #contract: ServiceContractSnapshot | undefined;
  #method: CapturedMethodDefinition | undefined;
  #call: RPCCallReservation | undefined;
  #completion: CompletionReservation | undefined;
  #guard: UnaryPublication | undefined;
  #completionDeadline: TrustedDeadline | undefined;
  #header: ApplicationHeader | undefined;
  #fields: ApplicationHeaderInput | undefined;
  #group: ApplicationGroup | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #target: RPCUnaryStartTarget<Exchange> | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #cleanup: SessionCleanup | undefined;
  #job = false;
  #workClass: ApplicationWorkClass;
  #state: "encoding" | "prepared" | "starting" | "started" | "closed" | "failed" = "encoding";
  #failure: unknown;
  #exchange: Exchange | undefined;
  #enteredEncoding = false;
  #saving = false;
  #saveTail = false;
  #saveEntered = false;
  #encoding = false;
  #callbackActive = false;
  #busy = false;
  #collecting = false;
  readonly #inputBytes: number;
  #abort = new AbortController();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #detached: (() => void) | undefined;
  #observed = false;
  #clock: TrustedClock | undefined;
  #cleanupWake: (() => void) | undefined;
  #creatingCleanup = false;
  constructor(method: CapturedMethodDefinition, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    options: RPCUnaryPreparationOptions, source: RPCPublicationGuard, target: RPCUnaryStartTarget<Exchange>,
    clock: TrustedClock, parent: TrustedDeadline, random: RandomFill, delivery: ReceiveDeliveryGate,
    group: ApplicationGroup, authentication: V4AuthenticatedContext, cleanup: SessionCleanup,
    call: RPCCallReservation, completion: CompletionReservation, workClass: ApplicationWorkClass,
    inputBytes: number, runtimeBytes: bigint, references: readonly ResourceReference[], localAuthority?: string, destination?: ServiceBindingTarget, resume = false, diagnostics?: DiagnosticObserver) {
    this.#localAuthority = localAuthority; this.#namespace = namespace; this.#destination = destination;
    this.#workClass = workClass; this.#inputBytes = inputBytes; this.#clock = clock;
    const limit = unaryResponseLimit(contract, options), charges = rpcUnaryPreparationCharges(contract, method, limit, inputBytes, runtimeBytes);
    if (references.length !== charges.length || !references.every(ref => references[0]!.sameEnvironment(ref)) ||
        !contract.sameEnvironment(references[0]!) || !parent.belongsTo(clock) || (method.shape !== "unary" && method.shape !== "server_streaming")) throw new RPCProtocolError("rpc_request_binding");
    contract.checkMethod(namespace, method);
    if (resume && (method.shape !== "unary" || contract.semantics !== "execution" || contract.optionalUint(13) !== 1n || method.request.implementation !== "bytes" || method.response?.implementation !== "bytes")) throw new RPCProtocolError("resume_binding");
    if ((contract.semantics === "execution") !== (offer !== undefined) || contract.semantics !== "execution" && options.admissionNotAfterMS !== undefined) throw new RPCProtocolError("admission_offer_unavailable");
    this.#reference = references[3]!.take(charges[3]!);
    this.#method = method; this.#target = target; this.#call = call; this.#completion = completion;
    this.#group = group; this.#authentication = authentication; this.#cleanup = cleanup; this.#busy = true;
    try {
      this.#diagnostic = new DiagnosticActivity(diagnostics, "application");
      cleanup.startJob(); this.#job = true;
      this.#exchangeReference = references[0]!.take(charges[0]!); this.#responseReference = references[2]!.take(charges[2]!);
      this.#request = new RPCPayload(contract.requestMaxBytes, runtimeBytes, references[1]!);
      this.#contract = contract.retain(); this.#codec = new ApplicationHeaderCodec(runtimeBytes, references[4]!, references[5]!);
      source.check(); this.#checkLive();
      const sample = clock.sample(), now = sample.requireInterval(), horizon = contract.uint(contract.semantics === "execution" ? 17 : 11);
      parent.checkAt(sample); this.#checkLive();
      const latest = timeAdd(now.lowerMS, horizon);
      const cap = options.deadlineAtMS ?? timeAdd(now.lowerMS, min(options.defaultLifetimeMS, horizon));
      if (cap > latest || cap <= now.upperMS) throw new TimeError("time_expired");
      // Wire lifetime belongs to the immutable operation. The Session can
      // tighten local safety without rewriting its deadline or digest.
      const deadline = new TrustedDeadline(clock, min(cap, parent.cap), sample); deadline.tightenFrom(parent); this.#checkLive();
      if (method.shape === "server_streaming") {
        // Receive grace belongs to this immutable operation. It cannot extend
        // authorization, alter the wire deadline, or restart on a later read.
        this.#completionDeadline = new TrustedDeadline(clock, min(timeAdd(cap, 5000n), parent.cap), sample);
        this.#completionDeadline.tightenFrom(parent); this.#checkLive();
      }
      const preparation = deadline.fork(min(deadline.cap, timeAdd(now.lowerMS, 60000n)));
      const digest = new Uint8Array(32); contract.copyDigest(digest);
      let operationID: Uint8Array<ArrayBuffer> | undefined, requestDigest: Uint8Array<ArrayBuffer> | undefined, cutoff: TrustedDeadline | undefined;
      if (offer !== undefined) {
        // Encoding this exact captured Offer checks digest and finite policy.
        offer.copyEncoded(contract, maximum, new Uint8Array(256));
        const latestCutoff = timeAdd(now.lowerMS, contract.uint(16));
        const selected = min(min(options.admissionNotAfterMS ?? latestCutoff, offer.notAfterMS), cap);
        if (selected <= now.upperMS || selected <= offer.notBeforeMS || selected > latestCutoff) throw new RPCProtocolError("admission_window_closed");
        cutoff = deadline.fork(min(selected, deadline.cap)); operationID = new Uint8Array(32); requestDigest = new Uint8Array(32);
        let prefix = selected;
        for (let n = 7; n >= 0; n--) { operationID[n] = Number(prefix & 255n); prefix >>= 8n; }
        random(operationID.subarray(8)); this.#checkLive();
      }
      this.#guard = new UnaryPublication(source, deadline, preparation, cutoff, offer?.notBeforeMS);
      this.#fields = Object.freeze({ kind: resume ? "resume_request" : method.shape === "server_streaming" ? (offer === undefined ? "transient_stream_request" : "execution_stream_request") : (offer === undefined ? "transient_unary_request" : "execution_unary_request"), typeID: contract.typeID,
        payloadBytes: 0, contractDigest: digest, deadlineAtMS: cap, admissionMode: options.admission === "try_now" ? 1 : 0,
        responseLimitBytes: limit, ...(operationID === undefined ? {} : { operationID, requestDigest: requestDigest! }) });
      this.#lease = delivery.retain(this.#reference, () => this.close());
      this.#guard.checkPrepared(); this.#checkLive(); Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
    } catch (error) { this.#failure = error; this.#state = "failed"; throw error; }
    finally { this.#busy = false; this.#collect(); }
    this.#tick();
  }
  #checkLive(): void {
    if (this.#state === "closed" || this.#state === "failed") throw this.#failure ?? new RPCProtocolError("rpc_request_closed");
    this.#reference!.checkRetained();
  }
  #checkPrepared(): void {
    this.#checkLive(); this.#guard!.checkPrepared(); this.#checkLive(); this.#lease!.check(); this.#checkLive();
    if (!this.#guard!.current()) throw new RPCProtocolError("source_unavailable");
  }
  readonly #tick = (): void => {
    this.#timer = undefined;
    if (this.#state !== "encoding" && this.#state !== "prepared") return;
    this.#busy = true;
    try {
      this.#checkPrepared(); const remaining = this.#guard!.publicationRemainingMS(); this.#checkLive();
      this.#timer = setTimeout(this.#tick, timerChunk(remaining));
    }
    catch (error) {
      if ((this.#state === "encoding" || this.#state === "prepared") && error instanceof TimeError &&
          ["time_pending", "time_unavailable", "time_continuity"].includes(error.code)) this.#timer = setTimeout(this.#tick, 1000);
      else this.#fail(error);
    } finally { this.#busy = false; this.#collect(); }
  };
  /** Exactly one actual encoder invocation; cancellation stops observation and
   * closes preparation authority, while the original callback keeps its bill. */
  encode(value: unknown, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void> {
    this.#checkLive();
    if (this.#enteredEncoding || this.#state !== "encoding") throw new RPCProtocolError("rpc_preparation_incomplete");
    this.#enteredEncoding = true; this.#encoding = true;
    const canceled = (): void => this.close();
    try {
      signal?.addEventListener("abort", canceled, { once: true });
      if (signal?.aborted) canceled();
    } catch (error) { this.#encoding = false; this.#fail(error); throw error; }
    const actual = this.#encode(value, context);
    return observeTask(actual, this.#abort.signal, () => this.#failure ?? new RPCProtocolError("canceled"))
      .finally(() => signal?.removeEventListener("abort", canceled));
  }
  async #encode(value: unknown, context: V4ApplicationContext | undefined): Promise<void> {
    let permit: ApplicationPermit | undefined, callback = false;
    try {
      this.#checkPrepared();
      const definition = this.#method!.request, application = definition.application;
      // Revalidate backing before the callback; no arbitrary properties are read.
      if (messageInputBytes(value, definition.implementation, definition.maximum) > this.#inputBytes) throw new RPCProtocolError("encode_failed");
      let encoded: Uint8Array;
      if (application === undefined) encoded = definition.implementation === "bytes" ? value as Uint8Array : encodeText(value as string, this.#contract!.requestMaxBytes);
      else {
        const direct = application.execution === "sync"
          ? this.#group!.synchronous(context, () => this.#checkPrepared(), () => {
            this.#cleanup!.enterCallback(); callback = this.#callbackActive = true; return application.encode(context!, value);
          }) : { used: false as const };
        if (direct.used) encoded = direct.value;
        else {
          permit = this.#fields!.admissionMode === 1 ? this.#group!.tryOrdinary(this.#workClass, context)
            : await this.#group!.acquire(this.#workClass, this.#abort.signal, () => this.#checkPrepared(), context);
          this.#checkPrepared();
          const invocation = this.#group!.context(permit, this.#authentication!, this.#abort.signal);
          // The actual callback retains only this compact owner/context.
          context = undefined;
          try {
            this.#cleanup!.enterCallback(); callback = this.#callbackActive = true;
            encoded = application.execution === "sync" ? application.encode(invocation.context, value) : await application.encode(invocation.context, value);
          }
          finally { invocation.release(); }
        }
      }
      this.#checkPrepared();
      const bytes = application === undefined ? encoded : checkApplicationMessageOutput(encoded, definition.maximum);
      if (byteLength(bytes) > this.#contract!.requestMaxBytes) throw new RPCProtocolError("application_request_limit");
      this.#request!.write(0, bytes);
      const fields = { ...this.#fields!, payloadBytes: byteLength(bytes) };
      let header = this.#codec!.create(fields);
      if (header.has(1)) {
        const original = this.#request!.borrow(header.payloadBytes);
        try { this.#contract!.executionDigest(header, original.bytes, fields.requestDigest!); }
        finally { original.release(); }
        header = this.#codec!.create(fields);
      }
      this.#contract!.checkRequest(header); this.#checkPrepared();
      if (header.has(1) && this.#localAuthority !== undefined && this.#destination !== undefined) this.#operationReference = operationReference({ tenant: this.#authentication!.tenant, audience: this.#authentication!.audience,
        namespace: this.#namespace, subject: this.#authentication!.localSubject, authority: this.#localAuthority,
        operation: hex(fields.operationID!), requestDigest: hex(fields.requestDigest!), contractDigest: hex(fields.contractDigest) }, this.#destination, header.uint(5), Number(this.#contract!.uint(13)) as 0 | 1, Number(this.#contract!.uint(19)) as 0 | 1, Number(header.uint(8)), this.#method!.shape === "server_streaming" ? 1 : 0);
      this.#header = header; this.#state = "prepared";
      this.#clearEncoding();
    } catch (error) { this.#fail(error); throw error; }
    finally {
      value = undefined; context = undefined; permit?.release();
      if (callback) this.#cleanup!.exitCallback(); this.#callbackActive = false; this.#encoding = false; this.#collect();
    }
  }
  /** Composition-only: the candidate has not been handed to application code. */
  async saveReference(store: V4OperationReferenceStore, context?: V4ApplicationContext, signal?: AbortSignal): Promise<ReferenceSaveReport> {
    const canceled = (): void => this.close();
    try {
      this.checkReady(); if (applicationHasPermit(context)) throw new RPCProtocolError("admission_mode_incompatible");
      if (!this.execution || this.#saveEntered) throw new RPCProtocolError("operation_reference_unavailable");
      store.checkDomain(this.#destination!.authority); this.#saveEntered = this.#saving = true;
      signal?.addEventListener("abort", canceled, { once: true });
      if (signal?.aborted) throw new RPCProtocolError("canceled");
      this.#saveTail = this.#target?.releaseUnused !== undefined;
      let task: Promise<ReferenceSaveReport>;
      try { task = beginReferenceSave(store, { reference: this.reference(), owner: this.#reference!, group: this.#group!, authentication: this.#authentication!,
        cleanup: this.#cleanup!, signal: this.#abort.signal, ...(context === undefined ? {} : { context }), immediate: this.#header!.uint(7) === 1n,
        check: () => this.#checkPrepared(), ...(this.#saveTail ? { settled: () => { this.#saveTail = false; this.#collect(); } } : {}) }, referenceStoreRetention(store)); }
      catch (error) { this.#saveTail = false; throw error; }
      const report = await task;
      if (report.failure !== undefined || report.save.outcome !== "confirmed") {
        const failure = this.#failure === undefined ? report.failure : referenceSaveFailure(this.#failure);
        this.close(); return referenceSaveReport({ ...report, ...(failure === undefined ? {} : { failure }) });
      }
      try { this.#checkPrepared(); if (signal?.aborted) throw new RPCProtocolError("canceled"); }
      catch (error) { this.close(); return referenceSaveReport({ ...report, failure: referenceSaveFailure(error) }); }
      return report;
    } catch (error) {
      this.close(); return referenceSaveReport({ save: Object.freeze({ attempted: false, outcome: "unknown" as const }),
        failure: referenceSaveFailure(error), cleanup: this.cleanupStatus() });
    } finally { signal?.removeEventListener("abort", canceled); this.#saving = false; this.#collect(); }
  }
  start(context?: V4ApplicationContext, signal?: AbortSignal): RPCUnaryStartResult<Exchange> {
    if (this.#exchange !== undefined) return Object.freeze({ status: "admitted", exchange: this.#exchange });
    this.#checkLive();
    if (this.#state !== "prepared" || this.#busy || this.#encoding || this.#saving) throw new RPCProtocolError("rpc_preparation_incomplete");
    if (signal?.aborted) throw new RPCProtocolError("canceled");
    // Compatibility precedes any transfer and does not alter fixed bytes.
    if (applicationHasPermit(context) && this.#header!.uint(7) !== 1n) throw new RPCProtocolError("admission_mode_incompatible");
    const immediate = this.#header!.uint(7) === 1n;
    let claim: CompletionClaim | undefined;
    let reserved: RPCPreparedStart<Exchange> | undefined;
    this.#busy = true;
    try {
      this.#checkPrepared(); this.#guard!.check(); this.#checkLive();
      this.#target!.check(this.#header!, this.#call!); this.#checkLive();
      reserved = this.#target!.reserve?.(this.#header!, this.#call!); this.#checkLive();
      if (applicationHasCompletionAncestor(context)) claim = this.#completion!.group.claimCompletion(context!);
      if (signal?.aborted) throw new RPCProtocolError("canceled");
      const workClass = applicationWorkClass(this.#workClass, context);
      this.#checkLive();
      if (!this.#guard!.current() || !this.#target!.current(this.#header!, this.#call!) || reserved?.current() === false) throw new RPCProtocolError("not_ready");
      // No host callback, await or observer occurs between this scalar gate
      // and sealing authority. Subsequent failures can never restore it.
      this.#call!.inheritClass(workClass); this.#state = "starting";
      const transfer: RPCUnaryTransfer = { diagnostic: this.#diagnostic, header: this.#header!, contract: this.#contract!, request: this.#request!,
        deadline: this.#guard!.deadline, guard: this.#guard!, references: [this.#exchangeReference!, this.#responseReference!],
        ...(this.#completionDeadline === undefined ? {} : { completionDeadline: this.#completionDeadline }),
        call: this.#call!, completion: this.#completion!, method: this.#method! };
      this.#exchange = reserved === undefined ? this.#target!.start(transfer, claim) : reserved.start(transfer, claim); claim = undefined;
      this.#diagnostic = undefined;
      this.#checkLive();
      this.#request = undefined; this.#exchangeReference = this.#responseReference = undefined;
      this.#call = undefined; this.#completion = undefined; this.#state = "started";
      return Object.freeze({ status: "admitted", exchange: this.#exchange });
    } catch (error) {
      if (this.#state === "prepared") {
        if (error instanceof RPCProtocolError && error.message === "canceled" || error instanceof TimeError && ["time_pending", "time_unavailable", "time_continuity"].includes(error.code)) throw error;
        const reason = error instanceof ResourceError && error.code === "resource_exhausted" ? "resource_exhausted" :
          error instanceof RPCProtocolError && error.message === "not_ready" ? "not_ready" :
            error instanceof Error && error.message === "completion_dependency_unavailable" ? "dependency_unavailable" : undefined;
        if (immediate && reason !== undefined) return Object.freeze({ status: "not_admitted", submission: "not_submitted", reason });
      }
      this.#fail(error); throw error;
    } finally { reserved?.release(); claim?.release(); this.#busy = false; this.#collect(); }
  }
  get execution(): boolean { return this.#operationReference !== undefined; }
  reference(): V4OperationReference { if (this.#operationReference === undefined) throw new RPCProtocolError("operation_reference_unavailable"); return this.#operationReference; }
  get prepared(): boolean { return this.#state === "prepared"; }
  cleanupStatus(): V4CleanupStatus {
    if (this.#exchange !== undefined) return this.#exchange.cleanupStatus();
    this.#collect();
    return cleanupResult({ status: this.#reference === undefined ? "complete" : "pending",
      core_cleanup: this.#reference === undefined ? "complete" : "pending", pending_callbacks: this.#callbackActive || this.#saveTail ? 1n : 0n });
  }
  /** A public prepared handle can be closed or started during this finite
   * observation. Transfer follows its original exchange without extending the
   * observer's deadline; cancellation retains no perpetual Promise reaction. */
  waitPreparedCleanup(signal?: AbortSignal): Promise<V4CleanupStatus> {
    if (this.#cleanupWake !== undefined || this.#creatingCleanup) throw new RPCProtocolError("wait_in_progress");
    this.#creatingCleanup = true;
    try {
      const initial = this.cleanupStatus();
      if (initial.status !== "pending") return Promise.resolve(initial);
      if (signal?.aborted) return Promise.reject(new RPCProtocolError("wait_canceled"));
      const clock = this.#clock!, reference = this.#reference!.borrow();
      return new Promise<V4CleanupStatus>((resolve, reject) => {
        const abort = new AbortController();
        let done = false, checking = false, delegated = false, timer: ReturnType<typeof setTimeout> | undefined, window: TrustedWindow;
        const finish = (canceled = false, expired = false): void => {
          if (done) return; done = true; this.#cleanupWake = undefined;
          if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", cancel); abort.abort();
          const status = this.cleanupStatus(); if (!delegated) reference.release();
          if (canceled) reject(new RPCProtocolError("wait_canceled"));
          else resolve(expired && status.status === "pending" ? cleanupResult({ ...status, status: "cleanup_incomplete" }) : status);
        };
        const cancel = (): void => finish(true);
        const wake = (): void => {
          if (done || checking) return; checking = true;
          try {
            if (this.cleanupStatus().status !== "pending") { finish(); return; }
            if (!delegated && this.#exchange?.waitCleanup !== undefined) {
              const actual = this.#exchange.waitCleanup({ signal: abort.signal }); delegated = true;
              void actual.then(() => finish(), () => finish(false, true)).finally(() => reference.release());
            }
          } finally { checking = false; }
        };
        const tick = (): void => {
          timer = undefined; wake(); if (done) return;
          try { window.check(); timer = setTimeout(tick, timerChunk(window.remainingMS())); } catch { finish(false, true); }
        };
        this.#cleanupWake = wake; signal?.addEventListener("abort", cancel, { once: true });
        try { window = new TrustedWindow(clock, 5000n); if (signal?.aborted) cancel(); else tick(); }
        catch { finish(false, true); }
      });
    } finally { this.#creatingCleanup = false; }
  }
  checkReady(): void {
    if (this.#busy || this.#state !== "prepared") throw new RPCProtocolError("rpc_preparation_incomplete");
    this.#busy = true;
    try { this.#checkPrepared(); } finally { this.#busy = false; this.#collect(); }
  }
  onDetach(callback: () => void): void {
    if (this.#observed) throw new RPCProtocolError("rpc_request_owner"); this.#observed = true;
    if (this.#reference === undefined || this.#state === "closed" || this.#state === "failed" || this.#state === "started") callback(); else this.#detached = callback;
  }
  #fail(error: unknown): void { this.#diagnostic?.failure(error); this.#failure ??= error; this.#guard?.close(); this.#exchange?.close(); this.#state = "failed"; this.#collect(); }
  close(): void {
    if (this.#exchange !== undefined) { this.#exchange.close(); return; }
    if (this.#state === "closed" || this.#state === "failed") return; this.#guard?.close(); this.#state = "closed"; this.#collect();
  }
  #clearEncoding(): void {
    this.#fields?.contractDigest.fill(0); this.#fields?.operationID?.fill(0); this.#fields?.requestDigest?.fill(0); this.#fields = undefined;
    this.#codec?.close(); this.#codec = undefined;
  }
  #collect(): void {
    if (this.#busy || this.#collecting || this.#state === "encoding" || this.#state === "prepared") return;
    this.#collecting = true;
    try {
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    // Ordinary preparation drops source closures immediately. Recovery keeps
    // its paid target qualification until the actual local encoder/save exits.
    if (this.#target?.releaseUnused === undefined) this.#target = undefined;
    else if (!this.#encoding && !this.#saving && !this.#saveTail) { this.#target.releaseUnused(); this.#target = undefined; }
    this.#guard = undefined; this.#completionDeadline = undefined; this.#lease?.release(); this.#lease = undefined;
    const detached = this.#detached; this.#detached = undefined; detached?.();
    this.#abort.abort();
    if (this.#encoding || this.#saving || this.#saveTail) return;
    this.#diagnostic?.close(); this.#diagnostic = undefined;
    this.#clearEncoding(); this.#request?.close(); this.#request = undefined;
    this.#call?.close(); this.#call = undefined; this.#completion?.close(); this.#completion = undefined;
    this.#exchangeReference?.release(); this.#exchangeReference = undefined; this.#responseReference?.release(); this.#responseReference = undefined;
    this.#contract?.release(); this.#contract = undefined; this.#method = undefined; this.#group = undefined; this.#authentication = undefined;
    this.#reference?.release(); this.#reference = undefined; this.#clock = undefined;
    if (this.#job) { this.#job = false; this.#cleanup!.finishJob(); } this.#cleanup = undefined;
    } finally { this.#collecting = false; this.#cleanupWake?.(); }
  }
  toJSON(): object { return {}; }
}
Object.freeze(RPCUnaryPreparation.prototype); Object.freeze(RPCUnaryPreparation);
