import { operationReference, type V4OperationReference } from "../operationReference.js";
import { beginReferenceSave, referenceStoreRetention, referenceSaveFailure, referenceSaveReport, type V4OperationReferenceStore, type ReferenceSaveReport } from "../operationReferenceStore.js";
import { hex } from "./executionManagementCodec.js";
import type { RandomFill } from "./random.js";
import type { ServiceBindingTarget } from "./serviceBindingConfig.js";
import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge, type ApplicationHeader } from "./applicationHeader.js";
import { applicationHasPermit, type ApplicationGroup, type ApplicationPermit, type ApplicationWorkClass } from "./applicationExecutor.js";
import { byteLength } from "./cbor.js";
import type { TrustedClock } from "./clock.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import { checkApplicationMessageOutput, messageInputBytes } from "./messageCodec.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import { encodeText } from "./rpcUnaryPreparation.js";
import type { AdmissionOffer, ServiceContractSnapshot } from "./serviceContract.js";
import type { SessionCleanup } from "./sessionCleanup.js";
import { observeTask } from "./taskObservation.js";
import { timeAdd } from "./timeArithmetic.js";

export interface NotifyPreparationOptions {
  readonly timeoutMS?: bigint; readonly deadlineAtMS?: bigint; readonly admissionNotAfterMS?: bigint; readonly admission?: "queued" | "try_now";
}
export interface NotifyProgress {
  readonly state: "encoding" | "prepared" | "started" | "terminal";
  readonly submission: "not_submitted" | "unknown" | "submitted";
  readonly reason?: "closed" | "canceled" | "deadline_exceeded" | "channel_closed";
}
export type NotifyStartResult = Readonly<{ status: "admitted" }> | Readonly<{ status: "not_admitted"; submission: "not_submitted"; reason: "not_ready" | "resource_exhausted" }>;
export interface NotifyStartTarget { start(operation: NotifyPreparation): NotifyStartResult; }
export function captureNotifyOptions(input: NotifyPreparationOptions = {}, context?: V4ApplicationContext): Required<Pick<NotifyPreparationOptions, "timeoutMS">> & NotifyPreparationOptions {
  const { timeoutMS = 30000n, deadlineAtMS, admissionNotAfterMS, admission } = input;
  const nested = applicationHasPermit(context);
  if (admission !== undefined && admission !== "queued" && admission !== "try_now") throw new RPCProtocolError("notify_options");
  if (nested && admission === "queued") throw new RPCProtocolError("admission_mode_incompatible");
  for (const value of [timeoutMS, deadlineAtMS, admissionNotAfterMS]) if (value !== undefined && (typeof value !== "bigint" || value < 1n || value >= 1n << 64n)) throw new RPCProtocolError("notify_options");
  return Object.freeze({ timeoutMS, admission: admission ?? (nested ? "try_now" : "queued"), ...(deadlineAtMS === undefined ? {} : { deadlineAtMS }), ...(admissionNotAfterMS === undefined ? {} : { admissionNotAfterMS }) });
}
export function notifyPreparationCharges(method: CapturedMethodDefinition, contract: Pick<ServiceContractSnapshot, "requestMaxBytes">, inputBytes: number, runtimeBytes: bigint): readonly ResourceVector[] {
  return [new ResourceVector([8192n + 8n * runtimeBytes + BigInt(inputBytes + method.request.maximum) + (method.request.application?.applicationBytes ?? 0n),
    0n, 0n, 16n, 1n, 4n, 1n, 0n, 0n, 0n, 0n]), rpcPayloadCharge(contract.requestMaxBytes, runtimeBytes),
    applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes)];
}

/** Original immutable notification and local submission ownership. Execution
 * references share the same ID/digest format; neither variant owns a reply. */
export class NotifyPreparation {
  #reference: ResourceReference | undefined;
  #payload: RPCPayload | undefined;
  #codec: ApplicationHeaderCodec | undefined;
  #contract: ServiceContractSnapshot | undefined;
  #method: CapturedMethodDefinition | undefined;
  #group: ApplicationGroup | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #cleanup: SessionCleanup | undefined;
  #source: RPCPublicationGuard | undefined;
  #target: NotifyStartTarget | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #deadline: TrustedDeadline | undefined;
  #preparationDeadline: TrustedDeadline | undefined;
  #header: ApplicationHeader | undefined;
  #wireDeadline = 0n;
  #cutoff: TrustedDeadline | undefined;
  #notBefore: bigint | undefined;
  #operationID: Uint8Array<ArrayBuffer> | undefined;
  #operationReference: V4OperationReference | undefined;
  #localAuthority: string | undefined;
  #destination: ServiceBindingTarget | undefined;
  #namespace: string;
  #admission: 0 | 1;
  #saving = false;
  #saveEntered = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  readonly #abort = new AbortController();
  #state: NotifyProgress["state"] = "encoding";
  #submission: NotifyProgress["submission"] = "not_submitted";
  #reason: NotifyProgress["reason"];
  #closed = false;
  #encoding = false;
  #callback = false;
  #publishing = false;
  #begun = false;
  #job = false;
  #groupHeld = false;
  #busy = false;
  #detached: (() => void) | undefined;
  #waiter: (() => void) | undefined;
  #canceledPublication: (() => void) | undefined;
  constructor(method: CapturedMethodDefinition, namespace: string, contract: ServiceContractSnapshot, options: NotifyPreparationOptions,
    source: RPCPublicationGuard, target: NotifyStartTarget, clock: TrustedClock, parent: TrustedDeadline,
    group: ApplicationGroup, authentication: V4AuthenticatedContext, delivery: ReceiveDeliveryGate, cleanup: SessionCleanup,
    readonly workClass: ApplicationWorkClass, readonly inputBytes: number, runtimeBytes: bigint, references: readonly ResourceReference[],
    offer?: AdmissionOffer, random?: RandomFill, localAuthority?: string, destination?: ServiceBindingTarget) {
    const costs = notifyPreparationCharges(method, contract, inputBytes, runtimeBytes), captured = captureNotifyOptions(options);
    if (method.shape !== "notify" || (method.semantics === "execution") !== (offer !== undefined) || references.length !== costs.length ||
        !references.every(reference => references[0]!.sameEnvironment(reference)) || !contract.sameEnvironment(references[0]!)) throw new RPCProtocolError("notify_binding");
    if (method.semantics === "execution" && (random === undefined || localAuthority === undefined || destination === undefined) ||
        method.semantics !== "execution" && captured.admissionNotAfterMS !== undefined) throw new RPCProtocolError("notify_binding");
    this.#namespace = namespace; this.#admission = captured.admission === "try_now" ? 1 : 0; this.#localAuthority = localAuthority; this.#destination = destination;
    contract.checkMethod(namespace, method); this.#reference = references[0]!.take(costs[0]!); this.#busy = true;
    this.#method = method; this.#source = source; this.#target = target; this.#group = group; this.#authentication = authentication; this.#cleanup = cleanup;
    try {
      cleanup.startJob(); this.#job = true; group.retain(); this.#groupHeld = true;
      this.#payload = new RPCPayload(contract.requestMaxBytes, runtimeBytes, references[1]!);
      this.#codec = new ApplicationHeaderCodec(runtimeBytes, references[2]!, references[3]!); this.#contract = contract.retain();
      source.check(); const sample = clock.sample(), now = sample.requireInterval(), horizon = contract.uint(offer === undefined ? 11 : 17);
      parent.checkAt(sample);
      this.#wireDeadline = captured.deadlineAtMS ?? timeAdd(now.lowerMS, captured.timeoutMS < horizon ? captured.timeoutMS : horizon);
      if (this.#wireDeadline > timeAdd(now.lowerMS, horizon) || this.#wireDeadline <= now.upperMS) throw new RPCProtocolError("deadline_exceeded");
      this.#deadline = parent.fork(this.#wireDeadline < parent.cap ? this.#wireDeadline : parent.cap);
      this.#preparationDeadline = this.#deadline.fork(timeAdd(now.lowerMS, 60000n) < this.#deadline.cap ? timeAdd(now.lowerMS, 60000n) : this.#deadline.cap);
      if (offer !== undefined) {
        offer.copyEncoded(contract, (1n << 64n) - 1n, new Uint8Array(256));
        const latest = timeAdd(now.lowerMS, contract.uint(16));
        let cutoff = captured.admissionNotAfterMS ?? latest;
        if (offer.notAfterMS < cutoff) cutoff = offer.notAfterMS;
        if (this.#wireDeadline < cutoff) cutoff = this.#wireDeadline;
        if (cutoff <= now.upperMS || cutoff <= offer.notBeforeMS || cutoff > latest) throw new RPCProtocolError("admission_window_closed");
        this.#notBefore = offer.notBeforeMS; this.#cutoff = this.#deadline.fork(cutoff < this.#deadline.cap ? cutoff : this.#deadline.cap);
        this.#operationID = new Uint8Array(32); let prefix = cutoff;
        for (let n = 7; n >= 0; n--) { this.#operationID[n] = Number(prefix & 255n); prefix >>= 8n; }
        random!(this.#operationID.subarray(8));
      }
      this.#lease = delivery.retain(this.#reference, () => this.close()); this.checkPublication();
      Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
    finally { this.#busy = false; this.#collect(); }
    this.#tick();
  }
  #tick(): void {
    this.#timer = undefined;
    if (this.#state === "terminal") return;
    try {
      this.checkPublication(); let left = this.#deadline!.remainingMS();
      if (!this.#begun) { const prepared = this.#preparationDeadline!.remainingMS(); if (prepared < left) left = prepared;
        if (this.#cutoff !== undefined) { const cutoff = this.#cutoff.remainingMS(); if (cutoff < left) left = cutoff; } }
      if (this.current()) this.#timer = setTimeout(() => this.#tick(), timerChunk(left));
    }
    catch { this.close("deadline_exceeded"); }
  }
  onDetach(callback: () => void): void { if (this.#detached !== undefined) throw new RPCProtocolError("notify_owner"); this.#detached = callback; this.#collect(); }
  checkPublication(): void {
    if (this.#state === "terminal" || this.#closed && !this.#begun) throw new RPCProtocolError("notify_closed");
    this.#reference!.checkRetained(); this.#deadline!.check(); if (!this.#begun) { this.#preparationDeadline!.check(); this.#cutoff?.check(); }
    if (!this.current()) throw new RPCProtocolError("notify_closed"); this.#lease!.check(); this.#source!.check();
    if (!this.#source!.current()) throw new RPCProtocolError("source_unavailable");
  }
  checkStart(): void {
    this.checkPublication();
    if (!this.#begun && this.#notBefore !== undefined && this.#deadline!.sample().requireInterval().lowerMS < this.#notBefore) throw new RPCProtocolError("time_pending");
  }
  current(): boolean { return this.#state !== "terminal" && (!this.#closed || this.#begun) && this.#source?.current() === true; }
  encode(value: unknown, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void> {
    if (this.#state !== "encoding" || this.#encoding) throw new RPCProtocolError("notify_owner"); this.#encoding = true;
    const cancel = (): void => this.close("canceled");
    signal?.addEventListener("abort", cancel, { once: true }); context?.signal.addEventListener("abort", cancel, { once: true });
    if (signal?.aborted || context?.signal.aborted) cancel();
    return observeTask(this.#encode(value, context), this.#abort.signal).finally(() => {
      signal?.removeEventListener("abort", cancel); context?.signal.removeEventListener("abort", cancel);
    });
  }
  async #encode(value: unknown, context?: V4ApplicationContext): Promise<void> {
    let permit: ApplicationPermit | undefined;
    try {
      this.checkPublication(); const codec = this.#method!.request, application = codec.application;
      if (messageInputBytes(value, codec.implementation, codec.maximum) > this.inputBytes) throw new RPCProtocolError("encode_failed");
      let encoded: Uint8Array;
      if (application === undefined) encoded = codec.implementation === "bytes" ? value as Uint8Array : encodeText(value as string, this.#contract!.requestMaxBytes);
      else {
        const enter = (): void => { this.#cleanup!.enterCallback(); this.#callback = true; };
        const direct = application.execution === "sync" ? this.#group!.synchronous(context, () => this.checkPublication(), () => { enter(); return application.encode(context!, value); }) : { used: false as const };
        if (direct.used) encoded = direct.value;
        else {
          permit = applicationHasPermit(context) ? this.#group!.tryOrdinary(this.workClass, context) : await this.#group!.acquire(this.workClass, this.#abort.signal, () => this.checkPublication(), context);
          this.checkPublication(); const invocation = this.#group!.context(permit, this.#authentication!, this.#abort.signal); context = undefined;
          try { enter(); encoded = application.execution === "sync" ? application.encode(invocation.context, value) : await application.encode(invocation.context, value); }
          finally { invocation.release(); }
        }
      }
      this.checkPublication(); const bytes = checkApplicationMessageOutput(encoded, codec.maximum);
      if (byteLength(bytes) > this.#contract!.requestMaxBytes) throw new RPCProtocolError("application_request_limit");
      this.#payload!.write(0, bytes); this.#payload!.seal(); const digest = new Uint8Array(32); this.#contract!.copyDigest(digest);
      const requestDigest = this.#operationID === undefined ? undefined : new Uint8Array(32);
      try {
        const fields = { kind: this.#operationID === undefined ? "observation_notify" as const : "execution_notify" as const,
          typeID: this.#method!.typeID, payloadBytes: byteLength(bytes), deadlineAtMS: this.#wireDeadline, contractDigest: digest,
          ...(this.#operationID === undefined ? {} : { operationID: this.#operationID, requestDigest: requestDigest!, admissionMode: this.#admission, responseLimitBytes: 0 }) };
        let header = this.#codec!.create(fields);
        if (requestDigest !== undefined) {
          const original = this.#payload!.borrow(byteLength(bytes));
          try { this.#contract!.executionDigest(header, original.bytes, requestDigest); } finally { original.release(); }
          header = this.#codec!.create(fields);
          this.#operationReference = operationReference({ tenant: this.#authentication!.tenant, audience: this.#authentication!.audience,
            namespace: this.#namespace, subject: this.#authentication!.localSubject, authority: this.#localAuthority!, operation: hex(this.#operationID!),
            requestDigest: hex(requestDigest), contractDigest: hex(digest) }, this.#destination!, this.#wireDeadline,
            Number(this.#contract!.uint(13)) as 0 | 1, Number(this.#contract!.uint(19)) as 0 | 1, 0, 2);
        }
        this.#header = header;
      } finally { digest.fill(0); requestDigest?.fill(0); this.#operationID?.fill(0); this.#operationID = undefined; }
      this.#contract!.checkRequest(this.#header); this.checkPublication(); this.#state = "prepared";
    } catch (error) { this.close(); throw error; }
    finally { permit?.release(); if (this.#callback) this.#cleanup!.exitCallback(); this.#callback = false; this.#encoding = false; this.#collect(); }
  }
  get execution(): boolean { return this.#operationReference !== undefined; }
  reference(): V4OperationReference { if (this.#operationReference === undefined) throw new RPCProtocolError("operation_reference_unavailable"); return this.#operationReference; }
  async saveReference(store: V4OperationReferenceStore, context?: V4ApplicationContext, signal?: AbortSignal): Promise<ReferenceSaveReport> {
    const cancel = (): void => this.close("canceled");
    try {
      this.checkPublication();
      if (applicationHasPermit(context)) throw new RPCProtocolError("admission_mode_incompatible");
      if (this.#state !== "prepared" || !this.execution || this.#saveEntered) throw new RPCProtocolError("operation_reference_unavailable");
      store.checkDomain(this.#destination!.authority); this.#saveEntered = this.#saving = true;
      signal?.addEventListener("abort", cancel, { once: true }); if (signal?.aborted) throw new RPCProtocolError("canceled");
      const report = await beginReferenceSave(store, { reference: this.reference(), owner: this.#reference!, group: this.#group!, authentication: this.#authentication!,
        cleanup: this.#cleanup!, signal: this.#abort.signal, ...(context === undefined ? {} : { context }), immediate: this.#admission === 1,
        check: () => this.checkPublication() }, referenceStoreRetention(store));
      if (report.failure !== undefined || report.save.outcome !== "confirmed") { this.close(); return report; }
      try { this.checkPublication(); if (signal?.aborted) throw new RPCProtocolError("canceled"); }
      catch (error) { this.close(); return referenceSaveReport({ ...report, failure: referenceSaveFailure(error) }); }
      return report;
    } catch (error) {
      this.close(); return referenceSaveReport({ save: Object.freeze({ attempted: false, outcome: "unknown" as const }), failure: referenceSaveFailure(error), cleanup: this.cleanupStatus() });
    } finally { signal?.removeEventListener("abort", cancel); this.#saving = false; this.#collect(); }
  }
  start(context?: V4ApplicationContext, signal?: AbortSignal): NotifyStartResult {
    if (this.#state === "started" || this.#begun) return Object.freeze({ status: "admitted" });
    this.checkStart(); if (this.#state !== "prepared" || this.#saving) throw new RPCProtocolError("notify_not_prepared");
    if (applicationHasPermit(context) && this.execution && this.#admission === 0) throw new RPCProtocolError("admission_mode_incompatible");
    if (signal?.aborted || context?.signal.aborted) throw new RPCProtocolError("canceled");
    return this.#target!.start(this);
  }
  /** Called only by the original publisher after its scalar admission gate. */
  admit(cancel: () => void): void { if (this.#state !== "prepared" || !this.current()) throw new RPCProtocolError("notify_owner"); this.#state = "started"; this.#publishing = true; this.#canceledPublication = cancel; }
  header(): ApplicationHeader { if (this.#header === undefined) throw new RPCProtocolError("notify_not_prepared"); return this.#header; }
  borrow(): RPCPayloadBorrow { return this.#payload!.borrow(this.header().payloadBytes); }
  begun(): void { this.#begun = true; this.#submission = "unknown"; }
  publicationFinished(submitted: boolean): void {
    if (submitted) this.#submission = "submitted"; else this.#reason ??= "channel_closed";
    this.#state = "terminal"; this.#publishing = false; this.#canceledPublication = undefined; this.#abort.abort(); this.#waiter?.(); this.#collect();
  }
  status(): Readonly<NotifyProgress> { return Object.freeze({ state: this.#state, submission: this.#submission, ...(this.#reason === undefined ? {} : { reason: this.#reason }) }); }
  waitSubmission(signal?: AbortSignal): Promise<Readonly<NotifyProgress & { wait?: "canceled" }>> {
    if (this.#waiter !== undefined) throw new RPCProtocolError("notify_wait_in_progress");
    if (this.#state !== "started" || signal?.aborted) return Promise.resolve(Object.freeze({ ...this.status(), ...(signal?.aborted ? { wait: "canceled" as const } : {}) }));
    return new Promise(resolve => {
      const finish = (): void => { this.#waiter = undefined; signal?.removeEventListener("abort", finish); resolve(Object.freeze({ ...this.status(), ...(signal?.aborted ? { wait: "canceled" as const } : {}) })); };
      this.#waiter = finish; signal?.addEventListener("abort", finish, { once: true }); if (signal?.aborted || this.#state === "terminal") finish();
    });
  }
  close(reason: NotifyProgress["reason"] = "closed"): void {
    if (this.#closed) return; this.#closed = true;
    // The caller relinquishes observation, never a previously admitted tail.
    if (!this.#begun) {
      this.#reason = reason; this.#abort.abort(); this.#canceledPublication?.(); if (!this.#publishing) this.#state = "terminal";
      this.#source = undefined; this.#target = undefined; this.#lease?.release(); this.#lease = undefined;
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
      const detach = this.#detached; this.#detached = undefined; detach?.();
    }
    this.#waiter?.(); this.#collect();
  }
  #collect(): void {
    if (this.#busy || this.#encoding || this.#saving || this.#publishing || this.#state !== "terminal") return; this.#busy = true;
    try {
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
      this.#lease?.release(); this.#lease = undefined; this.#payload?.close(); this.#payload = undefined;
      this.#codec?.close(); this.#codec = undefined; this.#contract?.release(); this.#contract = undefined; this.#method = undefined;
      this.#operationID?.fill(0); this.#operationID = undefined; this.#cutoff = undefined; this.#destination = undefined; this.#localAuthority = undefined;
      this.#source = undefined; this.#target = undefined; this.#deadline = undefined; this.#preparationDeadline = undefined; this.#authentication = undefined; this.#header = undefined;
      if (this.#groupHeld) this.#group!.release(); this.#groupHeld = false; this.#group = undefined;
      if (this.#job) this.#cleanup!.finishJob(); this.#job = false; this.#cleanup = undefined;
      this.#reference?.release(); this.#reference = undefined; const detach = this.#detached; this.#detached = undefined; detach?.();
    } finally { this.#busy = false; }
  }
  cleanupStatus(): V4CleanupStatus { const done = this.#reference === undefined; return Object.freeze({ status: done ? "complete" : "pending", core_cleanup: done ? "complete" : "pending", pending_callbacks: this.#callback ? 1n : 0n }); }
}
