import type { V4StreamOwner } from "../public.js";
import type { RPCStreamingExchange } from "./rpcStreamingExchange.js";
import type { RPCStreamPoolDemand } from "./rpcPreacceptedStreams.js";
import { captureNotifyOptions, type NotifyPreparation, type NotifyPreparationOptions, type NotifyProgress } from "./notifyPreparation.js";
import { staticServiceContracts, type V4StaticServiceContracts } from "../staticServiceContracts.js";
import { referenceSaveFailure, referenceSaveReport, type V4OperationReferenceStore, type ReferenceSaveReport } from "../operationReferenceStore.js";
import type { V4OperationReference } from "../operationReference.js";
import type { V4AdmissionOffer } from "../admissionOffer.js";
import { cleanupResult } from "./lifecycle.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import { applicationHasPermit } from "./applicationExecutor.js";
import type { TrustedClock } from "./clock.js";
import type { ContractQueryTarget } from "./contractQuery.js";
import type { ContractQueryAcquisition, ContractQueryDestination } from "./contractQueryAcquisition.js";
import type { ContractSnapshotBatch, ContractSnapshotItem } from "./contractSnapshotReader.js";
import { timerChunk, TrustedDeadline } from "./deadline.js";

import type { ProtectedResourceReservation, ResourceReference, ResourceRequest } from "./resources.js";
import { RPCUnaryCall } from "./rpcUnaryCall.js";
import type { RPCUnaryTakeResult } from "./rpcUnaryExchange.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { captureUnaryOptions, type RPCUnaryPreparation, type RPCUnaryPreparationOptions } from "./rpcUnaryPreparation.js";
import type { AdmissionOffer, ServiceContractSnapshot } from "./serviceContract.js";
import { checkServiceBindingTarget, type CapturedBindingMethod, type CapturedServiceBinding } from "./serviceBindingConfig.js";
import type { ServiceOfferParticipant, ServiceOfferWork } from "./serviceOfferWork.js";
import type { ServiceBindingReservation } from "./serviceBindingPool.js";
import { observeTask } from "./taskObservation.js";
import type { ContractRenewalProtection } from "./queryRenewalPosition.js";
import { captureServiceOfferTiming, serviceOfferBlocked, type ServiceOfferTiming, type ServiceOfferMembership } from "./serviceOfferPlan.js";

export interface ServiceBindingLease { check(): void; release(): void }
/** SDK-only source. A Controller source selects existing accepting Sessions;
 * actual protocol work always uses the selected original Session capabilities. */
export interface ServiceBindingSource {
  readonly clock: TrustedClock;
  readonly group: object;
  incarnation?(): object;
  resumeSource?(stream: V4StreamOwner): ServiceBindingSource;
  observeCurrent?(reference: ResourceReference, changed: () => void): () => void;
  waitForCurrent?(deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void>;
  check(): void;
  current(): boolean;
  checkDependency(method: CapturedBindingMethod, contract: ServiceContractSnapshot): void;
  authentication(): V4AuthenticatedContext;
  deadline(duration: bigint): TrustedDeadline;
  protectRenewal(reference: ResourceReference): ContractRenewalProtection | undefined;
  observeAvailability(reference: ResourceReference, wake: () => void): () => void;
  retain(reference: ResourceReference, closed: () => void): ServiceBindingLease;
  query(targets: readonly ContractQueryTarget[], deadline: TrustedDeadline, windows: readonly bigint[], context: V4ApplicationContext | undefined,
    delivery: () => ContractQueryDestination, renewal?: ContractRenewalProtection): ContractQueryAcquisition;
  prepareNotify(method: CapturedBindingMethod, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined, value: unknown, options: NotifyPreparationOptions,
    context?: V4ApplicationContext, signal?: AbortSignal): Promise<NotifyPreparation>;
  prepareStream(method: CapturedBindingMethod, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    value: unknown, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation<RPCStreamingExchange>>;
  preacceptStreams(namespace: string, targets: readonly Readonly<{ method: CapturedBindingMethod; contract: ServiceContractSnapshot }>[]): readonly RPCStreamPoolDemand[];
  prepareResume(method: CapturedBindingMethod, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    stream: V4StreamOwner, token: Uint8Array, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation>;
  prepareDispatch?(method: CapturedBindingMethod, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    value: unknown, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation>;
  prepare(method: CapturedBindingMethod, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    value: unknown, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation>;
}
export type ServiceContractAvailability = "not_ready" | "available" | "time_pending" | "offer_expired" | "source_unavailable" | "closed";
export interface ServiceContractProgress {
  readonly availability: ServiceContractAvailability;
  readonly installed: boolean;
  readonly acceptance: "exact" | "bounded";
  readonly digest?: string;
  readonly offer?: V4AdmissionOffer;
  readonly refresh: "idle" | "checking" | "installed" | "rejected" | "deferred" | "blocked";
  readonly reason?: string;
}
export interface ServiceRefreshResult { readonly method: object; readonly contract: ServiceContractProgress }
interface MethodSlot {
  config: CapturedBindingMethod | undefined;
  readonly acceptance: "exact" | "bounded";
  current: ServiceContractSnapshot | undefined;
  offer: AdmissionOffer | undefined;
  position: ProtectedResourceReservation | undefined;
  retired: ProtectedResourceReservation | undefined;
  job: RefreshJob | undefined;
  generation: bigint;
  refresh: ServiceContractProgress["refresh"];
  reason: string | undefined;
  membership: ServiceOfferMembership | undefined;
  advertisementAfterMS: bigint | undefined;
}
interface RefreshJob {
  readonly slots: readonly MethodSlot[];
  readonly deadline: TrustedDeadline;
  readonly abort: AbortController;
  readonly update: Uint8Array | undefined;
  readonly generation: bigint[];
  readonly context: V4ApplicationContext | undefined;
  query: ContractQueryAcquisition | undefined;
  promise: Promise<readonly ServiceRefreshResult[]>;
  timer: ReturnType<typeof setTimeout> | undefined;
  joined: boolean;
  readonly renewal: boolean;
  readonly incarnation: object | undefined;
}
const maximum = (1n << 64n) - 1n;
function digest(contract: ServiceContractSnapshot): string {
  const bytes = new Uint8Array(32); contract.copyDigest(bytes);
  try { return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join(""); } finally { bytes.fill(0); }
}
function failure(error: unknown): string {
  return error instanceof Error && /^[a-z][a-z0-9_]{0,63}$/u.test(error.message) ? error.message : "source_unavailable";
}
function equal(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  return a === undefined || b === undefined ? a === b : a.length === b.length && a.every((value, index) => value === b[index]);
}

/** Service-level current/candidate ownership. All original method positions
 * exist before the first query; descriptor-only methods never cause implicit
 * network work. Installation and Prepare capture use this same scalar gate. */
export class ServiceBinding implements ServiceOfferParticipant {
  #advertisementTimer: ReturnType<typeof setTimeout> | undefined;
  #advertisementRunning = false;
  #advertisementCursor = 0;
  #staticContracts: V4StaticServiceContracts | undefined;
  #source: ServiceBindingSource | undefined;
  #reservation: ServiceBindingReservation | undefined;
  #lease: ServiceBindingLease | undefined;
  #config: CapturedServiceBinding | undefined;
  readonly #slots: MethodSlot[];
  readonly #methods = new WeakMap<object, MethodSlot>();
  readonly #jobs = new Set<RefreshJob>();
  readonly #calls = new Set<RPCUnaryCall>();
  readonly #notifyCalls = new Set<NotifyPreparation>();
  readonly #streamPools = new Map<object, RPCStreamPoolDemand>();
  readonly #abort = new AbortController();
  #closed = false;
  #sealed = false;
  #delivered = false;
  #busy = false;
  #onClose: (() => void) | undefined;
  #renewal: ContractRenewalProtection | undefined;
  #protecting = false;
  #incarnation: object | undefined;
  #unobserveCurrent: (() => void) | undefined;
  #syncingStreams = false;
  #renewalIncarnation: object | undefined;
  constructor(config: CapturedServiceBinding, reservation: ServiceBindingReservation, source: ServiceBindingSource) {
    this.#config = config; this.#reservation = reservation; this.#source = source;
    this.#slots = config.methods.map((method, index) => ({ config: method, acceptance: method.acceptance.mode, current: undefined, offer: undefined,
      position: reservation.current[index]!, retired: undefined, job: undefined, generation: 0n, refresh: "idle", reason: undefined, membership: undefined, advertisementAfterMS: undefined }));
    for (const slot of this.#slots) this.#methods.set(slot.config!.method, slot);
    try {
      reservation.onClose(() => this.close()); this.#check();
      this.#lease = source.retain(reservation.reference, () => this.close()); this.#check();
      this.#unobserveCurrent = source.observeCurrent?.(reservation.reference, () => this.#sourceChanged());
      Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  get config(): CapturedServiceBinding {
    if (this.#config === undefined) throw new RPCProtocolError("service_binding_closed"); return this.#config;
  }
  #check(): void {
    if (this.#closed || this.#sealed) throw new RPCProtocolError("service_binding_closed");
    this.#reservation!.check(); this.#source!.check(); this.#lease?.check();
    checkServiceBindingTarget(this.config.target, this.#source!.authentication());
    if (this.#closed || this.#sealed || !this.#source?.current()) throw new RPCProtocolError("source_unavailable");
    const incarnation = this.#source.incarnation?.();
    if (this.#incarnation !== incarnation) {
      this.#incarnation = incarnation; this.#releaseRenewal();
      for (const demand of this.#streamPools.values()) demand.close(); this.#streamPools.clear();
    }
  }
  /** Only publication or an explicit refresh renews these declared demands.
   * Prepare/Call and read-only checks never create an accepted Stream pool. */
  #sourceChanged(): void {
    if (this.#closed || !this.#delivered || this.#syncingStreams) return;
    this.#syncingStreams = true;
    let demands: readonly RPCStreamPoolDemand[] = [];
    try {
      this.#check(); const incarnation = this.#incarnation;
      if (incarnation !== this.#renewalIncarnation) {
        this.#renewalIncarnation = incarnation;
        // Reuse the same logical membership and exact digest. Notification
        // wakes blocked scheduling without replacing a live query or its cap.
        for (const slot of this.#slots) slot.membership?.sourceAvailable();
      }
      const streaming = this.#slots.filter(slot => slot.config!.preacceptStream && slot.current !== undefined && !this.#streamPools.has(slot.config!.method));
      if (streaming.length === 0) return;
      const generations = streaming.map(slot => slot.generation);
      demands = this.#source!.preacceptStreams(this.config.namespace, streaming.map(slot => ({ method: slot.config!, contract: slot.current! })));
      this.#check();
      if (incarnation !== this.#incarnation || streaming.some((slot, index) => slot.generation !== generations[index])) return;
      for (let index = 0; index < streaming.length; index++) this.#streamPools.set(streaming[index]!.config!.method, demands[index]!);
      demands = [];
    } catch { /* Original pool admission reports not_ready until capacity exists. */ }
    finally { for (const demand of demands) demand.close(); this.#syncingStreams = false; }
  }
  #select(methods: readonly object[]): MethodSlot[] {
    if (!Array.isArray(methods) || methods.length < 1 || methods.length > this.#slots.length || new Set(methods).size !== methods.length) throw new RPCProtocolError("service_selector_invalid");
    return methods.map(method => {
      const slot = this.#methods.get(method);
      if (slot === undefined) throw new RPCProtocolError("service_selector_invalid"); return slot;
    });
  }
  #checkOwner(): void {
    if (this.#closed || this.#sealed) throw new RPCProtocolError("service_binding_closed");
    this.#reservation!.check(); this.#lease?.check();
  }
  deadline(duration: bigint): TrustedDeadline {
    this.#checkOwner(); return this.#source!.deadline(duration);
  }
  checkDelivery(): void {
    // A transferred preparation already owns its original Session safety gate.
    // Replacing Controller.current cannot recall that independent work.
    if (this.#source?.incarnation === undefined) this.#check(); else this.#checkOwner();
  }
  async #waitForCurrent(deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void> {
    this.#checkOwner();
    const source = this.#source!;
    if (source.waitForCurrent === undefined) return;
    const release = this.#reservation!.hold();
    try {
      await source.waitForCurrent(deadline, context, AbortSignal.any([this.#abort.signal, ...(signal === undefined ? [] : [signal])]));
      this.#check(); deadline.check();
    } finally { release(); this.#collect(); }
  }
  async #readyOptions<T extends { readonly deadlineAtMS?: bigint; readonly admission?: "queued" | "try_now" }>(method: object, options: T,
    lifetime: bigint, context?: V4ApplicationContext, signal?: AbortSignal): Promise<T> {
    this.#checkOwner(); if (this.#source!.waitForCurrent === undefined) return options;
    const slot = this.#select([method])[0]!, contract = slot.current;
    if (contract === undefined) throw new RPCProtocolError("not_ready");
    const horizon = contract.uint(contract.semantics === "execution" ? 17 : 11), duration = lifetime < horizon ? lifetime : horizon;
    const deadline = options.deadlineAtMS === undefined ? this.deadline(duration) : new TrustedDeadline(this.#source!.clock, options.deadlineAtMS);
    if (options.admission === "try_now" || applicationHasPermit(context)) this.#check();
    else await this.#waitForCurrent(deadline, context, signal);
    return { ...options, deadlineAtMS: deadline.cap };
  }
  onClose(callback: () => void): void {
    if (this.#onClose !== undefined) throw new RPCProtocolError("service_binding_owner");
    if (this.#closed) callback(); else this.#onClose = callback;
  }
  async initialize(deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal, contracts?: V4StaticServiceContracts): Promise<this> {
    if (this.#delivered) throw new RPCProtocolError("service_binding_owner");
    const release = this.#reservation!.hold();
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    try {
      const initial = this.#slots.filter(slot => slot.config!.initial);
      if (contracts === undefined) { if (initial.length !== 0) await this.#refresh(initial, deadline, undefined, context, signal); }
      else {
        this.#check(); deadline.check(); if (signal?.aborted) throw new RPCProtocolError("canceled");
        if (context !== undefined) applicationHasPermit(context);
        this.#staticContracts = contracts;
        const entries = staticServiceContracts(contracts, this.config.definition, this.config.target, this.#source!.authentication(), this.#reservation!.reference).filter(entry => this.#methods.get(entry.method)?.config?.initial);
        // Retain every body before validation samples the host clock. These
        // are the registered original snapshots, not extra body copies.
        const retained: ServiceContractSnapshot[] = [];
        try {
          for (const entry of entries) retained.push(entry.contract.retain());
          for (const entry of entries) {
            const slot = this.#methods.get(entry.method)!;
            this.#validate(slot, entry.contract, entry.offer, false);
            this.#check(); deadline.check(); if (signal?.aborted || context?.signal.aborted) throw new RPCProtocolError("canceled");
            // No host work after this final gate. Transfer this exact retained
            // reference into the ordinary method current slot.
            slot.current = entry.contract; slot.offer = entry.offer; slot.generation++; slot.refresh = "installed";
            retained.splice(retained.indexOf(entry.contract), 1);
          }
        } finally { for (const contract of retained) contract.release(); }
      }
      this.#check(); deadline.check(); if (signal?.aborted) throw new RPCProtocolError("canceled");
      if (context !== undefined) applicationHasPermit(context);
      for (const slot of initial) {
        if (slot.current === undefined) throw new RPCProtocolError(slot.reason ?? "not_ready"); this.#validate(slot, slot.current, slot.offer, false);
      }
      const streaming = initial.filter(slot => slot.config!.preacceptStream);
      if (streaming.length !== 0) {
        if (applicationHasPermit(context)) throw new RPCProtocolError("admission_mode_incompatible");
        // Admit all declared targets before awaiting any OPEN. A static set
        // larger than the original pool fails initialization, not later calls.
        const demands = this.#source!.preacceptStreams(this.config.namespace, streaming.map(slot => ({ method: slot.config!, contract: slot.current! })));
        for (let index = 0; index < streaming.length; index++) this.#streamPools.set(streaming[index]!.config!.method, demands[index]!);
        for (const demand of demands) await demand.ready(deadline, cancellation);
      }
      if (initial.length !== 0 && this.config.offerRefresh === "managed" && this.#staticContracts === undefined) await this.enrollOffers(deadline, this.config.offerTiming, context, signal);
      // The last validation may sample the host clock. Recheck the original
      // source and cancellation immediately before public transfer.
      this.#check(); deadline.check(); if (context !== undefined) applicationHasPermit(context);
      if (signal?.aborted) throw new RPCProtocolError("canceled");
      if (this.#closed || this.#sealed || !this.#source?.current()) throw new RPCProtocolError("source_unavailable");
      for (const slot of this.#slots) slot.membership?.activate(this);
      this.#renewalIncarnation = this.#incarnation;
      this.#delivered = true; this.#scheduleAdvertisements(); return this;
    } catch (error) { this.close(); throw error; }
    finally { release(); this.#collect(); }
  }
  // One charged binding timer coalesces installed bounded methods. The normal
  // refresh owner retains its single-flight and J/Q/candidate responsibility;
  // advertisement work never borrows the protected exact-Offer position.
  #needsAdvertisement(slot: MethodSlot): boolean {
    return slot.current !== undefined && (slot.acceptance === "bounded" ||
      this.#staticContracts !== undefined && this.config.offerRefresh === "managed" && slot.current.semantics === "execution");
  }
  #deferAdvertisements(slots: readonly MethodSlot[]): void {
    if (this.#closed || !this.#delivered) return;
    try {
      const now = this.#source!.clock.sample().requireInterval().upperMS;
      for (const slot of slots) if (this.#needsAdvertisement(slot)) {
        slot.advertisementAfterMS = now > maximum - this.config.contractCheckIntervalMS ? maximum : now + this.config.contractCheckIntervalMS;
      }
    } catch { /* Recovery uses the same bounded timer, never a new query deadline. */ }
  }
  #scheduleAdvertisements(): void {
    if (this.#closed || !this.#delivered || this.#advertisementRunning || this.#advertisementTimer !== undefined) return;
    const slots = this.#slots.filter(slot => this.#needsAdvertisement(slot));
    if (slots.length === 0) return;
    const interval = this.config.contractCheckIntervalMS;
    let wait = interval;
    try {
      const now = this.#source!.clock.sample().requireInterval().upperMS;
      for (const slot of slots) {
        slot.advertisementAfterMS ??= now > maximum - interval ? maximum : now + interval;
        const remaining = slot.advertisementAfterMS > now ? slot.advertisementAfterMS - now : 0n;
        if (remaining < wait) wait = remaining;
      }
    } catch { /* No time evidence grants a query. */ }
    if (this.#closed || !this.#delivered) return;
    this.#advertisementTimer = setTimeout(() => {
      this.#advertisementTimer = undefined;
      void this.#checkAdvertisements();
    }, timerChunk(wait));
  }
  async #checkAdvertisements(): Promise<void> {
    if (this.#closed || this.#advertisementRunning) return;
    this.#advertisementRunning = true;
    const selected: MethodSlot[] = [];
    try {
      this.#check();
      const now = this.#source!.clock.sample().requireInterval().upperMS; this.#check();
      for (let index = 0; index < this.#slots.length && selected.length < 8; index++) {
        const slot = this.#slots[(this.#advertisementCursor + index) % this.#slots.length]!;
        if (!this.#needsAdvertisement(slot) || slot.advertisementAfterMS === undefined || slot.advertisementAfterMS > now) continue;
        // A pending exact renewal/update wins. Keep a finite next opportunity
        // instead of adding a waiter or consuming a second candidate position.
        const offerDue = slot.membership !== undefined && slot.offer !== undefined &&
          slot.offer.notAfterMS <= now + this.#reservation!.pool.offers.envelope().advanceMS;
        if (slot.job !== undefined || offerDue) { this.#deferAdvertisements([slot]); continue; }
        selected.push(slot);
      }
      if (selected.length !== 0) {
        this.#advertisementCursor = (this.#slots.indexOf(selected[selected.length - 1]!) + 1) % this.#slots.length;
        const deadline = this.#source!.deadline(90000n);
        await this.#refresh(selected, deadline, undefined, undefined, undefined);
        for (const slot of selected) if (slot.job === undefined && slot.refresh === "rejected" && slot.reason !== undefined) {
          if (slot.reason === "resource_exhausted" || slot.reason === "refresh_in_progress") slot.refresh = "deferred";
          else if (serviceOfferBlocked(slot.reason)) slot.refresh = "blocked";
        }
      }
    } catch (error) {
      const reason = failure(error);
      for (const slot of selected) if (slot.job === undefined) {
        slot.refresh = serviceOfferBlocked(reason) ? "blocked" : "deferred"; slot.reason = reason;
      }
      // An unavailable source remains passive. This wake only rechecks the
      // original local source; it cannot Acquire, reconnect, or query a peer.
      if (selected.length === 0) this.#deferAdvertisements(this.#slots);
    } finally {
      this.#deferAdvertisements(selected); this.#advertisementRunning = false;
      this.#collect(); this.#scheduleAdvertisements();
    }
  }
  /** A read-only structural gate. It never queries, opens, or replenishes. */
  checkDependency(method: object): void {
    this.#check(); const slot = this.#select([method])[0]!;
    if (slot.current === undefined) throw new RPCProtocolError("not_ready");
    this.#validate(slot, slot.current, slot.offer, false);
    this.#source!.checkDependency(slot.config!, slot.current);
    this.#check();
  }
  ownsMethod(method: object): boolean { return this.#methods.has(method); }
  contract(method: object): ServiceContractProgress {
    const slot = this.#select([method])[0]!;
    let availability: ServiceContractAvailability = slot.current === undefined ? "not_ready" : "available";
    if (this.#closed) availability = "closed";
    else {
      try {
        this.#check();
        if (slot.offer !== undefined) {
          const now = this.#source!.clock.sample().requireInterval();
          if (now.upperMS >= slot.offer.notAfterMS) availability = "offer_expired";
          else if (now.lowerMS < slot.offer.notBeforeMS) availability = "time_pending";
        }
      } catch { availability = "source_unavailable"; }
    }
    const installedDigest = slot.current === undefined ? undefined : digest(slot.current);
    // Only copy an already installed, validated advertisement. The public value
    // retains no contract body, clock, binding, Session or runtime capability.
    const offer: V4AdmissionOffer | undefined = installedDigest === undefined || slot.offer === undefined ? undefined : Object.freeze({
      serviceContractDigest: installedDigest, notBeforeMS: slot.offer.notBeforeMS, notAfterMS: slot.offer.notAfterMS,
    });
    return Object.freeze({ availability, installed: slot.current !== undefined, acceptance: slot.acceptance,
      ...(installedDigest === undefined ? {} : { digest: installedDigest }), ...(offer === undefined ? {} : { offer }), refresh: slot.refresh,
      ...(slot.reason === undefined ? {} : { reason: slot.reason }) });
  }
  async refresh(methods: readonly object[], deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<readonly ServiceRefreshResult[]> {
    const slots = this.#select(methods); await this.#waitForCurrent(deadline, context, signal);
    const result = await this.#refresh(slots, deadline, undefined, context, signal);
    if (this.#source?.incarnation !== undefined) this.#sourceChanged();
    return result;
  }
  async update(method: object, approved: Uint8Array, deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<readonly ServiceRefreshResult[]> {
    const slots = this.#select([method]);
    if (slots[0]!.current === undefined) throw new RPCProtocolError("not_ready");
    if (!(approved instanceof Uint8Array) || approved.length !== 32) throw new RPCProtocolError("service_selector_invalid");
    const digest = new Uint8Array(approved);
    await this.#waitForCurrent(deadline, context, signal);
    return this.#refresh(slots, deadline, digest, context, signal);
  }
  /** Establish both original future vectors before a managed binding can be
   * handed off. An occupied old physical tail is awaited within this original
   * deadline; no query is canceled and no replacement slot is allocated. */
  protectRenewal(deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void> {
    return this.#protectRenewal(deadline, context, signal, false);
  }
  async #protectRenewal(deadline: TrustedDeadline, context: V4ApplicationContext | undefined, signal: AbortSignal | undefined, pending: boolean): Promise<void> {
    this.#check();
    if (!pending && !this.#slots.some(slot => slot.current?.semantics === "execution")) throw new RPCProtocolError("admission_offer_unavailable");
    if (!deadline.belongsTo(this.#source!.clock)) throw new RPCProtocolError("time_owner");
    if (this.#renewal !== undefined) return;
    if (this.#protecting) throw new RPCProtocolError("query_wait_in_progress");
    const release = this.#reservation!.hold(); this.#protecting = true;
    try {
      await new Promise<void>((resolve, reject) => {
        let timer: ReturnType<typeof setTimeout> | undefined, unobserve: (() => void) | undefined, complete = false, checking = false;
        const finish = (error?: unknown): void => {
          if (complete) return; complete = true;
          if (timer !== undefined) clearTimeout(timer); unobserve?.();
          signal?.removeEventListener("abort", cancel); context?.signal.removeEventListener("abort", cancel); this.#abort.signal.removeEventListener("abort", cancel);
          if (error === undefined) resolve(); else reject(error);
        };
        const cancel = (): void => finish(new RPCProtocolError("canceled"));
        const attempt = (): void => {
          if (complete || checking) return; checking = true;
          try {
            this.#check(); deadline.check(); if (context !== undefined) applicationHasPermit(context);
            if (signal?.aborted || context?.signal.aborted || this.#abort.signal.aborted) throw new RPCProtocolError("canceled");
            const protection = this.#source!.protectRenewal(this.#reservation!.reference);
            if (protection !== undefined) { this.#renewal = protection; finish(); }
          } catch (error) { finish(error); }
          finally { checking = false; }
        };
        const tick = (): void => {
          timer = undefined; attempt();
          if (!complete) try { timer = setTimeout(tick, timerChunk(deadline.remainingMS())); } catch (error) { finish(error); }
        };
        try {
          unobserve = this.#source!.observeAvailability(this.#reservation!.reference, attempt);
          signal?.addEventListener("abort", cancel, { once: true }); context?.signal.addEventListener("abort", cancel, { once: true });
          this.#abort.signal.addEventListener("abort", cancel, { once: true }); tick();
        } catch (error) { finish(error); }
      });
      this.#check(); deadline.check();
      if (signal?.aborted || context?.signal.aborted) throw new RPCProtocolError("canceled");
    } catch (error) { this.#releaseRenewal(); throw error; }
    finally { this.#protecting = false; release(); this.#collect(); }
  }
  /** Only the managed scheduler asks for protected exact-digest renewal.
   * Bounded advertisement checks and explicit changes use ordinary capacity. */
  renew(methods: readonly object[], deadline: TrustedDeadline): Promise<readonly ServiceRefreshResult[]> {
    this.#check(); const slots = this.#select(methods);
    if (this.#renewal === undefined || slots.some(slot => slot.current?.semantics !== "execution")) throw new RPCProtocolError("query_renewal_unavailable");
    return this.#refresh(slots, deadline, undefined, undefined, undefined, true);
  }
  /** SDK managed handoff gate. It qualifies every simultaneous source group,
   * then retains the same method memberships for updates and eventual Close.
   * The scheduler activates these members only at its actual publication gate. */
  async enrollOffers(deadline: TrustedDeadline, timing?: ServiceOfferTiming, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void> {
    this.#check(); const captured = captureServiceOfferTiming(timing);
    const slots = this.#slots.filter(slot => slot.current?.semantics === "execution" && slot.membership === undefined);
    if (slots.length === 0) return;
    await this.protectRenewal(deadline, context, signal); this.#check();
    let members: readonly ServiceOfferMembership[] = [];
    try {
      members = this.#reservation!.pool.offers.admit(slots.map(slot => ({ method: slot, namespace: this.config.namespace, typeID: slot.config!.facts.typeID, group: this.#source!.group,
        authority: this.config.target.authority, maximumWindowMS: this.config.maximumOfferWindowMS, timing: captured, offer: slot.offer! })), this.#reservation!.reference);
      this.#check(); deadline.check(); if (context !== undefined) applicationHasPermit(context);
      if (signal?.aborted || slots.some(slot => slot.membership !== undefined || slot.offer === undefined || slot.current?.semantics !== "execution")) throw new RPCProtocolError("canceled");
      for (let index = 0; index < slots.length; index++) slots[index]!.membership = members[index]!;
      if (this.#delivered) for (const member of members) member.activate(this);
    } catch (error) {
      for (const member of members) member.close();
      if (!this.#slots.some(slot => slot.membership !== undefined)) this.#releaseRenewal();
      throw error;
    }
  }
  #refresh(slots: readonly MethodSlot[], deadline: TrustedDeadline, update: Uint8Array | undefined,
    context: V4ApplicationContext | undefined, signal: AbortSignal | undefined, renewal = false): Promise<readonly ServiceRefreshResult[]> {
    this.#check(); deadline.check();
    if (!deadline.belongsTo(this.#source!.clock)) throw new RPCProtocolError("time_owner");
    if (signal?.aborted) throw new RPCProtocolError("canceled"); if (context !== undefined) applicationHasPermit(context);
    const pendingUpdate = [...this.#jobs].find(job => job.update !== undefined && job.slots.some(slot => slots.includes(slot)));
    if (update !== undefined && pendingUpdate !== undefined && !equal(pendingUpdate.update, update)) throw new RPCProtocolError("contract_update_in_progress");
    const existing = [...this.#jobs].find(job => job.slots.length === slots.length && job.slots.every(slot => slots.includes(slot)) && equal(job.update, update) &&
      (!renewal || job.renewal));
    if (existing !== undefined) return this.#join(existing, deadline, context, signal);
    if (this.#jobs.size >= 4 || update !== undefined && slots.some(slot => slot.job !== undefined && slot.generation === maximum)) throw new RPCProtocolError("resource_exhausted");
    const release = this.#reservation!.hold(), abort = new AbortController();
    const job: RefreshJob = { slots: Object.freeze([...slots]), deadline, abort, update, context,
      generation: slots.map(slot => slot.generation), query: undefined, promise: Promise.resolve([]), timer: undefined, joined: false, renewal, incarnation: this.#incarnation };
    for (const slot of slots) {
      if (slot.job !== undefined) {
        // Explicit approval revokes only this method's older candidate install
        // right. Its original query and physical position must still exit.
        if (update !== undefined) slot.generation++;
      } else { slot.job = job; slot.refresh = "checking"; slot.reason = undefined; }
    }
    this.#jobs.add(job);
    const abortJob = (error: unknown): void => { abort.abort(error); job.query?.close(); };
    const cancel = (): void => abortJob(new RPCProtocolError("canceled"));
    const tick = (): void => {
      job.timer = undefined;
      try { deadline.check(); if (!abort.signal.aborted) job.timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
      catch (error) { abortJob(error); }
    };
    signal?.addEventListener("abort", cancel, { once: true }); context?.signal.addEventListener("abort", cancel, { once: true });
    job.promise = Promise.resolve().then(() => this.#run(job)).finally(() => {
      if (job.timer !== undefined) clearTimeout(job.timer); job.timer = undefined;
      signal?.removeEventListener("abort", cancel); context?.signal.removeEventListener("abort", cancel);
      for (const slot of slots) if (slot.job === job) slot.job = undefined;
      this.#jobs.delete(job); job.update?.fill(0);
      this.#deferAdvertisements(slots); release(); this.#collect(); this.#scheduleAdvertisements();
    });
    tick(); if (signal?.aborted || context?.signal.aborted) cancel();
    // The caller's finite observation can end while original physical work is
    // still charged. A canceled wait never releases the method single-flight.
    return observeTask(job.promise, abort.signal, () => abort.signal.reason ?? new RPCProtocolError("canceled"));
  }
  #join(job: RefreshJob, deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<readonly ServiceRefreshResult[]> {
    if (job.joined) throw new RPCProtocolError("resource_exhausted"); job.joined = true;
    const abort = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
    const cancel = (): void => abort.abort(new RPCProtocolError("wait_canceled"));
    const tick = (): void => {
      timer = undefined;
      try { deadline.check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
      catch (error) { abort.abort(error); }
    };
    signal?.addEventListener("abort", cancel, { once: true }); context?.signal.addEventListener("abort", cancel, { once: true });
    this.#abort.signal.addEventListener("abort", cancel, { once: true });
    tick(); if (signal?.aborted || context?.signal.aborted || this.#abort.signal.aborted) cancel();
    return observeTask(job.promise, abort.signal, () => abort.signal.reason).finally(() => {
      if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", cancel); context?.signal.removeEventListener("abort", cancel);
      this.#abort.signal.removeEventListener("abort", cancel); job.joined = false;
    });
  }
  #checkJob(job: RefreshJob): void {
    this.#check(); if (job.incarnation !== this.#incarnation) throw new RPCProtocolError("source_unavailable"); job.deadline.check(); if (job.abort.signal.aborted) throw new RPCProtocolError("canceled");
    if (job.context !== undefined) applicationHasPermit(job.context);
  }
  #validate(slot: MethodSlot, candidate: ServiceContractSnapshot, offer: AdmissionOffer | undefined, update: boolean): void {
    candidate.checkMethod(this.config.namespace, slot.config!.facts); candidate.checkPolicy(slot.config!.acceptance);
    if (!candidate.sameEnvironment(this.#reservation!.reference)) throw new RPCProtocolError("service_contract_owner");
    if (slot.current !== undefined) slot.current.accepts(candidate, slot.config!.acceptance, update);
    const configured = slot.config!.defaultResponseLimitBytes;
    if (configured !== undefined && (slot.config!.facts.shape === "notify" || configured < candidate.minResponseBytes || configured > candidate.maxResponseBytes)) throw new RPCProtocolError("response_limit_unsupported");
    if (candidate.semantics === "execution") {
      if (offer === undefined) throw new RPCProtocolError("admission_offer_unavailable");
      const scratch = new Uint8Array(256);
      try { offer.copyEncoded(candidate, this.config.maximumOfferWindowMS, scratch); } finally { scratch.fill(0); }
      // A future valid Offer may be installed, but is not callable yet.
      if (this.#source!.clock.sample().requireInterval().upperMS >= offer.notAfterMS) throw new RPCProtocolError("admission_window_closed");
    } else if (offer !== undefined) throw new RPCProtocolError("admission_offer_unavailable");
  }
  async #installFetched(job: RefreshJob, slot: MethodSlot, item: ContractSnapshotItem, position: ProtectedResourceReservation,
    candidates: Set<ProtectedResourceReservation>): Promise<void> {
    let member: ServiceOfferMembership | undefined;
    try {
      this.#checkJob(job);
      if (this.#delivered && this.config.offerRefresh === "managed" && slot.current === undefined && item.contract?.semantics === "execution") {
        this.#validate(slot, item.contract, item.offer, false);
        // The fetched bytes occupy the binding's original future-current. Its
        // last original J/Q task must actually exit before first protection.
        job.query!.close(); await job.query!.waitForReuse(job.abort.signal); this.#checkJob(job);
        await this.#protectRenewal(job.deadline, job.context, job.abort.signal, true); this.#checkJob(job);
        [member] = this.#reservation!.pool.offers.admit([{ method: slot, namespace: this.config.namespace, typeID: slot.config!.facts.typeID, group: this.#source!.group, authority: this.config.target.authority,
          maximumWindowMS: this.config.maximumOfferWindowMS, timing: this.config.offerTiming, offer: item.offer! }], this.#reservation!.reference);
        this.#checkJob(job);
        if (slot.current !== undefined || slot.membership !== undefined || slot.job !== job || slot.generation !== job.generation[job.slots.indexOf(slot)]) throw new RPCProtocolError("contract_update_in_progress");
        slot.membership = member;
      }
      const reason = this.#install(job, slot, item, position, candidates);
      if (reason === undefined) { member?.activate(this); member = undefined; }
    } catch (error) { if (slot.job === job) { slot.refresh = "rejected"; slot.reason = failure(error); } }
    finally {
      if (member !== undefined) { if (slot.membership === member) slot.membership = undefined; member.close(); }
      if (!this.#slots.some(method => method.membership !== undefined)) this.#releaseRenewal();
    }
  }
  /** Explicit refresh and shared renewal install through this same gate. */
  #install(job: RefreshJob, slot: MethodSlot, item: ContractSnapshotItem, position: ProtectedResourceReservation,
    candidates: Set<ProtectedResourceReservation>): string | undefined {
    try {
      this.#checkJob(job);
      if (item.contract === undefined) throw new RPCProtocolError(item.status === "denied" ? "permission_denied" : "method_unavailable");
      this.#validate(slot, item.contract, item.offer, job.update !== undefined);
      const commitWindow = slot.membership?.prepareUpdate(item.offer!);
      const commitPool = this.#streamPools.get(slot.config!.method)?.prepareUpdate(item.contract);
      this.#checkJob(job);
      if (slot.job !== job || slot.generation !== job.generation[job.slots.indexOf(slot)] || slot.generation === maximum) throw new RPCProtocolError("contract_update_in_progress");
      // No host work between the final scalar gate and installation.
      const previous = slot.current; let retired: ProtectedResourceReservation | undefined;
      const next = previous === item.contract ? undefined : item.contract.retain();
      try { commitPool?.check(); commitWindow?.(); } catch (error) { next?.release(); throw error; }
      commitPool?.commit();
      if (previous !== item.contract) {
        slot.current = next!;
        if (previous !== undefined) {
          retired = slot.retired = slot.position; slot.position = position; candidates.delete(position);
        }
      }
      slot.offer = item.offer; slot.generation++; slot.refresh = "installed"; slot.reason = undefined;
      if (retired !== undefined) { previous!.release(); this.#reservation!.retire(retired); }
      return;
    } catch (error) {
      const reason = failure(error);
      // A superseded query cannot replace a newer refresh's projection.
      if (slot.job === job) { slot.refresh = "rejected"; slot.reason = reason; }
      return reason;
    }
  }
  renewalSource(): ServiceBindingSource {
    this.#check();
    if (this.#renewal === undefined && this.#slots.some(slot => slot.membership !== undefined)) {
      this.#renewal = this.#source!.protectRenewal(this.#reservation!.reference);
      if (this.#renewal === undefined) throw new RPCProtocolError("query_renewal_unavailable");
      this.#check();
    }
    return this.#source!;
  }
  renewalUnavailable(members: readonly ServiceOfferMembership[], reason: string): void {
    if (this.#closed) return;
    for (const slot of this.#slots) if (slot.membership !== undefined && members.includes(slot.membership) && slot.job === undefined) {
      slot.refresh = serviceOfferBlocked(reason) ? "blocked" : "deferred"; slot.reason = reason;
    }
  }
  claimRenewal(members: readonly ServiceOfferMembership[], deadline: TrustedDeadline): ServiceOfferWork | undefined {
    this.#check(); deadline.check();
    if (this.#renewal === undefined || !deadline.belongsTo(this.#source!.clock) || members.length < 1 || members.length > 8 ||
        new Set(members).size !== members.length) throw new RPCProtocolError("query_renewal_unavailable");
    const slots = members.map(member => this.#slots.find(slot => slot.membership === member));
    if (slots.some(slot => slot === undefined || slot.current?.semantics !== "execution")) throw new RPCProtocolError("query_renewal_unavailable");
    const selected = slots as MethodSlot[];
    for (const slot of selected) if (slot.retired?.cleanupComplete()) slot.retired = undefined;
    if (this.#jobs.size >= 4 || selected.some(slot => slot.job !== undefined || slot.retired !== undefined)) return;
    const reservation = this.#reservation!, release = reservation.hold(), protection = this.#renewal;
    const known: ServiceContractSnapshot[] = [], targets: ContractQueryTarget[] = [];
    const candidates = new Set<ProtectedResourceReservation>(); let positions: ProtectedResourceReservation[] = [];
    let resolve!: (results: readonly ServiceRefreshResult[]) => void, finished = false, requested = false, captured = false;
    const reasons: (string | undefined)[] = selected.map(() => "source_unavailable");
    const job: RefreshJob = { slots: selected, deadline, abort: new AbortController(), update: undefined, context: undefined,
      generation: selected.map(slot => slot.generation), query: undefined,
      promise: new Promise(done => { resolve = done; }), timer: undefined, joined: false, renewal: true, incarnation: this.#incarnation };
    try {
      for (const slot of selected) {
        const snapshot = slot.current!.retain(); known.push(snapshot);
        const wantedDigest = new Uint8Array(32); snapshot.copyDigest(wantedDigest);
        targets.push(Object.freeze({ namespace: this.config.namespace, typeID: slot.config!.facts.typeID, known: snapshot, wantedDigest }));
      }
      this.#check(); deadline.check();
      if (selected.some((slot, index) => slot.job !== undefined || slot.generation !== job.generation[index])) throw new RPCProtocolError("refresh_in_progress");
      for (const slot of selected) { slot.job = job; slot.refresh = "checking"; slot.reason = undefined; }
      this.#jobs.add(job);
      return Object.freeze<ServiceOfferWork>({ targets: Object.freeze(targets), windows: Object.freeze(selected.map(() => this.config.maximumOfferWindowMS)), protection,
        candidateRequests: (): readonly ResourceRequest[] => {
          this.#checkJob(job); if (requested || finished) throw new RPCProtocolError("service_binding_owner"); requested = true;
          return reservation.candidateRequests(selected.length);
        },
        captureCandidates: (references): readonly ResourceReference[] => {
          this.#checkJob(job);
          if (!requested || captured || finished || references.length !== selected.length) throw new RPCProtocolError("service_binding_owner");
          captured = true; positions = reservation.adoptCandidates(references); for (const position of positions) candidates.add(position);
          const bodies: ResourceReference[] = [];
          try { for (const position of positions) bodies.push(position.checkout()); return bodies; }
          catch (error) { for (const body of bodies) body.release(); throw error; }
        },
        current: (): boolean => {
          if (finished) return false;
          try { this.#checkJob(job); return selected.every((slot, index) => slot.job === job && slot.generation === job.generation[index]); }
          catch { return false; }
        },
        install: (batch, offset): void => {
          for (let index = 0; index < selected.length; index++) reasons[index] = this.#install(job, selected[index]!, batch.item(offset + index), positions[index]!, candidates);
        },
        finish: (reason): readonly (string | undefined)[] => {
          if (finished) return reasons; finished = true;
          for (const target of targets) target.wantedDigest!.fill(0);
          for (const snapshot of known) snapshot.release(); known.length = 0;
          for (const position of candidates) reservation.retire(position); candidates.clear(); positions = [];
          for (let index = 0; index < selected.length; index++) {
            const slot = selected[index]!;
            if (reason !== undefined && slot.refresh !== "installed") reasons[index] = reason;
            if (slot.job === job) {
              if (slot.refresh === "checking") { slot.refresh = "rejected"; slot.reason = reasons[index]; }
              if (reasons[index] !== undefined && serviceOfferBlocked(reasons[index]!)) slot.refresh = "blocked";
              slot.job = undefined;
            }
          }
          const results = Object.freeze(selected.map(slot => Object.freeze({ method: slot.config!.method, contract: this.contract(slot.config!.method) })));
          this.#jobs.delete(job); release(); this.#collect(); resolve(results); return reasons;
        },
      });
    } catch (error) {
      for (const target of targets) target.wantedDigest!.fill(0); for (const snapshot of known) snapshot.release();
      for (const slot of selected) if (slot.job === job) slot.job = undefined;
      this.#jobs.delete(job); release(); throw error;
    }
  }
  async #run(job: RefreshJob): Promise<readonly ServiceRefreshResult[]> {
    // At most one batch per job is live. A large service never expands into one
    // host task, query owner or decoder per method.
    const joined = new Set<MethodSlot>();
    for (let offset = 0; offset < job.slots.length; offset += 8) {
      const selected = job.slots.slice(offset, offset + 8), work: MethodSlot[] = [];
      let result: ContractSnapshotBatch | undefined, references: readonly ResourceReference[] = [];
      const positions = new Map<MethodSlot, ProtectedResourceReservation>(), candidates = new Set<ProtectedResourceReservation>();
      try {
        this.#checkJob(job);
        for (const slot of selected) {
          if (joined.has(slot)) continue;
          if (slot.job !== undefined && slot.job !== job) {
            const original = slot.job;
            await this.#join(original, job.deadline, job.context, job.abort.signal); this.#checkJob(job);
            if (job.update === undefined) {
              for (const covered of original.slots) if (job.slots.includes(covered)) joined.add(covered);
              continue;
            }
          }
          if (slot.job !== undefined && slot.job !== job) throw new RPCProtocolError("contract_update_in_progress");
          if (slot.job !== job) { slot.job = job; job.generation[job.slots.indexOf(slot)] = slot.generation; }
          else if (slot.generation !== job.generation[job.slots.indexOf(slot)]) throw new RPCProtocolError("contract_update_in_progress");
          slot.refresh = "checking"; slot.reason = undefined;
          if (job.update !== undefined || slot.current === undefined || slot.current.semantics === "execution" || slot.acceptance === "bounded") work.push(slot);
        }
        if (work.length !== 0 && this.#staticContracts !== undefined) {
          const entries = staticServiceContracts(this.#staticContracts, this.config.definition, this.config.target, this.#source!.authentication(), this.#reservation!.reference);
          for (const slot of work) {
            const entry = entries.find(item => item.method === slot.config!.method);
            if (entry === undefined || job.update !== undefined && !entry.contract.hasDigest(job.update)) {
              slot.refresh = "rejected"; slot.reason = "method_unavailable"; continue;
            }
            if (slot.current !== undefined && digest(slot.current) === digest(entry.contract)) {
              this.#validate(slot, entry.contract, entry.offer, job.update !== undefined);
              const commitWindow = slot.membership?.prepareUpdate(entry.offer!);
              this.#checkJob(job);
              if (slot.job !== job || slot.generation !== job.generation[job.slots.indexOf(slot)]) throw new RPCProtocolError("contract_update_in_progress");
              commitWindow?.(); slot.offer = entry.offer; slot.refresh = "installed"; slot.reason = undefined;
            } else {
              let position = slot.position!;
              if (slot.current !== undefined) { [position] = this.#reservation!.candidates(1) as [ProtectedResourceReservation]; candidates.add(position); }
              this.#install(job, slot, { status: "available_full", contract: entry.contract, offer: entry.offer }, position, candidates);
            }
          }
        } else if (work.length !== 0) {
          for (const slot of work) {
            if (slot.retired?.cleanupComplete()) slot.retired = undefined;
            if (slot.retired !== undefined) throw new RPCProtocolError("resource_exhausted");
          }
          const targets: ContractQueryTarget[] = work.map(slot => {
            let wanted: Uint8Array | undefined = job.update;
            if (wanted === undefined && slot.current !== undefined && (slot.acceptance === "exact" || job.renewal)) {
              wanted = new Uint8Array(32); slot.current.copyDigest(wanted);
            }
            return { namespace: this.config.namespace, typeID: slot.config!.facts.typeID,
              ...(wanted === undefined ? {} : { wantedDigest: wanted }),
              ...(slot.current === undefined || wanted !== undefined && !slot.current.hasDigest(wanted) ? {} : { known: slot.current }) };
          });
          try {
            this.#checkJob(job);
            job.query = this.#source!.query(targets, job.deadline, work.map(() => this.config.maximumOfferWindowMS), job.context, () => {
              const replacements = work.filter(slot => slot.current !== undefined);
              const acquired = replacements.length === 0 ? [] : this.#reservation!.candidates(replacements.length);
              for (let i = 0; i < replacements.length; i++) { positions.set(replacements[i]!, acquired[i]!); candidates.add(acquired[i]!); }
              for (const slot of work) if (!positions.has(slot)) positions.set(slot, slot.position!);
              references = this.#reservation!.delivery(work.map(slot => positions.get(slot)!)); return references;
            }, job.renewal ? this.#renewal : undefined);
          } finally { for (const target of targets) if (target.wantedDigest !== job.update) target.wantedDigest?.fill(0); }
          const progress = await job.query.wait(job.abort.signal); this.#checkJob(job);
          if (progress.state !== "ready") throw new RPCProtocolError(progress.sdkError ?? progress.failure ?? "source_unavailable");
          result = job.query.take();
          for (let i = 0; i < work.length; i++) {
            const slot = work[i]!, item = result.item(i), position = positions.get(slot)!;
            await this.#installFetched(job, slot, item, position, candidates);
          }
        }
        for (const slot of selected) if (slot.job === job && slot.refresh === "checking") slot.refresh = "idle";
      } catch (error) {
        for (const slot of selected) if (slot.job === job && slot.refresh === "checking") { slot.refresh = "rejected"; slot.reason = failure(error); }
      } finally {
        result?.release(); job.query?.close();
        for (const reference of references) reference.release();
        for (const position of candidates) this.#reservation?.retire(position);
        if (job.query !== undefined) await job.query.waitForReuse();
        job.query = undefined;
      }
    }
    const results = job.slots.map(slot => Object.freeze({ method: slot.config!.method, contract: this.contract(slot.config!.method) }));
    Object.defineProperty(results, "then", { value: undefined }); return Object.freeze(results);
  }
  /** Convenience Call owns the hidden preparation through the original final
   * result capability. Explicitly returned preparations remain independent. */
  callUnary(method: object, value: unknown, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext,
    signal?: AbortSignal): Promise<RPCUnaryTakeResult> {
    const captured = captureUnaryOptions(options, context);
    this.#checkOwner(); const slot = this.#select([method])[0]!;
    if (slot.current === undefined) throw new RPCProtocolError("not_ready");
    if (slot.config!.facts.shape !== "unary") throw new RPCProtocolError("rpc_request_binding");
    // Construct the caller's final native result capability before passive
    // readiness work. Only preparation metadata flows through helper Promises.
    // Returning from an async wrapper would create a second payload recipient.
    this.#checkOwner();
    const release = this.#reservation!.hold(); let call: RPCUnaryCall | undefined;
    try {
      call = new RPCUnaryCall(context, signal, () => { if (call !== undefined) this.#calls.delete(call); release(); this.#collect(); });
      this.#calls.add(call);
      try { this.#checkOwner(); call.begin(cancellation => this.#prepareCallUnary(method, value, captured, context, cancellation)); }
      catch (error) { call.fail(error); }
      const promise = call.promise;
      call.arm();
      return promise;
    } catch (error) { call?.close(); release(); throw error; }
  }
  async prepareNotify(method: object, value: unknown, options: NotifyPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<NotifyPreparation> {
    const initial = captureNotifyOptions(options, context);
    options = await this.#readyOptions(method, initial, initial.timeoutMS, context, signal);
    this.#check(); const captured = captureNotifyOptions(options, context); this.#check(); const slot = this.#select([method])[0]!;
    if (slot.current === undefined) throw new RPCProtocolError("not_ready");
    if (slot.config!.facts.shape !== "notify") throw new RPCProtocolError("notify_binding");
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    return this.#source!.prepareNotify(slot.config!, this.config.namespace, slot.current, slot.offer, value, captured, context, cancellation).then(operation => {
      if (this.#closed || cancellation.aborted) { operation.close(); throw new RPCProtocolError("service_binding_closed"); }
      return operation;
    });
  }
  async notify(method: object, value: unknown, options: NotifyPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<Readonly<NotifyProgress>> {
    this.#checkOwner(); const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    const operation = await this.prepareNotify(method, value, options, context, cancellation); this.#notifyCalls.add(operation);
    try {
      this.checkDelivery(); const started = operation.start(context, cancellation);
      if (started.status === "not_admitted") throw new RPCProtocolError(started.reason);
      return await operation.waitSubmission(cancellation);
    } finally { this.#notifyCalls.delete(operation); operation.close(); }
  }
  async prepareAndSaveNotify(method: object, value: unknown, store: V4OperationReferenceStore, options: NotifyPreparationOptions,
    context?: V4ApplicationContext, signal?: AbortSignal): Promise<ReferenceSaveReport & { reference?: V4OperationReference; preparation?: NotifyPreparation }> {
    let preparation: NotifyPreparation | undefined, reference: V4OperationReference | undefined, report: ReferenceSaveReport | undefined;
    try {
      this.#checkOwner(); if (applicationHasPermit(context)) throw new RPCProtocolError("admission_mode_incompatible");
      const slot = this.#select([method])[0]!;
      if (slot.config!.facts.shape !== "notify" || slot.config!.facts.semantics !== "execution") throw new RPCProtocolError("operation_reference_unavailable");
      store.checkDomain(this.config.target.authority);
      const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
      preparation = await this.prepareNotify(method, value, options, context, cancellation); reference = preparation.reference();
      report = await preparation.saveReference(store, context, cancellation);
      if (report.failure !== undefined) return referenceSaveReport({ ...report, reference });
      this.checkDelivery(); preparation.checkPublication(); if (cancellation.aborted) throw new RPCProtocolError("canceled");
      return referenceSaveReport({ ...report, reference, preparation });
    } catch (error) {
      preparation?.close();
      return referenceSaveReport({ save: report?.save ?? Object.freeze({ attempted: false, outcome: "unknown" as const }),
        cleanup: report?.cleanup ?? preparation?.cleanupStatus() ?? cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n }),
        failure: referenceSaveFailure(error), ...(reference === undefined ? {} : { reference }) });
    }
  }
  async prepareStream(method: object, value: unknown, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation<RPCStreamingExchange>> {
    options = await this.#readyOptions(method, captureUnaryOptions(options, context), options.defaultLifetimeMS, context, signal);
    this.#check(); const slot = this.#select([method])[0]!;
    const captured = { ...captureUnaryOptions(options, context) }; delete captured.defaultResponseLimitBytes;
    if (slot.config!.facts.shape !== "server_streaming") throw new RPCProtocolError("rpc_request_binding");
    if (slot.config!.defaultResponseLimitBytes !== undefined) captured.defaultResponseLimitBytes = slot.config!.defaultResponseLimitBytes;
    this.#check(); const current = slot.current; if (current === undefined) throw new RPCProtocolError("not_ready");
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    return this.#source!.prepareStream(slot.config!, this.config.namespace, current, slot.offer, value, captured, context, cancellation).then(preparation => {
      if (this.#closed || cancellation.aborted) { preparation.close(); throw new RPCProtocolError("service_binding_closed"); } return preparation;
    });
  }
  async prepareResume(method: object, stream: V4StreamOwner, token: Uint8Array, options: RPCUnaryPreparationOptions,
    context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation> {
    this.#checkOwner(); const slot = this.#select([method])[0]!;
    const captured = { ...captureUnaryOptions(options, context) }; delete captured.defaultResponseLimitBytes;
    if (slot.config!.defaultResponseLimitBytes !== undefined) captured.defaultResponseLimitBytes = slot.config!.defaultResponseLimitBytes;
    this.#checkOwner(); const source = this.#source!.resumeSource?.(stream) ?? this.#source!;
    source.check(); checkServiceBindingTarget(this.config.target, source.authentication());
    const current = slot.current;
    if (current === undefined) throw new RPCProtocolError("not_ready");
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    return source.prepareResume(slot.config!, this.config.namespace, current, slot.offer, stream, token, captured, context, cancellation).then(preparation => {
      if (this.#closed || cancellation.aborted) { preparation.close(); throw new RPCProtocolError("service_binding_closed"); }
      return preparation;
    });
  }
  prepareResumeAndSave(method: object, stream: V4StreamOwner, token: Uint8Array, store: V4OperationReferenceStore,
    options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal) {
    return this.#prepareAndSave(method, store, "unary", cancellation => this.prepareResume(method, stream, token, options, context, cancellation), context, signal);
  }
  async #prepareCallUnary(method: object, value: unknown, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation> {
    if (this.#source?.prepareDispatch === undefined || options.admission === "try_now" || applicationHasPermit(context)) {
      return this.prepareUnary(method, value, options, context, signal);
    }
    options = await this.#readyOptions(method, captureUnaryOptions(options, context), options.defaultLifetimeMS, context, signal);
    this.#check(); const slot = this.#select([method])[0]!, contract = slot.current;
    if (contract === undefined) throw new RPCProtocolError("not_ready");
    const captured = { ...captureUnaryOptions(options, context) }; delete captured.defaultResponseLimitBytes;
    if (slot.config!.defaultResponseLimitBytes !== undefined) captured.defaultResponseLimitBytes = slot.config!.defaultResponseLimitBytes;
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    const prepared = await this.#source!.prepareDispatch!(slot.config!, this.config.namespace, contract, slot.offer, value, captured, context, cancellation);
    if (this.#closed || cancellation.aborted) { prepared.close(); throw new RPCProtocolError("service_binding_closed"); }
    return prepared;
  }
  async prepareUnary(method: object, value: unknown, options: RPCUnaryPreparationOptions, context?: V4ApplicationContext, signal?: AbortSignal): Promise<RPCUnaryPreparation> {
    options = await this.#readyOptions(method, captureUnaryOptions(options, context), options.defaultLifetimeMS, context, signal);
    this.#check(); const slot = this.#select([method])[0]!, contract = slot.current;
    if (contract === undefined) throw new RPCProtocolError("not_ready");
    // Capture all caller getters before selecting the actual immutable pair.
    const captured = { ...captureUnaryOptions(options, context) }; delete captured.defaultResponseLimitBytes;
    if (slot.config!.defaultResponseLimitBytes !== undefined) captured.defaultResponseLimitBytes = slot.config!.defaultResponseLimitBytes;
    this.#check(); const current = slot.current;
    if (current === undefined) throw new RPCProtocolError("not_ready");
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    return this.#source!.prepare(slot.config!, this.config.namespace, current, slot.offer, value, captured, context, cancellation).then(preparation => {
      if (this.#closed || cancellation.aborted) { preparation.close(); throw new RPCProtocolError("service_binding_closed"); }
      // The caller now owns the original preparation. Closing the binding
      // cannot recall it, replace its contract, or cancel its later operation.
      return preparation;
    });
  }
  /** Keep the candidate private through persistence and the final public gate. */
  async prepareAndSaveUnary(method: object, value: unknown, store: V4OperationReferenceStore, options: RPCUnaryPreparationOptions,
    context?: V4ApplicationContext, signal?: AbortSignal): Promise<ReferenceSaveReport & { reference?: V4OperationReference; preparation?: RPCUnaryPreparation }> {
    return this.#prepareAndSave(method, store, "unary", cancellation => this.prepareUnary(method, value, options, context, cancellation), context, signal);
  }
  async prepareAndSaveStream(method: object, value: unknown, store: V4OperationReferenceStore, options: RPCUnaryPreparationOptions,
    context?: V4ApplicationContext, signal?: AbortSignal): Promise<ReferenceSaveReport & { reference?: V4OperationReference; preparation?: RPCUnaryPreparation<RPCStreamingExchange> }> {
    return this.#prepareAndSave(method, store, "server_streaming", cancellation => this.prepareStream(method, value, options, context, cancellation), context, signal);
  }
  async #prepareAndSave<Preparation extends RPCUnaryPreparation | RPCUnaryPreparation<RPCStreamingExchange>>(method: object,
    store: V4OperationReferenceStore, shape: "unary" | "server_streaming", prepare: (signal: AbortSignal) => Promise<Preparation>,
    context?: V4ApplicationContext, signal?: AbortSignal): Promise<ReferenceSaveReport & { reference?: V4OperationReference; preparation?: Preparation }> {
    let preparation: Preparation | undefined, reference: V4OperationReference | undefined, report: ReferenceSaveReport | undefined;
    try {
      this.#checkOwner(); if (applicationHasPermit(context)) throw new RPCProtocolError("admission_mode_incompatible");
      const slot = this.#select([method])[0]!;
      if (slot.config!.facts.shape !== shape || slot.config!.facts.semantics !== "execution") throw new RPCProtocolError("operation_reference_unavailable");
      store.checkDomain(this.config.target.authority);
      const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
      preparation = await prepare(cancellation); reference = preparation.reference();
      report = await preparation.saveReference(store, context, cancellation);
      if (report.failure !== undefined) return referenceSaveReport({ ...report, reference });
      this.checkDelivery(); preparation.checkReady(); if (cancellation.aborted) throw new RPCProtocolError("canceled");
      return referenceSaveReport({ ...report, reference, preparation });
    } catch (error) {
      preparation?.close();
      return referenceSaveReport({ save: report?.save ?? Object.freeze({ attempted: false, outcome: "unknown" as const }),
        cleanup: report?.cleanup ?? preparation?.cleanupStatus() ?? cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n }),
        failure: referenceSaveFailure(error), ...(reference === undefined ? {} : { reference }) });
    }
  }
  seal(): void { this.#sealed = true; }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#abort.abort();
    this.#unobserveCurrent?.(); this.#unobserveCurrent = undefined;
    if (this.#advertisementTimer !== undefined) clearTimeout(this.#advertisementTimer);
    this.#advertisementTimer = undefined;
    for (const call of this.#calls) call.close();
    for (const operation of this.#notifyCalls) operation.close(); this.#notifyCalls.clear();
    for (const demand of this.#streamPools.values()) demand.close(); this.#streamPools.clear();
    for (const job of this.#jobs) { job.abort.abort(new RPCProtocolError("service_binding_closed")); job.query?.close(); }
    this.#lease?.release(); this.#lease = undefined; this.#source = undefined; this.#staticContracts = undefined;
    this.#releaseRenewal();
    for (const slot of this.#slots) { slot.membership?.close(); slot.membership = undefined; slot.current?.release(); slot.current = undefined; slot.offer = undefined; }
    const closed = this.#onClose; this.#onClose = undefined; closed?.();
    this.#reservation?.close(); this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#busy || this.#jobs.size !== 0 || this.#calls.size !== 0 || this.#protecting || this.#advertisementRunning) return; this.#busy = true;
    try {
      this.#reservation?.collect(); this.#reservation = undefined; this.#config = undefined;
      for (const slot of this.#slots) { slot.config = undefined; slot.position = slot.retired = undefined; }
    } finally { this.#busy = false; }
  }
  #releaseRenewal(): void { this.#renewal?.close(); this.#renewal = undefined; }
  toJSON(): object { return {}; }
}
Object.freeze(ServiceBinding.prototype); Object.freeze(ServiceBinding);
