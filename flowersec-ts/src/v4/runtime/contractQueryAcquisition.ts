import { CBORWireError } from "./cbor.js";
import { SchemaValidationError } from "./schema.js";
import type { TrustedClock } from "./clock.js";
import type { V4ApplicationContext } from "../streamHandlers.js";
import { applicationHasPermit, type ApplicationGroup } from "./applicationExecutor.js";
import type { FixedQueryProtection, FixedQueryWork } from "./fixedQueryExecutor.js";
import type { ContractQueryClient, ContractQueryCall } from "./contractQueryClient.js";
import type { ContractQueryTarget } from "./contractQuery.js";
import type { ContractSnapshotBatch} from "./contractSnapshotReader.js";
import { contractSnapshotResultCapacityCharges } from "./contractSnapshotReader.js";
import type { RPCChannelRuntime } from "./rpcChannel.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import type { TrustedDeadline } from "./deadline.js";
import { TimeError } from "./timeArithmetic.js";
import { ResourceError, ResourceVector, type ProtectedResourceReservation, type ResourceReference, type ResourceRoot } from "./resources.js";
import type { ContractQueryServiceStep } from "./contractQueryService.js";
import { QueryRenewalPosition, type QueryRenewalReservation, type ContractRenewalProtection, type QueryPreparationReservation, type ContractQueryPreparation } from "./queryRenewalPosition.js";

import { DiagnosticActivity, type DiagnosticObserver } from "./diagnosticObservation.js";
const capability = Symbol("original Environment contract acquisition"), NativePromise = Promise;
export type ContractQueryFailure = "cancelled" | "deadline_exceeded" | "source_unavailable" | "response_invalid";
export interface ContractQueryProgress {
  readonly state: "prepared" | "waiting" | "decoding" | "ready" | "taken" | "failed";
  /** Original request entered the channel queue; this is not wire publication. */
  readonly queued: boolean;
  readonly failure?: ContractQueryFailure;
  readonly sdkError?: RPCSDKError;
}
function invalidResponse(error: unknown): boolean {
  return error instanceof CBORWireError || error instanceof SchemaValidationError || error instanceof RPCProtocolError &&
    ["query_response_binding", "query_response_size", "query_response_count", "query_response_status", "query_target_index",
      "query_target_mismatch", "query_wanted_mismatch", "query_unchanged_without_known", "query_unchanged_mismatch", "query_offer_presence",
      "service_contract_body", "service_contract_mismatch", "admission_offer_unavailable"].includes(error.code);
}
export interface ContractQueryWaitResult extends ContractQueryProgress { readonly waitStatus: "ready" | "wait_canceled" }
/** SDK-only deferred candidate checkout, after the original J position has
 * been claimed. It cannot run application code or start another query. */
export type ContractQueryDestination = readonly ResourceReference[] | Readonly<{ bodies: readonly ResourceReference[] }>;
export type ContractQueryDelivery = ContractQueryDestination | (() => ContractQueryDestination);
interface Waiter { readonly resolve: (result: ContractQueryWaitResult) => void; readonly signal: AbortSignal | undefined; readonly cancelled: () => void }
interface CleanupWaiter { readonly resolve: (result: "reusable" | "wait_canceled") => void; readonly signal: AbortSignal | undefined; readonly cancelled: () => void }
export function contractQueryAcquisitionCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return new ResourceVector([4352n + runtimeBytes, 0n, 0n, 17n, 0n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
export function contractQueryAcquisitionsCharges(limit: 2 | 4, runtimeBytes: bigint): readonly ResourceVector[] {
  if (limit !== 2 && limit !== 4 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const costs = [new ResourceVector([5120n + runtimeBytes, 0n, 0n, BigInt(limit + 66), 0n, 0n, 0n, 0n, 0n, 0n, 0n])];
  const position = [contractQueryAcquisitionCharge(runtimeBytes), ...contractSnapshotResultCapacityCharges(8, runtimeBytes)];
  for (let i = 0; i < limit; i++) costs.push(...position);
  return costs;
}

/** The same Environment slot spans preparation, network Q, fixed decode,
 * optional wait, owned delivery and all physical tails. It cannot be converted
 * into a general completion or an uncounted late-take result. */
export class ContractQueryAcquisition implements FixedQueryWork {
  #reference: ResourceReference | undefined;
  #pool: ContractQueryAcquisitions | undefined;
  #call: ContractQueryCall | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #deadline: TrustedDeadline | undefined;
  #context: V4ApplicationContext | undefined;
  readonly #contextCancelled = (): void => this.#fail("cancelled");
  #detachedDelivery = false;
  #protection: FixedQueryProtection | undefined;
  #consumer: object | undefined;
  #wake: (() => void) | undefined;
  #references: ResourceReference[];
  readonly #windows: bigint[] = [];
  #result: ContractSnapshotBatch | undefined;
  #delivered: ContractSnapshotBatch | undefined;
  #phase: ContractQueryProgress["state"] = "prepared";
  #queued = false;
  #failure: ContractQueryFailure | undefined;
  #sdkError: RPCSDKError | undefined;
  #closed = false;
  #working = false;
  #cleaned = false;
  #collecting = false;
  #waiter: Waiter | undefined;
  #cleanupWaiter: CleanupWaiter | undefined;
  #reusableProtection = false;
  constructor(token: symbol, pool: ContractQueryAcquisitions, runtimeBytes: bigint, references: ResourceReference[], private readonly diagnostic?: DiagnosticActivity) {
    if (token !== capability || references.length !== 10) throw new RPCProtocolError("rpc_query_owner");
    this.#pool = pool; this.#references = references.slice(1); this.#reference = references[0]!.take(contractQueryAcquisitionCharge(runtimeBytes));
    diagnostic?.holdPublication();
    Object.freeze(this);
  }
  prepare(token: symbol, group: ApplicationGroup, client: ContractQueryClient, deadline: TrustedDeadline,
    windows: readonly bigint[], context: V4ApplicationContext | undefined, delivery?: ContractQueryDestination, preparation?: ContractQueryPreparation): void {
    if (token !== capability || this.#phase !== "prepared" || this.#deadline !== undefined) throw new RPCProtocolError("rpc_query_owner");
    this.#working = true;
    try {
      this.#deadline = deadline; this.#context = context;
      if (!Array.isArray(windows) || windows.length < 1 || windows.length > 8) throw new RPCProtocolError("configuration_capacity");
      for (let i = 0; i < windows.length; i++) {
        const window = windows[i];
        if (typeof window !== "bigint" || window < 1n || window >= 1n << 64n) throw new RPCProtocolError("configuration_capacity");
        this.#windows.push(window);
      }
      this.#check();
      if (delivery !== undefined) {
        // A binding supplies its already prepaid future-current/candidate
        // positions. The fixed reader writes there directly, so installing a
        // large service does not pin an acquisition for every earlier batch.
        const costs = contractSnapshotResultCapacityCharges(this.#windows.length, this.#pool!.runtimeBytes);
        const bodiesOnly = "bodies" in delivery, positions = bodiesOnly ? delivery.bodies : delivery;
        const offset = bodiesOnly ? 1 : 0;
        if (positions.length !== costs.length - offset || !positions.every(reference => reference.sameEnvironment(this.#reference!))) throw new RPCProtocolError("query_result_owner");
        const transferred: ResourceReference[] = [];
        try { for (let i = 0; i < positions.length; i++) transferred.push(positions[i]!.take(costs[i + offset]!)); }
        catch (error) { for (const reference of transferred) reference.release(); throw error; }
        // A cross-binding batch keeps the original acquisition's prepaid
        // metadata while its bodies go straight to each method's position.
        if (bodiesOnly) transferred.unshift(this.#references.shift()!);
        this.#releaseUnused(); this.#references = transferred; this.#detachedDelivery = true;
      }
      context?.signal.addEventListener("abort", this.#contextCancelled, { once: true });
      this.#check(); this.#lease = client.retainDelivery(this.#reference!, () => this.#fail("source_unavailable"));
      this.#check();
      if (preparation !== undefined) {
        preparation.check(); if (preparation.fixed.group !== group || preparation.fixed.direction !== 1) throw new RPCProtocolError("rpc_query_owner");
        preparation.fixed.attach(this); this.#protection = preparation.fixed; this.#reusableProtection = true;
      } else {
        this.#protection = group.protectQueryAcquisition(this.#reference!); this.#protection.attach(this);
      }
      this.#check();
    } finally { this.#working = false; this.#collect(); }
  }
  start(token: symbol, client: ContractQueryClient, channel: RPCChannelRuntime, targets: readonly ContractQueryTarget[], renewal?: QueryRenewalReservation, preparation?: QueryPreparationReservation): void {
    if (token !== capability || this.#phase !== "prepared" || this.#protection === undefined) throw new RPCProtocolError("rpc_query_owner");
    this.#working = true;
    try {
      this.#check(); this.#call = client.begin(channel, targets, this.#deadline!, this.#windows.length, renewal, preparation); this.#queued = true;
      this.#call.observe(() => { this.#wake?.(); this.#collect(); });
      this.#phase = "waiting"; this.#wake?.();
    } finally { this.#working = false; this.#collect(); }
  }
  #check(): void {
    if (this.#closed) throw new RPCProtocolError("query_closed");
    this.#reference!.check();
    if (this.#context !== undefined) applicationHasPermit(this.#context);
    this.#deadline?.check(); this.#lease?.check();
    if (this.#closed) throw new RPCProtocolError("query_closed");
  }
  sameEnvironment(reference: ResourceReference): boolean {
    if (this.#closed || this.#reference === undefined) throw new RPCProtocolError("query_closed"); return this.#reference.sameEnvironment(reference);
  }
  attachWake(wake: () => void, consumer: object): void {
    if (this.#consumer !== undefined || this.#closed) throw new RPCProtocolError("rpc_query_consumer"); this.#consumer = consumer; this.#wake = wake;
  }
  progress(): ContractQueryProgress {
    return Object.freeze({ state: this.#phase, queued: this.#queued, ...(this.#failure === undefined ? {} : { failure: this.#failure }), ...(this.#sdkError === undefined ? {} : { sdkError: this.#sdkError }) });
  }
  stepPosition(position: number, consumer?: object): ContractQueryServiceStep {
    if (position !== 0 || consumer === undefined || this.#consumer !== consumer || this.#working) throw new RPCProtocolError("rpc_query_consumer");
    if (this.#closed) { this.#collect(); return "idle"; }
    if (this.#phase === "taken") return "idle";
    this.#working = true;
    try {
      this.#check();
      if (this.#phase === "prepared") return "idle";
      if (this.#phase === "ready") return "blocked";
      const call = this.#call!;
      if (this.#phase === "waiting") {
        const progress = call.progress();
        if (!progress.done) return "blocked";
        if (progress.abandoned || progress.failure !== undefined) { this.#fail("source_unavailable"); return "progress"; }
        if (progress.sdkError !== undefined) { this.#sdkError = progress.sdkError; this.#fail("source_unavailable"); return "progress"; }
        if (!call.beginDecode(this.#windows, this.#references.slice(0, call.count + 1))) return "blocked";
        // The exact result positions moved into the reader. Unused maximum
        // positions are returned only after this original operation settles.
        this.#references.splice(0, call.count + 1); this.#phase = "decoding"; return "progress";
      }
      if (call.stepDecode()) {
        this.#result = call.take(); this.#phase = "ready"; this.#notifyWaiter();
      }
      return "progress";
    } catch (error) {
      if (error instanceof TimeError) this.#fail(error.code === "time_expired" ? "deadline_exceeded" : error.code === "time_cancelled" ? "cancelled" : "source_unavailable");
      else if (this.#closed) this.#collect();
      else if (invalidResponse(error)) {
        this.#call?.failResponse(); this.#fail("response_invalid");
      } else this.#fail("source_unavailable");
      return "progress";
    } finally { this.#working = false; this.#collect(); }
  }
  nextDeadlineMS(): bigint | undefined {
    if (this.#closed || this.#phase === "taken" || this.#phase === "failed") return;
    return this.#deadline!.remainingMS();
  }
  /** Pure ownership transfer of a completed fixed SDK result; no user codec
   * runs here. Query-owned bodies keep the acquisition occupied until release;
   * binding-owned bodies remain charged to their original installation vector. */
  take(): ContractSnapshotBatch {
    if (this.#working || this.#phase !== "ready" || this.#result === undefined) throw new RPCProtocolError("query_result_unavailable");
    this.#working = true;
    try {
      this.#check(); const result = this.#result;
      if (this.#phase !== "ready" || result === undefined) throw new RPCProtocolError("query_result_unavailable");
      this.#result = undefined; if (!this.#detachedDelivery) this.#delivered = result; this.#phase = "taken";
      this.diagnostic?.event({ state: "ready", code: "ok" }); this.diagnostic?.close();
      this.#call?.close(); this.#releaseUnused(); this.#detachContext(); this.#deadline = undefined;
      this.#lease?.release(); this.#lease = undefined;
      this.#notifyWaiter(); return result;
    } finally { this.#working = false; this.#collect(); }
  }
  /** Exactly one prepaid observer. Aborting this wait only detaches the wait;
   * it cannot cancel the original query or manufacture another result owner. */
  wait(signal?: AbortSignal): Promise<ContractQueryWaitResult> {
    if (this.#waiter !== undefined || this.#cleanupWaiter !== undefined) return NativePromise.reject(new RPCProtocolError("query_wait_in_progress"));
    if (this.#phase === "ready" || this.#phase === "taken" || this.#phase === "failed" || signal?.aborted) return NativePromise.resolve(this.#waitResult(signal?.aborted ?? false));
    return new NativePromise(resolve => {
      const waiter: Waiter = { resolve, signal, cancelled: () => { if (this.#waiter === waiter) this.#settleWaiter(true); } };
      this.#waiter = waiter; signal?.addEventListener("abort", waiter.cancelled, { once: true });
      if (signal?.aborted) waiter.cancelled();
    });
  }
  /** Uses the same single observation allowance after result transfer. Ready
   * bytes alone do not prove that the original J/Q vectors can be reused. */
  waitForReuse(signal?: AbortSignal): Promise<"reusable" | "wait_canceled"> {
    if (this.#waiter !== undefined || this.#cleanupWaiter !== undefined) return NativePromise.reject(new RPCProtocolError("query_wait_in_progress"));
    if (this.#phase !== "taken" && this.#phase !== "failed") return NativePromise.reject(new RPCProtocolError("query_result_unavailable"));
    if (this.#cleaned) return NativePromise.resolve("reusable");
    if (signal?.aborted) return NativePromise.resolve("wait_canceled");
    return new NativePromise(resolve => {
      const waiter: CleanupWaiter = { resolve, signal, cancelled: () => { if (this.#cleanupWaiter === waiter) this.#settleCleanup(true); } };
      this.#cleanupWaiter = waiter; signal?.addEventListener("abort", waiter.cancelled, { once: true });
      if (signal?.aborted) waiter.cancelled(); else this.#collect();
    });
  }
  #settleCleanup(cancelled: boolean): void {
    const waiter = this.#cleanupWaiter; if (waiter === undefined || !cancelled && !this.#cleaned) return;
    this.#cleanupWaiter = undefined; waiter.signal?.removeEventListener("abort", waiter.cancelled); waiter.resolve(cancelled ? "wait_canceled" : "reusable");
  }
  #waitResult(cancelled: boolean): ContractQueryWaitResult {
    return Object.freeze({ ...this.progress(), waitStatus: cancelled ? "wait_canceled" : "ready" });
  }
  #settleWaiter(cancelled = false): void {
    const waiter = this.#waiter; if (waiter === undefined) return;
    this.#waiter = undefined; waiter.signal?.removeEventListener("abort", waiter.cancelled); waiter.resolve(this.#waitResult(cancelled));
  }
  #notifyWaiter(): void { if (this.#phase === "ready" || this.#phase === "taken" || this.#phase === "failed") this.#settleWaiter(); }
  #fail(failure: ContractQueryFailure): void {
    if (this.#closed) return;
    if (this.#phase !== "taken") { this.diagnostic?.failure(new Error(failure === "cancelled" ? "canceled" : failure)); this.#phase = "failed"; this.#failure = failure; }
    this.#closed = true; this.#detachContext(); this.#deadline = undefined;
    this.#lease?.release(); this.#lease = undefined;
    this.#call?.close(); this.#wake?.(); this.#notifyWaiter(); this.#collect();
  }
  #detachContext(): void { this.#context?.signal.removeEventListener("abort", this.#contextCancelled); this.#context = undefined; }
  #releaseUnused(): void { for (const reference of this.#references) reference.release(); this.#references.length = 0; }
  /** Called by the original pool's accounting observer after actual release. */
  collect(token: symbol): void { if (token !== capability) throw new RPCProtocolError("rpc_query_owner"); this.#collect(); }
  #collect(): void {
    if (this.#working || this.#collecting || this.#cleaned || !this.#closed && this.#phase !== "taken") return;
    this.#collecting = true;
    try {
      this.#result?.release(); this.#result = undefined; this.#releaseUnused();
      this.#call?.close();
      if (this.#call?.cleanupComplete() === false || this.#delivered?.cleanupComplete() === false || !this.#pool!.deliveryReleased(capability, this)) return;
      this.#call = undefined; this.#delivered = undefined; this.#closed = true;
      this.#lease?.release(); this.#lease = undefined; this.#deadline = undefined; this.#detachContext(); this.#windows.length = 0;
      this.#reference?.release(); this.#reference = undefined; this.#cleaned = true;
      this.diagnostic?.finishPublication(); this.diagnostic?.close();
      const protection = this.#protection; this.#protection = undefined;
      if (this.#reusableProtection) protection?.detach(this); else protection?.close();
      const pool = this.#pool; this.#pool = undefined; pool?.released(capability, this);
      const wake = this.#wake; this.#wake = undefined; this.#consumer = undefined; wake?.(); this.#settleWaiter();
      this.#settleCleanup(false);
    } finally { this.#collecting = false; }
  }
  close(): void { this.#fail("cancelled"); }
  cleanupComplete(): boolean { this.#collect(); return this.#cleaned; }
  toJSON(): object { return {}; }
}

/** One finite acquisition table per original Environment. Complete output
 * reservations are protected before a query starts; only exact original
 * positions can return them. Both ordinary and constrained use this owner. */
export class ContractQueryAcquisitions {
  #reference: ResourceReference | undefined;
  readonly #positions: ProtectedResourceReservation[][] = [];
  readonly #owners: (ContractQueryAcquisition | undefined)[];
  readonly #renewal: QueryRenewalPosition;
  #observer: (() => void) | undefined;
  #working = false;
  #collecting = false;
  #closed = false;
  constructor(root: ResourceRoot, private readonly clock: TrustedClock, readonly limit: 2 | 4, readonly runtimeBytes: bigint, references: readonly ResourceReference[], private readonly diagnostics?: DiagnosticObserver) {
    const costs = contractQueryAcquisitionsCharges(limit, runtimeBytes);
    if (references.length !== costs.length || !references.every(ref => references[0]!.sameEnvironment(ref))) throw new RPCProtocolError("rpc_query_owner");
    this.#owners = Array<ContractQueryAcquisition | undefined>(limit).fill(undefined);
    this.#renewal = new QueryRenewalPosition(limit, index => this.#owners[index] === undefined && this.#positions[index] !== undefined &&
      this.#positions[index]!.every(position => position.available()));
    this.#reference = references[0]!.take(costs[0]!);
    try {
      for (let slot = 0; slot < limit; slot++) {
        const positions: ProtectedResourceReservation[] = []; this.#positions.push(positions);
        for (let n = 0; n < 10; n++) { const index = 1 + slot * 10 + n; positions.push(root.protect(references[index]!, costs[index]!)); }
      }
      this.#observer = root.observeAvailability(this.#reference, () => this.#collect()); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("query_acquisitions_closed"); this.#reference!.check(); }
  sameEnvironment(reference: ResourceReference, clock: TrustedClock): boolean {
    this.#check(); return clock === this.clock && this.#reference!.sameEnvironment(reference);
  }
  protectRenewal(reference: ResourceReference): QueryRenewalReservation | undefined {
    this.#check(); if (!this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("rpc_query_owner");
    if (this.#working) return; return this.#renewal.protect(reference);
  }
  protectPreparation(reference: ResourceReference): QueryPreparationReservation {
    this.#check();
    if (this.#working || !this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("rpc_query_owner");
    return this.#renewal.protectPreparation(reference);
  }
  acquire(group: ApplicationGroup, client: ContractQueryClient, channel: RPCChannelRuntime, targets: readonly ContractQueryTarget[],
    deadline: TrustedDeadline, windows: readonly bigint[], context?: V4ApplicationContext, delivery?: ContractQueryDelivery,
    renewal?: ContractRenewalProtection, preparation?: ContractQueryPreparation): ContractQueryAcquisition {
    this.#check(); if (this.#working) throw new RPCProtocolError("query_busy"); this.#working = true;
    const references: ResourceReference[] = [];
    const diagnostic = new DiagnosticActivity(this.diagnostics, "application");
    let owner: ContractQueryAcquisition | undefined;
    try {
      if (!deadline.belongsTo(this.clock) || !client.sameEnvironment(this.#reference!) || !group.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_query_owner");
      if (preparation !== undefined) { preparation.check(); if (renewal !== undefined) throw new RPCProtocolError("rpc_query_owner"); }
      const index = preparation === undefined ? this.#renewal.select(renewal?.environment, targets) : this.#renewal.selectPreparation(preparation.environment);
      if (index < 0) throw new ResourceError("resource_exhausted");
      for (const position of this.#positions[index]!) references.push(position.checkout());
      owner = new ContractQueryAcquisition(capability, this, this.runtimeBytes, references, diagnostic); this.#owners[index] = owner;
      const destination = typeof delivery === "function" ? delivery() : delivery;
      owner.prepare(capability, group, client, client.acquisitionDeadline(deadline), windows, context, destination, preparation); this.#check();
      owner.start(capability, client, channel, targets, renewal?.session, preparation?.session); this.#check(); return owner;
    } catch (error) { diagnostic.failure(error); owner?.close(); throw error; }
    finally { if (owner === undefined) for (const reference of references) reference.release(); this.#working = false; this.#collect(); }
  }
  deliveryReleased(token: symbol, owner: ContractQueryAcquisition): boolean {
    if (token !== capability) throw new RPCProtocolError("rpc_query_owner");
    const index = this.#owners.indexOf(owner); if (index < 0) throw new RPCProtocolError("rpc_query_owner");
    return this.#positions[index]!.slice(1).every(position => this.#closed ? position.cleanupComplete() : position.available());
  }
  released(token: symbol, owner: ContractQueryAcquisition): void {
    if (token !== capability) throw new RPCProtocolError("rpc_query_owner");
    const index = this.#owners.indexOf(owner); if (index >= 0) this.#owners[index] = undefined; this.#collect();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#renewal.close();
    for (const positions of this.#positions) for (const position of positions) position.closeAfterUse();
    for (const owner of this.#owners) owner?.close(); this.#collect();
  }
  #collect(): void {
    if (this.#working || this.#collecting) return; this.#collecting = true;
    try {
      for (const owner of this.#owners) owner?.collect(capability);
      this.#renewal.collect();
      if (!this.#closed || this.#owners.some(owner => owner !== undefined) || this.#positions.some(positions => positions.some(position => !position.cleanupComplete()))) return;
      this.#observer?.(); this.#observer = undefined; this.#reference?.release(); this.#reference = undefined;
    } finally { this.#collecting = false; }
  }
  get pending(): number { return this.#owners.reduce((count, owner) => count + (owner === undefined ? 0 : 1), 0); }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
for (const constructor of [ContractQueryAcquisition, ContractQueryAcquisitions]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
