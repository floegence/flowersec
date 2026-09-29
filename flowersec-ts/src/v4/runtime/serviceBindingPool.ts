import { sha256 } from "@noble/hashes/sha2.js";
import { ResourceVector, type ResourceAccount, type ResourceOwner, type ResourceReference, type ResourceRequest, type ResourceRoot, type ProtectedResourceReservation } from "./resources.js";
import { contractSnapshotResultCapacityCharges } from "./contractSnapshotReader.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { CapturedServiceBinding } from "./serviceBindingConfig.js";
import { ServiceOfferScheduler } from "./serviceOfferScheduler.js";
import { ServiceOfferPlan } from "./serviceOfferPlan.js";
import type { TrustedClock } from "./clock.js";

export function serviceBindingPoolCharge(runtimeBytes: bigint): ResourceVector {
  // Complete fixed method index, legal-group/EDF scratch and the sole shared
  // renewal task/wake. Idle managed bindings do not run per-method timers.
  return new ResourceVector([57344n + 576n * runtimeBytes, 0n, 0n, 386n, 1n, 2n, 1n, 0n, 0n, 0n, 0n]);
}
export function serviceBindingAccount(root: ResourceRoot, owner: ResourceOwner, methods: 16 | 256, maximum: ResourceVector): ResourceAccount {
  const identity = new TextEncoder().encode(JSON.stringify([owner.tenant, owner.environment, owner.backing, "service_bindings"]));
  const digest = sha256(identity), id = Array.from(digest.subarray(0, 16), byte => byte.toString(16).padStart(2, "0")).join("");
  identity.fill(0); digest.fill(0);
  const values = [...maximum.values()]; values[0] = methods === 16 ? 1048576n : 6291456n;
  return root.account("pool", id, new ResourceVector(values));
}
export function serviceBindingCharge(count: number, runtimeBytes: bigint): ResourceVector {
  // Complete method/selector/policy, wait/cancellation and fixed target index.
  // Payload bodies have separate prepaid positions, including unused methods.
  return new ResourceVector([8192n + BigInt(count) * (6528n + runtimeBytes), 0n, 0n, BigInt(34 + count * 4), 5n, 9n, 5n, 0n, 0n, 0n, 0n]);
}
interface ServiceBindingRoot { users: number; reservations: number }
const capability = Symbol("original Environment service binding");

/** One service root and all its method positions. A closing binding remains
 * counted until every retained current/candidate/query reference has exited. */
export class ServiceBindingReservation {
  #reference: ResourceReference | undefined;
  readonly current: ProtectedResourceReservation[] = [];
  readonly #positions = new Set<ProtectedResourceReservation>();
  #batch: ProtectedResourceReservation | undefined;
  #close: (() => void) | undefined;
  #closed = false;
  #finished = false;
  #busy = false;
  #next = 0n;
  #users = 0;
  #configuration: CapturedServiceBinding | undefined;
  constructor(token: symbol, readonly pool: ServiceBindingPool, readonly count: number, readonly owner: ResourceOwner, references: readonly ResourceReference[], configuration: CapturedServiceBinding, readonly publicRoot: object, readonly rootState: ServiceBindingRoot) {
    if (token !== capability || references.length !== count + 2) throw new RPCProtocolError("service_binding_owner");
    this.#configuration = configuration;
    this.#reference = references[0]!.take(serviceBindingCharge(count, pool.runtimeBytes));
    const costs = contractSnapshotResultCapacityCharges(8, pool.runtimeBytes);
    try {
      this.#batch = pool.root.protect(references[1]!, costs[0]!); this.#positions.add(this.#batch);
      for (let i = 0; i < count; i++) {
        const position = pool.root.protect(references[i + 2]!, costs[1]!); this.current.push(position); this.#positions.add(position);
      }
      Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  check(): void { if (this.#closed) throw new RPCProtocolError("service_binding_closed"); this.pool.check(); this.#reference!.check(); }
  claim(configuration: CapturedServiceBinding, pool: ServiceBindingPool): void {
    this.check();
    if (this.#configuration !== configuration || pool !== this.pool) throw new RPCProtocolError("service_binding_owner");
    this.#configuration = undefined;
  }
  get reference(): ResourceReference { this.check(); return this.#reference!; }
  hold(): () => void {
    this.check(); if (this.rootState.users >= (this.pool.methodLimit === 16 ? 2 : 4)) throw new RPCProtocolError("resource_exhausted"); this.#users++; this.rootState.users++; let held = true;
    return () => { if (held) { held = false; this.#users--; this.rootState.users--; this.collect(); } };
  }
  onClose(close: () => void): void {
    if (this.#close !== undefined) throw new RPCProtocolError("service_binding_owner"); this.#close = close; if (this.#closed) close();
  }
  /** Pay the complete candidate batch at once before checking out any slot. */
  candidates(count: number): ProtectedResourceReservation[] {
    const references = this.pool.root.reserveBatch(this.candidateRequests(count));
    try { return this.adoptCandidates(references); } finally { for (const reference of references) reference.release(); }
  }
  /** Used by one original query to reserve a legal cross-binding batch in one
   * root transaction, without partial vector acquisition across participants. */
  candidateRequests(count: number): readonly ResourceRequest[] {
    this.check(); this.collect();
    if (count < 1 || count > 8 || this.#positions.size + count > 1 + 2 * this.count || this.#next === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
    const costs = contractSnapshotResultCapacityCharges(count, this.pool.runtimeBytes), id = ++this.#next;
    return costs.slice(1).map((charge, index) => ({ accounts: this.pool.accounts,
      owner: { ...this.owner, kind: `${this.owner.kind}_candidate_${id}_${index}` }, charge }));
  }
  adoptCandidates(references: readonly ResourceReference[]): ProtectedResourceReservation[] {
    this.check(); this.collect(); const count = references.length;
    if (count < 1 || count > 8 || this.#positions.size + count > 1 + 2 * this.count ||
        !references.every(reference => reference.sameEnvironment(this.#reference!))) throw new RPCProtocolError("resource_exhausted");
    const costs = contractSnapshotResultCapacityCharges(count, this.pool.runtimeBytes);
    const positions: ProtectedResourceReservation[] = [];
    try {
      for (let i = 0; i < count; i++) positions.push(this.pool.root.protect(references[i]!, costs[i + 1]!));
      this.check(); for (const position of positions) this.#positions.add(position); return positions;
    } catch (error) { for (const position of positions) position.closeAfterUse(); throw error; }
  }
  delivery(positions: readonly ProtectedResourceReservation[]): ResourceReference[] {
    this.check();
    if (positions.length < 1 || positions.length > 8 || !this.#batch!.available() || new Set(positions).size !== positions.length ||
        positions.some(position => !this.#positions.has(position) || !position.available())) throw new RPCProtocolError("resource_exhausted");
    const references: ResourceReference[] = [];
    try { references.push(this.#batch!.checkout()); for (const position of positions) references.push(position.checkout()); return references; }
    catch (error) { for (const reference of references) reference.release(); throw error; }
  }
  retire(position: ProtectedResourceReservation): void {
    if (!this.#positions.has(position)) throw new RPCProtocolError("service_binding_owner"); position.closeAfterUse(); this.collect();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#configuration = undefined;
    const close = this.#close; this.#close = undefined;
    try { close?.(); } finally { for (const position of this.#positions) position.closeAfterUse(); this.collect(); }
  }
  collect(): void {
    if (this.#busy || this.#finished) return; this.#busy = true;
    try {
      for (const position of this.#positions) if (position.cleanupComplete()) this.#positions.delete(position);
      if (!this.#closed || this.#positions.size !== 0 || this.#users !== 0) return;
      this.#batch = undefined; this.current.length = 0; this.#reference?.release(); this.#reference = undefined; this.#finished = true;
      this.pool.released(capability, this);
    } finally { this.#busy = false; }
  }
  cleanupComplete(): boolean { this.collect(); return this.#finished; }
}

/** The shared Environment method count is independent of Session K and query
 * J. Multiple fixed Session bindings always consume distinct actual owners. */
export class ServiceBindingPool {
  #reference: ResourceReference | undefined;
  #offers: ServiceOfferPlan | undefined;
  #scheduler: ServiceOfferScheduler | undefined;
  readonly #bindings = new Set<ServiceBindingReservation>();
  readonly #roots = new Map<object, ServiceBindingRoot>();
  #methods = 0;
  #sequence = 0n;
  #observer: (() => void) | undefined;
  #closed = false;
  #closing = false;
  #busy = false;
  constructor(readonly root: ResourceRoot, readonly accounts: readonly ResourceAccount[], readonly owner: ResourceOwner,
    readonly methodLimit: 16 | 256, readonly runtimeBytes: bigint, reference: ResourceReference, clock: TrustedClock) {
    if (methodLimit !== 16 && methodLimit !== 256) throw new RPCProtocolError("configuration_capacity");
    this.#reference = reference.take(serviceBindingPoolCharge(runtimeBytes));
    try {
      this.#offers = new ServiceOfferPlan(clock, methodLimit, this.#reference);
      this.#scheduler = new ServiceOfferScheduler(root, clock, this.#offers, () => this.collect());
      this.#observer = root.observeAvailability(this.#reference, () => this.collect()); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  check(): void { if (this.#closed) throw new RPCProtocolError("service_binding_closed"); this.#reference!.check(); }
  get offers(): ServiceOfferPlan { this.check(); return this.#offers!; }
  reserve(config: CapturedServiceBinding, publicRoot: object = Object.freeze({})): ServiceBindingReservation {
    this.check(); const count = config.methods.length;
    const existing = this.#roots.get(publicRoot);
    if (existing === undefined && this.#roots.size >= 64 || count > this.methodLimit - this.#methods || this.#sequence === (1n << 64n) - 1n) throw new RPCProtocolError("configuration_capacity");
    const owner = { ...this.owner, kind: `service_${++this.#sequence}` };
    const result = contractSnapshotResultCapacityCharges(8, this.runtimeBytes);
    const charges = [serviceBindingCharge(count, this.runtimeBytes), result[0]!, ...Array.from({ length: count }, () => result[1]!)];
    const references = this.root.reserveBatch(charges.map((charge, index) => ({ accounts: this.accounts, owner: { ...owner, kind: `${owner.kind}_${index}` }, charge })));
    try {
      const rootState = existing ?? { users: 0, reservations: 0 };
      const binding = new ServiceBindingReservation(capability, this, count, owner, references, config, publicRoot, rootState);
      rootState.reservations++; this.#roots.set(publicRoot, rootState);
      this.#bindings.add(binding); this.#methods += count; return binding;
    } finally { for (const reference of references) reference.release(); }
  }
  released(token: symbol, binding: ServiceBindingReservation): void {
    if (token !== capability) throw new RPCProtocolError("service_binding_owner");
    if (this.#bindings.delete(binding)) {
      this.#methods -= binding.count;
      if (--binding.rootState.reservations === 0) this.#roots.delete(binding.publicRoot);
    } this.collect();
  }
  collect(): void {
    if (this.#busy || this.#closing) return; this.#busy = true;
    try {
      for (const binding of this.#bindings) binding.collect();
      if (!this.#closed || this.#bindings.size !== 0 || this.#scheduler?.cleanupComplete() === false) return;
      this.#scheduler = undefined;
      this.#observer?.(); this.#observer = undefined; this.#reference?.release(); this.#reference = undefined;
    } finally { this.#busy = false; }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#closing = true;
    try { this.#scheduler?.close(); for (const binding of this.#bindings) binding.close(); this.#offers?.close(); this.#offers = undefined; }
    finally { this.#closing = false; this.collect(); }
  }
  cleanupComplete(): boolean { this.collect(); return this.#reference === undefined; }
}
Object.freeze(ServiceBindingReservation.prototype); Object.freeze(ServiceBindingReservation);
Object.freeze(ServiceBindingPool.prototype); Object.freeze(ServiceBindingPool);
