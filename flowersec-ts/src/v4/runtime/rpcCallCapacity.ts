import type { ApplicationWorkClass } from "./applicationExecutor.js";
import { ResourceError, ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";

const capability = Symbol("original general call capacity"), maximum = (1n << 64n) - 1n;
interface Slot {
  generation: bigint;
  handle: RPCCallReservation | undefined;
  position: RPCCallPosition | undefined;
  workClass: ApplicationWorkClass;
  submitted: boolean;
  association: object | undefined;
  released: boolean;
  tails: number;
  networkCleaned: (() => void) | undefined;
  observed: boolean;
}
interface State { capacity: RPCCallCapacity | undefined; readonly index: number; readonly generation: bigint }
const owners = new WeakMap<RPCCallReservation, State>();
const positions = new WeakMap<RPCCallPosition, { capacity: RPCCallCapacity | undefined; index: number; closed: boolean; workClass: ApplicationWorkClass }>();
/** One reusable opportunity in the original K table, including full/late tails. */
export class RPCCallPosition {
  constructor(token: symbol, capacity: RPCCallCapacity, index: number, workClass: ApplicationWorkClass) {
    if (token !== capability) throw new RPCProtocolError("rpc_call_owner");
    positions.set(this, { capacity, index, workClass, closed: false }); Object.freeze(this);
  }
  available(): boolean { const state = positions.get(this)!; return !state.closed && state.capacity?.positionAvailable(this) === true; }
  checkout(): RPCCallReservation {
    const state = positions.get(this)!;
    if (state.closed || state.capacity === undefined) throw new RPCProtocolError("rpc_call_closed");
    return state.capacity.checkoutPosition(this);
  }
  close(): void { const state = positions.get(this)!; if (state.closed) return; state.closed = true; state.capacity?.retirePosition(this); }
  cleanupComplete(): boolean { return positions.get(this)!.capacity === undefined; }
}


/** A local general-call opportunity. Closing the local result does not return
 * an unsettled wire association or a physical publication tail. */
export class RPCCallReservation {
  constructor(token: symbol, state: State) {
    if (token !== capability) throw new RPCProtocolError("rpc_call_owner");
    owners.set(this, state); Object.freeze(this);
  }
  check(): void {
    const state = owners.get(this); if (state?.capacity === undefined) throw new RPCProtocolError("rpc_call_closed");
    state.capacity.check(this);
  }
  /** Start can inherit a resident ancestor after an external short Prepare.
   * Upgrading cannot consume the last remaining short opportunity. */
  inheritClass(workClass: ApplicationWorkClass): void {
    const capacity = owners.get(this)?.capacity;
    if (capacity === undefined) throw new RPCProtocolError("rpc_call_closed"); capacity.inheritClass(this, workClass);
  }
  workClass(): ApplicationWorkClass {
    const capacity = owners.get(this)?.capacity;
    if (capacity === undefined) throw new RPCProtocolError("rpc_call_closed"); return capacity.workClass(this);
  }
  close(): void { owners.get(this)?.capacity?.release(this); }
  networkComplete(): boolean {
    const capacity = owners.get(this)?.capacity; return capacity === undefined || capacity.networkComplete(this);
  }
  onNetworkCleanup(callback: () => void): void {
    const capacity = owners.get(this)?.capacity;
    if (capacity === undefined) callback(); else capacity.onNetworkCleanup(this, callback);
  }
  cleanupComplete(): boolean { return owners.get(this)?.capacity === undefined; }
  toJSON(): object { return {}; }
}

export function rpcCallCapacityCharge(limit: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return new ResourceVector([1024n + runtimeBytes + BigInt(limit) * (128n + runtimeBytes), 0n, 0n, BigInt(limit + 1), 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}

/** One original Session-wide local submission table, shared by every channel
 * and response-bearing stream. A short call may use every free general slot;
 * resident work leaves one opportunity while no actual short call owns it.
 * Entries span preparation, full/late delivery and physical tails. The compact
 * closed table retains no Session, carrier, credential, clock or executor. */
export class RPCCallCapacity {
  #reference: ResourceReference | undefined;
  readonly #slots: Slot[];
  #used = 0;
  #short = 0;
  #closed = false;
  #limit: number;
  #bound: boolean;
  get limit(): number { return this.#limit; }
  constructor(limit: number, runtimeBytes: bigint, reference: ResourceReference, preparing = false) {
    this.#limit = limit; this.#bound = !preparing;
    this.#reference = reference.take(rpcCallCapacityCharge(limit, runtimeBytes));
    try {
      this.#slots = Array.from({ length: limit }, () => ({ generation: 0n, handle: undefined, position: undefined, workClass: "short" as const,
        submitted: false, association: undefined, released: false, tails: 0, networkCleaned: undefined, observed: false }));
      Object.freeze(this);
    } catch (error) { this.#reference.release(); this.#reference = undefined; throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("rpc_calls_closed"); this.#reference!.check(); }
  #slot(handle: RPCCallReservation): Slot {
    const state = owners.get(handle), slot = state?.capacity === this ? this.#slots[state.index] : undefined;
    if (slot === undefined || slot.handle !== handle || slot.generation !== state!.generation) throw new RPCProtocolError("rpc_call_owner");
    return slot;
  }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  borrowReference(): ResourceReference { this.#check(); return this.#reference!.borrow(); }
  bindLimit(limit: number): void {
    this.#check();
    if (this.#bound || !Number.isSafeInteger(limit) || limit < 1 || limit > this.#limit || this.#slots.some(slot => slot.handle !== undefined) ||
        this.#used > limit || this.#slots.slice(limit).some(slot => slot.position !== undefined)) throw new RPCProtocolError("configuration_capacity");
    const resident = this.#slots.filter(slot => slot.position !== undefined && positions.get(slot.position)!.workClass === "resident").length;
    if (resident >= limit) throw new RPCProtocolError("configuration_capacity");
    this.#limit = limit; this.#slots.length = limit; this.#bound = true;
  }
  protect(workClass: ApplicationWorkClass): RPCCallPosition {
    this.#check();
    if (workClass !== "short" && workClass !== "resident") throw new RPCProtocolError("rpc_call_owner");
    const ceiling = this.limit - Number(workClass === "resident" && this.#short === 0);
    if (this.#used >= ceiling) throw new ResourceError("resource_exhausted");
    const index = this.#slots.findIndex(slot => slot.handle === undefined && slot.position === undefined && slot.generation < maximum);
    if (index < 0) throw new ResourceError("resource_exhausted");
    const position = new RPCCallPosition(capability, this, index, workClass);
    this.#slots[index]!.position = position; this.#used++; return position;
  }
  positionAvailable(position: RPCCallPosition): boolean {
    const state = positions.get(position);
    return !this.#closed && state?.capacity === this && !state.closed && this.#slots[state.index]?.handle === undefined && this.#slots[state.index]!.generation < maximum;
  }
  checkoutPosition(position: RPCCallPosition): RPCCallReservation {
    this.#check(); const state = positions.get(position);
    if (!this.#bound || state?.capacity !== this || !this.positionAvailable(position)) throw new ResourceError("resource_exhausted");
    return this.#claim(state.index, state.workClass);
  }
  retirePosition(position: RPCCallPosition): void {
    const state = positions.get(position);
    if (state?.capacity !== this || this.#slots[state.index]?.position !== position) throw new RPCProtocolError("rpc_call_owner");
    this.#collect(this.#slots[state.index]!);
  }
  reserve(workClass: ApplicationWorkClass): RPCCallReservation {
    this.#check(); if (!this.#bound) throw new RPCProtocolError("rpc_call_owner");
    if (workClass !== "short" && workClass !== "resident") throw new RPCProtocolError("rpc_call_owner");
    const ceiling = this.limit - Number(workClass === "resident" && this.#short === 0);
    if (this.#used >= ceiling) throw new ResourceError("resource_exhausted");
    const index = this.#slots.findIndex(slot => slot.handle === undefined && slot.position === undefined && slot.generation < maximum);
    if (index < 0) throw new ResourceError("resource_exhausted");
    this.#used++; return this.#claim(index, workClass);
  }
  #claim(index: number, workClass: ApplicationWorkClass): RPCCallReservation {
    const slot = this.#slots[index]!, generation = slot.generation + 1n;
    if (generation > maximum) throw new ResourceError("resource_exhausted");
    const handle = new RPCCallReservation(capability, { capacity: this, index, generation });
    slot.generation = generation; slot.handle = handle; slot.workClass = workClass;
    slot.submitted = slot.released = slot.observed = false; slot.association = undefined; slot.tails = 0; slot.networkCleaned = undefined;
    if (workClass === "short") this.#short++; return handle;
  }
  check(handle: RPCCallReservation): void {
    this.#check(); if (this.#slot(handle).released) throw new RPCProtocolError("rpc_call_closed");
  }
  checkUnsubmitted(handle: RPCCallReservation): void {
    this.check(handle); if (this.#slot(handle).submitted) throw new RPCProtocolError("rpc_call_owner");
  }
  inheritClass(handle: RPCCallReservation, workClass: ApplicationWorkClass): void {
    this.checkUnsubmitted(handle);
    if (workClass !== "short" && workClass !== "resident") throw new RPCProtocolError("rpc_call_owner");
    const slot = this.#slot(handle);
    if (slot.workClass === "resident" || workClass === "short") return;
    if (this.#short === 1 && this.#used >= this.limit) throw new ResourceError("resource_exhausted");
    slot.workClass = "resident"; this.#short--;
  }
  workClass(handle: RPCCallReservation): ApplicationWorkClass { this.check(handle); return this.#slot(handle).workClass; }
  networkComplete(handle: RPCCallReservation): boolean {
    const slot = this.#slot(handle); return slot.association === undefined && slot.tails === 0;
  }
  onNetworkCleanup(handle: RPCCallReservation, callback: () => void): void {
    const slot = this.#slot(handle);
    if (slot.observed || !slot.submitted) throw new RPCProtocolError("rpc_call_owner");
    slot.observed = true;
    if (slot.association === undefined && slot.tails === 0) callback(); else slot.networkCleaned = callback;
  }
  attach(handle: RPCCallReservation, association: object): void {
    this.checkUnsubmitted(handle); const slot = this.#slot(handle);
    slot.submitted = true; slot.association = association;
  }
  settled(handle: RPCCallReservation, association: object): void {
    const slot = this.#slot(handle);
    if (slot.association !== association) throw new RPCProtocolError("rpc_call_owner");
    slot.association = undefined; this.#collect(slot);
  }
  retainPublication(handle: RPCCallReservation, association: object): () => void {
    const slot = this.#slot(handle);
    if (slot.association !== association || slot.tails >= 64) throw new RPCProtocolError("rpc_call_owner");
    slot.tails++; let active = true;
    return () => { if (!active) return; active = false; slot.tails--; this.#collect(slot); };
  }
  release(handle: RPCCallReservation): void { const slot = this.#slot(handle); slot.released = true; this.#collect(slot); }
  #collect(slot: Slot): void {
    const cleaned = slot.association === undefined && slot.tails === 0 ? slot.networkCleaned : undefined;
    if (cleaned !== undefined) slot.networkCleaned = undefined;
    if (slot.handle !== undefined && slot.released && slot.association === undefined && slot.tails === 0) {
      owners.get(slot.handle)!.capacity = undefined; slot.handle = undefined;
      if (slot.position === undefined) this.#used--; if (slot.workClass === "short") this.#short--;
    }
    if (slot.handle === undefined && slot.position !== undefined && positions.get(slot.position)!.closed) {
      positions.get(slot.position)!.capacity = undefined; slot.position = undefined; this.#used--;
    }
    if (this.#closed && this.#used === 0) {
      this.#slots.length = 0; this.#reference?.release(); this.#reference = undefined;
    }
    cleaned?.();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const slot of this.#slots) slot.position?.close();
    if (this.#used === 0) { this.#slots.length = 0; this.#reference?.release(); this.#reference = undefined; }
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
for (const constructor of [RPCCallCapacity, RPCCallReservation, RPCCallPosition]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
