import type { ApplicationGroup } from "./applicationExecutor.js";
import type { ContractQueryServiceStep } from "./contractQueryService.js";
import { ResourceError, ResourceVector, type ResourceReference, type ResourceRoot, type ResourceServiceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { timerChunk } from "./deadline.js";

const capability = Symbol("protected fixed SDK query lane");
const hostNow = performance.now.bind(performance);
/** Implemented only by original SDK incoming service/acquisition owners. */
export interface FixedQueryWork {
  sameEnvironment(reference: ResourceReference): boolean;
  attachWake(wake: () => void, consumer: object): void;
  stepPosition(position: number, consumer?: object): ContractQueryServiceStep;
  nextDeadlineMS(): bigint | undefined;
  close(): void;
  cleanupComplete(): boolean;
}
interface Slot {
  owner: FixedQueryProtection | undefined;
  backing: ResourceReference | undefined;
  service: FixedQueryWork | undefined;
  position: number;
  eligible: boolean;
  ready: boolean;
  running: boolean;
  wakeAt: number | undefined;
}
function slot(): Slot { return { owner: undefined, backing: undefined, service: undefined, position: 0, eligible: false, ready: false, running: false, wakeAt: undefined }; }

/** Actual pre-admission protection for a Session's two incoming queries or
 * one original Environment acquisition. These are fixed descriptors in the
 * original application executor, not workers or a second request queue. */
export class FixedQueryProtection {
  #executor: FixedQueryExecutor | undefined;
  #service: FixedQueryWork | undefined;
  #closed = false;
  #remaining: number;
  constructor(token: symbol, executor: FixedQueryExecutor, readonly group: ApplicationGroup, readonly direction: 0 | 1) {
    if (token !== capability) throw new RPCProtocolError("rpc_query_consumer"); this.#executor = executor; this.#remaining = direction === 0 ? 2 : 1; Object.freeze(this);
  }
  attach(service: FixedQueryWork): void {
    if (this.#closed || this.#service !== undefined) throw new RPCProtocolError("rpc_query_consumer");
    this.#executor!.attach(this, service); this.#service = service;
  }
  wake(): void { this.#executor?.wake(this); }
  detach(service: FixedQueryWork): void {
    if (this.#service !== service || !service.cleanupComplete()) throw new RPCProtocolError("rpc_query_consumer");
    this.#executor?.detach(this, service); this.#service = undefined;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#service?.close(); this.#executor?.cancel(this);
  }
  retired(token: symbol): void {
    if (token !== capability || this.#remaining === 0) throw new RPCProtocolError("rpc_query_consumer");
    if (--this.#remaining === 0) { this.#service = undefined; this.#executor = undefined; this.group.release(); }
  }
  get closed(): boolean { return this.#closed; }
  cleanupComplete(): boolean { return this.#remaining === 0; }
}

/** One running step and four actual ready descriptors. The finite protection
 * index holds the other eligible owners, without allocating work per wake or
 * using ordinary/Completion permits. Each host turn executes one bounded SDK
 * step and yields to transport I/O; the host clock schedules wakeups only.
 * Original trusted deadlines still authorize/refuse every real query action. */
export class FixedQueryExecutor {
  #reference: ResourceServiceReference | undefined;
  // Presets protect eight/four or four/two incoming/acquisition positions.
  // Outgoing query positions are never general Completion reservations.
  readonly #slots: Slot[];
  readonly #incoming: number;
  readonly #ready: number[] = [];
  #lastGroup: ApplicationGroup | undefined;
  #cursor = 0;
  #lastDirection: 0 | 1 = 1;
  #running = false;
  #closed = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #timerGeneration = 0n;
  constructor(root: ResourceRoot) {
    const owners = root.applicationResources.queryOwners;
    // A Session requires two original incoming owners. Round the protected
    // partition to complete pairs; all remaining descriptors serve individual
    // acquisitions, including explicitly configured non-preset capacities.
    this.#incoming = 2 * Math.floor(owners / 3);
    this.#slots = Array.from({ length: owners }, slot);
    this.#reference = root.reserveService(new ResourceVector([256n * 1024n, 0n, 0n, BigInt(owners + 1), 1n, 1n, 1n, 0n, 0n, 0n, 0n]));
  }
  get reference(): ResourceServiceReference { this.#check(); return this.#reference!; }
  #check(): void { if (this.#closed || this.#reference === undefined) throw new RPCProtocolError("rpc_query_executor_closed"); this.#reference.check(); }
  protect(group: ApplicationGroup, original: ResourceReference, direction: 0 | 1 = 0): FixedQueryProtection {
    this.#check(); group.check();
    if (!group.sameEnvironment(original) || direction === 0 && this.#slots.some(slot => slot.owner?.group === group && slot.owner.direction === 0)) throw new RPCProtocolError("rpc_query_consumer");
    const indices: number[] = [], count = direction === 0 ? 2 : 1;
    for (let i = direction === 0 ? 0 : this.#incoming; i < (direction === 0 ? this.#incoming : this.#slots.length) && indices.length < count; i++) if (this.#slots[i]!.owner === undefined) indices.push(i);
    if (indices.length !== count) throw new ResourceError("resource_exhausted");
    const references: ResourceReference[] = [];
    let retained = false;
    try {
      for (let i = 0; i < count; i++) references.push(original.borrow());
      group.retain(); retained = true;
      const owner = new FixedQueryProtection(capability, this, group, direction);
      for (let n = 0; n < count; n++) Object.assign(this.#slots[indices[n]!]!, slot(), { owner, backing: references[n]!, position: n });
      return owner;
    } catch (error) { for (const reference of references) reference.release(); if (retained) group.release(); throw error; }
  }
  attach(owner: FixedQueryProtection, service: FixedQueryWork): void {
    this.#check(); owner.group.check();
    const slots = this.#slots.filter(slot => slot.owner === owner);
    if (slots.length !== (owner.direction === 0 ? 2 : 1) || owner.closed || slots.some(slot => slot.service !== undefined || !service.sameEnvironment(slot.backing!))) throw new RPCProtocolError("rpc_query_consumer");
    service.attachWake(() => owner.wake(), owner);
    for (const slot of slots) { slot.service = service; slot.eligible = true; }
    this.#schedule();
  }
  wake(owner: FixedQueryProtection): void {
    if (owner.closed) { this.cancel(owner); return; }
    if (this.#closed) return;
    for (const slot of this.#slots) if (slot.owner === owner && slot.service !== undefined) { slot.eligible = true; slot.wakeAt = undefined; }
    this.#schedule();
  }
  detach(owner: FixedQueryProtection, service: FixedQueryWork): void {
    for (let index = 0; index < this.#slots.length; index++) {
      const slot = this.#slots[index]!;
      if (slot.owner !== owner) continue;
      if (slot.service !== service) throw new RPCProtocolError("rpc_query_consumer");
      const at = this.#ready.indexOf(index); if (at >= 0) this.#ready.splice(at, 1);
      slot.service = undefined; slot.eligible = slot.ready = false; slot.wakeAt = undefined;
    }
    if (owner.closed) this.cancel(owner); else this.#schedule();
  }
  cancel(owner: FixedQueryProtection): void {
    for (let i = 0; i < this.#slots.length; i++) if (this.#slots[i]!.owner === owner) {
      const slot = this.#slots[i]!; slot.eligible = false; slot.wakeAt = undefined;
      const at = this.#ready.indexOf(i); if (at >= 0) this.#ready.splice(at, 1); slot.ready = false;
      if (!slot.running && slot.service?.cleanupComplete() !== false && slot.owner === owner) this.#retire(slot);
    }
    this.#schedule(); this.#collect();
  }
  cancelGroup(group: ApplicationGroup): void { for (const slot of this.#slots) if (slot.owner?.group === group) slot.owner.close(); }
  #retire(slot: Slot): void {
    const owner = slot.owner; if (owner === undefined) return;
    const backing = slot.backing; Object.assign(slot, { owner: undefined, backing: undefined, service: undefined, position: 0, eligible: false, ready: false, running: false, wakeAt: undefined });
    backing?.release(); owner.retired(capability);
  }
  #promote(): void {
    while (this.#ready.length < 4) {
      let candidate = -1;
      for (let pass = 0; pass < 3 && candidate < 0; pass++) for (let n = 0; n < this.#slots.length; n++) {
        const index = (this.#cursor + n) % this.#slots.length, slot = this.#slots[index]!;
        if (slot.owner === undefined || slot.owner.closed || slot.service === undefined || !slot.eligible || slot.ready || slot.running ||
            pass < 2 && slot.owner.direction === this.#lastDirection || pass === 0 && slot.owner.group === this.#lastGroup) continue;
        candidate = index; break;
      }
      if (candidate < 0) break;
      const slot = this.#slots[candidate]!; slot.ready = true; slot.eligible = false;
      this.#ready.push(candidate); this.#cursor = (candidate + 1) % this.#slots.length; this.#lastGroup = slot.owner!.group; this.#lastDirection = slot.owner!.direction;
    }
  }
  #schedule(): void {
    if (this.#closed || this.#running) return;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    const now = hostNow();
    for (const slot of this.#slots) if (slot.wakeAt !== undefined && slot.wakeAt <= now) { slot.eligible = true; slot.wakeAt = undefined; }
    this.#promote();
    let delay: number | undefined = this.#ready.length === 0 ? undefined : 0;
    if (delay === undefined) for (const slot of this.#slots) if (slot.wakeAt !== undefined) delay = Math.min(delay ?? Infinity, Math.max(0, Math.ceil(slot.wakeAt - now)));
    if (delay === undefined) return;
    const generation = ++this.#timerGeneration;
    this.#timer = setTimeout(() => { if (this.#closed || generation !== this.#timerGeneration) return; this.#timer = undefined; this.#run(); }, delay);
  }
  #run(): void {
    if (this.#closed || this.#running) return;
    const now = hostNow();
    for (const slot of this.#slots) if (slot.wakeAt !== undefined && slot.wakeAt <= now) { slot.eligible = true; slot.wakeAt = undefined; }
    this.#promote(); const index = this.#ready.shift(); if (index === undefined) { this.#schedule(); return; }
    const slot = this.#slots[index]!, owner = slot.owner!; slot.ready = false; slot.running = this.#running = true;
    try {
      this.#check(); owner.group.check(); slot.backing!.check();
      const result = slot.service!.stepPosition(slot.position, owner);
      if (!owner.closed && slot.service !== undefined && result === "progress") slot.eligible = true;
      else if (!owner.closed && slot.service !== undefined && result === "blocked") {
        let remaining: bigint | undefined;
        try { remaining = slot.service!.nextDeadlineMS(); } catch { remaining = 1n; }
        if (remaining !== undefined) slot.wakeAt = hostNow() + timerChunk(remaining);
      }
    } catch { owner.close(); }
    finally {
      slot.running = this.#running = false;
      if (owner.closed && slot.service?.cleanupComplete() !== false && slot.owner === owner) this.#retire(slot);
      this.#schedule(); this.#collect();
    }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#timerGeneration++;
    for (const slot of this.#slots) slot.owner?.close(); this.#collect();
  }
  #collect(): void { if (this.#closed && !this.#running && this.#slots.every(slot => slot.owner === undefined)) { this.#reference?.release(); this.#reference = undefined; this.#lastGroup = undefined; } }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
for (const constructor of [FixedQueryExecutor, FixedQueryProtection]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
