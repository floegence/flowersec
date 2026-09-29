import type { TrustedDeadline } from "./deadline.js";
import type { TrustedClock } from "./clock.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { ResourceReference } from "./resources.js";
import type { AdmissionOffer } from "./serviceContract.js";
import { timeAdd } from "./timeArithmetic.js";
import type { ServiceOfferParticipant } from "./serviceOfferWork.js";

export function serviceOfferBlocked(reason: string): boolean {
  return ["source_unavailable", "permission_denied", "service_unavailable", "query_source_unavailable", "query_client_closed",
    "method_unavailable", "deadline_exceeded", "time_expired", "time_cancelled", "service_binding_closed"].includes(reason);
}
const maximum = (1n << 64n) - 1n, capability = Symbol("original managed Offer membership");
export interface ServiceOfferTiming {
  /** Includes admission, scheduling, response validation and actual tail reuse. */
  readonly batchMS: bigint;
  readonly suspendMS: bigint;
  readonly joinMS: bigint;
  readonly timeErrorMS: bigint;
}
export function captureServiceOfferTiming(input: ServiceOfferTiming = { batchMS: 2000n, suspendMS: 60000n, joinMS: 12000n, timeErrorMS: 2000n }): ServiceOfferTiming {
  const { batchMS, suspendMS, joinMS, timeErrorMS } = input;
  if (typeof batchMS !== "bigint" || batchMS < 1n || [batchMS, suspendMS, joinMS, timeErrorMS].some(value => typeof value !== "bigint" || value < 0n || value > maximum)) throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ batchMS, suspendMS, joinMS, timeErrorMS });
}
export interface ServiceOfferEnvelope {
  readonly methods: number;
  readonly groups: number;
  readonly batches: number;
  readonly requiredMS: bigint;
  readonly advanceMS: bigint;
  readonly deadlineMS: bigint;
  readonly minimumRemainingMS: bigint;
}
/** Actual source/Session identity is an SDK object. Namespace is deliberately
 * absent: same-authority, same-Session targets may batch across namespaces. */
export interface ServiceOfferInput {
  readonly method: object;
  readonly namespace: string;
  readonly typeID: number;
  readonly group: object;
  readonly authority: string;
  readonly maximumWindowMS: bigint;
  readonly timing: ServiceOfferTiming;
  readonly offer: AdmissionOffer;
}
interface Entry {
  readonly input: Omit<ServiceOfferInput, "offer">;
  readonly membership: ServiceOfferMembership;
  offer: AdmissionOffer;
  active: boolean;
  participant: ServiceOfferParticipant | undefined;
  readonly order: bigint;
  retryAtMS: bigint;
  failures: number;
  inFlight: boolean;
  blocked: boolean;
  sourceChanged: boolean;
  deadlineCap: bigint | undefined;
}
export interface ScheduledOffer {
  readonly membership: ServiceOfferMembership;
  readonly participant: ServiceOfferParticipant;
  readonly group: object;
  readonly authority: string;
}
export class ServiceOfferMembership {
  #plan: ServiceOfferPlan | undefined;
  #reference: ResourceReference | undefined;
  constructor(token: symbol, plan: ServiceOfferPlan, reference: ResourceReference) {
    if (token !== capability) throw new RPCProtocolError("service_binding_owner");
    this.#plan = plan; this.#reference = reference.borrow(); Object.freeze(this);
  }
  check(token: symbol, plan: ServiceOfferPlan): void {
    if (token !== capability || this.#plan !== plan) throw new RPCProtocolError("service_binding_closed"); this.#reference!.checkRetained();
  }
  activate(participant: ServiceOfferParticipant): void {
    if (this.#plan === undefined) throw new RPCProtocolError("service_binding_closed"); this.#plan.activate(capability, this, participant);
  }
  sourceAvailable(): void {
    if (this.#plan === undefined) throw new RPCProtocolError("service_binding_closed"); this.#plan.sourceAvailable(capability, this);
  }
  prepareUpdate(offer: AdmissionOffer): () => void {
    if (this.#plan === undefined) throw new RPCProtocolError("service_binding_closed"); return this.#plan.prepareUpdate(capability, this, offer);
  }
  close(): void {
    const plan = this.#plan; if (plan === undefined) return;
    this.#plan = undefined; plan.release(capability, this); this.#reference?.release(); this.#reference = undefined;
  }
  toJSON(): object { return {}; }
}

/** One Environment's real simultaneous remote renewal responsibilities.
 * Pending admission also counts, so concurrent Bind cannot each qualify using
 * an incomplete method set. Arithmetic is a conditional configuration gate,
 * not a measurement or a claim that the source/provider meets its envelope. */
export class ServiceOfferPlan {
  #clock: TrustedClock | undefined;
  #reference: ResourceReference | undefined;
  readonly #entries = new Map<ServiceOfferMembership, Entry>();
  #generation = 0n;
  #closed = false;
  #nextOrder = 0n;
  #cursor = 0n;
  #wake: (() => void) | undefined;
  constructor(clock: TrustedClock, readonly limit: 16 | 256, reference: ResourceReference) {
    this.#clock = clock; this.#reference = reference.borrow(); Object.freeze(this);
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("service_binding_closed"); this.#reference!.checkRetained(); }
  observe(wake: () => void): void { this.#check(); if (this.#wake !== undefined) throw new RPCProtocolError("service_binding_owner"); this.#wake = wake; }
  #groups<T extends Pick<ServiceOfferInput, "group" | "authority" | "namespace" | "typeID">>(inputs: readonly T[]): T[][] {
    const sources = new Map<object, Map<string, { targets: Set<string>; inputs: T[] }[]>>();
    const groups: T[][] = [];
    for (const input of inputs) {
      let authorities = sources.get(input.group);
      if (authorities === undefined) { authorities = new Map(); sources.set(input.group, authorities); }
      let lanes = authorities.get(input.authority);
      if (lanes === undefined) { lanes = []; authorities.set(input.authority, lanes); }
      const key = `${input.namespace}:${input.typeID}`;
      let lane = lanes.find(candidate => !candidate.targets.has(key));
      if (lane === undefined) { lane = { targets: new Set(), inputs: [] }; lanes.push(lane); groups.push(lane.inputs); }
      lane.targets.add(key); lane.inputs.push(input);
    }
    return groups;
  }
  #envelope(inputs: readonly Pick<ServiceOfferInput, "group" | "authority" | "namespace" | "typeID" | "timing">[]): ServiceOfferEnvelope {
    const groups = this.#groups(inputs);
    let suspendMS = 0n, joinMS = 0n, timeErrorMS = 0n;
    for (const input of inputs) {
      if (input.timing.suspendMS > suspendMS) suspendMS = input.timing.suspendMS;
      if (input.timing.joinMS > joinMS) joinMS = input.timing.joinMS;
      if (input.timing.timeErrorMS > timeErrorMS) timeErrorMS = input.timing.timeErrorMS;
    }
    let batches = 0, duration = 0n;
    for (const group of groups) {
      const n = Math.ceil(group.length / 8); batches += n;
      let batchMS = 0n;
      for (const input of group) if (input.timing.batchMS > batchMS) batchMS = input.timing.batchMS;
      if (batchMS > maximum / BigInt(n)) throw new RPCProtocolError("configuration_capacity");
      duration = timeAdd(duration, BigInt(n) * batchMS);
    }
    const requiredMS = timeAdd(timeAdd(duration, suspendMS), timeAdd(joinMS, timeErrorMS));
    const advanceMS = timeAdd(requiredMS, 30000n), deadlineMS = timeAdd(requiredMS, 20000n);
    if (advanceMS > maximum / 2n) throw new RPCProtocolError("configuration_capacity");
    return Object.freeze({ methods: inputs.length, groups: groups.length, batches, requiredMS, advanceMS, deadlineMS,
      minimumRemainingMS: advanceMS * 2n > 300000n ? advanceMS * 2n : 300000n });
  }
  envelope(): ServiceOfferEnvelope { this.#check(); return this.#envelope([...this.#entries.values()].map(entry => entry.input)); }
  #window(offer: AdmissionOffer, maximumWindowMS: bigint, upperMS: bigint, remainingMS: bigint): void {
    if (maximumWindowMS < remainingMS || offer.notBeforeMS >= offer.notAfterMS || offer.notAfterMS - offer.notBeforeMS > maximumWindowMS) throw new RPCProtocolError("configuration_capacity");
    const begins = upperMS > offer.notBeforeMS ? upperMS : offer.notBeforeMS;
    if (begins >= offer.notAfterMS || offer.notAfterMS - begins < remainingMS) throw new RPCProtocolError("admission_window_closed");
  }
  admit(inputs: readonly ServiceOfferInput[], reference: ResourceReference): readonly ServiceOfferMembership[] {
    this.#check();
    if (!this.#reference!.sameEnvironment(reference) || inputs.length < 1 || inputs.length > this.limit - this.#entries.size ||
        this.#generation === maximum || this.#nextOrder > maximum - BigInt(inputs.length)) throw new RPCProtocolError("configuration_capacity");
    const captured = inputs.map(input => Object.freeze({ method: input.method, namespace: input.namespace, typeID: input.typeID, group: input.group, authority: input.authority,
      maximumWindowMS: input.maximumWindowMS, timing: captureServiceOfferTiming(input.timing), offer: input.offer }));
    const seen = new Set<object>();
    for (const input of captured) {
      if (input.method === null || typeof input.method !== "object" || input.group === null || typeof input.group !== "object" ||
          typeof input.namespace !== "string" || input.namespace.length < 1 || input.namespace.length > 128 ||
          !Number.isSafeInteger(input.typeID) || input.typeID < 1 || input.typeID > 4294967295 ||
          typeof input.authority !== "string" || input.authority.length < 1 || input.authority.length > 256 ||
          typeof input.maximumWindowMS !== "bigint" || input.maximumWindowMS < 1n || input.maximumWindowMS > maximum || seen.has(input.method) ||
          [...this.#entries.values()].some(entry => entry.input.method === input.method)) throw new RPCProtocolError("configuration_capacity");
      seen.add(input.method);
    }
    const generation = this.#generation, now = this.#clock!.sample().requireInterval(); this.#check();
    if (this.#generation !== generation) throw new RPCProtocolError("renewal_plan_changed");
    const all = [...this.#entries.values()].map(entry => ({ ...entry.input, offer: entry.offer })).concat(captured), envelope = this.#envelope(all);
    for (const input of all) this.#window(input.offer, input.maximumWindowMS, now.upperMS, envelope.minimumRemainingMS);
    const members: ServiceOfferMembership[] = [];
    try {
      for (let index = 0; index < captured.length; index++) members.push(new ServiceOfferMembership(capability, this, reference));
      for (let index = 0; index < members.length; index++) {
        const { offer, ...input } = captured[index]!;
        this.#entries.set(members[index]!, { input: Object.freeze(input), membership: members[index]!, offer, active: false,
          participant: undefined, order: ++this.#nextOrder, retryAtMS: 0n, failures: 0, inFlight: false, blocked: false, sourceChanged: false, deadlineCap: undefined });
      }
      this.#generation++; this.#wake?.(); return Object.freeze(members);
    } catch (error) { for (const member of members) member.close(); throw error; }
  }
  #entry(token: symbol, member: ServiceOfferMembership): Entry {
    this.#check(); if (token !== capability) throw new RPCProtocolError("service_binding_owner"); member.check(capability, this);
    const entry = this.#entries.get(member); if (entry === undefined) throw new RPCProtocolError("service_binding_owner"); return entry;
  }
  activate(token: symbol, member: ServiceOfferMembership, participant: ServiceOfferParticipant): void {
    const entry = this.#entry(token, member);
    if (entry.participant !== undefined && entry.participant !== participant) throw new RPCProtocolError("service_binding_owner");
    entry.participant = participant; entry.active = true; this.#wake?.();
  }
  /** A new accepting incarnation can wake blocked work in this same group.
   * An old in-flight query keeps its deadline and physical ownership until
   * finish; this notification cannot start another query beside its tail. */
  sourceAvailable(token: symbol, member: ServiceOfferMembership): void {
    const entry = this.#entry(token, member);
    entry.sourceChanged = true;
    if (!entry.inFlight) entry.blocked = false;
    this.#wake?.();
  }
  prepareUpdate(token: symbol, member: ServiceOfferMembership, offer: AdmissionOffer): () => void {
    const entry = this.#entry(token, member), generation = this.#generation, previous = entry.offer;
    const now = this.#clock!.sample().requireInterval(); this.#entry(token, member);
    if (generation !== this.#generation) throw new RPCProtocolError("renewal_plan_changed");
    this.#window(offer, entry.input.maximumWindowMS, now.upperMS, this.envelope().minimumRemainingMS);
    // While the original window is live, renewal cannot introduce an
    // admission gap. Recovery after an actual expiry cannot erase that gap.
    if (entry.offer.notAfterMS > now.upperMS && offer.notBeforeMS > entry.offer.notAfterMS) throw new RPCProtocolError("admission_window_closed");
    let used = false;
    return () => {
      this.#entry(token, member);
      if (used || generation !== this.#generation || entry.offer !== previous) throw new RPCProtocolError("renewal_plan_changed");
      used = true; entry.offer = offer; entry.retryAtMS = 0n; entry.failures = 0; entry.blocked = false; entry.deadlineCap = undefined; this.#wake?.();
    };
  }
  release(token: symbol, member: ServiceOfferMembership): void {
    if (token !== capability) throw new RPCProtocolError("service_binding_owner");
    if (this.#entries.delete(member) && this.#generation < maximum) this.#generation++; this.#wake?.();
  }
  /** One EDF batch, with stable rotation for equal expiry. Fill the selected
   * legal group up to eight; an unrelated namespace is not a reason to split. */
  schedule(upperMS: bigint): Readonly<{ batch: readonly ScheduledOffer[]; waitMS?: bigint }> {
    this.#check(); const advance = this.envelope().advanceMS;
    const eligible = [...this.#entries.values()].filter(entry => entry.active && entry.participant !== undefined && !entry.inFlight && !entry.blocked);
    const due = (entry: Entry): bigint => {
      if (entry.sourceChanged) return entry.retryAtMS;
      const time = entry.offer.notAfterMS > advance ? entry.offer.notAfterMS - advance : 0n;
      return time > entry.retryAtMS ? time : entry.retryAtMS;
    };
    const compare = (a: Entry, b: Entry): number => {
      if (a.offer.notAfterMS !== b.offer.notAfterMS) return a.offer.notAfterMS < b.offer.notAfterMS ? -1 : 1;
      if ((a.order > this.#cursor) !== (b.order > this.#cursor)) return a.order > this.#cursor ? -1 : 1;
      return a.order < b.order ? -1 : a.order > b.order ? 1 : 0;
    };
    const first = eligible.filter(entry => due(entry) <= upperMS).sort(compare)[0];
    if (first === undefined) {
      let next: bigint | undefined;
      for (const entry of eligible) { const at = due(entry); if (next === undefined || at < next) next = at; }
      return Object.freeze({ batch: Object.freeze([]), ...(next === undefined ? {} : { waitMS: next > upperMS ? next - upperMS : 1n }) });
    }
    // Repeat occurrences cannot share a wire target. Use the same bounded
    // legal partition as qualification, so timing never assumes an impossible
    // batch and still permits unrelated namespaces to share an original query.
    const legal = this.#groups([...this.#entries.values()].map(entry => entry.input)).find(group => group.includes(first.input))!;
    const batch = eligible.filter(entry => legal.includes(entry.input) && entry.retryAtMS <= upperMS).sort(compare).slice(0, 8);
    for (const entry of batch) { entry.inFlight = true; entry.sourceChanged = false; }
    this.#cursor = batch.at(-1)!.order;
    return Object.freeze({ batch: Object.freeze(batch.map(entry => Object.freeze({ membership: entry.membership, participant: entry.participant!,
      group: entry.input.group, authority: entry.input.authority }))) });
  }
  /** Retries inherit the first attempt's absolute cap. A changed plan or
   * repeated resource failure cannot restart a renewal's clock. */
  start(members: readonly ServiceOfferMembership[], deadline: TrustedDeadline): void {
    this.#check();
    for (const member of members) {
      const entry = this.#entries.get(member);
      if (entry === undefined || !entry.inFlight) throw new RPCProtocolError("service_binding_closed");
      if (entry.deadlineCap !== undefined && entry.deadlineCap < deadline.cap) deadline.tighten(entry.deadlineCap);
    }
    for (const member of members) this.#entries.get(member)!.deadlineCap = deadline.cap;
  }
  finish(members: readonly ServiceOfferMembership[], upperMS: bigint, reason?: string): void {
    if (this.#closed) return;
    for (const member of members) {
      const entry = this.#entries.get(member); if (entry === undefined) continue; entry.inFlight = false;
      if (reason === undefined) continue;
      entry.failures = Math.min(6, entry.failures + 1);
      entry.blocked = serviceOfferBlocked(reason) && !entry.sourceChanged;
      const delay = reason === "refresh_in_progress" || reason === "resource_exhausted" ? 1000n : BigInt(Math.min(30000, 1000 * 2 ** (entry.failures - 1)));
      entry.retryAtMS = upperMS > maximum - delay ? maximum : upperMS + delay;
    }
    this.#wake?.();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#wake = undefined;
    for (const member of this.#entries.keys()) member.close(); this.#clock = undefined; this.#reference?.release(); this.#reference = undefined;
  }
}
for (const type of [ServiceOfferPlan, ServiceOfferMembership]) { Object.freeze(type.prototype); Object.freeze(type); }
