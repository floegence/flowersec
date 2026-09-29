import type { ContractQueryCodecs} from "./contractQueryCodecs.js";
import { type ContractQueryCodecLease } from "./contractQueryCodecs.js";
import type { ApplicationHeaderCodec } from "./applicationHeader.js";
import type { ContractQueryTargets} from "./contractQuery.js";
import { type ContractQueryCodec, contractQueryTargetsCharge, type ContractQueryTarget } from "./contractQuery.js";
import { ContractQueryExchange, contractQueryExchangeCapacityCharges } from "./contractQueryExchange.js";
import { ContractSnapshotReader, contractSnapshotReaderCharges, type ContractSnapshotBatch } from "./contractSnapshotReader.js";
import type { RPCChannelRuntime } from "./rpcChannel.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { RPCCompletion } from "./rpcCompletion.js";
import type { RPCNetwork } from "./rpcNetwork.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import type { TrustedDeadline } from "./deadline.js";
import { ResourceVector, type ResourceRoot, type ResourceReference, type ProtectedResourceReservation } from "./resources.js";
import { QueryRenewalPosition, type QueryRenewalReservation, type QueryPreparationReservation } from "./queryRenewalPosition.js";

const capability = Symbol("original outgoing fixed query"), maximum = (1n << 64n) - 1n;
interface CallState { readonly client: ContractQueryClient; readonly index: number; readonly generation: bigint }
const calls = new WeakMap<ContractQueryCall, CallState>();
interface Slot {
  generation: bigint;
  call: ContractQueryCall | undefined;
  targets: ContractQueryTargets | undefined;
  exchange: ContractQueryExchange | undefined;
  deadline: TrustedDeadline | undefined;
  wake: (() => void) | undefined;
  closed: boolean;
  decoded: boolean;
}
function slot(): Slot { return { generation: 0n, call: undefined, targets: undefined, exchange: undefined, deadline: undefined, wake: undefined, closed: false, decoded: false }; }
export function contractQueryClientCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const vector = [contractQueryTargetsCharge(runtimeBytes), ...contractQueryExchangeCapacityCharges(8, runtimeBytes)];
  return [new ResourceVector([6144n + runtimeBytes, 0n, 0n, 83n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    ...contractSnapshotReaderCharges(runtimeBytes), ...vector, ...vector];
}

/** Generation-bound control for one original outgoing Q. Its Environment
 * acquisition owner supplies the full delivery vector and fixed SDK position.
 * Closing never cancels another waiter or returns a physical tail early. */
export class ContractQueryCall {
  constructor(token: symbol, state: CallState) {
    if (token !== capability) throw new RPCProtocolError("rpc_query_owner"); calls.set(this, state); Object.freeze(this);
  }
  #state(): CallState { const state = calls.get(this); if (state === undefined) throw new RPCProtocolError("query_closed"); return state; }
  observe(wake: () => void): void { this.#state().client.observe(this, wake); }
  get count(): number { return this.#state().client.targetCount(this); }
  progress(): ReturnType<RPCCompletion["progress"]> { return this.#state().client.progress(this); }
  beginDecode(windows: readonly bigint[], references: readonly ResourceReference[]): boolean { return this.#state().client.beginDecode(this, windows, references); }
  stepDecode(): boolean { return this.#state().client.stepDecode(this); }
  take(): ContractSnapshotBatch { return this.#state().client.take(this); }
  check(): void { this.#state().client.checkCall(this); }
  remainingMS(): bigint { return this.#state().client.remainingMS(this); }
  failResponse(): void { this.#state().client.failResponse(this); }
  close(): void { calls.get(this)?.client.closeCall(this); }
  cleanupComplete(): boolean { const state = calls.get(this); return state === undefined || state.client.callCleaned(this); }
  toJSON(): object { return {}; }
}

/** One Session's outgoing Q2 vectors and one incremental response scratch set.
 * All actual positions are protected before ordinary channel activation. There
 * is no new root reservation on submit, receipt, cancellation or decoding.
 * The original network Q2 and these physical positions are distinct gates. */
export class ContractQueryClient implements RPCPublicationGuard {
  #reference: ResourceReference | undefined;
  #network: RPCNetwork | undefined;
  readonly #runtimeBytes: bigint;
  #deadline: TrustedDeadline | undefined;
  #delivery: ReceiveDeliveryGate | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #codecLease: ContractQueryCodecLease | undefined;
  #codec: ContractQueryCodec | undefined;
  #headers: ApplicationHeaderCodec | undefined;
  #reader: ContractSnapshotReader | undefined;
  #root: ResourceRoot | undefined;
  readonly #positionReferences: ResourceReference[][] = [];
  readonly #positions: ProtectedResourceReservation[][] = [];
  readonly #slots: Slot[] = [slot(), slot()];
  readonly #renewal = new QueryRenewalPosition(2, index => this.#slots[index]!.call === undefined && this.#slots[index]!.generation < maximum &&
    (this.#positions[index] !== undefined ? this.#positions[index]!.every(position => position.available()) : this.#positionReferences[index]?.length === 4));
  #decoding: ContractQueryCall | undefined;
  #observer: (() => void) | undefined;
  #working = false;
  #collecting = false;
  #closed = false;
  #draining = false;
  constructor(root: ResourceRoot, runtimeBytes: bigint, references: readonly ResourceReference[]) {
    const costs = contractQueryClientCharges(runtimeBytes);
    if (references.length !== costs.length || !references.every(ref => references[0]!.sameEnvironment(ref))) throw new RPCProtocolError("rpc_query_owner");
    this.#runtimeBytes = runtimeBytes; this.#root = root;
    this.#reference = references[0]!.take(costs[0]!);
    try {
      this.#reader = new ContractSnapshotReader(runtimeBytes, references.slice(1, 5));
      for (let index = 0; index < 2; index++) {
        const positions: ResourceReference[] = []; this.#positionReferences.push(positions);
        for (let item = 0; item < 4; item++) { const at = 5 + index * 4 + item; positions.push(references[at]!.take(costs[at]!)); }
      }
      this.#observer = root.observeAvailability(this.#reference, () => this.#collect()); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  bind(network: RPCNetwork, codecs: ContractQueryCodecs, delivery: ReceiveDeliveryGate, deadline: TrustedDeadline): void {
    this.#check();
    if (this.#network !== undefined || !network.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_query_owner");
    try {
      const costs = contractQueryClientCharges(this.#runtimeBytes);
      for (const [index, references] of this.#positionReferences.entries()) {
        const positions: ProtectedResourceReservation[] = []; this.#positions.push(positions);
        for (const [item, reference] of references.entries()) positions.push(this.#root!.protect(reference, costs[5 + index * 4 + item]!));
      }
      this.#positionReferences.length = 0;
      this.#network = network; this.#deadline = deadline; this.#delivery = delivery;
      this.#codecLease = codecs.claim(network, 1, this.#reference!);
      this.#codec = this.#codecLease.targets; this.#headers = this.#codecLease.headers;
      this.#lease = delivery.retain(this.#reference!, () => this.close());
      network.claimQueryClient(this);
    } catch (error) { this.close(); throw error; }
  }
  protectPreparation(reference: ResourceReference): QueryPreparationReservation {
    this.#check();
    if (this.#working || this.#draining || !this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("rpc_query_owner");
    return this.#renewal.protectPreparation(reference);
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("query_client_closed"); this.#reference!.check(); }
  #enter(): void { this.#check(); if (this.#network === undefined) throw new RPCProtocolError("query_source_unavailable"); if (this.#working) throw new RPCProtocolError("query_busy"); this.#working = true; }
  #leave(): void { this.#working = false; this.#collect(); }
  #slot(call: ContractQueryCall, retained = false): Slot {
    const state = calls.get(call), slot = state?.client === this ? this.#slots[state.index] : undefined;
    if (slot === undefined || slot.call !== call || slot.generation !== state!.generation) throw new RPCProtocolError("rpc_query_owner");
    if (!retained) { this.#check(); if (slot.closed) throw new RPCProtocolError("query_closed"); }
    return slot;
  }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  retainDelivery(reference: ResourceReference, revoked: () => void): ReturnType<ReceiveDeliveryGate["retain"]> {
    this.#check(); return this.#delivery!.retain(reference, revoked);
  }
  /** The original source gate is checked again by the publisher at each
   * fragment admission and by the response owner before decoding/delivery. */
  check(): void {
    this.#check(); const working = this.#working; this.#working = true;
    try { this.#lease!.check(); this.#check(); }
    finally { this.#working = working; this.#collect(); }
  }
  current(): boolean { return !this.#closed && this.#reference !== undefined; }
  acquisitionDeadline(original: TrustedDeadline): TrustedDeadline {
    this.#check();
    const child = this.#deadline!.fork(original.cap); child.tightenFrom(original); this.#check(); return child;
  }
  protectRenewal(reference: ResourceReference): QueryRenewalReservation | undefined {
    this.#check();
    if (this.#draining || !this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("query_source_unavailable");
    if (this.#working) return; return this.#renewal.protect(reference);
  }
  begin(channel: RPCChannelRuntime, targets: readonly ContractQueryTarget[], original: TrustedDeadline, expectedCount: number,
    renewal?: QueryRenewalReservation, preparation?: QueryPreparationReservation): ContractQueryCall {
    this.#enter();
    const references: ResourceReference[] = [];
    let selected: Slot | undefined;
    try {
      if (this.#draining || !channel.belongsTo(this.#network!)) throw new RPCProtocolError("query_source_unavailable");
      this.#lease!.check(); this.#check();
      if (renewal !== undefined && preparation !== undefined) throw new RPCProtocolError("rpc_query_owner");
      const index = preparation === undefined ? this.#renewal.select(renewal, targets) : this.#renewal.selectPreparation(preparation);
      if (index < 0) throw new RPCProtocolError("resource_exhausted");
      const deadline = this.acquisitionDeadline(original); this.#check();
      if (renewal !== undefined) this.#renewal.check(renewal);
      if (preparation !== undefined && this.#renewal.checkPreparation(preparation) !== index) throw new RPCProtocolError("rpc_query_owner");
      for (const position of this.#positions[index]!) references.push(position.checkout());
      const request = this.#codec!.prepare(targets, references[0]!);
      if (request.count !== expectedCount) { request.release(); throw new RPCProtocolError("query_target_count"); }
      selected = this.#slots[index]!; selected.generation++; selected.targets = request; selected.deadline = deadline;
      selected.call = new ContractQueryCall(capability, { client: this, index, generation: selected.generation });
      const header = this.#network!.queryHeader(this, this.#headers!, request.encodedBytes, deadline.cap);
      selected.exchange = new ContractQueryExchange(request, header, deadline, this.#runtimeBytes, references.slice(1), this);
      const position = selected;
      selected.exchange.observe(() => position.wake?.());
      this.#check(); if (renewal !== undefined) this.#renewal.check(renewal);
      if (preparation !== undefined && this.#renewal.checkPreparation(preparation) !== index) throw new RPCProtocolError("rpc_query_owner");
      selected.exchange.submit(channel); return selected.call;
    } catch (error) { if (selected !== undefined) { selected.closed = true; selected.exchange?.close(); } throw error; }
    finally { for (const reference of references) reference.release(); this.#leave(); }
  }
  observe(call: ContractQueryCall, wake: () => void): void {
    const slot = this.#slot(call); if (slot.wake !== undefined) throw new RPCProtocolError("rpc_query_consumer");
    slot.wake = wake; if (slot.exchange!.progress().done) wake();
  }
  targetCount(call: ContractQueryCall): number { return this.#slot(call).targets!.count; }
  progress(call: ContractQueryCall): ReturnType<RPCCompletion["progress"]> { return this.#slot(call).exchange!.progress(); }
  checkCall(call: ContractQueryCall): void {
    this.#enter();
    try { const slot = this.#slot(call); this.#lease!.check(); slot.exchange!.checkDelivery(); this.#slot(call); }
    finally { this.#leave(); }
  }
  remainingMS(call: ContractQueryCall): bigint {
    this.#enter(); try { const value = this.#slot(call).deadline!.remainingMS(); this.#slot(call); return value; }
    finally { this.#leave(); }
  }
  beginDecode(call: ContractQueryCall, windows: readonly bigint[], references: readonly ResourceReference[]): boolean {
    this.#enter();
    try {
      const slot = this.#slot(call);
      if (slot.decoded || this.#decoding === call) throw new RPCProtocolError("query_already_decoded");
      if (this.#decoding !== undefined) return false;
      this.#lease!.check(); this.#slot(call);
      this.#reader!.beginResponse(slot.exchange!, windows, references); this.#decoding = call; return true;
    } finally { this.#leave(); }
  }
  stepDecode(call: ContractQueryCall): boolean {
    this.#enter();
    try {
      this.#slot(call); if (this.#decoding !== call) throw new RPCProtocolError("rpc_query_consumer");
      this.#lease!.check(); this.#slot(call); return this.#reader!.step();
    } finally { this.#leave(); }
  }
  take(call: ContractQueryCall): ContractSnapshotBatch {
    this.#enter();
    try {
      const slot = this.#slot(call); if (this.#decoding !== call || slot.decoded) throw new RPCProtocolError("query_result_unavailable");
      this.#lease!.check(); this.#slot(call);
      const result = this.#reader!.take(); slot.decoded = true; this.#decoding = undefined;
      for (const other of this.#slots) if (other.call !== call) other.wake?.(); return result;
    } finally { this.#leave(); }
  }
  failResponse(call: ContractQueryCall): void { const slot = this.#slot(call, true); slot.closed = true; slot.exchange?.failResponse(); this.#collect(); }
  closeCall(call: ContractQueryCall): void {
    const slot = this.#slot(call, true); if (slot.closed) return;
    slot.closed = true; slot.exchange?.close(); this.#collect();
  }
  callCleaned(call: ContractQueryCall): boolean { this.#collect(); return calls.get(call)?.client !== this; }
  #collect(): void {
    if (this.#working || this.#collecting) return;
    this.#collecting = true;
    try {
      for (const slot of this.#slots) {
        if (!slot.closed && !this.#closed || slot.call === undefined) continue;
        if (this.#decoding === slot.call) {
          this.#reader?.cancel(); this.#decoding = undefined;
          for (const other of this.#slots) if (other !== slot) other.wake?.();
        }
        slot.exchange?.close(); if (slot.exchange?.cleanupComplete() === false) continue;
        slot.targets?.release(); calls.delete(slot.call);
        const wake = slot.wake, generation = slot.generation;
        Object.assign(slot, { generation, call: undefined, targets: undefined, exchange: undefined, deadline: undefined, wake: undefined, closed: false, decoded: false });
        wake?.();
      }
      this.#renewal.collect();
      if (!this.#closed || this.#positionReferences.length !== 0 || this.#slots.some(slot => slot.call !== undefined) || this.#positions.some(positions => positions.some(position => !position.cleanupComplete()))) return;
      this.#reader?.close(); this.#reader = undefined; this.#codecLease?.release(); this.#codecLease = undefined; this.#codec = undefined; this.#headers = undefined;
      this.#observer?.(); this.#observer = undefined; this.#lease?.release(); this.#lease = undefined; this.#delivery = undefined;
      this.#reference?.release(); this.#reference = undefined; this.#network = undefined; this.#deadline = undefined; this.#root = undefined;
    } finally { this.#collecting = false; }
  }
  drain(): void { this.#check(); this.#draining = true; }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#renewal.close();
    for (const references of this.#positionReferences) for (const reference of references) reference.release(); this.#positionReferences.length = 0;
    for (const slot of this.#slots) { slot.closed = true; slot.exchange?.close(); slot.wake?.(); }
    for (const positions of this.#positions) for (const position of positions) position.closeAfterUse();
    this.#collect();
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
for (const constructor of [ContractQueryClient, ContractQueryCall]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
