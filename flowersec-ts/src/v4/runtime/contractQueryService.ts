import type { ContractQueryCodecs} from "./contractQueryCodecs.js";
import { type ContractQueryCodecLease } from "./contractQueryCodecs.js";
import type { ApplicationHeaderCodec, ApplicationHeader } from "./applicationHeader.js";
import { CBORWireError } from "./cbor.js";
import type { ContractQueryAccess } from "./contractQueryAccess.js";
import type { ContractQueryTargets} from "./contractQuery.js";
import { type ContractQueryCodec, contractQueryTargetsCharge } from "./contractQuery.js";
import type { ContractRoutes} from "./contractRoutes.js";
import { type ContractQuerySelection } from "./contractRoutes.js";
import { ContractSnapshotWriter, contractSnapshotWriterCapacityCharges, type ContractSnapshotChoice } from "./contractSnapshotWriter.js";
import type { TrustedDeadline } from "./deadline.js";
import type { RPCChannelRuntime } from "./rpcChannel.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCRequestInput } from "./rpcInput.js";
import type { RPCNetwork} from "./rpcNetwork.js";
import { type RPCNetworkTicket } from "./rpcNetwork.js";
import { rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { RPCReadyRequest } from "./rpcReceiver.js";
import { ResourceVector, type ResourceReference, type ResourceRoot, type ProtectedResourceReservation } from "./resources.js";
import { SchemaValidationError } from "./schema.js";
import { TimeError } from "./timeArithmetic.js";

const maximum = (1n << 64n) - 1n, capability = Symbol("original fixed query publication");
export type ContractQueryServiceStep = "progress" | "blocked" | "idle";
interface Pending {
  readonly ticket: RPCNetworkTicket;
  readonly input: RPCRequestInput;
  readonly deadline: TrustedDeadline;
  channel: RPCChannelRuntime | undefined;
}
interface Output {
  generation: bigint;
  phase: "free" | "resolve" | "writer" | "encode" | "publish" | "tail";
  ticket: RPCNetworkTicket | undefined;
  channel: RPCChannelRuntime | undefined;
  header: ApplicationHeader | undefined;
  deadline: TrustedDeadline | undefined;
  targets: ContractQueryTargets | undefined;
  references: ResourceReference[];
  selections: ContractQuerySelection[];
  choices: ContractSnapshotChoice[];
  epoch: bigint;
  writer: ContractSnapshotWriter | undefined;
  sourceHeld: boolean;
}
function output(): Output { return { generation: 0n, phase: "free", ticket: undefined, channel: undefined, header: undefined, deadline: undefined,
  targets: undefined, references: [], selections: [], choices: [], epoch: 0n, writer: undefined, sourceHeld: false }; }
export function contractQueryServiceCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const writer = contractSnapshotWriterCapacityCharges(8, runtimeBytes);
  return [new ResourceVector([8192n + runtimeBytes, 0n, 0n, 25n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    rpcPayloadCharge(2048, runtimeBytes), rpcPayloadCharge(2048, runtimeBytes),
    contractQueryTargetsCharge(runtimeBytes), ...writer, contractQueryTargetsCharge(runtimeBytes), ...writer];
}
function refusal(error: unknown): RPCSDKError {
  return error instanceof TimeError && (error.code === "time_expired" || error.code === "time_cancelled") ? "deadline_exceeded" : "service_unavailable";
}
class QueryPublication implements RPCPublicationGuard {
  constructor(readonly service: ContractQueryService, readonly index: number, readonly generation: bigint) { Object.freeze(this); }
  check(): void { this.service.checkPublication(capability, this.index, this.generation); }
  current(): boolean { return this.service.publicationCurrent(capability, this.index, this.generation); }
}

/** Two original complete response vectors plus two small pending requests,
 * shared by every ordinary channel in this Session. Pending input is network
 * responsibility only. Full source reads begin after a response vector can be
 * transferred exclusively. A ReplySlot ending cannot return a provider tail.
 * The root fixed SDK executor drives step(); this owner creates no worker and
 * calls no application handler, authorizer or external source I/O. */
export class ContractQueryService {
  #reference: ResourceReference | undefined;
  readonly #network: RPCNetwork;
  #routes: ContractRoutes | undefined;
  #access: ContractQueryAccess | undefined;
  readonly #deadline: TrustedDeadline;
  readonly #runtimeBytes: bigint;
  #codecLease: ContractQueryCodecLease | undefined;
  #targets: ContractQueryCodec | undefined;
  #headers: ApplicationHeaderCodec | undefined;
  readonly #pendingPositions: ProtectedResourceReservation[] = [];
  readonly #outputPositions: ProtectedResourceReservation[][] = [];
  readonly #pending: (Pending | undefined)[] = [undefined, undefined];
  readonly #outputs: Output[] = [output(), output()];
  #cursor = 0;
  #pendingCursor = 0;
  #closed = false;
  #draining = false;
  #working = false;
  #wake: (() => void) | undefined;
  #consumer: object | undefined;
  #unobserve: (() => void) | undefined;
  constructor(network: RPCNetwork, codecs: ContractQueryCodecs, routes: ContractRoutes, access: ContractQueryAccess, root: ResourceRoot,
    deadline: TrustedDeadline, runtimeBytes: bigint, references: readonly ResourceReference[]) {
    const costs = contractQueryServiceCharges(runtimeBytes);
    if (references.length !== costs.length || !references.every(ref => network.sameEnvironment(ref)) ||
        !routes.sameEnvironment(references[0]!) || !access.sameEnvironment(references[0]!)) throw new RPCProtocolError("rpc_query_owner");
    this.#network = network; this.#routes = routes; this.#access = access; this.#deadline = deadline; this.#runtimeBytes = runtimeBytes;
    this.#reference = references[0]!.take(costs[0]!);
    try {
      this.#codecLease = codecs.claim(network, 0, this.#reference);
      this.#targets = this.#codecLease.targets; this.#headers = this.#codecLease.headers;
      for (let index = 1; index < 3; index++) this.#pendingPositions.push(root.protect(references[index]!, costs[index]!));
      for (let slot = 0; slot < 2; slot++) {
        const positions: ProtectedResourceReservation[] = []; this.#outputPositions.push(positions);
        for (let item = 0; item < 3; item++) { const index = 3 + slot * 3 + item; positions.push(root.protect(references[index]!, costs[index]!)); }
      }
      this.#unobserve = access.observe(this.#reference, () => this.#notify());
      network.claimQueries(this); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("rpc_queries_closed"); this.#reference!.check(); }
  #enter(): void { this.#check(); if (this.#working) throw new RPCProtocolError("query_busy"); this.#working = true; }
  #leave(): void { this.#working = false; this.#collect(); }
  belongsTo(network: RPCNetwork): boolean { this.#check(); return this.#network === network; }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  /** Once-only wake for the original fixed SDK registration, never user code. */
  attachWake(wake: () => void, consumer: object): void {
    this.#check(); if (this.#consumer !== undefined) throw new RPCProtocolError("rpc_query_consumer"); this.#consumer = consumer; this.#wake = wake;
  }
  #notify(): void { this.#wake?.(); }
  openInput(ticket: RPCNetworkTicket, header: ApplicationHeader): RPCRequestInput {
    this.#enter();
    try {
      this.#collectPending();
      const state = this.#network.state(ticket);
      if (this.#draining) throw new RPCProtocolError("rpc_queries_draining");
      if (state.outgoing || !state.query || this.#network.request(ticket) !== header || header.kind !== "query_contracts_request" ||
          header.payloadBytes > 2048) throw new RPCProtocolError("query_request_binding");
      const index = this.#pending.findIndex((value, at) => value === undefined && this.#pendingPositions[at]!.available());
      if (index < 0) throw new RPCProtocolError("rpc_query_pending_exhausted");
      const deadline = this.#deadline.fork(header.uint(5)); this.#check();
      const reference = this.#pendingPositions[index]!.checkout();
      try {
        const input = new RPCRequestInput(header, { capture: true, fixedRequest: "query_contracts_request", deadline, runtimeBytes: this.#runtimeBytes }, reference);
        this.#pending[index] = { ticket, input, deadline, channel: undefined }; return input;
      } finally { reference.release(); }
    } finally { this.#leave(); }
  }
  /** The channel's sole dispatcher transfers only its exact completed input. */
  accept(channel: RPCChannelRuntime, ready: RPCReadyRequest): boolean {
    this.#enter();
    try {
      if (!this.#network.state(ready.ticket).query) return false;
      channel.checkIncoming(ready.ticket); this.#check();
      if (ready.refusal !== undefined) { channel.replySDK(ready.ticket, ready.refusal); this.#collectPending(); return true; }
      const pending = this.#pending.find(value => value?.ticket === ready.ticket);
      if (pending === undefined || pending.input !== ready.input || pending.input.state !== "complete" || pending.channel !== undefined) throw new RPCProtocolError("rpc_query_input_owner");
      pending.channel = channel; this.#notify(); return true;
    } finally { this.#leave(); }
  }
  #collectPending(): void {
    for (let i = 0; i < this.#pending.length; i++) {
      const pending = this.#pending[i]; if (pending !== undefined && pending.input.cleanupComplete()) this.#pending[i] = undefined;
    }
  }
  #refusePending(index: number, code: RPCSDKError): void {
    const pending = this.#pending[index]!;
    try { if (this.#network.live(pending.ticket)) pending.channel!.replySDK(pending.ticket, code); }
    catch { pending.channel?.close(); }
    finally { pending.input.close(); this.#pending[index] = undefined; }
  }
  #begin(index: number, available: number): void {
    const pending = this.#pending[index]!, slot = this.#outputs[available]!;
    let borrow: RPCPayloadBorrow | undefined;
    const references: ResourceReference[] = [];
    try {
      borrow = pending.input.borrow(); this.#check();
      for (const position of this.#outputPositions[available]!) references.push(position.checkout());
      const targets = this.#targets!.decode(borrow.bytes, references[0]!);
      slot.generation++; slot.phase = "resolve"; slot.targets = targets; slot.references = references.slice(1);
      slot.ticket = pending.ticket; slot.channel = pending.channel; slot.header = pending.input.header; slot.deadline = pending.deadline;
    } catch (error) {
      for (const reference of references) reference.release();
      if (error instanceof CBORWireError || error instanceof SchemaValidationError) pending.channel!.close();
      else if (!this.#closed) this.#refusePending(index, refusal(error));
      if (this.#closed) throw error;
    } finally { borrow?.release(); pending.input.close(); this.#pending[index] = undefined; }
  }
  #checkSlot(slot: Output): void {
    this.#check(); slot.deadline!.check(); this.#check();
    if (!this.#network.live(slot.ticket!)) throw new RPCProtocolError("rpc_query_terminal");
    if (this.#network.state(slot.ticket!).stopRequested) throw new RPCProtocolError("rpc_query_stopped");
  }
  #reject(slot: Output, code: RPCSDKError): void {
    try { if (this.#network.live(slot.ticket!)) slot.channel!.replySDK(slot.ticket!, code); }
    catch { slot.channel?.close(); }
    finally { this.#release(slot); }
  }
  #release(slot: Output): void {
    slot.writer?.close();
    if (slot.sourceHeld || slot.writer?.cleanupComplete() === false) return;
    slot.writer = undefined; slot.targets?.release(); slot.targets = undefined;
    for (const ref of slot.references) ref.release(); slot.references.length = 0;
    for (const selection of slot.selections) selection.close(); slot.selections.length = slot.choices.length = 0;
    slot.channel = undefined; slot.ticket = undefined; slot.header = undefined; slot.deadline = undefined; slot.epoch = 0n; slot.phase = "free";
  }
  #advance(index: number): void {
    const slot = this.#outputs[index]!;
    try {
      this.#checkSlot(slot);
      if (slot.phase === "resolve") {
        const target = slot.choices.length, access = this.#access!.read(slot.targets!.identity(target));
        this.#check();
        if (slot.epoch !== 0n && slot.epoch !== access.epoch) throw new RPCProtocolError("query_authorization_changed");
        slot.epoch = access.epoch;
        if (access.permission !== "allowed") slot.choices.push({ status: access.permission });
        else {
          const selected = this.#routes!.query(slot.targets!, target);
          if (this.#closed) { selected?.close(); this.#check(); }
          if (selected === undefined) slot.choices.push({ status: "unavailable" });
          else { slot.selections.push(selected); slot.choices.push(selected.choice); }
        }
        if (slot.choices.length === slot.targets!.count) slot.phase = "writer";
      } else if (slot.phase === "writer") {
        slot.writer = new ContractSnapshotWriter(slot.targets!, slot.choices, this.#runtimeBytes, slot.references); slot.references.length = 0; slot.phase = "encode";
      } else if (slot.phase === "encode") {
        if (slot.writer!.step()) slot.phase = "publish";
      } else if (slot.phase === "publish") {
        this.#access!.check(slot.epoch); this.#check();
        this.#routes!.checkQueryPublication(slot.selections); this.#check();
        if (!this.#access!.current(slot.epoch)) throw new RPCProtocolError("query_authorization_changed");
        const header = this.#headers!.response(slot.header!, "query_contracts_response", slot.writer!.encodedBytes), borrow = slot.writer!.borrow();
        const generation = slot.generation; slot.sourceHeld = true;
        const source: RPCPayloadBorrow = Object.freeze({ bytes: borrow.bytes, release: () => {
          if (!slot.sourceHeld || slot.generation !== generation) return;
          borrow.release(); slot.sourceHeld = false; this.#release(slot); this.#notify(); this.#collect();
        } });
        const channel = slot.channel!;
        try {
          channel.queueResponse(slot.ticket!, header, source, new QueryPublication(this, index, generation)); slot.phase = "tail"; slot.writer!.close();
        } catch (error) { source.release(); channel.close(); throw error; }
      }
    } catch (error) {
      if (slot.phase === "free") return;
      if (!this.#closed) {
        const stopped = this.#network.live(slot.ticket!) && this.#network.state(slot.ticket!).stopRequested;
        this.#reject(slot, stopped ? "response_output_stopped" : refusal(error));
      } else this.#release(slot);
    }
  }
  /** One bounded work opportunity; blocked callers wait for the original wake
   * or deadline timer instead of repeatedly re-enqueuing an empty step. */
  step(): ContractQueryServiceStep {
    this.#enter();
    try {
      if (this.#consumer !== undefined) throw new RPCProtocolError("rpc_query_consumer");
      this.#collectPending();
      let blocked = false;
      for (let offset = 0; offset < 2; offset++) {
        const index = (this.#cursor + offset) % 2, result = this.#stepPosition(index);
        if (result === "progress") { this.#cursor = (index + 1) % 2; return result; }
        blocked ||= result === "blocked";
      }
      return blocked ? "blocked" : "idle";
    } finally { this.#leave(); }
  }
  stepPosition(index: number, consumer?: object): ContractQueryServiceStep {
    this.#enter();
    try {
      if (this.#consumer !== consumer || index !== 0 && index !== 1) throw new RPCProtocolError("rpc_query_owner");
      this.#collectPending(); return this.#stepPosition(index);
    } finally { this.#leave(); }
  }
  #stepPosition(index: number): ContractQueryServiceStep {
    const slot = this.#outputs[index]!;
    if (slot.phase !== "free" && slot.phase !== "tail") { this.#advance(index); return "progress"; }
    for (let offset = 0; offset < 2; offset++) {
      const at = (this.#pendingCursor + offset) % 2, pending = this.#pending[at];
      if (pending?.channel === undefined) continue;
      try { pending.deadline.check(); this.#access!.checkActive(); this.#check(); }
      catch (error) { if (this.#closed) throw error; this.#refusePending(at, refusal(error)); this.#pendingCursor = (at + 1) % 2; return "progress"; }
      if (slot.phase !== "free" || slot.generation === maximum || !this.#outputPositions[index]!.every(position => position.available())) return "blocked";
      this.#begin(at, index); this.#pendingCursor = (at + 1) % 2; return "progress";
    }
    return "idle";
  }
  checkPublication(token: symbol, index: number, generation: bigint): void {
    if (token !== capability || !this.publicationCurrent(token, index, generation)) throw new RPCProtocolError("rpc_query_publication");
    const slot = this.#outputs[index]!;
    slot.deadline!.check(); this.#check(); this.#access!.check(slot.epoch); this.#check();
    this.#routes!.checkQueryPublication(slot.selections);
    if (!this.publicationCurrent(token, index, generation)) throw new RPCProtocolError("rpc_query_publication");
  }
  publicationCurrent(token: symbol, index: number, generation: bigint): boolean {
    const slot = this.#outputs[index];
    return token === capability && !this.#closed && slot !== undefined && slot.generation === generation && slot.phase === "tail" && slot.sourceHeld &&
      this.#access!.current(slot.epoch) && slot.selections.every(selection => selection.current());
  }
  nextDeadlineMS(): bigint | undefined {
    this.#enter();
    try {
      let earliest: bigint | undefined;
      for (const pending of this.#pending) if (pending?.channel !== undefined) {
        const remaining = pending.deadline.remainingMS(); earliest = earliest === undefined || remaining < earliest ? remaining : earliest;
      }
      return earliest;
    } finally { this.#leave(); }
  }
  drain(): void { this.#check(); this.#draining = true; this.#notify(); }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const position of this.#pendingPositions) position.closeAfterUse();
    for (const positions of this.#outputPositions) for (const position of positions) position.closeAfterUse();
    if (!this.#working) this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#working) return;
    for (const pending of this.#pending) pending?.input.close(); this.#collectPending();
    for (const slot of this.#outputs) if (slot.phase !== "free") this.#release(slot);
    // Closed publication guards have no future lookup authority. Physical
    // output keeps only its original writer/body pins, not the route/auth graph.
    for (const slot of this.#outputs) { for (const selection of slot.selections) selection.close(); slot.selections.length = 0; }
    this.#unobserve?.(); this.#unobserve = undefined;
    this.#routes = undefined; this.#access = undefined; this.#consumer = undefined;
    if (this.#pending.some(pending => pending !== undefined) || this.#outputs.some(slot => slot.phase !== "free") ||
        this.#pendingPositions.some(position => !position.cleanupComplete()) || this.#outputPositions.some(positions => positions.some(position => !position.cleanupComplete()))) return;
    this.#codecLease?.release(); this.#codecLease = undefined; this.#targets = undefined; this.#headers = undefined;
    this.#routes = undefined; this.#access = undefined; this.#reference?.release(); this.#reference = undefined;
    const wake = this.#wake; this.#wake = undefined; wake?.();
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
Object.freeze(ContractQueryService.prototype); Object.freeze(ContractQueryService);
