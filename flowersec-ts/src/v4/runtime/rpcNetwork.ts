import type { ApplicationHeader} from "./applicationHeader.js";
import { type ApplicationHeaderCodec } from "./applicationHeader.js";
import type { ApplicationWorkClass } from "./applicationExecutor.js";
import type { RPCCallCapacity} from "./rpcCallCapacity.js";
import { type RPCCallReservation } from "./rpcCallCapacity.js";
import { byteLength } from "./cbor.js";
import { ResourceError, ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError, type RPCFragmentPart } from "./rpcFragment.js";
import type { RPCOutputInterest } from "./rpcOutputInterest.js";
import type { V4OutputInterestReason } from "../serviceHandlers.js";

export interface RPCNetworkConfig {
  readonly profile: "services" | "execution";
  readonly maxGeneral: number;
  readonly query: Readonly<{ typeID: number; contractDigest: Uint8Array }>;
  readonly resultRead?: Readonly<{ typeID: number; contractDigest: Uint8Array }>;
  readonly runtimeBytes: bigint;
}
const token = Symbol("original RPC association"), maximum = (1n << 64n) - 1n;
interface ChannelState { network: RPCNetwork | undefined; readonly index: number; readonly generation: bigint }
interface TicketState { network: RPCNetwork | undefined; readonly side: 0 | 1; readonly index: number; readonly generation: bigint }
const channels = new WeakMap<RPCChannel, ChannelState>(), tickets = new WeakMap<RPCNetworkTicket, TicketState>();
export class RPCChannel {
  constructor(capability: symbol, state: ChannelState) { if (capability !== token) throw new RPCProtocolError("rpc_owner"); channels.set(this, state); Object.freeze(this); }
  toJSON(): object { return {}; }
}
export class RPCNetworkTicket {
  constructor(capability: symbol, state: TicketState) { if (capability !== token) throw new RPCProtocolError("rpc_owner"); tickets.set(this, state); Object.freeze(this); }
  toJSON(): object { return {}; }
}
interface ChannelSlot {
  generation: bigint; owner: RPCChannel | undefined; closed: boolean;
  sent: bigint; received: bigint; liveTickets: number; reader: object | undefined; publisher: object | undefined;
}
interface MessageSlot {
  generation: bigint; owner: RPCNetworkTicket | undefined; channel: RPCChannel | undefined;
  request: ApplicationHeader | undefined; response: ApplicationHeader | undefined;
  call: RPCCallReservation | undefined;
  output: RPCOutputInterest | undefined;
  stream: object | undefined; streamClosed: boolean; streamBorrows: number;
  query: boolean; requestSerial: bigint; responseSerial: bigint;
  requestOffset: number; responseOffset: number;
  requestDone: boolean; responseDone: boolean; requestAborted: boolean; responseAborted: boolean; inputValidated: boolean; inputClaimed: boolean;
  late: boolean; stopRequested: boolean; stopSent: boolean;
}
export interface RPCReceivedPart {
  readonly ticket: RPCNetworkTicket;
  readonly kind: "begin" | "data" | "abort" | "stop_output";
  readonly response: boolean;
  readonly complete: boolean;
  readonly header?: ApplicationHeader;
  readonly payload?: Uint8Array;
}
function config(c: RPCNetworkConfig): RPCNetworkConfig {
  const profile = c.profile, maxGeneral = c.maxGeneral, runtimeBytes = c.runtimeBytes, query = c.query;
  const typeID = query.typeID, contractDigest = query.contractDigest;
  if (profile !== "services" && profile !== "execution" || !Number.isSafeInteger(maxGeneral) || maxGeneral < 1 || maxGeneral > 1024 ||
      !Number.isSafeInteger(typeID) || typeID < 1 || typeID > 0xffffffff || byteLength(contractDigest) !== 32 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const read = c.resultRead;
  if (read !== undefined && (profile !== "execution" || !Number.isSafeInteger(read.typeID) || read.typeID < 1 || read.typeID > 0xffffffff ||
      byteLength(read.contractDigest) !== 32)) throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ profile, maxGeneral, runtimeBytes, query: Object.freeze({ typeID, contractDigest: new Uint8Array(contractDigest) }),
    ...(read === undefined ? {} : { resultRead: Object.freeze({ typeID: read.typeID, contractDigest: new Uint8Array(read.contractDigest) }) }) });
}
export function rpcNetworkCharge(input: RPCNetworkConfig): ResourceVector {
  const c = config(input), count = BigInt(2 * (c.maxGeneral + 2));
  // One Session-wide incoming ReplySlot and outgoing completion descriptor
  // table. Payloads, channel readers, credit and provider tails pay separately.
  return new ResourceVector([count * (1024n + c.runtimeBytes) + 4096n + 64n * c.runtimeBytes, 0n, 0n, count + 72n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
function newSlot(): MessageSlot {
  return { generation: 0n, owner: undefined, channel: undefined, request: undefined, response: undefined, call: undefined, output: undefined, stream: undefined, streamClosed: false, streamBorrows: 0, query: false,
    requestSerial: 0n, responseSerial: 0n, requestOffset: 0, responseOffset: 0, requestDone: false, responseDone: false,
    requestAborted: false, responseAborted: false, inputValidated: false, inputClaimed: false, late: false, stopRequested: false, stopSent: false };
}
/** Shared by all ordinary channels of one original Session. Tickets account
 * for exact associations, not payload admission, authorization or dispatch.
 * Scalar mutations never invoke application/provider callbacks. The explicit
 * flushOutputEvents handoff runs only after the caller leaves that gate. */
export class RPCNetwork {
  readonly #config: RPCNetworkConfig;
  readonly #calls: RPCCallCapacity;
  #reference: ResourceReference | undefined;
  readonly #channels: ChannelSlot[];
  readonly #slots: readonly [MessageSlot[], MessageSlot[]];
  readonly #counts = [[0, 0], [0, 0]];
  #closed = false;
  #publications = 0;
  readonly #outputSignals = new Set<RPCOutputInterest>();
  #inputs: object | undefined;
  #queries: object | undefined;
  #queryClient: object | undefined;
  #queryCodecs: object | undefined;
  #queryAssembly: object | undefined;
  #queriesReady = false;
  readonly #digest = new Uint8Array(32);
  constructor(input: RPCNetworkConfig, reference: ResourceReference, calls: RPCCallCapacity) {
    const c = this.#config = config(input);
    if (calls.limit !== c.maxGeneral || !calls.sameEnvironment(reference)) throw new RPCProtocolError("rpc_call_owner");
    this.#calls = calls;
    this.#reference = reference.take(rpcNetworkCharge(c));
    try {
    this.#channels = Array.from({ length: 8 }, () => ({ generation: 0n, owner: undefined, closed: false, sent: 0n, received: 0n, liveTickets: 0, reader: undefined, publisher: undefined }));
    this.#slots = [Array.from({ length: c.maxGeneral + 2 }, newSlot), Array.from({ length: c.maxGeneral + 2 }, newSlot)];
    } catch (error) { this.#reference.release(); this.#reference = undefined; throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("rpc_closed"); this.#reference!.check(); }
  #channel(owner: RPCChannel, retained = false): ChannelSlot {
    const state = channels.get(owner), slot = state?.network === this ? this.#channels[state.index] : undefined;
    if (slot === undefined || slot.owner !== owner || slot.generation !== state!.generation) throw new RPCProtocolError("rpc_channel_owner");
    if (!retained) { this.#check(); if (slot.closed) throw new RPCProtocolError("rpc_channel_closed"); }
    return slot;
  }
  #ticket(owner: RPCNetworkTicket, retained = false): [MessageSlot, TicketState] {
    const state = tickets.get(owner), slot = state?.network === this ? this.#slots[state.side][state.index] : undefined;
    if (slot === undefined || slot.owner !== owner || slot.generation !== state!.generation) throw new RPCProtocolError("rpc_ticket_owner");
    if (slot.stream === undefined) this.#channel(slot.channel!, retained);
    else if (!retained) { this.#check(); if (slot.streamClosed) throw new RPCProtocolError("rpc_stream_closed"); }
    return [slot, state!];
  }
  openChannel(): RPCChannel {
    this.#check(); const index = this.#channels.findIndex(slot => slot.owner === undefined && slot.generation < maximum);
    if (index < 0) throw new ResourceError("resource_exhausted");
    const slot = this.#channels[index]!, generation = slot.generation + 1n;
    const owner = new RPCChannel(token, { network: this, index, generation });
    slot.owner = owner; slot.generation = generation; slot.closed = false; slot.sent = slot.received = 0n; return owner;
  }
  claimReader(channel: RPCChannel, owner: object): void {
    const slot = this.#channel(channel); if (slot.reader !== undefined) throw new RPCProtocolError("rpc_reader_owner"); slot.reader = owner;
  }
  claimPublisher(channel: RPCChannel, owner: object): void {
    const slot = this.#channel(channel); if (slot.publisher !== undefined) throw new RPCProtocolError("rpc_publisher_owner"); slot.publisher = owner;
  }
  #query(header: ApplicationHeader, outgoing: boolean): boolean {
    if (header.kind !== "query_contracts_request") return false;
    header.copyBytes(6, this.#digest);
    let difference = header.typeID === this.#config.query.typeID ? 0 : 1;
    for (let i = 0; i < 32; i++) difference |= this.#digest[i]! ^ this.#config.query.contractDigest[i]!;
    this.#digest.fill(0);
    if (difference !== 0 && outgoing) throw new RPCProtocolError("rpc_query_binding"); return difference === 0;
  }
  #request(header: ApplicationHeader, outgoing: boolean): boolean {
    if (!["execution_unary_request", "transient_unary_request", "query_contracts_request", "read_result_request"].includes(header.kind) ||
        outgoing && this.#config.profile !== "execution" && (header.kind === "execution_unary_request" || header.kind === "read_result_request")) throw new RPCProtocolError("rpc_request_variant");
    if (outgoing && header.kind === "read_result_request" && !this.resultReadMatches(header)) throw new RPCProtocolError("rpc_result_read_binding");
    return this.#query(header, outgoing);
  }
  resultReadMatches(header: ApplicationHeader): boolean {
    const read = this.#config.resultRead;
    if (read === undefined || header.kind !== "read_result_request" || header.typeID !== read.typeID) return false;
    header.copyBytes(6, this.#digest);
    let difference = 0; for (let i = 0; i < 32; i++) difference |= this.#digest[i]! ^ read.contractDigest[i]!;
    this.#digest.fill(0); return difference === 0;
  }
  resultReadHeader(codec: ApplicationHeaderCodec, payloadBytes: number, deadlineAtMS: bigint): ApplicationHeader {
    this.#check(); const read = this.#config.resultRead;
    if (read === undefined || payloadBytes < 1 || payloadBytes > 1024) throw new RPCProtocolError("rpc_result_read_binding");
    return codec.create({ kind: "read_result_request", typeID: read.typeID, contractDigest: read.contractDigest, payloadBytes, deadlineAtMS });
  }
  #reserve(side: 0 | 1, channel: RPCChannel, header: ApplicationHeader): RPCNetworkTicket {
    this.#channel(channel); const query = this.#request(header, side === 0), category = query ? 1 : 0;
    if (this.#counts[side]![category]! >= (query ? 2 : this.#config.maxGeneral)) throw new ResourceError("resource_exhausted");
    const index = this.#slots[side].findIndex(slot => slot.owner === undefined && slot.generation < maximum);
    if (index < 0) throw new ResourceError("resource_exhausted");
    const slot = this.#slots[side][index]!, generation = slot.generation + 1n;
    const owner = new RPCNetworkTicket(token, { network: this, side, index, generation });
    Object.assign(slot, newSlot(), { generation, owner, channel, request: header, query });
    this.#counts[side]![category] = this.#counts[side]![category]! + 1; this.#channel(channel).liveTickets++; return owner;
  }
  /** The original local preparation owns K capacity before any application
   * encoder runs. Query Q2 never borrows a general or short opportunity. */
  reserveCall(workClass: ApplicationWorkClass): RPCCallReservation { this.#check(); return this.#calls.reserve(workClass); }
  /** Scalar preflight only: no serial, association or publication is created. */
  checkOutgoing(channel: RPCChannel, request: ApplicationHeader, call?: RPCCallReservation): void {
    this.#check(); const state = this.#channel(channel), query = this.#request(request, true);
    if (query !== (call === undefined)) throw new RPCProtocolError("rpc_call_owner");
    if (call !== undefined) this.#calls.checkUnsubmitted(call);
    if (state.sent === maximum || this.#counts[0]![query ? 1 : 0]! >= (query ? 2 : this.#config.maxGeneral) ||
        !this.#slots[0].some(slot => slot.owner === undefined && slot.generation < maximum)) throw new ResourceError("resource_exhausted");
  }
  reserveOutgoing(channel: RPCChannel, request: ApplicationHeader, call?: RPCCallReservation): RPCNetworkTicket {
    this.checkOutgoing(channel, request, call);
    const ticket = this.#reserve(0, channel, request);
    if (call !== undefined) { this.#calls.attach(call, ticket); this.#ticket(ticket)[0].call = call; }
    return ticket;
  }
  /** Dedicated streams occupy the same original general descriptors as unary
   * calls. Incoming ownership precedes OPEN acceptance and header parsing. */
  reserveIncomingStream(stream: object): RPCNetworkTicket {
    return this.#reserveStream(1, stream);
  }
  checkOutgoingStream(request: ApplicationHeader, call: RPCCallReservation): void {
    this.#check(); this.#streamRequest(request, true); this.#calls.checkUnsubmitted(call);
    if (this.#counts[0]![0]! >= this.#config.maxGeneral ||
        !this.#slots[0].some(slot => slot.owner === undefined && slot.generation < maximum)) throw new ResourceError("resource_exhausted");
  }
  reserveOutgoingStream(stream: object, request: ApplicationHeader, call: RPCCallReservation): RPCNetworkTicket {
    this.checkOutgoingStream(request, call);
    const ticket = this.#reserveStream(0, stream), slot = this.#ticket(ticket)[0];
    slot.request = request; this.#calls.attach(call, ticket); slot.call = call; return ticket;
  }
  /** Private vector reservation: no call submission or reader is attached
   * until the original prepared Start commits. A miss can return this slot. */
  prepareOutgoingStream(stream: object, request: ApplicationHeader, call: RPCCallReservation): Readonly<{
    current(): boolean; commit(): RPCNetworkTicket; release(): void;
  }> {
    this.checkOutgoingStream(request, call);
    const ticket = this.#reserveStream(0, stream); let active = true, committed = false;
    const current = (): boolean => active && !committed && !this.#closed && this.live(ticket);
    return Object.freeze({ current, commit: () => {
      if (!current()) throw new RPCProtocolError("not_ready");
      const slot = this.#ticket(ticket)[0]; this.#calls.checkUnsubmitted(call);
      this.#calls.attach(call, ticket); slot.call = call; slot.request = request; committed = true; return ticket;
    }, release: () => { if (!active) return; active = false; if (!committed) this.closeStream(ticket, stream); } });
  }
  #streamRequest(header: ApplicationHeader, outgoing: boolean): void {
    if (header.kind !== "transient_stream_request" && header.kind !== "execution_stream_request" && header.kind !== "resume_request" ||
        outgoing && (header.kind === "execution_stream_request" || header.kind === "resume_request") && this.#config.profile !== "execution") throw new RPCProtocolError("rpc_request_variant");
  }
  #reserveStream(side: 0 | 1, stream: object): RPCNetworkTicket {
    this.#check();
    if (stream === null || typeof stream !== "object" || this.#slots.some(list => list.some(slot => slot.stream === stream))) throw new RPCProtocolError("rpc_stream_owner");
    if (this.#counts[side]![0]! >= this.#config.maxGeneral) throw new ResourceError("resource_exhausted");
    const index = this.#slots[side].findIndex(slot => slot.owner === undefined && slot.generation < maximum);
    if (index < 0) throw new ResourceError("resource_exhausted");
    const slot = this.#slots[side][index]!, generation = slot.generation + 1n;
    const owner = new RPCNetworkTicket(token, { network: this, side, index, generation });
    Object.assign(slot, newSlot(), { generation, owner, stream }); this.#counts[side]![0] = this.#counts[side]![0]! + 1; return owner;
  }
  bindIncomingStream(ticket: RPCNetworkTicket, stream: object, header: ApplicationHeader): void {
    const [slot, state] = this.#ticket(ticket); this.#streamRequest(header, false);
    if (state.side !== 1 || slot.stream !== stream || slot.request !== undefined) throw new RPCProtocolError("rpc_stream_owner");
    slot.request = header;
  }
  checkStream(ticket: RPCNetworkTicket, stream: object): void {
    if (this.#ticket(ticket)[0].stream !== stream) throw new RPCProtocolError("rpc_stream_owner");
  }
  completeStreamRequest(ticket: RPCNetworkTicket, stream: object): void {
    const [slot] = this.#ticket(ticket);
    if (slot.stream !== stream || slot.request === undefined || slot.requestDone) throw new RPCProtocolError("rpc_stream_owner");
    slot.requestOffset = slot.request.payloadBytes; slot.requestDone = true;
  }
  /** Item boundaries never settle this association. All actual reader,
   * callback and publication tails must exit before the original slot retires. */
  retainStream(ticket: RPCNetworkTicket, stream: object): () => void {
    const [slot] = this.#ticket(ticket);
    if (slot.stream !== stream || slot.streamBorrows >= 64) throw new RPCProtocolError("rpc_stream_owner");
    slot.streamBorrows++; let live = true;
    return () => {
      if (!live) return; live = false; slot.streamBorrows--;
      if (slot.streamClosed && slot.streamBorrows === 0) this.release(ticket);
    };
  }
  closeStream(ticket: RPCNetworkTicket, stream: object): void {
    if (!this.live(ticket)) return;
    const [slot] = this.#ticket(ticket, true);
    if (slot.stream !== stream) throw new RPCProtocolError("rpc_stream_owner");
    slot.streamClosed = true;
    if (slot.streamBorrows === 0) this.release(ticket);
  }
  checkBinding(ticket: RPCNetworkTicket, channel: RPCChannel, outgoing: boolean): void {
    const [slot, state] = this.#ticket(ticket);
    if (slot.channel !== channel || (state.side === 0) !== outgoing) throw new RPCProtocolError("rpc_ticket_owner");
  }
  bindOutput(ticket: RPCNetworkTicket, output: RPCOutputInterest): void {
    const [slot, state] = this.#ticket(ticket);
    if (state.side !== 1 || slot.query || !slot.requestDone || !slot.inputValidated || slot.output !== undefined ||
        !output.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_output_owner");
    slot.output = output;
    if (slot.stopRequested) this.#loseOutput(slot, "response_output_stopped");
  }
  #loseOutput(slot: MessageSlot, reason: V4OutputInterestReason, detached = false): void {
    if (slot.output === undefined) return;
    slot.output.lose(reason, detached); this.#outputSignals.add(slot.output);
  }
  /** Separate host handoff after the scalar network gate. */
  flushOutputEvents(): void {
    for (const output of this.#outputSignals) { this.#outputSignals.delete(output); output.flush(); }
    this.#collect();
  }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  get generalLimit(): number { return this.#config.maxGeneral; }
  get profile(): "services" | "execution" { return this.#config.profile; }
  claimInputs(owner: object): void { this.#check(); if (this.#inputs !== undefined) throw new RPCProtocolError("rpc_input_owner"); this.#inputs = owner; }
  claimQueries(owner: object): void { this.#check(); if (this.#queries !== undefined) throw new RPCProtocolError("rpc_query_owner"); this.#queries = owner; }
  claimQueryAssembly(owner: object): void {
    this.#check();
    if (this.#queryAssembly !== undefined || this.#channels.some(channel => channel.owner !== undefined)) throw new RPCProtocolError("rpc_query_owner");
    this.#queryAssembly = owner;
  }
  completeQueryAssembly(owner: object): void {
    this.#check();
    if (owner !== this.#queryAssembly || this.#queriesReady || this.#inputs === undefined || this.#queries === undefined ||
        this.#queryClient === undefined || this.#queryCodecs === undefined) throw new RPCProtocolError("rpc_query_owner");
    this.#queriesReady = true;
  }
  closeQueryAssembly(owner: object): void { if (owner === this.#queryAssembly) this.#queriesReady = false; }
  requireQueries(): void { this.#check(); if (!this.#queriesReady) throw new RPCProtocolError("configuration_capacity"); }
  claimQueryCodecs(owner: object): void { this.#check(); if (this.#queryCodecs !== undefined) throw new RPCProtocolError("rpc_query_owner"); this.#queryCodecs = owner; }
  claimQueryClient(owner: object): void { this.#check(); if (this.#queryClient !== undefined) throw new RPCProtocolError("rpc_query_owner"); this.#queryClient = owner; }
  queryHeader(owner: object, codec: ApplicationHeaderCodec, payloadBytes: number, deadlineAtMS: bigint): ApplicationHeader {
    this.#check(); if (this.#queryClient !== owner || payloadBytes < 1 || payloadBytes > 2048) throw new RPCProtocolError("rpc_query_owner");
    return codec.create({ kind: "query_contracts_request", typeID: this.#config.query.typeID, contractDigest: this.#config.query.contractDigest, payloadBytes, deadlineAtMS });
  }
  claimInput(owner: object, ticket: RPCNetworkTicket, header: ApplicationHeader): void {
    const [slot, state] = this.#ticket(ticket);
    if (this.#inputs !== owner || state.side !== 1 || slot.request !== header || slot.inputClaimed) throw new RPCProtocolError("rpc_input_owner");
    slot.inputClaimed = true;
  }
  live(ticket: RPCNetworkTicket): boolean { return tickets.get(ticket)?.network === this; }
  request(ticket: RPCNetworkTicket): ApplicationHeader { return this.#ticket(ticket, true)[0].request!; }
  state(ticket: RPCNetworkTicket): Readonly<{ outgoing: boolean; query: boolean; requestSerial: bigint; responseSerial: bigint;
    requestOffset: number; responseOffset: number; requestDone: boolean; responseDone: boolean; requestAborted: boolean;
    responseAborted: boolean; inputValidated: boolean; stopRequested: boolean; stopSent: boolean }> {
    const [s, t] = this.#ticket(ticket, true);
    return { outgoing: t.side === 0, query: s.query, requestSerial: s.requestSerial, responseSerial: s.responseSerial,
      requestOffset: s.requestOffset, responseOffset: s.responseOffset, requestDone: s.requestDone, responseDone: s.responseDone,
      requestAborted: s.requestAborted, responseAborted: s.responseAborted, inputValidated: s.inputValidated, stopRequested: s.stopRequested, stopSent: s.stopSent };
  }
  inputComplete(ticket: RPCNetworkTicket, validated: boolean): void {
    const [slot, state] = this.#ticket(ticket);
    if (state.side !== 1 || !slot.requestDone || slot.requestAborted) throw new RPCProtocolError("rpc_input_state");
    slot.inputValidated = validated;
  }
  nextBegin(ticket: RPCNetworkTicket, header: ApplicationHeader): Readonly<{ serial: bigint; replyTo: bigint }> {
    const [slot, state] = this.#ticket(ticket), channel = this.#channel(slot.channel!);
    if (channel.sent === maximum) throw new ResourceError("resource_exhausted");
    if (state.side === 0) {
      if (slot.requestSerial !== 0n || header !== slot.request) throw new RPCProtocolError("rpc_publication_owner");
    } else {
      if (!slot.requestDone || slot.responseSerial !== 0n) throw new RPCProtocolError("rpc_duplicate_response");
      header.checkResponse(slot.request!);
      if (slot.requestAborted && !header.isSDKError()) throw new RPCProtocolError("rpc_abort_response");
    }
    return { serial: channel.sent + 1n, replyTo: state.side === 0 ? 0n : slot.requestSerial };
  }
  sentStop(ticket: RPCNetworkTicket): void {
    if (this.#ticket(ticket)[0].stream !== undefined) throw new RPCProtocolError("rpc_fragment_association");
    const [slot, state] = this.#ticket(ticket);
    if (state.side !== 0 || !slot.requestDone || slot.requestAborted || slot.responseDone || slot.stopSent) throw new RPCProtocolError("rpc_stop_output_state");
    slot.stopSent = true;
  }
  late(ticket: RPCNetworkTicket): boolean { return this.#ticket(ticket, true)[0].late; }
  abandon(ticket: RPCNetworkTicket): void {
    const [slot, state] = this.#ticket(ticket, true); if (state.side !== 0) throw new RPCProtocolError("rpc_ticket_owner");
    slot.late = true; // The original full/late position remains occupied.
  }
  /** Called only at the original publisher's first accepted BEGIN byte. A
   * canceled unsubmitted request has not entered this gate and burns no serial. */
  commitBegin(ticket: RPCNetworkTicket, header: ApplicationHeader): bigint {
    const { serial } = this.nextBegin(ticket, header);
    const [slot, state] = this.#ticket(ticket), channel = this.#channel(slot.channel!);
    channel.sent = serial;
    if (state.side === 0) { slot.requestSerial = serial; slot.requestDone = header.payloadBytes === 0; }
    else { slot.response = header; slot.responseSerial = serial; slot.responseDone = header.payloadBytes === 0; }
    return serial;
  }
  sentData(ticket: RPCNetworkTicket, offset: number, bytes: number): void {
    if (this.#ticket(ticket)[0].stream !== undefined) throw new RPCProtocolError("rpc_fragment_association");
    const [slot, state] = this.#ticket(ticket), response = state.side === 1;
    const serial = response ? slot.responseSerial : slot.requestSerial, header = response ? slot.response : slot.request;
    const next = response ? slot.responseOffset : slot.requestOffset, done = response ? slot.responseDone : slot.requestDone;
    if (serial === 0n || header === undefined || done || offset !== next || !Number.isSafeInteger(bytes) || bytes < 1 || bytes > header.payloadBytes - next) throw new RPCProtocolError("rpc_payload_offset");
    if (response) { slot.responseOffset += bytes; slot.responseDone = slot.responseOffset === header.payloadBytes; }
    else { slot.requestOffset += bytes; slot.requestDone = slot.requestOffset === header.payloadBytes; }
  }
  sentAbort(ticket: RPCNetworkTicket, offset: number): void {
    if (this.#ticket(ticket)[0].stream !== undefined) throw new RPCProtocolError("rpc_fragment_association");
    const [slot, state] = this.#ticket(ticket);
    const response = state.side === 1;
    if (response ? slot.responseSerial === 0n || slot.responseDone || slot.responseOffset !== offset :
        slot.requestSerial === 0n || slot.requestDone || slot.requestOffset !== offset) throw new RPCProtocolError("rpc_abort_state");
    if (response) slot.responseDone = slot.responseAborted = true;
    else slot.requestDone = slot.requestAborted = true;
  }

  #find(channel: RPCChannel, serial: bigint, response: boolean): MessageSlot | undefined {
    return this.#slots[response ? 0 : 1].find(slot => slot.owner !== undefined && slot.channel === channel &&
      (response ? slot.responseSerial : slot.requestSerial) === serial);
  }
  receive(channelOwner: RPCChannel, part: RPCFragmentPart, header?: ApplicationHeader): RPCReceivedPart | undefined {
    const channel = this.#channel(channelOwner), f = part.fragment;
    if (f.kind === 0) {
      if (!part.first || !part.last || header === undefined || channel.received === maximum || f.serial !== channel.received + 1n) throw new RPCProtocolError("rpc_begin_serial");
      const response = header.isResponse(), replyTo = f.replyTo ?? 0n;
      let slot: MessageSlot;
      if (response) {
        const original = this.#slots[0].find(candidate => candidate.owner !== undefined && candidate.channel === channelOwner && candidate.requestSerial === replyTo && replyTo !== 0n);
        if (original === undefined || !original.requestDone || original.responseSerial !== 0n) throw new RPCProtocolError("rpc_response_association");
        header.checkResponse(original.request!);
        if (original.requestAborted && !header.isSDKError()) throw new RPCProtocolError("rpc_abort_response");
        slot = original; slot.response = header; slot.responseSerial = f.serial; slot.responseDone = header.payloadBytes === 0;
      } else {
        if (replyTo !== 0n) throw new RPCProtocolError("rpc_request_reply_to");
        slot = this.#ticket(this.#reserve(1, channelOwner, header))[0]; slot.requestSerial = f.serial; slot.requestDone = header.payloadBytes === 0;
      }
      channel.received = f.serial;
      return { ticket: slot.owner!, kind: "begin", response, complete: header.payloadBytes === 0, header };
    }
    if (header !== undefined) throw new RPCProtocolError("rpc_fragment_header");
    if (f.kind === 3) {
      if (!part.first || !part.last || f.serial === 0n || f.serial > channel.received) throw new RPCProtocolError("rpc_stop_output_state");
      const slot = this.#slots[1].find(candidate => candidate.owner !== undefined && candidate.channel === channelOwner && candidate.requestSerial === f.serial);
      if (slot === undefined) {
        if (this.#find(channelOwner, f.serial, true) !== undefined) throw new RPCProtocolError("rpc_stop_output_state");
        return undefined; // Retired serial: no history or guessed message role.
      }
      if (!slot.requestDone || slot.requestAborted || !slot.inputValidated) throw new RPCProtocolError("rpc_stop_output_state");
      if (slot.stopRequested || slot.responseDone) return undefined;
      slot.stopRequested = true; this.#loseOutput(slot, "response_output_stopped");
      return { ticket: slot.owner!, kind: "stop_output", response: true, complete: false };
    }

    const request = this.#find(channelOwner, f.serial, false), responseSlot = this.#find(channelOwner, f.serial, true);
    if ((request === undefined) === (responseSlot === undefined)) throw new RPCProtocolError("rpc_fragment_association");
    const response = responseSlot !== undefined, slot = (responseSlot ?? request)!;
    const current = (response ? slot.response : slot.request)!, next = response ? slot.responseOffset : slot.requestOffset;
    if ((response ? slot.responseDone : slot.requestDone) || f.offset === undefined || f.offset + part.chunkOffset !== next) throw new RPCProtocolError("rpc_payload_offset");
    if (f.kind === 2) {
      if (!part.first || !part.last || part.chunkOffset !== 0 || next >= current.payloadBytes) throw new RPCProtocolError("rpc_abort_state");
      if (response) slot.responseDone = slot.responseAborted = true;
      else slot.requestDone = slot.requestAborted = true;
      return { ticket: slot.owner!, kind: "abort", response, complete: true };
    }
    const count = f.payload === undefined ? 0 : byteLength(f.payload);
    if (count < 1 || count > current.payloadBytes - next) throw new RPCProtocolError("rpc_payload_length");
    const complete = next + count === current.payloadBytes;
    if (complete && !part.last) throw new RPCProtocolError("rpc_payload_length");
    if (response) { slot.responseOffset += count; slot.responseDone = complete; }
    else { slot.requestOffset += count; slot.requestDone = complete; }
    return { ticket: slot.owner!, kind: "data", response, complete, payload: f.payload! };
  }
  /** Real publication borrows survive logical abandon and channel close. */
  retainPublication(ticket: RPCNetworkTicket): () => void {
    const [slot] = this.#ticket(ticket);
    if (this.#publications >= 64) throw new ResourceError("resource_exhausted");
    const finishCall = slot.call === undefined ? undefined : this.#calls.retainPublication(slot.call, ticket);
    this.#publications++; let active = true;
    // The physical tail carries no future publication rights and never writes
    // the reusable message slot. A terminal response can free that slot now.
    return () => { if (!active) return; active = false; this.#publications--; this.#collect(); finishCall?.(); };
  }

  release(ticket: RPCNetworkTicket): void {
    const state = tickets.get(ticket); if (state?.network !== this) return;
    const [slot] = this.#ticket(ticket, true);
    if (slot.stream !== undefined) {
      if (!slot.streamClosed || slot.streamBorrows !== 0) throw new RPCProtocolError("rpc_unsettled_owner");
      const call = slot.call;
      this.#loseOutput(slot, "owner_unavailable", true);
      this.#counts[state.side]![0] = this.#counts[state.side]![0]! - 1;
      Object.assign(slot, newSlot(), { generation: slot.generation }); state.network = undefined;
      this.#collect(); if (call !== undefined) this.#calls.settled(call, ticket); return;
    }
    const channel = this.#channel(slot.channel!, true);
    if (!channel.closed && !this.#closed && slot.requestSerial !== 0n && (!slot.requestDone || !slot.responseDone)) throw new RPCProtocolError("rpc_unsettled_owner");
    const category = slot.query ? 1 : 0;
    const call = slot.call;
    this.#loseOutput(slot, slot.responseDone && !channel.closed && !this.#closed ? "response_complete" : "owner_unavailable", true);
    this.#counts[state.side]![category] = this.#counts[state.side]![category]! - 1; channel.liveTickets--;
    Object.assign(slot, newSlot(), { generation: slot.generation }); state.network = undefined;
    this.#collectChannel(channel); this.#collect();
    if (call !== undefined) this.#calls.settled(call, ticket);
  }
  closeChannel(owner: RPCChannel): void {
    const state = channels.get(owner); if (state?.network !== this) return;
    const channel = this.#channel(owner, true); channel.closed = true;
    for (const list of this.#slots) for (const slot of list) if (slot.owner !== undefined && slot.channel === owner) this.release(slot.owner);
    this.#collectChannel(channel);
  }
  #collectChannel(channel: ChannelSlot): void {
    if (!channel.closed || channel.owner === undefined || channel.liveTickets !== 0) return;
    channels.get(channel.owner)!.network = undefined; channel.owner = undefined; channel.reader = channel.publisher = undefined;
  }
  close(): void {
    this.#closed = true;
    for (const channel of this.#channels) if (channel.owner !== undefined) this.closeChannel(channel.owner);
    for (const list of this.#slots) for (const slot of list) if (slot.owner !== undefined && slot.stream !== undefined) this.closeStream(slot.owner, slot.stream);
    this.#calls.close();
    this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#outputSignals.size !== 0 || this.#publications !== 0 || this.#channels.some(channel => channel.owner !== undefined) || this.#counts.some(counts => counts.some(count => count !== 0))) return;
    this.#digest.fill(0); this.#config.query.contractDigest.fill(0); this.#config.resultRead?.contractDigest.fill(0); this.#inputs = undefined; this.#queries = undefined; this.#queryClient = undefined; this.#queryCodecs = undefined; this.#queryAssembly = undefined; this.#queriesReady = false;
    this.#slots[0].length = this.#slots[1].length = this.#channels.length = 0;
    this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
