import type { ResponsePublication } from "../responsePublication.js";
import { transportV4ApplicationHeaders as registry } from "../../generated/transportV4Registry.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { byteLength, byteSlice } from "./cbor.js";
import { FixedCBORWriter } from "./cborWriter.js";
import { encodeRPCFragment, rpcDataMaxBytes, RPCProtocolError, type RPCFragment } from "./rpcFragment.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import type { RPCNetwork} from "./rpcNetwork.js";
import { type RPCChannel, type RPCNetworkTicket } from "./rpcNetwork.js";
import type { RPCPayloadBorrow } from "./rpcPayload.js";
import type { RPCReceiver } from "./rpcReceiver.js";
import type { RPCStreamOwner } from "./rpcStream.js";
import { ResourceVector, type ProtectedResourceReservation, type ResourceReference } from "./resources.js";
import type { ReliableWriteRequest } from "./writeRequest.js";
import { TimeError } from "./timeArithmetic.js";

const codes: Readonly<Record<string, number>> = Object.freeze({ ...registry.sdk_error_codes });
type Category = "query" | "request" | "completion";
/** Private SDK policy owner. check may sample its original trusted clock;
 * current is a pure scalar/generation gate immediately before admission. */
export interface RPCPublicationGuard {
  readonly responsePublication?: ResponsePublication | undefined;
  check(): void;
  current(): boolean;
  /** Earlier pre-BEGIN preparation/cutoff, when the original owner has one. */
  publicationRemainingMS?(): bigint;
  /** Original SDK scalar transition, invoked only after request BEGIN enters
   * the immutable Stream publication gate. It must not call application code. */
  admitted?(): void;
  /** Rebind the same pre-BEGIN windows to another SDK-selected source. */
  reroute?(source: RPCPublicationGuard): RPCPublicationGuard;
  /** Original SDK observation after the complete successful response reaches
   * the native provider. This never invokes an application callback. */
  responseHandedOff?(): void;
  /** The physical tail of a response publication has completed. */
  publicationPhysicalComplete?(): void;
}
interface Publication {
  readonly ticket: RPCNetworkTicket; readonly outgoing: boolean; readonly query: boolean;
  header: ApplicationHeader | undefined; payload: RPCPayloadBorrow | undefined; small: RPCSDKError | undefined;
  stopping: boolean; revision: bigint; category: Category | undefined;
  guard: RPCPublicationGuard | undefined;
  lifecycle: RPCPublicationGuard | undefined;
  readonly observation: ResponsePublication | undefined;
}
export function rpcPublisherCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  // One candidate/current fragment, canonical header and fixed small output.
  // The Stream's separate protected immutable copy is charged by writeRequest.
  return new ResourceVector([16384n + 512n + 2048n + runtimeBytes, 0n, 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}

/** One publisher for one channel direction. A conservative one-fragment batch
 * uses the common four-fragment maximum without requiring full-fragment peer
 * credit. The Stream owns the complete accepted fragment while its record
 * sender advances across credit/rekey gates. No per-call send task is created. */
export class RPCPublisher {
  readonly #network: RPCNetwork;
  readonly #channel: RPCChannel;
  readonly #receiver: RPCReceiver;
  readonly #stream: RPCStreamOwner;
  readonly #position: ProtectedResourceReservation;
  #reference: ResourceReference | undefined;
  #wire: Uint8Array = new Uint8Array();
  #header: Uint8Array = new Uint8Array();
  #small: Uint8Array = new Uint8Array();
  readonly #entries = new Map<RPCNetworkTicket, Publication>();
  readonly #ready: Record<Category, Set<Publication>> = { query: new Set(), request: new Set(), completion: new Set() };
  #generalRun = 0;
  #completionRun = 0;
  #requestRun = 0;
  #busy = false;
  #closed = false;
  #current: ReliableWriteRequest | undefined;
  #currentEntry: Publication | undefined;
  #tailPayload: RPCPayloadBorrow | undefined;
  constructor(network: RPCNetwork, channel: RPCChannel, receiver: RPCReceiver, stream: RPCStreamOwner,
    position: ProtectedResourceReservation, runtimeBytes: bigint, reference: ResourceReference, private readonly reusablePosition = false) {
    if (!network.sameEnvironment(reference) || stream.kind !== "flowersec.rpc.v4" || stream.metadata.length !== 0 || stream.maxWriteBytes < 16384) throw new RPCProtocolError("rpc_publisher_owner");
    this.#network = network; this.#channel = channel; this.#receiver = receiver; this.#stream = stream; this.#position = position;
    this.#reference = reference.take(rpcPublisherCharge(runtimeBytes));
    try { network.claimPublisher(channel, this); }
    catch (error) { this.#reference.release(); this.#reference = undefined; throw error; }
    try { this.#wire = new Uint8Array(16384); this.#header = new Uint8Array(512); this.#small = new Uint8Array(256); }
    catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("rpc_publisher_closed"); this.#reference!.check(); }
  #add(ticket: RPCNetworkTicket, outgoing: boolean, header: ApplicationHeader | undefined, payload: RPCPayloadBorrow | undefined,
    small?: RPCSDKError, guard?: RPCPublicationGuard, observation?: ResponsePublication, lifecycle?: RPCPublicationGuard): void {
    this.#check(); this.#sync(); this.#network.checkBinding(ticket, this.#channel, outgoing);
    if (this.#entries.has(ticket)) throw new RPCProtocolError("rpc_duplicate_publication");
    const state = this.#network.state(ticket);
    if (outgoing ? state.requestSerial !== 0n || header !== this.#network.request(ticket) : !state.requestDone || state.responseSerial !== 0n) throw new RPCProtocolError("rpc_publication_owner");
    if (header !== undefined && byteLength(payload!.bytes) !== header.payloadBytes) throw new RPCProtocolError("rpc_payload_length");
    if (!outgoing && header !== undefined) header.checkResponse(this.#network.request(ticket));
    this.#entries.set(ticket, { ticket, outgoing, query: state.query, header, payload, small, guard, lifecycle: lifecycle ?? guard,
      observation: outgoing ? undefined : observation ?? guard?.responsePublication, stopping: false, revision: 0n, category: undefined });
  }
  addRequest(ticket: RPCNetworkTicket, payload: RPCPayloadBorrow, guard?: RPCPublicationGuard): void { this.#add(ticket, true, this.#network.request(ticket), payload, undefined, guard); }
  addResponse(ticket: RPCNetworkTicket, header: ApplicationHeader, payload: RPCPayloadBorrow, guard?: RPCPublicationGuard): void { this.#add(ticket, false, header, payload, undefined, guard); }
  replySDK(ticket: RPCNetworkTicket, code: RPCSDKError, guard?: RPCPublicationGuard): void {
    if (!Object.hasOwn(codes, code) || code === "source_overflow") throw new RPCProtocolError("rpc_error_variant");
    this.#add(ticket, false, undefined, undefined, code, undefined, guard?.responsePublication, guard);
    guard?.responsePublication?.unknown(code === "deadline_exceeded" ? "deadline" : "response_superseded");
  }
  stop(ticket: RPCNetworkTicket): void {
    this.#check(); const entry = this.#entries.get(ticket);
    if (entry === undefined || !entry.outgoing) throw new RPCProtocolError("rpc_publication_owner");
    if (!this.#network.live(ticket)) { this.#remove(entry); return; }
    if (this.#network.state(ticket).requestSerial === 0n) {
      this.#remove(entry); this.#receiver.cancelUnsubmitted(ticket); return;
    }
    if (!entry.stopping) { entry.stopping = true; entry.revision++; this.#receiver.abandon(ticket); }
    this.#sync();
  }
  #remove(entry: Publication): void {
    if (entry.category !== undefined) this.#ready[entry.category].delete(entry);
    entry.category = undefined; this.#entries.delete(entry.ticket); this.#detachPayload(entry); entry.guard = undefined;
    // An admitted fragment owns its actual tail until publishNext's finally.
    if (this.#currentEntry !== entry) this.#completePhysical(entry);
  }
  #completePhysical(entry: Publication): void {
    const lifecycle = entry.lifecycle; entry.lifecycle = undefined;
    lifecycle?.publicationPhysicalComplete?.();
    entry.observation?.physicalDone();
  }
  #detachPayload(entry: Publication): void {
    if (entry.payload === undefined) return;
    // The logical terminal can free the peer's ReplySlot before this physical
    // fragment exits. Retain its original source/vector through that real tail.
    if (this.#currentEntry === entry) this.#tailPayload = entry.payload;
    else entry.payload.release();
    entry.payload = undefined;
  }
  #revoke(entry: Publication, error?: unknown): void {
    entry.observation?.unknown(error instanceof TimeError || error instanceof RPCProtocolError && error.code === "deadline_exceeded" ? "deadline" : "owner_unavailable");
    entry.guard = undefined;
    if (!this.#network.live(entry.ticket)) { this.#remove(entry); return; }
    if (entry.outgoing) { this.stop(entry.ticket); return; }
    entry.stopping = true; entry.revision++;
    if (this.#network.state(entry.ticket).responseSerial === 0n) {
      this.#detachPayload(entry); entry.header = undefined;
      entry.small = error instanceof TimeError && error.code === "time_expired" ? "deadline_exceeded" :
        error instanceof RPCProtocolError && ["result_expired", "permission_denied", "deadline_exceeded"].includes(error.code) ? error.code as RPCSDKError : "service_unavailable";
      // This bounded refusal is the new unpublished candidate, not an ABORT.
      entry.stopping = false;
    }
  }
  #sync(): void {
    for (const entry of this.#entries.values()) {
      if (!this.#network.live(entry.ticket)) { entry.observation?.unknown("owner_unavailable"); this.#remove(entry); continue; }
      const state = this.#network.state(entry.ticket);
      if (!entry.outgoing && state.stopRequested && !state.responseDone && !entry.stopping) {
        entry.observation?.unknown(state.responseSerial === 0n ? "response_superseded" : "response_aborted");
        entry.stopping = true; entry.revision++;
        if (state.responseSerial === 0n) { this.#detachPayload(entry); entry.header = undefined; entry.small = "response_output_stopped"; entry.guard = undefined; }
      }
      let ready = false;
      if (entry.outgoing) ready = state.requestSerial === 0n || !state.requestDone || entry.stopping && !state.requestAborted && !state.stopSent && !state.responseDone;
      else ready = !state.responseDone;
      const category = !ready ? undefined : entry.query ? "query" : entry.outgoing && !entry.stopping ? "request" : "completion";
      if (entry.category === category) continue;
      if (entry.category !== undefined) this.#ready[entry.category].delete(entry);
      entry.category = category; if (category !== undefined) this.#ready[category].add(entry);
    }
  }
  #select(): Publication | undefined {
    this.#sync();
    const q = this.#ready.query.size !== 0, r = this.#ready.request.size !== 0, c = this.#ready.completion.size !== 0;
    const category: Category | undefined = q && (!r && !c || this.#generalRun >= 8) ? "query" :
      c && (!r || this.#requestRun >= 1 || this.#completionRun < 8) ? "completion" : r ? "request" : q ? "query" : undefined;
    return category === undefined ? undefined : this.#ready[category].values().next().value;
  }
  ready(): boolean { this.#check(); return this.#select() !== undefined; }
  load(): number { this.#check(); return this.#entries.size + Number(this.#busy); }
  businessPending(): boolean { return this.#entries.size !== 0 || this.#busy; }
  #served(entry: Publication): void {
    const category = entry.category!;
    if (category === "query") this.#generalRun = 0;
    else {
      this.#generalRun = Math.min(8, this.#generalRun + 1);
      if (category === "completion") { this.#completionRun = Math.min(8, this.#completionRun + 1); this.#requestRun = 0; }
      else { this.#requestRun = 1; this.#completionRun = 0; }
    }
    this.#ready[category].delete(entry); this.#ready[category].add(entry);
  }
  #fragment(entry: Publication): RPCFragment {
    const state = this.#network.state(entry.ticket), serial = entry.outgoing ? state.requestSerial : state.responseSerial;
    const offset = entry.outgoing ? state.requestOffset : state.responseOffset, done = entry.outgoing ? state.requestDone : state.responseDone;
    if (entry.outgoing && entry.stopping && done) return { kind: 3, serial: state.requestSerial };
    if (serial !== 0n && entry.stopping && entry.small !== "response_output_stopped") return { kind: 2, serial, offset };
    if (entry.small !== undefined) {
      const writer = new FixedCBORWriter(this.#small).map(1).uint(0).uint(codes[entry.small]!);
      const payload = writer.result();
      entry.header ??= this.#receiver.sdkResponse(entry.ticket, payload.length);
    }
    if (serial === 0n) {
      const next = this.#network.nextBegin(entry.ticket, entry.header!), n = entry.header!.encode(this.#header);
      return { kind: 0, serial: next.serial, replyTo: next.replyTo, header: byteSlice(this.#header, 0, n) };
    }
    const payload = entry.small === undefined ? entry.payload!.bytes : byteSlice(this.#small, 0, entry.header!.payloadBytes);
    return { kind: 1, serial, offset, payload: byteSlice(payload, offset, Math.min(entry.header!.payloadBytes, offset + rpcDataMaxBytes)) };
  }
  /** One bounded service turn. The channel owns the single pump/wakeup task.
   * Selection may be canceled without consuming serials or fairness turns. */
  async publishNext(): Promise<boolean> {
    this.#check(); if (this.#busy) throw new RPCProtocolError("rpc_publication_busy");
    this.#busy = true;
    let request: ReliableWriteRequest | undefined, committed = false;
    let releasePublication: (() => void) | undefined, observation: ResponsePublication | undefined;
    try {
      const entry = this.#select(); if (entry === undefined) return false;
      this.#currentEntry = entry; observation = entry.observation;
      if (entry.guard !== undefined) {
        try { entry.guard.check(); }
        catch (error) { this.#check(); this.#revoke(entry, error); return false; }
        this.#check(); if (!entry.guard?.current()) { this.#revoke(entry); return false; }
      }
      const revision = entry.revision, fragment = this.#fragment(entry), size = encodeRPCFragment(fragment, this.#wire);
      const reference = this.#position.checkout();
      try { request = this.#stream.prepareFragment(byteSlice(this.#wire, 0, size), reference); }
      finally { reference.release(); }
      this.#current = request;
      request.checkProtocolAdmission(); // Clock/provider hooks remain outside the commit gate.
      if (entry.guard !== undefined) {
        try { entry.guard.check(); }
        catch (error) { this.#check(); this.#revoke(entry, error); request.cancel(); return false; }
      }
      this.#check();
      if (this.#select() !== entry || entry.revision !== revision || !this.#network.live(entry.ticket)) { request.cancel(); return false; }
      if (fragment.kind === 0 && this.#network.nextBegin(entry.ticket, entry.header!).serial !== fragment.serial) { request.cancel(); return false; }
      if (entry.guard !== undefined && !entry.guard.current()) { this.#revoke(entry); request.cancel(); return false; }
      releasePublication = this.#network.retainPublication(entry.ticket);
      if (!request.admitProtocol()) return false;
      committed = true;
      // From here to start(), only original SDK scalar gates run. The Stream
      // owns the complete immutable copy, including any yet unticketed suffix.
      if (fragment.kind === 0) {
        this.#network.commitBegin(entry.ticket, entry.header!);
        if (entry.outgoing) entry.guard?.admitted?.();
      }
      else if (fragment.kind === 1) this.#network.sentData(entry.ticket, fragment.offset!, byteLength(fragment.payload!));
      else if (fragment.kind === 2) this.#network.sentAbort(entry.ticket, fragment.offset!);
      else this.#network.sentStop(entry.ticket);
      this.#served(entry);
      const state = this.#network.state(entry.ticket);
      if (entry.outgoing ? state.requestDone : state.responseDone) this.#detachPayload(entry);
      if (!entry.outgoing && state.responseDone && fragment.kind !== 2 && !entry.stopping && entry.small === undefined) {
        const original = observation, lifecycle = entry.lifecycle;
        if (original !== undefined || lifecycle?.responseHandedOff !== undefined) request.observeProtocolHandoff(() => {
          original?.handoff(); lifecycle?.responseHandedOff?.();
        });
      }
      if (!entry.outgoing && state.responseDone) { this.#network.release(entry.ticket); this.#remove(entry); }
      request.start();
      this.#network.flushOutputEvents();
      await request.waitCleanup();
      if (request.progress().accepted_bytes !== BigInt(size) || request.progress().terminal_reason !== "complete") throw new RPCProtocolError("rpc_publication_failed");
      return true;
    } catch (error) {
      observation?.unknown("publish_failed");
      if (committed) { this.close(); this.#receiver.close(); void this.#stream.reset().catch(() => undefined); }
      throw error;
    } finally {
      if (!committed) request?.cancel();
      else await request?.waitCleanup();
      releasePublication?.();
      this.#current = undefined; this.#wire.fill(0); this.#header.fill(0); this.#small.fill(0);
      const entry = this.#currentEntry; this.#currentEntry = undefined; this.#busy = false;
      if (entry !== undefined && !this.#entries.has(entry.ticket)) this.#completePhysical(entry);
      const tail = this.#tailPayload; this.#tailPayload = undefined; tail?.release(); this.#collect();
      this.#network.flushOutputEvents();
    }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#currentEntry?.observation?.unknown("owner_unavailable");
    this.#current?.cancel(); // An accepted fragment can only end with its real Stream.
    for (const entry of this.#entries.values()) { entry.observation?.unknown("owner_unavailable"); this.#remove(entry); }
    if (!this.reusablePosition) this.#position.closeAfterUse(); this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#busy) return;
    this.#wire.fill(0); this.#header.fill(0); this.#small.fill(0);
    this.#wire = this.#header = this.#small = new Uint8Array();
    this.#reference?.release(); this.#reference = undefined;
  }
}
