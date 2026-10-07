import type { ApplicationGroup } from "./applicationExecutor.js";
import type { RPCCallReservation } from "./rpcCallCapacity.js";
import type { V4StreamOwner } from "../public.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import type { RPCCompletion, RPCSDKError } from "./rpcCompletion.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCNetwork} from "./rpcNetwork.js";
import { type RPCChannel, type RPCNetworkTicket } from "./rpcNetwork.js";
import type { RPCPayloadBorrow } from "./rpcPayload.js";
import { RPCPublisher, type RPCPublicationGuard } from "./rpcPublisher.js";
import { RPCReceiver, type RPCIncomingAdmission, type RPCReadyRequest } from "./rpcReceiver.js";
import { acquireRPCStream, type RPCStreamOwner } from "./rpcStream.js";
import { ResourceVector, type ResourceReference, type ProtectedResourceReservation } from "./resources.js";
import type { RPCOutputInterest } from "./rpcOutputInterest.js";

const NativePromise = Promise;
/** A coalesced SDK wake with one prepaid waiter, not a queue of tasks. */
class ChannelWake {
  #pending = false;
  #closed = false;
  #resolve: (() => void) | undefined;
  signal(): void { this.#pending = true; const resolve = this.#resolve; this.#resolve = undefined; resolve?.(); }
  wait(): Promise<void> {
    if (this.#closed || this.#pending) { this.#pending = false; return NativePromise.resolve(); }
    if (this.#resolve !== undefined) throw new RPCProtocolError("rpc_wait_in_progress");
    return new NativePromise<void>(resolve => { this.#resolve = resolve; });
  }
  close(): void { this.#closed = true; this.signal(); }
}
export function rpcChannelCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return new ResourceVector([2048n + runtimeBytes, 0n, 0n, 4n, 2n, 3n, 1n, 0n, 0n, 0n, 0n]);
}
export interface RPCChannelReferences {
  readonly channel: ResourceReference;
  readonly adapter: ResourceReference;
  readonly application: ApplicationGroup;
  readonly receiver: readonly ResourceReference[];
  readonly publisher: ResourceReference;
  /** Charged to the original Session and direction send accounts. */
  readonly publication: ProtectedResourceReservation;
  /** Session-owned future position and group survive a channel generation. */
  readonly reusable?: boolean;
}

/** Actual authenticated Stream composition. Creation consumes the admission
 * reservation supplied by the Session's SDK service assembly; it does not
 * authenticate a peer, create bootstrap scope 1 or grant application dispatch.
 * Each channel has one reader, one publisher and one finite request wake. */
export class RPCChannelRuntime {
  readonly #network: RPCNetwork;
  readonly #channel: RPCChannel;
  readonly #abort = new AbortController();
  readonly #sendWake = new ChannelWake();
  readonly #requestWake = new ChannelWake();
  #reference: ResourceReference | undefined;
  #stream: RPCStreamOwner | undefined;
  #receiver: RPCReceiver | undefined;
  #publisher: RPCPublisher | undefined;
  #position: ProtectedResourceReservation | undefined;
  #started = false;
  #closed = false;
  #draining = false;
  #inputEnded = false;
  #finishing = false;
  #outputEnded = false;
  #reading = false;
  #publishing = false;
  #physical = false;
  #collecting = false;
  #failure: unknown;
  readonly #reusable: boolean;
  #changed: (() => void) | undefined;
  constructor(stream: V4StreamOwner, network: RPCNetwork, admission: RPCIncomingAdmission,
    runtimeBytes: bigint, references: RPCChannelReferences) {
    network.requireQueries(); this.#network = network; this.#reusable = references.reusable === true;
    if (![references.channel, references.adapter, references.publisher, ...references.receiver].every(ref => network.sameEnvironment(ref)) ||
        !references.publication.sameEnvironment(references.channel) || !references.publication.available()) throw new RPCProtocolError("rpc_channel_owner");
    this.#reference = references.channel.take(rpcChannelCharge(runtimeBytes));
    try { this.#channel = network.openChannel(); }
    catch (error) { this.#reference.release(); this.#reference = undefined; throw error; }
    try {
      this.#stream = acquireRPCStream(stream, { kind: "message", readBytes: 16384, inputBackingBytes: 1, inputEntries: 1,
        gracefulFinishMS: 30000, cleanupMS: 5000, prepaid: references.adapter, application: references.application,
        reusableApplication: this.#reusable });
      this.#position = references.publication;
      this.#receiver = new RPCReceiver(network, this.#channel, admission, runtimeBytes, references.receiver);
      this.#publisher = new RPCPublisher(network, this.#channel, this.#receiver, this.#stream, this.#position, runtimeBytes, references.publisher, this.#reusable);
      this.#stream.invalidateWith(() => this.close());
      this.#stream.ioEndedWith(() => this.close());
      this.#stream.cleanupWith(() => { this.#physical = true; this.#collect(); });
    } catch (error) {
      this.#publisher?.close(); if (!this.#reusable) this.#position?.close(); this.#receiver?.close(); this.#network.closeChannel(this.#channel);
      this.#stream?.rollback(); this.#stream = undefined; this.#reference.release(); this.#reference = undefined; throw error;
    }
  }
  #check(): void {
    if (this.#failure !== undefined) throw this.#failure;
    if (this.#closed) throw new RPCProtocolError("rpc_channel_closed"); this.#reference!.check(); this.#stream!.check();
  }
  checkDependency(): void { this.#check(); if (!this.#started) throw new RPCProtocolError("not_ready"); }
  ready(): boolean { try { this.checkDependency(); return true; } catch { return false; } }
  gracefullyEnded(): boolean { return this.#inputEnded && this.#outputEnded; }
  businessPending(): boolean {
    return this.#publisher?.businessPending() === true || !this.#closed && (this.#receiver!.pendingFragment() || !this.#network.channelIdle(this.#channel));
  }
  requestReady(): boolean { return this.ready() && !this.#draining && !this.#inputEnded && !this.#finishing; }
  #checkRequest(): void { this.#check(); if (this.#draining || this.#inputEnded || this.#finishing) throw new RPCProtocolError("not_ready"); }
  requestLoad(): number { this.checkDependency(); return this.#publisher!.load(); }
  onChange(changed: () => void): void { if (this.#changed !== undefined) throw new RPCProtocolError("rpc_channel_owner"); this.#changed = changed; }
  start(): void {
    this.#check(); if (this.#started) return; this.#started = true;
    this.#reading = this.#publishing = true;
    void this.#read(); void this.#publish();
  }
  checkRequestAdmission(header: ApplicationHeader, call: RPCCallReservation): void {
    this.#checkRequest(); this.#network.checkOutgoing(this.#channel, header, call);
  }
  requestAdmissionCurrent(header: ApplicationHeader, call: RPCCallReservation): boolean {
    if (this.#closed || !this.#started || this.#draining || this.#inputEnded || this.#finishing) return false;
    this.#network.checkOutgoing(this.#channel, header, call); return true;
  }
  #retainPayload(payload: RPCPayloadBorrow): RPCPayloadBorrow {
    const send = payload.retainSend(this.#reference!);
    let held = true;
    return Object.freeze({ bytes: payload.bytes, retainSend: payload.retainSend, release: () => {
      if (!held) return; held = false;
      try { payload.release(); } finally { send.release(); }
    } });
  }
  queueRequest(header: ApplicationHeader, completion: RPCCompletion, payload: RPCPayloadBorrow, guard?: RPCPublicationGuard, call?: RPCCallReservation): RPCNetworkTicket {
    this.#checkRequest(); const ticket = this.#network.reserveOutgoing(this.#channel, header, call);
    let retained: RPCPayloadBorrow | undefined;
    try {
      retained = this.#retainPayload(payload);
      this.#receiver!.attachCompletion(ticket, completion); this.#publisher!.addRequest(ticket, retained, guard); retained = undefined;
      this.#sendWake.signal(); return ticket;
    } catch (error) { retained?.release(); this.#receiver!.cancelUnsubmitted(ticket); throw error; }
  }
  queueResponse(ticket: RPCNetworkTicket, header: ApplicationHeader, payload: RPCPayloadBorrow, guard?: RPCPublicationGuard): void {
    this.#check(); const retained = this.#retainPayload(payload);
    try { this.#publisher!.addResponse(ticket, header, retained, guard); }
    catch (error) { retained.release(); throw error; }
    this.#sendWake.signal();
  }
  resultReadHeader(payloadBytes: number, deadlineAtMS: bigint): ApplicationHeader {
    this.#check(); return this.#receiver!.resultReadHeader(payloadBytes, deadlineAtMS);
  }
  queueResultRead(ticket: RPCNetworkTicket, payload: RPCPayloadBorrow, guard: RPCPublicationGuard): void {
    this.#check(); const header = this.#receiver!.resultReadResponse(ticket, payload.bytes.length);
    this.queueResponse(ticket, header, payload, guard);
  }
  checkIncoming(ticket: RPCNetworkTicket): void { this.#check(); this.#network.checkBinding(ticket, this.#channel, false); }
  bindOutput(ticket: RPCNetworkTicket, output: RPCOutputInterest): void { this.checkIncoming(ticket); this.#network.bindOutput(ticket, output); }
  flushOutputEvents(): void { this.#network.flushOutputEvents(); }
  belongsTo(network: RPCNetwork): boolean { this.#check(); return this.#network === network; }
  replySDK(ticket: RPCNetworkTicket, code: RPCSDKError, guard?: RPCPublicationGuard): void {
    this.#check(); this.#publisher!.replySDK(ticket, code, guard); this.#sendWake.signal();
  }
  stop(ticket: RPCNetworkTicket): void {
    this.#check(); if (!this.#network.live(ticket)) return;
    this.#publisher!.stop(ticket); this.#sendWake.signal();
  }
  nextRequest(): RPCReadyRequest | undefined { this.#check(); return this.#receiver!.nextRequest(); }
  /** Exactly one SDK dispatcher can await this channel's ready-set signal. */
  waitRequests(): Promise<void> { this.#check(); return this.#requestWake.wait(); }
  async #read(): Promise<void> {
    try {
      while (!this.#closed) {
        await this.#stream!.readInto(16384, bytes => this.#receiver!.feed(bytes), this.#abort.signal);
        if (this.#closed) break;
        this.#sendWake.signal(); this.#requestWake.signal();
        const state = this.#stream!.readState();
        if (state.stream_status === "eof") {
          this.#receiver!.end(); this.#inputEnded = true;
          this.#sendWake.signal(); this.#changed?.(); break;
        }
        if (state.stream_status === "aborted") throw new RPCProtocolError("rpc_channel_aborted");
      }
    } catch (error) { if (!this.#closed) this.#failure = error; this.close(); }
    finally { this.#reading = false; this.#stream?.releaseReader(); this.#finishChannel(); this.#collect(); }
  }
  async #publish(): Promise<void> {
    try {
      while (!this.#closed) {
        if (this.#publisher!.ready()) await this.#publisher!.publishNext();
        else if ((this.#draining || this.#inputEnded) && !this.#receiver!.pendingFragment() &&
            this.#publisher!.load() === 0 && this.#network.channelIdle(this.#channel)) {
          // FIN seals only this direction. Every accepted reply and its real
          // publisher tail has left the original network before this point.
          this.#finishing = true;
          await this.#stream!.finish({ signal: this.#abort.signal }); this.#outputEnded = true; break;
        } else await this.#sendWake.wait();
      }
    } catch (error) { if (!this.#closed) this.#failure = error; this.close(); }
    finally { this.#publishing = false; this.#finishChannel(); this.#collect(); }
  }
  drain(): void {
    if (this.#closed) return;
    this.#draining = true; this.#sendWake.signal();
  }
  #finishChannel(): void {
    if (this.#inputEnded && this.#outputEnded && !this.#reading && !this.#publishing) this.#close(false);
  }
  close(): void { this.#close(true); }
  #close(reset: boolean): void {
    if (this.#closed) return; this.#closed = true;
    this.#abort.abort(); this.#sendWake.close(); this.#requestWake.close();
    this.#receiver?.close(); this.#publisher?.close(); if (!this.#reusable) this.#position?.closeAfterUse();
    const stream = this.#stream;
    if (stream !== undefined) {
      stream.releaseDelivery();
      if (reset) void stream.reset().catch(() => undefined).finally(() => { this.#physical = stream.cleanupStatus().core_cleanup === "complete"; this.#collect(); });
      else this.#physical = stream.cleanupStatus().core_cleanup === "complete";
    }
    this.#collect(); this.#changed?.();
  }
  #collect(): void {
    if (this.#collecting || !this.#closed || this.#reading || this.#publishing || !this.#physical ||
        this.#position !== undefined && (this.#reusable ? !this.#position.available() && !this.#position.cleanupComplete() : !this.#position.cleanupComplete())) return;
    this.#collecting = true;
    try {
      this.#receiver = undefined; this.#publisher = undefined; this.#position = undefined;
      if (!this.#reusable) this.#stream?.application.close(); this.#stream?.release(); this.#stream = undefined;
      this.#reference?.release(); this.#reference = undefined;
    } finally { this.#collecting = false; }
    const changed = this.#changed; this.#changed = undefined; changed?.();
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
