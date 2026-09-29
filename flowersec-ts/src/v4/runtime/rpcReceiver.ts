import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge, type ApplicationHeader, type ApplicationMessageKind } from "./applicationHeader.js";
import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge } from "./cbor.js";
import type { RPCCompletion} from "./rpcCompletion.js";
import { type RPCSDKError } from "./rpcCompletion.js";
import { RPCFragmentParser, RPCProtocolError, rpcFragmentParserCharge } from "./rpcFragment.js";
import type { RPCRequestInput } from "./rpcInput.js";
import type { RPCNetwork} from "./rpcNetwork.js";
import { type RPCChannel, type RPCNetworkTicket, type RPCReceivedPart } from "./rpcNetwork.js";
import { ResourceVector, type ResourceReference } from "./resources.js";

/** Implemented by the SDK's admitted service table, never a user callback.
 * This synchronous gate returns complete capture or prepaid hash/discard
 * ownership and cannot wait for a handler, output or another resource pool. */
export interface RPCIncomingAdmission {
  openInput(ticket: RPCNetworkTicket, header: ApplicationHeader): RPCRequestInput;
}
function errorConfig(runtimeBytes: bigint) { return { bytes: 256, nodes: 8, textBytes: 0, arrayItems: 1, runtimeBytes }; }
export function rpcReceiverCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return [new ResourceVector([2048n + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]),
    rpcFragmentParserCharge(runtimeBytes), applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes), cborDecoderCharge(errorConfig(runtimeBytes))];
}
interface InputEntry { readonly ticket: RPCNetworkTicket; input: RPCRequestInput | undefined; ready: boolean; refusal: RPCSDKError | undefined }
export interface RPCReadyRequest { readonly ticket: RPCNetworkTicket; readonly input?: RPCRequestInput; readonly refusal?: RPCSDKError }

/** One reader per admitted channel. All live descriptors consume the original
 * Session network positions; there is no independent channel-sized result
 * table, unbounded work queue, DATA buffer or completed-serial history. */
export class RPCReceiver {
  readonly #network: RPCNetwork;
  readonly #channel: RPCChannel;
  readonly #admission: RPCIncomingAdmission;
  #reference: ResourceReference | undefined;
  #parser: RPCFragmentParser | undefined;
  #codec: ApplicationHeaderCodec | undefined;
  #errors: CBORDecoder | undefined;
  readonly #inputs = new Map<RPCNetworkTicket, InputEntry>();
  readonly #completions = new Map<RPCNetworkTicket, RPCCompletion>();
  #failure: unknown;
  #closed = false;
  #feeding = false;
  constructor(network: RPCNetwork, channel: RPCChannel, admission: RPCIncomingAdmission, runtimeBytes: bigint, references: readonly ResourceReference[]) {
    const charges = rpcReceiverCharges(runtimeBytes);
    if (references.length !== charges.length || references.some(reference => !network.sameEnvironment(reference))) throw new RPCProtocolError("rpc_receiver_owner");
    this.#network = network; this.#channel = channel; this.#admission = admission;
    this.#reference = references[0]!.take(charges[0]!);
    try { network.claimReader(channel, this); }
    catch (error) { this.#reference.release(); this.#reference = undefined; throw error; }
    try {
      this.#parser = new RPCFragmentParser(runtimeBytes, references[1]!);
      this.#codec = new ApplicationHeaderCodec(runtimeBytes, references[2]!, references[3]!);
      this.#errors = new CBORDecoder(errorConfig(runtimeBytes), references[4]!);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void {
    if (this.#failure !== undefined) throw this.#failure;
    if (this.#closed) throw new RPCProtocolError("rpc_receiver_closed"); this.#reference!.check();
  }
  attachCompletion(ticket: RPCNetworkTicket, completion: RPCCompletion): void {
    this.#check(); this.#network.checkBinding(ticket, this.#channel, true);
    if (this.#completions.has(ticket) || completion.request !== this.#network.request(ticket) ||
        !completion.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_completion_owner");
    this.#completions.set(ticket, completion);
  }
  /** Only a request canceled before its first BEGIN byte can detach here. */
  cancelUnsubmitted(ticket: RPCNetworkTicket): void {
    this.#check(); this.#network.checkBinding(ticket, this.#channel, true);
    if (this.#network.state(ticket).requestSerial !== 0n) throw new RPCProtocolError("rpc_request_submitted");
    this.#completions.get(ticket)?.close(); this.#completions.delete(ticket); this.#network.release(ticket);
  }
  abandon(ticket: RPCNetworkTicket): void {
    this.#check(); const completion = this.#completions.get(ticket);
    if (completion === undefined) throw new RPCProtocolError("rpc_completion_owner");
    this.#network.abandon(ticket); completion.abandon();
  }
  sdkResponse(ticket: RPCNetworkTicket, payloadBytes: number): ApplicationHeader {
    this.#check(); this.#network.checkBinding(ticket, this.#channel, false);
    const request = this.#network.request(ticket);
    return this.#codec!.response(request, request.kind.replace(/_request$/u, "_sdk_error") as ApplicationMessageKind, payloadBytes);
  }
  resultReadHeader(payloadBytes: number, deadlineAtMS: bigint): ApplicationHeader {
    this.#check(); return this.#network.resultReadHeader(this.#codec!, payloadBytes, deadlineAtMS);
  }
  resultReadResponse(ticket: RPCNetworkTicket, payloadBytes: number): ApplicationHeader {
    this.#check(); this.#network.checkBinding(ticket, this.#channel, false);
    const request = this.#network.request(ticket);
    if (!this.#network.resultReadMatches(request)) throw new RPCProtocolError("rpc_result_read_binding");
    return this.#codec!.response(request, "read_result_response", payloadBytes);
  }
  feed(bytes: Uint8Array): number {
    this.#check(); if (this.#feeding) throw new RPCProtocolError("rpc_reader_busy");
    this.#feeding = true; let consumed = 0;
    try {
      while (consumed < byteLength(bytes)) {
        const parsed = this.#parser!.next(byteSlice(bytes, consumed, byteLength(bytes)));
        if (parsed.consumed === 0) throw new RPCProtocolError("rpc_parser_progress");
        consumed += parsed.consumed;
        if (parsed.part === undefined) continue;
        const header = parsed.part.fragment.kind === 0 ? this.#codec!.decode(parsed.part.fragment.header!) : undefined;
        const part = this.#network.receive(this.#channel, parsed.part, header);
        if (part !== undefined) this.#accept(part);
      }
      return consumed;
    } catch (error) { this.#failure = error; this.close(); throw error; }
    finally { this.#feeding = false; this.#network.flushOutputEvents(); }
  }
  #accept(part: RPCReceivedPart): void {
    const { ticket } = part;
    if (part.kind === "stop_output") return; // The original publisher observes the same slot's monotonic intent.
    if (part.response) {
      const completion = this.#completions.get(ticket);
      if (completion === undefined) throw new RPCProtocolError("rpc_completion_owner");
      if (part.kind === "begin") completion.begin(part.header!);
      else if (part.kind === "data") completion.write(this.#network.state(ticket).responseOffset - byteLength(part.payload!), part.payload!);
      else completion.abort();
      if (part.complete) {
        if (part.kind !== "abort") completion.finish(this.#errors!, this.#network.state(ticket));
        // This same synchronous turn revokes unsubmitted stop eligibility.
        // An already accepted marker retains only its physical publication tail.
        this.#completions.delete(ticket); this.#network.release(ticket);
      }
      return;
    }
    if (part.kind === "begin") {
      const input = this.#admission.openInput(ticket, part.header!);
      try {
        this.#network.checkBinding(ticket, this.#channel, false);
        if (input.header !== part.header || input.state !== "collecting" || !input.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_input_owner");
        this.#inputs.set(ticket, { ticket, input, ready: false, refusal: undefined });
      } catch (error) { input.close(); throw error; }
    }
    const entry = this.#inputs.get(ticket);
    if (entry?.input === undefined || entry.ready) throw new RPCProtocolError("rpc_input_owner");
    if (part.kind === "data") entry.input.write(this.#network.state(ticket).requestOffset - byteLength(part.payload!), part.payload!);
    if (!part.complete) return;
    if (part.kind === "abort") {
      entry.input.abort(this.#network.state(ticket).requestOffset); entry.input.close(); entry.input = undefined;
      entry.refusal = "request_message_aborted";
    } else {
      entry.input.finish(); this.#network.inputComplete(ticket, entry.input.state === "complete");
      entry.refusal = entry.input.refusal;
      if (entry.refusal === undefined) {
        try { entry.input.checkDeadline(); } catch { entry.refusal = "deadline_exceeded"; }
      }
      if (entry.refusal !== undefined) { entry.input.close(); entry.input = undefined; }
    }
    entry.ready = true;
  }
  /** Transfers one verified request or bounded refusal to the SDK dispatcher.
   * Its network ReplySlot remains occupied until the original response ends. */
  nextRequest(): RPCReadyRequest | undefined {
    this.#check();
    for (const [ticket, entry] of this.#inputs) {
      if (!entry.ready) continue;
      this.#inputs.delete(ticket);
      return { ticket, ...(entry.input === undefined ? {} : { input: entry.input }), ...(entry.refusal === undefined ? {} : { refusal: entry.refusal }) };
    }
    return undefined;
  }
  pendingFragment(): boolean { return !this.#closed && this.#parser!.pending(); }
  end(): void {
    this.#check();
    try {
      this.#parser!.end();
      if (this.#completions.size !== 0) throw new RPCProtocolError("rpc_message_truncated");
      for (const entry of this.#inputs.values()) if (!entry.ready) throw new RPCProtocolError("rpc_message_truncated");
    } catch (error) { this.#failure = error; this.close(); throw error; }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const entry of this.#inputs.values()) entry.input?.close(); this.#inputs.clear();
    for (const completion of this.#completions.values()) completion.channelClosed(); this.#completions.clear();
    this.#network.closeChannel(this.#channel);
    this.#parser?.close(); this.#parser = undefined; this.#codec?.close(); this.#codec = undefined; this.#errors?.close(); this.#errors = undefined;
    this.#reference?.release(); this.#reference = undefined;
    this.#network.flushOutputEvents();
  }
}
