import type { ApplicationHeader } from "./applicationHeader.js";
import { byteSlice } from "./cbor.js";
import type { ContractQueryTargets} from "./contractQuery.js";
import { contractQueryRequestBytes } from "./contractQuery.js";
import type { TrustedDeadline } from "./deadline.js";
import type { RPCChannelRuntime } from "./rpcChannel.js";
import { RPCCompletion, rpcCompletionCharge } from "./rpcCompletion.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCNetworkTicket } from "./rpcNetwork.js";
import { RPCPayload, rpcPayloadCharge } from "./rpcPayload.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";

export function contractQueryExchangeCharges(request: ContractQueryTargets, runtimeBytes: bigint): readonly ResourceVector[] {
  return contractQueryExchangeCapacityCharges(request.count, runtimeBytes);
}
export function contractQueryExchangeCapacityCharges(count: number, runtimeBytes: bigint): readonly ResourceVector[] {
  if (!Number.isSafeInteger(count) || count < 1 || count > 8 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return [new ResourceVector([2048n + runtimeBytes, 0n, 0n, 8n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]),
    rpcPayloadCharge(contractQueryRequestBytes, runtimeBytes), rpcCompletionCharge(count * 9216, runtimeBytes)];
}

/** One original outgoing fixed read. The request bytes, full completion and
 * immutable targets originate here together. A decoder cannot replace targets
 * with a different same-length request, or derive known bodies from digests.
 * The containing acquisition owner supplies Q2, tasks, timer, delivery copies
 * and all references atomically before submitting this exchange. */
export class ContractQueryExchange implements RPCPublicationGuard {
  #reference: ResourceReference | undefined;
  #targets: ContractQueryTargets | undefined;
  #payload: RPCPayload | undefined;
  #completion: RPCCompletion | undefined;
  #channel: RPCChannelRuntime | undefined;
  #ticket: RPCNetworkTicket | undefined;
  readonly #deadline: TrustedDeadline;
  #submitted = false;
  #responseClaimed = false;
  #closed = false;
  #working = false;
  #wake: (() => void) | undefined;
  #source: RPCPublicationGuard | undefined;
  readonly header: ApplicationHeader;
  constructor(request: ContractQueryTargets, header: ApplicationHeader, deadline: TrustedDeadline,
    runtimeBytes: bigint, references: readonly ResourceReference[], source?: RPCPublicationGuard) {
    const costs = contractQueryExchangeCharges(request, runtimeBytes);
    if (!request.local || header.kind !== "query_contracts_request" || header.payloadBytes !== request.encodedBytes || header.uint(5) !== deadline.cap ||
        references.length !== costs.length || !references.every(ref => request.sameEnvironment(ref))) throw new RPCProtocolError("query_request_binding");
    this.header = header; this.#deadline = deadline; this.#source = source;
    this.#reference = references[0]!.take(costs[0]!);
    let scratch: Uint8Array | undefined;
    try {
      this.#targets = request.retain();
      this.#payload = new RPCPayload(contractQueryRequestBytes, runtimeBytes, references[1]!);
      this.#completion = new RPCCompletion(header, request.responseBytes, runtimeBytes, references[2]!);
      scratch = new Uint8Array(contractQueryRequestBytes);
      const length = request.copyEncoded(scratch); this.#payload.write(0, byteSlice(scratch, 0, length));
      Object.freeze(this);
    } catch (error) { this.close(); throw error; }
    finally { scratch?.fill(0); }
  }
  #check(): void {
    if (this.#closed) throw new RPCProtocolError("query_closed");
    if (this.#working) throw new RPCProtocolError("query_busy"); this.#reference!.check();
  }
  #checkDeadline(): void {
    this.#check(); this.#working = true;
    try { this.#deadline.check(); this.#source?.check(); }
    finally { this.#working = false; this.#collect(); }
    this.#check();
  }
  submit(channel: RPCChannelRuntime): RPCNetworkTicket {
    this.#checkDeadline(); if (this.#submitted) throw new RPCProtocolError("query_already_submitted");
    const borrow = this.#payload!.borrow(this.header.payloadBytes);
    try {
      const ticket = channel.queueRequest(this.header, this.#completion!, borrow, this);
      this.#ticket = ticket; this.#channel = channel; this.#submitted = true; return ticket;
    } catch (error) { borrow.release(); this.close(); throw error; }
  }
  progress(): ReturnType<RPCCompletion["progress"]> { this.#check(); return this.#completion!.progress(); }
  observe(wake: () => void): void {
    this.#check(); if (this.#wake !== undefined) throw new RPCProtocolError("rpc_query_consumer");
    this.#wake = wake; this.#completion!.observe(wake);
  }
  failResponse(): void { this.#channel?.close(); this.close(); }
  /** One complete decode attempt, through the original response owner. No
   * result/CompletionReservation is manufactured by this transition. */
  claimResponse(): Readonly<{ targets: ContractQueryTargets; completion: RPCCompletion }> {
    this.#checkDeadline();
    const completion = this.#completion!, progress = completion.progress();
    if (!this.#submitted || this.#responseClaimed || !progress.done || progress.abandoned || progress.failure !== undefined ||
        progress.sdkError !== undefined || progress.header?.kind !== "query_contracts_response") throw new RPCProtocolError("query_result_unavailable");
    this.#responseClaimed = true;
    return Object.freeze({ targets: this.#targets!, completion });
  }
  checkDelivery(): void { this.#checkDeadline(); }
  check(): void { this.#checkDeadline(); }
  current(): boolean { return this.#submitted && !this.#closed && this.#reference !== undefined && this.#source?.current() !== false; }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    if (this.#submitted) {
      // The existing channel alone decides pre-BEGIN cancel versus ABORT/
      // STOP_OUTPUT. Late input still owns its original full completion.
      try { this.#channel?.stop(this.#ticket!); } catch { /* A closed channel already owns terminal cleanup. */ }
      this.#completion?.abandon();
    } else this.#completion?.close();
    this.#payload?.close(); this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#working || this.#payload?.cleanupComplete() === false || this.#completion?.cleanupComplete() === false) return;
    this.#targets?.release(); this.#targets = undefined; this.#payload = undefined; this.#completion = undefined;
    this.#channel = undefined; this.#ticket = undefined; this.#reference?.release(); this.#reference = undefined;
    this.#wake = undefined; this.#source = undefined;
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
  toJSON(): object { return {}; }
}
Object.freeze(ContractQueryExchange.prototype); Object.freeze(ContractQueryExchange);
