import { transportV4ApplicationHeaders as registry } from "../../generated/transportV4Registry.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { byteLength, type CBORDecoder } from "./cbor.js";
import type { ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";

export type RPCSDKError = keyof typeof registry.sdk_error_codes;
const sdkErrors = new Map<number, RPCSDKError>(Object.entries(registry.sdk_error_codes).map(([name, code]) => [code, name as RPCSDKError]));
export function rpcCompletionCharge(limit: number, runtimeBytes: bigint) { return rpcPayloadCharge(Math.max(limit, 256), runtimeBytes); }

/** Original full unary result reservation, established before BEGIN. A local
 * abandon keeps the same bounded late association until authenticated terminal
 * input, including validation of the fixed SDK error payload. */
export class RPCCompletion {
  readonly request: ApplicationHeader;
  readonly #limit: number;
  readonly #body: RPCPayload;
  #header: ApplicationHeader | undefined;
  #next = 0;
  #done = false;
  #abandoned = false;
  #failure: "response_aborted" | "channel_closed" | undefined;
  #sdkError: RPCSDKError | undefined;
  #wake: (() => void) | undefined;
  #observed = false;
  #contract: ServiceContractSnapshot | undefined;
  constructor(request: ApplicationHeader, limit: number, runtimeBytes: bigint, reference: ResourceReference, contract?: ServiceContractSnapshot) {
    if (request.isResponse() || !Number.isSafeInteger(limit) || limit < 0 || limit > 1048576 || request.has(8) && request.uint(8) !== BigInt(limit)) throw new RPCProtocolError("rpc_completion_limit");
    if (contract !== undefined) { contract.checkRequest(request); if (!contract.sameEnvironment(reference)) throw new RPCProtocolError("rpc_completion_owner"); }
    this.request = request; this.#limit = limit; this.#body = new RPCPayload(Math.max(limit, 256), runtimeBytes, reference);
    try { this.#contract = contract?.retain(); } catch (error) { this.#body.close(); throw error; }
  }
  sameEnvironment(reference: ResourceReference): boolean { return this.#body.sameEnvironment(reference); }
  get responseLimit(): number { return this.#limit; }
  /** One original SDK owner, never a user completion callback. It only marks
   * finite work eligible; it must not decode or dispatch from the reader. */
  observe(wake: () => void): void { if (this.#observed) throw new RPCProtocolError("rpc_completion_owner"); this.#observed = true; this.#wake = wake; if (this.#done) this.#notify(); }
  #notify(): void {
    if (this.#done) { this.#contract?.release(); this.#contract = undefined; }
    const wake = this.#wake; this.#wake = undefined; wake?.();
  }
  begin(header: ApplicationHeader): void {
    if (this.#header !== undefined || this.#done) throw new RPCProtocolError("rpc_duplicate_response");
    header.checkResponse(this.request);
    this.#contract?.checkResponse(this.request, header);
    if (header.payloadBytes > (header.isSDKError() ? 256 : this.#limit)) throw new RPCProtocolError("application_response_limit");
    this.#body.check(); this.#header = header;
  }
  write(offset: number, bytes: Uint8Array): void {
    const n = byteLength(bytes);
    if (this.#header === undefined || this.#done || offset !== this.#next || n < 1 || n > this.#header.payloadBytes - offset) throw new RPCProtocolError("rpc_payload_offset");
    // A fixed error still has to be decoded after abandon. Other late input
    // is consumed at the authenticated byte boundary without application work.
    if (!this.#abandoned || this.#header.isSDKError()) this.#body.write(offset, bytes);
    this.#next += n;
  }
  validateBody(check: (bytes: Uint8Array) => void): void {
    if (this.#header === undefined || this.#done || this.#abandoned || this.#next !== this.#header.payloadBytes) throw new RPCProtocolError("rpc_response_incomplete");
    const body = this.#body.borrow(this.#next); try { check(body.bytes); } finally { body.release(); }
  }
  finish(decoder: CBORDecoder | undefined, original: Readonly<{ requestAborted: boolean; stopSent: boolean }>): void {
    const header = this.#header;
    if (header === undefined || this.#done || this.#next !== header.payloadBytes) throw new RPCProtocolError("rpc_response_incomplete");
    if (header.isSDKError()) {
      if (decoder === undefined) throw new RPCProtocolError("rpc_error_association");
      const payload = this.#body.borrow(this.#next);
      try {
        const doc = decoder.decodeMap(payload.bytes, "ApplicationSDKError");
        try { this.#sdkError = sdkErrors.get(Number(doc.uint(doc.field(0, 0)))); }
        finally { doc.release(); }
      } finally { payload.release(); }
      if (this.#sdkError === undefined || this.#sdkError === "source_overflow" && !this.request.kind.endsWith("stream_request") ||
          this.#sdkError === "request_message_aborted" && !original.requestAborted ||
          this.#sdkError === "response_output_stopped" && !original.stopSent ||
          original.requestAborted && this.#sdkError !== "request_message_aborted") throw new RPCProtocolError("rpc_error_association");
    } else if (original.requestAborted) throw new RPCProtocolError("rpc_error_association");
    this.#done = true; if (this.#abandoned) this.#body.close(); this.#notify();
  }
  abort(): void {
    if (this.#header === undefined || this.#done || this.#next >= this.#header.payloadBytes) throw new RPCProtocolError("rpc_abort_state");
    this.#done = true; this.#failure = "response_aborted"; this.#body.close(); this.#notify();
  }
  abandon(): void { this.#abandoned = true; if (this.#done) this.#body.close(); }
  progress(): Readonly<{ done: boolean; abandoned: boolean; failure?: "response_aborted" | "channel_closed"; sdkError?: RPCSDKError; header?: ApplicationHeader }> {
    return { done: this.#done, abandoned: this.#abandoned, ...(this.#failure === undefined ? {} : { failure: this.#failure }),
      ...(this.#sdkError === undefined ? {} : { sdkError: this.#sdkError }), ...(this.#header === undefined ? {} : { header: this.#header }) };
  }
  borrow(): RPCPayloadBorrow {
    if (!this.#done || this.#abandoned || this.#failure !== undefined || this.#sdkError !== undefined) throw new RPCProtocolError("rpc_result_unavailable");
    return this.#body.borrow(this.#next);
  }
  channelClosed(): void {
    if (this.#done) return; this.#done = true; this.#failure = "channel_closed"; this.#body.close(); this.#notify();
  }
  close(): void { this.#abandoned = true; this.#done = true; this.#body.close(); this.#notify(); }
  cleanupComplete(): boolean { return this.#body.cleanupComplete(); }
  toJSON(): object { return {}; }
}
