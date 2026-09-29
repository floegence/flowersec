import { sha256 } from "@noble/hashes/sha2.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { byteLength } from "./cbor.js";
import type { TrustedDeadline } from "./deadline.js";
import type { ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";
import type { CapturedContractRoute } from "./contractRoutes.js";

type InputState = "collecting" | "complete" | "rejected" | "aborted" | "failed" | "closed";
export interface RPCInputConfig {
  readonly runtimeBytes: bigint;
  readonly capture: boolean;
  readonly deadline?: TrustedDeadline;
  readonly contract?: ServiceContractSnapshot;
  readonly route?: CapturedContractRoute;
  /** A fixed SDK query has a separately verified trusted method binding. */
  readonly fixedRequest?: "query_contracts_request" | "read_result_request";
  readonly refusal?: RPCSDKError;
}
export function rpcInputCharge(header: ApplicationHeader, config: Pick<RPCInputConfig, "capture" | "runtimeBytes">) {
  if (header.isResponse()) throw new RPCProtocolError("rpc_input_variant");
  return rpcPayloadCharge(config.capture ? header.payloadBytes : 0, config.runtimeBytes);
}

/** A bounded complete-input gate. The SDK admission table selects capture or
 * prepaid discard before DATA; this owner never invokes an application codec
 * or handler. Known execution requests hash discarded bytes as well. */
export class RPCRequestInput {
  readonly header: ApplicationHeader;
  readonly refusal: RPCSDKError | undefined;
  readonly #deadline: TrustedDeadline | undefined;
  readonly #capture: boolean;
  readonly #verifiable: boolean;
  readonly #body: RPCPayload;
  #hash: ReturnType<typeof sha256.create> | undefined;
  #route: CapturedContractRoute | undefined;
  #next = 0;
  #state: InputState = "collecting";
  constructor(header: ApplicationHeader, config: RPCInputConfig, reference: ResourceReference) {
    rpcInputCharge(header, config);
    const { contract, fixedRequest, capture, refusal, deadline, runtimeBytes, route } = config;
    if (contract !== undefined && fixedRequest !== undefined ||
        fixedRequest !== undefined && (header.kind !== fixedRequest || header.has(1) || header.payloadBytes > 4096) ||
        contract === undefined && fixedRequest === undefined && (capture || refusal === undefined) ||
        !capture && refusal === undefined || capture && deadline === undefined || !header.has(5) || deadline !== undefined && deadline.cap > header.uint(5) ||
        route !== undefined && (route.contract !== contract || !capture)) throw new RPCProtocolError("rpc_input_binding");
    if (contract !== undefined && !contract.sameEnvironment(reference)) throw new RPCProtocolError("rpc_input_owner");
    if (capture) contract?.checkRequest(header);
    this.header = header; this.refusal = refusal; this.#capture = capture; this.#deadline = deadline;
    this.#verifiable = !header.has(1) || contract !== undefined;
    this.#body = new RPCPayload(capture ? header.payloadBytes : 0, runtimeBytes, reference);
    try {
      if (header.has(1) && contract !== undefined) { this.#hash = sha256.create(); contract.seedExecutionHash(header, this.#hash, !capture); }
      this.#route = route;
    } catch (error) { this.close(); throw error; }
  }
  get state(): InputState { return this.#state; }
  sameEnvironment(reference: ResourceReference): boolean { return this.#body.sameEnvironment(reference); }
  write(offset: number, bytes: Uint8Array): void {
    const length = byteLength(bytes);
    if (this.#state !== "collecting" || offset !== this.#next || length < 1 || length > this.header.payloadBytes - this.#next) throw new RPCProtocolError("rpc_payload_offset");
    this.#body.check(); this.#hash?.update(bytes);
    if (this.#capture) this.#body.write(offset, bytes);
    this.#next += length;
  }
  finish(): void {
    if (this.#state !== "collecting" || this.#next !== this.header.payloadBytes) throw new RPCProtocolError("rpc_input_incomplete");
    try {
      if (this.#hash !== undefined) {
        const actual = this.#hash.digest(), expected = new Uint8Array(32);
        try {
          this.header.copyBytes(4, expected);
          let difference = 0; for (let i = 0; i < 32; i++) difference |= actual[i]! ^ expected[i]!;
          if (difference !== 0) throw new RPCProtocolError("application_request_digest");
        } finally { actual.fill(0); expected.fill(0); }
      }
      this.#state = this.#verifiable ? "complete" : "rejected";
    } catch (error) { this.#state = "failed"; this.#body.close(); throw error; }
    finally { this.#hash?.destroy(); this.#hash = undefined; }
  }
  abort(offset: number): void {
    if (this.#state !== "collecting" || offset !== this.#next || offset >= this.header.payloadBytes) throw new RPCProtocolError("rpc_abort_state");
    this.#state = "aborted"; this.#hash?.destroy(); this.#hash = undefined; this.#body.close();
  }
  borrow(): RPCPayloadBorrow {
    if (this.#state !== "complete" || !this.#capture || this.refusal !== undefined) throw new RPCProtocolError("rpc_input_unavailable");
    this.#deadline!.check(); return this.#body.borrow(this.header.payloadBytes);
  }
  takeRoute(): CapturedContractRoute {
    if (this.#state !== "complete" || this.refusal !== undefined || this.#route === undefined) throw new RPCProtocolError("rpc_route_owner");
    const route = this.#route; route.check(); this.#route = undefined; return route;
  }
  checkDeadline(): void { if (this.#deadline === undefined) throw new RPCProtocolError("deadline_exceeded"); this.#deadline.check(); }
  forkDeadline(): TrustedDeadline {
    if (this.#state !== "complete" || this.#deadline === undefined) throw new RPCProtocolError("rpc_input_unavailable");
    return this.#deadline.fork(this.#deadline.cap);
  }
  close(): void {
    this.#state = "closed"; this.#hash?.destroy(); this.#hash = undefined; this.#route?.close(); this.#route = undefined; this.#body.close();
  }
  cleanupComplete(): boolean { return this.#body.cleanupComplete(); }
  toJSON(): object { return {}; }
}
