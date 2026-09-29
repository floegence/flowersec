import type { ApplicationHeader } from "./applicationHeader.js";
import type { ContractRoutes} from "./contractRoutes.js";
import { type CapturedContractRoute } from "./contractRoutes.js";
import type { ContractQueryService } from "./contractQueryService.js";
import type { TrustedDeadline } from "./deadline.js";
import { TimeError } from "./timeArithmetic.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCRequestInput, rpcInputCharge } from "./rpcInput.js";
import { rpcPayloadCharge } from "./rpcPayload.js";
import type { RPCIncomingAdmission } from "./rpcReceiver.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import type { RPCNetwork} from "./rpcNetwork.js";
import { type RPCNetworkTicket } from "./rpcNetwork.js";
import { ResourceError, ResourceVector, type ResourceReference, type ResourceRoot, type ResourceAccount, type ResourceOwner, type ProtectedResourceReservation } from "./resources.js";

export interface ServiceInputsConfig {
  readonly root: ResourceRoot;
  readonly accounts: readonly ResourceAccount[];
  readonly owner: ResourceOwner;
  readonly deadline: TrustedDeadline;
  readonly maxCaptureBytes: number;
  readonly runtimeBytes: bigint;
}
export function serviceInputsCharges(generalLimit: number, runtimeBytes: bigint): readonly ResourceVector[] {
  if (!Number.isSafeInteger(generalLimit) || generalLimit < 1 || generalLimit > 1024 || runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const floor = rpcPayloadCharge(0, runtimeBytes), count = generalLimit + 2;
  return [new ResourceVector([BigInt(count) * 64n + 1024n + runtimeBytes, 0n, 0n, BigInt(count + 1), 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    ...Array.from({ length: count }, () => floor)];
}

/** Concrete trusted SDK admission shared by every ordinary channel. K+2 real
 * protected discard/hash positions precede channel activation. Complete input
 * capture is a try-reservation in the same root; pressure chooses refusal and
 * never blocks the shared reader or calls application code. */
export class ServiceInputs implements RPCIncomingAdmission {
  readonly #network: RPCNetwork;
  #routes: ContractRoutes | undefined;
  #root: ResourceRoot | undefined;
  readonly #accounts: ResourceAccount[];
  readonly #owner: ResourceOwner;
  readonly #deadline: TrustedDeadline;
  readonly #maximum: number;
  readonly #runtimeBytes: bigint;
  readonly #positions: ProtectedResourceReservation[] = [];
  #reference: ResourceReference | undefined;
  #queries: ContractQueryService | undefined;
  #serial = 0n;
  #closed = false;
  constructor(network: RPCNetwork, routes: ContractRoutes, config: ServiceInputsConfig, references: readonly ResourceReference[]) {
    const { root, accounts, owner, deadline, maxCaptureBytes, runtimeBytes } = config;
    const charges = serviceInputsCharges(network.generalLimit, runtimeBytes);
    if (!Number.isSafeInteger(maxCaptureBytes) || maxCaptureBytes < 0 || maxCaptureBytes > 1048576 || accounts.length > 8 || references.length !== charges.length ||
        references.some(reference => !network.sameEnvironment(reference)) || !routes.sameEnvironment(references[0]!)) throw new RPCProtocolError("configuration_capacity");
    this.#network = network; this.#routes = routes; this.#root = root; this.#accounts = [...accounts]; this.#owner = Object.freeze({ ...owner });
    this.#deadline = deadline; this.#maximum = maxCaptureBytes; this.#runtimeBytes = runtimeBytes;
    this.#reference = references[0]!.take(charges[0]!);
    try {
      for (let i = 1; i < charges.length; i++) this.#positions.push(root.protect(references[i]!, charges[i]!));
      network.claimInputs(this);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("rpc_inputs_closed"); this.#reference!.check(); }
  installQueries(queries: ContractQueryService): void {
    this.#check();
    if (this.#queries !== undefined || !queries.belongsTo(this.#network) || !queries.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_query_owner");
    this.#queries = queries;
  }
  openInput(ticket: RPCNetworkTicket, header: ApplicationHeader): RPCRequestInput {
    this.#check(); this.#network.claimInput(this, ticket, header);
    let code: RPCSDKError = "service_contract_mismatch";
    const query = this.#network.state(ticket).query;
    if (query && this.#queries !== undefined) {
      try { return this.#queries.openInput(ticket, header); }
      catch (error) {
        if (error instanceof TimeError) code = error.code === "time_expired" || error.code === "time_cancelled" ? "deadline_exceeded" : "service_unavailable";
        else if (error instanceof RPCProtocolError && (error.code === "rpc_queries_closed" || error.code === "rpc_queries_draining")) code = "service_unavailable";
        else throw error;
      }
    }
    // Exact unary and dedicated streaming variants use the same route table.
    // Fixed SDK query/result reads are installed by their separate trusted
    // service owners; their numeric type never selects a user implementation.
    const ordinary = ["transient_unary_request", "execution_unary_request", "transient_stream_request", "execution_stream_request", "resume_request"].includes(header.kind);
    const known = ordinary ? this.#routes!.known(header)?.retain() : undefined;
    try {
      if (header.kind === "read_result_request" && this.#network.resultReadMatches(header)) {
        try {
          if (header.payloadBytes < 1 || header.payloadBytes > 1024) throw new RPCProtocolError("service_contract_mismatch");
          const deadline = this.#deadline.fork(header.uint(5) < this.#deadline.cap ? header.uint(5) : this.#deadline.cap);
          deadline.check();
          if (this.#serial === (1n << 64n) - 1n) throw new RPCProtocolError("rpc_inputs_closed");
          const reference = this.#root!.reserve({ owner: { ...this.#owner, kind: `v4_rpc_input_${++this.#serial}` }, accounts: this.#accounts,
            charge: rpcInputCharge(header, { capture: true, runtimeBytes: this.#runtimeBytes }) });
          try { return new RPCRequestInput(header, { capture: true, runtimeBytes: this.#runtimeBytes, deadline, fixedRequest: "read_result_request" }, reference); }
          finally { reference.release(); }
        } catch (error) {
          code = error instanceof ResourceError ? "resource_exhausted" : error instanceof TimeError ? "deadline_exceeded" : "service_contract_mismatch";
        }
      } else if (!ordinary && !(query && this.#queries !== undefined)) code = query ? "service_unavailable" : "service_contract_mismatch";
      if (known !== undefined) {
        let route: CapturedContractRoute | undefined;
        try {
          known.checkRequest(header);
          if (header.has(1) && this.#network.profile !== "execution") code = "service_unavailable";
          else if (header.payloadBytes > this.#maximum) code = "resource_exhausted";
          else {
            route = this.#routes!.capture(header);
            if (route === undefined || !route.registered) code = "service_unavailable";
            else {
              const deadline = this.#deadline.fork(header.uint(5) < this.#deadline.cap ? header.uint(5) : this.#deadline.cap);
              if (known.semantics === "transient") {
                const now = deadline.sample().requireInterval();
                if (header.uint(5) - now.lowerMS > known.uint(11)) throw new RPCProtocolError("deadline_exceeded");
              }
              if (this.#serial === (1n << 64n) - 1n) throw new RPCProtocolError("rpc_inputs_closed");
              const reference = this.#root!.reserve({ owner: { ...this.#owner, kind: `v4_rpc_input_${(++this.#serial).toString(16)}` },
                accounts: this.#accounts, charge: rpcInputCharge(header, { capture: true, runtimeBytes: this.#runtimeBytes }) });
              try {
                this.#check();
                const input = new RPCRequestInput(header, { capture: true, runtimeBytes: this.#runtimeBytes, deadline, contract: route.contract, route }, reference);
                route = undefined; return input;
              } finally { reference.release(); }
            }
          }
        } catch (error) {
          if (error instanceof ResourceError && error.code === "resource_exhausted") code = "resource_exhausted";
          else if (error instanceof TimeError || error instanceof RPCProtocolError && error.code === "deadline_exceeded") code = "deadline_exceeded";
          else if (error instanceof RPCProtocolError && error.code === "response_limit_unsupported") code = "response_limit_unsupported";
          else if (error instanceof RPCProtocolError && ["application_contract_variant", "application_request_limit", "service_contract_mismatch"].includes(error.code)) code = "service_contract_mismatch";
          else { this.#check(); code = "service_unavailable"; }
        } finally { route?.close(); }
      }
      this.#check();
      const position = this.#positions.find(candidate => candidate.available());
      if (position === undefined) throw new RPCProtocolError("rpc_input_floor_exhausted");
      const reference = position.checkout();
      try {
        return new RPCRequestInput(header, { capture: false, runtimeBytes: this.#runtimeBytes, refusal: code,
          ...(known === undefined ? {} : { contract: known }) }, reference);
      } finally { reference.release(); }
    } finally { known?.release(); }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const position of this.#positions) position.closeAfterUse();
    this.#routes = undefined; this.#queries = undefined; this.#root = undefined; this.#accounts.length = 0; this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#positions.some(position => !position.cleanupComplete())) return;
    this.#positions.length = 0; this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
