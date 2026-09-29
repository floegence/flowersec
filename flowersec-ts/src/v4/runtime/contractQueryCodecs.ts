import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge } from "./applicationHeader.js";
import { ContractQueryCodec, contractQueryCodecCharges } from "./contractQuery.js";
import type { RPCNetwork } from "./rpcNetwork.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { ResourceVector, type ResourceReference } from "./resources.js";

export function contractQueryCodecsCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return [new ResourceVector([512n + runtimeBytes, 0n, 0n, 3n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    ...contractQueryCodecCharges(runtimeBytes), applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes)];
}
export interface ContractQueryCodecLease {
  readonly targets: ContractQueryCodec;
  readonly headers: ApplicationHeaderCodec;
  release(): void;
}

/** One synchronous target/header scratch set for both directions of one
 * Session. It retains no response or channel data. Each direction claims once;
 * close stops new claims, while original users keep the exact backing alive. */
export class ContractQueryCodecs {
  #network: RPCNetwork | undefined;
  #reference: ResourceReference | undefined;
  #targets: ContractQueryCodec | undefined;
  #headers: ApplicationHeaderCodec | undefined;
  readonly #claimed = [false, false];
  #users = 0;
  #closed = false;
  constructor(network: RPCNetwork, runtimeBytes: bigint, references: readonly ResourceReference[]) {
    const costs = contractQueryCodecsCharges(runtimeBytes);
    if (references.length !== costs.length || !references.every(reference => network.sameEnvironment(reference))) throw new RPCProtocolError("rpc_query_owner");
    this.#network = network; this.#reference = references[0]!.take(costs[0]!);
    try {
      this.#targets = new ContractQueryCodec(runtimeBytes, references.slice(1, 3));
      this.#headers = new ApplicationHeaderCodec(runtimeBytes, references[3]!, references[4]!);
      network.claimQueryCodecs(this); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  claim(network: RPCNetwork, direction: 0 | 1, reference: ResourceReference): ContractQueryCodecLease {
    if (this.#closed || network !== this.#network || direction !== 0 && direction !== 1 || this.#claimed[direction] ||
        !this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("rpc_query_owner");
    this.#reference!.check(); this.#claimed[direction] = true; this.#users++;
    let released = false;
    return Object.freeze({ targets: this.#targets!, headers: this.#headers!, release: () => {
      if (released) return; released = true; this.#users--; this.#collect();
    } });
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#collect(); }
  #collect(): void {
    if (!this.#closed || this.#users !== 0) return;
    this.#targets?.close(); this.#targets = undefined; this.#headers?.close(); this.#headers = undefined;
    this.#network = undefined; this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
Object.freeze(ContractQueryCodecs.prototype); Object.freeze(ContractQueryCodecs);
