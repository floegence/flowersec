import type * as ContractQueryAcquisitionTypes from "./contractQueryAcquisition.js";
import type { V4ApplicationContext } from "../streamHandlers.js";
import type { ApplicationGroup } from "./applicationExecutor.js";
import type { ContractQueryAccess } from "./contractQueryAccess.js";
import type { ContractQueryAcquisitions} from "./contractQueryAcquisition.js";
import { type ContractQueryAcquisition } from "./contractQueryAcquisition.js";
import { ContractQueryClient, contractQueryClientCharges } from "./contractQueryClient.js";
import { ContractQueryCodecs, contractQueryCodecsCharges } from "./contractQueryCodecs.js";
import { ContractQueryService, contractQueryServiceCharges } from "./contractQueryService.js";
import type { ContractQueryTarget } from "./contractQuery.js";
import type { ContractRoutes } from "./contractRoutes.js";
import type { TrustedDeadline } from "./deadline.js";
import type { FixedQueryProtection } from "./fixedQueryExecutor.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import type { RPCChannelRuntime } from "./rpcChannel.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCNetwork } from "./rpcNetwork.js";
import type { RPCReadyRequest } from "./rpcReceiver.js";
import type { ServiceInputs } from "./serviceInputs.js";
import { ResourceVector, type ResourceReference, type ResourceRoot } from "./resources.js";
import { ContractRenewalProtection, type ContractQueryPreparation } from "./queryRenewalPosition.js";

/** The Session's single fixed-query share in its original RPC account.
 * Query/binding delivery bodies, the K+2 network index, channel credit/readers
 * and fragment/provider copies have their own original admission vectors. */
export function contractQuerySessionCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const costs = [new ResourceVector([1024n + runtimeBytes, 0n, 0n, 8n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    ...contractQueryCodecsCharges(runtimeBytes), ...contractQueryServiceCharges(runtimeBytes), ...contractQueryClientCharges(runtimeBytes)];
  const bytes = costs.reduce((total, charge) => total + charge.values()[0]!, 0n), limit = 512n * 1024n;
  if (bytes > limit) throw new RPCProtocolError("configuration_capacity");
  // This remainder is still protected from general RPC work, not additional
  // slots or a source for runtime allocations outside the declared vectors.
  costs.push(new ResourceVector([limit - bytes, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  return Object.freeze(costs);
}

/** Sole fixed-query assembly for an admitted Session. Construction precedes
 * any ordinary channel's positive activation. Incoming Q2, pending requests,
 * outgoing Q2 and shared codecs cannot be split into independently sized
 * per-channel services. No application handler or authorizer runs here. */
export class ContractQuerySession {
  #reference: ResourceReference | undefined;
  #remainder: ResourceReference | undefined;
  #network: RPCNetwork | undefined;
  #group: ApplicationGroup | undefined;
  #codecs: ContractQueryCodecs | undefined;
  #incoming: ContractQueryService | undefined;
  #outgoing: ContractQueryClient | undefined;
  #protection: FixedQueryProtection | undefined;
  #observer: (() => void) | undefined;
  #closed = false;
  #collecting = false;
  constructor(network: RPCNetwork, inputs: ServiceInputs, routes: ContractRoutes, access: ContractQueryAccess,
    group: ApplicationGroup, root: ResourceRoot, delivery: ReceiveDeliveryGate, deadline: TrustedDeadline,
    runtimeBytes: bigint, references: readonly ResourceReference[], prepaidProtection?: FixedQueryProtection, prepaidClient?: ContractQueryClient) {
    const costs = contractQuerySessionCharges(runtimeBytes);
    if (references.length !== costs.length || !references.every(reference => network.sameEnvironment(reference)) ||
        !group.sameEnvironment(references[0]!)) throw new RPCProtocolError("rpc_query_owner");
    this.#network = network; this.#group = group; this.#reference = references[0]!.take(costs[0]!);
    try {
      network.claimQueryAssembly(this);
      this.#remainder = references.at(-1)!.take(costs.at(-1)!);
      if (prepaidProtection !== undefined && (prepaidProtection.group !== group || prepaidProtection.direction !== 0 || prepaidProtection.closed)) throw new RPCProtocolError("rpc_query_owner");
      this.#protection = prepaidProtection ?? group.protectQueries(this.#reference);
      this.#codecs = new ContractQueryCodecs(network, runtimeBytes, references.slice(1, 6));
      this.#incoming = new ContractQueryService(network, this.#codecs, routes, access, root, deadline, runtimeBytes, references.slice(6, 15));
      if (prepaidClient !== undefined && !prepaidClient.sameEnvironment(this.#reference)) throw new RPCProtocolError("rpc_query_owner");
      this.#outgoing = prepaidClient ?? new ContractQueryClient(root, runtimeBytes, references.slice(15, 28));
      // The actual outgoing owner already holds every primary. Assembly's
      // prepaid identity aliases have served their check and can now return,
      // before those same primaries become reusable protected positions.
      if (prepaidClient !== undefined) for (const reference of references.slice(15, 28)) reference.release();
      this.#outgoing.bind(network, this.#codecs, delivery, deadline);
      this.#protection.attach(this.#incoming); inputs.installQueries(this.#incoming);
      this.#observer = root.observeAvailability(this.#reference, () => this.#collect());
      network.completeQueryAssembly(this); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("rpc_queries_closed"); this.#reference!.check(); }
  /** The channel's sole SDK dispatcher hands complete fixed inputs here. */
  accept(channel: RPCChannelRuntime, request: RPCReadyRequest): boolean {
    this.#check(); if (!channel.belongsTo(this.#network!)) throw new RPCProtocolError("rpc_query_owner");
    return this.#incoming!.accept(channel, request);
  }
  acquire(acquisitions: ContractQueryAcquisitions, channel: RPCChannelRuntime, targets: readonly ContractQueryTarget[],
    deadline: TrustedDeadline, windows: readonly bigint[], context?: V4ApplicationContext, delivery?: ContractQueryAcquisitionTypes.ContractQueryDelivery,
    renewal?: ContractRenewalProtection, preparation?: ContractQueryPreparation): ContractQueryAcquisition {
    this.#check();
    return acquisitions.acquire(this.#group!, this.#outgoing!, channel, targets, deadline, windows, context, delivery, renewal, preparation);
  }
  protectRenewal(acquisitions: ContractQueryAcquisitions, channel: RPCChannelRuntime, reference: ResourceReference): ContractRenewalProtection | undefined {
    this.#check(); if (!channel.belongsTo(this.#network!)) throw new RPCProtocolError("rpc_query_owner");
    const environment = acquisitions.protectRenewal(reference); if (environment === undefined) return;
    try {
      const session = this.#outgoing!.protectRenewal(reference);
      if (session === undefined) { environment.close(); return; }
      return new ContractRenewalProtection(environment, session);
    } catch (error) { environment.close(); throw error; }
  }
  drain(): void { this.#check(); this.#incoming!.drain(); this.#outgoing!.drain(); }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#network?.closeQueryAssembly(this);
    this.#outgoing?.close(); this.#incoming?.close(); this.#protection?.close(); this.#codecs?.close(); this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#collecting) return; this.#collecting = true;
    try {
      if (this.#incoming?.cleanupComplete() === false || this.#outgoing?.cleanupComplete() === false ||
          this.#protection?.cleanupComplete() === false || this.#codecs?.cleanupComplete() === false) return;
      this.#incoming = undefined; this.#outgoing = undefined; this.#protection = undefined; this.#codecs = undefined;
      this.#network = undefined; this.#group = undefined; this.#observer?.(); this.#observer = undefined;
      this.#remainder?.release(); this.#remainder = undefined; this.#reference?.release(); this.#reference = undefined;
    } finally { this.#collecting = false; }
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
Object.freeze(ContractQuerySession.prototype); Object.freeze(ContractQuerySession);
