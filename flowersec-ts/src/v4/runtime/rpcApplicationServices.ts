import { applicationGroup, type ApplicationGroup, type CompletionPosition } from "./applicationExecutor.js";
import type { FixedQueryProtection } from "./fixedQueryExecutor.js";
import type { RPCApplicationPlan } from "./rpcApplication.js";
import { ContractQueryClient } from "./contractQueryClient.js";
import { notifyChannelCharges } from "./notifyChannel.js";
import type { ResourceAccount, ResourceOwner, ResourceReference, ResourceRoot } from "./resources.js";

/** The original candidate groups and protected service positions. Reservation
 * does not enter application code or attach query work. */
export interface RPCApplicationServices {
  readonly group: ApplicationGroup;
  readonly completion: CompletionPosition;
  readonly channelGroups: readonly ApplicationGroup[];
  readonly notificationGroups: readonly ApplicationGroup[];
  readonly queries: FixedQueryProtection;
  readonly outgoing: ContractQueryClient;
  readonly queryResponses: readonly (readonly [ResourceReference, ResourceReference])[];
}

export function closeRPCApplicationServices(services: RPCApplicationServices): void {
  services.outgoing.close(); services.queries.close(); services.completion.close();
  for (const response of services.queryResponses) for (const reference of response) reference.release();
  for (const group of services.notificationGroups) group.close();
  for (const group of services.channelGroups) group.close(); services.group.close();
}

export function reserveRPCApplicationServices(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner,
  runtimeBytes: bigint, plan: RPCApplicationPlan, consume: (indices: readonly number[], build: (references: readonly ResourceReference[]) => void) => void,
  queryReference: ResourceReference): RPCApplicationServices {
  let group: ApplicationGroup | undefined, completion: CompletionPosition | undefined,
    queries: FixedQueryProtection | undefined, outgoing: ContractQueryClient | undefined;
  const notificationGroups: ApplicationGroup[] = [], channelGroups: ApplicationGroup[] = [];
  const queryResponses: [ResourceReference, ResourceReference][] = [];
  try {
    consume([1], ([reference]) => { group = applicationGroup(root, accounts, { ...owner, kind: "rpc_application" }, runtimeBytes, true, reference); });
    if (plan.resultRead > plan.management) group!.enableManagement();
    consume([6], ([reference]) => { completion = group!.protectCompletion(runtimeBytes, reference!); });
    queries = group!.protectQueries(queryReference);
    for (let position = 0; position < 8; position++) consume([plan.channel + position * plan.channelWidth + 2], ([reference]) => {
      channelGroups.push(applicationGroup(root, accounts, { ...owner, kind: `rpc_channel_${position}` }, runtimeBytes, true, reference));
    });
    const width = notifyChannelCharges(runtimeBytes).length;
    for (let position = 0; position < 2; position++) consume([plan.notify + position * width + 2], ([reference]) => {
      notificationGroups.push(applicationGroup(root, accounts, { ...owner, kind: `notify_channel_${position}` }, runtimeBytes, false, reference));
    });
    consume(Array.from({ length: 13 }, (_, index) => plan.queries + 15 + index), references => { outgoing = new ContractQueryClient(root, runtimeBytes, references); });
    for (const index of [11, 14]) consume([plan.queries + index], ([reference]) => {
      const primary = reference!.take(plan.charges[plan.queries + index]!);
      try { queryResponses.push([primary, primary.borrow()]); } catch (error) { primary.release(); throw error; }
    });
    return Object.freeze({ outgoing: outgoing!, group: group!, completion: completion!, queries, queryResponses: Object.freeze(queryResponses), channelGroups: Object.freeze(channelGroups), notificationGroups: Object.freeze(notificationGroups) });
  } catch (error) {
    outgoing?.close(); queries?.close(); completion?.close(); for (const response of queryResponses) for (const reference of response) reference.release();
    for (const current of [...notificationGroups, ...channelGroups]) current.close(); group?.close(); throw error;
  }
}
