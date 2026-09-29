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
  readonly channelGroup: ApplicationGroup;
  readonly notificationGroups: readonly ApplicationGroup[];
  readonly queries: FixedQueryProtection;
  readonly outgoing: ContractQueryClient;
}

export function closeRPCApplicationServices(services: RPCApplicationServices): void {
  services.outgoing.close(); services.queries.close(); services.completion.close();
  for (const group of services.notificationGroups) group.close();
  services.channelGroup.close(); services.group.close();
}

export function reserveRPCApplicationServices(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner,
  runtimeBytes: bigint, plan: RPCApplicationPlan, consume: (indices: readonly number[], build: (references: readonly ResourceReference[]) => void) => void,
  queryReference: ResourceReference): RPCApplicationServices {
  let group: ApplicationGroup | undefined, completion: CompletionPosition | undefined, channelGroup: ApplicationGroup | undefined,
    queries: FixedQueryProtection | undefined, outgoing: ContractQueryClient | undefined;
  const notificationGroups: ApplicationGroup[] = [];
  try {
    consume([1], ([reference]) => { group = applicationGroup(root, accounts, { ...owner, kind: "rpc_application" }, runtimeBytes, true, reference); });
    consume([6], ([reference]) => { completion = group!.protectCompletion(runtimeBytes, reference!); });
    queries = group!.protectQueries(queryReference);
    consume([plan.channel + 2], ([reference]) => { channelGroup = applicationGroup(root, accounts, { ...owner, kind: "rpc_first_channel" }, runtimeBytes, true, reference); });
    const width = notifyChannelCharges(runtimeBytes).length;
    for (let position = 0; position < 2; position++) consume([plan.notify + position * width + 2], ([reference]) => {
      notificationGroups.push(applicationGroup(root, accounts, { ...owner, kind: `notify_channel_${position}` }, runtimeBytes, false, reference));
    });
    consume(Array.from({ length: 13 }, (_, index) => plan.queries + 15 + index), references => { outgoing = new ContractQueryClient(root, runtimeBytes, references); });
    return Object.freeze({ outgoing: outgoing!, group: group!, completion: completion!, queries, channelGroup: channelGroup!, notificationGroups: Object.freeze(notificationGroups) });
  } catch (error) {
    outgoing?.close(); queries?.close(); completion?.close(); for (const current of notificationGroups) current.close(); channelGroup?.close(); group?.close(); throw error;
  }
}
