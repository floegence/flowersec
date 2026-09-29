import type { V4StreamOwner } from "../public.js";
import type { ResourceReference } from "./resources.js";
import type { MessageStreamAdapterOwner, StreamAdapterProfile } from "./streamAdapter.js";
import type { ReliableWriteRequest } from "./writeRequest.js";

/** SDK capability installed only by the original authenticated Stream. A
 * public Write implementation cannot claim all-or-zero fragment admission. */
export interface RPCStreamOwner extends MessageStreamAdapterOwner {
  unused(): boolean;
  prepareFragment(bytes: Uint8Array, reference: ResourceReference): ReliableWriteRequest;
}
const owners = new WeakMap<V4StreamOwner, (profile: StreamAdapterProfile) => RPCStreamOwner>();
export function registerRPCStream(stream: V4StreamOwner, acquire: (profile: StreamAdapterProfile) => RPCStreamOwner): void {
  if (owners.has(stream)) throw new Error("stream_owner"); owners.set(stream, acquire);
}
export function acquireRPCStream(stream: V4StreamOwner, profile: StreamAdapterProfile): RPCStreamOwner {
  const acquire = owners.get(stream); if (acquire === undefined) throw new Error("stream_owner");
  return acquire(profile);
}
