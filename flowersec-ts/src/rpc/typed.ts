import type { RpcCaller } from "./caller.js";
import { RpcCallError } from "./callError.js";

export async function callTyped<TResp>(
  rpc: RpcCaller,
  typeId: number,
  req: unknown,
  opts: Readonly<{ signal?: AbortSignal; assert?: (v: unknown) => TResp }> = {}
): Promise<TResp> {
  const resp = await rpc.call(typeId, req, opts.signal);
  if (resp.error != null) throw new RpcCallError(resp.error.code, resp.error.message, typeId);
  if (opts.assert != null) return opts.assert(resp.payload);
  return resp.payload as TResp;
}

