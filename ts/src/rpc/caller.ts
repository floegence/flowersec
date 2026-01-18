import type { RpcError } from "../gen/flowersec/rpc/v1.gen.js";

export type RpcCaller = {
  call(typeId: number, payload: unknown, signal?: AbortSignal): Promise<{ payload: unknown; error?: RpcError }>;
  onNotify(typeId: number, handler: (payload: unknown) => void): () => void;
};

