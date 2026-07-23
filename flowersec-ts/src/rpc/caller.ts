import type { RpcError } from "./wire.js";

export type RpcCaller = {
  call(typeId: number, payload: unknown, signal?: AbortSignal): Promise<{ payload: unknown; error?: RpcError }>;
  onNotify(typeId: number, handler: (payload: unknown) => void): () => void;
};
