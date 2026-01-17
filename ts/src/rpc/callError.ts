// RpcCallError represents an RPC-layer error returned in the wire envelope.
export class RpcCallError extends Error {
  readonly code: number;
  readonly typeId: number;

  constructor(code: number, message?: string, typeId?: number) {
    super(message ?? "rpc error");
    this.name = "RpcCallError";
    this.code = code >>> 0;
    this.typeId = (typeId ?? 0) >>> 0;
  }
}

