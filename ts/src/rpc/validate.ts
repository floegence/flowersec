import type { RpcEnvelope } from "../gen/flowersec/rpc/v1.gen.js";
import { isSafeU32Number, isSafeU64Number } from "../utils/number.js";

// assertRpcEnvelope validates numeric fields that are u32/u64 in the IDL.
//
// The wire format is JSON, so JS numbers are used. For u64 we enforce the safe integer range
// to avoid silent precision loss on request/response correlation.
export function assertRpcEnvelope(v: unknown): RpcEnvelope {
  if (typeof v !== "object" || v == null) throw new Error("bad rpc envelope");
  const o = v as any;
  if (!isSafeU32Number(o.type_id)) throw new Error("bad rpc envelope: type_id");
  if (!isSafeU64Number(o.request_id)) throw new Error("bad rpc envelope: request_id");
  if (!isSafeU64Number(o.response_to)) throw new Error("bad rpc envelope: response_to");
  // payload: unknown (JSON)
  if (o.error != null) {
    if (typeof o.error !== "object" || o.error == null) throw new Error("bad rpc envelope: error");
    if (!isSafeU32Number(o.error.code)) throw new Error("bad rpc envelope: error.code");
    const msg = o.error.message;
    if (msg !== undefined && typeof msg !== "string") throw new Error("bad rpc envelope: error.message");
  }
  return o as RpcEnvelope;
}

