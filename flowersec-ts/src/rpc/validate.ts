import type { RpcEnvelope, RpcError } from "./wire.js";
import { isSafeU32Number, isSafeU64Number } from "../utils/number.js";

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

// assertRpcEnvelope validates numeric fields that are u32/u64 in the IDL.
//
// The wire format is JSON, so JS numbers are used. For u64 we enforce the safe integer range
// to avoid silent precision loss on request/response correlation.
export function assertRpcEnvelope(v: unknown): RpcEnvelope {
  if (typeof v !== "object" || v == null || Array.isArray(v)) throw new Error("bad rpc envelope");
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.some((key) => key !== "type_id" && key !== "request_id" && key !== "response_to" && key !== "payload" && key !== "error")) {
    throw new Error("bad rpc envelope: shape");
  }
  if (!Object.prototype.hasOwnProperty.call(o, "payload")) throw new Error("bad rpc envelope: payload");
  assertRpcTypeId(o.type_id);
  if (!isSafeU64Number(o.request_id)) throw new Error("bad rpc envelope: request_id");
  if (!isSafeU64Number(o.response_to)) throw new Error("bad rpc envelope: response_to");
  if (o.request_id !== 0 && o.response_to !== 0) throw new Error("bad rpc envelope: request/response shape");
  if (o.error != null && o.response_to === 0) throw new Error("bad rpc envelope: error shape");
  if (o.error != null) assertRpcError(o.error);
  return o as unknown as RpcEnvelope;
}

export function assertRpcTypeId(value: unknown): number {
  if (!isSafeU32Number(value) || value === 0) throw new RangeError("RPC typeId must be a non-zero u32 integer");
  return value;
}

export function assertRpcError(value: unknown): RpcError {
  if (typeof value !== "object" || value == null) throw new Error("bad rpc envelope: error");
  const error = value as Record<string, unknown>;
  if (Object.keys(error).some((key) => key !== "code" && key !== "message")) {
    throw new Error("bad rpc envelope: error shape");
  }
  if (!isSafeU32Number(error.code) || error.code === 0) {
    throw new Error("bad rpc envelope: error.code");
  }
  const message = error.message;
  if (message !== undefined && typeof message !== "string") {
    throw new Error("bad rpc envelope: error.message");
  }
  if (typeof message === "string") {
    const encoded = encoder.encode(message);
    if (encoded.byteLength > 1_024 || strictDecoder.decode(encoded) !== message) {
      throw new Error("bad rpc envelope: error.message");
    }
  }
  return message === undefined ? { code: error.code } : { code: error.code, message };
}
