import { byteLength, byteSlice, type CBORDocument } from "./cbor.js";

export type ContractRangeField = "history_retention_ms" | "result_retention_ms" | "min_response_limit_bytes" | "max_response_bytes";
export interface ContractRange { readonly field: ContractRangeField; readonly lower: bigint; readonly upper: bigint }
export type ContractAcceptance = { readonly mode: "exact" } | { readonly mode: "bounded"; readonly ranges: readonly ContractRange[] };
export class ContractPolicyError extends Error {
  readonly code = "contract_policy_rejected";
  constructor() { super("contract_policy_rejected"); this.name = "ContractPolicyError"; }
}
function reject(): never { throw new ContractPolicyError(); }
function fieldID(field: ContractRangeField): number {
  switch (field) {
    case "history_retention_ms": return 14;
    case "result_retention_ms": return 15;
    case "min_response_limit_bytes": return 9;
    case "max_response_bytes": return 10;
    default: return reject();
  }
}
function validatePolicy(policy: ContractAcceptance): void {
  if (policy.mode === "exact") {
    if ("ranges" in policy) reject();
    return;
  }
  if (policy.mode !== "bounded" || !Array.isArray(policy.ranges) || policy.ranges.length < 1 || policy.ranges.length > 4) reject();
  for (let j = 0; j < policy.ranges.length; j++) {
    const range = policy.ranges[j]!, id = fieldID(range.field), minimum = id >= 14 ? 1n : 0n, maximum = id >= 14 ? 0xffffffffffffffffn : 1048576n;
    if (typeof range.lower !== "bigint" || typeof range.upper !== "bigint" || range.lower < minimum || range.lower > range.upper || range.upper > maximum) reject();
    for (let k = 0; k < j; k++) if (policy.ranges[k]!.field === range.field) reject();
  }
}

// The original binding charges its fixed descriptor/runtime storage before
// capture. No callback, arbitrary field path, or caller-owned array is retained.
export function captureContractAcceptance(policy: ContractAcceptance): ContractAcceptance {
  validatePolicy(policy);
  if (policy.mode === "exact") return Object.freeze({ mode: "exact" });
  const ranges = policy.ranges.map(({ field, lower, upper }) => Object.freeze({ field, lower, upper }));
  return Object.freeze({ mode: "bounded", ranges: Object.freeze(ranges) });
}

const immutableShape = new Set([0, 1, 2, 3, 4, 5, 6, 7, 20, 21, 22, 27]);

// Both documents must be exclusive schema-validated ServiceContract owners.
// The caller supplies 512 already charged scratch bytes; comparison neither
// copies whole contracts nor retains a third snapshot. This is a semantic gate,
// not authentication, Offer readiness or a resource/install capability.
export type ContractPolicyDocument = Pick<CBORDocument, "schema" | "uint" | "field" | "encodedSize" | "copyRange">;
export function checkContractAcceptance(candidate: ContractPolicyDocument, current: ContractPolicyDocument | undefined,
  policy: ContractAcceptance, scratch: Uint8Array, explicitUpdate = false): void {
  validatePolicy(policy);
  if (candidate.schema() !== "ServiceContract" || current !== undefined && current.schema() !== "ServiceContract" || byteLength(scratch) < 512) reject();
  const shape = candidate.uint(candidate.field(0, 2));
  if (policy.mode === "bounded") for (const range of policy.ranges) {
    const id = fieldID(range.field), node = candidate.field(0, id);
    if (node < 0 || (id === 9 || id === 10) && shape === 2n) reject();
    const n = candidate.uint(node);
    if (n < range.lower || n > range.upper) reject();
    if (current !== undefined) {
      const old = current.field(0, id);
      if (old < 0) reject();
      const oldValue = current.uint(old);
      if (oldValue < range.lower || oldValue > range.upper) reject();
    }
  }
  if (current === undefined) return;
  const left = byteSlice(scratch, 0, 256), right = byteSlice(scratch, 256, 512);
  for (let id = 0; id < 29; id++) {
    if (policy.mode === "exact" && explicitUpdate && !immutableShape.has(id)) continue;
    if (policy.mode === "bounded" && policy.ranges.some(range => fieldID(range.field) === id)) continue;
    const a = current.field(0, id), b = candidate.field(0, id);
    if (a < 0 || b < 0) { if (a !== b) reject(); continue; }
    const size = current.encodedSize(a);
    if (size !== candidate.encodedSize(b)) reject();
    for (let offset = 0; offset < size; offset += 256) {
      const length = Math.min(256, size - offset);
      current.copyRange(a, offset, byteSlice(left, 0, length));
      candidate.copyRange(b, offset, byteSlice(right, 0, length));
      for (let j = 0; j < length; j++) if (left[j] !== right[j]) reject();
    }
  }
}
