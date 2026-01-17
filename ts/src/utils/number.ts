// isSafeU64Number checks whether v is a JSON number that can safely represent a u64 in JS.
// Values must be integers in [0, Number.MAX_SAFE_INTEGER].
export function isSafeU64Number(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= Number.MAX_SAFE_INTEGER;
}

// isSafeU32Number checks whether v is a JSON number that can safely represent a u32 in JS.
export function isSafeU32Number(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff;
}

