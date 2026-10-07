/** Private provider facts. Neither signal is an authenticated terminal proof. */
export class NativeDirectionFailure extends Error {
  constructor(readonly code: "normal_drained" | "direction_reset") {
    super(code); this.name = "NativeDirectionFailure";
  }
}

// Only original provider calls may record this fact. Redacted public errors
// carry the same private fact without retaining the provider or raw exception.
const connectionFailures = new WeakSet<object>();
export function observeNativeConnectionFailure(error: unknown): void {
  try { if (error instanceof Error && error.message === "carrier_failed") connectionFailures.add(error); }
  catch { /* Provider exception getters cannot manufacture a connection fact. */ }
}
export function originalNativeConnectionFailure(error: unknown): boolean {
  return error !== null && typeof error === "object" && connectionFailures.has(error);
}
export function retainNativeConnectionFailure<T extends object>(projection: T, original: unknown): T {
  if (originalNativeConnectionFailure(original)) connectionFailures.add(projection);
  return projection;
}

/** An unexpected EOF is observed at the original connection read boundary. */
export function nativeConnectionEnded<T extends object>(failure: T): T {
  connectionFailures.add(failure); return failure;
}
