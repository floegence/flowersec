import { RuntimeError } from "../runtime/errors.js";
import type { SessionProtocolRuntimeV3 } from "./session.js";

export const browserSessionRuntimeV3: SessionProtocolRuntimeV3 = Object.freeze({
  entropy(length) {
    requireLength(length);
    const runtime = (globalThis as unknown as { crypto?: Crypto }).crypto;
    if (runtime === undefined || typeof runtime.getRandomValues !== "function") {
      throw new RuntimeError("runtime_unsupported", "browser cryptographic entropy is unavailable");
    }
    const output = new Uint8Array(length);
    runtime.getRandomValues(output);
    return output;
  },
  monotonicMilliseconds() {
    return performance.now();
  },
});

function requireLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) {
    throw new RangeError("entropy length must be an integer from 1 to 65536");
  }
}
