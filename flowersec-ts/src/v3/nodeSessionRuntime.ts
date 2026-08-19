import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";

import type { SessionProtocolRuntimeV3 } from "./session.js";

export const nodeSessionRuntimeV3: SessionProtocolRuntimeV3 = Object.freeze({
  entropy(length) {
    if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) {
      throw new RangeError("entropy length must be an integer from 1 to 65536");
    }
    return Uint8Array.from(randomBytes(length));
  },
  monotonicMilliseconds() {
    return performance.now();
  },
});
