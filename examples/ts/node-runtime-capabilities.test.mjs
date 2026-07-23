import assert from "node:assert/strict";
import test from "node:test";

import {
  NODE_RUNTIME_CAPABILITY_V2,
  encodeRuntimeCapabilityDescriptorV2,
  runtimeCapabilityDigestHexV2,
} from "../../flowersec-ts/dist/node/index.js";
import { renderNodeRuntimeCapabilityV2 } from "./node-runtime-capabilities.mjs";

test("renders the canonical Node.js Transport v2 capability", () => {
  assert.equal(NODE_RUNTIME_CAPABILITY_V2.tuples.length, 0);
  assert.equal(
    renderNodeRuntimeCapabilityV2(),
    [
      `descriptor=${encodeRuntimeCapabilityDescriptorV2(NODE_RUNTIME_CAPABILITY_V2)}`,
      "tuple_count=0",
      `digest=${runtimeCapabilityDigestHexV2(NODE_RUNTIME_CAPABILITY_V2)}`,
      "",
    ].join("\n"),
  );
});
