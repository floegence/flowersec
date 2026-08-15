import { describe, expect, test } from "vitest";

import { assertRpcEnvelope } from "./validate.js";

const envelope = (error: unknown): unknown => ({
  type_id: 1,
  request_id: 0,
  response_to: 1,
  payload: {},
  error,
});

describe("RPC envelope validation", () => {
  test("enforces the portable inbound RPC error invariant", () => {
    expect(() => assertRpcEnvelope(envelope({
      code: 1,
      message: "a".repeat(1_024),
    }))).not.toThrow();
    expect(() => assertRpcEnvelope(envelope({
      code: 1,
      message: "é".repeat(512),
    }))).not.toThrow();
    for (const [name, error] of [
      ["zero code", { code: 0 }],
      ["ASCII message over 1024 bytes", { code: 1, message: "a".repeat(1_025) }],
      ["multibyte message over 1024 bytes", { code: 1, message: "é".repeat(513) }],
      ["lone surrogate", { code: 1, message: "\ud800" }],
      ["extra error field", { code: 1, internal: "secret" }],
    ] as const) {
      expect(() => assertRpcEnvelope(envelope(error)), name).toThrow();
    }
  });
});
