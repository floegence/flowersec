import { describe, expect, test } from "vitest";

import { createConnectionControllerV3 } from "./connectSessionV3.js";

describe("Node v3 session facade", () => {
  test("constructs an idle raw-QUIC-capable controller without an origin", () => {
    let acquisitions = 0;
    const controller = createConnectionControllerV3({
      acquire: async () => {
        acquisitions += 1;
        return { kind: "failure", code: "unused", disposition: { kind: "terminal" } };
      },
    }, { maximumAttempts: 1 });

    expect(controller.state).toBe("idle");
    expect(acquisitions).toBe(0);
  });

  test("projects an invalid RPC handler registry to the public v3 error boundary", () => {
    expect(() => createConnectionControllerV3({
      acquire: async () => ({ kind: "failure", code: "unused", disposition: { kind: "terminal" } }),
    }, {
      maximumAttempts: 1,
      rpcHandlers: {} as never,
    })).toThrow(expect.objectContaining({
      name: "ConnectError",
      code: "artifact_invalid",
      disposition: { kind: "terminal" },
    }));
  });
});
