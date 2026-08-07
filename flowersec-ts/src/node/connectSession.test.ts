import { describe, expect, test } from "vitest";

import type { ArtifactSource } from "../connectionController.js";
import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import { connectNodeSession, createNodeConnectionController } from "./connectSession.js";

describe("Node session facade", () => {
  test.each([
    "https://app.example/path",
    "ftp://app.example",
    "not a URL",
  ])("rejects invalid origin %s before dialing", async (origin) => {
    await expect(connectNodeSession({} as ArtifactLeaseV2, { origin }))
      .rejects.toMatchObject({ name: "ConnectError", code: "invalid_options" });
  });

  test("constructs an idle ConnectionController without acquiring early", () => {
    let acquisitions = 0;
    const source: ArtifactSource = {
      acquire: async () => {
        acquisitions += 1;
        return { kind: "failure", code: "unused", disposition: { kind: "terminal" } };
      },
    };
    const controller = createNodeConnectionController(source, {
      origin: "https://app.example",
      maxAttempts: 3,
    });

    expect(controller.state).toBe("idle");
    expect(acquisitions).toBe(0);
  });
});
