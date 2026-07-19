import { describe, expect, test } from "vitest";

import type { DirectClientConnectArtifact, TunnelClientConnectArtifact } from "./artifact.js";
import { resolveConnectArtifact } from "./resolveArtifact.js";

function makeDirectArtifact(): DirectClientConnectArtifact {
  return {
    v: 1,
    transport: "direct",
    direct_info: {
      ws_url: "ws://example.invalid/ws",
      channel_id: "chan_1",
      e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
      channel_init_expire_at_unix_s: 123,
      default_suite: 1,
    },
  };
}

function makeTunnelArtifact(): TunnelClientConnectArtifact {
  return {
    v: 1,
    transport: "tunnel",
    tunnel_grant: {
      tunnel_url: "ws://example.invalid/ws",
      channel_id: "chan_1",
      token: "tok",
      role: 1,
      e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
      channel_init_expire_at_unix_s: 123,
      idle_timeout_seconds: 30,
      default_suite: 1,
      allowed_suites: [1],
    },
  };
}

describe("resolveConnectArtifact", () => {
  test("resolves canonical direct and tunnel artifacts", async () => {
    await expect(resolveConnectArtifact(makeDirectArtifact())).resolves.toMatchObject({
      kind: "direct",
      input: makeDirectArtifact().direct_info,
    });
    await expect(resolveConnectArtifact(makeTunnelArtifact())).resolves.toMatchObject({
      kind: "tunnel",
      input: makeTunnelArtifact().tunnel_grant,
    });
  });

  test("rejects malformed values as invalid ConnectArtifact", async () => {
    await expect(resolveConnectArtifact({ ws_url: "ws://example.invalid/ws" } as never)).rejects.toMatchObject({
      stage: "validate",
      code: "invalid_input",
      path: "auto",
    });
  });
});
