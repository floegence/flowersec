import { describe, expect, test } from "vitest";

import { FlowersecError } from "../utils/errors.js";
import { normalizeConnectInput } from "./internalNormalize.js";

function makeDirectArtifact() {
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

function makeTunnelArtifact() {
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

describe("normalizeConnectInput", () => {
  test("fails fast on mixed legacy direct and tunnel inputs", async () => {
    await expect(
      normalizeConnectInput({
        ws_url: "ws://example.invalid/ws",
        tunnel_url: "ws://example.invalid/tunnel",
      }),
    ).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
  });

  test("fails fast when artifact fields are mixed with legacy inputs", async () => {
    await expect(
      normalizeConnectInput({
        ...makeDirectArtifact(),
        ws_url: "ws://example.invalid/ws",
      }),
    ).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
  });

  test("rejects direct and tunnel wrappers at opposite roles", async () => {
    await expect(
      normalizeConnectInput({ grant_server: makeTunnelArtifact().tunnel_grant }),
    ).rejects.toMatchObject({ stage: "validate", code: "role_mismatch", path: "tunnel" });

    await expect(
      normalizeConnectInput({ grant_client: makeTunnelArtifact().tunnel_grant, ws_url: "ws://example.invalid/ws" }),
    ).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
  });

  test("keeps direct and tunnel artifacts mutually exclusive at the boundary", async () => {
    await expect(
      normalizeConnectInput({
        ...makeTunnelArtifact(),
        direct_info: makeDirectArtifact().direct_info,
      }),
    ).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
  });

  test("routes canonical artifacts without changing their transport kind", async () => {
    await expect(normalizeConnectInput(makeDirectArtifact())).resolves.toMatchObject({
      kind: "direct",
      input: makeDirectArtifact().direct_info,
    });
    await expect(normalizeConnectInput(makeTunnelArtifact())).resolves.toMatchObject({
      kind: "tunnel",
      input: makeTunnelArtifact().tunnel_grant,
    });
  });

  test("rejects non-object and non-JSON string inputs", async () => {
    await expect(normalizeConnectInput("not json")).rejects.toMatchObject({
      stage: "validate",
      code: "invalid_input",
      path: "auto",
    });
    await expect(normalizeConnectInput(null)).rejects.toMatchObject({
      stage: "validate",
      code: "invalid_input",
      path: "auto",
    });
  });

  test("parses JSON strings and routes them", async () => {
    await expect(normalizeConnectInput(JSON.stringify({ ws_url: "ws://example.invalid/ws" }))).resolves.toMatchObject({
      kind: "direct",
      input: { ws_url: "ws://example.invalid/ws" },
    });
  });

  test("preserves parse failures as invalid_input", async () => {
    await expect(normalizeConnectInput("{")).rejects.toBeInstanceOf(FlowersecError);
    await expect(normalizeConnectInput("{")).rejects.toMatchObject({
      stage: "validate",
      code: "invalid_input",
      path: "auto",
    });
  });
});
