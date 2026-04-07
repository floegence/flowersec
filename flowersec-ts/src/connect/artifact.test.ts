import { describe, expect, test } from "vitest";

import { assertConnectArtifact } from "./artifact.js";

describe("assertConnectArtifact", () => {
  test("accepts tunnel artifacts and sanitizes invalid correlation ids to absence", () => {
    const artifact = assertConnectArtifact({
      v: 1,
      transport: "tunnel",
      tunnel_grant: {
        tunnel_url: "ws://example.invalid/ws",
        channel_id: "chan_1",
        channel_init_expire_at_unix_s: 123,
        idle_timeout_seconds: 30,
        role: 1,
        token: "tok",
        e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
        allowed_suites: [1],
        default_suite: 1,
      },
      correlation: {
        v: 1,
        trace_id: " bad trace ",
        session_id: "session-0001",
        tags: [{ key: "flow", value: "demo" }],
      },
    });

    expect(artifact.transport).toBe("tunnel");
    expect(artifact.correlation?.trace_id).toBeUndefined();
    expect(artifact.correlation?.session_id).toBe("session-0001");
    expect(artifact.correlation?.tags).toEqual([{ key: "flow", value: "demo" }]);
  });

  test("rejects unknown top-level fields", () => {
    expect(() =>
      assertConnectArtifact({
        v: 1,
        transport: "direct",
        direct_info: {
          ws_url: "ws://example.invalid/ws",
          channel_id: "chan_1",
          e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
          channel_init_expire_at_unix_s: 123,
          default_suite: 1,
        },
        extra: true,
      })
    ).toThrow(/bad DirectClientConnectArtifact\.extra/);
  });

  test("rejects server-role tunnel artifacts", () => {
    expect(() =>
      assertConnectArtifact({
        v: 1,
        transport: "tunnel",
        tunnel_grant: {
          tunnel_url: "ws://example.invalid/ws",
          channel_id: "chan_1",
          channel_init_expire_at_unix_s: 123,
          idle_timeout_seconds: 30,
          role: 2,
          token: "tok",
          e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
          allowed_suites: [1],
          default_suite: 1,
        },
      })
    ).toThrow(/role/);
  });

  test("rejects duplicate scope entries", () => {
    expect(() =>
      assertConnectArtifact({
        v: 1,
        transport: "direct",
        direct_info: {
          ws_url: "ws://example.invalid/ws",
          channel_id: "chan_1",
          e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
          channel_init_expire_at_unix_s: 123,
          default_suite: 1,
        },
        scoped: [
          { scope: "proxy.runtime", scope_version: 1, critical: false, payload: {} },
          { scope: "proxy.runtime", scope_version: 1, critical: false, payload: {} },
        ],
      })
    ).toThrow(/bad ConnectArtifact\.scoped/);
  });

  test("rejects payloads over normalized byte budget", () => {
    expect(() =>
      assertConnectArtifact({
        v: 1,
        transport: "direct",
        direct_info: {
          ws_url: "ws://example.invalid/ws",
          channel_id: "chan_1",
          e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
          channel_init_expire_at_unix_s: 123,
          default_suite: 1,
        },
        scoped: [
          {
            scope: "proxy.runtime",
            scope_version: 1,
            critical: false,
            payload: { big: "x".repeat(9000) },
          },
        ],
      })
    ).toThrow(/bad ScopeMetadataEntry\.payload/);
  });
});
