import { beforeEach, describe, expect, test, vi } from "vitest";
import { FlowersecError } from "./utils/errors.js";

const mocks = vi.hoisted(() => {
  const connectDirect = vi.fn();
  const connectTunnel = vi.fn();
  return { connectDirect, connectTunnel };
});

vi.mock("./direct-client/connect.js", () => ({
  connectDirect: (...args: unknown[]) => mocks.connectDirect(...args),
}));

vi.mock("./tunnel-client/connect.js", () => ({
  connectTunnel: (...args: unknown[]) => mocks.connectTunnel(...args),
}));

import { connect } from "./facade.js";

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("connect", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test.each([
    ["raw direct info", { ws_url: "ws://example.invalid/ws" }],
    ["serialized JSON", JSON.stringify({ ws_url: "ws://example.invalid/ws" })],
    ["raw tunnel grant", { tunnel_url: "ws://example.invalid/ws", role: 1 }],
    ["grant wrapper", { grant_client: { tunnel_url: "ws://example.invalid/ws", role: 1 } }],
    [
      "control-plane envelope",
      {
        connect_artifact: {
          v: 1,
          transport: "direct",
          direct_info: {
            ws_url: "ws://example.invalid/ws",
            channel_id: "chan_1",
            e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
            channel_init_expire_at_unix_s: 123,
            default_suite: 1,
          },
        },
      },
    ],
  ])("rejects %s instead of treating it as an artifact", async (_name, input) => {
    const p = connect(input as never, { origin: "https://app.example" });
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("routes canonical direct artifacts to connectDirect", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const input = {
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
    const out = await connect(input, { origin: "https://app.example" });
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith(input.direct_info, { origin: "https://app.example" });
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("routes canonical tunnel artifacts to connectTunnel", async () => {
    mocks.connectTunnel.mockResolvedValueOnce({ path: "tunnel" });
    const input = {
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
    } as const;

    const out = await connect(input, { origin: "https://app.example" });

    expect(out).toEqual({ path: "tunnel" });
    expect(mocks.connectTunnel).toHaveBeenCalledWith(input.tunnel_grant, { origin: "https://app.example" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
  });

  test("rejects critical scoped artifact when no resolver is registered", async () => {
    const input = {
      v: 1,
      transport: "direct",
      direct_info: {
        ws_url: "ws://example.invalid/ws",
        channel_id: "chan_1",
        e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
        channel_init_expire_at_unix_s: 123,
        default_suite: 1,
      },
      scoped: [{ scope: "proxy.runtime", scope_version: 2, critical: true, payload: { mode: "strict" } }],
    };
    const p = connect(input, { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "resolve_failed", path: "direct" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
  });

  test("ignores non-critical scoped artifact when no resolver is registered", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const onDiagnosticEvent = vi.fn();
    const input = {
      v: 1,
      transport: "direct",
      direct_info: {
        ws_url: "ws://example.invalid/ws",
        channel_id: "chan_1",
        e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
        channel_init_expire_at_unix_s: 123,
        default_suite: 1,
      },
      scoped: [{ scope: "proxy.runtime", scope_version: 2, critical: false, payload: { mode: "hint" } }],
      correlation: { v: 1, trace_id: "trace-artifact-1", session_id: "session-artifact-1", tags: [] },
    };
    const out = await connect(input, { origin: "https://app.example", observer: { onDiagnosticEvent } });
    await flushMicrotasks();
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith(
      input.direct_info,
      expect.objectContaining({ origin: "https://app.example" })
    );
    expect(onDiagnosticEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "scope",
        code_domain: "event",
        code: "scope_ignored_missing_resolver",
        result: "skip",
        trace_id: "trace-artifact-1",
        session_id: "session-artifact-1",
      })
    );
  });

  test("passes scope_version into the configured resolver", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const resolver = vi.fn();
    const input = {
      v: 1,
      transport: "direct",
      direct_info: {
        ws_url: "ws://example.invalid/ws",
        channel_id: "chan_1",
        e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
        channel_init_expire_at_unix_s: 123,
        default_suite: 1,
      },
      scoped: [{ scope: "proxy.runtime", scope_version: 2, critical: true, payload: { mode: "strict" } }],
    };
    await connect(input, {
      origin: "https://app.example",
      scopeResolvers: {
        "proxy.runtime": resolver,
      },
    });
    expect(resolver).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "proxy.runtime", scope_version: 2, critical: true, payload: { mode: "strict" } })
    );
  });

  test("fails fast on malformed optional scope when a resolver is registered", async () => {
    const input = {
      v: 1,
      transport: "direct",
      direct_info: {
        ws_url: "ws://example.invalid/ws",
        channel_id: "chan_1",
        e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
        channel_init_expire_at_unix_s: 123,
        default_suite: 1,
      },
      scoped: [{ scope: "proxy.runtime", scope_version: 2, critical: false, payload: { mode: "bad" } }],
    };
    const p = connect(input, {
      origin: "https://app.example",
      scopeResolvers: {
        "proxy.runtime": () => {
          throw new Error("bad payload");
        },
      },
    });
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "resolve_failed", path: "direct" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
  });

  test("supports relaxed handling for optional scope resolver failures", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const onDiagnosticEvent = vi.fn();
    const input = {
      v: 1,
      transport: "direct",
      direct_info: {
        ws_url: "ws://example.invalid/ws",
        channel_id: "chan_1",
        e2ee_psk_b64u: "Zm9vYmFyYmF6cXV4eHl6MDEyMzQ1Njc4OWFiY2RlZg",
        channel_init_expire_at_unix_s: 123,
        default_suite: 1,
      },
      scoped: [{ scope: "proxy.runtime", scope_version: 2, critical: false, payload: { mode: "bad" } }],
    };
    const out = await connect(input, {
      origin: "https://app.example",
      observer: { onDiagnosticEvent },
      scopeResolvers: {
        "proxy.runtime": () => {
          throw new Error("bad payload");
        },
      },
      relaxedOptionalScopeValidation: true,
    });
    await flushMicrotasks();
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith(
      input.direct_info,
      expect.objectContaining({ origin: "https://app.example", relaxedOptionalScopeValidation: true })
    );
    expect(onDiagnosticEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "scope",
        code_domain: "event",
        code: "scope_ignored_relaxed_validation",
        result: "skip",
      })
    );
  });

});
