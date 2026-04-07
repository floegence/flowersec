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

describe("connect (auto-detect)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("routes ws_url inputs to connectDirect", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const input = { ws_url: "ws://example.invalid/ws" };
    const out = await connect(input, { origin: "https://app.example" });
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith(input, { origin: "https://app.example" });
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("routes tunnel_url inputs to connectTunnel", async () => {
    mocks.connectTunnel.mockResolvedValueOnce({ path: "tunnel" });
    const input = { tunnel_url: "ws://example.invalid/ws" };
    const out = await connect(input, { origin: "https://app.example" });
    expect(out).toEqual({ path: "tunnel" });
    expect(mocks.connectTunnel).toHaveBeenCalledWith(input, { origin: "https://app.example" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
  });

  test("routes grant_client wrapper inputs to connectTunnel", async () => {
    mocks.connectTunnel.mockResolvedValueOnce({ path: "tunnel" });
    const input = { grant_client: { tunnel_url: "ws://example.invalid/ws" } };
    const out = await connect(input, { origin: "https://app.example" });
    expect(out).toEqual({ path: "tunnel" });
    expect(mocks.connectTunnel).toHaveBeenCalledWith(input, { origin: "https://app.example" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
  });

  test("rejects grant_server wrapper inputs at the client-facing edge", async () => {
    const input = { grant_server: { tunnel_url: "ws://example.invalid/ws" } };
    const p = connect(input, { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "role_mismatch", path: "tunnel" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("rejects hybrid legacy inputs instead of preferring one side", async () => {
    const input = { ws_url: "ws://example.invalid/ws", tunnel_url: "ws://tunnel.invalid/ws" };
    const p = connect(input, { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("parses JSON strings and routes to connectDirect", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const out = await connect('{ "ws_url": "ws://example.invalid/ws" }', { origin: "https://app.example" });
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith({ ws_url: "ws://example.invalid/ws" }, { origin: "https://app.example" });
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("rejects invalid JSON strings and preserves parse cause", async () => {
    const p = connect('{ "ws_url": ', { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await p.catch((e) => {
      expect(e).toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
      expect((e as FlowersecError).cause).toBeInstanceOf(SyntaxError);
    });
  });

  test("rejects bare token-like inputs", async () => {
    const input = { token: "tok" };
    const p = connect(input, { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
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
    };
    const out = await connect(input, { origin: "https://app.example" });
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith(input.direct_info, { origin: "https://app.example" });
  });

  test("passes scope_version into experimental resolver", async () => {
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
      scopeResolvers: {
        "proxy.runtime": () => {
          throw new Error("bad payload");
        },
      },
      relaxedOptionalScopeValidation: true,
    });
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith(
      input.direct_info,
      expect.objectContaining({ origin: "https://app.example", relaxedOptionalScopeValidation: true })
    );
  });

  test("rejects raw legacy objects mixed with artifact-only fields", async () => {
    const input = { ws_url: "ws://example.invalid/ws", correlation: { v: 1, tags: [] } };
    const p = connect(input, { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("rejects unknown objects with invalid_input", async () => {
    const p = connect({ hello: "world" }, { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("rejects non-JSON strings with invalid_input", async () => {
    const p = connect("not json", { origin: "https://app.example" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "auto" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });
});
