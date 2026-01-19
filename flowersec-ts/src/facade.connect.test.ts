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

  test("prefers direct when both ws_url and tunnel_url are present", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const input = { ws_url: "ws://example.invalid/ws", tunnel_url: "ws://tunnel.invalid/ws" };
    const out = await connect(input, { origin: "https://app.example" });
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith(input, { origin: "https://app.example" });
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("parses JSON strings and routes to connectDirect", async () => {
    mocks.connectDirect.mockResolvedValueOnce({ path: "direct" });
    const out = await connect('{ "ws_url": "ws://example.invalid/ws" }', { origin: "https://app.example" });
    expect(out).toEqual({ path: "direct" });
    expect(mocks.connectDirect).toHaveBeenCalledWith({ ws_url: "ws://example.invalid/ws" }, { origin: "https://app.example" });
    expect(mocks.connectTunnel).not.toHaveBeenCalled();
  });

  test("routes token-like inputs to connectTunnel", async () => {
    mocks.connectTunnel.mockResolvedValueOnce({ path: "tunnel" });
    const input = { token: "tok" };
    const out = await connect(input, { origin: "https://app.example" });
    expect(out).toEqual({ path: "tunnel" });
    expect(mocks.connectTunnel).toHaveBeenCalledWith(input, { origin: "https://app.example" });
    expect(mocks.connectDirect).not.toHaveBeenCalled();
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
