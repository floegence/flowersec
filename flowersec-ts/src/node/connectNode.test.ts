import { beforeEach, describe, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const connect = vi.fn();
  const wsFactory = vi.fn();
  const createNodeWsFactory = vi.fn(() => wsFactory);
  return { connect, wsFactory, createNodeWsFactory };
});

vi.mock("../facade.js", () => ({
  connect: (...args: unknown[]) => mocks.connect(...args),
}));

vi.mock("./wsFactory.js", () => ({
  createNodeWsFactory: () => mocks.createNodeWsFactory(),
}));

import { connectNode } from "./connect.js";

describe("connectNode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("injects default wsFactory", async () => {
    mocks.connect.mockResolvedValueOnce({ ok: true });
    const input = { ws_url: "ws://example.invalid/ws" };
    const out = await connectNode(input, { origin: "https://app.example" });
    expect(out).toEqual({ ok: true });
    expect(mocks.createNodeWsFactory).toHaveBeenCalledTimes(1);
    expect(mocks.connect).toHaveBeenCalledWith(input, { origin: "https://app.example", wsFactory: mocks.wsFactory });
  });

  test("preserves caller-provided wsFactory", async () => {
    const callerWsFactory = vi.fn();
    mocks.connect.mockResolvedValueOnce({ ok: true });
    const input = { tunnel_url: "ws://example.invalid/ws" };
    const out = await connectNode(input, { origin: "https://app.example", wsFactory: callerWsFactory as any });
    expect(out).toEqual({ ok: true });
    expect(mocks.createNodeWsFactory).not.toHaveBeenCalled();
    expect(mocks.connect).toHaveBeenCalledWith(input, { origin: "https://app.example", wsFactory: callerWsFactory });
  });
});
