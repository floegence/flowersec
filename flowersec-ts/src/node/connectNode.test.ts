import { beforeEach, describe, expect, test, vi } from "vitest";
import type { ConnectArtifact } from "../connect/artifact.js";

const mocks = vi.hoisted(() => {
  const connect = vi.fn();
  const wsFactory = vi.fn();
  const createNodeWsFactory = vi.fn((_opts?: unknown) => wsFactory);
  return { connect, wsFactory, createNodeWsFactory };
});

vi.mock("../facade.js", () => ({
  connect: (...args: unknown[]) => mocks.connect(...args),
}));

vi.mock("./wsFactory.js", () => ({
  createNodeWsFactory: (opts?: unknown) => mocks.createNodeWsFactory(opts),
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
    expect(mocks.createNodeWsFactory).toHaveBeenCalledWith({ maxPayload: expect.any(Number), perMessageDeflate: false });
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

  test("accepts ConnectArtifact inputs on the stable typed path", async () => {
    mocks.connect.mockResolvedValueOnce({ ok: true });
    const artifact: ConnectArtifact = {
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

    const out = await connectNode(artifact, { origin: "https://app.example" });

    expect(out).toEqual({ ok: true });
    expect(mocks.createNodeWsFactory).toHaveBeenCalledTimes(1);
    expect(mocks.connect).toHaveBeenCalledWith(
      artifact,
      expect.objectContaining({ origin: "https://app.example", wsFactory: mocks.wsFactory })
    );
  });
});
