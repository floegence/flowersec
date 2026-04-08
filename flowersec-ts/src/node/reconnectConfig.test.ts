import { afterEach, describe, expect, test, vi } from "vitest";

const connectNodeMock = vi.fn();
const connectTunnelNodeMock = vi.fn();
const connectDirectNodeMock = vi.fn();
const requestConnectArtifactMock = vi.fn();

vi.mock("./connect.js", () => ({
  connectNode: (...args: unknown[]) => connectNodeMock(...args),
  connectTunnelNode: (...args: unknown[]) => connectTunnelNodeMock(...args),
  connectDirectNode: (...args: unknown[]) => connectDirectNodeMock(...args),
}));

vi.mock("../controlplane/index.js", () => ({
  requestConnectArtifact: (...args: unknown[]) => requestConnectArtifactMock(...args),
  requestEntryConnectArtifact: (...args: unknown[]) => requestConnectArtifactMock(...args),
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("createNodeReconnectConfig", () => {
  test("builds tunnel reconnect config with grant fetchers", async () => {
    connectTunnelNodeMock.mockResolvedValue({ client: true });

    const { createNodeReconnectConfig } = await import("./reconnectConfig.js");
    const getGrant = vi.fn().mockResolvedValue({ channel_id: "chan_1" });
    const config = createNodeReconnectConfig({
      getGrant,
      connect: { origin: "https://node.example.test", handshakeTimeoutMs: 3000 },
    });

    const out = await config.connectOnce({ signal: new AbortController().signal, observer: {} });
    expect(out).toEqual({ client: true });
    expect(getGrant).toHaveBeenCalledTimes(1);
    expect(connectTunnelNodeMock).toHaveBeenCalledWith(
      { channel_id: "chan_1" },
      expect.objectContaining({ origin: "https://node.example.test", handshakeTimeoutMs: 3000 })
    );
  });

  test("builds direct reconnect config with getDirectInfo", async () => {
    connectDirectNodeMock.mockResolvedValue({ client: true });

    const { createNodeReconnectConfig } = await import("./reconnectConfig.js");
    const getDirectInfo = vi.fn().mockResolvedValue({ ws_url: "ws://example.invalid/ws", channel_id: "chan_2" });
    const config = createNodeReconnectConfig({
      mode: "direct",
      getDirectInfo,
      connect: { origin: "https://node.example.test", connectTimeoutMs: 2000 },
    });

    await config.connectOnce({ signal: new AbortController().signal, observer: { onConnect: vi.fn() } });
    expect(getDirectInfo).toHaveBeenCalledTimes(1);
    expect(connectDirectNodeMock).toHaveBeenCalledWith(
      { ws_url: "ws://example.invalid/ws", channel_id: "chan_2" },
      expect.objectContaining({ origin: "https://node.example.test", connectTimeoutMs: 2000 })
    );
  });

  test("builds tunnel reconnect config with artifact controlplane fetch, signal passthrough, and trace carry", async () => {
    requestConnectArtifactMock
      .mockResolvedValueOnce({
        v: 1,
        transport: "tunnel",
        tunnel_grant: { tunnel_url: "ws://example.invalid/ws", channel_id: "chan_1" },
        correlation: { v: 1, trace_id: "trace-0001", session_id: "session-0001", tags: [] },
      })
      .mockResolvedValueOnce({
        v: 1,
        transport: "tunnel",
        tunnel_grant: { tunnel_url: "ws://example.invalid/ws", channel_id: "chan_2" },
        correlation: { v: 1, trace_id: "trace-0001", session_id: "session-0002", tags: [] },
      });
    connectNodeMock.mockResolvedValue({ client: true });

    const { createNodeReconnectConfig } = await import("./reconnectConfig.js");
    const config = createNodeReconnectConfig({
      artifactControlplane: {
        baseUrl: "https://cp.example.com",
        endpointId: "env_art_1",
      },
      connect: { origin: "https://node.example.test", connectTimeoutMs: 1500 },
    });

    const ac1 = new AbortController();
    const ac2 = new AbortController();
    await config.connectOnce({ signal: ac1.signal, observer: {} });
    await config.connectOnce({ signal: ac2.signal, observer: {} });

    expect(requestConnectArtifactMock).toHaveBeenNthCalledWith(1, {
      baseUrl: "https://cp.example.com",
      endpointId: "env_art_1",
      correlation: undefined,
      signal: ac1.signal,
    });
    expect(requestConnectArtifactMock).toHaveBeenNthCalledWith(2, {
      baseUrl: "https://cp.example.com",
      endpointId: "env_art_1",
      correlation: { traceId: "trace-0001" },
      signal: ac2.signal,
    });
    expect(connectNodeMock).toHaveBeenCalledTimes(2);
    expect(connectNodeMock).toHaveBeenLastCalledWith(
      expect.objectContaining({
        transport: "tunnel",
        correlation: expect.objectContaining({ session_id: "session-0002" }),
      }),
      expect.objectContaining({
        origin: "https://node.example.test",
        signal: ac2.signal,
      })
    );
  });

  test("surfaces artifact refresh failures without falling back to a second path", async () => {
    requestConnectArtifactMock.mockRejectedValue(new Error("artifact refresh failed"));

    const { createNodeReconnectConfig } = await import("./reconnectConfig.js");
    const config = createNodeReconnectConfig({
      artifactControlplane: {
        baseUrl: "https://cp.example.com",
        endpointId: "env_art_1",
      },
      connect: { origin: "https://node.example.test" },
    });

    await expect(config.connectOnce({ signal: new AbortController().signal, observer: {} })).rejects.toThrow(
      "artifact refresh failed"
    );
    expect(connectNodeMock).not.toHaveBeenCalled();
    expect(connectTunnelNodeMock).not.toHaveBeenCalled();
  });
});
