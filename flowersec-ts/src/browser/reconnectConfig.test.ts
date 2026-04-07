import { afterEach, describe, expect, test, vi } from "vitest";

const connectBrowserMock = vi.fn();
const connectTunnelBrowserMock = vi.fn();
const connectDirectBrowserMock = vi.fn();
const requestChannelGrantMock = vi.fn();
const requestConnectArtifactMock = vi.fn();

vi.mock("./connect.js", () => ({
  connectBrowser: (...args: unknown[]) => connectBrowserMock(...args),
  connectTunnelBrowser: (...args: unknown[]) => connectTunnelBrowserMock(...args),
  connectDirectBrowser: (...args: unknown[]) => connectDirectBrowserMock(...args),
}));

vi.mock("./controlplane.js", () => ({
  requestChannelGrant: (...args: unknown[]) => requestChannelGrantMock(...args),
  requestConnectArtifact: (...args: unknown[]) => requestConnectArtifactMock(...args),
  requestEntryConnectArtifact: (...args: unknown[]) => requestConnectArtifactMock(...args),
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("createBrowserReconnectConfig", () => {
  test("builds tunnel reconnect config with controlplane grant fetch", async () => {
    requestChannelGrantMock.mockResolvedValue({ channel_id: "chan_1" });
    connectTunnelBrowserMock.mockResolvedValue({ client: true });

    const { createBrowserReconnectConfig } = await import("./reconnectConfig.js");
    const config = createBrowserReconnectConfig({
      controlplane: { baseUrl: "https://cp.example.com", endpointId: "env_1" },
      connect: { handshakeTimeoutMs: 3000 },
    });

    const out = await config.connectOnce({ signal: new AbortController().signal, observer: {} });
    expect(out).toEqual({ client: true });
    expect(requestChannelGrantMock).toHaveBeenCalledWith({ baseUrl: "https://cp.example.com", endpointId: "env_1" });
    expect(connectTunnelBrowserMock).toHaveBeenCalledWith(
      { channel_id: "chan_1" },
      expect.objectContaining({ handshakeTimeoutMs: 3000 })
    );
  });

  test("builds direct reconnect config with getDirectInfo", async () => {
    connectDirectBrowserMock.mockResolvedValue({ client: true });

    const { createBrowserReconnectConfig } = await import("./reconnectConfig.js");
    const getDirectInfo = vi.fn().mockResolvedValue({ ws_url: "ws://example.invalid/ws", channel_id: "chan_2" });
    const config = createBrowserReconnectConfig({
      mode: "direct",
      getDirectInfo,
      connect: { connectTimeoutMs: 2000 },
    });

    await config.connectOnce({ signal: new AbortController().signal, observer: { onConnect: vi.fn() } });
    expect(getDirectInfo).toHaveBeenCalledTimes(1);
    expect(connectDirectBrowserMock).toHaveBeenCalledWith(
      { ws_url: "ws://example.invalid/ws", channel_id: "chan_2" },
      expect.objectContaining({ connectTimeoutMs: 2000 })
    );
  });

  test("builds tunnel reconnect config with artifact controlplane fetch and trace carry", async () => {
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
    connectBrowserMock.mockResolvedValue({ client: true });

    const { createBrowserReconnectConfig } = await import("./reconnectConfig.js");
    const config = createBrowserReconnectConfig({
      artifactControlplane: { baseUrl: "https://cp.example.com", endpointId: "env_art_1" },
    });

    await config.connectOnce({ signal: new AbortController().signal, observer: {} });
    await config.connectOnce({ signal: new AbortController().signal, observer: {} });

    expect(requestConnectArtifactMock).toHaveBeenNthCalledWith(1, {
      baseUrl: "https://cp.example.com",
      endpointId: "env_art_1",
      correlation: undefined,
    });
    expect(requestConnectArtifactMock).toHaveBeenNthCalledWith(2, {
      baseUrl: "https://cp.example.com",
      endpointId: "env_art_1",
      correlation: { traceId: "trace-0001" },
    });
    expect(connectBrowserMock).toHaveBeenCalledTimes(2);
  });
});
