import { afterEach, describe, expect, test, vi } from "vitest";

const connectTunnelBrowserMock = vi.fn();
const connectDirectBrowserMock = vi.fn();
const requestChannelGrantMock = vi.fn();

vi.mock("./connect.js", () => ({
  connectTunnelBrowser: (...args: unknown[]) => connectTunnelBrowserMock(...args),
  connectDirectBrowser: (...args: unknown[]) => connectDirectBrowserMock(...args),
}));

vi.mock("./controlplane.js", () => ({
  requestChannelGrant: (...args: unknown[]) => requestChannelGrantMock(...args),
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
});
