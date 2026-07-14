import { afterEach, describe, expect, test, vi } from "vitest";

const connectBrowserMock = vi.fn();
vi.mock("./connect.js", () => ({ connectBrowser: (...args: unknown[]) => connectBrowserMock(...args) }));
afterEach(() => vi.clearAllMocks());

describe("createBrowserReconnectConfig", () => {
  test("uses the discriminated artifact source", async () => {
    connectBrowserMock.mockResolvedValue({ client: true });
    const artifact = { v: 1 as const, transport: "direct" as const, direct_info: {} as any };
    const { createBrowserReconnectConfig } = await import("./reconnectConfig.js");
    const config = createBrowserReconnectConfig({ source: { kind: "once", artifact }, connect: { connectTimeoutMs: 2000 } as any });
    await config.connectOnce({ signal: new AbortController().signal, observer: {} });
    expect(connectBrowserMock).toHaveBeenCalledWith(artifact, expect.objectContaining({ connectTimeoutMs: 2000 }));
    await expect(config.connectOnce({ signal: new AbortController().signal, observer: {} })).rejects.toThrow(/consumed/);
  });

  test("requires refreshable sources for automatic reconnect", async () => {
    const { createBrowserReconnectConfig } = await import("./reconnectConfig.js");
    const artifact = { v: 1 as const, transport: "tunnel" as const, tunnel_grant: {} as any };
    expect(() => createBrowserReconnectConfig({ source: { kind: "once", artifact }, autoReconnect: { enabled: true } })).toThrow(/refreshable/);
  });
});
