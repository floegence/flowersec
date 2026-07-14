import { afterEach, describe, expect, test, vi } from "vitest";

const connectNodeMock = vi.fn();
const requestConnectArtifactMock = vi.fn();

vi.mock("./connect.js", () => ({ connectNode: (...args: unknown[]) => connectNodeMock(...args) }));
vi.mock("../controlplane/index.js", () => ({
  requestConnectArtifact: (...args: unknown[]) => requestConnectArtifactMock(...args),
  requestEntryConnectArtifact: (...args: unknown[]) => requestConnectArtifactMock(...args),
}));

afterEach(() => vi.clearAllMocks());

describe("createNodeReconnectConfig", () => {
  test("consumes a one-time source once and rejects automatic reconnect", async () => {
    connectNodeMock.mockResolvedValue({ client: true });
    const { createNodeReconnectConfig } = await import("./reconnectConfig.js");
    const source = { kind: "once" as const, artifact: { v: 1 as const, transport: "direct" as const, direct_info: {} as any } };
    expect(() => createNodeReconnectConfig({ source, autoReconnect: { enabled: true } })).toThrow(/refreshable/);
    const config = createNodeReconnectConfig({ source, connect: { origin: "https://node.example.test" } as any });
    await config.connectOnce({ signal: new AbortController().signal, observer: {} });
    await expect(config.connectOnce({ signal: new AbortController().signal, observer: {} })).rejects.toThrow(/consumed/);
  });

  test("refreshes artifacts and carries trace context", async () => {
    requestConnectArtifactMock
      .mockResolvedValueOnce({ v: 1, transport: "tunnel", tunnel_grant: {} as any, correlation: { v: 1, trace_id: "trace-1", tags: [] } })
      .mockResolvedValueOnce({ v: 1, transport: "tunnel", tunnel_grant: {} as any, correlation: { v: 1, trace_id: "trace-1", tags: [] } });
    connectNodeMock.mockResolvedValue({ client: true });
    const { createNodeReconnectConfig } = await import("./reconnectConfig.js");
    const { createControlplaneArtifactSource } = await import("../reconnect/artifactControlplane.js");
    const config = createNodeReconnectConfig({
      source: createControlplaneArtifactSource({ baseUrl: "https://cp.example.com", endpointId: "env_1" }),
      connect: { origin: "https://node.example.test" } as any,
    });
    await config.connectOnce({ signal: new AbortController().signal, observer: {} });
    await config.connectOnce({ signal: new AbortController().signal, observer: {} });
    expect(requestConnectArtifactMock).toHaveBeenNthCalledWith(2, expect.objectContaining({ correlation: { traceId: "trace-1" } }));
    expect(connectNodeMock).toHaveBeenCalledTimes(2);
  });
});
