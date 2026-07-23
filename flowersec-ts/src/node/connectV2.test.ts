import { beforeEach, describe, expect, test, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  connect: vi.fn(),
  createInternal: vi.fn(),
  createAttemptFactory: vi.fn(() => ({ create: vi.fn() })),
  wsFactory: vi.fn(),
  createNodeWsFactory: vi.fn(() => vi.fn()),
}));

vi.mock("../browser/connectV2.js", () => ({
  createBrowserSessionConnectorV2InternalStage: mocks.createInternal,
  createWebSocketAttemptFactoryV2InternalStage: mocks.createAttemptFactory,
}));
vi.mock("./wsFactory.js", () => ({ createNodeWsFactory: mocks.createNodeWsFactory }));

import { connectNodeSessionV2 } from "./connectV2.js";

describe("connectNodeSessionV2", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.connect.mockResolvedValue({ candidate: { id: "private" }, session: { close: vi.fn() } });
    mocks.createInternal.mockReturnValue({ connect: mocks.connect });
  });

  test("returns only the carrier-neutral session and binds the Node runtime", async () => {
    const lease = { artifact: {} as never, commitSpend: vi.fn() };
    const session = await connectNodeSessionV2(lease, { origin: "https://app.example" });
    expect(session).toEqual({ close: expect.any(Function) });
    expect(session).not.toHaveProperty("candidate");
    expect(mocks.createInternal).toHaveBeenCalledWith(lease, expect.objectContaining({
      runtime: "node",
      capability: expect.objectContaining({ runtime: "node" }),
      admissionReasons: expect.any(Set),
      attemptFactory: expect.any(Object),
    }));
  });

  test.each(["https://app.example/path", "ftp://app.example", "not a URL"])("rejects invalid origin %s before dialing", async (origin) => {
    await expect(connectNodeSessionV2({ artifact: {} as never, commitSpend: vi.fn() }, { origin })).rejects.toThrow(/origin/);
    expect(mocks.createInternal).not.toHaveBeenCalled();
  });
});
