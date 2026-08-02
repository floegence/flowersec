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
import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import { classifyConnectErrorV2 } from "../v2/errorClassification.js";
import { ConnectError } from "../utils/errors.js";

describe("connectNodeSessionV2", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const termination = Promise.resolve({ error: new Error("closed") });
    mocks.connect.mockResolvedValue({
      candidate: { id: "private" },
      session: {
        path: "direct",
        endpointInstanceId: "private",
        rpc: { call: vi.fn(), notify: vi.fn(), onNotify: vi.fn() },
        termination,
        openStream: vi.fn(),
        acceptStream: vi.fn(),
        rekey: vi.fn(),
        probeLiveness: vi.fn(),
        waitTermination: vi.fn(async () => await termination),
        close: vi.fn(async () => undefined),
      },
    });
    mocks.createInternal.mockReturnValue({ connect: mocks.connect });
  });

  test("returns only the carrier-neutral session and binds the Node runtime", async () => {
    const lease = {} as ArtifactLeaseV2;
    const session = await connectNodeSessionV2(lease, { origin: "https://app.example" });
    expect(session).toEqual(expect.objectContaining({ close: expect.any(Function) }));
    expect(session).not.toHaveProperty("candidate");
    expect(session).not.toHaveProperty("path");
    expect(session).not.toHaveProperty("endpointInstanceId");
    expect(mocks.createInternal).toHaveBeenCalledWith(lease, expect.objectContaining({
      runtime: "node",
      capability: expect.objectContaining({ runtime: "node" }),
      admissionReasons: expect.any(Set),
      attemptFactory: expect.any(Object),
    }));
  });

  test.each(["https://app.example/path", "ftp://app.example", "not a URL"])("rejects invalid origin %s before dialing", async (origin) => {
    const error = await connectNodeSessionV2({} as ArtifactLeaseV2, { origin }).catch((value: unknown) => value);
    expect(error).toEqual(expect.objectContaining({ name: "ConnectError", code: "invalid_options" }));
    expect(error).toBeInstanceOf(ConnectError);
    expect(classifyConnectErrorV2(error as ConnectError).action).toBe("stop");
    expect(mocks.createInternal).not.toHaveBeenCalled();
  });

  test("projects local TLS option failures to ConnectError", async () => {
    mocks.createNodeWsFactory.mockImplementationOnce(() => { throw new TypeError("invalid CA"); });
    await expect(connectNodeSessionV2({} as ArtifactLeaseV2, {
      origin: "https://app.example",
      tls: { ca: "invalid" },
    })).rejects.toEqual(expect.objectContaining({ name: "ConnectError", code: "invalid_options" }));
    expect(mocks.createInternal).not.toHaveBeenCalled();
  });
});
