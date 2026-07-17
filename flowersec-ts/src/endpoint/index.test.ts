import { beforeEach, describe, expect, test, vi } from "vitest";

import { YamuxPingTimeoutError } from "../yamux/errors.js";

const mocks = vi.hoisted(() => {
  const openStream = vi.fn();
  const probeLiveness = vi.fn();

  class MockYamuxSession {
    constructor(_connection: unknown, _options: unknown) {}

    async openStream(options: unknown) {
      return await openStream(options);
    }

    async probeLiveness(timeoutMs: number) {
      return await probeLiveness(timeoutMs);
    }

    close() {}
  }

  return { MockYamuxSession, openStream, probeLiveness };
});

vi.mock("../yamux/session.js", () => ({ YamuxSession: mocks.MockYamuxSession }));

import { Session } from "./index.js";

const secure = {
  read: vi.fn(),
  write: vi.fn(),
  close: vi.fn(),
  rekeyNow: vi.fn(),
};

describe("endpoint Session public errors", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  test("rejects a blank stream kind before opening a Yamux stream", async () => {
    const session = Session.create("tunnel", secure as any);

    await expect(session.openStream(" \t ")).rejects.toMatchObject({
      path: "tunnel",
      stage: "rpc",
      code: "missing_stream_kind",
    });
    expect(mocks.openStream).not.toHaveBeenCalled();
  });

  test("maps Yamux ping timeout to typed endpoint timeout", async () => {
    mocks.probeLiveness.mockRejectedValueOnce(new YamuxPingTimeoutError());
    const session = Session.create("direct", secure as any);

    await expect(session.probeLiveness(25)).rejects.toMatchObject({
      path: "direct",
      stage: "yamux",
      code: "timeout",
    });
  });

  test("preserves ping_failed for other endpoint probe failures", async () => {
    mocks.probeLiveness.mockRejectedValueOnce(new Error("transport failed"));
    const session = Session.create("tunnel", secure as any);

    await expect(session.probeLiveness(25)).rejects.toMatchObject({
      path: "tunnel",
      stage: "yamux",
      code: "ping_failed",
    });
  });
});
