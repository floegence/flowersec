import { describe, expect, test, vi } from "vitest";

import type { RpcClient } from "../rpc/client.js";
import { SessionError, type InternalByteStreamV2, type InternalSessionV2 } from "./contract.js";
import { projectSessionV2 } from "./publicSession.js";

describe("opaque public SessionV2 projection", () => {
  test("removes path, endpoint, and logical stream IDs at runtime", async () => {
    const terminal = new Error("peer secret: candidate=q1 endpoint=server-private");
    const stream = fakeStream(terminal);
    const internal = fakeSession(stream, terminal);
    const session = projectSessionV2(internal);

    expect(Object.isFrozen(session)).toBe(true);
    expect(session).not.toHaveProperty("path");
    expect(session).not.toHaveProperty("endpointInstanceId");

    const opened = await session.openStream("data");
    expect(opened).not.toHaveProperty("id");
    expect(opened).not.toHaveProperty("carrier");
    expect(opened.terminalError).toEqual(new SessionError("operation_failed"));
    expect(opened.terminalError?.message).not.toContain("candidate");

    const incoming = await session.acceptStream();
    expect(incoming).not.toHaveProperty("id");
    expect(incoming.stream).not.toHaveProperty("id");
    expect(incoming).toEqual(expect.objectContaining({ kind: "data", metadata: { purpose: "test" } }));
  });

  test("projects operation and termination failures to the closed error set", async () => {
    const internalError = Object.assign(new Error("wire transcript and peer detail"), {
      name: "SessionV2Error",
      code: "timeout",
    });
    const stream = fakeStream(internalError);
    stream.read = vi.fn(async () => { throw internalError; });
    const session = projectSessionV2(fakeSession(stream, internalError));

    await expect((await session.openStream("data")).read()).rejects.toEqual(new SessionError("timeout"));
    await expect(session.waitTermination()).resolves.toEqual({ error: new SessionError("timeout") });
    expect(session).not.toHaveProperty("termination");
    expect((await session.waitTermination()).error).not.toHaveProperty("cause");
  });

  test("preserves stable retryable session error codes across the public projection", async () => {
    for (const [internalCode, publicCode] of [
      ["stream_reset", "stream_reset"],
      ["rekey_failed", "rekey_failed"],
      ["liveness_failed", "liveness_failed"],
    ] as const) {
      const internalError = Object.assign(new Error(`private detail for ${internalCode}`), {
        name: "SessionV2Error",
        code: internalCode,
      });
      const stream = fakeStream(internalError);
      stream.read = vi.fn(async () => { throw internalError; });
      const session = projectSessionV2(fakeSession(stream, internalError));

      await expect((await session.openStream("data")).read()).rejects.toEqual(new SessionError(publicCode));
      await expect(session.waitTermination()).resolves.toEqual({ error: new SessionError(publicCode) });
    }
  });

  test("projects RPC application outcomes as a discriminated union", async () => {
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    internal.rpc.call = vi.fn()
      .mockResolvedValueOnce({ payload: { accepted: true } })
      .mockResolvedValueOnce({ payload: null, error: { code: 409, message: "conflict" } });
    const session = projectSessionV2(internal);

    await expect(session.rpc.call(1, {}, decodeAccepted)).resolves.toEqual({
      ok: true,
      payload: { accepted: true },
    });
    await expect(session.rpc.call(2, {}, decodeAccepted)).resolves.toEqual({
      ok: false,
      error: { code: 409, message: "conflict" },
    });
  });

  test("rejects a successful RPC payload that its decoder does not accept", async () => {
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    internal.rpc.call = vi.fn().mockResolvedValue({ payload: { accepted: "yes" } });
    const session = projectSessionV2(internal);

    await expect(session.rpc.call(1, {}, decodeAccepted)).rejects.toEqual(
      new SessionError("operation_failed"),
    );
  });
});

function decodeAccepted(payload: unknown): Readonly<{ accepted: boolean }> {
  if (
    typeof payload !== "object"
    || payload === null
    || !("accepted" in payload)
    || typeof payload.accepted !== "boolean"
  ) {
    throw new TypeError("invalid accepted response");
  }
  return { accepted: payload.accepted };
}

function fakeStream(error: Error): InternalByteStreamV2 & { read: ReturnType<typeof vi.fn> } {
  return {
    id: 17n,
    kind: "data",
    terminalError: error,
    read: vi.fn(async () => null),
    write: vi.fn(async (data: Uint8Array) => data.length),
    closeWrite: vi.fn(async () => undefined),
    reset: vi.fn(async () => undefined),
    close: vi.fn(async () => undefined),
  };
}

function fakeSession(stream: InternalByteStreamV2, error: Error): InternalSessionV2 {
  const termination = Promise.resolve({ error });
  return {
    path: "tunnel",
    endpointInstanceId: "server-private",
    rpc: {
      call: vi.fn(async () => ({ payload: null })),
      notify: vi.fn(async () => undefined),
      onNotify: vi.fn(() => () => undefined),
    } as unknown as RpcClient,
    termination,
    openStream: vi.fn(async () => stream),
    acceptStream: vi.fn(async () => ({ id: 19n, kind: "data", metadata: { purpose: "test" }, stream })),
    rekey: vi.fn(async () => undefined),
    probeLiveness: vi.fn(async () => 1),
    waitTermination: vi.fn(async () => await termination),
    close: vi.fn(async () => undefined),
  };
}
