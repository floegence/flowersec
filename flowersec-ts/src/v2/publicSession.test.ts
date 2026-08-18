import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import type { RpcClient } from "../rpc/client.js";
import { SessionError, type InternalByteStreamV2, type InternalSessionV2 } from "./contract.js";
import { projectSessionV2 } from "./publicSession.js";

const notificationFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v2/rpc_notification_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  type_id: number;
  payloads: readonly Readonly<{
    id: string;
    json: string;
    decoder: "state_object" | "string_array" | "string";
    expected_value?: string;
    outcome: "success" | "decode_failure";
  }>[];
  subscription_scenarios: readonly string[];
}>;

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
    expect(incoming.kind).toBe("data");
    expect(incoming.metadata.values).toEqual({ purpose: "test" });
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

  test("classifies a carrier close as a closed session without exposing carrier details", async () => {
    const internalError = Object.assign(new Error("private carrier detail"), {
      name: "CarrierError",
      code: "closed",
    });
    const stream = fakeStream(internalError);
    const session = projectSessionV2(fakeSession(stream, internalError));

    await expect(session.waitTermination()).resolves.toEqual({ error: new SessionError("closed") });
    expect((await session.waitTermination()).error.message).not.toContain("carrier");
  });

  test("cancels waitTermination through OperationOptions", async () => {
    const terminal = new Promise<never>(() => undefined);
    const internal = fakeSession(fakeStream(new Error("closed")), new Error("closed"));
    internal.waitTermination = async () => await terminal;
    const session = projectSessionV2(internal);
    const controller = new AbortController();
    const waiting = session.waitTermination({ signal: controller.signal });
    controller.abort();

    await expect(waiting).rejects.toEqual(new SessionError("canceled"));
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

  test("rejects invalid RPC type IDs before invoking the internal peer", async () => {
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    internal.rpc.call = vi.fn();
    internal.rpc.notify = vi.fn();
    internal.rpc.onNotify = vi.fn();
    const session = projectSessionV2(internal);
    for (const typeId of [-1, 0, 1.5, 0x1_0000_0000]) {
      await expect(session.rpc.call(typeId, {}, decodeAccepted)).rejects.toEqual(new SessionError("operation_failed"));
      await expect(session.rpc.notify(typeId, {})).rejects.toEqual(new SessionError("operation_failed"));
      expect(() => session.rpc.onNotify(typeId, decodeAccepted, () => undefined)).toThrow(/typeId/);
    }
    expect(internal.rpc.call).not.toHaveBeenCalled();
    expect(internal.rpc.notify).not.toHaveBeenCalled();
    expect(internal.rpc.onNotify).not.toHaveBeenCalled();
  });

  test("accepts the maximum u32 RPC type ID at every public entry point", async () => {
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    Object.defineProperty(internal, "termination", { value: new Promise<never>(() => undefined) });
    internal.rpc.call = vi.fn(async () => ({ payload: { accepted: true } }));
    internal.rpc.notify = vi.fn(async () => undefined);
    internal.rpc.onNotify = vi.fn(() => () => undefined);
    const session = projectSessionV2(internal);
    await expect(session.rpc.call(0xffff_ffff, {}, decodeAccepted)).resolves.toEqual({
      ok: true,
      payload: { accepted: true },
    });
    await expect(session.rpc.notify(0xffff_ffff, {})).resolves.toBeUndefined();
    const unsubscribe = session.rpc.onNotify(0xffff_ffff, decodeAccepted, () => undefined);
    unsubscribe();
    expect(internal.rpc.call).toHaveBeenCalledWith(0xffff_ffff, {}, undefined);
    expect(internal.rpc.notify).toHaveBeenCalledWith(0xffff_ffff, {});
    expect(internal.rpc.onNotify).toHaveBeenCalledWith(0xffff_ffff, expect.any(Function));
  });

  test("projects a malformed inbound RPC response to a stable session failure", async () => {
    const secret = "malformed-rpc-secret-marker";
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    internal.rpc.call = vi.fn().mockRejectedValue(
      new Error(`invalid RPC application error: ${secret}`),
    );
    const session = projectSessionV2(internal);

    let failure: unknown;
    try {
      await session.rpc.call(1, {}, decodeAccepted);
    } catch (error) {
      failure = error;
    }
    expect(failure).toEqual(new SessionError("operation_failed"));
    expect(String(failure)).not.toContain(secret);
    expect(failure).not.toHaveProperty("cause");
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

  test("decodes notifications and isolates decoder and handler failures", async () => {
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    let dispatch: ((payload: unknown) => void) | undefined;
    const unsubscribeInternal = vi.fn();
    internal.rpc.onNotify = vi.fn((_typeId, handler) => {
      dispatch = handler;
      return unsubscribeInternal;
    });
    const session = projectSessionV2(internal);
    const observed: boolean[] = [];
    const unsubscribe = session.rpc.onNotify(7, decodeAccepted, async (payload) => {
      observed.push(payload.accepted);
      if (!payload.accepted) throw new Error("handler failure");
    });

    dispatch?.({ accepted: true });
    dispatch?.({ accepted: "invalid" });
    dispatch?.({ accepted: false });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(observed).toEqual([true, false]);
    unsubscribe();
    unsubscribe();
    expect(unsubscribeInternal).toHaveBeenCalledTimes(1);
  });

  test("executes shared notification payload and lifecycle vectors", () => {
    expect(notificationFixture.subscription_scenarios).toEqual([
      "duplicate_subscriptions_receive_independently",
      "cancel_is_idempotent",
      "handler_failure_is_isolated",
      "session_close_terminates_subscriptions",
    ]);

    for (const vector of notificationFixture.payloads) {
      const terminal = new Error("closed");
      const internal = fakeSession(fakeStream(terminal), terminal);
      let dispatch: ((payload: unknown) => void) | undefined;
      internal.rpc.onNotify = vi.fn((_typeId, handler) => {
        dispatch = handler;
        return () => undefined;
      });
      const session = projectSessionV2(internal);
      const observed: unknown[] = [];
      const unsubscribe = session.rpc.onNotify(
        notificationFixture.type_id,
        (payload) => decodeFixturePayload(vector.decoder, payload),
        (payload) => { observed.push(payload); },
      );

      dispatch?.(JSON.parse(vector.json));

      if (vector.outcome === "decode_failure") {
        expect(observed, vector.id).toEqual([]);
      } else if (vector.decoder === "string_array") {
        expect(observed, vector.id).toEqual([JSON.parse(vector.json)]);
      } else {
        expect(observed, vector.id).toEqual([vector.expected_value]);
      }
      unsubscribe();
    }
  });

  test("keeps duplicate subscriptions independent and clears them on close", async () => {
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    const handlers = new Set<(payload: unknown) => void>();
    const unsubscribeInternal = vi.fn((handler: (payload: unknown) => void) => {
      handlers.delete(handler);
    });
    internal.rpc.onNotify = vi.fn((_typeId, handler) => {
      handlers.add(handler);
      return () => unsubscribeInternal(handler);
    });
    const session = projectSessionV2(internal);
    const observed: string[] = [];
    const first = session.rpc.onNotify(7, decodeMessage, (payload) => {
      observed.push(`first:${payload}`);
      throw new Error("isolated handler failure");
    });
    session.rpc.onNotify(7, decodeMessage, (payload) => {
      observed.push(`second:${payload}`);
    });

    for (const handler of [...handlers]) handler({ message: "one" });
    expect(observed).toEqual(["first:one", "second:one"]);

    first();
    first();
    for (const handler of [...handlers]) handler({ message: "two" });
    expect(observed).toEqual(["first:one", "second:one", "second:two"]);

    await session.close();
    expect(handlers).toHaveLength(0);
    expect(unsubscribeInternal).toHaveBeenCalledTimes(2);
    const afterClose = session.rpc.onNotify(7, decodeMessage, () => undefined);
    afterClose();
    afterClose();
    expect(internal.rpc.onNotify).toHaveBeenCalledTimes(2);
  });

  test("rejects non-JSON outbound payloads before calling the internal peer", async () => {
    const terminal = new Error("closed");
    const internal = fakeSession(fakeStream(terminal), terminal);
    const session = projectSessionV2(internal);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const invalidPayloads: unknown[] = [
      1n,
      undefined,
      Number.POSITIVE_INFINITY,
      { value: 1n },
      { value: undefined },
      cyclic,
      { value: Number.NaN },
    ];

    for (const payload of invalidPayloads) {
      await expect(session.rpc.call(1, payload as never, decodeAccepted))
        .rejects.toEqual(new SessionError("operation_failed"));
      await expect(session.rpc.notify(2, payload as never))
        .rejects.toEqual(new SessionError("operation_failed"));
    }

    expect(internal.rpc.call).not.toHaveBeenCalled();
    expect(internal.rpc.notify).not.toHaveBeenCalled();
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

function decodeFixturePayload(
  decoder: "state_object" | "string_array" | "string",
  payload: unknown,
): unknown {
  if (decoder === "state_object") return decodeState(payload);
  if (decoder === "string_array") {
    if (!Array.isArray(payload) || payload.some((value) => typeof value !== "string")) {
      throw new TypeError("expected notification string array");
    }
    return payload;
  }
  if (typeof payload !== "string") throw new TypeError("expected notification string");
  return payload;
}

function decodeState(payload: unknown): string {
  if (
    typeof payload !== "object"
    || payload === null
    || !("state" in payload)
    || typeof payload.state !== "string"
  ) {
    throw new TypeError("expected notification state");
  }
  return payload.state;
}

function decodeMessage(payload: unknown): string {
  if (
    typeof payload !== "object"
    || payload === null
    || !("message" in payload)
    || typeof payload.message !== "string"
  ) {
    throw new TypeError("expected notification message");
  }
  return payload.message;
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
