import { afterEach, describe, expect, test, vi } from "vitest";

import type { CarrierSessionV3, CarrierStreamV3 } from "../v3/carrier.js";
import type { ReceivedSessionAdmissionV3 } from "../v3/serverAdmission.js";
import {
  respondTunnelPairAdmissionsV3,
  spliceTunnelStreamsV3,
} from "./tunnelRuntimeV3.js";

describe("Node TunnelRuntimeV3 lifecycle bounds", () => {
  afterEach(() => vi.useRealTimers());

  test("bounds paired admission when an admission FIN never settles", async () => {
    vi.useFakeTimers();
    const first = fakeAdmission(fakeStream());
    const second = fakeAdmission(fakeStream({ closeWrite: () => new Promise(() => {}) }));

    const responding = respondTunnelPairAdmissionsV3(
      first,
      second,
      new AbortController().signal,
      20,
    );
    const rejection = expect(responding).rejects.toThrow("Flowersec tunnel admission response timed out");

    await vi.advanceTimersByTimeAsync(20);
    await rejection;
    expect(first.stream.closeWrite).toHaveBeenCalledOnce();
    expect(second.stream.closeWrite).toHaveBeenCalledOnce();
  });

  test("aborts both control streams after the reverse half-close grace", async () => {
    vi.useFakeTimers();
    const left = fakeStream({ read: async () => null });
    let rejectRightRead: ((error: Error) => void) | undefined;
    const right = fakeStream({
      read: () => new Promise((_resolve, reject) => { rejectRightRead = reject; }),
      abort: (error) => rejectRightRead?.(error ?? new Error("aborted")),
    });

    const splicing = spliceTunnelStreamsV3(
      left,
      right,
      new AbortController().signal,
      20,
    );
    const rejection = expect(splicing).rejects.toThrow("Flowersec tunnel control half-close timed out");

    await vi.advanceTimersByTimeAsync(20);
    await rejection;
    expect(right.closeWrite).toHaveBeenCalledOnce();
    expect(left.abort).toHaveBeenCalledOnce();
    expect(right.abort).toHaveBeenCalledOnce();
  });

  test("starts the control half-close grace before a stuck FIN settles", async () => {
    vi.useFakeTimers();
    const left = fakeStream({ read: async () => null });
    const right = fakeStream({
      read: () => new Promise(() => {}),
      closeWrite: () => new Promise(() => {}),
    });

    const splicing = spliceTunnelStreamsV3(
      left,
      right,
      new AbortController().signal,
      20,
    );
    const rejection = expect(splicing).rejects.toThrow("Flowersec tunnel control half-close timed out");

    await vi.advanceTimersByTimeAsync(20);
    await rejection;
    expect(left.abort).toHaveBeenCalledOnce();
    expect(right.abort).toHaveBeenCalledOnce();
  });

  test("does not mistake an undefined copy rejection for a clean half-close", async () => {
    const left = fakeStream({ read: () => Promise.reject(undefined) });
    const right = fakeStream({ read: () => new Promise(() => {}) });

    await expect(spliceTunnelStreamsV3(
      left,
      right,
      new AbortController().signal,
    )).rejects.toBeUndefined();
    expect(left.reset).toHaveBeenCalledOnce();
    expect(right.reset).toHaveBeenCalledOnce();
  });
});

function fakeAdmission(stream: CarrierStreamV3): ReceivedSessionAdmissionV3 {
  const carrier = {
    kind: "websocket",
    path: "tunnel",
    inboundBidirectionalStreamCapacity: 3,
    openStream: async () => stream,
    acceptStream: async () => stream,
    waitTermination: async () => undefined,
    close: async () => undefined,
    abort: () => undefined,
  } satisfies CarrierSessionV3;
  return {
    carrier,
    stream,
    rawFSB3: new Uint8Array(),
    decoded: undefined,
  } as unknown as ReceivedSessionAdmissionV3;
}

function fakeStream(overrides: Partial<CarrierStreamV3> = {}): CarrierStreamV3 {
  const read = overrides.read ?? (async () => null);
  const write = overrides.write ?? (async (data: Uint8Array) => data.length);
  const closeWrite = overrides.closeWrite ?? (async () => undefined);
  const stopSending = overrides.stopSending ?? (async () => undefined);
  const reset = overrides.reset ?? (async () => undefined);
  const abort = overrides.abort ?? (() => undefined);
  return {
    read: vi.fn(read),
    write: vi.fn(write),
    closeWrite: vi.fn(closeWrite),
    stopSending: vi.fn(stopSending),
    reset: vi.fn(reset),
    abort: vi.fn(abort),
  } satisfies CarrierStreamV3;
}
