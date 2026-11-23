import { afterEach, describe, expect, test, vi } from "vitest";

import { CarrierError, type CarrierSessionV3, type CarrierStreamV3 } from "../v3/carrier.js";
import type { ReceivedSessionAdmissionV3 } from "../v3/serverAdmission.js";
import {
  activateTunnelControlStreamsV3,
  bridgeTunnelPairV3,
  rejectTunnelPairAdmissionsV3,
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

  test("bounds paired rejection when an admission FIN never settles", async () => {
    vi.useFakeTimers();
    const first = fakeAdmission(fakeStream());
    const second = fakeAdmission(fakeStream({ closeWrite: () => new Promise(() => {}) }));

    const rejecting = rejectTunnelPairAdmissionsV3(
      [first, second],
      "pair_timeout",
      true,
      new Set(["pair_timeout"]),
      new AbortController().signal,
      20,
    );
    const rejection = expect(rejecting).rejects.toThrow(
      "Flowersec tunnel admission rejection timed out",
    );

    await vi.advanceTimersByTimeAsync(20);
    await rejection;
    expect(first.carrier.abort).toHaveBeenCalledOnce();
    expect(second.carrier.abort).toHaveBeenCalledOnce();
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

  test("forwards a reverse control tail after EOF and completes both FINs without reset", async () => {
    const forwardFIN = deferred<void>();
    const reverse = deferred<Uint8Array>();
    const left = fakeStream();
    const right = fakeStream({ closeWrite: async () => { forwardFIN.resolve(); } });
    vi.mocked(right.read).mockReturnValueOnce(reverse.promise);
    const tail = Uint8Array.of(5, 7, 11);

    const splicing = spliceTunnelStreamsV3(left, right, new AbortController().signal, 1_000);
    await forwardFIN.promise;
    expect(left.closeWrite).not.toHaveBeenCalled();
    reverse.resolve(tail);
    await splicing;
    expect(left.write).toHaveBeenCalledWith(tail, expect.anything());
    for (const leg of [left, right]) {
      expect(leg.closeWrite).toHaveBeenCalledOnce();
      expect(leg.abort).not.toHaveBeenCalled();
      expect(leg.reset).not.toHaveBeenCalled();
    }
  });

  test("preserves a reverse control failure while the forward FIN is pending", async () => {
    vi.useFakeTimers();
    const forwardFIN = deferred<void>();
    const reverse = deferred<Uint8Array>();
    const failure = new Error("reverse stream reset");
    const left = fakeStream();
    const right = fakeStream({
      closeWrite: () => { forwardFIN.resolve(); return new Promise(() => {}); },
      read: () => reverse.promise,
    });

    const splicing = spliceTunnelStreamsV3(left, right, new AbortController().signal, 20);
    const outcome = splicing.catch((error: unknown) => error);
    await forwardFIN.promise;
    reverse.reject(failure);
    await vi.advanceTimersByTimeAsync(20);
    expect(await outcome).toBe(failure);
    expect(left.abort).toHaveBeenCalledWith(failure);
    expect(right.abort).toHaveBeenCalledWith(failure);
  });

  test("revoking a half-closed control stream preserves the cancellation reason", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const forwardFIN = deferred<void>();
    const left = fakeStream();
    const right = fakeStream({
      closeWrite: async () => { forwardFIN.resolve(); },
      read: () => new Promise(() => {}),
    });
    const reason = new Error("pair revoked");

    const splicing = spliceTunnelStreamsV3(left, right, controller.signal, 20);
    const outcome = splicing.catch((error: unknown) => error);
    await forwardFIN.promise;
    controller.abort(reason);
    await vi.advanceTimersByTimeAsync(20);
    expect(await outcome).toBe(reason);
    expect(left.abort).toHaveBeenCalledWith(reason);
    expect(right.abort).toHaveBeenCalledWith(reason);
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

  test("drains the control tail when an auxiliary receive closes first", async () => {
    const forwardFIN = deferred<void>();
    const reverse = deferred<Uint8Array>();
    const receive = deferred<CarrierStreamV3>();
    const right = fakeStream();
    const left = fakeStream({ closeWrite: async () => { forwardFIN.resolve(); } });
    vi.mocked(left.read).mockReturnValueOnce(reverse.promise);
    const first = fakeCarrier({ acceptStream: () => receive.promise });
    vi.mocked(first.acceptStream).mockResolvedValueOnce(left);
    const second = fakeCarrier({ openStream: async () => right, acceptStream: () => receive.promise });
    const pair = bridgeTunnelPairV3(first, second, new AbortController().signal, pairLimits);

    await forwardFIN.promise;
    receive.reject(new CarrierError("closed", "accept closed"));
    await new Promise<void>((resolve) => setImmediate(resolve));
    const tail = Uint8Array.of(13);
    reverse.resolve(tail);
    await pair;
    expect(right.write).toHaveBeenCalledWith(tail, expect.anything());
    expect(first.abort).not.toHaveBeenCalled();
    expect(second.abort).not.toHaveBeenCalled();
  });

  test("preserves the control read error and aborts both carriers", async () => {
    const failure = new CarrierError("reset", "reverse reset");
    const first = fakeCarrier({ acceptStream: canceledAccept });
    vi.mocked(first.acceptStream).mockResolvedValueOnce(fakeStream({ read: () => new Promise(() => {}) }));
    const second = fakeCarrier({
      openStream: async () => fakeStream({ read: async () => { throw failure; } }),
      acceptStream: canceledAccept,
    });
    await expect(bridgeTunnelPairV3(first, second, new AbortController().signal, pairLimits)).rejects.toBe(failure);
    expect(first.abort).toHaveBeenCalledOnce();
    expect(second.abort).toHaveBeenCalledOnce();
  });

  test("rejects a client FIN before the server FIN", async () => {
    const first = fakeCarrier({ acceptStream: canceledAccept });
    vi.mocked(first.acceptStream).mockResolvedValueOnce(fakeStream());
    const second = fakeCarrier({ acceptStream: canceledAccept });
    await expect(bridgeTunnelPairV3(first, second, new AbortController().signal, pairLimits)).rejects.toThrow("client FIN preceded server FIN");
    expect(first.close).not.toHaveBeenCalled();
    expect(first.abort).toHaveBeenCalledOnce();
    expect(second.abort).toHaveBeenCalledOnce();
  });

  test("retires only the client after both FIN writes settle and waits for the server", async () => {
    const requestFIN = deferred<void>();
    const replyFIN = deferred<void>();
    const waiting = deferred<void>();
    const consumed = deferred<boolean>();
    const request = fakeStream({ closeWrite: () => replyFIN.promise });
    const response = fakeStream({ closeWrite: async () => { requestFIN.resolve(); } });
    vi.mocked(response.read).mockImplementationOnce(async () => { await requestFIN.promise; return Uint8Array.of(7); });
    const first = fakeCarrier({ acceptStream: canceledAccept });
    const second = fakeCarrier({ acceptStream: canceledAccept, waitRemoteSessionClose: () => { waiting.resolve(); return consumed.promise; } });
    vi.mocked(first.acceptStream).mockResolvedValueOnce(response);
    vi.mocked(second.openStream).mockResolvedValueOnce(request);
    const pair = bridgeTunnelPairV3(first, second, new AbortController().signal, pairLimits);

    await requestFIN.promise;
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(request.write).toHaveBeenCalledWith(Uint8Array.of(7), expect.anything());
    expect(first.close).not.toHaveBeenCalled();
    replyFIN.resolve();
    await waiting.promise;
    expect(first.close).toHaveBeenCalledWith({ code: 1, reason: "session closed" });
    consumed.resolve(true);
    await pair;
    expect(first.close).toHaveBeenCalledOnce();
    expect(second.close).not.toHaveBeenCalled();
    expect(first.abort).not.toHaveBeenCalled();
    expect(second.abort).not.toHaveBeenCalled();
  });

  test.each(["revocation", "timeout", "reset", "wrong reason"])("preserves %s while waiting for the server to retire", async (outcome) => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const waiting = deferred<void>();
    const termination = deferred<boolean>();
    const first = fakeCarrier({ acceptStream: canceledAccept });
    const second = fakeCarrier({ acceptStream: canceledAccept, waitRemoteSessionClose: () => { waiting.resolve(); return termination.promise; } });
    stageOrderedFINs(first, second);
    const pair = bridgeTunnelPairV3(first, second, controller.signal, pairLimits);
    const failure = new CarrierError(outcome === "reset" ? "reset" : "aborted", outcome);
    const rejected = outcome === "timeout" ? expect(pair).rejects.toThrow("carrier close timed out") :
      outcome === "wrong reason" ? expect(pair).rejects.toThrow("missing normal tunnel server close") : expect(pair).rejects.toBe(failure);
    await waiting.promise;
    if (outcome === "timeout") await vi.advanceTimersByTimeAsync(pairLimits.cleanupTimeoutMs);
    else if (outcome === "reset") termination.reject(failure);
    else if (outcome === "wrong reason") termination.resolve(false);
    else controller.abort(failure);
    await rejected;
    termination.resolve(false);
    await Promise.resolve();
    expect(second.close).not.toHaveBeenCalled();
    expect(first.abort).toHaveBeenCalledOnce();
    expect(second.abort).toHaveBeenCalledOnce();
  });

  test("bounds a stuck graceful close of the client carrier", async () => {
    vi.useFakeTimers();
    const first = fakeCarrier({ acceptStream: canceledAccept, close: () => new Promise(() => {}) });
    const second = fakeCarrier({ acceptStream: canceledAccept });
    stageOrderedFINs(first, second);
    const pair = bridgeTunnelPairV3(first, second, new AbortController().signal, pairLimits);
    const rejected = expect(pair).rejects.toThrow("carrier close timed out");
    await vi.advanceTimersByTimeAsync(pairLimits.cleanupTimeoutMs);
    await rejected;
    expect(first.close).toHaveBeenCalledOnce();
    expect(second.abort).toHaveBeenCalledOnce();
  });

  test("aborts an initial control stream when its peer never activates", async () => {
    vi.useFakeTimers();
    const incoming = fakeStream();
    const first = fakeCarrier({ acceptStream: async () => incoming });
    const second = fakeCarrier({ openStream: () => new Promise(() => {}) });

    const activation = activateTunnelControlStreamsV3(
      first,
      second,
      new AbortController().signal,
      20,
    );
    const rejection = expect(activation).rejects.toThrow("Flowersec tunnel activation timed out");

    await vi.advanceTimersByTimeAsync(20);
    await rejection;
    expect(incoming.abort).toHaveBeenCalledOnce();
  });

  test("aborts a control stream returned after the activation deadline", async () => {
    vi.useFakeTimers();
    let returnIncoming!: (stream: CarrierStreamV3) => void;
    const incoming = fakeStream();
    const first = fakeCarrier({
      acceptStream: () => new Promise((resolve) => { returnIncoming = resolve; }),
    });
    const second = fakeCarrier();

    const activation = activateTunnelControlStreamsV3(
      first,
      second,
      new AbortController().signal,
      20,
    );
    const rejection = expect(activation).rejects.toThrow("Flowersec tunnel activation timed out");

    await vi.advanceTimersByTimeAsync(20);
    await rejection;
    returnIncoming(incoming);
    await vi.runAllTimersAsync();
    expect(incoming.abort).toHaveBeenCalledOnce();
    expect(second.openStream).not.toHaveBeenCalled();
  });
});

const pairLimits = { maxConcurrentStreams: 2, admissionTimeoutMs: 500, cleanupTimeoutMs: 200 };

const canceledAccept: CarrierSessionV3["acceptStream"] = ({ signal } = {}) =>
  new Promise((_, reject) => signal!.addEventListener("abort", () => reject(signal!.reason), { once: true }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fakeAdmission(stream: CarrierStreamV3): ReceivedSessionAdmissionV3 {
  const carrier = fakeCarrier({
    openStream: async () => stream,
    acceptStream: async () => stream,
  });
  return {
    carrier,
    stream,
    rawFSB3: new Uint8Array(),
    decoded: undefined,
  } as unknown as ReceivedSessionAdmissionV3;
}

function stageOrderedFINs(first: CarrierSessionV3, second: CarrierSessionV3): void {
  const serverFIN = deferred<null>();
  vi.mocked(first.acceptStream).mockResolvedValueOnce(fakeStream({ read: () => serverFIN.promise, closeWrite: async () => { serverFIN.resolve(null); } }));
  vi.mocked(second.openStream).mockResolvedValueOnce(fakeStream());
}

function fakeCarrier(overrides: Partial<CarrierSessionV3> = {}): CarrierSessionV3 {
  const carrier = {
    kind: "websocket",
    path: "tunnel",
    inboundBidirectionalStreamCapacity: 3,
    openStream: overrides.openStream ?? (async () => fakeStream()),
    acceptStream: overrides.acceptStream ?? (async () => fakeStream()),
    waitTermination: vi.fn(overrides.waitTermination ?? (async () => undefined)),
    waitRemoteSessionClose: vi.fn(overrides.waitRemoteSessionClose ?? (async () => true)),
    close: vi.fn(overrides.close ?? (async () => undefined)),
    abort: vi.fn(() => undefined),
  } satisfies CarrierSessionV3;
  return {
    ...carrier,
    openStream: vi.fn(carrier.openStream),
    acceptStream: vi.fn(carrier.acceptStream),
  };
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
