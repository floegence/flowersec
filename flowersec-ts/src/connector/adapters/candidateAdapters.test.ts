import { describe, expect, test, vi } from "vitest";

import type { ArtifactV2, CanonicalArtifactCandidateV2 } from "../../v2/artifact.js";
import type { NativeCarrierSessionV2, NativeCarrierStreamV2 } from "../../v2/carrier.js";
import type { WebSocketLike } from "../../ws-client/binaryTransport.js";
import { createWebSocketCandidateFactoryV2 } from "./webSocketCandidate.js";
import { createWebTransportCandidateFactoryV2 } from "./webTransportCandidate.js";

describe("runtime candidate adapters", () => {
  test("WebTransport binds admission stream direction and finalizes exactly once", async () => {
    const accepted = nativeStream();
    const opened = nativeStream();
    const carrier = nativeCarrier({ accepted, opened });
    const candidate = webTransportCandidate();
    const create = vi.fn(async () => carrier.value);
    const attempt = createWebTransportCandidateFactoryV2(create).create(candidate, artifact("direct"));
    const ready = await attempt.ready();

    const admission = await ready.openAdmissionChannel();
    expect(admission.framing).toBe("stream");
    expect(carrier.acceptStream).toHaveBeenCalledOnce();
    expect(carrier.openStream).not.toHaveBeenCalled();
    expect(ready.finalize().kind).toBe("webtransport");
    expect(() => ready.finalize()).toThrow("already finalized");
    await ready.close();
    ready.abort();
    expect(carrier.close).toHaveBeenCalledOnce();
    expect(carrier.abort).toHaveBeenCalledWith({ code: 6, reason: "candidate aborted" });
  });

  test("WebTransport links parent cancellation and rejects the wrong carrier", async () => {
    const controller = new AbortController();
    controller.abort(new Error("canceled"));
    const factory = vi.fn(async (_candidate, _artifact, signal: AbortSignal) => {
      expect(signal.aborted).toBe(true);
      throw signal.reason;
    });
    const attempt = createWebTransportCandidateFactoryV2(factory)
      .create(webTransportCandidate(), artifact("direct"));
    await expect(attempt.ready(controller.signal)).rejects.toThrow("canceled");
    attempt.abort();

    expect(() => createWebTransportCandidateFactoryV2(factory).create(
      { ...webTransportCandidate(), carrier: "raw_quic" },
      artifact("direct"),
    )).toThrow("unsupported WebTransport carrier");
  });

  test.each([
    ["direct", "flowersec.direct.v2"],
    ["tunnel", "flowersec.tunnel.v2"],
  ] as const)("WebSocket uses the %s admission subprotocol", async (path, expectedProtocol) => {
    const socket = fakeSocket(1, expectedProtocol);
    const create = vi.fn(() => socket.value);
    const attempt = createWebSocketCandidateFactoryV2(create)
      .create(webSocketCandidate(), artifact(path));
    const ready = await attempt.ready();

    expect(create).toHaveBeenCalledWith(webSocketCandidate().normalized_url, expectedProtocol);
    expect(ready.inboundBidirectionalStreamCapacity).toBe(66);
    expect((await ready.openAdmissionChannel()).framing).toBe("message");
    expect(ready.finalize().kind).toBe("websocket");
    expect(() => ready.finalize()).toThrow("already finalized");
    await ready.close();
    expect(socket.close).toHaveBeenCalled();
  });

  test("WebSocket propagates pre-open errors, protocol mismatch, and cancellation", async () => {
    const errored = fakeSocket(0);
    const erroredAttempt = createWebSocketCandidateFactoryV2(() => errored.value)
      .create(webSocketCandidate(), artifact("direct"));
    const pendingError = erroredAttempt.ready();
    errored.emit("error", {});
    await expect(pendingError).rejects.toThrow("failed before ready");

    const closed = fakeSocket(0);
    const closedAttempt = createWebSocketCandidateFactoryV2(() => closed.value)
      .create(webSocketCandidate(), artifact("direct"));
    const pendingClose = closedAttempt.ready();
    closed.emit("close", {});
    await expect(pendingClose).rejects.toThrow("closed before ready");

    const mismatched = fakeSocket(0, "wrong.protocol");
    const mismatchAttempt = createWebSocketCandidateFactoryV2(() => mismatched.value)
      .create(webSocketCandidate(), artifact("direct"));
    const pendingMismatch = mismatchAttempt.ready();
    mismatched.emit("open", {});
    await expect(pendingMismatch).rejects.toThrow("unexpected WebSocket subprotocol");

    const canceled = fakeSocket(0);
    const controller = new AbortController();
    const canceledAttempt = createWebSocketCandidateFactoryV2(() => canceled.value)
      .create(webSocketCandidate(), artifact("direct"));
    const pendingCancel = canceledAttempt.ready(controller.signal);
    controller.abort();
    await expect(pendingCancel).rejects.toThrow("candidate aborted");
    expect(canceled.close).toHaveBeenCalled();
    canceledAttempt.abort();

    const preCanceled = fakeSocket(0);
    const preCanceledSignal = new AbortController();
    preCanceledSignal.abort();
    const preCanceledAttempt = createWebSocketCandidateFactoryV2(() => preCanceled.value)
      .create(webSocketCandidate(), artifact("direct"));
    await expect(preCanceledAttempt.ready(preCanceledSignal.signal)).rejects.toThrow("candidate aborted");

    expect(() => createWebSocketCandidateFactoryV2(() => canceled.value).create(
      { ...webSocketCandidate(), carrier: "webtransport" },
      artifact("direct"),
    )).toThrow("unsupported WebSocket carrier");
  });
});

function artifact(path: "direct" | "tunnel"): ArtifactV2 {
  return {
    path: {
      kind: path,
      ...(path === "tunnel" ? { role: 1 } : {}),
    },
    session: { max_inbound_streams: 64 },
  } as ArtifactV2;
}

function webTransportCandidate(): CanonicalArtifactCandidateV2 {
  return {
    carrier: "webtransport",
    id: "t1",
    normalized_url: "https://example.test/flowersec/webtransport/v2/direct",
    wire_profile: "native-quic-v2",
  } as CanonicalArtifactCandidateV2;
}

function webSocketCandidate(): CanonicalArtifactCandidateV2 {
  return {
    carrier: "websocket",
    id: "w1",
    normalized_url: "wss://example.test/flowersec/v2/direct",
    wire_profile: "flowersec-direct/2",
  } as CanonicalArtifactCandidateV2;
}

function nativeStream(): NativeCarrierStreamV2 {
  return {
    read: vi.fn(async () => null),
    write: vi.fn(async (data: Uint8Array) => data.length),
    closeWrite: vi.fn(async () => undefined),
    stopSending: vi.fn(async () => undefined),
    reset: vi.fn(async () => undefined),
    abort: vi.fn(),
  };
}

function nativeCarrier(streams: Readonly<{ accepted: NativeCarrierStreamV2; opened: NativeCarrierStreamV2 }>) {
  const acceptStream = vi.fn(async () => streams.accepted);
  const openStream = vi.fn(async () => streams.opened);
  const close = vi.fn(async () => undefined);
  const abort = vi.fn();
  return {
    value: {
      kind: "webtransport" as const,
      path: "direct" as const,
      inboundBidirectionalStreamCapacity: 66,
      acceptStream,
      openStream,
      waitTermination: vi.fn(async () => undefined),
      close,
      abort,
    } satisfies NativeCarrierSessionV2,
    acceptStream,
    openStream,
    close,
    abort,
  };
}

function fakeSocket(readyState: number, protocol?: string) {
  const listeners = new Map<string, Set<(event: unknown) => void>>();
  const close = vi.fn();
  const value = {
    binaryType: "",
    readyState,
    bufferedAmount: 0,
    protocol,
    send: vi.fn(),
    close,
    addEventListener(type: string, listener: (event: unknown) => void) {
      const current = listeners.get(type) ?? new Set();
      current.add(listener);
      listeners.set(type, current);
    },
    removeEventListener(type: string, listener: (event: unknown) => void) {
      listeners.get(type)?.delete(listener);
    },
  } as WebSocketLike & Readonly<{ protocol?: string }>;
  return {
    value,
    close,
    emit(type: string, event: unknown) {
      for (const listener of listeners.get(type) ?? []) listener(event);
    },
  };
}
