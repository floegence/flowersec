import { describe, expect, test, vi } from "vitest";

import type { ArtifactV2, CanonicalArtifactCandidateV2 } from "../../v2/artifact.js";
import type { NativeCarrierSessionV2, NativeCarrierStreamV2 } from "../../v2/carrier.js";
import { createRawQuicCandidateFactoryV2 } from "./rawQuicCandidate.js";

describe("raw QUIC candidate adapter", () => {
  test.each(["direct", "tunnel"] as const)(
    "opens a native admission stream and finalizes the %s carrier exactly once",
    async (path) => {
      const admission = nativeStream();
      const carrier = nativeCarrier(path, admission);
      const connect = vi.fn(async () => carrier.value);
      const candidate = rawQuicCandidate();
      const attempt = createRawQuicCandidateFactoryV2(connect).create(candidate, artifact(path));

      const ready = await attempt.ready();

      expect(connect).toHaveBeenCalledOnce();
      expect(connect.mock.calls[0]?.[0]).toBe(candidate);
      expect(connect.mock.calls[0]?.[1].path.kind).toBe(path);
      expect(connect.mock.calls[0]?.[2]).toBeInstanceOf(AbortSignal);
      expect((await ready.openAdmissionChannel()).framing).toBe("stream");
      expect(carrier.openStream).toHaveBeenCalledOnce();
      expect(ready.finalize().kind).toBe("raw_quic");
      expect(() => ready.finalize()).toThrow("already finalized");
      await ready.close();
      ready.abort();
      expect(carrier.close).toHaveBeenCalledOnce();
      expect(carrier.abort).toHaveBeenCalledWith({ code: 6, reason: "candidate aborted" });
    },
  );

  test("links cancellation and rejects a mismatched carrier", async () => {
    const controller = new AbortController();
    const connect = vi.fn(async (_candidate, _artifact, signal: AbortSignal) => {
      await new Promise<void>((_resolve, reject) => {
        signal.addEventListener("abort", () => reject(signal.reason), { once: true });
      });
      throw new Error("unreachable");
    });
    const attempt = createRawQuicCandidateFactoryV2(connect)
      .create(rawQuicCandidate(), artifact("direct"));
    const pending = attempt.ready(controller.signal);
    controller.abort(new Error("canceled"));
    await expect(pending).rejects.toThrow("canceled");
    attempt.abort();

    expect(() => createRawQuicCandidateFactoryV2(connect).create(
      { ...rawQuicCandidate(), carrier: "webtransport" },
      artifact("direct"),
    )).toThrow("unsupported raw QUIC carrier");
  });
});

function artifact(path: "direct" | "tunnel"): ArtifactV2 {
  return {
    path: { kind: path, ...(path === "tunnel" ? { role: 1 } : {}) },
    session: { max_inbound_streams: 64 },
  } as ArtifactV2;
}

function rawQuicCandidate(): CanonicalArtifactCandidateV2 {
  return {
    carrier: "raw_quic",
    id: "q1",
    normalized_url: "quic://localhost:443",
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

function nativeCarrier(path: "direct" | "tunnel", admission: NativeCarrierStreamV2) {
  const openStream = vi.fn(async () => admission);
  const close = vi.fn(async () => undefined);
  const abort = vi.fn();
  return {
    value: {
      kind: "raw_quic" as const,
      path,
      inboundBidirectionalStreamCapacity: 66,
      openStream,
      acceptStream: vi.fn(async () => nativeStream()),
      waitTermination: vi.fn(async () => undefined),
      close,
      abort,
    } satisfies NativeCarrierSessionV2,
    openStream,
    close,
    abort,
  };
}
