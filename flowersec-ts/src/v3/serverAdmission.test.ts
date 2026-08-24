import { readFileSync } from "node:fs";

import { describe, expect, test, vi } from "vitest";

import {
  AdmissionStatusV3,
  ArtifactV3Error,
  buildFSB3RequestV3,
  decodeArtifactV3JSON,
  decodeFSB3RequestV3,
  encodeFSB3RequestV3,
  type ArtifactV3,
} from "./artifact.js";
import type { CarrierSessionV3, CarrierStreamV3 } from "./carrier.js";
import {
  acceptCarrierSessionV3,
  createAdmissionReasonRegistryV3,
  acceptReceivedSessionV3,
  receiveSessionAdmissionV3,
  rejectSessionAdmissionV3,
  type ReceivedSessionAdmissionV3,
} from "./serverAdmission.js";
import type { SessionProtocolRuntimeV3 } from "./session.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const directArtifact = decodeArtifactV3JSON(fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "direct")!.artifact_json);
const tunnelArtifact = decodeArtifactV3JSON(fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "tunnel")!.artifact_json);

describe("transport v3 server admission", () => {
  test("validates deployment reason registries at configuration time", () => {
    expect(createAdmissionReasonRegistryV3(["expired_artifact"], ["policy_denied"]))
      .toEqual(new Set(["expired_artifact", "policy_denied"]));
    expect(() => createAdmissionReasonRegistryV3([], ["1invalid"])).toThrowError(ArtifactV3Error);
    expect(() => createAdmissionReasonRegistryV3([], ["tls_pin_mismatch"]))
      .toThrowError(ArtifactV3Error);
    expect(() => createAdmissionReasonRegistryV3(["capacity"], ["capacity"]))
      .toThrowError(TypeError);
  });

  test("aborts the carrier when rejection encoding fails before the first write", async () => {
    const abort = vi.fn<CarrierSessionV3["abort"]>();
    const write = vi.fn<CarrierStreamV3["write"]>(async () => 0);
    const received = fakeReceived(abort, write);

    await expect(rejectSessionAdmissionV3(received, {
      accepted: false,
      status: AdmissionStatusV3.Reject,
      reason: "tls_pin_mismatch",
    }, new Set(["tls_pin_mismatch"]))).rejects.toThrowError(ArtifactV3Error);

    expect(write).not.toHaveBeenCalled();
    expect(abort).toHaveBeenCalledOnce();
    expect(abort).toHaveBeenCalledWith({ code: 6, reason: "admission rejected" });
  });

  test("resolves application handlers only after artifact binding and expiry validation", async () => {
    const resolveRPCRouter = vi.fn(() => {
      throw new Error("handler resolver must not run");
    });
    const mismatchedArtifact = {
      ...directArtifact,
      path: { ...directArtifact.path, routing_token: "different-routing-token" },
    } satisfies ArtifactV3;

    await expect(acceptReceivedSessionV3(validReceived(directArtifact), mismatchedArtifact, {
      runtime: {} as SessionProtocolRuntimeV3,
      admissionReasons: new Set(["expired_artifact"]),
      resolveRPCRouter,
    })).rejects.toThrow("authorized artifact does not match admission");
    expect(resolveRPCRouter).not.toHaveBeenCalled();

    await expect(acceptReceivedSessionV3(validReceived(directArtifact), directArtifact, {
      runtime: {} as SessionProtocolRuntimeV3,
      admissionReasons: new Set(["expired_artifact"]),
      resolveRPCRouter,
      nowUnixSeconds: () => directArtifact.session.init_expire_at_unix_s,
    })).rejects.toMatchObject({ reason: "expired_artifact" });
    expect(resolveRPCRouter).not.toHaveBeenCalled();
  });

  test("aborts direct received-session resources on carrier binding mismatch", async () => {
    const received = validReceived(directArtifact);
    const mismatched = {
      ...received,
      carrier: { ...received.carrier, kind: "raw_quic" as const },
    } satisfies ReceivedSessionAdmissionV3;

    await expect(acceptReceivedSessionV3(mismatched, directArtifact, {
      runtime: {} as SessionProtocolRuntimeV3,
      admissionReasons: new Set(["expired_artifact"]),
    })).rejects.toThrow("admission carrier binding mismatch");

    expect(received.stream.abort).toHaveBeenCalledOnce();
    expect(received.carrier.abort).toHaveBeenCalledOnce();
  });

  test("rejects carrier binding before application authorization or stateful lease spend", async () => {
    if (directArtifact.path.kind !== "direct") throw new Error("direct artifact required");
    const chosen = directArtifact.path.candidates.find(({ carrier }) => carrier === "webtransport");
    if (chosen === undefined) throw new Error("WebTransport candidate required");
    const rawFSB3 = encodeFSB3RequestV3(buildFSB3RequestV3(directArtifact, chosen.id));
    const write = vi.fn<CarrierStreamV3["write"]>(async (value) => value.length);
    const streamAbort = vi.fn<CarrierStreamV3["abort"]>();
    let nextRead: Uint8Array | null = rawFSB3;
    const stream = {
      read: async () => {
        const value = nextRead;
        nextRead = null;
        return value;
      },
      write,
      closeWrite: vi.fn(async () => undefined),
      stopSending: async () => undefined,
      reset: async () => undefined,
      abort: streamAbort,
    } satisfies CarrierStreamV3;
    const carrierAbort = vi.fn<CarrierSessionV3["abort"]>();
    const carrier = {
      kind: "websocket",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
      openStream: async () => stream,
      acceptStream: async () => stream,
      waitTermination: async () => undefined,
      close: async () => undefined,
      abort: carrierAbort,
    } satisfies CarrierSessionV3;
    let spends = 0;
    const authorize = vi.fn(async () => {
      spends += 1;
      return { accepted: true as const, artifact: directArtifact };
    });

    await expect(acceptCarrierSessionV3(carrier, authorize, {
      runtime: {} as SessionProtocolRuntimeV3,
      admissionReasons: new Set(["expired_artifact"]),
    })).rejects.toThrow("admission carrier binding mismatch");

    expect(authorize).not.toHaveBeenCalled();
    expect(spends).toBe(0);
    expect(write).not.toHaveBeenCalled();
    expect(streamAbort).toHaveBeenCalledOnce();
    expect(carrierAbort).toHaveBeenCalled();
  });

  test.each([
    ["v2 magic", (header: Uint8Array) => { header[3] = 0x32; }],
    ["v2 version", (header: Uint8Array) => { header[4] = 2; }],
    ["invalid path", (header: Uint8Array) => { header[5] = 0; }],
    ["nonzero reserved[0]", (header: Uint8Array) => { header[6] = 1; }],
    ["nonzero reserved[1]", (header: Uint8Array) => { header[7] = 1; }],
  ] as const)("rejects an invalid streaming admission header (%s) before waiting for its declared payload", async (
    _name,
    mutateHeader,
  ) => {
    const chosen = directArtifact.path.candidates.find(({ carrier }) => carrier === "websocket");
    if (chosen === undefined) throw new Error("WebSocket candidate required");
    const valid = encodeFSB3RequestV3(buildFSB3RequestV3(directArtifact, chosen.id));
    const header = valid.slice(0, 12);
    mutateHeader(header);
    new DataView(header.buffer, header.byteOffset, header.byteLength).setUint32(8, 32_768, false);

    const read = vi.fn<CarrierStreamV3["read"]>(async () => {
      if (read.mock.calls.length === 1) return header;
      return await new Promise<Uint8Array | null>(() => {});
    });
    const streamAbort = vi.fn<CarrierStreamV3["abort"]>();
    const stream = {
      read,
      write: async (value: Uint8Array) => value.length,
      closeWrite: async () => undefined,
      stopSending: async () => undefined,
      reset: async () => undefined,
      abort: streamAbort,
    } satisfies CarrierStreamV3;
    const carrierAbort = vi.fn<CarrierSessionV3["abort"]>();
    const carrier = {
      kind: "websocket",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
      openStream: async () => stream,
      acceptStream: async () => stream,
      waitTermination: async () => undefined,
      close: async () => undefined,
      abort: carrierAbort,
    } satisfies CarrierSessionV3;

    const outcome = await Promise.race([
      receiveSessionAdmissionV3(carrier).then(
        () => "accepted",
        () => "rejected",
      ),
      new Promise<"payload timeout">((resolve) => {
        setTimeout(() => resolve("payload timeout"), 100);
      }),
    ]);

    expect(outcome).toBe("rejected");
    expect(read).toHaveBeenCalledOnce();
    expect(streamAbort).toHaveBeenCalledOnce();
    expect(carrierAbort).toHaveBeenCalledOnce();
  });

  test("rejects tunnel path mismatch before authorization, FSA3, or resource reuse", async () => {
    if (tunnelArtifact.path.kind !== "tunnel") throw new Error("tunnel artifact required");
    const chosen = tunnelArtifact.path.candidates.find(({ carrier }) => carrier === "websocket");
    if (chosen === undefined) throw new Error("WebSocket candidate required");
    const rawFSB3 = encodeFSB3RequestV3(buildFSB3RequestV3(tunnelArtifact, chosen.id));
    let pending: Uint8Array | null = rawFSB3;
    const write = vi.fn<CarrierStreamV3["write"]>(async (value) => value.length);
    const streamAbort = vi.fn<CarrierStreamV3["abort"]>();
    const stream = {
      read: async () => {
        const value = pending;
        pending = null;
        return value;
      },
      write,
      closeWrite: vi.fn(async () => undefined),
      stopSending: async () => undefined,
      reset: async () => undefined,
      abort: streamAbort,
    } satisfies CarrierStreamV3;
    const carrierAbort = vi.fn<CarrierSessionV3["abort"]>();
    const carrier = {
      kind: "websocket",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
      openStream: async () => stream,
      acceptStream: async () => stream,
      waitTermination: async () => undefined,
      close: async () => undefined,
      abort: carrierAbort,
    } satisfies CarrierSessionV3;
    const authorize = vi.fn(async () => ({ accepted: true as const, artifact: tunnelArtifact }));

    await expect(acceptCarrierSessionV3(carrier, authorize, {
      runtime: {} as SessionProtocolRuntimeV3,
      admissionReasons: new Set(["expired_artifact"]),
    })).rejects.toThrow("admission carrier binding mismatch");

    expect(authorize).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(streamAbort).toHaveBeenCalledOnce();
    expect(carrierAbort).toHaveBeenCalledOnce();
  });

  test("cancels a handler resolver that ignores its admission signal", async () => {
    const controller = new AbortController();
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    const accepting = acceptReceivedSessionV3(validReceived(directArtifact), directArtifact, {
      runtime: {} as SessionProtocolRuntimeV3,
      admissionReasons: new Set(["expired_artifact"]),
      resolveRPCRouter: () => {
        markStarted();
        return new Promise(() => {});
      },
      signal: controller.signal,
    });

    await started;
    controller.abort(new Error("accept canceled"));
    await expect(accepting).rejects.toThrow("accept canceled");
  });
});

function validReceived(artifact: ArtifactV3): ReceivedSessionAdmissionV3 {
  const chosen = artifact.path.candidates.find(({ carrier }) => carrier === "websocket");
  if (chosen === undefined) throw new Error("WebSocket candidate required");
  const rawFSB3 = encodeFSB3RequestV3(buildFSB3RequestV3(artifact, chosen.id));
  const stream = {
    read: async () => null,
    write: vi.fn(async (value: Uint8Array) => value.length),
    closeWrite: vi.fn(async () => undefined),
    stopSending: async () => undefined,
    reset: async () => undefined,
    abort: vi.fn(),
  } satisfies CarrierStreamV3;
  const carrier = {
    kind: "websocket",
    path: artifact.path.kind,
    inboundBidirectionalStreamCapacity: 3,
    openStream: async () => stream,
    acceptStream: async () => stream,
    waitTermination: async () => undefined,
    close: async () => undefined,
    abort: vi.fn(),
  } satisfies CarrierSessionV3;
  return Object.freeze({
    carrier,
    stream,
    rawFSB3,
    decoded: decodeFSB3RequestV3(rawFSB3),
  });
}

function fakeReceived(
  abort: CarrierSessionV3["abort"],
  write: CarrierStreamV3["write"],
): ReceivedSessionAdmissionV3 {
  const stream = {
    read: async () => null,
    write,
    closeWrite: async () => undefined,
    stopSending: async () => undefined,
    reset: async () => undefined,
    abort: () => undefined,
  } satisfies CarrierStreamV3;
  const carrier = {
    kind: "websocket",
    path: "direct",
    inboundBidirectionalStreamCapacity: 3,
    openStream: async () => stream,
    acceptStream: async () => stream,
    waitTermination: async () => undefined,
    close: async () => undefined,
    abort,
  } satisfies CarrierSessionV3;
  return {
    carrier,
    stream,
    rawFSB3: new Uint8Array(),
    decoded: undefined,
  } as unknown as ReceivedSessionAdmissionV3;
}
