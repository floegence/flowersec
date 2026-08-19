import { describe, expect, test, vi } from "vitest";

import { AdmissionStatusV3, ArtifactV3Error } from "./artifact.js";
import type { CarrierSessionV3, CarrierStreamV3 } from "./carrier.js";
import {
  createAdmissionReasonRegistryV3,
  rejectSessionAdmissionV3,
  type ReceivedSessionAdmissionV3,
} from "./serverAdmission.js";

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
});

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
