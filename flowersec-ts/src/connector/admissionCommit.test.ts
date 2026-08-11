import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  AdmissionStatusV2,
  buildFSB2RequestV2,
  decodeArtifactV2JSON,
  encodeFSA2ResponseV2,
  encodeFSB2RequestV2,
  validateArtifactV2,
} from "../v2/artifact.js";
import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import type { CarrierSessionV2 } from "../v2/carrier.js";
import { nodeSessionRuntimeV2 } from "../node/sessionRuntime.js";
import { wrapArtifact } from "../v2/opaqueArtifact.js";
import { sessionConfigFromArtifactV2 } from "./sessionConfig.js";
import {
  commitClientAdmissionV2,
  type ClientAdmissionChannelV2,
  CredentialCommitError,
  type ReadyAdmissionTransportV2,
} from "./admissionCommit.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;

describe("client admission commit", () => {
  test("spends once, exchanges message framing, and finalizes the bound carrier", async () => {
    const context = admissionContext();
    const response = encodeFSA2ResponseV2({ status: AdmissionStatusV2.Success, reason: "" });
    const channel = messageChannel(response);
    const carrier = {} as CarrierSessionV2;
    const ready = readyTransport(context.candidate, channel.value, carrier);

    await expect(commitClientAdmissionV2(
      ready.value,
      context.lease,
      context.assertValid,
      context.rawFSB2,
      context.config,
    )).resolves.toBe(carrier);

    expect(context.spend).toHaveBeenCalledOnce();
    expect(context.assertValid).toHaveBeenCalledTimes(2);
    expect(channel.write).toHaveBeenCalledWith(context.rawFSB2, {});
    expect(ready.finalize).toHaveBeenCalledOnce();
    expect(channel.abort).not.toHaveBeenCalled();
  });

  test.each([
    ["carrier", (ready: ReadyAdmissionTransportV2) => ({ ...ready, kind: "webtransport" as const })],
    ["path", (ready: ReadyAdmissionTransportV2) => ({ ...ready, path: "tunnel" as const })],
    ["capacity", (ready: ReadyAdmissionTransportV2) => ({ ...ready, inboundBidirectionalStreamCapacity: 1 })],
  ])("rejects a %s binding mismatch before opening or spending", async (_name, mutate) => {
    const context = admissionContext();
    const channel = messageChannel(new Uint8Array());
    const ready = readyTransport(context.candidate, channel.value, {} as CarrierSessionV2);

    await expect(commitClientAdmissionV2(
      mutate(ready.value),
      context.lease,
      context.assertValid,
      context.rawFSB2,
      context.config,
    )).rejects.toThrow();
    expect(context.spend).not.toHaveBeenCalled();
    expect(ready.open).not.toHaveBeenCalled();
  });

  test("aborts the channel and transport when durable spend fails", async () => {
    const context = admissionContext("websocket", async () => { throw new Error("disk failed"); });
    const channel = messageChannel(new Uint8Array());
    const ready = readyTransport(context.candidate, channel.value, {} as CarrierSessionV2);

    await expect(commitClientAdmissionV2(
      ready.value,
      context.lease,
      context.assertValid,
      context.rawFSB2,
      context.config,
    )).rejects.toBeInstanceOf(CredentialCommitError);
    expect(channel.abort).toHaveBeenCalledOnce();
    expect(ready.abort).toHaveBeenCalledOnce();
    expect(channel.write).not.toHaveBeenCalled();
  });

  test("preserves an explicit peer rejection and never finalizes", async () => {
    const context = admissionContext();
    const channel = messageChannel(encodeFSA2ResponseV2({
      status: AdmissionStatusV2.Reject,
      reason: "policy_denied",
    }));
    const ready = readyTransport(context.candidate, channel.value, {} as CarrierSessionV2);

    await expect(commitClientAdmissionV2(
      ready.value,
      context.lease,
      context.assertValid,
      context.rawFSB2,
      context.config,
    )).rejects.toThrow("policy_denied");
    expect(context.spend).toHaveBeenCalledOnce();
    expect(ready.finalize).not.toHaveBeenCalled();
    expect(channel.abort).toHaveBeenCalledOnce();
    expect(ready.abort).toHaveBeenCalledOnce();
  });

  test("exchanges a fragmented stream-framed admission response", async () => {
    const context = admissionContext("raw_quic");
    const response = encodeFSA2ResponseV2({ status: AdmissionStatusV2.Success, reason: "" });
    const stream = streamChannel([response.subarray(0, 3), response.subarray(3)]);
    const ready = readyTransport(context.candidate, stream.channel, {} as CarrierSessionV2);
    await expect(commitClientAdmissionV2(
      ready.value,
      context.lease,
      context.assertValid,
      context.rawFSB2,
      context.config,
    )).resolves.toBeDefined();
    expect(stream.closeWrite).toHaveBeenCalledOnce();
    expect(context.spend).toHaveBeenCalledOnce();
  });

  test("rejects trailing bytes after a stream-framed response", async () => {
    const context = admissionContext("raw_quic");
    const response = encodeFSA2ResponseV2({ status: AdmissionStatusV2.Success, reason: "" });
    const stream = streamChannel([response, Uint8Array.of(9)]);
    const ready = readyTransport(context.candidate, stream.channel, {} as CarrierSessionV2);
    await expect(commitClientAdmissionV2(
      ready.value,
      context.lease,
      context.assertValid,
      context.rawFSB2,
      context.config,
    )).rejects.toThrow("trailing bytes");
    expect(ready.abort).toHaveBeenCalledOnce();
  });
});

function admissionContext(carrier: "websocket" | "raw_quic" = "websocket", commitSpend: () => Promise<void> = async () => undefined) {
  const artifact = decodeArtifactV2JSON(fixture.positive[0]!.artifact_json);
  const candidate = validateArtifactV2(artifact).candidates.find((entry) => entry.carrier === carrier);
  if (candidate === undefined) throw new Error("fixture has no WebSocket candidate");
  const rawFSB2 = encodeFSB2RequestV2(buildFSB2RequestV2(artifact, candidate.id));
  const spend = vi.fn(commitSpend);
  return {
    candidate,
    rawFSB2,
    config: sessionConfigFromArtifactV2(artifact, rawFSB2, nodeSessionRuntimeV2),
    lease: createArtifactLeaseV2(wrapArtifact(artifact), spend),
    spend,
    assertValid: vi.fn(),
  };
}

function messageChannel(response: Uint8Array) {
  const write = vi.fn(async () => undefined);
  const abort = vi.fn();
  return {
    value: {
      framing: "message" as const,
      write,
      read: vi.fn(async () => response),
      abort,
    },
    write,
    abort,
  };
}

function readyTransport(
  candidate: ReturnType<typeof validateArtifactV2>["candidates"][number],
  channel: ClientAdmissionChannelV2,
  carrier: CarrierSessionV2,
) {
  const open = vi.fn(async () => channel);
  const finalize = vi.fn(() => carrier);
  const abort = vi.fn();
  return {
    value: {
      candidate,
      kind: candidate.carrier,
      path: candidate.normalized_url.includes("tunnel") ? "tunnel" as const : "direct" as const,
      inboundBidirectionalStreamCapacity: 66,
      openAdmissionChannel: open,
      finalize,
      close: vi.fn(async () => undefined),
      abort,
    },
    open,
    finalize,
    abort,
  };
}

function streamChannel(chunks: readonly Uint8Array[]) {
  const queue = [...chunks];
  const writes: Uint8Array[] = [];
  const closeWrite = vi.fn(async () => undefined);
  const stream = {
    read: vi.fn(async () => queue.shift() ?? null),
    write: vi.fn(async (data: Uint8Array) => { writes.push(data.slice()); return data.length; }),
    closeWrite,
    stopSending: vi.fn(async () => undefined),
    reset: vi.fn(async () => undefined),
    abort: vi.fn(),
  };
  return {
    channel: { framing: "stream" as const, stream, abort: vi.fn() },
    writes,
    closeWrite,
  };
}
