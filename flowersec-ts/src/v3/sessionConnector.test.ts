import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import {
  AdmissionStatusV3,
  admissionBindingV3,
  decodeArtifactV3JSON,
  decodeFSB3RequestV3,
  encodeFSA3ResponseV3,
  type ArtifactV3,
} from "./artifact.js";
import {
  artifactLeaseStateV3,
  createArtifactLeaseV3Internal,
} from "./artifactLease.js";
import { createMemoryCarrierPairV3 } from "./carrier.js";
import { detectNodeRuntimeCapabilityV3 } from "./nodeRuntime.js";
import { nodeSessionRuntimeV3 } from "./nodeSessionRuntime.js";
import { TransportFailureV3 } from "./security.js";
import {
  connectArtifactLeaseV3,
  type ReadyAdmissionTransportV3,
  type SessionConnectorRuntimeV3,
} from "./sessionConnector.js";
import {
  establishSessionV3,
  type SessionConfigV3,
} from "./session.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const artifact = decodeArtifactV3JSON(fixture.positive[0]!.artifact_json);
const connectorArtifact = {
  ...artifact,
  path: {
    ...artifact.path,
    candidates: artifact.path.candidates.filter(({ id }) => id === "w-ca"),
  },
} as ArtifactV3;

describe("transport v3 session connector", () => {
  test("completes FSB3, durable spend, FSA3, and FSH3 before carrying session data", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "websocket",
      path: "direct",
      inboundBidirectionalStreamCapacity: connectorArtifact.session.max_inbound_streams + 2,
    });
    const spend = vi.fn(async () => undefined);
    const retire = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(connectorArtifact, spend, retire);
    let serverSession: ReturnType<typeof establishSessionV3> | undefined;
    let fsb3: Uint8Array | undefined;

    const runtime: SessionConnectorRuntimeV3 = {
      capabilitySnapshot: detectNodeRuntimeCapabilityV3,
      protocolRuntime: nodeSessionRuntimeV3,
      nowUnixSeconds: () => 1_900_000_000,
      dial: async (candidate): Promise<ReadyAdmissionTransportV3> => ({
        candidate,
        openAdmissionChannel: async () => ({
          framing: "message",
          write: async (data) => {
            decodeFSB3RequestV3(data);
            fsb3 = data.slice();
          },
          read: async () => encodeFSA3ResponseV3({ status: AdmissionStatusV3.Success, reason: "" }),
          abort: () => undefined,
        }),
        finalize: () => {
          if (fsb3 === undefined) throw new Error("FSB3 must precede carrier finalization");
          serverSession = establishSessionV3(serverCarrier, serverConfig(connectorArtifact, fsb3));
          return clientCarrier;
        },
        close: async () => await clientCarrier.close(),
        abort: () => clientCarrier.abort({ code: 6, reason: "candidate aborted" }),
      }),
    };

    const connected = await connectArtifactLeaseV3(lease, runtime);
    if (serverSession === undefined) throw new Error("server session was not started");
    const accepted = await serverSession;

    expect(spend).toHaveBeenCalledOnce();
    expect(retire).not.toHaveBeenCalled();
    expect(artifactLeaseStateV3(lease)).toBe("consumed");

    const opened = connected.openStream("connector-coverage");
    const incoming = await accepted.acceptStream();
    const outgoing = await opened;
    await outgoing.write(new Uint8Array([1, 2, 3, 4]));
    expect(await incoming.stream.read()).toEqual(new Uint8Array([1, 2, 3, 4]));
    await Promise.all([connected.close(), accepted.close()]);
  });

  test("retires without spending when TLS fails before admission", async () => {
    const spend = vi.fn(async () => undefined);
    const retire = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(artifact, spend, retire);

    await expect(connectArtifactLeaseV3(lease, {
      capabilitySnapshot: detectNodeRuntimeCapabilityV3,
      protocolRuntime: nodeSessionRuntimeV3,
      nowUnixSeconds: () => 1_900_000_000,
      dial: async () => { throw new TransportFailureV3("tls_failed", "ca_untrusted"); },
    })).rejects.toMatchObject({ code: "transport_security_failed" });

    expect(spend).not.toHaveBeenCalled();
    expect(retire).toHaveBeenCalledOnce();
    expect(artifactLeaseStateV3(lease)).toBe("retired");
  });

  test("uses one active-pin snapshot for every candidate in a race", async () => {
    const lease = createArtifactLeaseV3Internal(artifact, async () => undefined);
    const attemptTimes: number[] = [];
    let reads = 0;
    await expect(connectArtifactLeaseV3(lease, {
      capabilitySnapshot: () => detectNodeRuntimeCapabilityV3(true),
      protocolRuntime: nodeSessionRuntimeV3,
      nowUnixSeconds: () => {
        reads += 1;
        return reads === 1 ? 1_900_000_000 : 1_900_000_001;
      },
      dial: async (_candidate, _artifact, attemptNow): Promise<ReadyAdmissionTransportV3> => {
        attemptTimes.push(attemptNow);
        throw new TransportFailureV3("connection_failed");
      },
    })).rejects.toMatchObject({ code: "connection_failed" });
    expect(attemptTimes).toHaveLength(3);
    expect(attemptTimes).toEqual([1_900_000_001, 1_900_000_001, 1_900_000_001]);
  });

  test("keeps the lease consumed after an FSA3 retryable response", async () => {
    const spend = vi.fn(async () => undefined);
    const retire = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(connectorArtifact, spend, retire);
    const finalize = vi.fn(() => { throw new Error("retryable admission must not finalize the carrier"); });

    await expect(connectArtifactLeaseV3(lease, {
      capabilitySnapshot: detectNodeRuntimeCapabilityV3,
      protocolRuntime: nodeSessionRuntimeV3,
      nowUnixSeconds: () => 1_900_000_000,
      dial: async (candidate): Promise<ReadyAdmissionTransportV3> => ({
        candidate,
        openAdmissionChannel: async () => ({
          framing: "message",
          write: async () => undefined,
          read: async () => encodeFSA3ResponseV3(
            { status: AdmissionStatusV3.Retryable, reason: "try_again" },
            new Set(["try_again"]),
          ),
          abort: () => undefined,
        }),
        finalize,
        close: async () => undefined,
        abort: () => undefined,
      }),
    })).rejects.toMatchObject({
      code: "connection_failed",
      disposition: { kind: "retryable" },
    });

    expect(spend).toHaveBeenCalledOnce();
    expect(retire).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
    expect(artifactLeaseStateV3(lease)).toBe("consumed");
  });

  test("keeps the lease consumed after an FSA3 terminal rejection", async () => {
    const spend = vi.fn(async () => undefined);
    const retire = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(connectorArtifact, spend, retire);

    await expect(connectArtifactLeaseV3(lease, {
      capabilitySnapshot: detectNodeRuntimeCapabilityV3,
      protocolRuntime: nodeSessionRuntimeV3,
      nowUnixSeconds: () => 1_900_000_000,
      dial: async (candidate): Promise<ReadyAdmissionTransportV3> => ({
        candidate,
        openAdmissionChannel: async () => ({
          framing: "message",
          write: async () => undefined,
          read: async () => encodeFSA3ResponseV3(
            { status: AdmissionStatusV3.Reject, reason: "denied" },
            new Set(["denied"]),
          ),
          abort: () => undefined,
        }),
        finalize: () => { throw new Error("rejected admission must not finalize the carrier"); },
        close: async () => undefined,
        abort: () => undefined,
      }),
    })).rejects.toMatchObject({
      code: "connection_failed",
      disposition: { kind: "terminal" },
    });

    expect(spend).toHaveBeenCalledOnce();
    expect(retire).not.toHaveBeenCalled();
    expect(artifactLeaseStateV3(lease)).toBe("consumed");
  });

  test("keeps the lease consumed when FSH3 establishment fails", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "websocket",
      path: "direct",
      inboundBidirectionalStreamCapacity: connectorArtifact.session.max_inbound_streams + 2,
    });
    serverCarrier.abort({ code: 6, reason: "injected FSH3 failure" });
    const spend = vi.fn(async () => undefined);
    const retire = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(connectorArtifact, spend, retire);

    await expect(connectArtifactLeaseV3(lease, {
      capabilitySnapshot: detectNodeRuntimeCapabilityV3,
      protocolRuntime: nodeSessionRuntimeV3,
      nowUnixSeconds: () => 1_900_000_000,
      dial: async (candidate): Promise<ReadyAdmissionTransportV3> => ({
        candidate,
        openAdmissionChannel: async () => ({
          framing: "message",
          write: async () => undefined,
          read: async () => encodeFSA3ResponseV3({ status: AdmissionStatusV3.Success, reason: "" }),
          abort: () => undefined,
        }),
        finalize: () => clientCarrier,
        close: async () => await clientCarrier.close(),
        abort: () => clientCarrier.abort({ code: 6, reason: "candidate aborted" }),
      }),
    })).rejects.toMatchObject({
      code: "connection_failed",
      disposition: { kind: "terminal" },
    });

    expect(spend).toHaveBeenCalledOnce();
    expect(retire).not.toHaveBeenCalled();
    expect(artifactLeaseStateV3(lease)).toBe("consumed");
  });

  test("skips an unsupported raw QUIC candidate without invoking the dialer", async () => {
    const rawOnlyArtifact = {
      ...artifact,
      path: {
        ...artifact.path,
        candidates: artifact.path.candidates.filter(({ carrier }) => carrier === "raw_quic"),
      },
    } as ArtifactV3;
    const retire = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(rawOnlyArtifact, async () => undefined, retire);
    const dial = vi.fn(async (): Promise<ReadyAdmissionTransportV3> => {
      throw new Error("unsupported raw QUIC must not reach the dialer");
    });

    await expect(connectArtifactLeaseV3(lease, {
      capabilitySnapshot: detectNodeRuntimeCapabilityV3,
      protocolRuntime: nodeSessionRuntimeV3,
      nowUnixSeconds: () => 1_900_000_000,
      dial,
    })).rejects.toMatchObject({ code: "transport_security_unsupported" });

    expect(dial).not.toHaveBeenCalled();
    expect(retire).toHaveBeenCalledOnce();
    expect(artifactLeaseStateV3(lease)).toBe("retired");
  });
});

function serverConfig(value: ArtifactV3, rawFSB3: Uint8Array): SessionConfigV3 {
  const binding = admissionBindingV3(rawFSB3);
  return {
    role: "server",
    path: "direct",
    channelID: value.session.channel_id,
    sessionContractHash: base64urlDecode(value.session.contract_hash_b64u),
    suite: value.session.default_suite,
    psk: base64urlDecode(value.session.e2ee_psk_b64u),
    maxInboundStreams: value.session.max_inbound_streams,
    sessionContract: value.session,
    localAdmissionBinding: binding,
    peerAdmissionBinding: binding,
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    idleTimeoutMs: value.session.idle_timeout_seconds * 1_000,
    closeTimeoutMs: 5_000,
    runtime: nodeSessionRuntimeV3,
  };
}
