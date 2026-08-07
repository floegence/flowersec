import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  computeSessionContractHashV2,
  decodeArtifactV2JSON,
  type ArtifactV2,
  type CanonicalArtifactCandidateV2,
} from "../v2/artifact.js";
import { createArtifactLeaseV2 } from "../v2/artifactLease.js";
import {
  createMemoryCarrierPairV2,
  type CarrierSessionV2,
  type NativeCarrierSessionV2,
} from "../v2/carrier.js";
import { nodeSessionRuntimeV2 } from "../node/sessionRuntime.js";
import { NODE_RUNTIME_CAPABILITY_V2 } from "../node/runtimeCapability.js";
import { wrapArtifact } from "../v2/opaqueArtifact.js";
import { acceptNativeSessionV2 } from "./sessionAcceptor.js";
import type { ReadyAdmissionTransportV2 } from "./admissionCommit.js";
import {
  composeCandidateAttemptFactoryV2,
  type CandidateAttemptFactoryV2,
  SessionConnectorV2,
} from "./sessionConnector.js";

describe("neutral session connector candidate composition", () => {
  test("routes each carrier to its runtime-owned factory", () => {
    const candidate = {
      carrier: "webtransport",
      id: "t1",
      normalized_url: "https://example.test/flowersec/webtransport/v2/direct",
      wire_profile: "native-quic-v2",
    } as CanonicalArtifactCandidateV2;
    const artifact = {} as ArtifactV2;
    const attempt = { candidate, ready: vi.fn(), abort: vi.fn() };
    const create = vi.fn(() => attempt);
    const factory = composeCandidateAttemptFactoryV2({
      webtransport: { create } satisfies CandidateAttemptFactoryV2,
    });

    expect(factory.create(candidate, artifact)).toBe(attempt);
    expect(create).toHaveBeenCalledWith(candidate, artifact);
  });

  test("fails closed when the runtime does not implement a carrier", () => {
    const candidate = { carrier: "raw_quic" } as CanonicalArtifactCandidateV2;
    expect(() => composeCandidateAttemptFactoryV2({}).create(candidate, {} as ArtifactV2))
      .toThrow("runtime does not implement raw_quic");
  });

  test("commits admission once and establishes a carrier-neutral Session", async () => {
    const parsed = decodeArtifactV2JSON(fixture.positive[0]!.artifact_json);
    const webTransport = parsed.path.candidates.find(({ carrier }) => carrier === "webtransport");
    if (webTransport === undefined) throw new Error("fixture has no WebTransport candidate");
    const artifact = {
      ...parsed,
      path: { ...parsed.path, candidates: [webTransport] },
    } as ArtifactV2;
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
    });
    const spend = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV2(wrapArtifact(artifact), spend);
    const connector = new SessionConnectorV2(lease, {
      create(candidate) {
        return {
          candidate,
          ready: async () => readyWebTransport(candidate, clientCarrier),
          abort: () => clientCarrier.abort({ code: 6, reason: "candidate aborted" }),
        };
      },
    }, {
      runtime: nodeSessionRuntimeV2,
      capability: NODE_RUNTIME_CAPABILITY_V2,
    });

    const accepting = acceptNativeSessionV2(
      serverCarrier as NativeCarrierSessionV2,
      async () => ({ accepted: true, artifact }),
      { runtime: nodeSessionRuntimeV2 },
    );
    const [connected, serverSession] = await Promise.all([connector.connect(), accepting]);
    expect(connected.candidate.id).toBe(webTransport.id);
    expect(spend).toHaveBeenCalledOnce();
    expect(connector.state).toBe("established");

    const opened = connected.session.openStream("coverage");
    const incoming = await serverSession.acceptStream();
    const outgoing = await opened;
    await outgoing.write(new Uint8Array([1, 2, 3]));
    expect(await incoming.stream.read()).toEqual(new Uint8Array([1, 2, 3]));
    await Promise.all([connected.session.close(), serverSession.close()]);
  });

  test("reports all candidate dial failures with bounded diagnostics", async () => {
    const artifact = testArtifact();
    const lease = createArtifactLeaseV2(wrapArtifact(artifact), async () => undefined);
    const attempts = vi.fn((candidate: CanonicalArtifactCandidateV2) => ({
      candidate,
      ready: async () => { throw new Error(`dial failed ${candidate.id}`); },
      abort: vi.fn(),
    }));
    const connector = new SessionConnectorV2(lease, { create: attempts }, {
      runtime: nodeSessionRuntimeV2,
      capability: NODE_RUNTIME_CAPABILITY_V2,
    });
    const error = await connector.connect().catch((value: unknown) => value);
    expect(error).toMatchObject({ code: "connection_failed" });
    expect(connector.state).toBe("terminated");
    expect(attempts).toHaveBeenCalledTimes(2);
  });

  test("fails closed when candidate creation throws before a race starts", async () => {
    const connector = new SessionConnectorV2(
      createArtifactLeaseV2(wrapArtifact(testArtifact()), async () => undefined),
      { create: () => { throw new Error("factory unavailable"); } },
      { runtime: nodeSessionRuntimeV2, capability: NODE_RUNTIME_CAPABILITY_V2 },
    );
    await expect(connector.connect()).rejects.toMatchObject({ code: "connection_failed" });
    expect(connector.state).toBe("terminated");
  });

  test.each([
    { connectTimeoutMs: 0 },
    { loserCloseTimeoutMs: 0 },
  ])("rejects invalid connector option %o before starting candidates", async (options) => {
    const attemptFactory = { create: vi.fn() };
    const connector = new SessionConnectorV2(
      createArtifactLeaseV2(wrapArtifact(testArtifact()), async () => undefined),
      attemptFactory,
      { runtime: nodeSessionRuntimeV2, capability: NODE_RUNTIME_CAPABILITY_V2, ...options },
    );
    await expect(connector.connect()).rejects.toMatchObject({ code: "invalid_options" });
    expect(attemptFactory.create).not.toHaveBeenCalled();
  });

  test("rejects an expired artifact without starting its candidates", async () => {
    const attemptFactory = { create: vi.fn() };
    const connector = new SessionConnectorV2(
      createArtifactLeaseV2(wrapArtifact(testArtifact()), async () => undefined),
      attemptFactory,
      { runtime: nodeSessionRuntimeV2, capability: NODE_RUNTIME_CAPABILITY_V2, now: () => Number.MAX_SAFE_INTEGER },
    );
    await expect(connector.connect()).rejects.toMatchObject({ code: "timeout" });
    expect(attemptFactory.create).not.toHaveBeenCalled();
  });

  test("cancels a pending candidate and reports cancellation", async () => {
    const controller = new AbortController();
    let rejectReady!: (error: unknown) => void;
    const connector = new SessionConnectorV2(
      createArtifactLeaseV2(wrapArtifact(testArtifact()), async () => undefined),
      {
        create(candidate) {
          return {
            candidate,
            ready: async () => await new Promise<ReadyAdmissionTransportV2>((_resolve, reject) => { rejectReady = reject; }),
            abort: vi.fn(() => rejectReady(new Error("aborted"))),
          };
        },
      },
      { runtime: nodeSessionRuntimeV2, capability: NODE_RUNTIME_CAPABILITY_V2 },
    );
    const pending = connector.connect({ signal: controller.signal });
    controller.abort(new Error("caller canceled"));
    await expect(pending).rejects.toMatchObject({ code: "canceled" });
    expect(connector.state).toBe("terminated");
  });

  test("closes a ready loser and the selected candidate when admission cannot open", async () => {
    const closed: string[] = [];
    const aborted: string[] = [];
    const connector = new SessionConnectorV2(
      createArtifactLeaseV2(wrapArtifact(testArtifact()), async () => undefined),
      {
        create(candidate) {
          return {
            candidate,
            ready: async () => ({
              candidate,
              kind: candidate.carrier,
              path: "direct",
              inboundBidirectionalStreamCapacity: 66,
              openAdmissionChannel: async () => { throw new Error(`admission unavailable ${candidate.id}`); },
              finalize: () => { throw new Error("must not finalize"); },
              close: async () => { closed.push(candidate.id); },
              abort: () => { aborted.push(candidate.id); },
            }),
            abort: () => { aborted.push(candidate.id); },
          };
        },
      },
      { runtime: nodeSessionRuntimeV2, capability: NODE_RUNTIME_CAPABILITY_V2 },
    );

    await expect(connector.connect()).rejects.toMatchObject({ code: "connection_failed" });
    expect(closed).toEqual(expect.arrayContaining(["w1", "t1"]));
    expect(aborted).toHaveLength(1);
    expect(["w1", "t1"]).toContain(aborted[0]);
    expect(connector.state).toBe("terminated");
  });

  test("fails closed when ready candidate cleanup itself fails", async () => {
    const connector = new SessionConnectorV2(
      createArtifactLeaseV2(wrapArtifact(testArtifact()), async () => undefined),
      {
        create(candidate) {
          return {
            candidate,
            ready: async () => ({
              candidate,
              kind: candidate.carrier,
              path: "direct",
              inboundBidirectionalStreamCapacity: 66,
              openAdmissionChannel: async () => { throw new Error("must not open admission"); },
              finalize: () => { throw new Error("must not finalize"); },
              close: async () => { throw new Error(`close failed ${candidate.id}`); },
              abort: vi.fn(),
            }),
            abort: vi.fn(),
          };
        },
      },
      { runtime: nodeSessionRuntimeV2, capability: NODE_RUNTIME_CAPABILITY_V2 },
    );

    await expect(connector.connect()).rejects.toMatchObject({ code: "not_connected" });
    expect(connector.state).toBe("terminated");
  });
});

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;

function readyWebTransport(
  candidate: CanonicalArtifactCandidateV2,
  carrier: CarrierSessionV2,
) {
  let finalized = false;
  return {
    candidate,
    kind: "webtransport" as const,
    path: carrier.path,
    inboundBidirectionalStreamCapacity: carrier.inboundBidirectionalStreamCapacity,
    openAdmissionChannel: async () => {
      const stream = await carrier.acceptStream();
      return { framing: "stream" as const, stream, abort: (error: Error) => stream.abort(error) };
    },
    finalize: () => {
      if (finalized) throw new Error("candidate already finalized");
      finalized = true;
      return carrier;
    },
    close: async () => await carrier.close(),
    abort: () => carrier.abort({ code: 6, reason: "candidate aborted" }),
  };
}

function testArtifact(): ArtifactV2 {
  const artifact = decodeArtifactV2JSON(fixture.positive[0]!.artifact_json);
  const session = { ...artifact.session };
  return {
    ...artifact,
    session: {
      ...session,
      contract_hash_b64u: computeSessionContractHashV2(session).hashBase64URL,
    },
  };
}
