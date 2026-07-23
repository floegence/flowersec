import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  computeSessionContractHashV2,
  decodeArtifactV2JSON,
  type ArtifactCandidateV2,
  type ArtifactV2,
} from "../v2/artifact.js";
import { SessionV2Error, type SessionConfigV2, type SessionV2 } from "../v2/session.js";
import { AdmissionSessionV2Error } from "../v2/admittedSession.js";
import {
  BROWSER_RUNTIME_CAPABILITY_V2,
  NODE_RUNTIME_CAPABILITY_V2,
  type RuntimeCapabilityDescriptorV2,
} from "../v2/capability.js";
import {
  createBrowserSessionConnectorV2InternalStage as createBrowserSessionConnectorV2InternalStageWithOpaqueArtifact,
  type BrowserCandidateAttemptFactoryV2,
  type BrowserCandidateAttemptV2,
  type BrowserPreparedCandidateV2,
} from "./connectV2.js";
import { wrapArtifact } from "../v2/opaqueArtifact.js";
import { AbortError, FlowersecError, TimeoutError } from "../utils/errors.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const artifact = decodeArtifactV2JSON(fixture.positive[0]!.artifact_json);

function createBrowserSessionConnectorV2InternalStage(
  lease: Omit<Parameters<typeof createBrowserSessionConnectorV2InternalStageWithOpaqueArtifact>[0], "artifact"> & {
    readonly artifact: ArtifactV2;
  },
  options: Parameters<typeof createBrowserSessionConnectorV2InternalStageWithOpaqueArtifact>[1],
) {
  return createBrowserSessionConnectorV2InternalStageWithOpaqueArtifact({
    ...lease,
    artifact: wrapArtifact(lease.artifact),
  }, options);
}

describe("browser SessionV2 equal-candidate connector", () => {
  test("does not start a candidate removed by runtime capability detection", async () => {
    const events: string[] = [];
    const ready = deferred<void>();
    const capability: RuntimeCapabilityDescriptorV2 = Object.freeze({
      ...BROWSER_RUNTIME_CAPABILITY_V2,
      tuples: Object.freeze(BROWSER_RUNTIME_CAPABILITY_V2.tuples.filter(({ carrier }) => carrier === "websocket")),
      unsupported: Object.freeze([
        ...BROWSER_RUNTIME_CAPABILITY_V2.unsupported,
        Object.freeze({ carrier: "webtransport" as const, reason: "browser_webtransport_api_unavailable" }),
      ]),
    });
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability,
    });

    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    expect(events).not.toContain("ready:t1");
    ready.resolve();
    await expect(connecting).resolves.toMatchObject({ candidate: { id: "w1" } });
  });

  test("starts WSS and WT behind one barrier, closes losers, durably spends, then commits only the winner", async () => {
    const events: string[] = [];
    const wssReady = deferred<void>();
    const wtReady = deferred<void>();
    const session = {} as SessionV2;
    let committedConfig: SessionConfigV2 | undefined;
    const factory = fakeFactory(events, session, new Map([
      ["w1", wssReady],
      ["t1", wtReady],
    ]), (config) => { committedConfig = config; });
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    const connecting = connector.connect();
    await eventually(() => {
      expect(events).toContain("ready:w1");
      expect(events).toContain("ready:t1");
    });
    wtReady.resolve();
    await expect(connecting).resolves.toMatchObject({ candidate: { id: "t1" }, session });
    expect(new Set(events.slice(0, 2))).toEqual(new Set([
      "ready:w1",
      "ready:t1",
    ]));
    expect(events.slice(2)).toEqual([
      "abort:w1",
      "spend",
      "commit:t1",
    ]);
    expect(connector.state).toBe("established");
    expect(committedConfig).toMatchObject({
      maxInboundStreams: 64,
      idleTimeoutMs: 60_000,
    });
    await expect(connector.connect()).rejects.toMatchObject({
      path: "direct",
      stage: "validate",
      code: "invalid_input",
    });
    expect(connector.state).toBe("established");
  });

  test("never writes FSB2 when durable spend fails and rejects artifact reuse", async () => {
    const events: string[] = [];
    const ready = deferred<void>();
    const factory = fakeFactory(events, {} as SessionV2, new Map([["w1", ready]]));
    const websocketOnly = withCandidates(artifact, ["w1"]);
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: websocketOnly,
      commitSpend: async () => { events.push("spend"); throw new Error("durability failed"); },
    }, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });
    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    ready.resolve();
    await expect(connecting).rejects.toMatchObject({
      name: "FlowersecError",
      path: "direct",
      stage: "handshake",
      code: "credential_commit_failed",
    } satisfies Partial<FlowersecError>);
    expect(events).toEqual(["ready:w1", "spend", "close:w1"]);
    expect(connector.state).toBe("terminated");
    await expect(connector.connect()).rejects.toThrow("already claimed");
  });

  test("applies artifact establish deadline before spend and leaves the durable lease recoverable", async () => {
    const events: string[] = [];
    const wssReady = deferred<void>();
    const wtReady = deferred<void>();
    const deadline = new AbortController();
    const factory = fakeFactory(events, {} as SessionV2, new Map([
      ["w1", wssReady],
      ["t1", wtReady],
    ]));
    const lease = {
      artifact,
      commitSpend: async () => { events.push("spend"); },
    };
    const connector = createBrowserSessionConnectorV2InternalStage(lease, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      deadlineFactory: (timeoutMs, phase) => {
        expect(timeoutMs).toBe(30_000);
        expect(phase).toBe("establish");
        return { signal: deadline.signal, cancel: () => undefined };
      },
    });
    const connecting = connector.connect();
    await eventually(() => {
      expect(events).toContain("ready:w1");
      expect(events).toContain("ready:t1");
    });
    deadline.abort(new Error("establish timeout"));
    await expect(connecting).rejects.toMatchObject({
      path: "direct",
      stage: "connect",
      code: "timeout",
      diagnostics: expect.arrayContaining([
        expect.objectContaining({ stage: "close", code: "timeout" }),
      ]),
    });
    expect(events).not.toContain("spend");
    expect(events.some((event) => event.startsWith("commit:"))).toBe(false);

    const retryEvents: string[] = [];
    const retryReady = deferred<void>();
    const retry = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: lease.commitSpend,
    }, {
      attemptFactory: fakeFactory(retryEvents, {} as SessionV2, new Map([["w1", retryReady]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });
    const retrying = retry.connect();
    await eventually(() => expect(retryEvents).toContain("ready:w1"));
    retryReady.resolve();
    await expect(retrying).resolves.toMatchObject({ candidate: { id: "w1" } });
    expect(events).toContain("spend");
  });

  test("rejects an expired artifact before starting candidates or spending", async () => {
    const events: string[] = [];
    const now = 2_000_000_000_000;
    const expired = withExpiry(withCandidates(artifact, ["w1"]), now);
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: expired,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map([["w1", deferred<void>()]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      now: () => now,
    });

    const failure = await connector.connect().catch((error: unknown) => error);
    expect(failure).toMatchObject({
      name: "FlowersecError",
      path: "direct",
      stage: "validate",
      code: "timeout",
    });
    expect((failure as Error).message).toContain("expired");
    expect(events).toEqual([]);
  });

  test("does not spend when the artifact expires after the candidate race", async () => {
    const events: string[] = [];
    let now = 2_000_000_000_000;
    const expires = now + 60_000;
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withExpiry(withCandidates(artifact, ["w1"]), expires),
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      now: () => now,
    });

    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    now = expires;
    ready.resolve();
    await expect(connecting).rejects.toThrow("expired");
    expect(events).not.toContain("spend");
    expect(events.some((event) => event.startsWith("commit:"))).toBe(false);
  });

  test("does not write FSB2 when the artifact expires during durable spend", async () => {
    const events: string[] = [];
    let now = 2_000_000_000_000;
    const expires = now + 60_000;
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withExpiry(withCandidates(artifact, ["w1"]), expires),
      commitSpend: async () => { events.push("spend"); now = expires; },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      now: () => now,
    });

    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    ready.resolve();
    await expect(connecting).rejects.toThrow("expired");
    expect(events.filter((event) => event === "spend")).toHaveLength(1);
    expect(events.some((event) => event.startsWith("commit:"))).toBe(false);
  });

  test("does not spend when cancellation arrives after candidate cleanup", async () => {
    const events: string[] = [];
    const controller = new AbortController();
    const now = 2_000_000_000_000;
    let clockReads = 0;
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withExpiry(withCandidates(artifact, ["w1"]), now + 60_000),
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      now: () => {
        clockReads++;
        if (clockReads === 2) controller.abort(new Error("canceled before spend"));
        return now;
      },
    });

    const connecting = connector.connect({ signal: controller.signal });
    ready.resolve();
    await expect(connecting).rejects.toMatchObject({
      path: "direct",
      stage: "attach",
      code: "canceled",
    });
    expect(events).not.toContain("spend");
    expect(events).toContain("close:w1");
  });

  test("does not commit FSB2 when durable spend ignores cancellation", async () => {
    const events: string[] = [];
    const controller = new AbortController();
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => {
        events.push("spend");
        controller.abort(new Error("canceled during spend"));
      },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    const connecting = connector.connect({ signal: controller.signal });
    ready.resolve();
    await expect(connecting).rejects.toMatchObject({
      path: "direct",
      stage: "handshake",
      code: "canceled",
    });
    expect(events).toContain("spend");
    expect(events.some((event) => event.startsWith("commit:"))).toBe(false);
  });

  test("does not return success when prepared commit ignores cancellation", async () => {
    const events: string[] = [];
    const controller = new AbortController();
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: fakeFactory(
        events,
        {} as SessionV2,
        new Map([["w1", ready]]),
        () => controller.abort(new Error("canceled during commit")),
      ),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    const connecting = connector.connect({ signal: controller.signal });
    ready.resolve();
    await expect(connecting).rejects.toMatchObject({
      path: "direct",
      stage: "attach",
      code: "canceled",
    });
    expect(events).toContain("commit:w1");
    expect(events).toContain("close:w1");
    expect(connector.state).toBe("terminated");
  });

  test("aggregates loser abort failures and closes the selected winner before spend", async () => {
    const events: string[] = [];
    const wssReady = deferred<void>();
    const wtReady = deferred<void>();
    const factory = cleanupFailingFactory(events, new Map([
      ["w1", wssReady],
      ["t1", wtReady],
    ]), "w1");
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      loserCloseTimeoutMs: 50,
    });

    const connecting = connector.connect();
    await eventually(() => {
      expect(events).toContain("ready:w1");
      expect(events).toContain("ready:t1");
    });
    wtReady.resolve();
    const failure = await connecting.catch((error: unknown) => error);
    expect(failure).toMatchObject({
      name: "FlowersecError",
      path: "direct",
      stage: "close",
      code: "not_connected",
      diagnostics: expect.arrayContaining([
        expect.objectContaining({ candidateId: "w1", carrier: "websocket", stage: "close", code: "not_connected" }),
      ]),
    });
    expect(failure).toBeInstanceOf(FlowersecError);
    expect((failure as Error).message).toContain("abort failed: w1");
    expect(events).toContain("close:t1");
    expect(events).not.toContain("spend");
    expect(connector.state).toBe("terminated");
  });

  test("bounds a hanging loser abort and closes the selected winner before spend", async () => {
    const events: string[] = [];
    const wssReady = deferred<void>();
    const wtReady = deferred<void>();
    const factory = cleanupHangingFactory(events, new Map([
      ["w1", wssReady],
      ["t1", wtReady],
    ]), "w1");
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      loserCloseTimeoutMs: 20,
    });

    const connecting = connector.connect();
    await eventually(() => {
      expect(events).toContain("ready:w1");
      expect(events).toContain("ready:t1");
    });
    wtReady.resolve();
    await expect(connecting).rejects.toMatchObject({
      path: "direct",
      stage: "close",
      code: "timeout",
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          candidateId: "w1",
          carrier: "websocket",
          stage: "close",
          code: "timeout",
          message: expect.stringContaining("cleanup timeout"),
        }),
      ]),
    });
    expect(events).toContain("abort:w1");
    expect(events).toContain("close:t1");
    expect(events).not.toContain("spend");
  });

  test("closes a loser that becomes ready after synchronous abort", async () => {
    const events: string[] = [];
    const wssReady = deferred<void>();
    const wtReady = deferred<void>();
    const factory = cleanupHangingFactory(events, new Map([
      ["w1", wssReady],
      ["t1", wtReady],
    ]), "w1");
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      loserCloseTimeoutMs: 50,
    });

    const connecting = connector.connect();
    await eventually(() => {
      expect(events).toContain("ready:w1");
      expect(events).toContain("ready:t1");
    });
    wtReady.resolve();
    setTimeout(() => wssReady.resolve(), 5);
    await expect(connecting).resolves.toMatchObject({ candidate: { id: "t1" } });
    expect(events).toContain("close:w1");
    expect(events).not.toContain("close:t1");
    expect(events).toContain("spend");
  });

  test("bounds cleanup when the candidate race is canceled before a winner is selected", async () => {
    const events: string[] = [];
    const wssReady = deferred<void>();
    const wtReady = deferred<void>();
    const controller = new AbortController();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: cleanupHangingFactory(events, new Map([
        ["w1", wssReady],
        ["t1", wtReady],
      ]), "w1"),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      loserCloseTimeoutMs: 20,
    });

    const connecting = connector.connect({ signal: controller.signal });
    await eventually(() => {
      expect(events).toContain("ready:w1");
      expect(events).toContain("ready:t1");
    });
    controller.abort(new Error("candidate race canceled"));
    await expect(connecting).rejects.toMatchObject({
      path: "direct",
      stage: "connect",
      code: "canceled",
      diagnostics: expect.arrayContaining([
        expect.objectContaining({ stage: "close", code: "canceled" }),
      ]),
    });
    expect(connector.state).toBe("terminated");
    expect(events).toContain("abort:w1");
    expect(events).toContain("abort:t1");
  });

  test("bounds selected candidate close when durable spend fails", async () => {
    const events: string[] = [];
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => { events.push("spend"); throw new Error("durability failed"); },
    }, {
      attemptFactory: closeHangingFactory(events, ready),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      loserCloseTimeoutMs: 20,
    });
    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    ready.resolve();
    await expect(connecting).rejects.toThrow("durability failed");
    expect(events).toContain("spend");
    expect(connector.state).toBe("terminated");
  });

  test("clears cleanup resources when selected candidate close throws synchronously", async () => {
    vi.useFakeTimers();
    try {
      const events: string[] = [];
      const ready = deferred<void>();
      ready.resolve();
      const connector = createBrowserSessionConnectorV2InternalStage({
        artifact: withCandidates(artifact, ["w1"]),
        commitSpend: async () => { throw new Error("durability failed"); },
      }, {
        attemptFactory: closeSynchronousThrowFactory(events, ready),
        admissionReasons: new Set(),
        capability: BROWSER_RUNTIME_CAPABILITY_V2,
        loserCloseTimeoutMs: 20,
      });

      const failure = await connector.connect().catch((error: unknown) => error) as FlowersecError;
      expect(failure).toMatchObject({
        stage: "handshake",
        code: "credential_commit_failed",
        diagnostics: expect.arrayContaining([
          expect.objectContaining({ stage: "close", code: "not_connected" }),
        ]),
      });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  test("keeps the primary spend error when timeout abort cleanup throws", async () => {
    vi.useFakeTimers();
    try {
      const ready = deferred<void>();
      ready.resolve();
      const connector = createBrowserSessionConnectorV2InternalStage({
        artifact: withCandidates(artifact, ["w1"]),
        commitSpend: async () => { throw new Error("durability failed"); },
      }, {
        attemptFactory: closeAndAbortFailingFactory(ready),
        admissionReasons: new Set(),
        capability: BROWSER_RUNTIME_CAPABILITY_V2,
        loserCloseTimeoutMs: 20,
      });

      const failurePromise = connector.connect().catch((error: unknown) => error) as Promise<FlowersecError>;
      await vi.advanceTimersByTimeAsync(20);
      const failure = await failurePromise;
      expect(failure).toMatchObject({
        stage: "handshake",
        code: "credential_commit_failed",
        diagnostics: expect.arrayContaining([
          expect.objectContaining({
            stage: "close",
            code: "timeout",
            message: expect.stringContaining("prepared abort failed"),
          }),
        ]),
      });
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  test("maps admission failure to the stable high-level error contract", async () => {
    const events: string[] = [];
    const ready = deferred<void>();
    const admissionError = new AdmissionSessionV2Error("rejected", "FSA2 rejected");
    const factory = fakeFactory(events, {} as SessionV2, new Map([["w1", ready]]), undefined, admissionError);
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });
    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    ready.resolve();
    await expect(connecting).rejects.toMatchObject({
      name: "FlowersecError",
      path: "direct",
      stage: "attach",
      code: "attach_failed",
    });
  });

  test("maps session handshake failure separately from admission", async () => {
    const events: string[] = [];
    const ready = deferred<void>();
    const handshakeError = new SessionV2Error("handshake", "FSH2 rejected");
    const factory = fakeFactory(events, {} as SessionV2, new Map([["w1", ready]]), undefined, handshakeError);
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: factory,
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    ready.resolve();
    await expect(connecting).rejects.toMatchObject({
      name: "FlowersecError",
      path: "direct",
      stage: "handshake",
      code: "handshake_failed",
    });
  });

  test("reports each failed candidate with stable dial diagnostics", async () => {
    const events: string[] = [];
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    const connecting = connector.connect();
    await eventually(() => expect(events).toContain("ready:w1"));
    ready.reject(new Error("dial refused"));
    const failure = await connecting.catch((error: unknown) => error) as FlowersecError;
    expect(failure).toMatchObject({
      path: "direct",
      stage: "connect",
      code: "dial_failed",
      diagnostics: [{
        candidateId: "w1",
        carrier: "websocket",
        stage: "connect",
        code: "dial_failed",
        message: "dial refused",
      }],
    });
    expect(Object.isFrozen(failure.diagnostics)).toBe(true);
    expect(Object.isFrozen(failure.diagnostics[0])).toBe(true);
  });

  test("bounds candidate diagnostic messages by UTF-8 bytes", async () => {
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => undefined,
    }, {
      attemptFactory: fakeFactory([], {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    const connecting = connector.connect();
    ready.reject(new Error(`dial refused: ${"界".repeat(1_000)}`));
    const failure = await connecting.catch((error: unknown) => error) as FlowersecError;
    expect(failure.diagnostics[0]!.message).toContain("dial refused");
    expect(new TextEncoder().encode(failure.diagnostics[0]!.message).length).toBeLessThanOrEqual(1_024);
  });

  test("preserves candidate create timeout at the connect stage", async () => {
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => undefined,
    }, {
      attemptFactory: {
        create: () => { throw new TimeoutError("candidate create timeout"); },
      },
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    await expect(connector.connect()).rejects.toMatchObject({
      path: "direct",
      stage: "connect",
      code: "timeout",
      diagnostics: [expect.objectContaining({ stage: "connect", code: "timeout" })],
    });
  });

  test("preserves candidate ready cancellation at the connect stage", async () => {
    const ready = deferred<void>();
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact: withCandidates(artifact, ["w1"]),
      commitSpend: async () => undefined,
    }, {
      attemptFactory: fakeFactory([], {} as SessionV2, new Map([["w1", ready]])),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
    });

    const connecting = connector.connect();
    ready.reject(new AbortError("candidate ready canceled"));
    await expect(connecting).rejects.toMatchObject({
      path: "direct",
      stage: "connect",
      code: "canceled",
      diagnostics: [expect.objectContaining({ stage: "connect", code: "canceled" })],
    });
  });

  test("maps invalid connector options before starting candidates", async () => {
    const events: string[] = [];
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => { events.push("spend"); },
    }, {
      attemptFactory: fakeFactory(events, {} as SessionV2, new Map()),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      loserCloseTimeoutMs: 0,
    });

    await expect(connector.connect()).rejects.toMatchObject({
      path: "direct",
      stage: "validate",
      code: "invalid_option",
    });
    expect(events).toEqual([]);
  });

  test("rejects a malformed deadline handle as an invalid option", async () => {
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => undefined,
    }, {
      attemptFactory: fakeFactory([], {} as SessionV2, new Map()),
      admissionReasons: new Set(),
      capability: BROWSER_RUNTIME_CAPABILITY_V2,
      deadlineFactory: () => ({}) as never,
    });

    await expect(connector.connect()).rejects.toMatchObject({
      path: "direct",
      stage: "validate",
      code: "invalid_option",
    });
  });

  test("maps an empty capability intersection to transport policy denial", async () => {
    const capability: RuntimeCapabilityDescriptorV2 = Object.freeze({
      ...BROWSER_RUNTIME_CAPABILITY_V2,
      tuples: Object.freeze(BROWSER_RUNTIME_CAPABILITY_V2.tuples.filter(({ path }) => path === "tunnel")),
    });
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => undefined,
    }, {
      attemptFactory: fakeFactory([], {} as SessionV2, new Map()),
      admissionReasons: new Set(),
      capability,
    });

    await expect(connector.connect()).rejects.toMatchObject({
      path: "direct",
      stage: "validate",
      code: "transport_policy_denied",
    });
  });

  test("maps a capability descriptor for the wrong runtime to invalid option", async () => {
    const connector = createBrowserSessionConnectorV2InternalStage({
      artifact,
      commitSpend: async () => undefined,
    }, {
      attemptFactory: fakeFactory([], {} as SessionV2, new Map()),
      admissionReasons: new Set(),
      capability: NODE_RUNTIME_CAPABILITY_V2,
    });

    await expect(connector.connect()).rejects.toMatchObject({
      path: "direct",
      stage: "validate",
      code: "invalid_option",
    });
  });
});

function cleanupHangingFactory(
  events: string[],
  readiness: ReadonlyMap<string, Deferred<void>>,
  hangingID: string,
): BrowserCandidateAttemptFactoryV2 {
  return {
    create(candidate) {
      const gate = readiness.get(candidate.id);
      if (gate === undefined) throw new Error(`unexpected candidate ${candidate.id}`);
      return {
        candidate,
        ready: async () => {
          events.push(`ready:${candidate.id}`);
          await gate.promise;
          return {
            candidate,
            commit: async () => ({} as SessionV2),
            close: async () => { events.push(`close:${candidate.id}`); },
            abort: () => { events.push(`prepared-abort:${candidate.id}`); },
          };
        },
        abort: () => {
          events.push(`abort:${candidate.id}`);
          if (candidate.id !== hangingID) gate.reject(new Error("attempt aborted"));
        },
      };
    },
  };
}

function cleanupFailingFactory(
  events: string[],
  readiness: ReadonlyMap<string, Deferred<void>>,
  failingID: string,
): BrowserCandidateAttemptFactoryV2 {
  return {
    create(candidate) {
      const gate = readiness.get(candidate.id);
      if (gate === undefined) throw new Error(`unexpected candidate ${candidate.id}`);
      return {
        candidate,
        ready: async () => {
          events.push(`ready:${candidate.id}`);
          await gate.promise;
          return {
            candidate,
            commit: async () => ({} as SessionV2),
            close: async () => { events.push(`close:${candidate.id}`); },
            abort: () => { events.push(`prepared-abort:${candidate.id}`); },
          };
        },
        abort: () => {
          events.push(`abort:${candidate.id}`);
          if (candidate.id === failingID) {
            gate.reject(new Error("attempt aborted"));
            throw new Error(`abort failed: ${candidate.id}`);
          }
        },
      };
    },
  };
}

function closeHangingFactory(events: string[], readiness: Deferred<void>): BrowserCandidateAttemptFactoryV2 {
  return {
    create(candidate) {
      return {
        candidate,
        ready: async () => {
          events.push(`ready:${candidate.id}`);
          await readiness.promise;
          return {
            candidate,
            commit: async () => ({} as SessionV2),
            close: async () => {
              events.push(`close:${candidate.id}`);
              await new Promise<void>(() => undefined);
            },
            abort: () => { events.push(`prepared-abort:${candidate.id}`); },
          };
        },
        abort: () => { events.push(`abort:${candidate.id}`); readiness.reject(new Error("attempt aborted")); },
      };
    },
  };
}

function closeSynchronousThrowFactory(
  events: string[],
  readiness: Deferred<void>,
): BrowserCandidateAttemptFactoryV2 {
  return {
    create(candidate) {
      return {
        candidate,
        ready: async () => {
          await readiness.promise;
          return {
            candidate,
            commit: async () => ({} as SessionV2),
            close: () => {
              events.push(`close:${candidate.id}`);
              throw new Error("selected close failed synchronously");
            },
            abort: () => undefined,
          };
        },
        abort: () => undefined,
      };
    },
  };
}

function closeAndAbortFailingFactory(readiness: Deferred<void>): BrowserCandidateAttemptFactoryV2 {
  return {
    create(candidate) {
      return {
        candidate,
        ready: async () => {
          await readiness.promise;
          return {
            candidate,
            commit: async () => ({} as SessionV2),
            close: async () => await new Promise<void>(() => undefined),
            abort: () => { throw new Error("prepared abort failed"); },
          };
        },
        abort: () => undefined,
      };
    },
  };
}

function fakeFactory(
  events: string[],
  session: SessionV2,
  readiness: ReadonlyMap<string, Deferred<void>>,
  inspectConfig?: (config: SessionConfigV2) => void,
  commitError?: Error,
): BrowserCandidateAttemptFactoryV2 {
  return {
    create(candidate) {
      const gate = readiness.get(candidate.id);
      if (gate === undefined) throw new Error(`unexpected candidate ${candidate.id}`);
      let aborted = false;
      const prepared: BrowserPreparedCandidateV2 = {
        candidate,
        commit: async (rawFSB2, _reasons, config) => {
          expect(new TextDecoder().decode(rawFSB2).startsWith("FSB2")).toBe(true);
          inspectConfig?.(config);
          events.push(`commit:${candidate.id}`);
          if (commitError !== undefined) throw commitError;
          return session;
        },
        close: async () => { events.push(`close:${candidate.id}`); },
        abort: () => { events.push(`prepared-abort:${candidate.id}`); },
      };
      const attempt: BrowserCandidateAttemptV2 = {
        candidate,
        ready: async () => {
          events.push(`ready:${candidate.id}`);
          await gate.promise;
          if (aborted) throw new Error("attempt aborted");
          return prepared;
        },
        abort: () => { aborted = true; events.push(`abort:${candidate.id}`); gate.reject(new Error("attempt aborted")); },
      };
      return attempt;
    },
  };
}

function withCandidates(value: ArtifactV2, ids: readonly string[]): ArtifactV2 {
  const candidates = value.path.candidates.filter((candidate: ArtifactCandidateV2) => ids.includes(candidate.id));
  return { ...value, path: { ...value.path, candidates } } as ArtifactV2;
}

function withExpiry(value: ArtifactV2, expiresAtMilliseconds: number): ArtifactV2 {
  const session = {
    ...value.session,
    init_expire_at_unix_s: Math.floor(expiresAtMilliseconds / 1_000),
  };
  return {
    ...value,
    session: {
      ...session,
      contract_hash_b64u: computeSessionContractHashV2(session).hashBase64URL,
    },
  };
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
}>;

function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { assertion(); return; } catch { await new Promise((resolve) => setTimeout(resolve, 0)); }
  }
  assertion();
}
