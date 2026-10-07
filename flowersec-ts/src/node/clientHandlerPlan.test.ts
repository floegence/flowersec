import { createPrivateKey } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { MethodDefinition, ServiceDefinition, bytesMessageCodec, configureNodeWSS, createHandlerPlan } from "./index.js";
import { createCurrentNodeSession } from "../v4/testSupport/currentNodeSession.js";
import { currentPeerContract } from "../interop/currentContracts.js";
import { peerPingMethod, peerCompletionMethod, peerServices } from "../interop/currentPeer.js";

const signal = () => AbortSignal.timeout(10000);
const key = (algorithm: "identity" | "noise") => createPrivateKey({ key: Buffer.concat([
  Buffer.from(algorithm === "identity" ? "302e020100300506032b657004220420" : "302e020100300506032b656e04220420", "hex"), Buffer.alloc(32, 1),
]), format: "der", type: "pkcs8" });

describe("ordinary client HandlerPlan ownership", () => {
  it("serves peer-opened streams on a retained client plan after its public owner closes", async () => {
    let admissions = 0;
    const owner = await createCurrentNodeSession(environment => createHandlerPlan(environment, { applicationBytes: 1024n }), "https://app.example", {
      closeClientPlanAfterConfigure: true,
      clientPlan: environment => createHandlerPlan(environment, { applicationBytes: 1024n, streams: [{ kind: "client.plan.echo", authorize: () => { admissions++; return true; },
        options: { applicationBytes: 1024n, maxConcurrentStreams: 1, maxAuthorizing: 1, applicationTimeoutMS: 10000n },
        handler: async (stream, context) => {
          const input = await stream.read(32n, { signal: context.signal });
          if (input.wait_status !== "ready" || input.stream_status === "aborted") throw new Error("client plan read failed");
          const progress = await stream.write(input.data, { signal: context.signal });
          if (progress.accepted_bytes !== BigInt(input.data.length)) throw new Error("client plan write failed");
          await stream.finish({ signal: context.signal });
        },
      }] }),
    });
    try {
      const stream = await owner.accepted.session.openStream("client.plan.echo", { signal: signal() });
      try {
        const payload = new Uint8Array([1, 2, 3]);
        const written = await stream.write(payload, { signal: signal() }); expect(written.terminal_reason).toBe("complete");
        await stream.closeWrite({ signal: signal() });
        const response = await stream.read(32n, { signal: signal() }); expect(response.data).toEqual(payload);
        await stream.finish({ signal: signal() }); expect(admissions).toBe(1);
      } finally { await stream.close(); }
    } finally { await owner.close(); }
  });

  it("refuses raw handler headroom before acquiring or spending material", async () => {
    let acquisitions = 0;
    await expect(createCurrentNodeSession(environment => createHandlerPlan(environment, { applicationBytes: 1024n }), "https://app.example", {
      onSourceAcquire: () => { acquisitions++; },
      clientPlan: environment => createHandlerPlan(environment, { applicationBytes: 1024n, streams: [{ kind: "client.plan.overcommitted", authorize: () => true,
        options: { applicationBytes: 1024n, maxConcurrentStreams: 32, maxAuthorizing: 1, applicationTimeoutMS: 10000n }, handler: async () => undefined,
      }] }),
    })).rejects.toThrow();
    expect(acquisitions).toBe(0);
  });
  it("refuses a foreign Environment plan before installing a new client provider", async () => {
    const owner = await createCurrentNodeSession(environment => createHandlerPlan(environment, { applicationBytes: 1024n }));
    const foreignPlan = createHandlerPlan(owner.serverEnvironment, { applicationBytes: 1024n });
    try {
      expect(() => configureNodeWSS(owner.clientEnvironment, { identityKey: key("identity"), noiseKey: key("noise"), handlerPlan: foreignPlan, poolStore: owner.poolStore,
        limits: { maxFrame: 65536, maxStreams: 18, receiveQueueBytes: 16384, maxDataBytes: 4096, maxCursorBytes: 65536, maxWriteBytes: 65536,
          writeDeadlineMS: 10000n, operationDeadlineMS: 10000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n, cryptoKeys: 100 },
        carrier: { remoteAddress: "127.0.0.1", queueMessages: 8, runtimeBytes: 1024n, nativeBytes: 1048576n, prepareBytes: 262144 },
      })).toThrow("owner_unavailable");
      expect((await owner.session.probeLiveness({ signal: signal() })).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally { foreignPlan.close(); await owner.close(); }
  });
});


describe("current typed service registration boundaries", () => {
  const codec = bytesMessageCodec({ schemaDigest: new Uint8Array(32), revision: "1", maxMessageBytes: 4096 });
  const method = (typeID: number) => new MethodDefinition({ typeID, shape: "unary", unarySemantics: "transient",
    request: codec, response: codec, requestMaxBytes: 4096, minResponseLimitBytes: 0, maxResponseBytes: 4096, restartFlush: false });

  it("keeps method IDs inside the nonzero uint32 range and unique within one service", () => {
    expect(method(1).typeID).toBe(1);
    expect(method(0xffff_ffff).typeID).toBe(0xffff_ffff);
    for (const typeID of [0, -1, 1.5, 0x1_0000_0000]) {
      expect(() => method(typeID), `type ID ${typeID}`).toThrow("service_definition_invalid");
    }
    expect(() => new ServiceDefinition({ namespace: "example.boundary", methods: { first: method(1), duplicate: method(1) } }))
      .toThrow("service_definition_duplicate");
  });

  it("rejects duplicate typed handlers during immutable HandlerPlan capture", async () => {
    const owner = await createCurrentNodeSession(environment => createHandlerPlan(environment, { applicationBytes: 1024n }));
    const first = vi.fn(async (_context: unknown, request: Uint8Array) => request);
    const second = vi.fn(async (_context: unknown, request: Uint8Array) => request);
    const registration = (handler: typeof first) => ({ namespace: "flowersec.parity", method: peerPingMethod,
      contract: currentPeerContract(7001), handler,
      options: { workClass: "short" as const, maxConcurrentCalls: 1, applicationBytes: 1024n, authorization: "authenticated" as const } });
    try {
      expect(() => createHandlerPlan(owner.clientEnvironment, { applicationBytes: 4096n, services: { ...peerServices, profile: "services",
        unaryHandlers: [registration(first), registration(second)] } })).toThrow("configuration_capacity");
      expect(first).not.toHaveBeenCalled();
      expect(second).not.toHaveBeenCalled();
      const options = { applicationBytes: 4096n, services: { ...peerServices, profile: "services" as const,
        unaryHandlers: [registration(first), { ...registration(second), method: peerCompletionMethod, contract: currentPeerContract(7003) }] } };
      const plans: ReturnType<typeof createHandlerPlan>[] = [];
      try {
        // Distinct retained contracts and simultaneous plans need independent
        // original resource owners, including while another plan is retained.
        plans.push(createHandlerPlan(owner.clientEnvironment, options));
        plans.push(createHandlerPlan(owner.clientEnvironment, options));
      } finally { for (const plan of plans) plan.close(); }
    } finally { await owner.close(); }
  });
});
