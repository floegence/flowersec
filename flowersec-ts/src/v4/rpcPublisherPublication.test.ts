import { describe, expect, it, vi } from "vitest";
import { createMaintenanceOwner, ResponsePublication, responsePublicationCharge } from "./responsePublication.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge } from "./runtime/applicationHeader.js";
import { TrustedDeadline } from "./runtime/deadline.js";
import { V4EnvironmentRuntime } from "./runtime/environment.js";
import { RPCCallCapacity, rpcCallCapacityCharge } from "./runtime/rpcCallCapacity.js";
import { rpcDataMaxBytes, type RPCFragment } from "./runtime/rpcFragment.js";
import { RPCNetwork, rpcNetworkCharge } from "./runtime/rpcNetwork.js";
import { RPCPayload, rpcPayloadCharge } from "./runtime/rpcPayload.js";
import { RPCPublisher, rpcPublisherCharge, type RPCPublicationGuard } from "./runtime/rpcPublisher.js";
import { RPCReceiver, rpcReceiverCharges } from "./runtime/rpcReceiver.js";
import type { RPCStreamOwner } from "./runtime/rpcStream.js";
import { ResourceRoot, ResourceVector, type ResourceReference } from "./runtime/resources.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { ReliableWriteRequest, writeRequestCharge } from "./runtime/writeRequest.js";

interface NativeSend { readonly fragmentKind: number; readonly admit: () => void; readonly finish: () => void; readonly fail: () => void; }
function fixture(payloadBytes = 2 * rpcDataMaxBytes + 1, handlerRunning = false) {
  const runtime = 1024n, limit = new ResourceVector(Array<bigint>(11).fill(100000000n));
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  let now = 0n;
  const environment = new V4EnvironmentRuntime({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32),
    runtimeBytes: runtime, namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, acquireMS: 10000n, cleanupMS: 25,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: now, incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1000n }) },
    random: bytes => crypto.getRandomValues(bytes) });
  let backing = 10;
  const reserve = (charge: ResourceVector): ResourceReference => root.reserve({ accounts: environment.resources.accounts,
    owner: { ...environment.resources.owner, kind: "publisher_test", backing: (++backing).toString(16).padStart(32, "0") }, charge });
  const construct = <T>(charge: ResourceVector, create: (reference: ResourceReference) => T): T => {
    const reference = reserve(charge); try { return create(reference); } finally { reference.release(); }
  };
  const calls = construct(rpcCallCapacityCharge(4, runtime), reference => new RPCCallCapacity(4, runtime, reference));
  const config = { profile: "services" as const, maxGeneral: 4, query: { typeID: 43, contractDigest: new Uint8Array(32).fill(1) }, runtimeBytes: runtime };
  const network = construct(rpcNetworkCharge(config), reference => new RPCNetwork(config, reference, calls));
  const channel = network.openChannel();
  const headerReferences = [reserve(applicationHeaderCharge(runtime)), reserve(applicationHeaderDecoderCharge(runtime))];
  const headers = new ApplicationHeaderCodec(runtime, headerReferences[0]!, headerReferences[1]!);
  headerReferences.forEach(reference => reference.release());
  const request = headers.create({ kind: "transient_unary_request", typeID: 42, payloadBytes: 0,
    contractDigest: new Uint8Array(32).fill(2), deadlineAtMS: 20000n, admissionMode: 0, responseLimitBytes: 1048576 });
  const receive = (fragment: RPCFragment) => network.receive(channel, { fragment, first: true, last: true, chunkOffset: 0 }, fragment.kind === 0 ? request : undefined);
  const ticket = receive({ kind: 0, serial: 1n, replyTo: 0n })!.ticket;
  network.inputComplete(ticket, true);
  const receiverReferences = rpcReceiverCharges(runtime).map(reserve);
  const receiver = new RPCReceiver(network, channel, { openInput: () => { throw new Error("unexpected_input"); } }, runtime, receiverReferences);
  receiverReferences.forEach(reference => reference.release());
  const maintenance = createMaintenanceOwner(environment, 1);
  const publication = construct(responsePublicationCharge(runtime), reference => new ResponsePublication(maintenance, runtime, reference));
  expect(publication.view.transferTo(maintenance)).toBe("success"); if (!handlerRunning) publication.endHandler();
  const deadline = new TrustedDeadline(environment.clock, 20000n);
  const position = root.protect(reserve(writeRequestCharge(16384, runtime)), writeRequestCharge(16384, runtime));
  const sends: NativeSend[] = [];
  const stream = { kind: "flowersec.rpc.v4", metadata: new Uint8Array(), maxWriteBytes: 16384,
    prepareFragment: (bytes: Uint8Array, reference: ResourceReference) => new ReliableWriteRequest({ maxChunk: 16384,
      readyBytes: () => 16384, waitReady: async () => { throw new Error("unexpected_wait"); },
      send: (part, admitted) => new Promise<void>((resolve, reject) => sends.push({ fragmentKind: part[4]!,
        admit: () => admitted(part.length), finish: resolve, fail: () => reject(new Error("native_tail_failed")) })), release: () => undefined
    }, bytes, deadline, runtime, reference), reset: async () => undefined } as unknown as RPCStreamOwner;
  const publisher = construct(rpcPublisherCharge(runtime), reference => new RPCPublisher(network, channel, receiver, stream, position, runtime, reference));
  const physicalComplete = vi.fn(), responseHandedOff = vi.fn(); let current = true;
  const guard: RPCPublicationGuard = { responsePublication: publication, check: () => publication.check(), current: () => current,
    publicationPhysicalComplete: physicalComplete, responseHandedOff };
  const payload = construct(rpcPayloadCharge(payloadBytes, runtime), reference => new RPCPayload(payloadBytes, runtime, reference));
  payload.write(0, new Uint8Array(payloadBytes).fill(7));
  const queueOriginal = () => {
    publication.select(deadline, environment.clock, 5000n);
    publisher.addResponse(ticket, headers.response(request, "transient_unary_response", payloadBytes), payload.borrow(payloadBytes), guard); payload.close();
  };
  const publish = async (kind: number) => {
    const index = sends.length, done = publisher.publishNext();
    await expect.poll(() => sends.length).toBe(index + 1);
    const send = sends[index]!; expect(send.fragmentKind).toBe(kind); return { send, done };
  };
  const complete = async (kind: number) => { const { send, done } = await publish(kind); send.admit(); send.finish(); expect(await done).toBe(true); };
  const close = async () => {
    publisher.close(); receiver.close(); network.close(); calls.close(); payload.close(); headers.close(); publication.physicalDone();
    maintenance.close(); await environment.close(); root.close(); expect(root.snapshot().cleanupComplete).toBe(true);
  };
  return { publication, maintenance, publisher, physicalComplete, responseHandedOff, queueOriginal, publish, complete, close,
    advance: (value: bigint) => { now = value; }, revoke: () => { current = false; },
    stop: () => receive({ kind: 3, serial: 1n }), replySDK: () => publisher.replySDK(ticket, "service_failed", guard) };
}

describe("original RPC response publication frontier", () => {
  it("keeps BEGIN, intermediate DATA and a blocked final body pending until the final provider handoff", async () => {
    const f = fixture();
    try {
      f.queueOriginal(); await f.complete(0);
      expect(f.publication.view.state()).toEqual({ state: "pending" }); expect(f.physicalComplete).not.toHaveBeenCalled();
      await f.complete(1);
      expect(f.publication.view.state()).toEqual({ state: "pending" }); expect(f.physicalComplete).not.toHaveBeenCalled();
      await f.complete(1);
      const { send, done } = await f.publish(1);
      expect(f.publication.view.state()).toEqual({ state: "pending" }); expect(f.physicalComplete).not.toHaveBeenCalled();
      expect(f.responseHandedOff).not.toHaveBeenCalled();
      send.admit(); expect(await f.publication.view.wait()).toEqual({ state: "flushed" });
      expect(f.responseHandedOff).toHaveBeenCalledTimes(1);
      f.maintenance.close(); expect(f.maintenance.cleanupComplete()).toBe(false);
      send.finish(); await done;
      expect(f.physicalComplete).toHaveBeenCalledTimes(1); expect(f.maintenance.cleanupComplete()).toBe(true);
      expect(f.responseHandedOff).toHaveBeenCalledTimes(1);
      expect(f.publication.view.state()).toEqual({ state: "flushed" });
    } finally { await f.close(); }
  });
  it("leaves a physically completed SDK replacement unknown", async () => {
    const f = fixture();
    try {
      f.replySDK(); await f.complete(0); expect(f.physicalComplete).not.toHaveBeenCalled(); await f.complete(1);
      expect(f.physicalComplete).toHaveBeenCalledTimes(1);
      expect(await f.publication.view.wait()).toEqual({ state: "unknown", cause: "response_superseded" });
      expect(f.responseHandedOff).not.toHaveBeenCalled();
    } finally { await f.close(); }
  });
  it("does not flush an SDK replacement selected after the original guard is revoked", async () => {
    const f = fixture();
    try {
      f.queueOriginal(); f.revoke(); expect(await f.publisher.publishNext()).toBe(false);
      await f.complete(0); await f.complete(1);
      expect(f.physicalComplete).toHaveBeenCalledTimes(1);
      expect(await f.publication.view.wait()).toEqual({ state: "unknown", cause: "owner_unavailable" });
    } finally { await f.close(); }
  });
  it("keeps a physically completed SDK response owned until its handler exits", async () => {
    const f = fixture(1, true);
    try {
      f.replySDK(); await f.complete(0); await f.complete(1);
      expect(await f.publication.view.wait()).toEqual({ state: "unknown", cause: "response_superseded" });
      f.maintenance.close(); expect(f.maintenance.cleanupComplete()).toBe(false);
      f.publication.endHandler(); expect(f.maintenance.cleanupComplete()).toBe(true);
      expect(f.publication.view.state()).toEqual({ state: "unknown", cause: "response_superseded" });
    } finally { await f.close(); }
  });
  it("keeps a completed response ABORT unknown", async () => {
    const f = fixture();
    try {
      f.queueOriginal(); await f.complete(0); f.stop(); await f.complete(2);
      expect(f.physicalComplete).toHaveBeenCalledTimes(1);
      expect(await f.publication.view.wait()).toEqual({ state: "unknown", cause: "response_aborted" });
    } finally { await f.close(); }
  });
  it("checks the original fixed deadline at final provider handoff", async () => {
    const f = fixture(1);
    try {
      f.queueOriginal(); await f.complete(0); const { send, done } = await f.publish(1);
      f.advance(5000n); send.admit(); send.finish(); await done;
      expect(await f.publication.view.wait()).toEqual({ state: "unknown", cause: "deadline" });
    } finally { await f.close(); }
  });
  it("keeps an observed final handoff flushed after a later native tail failure", async () => {
    const f = fixture(1);
    try {
      f.queueOriginal(); await f.complete(0); const { send, done } = await f.publish(1);
      const failed = expect(done).rejects.toThrow("rpc_publication_failed");
      send.admit(); expect(await f.publication.view.wait()).toEqual({ state: "flushed" }); send.fail(); await failed;
      expect(f.physicalComplete).toHaveBeenCalledTimes(1); expect(f.publication.view.state()).toEqual({ state: "flushed" });
    } finally { await f.close(); }
  });
});
