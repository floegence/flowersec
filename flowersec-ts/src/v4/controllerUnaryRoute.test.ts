import { describe, expect, it } from "vitest";
import { V4MethodDefinition, methodDefinition } from "./serviceDefinition.js";
import { v4UTF8MessageCodec } from "./messageDefinition.js";
import { encode, map, text, u, array, fill } from "./testSupport/credentials.js";
import { applicationGroup } from "./runtime/applicationExecutor.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge } from "./runtime/applicationHeader.js";
import { TrustedClock, trustedClockCharge } from "./runtime/clock.js";
import { TrustedDeadline } from "./runtime/deadline.js";
import type { ControllerUnaryRoute, ControllerUnaryRouteRequest } from "./runtime/controllerUnaryRoute.js";
import { ReceiveDeliveryGate, receiveDeliveryCharge } from "./runtime/receiveDirection.js";
import { RPCCallCapacity, rpcCallCapacityCharge, type RPCCallReservation } from "./runtime/rpcCallCapacity.js";
import type { RPCChannelRuntime } from "./runtime/rpcChannel.js";
import type { RPCCompletion } from "./runtime/rpcCompletion.js";
import type { RPCNetworkTicket } from "./runtime/rpcNetwork.js";
import { RPCPayload, type RPCPayloadBorrow } from "./runtime/rpcPayload.js";
import type { RPCPublicationGuard } from "./runtime/rpcPublisher.js";
import { RPCUnaryExchange, rpcUnaryExchangeCharges } from "./runtime/rpcUnaryExchange.js";
import { RPCUnaryResultRecipient } from "./runtime/rpcUnaryResultRecipient.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { ServiceContractSnapshot, serviceContractCharge, serviceContractDecoderCharge } from "./runtime/serviceContract.js";
import { ClockRate } from "./runtime/timeArithmetic.js";

/** A bounded channel double exposes the actual pre-BEGIN gate and publication
 * tail. Resource, K, Completion, contract, header and result owners are real. */
function fixture() {
  const limit = new ResourceVector(Array<bigint>(11).fill(100000000n));
  const root = new ResourceRoot({ applicationResourceProfile: "client", profileRevision: "1".repeat(64), limit,
    accounts: 4, reservations: 128, references: 512, rootRuntimeBytes: 128n, accountRuntimeBytes: 128n,
    reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32);
  const accounts = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  let allocation = 0;
  const reserve = (charge: ResourceVector) => root.reserve({ accounts, charge,
    owner: { tenant, environment, kind: "queued_unary_test", backing: (++allocation).toString(16).padStart(32, "0") } });
  const clockRef = reserve(trustedClockCharge(1024n));
  let now = 0n;
  const clock = new TrustedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
    () => ({ milliseconds: now, incarnation: "3".repeat(32) }), 1024n, clockRef); clockRef.release();
  clock.installTrusted(clock.monotonic(), { lowerMS: 1000n, upperMS: 1000n });
  const deadline = new TrustedDeadline(clock, 20000n);
  const deliveryRef = reserve(receiveDeliveryCharge(1024n)), delivery = new ReceiveDeliveryGate(deadline, 1024n, deliveryRef); deliveryRef.release();
  const group = applicationGroup(root, accounts, { tenant, environment, kind: "queued_unary_group", backing: "4".repeat(32) }, 1024n, true);
  const capacityRef = reserve(rpcCallCapacityCharge(8, 1024n)), capacity = new RPCCallCapacity(8, 1024n, capacityRef); capacityRef.release();
  const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
  const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
    requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
  const facts = methodDefinition(method);
  const contractRefs = [reserve(serviceContractCharge(1024n)), reserve(serviceContractDecoderCharge(1024n))];
  const contract = new ServiceContractSnapshot(encode(map({ 0: text("example.route"), 1: u(42), 2: u(0), 3: u(0),
    6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
    21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, contractRefs[0]!, contractRefs[1]!);
  contractRefs.forEach(reference => reference.release());
  const headerRefs = [reserve(applicationHeaderCharge(1024n)), reserve(applicationHeaderDecoderCharge(1024n))];
  const headers = new ApplicationHeaderCodec(1024n, headerRefs[0]!, headerRefs[1]!); headerRefs.forEach(reference => reference.release());
  const digest = new Uint8Array(32); contract.copyDigest(digest);
  const header = headers.create({ kind: "transient_unary_request", typeID: 42, payloadBytes: 5, contractDigest: digest,
    deadlineAtMS: 20000n, admissionMode: 0, responseLimitBytes: 128 });
  const authentication = { tenant: "tenant", audience: "service", localRole: "client" as const, localSubject: "client",
    peerSubject: "server", peerIdentityDigest: "5".repeat(64) };
  const publication: RPCPublicationGuard = { check: () => deadline.check(), current: () => true,
    reroute: source => ({ check: () => { deadline.check(); source.check(); }, current: () => source.current(),
      reroute: publicationSource => publication.reroute!(publicationSource) }) };
  interface Channel {
    exchange: RPCUnaryExchange;
    guard: RPCPublicationGuard;
    response: RPCCompletion;
    payload: RPCPayloadBorrow;
    call: RPCCallReservation;
    tail: () => void;
    stopped: boolean;
    settled: boolean;
    held: boolean;
    release(): void;
    settle(): void;
  }
  const channels: Channel[] = [], observers = new Set<() => void>(), exchanges: RPCUnaryExchange[] = [];
  let selected = 0, current = 0, selections = 1, reserveHook: (() => void) | undefined;
  const snapshots: ControllerUnaryRouteRequest[] = [];
  const route: ControllerUnaryRoute = {
    get selections() { return selections; }, current: () => selected === current, check: () => deadline.check(),
    observe: (reference, changed) => {
      const original = reference.borrow(); observers.add(changed); let active = true;
      return () => { if (!active) return; active = false; observers.delete(changed); original.release(); };
    },
    reserve: request => {
      expect(channels[channels.length - 1]!.guard.current()).toBe(false);
      reserveHook?.(); snapshots.push(request);
      if (selected === current || selections >= 3) return undefined;
      selected = current; selections++;
      return create(request.bytes, request.publication.reroute!(publication));
    },
  };
  function create(bytes: Uint8Array = new TextEncoder().encode("hello"), source = publication): RPCUnaryExchange {
    const refs = rpcUnaryExchangeCharges(bytes.length, 128, 1024n, facts).map(reserve);
    const payload = new RPCPayload(bytes.length, 1024n, refs[1]!); payload.write(0, bytes);
    const call = capacity.reserve("short"), completion = group.reserveCompletion();
    const exchange = new RPCUnaryExchange(header, contract, payload, deadline, source, delivery, root, 1024n,
      [refs[0]!, refs[2]!], call, completion, facts, authentication, undefined, undefined, route);
    refs.forEach(reference => reference.release()); exchanges.push(exchange);
    let state: Channel;
    const channel = {
      queueRequest: (_header: unknown, response: RPCCompletion, borrow: RPCPayloadBorrow, guard: RPCPublicationGuard) => {
        const ticket = {} as RPCNetworkTicket; capacity.attach(call, ticket);
        state = { exchange, response, payload: borrow, guard, call, tail: capacity.retainPublication(call, ticket), stopped: false, settled: false, held: false,
          release: () => { state.held = false; state.payload.release(); state.tail(); },
          settle: () => { if (state.settled) return; state.settled = true; capacity.settled(call, ticket); } };
        channels.push(state); return ticket;
      },
      stop: (_ticket: RPCNetworkTicket) => {
        if (state.stopped) return; state.stopped = true; state.response.close();
        state.settle();
        if (!state.held) state.release();
      },
    } as unknown as RPCChannelRuntime;
    exchange.submit(channel); return exchange;
  }
  return { root, header, deadline, channels, snapshots, create,
    advance: (generation: number) => { current = generation; for (const observer of [...observers]) observer(); },
    setReserveHook: (hook: () => void) => { reserveHook = hook; }, expire: () => { now = 20000n; },
    finish: (value = "world") => {
      const state = channels[channels.length - 1]!, bytes = new TextEncoder().encode(value);
      state.guard.admitted?.(); state.response.begin(headers.response(header, "transient_unary_response", bytes.length));
      state.response.write(0, bytes); state.response.finish(undefined, { requestAborted: false, stopSent: false }); state.settle();
    },
    close: () => {
      exchanges.forEach(exchange => exchange.close()); channels.forEach(channel => channel.release());
      delivery.close(); capacity.close(); group.close(); contract.release(); headers.close(); clock.close();
      accounts.forEach(account => account.close()); root.close();
    },
  };
}

describe("Controller queued unary route ownership", () => {
  it("moves the original final recipient and preserves bytes, header and deadline through two reselections", async () => {
    const f = fixture();
    try {
      const operation = f.create(), recipient = new RPCUnaryResultRecipient({}); recipient.arm(); operation.receiveResult(recipient);
      f.advance(1); f.advance(2);
      expect(f.channels).toHaveLength(3);
      for (const snapshot of f.snapshots) {
        expect(snapshot.header).toBe(f.header); expect(snapshot.deadline).toBe(f.deadline);
        expect(snapshot.bytes).toEqual(new TextEncoder().encode("hello"));
      }
      f.finish(); const current = f.channels[f.channels.length - 1]!;
      expect(current.call.networkComplete()).toBe(false);
      current.release(); expect(current.call.networkComplete()).toBe(true);
      const result = await recipient.promise;
      expect(result).toMatchObject({ kind: "value", value: "world" }); if ("release" in result) result.release();
      expect(recipient.done).toBe(true); expect(operation.progress().submission).toBe("submitted");
    } finally { f.close(); }
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("retains the revoked physical tail while the replacement owns full new resources", async () => {
    const f = fixture();
    try {
      const operation = f.create(), old = f.channels[0]!; old.held = true;
      const before = f.root.snapshot().charged.values()[0]!; f.advance(1);
      expect(old.guard.current()).toBe(false); expect(old.call.networkComplete()).toBe(false);
      expect(f.root.snapshot().charged.values()[0]!).toBeGreaterThan(before);
      operation.close(); expect(operation.cleanupComplete()).toBe(false);
      old.release(); expect(operation.cleanupComplete()).toBe(true);
    } finally { f.close(); }
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("does not reselect after BEGIN, cancellation, deadline expiry or exhaustion", () => {
    for (const stop of ["begin", "close", "expire", "exhausted"] as const) {
      const f = fixture();
      try {
        const operation = f.create();
        if (stop === "begin") f.channels[0]!.guard.admitted?.();
        else if (stop === "close") operation.close();
        else if (stop === "expire") f.expire();
        else { f.advance(1); f.advance(2); }
        const count = f.channels.length; f.advance(3); expect(f.channels).toHaveLength(count);
        if (stop === "begin") expect(operation.progress().submission).toBe("submitted");
        else expect(operation.progress()).toMatchObject({ state: "failed", submission: "not_submitted" });
      } finally { f.close(); }
    }
  });
  it("preserves Close when replacement admission fails after reentrant cancellation", () => {
    const f = fixture();
    try {
      const operation = f.create();
      f.setReserveHook(() => { operation.close(); throw new Error("resource_exhausted"); });
      f.advance(1);
      expect(f.channels).toHaveLength(1);
      expect(f.channels[0]!.guard.current()).toBe(false);
      expect(operation.progress()).toMatchObject({ state: "failed", submission: "not_submitted", failure: "closed" });
    } finally { f.close(); }
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
  it("Close winning during replacement allocation permanently closes both route gates", () => {
    const f = fixture();
    try {
      const operation = f.create(); f.setReserveHook(() => operation.close()); f.advance(1);
      expect(f.channels).toHaveLength(2); expect(f.channels.every(channel => !channel.guard.current())).toBe(true);
      expect(operation.progress()).toMatchObject({ state: "failed", submission: "not_submitted" });
    } finally { f.close(); }
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
});
