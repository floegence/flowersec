import { expect, it } from "vitest";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { RPCCallCapacity, rpcCallCapacityCharge } from "./runtime/rpcCallCapacity.js";

function fixture(limit: number) {
  const capacity = new ResourceVector(Array<bigint>(11).fill(1000000n));
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit: capacity,
    accounts: 2, reservations: 8, references: 16, rootRuntimeBytes: 128n, accountRuntimeBytes: 128n,
    reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const accounts = [root.account("tenant", "1".repeat(32), capacity), root.account("environment", "2".repeat(32), capacity)];
  const reference = root.reserve({ accounts, owner: { tenant: "1".repeat(32), environment: "2".repeat(32),
    kind: "call_capacity", backing: "3".repeat(32) }, charge: rpcCallCapacityCharge(limit, 1024n) });
  const calls = new RPCCallCapacity(limit, 1024n, reference, true); reference.release();
  return { root, calls, closeRoot: () => { for (const account of accounts) account.close(); root.close(); } };
}

it("keeps protected K backing through result, association and physical publication cleanup", () => {
  const { root, calls, closeRoot } = fixture(4);
  const short = calls.protect("short"), resident = calls.protect("resident");
  const charged = root.snapshot().charged.values();
  calls.bindLimit(3);
  expect(root.snapshot().charged.values()).toEqual(charged);
  expect(() => calls.reserve("resident")).toThrow("resource_exhausted");
  const ordinary = calls.reserve("short");
  expect(() => calls.reserve("short")).toThrow("resource_exhausted");
  const call = short.checkout(), association = {};
  calls.attach(call, association);
  const releasePublication = calls.retainPublication(call, association);
  call.close();
  expect(short.available()).toBe(false);
  calls.settled(call, association);
  expect(short.available()).toBe(false);
  expect(() => short.checkout()).toThrow("resource_exhausted");
  releasePublication();
  expect(call.cleanupComplete()).toBe(true);
  expect(short.available()).toBe(true);
  const repeated = short.checkout(), tail = {};
  calls.attach(repeated, tail);
  const releaseTail = calls.retainPublication(repeated, tail);
  ordinary.close(); repeated.close(); calls.settled(repeated, tail);
  short.close(); resident.close(); calls.close(); closeRoot();
  expect(short.cleanupComplete()).toBe(false);
  expect(root.snapshot().cleanupComplete).toBe(false);
  releaseTail();
  expect(short.cleanupComplete()).toBe(true);
  expect(calls.cleanupComplete()).toBe(true);
  expect(root.snapshot().cleanupComplete).toBe(true);
});

it("checks actual signed K before enabling prepaid call positions", () => {
  const { root, calls, closeRoot } = fixture(4);
  const first = calls.protect("short"), second = calls.protect("short");
  expect(() => first.checkout()).toThrow("resource_exhausted");
  expect(() => calls.bindLimit(1)).toThrow("configuration_capacity");
  expect(() => calls.bindLimit(5)).toThrow("configuration_capacity");
  calls.bindLimit(2);
  expect(() => calls.bindLimit(2)).toThrow("configuration_capacity");
  const call = second.checkout(); call.close();
  calls.close(); closeRoot();
  expect(first.cleanupComplete()).toBe(true);
  expect(root.snapshot().cleanupComplete).toBe(true);
});
