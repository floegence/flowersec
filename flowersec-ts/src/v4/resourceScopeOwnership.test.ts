import { expect, it } from "vitest";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";

it("retains one physical backing across original scopes without double charging the root",() => {
  const limit = new ResourceVector(Array<bigint>(11).fill(1000000n));
  const root = new ResourceRoot({profileRevision:"1".repeat(64),limit,accounts:4,reservations:8,references:16,
    rootRuntimeBytes:64n,accountRuntimeBytes:64n,reservationRuntimeBytes:64n,referenceRuntimeBytes:64n});
  const tenant = root.account("tenant","1".repeat(32),limit), environment = root.account("environment","2".repeat(32),limit),
    session = root.account("session","3".repeat(32),limit), direction = root.account("direction","4".repeat(32),limit);
  const charge = new ResourceVector([4096n,2048n,0n,1n,0n,0n,0n,1n,0n,0n,1n]);
  const native = root.reserve({accounts:[tenant,environment],owner:{tenant:"1".repeat(32),environment:"2".repeat(32),kind:"native_test",backing:"5".repeat(32)},charge});
  const paired = root.reserve({accounts:[tenant,environment,session,direction],owner:{tenant:"1".repeat(32),environment:"2".repeat(32),kind:"bridge_test",backing:"6".repeat(32)},charge});
  const before = root.snapshot().charged.values(), sessionBefore = session.usage().values();
  const scoped = native.borrowInScopesOf(paired);
  expect(root.snapshot().charged.values()).toEqual(before);
  expect(session.usage().values()).toEqual(sessionBefore.map((value,index) => value + charge.values()[index]!));
  // Releasing the old native registration cannot refund physical custody
  // while the actual bridge alias remains in the original Session scope.
  native.release(); scoped.check();
  expect(root.snapshot().charged.values()).toEqual(before);
  scoped.release(); paired.release();
  for (const account of [direction,session,environment,tenant]) account.close(); root.close();
  expect(root.snapshot().cleanupComplete).toBe(true);
});

it("keeps a protected request and its selected send scope occupied through the last prepaid tail", () => {
  const limit = new ResourceVector(Array<bigint>(11).fill(1000000n));
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 4, reservations: 2, references: 3,
    rootRuntimeBytes: 64n, accountRuntimeBytes: 64n, reservationRuntimeBytes: 64n, referenceRuntimeBytes: 64n });
  const tenant = root.account("tenant", "1".repeat(32), limit), environment = root.account("environment", "2".repeat(32), limit),
    session = root.account("session", "3".repeat(32), limit), direction = root.account("direction", "4".repeat(32), limit);
  const owner = { tenant: "1".repeat(32), environment: "2".repeat(32), kind: "prepared_request", backing: "5".repeat(32) };
  const charge = new ResourceVector([4096n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const request = root.reserve({ accounts: [tenant, environment], owner, charge }), alias = request.borrow();
  const position = root.protectScoped(request, charge, [alias]);
  const sender = root.reserve({ accounts: [tenant, environment, session, direction], owner: { ...owner, kind: "channel", backing: "6".repeat(32) }, charge });
  const primary = position.checkoutScoped([tenant, environment, session]);
  const charged = root.snapshot().charged.values(), directionBefore = direction.usage().values();
  // The root has no unused reference slot: actual publication must use the
  // alias admitted with this workload before connection material acquisition.
  const tail = primary.borrowInScopesOf(sender);
  expect(root.snapshot().charged.values()).toEqual(charged);
  expect(direction.usage().values()).toEqual(directionBefore.map((value, index) => value + charge.values()[index]!));
  primary.release();
  expect(position.available()).toBe(false); tail.check();
  expect(() => position.checkoutScoped([tenant, environment, session])).toThrow("resource_exhausted");
  expect(direction.usage().values()).toEqual(directionBefore.map((value, index) => value + charge.values()[index]!));
  tail.release();
  expect(position.available()).toBe(true); expect(direction.usage().values()).toEqual(directionBefore);
  const next = position.checkoutScoped([tenant, environment, session]); next.release(); position.closeAfterUse(); sender.release();
  for (const account of [direction, session, environment, tenant]) account.close(); root.close();
  expect(root.snapshot().cleanupComplete).toBe(true);
});
