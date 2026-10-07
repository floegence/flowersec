import { describe, expect, it } from "vitest";
import { ResourceRoot, ResourceVector, type ApplicationResourceProfile } from "./runtime/resources.js";
import { applicationEnvelope, applicationGroup, applicationWorkload } from "./runtime/applicationExecutor.js";

function fixture(applicationResourceProfile: ApplicationResourceProfile) {
  const limit = new ResourceVector(Array<bigint>(11).fill(100000000n));
  const root = new ResourceRoot({ applicationResourceProfile, profileRevision: "1".repeat(64), limit,
    accounts: 4, reservations: 64, references: 128, rootRuntimeBytes: 128n,
    accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const accounts = [root.account("tenant", "1".repeat(32), limit), root.account("environment", "2".repeat(32), limit)];
  const owner = { tenant: "1".repeat(32), environment: "2".repeat(32), kind: "application_group", backing: "3".repeat(32) };
  const first = applicationGroup(root, accounts, owner, 1024n, true);
  const second = applicationGroup(root, accounts, { ...owner, backing: "4".repeat(32) }, 1024n, true);
  return { root, accounts, first, second };
}

describe("shared application resource presets", () => {
  it.each([
    { preset: "client" as const, ordinary: 26, resident: 18, bytes: 7n * 1024n * 1024n },
    { preset: "server" as const, ordinary: 26, resident: 18, bytes: 7n * 1024n * 1024n },
    { preset: "constrained" as const, ordinary: 8, resident: 6, bytes: 3n * 1024n * 1024n },
  ])("protects real short and Completion opportunities on a shared $preset root", ({ preset, ordinary, resident, bytes }) => {
    const { root, accounts, first, second } = fixture(preset);
    const permits = [];
    try {
      expect(first.executor).toBe(second.executor);
      expect(applicationEnvelope(root)).toMatchObject({ bytes, running: ordinary, ready: ordinary * 2,
        residentRunning: resident, residentReady: resident * 2 });
      for (let n = 0; n < resident; n++) permits.push((n % 2 === 0 ? first : second).tryOrdinary("resident"));
      expect(() => second.tryOrdinary("resident")).toThrow("would_block");
      for (let n = resident; n < ordinary; n++) permits.push(second.tryOrdinary("short"));
      expect(() => first.tryOrdinary("short")).toThrow("would_block");
      // Completion owns separate original service positions even while every
      // ordinary position is retained across both participating groups.
      const complete = first.executor.tryAcquire(first, "completion");
      permits.push(complete);
      expect(applicationWorkload(root)).toMatchObject({ ordinaryRunning: ordinary, residentRunning: resident, completionRunning: 1 });
      first.close(); second.close();
      expect(root.snapshot().reservations).toBeGreaterThan(0);
      expect(applicationWorkload(root)?.ordinaryRunning).toBe(ordinary);
    } finally {
      first.close(); second.close();
      for (const permit of permits) permit.release();
      for (const account of accounts) account.close();
      root.close();
    }
    expect(root.snapshot().cleanupComplete).toBe(true);
  });
});

it("enables one shared management lane only for execution and retains started work after close", async () => {
  const { root, accounts, first, second } = fixture("client"), signal = new AbortController();
  const before = root.snapshot().reservations;
  first.enableManagement();
  expect(root.snapshot().reservations).toBe(before + 1);
  second.enableManagement();
  expect(root.snapshot().reservations).toBe(before + 1);
  const one = await first.management(signal.signal, () => {}), two = await second.management(signal.signal, () => {});
  let entered = false;
  const waiting = second.management(signal.signal, () => {}).then(permit => { entered = true; return permit; });
  await Promise.resolve(); expect(entered).toBe(false);
  one.release(); const three = await waiting; expect(entered).toBe(true);
  first.close(); second.close();
  expect(root.snapshot().reservations).toBeGreaterThan(0);
  two.release(); three.release();
  for (const account of accounts) account.close(); root.close();
  expect(root.snapshot().cleanupComplete).toBe(true);
});
