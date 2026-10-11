import { afterEach, describe, expect, it, vi } from "vitest";
import { V4EnvironmentRuntime, type V4EnvironmentClockConfig, type V4EnvironmentConfig } from "../v4/runtime/environment.js";
import { ResourceRoot, ResourceVector } from "../v4/runtime/resources.js";
import { createCurrentPeerClock, createCurrentServerClock } from "./currentClock.js";

function fixture(clock: V4EnvironmentClockConfig) {
  const limit = new ResourceVector([512n << 20n, 0n, 0n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const config: V4EnvironmentConfig = { root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, acquireMS: 10000n, cleanupMS: 25,
    clock, random: bytes => { crypto.getRandomValues(bytes); } };
  return { root, config };
}

afterEach(() => { vi.restoreAllMocks(); });

describe("current engineering clock installation", () => {
  it.each([createCurrentPeerClock, createCurrentServerClock])("anchors after delayed construction with %s", async createClock => {
    let wallMS = 100000, monotonicMS = 1000;
    vi.spyOn(Date, "now").mockImplementation(() => wallMS);
    vi.spyOn(performance, "now").mockImplementation(() => monotonicMS);
    const shared = fixture(createClock());
    // The configuration exists before Environment reserves its resources.
    wallMS += 250; monotonicMS += 250;
    const environment = new V4EnvironmentRuntime(shared.config);
    try {
      const installed = environment.clock.sample().requireInterval();
      expect(installed.lowerMS).toBeGreaterThanOrEqual(100200n);
      expect(installed.lowerMS).toBeLessThanOrEqual(BigInt(wallMS));
      expect(installed.upperMS).toBeGreaterThanOrEqual(BigInt(wallMS));
      wallMS += 25; monotonicMS += 25;
      const advanced = environment.clock.sample().requireInterval();
      expect(advanced.lowerMS).toBeGreaterThan(installed.lowerMS);
      expect(advanced.lowerMS).toBeLessThanOrEqual(BigInt(wallMS));
      expect(advanced.upperMS).toBeGreaterThanOrEqual(BigInt(wallMS));
    } finally { await environment.close(); }
    expect(shared.root.snapshot().reservations).toBe(0); shared.root.close();
  });

  it.each([
    { createClock: createCurrentPeerClock, bracketMS: 96, expectedWidth: 200n },
    { createClock: createCurrentServerClock, bracketMS: 100, expectedWidth: 100n },
  ])("retains the original usable envelope bound for $createClock", async ({ createClock, bracketMS, expectedWidth }) => {
    const wall = vi.spyOn(Date, "now").mockReturnValue(100000);
    vi.spyOn(performance, "now").mockReturnValue(0);
    const shared = fixture(createClock());
    wall.mockReturnValueOnce(100000).mockReturnValueOnce(100000 + bracketMS).mockReturnValue(100000 + bracketMS);
    const environment = new V4EnvironmentRuntime(shared.config);
    try {
      const interval = environment.clock.sample().requireInterval();
      expect(interval.upperMS - interval.lowerMS).toBe(expectedWidth);
      expect(interval.lowerMS).toBeLessThanOrEqual(100000n);
      expect(interval.upperMS).toBeGreaterThanOrEqual(BigInt(100000 + bracketMS));
    } finally { await environment.close(); }
    expect(shared.root.snapshot().reservations).toBe(0); shared.root.close();
  });

  it.each([
    { createClock: createCurrentPeerClock, bracketMS: 99, error: "time_width" },
    { createClock: createCurrentPeerClock, bracketMS: 100, error: "time_width" },
    { createClock: createCurrentPeerClock, bracketMS: 101, error: "time_unavailable" },
    { createClock: createCurrentPeerClock, bracketMS: -1, error: "time_unavailable" },
    { createClock: createCurrentServerClock, bracketMS: 101, error: "time_unavailable" },
    { createClock: createCurrentServerClock, bracketMS: -1, error: "time_unavailable" },
  ])("refuses $bracketMS ms sampling brackets for $createClock and releases construction resources", ({ createClock, bracketMS, error }) => {
    const wall = vi.spyOn(Date, "now").mockReturnValue(100000);
    vi.spyOn(performance, "now").mockReturnValue(0);
    const shared = fixture(createClock());
    wall.mockReturnValueOnce(100000).mockReturnValueOnce(100000 + bracketMS).mockReturnValue(100000 + bracketMS);
    try {
      expect(() => new V4EnvironmentRuntime(shared.config)).toThrow(error);
      expect(shared.root.snapshot().reservations).toBe(0);
    } finally { shared.root.close(); }
  });
});
