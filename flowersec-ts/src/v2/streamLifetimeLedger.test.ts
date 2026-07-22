import { describe, expect, test } from "vitest";

import {
  MAX_STREAM_LIFETIME_SLOTS_V2,
  StreamLifetimeLedgerV2,
  StreamLifetimeStateV2,
} from "./streamLifetimeLedger.js";

describe("StreamLifetimeLedgerV2", () => {
  test("uses exactly two bits for every bounded lifetime slot", () => {
    const client = new StreamLifetimeLedgerV2(1);
    const server = new StreamLifetimeLedgerV2(2);
    expect(client.backingBytes).toBe(MAX_STREAM_LIFETIME_SLOTS_V2 / 4);
    expect(server.backingBytes).toBe(MAX_STREAM_LIFETIME_SLOTS_V2 / 4);
    expect(client.peerReset(2_097_151n)).toBeUndefined();
    expect(server.peerReset(2_097_152n)).toBeUndefined();
    expect(() => client.peerReset(2_097_153n)).toThrowError(/capacity/);
    expect(() => server.peerReset(2_097_154n)).toThrowError(/capacity/);
  });

  test("advances only across contiguous resolved or abandoned identities", () => {
    const ledger = new StreamLifetimeLedgerV2(1);
    ledger.peerReset(5n);
    ledger.peerReset(3n);
    expect(ledger.frontier).toBe(0n);
    expect(ledger.validFSS2(1n)).toBe("accepted");
    expect(ledger.state(1n)).toBe(StreamLifetimeStateV2.PrefaceSeen);
    expect(ledger.frontier).toBe(0n);
    ledger.validOpen(1n);
    expect(ledger.frontier).toBe(5n);
  });

  test("handles RESET-before-FSS2, one late FSS2 reset, and duplicate identity", () => {
    const ledger = new StreamLifetimeLedgerV2(1);
    ledger.peerReset(3n);
    expect(ledger.state(3n)).toBe(StreamLifetimeStateV2.AbandonedNoFSS2);
    expect(ledger.validFSS2(3n)).toBe("reset");
    expect(ledger.state(3n)).toBe(StreamLifetimeStateV2.ActiveOrResolved);
    expect(() => ledger.validFSS2(3n)).toThrowError(/duplicate/);
  });

  test("does not resolve PREFACE_SEEN until OPEN or ordered reset commits", () => {
    const ledger = new StreamLifetimeLedgerV2(2);
    ledger.validFSS2(2n);
    expect(ledger.frontier).toBe(0n);
    ledger.localResetCommitted(2n);
    expect(ledger.frontier).toBe(2n);
    expect(() => ledger.validFSS2(2n)).toThrowError(/duplicate/);
  });
});
