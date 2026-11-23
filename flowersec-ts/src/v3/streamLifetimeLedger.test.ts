import { describe, expect, it } from 'vitest';
import { MAX_STREAM_LIFETIME_SLOTS_V3, maxLogicalStreamIDV3, StreamLifetimeLedgerV3, StreamLifetimeStateV3 } from './streamLifetimeLedger.js';

describe.each([1, 2] as const)('stream lifetime ledger for role %i', role => {
  const id = (slot: number) => 2n * BigInt(slot) + BigInt(role);
  it('does not allocate for unseen slots and remembers the highest valid identity', () => {
    const ledger = new StreamLifetimeLedgerV3(role), last = maxLogicalStreamIDV3(role);
    expect(ledger.state(last)).toBe(StreamLifetimeStateV3.Empty);
    expect(ledger.backingBytes).toBe(0);
    ledger.peerReset(last);
    expect(ledger.validFSS3(last)).toBe('reset');
    expect(() => ledger.validFSS3(last)).toThrow(/duplicate/);
    expect(ledger.frontier).toBe(0n);
    expect(ledger.backingBytes).toBeLessThan(MAX_STREAM_LIFETIME_SLOTS_V3 / 4);
    expect(() => ledger.peerReset(last + 2n)).toThrow(/capacity/);
  });
  it('advances across a page boundary only after earlier identities resolve', () => {
    const ledger = new StreamLifetimeLedgerV3(role);
    ledger.peerReset(id(4096));
    for (let slot = 0; slot < 4095; slot++) ledger.peerReset(id(slot));
    expect(ledger.validFSS3(id(4095))).toBe('accepted');
    expect(ledger.frontier).toBe(id(4094));
    ledger.validOpen(id(4095));
    expect(ledger.frontier).toBe(id(4096));
    expect(ledger.state(id(4097))).toBe(StreamLifetimeStateV3.Empty);
    expect(ledger.validFSS3(id(4096))).toBe('reset');
    expect(() => ledger.validFSS3(id(4096))).toThrow(/duplicate/);
  });
});
