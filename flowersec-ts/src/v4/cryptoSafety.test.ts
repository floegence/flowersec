import { expect, it } from "vitest";
import { transportV4CryptoUsageRegistry as registry } from "../generated/transportV4Registry.js";
import { TrustedClock, trustedClockCharge } from "./runtime/clock.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { TrustedDeadline } from "./runtime/deadline.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { CryptoUsageLedger, cryptoUsageCharge, type CryptoEpochUsage, type CryptoKeyUsage } from "./runtime/cryptoUsage.js";
import { RecordEpoch, recordEpochCharge } from "./runtime/recordCrypto.js";
import { datagramScope, wire } from "./runtime/wireRegistry.js";

// Real fixed profile limits and original resource owners. Large precharges
// exercise accounting only, without claiming provider/AEAD execution evidence.
function fixture(profile: keyof typeof registry.profiles) {
  let tick = 0n, owner = 1n;
  const limit = new ResourceVector([64n * 1024n * 1024n, 0n, 0n, 10000n, 100n, 100n, 100n, 100n, 100n, 100n, 100n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 8, reservations: 40, references: 80,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32);
  const accounts = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  const reserve = (kind: string, charge: ResourceVector) => root.reserve({
    owner: { tenant, environment, kind, backing: (owner++).toString(16).padStart(32, "0") }, charge, accounts,
  });
  const clock = new TrustedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 300000000n, maxRoundTripMS: 100n },
    () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), 128n, reserve("clock", trustedClockCharge(128n)));
  clock.installTrusted(clock.monotonic(), { lowerMS: 1000n, upperMS: 1000n });
  const config = { clock, profile, sendDirection: 0 as const, keys: 8, maintenance: { calls: 1n, blocks: 1n, bytes: 1n }, runtimeBytes: 128n };
  const ledger = new CryptoUsageLedger(config, reserve("ledger", cryptoUsageCharge(config)));
  const epochs: CryptoEpochUsage[] = [], keys: CryptoKeyUsage[] = [], records: RecordEpoch[] = [];
  return { clock, ledger, reserve, records, tick(value: bigint) { tick = value; },
    epoch(number: number) { const value = ledger.newEpoch(number); epochs.push(value); return value; },
    key(epoch: CryptoEpochUsage, scope: bigint, direction: 0 | 1) {
      const value = ledger.derive(epoch, scope, direction); keys.push(value); return value;
    },
    close() {
      for (const key of keys) key.close(); for (const epoch of epochs) epoch.close(); for (const epoch of records) epoch.close();
      ledger.close(); expect(ledger.cleanupComplete()).toBe(true); clock.close();
      for (const account of accounts) account.close(); root.close();
    },
  };
}
for (const profile of Object.keys(registry.profiles) as (keyof typeof registry.profiles)[]) {
  const limits = registry.profiles[profile], keyBlocks = BigInt(limits.key.authentication_blocks);
  const softBlocks = keyBlocks - keyBlocks / 5n, payload = Number((softBlocks - 1n) * 16n);
  it(`triggers safety from a live key before epoch or Session exhaustion: ${profile}`, () => {
    const f = fixture(profile);
    try {
      const epoch = f.epoch(0), key = f.key(epoch, 1n, 0);
      expect(f.ledger.rekeySafetySnapshot(epoch).triggered).toBe(false);
      key.precharge(wire.frame_types.STREAM_DATA!, 0, payload);
      expect(f.ledger.rekeySafetySnapshot(epoch).triggered).toBe(true);
      expect(f.ledger.usageSnapshot(key).session[1]).toBeLessThan(BigInt(limits.epoch.authentication_blocks) / 2n);
      key.close(); expect(f.ledger.rekeySafetySnapshot(epoch).triggered).toBe(false);
    } finally { f.close(); }
  });
  it(`excludes unaccepted inbound datagrams while preserving hard use: ${profile}`, () => {
    const f = fixture(profile);
    try {
      const epoch = f.epoch(0), key = f.key(epoch, datagramScope, 1);
      const cost = key.precharge(wire.frame_types.DATAGRAM!, 0, payload);
      expect(f.ledger.rekeySafetySnapshot(epoch).triggered).toBe(false);
      expect(f.ledger.usageSnapshot(key).key[1]).toBe(softBlocks);
      f.ledger.acceptDatagram(key, cost);
      expect(f.ledger.rekeySafetySnapshot(epoch).triggered).toBe(true);
      expect(() => f.ledger.acceptDatagram(key, cost)).toThrow("crypto_owner");
    } finally { f.close(); }
  });
  it(`keeps outgoing datagram precharges after a dropped send: ${profile}`, () => {
    const f = fixture(profile);
    try {
      const epoch = f.epoch(0), key = f.key(epoch, datagramScope, 0);
      key.precharge(wire.frame_types.DATAGRAM!, 0, payload);
      expect(f.ledger.rekeySafetySnapshot(epoch).triggered).toBe(true);
    } finally { f.close(); }
  });
  it(`retains epoch usage after key retirement and Session usage after rekey: ${profile}`, () => {
    const f = fixture(profile);
    try {
      const epoch = f.epoch(0), usable = BigInt(limits.epoch.authentication_blocks) - 1n, threshold = usable - usable / 5n;
      let spent = 0n, scope = 1n;
      while (spent < threshold) {
        const key = f.key(epoch, scope, 0);
        key.precharge(wire.frame_types.STREAM_DATA!, 0, Number((keyBlocks - 1n) * 16n));
        spent += keyBlocks; key.close(); scope += 2n;
      }
      expect(f.ledger.rekeySafetySnapshot(epoch).triggered).toBe(true);
      epoch.close(); const next = f.epoch(1), key = f.key(next, 1n, 0);
      expect(f.ledger.rekeySafetySnapshot(next)).toEqual({ epoch: 1, triggered: false });
      expect(f.ledger.usageSnapshot(key).session[1]).toBe(spent);
    } finally { f.close(); }
  });
  it(`binds root age to each root and distinguishes the authorization cap: ${profile}`, () => {
    const f = fixture(profile);
    try {
      const maximum = BigInt(limits.root_max_age_ms), deadline = new TrustedDeadline(f.clock, 1000n + 3n * maximum);
      const config = { clock: f.clock, born: f.clock.sample(), authorizationDeadline: deadline, epoch: 0, runtimeBytes: 128n };
      const original = new RecordEpoch(config, new Uint8Array(32).fill(7), new Uint8Array(32).fill(9), f.ledger,
        f.reserve("root", recordEpochCharge(128n)));
      f.records.push(original); f.tick(maximum * 4n / 5n + 1n);
      expect(original.rekeySafetySnapshot().remainingMS).toBeLessThan(maximum / 5n);
      expect(original.rekeySafetySnapshot().rootAgeLimited).toBe(true);
      const next = original.installSuccessor(new Uint8Array(32).fill(8), { ...config, born: f.clock.sample(), epoch: 1 },
        f.reserve("next_root", recordEpochCharge(128n)));
      f.records.push(next); expect(next.rekeySafetySnapshot().remainingMS).toBe(maximum);
      deadline.tighten(f.clock.sample().requireInterval().lowerMS + 1000n);
      expect(next.rekeySafetySnapshot().rootAgeLimited).toBe(false);
    } finally { f.close(); }
  });
}
