import { describe, expect, it } from "vitest";
import type { OperationOptions } from "../public/contract.js";
import { TrustedClock, trustedClockCharge } from "./runtime/clock.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { TrustedDeadline } from "./runtime/deadline.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { CryptoUsageLedger, cryptoUsageCharge } from "./runtime/cryptoUsage.js";
import { RecordEpoch, recordEpochCharge } from "./runtime/recordCrypto.js";
import { UnreliablePreparation, UnreliableRuntime, unreliableCharges, type NativeDatagrams } from "./runtime/unreliable.js";

function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function settle() { for (let i = 0; i < 16; i++) await Promise.resolve(); }

/** Controlled native tasks exercise original borrowing and cancellation. This
 * fixture does not qualify any real carrier, TLS provider or READY path. */
class DatagramTasks implements NativeDatagrams {
  peer!: DatagramTasks;
  maximum = 1024;
  holdWrites = false;
  holdReadExit = false;
  acknowledge = true;
  lastPacket = new Uint8Array();
  writes = 0;
  readonly borrowed: Uint8Array[] = [];
  readonly completions: ReturnType<typeof deferred<void>>[] = [];
  readonly queue: Uint8Array[] = [];
  reader: ReturnType<typeof deferred<Uint8Array>> | undefined;
  canceledReader: (() => void) | undefined;
  maxDatagramBytes() { return this.maximum; }
  async receive(maximum: number, options?: OperationOptions): Promise<Uint8Array> {
    if (options?.signal?.aborted) throw new Error("canceled");
    const queued = this.queue.shift(); if (queued !== undefined) return queued;
    if (this.reader !== undefined) throw new Error("concurrent native receive");
    const task = this.reader = deferred<Uint8Array>();
    const cancel = () => {
      const exit = () => task.reject(new Error("canceled"));
      if (this.holdReadExit) this.canceledReader = exit; else exit();
    };
    options?.signal?.addEventListener("abort", cancel, { once: true });
    if (options?.signal?.aborted) cancel();
    try { const bytes = await task.promise; if (bytes.length > maximum) throw new Error("oversized test packet"); return bytes; }
    finally { this.reader = undefined; options?.signal?.removeEventListener("abort", cancel); }
  }
  submit(bytes: Uint8Array, admitted: () => void) {
    if (bytes.length > this.maximum) return undefined;
    const task = deferred<void>();
    this.borrowed.push(bytes); this.completions.push(task); this.writes++;
    if (this.acknowledge) admitted();
    this.lastPacket = new Uint8Array(bytes); this.peer.deliver(new Uint8Array(bytes));
    if (!this.holdWrites) task.resolve();
    return Object.freeze({ completion: task.promise });
  }
  deliver(bytes: Uint8Array): void {
    const reader = this.reader; if (reader === undefined) this.queue.push(bytes); else reader.resolve(bytes);
  }
  releaseWrites(): void { for (const task of this.completions.splice(0)) task.resolve(); }
  releaseRead(): void { this.canceledReader?.(); this.canceledReader = undefined; }
}
function fixture(profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1") {
  let tick = 0n, owner = 1n;
  const limit = new ResourceVector([64n * 1024n * 1024n, 0n, 0n, 10000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 8, reservations: 100, references: 200,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32);
  const accounts = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  const reserve = (kind: string, charge: ResourceVector) => root.reserve({ owner: { tenant, environment, kind,
    backing: (owner++).toString(16).padStart(32, "0") }, accounts, charge });
  const clock = new TrustedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 100000n, maxRoundTripMS: 100n },
    () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), 128n, reserve("clock", trustedClockCharge(128n)));
  clock.installTrusted(clock.monotonic(), { lowerMS: 1000n, upperMS: 1000n });
  const deadline = new TrustedDeadline(clock, 10000n);
  const makeLedger = (sendDirection: 0 | 1) => {
    const config = { clock, profile, sendDirection, keys: 16, maintenance: { calls: 1n, blocks: 1n, bytes: 1n }, runtimeBytes: 128n };
    return new CryptoUsageLedger(config, reserve(`ledger_${sendDirection}`, cryptoUsageCharge(config)));
  };
  const ledgerA = makeLedger(0), ledgerB = makeLedger(1);
  const epochs: RecordEpoch[] = [];
  const epoch = (ledger: CryptoUsageLedger, number: number) => {
    const original = new RecordEpoch({ clock, born: clock.sample(), authorizationDeadline: deadline, epoch: number, runtimeBytes: 128n },
      new Uint8Array(32).fill(7 + number), new Uint8Array(32).fill(9), ledger, reserve("epoch", recordEpochCharge(128n)));
    epochs.push(original); return original;
  };
  const nativeA = new DatagramTasks(), nativeB = new DatagramTasks(); nativeA.peer = nativeB; nativeB.peer = nativeA;
  const prepare = (ledger: CryptoUsageLedger) => {
    const refs = unreliableCharges(128n).map((cost, index) => reserve(`unreliable_${index}`, cost));
    try { return new UnreliablePreparation(root, 128n, refs, ledger); } finally { for (const ref of refs) ref.release(); }
  };
  const preparedA = prepare(ledgerA), preparedB = prepare(ledgerB);
  const reference = reserve("session", new ResourceVector([128n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  const wakes = [0, 0], drops: { side: number; epoch: string }[] = [];
  const host = (ledger: CryptoUsageLedger) => ({ clock, profile, runtimeBytes: 128n, ledger, check: () => deadline.check(),
    available: () => true, recordCheck: () => deadline.check(), changed: () => { wakes[ledger === ledgerA ? 0 : 1]!++; },
    dropped: (epoch: "current" | "old" | "future") => { drops.push({ side: ledger === ledgerA ? 0 : 1, epoch }); },
    failed: () => { throw new Error("unexpected datagram reader failure"); } });
  const a = new UnreliableRuntime(preparedA, nativeA, host(ledgerA), epoch(ledgerA, 0), 0, reference);
  const b = new UnreliableRuntime(preparedB, nativeB, host(ledgerB), epoch(ledgerB, 0), 0, reference);
  a.start(); b.start();
  return { a, b, nativeA, nativeB, preparedA, preparedB, wakes, drops, tick: (value: bigint) => { tick = value; },
    rekey() { a.freeze(); b.freeze(); a.replaceEpoch(epoch(ledgerA, 1), 1); b.replaceEpoch(epoch(ledgerB, 1), 1); },
    async close() {
      a.close(); b.close(); nativeA.releaseWrites(); nativeB.releaseWrites(); nativeA.releaseRead(); nativeB.releaseRead(); await settle();
      expect(a.cleanupComplete()).toBe(true); expect(b.cleanupComplete()).toBe(true);
      for (const value of epochs) value.close(); ledgerA.close(); ledgerB.close(); reference.release(); clock.close();
      for (const account of accounts) account.close(); root.close();
    } };
}
const options = () => ({ expiresAtMS: 9000n });
describe("original unreliable message ownership", () => {
  for (const profile of ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"]) {
    it(`returns original plaintext bytes and drops authenticated replays with ${profile}`, async () => {
      const f = fixture(profile);
      try {
        expect(await f.a.send(new Uint8Array([1, 2, 3]), options())).toBe("accepted");
        expect(await f.b.receive()).toEqual(new Uint8Array([1, 2, 3]));
        f.nativeB.deliver(new Uint8Array(f.nativeA.lastPacket)); await settle();
        const abort = new AbortController(), replay = f.b.receive({ signal: abort.signal }); abort.abort();
        await expect(replay).rejects.toMatchObject({ code: "canceled" });
        expect(await f.a.send(new Uint8Array([4]), options())).toBe("accepted");
        expect(await f.b.receive()).toEqual(new Uint8Array([4]));
      } finally { await f.close(); }
    });
  }
  it("consumes authenticated replay eligibility when the original receive queue is full", async () => {
    const f = fixture();
    try {
      for (let index = 0; index < 65; index++) expect(await f.a.send(new Uint8Array([index]), options())).toBe("accepted");
      await settle(); const dropped = new Uint8Array(f.nativeA.lastPacket);
      for (let index = 0; index < 64; index++) expect(await f.b.receive()).toEqual(new Uint8Array([index]));
      f.nativeB.deliver(dropped); await settle();
      const abort = new AbortController(), replay = f.b.receive({ signal: abort.signal }); abort.abort();
      await expect(replay).rejects.toMatchObject({ code: "canceled" });
      expect(await f.a.send(new Uint8Array([77]), options())).toBe("accepted");
      expect(await f.b.receive()).toEqual(new Uint8Array([77]));
    } finally { await f.close(); }
  });
  it("keeps the actual native ciphertext borrow after the application cancels and the Session closes", async () => {
    const f = fixture(); f.nativeA.holdWrites = true;
    try {
      const abort = new AbortController(), sending = f.a.send(new Uint8Array([7]), { ...options(), signal: abort.signal });
      const borrowed = f.nativeA.borrowed[0]!; expect(borrowed.some(byte => byte !== 0)).toBe(true);
      abort.abort(); await expect(sending).rejects.toMatchObject({ code: "canceled" });
      f.a.close(); await settle(); expect(f.a.cleanupComplete()).toBe(false);
      f.preparedA.close(); expect(borrowed.some(byte => byte !== 0)).toBe(true);
      f.nativeA.releaseWrites(); await settle(); expect(borrowed.every(byte => byte === 0)).toBe(true);
      expect(f.a.cleanupComplete()).toBe(true);
    } finally { await f.close(); }
  });
  it("joins a submitted native write even when the provider omits the admission callback", async () => {
    const f = fixture(); f.nativeA.holdWrites = true; f.nativeA.acknowledge = false;
    try {
      let returned = false; const sending = f.a.send(new Uint8Array([8]), options()).then(result => { returned = true; return result; });
      await settle(); expect(returned).toBe(false); expect(f.nativeA.borrowed[0]!.some(byte => byte !== 0)).toBe(true);
      f.nativeA.releaseWrites(); expect(await sending).toBe("dropped_carrier");
      expect(f.nativeA.borrowed[0]!.every(byte => byte === 0)).toBe(true);
    } finally { await f.close(); }
  });
  it("waits for the original canceled reader to exit before releasing preparation", async () => {
    const f = fixture(); f.nativeA.holdReadExit = true;
    try {
      f.a.close(); await settle(); f.preparedA.close(); expect(f.a.cleanupComplete()).toBe(false);
      f.nativeA.releaseRead(); await settle(); expect(f.a.cleanupComplete()).toBe(true);
    } finally { await f.close(); }
  });
  it("drops queued sends after an actual MTU reduction and preserves the submitted predecessor", async () => {
    const f = fixture(); f.nativeA.holdWrites = true;
    try {
      const first = f.a.send(new Uint8Array([1]), options());
      const second = f.a.send(new Uint8Array(100), options()); f.nativeA.maximum = 76;
      f.nativeA.releaseWrites(); expect(await first).toBe("accepted"); expect(await second).toBe("dropped_carrier");
      expect(f.nativeA.writes).toBe(1); expect(f.a.maxMessageBytes()).toEqual({ bytes: 1n, scope: "local_submission" });
    } finally { await f.close(); }
  });
  it("discards unread old-epoch packets and accepts only messages encrypted for the replacement epoch", async () => {
    const f = fixture();
    try {
      expect(await f.a.send(new Uint8Array([1]), options())).toBe("accepted"); await settle();
      const old = new Uint8Array(f.nativeA.lastPacket); f.rekey(); f.nativeB.deliver(old); await settle();
      const abort = new AbortController(), receiving = f.b.receive({ signal: abort.signal }); abort.abort();
      await expect(receiving).rejects.toMatchObject({ code: "canceled" });
      expect(await f.a.send(new Uint8Array([2]), options())).toBe("accepted");
      expect(await f.b.receive()).toEqual(new Uint8Array([2]));
    } finally { await f.close(); }
  });
  it("checks expiry before queue exhaustion without resubmitting an expired message", async () => {
    const f = fixture(); f.nativeA.holdWrites = true;
    try {
      const held = Array.from({ length: 64 }, () => f.a.send(new Uint8Array([1]), options()));
      expect(await f.a.send(new Uint8Array([2]), { expiresAtMS: 1000n })).toBe("dropped_expired");
      expect(await f.a.send(new Uint8Array([2]), options())).toBe("dropped_budget");
      f.a.freeze(); f.nativeA.releaseWrites(); await Promise.all(held); expect(f.nativeA.writes).toBe(1);
    } finally { await f.close(); }
  });
});


it("wakes safety after seal and unique inbound acceptance while native output is still blocked", async () => {
  const f = fixture();
  try {
    f.nativeA.holdWrites = true;
    const writing = f.a.send(new Uint8Array([7]), options());
    await settle();
    expect(f.nativeA.completions).toHaveLength(1);
    expect(f.wakes[0]).toBeGreaterThan(0);
    expect(f.wakes[1]).toBeGreaterThan(0);
    expect(await f.b.receive()).toEqual(new Uint8Array([7]));
    const previous = f.wakes[1];
    f.nativeB.deliver(new Uint8Array(f.nativeA.lastPacket)); await settle();
    expect(f.wakes[1]).toBe(previous);
    expect(f.drops).toContainEqual({ side: 1, epoch: "current" });
    f.nativeA.releaseWrites(); expect(await writing).toBe("accepted");
    f.rekey();
    f.nativeB.deliver(new Uint8Array(f.nativeA.lastPacket)); await settle();
    expect(f.drops).toContainEqual({ side: 1, epoch: "old" });
  } finally { await f.close(); }
});
