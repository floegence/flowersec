import { afterEach, describe, expect, it, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, realpathSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createSQLitePoolBacking, openV4SQLitePoolStore, type V4SQLitePoolStore, type V4SQLitePoolOpenOptions } from "./sqlitePoolV4.js";
import { V4EnvironmentRuntime } from "../v4/runtime/environment.js";
import { ResourceRoot, ResourceVector } from "../v4/runtime/resources.js";
import { ClockRate } from "../v4/runtime/timeArithmetic.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { credentialFixture, fill } from "../v4/testSupport/credentials.js";
import { credentialVerifierCharge, verifyDirectCredentials } from "../v4/runtime/credentialVerifier.js";
import { credentialOwner } from "../v4/runtime/credentialSupport.js";
import { authenticatedSessionCharge } from "../v4/runtime/session.js";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { vi.restoreAllMocks(); for (const cleanup of cleanups.splice(0)) await cleanup(); });
function fixture(maxRecords = 4) {
  const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-pool-")), path = join(directory, "once.sqlite");
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const environment = new V4EnvironmentRuntime({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32),
    runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, acquireMS: 10000n, cleanupMS: 25,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: 0n, incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1010n }) }, random: bytes => { crypto.getRandomValues(bytes); } });
  const r = environment.resources, reserve = (kind: string, charge: ResourceVector) => root.reserve({ owner: credentialOwner(r, kind), accounts: r.accounts, charge });
  const namespace = environment.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
    maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
  const material = credentialFixture(r, environment.clock, reserve, "preauthorized_pool", undefined, namespace); material.bootstrap();
  const backing = createSQLitePoolBacking(environment, path, { maxPages: 64, maxRecords, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
  const options: V4SQLitePoolOpenOptions = { create: true, identity: { authority: "spend", storeID: fill(5), generation: 1n },
    continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16) }] };
  const stores: V4SQLitePoolStore[] = [];
  const open = (changes: Partial<V4SQLitePoolOpenOptions> = {}) => { const store = openV4SQLitePoolStore(backing, { ...options, ...changes }); stores.push(store); return store; };
  const original = () => {
    const ref = reserve("verify", credentialVerifierCharge(1024n));
    const closure = verifyDirectCredentials(material.config, material.input(), ref); ref.release();
    const admission = reserve("admission", authenticatedSessionCharge(8, 1024n)), facts = closure.poolSpendFacts(admission);
    const deadline = new TrustedDeadline(environment.clock, 10000n), owner = { connect: fill(8, 16), carrier: fill(9, 16), generation: 1n };
    return { closure, facts, admission, deadline, owner, close: () => { facts.close(); closure.close(); admission.release(); } };
  };
  cleanups.push(async () => {
    for (const store of stores) store.close(); await environment.close();
    rmSync(directory, { recursive: true }); backing.releaseRemoved(); expect(root.snapshot().reservations).toBe(0);
  });
  return { root, environment, material, backing, options, open, original, directory, path };
}

describe("Node v4 durable pool once", () => {
  it("durably writes exact original proof and winner once, retaining files after close", () => {
    const f = fixture(), store = f.open(), one = f.original();
    try { store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined); }
    finally { one.close(); }
    store.close(); expect(store.cleanupComplete()).toBe(true); expect(f.backing.retainedDiskBytes()).toBeGreaterThan(0n); expect(existsSync(f.path)).toBe(true);
    const db = new DatabaseSync(f.path, { readOnly: true });
    try {
      const row = db.prepare("SELECT source,state,retained_until,projection FROM spend").get()!;
      expect(row.source).toBe(1); expect(row.state).toBe(1);
      const retained = row.retained_until as Uint8Array; expect(new DataView(retained.buffer, retained.byteOffset, 8).getBigUint64(0)).toBe(604820000n);
      expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(fill(24)))).toBe(false);
    } finally { db.close(); }
    const reopened = f.open({ create: false }), two = f.original();
    try { expect(() => reopened.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined)).toThrow("spend_conflict"); }
    finally { two.close(); }
  });
  it("treats a lost real COMMIT receipt as spent_unknown and never grants another attempt", () => {
    const f = fixture(), store = f.open(), one = f.original(), exec = DatabaseSync.prototype.exec;
    let fault = true;
    const patched = vi.spyOn(DatabaseSync.prototype, "exec").mockImplementation(function(this: DatabaseSync, sql: string) {
      const result = exec.call(this, sql);
      if (fault && sql === "COMMIT") { fault = false; throw new Error("simulated receipt loss after durable commit"); }
      return result;
    });
    try { expect(() => store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined)).toThrowError(expect.objectContaining({ code: "spent_unknown", writeState: "unknown" })); }
    finally { patched.mockRestore(); one.close(); }
    expect(store.cleanupComplete()).toBe(true);
    const reopened = f.open({ create: false }), two = f.original();
    try { expect(() => reopened.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined)).toThrow("spend_conflict"); }
    finally { two.close(); }
  });
  it("cancellation before COMMIT leaves no record and releases only the original task", () => {
    const f = fixture(), store = f.open(), one = f.original(); let checks = 0;
    try { expect(() => store.consume(one.facts, one.owner, one.deadline, one.admission, () => { if (++checks === 4) throw new Error("canceled"); })).toThrow(); }
    finally { one.close(); }
    const two = f.original();
    try { store.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined); }
    finally { two.close(); }
  });
  it("preserves a committed row when the original owner closes after COMMIT", () => {
    const f = fixture(), store = f.open(), one = f.original(); let checks = 0;
    try { expect(() => store.consume(one.facts, one.owner, one.deadline, one.admission, () => { if (++checks === 5) throw new Error("closed original owner"); })).toThrowError(expect.objectContaining({ writeState: "committed" })); }
    finally { one.close(); }
    const two = f.original();
    try { expect(() => store.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined)).toThrow("spend_conflict"); }
    finally { two.close(); }
  });
  it("does not allow callbacks to stand in for a durable or independent continuity fact", () => {
    const f = fixture();
    expect(() => f.open({ continuity: { check: (() => true) as never } })).toThrow("history_unknown");
    expect(existsSync(f.path)).toBe(false);
  });
  it("refuses absent, mismatched and corrupted histories without creating a fresh database", () => {
    const f = fixture(); expect(() => f.open({ create: false })).toThrow("history_unknown"); expect(existsSync(f.path)).toBe(false);
    const store = f.open(); store.close();
    expect(() => f.open({ create: false, identity: { ...f.options.identity, storeID: fill(6) } })).toThrow("storage_format");
    const db = new DatabaseSync(f.path); db.exec("PRAGMA user_version=2"); db.close();
    expect(() => f.open({ create: false })).toThrow("storage_format");
  });
  it("requires actual Environment ownership and rejects an unconfigured issuer mapping", () => {
    const f = fixture(), store = f.open({ bindings: [{ tenant: "tenant", issuer: fill(7, 16) }] }), one = f.original();
    try { expect(() => store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined)).toThrow("owner_unavailable"); }
    finally { one.close(); }
  });
  it("retains disk allocation when Environment closes its real SQLite connection", async () => {
    const f = fixture(), store = f.open(); await f.environment.close();
    expect(store.cleanupComplete()).toBe(true); expect(f.environment.cleanupStatus().status).toBe("complete");
    expect(f.root.snapshot().charged.values()[2]).toBe(f.backing.retainedDiskBytes()); expect(f.backing.retainedDiskBytes()).toBeGreaterThan(0n);
    expect(() => f.backing.releaseRemoved()).toThrow("history_unknown");
  });
});
