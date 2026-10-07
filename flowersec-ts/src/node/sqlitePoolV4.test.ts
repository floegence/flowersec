import { ConnectionFacts } from "../v4/runtime/connectionFacts.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Worker } from "node:worker_threads";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, realpathSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { createSQLitePoolBacking, openV4SQLitePoolStore, type V4SQLitePoolStore, type V4SQLitePoolOpenOptions } from "./sqlitePoolV4.js";
import { V4EnvironmentRuntime } from "../v4/runtime/environment.js";
import { ResourceRoot, ResourceVector } from "../v4/runtime/resources.js";
import { ClockRate } from "../v4/runtime/timeArithmetic.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { credentialFixture, fill, map, u, text, bytes, array, encode, get, replace, sign, digest } from "../v4/testSupport/credentials.js";
import { Reference, type Value } from "../v4/testSupport/cbor.js";
import { credentialVerifierCharge, verifyDirectCredentials } from "../v4/runtime/credentialVerifier.js";
import { credentialOwner } from "../v4/runtime/credentialSupport.js";
import { authenticatedSessionCharge } from "../v4/runtime/session.js";
import { openV4SQLiteExecutionStore } from "./sqliteExecutionV4.js";
import { captureStorageFormat } from "./sqliteFormat.js";
import { SQLiteWorkerDatabase } from "./sqliteWorkerV4.js";

const cleanups: (() => Promise<void>)[] = [];
function decodeStored(raw: Uint8Array): Value {
  const decoded = new Reference().decode(raw, "", {}, BigInt(raw.length));
  if (!decoded.ok) throw new Error(decoded.error); return decoded.value;
}
afterEach(async () => { vi.restoreAllMocks(); for (const cleanup of cleanups.splice(0)) await cleanup(); });
function fixture(maxRecords = 4) {
  let tick = 0n;
  const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-pool-")), path = join(directory, "once.sqlite");
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({
    profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n
  });
  const environment = new V4EnvironmentRuntime({
    root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32),
    runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, acquireMS: 10000n, cleanupMS: 25,
    clock: {
      profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1010n })
    }, random: bytes => { crypto.getRandomValues(bytes); }
  });
  const r = environment.resources, reserve = (kind: string, charge: ResourceVector) => root.reserve({ owner: credentialOwner(r, kind), accounts: r.accounts, charge });
  const namespace = environment.namespace({
    tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
    maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384
  });
  const material = credentialFixture(r, environment.clock, reserve, "preauthorized_pool", undefined, namespace); material.bootstrap();
  const backing = createSQLitePoolBacking(environment, path, { maxPages: 128, maxRecords, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
  const options: V4SQLitePoolOpenOptions = {
    create: true, identity: { authority: "spend", storeID: fill(5), generation: 1n },
    continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16) }]
  };
  const stores: V4SQLitePoolStore[] = [];
  const open = async (changes: Partial<V4SQLitePoolOpenOptions> = {}) => { const store = await openV4SQLitePoolStore(backing, { ...options, ...changes }); stores.push(store); return store; };
  const original = (cap = 10000n) => {
    const ref = reserve("verify", credentialVerifierCharge(1024n));
    const closure = verifyDirectCredentials(material.config, material.input(), ref); ref.release();
    const admission = reserve("admission", authenticatedSessionCharge(8, 1024n)), facts = closure.poolSpendFacts(admission);
    const observed = new ConnectionFacts(); observed.source("preauthorized_pool");
    const deadline = new TrustedDeadline(environment.clock, cap), owner = {
      connect: fill(8, 16), carrier: fill(9, 16), generation: 1n,
      spendDispatched: () => observed.spendDispatched(), spent: () => observed.spent(), unspent: () => observed.unspent(),
    };
    return { closure, facts, admission, deadline, owner, observed, close: () => { facts.close(); closure.close(); admission.release(); } };
  };
  cleanups.push(async () => {
    for (const store of stores) store.close(); await Promise.all(stores.map(store => store.waitCleanup())); await environment.close();
    rmSync(directory, { recursive: true }); backing.releaseRemoved(); expect(root.snapshot().reservations).toBe(0);
  });
  return { root, environment, material, backing, options, open, original, directory, path, advance: (milliseconds: bigint) => { tick = milliseconds; } };
}

describe("Node v4 durable pool once", () => {
  it("reopens a historical spend whose certificate shortened only the session lifetime", async () => {
    const f = fixture();
    f.material.client = sign("IdentityCertificate", replace(f.material.client, { 9: u(5000) }), 11);
    f.material.artifact = sign("Artifact", replace(f.material.artifact, { 9: bytes(digest("certificate_digest", f.material.client)) }), 12);
    f.material.refreshActivation();
    const store = await f.open(), original = f.original();
    try {
      const facts = original.facts.fields(original.admission);
      expect(facts.activationEnd).toBe(10000n); expect(facts.sessionEnd).toBe(5000n);
      await store.consume(original.facts, original.owner, original.deadline, original.admission, () => undefined);
    } finally { original.close(); }
    store.close(); await store.waitCleanup(); f.advance(60000n);
    const reopened = await f.open({ create: false }); reopened.close(); await reopened.waitCleanup();
    const db = new DatabaseSync(f.path, { readOnly: true });
    try {
      const epoch = db.prepare("SELECT epoch FROM manifest").get()!.epoch as Uint8Array;
      expect(new DataView(epoch.buffer, epoch.byteOffset, 8).getBigUint64(0)).toBe(2n);
      expect(db.prepare("SELECT count(*) AS count FROM spend").get()!.count).toBe(1);
    } finally { db.close(); }
  });
  it("durably writes exact original proof and winner once, retaining files after close", async () => {
    const f = fixture(), store = await f.open(), one = f.original();
    try { await store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined); }
    finally { one.close(); }
    store.close(); await store.waitCleanup(); expect(store.cleanupComplete()).toBe(true); expect(f.backing.retainedDiskBytes()).toBeGreaterThan(0n); expect(existsSync(f.path)).toBe(true);
    const db = new DatabaseSync(f.path, { readOnly: true });
    try {
      const row = db.prepare("SELECT source,state,retained_until,projection FROM spend").get()!;
      expect(row.source).toBe(1); expect(row.state).toBe(1);
      const retained = row.retained_until as Uint8Array; expect(new DataView(retained.buffer, retained.byteOffset, 8).getBigUint64(0)).toBe(604820000n);
      expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(fill(24)))).toBe(false);
    } finally { db.close(); }
    const reopened = await f.open({ create: false }), two = f.original();
    try { await expect(reopened.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined)).rejects.toThrow("spend_conflict"); }
    finally { two.close(); }
  });
  it("treats a lost real COMMIT receipt as spent_unknown and never grants another attempt", async () => {
    const f = fixture(), store = await f.open(), one = f.original(), emit = Worker.prototype.emit;
    let fault = true;
    const patched = vi.spyOn(Worker.prototype, "emit").mockImplementation(function (this: Worker, event: string | symbol, ...args: unknown[]) {
      const message = args[0] as { type?: string; code?: string } | undefined;
      if (fault && event === "message" && message?.type === "result" && message.code === undefined) {
        fault = false; void this.terminate(); return true;
      }
      return emit.call(this, event, ...args);
    });
    try { await expect(store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined)).rejects.toThrowError(expect.objectContaining({ code: "spent_unknown", writeState: "unknown" })); }
    finally { patched.mockRestore(); one.close(); }
    expect(one.observed.snapshot()).toMatchObject({ phase: "unknown", spendState: "unknown", admissionState: "not_started", networkReady: "not_started" });
    await store.waitCleanup(); expect(store.cleanupComplete()).toBe(true);
    const reopened = await f.open({ create: false }), two = f.original();
    try { await expect(reopened.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined)).rejects.toThrow("spend_conflict"); }
    finally { two.close(); }
  });
  it("cancellation before COMMIT leaves no record and releases only the original task", async () => {
    const f = fixture(), store = await f.open(), one = f.original(); let cancel = false; const emit = Worker.prototype.emit;
    vi.spyOn(Worker.prototype, "emit").mockImplementation(function (this: Worker, event: string | symbol, ...args: unknown[]) {
      const message = args[0] as { type?: string; phase?: string } | undefined;
      if (event === "message" && message?.type === "gate" && message.phase === "commit") cancel = true;
      return emit.call(this, event, ...args);
    });
    try { await expect(store.consume(one.facts, one.owner, one.deadline, one.admission, () => { if (cancel) throw new Error("canceled"); })).rejects.toThrow(); }
    finally { vi.restoreAllMocks(); one.close(); }
    expect(one.observed.snapshot()).toMatchObject({ phase: "not_started", spendState: "unspent", admissionState: "not_started" });
    const two = f.original();
    try { await store.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined); }
    finally { two.close(); }
  });
  it("preserves a committed row when the original owner closes after COMMIT", async () => {
    const f = fixture(), store = await f.open(), one = f.original(); let cancel = false; const emit = Worker.prototype.emit;
    vi.spyOn(Worker.prototype, "emit").mockImplementation(function (this: Worker, event: string | symbol, ...args: unknown[]) {
      const message = args[0] as { type?: string; code?: string } | undefined;
      if (event === "message" && message?.type === "result" && message.code === undefined) cancel = true;
      return emit.call(this, event, ...args);
    });
    try { await expect(store.consume(one.facts, one.owner, one.deadline, one.admission, () => { if (cancel) throw new Error("closed original owner"); })).rejects.toThrowError(expect.objectContaining({ writeState: "committed" })); }
    finally { vi.restoreAllMocks(); one.close(); }
    expect(one.observed.snapshot()).toMatchObject({ phase: "spent_not_admitted", spent: true, spendState: "spent", admissionState: "not_started" });
    const two = f.original();
    try { await expect(store.consume(two.facts, two.owner, two.deadline, two.admission, () => undefined)).rejects.toThrow("spend_conflict"); }
    finally { two.close(); }
  });
  it("keeps canceled worker tails charged and admits no queued request", async () => {
    const f = fixture(), store = await f.open(), one = f.original(), stop = new AbortController(), emit = Worker.prototype.emit;
    let reached!: () => void, observedWorker: Worker | undefined, exitArguments: unknown[] | undefined, exitCallbacks: (() => void)[] = [];
    const writeReached = new Promise<void>(resolve => { reached = resolve; });
    vi.spyOn(Worker.prototype, "emit").mockImplementation(function (this: Worker, event: string | symbol, ...args: unknown[]) {
      const message = args[0] as { type?: string; phase?: string } | undefined;
      if (event === "message" && message?.type === "gate" && message.phase === "write") {
        observedWorker = this; reached(); return true;
      }
      if (this === observedWorker && event === "exit") {
        // Node removes its exit listeners after dispatch. Retain the callbacks
        // of this actual event so its observation can be delivered later.
        exitArguments = args; exitCallbacks = this.rawListeners("exit").map(listener => () => listener.call(this, args[0] as number)); return true;
      }
      return emit.call(this, event, ...args);
    });
    const consuming = store.consume(one.facts, { ...one.owner, signal: stop.signal }, one.deadline, one.admission, () => undefined);
    const rejected = expect(consuming).rejects.toMatchObject({ code: "owner_unavailable", writeState: "not_submitted" });
    await writeReached;
    await new Promise<void>(resolve => setImmediate(resolve));
    const second = f.original();
    try { await expect(store.consume(second.facts, second.owner, second.deadline, second.admission, () => undefined)).rejects.toMatchObject({ code: "capacity" }); }
    finally { second.close(); }
    const charged = f.root.snapshot().reservations;
    stop.abort(); await rejected;
    expect(f.root.snapshot().reservations).toBe(charged);
    expect(store.cleanupComplete()).toBe(false);
    await expect(f.open({ create: false })).rejects.toMatchObject({ code: "owner_unavailable" });
    await expect.poll(() => exitArguments !== undefined).toBe(true);
    expect(store.cleanupComplete()).toBe(false);
    vi.restoreAllMocks(); for (const callback of exitCallbacks) callback();
    await store.waitCleanup(); one.close(); expect(store.cleanupComplete()).toBe(true);
    const reopened = await f.open({ create: false }), replacement = f.original();
    try { await reopened.consume(replacement.facts, replacement.owner, replacement.deadline, replacement.admission, () => undefined); }
    finally { replacement.close(); }
  });
  it("observes the original deadline while a worker awaits authorization", async () => {
    const f = fixture(), store = await f.open(), one = f.original(1300n), emit = Worker.prototype.emit;
    vi.spyOn(Worker.prototype, "emit").mockImplementation(function (this: Worker, event: string | symbol, ...args: unknown[]) {
      const message = args[0] as { type?: string; phase?: string } | undefined;
      if (event === "message" && message?.type === "gate" && message.phase === "write") {
        f.advance(300n); return true;
      }
      return emit.call(this, event, ...args);
    });
    try { await expect(store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined)).rejects.toMatchObject({ code: "owner_unavailable", writeState: "not_submitted" }); }
    finally { vi.restoreAllMocks(); await store.waitCleanup(); one.close(); }
    expect(store.cleanupComplete()).toBe(true);
  });
  it("preserves the original continuity error at the write gate", async () => {
    const f = fixture(); let denied = false;
    const store = await f.open({ continuity: { check: () => { if (denied) return true as never; } } }), one = f.original(), emit = Worker.prototype.emit;
    vi.spyOn(Worker.prototype, "emit").mockImplementation(function (this: Worker, event: string | symbol, ...args: unknown[]) {
      const message = args[0] as { type?: string; phase?: string } | undefined;
      if (event === "message" && message?.type === "gate" && message.phase === "write") denied = true;
      return emit.call(this, event, ...args);
    });
    try { await expect(store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined)).rejects.toMatchObject({ code: "history_unknown", writeState: "not_submitted" }); }
    finally { vi.restoreAllMocks(); denied = false; one.close(); }
    const replacement = f.original();
    try { await store.consume(replacement.facts, replacement.owner, replacement.deadline, replacement.admission, () => undefined); }
    finally { replacement.close(); }
  });
  it("does not allow callbacks to stand in for a durable or independent continuity fact", async () => {
    const f = fixture();
    await expect(f.open({ continuity: { check: (() => true) as never } })).rejects.toThrow("history_unknown");
    expect(existsSync(f.path)).toBe(false);
  });
  it("refuses absent, mismatched and corrupted histories without creating a fresh database", async () => {
    const f = fixture(); await expect(f.open({ create: false })).rejects.toThrow("history_unknown"); expect(existsSync(f.path)).toBe(false);
    const store = await f.open(); store.close(); await store.waitCleanup();
    await expect(f.open({ create: false, identity: { ...f.options.identity, storeID: fill(6) } })).rejects.toMatchObject({ code: "storage_format", format: {
      code: "storage_format_incompatible", transactionGroup: "flowersec-v4-node-pool", wireProfile: "flowersec-v4-transport-security",
      requiredRevision: 1, observedRevision: { known: false, value: 0 }, reason: "identity_mismatch", exactConversionAvailable: false,
    } });
    const db = new DatabaseSync(f.path); db.exec("PRAGMA user_version=2"); db.close();
    await expect(f.open({ create: false })).rejects.toMatchObject({ code: "storage_format", format: {
      observedRevision: { known: false, value: 0 }, reason: "revision_conflict", exactConversionAvailable: false,
    } });
  });
  it("reports a verified future header without decoding or rewriting its records", async () => {
    const f = fixture(), store = await f.open(); store.close(); await store.waitCleanup();
    const db = new DatabaseSync(f.path);
    try {
      const current = db.prepare("SELECT sql FROM sqlite_schema WHERE name='manifest'").get()!.sql as string;
      db.exec("BEGIN IMMEDIATE"); db.exec("ALTER TABLE manifest RENAME TO original_manifest");
      db.exec(current.replace("CHECK(revision=1)", "CHECK(revision=2)"));
      db.exec("INSERT INTO manifest SELECT id,format,2,authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,spend_rows FROM original_manifest");
      db.exec("DROP TABLE original_manifest"); db.exec("PRAGMA user_version=2"); db.exec("COMMIT");
    } finally { db.close(); }
    const failure = await f.open({ create: false }).catch(error => error);
    expect(failure).toMatchObject({ code: "storage_format", writeState: "not_submitted", format: {
      code: "storage_format_incompatible", transactionGroup: "flowersec-v4-node-pool", wireProfile: "flowersec-v4-transport-security",
      requiredRevision: 1, observedRevision: { known: true, value: 2 }, reason: "newer_revision", exactConversionAvailable: false,
    } });
    expect(Object.isFrozen(failure.format)).toBe(true); expect(Object.isFrozen(failure.format.observedRevision)).toBe(true);
    expect(JSON.stringify(failure.format)).not.toContain(f.path); expect(JSON.stringify(failure.format)).not.toContain('"spend"');
    const unchanged = new DatabaseSync(f.path, { readOnly: true });
    try { expect(unchanged.prepare("SELECT revision,hex(epoch) AS epoch FROM manifest").get()).toMatchObject({ revision: 2, epoch: "0000000000000001" }); }
    finally { unchanged.close(); }
  });
  it("requires actual Environment ownership and rejects an unconfigured issuer mapping", async () => {
    const f = fixture(), store = await f.open({ bindings: [{ tenant: "tenant", issuer: fill(7, 16) }] }), one = f.original();
    try { await expect(store.consume(one.facts, one.owner, one.deadline, one.admission, () => undefined)).rejects.toThrow("owner_unavailable"); }
    finally { one.close(); }
  });
  it("rejects a damaged current pool schema before changing durable state", async () => {
    const f = fixture(), store = await f.open(); store.close(); await store.waitCleanup();
    const db = new DatabaseSync(f.path); db.exec("CREATE TABLE unexpected(value INTEGER)"); db.close();
    const original = readFileSync(f.path);
    await expect(f.open({ create: false })).rejects.toMatchObject({ code: "storage_format", writeState: "not_submitted", format: {
      requiredRevision: 1, observedRevision: { known: true, value: 1 }, reason: "schema_or_state_invalid",
    } });
    expect(readFileSync(f.path)).toEqual(original);
  });
  it.each(["projection", "lease", "retention", "proof", "tls", "carrier", "roles", "origin", "session"] as const)("refuses inconsistent current pool %s facts before advancing the epoch", async mutation => {
    const f = fixture(), store = await f.open(), original = f.original();
    try { await store.consume(original.facts, original.owner, original.deadline, original.admission, () => undefined); }
    finally { original.close(); }
    store.close(); await store.waitCleanup();
    const db = new DatabaseSync(f.path);
    try {
      if (mutation === "projection") db.exec("UPDATE spend SET projection=x'00'");
      else if (mutation === "lease") {
        const key = new Uint8Array(db.prepare("SELECT lease FROM spend").get()!.lease as Uint8Array); key[key.length - 1] = key[key.length - 1]! ^ 1;
        db.prepare("UPDATE spend SET lease=?").run(key);
      } else if (mutation === "retention") {
        const retention = new Uint8Array(8); new DataView(retention.buffer).setBigUint64(0, 1n);
        db.prepare("UPDATE spend SET retained_until=?").run(retention);
      } else if (mutation === "proof") {
        const bytes = new Uint8Array(db.prepare("SELECT projection FROM spend").get()!.projection as Uint8Array);
        const needle = f.material.input().activation!;
        const position = Buffer.from(bytes).indexOf(Buffer.from(needle)); expect(position).toBeGreaterThanOrEqual(0);
        bytes[position + needle.length - 1] = bytes[position + needle.length - 1]! ^ 1;
        db.prepare("UPDATE spend SET projection=?").run(bytes);
      } else {
        const projection = decodeStored(db.prepare("SELECT projection FROM spend").get()!.projection as Uint8Array);
        let changed: Value;
        if (mutation === "session") changed = replace(projection, { 22: get(projection, 24) });
        else {
          const descriptor = get(projection, 19); if (descriptor.kind !== "bytes") throw new Error("expected leg bytes");
          const leg = decodeStored(descriptor.value);
          const fields: Record<number, Value> = mutation === "tls" ? { 11: map({ 0: u(1), 1: { kind: "bool", value: true } }) } :
            mutation === "carrier" ? { 5: u(2) } : mutation === "roles" ? { 3: u(1) } :
              { 12: map({ 0: array(text("https://example.com"), text("https://example.com")), 1: { kind: "bool", value: false } }) };
          if (leg.kind !== "map") throw new Error("expected leg map");
          const selected = map({ ...Object.fromEntries(leg.value.map(([key, value]) => {
            if (key.kind !== "uint") throw new Error("expected leg key"); return [Number(key.value), value];
          })), ...fields });
          changed = replace(projection, { 19: bytes(encode(selected)) });
        }
        db.prepare("UPDATE spend SET projection=?").run(encode(changed));
      }
    } finally { db.close(); }
    const before = readFileSync(f.path);
    await expect(f.open({ create: false })).rejects.toMatchObject({ code: "storage_format", writeState: "not_submitted", format: {
      observedRevision: { known: true, value: 1 }, requiredRevision: 1, reason: "schema_or_state_invalid",
    } });
    expect(readFileSync(f.path)).toEqual(before);
  });
  it("rejects malformed worker revision projections without throwing from the message listener", () => {
    for (const observedRevision of [null, undefined, 1, "1", { known: true, value: 0 }, { known: false, value: 1 }]) {
      expect(captureStorageFormat({ code: "storage_format_incompatible", transactionGroup: "flowersec-v4-node-pool",
        wireProfile: "flowersec-v4-transport-security", requiredRevision: 1, exactConversionAvailable: false,
        reason: "revision_conflict", observedRevision }, "flowersec-v4-node-pool", 1)).toBeUndefined();
    }
  });
  it("admits the current empty journal and refuses a corrupted durable sequence before fencing", async () => {
    const f = fixture(), store = await f.open(), source = fill(78, 16);
    const journal = (next: bigint) => encode(map({ 0: u(2), 1: text("tenant"), 2: bytes(source), 3: u(next), 4: u(0), 5: u(0),
      7: array(), 8: { kind: "bool", value: false }, 9: array() }));
    await store.comparePoolJournal(source, undefined, journal(1n), () => undefined);
    store.close(); await store.waitCleanup();
    const reopened = await f.open({ create: false }); reopened.close(); await reopened.waitCleanup();
    const db = new DatabaseSync(f.path);
    try { db.prepare("UPDATE material_pool SET snapshot=? WHERE source=?").run(journal(0n), source); }
    finally { db.close(); }
    const before = readFileSync(f.path);
    await expect(f.open({ create: false })).rejects.toMatchObject({ code: "storage_format", writeState: "not_submitted", format: {
      observedRevision: { known: true, value: 1 }, requiredRevision: 1, reason: "schema_or_state_invalid",
    } });
    expect(readFileSync(f.path)).toEqual(before);
  });
  it.each(["historical", "certificate", "generation", "receipt", "material"] as const)("inspects %s TopUp journal facts before fencing", async mutation => {
    const f = fixture(), first = await f.open(); first.close(); await first.waitCleanup();
    const store = await f.open({ create: false }), source = fill(78, 16), operation = fill(79, 16);
    new DataView(operation.buffer).setBigUint64(0, 1n);
    const certificate = mutation === "certificate" ? map({ 0: text("tenant") }) : f.material.client;
    const identity = digest("certificate_digest", certificate), pool = fill(80), material = fill(81, 8), materialDigest = sha256(material);
    const receipt = map({ 0: u(9), 1: u(mutation === "generation" ? 3 : 1), 2: u(9000), 3: bytes(materialDigest), 4: bytes(identity) });
    const request = map({ 0: bytes(operation), 1: text("tenant"), 2: bytes(source), 3: u(1), 4: u(65536), 5: bytes(pool), 8: u(1100), 9: bytes(identity) });
    const pending = map({ 0: bytes(operation), 1: u(1), 2: u(1), 3: u(65536), 4: bytes(pool), 5: u(1), 6: u(1100),
      7: bytes(encode(certificate)), 8: bytes(identity), 9: bytes(sha256(encode(request))), 10: bytes(fill(82)), 11: u(9), 12: { kind: "bool", value: true }, 13: u(8),
      15: array(mutation === "receipt" ? replace(receipt, { 3: bytes(fill(83)) }) : receipt), 16: u(3), 17: u(2) });
    const journal = encode(map({ 0: u(2), 1: text("tenant"), 2: bytes(source), 3: u(2), 4: u(0), 5: u(9), 6: pending,
      7: array(map({ 0: u(9), 1: u(1), 2: u(9000), 3: bytes(mutation === "material" ? fill(84, 8) : material), 4: bytes(materialDigest), 5: bytes(identity) })),
      8: { kind: "bool", value: false }, 9: array(receipt) }));
    await store.comparePoolJournal(source, undefined, journal, () => undefined);
    store.close(); await store.waitCleanup(); f.advance(60000n);
    const before = readFileSync(f.path);
    if (mutation === "historical") {
      const reopened = await f.open({ create: false });
      expect(await reopened.readPoolJournal(source, () => undefined)).toEqual(journal);
      reopened.close(); await reopened.waitCleanup();
      const db = new DatabaseSync(f.path, { readOnly: true });
      try {
        const epoch = db.prepare("SELECT epoch FROM manifest").get()!.epoch as Uint8Array;
        expect(new DataView(epoch.buffer, epoch.byteOffset, 8).getBigUint64(0)).toBe(3n);
      } finally { db.close(); }
    } else {
      await expect(f.open({ create: false })).rejects.toMatchObject({ code: "storage_format", writeState: "not_submitted", format: {
        observedRevision: { known: true, value: 1 }, requiredRevision: 1, reason: "schema_or_state_invalid",
      } });
      expect(readFileSync(f.path)).toEqual(before);
    }
  });
  it("validates the complete execution schema before applying SQLite configuration", async () => {
    const f = fixture();
    const options = { create: true, identity: f.options.identity, continuity: { check: () => undefined }, maxContracts: 2,
      service: { tenant: "tenant", audience: "service", namespace: "test.execution", callerAuthorities: ["3".repeat(64)], maxRecords: 2, maxActive: 1, resultBytes: 1024n } };
    const store = await openV4SQLiteExecutionStore(f.backing, options); store.close(); await store.waitCleanup();
    const db = new DatabaseSync(f.path); db.exec("CREATE TABLE unexpected(value INTEGER)"); db.close();
    const original = readFileSync(f.path), configure = vi.spyOn(SQLiteWorkerDatabase.prototype, "configureCurrent");
    await expect(openV4SQLiteExecutionStore(f.backing, { ...options, create: false })).rejects.toMatchObject({ code: "storage_format", format: {
      requiredRevision: 1, observedRevision: { known: true, value: 1 }, reason: "schema_or_state_invalid",
    } });
    expect(configure).not.toHaveBeenCalled(); expect(readFileSync(f.path)).toEqual(original);
  });
  it("projects execution-store format refusal through its public open boundary", async () => {
    const f = fixture();
    const options = { create: true, identity: f.options.identity, continuity: { check: () => undefined }, maxContracts: 2,
      service: { tenant: "tenant", audience: "service", namespace: "test.execution", callerAuthorities: ["3".repeat(64)], maxRecords: 2, maxActive: 1, resultBytes: 1024n } };
    const store = await openV4SQLiteExecutionStore(f.backing, options);
    store.close(); await store.waitCleanup();
    const db = new DatabaseSync(f.path); db.exec("PRAGMA user_version=2"); db.close();
    await expect(openV4SQLiteExecutionStore(f.backing, { ...options, create: false })).rejects.toMatchObject({ code: "storage_format", writeState: "not_submitted", format: {
      code: "storage_format_incompatible", transactionGroup: "flowersec-v4-node-execution", wireProfile: "flowersec-v4-transport-security", requiredRevision: 1,
      observedRevision: { known: false, value: 0 }, reason: "revision_conflict", exactConversionAvailable: false,
    } });
  });
  it("projects malformed execution facts without exposing database text or advancing the epoch", async () => {
    const f = fixture();
    const options = { create: true, identity: f.options.identity, continuity: { check: () => undefined }, maxContracts: 2,
      service: { tenant: "tenant", audience: "service", namespace: "test.execution", callerAuthorities: ["3".repeat(64)], maxRecords: 2, maxActive: 1, resultBytes: 1024n } };
    const store = await openV4SQLiteExecutionStore(f.backing, options); store.close(); await store.waitCleanup();
    const db = new DatabaseSync(f.path);
    db.prepare("INSERT INTO executions VALUES(?,?,NULL,?,?)").run("x".repeat(67), '{"private-database-fact":', new Uint8Array(8), new Uint8Array(8)); db.close();
    const original = readFileSync(f.path), configure = vi.spyOn(SQLiteWorkerDatabase.prototype, "configureCurrent");
    const failure = await openV4SQLiteExecutionStore(f.backing, { ...options, create: false }).catch(error => error);
    expect(failure).toMatchObject({ message: "storage_format_incompatible", code: "storage_format", writeState: "not_submitted", format: {
      observedRevision: { known: true, value: 1 }, requiredRevision: 1, reason: "schema_or_state_invalid",
    } });
    expect(JSON.stringify(failure)).not.toContain("private-database-fact"); expect(configure).not.toHaveBeenCalled();
    expect(readFileSync(f.path)).toEqual(original);
  });
  it("retains disk allocation when Environment closes its real SQLite connection", async () => {
    const f = fixture(), store = await f.open(); await f.environment.close(); await store.waitCleanup();
    expect(store.cleanupComplete()).toBe(true); expect(f.environment.cleanupStatus().status).toBe("complete");
    expect(f.root.snapshot().charged.values()[2]).toBe(f.backing.retainedDiskBytes()); expect(f.backing.retainedDiskBytes()).toBeGreaterThan(0n);
    expect(() => f.backing.releaseRemoved()).toThrow("history_unknown");
  });
});
