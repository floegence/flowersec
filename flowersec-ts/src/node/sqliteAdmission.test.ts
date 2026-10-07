import { afterEach, describe, expect, it, vi } from "vitest";
import { SQLiteWorkerDatabase } from "./sqliteWorkerV4.js";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { createSQLitePoolBacking } from "./sqliteV4.js";
import { openSQLiteAdmissionStore, sqliteAdmissionCharge, type SQLiteAdmissionStore, type SQLiteAdmissionOpenOptions, type AdmissionResponse } from "./sqliteAdmission.js";
import { V4EnvironmentRuntime } from "../v4/runtime/environment.js";
import { ResourceRoot, ResourceVector } from "../v4/runtime/resources.js";
import { ClockRate } from "../v4/runtime/timeArithmetic.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { credentialFixture, fill, map, text, bytes, u, digest, sign, encode, replace } from "../v4/testSupport/credentials.js";
import { credentialVerifierCharge, verifyDirectCredentials, type ActivationSource } from "../v4/runtime/credentialVerifier.js";
import { credentialOwner } from "../v4/runtime/credentialSupport.js";
import { clearClientPreparation } from "../v4/runtime/clientAdmission.js";
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { vi.restoreAllMocks(); for (const cleanup of cleanups.splice(0)) await cleanup(); });
const profiles = ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"];
function fixture(source: ActivationSource = "live_authority", profile = profiles[0]!, maxRecords = 4) {
  const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-admission-"));
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({
    profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n
  });
  let tick = 0n;
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
  const material = credentialFixture(r, environment.clock, reserve, source, profile, namespace);
  material.bootstrap();
  const limits = { maxPages: 64, maxRecords, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n };
  const stores: SQLiteAdmissionStore[] = [], backings: ReturnType<typeof createSQLitePoolBacking>[] = [], originals: (() => void)[] = [];
  const createStore = (name: string, parentWinnerStore?: SQLiteAdmissionStore, changes: Partial<SQLiteAdmissionOpenOptions> = {}) => {
    const path = join(directory, name + ".sqlite"), backing = createSQLitePoolBacking(environment, path, limits);
    backings.push(backing);
    const options: SQLiteAdmissionOpenOptions = {
      create: true, identity: { authority: name, storeID: fill(5), generation: 1n },
      continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16), audience: "service", serverIdentity: digest("certificate_digest", material.server) }],
      ...(parentWinnerStore === undefined ? {} : { parentWinnerStore }), ...changes
    };
    const open = async (overrides: Partial<SQLiteAdmissionOpenOptions> = {}) => { const store = (await openSQLiteAdmissionStore(backing, { ...options, ...overrides })); stores.push(store); return store; };
    return { path, backing, options, open };
  };
  const original = (hello = fill(60), connectionSeed?: number) => {
    const selected = connectionSeed === undefined ? material : credentialFixture(r, environment.clock, reserve, source, profile, namespace, { connectionSeed });
    const ref = reserve("verify", credentialVerifierCharge(1024n));
    const closure = verifyDirectCredentials(selected.config, selected.input(), ref); ref.release();
    const admission = reserve("admission", sqliteAdmissionCharge(limits).add(new ResourceVector([1024n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])));
    const fields = closure.clientPreparation(admission);
    const context = map({
      0: text("4"), 1: text(profile), 2: u(0), 3: u(0), 4: bytes(fields.artifactDigest), 5: bytes(fields.routeDigest),
      6: bytes(fields.attempt), 7: bytes(fields.nonce), 8: bytes(hello), 9: u(0), 10: u(1), 11: u(0), 12: bytes(new Uint8Array())
    });
    const request = sign("FSB4", map({
      0: bytes(fields.artifactDigest), 1: text(fields.tenant), 2: bytes(fields.issuer), 3: bytes(fields.lease),
      4: bytes(fields.nonce), 5: bytes(fields.candidateID), 6: bytes(fields.routeDigest), 7: bytes(fields.attempt), 8: bytes(fill(61)), 9: bytes(hello),
      10: u(0), 11: u(1), 12: bytes(digest("transport_context_digest", context)), 13: bytes(fields.activation), 14: bytes(fields.clientCertificate)
    }), 14);
    const deadline = new TrustedDeadline(environment.clock, 10000n), cancellation = new AbortController();
    const owner = { acceptor: fill(7, 16), invocation: fill(8, 16), carrier: fill(9, 16), generation: 1n, signal: cancellation.signal };
    const close = () => { clearClientPreparation(fields); closure.close(); admission.release(); }; originals.push(close);
    return { closure, admission, deadline, owner, request, fsb: encode(request), context: encode(context), cancellation, close };
  };
  const admit = async (store: SQLiteAdmissionStore, one: ReturnType<typeof original>, dispatch = (_response: AdmissionResponse): void => undefined, guard = (): void => undefined) => (await store.admit(one.closure, one.fsb, one.context, one.owner, one.deadline, one.admission, guard, dispatch));
  cleanups.push(async () => {
    for (const close of originals) close();
    for (const store of stores) store.close();
    await Promise.all(stores.map(store => store.waitCleanup()));
    await environment.close();
    rmSync(directory, { recursive: true });
    for (const backing of backings) backing.releaseRemoved();
    expect(root.snapshot().reservations).toBe(0);
  });
  return { root, environment, material, createStore, original, admit, advance: (now: bigint) => { tick = now; } };
}
function read(path: string, sql: string) {
  const db = new DatabaseSync(path, { readOnly: true }); try { return db.prepare(sql).get()!; } finally { db.close(); }
}
function commitFault(which: number, after: () => void, before = false) {
  const exec = SQLiteWorkerDatabase.prototype.exec;
  let commits = 0;
  return vi.spyOn(SQLiteWorkerDatabase.prototype, "exec").mockImplementation(async function (this: SQLiteWorkerDatabase, sql: string) {
    const hit = sql === "COMMIT" && ++commits === which;
    if (hit && before) after();
    const result = await exec.call(this, sql);
    if (hit && !before) after();
    return result;
  });
}
describe("Node server admission authority", () => {
  it("derives the server facts from the authenticated request", () => {
    const f = fixture(), one = f.original(), fields = one.closure.serverAdmissionFields(one.fsb, one.context, one.admission);
    try { expect(fields.spendAuthority).toBe("spend"); expect(fields.source).toBe("live_authority"); }
    finally { for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0); }
  });
  for (const source of ["live_authority", "preauthorized_pool"] as const)
    for (const profile of profiles) {
      it(`durably admits ${source} once with ${profile} and rejects replay after reopen`, async () => {
        const f = fixture(source, profile), parent = f.createStore("winner"), winner = (await parent.open()), local = f.createStore("service", winner), store = (await local.open()), one = f.original();
        let response: AdmissionResponse | undefined;
        (await f.admit(store, one, r => { response = { serverEpoch: r.serverEpoch, reservationKey: new Uint8Array(r.reservationKey), admissionBinding: new Uint8Array(r.admissionBinding) }; }));
        expect(response?.serverEpoch).toBe(1n);
        expect(response?.reservationKey.some(n => n !== 0)).toBe(true);
        expect(response?.admissionBinding).toEqual(digest("admission_binding", one.request));
        one.close();
        store.close();
        await store.waitCleanup();
        winner.close();
        await winner.waitCleanup();
        const row = read(local.path, "SELECT * FROM admission");
        expect(row.state).toBe(1);
        expect(row.admission_count).toBe(1);
        for (const value of [one.fsb, one.owner.invocation, response!.reservationKey]) expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(value))).toBe(true);
        expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(fill(24)))).toBe(false);
        expect(read(parent.path, "SELECT count(*) AS n FROM parent_winner").n).toBe(source === "preauthorized_pool" ? 1 : 0);
        const reopened = (await local.open({ create: false, parentWinnerStore: (await parent.open({ create: false })) })), dispatch = vi.fn();
        await expect(f.admit(reopened, f.original(fill(62)), dispatch)).rejects.toThrow("admission_conflict");
        expect(dispatch).not.toHaveBeenCalled();
      });
    }
  it("confirms the exact original admitted CAS after its actual COMMIT receipt is lost", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), dispatch = vi.fn();
    const fault = commitFault(2, () => { throw new Error("lost admitted receipt"); });
    (await f.admit(store, f.original(), dispatch));
    fault.mockRestore();
    expect(dispatch).toHaveBeenCalledTimes(1);
    store.close();
    await store.waitCleanup();
    await expect(f.admit((await local.open({ create: false })), f.original(), dispatch)).rejects.toThrow("admission_conflict");
    expect(dispatch).toHaveBeenCalledTimes(1);
  });
  it("never confirms reserve uncertainty or upgrades it into admitted", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), dispatch = vi.fn();
    const fault = commitFault(1, () => { throw new Error("lost reserve receipt"); });
    await expect(f.admit(store, f.original(), dispatch)).rejects.toThrowError(expect.objectContaining({ code: "admission_unknown", writeState: "unknown" }));
    fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled();
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT state FROM admission").state).toBe(0);
    await expect(f.admit((await local.open({ create: false })), f.original(), dispatch)).rejects.toThrow("admission_conflict");
  });
  it("does not dispatch when the admitted COMMIT never reaches SQLite", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), dispatch = vi.fn();
    const fault = commitFault(2, () => { throw new Error("commit not submitted"); }, true);
    await expect(f.admit(store, f.original(), dispatch)).rejects.toThrow("admission_unknown");
    fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled();
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT state FROM admission").state).toBe(0);
  });
  for (const point of ["before_reserve", "after_reserve", "after_admit", "unknown_admit"] as const) {
    it(`does not dispatch after cancellation at ${point}`, async () => {
      const f = fixture(), local = f.createStore("service"), store = (await local.open()), one = f.original(), dispatch = vi.fn();
      const fault = point === "before_reserve" ? undefined : commitFault(point === "after_reserve" ? 1 : 2, () => {
        one.cancellation.abort(); if (point === "unknown_admit") throw new Error("lost receipt after cancel");
      });
      if (point === "before_reserve") one.cancellation.abort();
      await expect(f.admit(store, one, dispatch)).rejects.toThrow();
      fault?.mockRestore();
      expect(dispatch).not.toHaveBeenCalled();
      store.close();
      await store.waitCleanup();
      const row = read(local.path, "SELECT count(*) AS n, max(state) AS state FROM admission");
      expect(row.n).toBe(point === "before_reserve" ? 0 : 1);
      if (point !== "before_reserve") expect(row.state).toBe(point === "after_reserve" ? 0 : 1);
    });
  }
  it("rejects invalid signatures and changed local transcripts before either authority writes", async () => {
    const f = fixture("preauthorized_pool"), parent = f.createStore("winner"), winner = (await parent.open()), local = f.createStore("service", winner), store = (await local.open());
    for (const mode of ["signature", "transcript"]) {
      const one = f.original(), dispatch = vi.fn();
      if (mode === "signature") one.fsb = encode(sign("FSB4", one.request, 15)); else one.context = f.original(fill(90)).context;
      await expect(f.admit(store, one, dispatch)).rejects.toThrow();
      expect(dispatch).not.toHaveBeenCalled();
    }
    store.close();
    await store.waitCleanup();
    winner.close();
    await winner.waitCleanup();
    expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
    expect(read(parent.path, "SELECT count(*) AS n FROM parent_winner").n).toBe(0);
  });
  it("resolves the parent winner independently of the local admission service", async () => {
    const f = fixture("preauthorized_pool"), wrong = (await f.createStore("spend").open()), local = f.createStore("service", wrong), store = (await local.open());
    await expect(f.admit(store, f.original())).rejects.toThrow("owner_unavailable");
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("refuses another attempt through a second service sharing the parent winner authority", async () => {
    const f = fixture("preauthorized_pool"), winner = (await f.createStore("winner").open()), first = (await f.createStore("first", winner).open());
    (await f.admit(first, f.original()));
    f.material.activation = sign("ActivationAuthorization", replace(f.material.activation, { 9: bytes(fill(93, 16)) }), 13);
    const local = f.createStore("second", winner), second = (await local.open()), dispatch = vi.fn();
    await expect(f.admit(second, f.original(), dispatch)).rejects.toThrow("admission_conflict");
    expect(dispatch).not.toHaveBeenCalled();
    second.close(); await second.waitCleanup();
    expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("does not let a reentrant guard closure publish any row", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), dispatch = vi.fn();
    await expect(f.admit(store, f.original(), dispatch, () => store.close())).rejects.toThrow("closed");
    expect(dispatch).not.toHaveBeenCalled();
    await store.waitCleanup(); expect(store.cleanupComplete()).toBe(true);
    expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("keeps immutable request and owner copies across host hooks", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), one = f.original(), fsb = new Uint8Array(one.fsb), invocation = new Uint8Array(one.owner.invocation);
    (await f.admit(store, one, () => undefined, () => { one.fsb.fill(0); one.context.fill(0); one.owner.invocation.fill(0); }));
    store.close();
    await store.waitCleanup();
    const row = read(local.path, "SELECT projection FROM admission");
    for (const value of [fsb, invocation]) expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(value))).toBe(true);
  });
  it("rejects a lost receipt when the original deadline expires after commit", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), dispatch = vi.fn();
    const fault = commitFault(2, () => { f.advance(10000n); throw new Error("late commit receipt"); });
    await expect(f.admit(store, f.original(), dispatch)).rejects.toThrow("admission_unknown");
    fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled();
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT state FROM admission").state).toBe(1);
  });
  it("refuses a fresh valid lease when durable capacity is exhausted", async () => {
    const f = fixture("live_authority", profiles[0]!, 1), local = f.createStore("service"), store = (await local.open());
    (await f.admit(store, f.original()));
    const dispatch = vi.fn();
    await expect(f.admit(store, f.original(fill(80), 80), dispatch)).rejects.toThrow("capacity");
    expect(dispatch).not.toHaveBeenCalled();
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(1);
  });
  it("rechecks cancellation after the independent continuity callback", async () => {
    const f = fixture(), one = f.original();
    let armed = false;
    const local = f.createStore("service", undefined, { continuity: { check: () => { if (armed) one.cancellation.abort(); } } }), store = (await local.open());
    armed = true;
    const dispatch = vi.fn();
    await expect(f.admit(store, one, dispatch)).rejects.toThrow();
    expect(dispatch).not.toHaveBeenCalled();
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("does not confirm another projection after a lost real admitted COMMIT receipt", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), dispatch = vi.fn(), exec = SQLiteWorkerDatabase.prototype.exec;
    let commits = 0;
    const fault = vi.spyOn(SQLiteWorkerDatabase.prototype, "exec").mockImplementation(async function (this: SQLiteWorkerDatabase, sql: string) {
      await exec.call(this, sql);
      if (sql === "COMMIT" && ++commits === 2) { await this.run("UPDATE admission SET projection=?", fill(94)); throw new Error("changed committed projection"); }
    });
    await expect(f.admit(store, f.original(), dispatch)).rejects.toThrow("admission_unknown");
    fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled();
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT state FROM admission").state).toBe(1);
  });
  it("refuses a fence change before reserve publication", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open()), dispatch = vi.fn(), exec = SQLiteWorkerDatabase.prototype.exec;
    let changed = false;
    const fault = vi.spyOn(SQLiteWorkerDatabase.prototype, "exec").mockImplementation(async function (this: SQLiteWorkerDatabase, sql: string) {
      await exec.call(this, sql);
      if (sql === "BEGIN IMMEDIATE" && !changed) { changed = true; await this.run("UPDATE manifest SET epoch=?", Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 2)); }
    });
    await expect(f.admit(store, f.original(), dispatch)).rejects.toThrow("fenced");
    fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled();
    store.close();
    await store.waitCleanup();
    expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("requires independent continuity on reopen and refuses a changed exact format", async () => {
    const f = fixture(), local = f.createStore("service"), store = (await local.open());
    store.close();
    await store.waitCleanup();
    await expect(local.open({ create: false, continuity: { check: () => { throw new Error("history lost"); } } })).rejects.toThrow();
    const db = new DatabaseSync(local.path);
    db.exec("PRAGMA user_version=2");
    db.close();
    await expect(local.open({ create: false })).rejects.toMatchObject({ code: "storage_format", format: {
      code: "storage_format_incompatible", transactionGroup: "flowersec-node-admission", requiredRevision: 3,
      observedRevision: { known: false, value: 0 }, reason: "revision_conflict", exactConversionAvailable: false,
    } });
  });
  it("refuses a verified older admission header without running an upgrade", async () => {
    const f = fixture(), local = f.createStore("service"), store = await local.open(); store.close(); await store.waitCleanup();
    const db = new DatabaseSync(local.path);
    try {
      const current = db.prepare("SELECT sql FROM sqlite_schema WHERE name='manifest'").get()!.sql as string;
      db.exec("BEGIN IMMEDIATE"); db.exec("ALTER TABLE manifest RENAME TO original_manifest");
      db.exec(current.replace("CHECK(revision=3)", "CHECK(revision=2)"));
      db.exec("INSERT INTO manifest SELECT id,format,2,authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,admission_rows,winner_rows,relay_rows,issuance_rows FROM original_manifest");
      db.exec("DROP TABLE original_manifest"); db.exec("DROP TABLE live_authority"); db.exec("PRAGMA user_version=2"); db.exec("COMMIT");
    } finally { db.close(); }
    await expect(local.open({ create: false })).rejects.toMatchObject({ code: "storage_format", writeState: "not_submitted", format: {
      code: "storage_format_incompatible", transactionGroup: "flowersec-node-admission", wireProfile: "flowersec-v4-transport-security",
      requiredRevision: 3, observedRevision: { known: true, value: 2 }, reason: "older_revision", exactConversionAvailable: false,
    } });
    expect(read(local.path, "SELECT revision,hex(epoch) AS epoch FROM manifest")).toMatchObject({ revision: 2, epoch: "0000000000000001" });
    expect(read(local.path, "SELECT count(*) AS n FROM sqlite_schema WHERE name='live_authority'").n).toBe(0);
  });
  it("validates the complete current admission schema before applying SQLite configuration", async () => {
    const f = fixture(), local = f.createStore("service"), store = await local.open(); store.close(); await store.waitCleanup();
    const db = new DatabaseSync(local.path); db.exec("CREATE TABLE unexpected(value INTEGER)"); db.close();
    const configure = vi.spyOn(SQLiteWorkerDatabase.prototype, "configureCurrent");
    await expect(local.open({ create: false })).rejects.toMatchObject({ code: "storage_format", format: {
      requiredRevision: 3, observedRevision: { known: true, value: 3 }, reason: "schema_or_state_invalid",
    } });
    expect(configure).not.toHaveBeenCalled();
    expect(read(local.path, "SELECT hex(epoch) AS epoch FROM manifest").epoch).toBe("0000000000000001");
  });
  it("keeps the inspected connection locked against another writer through admission", async () => {
    const f = fixture(), local = f.createStore("service"), store = await local.open(); store.close(); await store.waitCleanup();
    const admit = SQLiteWorkerDatabase.prototype.admitWrites;
    const transition = vi.spyOn(SQLiteWorkerDatabase.prototype, "admitWrites").mockImplementation(async function (this: SQLiteWorkerDatabase) {
      const competing = new DatabaseSync(local.path);
      try { expect(() => competing.exec("CREATE TABLE unexpected(value INTEGER)")).toThrow("database is locked"); }
      finally { competing.close(); }
      await Reflect.apply(admit, this, []);
    });
    const configure = vi.spyOn(SQLiteWorkerDatabase.prototype, "configureCurrent");
    const reopened = await local.open({ create: false });
    expect(transition).toHaveBeenCalledOnce();
    expect(configure).toHaveBeenCalledOnce();
    reopened.close(); await reopened.waitCleanup();
    expect(read(local.path, "SELECT hex(epoch) AS epoch FROM manifest").epoch).toBe("0000000000000002");
    expect(read(local.path, "SELECT count(*) AS n FROM sqlite_schema WHERE name='unexpected'").n).toBe(0);
  });
});
