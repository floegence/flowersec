import { afterEach, describe, expect, it, vi } from "vitest";
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
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  let tick = 0n;
  const environment = new V4EnvironmentRuntime({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32),
    runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, acquireMS: 10000n, cleanupMS: 25,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1010n }) }, random: bytes => { crypto.getRandomValues(bytes); } });
  const r = environment.resources, reserve = (kind: string, charge: ResourceVector) => root.reserve({ owner: credentialOwner(r, kind), accounts: r.accounts, charge });
  const namespace = environment.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
    maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
  const material = credentialFixture(r, environment.clock, reserve, source, profile, namespace); material.bootstrap();
  const limits = { maxPages: 64, maxRecords, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n };
  const stores: SQLiteAdmissionStore[] = [], backings: ReturnType<typeof createSQLitePoolBacking>[] = [], originals: (() => void)[] = [];
  const createStore = (name: string, parentWinnerStore?: SQLiteAdmissionStore, changes: Partial<SQLiteAdmissionOpenOptions> = {}) => {
    const path = join(directory, name + ".sqlite"), backing = createSQLitePoolBacking(environment, path, limits); backings.push(backing);
    const options: SQLiteAdmissionOpenOptions = { create: true, identity: { authority: name, storeID: fill(5), generation: 1n },
      continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16), audience: "service", serverIdentity: digest("certificate_digest", material.server) }],
      ...(parentWinnerStore === undefined ? {} : { parentWinnerStore }), ...changes };
    const open = (overrides: Partial<SQLiteAdmissionOpenOptions> = {}) => { const store = openSQLiteAdmissionStore(backing, { ...options, ...overrides }); stores.push(store); return store; };
    return { path, backing, options, open };
  };
  const original = (hello = fill(60), connectionSeed?: number) => {
    const selected = connectionSeed === undefined ? material : credentialFixture(r, environment.clock, reserve, source, profile, namespace, { connectionSeed });
    const ref = reserve("verify", credentialVerifierCharge(1024n));
    const closure = verifyDirectCredentials(selected.config, selected.input(), ref); ref.release();
    const admission = reserve("admission", sqliteAdmissionCharge(limits).add(new ResourceVector([1024n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])));
    const fields = closure.clientPreparation(admission);
    const context = map({ 0: text("4"), 1: text(profile), 2: u(0), 3: u(0), 4: bytes(fields.artifactDigest), 5: bytes(fields.routeDigest),
      6: bytes(fields.attempt), 7: bytes(fields.nonce), 8: bytes(hello), 9: u(0), 10: u(1), 11: u(0), 12: bytes(new Uint8Array()) });
    const request = sign("FSB4", map({ 0: bytes(fields.artifactDigest), 1: text(fields.tenant), 2: bytes(fields.issuer), 3: bytes(fields.lease),
      4: bytes(fields.nonce), 5: bytes(fields.candidateID), 6: bytes(fields.routeDigest), 7: bytes(fields.attempt), 8: bytes(fill(61)), 9: bytes(hello),
      10: u(0), 11: u(1), 12: bytes(digest("transport_context_digest", context)), 13: bytes(fields.activation), 14: bytes(fields.clientCertificate) }), 14);
    const deadline = new TrustedDeadline(environment.clock, 10000n), cancellation = new AbortController();
    const owner = { acceptor: fill(7, 16), invocation: fill(8, 16), carrier: fill(9, 16), generation: 1n, signal: cancellation.signal };
    const close = () => { clearClientPreparation(fields); closure.close(); admission.release(); }; originals.push(close);
    return { closure, admission, deadline, owner, request, fsb: encode(request), context: encode(context), cancellation, close };
  };
  const admit = (store: SQLiteAdmissionStore, one: ReturnType<typeof original>, dispatch = (_response: AdmissionResponse): void => undefined, guard = (): void => undefined) =>
    store.admit(one.closure, one.fsb, one.context, one.owner, one.deadline, one.admission, guard, dispatch);
  cleanups.push(async () => {
    for (const close of originals) close(); for (const store of stores) store.close(); await environment.close();
    rmSync(directory, { recursive: true }); for (const backing of backings) backing.releaseRemoved(); expect(root.snapshot().reservations).toBe(0);
  });
  return { root, environment, material, createStore, original, admit, advance: (now: bigint) => { tick = now; } };
}

function read(path: string, sql: string) {
  const db = new DatabaseSync(path, { readOnly: true }); try { return db.prepare(sql).get()!; } finally { db.close(); }
}
function commitFault(which: number, after: () => void, before = false) {
  const exec = DatabaseSync.prototype.exec; let commits = 0;
  return vi.spyOn(DatabaseSync.prototype, "exec").mockImplementation(function(this: DatabaseSync, sql: string) {
    const hit = sql === "COMMIT" && ++commits === which;
    if (hit && before) after(); const result = exec.call(this, sql); if (hit && !before) after(); return result;
  });
}
describe("Node server admission authority", () => {
  it("derives the server facts from the authenticated request", () => {
    const f = fixture(), one = f.original(), fields = one.closure.serverAdmissionFields(one.fsb, one.context, one.admission);
    try { expect(fields.spendAuthority).toBe("spend"); expect(fields.source).toBe("live_authority"); }
    finally { for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0); }
  });
  for (const source of ["live_authority", "preauthorized_pool"] as const) for (const profile of profiles) {
    it(`durably admits ${source} once with ${profile} and rejects replay after reopen`, () => {
      const f = fixture(source, profile), parent = f.createStore("winner"), winner = parent.open(), local = f.createStore("service", winner), store = local.open(), one = f.original();
      let response: AdmissionResponse | undefined;
      f.admit(store, one, r => { response = { serverEpoch: r.serverEpoch, reservationKey: new Uint8Array(r.reservationKey), admissionBinding: new Uint8Array(r.admissionBinding) }; });
      expect(response?.serverEpoch).toBe(1n); expect(response?.reservationKey.some(n => n !== 0)).toBe(true);
      expect(response?.admissionBinding).toEqual(digest("admission_binding", one.request));
      one.close(); store.close(); winner.close(); const row = read(local.path, "SELECT * FROM admission");
      expect(row.state).toBe(1); expect(row.admission_count).toBe(1);
      for (const value of [one.fsb, one.owner.invocation, response!.reservationKey]) expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(value))).toBe(true);
      expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(fill(24)))).toBe(false);
      expect(read(parent.path, "SELECT count(*) AS n FROM parent_winner").n).toBe(source === "preauthorized_pool" ? 1 : 0);
      const reopened = local.open({ create: false, parentWinnerStore: parent.open({ create: false }) }), dispatch = vi.fn();
      expect(() => f.admit(reopened, f.original(fill(62)), dispatch)).toThrow("admission_conflict"); expect(dispatch).not.toHaveBeenCalled();
    });
  }
  it("confirms the exact original admitted CAS after its actual COMMIT receipt is lost", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), dispatch = vi.fn();
    const fault = commitFault(2, () => { throw new Error("lost admitted receipt"); });
    f.admit(store, f.original(), dispatch); fault.mockRestore(); expect(dispatch).toHaveBeenCalledTimes(1);
    store.close(); expect(() => f.admit(local.open({ create: false }), f.original(), dispatch)).toThrow("admission_conflict"); expect(dispatch).toHaveBeenCalledTimes(1);
  });
  it("never confirms reserve uncertainty or upgrades it into admitted", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), dispatch = vi.fn();
    const fault = commitFault(1, () => { throw new Error("lost reserve receipt"); });
    expect(() => f.admit(store, f.original(), dispatch)).toThrowError(expect.objectContaining({ code: "admission_unknown", writeState: "unknown" })); fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled(); store.close(); expect(read(local.path, "SELECT state FROM admission").state).toBe(0);
    expect(() => f.admit(local.open({ create: false }), f.original(), dispatch)).toThrow("admission_conflict");
  });
  it("does not dispatch when the admitted COMMIT never reaches SQLite", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), dispatch = vi.fn();
    const fault = commitFault(2, () => { throw new Error("commit not submitted"); }, true);
    expect(() => f.admit(store, f.original(), dispatch)).toThrow("admission_unknown"); fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled(); store.close(); expect(read(local.path, "SELECT state FROM admission").state).toBe(0);
  });
  for (const point of ["before_reserve", "after_reserve", "after_admit", "unknown_admit"] as const) {
    it(`does not dispatch after cancellation at ${point}`, () => {
      const f = fixture(), local = f.createStore("service"), store = local.open(), one = f.original(), dispatch = vi.fn();
      const fault = point === "before_reserve" ? undefined : commitFault(point === "after_reserve" ? 1 : 2, () => {
        one.cancellation.abort(); if (point === "unknown_admit") throw new Error("lost receipt after cancel");
      });
      if (point === "before_reserve") one.cancellation.abort();
      expect(() => f.admit(store, one, dispatch)).toThrow(); fault?.mockRestore(); expect(dispatch).not.toHaveBeenCalled(); store.close();
      const row = read(local.path, "SELECT count(*) AS n, max(state) AS state FROM admission");
      expect(row.n).toBe(point === "before_reserve" ? 0 : 1);
      if (point !== "before_reserve") expect(row.state).toBe(point === "after_reserve" ? 0 : 1);
    });
  }
  it("rejects invalid signatures and changed local transcripts before either authority writes", () => {
    const f = fixture("preauthorized_pool"), parent = f.createStore("winner"), winner = parent.open(), local = f.createStore("service", winner), store = local.open();
    for (const mode of ["signature", "transcript"]) {
      const one = f.original(), dispatch = vi.fn();
      if (mode === "signature") one.fsb = encode(sign("FSB4", one.request, 15)); else one.context = f.original(fill(90)).context;
      expect(() => f.admit(store, one, dispatch)).toThrow(); expect(dispatch).not.toHaveBeenCalled();
    }
    store.close(); winner.close(); expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0); expect(read(parent.path, "SELECT count(*) AS n FROM parent_winner").n).toBe(0);
  });
  it("resolves the parent winner independently of the local admission service", () => {
    const f = fixture("preauthorized_pool"), wrong = f.createStore("spend").open(), local = f.createStore("service", wrong), store = local.open();
    expect(() => f.admit(store, f.original())).toThrow("owner_unavailable"); store.close(); expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("refuses another attempt through a second service sharing the parent winner authority", () => {
    const f = fixture("preauthorized_pool"), winner = f.createStore("winner").open(), first = f.createStore("first", winner).open(); f.admit(first, f.original());
    f.material.activation = sign("ActivationAuthorization", replace(f.material.activation, { 9: bytes(fill(93, 16)) }), 13);
    const local = f.createStore("second", winner), second = local.open(), dispatch = vi.fn();
    expect(() => f.admit(second, f.original(), dispatch)).toThrow("admission_conflict"); expect(dispatch).not.toHaveBeenCalled(); second.close(); expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("does not let a reentrant guard closure publish any row", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), dispatch = vi.fn();
    expect(() => f.admit(store, f.original(), dispatch, () => store.close())).toThrow("closed"); expect(dispatch).not.toHaveBeenCalled();
    expect(store.cleanupComplete()).toBe(true); expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("keeps immutable request and owner copies across host hooks", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), one = f.original(), fsb = new Uint8Array(one.fsb), invocation = new Uint8Array(one.owner.invocation);
    f.admit(store, one, () => undefined, () => { one.fsb.fill(0); one.context.fill(0); one.owner.invocation.fill(0); });
    store.close(); const row = read(local.path, "SELECT projection FROM admission");
    for (const value of [fsb, invocation]) expect(Buffer.from(row.projection as Uint8Array).includes(Buffer.from(value))).toBe(true);
  });
  it("rejects a lost receipt when the original deadline expires after commit", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), dispatch = vi.fn();
    const fault = commitFault(2, () => { f.advance(10000n); throw new Error("late commit receipt"); });
    expect(() => f.admit(store, f.original(), dispatch)).toThrow("admission_unknown"); fault.mockRestore();
    expect(dispatch).not.toHaveBeenCalled(); store.close(); expect(read(local.path, "SELECT state FROM admission").state).toBe(1);
  });
  it("refuses a fresh valid lease when durable capacity is exhausted", () => {
    const f = fixture("live_authority", profiles[0]!, 1), local = f.createStore("service"), store = local.open();
    f.admit(store, f.original());
    const dispatch = vi.fn(); expect(() => f.admit(store, f.original(fill(80), 80), dispatch)).toThrow("capacity");
    expect(dispatch).not.toHaveBeenCalled(); store.close(); expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(1);
  });
  it("rechecks cancellation after the independent continuity callback", () => {
    const f = fixture(), one = f.original(); let armed = false;
    const local = f.createStore("service", undefined, { continuity: { check: () => { if (armed) one.cancellation.abort(); } } }), store = local.open(); armed = true;
    const dispatch = vi.fn(); expect(() => f.admit(store, one, dispatch)).toThrow(); expect(dispatch).not.toHaveBeenCalled();
    store.close(); expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("does not confirm another projection after a lost real admitted COMMIT receipt", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), dispatch = vi.fn(), exec = DatabaseSync.prototype.exec; let commits = 0;
    const fault = vi.spyOn(DatabaseSync.prototype, "exec").mockImplementation(function(this: DatabaseSync, sql) {
      exec.call(this, sql);
      if (sql === "COMMIT" && ++commits === 2) { this.prepare("UPDATE admission SET projection=?").run(fill(94)); throw new Error("changed committed projection"); }
    });
    expect(() => f.admit(store, f.original(), dispatch)).toThrow("admission_unknown"); fault.mockRestore(); expect(dispatch).not.toHaveBeenCalled();
    store.close(); expect(read(local.path, "SELECT state FROM admission").state).toBe(1);
  });
  it("refuses a fence change before reserve publication", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(), dispatch = vi.fn(), exec = DatabaseSync.prototype.exec; let changed = false;
    const fault = vi.spyOn(DatabaseSync.prototype, "exec").mockImplementation(function(this: DatabaseSync, sql) {
      exec.call(this, sql);
      if (sql === "BEGIN IMMEDIATE" && !changed) { changed = true; this.prepare("UPDATE manifest SET epoch=?").run(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 2)); }
    });
    expect(() => f.admit(store, f.original(), dispatch)).toThrow("fenced"); fault.mockRestore(); expect(dispatch).not.toHaveBeenCalled();
    store.close(); expect(read(local.path, "SELECT count(*) AS n FROM admission").n).toBe(0);
  });
  it("requires independent continuity on reopen and refuses a changed exact format", () => {
    const f = fixture(), local = f.createStore("service"), store = local.open(); store.close();
    expect(() => local.open({ create: false, continuity: { check: () => { throw new Error("history lost"); } } })).toThrow();
    const db = new DatabaseSync(local.path); db.exec("PRAGMA user_version=2"); db.close(); expect(() => local.open({ create: false })).toThrow("storage_format");
  });
});
