import { afterEach, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { createOriginalPoolSource, type V4PoolSourceConfiguration, type V4PreauthorizedPoolSource, type V4TopUpExchangeResult } from "./poolSource.js";
import { V4EnvironmentRuntime } from "./runtime/environment.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { credentialOwner } from "./runtime/credentialSupport.js";
import { registerPoolJournalStore, type PoolJournalStore } from "./runtime/poolJournal.js";
import { Reference, type Value } from "./testSupport/cbor.js";
import { array, bytes, credentialFixture, encode, fill, get, map, replace, sign, text, u } from "./testSupport/credentials.js";

const syntax = new Reference();
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
function decode(raw: Uint8Array): Value {
  const result = syntax.decode(raw, "", {}, BigInt(raw.length));
  if (!result.ok) throw new Error(result.error);
  return result.value;
}
function uint(value: Value): bigint { if (value.kind !== "uint") throw new Error("expected uint"); return value.value; }
function payload(value: Value): Uint8Array { if (value.kind !== "bytes") throw new Error("expected bytes"); return value.value; }
function arrayItem(value: Value, index = 0): Value {
  if (value.kind !== "array" || value.value[index] === undefined) throw new Error("expected array item");
  return value.value[index]!;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
function fixture() {
  let tick = 0n, generation = 1n, stored: Uint8Array | undefined;
  let attemptCommitFailure: "rolled_back" | "unknown" | undefined;
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 32, reservations: 512, references: 1024,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const environment = new V4EnvironmentRuntime({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32),
    runtimeBytes: 1024n, namespaces: 1, sources: 8, acquisitions: 4, materials: 16, sessions: 1, acquireMS: 10000n, cleanupMS: 25,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1010n }) },
    random: value => { crypto.getRandomValues(value); } });
  const resources = environment.resources;
  const reserve = (kind: string, charge: ResourceVector) => root.reserve({ owner: credentialOwner(resources, kind), accounts: resources.accounts, charge });
  const namespace = environment.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
    maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
  const credentials = credentialFixture(resources, environment.clock, reserve, "preauthorized_pool", undefined, namespace);
  credentials.bootstrap();
  const { resources: unusedResources, clock: unusedClock, namespaces: unusedNamespaces, ...basePolicy } = credentials.config;
  void unusedResources; void unusedClock; void unusedNamespaces;
  const policy = { ...basePolicy, authorities: ["authority"] };
  const original = reserve("test_pool_journal", new ResourceVector([1048576n, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
  // This in-memory journal is registered only inside the test. Production
  // registration belongs exclusively to the actual SQLite/IndexedDB owners.
  const store: PoolJournalStore = {
    async readPoolJournal(_key, check) { check(); return stored === undefined ? undefined : new Uint8Array(stored); },
    async comparePoolJournal(_key, expected, replacement, check) {
      check();
      if (expected === undefined ? stored !== undefined : stored === undefined || !Buffer.from(expected).equals(Buffer.from(stored))) throw new Error("operation_conflict");
      if (attemptCommitFailure !== undefined && stored !== undefined) {
        const next = decode(replacement), before = decode(stored);
        if (next.kind === "map" && before.kind === "map" && next.value.some(([key]) => uint(key) === 6n) && before.value.some(([key]) => uint(key) === 6n) &&
            uint(get(get(next, 6), 17)) > uint(get(get(before, 6), 17))) {
          const writeState = attemptCommitFailure; attemptCommitFailure = undefined;
          if (writeState === "unknown") stored = new Uint8Array(replacement);
          throw Object.assign(new Error("attempt fence commit failed"), { writeState });
        }
      }
      stored = new Uint8Array(replacement); check();
    },
  };
  registerPoolJournalStore(store, { environment, reference: () => original, generation: () => generation, check: () => original.check() });
  const calls: { method: 41006 | 41007; request: Value }[] = [];
  let exchange: (method: 41006 | 41007, request: Value) => Promise<V4TopUpExchangeResult> = async () => { throw new Error("response lost"); };
  const fence = (intent: Parameters<V4PoolSourceConfiguration["ownerFenceProof"]>[0]): Uint8Array => encode(sign("OwnerFenceProof", map({
    0: text(intent.tenant), 1: bytes(intent.sourceIncarnation), 2: bytes(intent.operationID), 3: bytes(intent.requestDigest),
    4: u(intent.currentGeneration), 5: u(environment.clock.sample().requireInterval().lowerMS), 6: u(intent.deadlineMS), 7: bytes(fill(76, 16)),
  }), 77));
  const configuration: V4PoolSourceConfiguration = {
    sourceIncarnation: fill(71, 16), poolDigest: fill(72), identityCertificate: encode(credentials.client), fenceAuthorityKeyID: fill(76, 16),
    fenceAuthorityPublicKey: ed25519.getPublicKey(fill(77)), operationLifetimeMS: 100n, callTimeoutMS: 1000n,
    providerRuntimeBytes: 1024n, create: true,
    ownerFenceProof: async intent => fence(intent),
    decodeMaterial: raw => {
      const record = decode(raw), input = credentials.input();
      return { ...input, artifact: payload(get(record, 0)), clientCertificate: payload(get(record, 1)), serverCertificate: payload(get(record, 2)), activation: payload(get(record, 3)) };
    },
    control: { async exchange(method, raw) {
      const request = decode(raw), persisted = get(decode(stored!), 6);
      expect(uint(get(persisted, 17))).toBe(uint(get(request, method === 41006 ? 6 : 8)));
      expect(get(persisted, 0)).toEqual(get(request, 0));
      calls.push({ method, request }); return await exchange(method, request);
    } },
  };
  const sources: V4PreauthorizedPoolSource[] = [];
  const open = async (changes: Partial<V4PoolSourceConfiguration> = {}) => {
    const source = await createOriginalPoolSource(environment, policy, store, { ...configuration, ...changes }, {
      signingPublicKey: ed25519.getPublicKey(fill(14)), noisePublicKey: credentials.publicNoise(0), check: () => undefined,
    });
    sources.push(source); return source;
  };
  const response = (request: Value, firstSequence = 1n, count = 1, entryGenerations?: readonly bigint[]): Uint8Array => {
    const input = credentials.input();
    const raw = encode(map({ 0: bytes(input.artifact), 1: bytes(input.clientCertificate), 2: bytes(input.serverCertificate), 3: bytes(input.activation) }));
    const unsigned = map({ 0: get(request, 0), 1: text("tenant"), 2: get(request, 2), 3: get(request, 6),
      4: array(...Array.from({ length: count }, (_, index) => map({ 0: u(firstSequence + BigInt(index)), 1: entryGenerations === undefined ? get(request, 6) : u(entryGenerations[index]!), 2: u(9000),
        3: bytes(raw), 4: bytes(sha256(raw)), 5: get(request, 9) }))),
      5: u(firstSequence + BigInt(count) - 1n), 6: { kind: "bool", value: false }, 8: { kind: "bool", value: true } });
    if (unsigned.kind !== "map") throw new Error("expected response map");
    return encode({ kind: "map", value: [...unsigned.value, [u(9), bytes(sha256(encode(unsigned)))]] });
  };
  cleanups.push(async () => {
    for (const source of sources) source.close();
    await Promise.all(sources.map(source => source.waitCleanup()));
    stored?.fill(0); original.release(); await environment.close();
  });
  return { open, calls, response, fence, configuration, advance: (milliseconds: bigint) => { tick += milliseconds; },
    advanceGeneration: () => { generation++; },
    failAttemptCommit: (mode: "rolled_back" | "unknown") => { attemptCommitFailure = mode; },
    exchange: (handler: typeof exchange) => { exchange = handler; },
    journal: () => decode(stored!), corrupt: (change: (value: Value) => Value) => { stored = encode(change(decode(stored!))); } };
}

describe("durable preauthorized TopUp recovery", () => {
  it("keeps TopUp handles opaque while retaining original status and cleanup ownership", async () => {
    const f = fixture(), source = await f.open();
    const result = await source.topUp({ desiredCount: 1 }), handle = result.handle!;
    expect(handle).toBeDefined();
    expect(handle).not.toHaveProperty("id");
    expect(handle).not.toHaveProperty("operationID");
    expect(handle).not.toHaveProperty("operation_id");
    expect(Reflect.ownKeys(handle)).toEqual([]);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(handle)).sort()).toEqual([
      "cleanupStatus", "constructor", "status", "toJSON", "toString", "waitCleanup",
    ]);
    expect(JSON.stringify(handle)).toBe("{}");
    expect(String(handle)).toBe("Flowersec.TopUpHandle");
    expect((await handle.status()).handle).toBe(handle);
    expect((await handle.waitCleanup()).status).toBe("complete");
  });

  it("replays the captured G1 response under a fresh G2 proof after the original append deadline", async () => {
    const f = fixture(), source = await f.open();
    let committed: Uint8Array = new Uint8Array();
    f.exchange(async (method, request) => {
      if (method !== 41006) throw new Error("unexpected ACK before installation");
      committed = f.response(request); throw new Error("committed response lost");
    });
    const first = await source.topUp({ desiredCount: 1 });
    expect(first.state).toBe("pending"); expect(first.callError).toBe("source_unavailable");
    expect(uint(get(decode(committed), 3))).toBe(1n);
    const initial = f.calls[0]!.request;
    f.advance(200n); f.advanceGeneration();
    f.exchange(async method => method === 41007 ? { kind: "acknowledged" } : { kind: "replay", response: committed });
    const recovered = await source.topUp({ desiredCount: 4 });
    expect(recovered.state).toBe("acked"); expect(recovered.callError).toBeUndefined(); expect(recovered.handle).toBe(first.handle);
    expect(recovered.adoptedOptions?.desiredCount).toBe(1);
    const replay = f.calls[1]!.request;
    for (const field of [0, 1, 2, 3, 4, 5, 8, 9]) expect(get(replay, field)).toEqual(get(initial, field));
    expect(uint(get(replay, 6))).toBe(2n); expect(get(replay, 7)).not.toEqual(get(initial, 7));
    const installed = get(f.journal(), 6);
    expect(uint(get(installed, 5))).toBe(1n); expect(uint(get(installed, 17))).toBe(2n);
    expect(uint(get(arrayItem(get(installed, 15)), 1))).toBe(1n);
    expect(get(installed, 10)).toEqual(get(decode(committed), 9));
    expect(uint(get(f.calls[2]!.request, 8))).toBe(2n);
    expect(f.calls.map(call => call.method)).toEqual([41006, 41006, 41007]);
  });

  it("first appends a persisted G1 intent at G2 after proof failure prevented any send", async () => {
    const f = fixture(), source = await f.open({ ownerFenceProof: async () => { throw new Error("owner proof unavailable"); } });
    const first = await source.topUp({ desiredCount: 1 });
    expect(first.state).toBe("pending"); expect(first.callError).toBe("source_unavailable"); expect(f.calls).toHaveLength(0);
    const original = get(f.journal(), 6);
    expect(uint(get(original, 5))).toBe(1n);
    source.close(); await source.waitCleanup(); f.advanceGeneration();
    const restarted = await f.open({ create: false });
    f.exchange(async (method, request) => {
      if (method === 41007) throw new Error("ACK receipt lost");
      expect(uint(get(request, 6))).toBe(2n);
      return { kind: "success", response: f.response(request) };
    });
    const result = await restarted.topUp({ desiredCount: 4 });
    expect(result.state).toBe("installed"); expect(result.callError).toBe("source_unavailable"); expect(result.adoptedOptions?.desiredCount).toBe(1);
    const installed = get(f.journal(), 6);
    expect(get(installed, 0)).toEqual(get(original, 0)); expect(get(installed, 9)).toEqual(get(original, 9));
    expect(uint(get(installed, 5))).toBe(1n); expect(uint(get(installed, 17))).toBe(2n);
    expect(uint(get(arrayItem(get(installed, 15)), 1))).toBe(2n);
    expect(uint(get(arrayItem(get(f.journal(), 9)), 1))).toBe(2n);
    expect(uint(get(arrayItem(get(f.journal(), 7)), 1))).toBe(2n);
    restarted.close(); await restarted.waitCleanup();
    const installedRecovery = await f.open({ create: false });
    f.exchange(async method => { if (method !== 41007) throw new Error("installed recovery must only ACK"); return { kind: "acknowledged" }; });
    expect((await installedRecovery.topUp()).state).toBe("acked");
    expect(uint(get(get(f.journal(), 6), 5))).toBe(1n);
    expect(uint(get(arrayItem(get(get(f.journal(), 6), 15)), 1))).toBe(2n);
    expect(f.calls.map(call => call.method)).toEqual([41006, 41007, 41007]);
  });

  it("replays the captured G2 commit at G3 while retaining its local G1 creation fence", async () => {
    const f = fixture(), source = await f.open({ ownerFenceProof: async () => { throw new Error("owner proof unavailable"); } });
    expect((await source.topUp({ desiredCount: 1 })).state).toBe("pending"); expect(f.calls).toHaveLength(0);
    const original = get(f.journal(), 6);
    source.close(); await source.waitCleanup(); f.advanceGeneration();
    const committing = await f.open({ create: false });
    let committed: Uint8Array = new Uint8Array();
    f.exchange(async (method, request) => {
      if (method !== 41006) throw new Error("unexpected ACK before installation");
      committed = f.response(request); throw new Error("committed response lost");
    });
    const lost = await committing.topUp();
    expect(lost.state).toBe("pending"); expect(lost.callError).toBe("source_unavailable");
    expect(uint(get(decode(committed), 3))).toBe(2n); expect(uint(get(get(f.journal(), 6), 5))).toBe(1n);
    committing.close(); await committing.waitCleanup(); f.advanceGeneration();
    const recovering = await f.open({ create: false });
    f.exchange(async method => method === 41007 ? { kind: "acknowledged" } : { kind: "replay", response: committed });
    const recovered = await recovering.topUp();
    expect(recovered.state).toBe("acked"); expect(recovered.callError).toBeUndefined();
    const replay = f.calls[1]!.request;
    expect(uint(get(replay, 6))).toBe(3n);
    for (const field of [0, 1, 2, 3, 4, 5, 8, 9]) expect(get(replay, field)).toEqual(get(f.calls[0]!.request, field));
    const installed = get(f.journal(), 6);
    expect(get(installed, 0)).toEqual(get(original, 0)); expect(get(installed, 9)).toEqual(get(original, 9));
    expect(uint(get(installed, 5))).toBe(1n); expect(uint(get(installed, 17))).toBe(3n);
    expect(uint(get(arrayItem(get(installed, 15)), 1))).toBe(2n);
    expect(get(installed, 10)).toEqual(get(decode(committed), 9));
    expect(uint(get(arrayItem(get(f.journal(), 9)), 1))).toBe(2n);
    expect(uint(get(arrayItem(get(f.journal(), 7)), 1))).toBe(2n);
    expect(uint(get(f.calls[2]!.request, 8))).toBe(3n);
    recovering.close(); await recovering.waitCleanup();
    await f.open({ create: false });
    expect(f.calls.map(call => call.method)).toEqual([41006, 41006, 41007]);
  });

  it("rejects a server response generation beyond the durably persisted attempt fence", async () => {
    const f = fixture(), source = await f.open();
    f.exchange(async (method, request) => {
      if (method !== 41006) throw new Error("invalid response must not ACK");
      return { kind: "success", response: f.response(replace(request, { 6: u(2) })) };
    });
    const result = await source.topUp({ desiredCount: 1 });
    expect(result.state).toBe("pending"); expect(result.callError).toBe("source_contract_invalid");
    expect(uint(get(get(f.journal(), 6), 5))).toBe(1n); expect(uint(get(get(f.journal(), 6), 17))).toBe(1n);
    expect(f.calls.map(call => call.method)).toEqual([41006]);
    expect(uint(get(f.journal(), 5))).toBe(0n); expect(get(f.journal(), 7)).toEqual(array());
  });

  it("rejects mixed entry generations even when each is inside creation-to-attempt bounds", async () => {
    const f = fixture(), source = await f.open({ ownerFenceProof: async () => { throw new Error("owner proof unavailable"); } });
    await source.topUp({ desiredCount: 2 }); expect(f.calls).toHaveLength(0);
    source.close(); await source.waitCleanup(); f.advanceGeneration();
    const restarted = await f.open({ create: false });
    f.exchange(async (method, request) => {
      if (method !== 41006) throw new Error("invalid response must not ACK");
      return { kind: "success", response: f.response(request, 1n, 2, [2n, 1n]) };
    });
    const result = await restarted.topUp();
    expect(result.state).toBe("pending"); expect(result.callError).toBe("source_contract_invalid");
    expect(uint(get(get(f.journal(), 6), 5))).toBe(1n); expect(uint(get(get(f.journal(), 6), 17))).toBe(2n);
    expect(f.calls.map(call => call.method)).toEqual([41006]);
    expect(uint(get(f.journal(), 5))).toBe(0n); expect(get(f.journal(), 7)).toEqual(array());
  });

  it.each(["rolled_back", "unknown"] as const)("sends nothing when the durable attempt fence commit is %s", async mode => {
    const f = fixture(), source = await f.open({ ownerFenceProof: async () => { throw new Error("owner proof unavailable"); } });
    await source.topUp({ desiredCount: 1 }); expect(f.calls).toHaveLength(0);
    const original = get(f.journal(), 6);
    source.close(); await source.waitCleanup(); f.advanceGeneration();
    const restarted = await f.open({ create: false }); f.failAttemptCommit(mode);
    const failed = await restarted.topUp();
    expect(failed.state).toBe("pending"); expect(failed.callError).toBe("source_unavailable"); expect(f.calls).toHaveLength(0);
    const pending = get(f.journal(), 6);
    expect(get(pending, 0)).toEqual(get(original, 0)); expect(get(pending, 9)).toEqual(get(original, 9));
    expect(uint(get(pending, 5))).toBe(1n); expect(uint(get(pending, 17))).toBe(mode === "unknown" ? 2n : 1n);
    if (mode === "unknown") {
      expect((await restarted.topUp()).callError).toBe("source_unavailable"); expect(f.calls).toHaveLength(0);
    }
    restarted.close(); await restarted.waitCleanup();
    const recovering = await f.open({ create: false });
    f.exchange(async (method, request) => method === 41007 ? { kind: "acknowledged" } : { kind: "success", response: f.response(request) });
    expect((await recovering.topUp()).state).toBe("acked");
    expect(uint(get(get(f.journal(), 6), 5))).toBe(1n); expect(uint(get(get(f.journal(), 6), 17))).toBe(2n);
    expect(f.calls.map(call => call.method)).toEqual([41006, 41007]);
  });

  it.each([0n, 3n])("rejects a persisted attempt generation %s outside its creation-to-current bounds", async attempt => {
    const f = fixture(), source = await f.open({ ownerFenceProof: async () => { throw new Error("owner proof unavailable"); } });
    await source.topUp({ desiredCount: 1 }); source.close(); await source.waitCleanup(); f.advanceGeneration();
    f.corrupt(journal => replace(journal, { 6: replace(get(journal, 6), { 17: u(attempt) }) }));
    await expect(f.open({ create: false })).rejects.toThrow("source_state_unknown"); expect(f.calls).toHaveLength(0);
  });

  it.each(["future", "mixed"] as const)("rejects %s Applied generations on Installed journal restart", async kind => {
    const f = fixture(), source = await f.open({ ownerFenceProof: async () => { throw new Error("owner proof unavailable"); } });
    await source.topUp({ desiredCount: 2 }); source.close(); await source.waitCleanup(); f.advanceGeneration();
    const installing = await f.open({ create: false });
    f.exchange(async (method, request) => {
      if (method === 41007) throw new Error("ACK receipt lost");
      return { kind: "success", response: f.response(request, 1n, 2) };
    });
    expect((await installing.topUp()).state).toBe("installed");
    installing.close(); await installing.waitCleanup(); f.advanceGeneration();
    f.corrupt(journal => {
      const pending = get(journal, 6);
      const changed = (entries: Value): Value => {
        if (entries.kind !== "array") throw new Error("expected Applied array");
        return array(...entries.value.map((entry, index) => index === 1 ? replace(entry, { 1: u(kind === "future" ? 3n : 1n) }) : entry));
      };
      return replace(journal, { 6: replace(pending, { 15: changed(get(pending, 15)) }), 7: changed(get(journal, 7)), 9: changed(get(journal, 9)) });
    });
    // Durable receipts and material metadata agree with the mutation. The
    // attempt bound and uniform batch generation must still reject it.
    await expect(f.open({ create: false })).rejects.toThrow("source_state_unknown");
    expect(f.calls.map(call => call.method)).toEqual([41006, 41007]);
  });

  it("recovers installed Applied facts using only ACK after material consumption and the original deadline", async () => {
    const f = fixture();
    f.exchange(async (method, request) => { if (method === 41007) throw new Error("ACK receipt lost"); return { kind: "success", response: f.response(request) }; });
    const source = await f.open(), installed = await source.topUp({ desiredCount: 1 });
    expect(installed.state).toBe("installed");
    const material = await source.acquire({ independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false });
    await material.close();
    const remaining = get(f.journal(), 7); expect(remaining.kind === "array" ? remaining.value.length : -1).toBe(0);
    source.close(); await source.waitCleanup(); f.advance(200n);
    const reopened = await f.open({ create: false, decodeMaterial: () => { throw new Error("installed recovery must not reparse spent material"); } });
    f.exchange(async method => { if (method !== 41007) throw new Error("installed recovery must not resend TopUp"); return { kind: "acknowledged" }; });
    const recovered = await reopened.topUp();
    expect(recovered.state).toBe("acked"); expect(recovered.handle).not.toBe(installed.handle);
    // Reopen has a new source observation. The internal ACK must still name
    // the same original operation, without exposing its wire ID on either handle.
    expect(get(f.calls[2]!.request, 0)).toEqual(get(f.calls[1]!.request, 0));
    expect(recovered.adoptedOptions).toEqual(installed.adoptedOptions);
    expect((await installed.handle!.status()).state).toBe("installed");
    expect(installed.handle!.cleanupStatus().status).toBe("complete");
    expect(recovered.handle!.cleanupStatus().status).toBe("complete");
    expect(f.calls.map(call => call.method)).toEqual([41006, 41007, 41007]);
  });

  it("rejects a shifted installed range whose final sequence still equals the persisted frontier", async () => {
    const f = fixture();
    f.exchange(async (method, request) => { if (method === 41007) throw new Error("ACK receipt lost"); return { kind: "success", response: f.response(request, 2n) }; });
    const source = await f.open();
    expect((await source.topUp({ desiredCount: 1 })).callError).toBe("source_contract_invalid");
    // Install a valid batch first, then corrupt every visible sequence together.
    // The original pre-append frontier must still expose the unauthorized gap.
    f.exchange(async (method, request) => { if (method === 41007) throw new Error("ACK receipt lost"); return { kind: "success", response: f.response(request) }; });
    expect((await source.topUp({ desiredCount: 1 })).state).toBe("installed");
    source.close(); await source.waitCleanup();
    f.corrupt(journal => {
      const pending = get(journal, 6), applied = get(pending, 15), history = get(journal, 9), materials = get(journal, 7);
      if (applied.kind !== "array" || history.kind !== "array" || materials.kind !== "array") throw new Error("expected journal arrays");
      const shift = (entry: Value) => replace(entry, { 0: u(2) });
      return replace(journal, { 5: u(2), 6: replace(pending, { 11: u(2), 15: array(...applied.value.map(shift)) }),
        7: array(...materials.value.map(shift)), 9: array(...history.value.map(shift)) });
    });
    await expect(f.open({ create: false })).rejects.toThrow("source_state_unknown");
  });

  it("keeps an expired intent pending until an authenticated terminal receipt and rejects its stale handle", async () => {
    const f = fixture(), source = await f.open(), original = await source.topUp({ desiredCount: 1 });
    f.advance(200n);
    f.exchange(async () => ({ kind: "error", error: { code: "top_up_request_expired", scope: "operation", write_action: "terminal" } }));
    const terminal = await source.topUp(); expect(terminal.state).toBe("terminal"); expect(terminal.handle).toBe(original.handle);
    f.exchange(async () => { throw new Error("response lost"); });
    const next = await source.topUp({ desiredCount: 1 }); expect(next.state).toBe("pending"); expect(next.handle).not.toBe(original.handle);
    const stale = await original.handle!.status();
    expect(stale.callError).toBe("stale_operation"); expect(stale.state).toBe("terminal"); expect(stale.handle).toBe(original.handle);
    expect(stale.handle).not.toBe(next.handle);
  });


  it("retains proven Installed state and the original handle when a query is canceled or its source is closed", async () => {
    const f = fixture();
    f.exchange(async (method, request) => { if (method === 41007) throw new Error("ACK receipt lost"); return { kind: "success", response: f.response(request) }; });
    const source = await f.open(), installed = await source.topUp({ desiredCount: 1 });
    const canceled = new AbortController(); canceled.abort();
    const beforeClose = await installed.handle!.status({ signal: canceled.signal });
    expect(beforeClose.state).toBe("installed"); expect(beforeClose.handle).toBe(installed.handle); expect(beforeClose.callError).toBe("canceled");
    source.close(); await source.waitCleanup();
    const afterClose = await installed.handle!.status();
    expect(afterClose.state).toBe("installed"); expect(afterClose.handle).toBe(installed.handle); expect(afterClose.callError).toBe("source_unavailable");
    expect((await installed.handle!.waitCleanup()).status).toBe("complete");
  });

  it("keeps an old operation's completed cleanup independent of a later operation's pending provider", async () => {
    const f = fixture(), source = await f.open();
    f.exchange(async () => ({ kind: "error", error: { code: "top_up_request_expired", scope: "operation", write_action: "terminal" } }));
    const terminal = await source.topUp({ desiredCount: 1 });
    const entered = deferred<void>(), release = deferred<V4TopUpExchangeResult>();
    f.exchange(async () => { entered.resolve(); return await release.promise; });
    const observer = new AbortController(), next = source.topUp({ desiredCount: 1 }, { signal: observer.signal });
    await entered.promise; observer.abort();
    const pending = await next;
    expect(pending.state).toBe("pending"); expect(pending.handle).not.toBe(terminal.handle);
    expect(source.cleanupStatus().status).toBe("pending");
    expect((await terminal.handle!.waitCleanup()).status).toBe("complete");
    const original = await terminal.handle!.status();
    expect(original.state).toBe("terminal"); expect(original.handle).toBe(terminal.handle);
    source.close(); release.resolve({ kind: "error", error: { code: "source_unavailable", scope: "source", write_action: "none" } });
    await pending.handle!.waitCleanup();
  });

  it("retains physical provider cleanup after an observer cancels and the source closes", async () => {
    const f = fixture(), proof = deferred<Uint8Array>(), entered = deferred<void>();
    let intent: Parameters<V4PoolSourceConfiguration["ownerFenceProof"]>[0] | undefined;
    const source = await f.open({ ownerFenceProof: async original => { intent = original; entered.resolve(); return await proof.promise; } });
    const observer = new AbortController(), operation = source.topUp({ desiredCount: 1 }, { signal: observer.signal });
    await entered.promise; observer.abort();
    const canceled = await operation; expect(canceled.callError).toBe("canceled"); source.close();
    expect(canceled.handle?.cleanupStatus().status).toBe("pending");
    let operationCleaned = false; const originalCleanup = canceled.handle!.waitCleanup().then(() => { operationCleaned = true; });
    expect(source.cleanupStatus().status).toBe("pending");
    let cleaned = false; const cleanup = source.waitCleanup().then(() => { cleaned = true; });
    await Promise.resolve(); expect(cleaned).toBe(false); expect(operationCleaned).toBe(false);
    proof.resolve(f.fence(intent!)); await Promise.all([cleanup, originalCleanup]);
    expect(source.cleanupStatus().status).toBe("complete"); expect(f.calls).toHaveLength(0);
  });
});
