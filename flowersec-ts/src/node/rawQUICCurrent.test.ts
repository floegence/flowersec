import { endpointListenerCandidateIndex, endpointListenerCost, nativeListenerSelectionCost, prepareEndpointNativeListeners, type NodeNativeTunnelListenerBinding } from "./endpointListener.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import { createPrivateKey, X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ClockRate, ResourceRoot, ResourceVector, createTransportEnvironment } from "./index.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { NativeProviderPositions } from "../v4/runtime/nativeProviderPositions.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { NativeDirectionFailure } from "../v4/runtime/nativeFailure.js";
import { NodeRawQUICCarrier, captureNodeRawQUIC, captureNodeRawQUICCandidates, nodeRawQUICAdmissionCosts, nodeRawQUICCandidateAdmissionCosts, nativeRawQUICQueueBytes, nodeNativePreparationBudgetCost, prepayNodeNativePreparationBudget, releaseNodeNativePreparationBudget, prepareNodeRawQUICCandidates } from "./rawQUICCurrent.js";
import type { NativeRawListener, NativePreparationBudget, NativeOperation, NativeRawSession, NativeRawStream, NativeTransportBinding, NativeWebTransportSession } from "./nativeTransportCurrent.js";
import { testCertificatePEM, testPrivateKeyPEM } from "../testSupport/tlsFixture.js";
import { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import { credentialOwner } from "../v4/runtime/credentialSupport.js";
import { bytes, encode, fill, map, text, u } from "../v4/testSupport/credentials.js";

function nativePreparationBudget(): NativePreparationBudget {
  let configured = false, closed = false;
  return { configure: () => { if (configured || closed) throw new Error("invalid_preparation_budget"); configured = true; },
    beginCandidate: () => { if (!configured || closed) throw new Error("preparation_budget_closed"); return Object.freeze({}); },
    usage: () => ({ preauthInputBytes: 0, addressAttempts: 0, workUnits: 0 }), close: () => { closed = true; } };
}
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function operation<T>(promise: Promise<T>, cancel = () => undefined): NativeOperation<T> { return { result: () => promise, cancel }; }
class NativeStream implements NativeRawStream {
  readonly ended = deferred<void>();
  readonly received = deferred<Uint8Array | null>();
  readonly written = deferred<void>();
  readonly reads: number[] = [];
  aborts = 0; readCancels = 0; submits = 0;
  input: Uint8Array | undefined;
  observer: ((reason: "normal_drained" | "direction_reset") => void) | undefined;
  constructor(readonly immediateAbort = false) {}
  read(maxBytes: number) { this.reads.push(maxBytes); return operation(this.received.promise, () => { this.readCancels++; }); }
  submit(data: Uint8Array) { this.submits++; this.input = data; return { completion: () => this.written.promise.finally(() => { this.input = undefined; }) }; }
  async closeWrite() {}
  async stopSending() {}
  async resetWrite() {}
  onWriteFailure(callback: (reason: "normal_drained" | "direction_reset") => void) { this.observer = callback; return () => { this.observer = undefined; }; }
  waitTermination() { return this.ended.promise; }
  abort() { this.aborts++; if (this.immediateAbort) this.ended.resolve(); }
}
class NativeSession<Kind extends "raw_quic" | "webtransport" = "raw_quic"> implements NativeRawSession {
  constructor(readonly kind: Kind = "raw_quic" as Kind, readonly path: "direct" | "tunnel" = "direct") {}
  readonly wireVersion = 4 as const;
  readonly inboundBidirectionalStreamCapacity = 3;
  readonly ended = deferred<void>();
  readonly maintenance = new NativeStream(true);
  readonly application = deferred<NativeRawStream>();
  opens = 0; accepts = 0; cancels = 0; aborts = 0; preparationCompletions = 0;
  tls() { return Object.freeze({ version: "TLSv1.3" as const, alpn: this.kind === "webtransport" ? "h3" as const : this.path === "direct" ? "flowersec-direct/4" as const : "flowersec-tunnel/4" as const, earlyDataAccepted: false as const,
    dedicatedConnection: true as const, peerLeafDER: new Uint8Array(new X509Certificate(testCertificatePEM).raw), certificateVerified: true }); }
  completePreparation() { this.preparationCompletions++; }
  exportKeyingMaterial(length: number) { return new Uint8Array(length).fill(1); }
  maxDatagramBytes() { return 0; }
  receiveDatagram(_maxBytes: number) { return operation(Promise.reject<Uint8Array>(new Error("datagram_unavailable"))); }
  submitDatagram(_bytes: Uint8Array) { return undefined; }
  openStream() { return ++this.opens === 1 ? operation(Promise.resolve(this.maintenance)) : operation(this.application.promise, () => { this.cancels++; }); }
  acceptStream() { this.accepts++; return operation(this.application.promise, () => { this.cancels++; }); }
  localAddress() { return { host: "127.0.0.1", port: 20000 }; }
  peerAddress() { return { host: "127.0.0.1", port: 30000 }; }
  async close() { this.abort(); await this.ended.promise; }
  waitTermination() { return this.ended.promise; }
  abort() { this.aborts++; }
}
function fixture() {
  const limit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 1000000n, 1000000n, 1024n, 1024n, 1024n, 1024n, 1024n, 1024n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 32, reservations: 128, references: 256,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const now = BigInt(Date.now()), beginning = performance.now();
  const environment = createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 1000,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 60000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - beginning)), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: now, upperMS: now }) },
    random: bytes => { crypto.getRandomValues(bytes); } });
  const owner = originalEnvironment(environment), options = captureNodeRawQUIC({ applicationStreams: 2, streamBufferBytes: 65544,
    runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n });
  const costs = nodeRawQUICAdmissionCosts(65536, options, 1024n), reserved = owner.admitDependencyPositions("test_raw_quic", costs[0]![1], costs[1]![1], 3);
  const positions = new NativeProviderPositions(reserved.positions), carrier = new NodeRawQUICCarrier(owner, reserved.dependency, positions, options, new TrustedDeadline(owner.clock, now + 10000n));
  const connected = deferred<NativeRawSession>(); let cancels = 0;
  const driver: NativeTransportBinding = { contractVersion: () => 4, createPreparationBudget: nativePreparationBudget, connectRawQuic: () => operation(connected.promise, () => { cancels++; }),
    bindRawQuic: async () => { throw new Error("unused server binding"); },
    connectWebTransport: () => { throw new Error("unused WebTransport binding"); }, bindWebTransport: async () => { throw new Error("unused WebTransport binding"); } };
  return { carrier, connected, positions, root, owner, environment, driver, options,
    prepare(signal?: AbortSignal) { return carrier.prepare(driver, { host: "localhost", port: 30000 }, { serverName: "localhost", mode: "ca", pins: [] }, signal); },
    cancels: () => cancels,
    async close() { await carrier.close(); await environment.close(); await environment.waitCleanup(); root.close(); },
  };
}

describe("current native QUIC original resource custody", () => {
  it("releases original connection custody after a synchronous native connect refusal", async () => {
    const f = fixture();
    const driver: NativeTransportBinding = { ...f.driver, connectRawQuic: () => { throw new Error("native connect refused"); } };
    await expect(f.carrier.prepare(driver, { host: "localhost", port: 30000 }, { serverName: "localhost", mode: "ca", pins: [] }))
      .rejects.toThrow("native connect refused");
    await f.carrier.close(); expect(f.positions.cleanupComplete()).toBe(true); await f.close();
  });

  it("retains the native accept gate after observer cancellation until the original accept exits", async () => {
    const f = fixture(), native = new NativeSession(); f.connected.resolve(native);
    await f.prepare(); f.carrier.activate(); f.carrier.nativeStreams.enable();
    const abort = new AbortController(), accepting = f.carrier.nativeStreams.accept({ signal: abort.signal });
    abort.abort(); await expect(accepting).rejects.toThrow("canceled"); expect(native.accepts).toBe(1);
    await expect(f.carrier.nativeStreams.accept()).rejects.toThrow("carrier_closed"); expect(native.accepts).toBe(1);
    const raw = new NativeStream(); native.application.resolve(raw);
    await Promise.resolve(); await Promise.resolve(); expect(raw.aborts).toBeGreaterThan(0);
    const closing = f.carrier.close(); native.ended.resolve(); raw.ended.resolve(); await closing; await f.close();
  });

  it("refuses new IO after physical native stream termination", async () => {
    const f = fixture(), native = new NativeSession(), raw = new NativeStream(); f.connected.resolve(native); native.application.resolve(raw);
    await f.prepare(); f.carrier.activate(); f.carrier.nativeStreams.enable();
    const stream = await f.carrier.nativeStreams.open(); raw.ended.resolve(); await Promise.resolve();
    expect(() => stream.submit(new Uint8Array([1]), () => {})).toThrow("carrier_closed");
    await expect(stream.read(1)).rejects.toThrow("carrier_closed"); expect(raw.submits).toBe(0); expect(raw.reads).toEqual([]);
    await stream.close(); native.ended.resolve(); await f.close();
  });

  it("joins physical FIN after peer stop overtakes the original write completion", async () => {
    const f = fixture(), native = new NativeSession(), raw = new NativeStream(); f.connected.resolve(native); native.application.resolve(raw);
    let fins = 0; raw.closeWrite = async () => { fins++; };
    await f.prepare(); f.carrier.activate(); f.carrier.nativeStreams.enable();
    const stream = await f.carrier.nativeStreams.open();
    try {
      const output = stream.submit(new Uint8Array([1]), () => {});
      expect(output).toBeDefined();
      raw.observer!("normal_drained"); raw.ended.resolve(); await Promise.resolve();
      expect(stream.cleanupComplete()).toBe(false);
      raw.written.resolve(); await output!.completion;
      expect(stream.cleanupComplete()).toBe(true);
      await stream.closeWrite(); await stream.closeWrite();
      expect(fins).toBe(0); expect(raw.aborts).toBe(0);
      expect(() => stream.submit(new Uint8Array([2]), () => {})).toThrow("carrier_closed");
    } finally { raw.written.resolve(); raw.ended.resolve(); await stream.close(); native.ended.resolve(); await f.close(); }
  });

  it("retains the original physical FIN failure after stream retirement", async () => {
    const f = fixture(), native = new NativeSession(), raw = new NativeStream(), tail = deferred<void>(); f.connected.resolve(native); native.application.resolve(raw);
    let fins = 0; raw.closeWrite = () => { fins++; return tail.promise; };
    await f.prepare(); f.carrier.activate(); f.carrier.nativeStreams.enable();
    const stream = await f.carrier.nativeStreams.open();
    try {
      const finishing = stream.closeWrite(); void finishing.catch(() => undefined);
      raw.ended.resolve(); await Promise.resolve(); expect(stream.cleanupComplete()).toBe(false);
      tail.reject(Object.assign(new Error("direction reset"), { source: "stream", reason: "direction_reset" }));
      await expect(finishing).rejects.toBeInstanceOf(NativeDirectionFailure);
      expect(stream.cleanupComplete()).toBe(true);
      expect(stream.closeWrite()).toBe(finishing); await expect(stream.closeWrite()).rejects.toBeInstanceOf(NativeDirectionFailure);
      expect(fins).toBe(1);
    } finally { tail.resolve(); raw.ended.resolve(); await stream.close(); native.ended.resolve(); await f.close(); }
  });

  it("returns cancellation promptly but retains a late connected native session until its physical exit", async () => {
    const f = fixture(), abort = new AbortController(), preparing = f.prepare(abort.signal);
    abort.abort(); await expect(preparing).rejects.toThrow("canceled");
    let finished = false; const closing = f.carrier.close().then(() => { finished = true; });
    await Promise.resolve(); expect(finished).toBe(false); expect(f.cancels()).toBeGreaterThan(0); expect(f.positions.cleanupComplete()).toBe(true);
    const native = new NativeSession(); f.connected.resolve(native);
    await Promise.resolve(); await Promise.resolve(); expect(native.aborts).toBeGreaterThan(0); expect(finished).toBe(false);
    native.ended.resolve(); await closing; await f.close();
  });

  it("does not reuse an application position after cancellation until the actual native create and handle terminate", async () => {
    const f = fixture(), native = new NativeSession(); f.connected.resolve(native);
    await f.prepare(); f.carrier.activate(); f.carrier.nativeStreams.enable();
    const abort = new AbortController(), opening = f.carrier.nativeStreams.open({ signal: abort.signal });
    abort.abort(); await expect(opening).rejects.toThrow("canceled"); expect(native.cancels).toBe(1);
    const raw = new NativeStream(); native.application.resolve(raw);
    await Promise.resolve(); await Promise.resolve(); expect(raw.aborts).toBeGreaterThan(0);
    const closing = f.carrier.close(); native.ended.resolve();
    expect(f.positions.cleanupComplete()).toBe(false);
    raw.ended.resolve(); await closing; expect(f.positions.cleanupComplete()).toBe(true); await f.close();
  });

  it("retains submitted byte borrows after physical stream closure until the original native write completion", async () => {
    const f = fixture(), native = new NativeSession(), raw = new NativeStream(); f.connected.resolve(native); native.application.resolve(raw);
    await f.prepare(); f.carrier.activate(); f.carrier.nativeStreams.enable();
    const stream = await f.carrier.nativeStreams.open(), bytes = new Uint8Array([1, 2, 3]); let admissions = 0;
    const submitted = stream.submit(bytes, () => { admissions++; }); expect(submitted).toBeDefined(); expect(admissions).toBe(1); expect(raw.input).toBe(bytes);
    let finished = false; const closing = stream.close().then(() => { finished = true; }); raw.ended.resolve();
    await Promise.resolve(); await Promise.resolve(); expect(finished).toBe(false); expect(stream.cleanupComplete()).toBe(false);
    raw.written.resolve(); await submitted!.completion; await closing; expect(raw.input).toBeUndefined(); expect(stream.cleanupComplete()).toBe(true);
    native.ended.resolve(); await f.close();
  });
  it("ends shared physical Prepare before waiting for a peer maintenance stream", async () => {
    const f = fixture(), native = new NativeSession(), costs = nodeRawQUICAdmissionCosts(65536, f.options, 1024n);
    const reserved = f.owner.admitDependencyPositions("test_shared_raw_quic", costs[0]![1], costs[1]![1], 3);
    const server = new NodeRawQUICCarrier(f.owner, reserved.dependency, new NativeProviderPositions(reserved.positions), f.options,
      new TrustedDeadline(f.owner.clock, f.owner.clock.sample().requireInterval().lowerMS + 10000n), "server");
    let settled = false;
    const accepting = server.accept(native, { host: "localhost", port: 20000, leaf: new X509Certificate(testCertificatePEM) });
    void accepting.then(() => { settled = true; }, () => { settled = true; });
    try {
      await Promise.resolve();
      expect(native.preparationCompletions).toBe(1); expect(native.accepts).toBe(1); expect(settled).toBe(false);
      native.application.resolve(native.maintenance); await accepting;
      server.completePreparation(); expect(native.preparationCompletions).toBe(1);
    } finally {
      native.application.resolve(native.maintenance); native.ended.resolve(); await accepting.catch(() => undefined); await server.close(); await f.close();
    }
  });
});


class NativeWebSession extends NativeSession<"webtransport"> implements NativeWebTransportSession {
  constructor() { super("webtransport"); }
  request() { return Object.freeze({ scheme: "https" as const, authority: "localhost:30000", path: "/flowersec/webtransport/v4/direct", tuple: "native_h3" as const,
    protocol: "webtransport-h3" as const, sessionFlowControl: false as const, streamPrefixes: "rfc_webtransport" as const, datagramContext: "rfc_h3_quarter_stream_id" as const }); }
}
function nativeCandidate(index: number, kind: "raw-quic" | "webtransport") {
  const candidateID = fill(index + 1, 16), leg = map({ 0: u(0), 1: bytes(fill(index + 2, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(kind === "webtransport" ? 2 : 0),
    6: text("localhost"), 7: u(30000), 8: text(kind === "webtransport" ? "/flowersec/webtransport/v4/direct" : ""), 9: text(kind === "webtransport" ? "h3" : "flowersec-direct/4"),
    10: text(""), 11: map({ 0: u(0), 1: { kind: "bool", value: true } }),
    ...(kind === "webtransport" ? { 12: map({ 0: { kind: "array", value: [text("https://localhost")] }, 1: { kind: "bool", value: true } }) } : {}) });
  return Object.freeze({ candidateIndex: index, candidateID, routeDigest: fill(index + 1), pathKind: 0 as const, accessClass: 0n,
    reliableProgress: "native_bound" as const, route: encode(map({ 0: u(0), 1: bytes(candidateID), 2: leg })) });
}
function nativeCandidateFields(f: ReturnType<typeof fixture>, preferred: number, candidates: ReturnType<typeof nativeCandidate>[], attempts: number) {
  return Object.freeze({ ...candidates.find(value => value.candidateIndex === preferred)!, candidates, totalCandidateAttempts: attempts, source: "preauthorized_pool" as const,
    preparationBytes: 262144, totalPreparationBytes: 1048576, preparationWork: 256, required: 0n, maxFrame: 65536,
    preparationDeadline: new TrustedDeadline(f.owner.clock, f.owner.clock.sample().requireInterval().lowerMS + 10000n) });
}
function nativeConfigurations() {
  const primary = { applicationStreams: 2, streamBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n,
    trustRootsDER: [new Uint8Array(new X509Certificate(testCertificatePEM).raw)] };
  return captureNodeRawQUICCandidates([primary, { ...primary, nativeCarrier: "webtransport", webTransport: { headerBytes: 1024, controlBytes: 16384, tuples: ["native_h3"], allowedOrigins: [], allowAbsentOrigin: true } }]);
}
function nativeCandidateAdmission(f: ReturnType<typeof fixture>, candidates: ReturnType<typeof nativeConfigurations>, attempts: number) {
  const costs = [nodeNativePreparationBudgetCost(1024n), ...nodeRawQUICCandidateAdmissionCosts(65536, candidates, 1024n, attempts)];
  const references = f.root.reserveBatch(costs.map(([kind, charge]) => ({ owner: credentialOwner(f.owner.resources, kind), accounts: f.owner.resources.accounts, charge })));
  const admission = new ClientSessionAdmission(costs, references, () => releaseNodeNativePreparationBudget(admission));
  prepayNodeNativePreparationBudget(f.owner, admission, f.driver); return admission;
}

describe("current native candidate preparation", () => {
  it("prepares WebTransport after the preferred raw candidate fully retires, using separately prepaid plans", async () => {
    const f = fixture(), configured = nativeConfigurations(), admission = nativeCandidateAdmission(f, configured, 2);
    const first = new NativeSession(), second = new NativeWebSession(), retired = deferred<void>(), calls: string[] = [];
    const originalAbort = first.abort.bind(first); first.abort = () => { originalAbort(); retired.resolve(); };
    first.openStream = () => operation(Promise.reject(new Error("native maintenance refused")));
    const driver: NativeTransportBinding = { ...f.driver,
      connectRawQuic: () => { calls.push("raw-quic"); return operation(Promise.resolve(first)); },
      connectWebTransport: () => { calls.push("webtransport"); return operation(Promise.resolve(second)); } };
    let selected: NodeRawQUICCarrier | undefined;
    try {
      const preparing = prepareNodeRawQUICCandidates(f.owner, nativeCandidateFields(f, 3, [nativeCandidate(0, "webtransport"), nativeCandidate(3, "raw-quic")], 2), configured,
        { "raw-quic": driver, webtransport: driver }, undefined, admission, 0, 0, 2);
      await retired.promise; expect(calls).toEqual(["raw-quic"]);
      first.ended.resolve(); selected = await preparing;
      expect(calls).toEqual(["raw-quic", "webtransport"]); expect(selected.nativeCarrier).toBe("webtransport"); expect(selected.selectedCandidateIndex).toBe(0);
    } finally { first.ended.resolve(); second.ended.resolve(); await selected?.close(); admission.close(); await f.close(); }
  });

  it("honors the signed attempt limit even when the local plan permits another carrier", async () => {
    const f = fixture(), configured = nativeConfigurations(), admission = nativeCandidateAdmission(f, configured, 2), calls: string[] = [];
    const driver: NativeTransportBinding = { ...f.driver,
      connectRawQuic: () => { calls.push("raw-quic"); throw new Error("native refused"); },
      connectWebTransport: () => { calls.push("webtransport"); throw new Error("must not dial"); } };
    try {
      await expect(prepareNodeRawQUICCandidates(f.owner, nativeCandidateFields(f, 1, [nativeCandidate(0, "webtransport"), nativeCandidate(1, "raw-quic")], 1), configured,
        { "raw-quic": driver, webtransport: driver }, undefined, admission, 0, 0, 2)).rejects.toThrow("native refused");
      expect(calls).toEqual(["raw-quic"]);
    } finally { admission.close(); await f.close(); }
  });

  it("does not prepare any candidate after cancellation", async () => {
    const f = fixture(), configured = nativeConfigurations(), admission = nativeCandidateAdmission(f, configured, 2), abort = new AbortController(); abort.abort();
    try {
      await expect(prepareNodeRawQUICCandidates(f.owner, nativeCandidateFields(f, 0, [nativeCandidate(0, "raw-quic"), nativeCandidate(1, "webtransport")], 2), configured,
        { "raw-quic": f.driver, webtransport: f.driver }, abort.signal, admission, 0, 0, 2)).rejects.toThrow("canceled");
    } finally { admission.close(); await f.close(); }
  });
});

class NativeTunnelSession<Kind extends "raw_quic" | "webtransport"> extends NativeSession<Kind> {
  completed = 0;
  constructor(kind: Kind, readonly listeningPort: number) { super(kind, "tunnel"); }
  override completePreparation() { this.completed++; }
  override acceptStream() { this.accepts++; return operation(Promise.resolve(this.maintenance)); }
  override localAddress() { return { host: "127.0.0.1", port: this.listeningPort }; }
  override abort() { super.abort(); this.ended.resolve(); }
  request() { return Object.freeze({ scheme: "https" as const, authority: `localhost:${this.listeningPort}`, path: "/flowersec/webtransport/v4/tunnel",
    tuple: "native_h3" as const, protocol: "webtransport-h3" as const, sessionFlowControl: false as const,
    streamPrefixes: "rfc_webtransport" as const, datagramContext: "rfc_h3_quarter_stream_id" as const }); }
}
function nativeTunnelCandidate(index: number, kind: "raw-quic" | "webtransport", port: number) {
  const candidateID = fill(index + 1, 16);
  const leg = (endpoint: 0 | 1, targetPort: number) => map({ 0: u(0), 1: bytes(fill(index + 20 + endpoint, 16)), 2: u(endpoint), 3: u(2), 4: u(endpoint), 5: u(kind === "webtransport" ? 2 : 0),
    6: text("localhost"), 7: u(targetPort), 8: text(kind === "webtransport" ? "/flowersec/webtransport/v4/tunnel" : ""),
    9: text(kind === "webtransport" ? "h3" : "flowersec-tunnel/4"), 10: text(""), 11: map({ 0: u(0), 1: { kind: "bool", value: true } }),
    ...(kind === "webtransport" ? { 12: map({ 0: { kind: "array", value: [text("https://localhost")] }, 1: { kind: "bool", value: true } }) } : {}) });
  return Object.freeze({ candidateIndex: index, candidateID, routeDigest: fill(index + 1), pathKind: 1 as const, accessClass: 0n,
    reliableProgress: "native_bound" as const, route: encode(map({ 0: u(1), 1: bytes(candidateID), 3: leg(0, port), 4: leg(1, 31000 + index) })) });
}
function nativeTunnelFields(f: ReturnType<typeof fixture>, preferred: number, candidates: ReturnType<typeof nativeTunnelCandidate>[]) {
  return Object.freeze({ ...candidates.find(candidate => candidate.candidateIndex === preferred)!, candidates, totalCandidateAttempts: 32, source: "preauthorized_pool" as const,
    preparationBytes: 262144, totalPreparationBytes: 1048576, preparationWork: 256, preparationAddressAttempts: 8, totalPreparationWork: 8192,
    required: 0n, maxFrame: 65536, preparationDeadline: new TrustedDeadline(f.owner.clock, f.owner.clock.sample().requireInterval().lowerMS + 10000n) });
}
function nativeListenerBinding(carrier: ReturnType<typeof nativeConfigurations>[number], port: number, onPrepared?: () => void): NodeNativeTunnelListenerBinding {
  return Object.freeze({ carrier, listener: Object.freeze({ host: "127.0.0.1", port, serverName: "localhost", ...(onPrepared === undefined ? {} : { onPrepared }),
    tls: Object.freeze({ certificateChainDER: [new Uint8Array(new X509Certificate(testCertificatePEM).raw)],
      privateKeyDER: new Uint8Array(createPrivateKey(testPrivateKeyPEM).export({ format: "der", type: "pkcs8" })) }) }) });
}
function nativeListenerAdmission(f: ReturnType<typeof fixture>, bindings: readonly NodeNativeTunnelListenerBinding[]) {
  const costs = [nodeNativePreparationBudgetCost(1024n), nativeListenerSelectionCost(1024n), ...bindings.flatMap(({ carrier }) =>
    [...nodeRawQUICAdmissionCosts(65536, carrier, 1024n), endpointListenerCost(1024n, carrier.providerRuntimeBytes + nativeRawQUICQueueBytes(carrier))])];
  const references = f.root.reserveBatch(costs.map(([kind, charge]) => ({ owner: credentialOwner(f.owner.resources, kind), accounts: f.owner.resources.accounts, charge })));
  const admission = new ClientSessionAdmission(costs, references, () => releaseNodeNativePreparationBudget(admission));
  prepayNodeNativePreparationBudget(f.owner, admission, f.driver); return admission;
}

describe("bounded native physical listener candidate preparation", () => {
  it("returns the actual alternate only after the losing socket's native cleanup ends", async () => {
    const f = fixture(), configured = nativeConfigurations(), bothBound = deferred<void>(), loserCanceled = deferred<void>(), loserEnded = deferred<void>();
    const pending = deferred<NativeRawSession>(), native = new NativeTunnelSession("webtransport", 30001), winnerEnded = deferred<void>();
    let bound = 0, settled = false, rawAborts = 0, transport: V4AuthenticatedTransport | undefined;
    const prepared = () => { if (++bound === 2) bothBound.resolve(); };
    const bindings = [nativeListenerBinding(configured[0]!, 30000, prepared), nativeListenerBinding(configured[1]!, 30001, prepared)];
    const admission = nativeListenerAdmission(f, bindings);
    const raw: NativeRawListener = { address: () => ({ host: "127.0.0.1", port: 30000 }),
      stopAcceptingCurrent: () => { throw new Error("candidate listener never drains"); },
      accept: () => operation(pending.promise, () => { loserCanceled.resolve(); pending.reject(new Error("canceled")); }),
      abort: () => { rawAborts++; }, close: async () => { rawAborts++; await loserEnded.promise; }, waitTermination: () => loserEnded.promise };
    const driver: NativeTransportBinding = { ...f.driver,
      bindRawQuic: async options => { expect(options.preparationBudget).toBeDefined(); return raw; },
      bindWebTransport: async options => { expect(options.preparationBudget).toBeDefined(); return { address: () => ({ host: "127.0.0.1", port: 30001 }),
        stopAcceptingCurrent: () => { throw new Error("candidate listener never drains"); },
        accept: () => operation(Promise.resolve(native)), abort: () => { winnerEnded.resolve(); }, close: async () => { winnerEnded.resolve(); }, waitTermination: () => winnerEnded.promise }; } };
    try {
      const preparing = prepareEndpointNativeListeners(f.owner, nativeTunnelFields(f, 0, [nativeTunnelCandidate(0, "raw-quic", 30000), nativeTunnelCandidate(1, "webtransport", 30001)]),
        bindings, { "raw-quic": driver, webtransport: driver }, new AbortController().signal, admission);
      void preparing.then(() => { settled = true; }, () => { settled = true; });
      await bothBound.promise; await loserCanceled.promise;
      expect(settled).toBe(false); expect(rawAborts).toBeGreaterThan(0); expect(native.completed).toBe(0);
      loserEnded.resolve(); transport = await preparing;
      expect(endpointListenerCandidateIndex(transport)).toBe(1); expect(native.completed).toBe(1); expect(native.accepts).toBe(0);
      transport.completePreparation?.(); expect(native.completed).toBe(1);
      native.maintenance.received.resolve(new Uint8Array([1]));
      expect(await transport.read(1)).toEqual(new Uint8Array([1])); expect(native.accepts).toBe(1); expect(native.completed).toBe(1);
    } finally { loserEnded.resolve(); await transport?.close(); admission.close(); await f.close(); }
  });

  it("keeps the original full Route when two signed candidates share one physical binding", async () => {
    const f = fixture(), configured = nativeConfigurations(), bindings = [nativeListenerBinding(configured[0]!, 30000)];
    const admission = nativeListenerAdmission(f, bindings), native = new NativeTunnelSession("raw_quic", 30000), ended = deferred<void>();
    let transport: V4AuthenticatedTransport | undefined, binds = 0;
    const driver: NativeTransportBinding = { ...f.driver, bindRawQuic: async () => { binds++; return {
      stopAcceptingCurrent: () => { throw new Error("candidate listener never drains"); },
      address: () => ({ host: "127.0.0.1", port: 30000 }), accept: () => operation(Promise.resolve(native)),
      abort: () => { ended.resolve(); }, close: async () => { ended.resolve(); }, waitTermination: () => ended.promise }; } };
    try {
      transport = await prepareEndpointNativeListeners(f.owner, nativeTunnelFields(f, 1, [nativeTunnelCandidate(0, "raw-quic", 30000), nativeTunnelCandidate(1, "raw-quic", 30000)]),
        bindings, { "raw-quic": driver }, new AbortController().signal, admission);
      expect(binds).toBe(1); expect(endpointListenerCandidateIndex(transport)).toBe(1); expect(native.completed).toBe(1); expect(native.accepts).toBe(0);
    } finally { await transport?.close(); admission.close(); await f.close(); }
  });
});
