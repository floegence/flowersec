import { isIP } from "node:net";
import { pinProfile } from "./wssV4.js";
import { createHash, X509Certificate } from "node:crypto";
import type { OperationOptions } from "../public/contract.js";
import type { V4AuthenticatedTransport, V4NativeApplicationStream, V4NativeStreamProvider } from "../v4/runtime/session.js";
import type { V4EnvironmentRuntime, EnvironmentDependency } from "../v4/runtime/environment.js";
import type { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import type { CarrierPreparationFields } from "../v4/runtime/credentialVerifier.js";
import type { VerifiedRelayCredentials } from "../v4/runtime/relayCredentials.js";
import type { ReadyIdentitySigner } from "../v4/runtime/noiseHandshake.js";
import type { RandomFill } from "../v4/runtime/random.js";
import { CredentialWork, credentialWorkCharge, equalCredential, requireCredential, type CredentialResources, type OwnedCredentialMap } from "../v4/runtime/credentialSupport.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import type { TrustedDeadline} from "../v4/runtime/deadline.js";
import { timerChunk } from "../v4/runtime/deadline.js";
import { NativeDirectionFailure } from "../v4/runtime/nativeFailure.js";
import { NativeProviderPositions, nativeProviderStreamCharge, type NativeProviderStreamPosition } from "../v4/runtime/nativeProviderPositions.js";
import type { NativeDatagrams } from "../v4/runtime/unreliable.js";
import { HopAuthentication, HopAuthenticationPreparation, hopAuthenticationCharge } from "../v4/runtime/hopAuthentication.js";
import { observeTask } from "../v4/runtime/taskObservation.js";
import type { NativePreparationBudget, NativeCandidatePreparationBudget, NativeOperation, NativeRawSession, NativeRawStream, NativeRawTLS, NativeRawConnectOptions, NativeWebTransportRequest, NativeWebTransportSession, NativeTransportBinding } from "./nativeTransportCurrent.js";

function nativeFailure(error: unknown): Error {
  if (error instanceof NativeDirectionFailure) return error;
  if (error instanceof Error) {
    const native = error as Error & { code?: string; source?: string; reason?: string };
    const reason = native.source === "stream" ? native.reason : native.code === "normal_drained" || native.code === "direction_reset" ? native.code : native.message;
    if (reason === "normal_drained" || reason === "direction_reset") return new NativeDirectionFailure(reason);
  }
  return new Error("carrier_failed");
}
export interface NodeRawQUICOptions {
  readonly applicationStreams: number;
  readonly streamBufferBytes: number;
  readonly runtimeBytes: bigint;
  readonly providerRuntimeBytes: bigint;
  readonly providerStreamBytes: bigint;
  readonly trustRootsDER?: readonly Uint8Array[];
  /** Built-in native carrier choice, captured before source acquisition. */
  readonly nativeCarrier?: "raw-quic" | "webtransport";
  readonly webTransport?: Readonly<{ headerBytes: number; controlBytes: number; tuples: readonly ("chromium_draft02" | "native_h3")[]; allowedOrigins: readonly string[]; allowAbsentOrigin: boolean }>;
}

/** A finite local carrier set. Each entry has its own TLS/Origin configuration;
 * a verified Route chooses among these entries and never supplies configuration. */
export function captureNodeRawQUICCandidates(inputs: readonly NodeRawQUICOptions[]): readonly NodeRawQUICOptions[] {
  requireCredential(Array.isArray(inputs) && inputs.length >= 1 && inputs.length <= 2, "configuration_capacity");
  const candidates: NodeRawQUICOptions[] = [];
  try {
    for (const input of inputs) candidates.push(captureNodeRawQUIC(input));
    const first = candidates[0]!;
    requireCredential(new Set(candidates.map(value => value.nativeCarrier ?? "raw-quic")).size === candidates.length &&
      candidates.every(value => value.applicationStreams === first.applicationStreams), "configuration_capacity");
    return Object.freeze(candidates);
  } catch (error) { for (const value of candidates) for (const root of value.trustRootsDER ?? []) root.fill(0); throw error; }
}

/** Reserves one independently owned native plan for each possible retry before
 * Acquire. Per-attempt vectors take only their actual carrier's bounded share. */
export function nodeRawQUICCandidateAdmissionCosts(maxFrame: number, candidates: readonly NodeRawQUICOptions[], runtimeBytes: bigint, attemptLimit: number): readonly (readonly [string, ResourceVector])[] {
  requireCredential(Number.isSafeInteger(attemptLimit) && attemptLimit >= 1 && attemptLimit <= 16 && candidates.length >= 1, "configuration_capacity");
  const plans = candidates.map(value => nodeRawQUICAdmissionCosts(maxFrame, value, runtimeBytes));
  const shape = plans[0]!;
  requireCredential(plans.every(plan => plan.length === shape.length && plan.every((part, index) => part[0] === shape[index]![0])), "configuration_capacity");
  const maximum = shape.map((part, index) => {
    const vectors = plans.map(plan => plan[index]![1].values());
    return [part[0], new ResourceVector(vectors[0]!.map((_, dimension) => vectors.reduce((value, current) => current[dimension]! > value ? current[dimension]! : value, 0n)))] as const;
  });
  return Object.freeze(Array.from({ length: attemptLimit }, () => [["node_raw_quic_candidate_route", credentialWorkCharge(16384, runtimeBytes)] as const, ...maximum]).flat());
}

export function nodeNativePreparationBudgetCost(runtimeBytes: bigint): readonly [string, ResourceVector] {
  return ["node_native_preparation_budget", new ResourceVector([16384n + runtimeBytes, 65536n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n])];
}
const preparationOwners = new WeakMap<ClientSessionAdmission, NodeNativePreparationOwner>();
export class NodeNativePreparationOwner {
  readonly #budget: NativePreparationBudget; readonly #dependency: ReturnType<V4EnvironmentRuntime["admitDependency"]>;
  #configured = false; #transferred = false; #closed = false;
  readonly #candidates = new Map<number, NativeCandidatePreparationBudget>();
  constructor(runtime: V4EnvironmentRuntime, binding: NativeTransportBinding, admission?: ClientSessionAdmission) {
    requireCredential(typeof binding.createPreparationBudget === "function", "configuration_capacity");
    const cost = nodeNativePreparationBudgetCost(runtime.resources.runtimeBytes), reference = admission?.take([cost])[0];
    try { this.#dependency = runtime.admitDependency(cost[0], cost[1], reference, admission); } finally { reference?.release(); }
    try { this.#budget = binding.createPreparationBudget(); this.#dependency.onClose(() => { this.#budget.close(); }); }
    catch (error) { this.#dependency.release(); throw error; }
  }
  configure(fields: CarrierPreparationFields): void {
    this.#dependency.check(); requireCredential(!this.#closed && !this.#configured, "credential_binding");
    const pool = fields.source === "preauthorized_pool";
    this.#budget.configure({ preauthInputBytes: pool ? fields.totalPreparationBytes ?? fields.preparationBytes : 1048576,
      addressAttempts: pool ? fields.totalCandidateAttempts ?? 1 : 2, workUnits: pool ? fields.totalPreparationWork ?? fields.preparationWork : 4096 }); this.#configured = true;
  }
  candidate(fields: CarrierPreparationFields): NativeCandidatePreparationBudget {
    this.#dependency.check(); requireCredential(!this.#closed && this.#configured, "credential_binding"); const pool = fields.source === "preauthorized_pool";
    const index = fields.candidateIndex ?? 0;
    requireCredential(Number.isSafeInteger(index) && index >= 0 && index < 16, "credential_binding");
    const original = this.#candidates.get(index); if (original !== undefined) return original;
    const candidate = this.#budget.beginCandidate({ preauthInputBytes: pool ? fields.preparationBytes : 1048576,
      addressAttempts: pool ? fields.preparationAddressAttempts ?? 1 : 2, workUnits: pool ? fields.preparationWork : 4096 });
    this.#candidates.set(index, candidate); return candidate;
  }
  transfer(carrier: NodeRawQUICCarrier): void { requireCredential(!this.#transferred && !this.#closed, "credential_binding"); carrier.retainPreparationOwner(() => this.close()); this.#transferred = true; }
  releaseUnused(): void { if (!this.#transferred) this.close(); }
  close(): void { if (this.#closed) return; this.#closed = true; this.#budget.close(); this.#candidates.clear(); this.#dependency.release(); }
}
export function prepayNodeNativePreparationBudget(runtime: V4EnvironmentRuntime, admission: ClientSessionAdmission, binding: NativeTransportBinding): void {
  requireCredential(!preparationOwners.has(admission), "credential_binding"); preparationOwners.set(admission, new NodeNativePreparationOwner(runtime, binding, admission));
}
export function releaseNodeNativePreparationBudget(admission: ClientSessionAdmission): void { preparationOwners.get(admission)?.releaseUnused(); preparationOwners.delete(admission); }
export function originalNodeNativePreparationOwner(runtime: V4EnvironmentRuntime, fields: CarrierPreparationFields, binding: NativeTransportBinding, admission?: ClientSessionAdmission): NodeNativePreparationOwner {
  const owner = admission === undefined ? new NodeNativePreparationOwner(runtime, binding) : preparationOwners.get(admission);
  requireCredential(owner !== undefined, "configuration_capacity"); try { owner.configure(fields); return owner; } catch (error) { owner.releaseUnused(); throw error; }
}

export function captureNodeRawQUIC(input: NodeRawQUICOptions, beforeCopy?: (validated: NodeRawQUICOptions) => void): NodeRawQUICOptions {
  const applicationStreams = input.applicationStreams, streamBufferBytes = input.streamBufferBytes;
  const runtimeBytes = input.runtimeBytes, providerRuntimeBytes = input.providerRuntimeBytes, providerStreamBytes = input.providerStreamBytes;
  const roots = input.trustRootsDER, nativeCarrier = input.nativeCarrier ?? "raw-quic", wt = input.webTransport;
  requireCredential(nativeCarrier === "raw-quic" || nativeCarrier === "webtransport", "configuration_capacity");
  if (nativeCarrier === "webtransport") {
    requireCredential(wt !== undefined && Number.isSafeInteger(wt.headerBytes) && wt.headerBytes >= 1024 && wt.headerBytes <= 65536 && Number.isSafeInteger(wt.controlBytes) && wt.controlBytes >= 16384 && wt.controlBytes <= 1048576 &&
      Array.isArray(wt.tuples) && wt.tuples.length >= 1 && wt.tuples.length <= 2 && new Set(wt.tuples).size === wt.tuples.length && wt.tuples.every(tuple => tuple === "chromium_draft02" || tuple === "native_h3") &&
      Array.isArray(wt.allowedOrigins) && wt.allowedOrigins.length <= 64 && new Set(wt.allowedOrigins).size === wt.allowedOrigins.length && typeof wt.allowAbsentOrigin === "boolean", "configuration_capacity");
    for (const origin of wt.allowedOrigins) { const parsed = new URL(origin); requireCredential(parsed.origin === origin && (parsed.protocol === "https:" || parsed.protocol === "http:") && origin.length <= 4096, "configuration_capacity"); }
  } else requireCredential(wt === undefined, "configuration_capacity");
  requireCredential(Number.isSafeInteger(applicationStreams) && applicationStreams >= 1 && applicationStreams <= 4096 &&
    Number.isSafeInteger(streamBufferBytes) && streamBufferBytes >= 65544 && streamBufferBytes <= 16777224 &&
    [runtimeBytes, providerRuntimeBytes, providerStreamBytes].every(value => typeof value === "bigint" && value > 0n && value <= 0xffffffffffffffffn) &&
    (roots === undefined || Array.isArray(roots) && roots.length > 0 && roots.length <= 64 && roots.every(value => value instanceof Uint8Array && value.byteLength > 0 && value.byteLength <= 65536) && roots.reduce((n, value) => n + value.byteLength, 0) <= 1048576), "configuration_capacity");
  const transport = { nativeCarrier, ...(wt === undefined ? {} : { webTransport: Object.freeze({ ...wt, tuples: Object.freeze([...wt.tuples]), allowedOrigins: Object.freeze([...wt.allowedOrigins]) }) }) };
  beforeCopy?.({ applicationStreams, streamBufferBytes, runtimeBytes, providerRuntimeBytes, providerStreamBytes, ...transport, ...(roots === undefined ? {} : { trustRootsDER: roots }) });
  return Object.freeze({ applicationStreams, streamBufferBytes, runtimeBytes, providerRuntimeBytes, providerStreamBytes, ...transport,
    ...(roots === undefined ? {} : { trustRootsDER: Object.freeze(roots.map(value => new Uint8Array(value))) }) });
}
/** Exact captured configuration for adoption of a physical listener. */
export function sameNodeRawQUICOptions(left: NodeRawQUICOptions, right: NodeRawQUICOptions): boolean {
  if ((left.nativeCarrier ?? "raw-quic") !== (right.nativeCarrier ?? "raw-quic") || left.applicationStreams !== right.applicationStreams ||
      left.streamBufferBytes !== right.streamBufferBytes || left.runtimeBytes !== right.runtimeBytes || left.providerRuntimeBytes !== right.providerRuntimeBytes || left.providerStreamBytes !== right.providerStreamBytes) return false;
  const roots = left.trustRootsDER, otherRoots = right.trustRootsDER;
  if ((roots === undefined) !== (otherRoots === undefined) || roots !== undefined && (roots.length !== otherRoots!.length || !roots.every((bytes, index) => equalCredential(bytes, otherRoots![index]!)))) return false;
  const wt = left.webTransport, otherWT = right.webTransport;
  return wt === undefined ? otherWT === undefined : otherWT !== undefined && wt.headerBytes === otherWT.headerBytes && wt.controlBytes === otherWT.controlBytes && wt.allowAbsentOrigin === otherWT.allowAbsentOrigin &&
    wt.tuples.length === otherWT.tuples.length && wt.tuples.every((tuple, index) => tuple === otherWT.tuples[index]) && wt.allowedOrigins.length === otherWT.allowedOrigins.length && wt.allowedOrigins.every((origin, index) => origin === otherWT.allowedOrigins[index]);
}
/** ABI4 prepays two native datagram queues, the fixed UDP receive scratch
 * buffer and aggregate receive/send windows before connect/bind. The native
 * endpoint uses a 1472-byte maximum payload; the supported UDP runtime has at
 * most 64 GRO segments and 32 receive slots. Library heap and stream metadata
 * remain separately covered by providerRuntimeBytes. */
export function nativeRawQUICQueueBytes(options: NodeRawQUICOptions): bigint {
  const streamRead = BigInt(Math.min(16384, options.streamBufferBytes)), aggregate = BigInt(options.applicationStreams + 1) * streamRead;
  const receiveScratch = 1472n * 64n * 32n;
  return 131072n + receiveScratch + (options.webTransport === undefined ? 0n : BigInt(2 * options.webTransport.controlBytes + 4 * options.webTransport.headerBytes)) + 2n * (aggregate < 16777216n ? aggregate : 16777216n);
}
export function nodeRawQUICAdmissionCosts(maxFrame: number, options: NodeRawQUICOptions, runtimeBytes: bigint): readonly (readonly [string, ResourceVector])[] {
  const maximum = Math.max(maxFrame, 65536) + 8; requireCredential(maximum <= options.streamBufferBytes, "configuration_capacity");
  const main = new ResourceVector([options.runtimeBytes + 65536n + 16384n + 1024n + BigInt(options.applicationStreams + 1) * 128n,
    options.providerRuntimeBytes + nativeRawQUICQueueBytes(options), 0n, BigInt(options.applicationStreams + 20), 4n, 8n, 1n, 1n, 1n, 0n, 5n]);
  const position = nativeProviderStreamCharge(maximum, options.runtimeBytes, options.providerStreamBytes);
  return [["node_raw_quic", main], ...Array.from({ length: options.applicationStreams + 1 }, () => ["carrier_stream_position", position] as const),
    ["node_raw_quic_policy", credentialWorkCharge(16384, runtimeBytes)]];
}

/** Each object is tied to actual native create/accept provenance. An observer
 * cancellation never releases a handle or byte borrow before native exit. */
class RawQUICStream implements V4NativeApplicationStream {
  readonly mode = "stream" as const;
  readonly #done: Promise<void>;
  #resolve!: () => void;
  #raw: NativeRawStream | undefined;
  #creating = true;
  #closed = false;
  #nativeEnded = false;
  #released = false;
  #reading = false;
  #writing = false;
  #unobservedWrite = false;
  #tails = 0;
  #borrowed = false;
  #input: Uint8Array | undefined;
  #read: NativeOperation<Uint8Array | null> | undefined;
  #writeFailure: NativeDirectionFailure | undefined;
  #writeObserver: ((failure: NativeDirectionFailure) => void) | undefined;
  #detachWrite: (() => void) | undefined;
  #fin: Promise<void> | undefined;
  #stop: Promise<void> | undefined;
  #reset: Promise<void> | undefined;
  constructor(readonly role: "client" | "server", readonly origin: "local" | "peer" | "maintenance", readonly maximum: number,
    private position: NativeProviderStreamPosition | undefined, private checking: (() => void) | undefined, private released: (() => void) | undefined) {
    this.#done = new Promise(resolve => { this.#resolve = resolve; });
  }
  attach(raw: NativeRawStream): void {
    if (!this.#creating) throw new Error("credential_binding");
    this.#raw = raw; this.#creating = false;
    void raw.waitTermination().then(() => { this.#nativeEnded = true; if (this.#unobservedWrite) this.#writing = false; this.#finish(); }, () => { void this.close(); });
    this.#detachWrite = raw.onWriteFailure(reason => { this.#writeFailure = new NativeDirectionFailure(reason); this.#writeObserver?.(this.#writeFailure); });
    if (this.#closed) raw.abort();
  }
  creationFailed(): void { if (!this.#creating) { void this.close(); return; } this.#creating = false; this.#nativeEnded = true; void this.close(); }
  #check(): void { if (this.#closed || this.#creating || this.#nativeEnded || this.#released) throw new Error("carrier_closed"); this.position!.check(); this.checking!(); }
  observeWriteFailure(callback: (failure: NativeDirectionFailure) => void): () => void {
    if (this.#writeObserver !== undefined) throw new Error("busy");
    this.#writeObserver = callback;
    if (this.#writeFailure !== undefined) queueMicrotask(() => { if (this.#writeObserver === callback) callback(this.#writeFailure!); });
    return () => { if (this.#writeObserver === callback) this.#writeObserver = undefined; };
  }
  async read(maxBytes: number, options?: OperationOptions): Promise<Uint8Array | null> {
    this.#check(); if (options?.signal?.aborted) throw new Error("canceled");
    requireCredential(Number.isSafeInteger(maxBytes) && maxBytes > 0 && maxBytes <= this.maximum, "configuration_capacity");
    if (this.#reading) throw new Error("busy");
    this.#borrowed = false; this.#input?.fill(0); this.#input = undefined; this.#reading = true;
    const cancel = () => this.#read?.cancel();
    options?.signal?.addEventListener("abort", cancel, { once: true });
    let actual: Promise<Uint8Array | null>;
    try {
      const operation = this.#read = this.#raw!.read(Math.min(maxBytes, 16384));
      actual = operation.result().catch(error => { throw nativeFailure(error); }).then(bytes => {
        if (bytes === null) return null;
        requireCredential(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= Math.min(maxBytes, 16384) && bytes.buffer.byteLength <= 16384, "credential_binding");
        if (this.#closed || options?.signal?.aborted) { bytes.fill(0); throw new Error("canceled"); }
        this.#input = bytes; this.#borrowed = true; return bytes;
      }).finally(() => { this.#reading = false; this.#read = undefined; options?.signal?.removeEventListener("abort", cancel); this.#finish(); });
      if (options?.signal?.aborted) operation.cancel();
    } catch (error) { this.#reading = false; this.#read = undefined; options?.signal?.removeEventListener("abort", cancel); this.#finish(); throw error; }
    return observeTask(actual, options?.signal);
  }
  submit(bytes: Uint8Array, admitted: () => void, beforeSubmit?: () => void): Readonly<{ completion: Promise<void> }> | undefined {
    this.#check(); if (this.#writing || this.#fin !== undefined || this.#reset !== undefined) return undefined;
    if (this.#writeFailure !== undefined) throw this.#writeFailure;
    requireCredential(bytes.length > 0 && bytes.length <= this.maximum, "configuration_capacity");
    // Acquire custody before native submission: synchronous promise hooks may
    // close the original owner while a receipt or completion is constructed.
    beforeSubmit?.();
    this.#writing = true;
    let native;
    try { native = this.#raw!.submit(bytes); }
    catch (error) { this.#writing = false; this.#finish(); throw nativeFailure(error); }
    if (native === undefined) { this.#writing = false; this.#finish(); return undefined; }
    try { admitted(); } catch { void this.close(); }
    let completion: Promise<void>;
    try {
      completion = native.completion().catch(error => { throw nativeFailure(error); })
        .finally(() => { this.#writing = false; this.#finish(); });
    } catch {
      // A malformed provider receipt cannot erase an accepted native borrow.
      // Keep custody until the actual stream termination observation settles.
      this.#unobservedWrite = true;
      if (this.#nativeEnded) this.#writing = false;
      void this.close(); completion = this.#done.then(() => { throw new Error("carrier_failed"); });
    }
    return Object.freeze({ completion });
  }
  async write(bytes: Uint8Array, options?: OperationOptions): Promise<number> {
    if (options?.signal?.aborted) throw new Error("canceled");
    const output = this.submit(bytes, () => {}); if (output === undefined) throw new Error("carrier_closed");
    await observeTask(output.completion, options?.signal); return bytes.length;
  }
  #tail(run: () => Promise<void>): Promise<void> {
    this.#tails++; let actual: Promise<void>;
    try { actual = run(); } catch (error) { this.#tails--; this.#finish(); return Promise.reject(error); }
    return actual.finally(() => { this.#tails--; this.#finish(); });
  }
  closeWrite(): Promise<void> {
    if (this.#fin !== undefined) return this.#fin;
    // Peer STOP_SENDING may retire both physical directions before the
    // original FIN record's completion resumes in JavaScript. Native cleanup
    // is then already complete; authenticated DRAINED remains Session-owned.
    if (this.#nativeEnded) return Promise.resolve();
    this.#check();
    return this.#fin ??= this.#tail(() => this.#raw!.closeWrite()).catch(error => { throw nativeFailure(error); });
  }
  stopSending(reason?: "normal_drained"): Promise<void> {
    this.#borrowed = false;
    if (this.#creating || this.#raw === undefined || this.#nativeEnded) return Promise.resolve();
    return this.#stop ??= this.#tail(() => this.#raw!.stopSending(reason));
  }
  resetWrite(): Promise<void> {
    if (this.#fin !== undefined) return this.#fin;
    if (this.#creating || this.#raw === undefined || this.#nativeEnded) return Promise.resolve();
    return this.#reset ??= this.#tail(() => this.#raw!.resetWrite());
  }
  close(): Promise<void> {
    this.#closed = true; this.#borrowed = false; this.#read?.cancel(); this.#raw?.abort(); this.#finish(); return this.#done;
  }
  cleanupComplete(): boolean { return this.#released; }
  waitTermination(): Promise<void> { return this.#done; }
  #finish(): void {
    if (this.#released || this.#creating || !this.#nativeEnded || this.#reading || this.#writing || this.#tails !== 0 || this.#borrowed) return;
    this.#released = this.#closed = true; this.#input?.fill(0); this.#input = undefined;
    this.#detachWrite?.(); this.#detachWrite = undefined; this.#writeObserver = undefined; this.#raw = undefined; this.checking = undefined;
    this.position?.release(); this.position = undefined;
    const done = this.released; this.released = undefined; done?.(); this.#resolve();
  }
}

interface Pin { readonly digest: Uint8Array; readonly from: bigint; readonly until: bigint }
interface TLSExpectation { readonly serverName: string; readonly mode: "ca" | "pin"; readonly pins: readonly Pin[] }
export class NodeRawQUICCarrier implements V4AuthenticatedTransport {
  readonly mode = "stream" as const;
  readonly nativeStreams: V4NativeStreamProvider;
  readonly nativeDatagrams: NativeDatagrams;
  #datagramReading = false;
  #datagramRead: NativeOperation<Uint8Array> | undefined;
  readonly #done: Promise<void>;
  #resolve!: () => void;
  #session: NativeRawSession | undefined;
  #tls: NativeRawTLS | undefined;
  #preparationOwnerRelease: (() => void) | undefined;
  #preparationCompleted = false;
  #wt: NativeWebTransportRequest | undefined;
  get nativeCarrier(): "raw-quic" | "webtransport" { return this.options.nativeCarrier ?? "raw-quic"; }
  #alpn(): "h3" | "flowersec-direct/4" | "flowersec-tunnel/4" { return this.nativeCarrier === "webtransport" ? "h3" : this.path === "direct" ? "flowersec-direct/4" : "flowersec-tunnel/4"; }
  #path(): string { return this.nativeCarrier === "webtransport" ? `/flowersec/webtransport/v4/${this.path}` : ""; }
  #checkOrigin(leg: OwnedCredentialMap, node = 0, schema = "Leg"): void {
    const origin = leg.optional("origin_policy", node, schema), actual = this.#wt?.origin;
    if (this.nativeCarrier === "raw-quic") { requireCredential(origin < 0 || leg.doc.boolean(leg.field("allow_absent", origin, "OriginPolicy"))); return; }
    requireCredential(origin >= 0 && this.#wt !== undefined);
    if (actual === undefined) requireCredential(leg.doc.boolean(leg.field("allow_absent", origin, "OriginPolicy")), "credential_untrusted");
    else requireCredential([...leg.items("origins", origin, "OriginPolicy")].some(entry => leg.doc.text(entry) === actual), "credential_untrusted");
  }
  #captureWT(session: NativeRawSession): void {
    if (this.nativeCarrier !== "webtransport") { requireCredential(session.kind === "raw_quic"); return; }
    requireCredential(session.kind === "webtransport" && typeof (session as NativeWebTransportSession).request === "function");
    const request = (session as NativeWebTransportSession).request();
    requireCredential(request.scheme === "https" && request.path === this.#path() && request.authority.length > 0 && request.authority.length <= 512 && (request.origin === undefined || request.origin.length <= 4096) &&
      request.sessionFlowControl === false && request.streamPrefixes === "rfc_webtransport" && request.datagramContext === "rfc_h3_quarter_stream_id" && this.options.webTransport!.tuples.includes(request.tuple) &&
      (request.tuple === "chromium_draft02" && request.protocol === "webtransport" || request.tuple === "native_h3" && request.protocol === "webtransport-h3"), "credential_untrusted");
    this.#wt = Object.freeze({ ...request });
  }
  #maintenance: RawQUICStream | undefined;
  #acceptedMaintenance: Promise<RawQUICStream> | undefined;
  readonly #streams = new Set<RawQUICStream>();
  readonly #physical = new Map<NativeRawStream, RawQUICStream>();
  #closed = false;
  #nativeEnded = false;
  #connecting = false;
  #operations = 0;
  #accepting = false;
  #activated = false;
  #applications = false;
  #released = false;
  #connect: NativeOperation<NativeRawSession> | undefined;
  #expectation: TLSExpectation | undefined;
  #certificateEnd: bigint | undefined;
  #accepted: Readonly<{ host: string; port: number; leaf: X509Certificate }> | undefined;
  constructor(private readonly environment: V4EnvironmentRuntime, private readonly dependency: EnvironmentDependency,
    private readonly positions: NativeProviderPositions, private readonly options: NodeRawQUICOptions,
    private readonly preparation: TrustedDeadline, readonly role: "client" | "server" = "client", private readonly path: "direct" | "tunnel" = "direct",
    readonly selectedCandidateIndex = -1, private readonly preparationBudget?: NativeCandidatePreparationBudget) {
    this.#done = new Promise(resolve => { this.#resolve = resolve; });
    this.nativeStreams = Object.freeze({ capacity: options.applicationStreams, enable: () => { this.#check(); this.#applications = true; },
      open: (operation?: OperationOptions) => this.#application(true, operation), accept: (operation?: OperationOptions) => this.#application(false, operation) });
    this.nativeDatagrams = Object.freeze({ maxDatagramBytes: () => this.maxDatagramBytes(),
      receive: (maximum: number, operation?: OperationOptions) => this.receiveDatagram(maximum, operation),
      submit: (bytes: Uint8Array, admitted: () => void) => this.submitDatagram(bytes, admitted) });
    dependency.onClose(() => { void this.close(); });
  }
  #check(): void { this.dependency.check(); if (this.#closed || this.#nativeEnded || this.#session === undefined) throw new Error("carrier_closed"); }
  #captureTLS(session: NativeRawSession): void {
    requireCredential(this.#tls === undefined); const native = session.tls();
    if (!(native.peerLeafDER instanceof Uint8Array) || native.peerLeafDER.length > 65536) {
      if (native.peerLeafDER instanceof Uint8Array) native.peerLeafDER.fill(0);
      requireCredential(false, "credential_untrusted");
    }
    // ABI4 returns this bounded owned copy. Keep exactly one private snapshot
    // for the original carrier rather than recopying its leaf on each guard.
    this.#tls = Object.freeze({ version: native.version, alpn: native.alpn, earlyDataAccepted: native.earlyDataAccepted, dedicatedConnection: native.dedicatedConnection,
      peerLeafDER: native.peerLeafDER, certificateVerified: native.certificateVerified });
  }
  checkPreparation(): void {
    this.#check(); this.preparation.check();
    const tls = this.#tls!;
    requireCredential(this.#session!.wireVersion === 4 && this.#session!.path === this.path && tls.version === "TLSv1.3" && tls.alpn === this.#alpn() &&
      tls.earlyDataAccepted === false && tls.dedicatedConnection === true && tls.peerLeafDER instanceof Uint8Array && (this.role === "server" || tls.peerLeafDER.length > 0) && tls.peerLeafDER.length <= 65536 &&
      this.#session!.inboundBidirectionalStreamCapacity >= this.options.applicationStreams + 1 && typeof this.#session!.maxDatagramBytes === "function" &&
      typeof this.#session!.receiveDatagram === "function" && typeof this.#session!.submitDatagram === "function", "credential_untrusted");
    const now = this.environment.clock.sample().requireInterval();
    if (this.#certificateEnd !== undefined) requireCredential(now.upperMS < this.#certificateEnd, "credential_expired");
    const expected = this.#expectation;
    if (expected !== undefined) {
      if (expected.mode === "ca") requireCredential(tls.certificateVerified, "credential_untrusted");
      else {
        const leaf = new Uint8Array(createHash("sha256").update(tls.peerLeafDER).digest());
        try { requireCredential(expected.pins.some(pin => now.lowerMS >= pin.from && now.upperMS < pin.until && equalCredential(pin.digest, leaf)), "credential_expired"); }
        finally { leaf.fill(0); }
      }
    }
  }
  /** Called only by the configured current native listener. A dedicated
   * candidate can finish physical Prepare before accepting its peer's first
   * maintenance stream; the original carrier retains that later native tail. */
  async accept(session: NativeRawSession, endpoint: Readonly<{ host: string; port: number; leaf: X509Certificate }>, signal?: AbortSignal,
    deferMaintenance = false): Promise<void> {
    this.dependency.check(); this.preparation.check();
    requireCredential(this.role === "server" && this.#session === undefined && !this.#closed, "credential_binding");
    this.#connecting = true; this.#session = session; this.#accepted = Object.freeze({ ...endpoint });
    const cancel = () => { void this.close(); };
    signal?.addEventListener("abort", cancel, { once: true });
    try {
      void session.waitTermination().then(() => { this.#nativeEnded = true; void this.close(); this.#finish(); },
        () => { void this.close(); });
      if (signal?.aborted) throw new Error("canceled");
      this.#captureWT(session); this.#captureTLS(session); this.checkPreparation();
      const local = session.localAddress();
      requireCredential(local.port === endpoint.port && (isIP(endpoint.host) === 0 || local.host === endpoint.host), "credential_binding");
      const now = this.environment.clock.sample().requireInterval(), from = BigInt(endpoint.leaf.validFromDate.getTime()), until = BigInt(endpoint.leaf.validToDate.getTime());
      requireCredential(now.lowerMS >= from && now.upperMS < until, "credential_expired"); this.#certificateEnd = until;
      this.#checkWTAuthority(endpoint.host, endpoint.port);
      // Shared ingress ends network Prepare after the original physical
      // binding checks, before waiting for a peer's HELLO/HOP stream. A
      // dedicated candidate keeps its explicit token until the physical
      // candidate race selects and retires all other sockets.
      if (this.preparationBudget === undefined) this.completePreparation();
      if (!deferMaintenance) this.#maintenance = await this.#createStream(false, true, signal === undefined ? undefined : { signal });
      this.checkPreparation(); this.#activated = true;
    } catch (error) { void this.close(); throw error; }
    finally { this.#connecting = false; signal?.removeEventListener("abort", cancel); this.#finish(); }
  }
  /** Compare complete original signed route facts with the accepted listener,
   * never with a remote header, proxy assertion or QUIC stream number. */
  checkAcceptedRoute(fields: CarrierPreparationFields, endpointRole: 0 | 1 = 1): void {
    this.checkPreparation(); const actual = this.#accepted;
    requireCredential(this.role === "server" && actual !== undefined && fields.accessClass === 0n, "credential_binding");
    const ref = this.environment.reserveConnectionWork("accepted_raw_quic_route", credentialWorkCharge(16384, this.environment.resources.runtimeBytes));
    let work: CredentialWork | undefined;
    try {
      work = new CredentialWork(this.environment.resources, 16384, ref);
      const route = work.parse(fields.route, "Route", 16384);
      try {
        const leg = route.field(this.path === "direct" ? "direct_leg" : endpointRole === 0 ? "client_leg" : "server_leg"), tls = route.field("tls_policy", leg, "Leg");
        requireCredential(route.uint("path_kind") === (this.path === "direct" ? 0n : 1n) && route.uint("access_class", leg, "Leg") === 0n && route.uint("carrier", leg, "Leg") === (this.nativeCarrier === "webtransport" ? 2n : 0n) &&
          route.uint("dialer_role", leg, "Leg") === (this.path === "direct" ? 0n : 2n) && route.uint("listener_role", leg, "Leg") === BigInt(endpointRole) && route.text("alpn", leg, "Leg") === this.#alpn() &&
          route.text("path", leg, "Leg") === this.#path() && route.text("subprotocol", leg, "Leg") === "" && route.text("host", leg, "Leg") === actual.host &&
          route.uint("port", leg, "Leg") === BigInt(actual.port) , "credential_binding");
        this.#checkOrigin(route, leg, "Leg"); this.#checkWTAuthority(actual.host, actual.port);
        const mode = route.uint("mode", tls, "TLSPolicy");
        if (mode === 0n) requireCredential(isIP(actual.host) ? actual.leaf.checkIP(actual.host) === actual.host : actual.leaf.checkHost(actual.host, { subject: "never" }) !== undefined, "credential_binding");
        else {
          requireCredential(mode === 1n && route.uint("pin_kind", tls, "TLSPolicy") === 0n, "credential_binding");
          const now = this.environment.clock.sample().requireInterval(), window = pinProfile(actual.leaf, now), digest = new Uint8Array(createHash("sha256").update(actual.leaf.raw).digest());
          try {
            requireCredential([...route.items("pins", tls, "TLSPolicy")].some(pin => {
              const from = route.uint("not_before_ms", pin, "TLSPin"), until = route.uint("not_after_ms", pin, "TLSPin");
              return now.lowerMS >= from && now.upperMS < until && from >= window.from && until <= window.until && equalCredential(digest, route.bytes("leaf_der_sha256", pin, "TLSPin"));
            }), "credential_binding");
          } finally { digest.fill(0); }
        }
      } finally { route.close(); }
      this.checkPreparation();
    } finally { work?.close(); ref.release(); }
  }
  checkAcceptedHopRoute(credentials: VerifiedRelayCredentials, reference: ResourceReference, localRole: 0 | 1 | 2 = 2): void {
    this.checkPreparation(); credentials.check(reference); const actual = this.#accepted; requireCredential(actual !== undefined && this.path === "tunnel");
    const ref = this.environment.reserveConnectionWork("accepted_relay_quic_policy", credentialWorkCharge(16384, this.environment.resources.runtimeBytes)); let work: CredentialWork | undefined; const bytes = credentials.descriptor(reference);
    try {
      work = new CredentialWork(this.environment.resources, 16384, ref); const leg = work.parse(bytes, "Leg", 16384, 16384, { selectors: { path_kind: "tunnel" } });
      try {
        const tls = leg.field("tls_policy"), host = leg.text("host");
        requireCredential(leg.uint("carrier") === (this.nativeCarrier === "webtransport" ? 2n : 0n) && leg.uint("access_class") === 0n && leg.uint("dialer_role") === (localRole === 2 ? BigInt(credentials.role) : 2n) && leg.uint("listener_role") === BigInt(localRole) && leg.text("alpn") === this.#alpn() && leg.text("path") === this.#path() && leg.text("subprotocol") === "" && host === actual.host && leg.uint("port") === BigInt(actual.port) ); this.#checkOrigin(leg); this.#checkWTAuthority(actual.host, actual.port);
        const mode = leg.uint("mode", tls, "TLSPolicy");
        if (mode === 0n) requireCredential(isIP(host) ? actual.leaf.checkIP(host) === host : actual.leaf.checkHost(host, { subject: "never" }) !== undefined);
        else {
          requireCredential(mode === 1n && leg.uint("pin_kind", tls, "TLSPolicy") === 0n); const now = this.environment.clock.sample().requireInterval(), window = pinProfile(actual.leaf, now), digest = new Uint8Array(createHash("sha256").update(actual.leaf.raw).digest());
          try { requireCredential([...leg.items("pins", tls, "TLSPolicy")].some(pin => { const from = leg.uint("not_before_ms", pin, "TLSPin"), until = leg.uint("not_after_ms", pin, "TLSPin"); return now.lowerMS >= from && now.upperMS < until && from >= window.from && until <= window.until && equalCredential(digest, leg.bytes("leaf_der_sha256", pin, "TLSPin")); })); }
          finally { digest.fill(0); }
        }
      } finally { leg.close(); }
    } finally { bytes.fill(0); work?.close(); ref.release(); }
  }
  #checkWTAuthority(host: string, port: number): void {
    if (this.#wt === undefined) return;
    const expected = new URL(`https://${isIP(host) === 6 ? `[${host}]` : host}:${port}${this.#path()}`);
    requireCredential(this.#wt.authority === expected.host, "credential_untrusted");
  }
  async prepare(driver: NativeTransportBinding, endpoint: Readonly<{ host: string; port: number }>, expectation: TLSExpectation, signal?: AbortSignal): Promise<void> {
    this.dependency.check(); this.preparation.check();
    requireCredential(this.role === "client" && !this.#connecting && this.#session === undefined && !this.#closed, "credential_binding");
    this.#expectation = expectation; this.#connecting = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let submitted = false, tlsVerified = false;
    const cancel = (): void => { this.#connect?.cancel(); void this.close(); };
    signal?.addEventListener("abort", cancel, { once: true });
    try {
      this.dependency.check(); this.preparation.check(); if (signal?.aborted) throw new Error("canceled");
      const connectOptions: NativeRawConnectOptions = { host: endpoint.host, port: endpoint.port, serverName: expectation.serverName, path: this.path,
        inboundBidirectionalStreamCapacity: this.options.applicationStreams + 1, readBufferBytes: Math.min(16384, this.options.streamBufferBytes), datagramQueueBytes: 65536,
        handshakeTimeoutMs: Math.min(60000, Number(this.preparation.remainingMS())), ...(this.preparationBudget === undefined ? {} : { preparationBudget: this.preparationBudget }), tlsMode: expectation.mode,
        ...(expectation.mode === "ca" ? { trustRootsDer: this.options.trustRootsDER! } : { activeLeafDerSha256: expectation.pins.map(pin => pin.digest) }) };
      const operation = this.#connect = this.nativeCarrier === "raw-quic" ? driver.connectRawQuic(connectOptions) : driver.connectWebTransport({ ...connectOptions,
        connectPath: this.#path() as "/flowersec/webtransport/v4/direct" | "/flowersec/webtransport/v4/tunnel", tuple: "native_h3", headerBytes: this.options.webTransport!.headerBytes, controlBytes: this.options.webTransport!.controlBytes });
      submitted = true;
      const tick = (): void => { try { this.preparation.check(); this.dependency.check(); timer = setTimeout(tick, timerChunk(this.preparation.remainingMS())); } catch { cancel(); } };
      tick(); if (signal?.aborted) cancel();
      const actual = operation.result().then(async session => {
        this.#session = session;
        void session.waitTermination().then(() => { this.#nativeEnded = true; void this.close(); this.#finish(); }, () => { void this.close(); });
        if (this.#closed || signal?.aborted) { session.abort(); throw new Error("canceled"); }
        this.#captureWT(session); this.#captureTLS(session); this.checkPreparation(); this.#checkWTAuthority(endpoint.host, endpoint.port);
        requireCredential(this.#wt === undefined || this.#wt.origin === undefined, "credential_untrusted");
        const certificate = new X509Certificate(this.#tls!.peerLeafDER), from = BigInt(certificate.validFromDate.getTime()), until = BigInt(certificate.validToDate.getTime());
        const now = this.environment.clock.sample().requireInterval();
        requireCredential(now.lowerMS >= from && now.upperMS < until && (isIP(expectation.serverName) ? certificate.checkIP(expectation.serverName) === expectation.serverName : certificate.checkHost(expectation.serverName, { subject: "never" }) !== undefined), "credential_untrusted");
        this.#certificateEnd = until;
        if (expectation.mode === "pin") pinProfile(certificate, now);
        tlsVerified = true;
        this.#maintenance = await this.#createStream(true, true); this.checkPreparation();
      }).finally(() => { this.#connecting = false; this.#connect = undefined; if (this.#session === undefined) this.#nativeEnded = true; this.#finish(); });
      await observeTask(actual, signal);
    } catch (error) {
      // A synchronous refusal transfers no native operation. A submitted
      // connection keeps its original custody through the actual continuation.
      if (!submitted) { this.#connecting = false; this.#nativeEnded = true; }
      void this.close();
      if (!tlsVerified && error instanceof Error && ["credential_binding", "credential_untrusted", "credential_expired"].includes(error.message))
        this.environment.diagnosticCounters.observe("tls_rejection", { phase: "prepare", code: "tls_rejected" });
      if (error instanceof Error && ["handshake_failed", "pin_mismatch", "pin_certificate_invalid", "invalid_alpn"].includes(error.message)) {
        this.environment.diagnosticCounters.observe("tls_rejection", { phase: "prepare", code: "tls_rejected" });
        throw new Error("authentication_failed");
      }
      throw error;
    }
    finally { if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", cancel); }
  }
  async authenticateHop(credentials: VerifiedRelayCredentials, signer: ReadyIdentitySigner,
    random: RandomFill, resources: CredentialResources, reference: ResourceReference, options?: OperationOptions, acceptedHello?: Uint8Array, prepared?: HopAuthenticationPreparation, originalDeadline?: TrustedDeadline): Promise<void> {
    const incarnation = new Uint8Array(16); let ref: ResourceReference | HopAuthenticationPreparation | undefined = prepared, hop: HopAuthentication | undefined;
    try {
      this.checkPreparation(); requireCredential(this.path === "tunnel" && (credentials.role === 0 || credentials.role === 1));
      if (originalDeadline !== undefined) this.preparation.tightenFrom(originalDeadline);
      if (this.role === "server") this.checkAcceptedHopRoute(credentials, reference, credentials.role);
      ref ??= this.environment.reserveConnectionWork("endpoint_hop_authentication", hopAuthenticationCharge(resources.runtimeBytes));
      random(incarnation); if (!(ref instanceof HopAuthenticationPreparation)) requireCredential(ref.sameEnvironment(reference));
      hop = new HopAuthentication({ resources, transport: this, credentials, localRole: credentials.role, localIncarnation: incarnation, random, signer, deadline: this.preparation,
        guard: () => this.checkPreparation(), ...(acceptedHello === undefined ? {} : { acceptedHello }) }, ref, reference); await hop.authenticateEndpoint(options);
    } finally { hop?.close(); incarnation.fill(0); if (ref instanceof HopAuthenticationPreparation) ref.close(); else ref?.release(); }
  }
  retainPreparationOwner(release: () => void): void { requireCredential(!this.#closed && this.#preparationOwnerRelease === undefined, "credential_binding"); this.#preparationOwnerRelease = release; }
  completePreparation(): void {
    if (this.#preparationCompleted) return;
    this.checkPreparation();
    if (this.preparationBudget !== undefined) requireCredential(typeof this.#session!.completePreparation === "function", "configuration_capacity");
    this.#session!.completePreparation?.(); this.#preparationCompleted = true;
  }
  activate(): void { this.checkPreparation(); this.#activated = true; }
  exportBinding(artifactDigest: Uint8Array): Uint8Array {
    this.checkPreparation(); requireCredential(artifactDigest.length === 32 && artifactDigest.some(byte => byte !== 0));
    const output = this.#session!.exportKeyingMaterial(32, "EXPORTER-flowersec-v4", artifactDigest); requireCredential(output.length === 32); return output;
  }
  async #createStream(local: boolean, maintenance: boolean, options?: OperationOptions): Promise<RawQUICStream> {
    this.#check(); if (options?.signal?.aborted) throw new Error("canceled");
    const position = this.positions.acquire(maintenance);
    let rawBinding: NativeRawStream | undefined;
    const stream = new RawQUICStream(this.role, maintenance ? "maintenance" : local ? "local" : "peer", this.options.streamBufferBytes, position,
      () => this.#check(), () => { if (rawBinding !== undefined) this.#physical.delete(rawBinding); this.#streams.delete(stream); this.#finish(); });
    this.#streams.add(stream); this.#operations++;
    let operation: NativeOperation<NativeRawStream>, acceptHeld = false;
    try {
      this.#check(); position.check();
      if (options?.signal?.aborted) throw new Error("canceled");
      if (!local && !maintenance) {
        if (this.#accepting) throw new Error("carrier_closed");
        this.#accepting = true; acceptHeld = true;
      }
      operation = local ? this.#session!.openStream() : this.#session!.acceptStream();
    }
    catch (error) { if (acceptHeld) this.#accepting = false; stream.creationFailed(); this.#operations--; this.#finish(); throw error; }
    const cancel = () => { operation.cancel(); void stream.close(); };
    options?.signal?.addEventListener("abort", cancel, { once: true });
    const actual = operation.result().then(raw => {
      try { requireCredential(!this.#physical.has(raw), "credential_binding"); rawBinding = raw; this.#physical.set(raw, stream); stream.attach(raw); }
      catch (error) { stream.creationFailed(); void this.close(); throw error; }
      if (this.#closed || options?.signal?.aborted) { void stream.close(); throw new Error("canceled"); } return stream; }, error => { stream.creationFailed(); throw error; })
      .finally(() => { if (acceptHeld) this.#accepting = false; this.#operations--; options?.signal?.removeEventListener("abort", cancel); this.#finish(); });
    if (options?.signal?.aborted) cancel();
    return observeTask(actual, options?.signal);
  }
  async #application(local: boolean, options?: OperationOptions): Promise<RawQUICStream> {
    this.#check(); if (!this.#activated || !this.#applications || !local && this.#accepting) throw new Error("carrier_closed");
    // The native accept owns its gate through actual completion. An observer's
    // cancellation can return earlier without admitting a second native accept.
    return this.#createStream(local, false, options);
  }
  #acceptMaintenance(options?: OperationOptions): Promise<RawQUICStream> {
    this.#check();
    if (!this.#activated || this.role !== "server") return Promise.reject(new Error("carrier_closed"));
    if (options?.signal?.aborted) return Promise.reject(new Error("canceled"));
    // One original native accept owns the prepaid maintenance position through
    // actual completion. Concurrent observers never create another accept.
    this.#acceptedMaintenance ??= this.#createStream(false, true, options).then(stream => {
      this.#check(); this.#maintenance = stream; return stream;
    });
    return observeTask(this.#acceptedMaintenance, options?.signal);
  }
  read(maxBytes: number, options?: OperationOptions): Promise<Uint8Array | null> {
    this.#check(); if (!this.#activated) return Promise.reject(new Error("carrier_closed"));
    return this.#maintenance === undefined ? this.#acceptMaintenance(options).then(stream => stream.read(maxBytes, options)) : this.#maintenance.read(maxBytes, options);
  }
  write(bytes: Uint8Array, options?: OperationOptions): Promise<number> {
    this.#check(); if (!this.#activated) return Promise.reject(new Error("carrier_closed"));
    return this.#maintenance === undefined ? this.#acceptMaintenance(options).then(stream => stream.write(bytes, options)) : this.#maintenance.write(bytes, options);
  }
  submit(bytes: Uint8Array, admitted: () => void, beforeSubmit?: () => void): Readonly<{ completion: Promise<void> }> | undefined { this.#check(); if (!this.#activated || this.#maintenance === undefined) return undefined; return this.#maintenance.submit(bytes, admitted, beforeSubmit); }
  maxDatagramBytes(): number {
    this.#check(); const maximum = this.#session!.maxDatagramBytes();
    if (!Number.isSafeInteger(maximum) || maximum < 0) throw new Error("carrier_failed");
    return Math.min(maximum, 1024);
  }
  async receiveDatagram(maximum: number, options?: OperationOptions): Promise<Uint8Array> {
    this.#check(); if (!this.#activated || !this.#applications || this.#datagramReading || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1024) throw new Error("carrier_closed");
    if (options?.signal?.aborted) throw new Error("canceled");
    this.#datagramReading = true; this.#operations++;
    let operation: NativeOperation<Uint8Array> | undefined;
    const cancel = () => operation?.cancel();
    try {
      operation = this.#datagramRead = this.#session!.receiveDatagram(maximum);
      if (this.#closed || options?.signal?.aborted) operation.cancel();
      options?.signal?.addEventListener("abort", cancel, { once: true }); if (options?.signal?.aborted) cancel();
      const bytes = await operation.result();
      try {
        this.#check(); if (options?.signal?.aborted) throw new Error("canceled");
        if (!(bytes instanceof Uint8Array) || bytes.length > maximum) throw new Error("carrier_failed");
        return new Uint8Array(bytes);
      } finally { bytes.fill(0); }
    } finally { options?.signal?.removeEventListener("abort", cancel); this.#datagramRead = undefined; this.#datagramReading = false; this.#operations--; this.#finish(); }
  }
  submitDatagram(bytes: Uint8Array, admitted: () => void): Readonly<{ completion: Promise<void> }> | undefined {
    this.#check(); if (!this.#activated || !this.#applications || bytes.length > this.maxDatagramBytes()) return undefined;
    const receipt = this.#session!.submitDatagram(bytes); if (receipt === undefined) return undefined;
    this.#operations++;
    let acknowledgment: unknown;
    try { admitted(); } catch (error) { acknowledgment = error; }
    const completion = (async () => {
      try { await receipt.completion(); if (acknowledgment !== undefined) throw acknowledgment; }
      finally { this.#operations--; this.#finish(); }
    })();
    return Object.freeze({ completion });
  }
  close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true; this.#connect?.cancel(); this.#datagramRead?.cancel(); this.positions.close();
      for (const stream of Array.from(this.#streams)) void stream.close();
      this.#session?.abort();
      if (this.#session === undefined && !this.#connecting) this.#nativeEnded = true;
    }
    this.#finish(); return this.#done;
  }
  waitTermination(): Promise<void> { return this.#done; }
  #finish(): void {
    if (this.#released || !this.#closed || !this.#nativeEnded || this.#connecting || this.#operations !== 0 || this.#streams.size !== 0 || !this.positions.cleanupComplete()) return;
    this.#released = true; this.#maintenance = undefined; this.#acceptedMaintenance = undefined; this.#session = undefined; this.#accepted = undefined; this.#tls?.peerLeafDER.fill(0); this.#tls = undefined; this.#wt = undefined;
    for (const pin of this.#expectation?.pins ?? []) pin.digest.fill(0); this.#expectation = undefined;
    this.#preparationOwnerRelease?.(); this.#preparationOwnerRelease = undefined; this.dependency.release(); this.#resolve();
  }
}

export function nodeRawQUICRouteCarrier(environment: V4EnvironmentRuntime, candidate: Pick<CarrierPreparationFields, "route" | "pathKind" | "accessClass">, endpointRole: 0 | 1 = 0, admission?: ClientSessionAdmission): "raw-quic" | "webtransport" {
  const reference = environment.reserveConnectionWork("node_raw_quic_candidate_route", credentialWorkCharge(16384, environment.resources.runtimeBytes), admission);
  let work: CredentialWork | undefined;
  try {
    work = new CredentialWork(environment.resources, 16384, reference);
    const route = work.parse(candidate.route, "Route", 16384);
    try {
      requireCredential(route.uint("path_kind") === BigInt(candidate.pathKind), "credential_binding");
      const leg = route.field(candidate.pathKind === 0 ? "direct_leg" : endpointRole === 0 ? "client_leg" : "server_leg"), carrier = route.uint("carrier", leg, "Leg");
      requireCredential(route.uint("access_class", leg, "Leg") === candidate.accessClass && (carrier === 0n || carrier === 2n), "credential_untrusted");
      return carrier === 2n ? "webtransport" : "raw-quic";
    } finally { route.close(); }
  } finally { work?.close(); reference.release(); }
}

/** Attempts only the verifier-authorized candidate order, with one separately
 * prepaid carrier plan per attempt. A failed provider is fully retired by
 * prepareNodeRawQUIC before the next candidate can consume its plan. */
export async function prepareNodeRawQUICCandidates(environment: V4EnvironmentRuntime, fields: CarrierPreparationFields,
  configured: readonly NodeRawQUICOptions[], drivers: Readonly<Partial<Record<"raw-quic" | "webtransport", NativeTransportBinding>>>,
  signal?: AbortSignal, admission?: ClientSessionAdmission, endpointRole: 0 | 1 = 0, physicalDialerRole: 0 | 1 | 2 = endpointRole,
  attemptLimit = fields.totalCandidateAttempts ?? 1): Promise<NodeRawQUICCarrier> {
  const candidates = fields.candidates ?? [], preferred = fields.candidateIndex ?? candidates[0]?.candidateIndex ?? -1;
  requireCredential(candidates.length > 0 && candidates.some(value => value.candidateIndex === preferred) && Number.isSafeInteger(attemptLimit) && attemptLimit >= 1 && attemptLimit <= 16, "credential_binding");
  if (fields.source === "preauthorized_pool") requireCredential(fields.preparationWork >= 1, "configuration_capacity");
  const signedLimit = fields.totalCandidateAttempts ?? 1;
  requireCredential(Number.isSafeInteger(signedLimit) && signedLimit >= 1, "credential_binding");
  const ordered = [candidates.find(value => value.candidateIndex === preferred)!, ...candidates.filter(value => value.candidateIndex !== preferred)].slice(0, Math.min(attemptLimit, signedLimit));
  const owner = originalNodeNativePreparationOwner(environment, fields, drivers[configured[0]?.nativeCarrier ?? "raw-quic"]!, admission);
  let lastError: unknown;
  try { for (const candidate of ordered) {
    if (signal?.aborted) throw new Error("canceled");
    fields.preparationDeadline.check();
    requireCredential(candidate.pathKind === fields.pathKind, "credential_binding");
    const kind = nodeRawQUICRouteCarrier(environment, candidate, endpointRole, admission), options = configured.find(value => (value.nativeCarrier ?? "raw-quic") === kind), driver = drivers[kind];
    if (options === undefined || driver === undefined) continue;
    const selected = Object.freeze({ ...fields, ...candidate });
    let carrier: NodeRawQUICCarrier | undefined;
    try {
      carrier = await prepareNodeRawQUIC(environment, selected, options, driver, signal, admission, endpointRole, physicalDialerRole, candidate.candidateIndex, owner.candidate(selected));
      // Network Prepare ends before durable spend. Activated HOP has its own
      // original Grant quota and cannot consume this candidate's UDP cap.
      carrier.completePreparation(); owner.transfer(carrier); return carrier;
    }
    catch (error) {
      if (carrier !== undefined) await Promise.allSettled([carrier.close(), carrier.waitTermination()]);
      lastError = error;
      const code = error instanceof Error ? error.message : "";
      if (signal?.aborted || ["canceled", "credential_binding", "credential_untrusted", "credential_expired", "credential_closed", "configuration_capacity", "resource_exhausted", "admission_closed", "required_guarantee_unavailable"].includes(code)) throw error;
    }
  }
  if (lastError !== undefined) throw lastError;
  throw new Error("connection_requirement_unavailable");
  } finally { owner.releaseUnused(); }
}

export async function prepareNodeRawQUIC(environment: V4EnvironmentRuntime, fields: CarrierPreparationFields, options: NodeRawQUICOptions,
  driver: NativeTransportBinding, signal?: AbortSignal, admission?: ClientSessionAdmission, endpointRole: 0 | 1 = 0, physicalDialerRole: 0 | 1 | 2 = endpointRole,
  selectedCandidateIndex = fields.candidateIndex ?? -1, preparationBudget?: NativeCandidatePreparationBudget): Promise<NodeRawQUICCarrier> {
  requireCredential(fields.accessClass === 0n, "credential_untrusted");
  const costs = nodeRawQUICAdmissionCosts(fields.maxFrame, options, environment.resources.runtimeBytes), refs = admission?.take(costs.slice(0, -1));
  let reserved: ReturnType<V4EnvironmentRuntime["admitDependencyPositions"]>;
  try { reserved = environment.admitDependencyPositions("node_raw_quic", costs[0]![1], costs[1]![1], options.applicationStreams + 1, refs, admission); }
  finally { for (const ref of refs ?? []) ref.release(); }
  const { dependency, positions: prepaid } = reserved;
  let positions: NativeProviderPositions | undefined, carrier: NodeRawQUICCarrier | undefined, work: CredentialWork | undefined;
  try {
    positions = new NativeProviderPositions(prepaid);
    const ref = environment.reserveConnectionWork("node_raw_quic_policy", costs[costs.length - 1]![1], admission);
    try { work = new CredentialWork(environment.resources, 16384, ref); } finally { ref.release(); }
    const route = work.parse(fields.route, "Route", 16384);
    let endpoint: { host: string; port: number }, expectation: TLSExpectation;
    try {
      const leg = route.field(fields.pathKind === 0 ? "direct_leg" : endpointRole === 0 ? "client_leg" : "server_leg"), tls = route.field("tls_policy", leg, "Leg"), origin = route.optional("origin_policy", leg, "Leg");
      requireCredential(route.uint("path_kind") === BigInt(fields.pathKind) && route.uint("access_class", leg, "Leg") === 0n && route.uint("carrier", leg, "Leg") === (options.nativeCarrier === "webtransport" ? 2n : 0n) &&
        route.uint("endpoint_role", leg, "Leg") === (fields.pathKind === 0 ? 1n : BigInt(endpointRole)) && route.uint("dialer_role", leg, "Leg") === BigInt(physicalDialerRole) && route.uint("listener_role", leg, "Leg") === (fields.pathKind === 0 ? 1n : physicalDialerRole === 2 ? BigInt(endpointRole) : 2n) && route.text("path", leg, "Leg") === (options.nativeCarrier === "webtransport" ? `/flowersec/webtransport/v4/${fields.pathKind === 0 ? "direct" : "tunnel"}` : "") &&
        route.text("subprotocol", leg, "Leg") === "" && route.text("alpn", leg, "Leg") === (options.nativeCarrier === "webtransport" ? "h3" : fields.pathKind === 0 ? "flowersec-direct/4" : "flowersec-tunnel/4") && (origin < 0 ? options.nativeCarrier !== "webtransport" : route.doc.boolean(route.field("allow_absent", origin, "OriginPolicy"))), "credential_untrusted");
      endpoint = { host: route.text("host", leg, "Leg"), port: Number(route.uint("port", leg, "Leg")) };
      const mode = route.uint("mode", tls, "TLSPolicy"), pins: Pin[] = [], now = environment.clock.sample().requireInterval();
      if (mode === 0n) requireCredential(options.trustRootsDER !== undefined, "configuration_capacity");
      else {
        requireCredential(mode === 1n && route.uint("pin_kind", tls, "TLSPolicy") === 0n, "credential_untrusted");
        for (const pin of route.items("pins", tls, "TLSPolicy")) {
          const from = route.uint("not_before_ms", pin, "TLSPin"), until = route.uint("not_after_ms", pin, "TLSPin");
          if (now.lowerMS >= from && now.upperMS < until) pins.push({ from, until, digest: route.bytes("leaf_der_sha256", pin, "TLSPin") });
        }
        requireCredential(pins.length > 0 && pins.length <= 16, "credential_expired");
      }
      expectation = { serverName: endpoint.host, mode: mode === 0n ? "ca" : "pin", pins };
    } finally { route.close(); work.close(); work = undefined; }
    carrier = new NodeRawQUICCarrier(environment, dependency, positions, options, fields.preparationDeadline, "client", fields.pathKind === 0 ? "direct" : "tunnel", selectedCandidateIndex, preparationBudget);
    await carrier.prepare(driver, endpoint, expectation, signal); requireCredential((fields.required & 1n) === 0n || carrier.maxDatagramBytes() >= 76, "required_guarantee_unavailable"); return carrier;
  } catch (error) {
    work?.close();
    if (carrier !== undefined) await Promise.allSettled([carrier.close(), carrier.waitTermination()]);
    else { positions?.close(); for (const position of prepaid) position.closeAfterUse(); dependency.release(); }
    throw error;
  }
}

/** Relay dialing is selected from the original verified server Grant. No
 * endpoint Session fields or direct route are manufactured for this hop. */
export function rawQUICRelayDialPolicy(environment: V4EnvironmentRuntime, credentials: VerifiedRelayCredentials, options: NodeRawQUICOptions, reference: ResourceReference): Readonly<{ endpoint: Readonly<{ host: string; port: number }>; expectation: TLSExpectation }> {
  credentials.check(reference);
  const ref = environment.reserveConnectionWork("relay_quic_dial_policy", credentialWorkCharge(16384, environment.resources.runtimeBytes)); let work: CredentialWork | undefined;
  const bytes = credentials.descriptor(reference);
  try {
    work = new CredentialWork(environment.resources, 16384, ref); const leg = work.parse(bytes, "Leg", 16384, 16384, { selectors: { path_kind: "tunnel" } });
    try {
      const tls = leg.field("tls_policy"), origin = leg.optional("origin_policy");
      requireCredential(leg.uint("carrier") === (options.nativeCarrier === "webtransport" ? 2n : 0n) && leg.uint("access_class") === 0n && leg.uint("dialer_role") === 2n && leg.uint("listener_role") === BigInt(credentials.role) && leg.text("alpn") === (options.nativeCarrier === "webtransport" ? "h3" : "flowersec-tunnel/4") && leg.text("path") === (options.nativeCarrier === "webtransport" ? "/flowersec/webtransport/v4/tunnel" : "") && leg.text("subprotocol") === "" && (origin < 0 || leg.doc.boolean(leg.field("allow_absent", origin, "OriginPolicy"))));
      const host = leg.text("host"), port = Number(leg.uint("port")), mode = leg.uint("mode", tls, "TLSPolicy"), pins: Pin[] = [], now = environment.clock.sample().requireInterval();
      if (mode === 0n) requireCredential(options.trustRootsDER !== undefined, "configuration_capacity");
      else { requireCredential(mode === 1n && leg.uint("pin_kind", tls, "TLSPolicy") === 0n); for (const pin of leg.items("pins", tls, "TLSPolicy")) {
        const from = leg.uint("not_before_ms", pin, "TLSPin"), until = leg.uint("not_after_ms", pin, "TLSPin"); if (now.lowerMS >= from && now.upperMS < until) pins.push({ from, until, digest: leg.bytes("leaf_der_sha256", pin, "TLSPin") });
      } requireCredential(pins.length > 0, "credential_expired"); }
      return Object.freeze({ endpoint: Object.freeze({ host, port }), expectation: Object.freeze({ mode: mode === 0n ? "ca" : "pin", serverName: host, pins: Object.freeze(pins) }) });
    } finally { leg.close(); }
  } finally { bytes.fill(0); work?.close(); ref.release(); }
}
