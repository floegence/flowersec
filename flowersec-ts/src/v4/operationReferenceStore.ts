import type { V4TransportEnvironment } from "./public.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "./streamHandlers.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import { encodeOperationReference, operationReferenceState, type V4OperationReference } from "./operationReference.js";
import { originalEnvironment, type V4EnvironmentRuntime, type EnvironmentDependency } from "./runtime/environment.js";
import { ResourceVector, type ProtectedResourceReservation, type ResourceReference } from "./runtime/resources.js";
import { type ApplicationGroup, type ApplicationPermit, type ApplicationWorkClass } from "./runtime/applicationExecutor.js";
import type { SessionCleanup } from "./runtime/sessionCleanup.js";
import { cleanupResult } from "./runtime/lifecycle.js";
import { timeAdd } from "./runtime/timeArithmetic.js";

export type V4ReferenceSaveOutcome = "confirmed" | "conflict" | "rejected" | "unknown";
export interface V4ReferenceStorePolicy {
  readonly targetDomain: string;
  readonly durability: "durable_create_or_compare";
  /** Application-owned backend enforces these shared quotas and expiration. */
  readonly storage: "application_owned";
  readonly maxRecords: number;
  /** Sum of canonical reference bytes; backend pages/indexes are application-owned. */
  readonly maxStoredBytes: bigint;
  readonly retentionMS: bigint;
  readonly maxConcurrentSaves: number;
  readonly applicationBytes: bigint;
  readonly workClass?: ApplicationWorkClass;
}
export interface V4ReferenceStoreRecord {
  /** Full logical operation identity, excluding payload/contract digests. */
  readonly identity: string;
  readonly reference: V4OperationReference;
  /** Borrowed only until the actual save callback settles. Copy to retain. */
  readonly canonical: Uint8Array;
  readonly retainUntilMS: bigint;
}
/** Confirm only after durable create-or-compare of the complete canonical
 * bytes. Same identity with different bytes is a conflict. Unknown commits
 * stay unknown; this callback must never dispatch, replay or create an outbox. */
export type V4ReferenceStoreSave = (context: V4ApplicationContext, record: V4ReferenceStoreRecord,
  policy: Readonly<V4ReferenceStorePolicy>) => Promise<V4ReferenceSaveOutcome>;
export type V4ReferenceSaveFailure = "canceled" | "closed" | "deadline_exceeded" | "resource_exhausted" | "preparation_failed" | "save_unknown" | "save_conflict" | "save_rejected" | "admission_mode_incompatible";
export interface V4ReferenceSaveStatus { readonly attempted: boolean; readonly outcome: V4ReferenceSaveOutcome }
export interface ReferenceSaveReport {
  readonly save: V4ReferenceSaveStatus;
  readonly failure?: V4ReferenceSaveFailure;
  readonly cleanup: V4CleanupStatus;
}
const capability = Symbol("admitted reference store"), NativePromise = Promise;
const add = EventTarget.prototype.addEventListener, remove = EventTarget.prototype.removeEventListener;
const aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const complete = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const initial = Object.freeze({ attempted: false, outcome: "unknown" as const });
export function referenceSaveFailure(error: unknown): V4ReferenceSaveFailure {
  const message = error instanceof Error ? error.message : "";
  return message === "admission_mode_incompatible" ? "admission_mode_incompatible" : message === "canceled" ? "canceled" : message === "closed" || message === "service_binding_closed" || message === "rpc_request_closed" ? "closed" :
    message === "time_expired" ? "deadline_exceeded" : (message === "resource_exhausted" || message === "would_block") ? "resource_exhausted" : "preparation_failed";
}
export function referenceSaveReport<T extends ReferenceSaveReport>(value: T): Readonly<T> {
  Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
}
export interface ReferenceSaveInvocation {
  readonly reference: V4OperationReference;
  readonly owner: ResourceReference;
  readonly group: ApplicationGroup;
  readonly authentication: V4AuthenticatedContext;
  readonly cleanup: SessionCleanup;
  readonly signal: AbortSignal;
  readonly context?: V4ApplicationContext;
  readonly immediate: boolean;
  readonly check: () => void;
  /** SDK-only release after the actual store task, including a late callback. */
  readonly settled?: () => void;
}
/** One local adapter registration. Persistent records and their retention are
 * owned by the declared application backend, independently of this SDK owner. */
export class V4OperationReferenceStore {
  #dependency: EnvironmentDependency | undefined;
  #save: V4ReferenceStoreSave | undefined;
  readonly #positions: readonly ProtectedResourceReservation[];
  readonly #active = new Set<ReferenceSaveAttempt>();
  readonly #policy: Readonly<V4ReferenceStorePolicy>;
  #closed = false;
  constructor(token: symbol, dependency: EnvironmentDependency, positions: readonly ProtectedResourceReservation[], policy: Readonly<V4ReferenceStorePolicy>, save: V4ReferenceStoreSave) {
    if (token !== capability) throw new Error("reference_store_owner");
    this.#dependency = dependency; this.#positions = positions; this.#policy = policy; this.#save = save;
    dependency.onClose(() => this.close()); Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#save = undefined; storeClocks.delete(this);
    for (const attempt of this.#active) attempt.cancel("closed");
    for (const position of this.#positions) position.closeAfterUse(); this.#collect();
  }
  cleanupStatus(): V4CleanupStatus {
    if (this.#dependency === undefined) return complete;
    return cleanupResult({ status: "pending", core_cleanup: "pending", pending_callbacks: BigInt([...this.#active].filter(attempt => attempt.callbackActive).length) });
  }
  toJSON(): object { return {}; }
  /** SDK composition only; never calls application code during this check. */
  checkDomain(domain: string): void {
    if (this.#closed) throw new Error("closed"); this.#dependency!.check();
    if (domain !== this.#policy.targetDomain) throw new Error("operation_reference_domain");
  }
  begin(token: symbol, input: ReferenceSaveInvocation, retainUntilMS: bigint): ReferenceSaveAttempt {
    if (token !== capability) throw new Error("reference_store_owner");
    this.checkDomain(operationReferenceState(input.reference).domain);
    if (!this.#dependency!.reference.sameEnvironment(input.owner)) throw new Error("reference_store_owner");
    const position = this.#positions.find(entry => entry.available());
    if (position === undefined) throw new Error("resource_exhausted");
    const reference = position.checkout();
    let attempt: ReferenceSaveAttempt | undefined;
    try {
      attempt = new ReferenceSaveAttempt(input, this.#policy, this.#save!, retainUntilMS, reference,
        () => { this.#active.delete(attempt!); this.#collect(); });
      this.#active.add(attempt); attempt.start(); return attempt;
    } catch (error) { reference.release(); throw error; }
  }
  #collect(): void { if (!this.#closed || this.#active.size !== 0) return; const dependency = this.#dependency; this.#dependency = undefined; dependency?.release(); }
}
/** Physical store work only retains this compact job after its observer exits.
 * Cancellation clears the original preparation check before waking callers. */
class ReferenceSaveAttempt {
  #reference: ResourceReference | undefined;
  #check: (() => void) | undefined;
  #save: V4ReferenceStoreSave | undefined;
  #group: ApplicationGroup | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #cleanup: SessionCleanup | undefined;
  #context: V4ApplicationContext | undefined;
  #record: V4ReferenceStoreRecord | undefined;
  #inputSignal: AbortSignal | undefined;
  #bytes = new Uint8Array(2048);
  readonly #abort = new AbortController();
  #resolve: ((value: ReferenceSaveReport) => void) | undefined;
  readonly promise = new NativePromise<ReferenceSaveReport>(resolve => { this.#resolve = resolve; });
  #status: V4ReferenceSaveStatus = initial;
  #canceled = false;
  #callback = false;
  #job = false;
  #settled: (() => void) | undefined;
  constructor(input: ReferenceSaveInvocation, readonly policy: Readonly<V4ReferenceStorePolicy>, save: V4ReferenceStoreSave,
    retainUntilMS: bigint, reference: ResourceReference, readonly released: () => void) {
    this.#settled = input.settled;
    this.#reference = reference; this.#check = input.check; this.#save = save; this.#group = input.group;
    this.#authentication = input.authentication; this.#cleanup = input.cleanup; this.#context = input.context;
    this.immediate = input.immediate; this.#inputSignal = input.context === undefined ? input.signal : AbortSignal.any([input.signal, input.context.signal]);
    try {
      const state = operationReferenceState(input.reference), t = state.target;
      this.#record = Object.freeze({ identity: [state.domain, t.tenant, t.audience, t.namespace, t.authority, t.subject, t.operation].join("\0"),
        reference: input.reference, canonical: encodeOperationReference(input.reference, this.#bytes), retainUntilMS });
      this.#cleanup.startJob(); this.#job = true;
    } catch (error) { this.#bytes.fill(0); reference.release(); throw error; }
  }
  readonly immediate: boolean;
  get callbackActive(): boolean { return this.#callback; }
  start(): void {
    add.call(this.#inputSignal, "abort", this.#canceledInput, { once: true });
    if (aborted.call(this.#inputSignal)) this.cancel("canceled");
    void this.#run();
  }
  readonly #canceledInput = (): void => { this.cancel("canceled"); };
  cancel(failure: V4ReferenceSaveFailure): void {
    if (this.#canceled) return; this.#canceled = true;
    this.#check = undefined; this.#context = undefined; this.#detach(); this.#abort.abort();
    this.#deliver(failure);
  }
  #detach(): void { if (this.#inputSignal !== undefined) remove.call(this.#inputSignal, "abort", this.#canceledInput); this.#inputSignal = undefined; }
  #checkEntry = (): void => {
    if (this.#canceled || this.#abort.signal.aborted) throw new Error("canceled"); this.#reference!.check(); this.#check!();
    if (this.#canceled) throw new Error("canceled");
  };
  async #run(): Promise<void> {
    let permit: ApplicationPermit | undefined, failure: V4ReferenceSaveFailure | undefined, returned = false;
    try {
      this.#checkEntry();
      permit = this.immediate ? this.#group!.tryOrdinary(this.policy.workClass!, this.#context)
        : await this.#group!.acquire(this.policy.workClass!, this.#abort.signal, this.#checkEntry, this.#context);
      this.#checkEntry(); this.#context = undefined;
      const invocation = this.#group!.context(permit, this.#authentication!, this.#abort.signal);
      try {
        this.#cleanup!.enterCallback(); this.#callback = true;
        this.#status = Object.freeze({ attempted: true, outcome: "unknown" });
        const outcome = await this.#save!(invocation.context, this.#record!, this.policy); returned = true;
        if (["confirmed", "conflict", "rejected", "unknown"].includes(outcome)) this.#status = Object.freeze({ attempted: true, outcome });
      } finally { invocation.release(); }
      this.#checkEntry();
      if (this.#status.outcome !== "confirmed") failure = this.#status.outcome === "conflict" ? "save_conflict" : this.#status.outcome === "rejected" ? "save_rejected" : "save_unknown";
    } catch (error) { failure = this.#status.attempted && !returned ? "save_unknown" : referenceSaveFailure(error); }
    finally {
      permit?.release(); this.#detach(); this.#check = this.#save = undefined; this.#group = undefined; this.#authentication = undefined; this.#context = undefined; this.#record = undefined;
      this.#bytes.fill(0); this.#bytes = new Uint8Array();
      if (this.#callback) this.#cleanup!.exitCallback(); this.#callback = false;
      const cleanup = this.#cleanup; this.#cleanup = undefined; if (this.#job) { this.#job = false; cleanup!.finishJob(); }
      this.#reference?.release(); this.#reference = undefined; this.released(); const settled = this.#settled; this.#settled = undefined; settled?.(); this.#deliver(failure);
    }
  }
  #deliver(failure?: V4ReferenceSaveFailure): void {
    const resolve = this.#resolve; this.#resolve = undefined;
    const cleanup = this.#reference === undefined ? complete : cleanupResult({ status: "pending", core_cleanup: "pending", pending_callbacks: this.#callback ? 1n : 0n });
    resolve?.(referenceSaveReport({ save: this.#status, cleanup, ...(failure === undefined ? {} : { failure }) }));
  }
}
export function beginReferenceSave(store: V4OperationReferenceStore, input: ReferenceSaveInvocation, retainUntilMS: bigint): Promise<ReferenceSaveReport> {
  return store.begin(capability, input, retainUntilMS).promise;
}
export function createV4OperationReferenceStore(environment: V4TransportEnvironment, policy: V4ReferenceStorePolicy, save: V4ReferenceStoreSave): V4OperationReferenceStore {
  return createOperationReferenceStore(originalEnvironment(environment), policy, save);
}
const storeClocks = new WeakMap<V4OperationReferenceStore, () => bigint>();
export function referenceStoreRetention(store: V4OperationReferenceStore): bigint {
  const sample = storeClocks.get(store); if (sample === undefined) throw new Error("reference_store_owner"); return sample();
}
/** Original assembler entry, shared by public and provider composition. */
export function createOperationReferenceStore(environment: V4EnvironmentRuntime, input: V4ReferenceStorePolicy, save: V4ReferenceStoreSave): V4OperationReferenceStore {
  const { targetDomain, durability, storage, maxRecords, maxStoredBytes, retentionMS, maxConcurrentSaves, applicationBytes, workClass = "resident" } = input;
  if (typeof save !== "function" || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(targetDomain) || durability !== "durable_create_or_compare" || storage !== "application_owned" ||
      !Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 1048576 || typeof maxStoredBytes !== "bigint" || maxStoredBytes < 2048n || maxStoredBytes > (1n << 63n) - 1n ||
      typeof retentionMS !== "bigint" || retentionMS <= 0n || retentionMS >= 1n << 64n || !Number.isSafeInteger(maxConcurrentSaves) || maxConcurrentSaves < 1 || maxConcurrentSaves > 64 ||
      typeof applicationBytes !== "bigint" || applicationBytes < 0n || applicationBytes > 16n * 1048576n || workClass !== "short" && workClass !== "resident") throw new Error("configuration_capacity");
  const policy = Object.freeze({ targetDomain, durability, storage, maxRecords, maxStoredBytes, retentionMS, maxConcurrentSaves, applicationBytes, workClass });
  const runtimeBytes = environment.resources.runtimeBytes;
  const charge = new ResourceVector([4096n + BigInt(maxConcurrentSaves) * 128n + runtimeBytes, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const job = new ResourceVector([8192n + 4n * runtimeBytes + applicationBytes, 0n, 0n, 8n, 1n, 3n, 1n, 0n, 0n, 0n, 0n]);
  const { dependency, positions } = environment.admitDependencyPositions("reference_store", charge, job, maxConcurrentSaves);
  try {
    const store = new V4OperationReferenceStore(capability, dependency, positions, policy, save), clock = environment.clock;
    dependency.check(); storeClocks.set(store, () => timeAdd(clock.sample().requireInterval().lowerMS, retentionMS)); return store;
  } catch (error) { for (const position of positions) position.close(); dependency.release(); throw error; }
}
Object.freeze(V4OperationReferenceStore.prototype); Object.freeze(V4OperationReferenceStore);
