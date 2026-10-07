import { noResponsePublication, type ResponsePublication } from "../responsePublication.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import type { V4OutputInterest, V4UnaryContext } from "../serviceHandlers.js";
import type { ResourceRoot} from "./resources.js";
import { ResourceError, ResourceVector, type ResourceReference, type ResourceServiceReference, type ResourceAccount, type ResourceOwner } from "./resources.js";
import { FixedManagementExecutor, type ManagementPermit } from "./fixedManagementExecutor.js";
import { FixedQueryExecutor, type FixedQueryProtection } from "./fixedQueryExecutor.js";
import { TimeError } from "./timeArithmetic.js";
import { V4ReadMethodError } from "../public.js";

export type ApplicationWorkClass = "short" | "resident";
type Lane = ApplicationWorkClass | "completion";
const enqueue = queueMicrotask;
interface OrdinaryEnvelope {
  readonly bytes: bigint;
  readonly running: number;
  readonly ready: number;
  readonly residentRunning: number;
  readonly residentReady: number;
}
const completionRunning = 2, completionReady = 4, completionOwners = 4096, maximumDepth = 8;
const services = new WeakMap<ResourceRoot, ApplicationExecutor>();
const contexts = new WeakMap<V4ApplicationContext, Invocation>();
interface Invocation {
  readonly permit: ApplicationPermit;
  readonly ancestors: readonly ApplicationPermit[];
  active: boolean;
  depth: number;
  readonly onExit: Set<() => void>;
}
interface Pending {
  readonly group: ApplicationGroup;
  readonly lane: Lane;
  readonly signal: AbortSignal;
  readonly check: () => void;
  readonly cancel: () => void;
  readonly resolve: (permit: ApplicationPermit) => void;
  readonly reject: (error: Error) => void;
  readonly claim: CompletionClaim | undefined;
  readonly parent: V4ApplicationContext | undefined;
}
function unavailable(): never { throw new Error("dependency_unavailable"); }
function invocation(context: V4ApplicationContext | undefined): Invocation | undefined {
  if (context === undefined) return;
  const state = contexts.get(context);
  if (state === undefined || !state.active || state.permit.released || context.signal.aborted) unavailable();
  return state;
}
export function applicationHasPermit(context: V4ApplicationContext | undefined): boolean { return invocation(context) !== undefined; }
export function applicationWorkClass(workClass: ApplicationWorkClass, context?: V4ApplicationContext): ApplicationWorkClass {
  if (workClass !== "short" && workClass !== "resident") throw new Error("owner_unavailable");
  const state = invocation(context);
  return state !== undefined && [state.permit, ...state.ancestors].some(permit => !permit.released && permit.lane === "resident") ? "resident" : workClass;
}
export function applicationHasCompletionAncestor(context: V4ApplicationContext | undefined): boolean {
  const state = invocation(context);
  return state !== undefined && [state.permit, ...state.ancestors].some(permit => permit.lane === "completion" && !permit.released);
}
export function applicationDependsOn(context: V4ApplicationContext | undefined, target: V4ApplicationContext | undefined): boolean {
  const state = invocation(context), other = target === undefined ? undefined : contexts.get(target);
  return state !== undefined && other?.active === true && !other.permit.released &&
    (state.permit === other.permit || state.ancestors.includes(other.permit));
}

/** An unstarted claim consumes protected capacity, but is not a running job. */
export class CompletionClaim {
  active = true;
  detachParent: (() => void) | undefined;
  constructor(readonly executor: ApplicationExecutor, readonly group: ApplicationGroup) {}
  release(): void { if (!this.active) return; this.active = false; this.detachParent?.(); this.detachParent = undefined; this.executor.returnClaim(this); }
}

/** An original ordinary position held before acquisition. It becomes a running
 * callback only at checkout; conversion transfers the same group reference. */
export class ApplicationStartPosition {
  active = true;
  constructor(readonly executor: ApplicationExecutor, readonly group: ApplicationGroup, readonly lane: ApplicationWorkClass) {}
  checkout(): ApplicationPermit { return this.executor.startReserved(this); }
  close(): void { if (this.active) this.executor.returnStart(this); }
}

/** A dormant result descriptor is charged by its message/result owner. It
 * reserves no execution slot and never decodes without a current receiver. */
export class CompletionReservation {
  #active = true;
  #waiting = false;
  #returned = false;
  #permit: ApplicationPermit | undefined;
  readonly #abort = new AbortController();
  constructor(readonly executor: ApplicationExecutor, readonly group: ApplicationGroup, readonly position?: CompletionPosition) {}
  acquire(signal: AbortSignal, check: () => void, context?: V4ApplicationContext, claim?: CompletionClaim): Promise<ApplicationPermit> {
    if (!this.#active || this.#waiting || this.#permit !== undefined) return Promise.reject(new Error("owner_unavailable"));
    this.#waiting = true;
    const original = (): void => { if (!this.#active) throw new Error("closed"); check(); };
    return this.group.completion(AbortSignal.any([signal, this.#abort.signal]), original, context, claim).then(permit => {
      if (!this.#active) { permit.release(); throw new Error("closed"); }
      this.#permit = permit;
      permit.onRelease(() => { this.#permit = undefined; this.#collect(); }); return permit;
    }).finally(() => { this.#waiting = false; this.#collect(); });
  }
  close(): void { if (!this.#active) return; this.#active = false; this.#abort.abort(); this.#collect(); }
  #collect(): void {
    if (this.#active || this.#waiting || this.#permit !== undefined || this.#returned) return;
    this.#returned = true; this.executor.returnCompletion(this);
  }
  cleanupComplete(): boolean { return this.#returned; }
}

export function completionPositionCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new ResourceError("configuration_capacity");
  return new ResourceVector([1024n + runtimeBytes, 0n, 0n, 2n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}

/** A reusable position in the same root's 4096-result set, held even while
 * dormant. A leased result and its actual decoder keep that one position until
 * both release; closing the Session never fabricates a second free position. */
export class CompletionPosition {
  #reference: ResourceReference | undefined;
  #current: CompletionReservation | undefined;
  #closed = false;
  constructor(readonly executor: ApplicationExecutor, readonly group: ApplicationGroup, runtimeBytes: bigint, reference: ResourceReference) {
    this.#reference = reference.take(completionPositionCharge(runtimeBytes));
  }
  available(): boolean { return !this.#closed && this.#current === undefined; }
  checkout(): CompletionReservation {
    this.group.check();
    if (!this.available()) throw new ResourceError("resource_exhausted");
    this.#reference!.check(); return this.#current = new CompletionReservation(this.executor, this.group, this);
  }
  returned(reservation: CompletionReservation): void {
    if (this.#current !== reservation) throw new Error("owner_unavailable");
    this.#current = undefined; this.#collect();
  }
  close(): void { this.#closed = true; this.#collect(); }
  #collect(): void {
    if (!this.#closed || this.#current !== undefined || this.#reference === undefined) return;
    this.#reference.release(); this.#reference = undefined; this.executor.returnCompletionPosition(this);
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}

/** Only the original actual invocation returns a started position. */
export class ApplicationPermit {
  released = false;
  started = false;
  #releaseObserver: (() => void) | undefined;
  #observed = false;
  constructor(readonly executor: ApplicationExecutor, readonly group: ApplicationGroup, readonly lane: Lane,
    readonly ancestors: readonly ApplicationPermit[]) { Object.defineProperty(this, "then", { value: undefined }); }
  onRelease(callback: () => void): void {
    if (this.#observed) throw new Error("owner_unavailable"); this.#observed = true;
    if (this.released) callback(); else this.#releaseObserver = callback;
  }
  release(): void {
    if (this.released) return; this.released = true;
    try { this.executor.returnPermit(this); }
    finally { const observer = this.#releaseObserver; this.#releaseObserver = undefined; observer?.(); }
  }
}

/** One participating Session/registration owner. Closing it stops future entry;
 * running callbacks and their captured group remain charged until actual exit. */
export class ApplicationGroup {
  closed = false;
  #retired = false;
  users = 0;
  ordinaryRunning = 0;
  readonly ordinary: Pending[] = [];
  readonly completions: Pending[] = [];
  readonly #shared = new Map<ResourceServiceReference, () => void>();
  constructor(readonly executor: ApplicationExecutor, private reference: ResourceReference | undefined) {}
  check(lane?: Lane): void {
    if (this.closed || this.reference === undefined || this.#retired && lane !== "completion") throw new Error("closed");
    if (this.#retired) this.reference.checkRetained(); else this.reference.check(); this.executor.check();
  }
  sameEnvironment(reference: ResourceReference): boolean { this.check(); return this.reference!.sameEnvironment(reference); }
  enableManagement(): void { this.check(); this.executor.enableManagement(); }
  management(signal: AbortSignal, check: () => void): Promise<ManagementPermit> { return this.executor.management(this, signal, check); }
  protectQueries(reference: ResourceReference): FixedQueryProtection { this.check(); return this.executor.protectQueries(this, reference); }
  protectQueryAcquisition(reference: ResourceReference): FixedQueryProtection { this.check(); return this.executor.protectQueries(this, reference, 1); }
  attachService(service: ResourceServiceReference): void {
    if (!this.#shared.has(service)) this.#shared.set(service, service.attach(this.reference!));
  }
  detachService(service: ResourceServiceReference): void { this.#shared.get(service)?.(); this.#shared.delete(service); }
  retain(lane?: Lane): void { this.check(lane); this.users++; }
  release(): void { if (this.users < 1) throw new Error("owner_unavailable"); this.users--; this.cleanup(); }
  close(): void { if (this.closed) return; this.closed = true; this.executor.cancelGroup(this); this.cleanup(); }
  /** End ordinary admission while original complete results can still enter
   * Completion. Existing result positions keep this compact group alive. */
  retireResults(): void {
    if (this.closed || this.#retired) return; this.#retired = true;
    this.executor.cancelGroup(this, false); this.cleanup();
  }
  cleanupComplete(): boolean { this.cleanup(); return this.reference === undefined; }
  businessPending(): boolean { return this.ordinaryRunning !== 0 || this.ordinary.length !== 0; }
  cleanup(): void {
    if (!this.closed && !this.#retired || this.users !== 0 || this.reference === undefined || this.ordinary.length !== 0 || this.completions.length !== 0) return;
    for (const detach of this.#shared.values()) detach(); this.#shared.clear();
    this.reference.release(); this.reference = undefined; this.executor.removeGroup(this);
  }
  tryOrdinary(workClass: ApplicationWorkClass, context?: V4ApplicationContext): ApplicationPermit {
    this.check(); return this.executor.tryAcquire(this, workClass, context);
  }
  reserveStart(workClass: ApplicationWorkClass): ApplicationStartPosition { this.check(); return this.executor.reserveStart(this, workClass); }
  acquire(workClass: ApplicationWorkClass, signal: AbortSignal, check: () => void, context?: V4ApplicationContext): Promise<ApplicationPermit> {
    return this.executor.acquire(this, workClass, signal, check, context);
  }
  completion(signal: AbortSignal, check: () => void, context?: V4ApplicationContext, claim?: CompletionClaim): Promise<ApplicationPermit> {
    return this.executor.acquire(this, "completion", signal, check, context, claim);
  }
  claimCompletion(context: V4ApplicationContext): CompletionClaim { this.check(); return this.executor.claim(this, context); }
  reserveCompletion(): CompletionReservation { this.check(); return this.executor.reserveCompletion(this); }
  protectCompletion(runtimeBytes: bigint, reference: ResourceReference): CompletionPosition {
    this.check(); if (!this.sameEnvironment(reference)) throw new Error("owner_unavailable");
    return this.executor.protectCompletion(this, runtimeBytes, reference);
  }
  /** A synchronous direct ordinary stage keeps its existing permit and ancestry. */
  synchronous<T>(context: V4ApplicationContext | undefined, check: () => void, action: () => T): Readonly<{ used: false }> | Readonly<{ used: true; value: T }> {
    const state = invocation(context);
    if (state === undefined || state.permit.executor !== this.executor || state.permit.lane === "completion") return { used: false };
    if (state.depth >= maximumDepth) unavailable();
    this.check(); check(); this.retain(); this.ordinaryRunning++; state.depth++;
    try { return { used: true, value: action() }; }
    finally { state.depth--; this.ordinaryRunning--; this.release(); }
  }
  context(permit: ApplicationPermit, authentication: V4AuthenticatedContext, signal: AbortSignal, outputInterest: V4OutputInterest, publication?: ResponsePublication): Readonly<{ context: V4UnaryContext; release(): void }>;
  context(permit: ApplicationPermit, authentication: V4AuthenticatedContext, signal: AbortSignal): Readonly<{ context: V4ApplicationContext; release(): void }>;
  context(permit: ApplicationPermit, authentication: V4AuthenticatedContext, signal: AbortSignal, outputInterest: undefined, publication: undefined, services: object): Readonly<{ context: V4ApplicationContext; release(): void }>;
  context(permit: ApplicationPermit, authentication: V4AuthenticatedContext, signal: AbortSignal, outputInterest?: V4OutputInterest, publication?: ResponsePublication, services?: object): Readonly<{ context: V4ApplicationContext; release(): void }> {
    this.check(permit.lane);
    if (permit.group !== this || permit.released || permit.started) throw new Error("owner_unavailable");
    permit.started = true;
    const context = Object.freeze({ authentication, signal, ...(services === undefined ? {} : { services }), ...(outputInterest === undefined ? {} : { outputInterest, responsePublication: publication?.view ?? noResponsePublication, maintenanceOwner: publication?.maintenance }) });
    const state: Invocation = { permit, ancestors: permit.ancestors, active: true, depth: 0, onExit: new Set() };
    contexts.set(context, state);
    return { context, release: () => {
      if (!state.active) return; state.active = false; contexts.delete(context);
      for (const callback of state.onExit) callback(); state.onExit.clear(); permit.release();
    } };
  }
}

/** Root-scoped ordinary and protected Completion service. Ordinary queues are
 * bounded and rotate across groups/classes; dormant results do not queue jobs. */
export class ApplicationExecutor {
  readonly #groups = new Set<ApplicationGroup>();
  #ordinary = 0;
  #resident = 0;
  #reserved = 0;
  #residentReserved = 0;
  readonly #startPositions = new Set<ApplicationStartPosition>();
  #ready = 0;
  #residentReady = 0;
  #completion = 0;
  #claims = 0;
  readonly #claimOwners = new Set<CompletionClaim>();
  readonly #resultOwners = new Set<CompletionReservation | CompletionPosition>();
  #completionPending = 0;
  #queued = false;
  #nextClass: ApplicationWorkClass = "short";
  #lastGroup: ApplicationGroup | undefined;
  #ordinaryReference: ResourceServiceReference | undefined;
  #completionReference: ResourceServiceReference | undefined;
  #fixedQueries: FixedQueryExecutor | undefined;
  #management: FixedManagementExecutor | undefined;
  readonly #envelope: OrdinaryEnvelope;
  constructor(private readonly root: ResourceRoot) {
    this.#envelope = root.applicationResources;
    const e = this.#envelope;
    this.#ordinaryReference = root.reserveService(new ResourceVector([e.bytes, 0n, 0n, BigInt(e.running + e.ready + 1), BigInt(e.running), BigInt(e.running), 0n, 0n, 0n, 0n, 0n]));
  }
  envelope(): Readonly<OrdinaryEnvelope> { return this.#envelope; }
  workload(): Readonly<{ ordinaryRunning: number; residentRunning: number; ordinaryReady: number; residentReady: number; completionRunning: number }> {
    return Object.freeze({ ordinaryRunning: this.#ordinary, residentRunning: this.#resident, ordinaryReady: this.#ready,
      residentReady: this.#residentReady, completionRunning: this.#completion });
  }
  check(): void { if (this.#ordinaryReference === undefined) throw new Error("closed"); this.#ordinaryReference.check(); }
  attach(reference: ResourceReference): ApplicationGroup {
    this.check(); if (this.#groups.size >= 4096) throw new ResourceError("resource_exhausted");
    const group = new ApplicationGroup(this, reference);
    try {
      group.attachService(this.#ordinaryReference!);
      if (this.#completionReference !== undefined) group.attachService(this.#completionReference);
      if (this.#fixedQueries !== undefined) group.attachService(this.#fixedQueries.reference);
      if (this.#management !== undefined) group.attachService(this.#management.reference);
      this.#groups.add(group); return group;
    } catch (error) { group.close(); throw error; }
  }
  enableCompletion(): void {
    this.check();
    if (this.#completionReference !== undefined) return;
    const reference = this.root.reserveService(new ResourceVector([256n * 1024n, 0n, 0n, 7n, 2n, 2n, 0n, 0n, 0n, 0n, 0n]));
    try { for (const group of this.#groups) group.attachService(reference); this.#completionReference = reference; }
    catch (error) { for (const group of this.#groups) group.detachService(reference); reference.release(); throw error; }
  }
  enableManagement(): void {
    this.check(); if (this.#management !== undefined) return;
    const lane = new FixedManagementExecutor(this.root), attached: ApplicationGroup[] = [];
    try {
      for (const group of this.#groups) { group.attachService(lane.reference); attached.push(group); }
      this.#management = lane;
    } catch (error) { for (const group of attached) group.detachService(lane.reference); lane.close(); throw error; }
  }
  management(group: ApplicationGroup, signal: AbortSignal, check: () => void): Promise<ManagementPermit> {
    if (group.executor !== this || this.#management === undefined) return Promise.reject(new Error("owner_unavailable"));
    return this.#management.acquire(group, signal, check);
  }
  protectQueries(group: ApplicationGroup, reference: ResourceReference, direction: 0 | 1 = 0): FixedQueryProtection {
    this.check();
    if (group.executor !== this) throw new Error("owner_unavailable");
    if (this.#fixedQueries === undefined) {
      const lane = new FixedQueryExecutor(this.root), attached: ApplicationGroup[] = [];
      try {
        for (const current of this.#groups) { current.attachService(lane.reference); attached.push(current); }
        this.#fixedQueries = lane;
      } catch (error) { for (const current of attached) current.detachService(lane.reference); lane.close(); throw error; }
    }
    return this.#fixedQueries.protect(group, reference, direction);
  }
  #ancestors(context: V4ApplicationContext | undefined): readonly ApplicationPermit[] {
    const state = invocation(context); if (state === undefined) return [];
    const parents = [state.permit, ...state.ancestors.filter(permit => !permit.released)];
    if (parents.length > maximumDepth) unavailable();
    return parents;
  }
  #ordinaryClass(lane: Lane, context?: V4ApplicationContext): Lane {
    if (lane === "completion") return lane;
    return applicationWorkClass(lane, context);
  }
  #available(lane: Lane, claim?: CompletionClaim): boolean {
    if (lane === "completion") return claim?.active === true || this.#completion + this.#claims < completionRunning;
    return this.#ordinary + this.#reserved < this.#envelope.running && (lane === "short" || this.#resident + this.#residentReserved < this.#envelope.residentRunning);
  }
  reserveStart(group: ApplicationGroup, lane: ApplicationWorkClass): ApplicationStartPosition {
    group.check(); applicationWorkClass(lane);
    if (!this.#available(lane) || this.#ready !== 0) throw new ResourceError("resource_exhausted");
    const position = new ApplicationStartPosition(this, group, lane);
    group.retain(); this.#startPositions.add(position); this.#reserved++; if (lane === "resident") this.#residentReserved++;
    return position;
  }
  startReserved(position: ApplicationStartPosition): ApplicationPermit {
    if (!position.active || !this.#startPositions.has(position)) throw new Error("owner_unavailable");
    position.group.check();
    const permit = new ApplicationPermit(this, position.group, position.lane, []);
    position.active = false; this.#startPositions.delete(position); this.#reserved--; this.#ordinary++; position.group.ordinaryRunning++;
    if (position.lane === "resident") { this.#residentReserved--; this.#resident++; }
    return permit;
  }
  returnStart(position: ApplicationStartPosition): void {
    if (!position.active || !this.#startPositions.delete(position)) throw new Error("owner_unavailable");
    position.active = false; this.#reserved--; if (position.lane === "resident") this.#residentReserved--;
    position.group.release(); this.#schedule(); this.#ordinaryReference?.available();
  }
  tryAcquire(group: ApplicationGroup, lane: Lane, context?: V4ApplicationContext, claim?: CompletionClaim): ApplicationPermit {
    group.check(lane); lane = this.#ordinaryClass(lane, context); const ancestors = this.#ancestors(context);
    if (lane === "completion") this.enableCompletion();
    if (claim !== undefined && (!claim.active || claim.executor !== this || claim.group !== group)) unavailable();
    if (!this.#available(lane, claim)) throw new Error(lane === "completion" ? "completion_dependency_unavailable" : "would_block");
    const permit = new ApplicationPermit(this, group, lane, ancestors);
    if (claim !== undefined) { claim.active = false; claim.detachParent?.(); claim.detachParent = undefined; this.#claims--; this.#claimOwners.delete(claim); }
    if (lane === "completion") this.#completion++; else { this.#ordinary++; group.ordinaryRunning++; if (lane === "resident") this.#resident++; }
    // A converted claim transfers its existing group reference to the permit.
    if (claim === undefined) group.retain(lane); return permit;
  }
  acquire(group: ApplicationGroup, lane: Lane, signal: AbortSignal, check: () => void,
    parent?: V4ApplicationContext, claim?: CompletionClaim): Promise<ApplicationPermit> {
    try {
      group.check(lane); check(); if (signal.aborted) throw new Error("canceled");
      const state = invocation(parent); lane = this.#ordinaryClass(lane, parent);
      if (lane === "completion") this.enableCompletion();
      if (this.#available(lane, claim) && (lane === "completion" ? this.#completionPending === 0 || claim !== undefined : this.#ready === 0)) {
        return Promise.resolve(this.tryAcquire(group, lane, parent, claim));
      }
      if (state !== undefined && (lane !== "completion" || applicationHasCompletionAncestor(parent))) unavailable();
      if (lane === "completion" ? this.#completionPending >= completionOwners : this.#ready >= this.#envelope.ready || lane === "resident" && this.#residentReady >= this.#envelope.residentReady) throw new ResourceError("resource_exhausted");
      return new Promise<ApplicationPermit>((resolve, reject) => {
        const job: Pending = { group, lane, signal, check, resolve, reject, claim, parent, cancel: () => this.#remove(job, new Error("canceled")) };
        if (lane === "completion") { group.completions.push(job); this.#completionPending++; }
        else { group.ordinary.push(job); this.#ready++; if (lane === "resident") this.#residentReady++; }
        signal.addEventListener("abort", job.cancel, { once: true });
        if (signal.aborted) job.cancel(); else this.#schedule();
      });
    } catch (error) { return Promise.reject(error); }
  }
  claim(group: ApplicationGroup, context: V4ApplicationContext): CompletionClaim {
    if (!applicationHasCompletionAncestor(context)) unavailable();
    this.enableCompletion();
    if (this.#completion + this.#claims >= completionRunning) throw new Error("completion_dependency_unavailable");
    const parent = invocation(context)!, claim = new CompletionClaim(this, group), revoke = (): void => claim.release();
    group.retain(); this.#claims++; this.#claimOwners.add(claim);
    parent.onExit.add(revoke); context.signal.addEventListener("abort", revoke, { once: true });
    claim.detachParent = () => { parent.onExit.delete(revoke); context.signal.removeEventListener("abort", revoke); };
    return claim;
  }
  reserveCompletion(group: ApplicationGroup): CompletionReservation {
    this.enableCompletion();
    if (this.#resultOwners.size >= completionOwners) throw new ResourceError("resource_exhausted");
    const reservation = new CompletionReservation(this, group);
    group.retain(); this.#resultOwners.add(reservation); return reservation;
  }
  protectCompletion(group: ApplicationGroup, runtimeBytes: bigint, reference: ResourceReference): CompletionPosition {
    this.enableCompletion();
    if (this.#resultOwners.size >= completionOwners) throw new ResourceError("resource_exhausted");
    group.retain();
    try {
      const position = new CompletionPosition(this, group, runtimeBytes, reference);
      this.#resultOwners.add(position); return position;
    } catch (error) { group.release(); throw error; }
  }
  returnCompletion(reservation: CompletionReservation): void {
    if (reservation.position !== undefined) reservation.position.returned(reservation);
    else if (this.#resultOwners.delete(reservation)) reservation.group.release();
    this.#completionReference?.available();
    this.#schedule();
  }
  returnCompletionPosition(position: CompletionPosition): void {
    if (this.#resultOwners.delete(position)) position.group.release();
    this.#completionReference?.available(); this.#schedule();
  }
  returnClaim(claim: CompletionClaim): void { this.#claimOwners.delete(claim); this.#claims--; claim.group.release(); this.#schedule(); }
  returnPermit(permit: ApplicationPermit): void {
    if (permit.lane === "completion") this.#completion--; else { this.#ordinary--; permit.group.ordinaryRunning--; if (permit.lane === "resident") this.#resident--; }
    permit.group.release(); this.#schedule();
  }
  #remove(job: Pending, error?: Error): boolean {
    const queue = job.lane === "completion" ? job.group.completions : job.group.ordinary, index = queue.indexOf(job);
    if (index < 0) return false; queue.splice(index, 1); job.signal.removeEventListener("abort", job.cancel);
    if (job.lane === "completion") this.#completionPending--; else { this.#ready--; if (job.lane === "resident") this.#residentReady--; }
    if (error !== undefined) { job.claim?.release(); job.reject(error); }
    job.group.cleanup(); return true;
  }
  #schedule(): void {
    if (this.#queued || this.#ready + this.#completionPending === 0) return;
    this.#queued = true; enqueue(() => { this.#queued = false; this.#drain(); });
  }
  #next(lane: Lane): Pending | undefined {
    const groups = [...this.#groups], start = this.#lastGroup === undefined ? 0 : (groups.indexOf(this.#lastGroup) + 1) % groups.length;
    for (let i = 0; i < groups.length; i++) {
      const group = groups[(start + i) % groups.length]!, queue = lane === "completion" ? group.completions : group.ordinary;
      const job = queue.find(entry => entry.lane === lane);
      if (job !== undefined) { this.#lastGroup = group; return job; }
    }
    return;
  }
  #start(job: Pending): void {
    try {
      job.check(); if (job.signal.aborted) throw new Error("canceled");
      const permit = this.tryAcquire(job.group, job.lane, job.parent, job.claim);
      this.#remove(job); job.resolve(permit);
    } catch (error) {
      // A pending result's original safety check can suspend without closing
      // its candidate. Preserve only these fixed SDK time reasons.
      const reason = error instanceof TimeError ? error.code : error instanceof V4ReadMethodError ? error.reason : undefined;
      this.#remove(job, reason === "time_pending" || reason === "time_unavailable" || reason === "time_continuity" ? new TimeError(reason) : new Error("closed"));
    }
  }
  #drain(): void {
    // Four eligible descriptors at most are promoted per completion wake. The
    // remaining bounded owner index stays dormant without separate poll jobs.
    for (let n = 0; n < completionReady && this.#available("completion"); n++) {
      const job = this.#next("completion"); if (job === undefined) break; this.#start(job);
    }
    for (let n = 0; n < this.#envelope.ready && this.#ordinary < this.#envelope.running; n++) {
      const first = this.#nextClass, second = first === "short" ? "resident" : "short";
      const job = (this.#available(first) ? this.#next(first) : undefined) ?? (this.#available(second) ? this.#next(second) : undefined);
      if (job === undefined) break; this.#nextClass = job.lane === "short" ? "resident" : "short"; this.#start(job);
    }
    if (this.#completionPending > 0 && this.#available("completion")) this.#schedule();
  }
  cancelGroup(group: ApplicationGroup, completions = true): void {
    this.#fixedQueries?.cancelGroup(group); this.#management?.cancelGroup(group);
    for (const position of this.#startPositions) if (position.group === group) position.close();
    for (const job of [...group.ordinary, ...(completions ? group.completions : [])]) this.#remove(job, new Error("closed"));
    if (completions) for (const claim of this.#claimOwners) if (claim.group === group) claim.release();
  }
  removeGroup(group: ApplicationGroup): void { this.#groups.delete(group); if (this.#lastGroup === group) this.#lastGroup = undefined; this.cleanup(); }
  cleanup(): void {
    if (this.#groups.size !== 0 || this.#resultOwners.size !== 0 || this.#ordinary + this.#reserved + this.#completion + this.#claims !== 0) return;
    this.#ordinaryReference?.release(); this.#ordinaryReference = undefined;
    this.#completionReference?.release(); this.#completionReference = undefined; services.delete(this.root);
    this.#fixedQueries?.close(); this.#fixedQueries = undefined;
    this.#management?.close(); this.#management = undefined;
  }
}

export function applicationGroupCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new ResourceError("configuration_capacity");
  return new ResourceVector([runtimeBytes + 1024n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function applicationGroup(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, runtimeBytes: bigint, completion: boolean,
  prepaid?: ResourceReference): ApplicationGroup {
  const charge = applicationGroupCharge(runtimeBytes), reference = prepaid?.take(charge) ?? root.reserve({ accounts, owner, charge });
  let executor = services.get(root), group: ApplicationGroup | undefined;
  try {
    if (executor === undefined) { executor = new ApplicationExecutor(root); services.set(root, executor); }
    if (completion) executor.enableCompletion();
    group = executor.attach(reference); return group;
  } catch (error) { reference.release(); executor?.cleanup(); throw error; }
}

/** Internal snapshot of the original root service, never a reservation. */
export function applicationWorkload(root: ResourceRoot): ReturnType<ApplicationExecutor["workload"]> | undefined { return services.get(root)?.workload(); }
/** The selected local envelope is fixed on the original budget root. */
export function applicationEnvelope(root: ResourceRoot): ReturnType<ApplicationExecutor["envelope"]> | undefined { return services.get(root)?.envelope(); }
