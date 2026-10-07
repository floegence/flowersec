import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { OperationOptions } from "../public/contract.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "./streamHandlers.js";
import type { V4MethodDefinition } from "./serviceDefinition.js";
import type { V4NotificationGap, V4NotificationSubscriptionOptions } from "./notificationSubscription.js";
import { methodDefinition } from "./serviceDefinition.js";
import { NotificationAccess, captureNotificationSubscription, type NotificationInput, type NotificationRegistration, type NotificationScheduler, type NotificationSubscribers } from "./runtime/notifyDispatch.js";
import { applicationGroup, applicationGroupCharge, applicationDependsOn, applicationHasPermit, type ApplicationGroup, type ApplicationPermit } from "./runtime/applicationExecutor.js";
import { ResourceError, ResourceVector, type ResourceReference } from "./runtime/resources.js";
import { TrustedWindow, timerChunk } from "./runtime/deadline.js";
import { RPCProtocolError } from "./runtime/rpcFragment.js";
import type { V4EnvironmentRuntime } from "./runtime/environment.js";
import type { V4AuthenticatedSessionRuntime } from "./runtime/session.js";

export type V4ControllerNotificationObservation = "current_only" | "drain_aware";
export type V4ControllerNotificationSourcePhase = "current" | "retained" | "draining";
export type V4ControllerNotificationGapReason =
  | "handoff" | "unattached" | "late_attachment" | "source_closed" | "source_unauthorized"
  | "dropped_budget" | "coalesced" | "expired" | "decode_error" | "handler_error";
export interface V4ControllerNotificationGap {
  readonly fromGeneration: bigint;
  readonly toGeneration: bigint;
  readonly reasons: readonly V4ControllerNotificationGapReason[];
  readonly knownDropped: bigint;
  readonly possibleGap: boolean;
}
export type V4ControllerNotificationEvent<Value> =
  | Readonly<{ kind: "notification"; value: Value; sourceGeneration: bigint; sourcePhase: V4ControllerNotificationSourcePhase }>
  | Readonly<{ kind: "observation_gap"; gap: V4ControllerNotificationGap }>;
export interface V4ControllerNotificationObservationStatus {
  readonly delivered: bigint;
  readonly pending: number;
  readonly callbackActive: boolean;
  readonly observedSources: number;
  readonly attachedToCurrent: boolean;
  readonly gap?: V4ControllerNotificationGap;
  readonly closed: boolean;
  readonly cleanupStatus: V4CleanupStatus;
}
export interface V4ControllerNotificationSubscriptionOptions<Input, Value = Input>
  extends Omit<V4NotificationSubscriptionOptions<Input, Value>, "project"> {
  readonly observation?: V4ControllerNotificationObservation;
  readonly maxObservedSessions?: 1 | 2;
  readonly project?: (context: V4ApplicationContext, value: Input) => Value | Promise<Value>;
}
export type V4ControllerNotificationHandler<Value> =
  (context: V4ApplicationContext, event: V4ControllerNotificationEvent<Value>) => void | Promise<void>;
export interface V4ControllerNotifications {
  subscribe<Input, Value = Input>(method: V4MethodDefinition<Input, any, "notify">,
    handler: V4ControllerNotificationHandler<Value>, options: V4ControllerNotificationSubscriptionOptions<Input, Value>): V4ControllerNotificationSubscription<Value>;
  Subscribe<Input, Value = Input>(method: V4MethodDefinition<Input, any, "notify">,
    handler: V4ControllerNotificationHandler<Value>, options: V4ControllerNotificationSubscriptionOptions<Input, Value>): V4ControllerNotificationSubscription<Value>;
}

interface Source {
  readonly runtime: V4AuthenticatedSessionRuntime;
  readonly generation: bigint;
  published: boolean;
  phase: V4ControllerNotificationSourcePhase;
  fenced: boolean;
  installing: boolean;
  closed: boolean;
  cleanupDone: boolean;
  registration: NotificationRegistration | undefined;
}
interface Pending { readonly source: Source; readonly job: NotificationInput; }
const maxUint64 = (1n << 64n) - 1n;
const gapReasons: readonly V4ControllerNotificationGapReason[] = Object.freeze([
  "handoff", "unattached", "late_attachment", "source_closed", "source_unauthorized", "dropped_budget", "coalesced", "expired", "decode_error", "handler_error",
]);

/** The root schedules the original isolated encoded inputs. Source registries
 * retain their admission and cleanup owners, but never add a ready queue. */
export class V4ControllerNotificationSubscription<Value> {
  #method: V4MethodDefinition<any, any, "notify"> | undefined;
  #handler: V4ControllerNotificationHandler<Value> | undefined;
  #options: V4ControllerNotificationSubscriptionOptions<any, Value> | undefined;
  readonly #sources: Source[] = [];
  readonly #jobs = new Map<NotificationInput, Source>();
  readonly #pending: Pending[] = [];
  readonly #waiters = new Set<() => void>();
  readonly #abort = new AbortController();
  #environment: V4EnvironmentRuntime | undefined;
  #dependency: ResourceReference | undefined;
  #registration: NotificationRegistration | undefined;
  #group: ApplicationGroup | undefined;
  #selected: NotificationInput | undefined;
  #gapRunning = false;
  #gapContext: V4ApplicationContext | undefined;
  #closed = false;
  #collecting = false;
  #driving = false;
  #lastWasGap = false;
  #gapReasons = 0;
  #gapFrom = 0n;
  #gapTo = 0n;
  #knownDropped = 0n;
  #possibleGap = false;
  #gapPending = false;
  #delivered = 0n;
  #closedCallback: (() => void) | undefined;
  #nextGeneration = 0n;
  #deferredRuntime: V4AuthenticatedSessionRuntime | undefined;
  #deferredGeneration: bigint | undefined;
  #deferredPublished = false;
  #deferredRetirement: "drain" | "retain" = "drain";
  #availabilityCleanup: (() => void) | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #closeWindow: TrustedWindow | undefined;
  #closeTimer: ReturnType<typeof setTimeout> | undefined;
  #incomplete = false;

  constructor(method: V4MethodDefinition<any, any, "notify">, handler: V4ControllerNotificationHandler<Value>, options: V4ControllerNotificationSubscriptionOptions<any, Value>,
    environment: V4EnvironmentRuntime, subscribers: NotificationSubscribers) {
    if (typeof handler !== "function" || options === null || typeof options !== "object") throw new Error("configuration_capacity");
    const observation = options.observation ?? "current_only", max = options.maxObservedSessions ?? 2, definition = methodDefinition(method);
    if (definition.shape !== "notify" || observation !== "current_only" && observation !== "drain_aware" || max !== 1 && max !== 2) throw new Error("configuration_capacity");
    this.#method = method; this.#handler = handler; this.#environment = environment;
    const captured = captureNotificationSubscription(options, definition);
    this.#options = Object.freeze({ ...captured, ...(options.project === undefined ? {} : { project: options.project }), observation, maxObservedSessions: max }) as V4ControllerNotificationSubscriptionOptions<any, Value>;
    const resources = environment.resources;
    try {
      // The existing subscriber registry enforces 128 roots and 32 per method,
      // including roots without a current Session and roots still cleaning up.
      this.#registration = subscribers.subscribe(method, definition, () => undefined, this.options, new NotificationAccess("allowed"));
      // One 256-byte mutable gap, one immutable snapshot, two source records,
      // one callback tail and bounded waiter metadata remain prepaid together.
      this.#dependency = environment.reserveConnectionWork("controller_notification", new ResourceVector([
        16896n + 8n * resources.runtimeBytes + options.applicationBytes, 0n, 0n, 40n, 1n, 4n, 1n, 0n, 0n, 0n, 0n,
      ]));
      const groupReference = environment.reserveConnectionWork("controller_notification_group", applicationGroupCharge(resources.runtimeBytes));
      try { this.#group = applicationGroup(resources.root, resources.accounts, resources.owner, resources.runtimeBytes, false, groupReference); }
      finally { groupReference.release(); }
      // Reserve the one passive retry observer with the root. Resource
      // exhaustion while attaching a Session must not require another
      // allocation just to hear when capacity becomes available again.
      this.#availabilityCleanup = resources.root.observeAvailability(this.#dependency, () => {
        const runtime = this.#deferredRuntime, generation = this.#deferredGeneration;
        if (!this.#closed && runtime !== undefined && generation !== undefined && this.#sources.length < this.options.maxObservedSessions!)
          this.attachSource(runtime, true, generation, this.#deferredPublished, this.#deferredRetirement);
      });
    } catch (error) { this.#availabilityCleanup?.(); this.#group?.close(); this.#dependency?.release(); this.#registration?.close(); throw error; }
    Object.defineProperty(this, "then", { value: undefined });
  }

  private get options(): V4ControllerNotificationSubscriptionOptions<any, Value> {
    if (this.#options === undefined) throw new Error("notification_closed"); return this.#options;
  }
  attachSource(runtime: V4AuthenticatedSessionRuntime, late = true, deferredGeneration?: bigint, deferredPublished = false, deferredRetirement: "drain" | "retain" = "drain"): void {
    if (this.#closed || this.#sources.some(source => source.runtime === runtime && !source.cleanupDone) || this.#deferredRuntime === runtime && deferredGeneration === undefined) return;
    const generation = deferredGeneration ?? (this.#nextGeneration === maxUint64 ? undefined : ++this.#nextGeneration);
    if (generation === undefined) { this.#recordGap("unattached", this.#nextGeneration, true); return; }
    if (this.#sources.length >= this.options.maxObservedSessions!) {
      this.#deferSource(runtime, generation, deferredPublished, deferredRetirement);
      return;
    }
    const source: Source = { runtime, generation, published: deferredPublished, phase: deferredPublished ? "current" : "draining", fenced: false, installing: true, closed: false, cleanupDone: false, registration: undefined };
    this.#sources.push(source);
    try {
      const authentication = runtime.controllerNotificationAuthentication(this.#dependency!);
      if (this.#authentication !== undefined && (Object.keys(authentication) as (keyof V4AuthenticatedContext)[]).some(key => this.#authentication![key] !== authentication[key])) {
        throw new Error("notification_target");
      }
      this.#authentication ??= Object.freeze({ ...authentication });
      if (this.#closed || source.closed) throw new Error("notification_closed");
      const scheduler: NotificationScheduler = {
        available: () => !this.#closed && !source.closed && !source.fenced && this.#jobs.size < (this.#selected?.entered ? 17 : 16),
        current: () => this.#eligible(source),
        attach: job => { this.#jobs.set(job, source); },
        ready: job => this.#enqueue(source, job),
        release: job => {
          this.#jobs.delete(job); const index = this.#pending.findIndex(item => item.job === job);
          if (index >= 0) this.#pending.splice(index, 1);
          if (this.#selected === job) this.#selected = undefined;
          this.#drive(); this.#notify(); this.#collect();
        },
        gap: reason => this.#sourceGap(source, reason),
      };
      source.registration = runtime.subscribeControllerNotification(this.#dependency!, this.#method!, (context, value) => {
        this.#delivered++;
        const sourcePhase = source.runtime.controllerNotificationDraining() ? "draining" : source.phase;
        return this.#handler!(context, Object.freeze({ kind: "notification", value: value as Value, sourceGeneration: source.generation, sourcePhase }));
      }, this.options, scheduler);
      source.registration.onReleased(() => {
        if (!source.closed) this.#recordGap("source_closed", source.generation, true);
        source.closed = true; source.cleanupDone = !source.installing; source.registration = undefined;
        this.#collectSources();
        const deferred = this.#deferredRuntime, deferredGeneration = this.#deferredGeneration, deferredPublished = this.#deferredPublished, deferredRetirement = this.#deferredRetirement;
        if (deferred !== undefined && deferredGeneration !== undefined && this.#sources.length < this.options.maxObservedSessions!) {
          this.#clearDeferred();
          // Retry only on the actual registration release that returns the
          // source slot. This is a bounded passive handoff: it never acquires,
          // retries while busy, or refunds the candidate's original owner.
          this.attachSource(deferred, true, deferredGeneration, deferredPublished, deferredRetirement);
        }
        this.#drive(); this.#notify(); this.#collect();
      });
      if (this.#closed || source.closed) { source.registration?.close(); return; }
      if (this.#deferredRuntime === runtime && this.#deferredGeneration === generation) this.#clearDeferred();
      if (deferredPublished) this.#handoff(source, deferredRetirement);
      if (late) this.#recordGap("late_attachment", generation, true);
    } catch (error) {
      this.#recordGap("unattached", generation, true); source.closed = true;
      source.registration?.close();
      this.#collectSources();
      if (!this.#closed && this.#capacityFailure(error)) this.#deferSource(runtime, generation, deferredPublished, deferredRetirement);
      else if (this.#deferredRuntime === runtime) this.#clearDeferred();
    } finally {
      source.installing = false;
      if (source.closed && source.registration === undefined) source.cleanupDone = true;
      this.#collectSources();
      const deferred = this.#deferredRuntime, generation = this.#deferredGeneration;
      if (!this.#closed && source.cleanupDone && deferred !== undefined && deferred !== runtime && generation !== undefined && this.#sources.length < this.options.maxObservedSessions!) {
        const published = this.#deferredPublished, retirement = this.#deferredRetirement;
        this.#clearDeferred(); this.attachSource(deferred, true, generation, published, retirement);
      }
      this.#collect();
    }
    this.flushSourcePublication();
  }

  #capacityFailure(error: unknown): boolean {
    return error instanceof ResourceError && error.code === "resource_exhausted" || error instanceof RPCProtocolError && error.code === "resource_exhausted";
  }
  #clearDeferred(): void {
    this.#deferredRuntime = undefined; this.#deferredGeneration = undefined; this.#deferredPublished = false; this.#deferredRetirement = "drain";
  }
  #deferSource(runtime: V4AuthenticatedSessionRuntime, generation: bigint, published: boolean, retirement: "drain" | "retain"): void {
    if (this.#deferredRuntime === undefined) {
      this.#deferredRuntime = runtime; this.#deferredGeneration = generation; this.#deferredPublished = published; this.#deferredRetirement = retirement;
    }
    this.#recordGap("unattached", generation, true);
  }

  publishSource(runtime: V4AuthenticatedSessionRuntime, retirement: "drain" | "retain" = "drain"): void {
    this.stageSourcePublication(runtime, retirement);
    this.flushSourcePublication();
  }
  /** Only SDK scalar changes: the Controller stages every root before any
   * cancellation, resource release, timer or application scheduling can run. */
  stageSourcePublication(runtime: V4AuthenticatedSessionRuntime, retirement: "drain" | "retain" = "drain"): void {
    if (this.#closed) return;
    if (this.#deferredRuntime !== undefined && this.#deferredRuntime !== runtime) this.#clearDeferred();
    const source = this.#sources.find(candidate => candidate.runtime === runtime && !candidate.closed);
    if (source === undefined) {
      if (this.#deferredRuntime === undefined && this.#nextGeneration !== maxUint64)
        this.#deferSource(runtime, ++this.#nextGeneration, true, retirement);
      if (this.#deferredRuntime === runtime) { this.#deferredPublished = true; this.#deferredRetirement = retirement; }
      // Publication fences the previous source before attachment. Every
      // observation mode updates its phase at this boundary; current_only
      // additionally closes the old source, while drain_aware keeps its tail.
      const previous = this.#sources.find(candidate => candidate.published && candidate.phase === "current" && !candidate.closed);
      if (previous !== undefined) {
        const next = this.#deferredGeneration ?? previous.generation;
        this.#recordGap("handoff", previous.generation, true, next);
        previous.phase = retirement === "retain" ? "retained" : "draining";
        if (this.options.observation === "current_only" || this.options.maxObservedSessions === 1) previous.fenced = true;
      }
      this.#recordGap("unattached", this.#deferredGeneration ?? 0n, true);
    } else {
      source.published = true; this.#handoff(source, retirement);
    }
  }
  flushSourcePublication(): void {
    if (this.#closed) return;
    for (const source of [...this.#sources]) if (source.fenced) this.#closeSource(source);
    this.#drive(); this.#notify();
  }
  #handoff(source: Source, retirement: "drain" | "retain"): void {
    if (source.closed || !source.published) return;
    const previous = this.#sources.find(candidate => candidate.published && candidate.phase === "current" && candidate !== source && !candidate.closed);
    if (previous === undefined) { source.phase = "current"; return; }
    this.#recordGap("handoff", previous.generation, true, source.generation);
    previous.phase = retirement === "retain" ? "retained" : "draining";
    source.phase = "current";
    if (this.options.observation === "current_only") previous.fenced = true;
  }
  retireSource(runtime: V4AuthenticatedSessionRuntime): void {
    const source = this.#sources.find(candidate => candidate.runtime === runtime && !candidate.cleanupDone);
    if (source !== undefined) { this.#recordGap("source_closed", source.generation, true); this.#closeSource(source); return; }
    if (this.#deferredRuntime === runtime) {
      const generation = this.#deferredGeneration ?? 0n;
      this.#clearDeferred();
      this.#recordGap("source_closed", generation, true);
      this.#notify();
    }
  }
  close(): void {
    if (this.#closed) return;
    this.#closed = true; this.#abort.abort();
    this.#availabilityCleanup?.(); this.#availabilityCleanup = undefined;
    if (this.#deferredRuntime !== undefined && this.#deferredGeneration !== undefined) this.#recordGap("source_closed", this.#deferredGeneration, true);
    this.#clearDeferred();
    for (const source of [...this.#sources]) this.#closeSource(source);
    this.#group?.close();
    try { this.#closeWindow = new TrustedWindow(this.#environment!.clock, 5000n); this.#tickClose(); }
    catch { this.#incomplete = true; }
    this.#notify(); this.#collect();
  }
  unsubscribe(): void { this.close(); }
  Close(): void { this.close(); }
  onClosed(callback: () => void): void {
    if (typeof callback !== "function" || this.#closedCallback !== undefined) throw new Error("owner_unavailable");
    this.#closedCallback = callback; this.#collect();
  }
  observationStatus(): V4ControllerNotificationObservationStatus {
    const gap = this.#gapSnapshot();
    return Object.freeze({ delivered: this.#delivered, pending: this.#pending.length + (this.#selected !== undefined && !this.#selected.entered && !this.#selected.closed ? 1 : 0),
      callbackActive: this.#selected?.entered === true || this.#gapContext !== undefined, observedSources: this.#sources.length,
      attachedToCurrent: this.#sources.some(source => !source.closed && source.published && source.phase === "current"),
      ...(gap === undefined ? {} : { gap }), closed: this.#closed, cleanupStatus: this.cleanupStatus() });
  }
  ObservationStatus(): V4ControllerNotificationObservationStatus { return this.observationStatus(); }
  cleanupStatus(): V4CleanupStatus {
    if (this.#closeWindow !== undefined && !this.#incomplete) try { this.#closeWindow.check(); } catch { this.#incomplete = true; }
    const status = this.#closed && this.#dependency === undefined ? "complete" : this.#incomplete ? "cleanup_incomplete" : "pending";
    return Object.freeze({ status, core_cleanup: this.#closed ? "complete" : "pending",
      pending_callbacks: this.#selected?.entered === true || this.#gapContext !== undefined ? 1n : 0n });
  }
  CleanupStatus(): V4CleanupStatus { return this.cleanupStatus(); }
  waitClosed(options: OperationOptions & Readonly<{ timeoutMS?: bigint; context?: V4ApplicationContext }> = {}): Promise<Readonly<{ closed: boolean; cleanupStatus: V4CleanupStatus; wait: "complete" | "canceled" | "deadline_exceeded" | "dependency_unavailable" }>> {
    const timeout = options.timeoutMS ?? 5000n;
    if (typeof timeout !== "bigint" || timeout < 1n || timeout > 120000n) return Promise.reject(new Error("notification_wait_options"));
    const result = (wait: "complete" | "canceled" | "deadline_exceeded" | "dependency_unavailable") => {
      const cleanupStatus = this.cleanupStatus();
      return Object.freeze({ closed: this.#closed,
        cleanupStatus: wait === "dependency_unavailable" && cleanupStatus.status === "pending" ? Object.freeze({ ...cleanupStatus, status: "cleanup_incomplete" }) : cleanupStatus,
        wait });
    };
    if (this.cleanupStatus().status === "complete") return Promise.resolve(result("complete"));
    if (options.signal?.aborted) return Promise.resolve(result("canceled"));
    try {
      applicationHasPermit(options.context);
      if (this.#selected?.dependsOn(options.context) || applicationDependsOn(options.context, this.#gapContext)) return Promise.resolve(result("dependency_unavailable"));
    } catch { return Promise.resolve(result("dependency_unavailable")); }
    if (this.#waiters.size >= 4) return Promise.reject(new Error("resource_exhausted"));
    const environment = this.#environment!, { runtimeBytes } = environment.resources;
    const reference = environment.reserveConnectionWork("controller_notification_wait", new ResourceVector([1024n + runtimeBytes, 0n, 0n, 2n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]));
    return new Promise(resolve => {
      let timer: ReturnType<typeof setTimeout> | undefined, window: TrustedWindow | undefined, done = false;
      const finish = (reason: "complete" | "canceled" | "deadline_exceeded"): void => {
        if (done) return; done = true; this.#waiters.delete(wake); options.signal?.removeEventListener("abort", cancel); options.context?.signal.removeEventListener("abort", cancel);
        if (timer !== undefined) clearTimeout(timer); reference.release(); resolve(result(reason));
      };
      const wake = (): void => {
        const status = this.cleanupStatus();
        if (status.status === "complete") finish("complete"); else if (status.status === "cleanup_incomplete") finish("deadline_exceeded");
      };
      const cancel = (): void => finish("canceled");
      const tick = (): void => {
        try {
          window!.check(); wake(); if (done) return;
          let left = window!.remainingMS();
          if (this.#closeWindow !== undefined) { const closeLeft = this.#closeWindow.remainingMS(); if (closeLeft < left) left = closeLeft; }
          timer = setTimeout(tick, timerChunk(left));
        } catch { finish("deadline_exceeded"); }
      };
      this.#waiters.add(wake); options.signal?.addEventListener("abort", cancel, { once: true }); options.context?.signal.addEventListener("abort", cancel, { once: true });
      try { window = new TrustedWindow(environment.clock, timeout); if (options.signal?.aborted || options.context?.signal.aborted) cancel(); else tick(); }
      catch { finish("deadline_exceeded"); }
    });
  }
  WaitClosed(options?: OperationOptions & Readonly<{ timeoutMS?: bigint; context?: V4ApplicationContext }>): ReturnType<V4ControllerNotificationSubscription<Value>["waitClosed"]> { return this.waitClosed(options); }

  #eligible(source: Source): boolean {
    return !this.#closed && !source.closed && !source.fenced && source.published && (this.options.observation === "drain_aware" || source.phase === "current");
  }
  #enqueue(source: Source, job: NotificationInput): void {
    if (this.#closed || source.closed) { job.close("source_closed"); return; }
    if (this.options.pendingPolicy === "latest_pending") {
      const selected = this.#selected !== undefined && !this.#selected.entered && !this.#selected.closed ? this.#selected : undefined;
      if (!this.#eligible(source) && (this.#pending.some(item => this.#eligible(item.source)) || selected !== undefined && this.#eligible(this.#jobs.get(selected)!))) {
        job.close("dropped_budget"); return;
      }
      // Closing an executor waiter keeps its physical input charged until it
      // exits, but removes its logical pending eligibility immediately.
      selected?.close("coalesced_pending");
      for (const older of [...this.#pending]) older.job.close("coalesced_pending");
    }
    this.#pending.push({ source, job }); this.#drive(); this.#notify();
  }
  #closeSource(source: Source): void {
    if (source.closed) return;
    source.closed = true; this.#recordGap("source_closed", source.generation, true); source.registration?.close();
    if (source.registration === undefined && !source.installing) source.cleanupDone = true;
    this.#collectSources(); this.#drive(); this.#notify(); this.#collect();
  }
  #sourceGap(source: Source, reason: V4NotificationGap): void {
    const mapped: V4ControllerNotificationGapReason = reason === "coalesced_pending" ? "coalesced"
      : reason === "deadline_exceeded" ? "expired" : reason === "permission_denied" ? "source_unauthorized"
      : reason === "subscription_closed" ? "source_closed" : reason === "projection_error" ? "decode_error" : reason;
    this.#recordGap(mapped, source.generation, reason === "source_closed", source.generation, reason === "handler_error" ? 0 : 1, reason !== "handler_error");
  }
  #recordGap(reason: V4ControllerNotificationGapReason, from: bigint, possible: boolean, to = from, dropped = 0, schedule = true): void {
    this.#gapReasons |= 1 << gapReasons.indexOf(reason);
    this.#gapFrom = this.#gapFrom === 0n ? from : from === 0n ? this.#gapFrom : this.#gapFrom < from ? this.#gapFrom : from;
    this.#gapTo = this.#gapTo > to ? this.#gapTo : to;
    const increment = BigInt(dropped);
    this.#knownDropped = increment > maxUint64 - this.#knownDropped ? maxUint64 : this.#knownDropped + increment;
    this.#possibleGap ||= possible; this.#gapPending ||= schedule;
  }
  #gapSnapshot(): V4ControllerNotificationGap | undefined {
    if (this.#gapReasons === 0) return undefined;
    return Object.freeze({ fromGeneration: this.#gapFrom, toGeneration: this.#gapTo, reasons: Object.freeze(gapReasons.filter((_reason, index) => (this.#gapReasons & (1 << index)) !== 0)), knownDropped: this.#knownDropped, possibleGap: this.#possibleGap });
  }
  #drive(): void {
    if (this.#driving || this.#closed || this.#selected !== undefined || this.#gapRunning) return;
    this.#driving = true;
    try {
      const index = this.#pending.findIndex(item => this.#eligible(item.source));
      if (this.#gapPending && this.#authentication !== undefined && (index < 0 || !this.#lastWasGap)) {
        this.#gapRunning = true; void this.#runGap(); return;
      }
      if (index < 0) return;
      const item = this.#pending.splice(index, 1)[0]!; this.#selected = item.job; this.#lastWasGap = false;
      try { item.source.registration!.dispatch(item.job); } catch { item.job.close("source_closed"); }
    } finally {
      this.#driving = false;
      if (!this.#closed && this.#selected === undefined && !this.#gapRunning && this.#pending.some(item => this.#eligible(item.source))) this.#drive();
    }
  }
  async #runGap(): Promise<void> {
    let permit: ApplicationPermit | undefined, invocation: ReturnType<ApplicationGroup["context"]> | undefined, timer: ReturnType<typeof setTimeout> | undefined;
    let entered = false;
    const abort = new AbortController(), close = (): void => abort.abort(); this.#abort.signal.addEventListener("abort", close, { once: true });
    const check = (): void => { if (this.#closed || abort.signal.aborted) throw new Error("notification_closed"); this.#dependency!.check(); };
    try {
      const window = new TrustedWindow(this.#environment!.clock, this.options.applicationTimeoutMS!);
      const tick = (): void => { try { window.check(); timer = setTimeout(tick, timerChunk(window.remainingMS())); } catch { abort.abort(); } }; tick();
      permit = await this.#group!.acquire(this.options.workClass, abort.signal, check); check();
      invocation = this.#group!.context(permit, this.#authentication!, abort.signal); this.#gapContext = invocation.context;
      check();
      const gap = this.#gapSnapshot()!; this.#gapPending = false; this.#lastWasGap = true; this.#delivered++; entered = true;
      await this.#handler!(invocation.context, Object.freeze({ kind: "observation_gap", gap }));
    } catch {
      // Application entry consumes this dispatch even when it throws. Keep the
      // compact failure readable; only a new observation can schedule a gap.
      if (entered) this.#recordGap("handler_error", 0n, false, 0n, 0, false);
      else if (!this.#closed) this.#recordGap("dropped_budget", 0n, false, 0n, 0, false);
      if (!entered) this.#gapPending = false;
    } finally {
      if (timer !== undefined) clearTimeout(timer); this.#abort.signal.removeEventListener("abort", close); abort.abort();
      invocation?.release(); permit?.release(); this.#gapContext = undefined; this.#gapRunning = false;
      this.#drive(); this.#notify(); this.#collect();
    }
  }
  #notify(): void { for (const waiter of [...this.#waiters]) waiter(); }
  #collectSources(): void { this.#sources.splice(0, this.#sources.length, ...this.#sources.filter(source => !source.cleanupDone)); }
  #tickClose(): void {
    this.#closeTimer = undefined;
    try { this.#closeWindow!.check(); this.#closeTimer = setTimeout(() => this.#tickClose(), timerChunk(this.#closeWindow!.remainingMS())); }
    catch { this.#incomplete = true; this.#notify(); this.#collect(); }
  }
  #collect(): void {
    if (this.#collecting || !this.#closed || this.#gapRunning || this.#jobs.size !== 0 || this.#sources.length !== 0 || this.#group?.cleanupComplete() === false) return;
    this.#collecting = true;
    try {
      if (this.#closeTimer !== undefined) clearTimeout(this.#closeTimer); this.#closeTimer = undefined; this.#closeWindow = undefined;
      this.#registration?.close(); this.#registration = undefined; this.#group = undefined;
      this.#dependency?.release(); this.#dependency = undefined; this.#environment = undefined;
      this.#method = undefined; this.#handler = undefined; this.#options = undefined; this.#authentication = undefined;
      this.#notify(); const callback = this.#closedCallback; this.#closedCallback = undefined; callback?.();
    } finally { this.#collecting = false; }
  }
}
