import { DiagnosticActivity, type DiagnosticObserver } from "./diagnosticObservation.js";
import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import type { V4NotificationHandler, V4NotificationHandlerOptions } from "../serviceHandlers.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";
import type { V4NotificationSubscriptionOptions, V4NotificationGap, V4ObservationStatus, V4NotificationWaitOptions, V4NotificationClosedResult } from "../notificationSubscription.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import { applicationDependsOn, applicationHasPermit, type ApplicationGroup, type ApplicationPermit } from "./applicationExecutor.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import type { CapturedContractRoute } from "./contractRoutes.js";
import { TrustedWindow, timerChunk, type TrustedDeadline } from "./deadline.js";
import type { TrustedClock } from "./clock.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { ResourceVector, type ResourceReference, type ResourceRoot, type ResourceAccount, type ResourceOwner } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCRequestInput } from "./rpcInput.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { SessionCleanup } from "./sessionCleanup.js";
import type { NotificationExecution } from "./notifyExecution.js";
const maximum = (1n << 64n) - 1n;
type Options = V4NotificationSubscriptionOptions<unknown, unknown>;
export function captureNotificationHandler(options: V4NotificationHandlerOptions): V4NotificationHandlerOptions {
  const { workClass, applicationBytes, authorization, applicationTimeoutMS = 30000n } = options;
  if (workClass !== "short" && workClass !== "resident" || typeof applicationBytes !== "bigint" || applicationBytes < 1n || applicationBytes >= 1n << 63n ||
    typeof applicationTimeoutMS !== "bigint" || applicationTimeoutMS < 1n || applicationTimeoutMS >= 1n << 64n ||
    authorization !== "authenticated" && typeof authorization !== "function") throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ workClass, applicationBytes, authorization, applicationTimeoutMS });
}
export function captureNotificationSubscription(options: Options, definition: CapturedMethodDefinition): Options {
  const base = captureNotificationHandler(options), { pendingPolicy = "drop_newest", project } = options;
  if (pendingPolicy !== "drop_newest" && pendingPolicy !== "latest_pending" || pendingPolicy === "latest_pending" && definition.semantics !== "observation" ||
    project !== undefined && typeof project !== "function") throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ ...base, pendingPolicy, ...(project === undefined ? {} : { project }) });
}
export function notificationRegistrationCharge(options: V4NotificationHandlerOptions, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([4096n + runtimeBytes + options.applicationBytes, 0n, 0n, 20n, 0n, 2n, 1n, 0n, 0n, 0n, 0n]);
}
export function notificationSubscribersCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([32768n + runtimeBytes, 0n, 0n, 129n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
/** Trusted method access is independent of observer projection and callbacks. */
export class NotificationAccess {
  #closed = false;
  constructor(private permission: "allowed" | "denied" | "unavailable") { }
  set(permission: "allowed" | "denied" | "unavailable"): void {
    if (!["allowed", "denied", "unavailable"].includes(permission)) throw new RPCProtocolError("notification_permission"); this.permission = permission;
  }
  check(): void { if (!this.current()) throw new RPCProtocolError(this.permission === "denied" ? "permission_denied" : "service_unavailable"); }
  current(): boolean { return !this.#closed && this.permission === "allowed"; }
  close(): void { this.#closed = true; }
}
interface SubscriptionHost {
  readonly clock: TrustedClock;
  reserve(charge: ResourceVector): ResourceReference;
  released(registration: NotificationRegistration): void;
}
/** A Controller supplies one original encoded-input scheduler for all of its
 * source registrations. No source creates an additional ready queue. */
export interface NotificationScheduler {
  available(): boolean;
  /** Scalar source eligibility at actual decoder/projection/handler entry. */
  current?(): boolean;
  attach(job: NotificationInput): void;
  ready(job: NotificationInput): void;
  release(job: NotificationInput): void;
  gap(reason: V4NotificationGap): void;
}
/** Compact registration accounting survives actual callback tails without a
 * backlink to the Session, route table, keys, reader or publication owner. */
export class NotificationSubscribers {
  #reference: ResourceReference | undefined;
  #host: Readonly<{ root: ResourceRoot; accounts: readonly ResourceAccount[]; owner: ResourceOwner; clock: TrustedClock; runtimeBytes: bigint; reserve?: (charge: ResourceVector) => ResourceReference }> | undefined;
  readonly #methods = new Map<object, Set<NotificationRegistration>>();
  #count = 0;
  #serial = 0n;
  #sequence = 0n;
  #closed = false;
  constructor(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, clock: TrustedClock, runtimeBytes: bigint, reference: ResourceReference, reserve?: (charge: ResourceVector) => ResourceReference) {
    this.#reference = reference.take(notificationSubscribersCharge(runtimeBytes)); this.#host = { root, accounts, owner, clock, runtimeBytes, ...(reserve === undefined ? {} : { reserve }) };
  }
  #reserve(charge: ResourceVector): ResourceReference {
    this.#reference!.checkRetained(); if (this.#sequence === maximum) throw new RPCProtocolError("resource_exhausted");
    const host = this.#host!; this.#sequence++;
    return host.reserve?.(charge) ?? host.root.reserve({ accounts: host.accounts, owner: { ...host.owner, kind: `notification_subscription_${this.#sequence}` }, charge });
  }
  subscribe(method: object, definition: CapturedMethodDefinition, handler: V4NotificationHandler<unknown>, options: Options,
    access: NotificationAccess, prepaid?: ResourceReference, scheduler?: NotificationScheduler): NotificationRegistration {
    const captured = captureNotificationSubscription(options, definition);
    if (this.#closed || this.#serial === maximum || this.#count >= 128 || (this.#methods.get(method)?.size ?? 0) >= 32 || typeof handler !== "function") throw new RPCProtocolError("resource_exhausted");
    this.#reference!.check(); access.check();
    const host = this.#host!, reference = prepaid ?? this.#reserve(notificationRegistrationCharge(captured, host.runtimeBytes));
    let registration: NotificationRegistration | undefined;
    try {
      registration = new NotificationRegistration(handler, captured, access, host.runtimeBytes, reference, {
        clock: host.clock, reserve: charge => this.#reserve(charge), released: original => {
          const set = this.#methods.get(method);
          if (set?.delete(original)) { this.#count--; if (set.size === 0) this.#methods.delete(method); } this.#collect();
        },
      }, ++this.#serial, scheduler);
      if (this.#closed || !access.current()) throw new RPCProtocolError("notification_closed");
      const set = this.#methods.get(method) ?? new Set<NotificationRegistration>(); set.add(registration); this.#methods.set(method, set); this.#count++;
      return registration;
    } catch (error) { registration?.close(); throw error; }
    finally { if (prepaid === undefined) reference.release(); }
  }
  get boundary(): bigint { return this.#serial; }
  businessPending(): boolean {
    for (const registrations of this.#methods.values()) for (const registration of registrations) if (!registration.idle) return true;
    return false;
  }
  snapshot(method: object, boundary = this.#serial): readonly NotificationRegistration[] { return [...(this.#methods.get(method) ?? [])].filter(registration => !registration.closed && registration.identity <= boundary); }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const set of [...this.#methods.values()]) for (const registration of [...set]) registration.close("source_closed"); this.#collect();
  }
  #collect(): void { if (!this.#closed || this.#count !== 0) return; this.#reference?.release(); this.#reference = undefined; this.#host = undefined; }
}
/** At most sixteen pending/cleanup duties plus the one actual running delivery.
 * latest_pending replaces only a candidate which has not entered application. */
export class NotificationRegistration {
  #reference: ResourceReference | undefined;
  #handler: V4NotificationHandler<unknown> | undefined;
  #options: Options | undefined;
  #access: NotificationAccess | undefined;
  #host: SubscriptionHost | undefined;
  readonly #jobs = new Set<NotificationInput>();
  readonly #ready: NotificationInput[] = [];
  readonly #waiters = new Set<() => void>();
  #selected: NotificationInput | undefined;
  #closed = false;
  #dropped = 0n;
  #gap: V4NotificationGap | undefined;
  #window: TrustedWindow | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #incomplete = false;
  #collecting = false;
  #onReleased: (() => void) | undefined;
  constructor(handler: V4NotificationHandler<unknown>, options: Options, access: NotificationAccess, readonly runtimeBytes: bigint, reference: ResourceReference, host: SubscriptionHost, readonly identity = 0n, private scheduler?: NotificationScheduler) {
    this.#reference = reference.take(notificationRegistrationCharge(options, runtimeBytes)); this.#handler = handler; this.#options = options; this.#access = access; this.#host = host;
  }
  get options(): Options { if (this.#options === undefined) throw new RPCProtocolError("notification_closed"); return this.#options; }
  get closed(): boolean { return this.#closed; }
  sameEnvironment(reference: ResourceReference): boolean { this.check(); return this.#reference!.sameEnvironment(reference); }
  get idle(): boolean { return this.#jobs.size === 0; }
  available(): boolean { return !this.#closed && this.#access!.current() && (this.scheduler?.available() ?? this.#jobs.size < (this.#selected?.entered ? 17 : 16)); }
  attach(job: NotificationInput): void { if (!this.available()) throw new RPCProtocolError("resource_exhausted"); this.scheduler?.attach(job); this.#jobs.add(job); }
  ready(job: NotificationInput): void {
    if (this.#closed || !this.#access!.current()) { job.close("source_closed"); return; }
    if (this.scheduler !== undefined) { this.scheduler.ready(job); return; }
    if (this.options.pendingPolicy === "latest_pending") {
      // The new independent bytes/work reservation already exists. Retiring a
      // selected executor waiter retains its original job until it really exits.
      const older = [...this.#ready]; this.#ready.length = 0;
      if (this.#selected !== undefined && !this.#selected.entered) older.push(this.#selected);
      for (const previous of older) previous.close("coalesced_pending");
    }
    this.#ready.push(job); this.#drive();
  }
  check(): void { if (this.#closed) throw new RPCProtocolError("notification_closed"); this.#reference!.checkRetained(); this.#access!.check(); }
  checkDispatch(): void { this.check(); if (this.#closed || this.scheduler?.current?.() === false) throw new RPCProtocolError("notification_closed"); }
  current(): boolean { return !this.#closed && this.#access?.current() === true; }
  dispatch(job: NotificationInput): void { this.check(); if (!this.#jobs.has(job)) throw new RPCProtocolError("notification_owner"); job.run(this.#handler!, this.options); }
  /** Completion observes the actual owner exit, never a passive wait timeout. */
  onReleased(callback: () => void): void {
    if (this.#onReleased !== undefined) throw new RPCProtocolError("notification_owner");
    if (this.#reference === undefined) callback(); else this.#onReleased = callback;
  }
  #drive(): void {
    if (!this.current() || this.#selected !== undefined) return;
    const job = this.#ready.shift(); if (job === undefined) return; this.#selected = job; job.run(this.#handler!, this.options);
  }
  gap(reason: V4NotificationGap): void { if (this.#dropped < maximum) this.#dropped++; this.#gap = reason; this.scheduler?.gap(reason); }
  release(job: NotificationInput): void {
    this.#jobs.delete(job); const index = this.#ready.indexOf(job); if (index >= 0) this.#ready.splice(index, 1);
    if (this.#selected === job) this.#selected = undefined; this.scheduler?.release(job); this.#drive(); this.#collect(); this.#notify();
  }
  close(reason: V4NotificationGap = "subscription_closed"): void {
    if (this.#closed) return; this.#closed = true;
    for (const job of [...this.#jobs]) job.close(reason); this.#ready.length = 0;
    if (this.#reference !== undefined) {
      try { this.#window = new TrustedWindow(this.#host!.clock, 5000n); this.#tick(); }
      catch { this.#incomplete = true; }
    }
    this.#collect(); this.#notify();
  }
  #tick(): void {
    this.#timer = undefined;
    if (this.#reference === undefined) return;
    try { this.#window!.check(); this.#timer = setTimeout(() => this.#tick(), timerChunk(this.#window!.remainingMS())); }
    catch { this.#incomplete = true; this.#notify(); }
  }
  #collect(): void {
    if (this.#collecting || !this.#closed || this.#jobs.size !== 0 || this.#waiters.size !== 0 || this.#reference === undefined) return; this.#collecting = true;
    try {
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#window = undefined;
      this.#handler = undefined; this.#options = undefined; this.#access = undefined;
      this.#reference.release(); this.#reference = undefined; const host = this.#host; this.#host = undefined; host?.released(this);
      this.scheduler = undefined; const released = this.#onReleased; this.#onReleased = undefined; released?.();
    } finally { this.#collecting = false; }
  }
  #notify(): void { for (const waiter of [...this.#waiters]) waiter(); }
  cleanupStatus(): V4CleanupStatus {
    if (this.#window !== undefined && !this.#incomplete) try { this.#window.check(); } catch { this.#incomplete = true; }
    const done = this.#closed && this.#jobs.size === 0;
    return Object.freeze({
      status: done ? "complete" : this.#incomplete ? "cleanup_incomplete" : "pending",
      core_cleanup: this.#closed ? "complete" : "pending", pending_callbacks: BigInt([...this.#jobs].filter(job => job.entered).length)
    });
  }
  status(): V4ObservationStatus {
    const running = this.#selected?.entered ? 1 : 0;
    return Object.freeze({
      closed: this.#closed, pending: this.#jobs.size - running, running, knownDropped: this.#dropped,
      ...(this.#gap === undefined ? {} : { lastGap: this.#gap }), cleanupStatus: this.cleanupStatus()
    });
  }
  waitClosed(options: V4NotificationWaitOptions = {}): Promise<V4NotificationClosedResult> {
    const { context, signal, timeoutMS = 5000n } = options;
    if (typeof timeoutMS !== "bigint" || timeoutMS < 1n || timeoutMS > 5000n) throw new RPCProtocolError("notification_wait_options");
    const result = (wait: V4NotificationClosedResult["wait"]): V4NotificationClosedResult => {
      const cleanupStatus = this.cleanupStatus();
      return Object.freeze({ closed: this.#closed, cleanupStatus: wait === "dependency_unavailable" && cleanupStatus.status === "pending" ? Object.freeze({ ...cleanupStatus, status: "cleanup_incomplete" }) : cleanupStatus, wait });
    };
    if (this.#closed && this.#jobs.size === 0) return Promise.resolve(result("complete"));
    if (signal?.aborted) return Promise.resolve(result("canceled"));
    try {
      applicationHasPermit(context);
      if (this.#selected?.dependsOn(context)) return Promise.resolve(result("dependency_unavailable"));
    } catch { return Promise.resolve(result("dependency_unavailable")); }
    if (this.#waiters.size >= 4) throw new RPCProtocolError("resource_exhausted");
    const host = this.#host!, reference = host.reserve(new ResourceVector([1024n + this.runtimeBytes, 0n, 0n, 2n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]));
    return new Promise(resolve => {
      let timer: ReturnType<typeof setTimeout> | undefined, window: TrustedWindow | undefined, done = false;
      const finish = (reason: V4NotificationClosedResult["wait"]): void => {
        if (done) return; done = true; this.#waiters.delete(wake);
        if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", cancel); context?.signal.removeEventListener("abort", cancel);
        reference.release(); const value = result(reason); this.#collect(); resolve(value);
      };
      const cancel = (): void => finish("canceled"), wake = (): void => {
        const status = this.cleanupStatus();
        if (status.status === "complete") finish("complete"); else if (status.status === "cleanup_incomplete") finish("deadline_exceeded");
      };
      const tick = (): void => {
        try {
          window!.check(); wake(); if (done) return;
          let left = window!.remainingMS(); if (this.#window !== undefined) { const closeLeft = this.#window.remainingMS(); if (closeLeft < left) left = closeLeft; }
          timer = setTimeout(tick, timerChunk(left));
        } catch { finish("deadline_exceeded"); }
      };
      this.#waiters.add(wake); signal?.addEventListener("abort", cancel, { once: true }); context?.signal.addEventListener("abort", cancel, { once: true });
      try { window = new TrustedWindow(host.clock, timeoutMS); if (signal?.aborted || context?.signal.aborted) cancel(); else tick(); }
      catch { finish("deadline_exceeded"); }
    });
  }
}
export function notificationWorkCharge(method: CapturedMethodDefinition, options: V4NotificationHandlerOptions, runtimeBytes: bigint): ResourceVector {
  const codec = method.request;
  return new ResourceVector([8192n + 8n * runtimeBytes + options.applicationBytes + BigInt(codec.maximum) * 3n + (codec.application?.applicationBytes ?? 0n),
    0n, 0n, 64n, 1n, 3n, 1n, 0n, 0n, 0n, 0n]);
}
/** One independently mutable observer input, produced only by full-input SDK
 * fanout. Application input entry is the replacement/Close linearization gate. */
export class NotificationInput {
  #execution: NotificationExecution | undefined;
  #reference: ResourceReference | undefined;
  #body: RPCPayload | undefined;
  #definition: CapturedMethodDefinition | undefined;
  #registration: NotificationRegistration | undefined;
  #group: ApplicationGroup | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #cleanup: SessionCleanup | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #deadline: TrustedDeadline | undefined;
  #context: V4ApplicationContext | undefined;
  readonly #abort = new AbortController();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #working = false;
  #entered = false;
  #callback = false;
  #closed = false;
  #reported = false;
  #groupHeld = false;
  #attached = false;
  #job = false;
  #busy = true;
  #diagnostic: DiagnosticActivity | undefined;
  readonly #length: number;
  constructor(payload: Uint8Array, definition: CapturedMethodDefinition, registration: NotificationRegistration, deadline: TrustedDeadline,
    group: ApplicationGroup, authentication: V4AuthenticatedContext, delivery: ReceiveDeliveryGate, cleanup: SessionCleanup,
    runtimeBytes: bigint, references: readonly ResourceReference[], execution?: NotificationExecution, diagnostics?: DiagnosticObserver) {
    this.#reference = references[1]!.take(notificationWorkCharge(definition, registration.options, runtimeBytes));
    this.#definition = definition; this.#registration = registration; this.#group = group; this.#authentication = authentication; this.#cleanup = cleanup; this.#deadline = deadline; this.#length = payload.length; this.#execution = execution;
    try {
      this.#diagnostic = new DiagnosticActivity(diagnostics, "application");
      cleanup.startJob(); this.#job = true; group.retain(); this.#groupHeld = true; registration.attach(this); this.#attached = true;
      this.#body = new RPCPayload(payload.length, runtimeBytes, references[0]!); this.#body.write(0, payload);
      this.#lease = delivery.retain(this.#reference, () => this.close("source_closed")); this.#check(); this.#tick();
    } catch (error) { this.close(); throw error; }
    finally { this.#busy = false; this.#collect(); }
  }
  get entered(): boolean { return this.#entered; }
  get closed(): boolean { return this.#closed; }
  dependsOn(context?: V4ApplicationContext): boolean { return applicationDependsOn(context, this.#context); }
  #check(): void {
    if (this.#closed) throw new RPCProtocolError("notification_closed"); this.#reference!.checkRetained(); this.#deadline!.check();
    if (this.#closed) throw new RPCProtocolError("notification_closed"); this.#lease!.check();
    if (this.#working) this.#registration!.checkDispatch(); else this.#registration!.check();
    if (this.#closed) throw new RPCProtocolError("notification_closed");
  }
  #tick(): void { this.#timer = undefined; try { this.#check(); const left = this.#deadline!.remainingMS(); if (!this.#closed) this.#timer = setTimeout(() => this.#tick(), timerChunk(left)); } catch { this.close("deadline_exceeded"); } }
  ready(): void { if (!this.#closed) this.#registration!.ready(this); }
  run(handler: V4NotificationHandler<unknown>, options: Options): void { if (this.#closed) return; this.#working = true; void this.#run(handler, options); }
  async #run(handler: V4NotificationHandler<unknown>, options: Options): Promise<void> {
    let permit: ApplicationPermit | undefined, borrow: RPCPayloadBorrow | undefined, invocation: ReturnType<ApplicationGroup["context"]> | undefined;
    let stage: V4NotificationGap = "dropped_budget";
    try {
      this.#check();
      permit = await (this.#execution?.tryNow ? this.#group!.tryOrdinary(options.workClass) : this.#group!.acquire(options.workClass, this.#abort.signal, () => this.#check()));
      this.#check();
      invocation = this.#group!.context(permit, this.#authentication!, this.#abort.signal);
      this.#context = invocation.context;
      const enter = (): void => {
        if (!this.#callback) {
          const original = this.#deadline!; this.#deadline = original.forkAgeAt(original.sample(), options.applicationTimeoutMS!);
          if (this.#timer !== undefined) clearTimeout(this.#timer); this.#tick(); this.#check();
        }
        this.#check();
        if (!this.#callback) { this.#entered = true; this.#cleanup!.enterCallback(); this.#callback = true; }
      };
      if (options.authorization !== "authenticated") {
        stage = "permission_denied";
        enter();
        if (await options.authorization(invocation.context) !== true) throw new RPCProtocolError("permission_denied");
        this.#check();
      }
      if (this.#execution !== undefined) {
        if (!(await this.#execution.admit(() => this.close("source_closed"))))
          return;
        this.#check();
        const executionDeadline = (await this.#execution.enter());
        this.#deadline!.tightenFrom(executionDeadline);
        if (this.#timer !== undefined) clearTimeout(this.#timer);
        this.#tick();
        this.#check();
      }
      const codec = this.#definition!.request;
      borrow = this.#body!.borrow(this.#length);
      let value: unknown;
      stage = "decode_error";
      if (codec.application === undefined)
        value = codec.implementation === "bytes" ? borrow.bytes : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(borrow.bytes);
      else {
        enter();
        value = codec.application.execution === "sync" ? codec.application.decode(invocation.context, borrow.bytes) : await codec.application.decode(invocation.context, borrow.bytes);
      }
      this.#check();
      if (options.project !== undefined) {
        stage = "projection_error";
        enter();
        value = await options.project(invocation.context, value);
        this.#check();
      }
      stage = "handler_error";
      enter();
      await handler(invocation.context, value);
      if (this.#execution !== undefined) {
        this.#check();
        (await this.#execution.finish());
      }
    }
    catch (error) { this.#diagnostic?.failure(error); this.#execution?.fail(); if (!this.#closed) this.#report(stage); }
    finally {
      invocation?.release(); this.#context = undefined; permit?.release(); borrow?.release();
      if (this.#callback) this.#cleanup!.exitCallback(); this.#callback = false; this.#working = false; this.close(); this.#collect();
    }
  }
  #report(reason: V4NotificationGap): void {
    if (this.#reported) return; this.#reported = true;
    if (reason === "dropped_budget") this.#diagnostic?.event({ code: "slow_consumer" }, "slow_consumer");
    this.#registration?.gap(reason);
  }
  close(reason?: V4NotificationGap): void {
    if (!this.#closed) {
      this.#closed = true; if (reason !== undefined && !this.#entered) this.#report(reason);
      this.#abort.abort(); if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#lease?.release(); this.#lease = undefined;
    }
    this.#collect();
  }
  #collect(): void {
    if (this.#busy || !this.#closed || this.#working) return; this.#busy = true;
    try {
      this.#body?.close(); this.#body = undefined; this.#definition = undefined;
      this.#execution?.close(); this.#execution = undefined;
      const registration = this.#attached ? this.#registration : undefined; this.#attached = false; this.#registration = undefined;
      if (this.#groupHeld) this.#group!.release(); this.#groupHeld = false; this.#group = undefined;
      if (this.#job) this.#cleanup!.finishJob(); this.#job = false; this.#cleanup = undefined;
      this.#diagnostic?.close(); this.#diagnostic = undefined;
      this.#authentication = undefined; this.#deadline = undefined; this.#reference?.release(); this.#reference = undefined; registration?.release(this);
    } finally { this.#busy = false; }
  }
}
/** The channel owns exactly one full-input check/fanout guard per physical
 * message. An observer registered after that guard cannot receive a replay. */
function notificationMessageLifetimeCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([1024n + runtimeBytes, 0n, 0n, 2n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
export function notificationMessageCharges(length: number, runtimeBytes: bigint): readonly ResourceVector[] {
  return [notificationMessageLifetimeCharge(runtimeBytes), rpcPayloadCharge(length, runtimeBytes)];
}
export class NotificationMessage {
  #reference: ResourceReference | undefined;
  #input: RPCRequestInput | undefined;
  #route: CapturedContractRoute | undefined;
  #deadline: TrustedDeadline | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #complete: ((route: CapturedContractRoute, input: RPCRequestInput, bytes: Uint8Array, deadline: TrustedDeadline) => boolean) | undefined;
  constructor(header: ApplicationHeader, route: CapturedContractRoute, deadline: TrustedDeadline, runtimeBytes: bigint, references: readonly ResourceReference[],
    complete: (route: CapturedContractRoute, input: RPCRequestInput, bytes: Uint8Array, deadline: TrustedDeadline) => boolean) {
    this.#reference = references[0]!.take(notificationMessageLifetimeCharge(runtimeBytes));
    try {
      this.#input = new RPCRequestInput(header, { capture: true, contract: route.contract, deadline, runtimeBytes }, references[1]!);
      this.#route = route; this.#complete = complete; this.#deadline = deadline; this.#tick();
    } catch (error) { this.close(); throw error; }
  }
  #tick(): void {
    this.#timer = undefined; if (this.#input === undefined) return;
    try { this.#deadline!.check(); this.#timer = setTimeout(() => this.#tick(), timerChunk(this.#deadline!.remainingMS())); }
    catch { this.close(); }
  }
  write(offset: number, bytes: Uint8Array): void {
    if (this.#input === undefined) return;
    try { this.#deadline!.check(); } catch { this.close(); return; }
    this.#input?.write(offset, bytes);
  }
  finish(): void {
    const input = this.#input; if (input === undefined) return;
    try {
      input.finish(); const deadline = input.forkDeadline(), borrow = input.borrow();
      try { if (this.#complete!(this.#route!, input, borrow.bytes, deadline)) { this.#input = undefined; this.#route = undefined; } } finally { borrow.release(); }
    } catch { /* Expired, unauthorized or invalid complete messages are local rejections. */ }
    finally { this.close(); }
  }
  close(): void {
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#deadline = undefined;
    this.#complete = undefined; this.#input?.close(); this.#input = undefined; this.#route?.close(); this.#route = undefined;
    this.#reference?.release(); this.#reference = undefined;
  }
}
