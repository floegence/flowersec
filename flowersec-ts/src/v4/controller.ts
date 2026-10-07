import { originalNativeConnectionFailure } from "./runtime/nativeFailure.js";
import { ConnectionFacts, unknownConnectionFacts } from "./runtime/connectionFacts.js";
import { connectionLocalReport, type LocalReport } from "./localReport.js";
import { ConnectionError, controllerFailureCode, sameConnectionDiagnostic, type ConnectionDiagnostic, type ConnectionFailurePhase, type ConnectionAttemptFacts } from "./connectionDiagnostic.js";
import type { ClientSessionAdmission } from "./runtime/sessionAdmission.js";
import type { ContractQueryPreparation } from "./runtime/queryRenewalPosition.js";
import { controllerServiceSource } from "./runtime/controllerServiceSource.js";
import { captureConnectionRequirements } from "./connectionRequirements.js";
import { ServiceBinding, type ServiceBindingLease } from "./runtime/serviceBinding.js";
import { captureServiceBinding, type CapturedServiceBinding } from "./runtime/serviceBindingConfig.js";
import { serviceClient, type V4ServiceBindOptions, type V4ServiceClient } from "./serviceClient.js";
import type { V4ServiceDefinition, V4ServiceMethods } from "./serviceDefinition.js";
import { InitializerWorkload, type InitializerWorkloadConfig, type InitializerMethodTarget } from "./runtime/initializerWorkload.js";
import { CandidateServiceDependencies, captureServiceDependencies, type CapturedServiceDependency, type V4InvocationServices, type V4ServiceDependencies } from "./serviceDependencies.js";
import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus, V4ConnectionRequirements } from "../generated/transportV4APIResults.js";
import { V4Session, type V4ConnectionMaterialSource, type V4TransportEnvironment } from "./public.js";
import type { V4ApplicationContext, V4RawStreamHandler, V4StreamOpenAuthorizer, V4StreamRegistrationOptions } from "./streamHandlers.js";
import { originalEnvironment, type EnvironmentDependency, type V4EnvironmentRuntime, type PreparedEnvironmentConnection } from "./runtime/environment.js";
import { V4AuthenticatedSessionRuntime } from "./runtime/session.js";
import { applicationGroup, applicationGroupCharge, type ApplicationGroup, type ApplicationWorkClass, type ApplicationStartPosition, applicationHasPermit } from "./runtime/applicationExecutor.js";
import { ResourceVector, type ResourceReference } from "./runtime/resources.js";
import { TrustedDeadline, TrustedWindow, timerChunk } from "./runtime/deadline.js";
import { cleanupResult } from "./runtime/lifecycle.js";
import type { RawStreamPreparation, CapturedRawStreamDeclaration } from "./runtime/rawStreamPreparation.js";
import { captureRegistration, checkRawStreamKind } from "./runtime/streamRegistration.js";
import { V4ControllerNotificationSubscription, type V4ControllerNotifications, type V4ControllerNotificationSubscriptionOptions, type V4ControllerNotificationHandler } from "./controllerNotifications.js";
import type { V4MethodDefinition } from "./serviceDefinition.js";
import { NotificationSubscribers, notificationSubscribersCharge } from "./runtime/notifyDispatch.js";
import { dispatchControllerUnary, type V4UnaryOperation, type V4UnaryOptions, type V4UnaryStartResult } from "./unaryOperation.js";

export interface V4ControllerInitializationContext<Dependencies extends V4ServiceDependencies> extends V4ApplicationContext {
  readonly services: V4InvocationServices<Dependencies>;
}
/** A raw handler installed on each private candidate before publication. */
export interface V4ControllerStreamDeclaration {
  readonly kind: string;
  readonly authorize?: V4StreamOpenAuthorizer;
  readonly handler: V4RawStreamHandler;
  readonly options: V4StreamRegistrationOptions;
}
export interface V4ControllerConfig<Dependencies extends V4ServiceDependencies = {}> {
  /** Keep one real replacement Session admission in the existing budget. */
  readonly handoffHeadroom?: boolean;
  readonly initializeServices?: Dependencies;
  readonly initializeStreams?: readonly V4ControllerStreamDeclaration[];
  readonly initializeWorkload?: InitializerWorkloadConfig;
  readonly source: V4ConnectionMaterialSource;
  readonly requirements?: Partial<V4ConnectionRequirements>;
  readonly attemptTimeoutMS?: bigint;
  readonly drainTimeoutMS?: bigint;
  /** The callback receives this attempt's fixed authenticated candidate. */
  readonly initializeSession?: (context: V4ControllerInitializationContext<Dependencies>, candidate: V4Session) => void | Promise<void>;
  readonly initializeWorkClass?: ApplicationWorkClass;
  /** Explicit allowance for the initializer's retained application graph. */
  readonly initializeApplicationBytes?: bigint;
}
export type V4ControllerReplaceOptions = OperationOptions & (
  | Readonly<{ retirement?: "drain"; retainUntilMS?: never }>
  | Readonly<{ retirement: "retain"; retainUntilMS: bigint }>);
export type V4ControllerDispatchOptions = Pick<V4UnaryOptions, "context" | "signal">;
export interface V4ControllerReplaceResult {
  readonly current: V4Session;
  readonly previous: V4Session | undefined;
  readonly retirement: "drain" | "retain";
  readonly previousRetained: boolean;
  readonly retirementError: unknown;
}
export interface V4ControllerStatus {
  readonly started: boolean;
  readonly closed: boolean;
  readonly current: boolean;
  readonly pending: boolean;
  readonly retired: boolean;
  readonly initializationBlocked: boolean;
  readonly attempts: bigint;
  /** Opaque local source generation of the published current Session. */
  readonly generation: bigint;
  readonly headroom: "disabled" | "reserved" | "in_use" | "unavailable";
  readonly diagnostic: ConnectionDiagnostic;
  readonly cleanup: V4CleanupStatus;
}
interface Link { readonly runtime: V4AuthenticatedSessionRuntime; readonly session: V4Session; readonly cleaned: Promise<void>; readonly dependencies: CandidateServiceDependencies; readonly generation: bigint }
interface CandidatePreparation {
  readonly abort: AbortController;
  readonly dependencies: CandidateServiceDependencies;
  readonly workload: InitializerWorkload | undefined;
  readonly callback: ApplicationStartPosition | undefined;
  readonly connection: PreparedEnvironmentConnection;
  readonly streams: RawStreamPreparation | undefined;
}
interface Attempt {
  readonly abort: AbortController;
  readonly window: TrustedWindow;
  readonly deadline: TrustedDeadline;
  readonly dependencies: CandidateServiceDependencies;
  readonly workload: InitializerWorkload | undefined;
  readonly callback: ApplicationStartPosition | undefined;
  readonly previous: Link | undefined;
  readonly retirement: "drain" | "retain";
  readonly retention: TrustedDeadline | undefined;
  readonly autoRetry: boolean;
  readonly ordinal: bigint;
  readonly generation: bigint;
  readonly reject: (error: unknown) => void;
  streams?: RawStreamPreparation;
  connection?: PreparedEnvironmentConnection;
  candidate: Link | undefined;
  entered: boolean;
  committed: boolean;
  settled: boolean;
  result: V4ControllerReplaceResult | undefined;
  timer: ReturnType<typeof setTimeout> | undefined;
  retryAfterMS?: bigint;
  retryAfterInvalid?: boolean;
  transportFailure?: boolean;
}
export interface PreparedControllerService<Methods extends V4ServiceMethods> {
  readonly deadline: TrustedDeadline;
  initialize(onClose?: () => void): Promise<V4ServiceClient<Methods>>;
  initializeBinding(onClose?: () => void): Promise<ServiceBinding>;
  prepareConnection(): void;
  limitDeadline(parent: TrustedDeadline): void;
  connect(): Promise<V4ControllerReplaceResult>;
  close(): void;
}
type PrepareControllerService = <Methods extends V4ServiceMethods>(definition: V4ServiceDefinition<Methods>, options: V4ServiceBindOptions, captured?: CapturedServiceBinding, root?: object) => PreparedControllerService<Methods>;
const servicePreparations = new WeakMap<object, PrepareControllerService>();
/** Internal factory admission. Resource failure is synchronous before Acquire. */
export function prepareControllerService<Methods extends V4ServiceMethods>(controller: object, definition: V4ServiceDefinition<Methods>,
  options: V4ServiceBindOptions, captured?: CapturedServiceBinding, root?: object): PreparedControllerService<Methods> {
  const prepare = servicePreparations.get(controller); if (prepare === undefined) throw new Error("owner_unavailable");
  return prepare(definition, options, captured, root);
}
interface PreparedControllerConnection { start(): Promise<V4ControllerReplaceResult>; close(): void }
const token = Symbol("original v4 controller");
const maxRetryAfterMS = 253402300799999n;
function compactError(error: unknown): Error {
  return new Error(controllerFailureCode(error));
}
const complete = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
function duration(value: bigint): bigint {
  if (typeof value !== "bigint" || value < 1n || value > 90000n) throw new Error("configuration_capacity"); return value;
}

/** Acquisition and publication owner. Protocol and business handles remain on
 * the original Session; replacing current never moves or replays their work. */
export class V4ConnectionController<Dependencies extends V4ServiceDependencies = {}> {
  #declarations: readonly CapturedServiceDependency[] = [];
  #streamDeclarations: readonly CapturedRawStreamDeclaration[] = [];
  #environment: V4EnvironmentRuntime | undefined;
  #config: Readonly<Omit<V4ControllerConfig<Dependencies>, "requirements"> & { requirements: V4ConnectionRequirements }> | undefined;
  #dependency: EnvironmentDependency | undefined;
  #group: ApplicationGroup | undefined;
  #current: Link | undefined;
  #retired: Link | undefined;
  #attempt: Attempt | undefined;
  readonly #links = new Set<Link>();
  readonly #waiters = new Set<() => void>();
  readonly #serviceClosures = new Set<() => void>();
  readonly #serviceObservers = new Set<() => void>();
  readonly #serviceGroup = Object.freeze({});
  #retention: TrustedDeadline | undefined;
  #retentionTimer: ReturnType<typeof setTimeout> | undefined;
  #closeTimer: ReturnType<typeof setTimeout> | undefined;
  #closeWindow: TrustedWindow | undefined;
  #closePromise: Promise<V4CleanupStatus> | undefined;
  #closeResolve: ((status: V4CleanupStatus) => void) | undefined;
  #started = false;
  #closed = false;
  #blocked = false;
  #incomplete = false;
  #attempts = 0n;
  #generation = 0n;
  #nextGeneration = 0n;
  #lastError: unknown;
  #lastFailurePhase: ConnectionFailurePhase = "controller";
  #lastConnectionFacts: ConnectionAttemptFacts | undefined;
  #initializing = false;
  #closing = false;
  #collecting = false;
  #resourceObserver: (() => void) | undefined;
  #workload: InitializerWorkload | undefined;
  #headroom: CandidatePreparation | undefined;
  #headroomEnabled = false;
  #reserving = false;
  #headroomRetryTimer: ReturnType<typeof setTimeout> | undefined;
  #headroomFailures = 0;
  #headroomStreams: readonly InitializerMethodTarget[] = [];
  #retryTimer: ReturnType<typeof setTimeout> | undefined;
  #retryWaiting = false;
  #retryWake: (() => void) | undefined;
  #retryFailures = 0;
  #retryAfterMS: bigint | undefined;
  #notificationOwners: NotificationSubscribers | undefined;
  readonly #notificationSubscriptions = new Set<V4ControllerNotificationSubscription<any>>();
  readonly notifications: V4ControllerNotifications;
  readonly Notifications: V4ControllerNotifications;

  constructor(capability: symbol, environment: V4EnvironmentRuntime, config: V4ControllerConfig<Dependencies>) {
    if (capability !== token) throw new Error("owner_unavailable");
    const handoffHeadroom = config.handoffHeadroom ?? false;
    if (typeof handoffHeadroom !== "boolean") throw new Error("configuration_capacity");
    this.#headroomEnabled = handoffHeadroom;
    const attemptTimeoutMS = duration(config.attemptTimeoutMS ?? 90000n), drainTimeoutMS = duration(config.drainTimeoutMS ?? 30000n);
    const initializeSession = config.initializeSession, initializeWorkClass = config.initializeWorkClass ?? "short";
    const initializeApplicationBytes = config.initializeApplicationBytes ?? 0n;
    if (typeof initializeApplicationBytes !== "bigint" || initializeApplicationBytes < 0n || initializeApplicationBytes > 0xffffffffffffffffn ||
        initializeSession !== undefined && (typeof initializeSession !== "function" || initializeApplicationBytes === 0n) ||
        initializeWorkClass !== "short" && initializeWorkClass !== "resident") throw new Error("configuration_capacity");
    this.#declarations = captureServiceDependencies(config.initializeServices);
    const streamDeclarations = config.initializeStreams ?? [];
    if (!Array.isArray(streamDeclarations) || streamDeclarations.length > 32) throw new Error("configuration_capacity");
    const streamKinds = new Set<string>();
    const capturedStreams: CapturedRawStreamDeclaration[] = [];
    for (const declaration of streamDeclarations) {
      if (declaration === null || typeof declaration !== "object" || typeof declaration.kind !== "string" ||
          declaration.kind.length < 1 || declaration.kind.length > 128 || streamKinds.has(declaration.kind) ||
          declaration.kind.normalize("NFC") !== declaration.kind || declaration.kind.startsWith("flowersec/") || declaration.kind === "flowersec.rpc.v4" ||
          typeof declaration.handler !== "function" || declaration.authorize !== undefined && typeof declaration.authorize !== "function" ||
          declaration.options === null || typeof declaration.options !== "object" || typeof declaration.options.applicationBytes !== "bigint" ||
          declaration.options.applicationBytes < 1n) throw new Error("configuration_capacity");
      try { checkRawStreamKind(declaration.kind); } catch { throw new Error("configuration_capacity"); }
      streamKinds.add(declaration.kind);
      // Capture all option caps and metadata contracts before source Acquire;
      // candidate registration below therefore cannot discover a malformed
      // initializer declaration after consuming a material.
      const options = captureRegistration(declaration.options);
      capturedStreams.push(Object.freeze({ ...declaration, options }));
    }
    this.#streamDeclarations = Object.freeze(capturedStreams);
    if (initializeSession === undefined && this.#declarations.length !== 0) throw new Error("configuration_capacity");
    const methodCount = this.#declarations.reduce((count, item) => count + item.declaration.binding.methods.length, 0);
    this.#config = Object.freeze({ source: config.source, requirements: captureConnectionRequirements(config.requirements),
      attemptTimeoutMS, drainTimeoutMS,
      ...(initializeSession === undefined ? {} : { initializeSession }), initializeWorkClass, initializeApplicationBytes,
      ...(config.initializeWorkload === undefined ? {} : { initializeWorkload: Object.freeze({ ...config.initializeWorkload }) }) });
    this.#environment = environment;
    // Fixed current/candidate/retired links, one attempt, 32 passive waiters and
    // their continuations. Session and application service vectors are separate.
    this.#dependency = environment.admitDependency("controller", new ResourceVector([
      32768n + 40n * environment.resources.runtimeBytes + BigInt(methodCount) * 8192n + BigInt(this.#streamDeclarations.length) * (environment.resources.runtimeBytes + 16384n),
      initializeApplicationBytes,
      0n, 40n + BigInt(methodCount) * 4n, 3n, 6n, 6n, 0n, 0n, 0n, 0n,
    ]));
    try {
      if (initializeSession !== undefined) {
        const { root, accounts, owner, runtimeBytes } = environment.resources;
        const references = environment.reserveInitializerWorkload([applicationGroupCharge(runtimeBytes)]);
        try { this.#group = applicationGroup(root, accounts, owner, runtimeBytes, true, references[0]!); }
        finally { for (const reference of references) reference.release(); }
      }
      this.#resourceObserver = environment.resources.root.observeAvailability(this.#dependency.reference, () => { this.#collect(); if (this.#closed) this.#wake(); });
      this.#dependency.onClose(() => { void this.close(); });
      this.#check();
    } catch (error) { this.#resourceObserver?.(); this.#group?.close(); this.#dependency.release(); throw error; }
    servicePreparations.set(this, (definition, options, captured, root) => this.#prepareService(definition, options, captured, root));
    const subscribeNotifications = <Input, Value = Input>(method: V4MethodDefinition<Input, any, "notify">,
      handler: V4ControllerNotificationHandler<Value>, options: V4ControllerNotificationSubscriptionOptions<Input, Value>) => {
      this.#check();
      if (this.#notificationOwners === undefined) {
        const { root, accounts, owner, runtimeBytes } = environment.resources;
        const reference = environment.reserveConnectionWork("controller_notification_subscribers", notificationSubscribersCharge(runtimeBytes));
        try { this.#notificationOwners = new NotificationSubscribers(root, accounts, owner, environment.clock, runtimeBytes, reference, charge => environment.reserveConnectionWork("controller_notification_registration", charge)); }
        finally { reference.release(); }
      }
      const subscription = new V4ControllerNotificationSubscription(method, handler, options, environment, this.#notificationOwners);
      this.#notificationSubscriptions.add(subscription as V4ControllerNotificationSubscription<any>);
      subscription.onClosed(() => { this.#notificationSubscriptions.delete(subscription as V4ControllerNotificationSubscription<any>); this.#collect(); this.#wake(); });
      const links = [...this.#links];
      for (const link of links) subscription.attachSource(link.runtime);
      const current = this.#current;
      if (current !== undefined) {
        const retired = this.#retired;
        if (retired !== undefined) subscription.publishSource(retired.runtime, this.#retention === undefined ? "drain" : "retain");
        subscription.publishSource(current.runtime, this.#retention === undefined ? "drain" : "retain");
      }
      return subscription;
    };
    this.notifications = Object.freeze({ subscribe: subscribeNotifications, Subscribe: subscribeNotifications });
    this.Notifications = this.notifications;
    Object.defineProperty(this, "then", { value: undefined });
  }

  start(): void {
    this.#check(); if (this.#started) return; this.#started = true;
    try { void this.#replace({}, true).catch(() => undefined); }
    catch (error) { this.#lastFailurePhase = "controller"; this.#lastError = new ConnectionError(controllerFailureCode(error), new ConnectionFacts().snapshot(), this.cleanupStatus()); this.#wake(); throw this.#lastError; }
  }
  replaceSession(options: V4ControllerReplaceOptions = {}): Promise<V4ControllerReplaceResult> {
    try { this.#check(); this.#started = true; this.#cancelRetry(); return this.#replace(options); }
    catch (error) { this.#lastFailurePhase = "controller"; this.#lastError = new ConnectionError(controllerFailureCode(error), new ConnectionFacts().snapshot(), this.cleanupStatus()); this.#wake(); return Promise.reject(this.#lastError); }
  }
  subscribeNotification<Input, Value = Input>(method: V4MethodDefinition<Input, any, "notify">,
    handler: V4ControllerNotificationHandler<Value>, options: V4ControllerNotificationSubscriptionOptions<Input, Value>) {
    return this.notifications.subscribe(method, handler, options);
  }
  subscribeNotifications<Input, Value = Input>(method: V4MethodDefinition<Input, any, "notify">,
    handler: V4ControllerNotificationHandler<Value>, options: V4ControllerNotificationSubscriptionOptions<Input, Value>) {
    return this.notifications.subscribe(method, handler, options);
  }
  /** Start one operation that was prepared through this Controller's service
   * binding. The operation retains its original route and can outlive a
   * replacement; repeated calls join the same local admission outcome. */
  dispatch<Value>(operation: V4UnaryOperation<Value>, options: V4ControllerDispatchOptions = {}): V4UnaryStartResult {
    return dispatchControllerUnary(operation, this.#serviceGroup, options);
  }
  Dispatch<Value>(operation: V4UnaryOperation<Value>, options: V4ControllerDispatchOptions = {}): V4UnaryStartResult {
    return this.dispatch(operation, options);
  }
  /** Wake an existing bounded reconnect wait. This never starts a parallel
   * attempt and never bypasses an authenticated absolute deadline. */
  retryNow(): boolean {
    if (!this.#retryWaiting || this.#closed) return false;
    if (this.#retryAfterMS !== undefined) {
      try {
        if (this.#environment!.clock.sample().requireInterval().lowerMS < this.#retryAfterMS) return false;
      } catch { return false; }
    }
    if (this.#retryTimer !== undefined) clearTimeout(this.#retryTimer);
    this.#retryTimer = undefined;
    this.#retryWake?.(); return true;
  }
  captureSession(): V4Session {
    this.#check(); if (this.#blocked || this.#initializing) throw new Error("initialization_blocked");
    const current = this.#current; if (current === undefined) throw new Error("not_ready");
    current.runtime.controllerGate(this.#dependency!.reference);
    this.#check(); if (current !== this.#current || this.#blocked || this.#initializing) throw new Error("not_ready");
    return current.session;
  }
  waitForSession(options?: OperationOptions): Promise<V4Session> {
    return this.#wait(() => {
      if (this.#closed) throw new Error("closed");
      if (this.#blocked) throw new Error("initialization_blocked");
      if (this.#initializing) return undefined;
      if (this.#current !== undefined) return this.captureSession();
      if (this.#attempt === undefined && !this.#retryWaiting && this.#lastError !== undefined) throw this.#lastError;
      return undefined;
    }, options?.signal);
  }
  /** Borrow this Controller without starting it. Method snapshots and policy
   * survive replacement; each operation captures one original Session. */
  async bindService<Methods extends V4ServiceMethods>(definition: V4ServiceDefinition<Methods>, options: V4ServiceBindOptions): Promise<V4ServiceClient<Methods>> {
    return this.#prepareService(definition, options).initialize();
  }
  #prepareService<Methods extends V4ServiceMethods>(definition: V4ServiceDefinition<Methods>, options: V4ServiceBindOptions, configuration?: CapturedServiceBinding, root?: object): PreparedControllerService<Methods> {
    this.#check();
    const { timeoutMS = 90000n, context, signal, contractSource } = options;
    const captured = configuration ?? captureServiceBinding(definition, options), environment = this.#environment!;
    const deadline = TrustedDeadline.ageAt(environment.clock, environment.clock.sample(), duration(timeoutMS), (1n << 64n) - 1n);
    const pool = environment.serviceBindings(captured.preset === "constrained" ? 16 : 256), reservation = pool.reserve(captured, root);
    let binding: ServiceBinding | undefined, pending: ServiceBindingLease | undefined, entered = false, closed = false, connected = false;
    const abort = new AbortController();
    let connection: PreparedControllerConnection | undefined, queries: ContractQueryPreparation | undefined;
    const close = (): void => {
      if (closed) return; closed = true; abort.abort(new Error("closed"));
      connection?.close(); queries?.close(); queries = undefined; binding?.close(); reservation.close(); pending?.release(); pending = undefined;
    };
    try {
      reservation.claim(captured, pool);
      const cancellation = AbortSignal.any([abort.signal, ...(signal === undefined ? [] : [signal])]);
      pending = this.#retainService(reservation.reference, () => abort.abort(new Error("closed")));
      const source = controllerServiceSource({ clock: environment.clock, group: this.#serviceGroup,
        check: () => this.#check(),
        capture: () => { this.captureSession(); return this.#current!.runtime; },
        current: runtime => !this.#closed && !this.#blocked && !this.#initializing && this.#current?.runtime === runtime,
        target: session => {
          this.#check(); if (this.#blocked || this.#initializing) throw new Error("initialization_blocked");
          const selected = this.#current?.runtime === session ? this.#current : this.#retired?.runtime === session ? this.#retired : undefined;
          if (selected === undefined) throw new Error("source_unavailable");
          selected.runtime.controllerGate(this.#dependency!.reference); this.#check();
          if (this.#blocked || this.#initializing || selected !== this.#current && selected !== this.#retired) throw new Error("source_unavailable");
          return selected.runtime;
        },
        wait: (limit, invocation, cancelled) => this.#waitForService(limit, invocation, cancelled),
        retain: (reference, closed) => this.#retainService(reference, closed),
        observe: (reference, wake) => environment.resources.root.observeAvailability(reference, wake),
        observeCurrent: (reference, changed) => {
          this.#check();
          if (!reference.sameEnvironment(this.#dependency!.reference)) throw new Error("owner_unavailable");
          if (this.#serviceObservers.size >= 256) throw new Error("resource_exhausted");
          const retained = reference.borrow(); let active = true;
          this.#serviceObservers.add(changed);
          return () => { if (!active) return; active = false; this.#serviceObservers.delete(changed); retained.release(); };
        },
      }, captured, () => queries);
      const prepareConnection = (): void => {
        this.#check(); if (closed || connected || connection !== undefined) throw new Error("service_binding_closed");
        deadline.check(); this.#cancelRetry();
        connection = this.#prepareReplacement({ signal: cancellation }, false, deadline, admission => {
          if (contractSource === undefined && captured.methods.some(method => method.initial)) {
            if (admission === undefined) throw new Error("configuration_capacity");
            queries = environment.reserveDependencyQueries(admission);
          }
        }, captured.methods.filter(method => method.preacceptStream).map(method => ({
          method: Object.freeze({ ...method, required: true }), namespace: captured.namespace, target: captured.target,
        })));
      };
      const initializeBinding = async (onClose?: () => void): Promise<ServiceBinding> => {
        if (entered || closed) throw new Error("service_binding_closed"); entered = true;
        try {
          await source.waitForCurrent!(deadline, context, cancellation);
          binding = new ServiceBinding(captured, reservation, source);
          if (onClose !== undefined) binding.onClose(onClose);
          await binding.initialize(deadline, context, cancellation, contractSource);
          binding.checkDelivery(); deadline.check(); if (cancellation.aborted) throw new Error("canceled");
          return binding;
        } catch (error) { close(); throw error; }
        finally { queries?.close(); queries = undefined; pending?.release(); pending = undefined; }
      };
      return Object.freeze({ deadline, close, prepareConnection, initializeBinding,
        limitDeadline: (parent: TrustedDeadline): void => {
          if (parent.belongsTo(environment.clock)) deadline.tightenFrom(parent);
          else deadline.tighten(parent.cap < deadline.cap ? parent.cap : deadline.cap);
        },
        connect: (): Promise<V4ControllerReplaceResult> => {
          if (connection === undefined) prepareConnection();
          this.#check(); if (closed || connected) throw new Error("service_binding_closed"); connected = true;
          deadline.check(); this.#started = true; return connection!.start();
        }, initialize: async (onClose?: () => void) => serviceClient(definition, await initializeBinding(onClose)) });
    } catch (error) { close(); throw error; }
  }
  #retainService(reference: ResourceReference, closed: () => void): ServiceBindingLease {
    this.#check();
    if (!reference.sameEnvironment(this.#dependency!.reference)) throw new Error("owner_unavailable");
    const retained = reference.borrow(); let released = false;
    this.#serviceClosures.add(closed);
    return Object.freeze({ check: () => { if (released) throw new Error("closed"); this.#check(); retained.check(); },
      release: () => { if (released) return; released = true; this.#serviceClosures.delete(closed); retained.release(); } });
  }
  #waitForService(deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void> {
    if (applicationHasPermit(context)) { this.captureSession(); return Promise.resolve(); }
    const cancellation = context === undefined ? signal : AbortSignal.any([context.signal, ...(signal === undefined ? [] : [signal])]);
    return this.#wait(() => {
      this.#check(); deadline.check();
      if (this.#blocked) throw new Error("initialization_blocked");
      if (this.#initializing || this.#current === undefined) return undefined;
      try { this.captureSession(); return true; }
      catch (error) {
        if (error instanceof Error && ["session_draining", "closed", "not_ready"].includes(error.message)) return undefined;
        throw error;
      }
    }, cancellation, deadline).then(() => undefined);
  }
  status(): V4ControllerStatus {
    return Object.freeze({ started: this.#started, closed: this.#closed, current: this.#current !== undefined,
      pending: this.#attempt !== undefined || this.#retryWaiting, retired: this.#retired !== undefined, initializationBlocked: this.#blocked || this.#initializing,
      attempts: this.#attempts, generation: this.#current?.generation ?? 0n,
      headroom: !this.#headroomEnabled ? "disabled" : this.#headroom !== undefined ? "reserved" : this.#attempt !== undefined || this.#retired !== undefined ? "in_use" : "unavailable", diagnostic: this.diagnostic(), cleanup: this.cleanupStatus() });
  }
  /** A frozen monitoring snapshot, detached from the current Session. */
  diagnostic(): ConnectionDiagnostic {
    const state = this.#closed ? "closed" : this.#current !== undefined ? "connected" :
      this.#attempt !== undefined ? "connecting" : this.#retryWaiting ? "waiting" :
      this.#lastError !== undefined || this.#blocked ? "failed" : "idle";
    const failure = this.#lastError === undefined ? undefined : Object.freeze({
      phase: this.#lastFailurePhase, code: controllerFailureCode(this.#lastError),
    });
    return Object.freeze({ state, attempt: this.#attempts,
      ...(this.#attempt?.connection === undefined && this.#lastConnectionFacts === undefined ? {} : { connection: this.#lastConnectionFacts ?? this.#attempt!.connection!.facts() }),
      cleanup: this.cleanupStatus(),
      ...(failure === undefined ? {} : { failure, retryDisposition: "preserve_facts" as const }) });
  }
  /** Explain only facts already observed by this Controller. */
  localReport(): LocalReport {
    const diagnostic = this.diagnostic();
    return connectionLocalReport(diagnostic.failure?.code ?? "unknown", diagnostic.connection ?? unknownConnectionFacts(), diagnostic.cleanup ?? this.cleanupStatus());
  }
  LocalReport(): LocalReport { return this.localReport(); }
  /** Uses the original bounded wait slots. Cancellation ends only this wait. */
  waitForDiagnostic(previous: ConnectionDiagnostic, options?: OperationOptions): Promise<ConnectionDiagnostic> {
    const captured: ConnectionDiagnostic = Object.freeze({ state: previous.state, attempt: previous.attempt,
      ...(previous.connection === undefined ? {} : { connection: Object.freeze({ ...previous.connection }) }),
      ...(previous.cleanup === undefined ? {} : { cleanup: Object.freeze({ ...previous.cleanup }) }),
      ...(previous.failure === undefined ? {} : { failure: Object.freeze({ phase: previous.failure.phase, code: previous.failure.code }) }),
      ...(previous.retryDisposition === undefined ? {} : { retryDisposition: previous.retryDisposition }) });
    return this.#wait(() => {
      const latest = this.diagnostic();
      return this.#closed || !sameConnectionDiagnostic(captured, latest) ? latest : undefined;
    }, options?.signal);
  }
  cleanupStatus(): V4CleanupStatus {
    if (this.#dependency === undefined) return complete;
    return cleanupResult({ status: this.#incomplete ? "cleanup_incomplete" : "pending", core_cleanup: "pending",
      pending_callbacks: BigInt(this.#links.size + (this.#attempt === undefined ? 0 : 1)) });
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    return this.#wait(() => this.#dependency === undefined ? complete : undefined, options?.signal);
  }
  close(): Promise<V4CleanupStatus> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closePromise = new Promise(resolve => { this.#closeResolve = resolve; });
    this.#closed = true; this.#closing = true;
    for (const subscription of this.#notificationSubscriptions) subscription.close();
    this.#cancelRetry();
    for (const closed of [...this.#serviceClosures]) closed();
    if (this.#headroomRetryTimer !== undefined) clearTimeout(this.#headroomRetryTimer); this.#headroomRetryTimer = undefined;
    this.#attempt?.abort.abort(new Error("closed"));
    if (this.#headroom !== undefined) { const prepared = this.#headroom; this.#headroom = undefined; this.#closeCandidate(prepared); }
    this.#group?.close();
    if (this.#retentionTimer !== undefined) clearTimeout(this.#retentionTimer);
    this.#retentionTimer = undefined; this.#retention = undefined;
    for (const link of this.#links) void link.session.close().catch(() => undefined);
    try { this.#closeWindow = new TrustedWindow(this.#environment!.clock, 5000n); this.#tickClose(); }
    catch { this.#incomplete = true; }
    this.#closing = false; this.#collect(); this.#wake(); return this.#closePromise;
  }
  toJSON(): object { return {}; }

  #check(): void { if (this.#closed) throw new Error("closed"); this.#dependency!.check(); }
  #cancelRetry(): void {
    if (this.#retryTimer !== undefined) clearTimeout(this.#retryTimer);
    this.#retryTimer = undefined; this.#retryWaiting = false;
    this.#retryAfterMS = undefined;
    this.#retryWake?.(); this.#retryWake = undefined;
  }
  #retryReached(deadline: bigint | undefined): boolean {
    if (deadline === undefined) return true;
    try { return this.#environment!.clock.sample().requireInterval().lowerMS >= deadline; }
    catch { return false; }
  }
  #armRetry(deadline: bigint | undefined, increment: boolean): void {
    if (this.#closed || this.#blocked || this.#current !== undefined || this.#attempt !== undefined || this.#retryWaiting) return;
    if (increment) this.#retryFailures = Math.min(8, this.#retryFailures + 1);
    const delay = Math.min(30000, 250 * (2 ** (this.#retryFailures - 1)));
    this.#retryAfterMS = deadline;
    this.#retryWaiting = true;
    let wake!: () => void;
    const manual = new Promise<void>(resolve => { wake = resolve; });
    this.#retryWake = wake;
    let wallDelay = 0;
    if (deadline !== undefined) {
      try {
        const now = this.#environment!.clock.sample().requireInterval().lowerMS;
        if (deadline > now) wallDelay = Number(deadline - now > 30000n ? 30000n : deadline - now);
      } catch { wallDelay = 30000; }
    }
    const timer = new Promise<void>(resolve => { this.#retryTimer = setTimeout(resolve, Math.max(delay, wallDelay)); });
    void Promise.race([manual, timer]).then(() => {
      if (!this.#retryWaiting || this.#closed) return;
      if (!this.#retryReached(deadline)) {
        this.#retryTimer = undefined; this.#retryWaiting = false; this.#retryWake = undefined;
        this.#armRetry(deadline, false); return;
      }
      this.#retryTimer = undefined; this.#retryWake = undefined;
      this.#retryAfterMS = undefined;
      // Admission reservation can synchronously wake observers. Keep the retry
      // visible until the next attempt owns its slot and clears the prior error.
      try { void this.#replace({}, true).catch(() => undefined); }
      catch (error) {
        this.#lastFailurePhase = "controller";
        this.#lastError = new ConnectionError(controllerFailureCode(error), this.#lastConnectionFacts ?? new ConnectionFacts().snapshot(), this.cleanupStatus());
      } finally { this.#retryWaiting = false; this.#wake(); }
    });
    this.#wake();
  }
  #scheduleRetry(deadline?: bigint): void { this.#armRetry(deadline, true); }
  #replace(options: V4ControllerReplaceOptions, autoRetry = false, parentDeadline?: TrustedDeadline): Promise<V4ControllerReplaceResult> {
    return this.#prepareReplacement(options, autoRetry, parentDeadline).start();
  }
  #prepareReplacement(options: V4ControllerReplaceOptions, autoRetry = false, parentDeadline?: TrustedDeadline, prepareService?: (admission: ClientSessionAdmission | undefined) => void, streamTargets: readonly InitializerMethodTarget[] = []): PreparedControllerConnection {
    if (this.#reserving) throw new Error("busy"); this.#reserving = true;
    try { return this.#prepareReplacementOwned(options, autoRetry, parentDeadline, prepareService, streamTargets); }
    finally { this.#reserving = false; }
  }
  #prepareReplacementOwned(options: V4ControllerReplaceOptions, autoRetry: boolean, parentDeadline: TrustedDeadline | undefined,
    prepareService: ((admission: ClientSessionAdmission | undefined) => void) | undefined, streamTargets: readonly InitializerMethodTarget[]): PreparedControllerConnection {
    this.#check(); if (options.signal?.aborted) throw new Error("canceled");
    if (this.#attempt !== undefined) throw new Error("busy");
    if (this.#workload?.cleanupComplete()) this.#workload = undefined;
    if (this.#workload !== undefined) throw new Error("resource_exhausted");
    if (this.#retired !== undefined) throw new Error("retirement_capacity");
    const previous = this.#current, retirement = options.retirement ?? "drain";
    if (retirement !== "drain" && retirement !== "retain" || retirement === "drain" && options.retainUntilMS !== undefined) throw new Error("invalid_argument");
    let retention: TrustedDeadline | undefined;
    if (retirement === "retain") {
      if (previous === undefined || typeof options.retainUntilMS !== "bigint") throw new Error("invalid_argument");
      const cap = previous.runtime.controllerGate(this.#dependency!.reference);
      if (options.retainUntilMS > cap) throw new Error("invalid_argument");
      retention = new TrustedDeadline(this.#environment!.clock, options.retainUntilMS);
    }
    const clock = this.#environment!.clock, sample = clock.sample();
    const deadline = TrustedDeadline.ageAt(clock, sample, this.#config!.attemptTimeoutMS!, parentDeadline?.cap ?? 0xffffffffffffffffn);
    if (parentDeadline !== undefined) deadline.tightenFrom(parentDeadline);
    const window = new TrustedWindow(clock, this.#config!.attemptTimeoutMS!);
    this.#check(); if (this.#attempt !== undefined || previous !== this.#current) throw new Error("busy");
    if (this.#attempts === 0xffffffffffffffffn) throw new Error("resource_exhausted");
    if (this.#nextGeneration === 0xffffffffffffffffn) throw new Error("resource_exhausted");
    if (prepareService !== undefined) this.#headroomStreams = streamTargets;
    const requiredStreams = prepareService === undefined ? this.#headroomStreams : streamTargets;
    let prepared: CandidatePreparation;
    if (this.#headroom !== undefined && prepareService === undefined) {
      prepared = this.#headroom; this.#headroom = undefined;
    } else prepared = this.#reserveCandidate(prepareService, requiredStreams);
    let newHeadroom = false;
    try {
      // The first connection and its promised replacement coexist before any
      // source call. Later replacements consume this same original admission.
      if (this.#headroomEnabled && previous === undefined && this.#headroom === undefined) {
        this.#headroom = this.#reserveCandidate(undefined, this.#headroomStreams); newHeadroom = true;
      }
      this.#check(); deadline.check();
      if (options.signal?.aborted || this.#attempt !== undefined || this.#current !== previous) throw new Error("canceled");
    } catch (error) {
      this.#closeCandidate(prepared);
      if (newHeadroom && this.#headroom !== undefined) { const unused = this.#headroom; this.#headroom = undefined; this.#closeCandidate(unused); }
      throw error;
    }
    const { dependencies, workload, callback, abort, connection, streams } = prepared;
    this.#workload = workload;
    let resolve!: (result: V4ControllerReplaceResult) => void, reject!: Attempt["reject"];
    const promise = new Promise<V4ControllerReplaceResult>((yes, no) => { resolve = yes; reject = no; });
    const generation = ++this.#nextGeneration;
    const attempt: Attempt = { abort, window, deadline, dependencies, workload, callback, previous, retirement, retention, autoRetry, reject, generation, ordinal: this.#attempts + 1n,
      connection, ...(streams === undefined ? {} : { streams }),
      candidate: undefined, entered: false, committed: false, settled: false, result: undefined, timer: undefined };
    this.#attempt = attempt; this.#attempts++; this.#lastError = undefined; this.#lastConnectionFacts = undefined; this.#lastFailurePhase = "connect";
    let started = false, finished = false;
    const cancel = (): void => { attempt.abort.abort(new Error("canceled")); };
    const aborted = (): void => {
      if (attempt.committed) return;
      attempt.connection?.failed(attempt.abort.signal.reason);
      if (attempt.entered) this.#blocked = true;
      if (!attempt.settled) {
        attempt.settled = true;
        const facts = attempt.connection!.facts();
        this.#lastConnectionFacts = Object.freeze({ ...facts,
          ...(facts.admissionState === "in_flight" ? { admissionState: "unknown" as const } : {}),
          ...(attempt.candidate === undefined ? {} : { applicationPublish: "failed" as const }) });
        this.#lastError = new ConnectionError(controllerFailureCode(attempt.abort.signal.reason), this.#lastConnectionFacts, this.cleanupStatus());
        reject(this.#lastError);
      }
      if (attempt.candidate !== undefined) void attempt.candidate.session.close().catch(() => undefined);
      if (!started) finish();
      this.#wake();
    };
    attempt.abort.signal.addEventListener("abort", aborted, { once: true });
    options.signal?.addEventListener("abort", cancel, { once: true });
    const finish = (): void => {
      if (finished) return; finished = true;
      if (attempt.timer !== undefined) clearTimeout(attempt.timer);
      options.signal?.removeEventListener("abort", cancel); attempt.abort.signal.removeEventListener("abort", aborted);
      attempt.connection?.close(); attempt.streams?.close(); attempt.workload?.close(); attempt.callback?.close();
      if (attempt.candidate === undefined) attempt.dependencies.close();
      this.#attempt = undefined; this.#initializing = false; this.#collect();
      if (!attempt.settled && attempt.result !== undefined) { attempt.settled = true; resolve(attempt.result); }
      const facts = this.#lastConnectionFacts ?? attempt.connection!.facts();
      if (started && !attempt.committed && attempt.autoRetry && !attempt.entered && !attempt.retryAfterInvalid &&
          (attempt.transportFailure || facts.phase === "not_started" && facts.spendState === "unspent") &&
          !attempt.abort.signal.aborted && !this.#closed && !this.#blocked && this.#current === undefined) this.#scheduleRetry(attempt.retryAfterMS);
      this.#wake();
    };
    // Cancellation can settle a prepared attempt before its factory starts it.
    void promise.catch(() => undefined);
    try {
      if (options.signal?.aborted) cancel();
      this.#checkAttempt(attempt);
      this.#tickAttempt(attempt);
      return Object.freeze({ close: () => { if (!finished) attempt.abort.abort(new Error("closed")); }, start: () => {
        if (started) return Promise.reject(new Error("closed"));
        if (finished) return promise; started = true;
        void this.#run(attempt).finally(finish).catch(() => undefined); return promise;
      } });
    } catch (error) { attempt.abort.abort(error); finish(); throw error; }
  }

  #reserveCandidate(prepareService?: (admission: ClientSessionAdmission | undefined) => void,
    streamTargets: readonly InitializerMethodTarget[] = []): CandidatePreparation {
    this.#check(); const dependencies = new CandidateServiceDependencies(this.#declarations), abort = new AbortController();
    let workload: InitializerWorkload | undefined, callback: ApplicationStartPosition | undefined;
    let streams: RawStreamPreparation | undefined, connection: PreparedEnvironmentConnection | undefined;
    try {
      const targets = dependencies.workloadTargets();
      if (targets.length !== 0) workload = new InitializerWorkload(this.#environment!, this.#group!, targets, this.#config!.initializeWorkload, this.#config!.initializeWorkClass);
      callback = this.#group?.reserveStart(this.#config!.initializeWorkClass!);
      connection = this.#environment!.prepareConnect(this.#config!.source, this.#config!.requirements, { signal: abort.signal }, admission => {
        this.#check(); dependencies.reserve(this.#environment!, admission, streamTargets); workload?.reserveCalls(admission); prepareService?.(admission);
        if (this.#streamDeclarations.length !== 0) streams = this.#environment!.reserveRawStreams(admission, this.#streamDeclarations);
      }, () => this.#wake(), runtime => {
        for (const subscription of this.#notificationSubscriptions) subscription.attachSource(runtime, false);
      });
      this.#check(); return { abort, dependencies, workload, callback, streams, connection };
    } catch (error) {
      abort.abort(error); connection?.close(); streams?.close(); workload?.close(); callback?.close(); dependencies.close(); throw error;
    }
  }
  #closeCandidate(prepared: CandidatePreparation): void {
    prepared.abort.abort(new Error("closed")); prepared.connection.close(); prepared.streams?.close();
    prepared.workload?.close(); prepared.callback?.close(); prepared.dependencies.close();
  }
  #replenishHeadroom(): void {
    if (!this.#headroomEnabled || this.#closed || this.#reserving || this.#headroomRetryTimer !== undefined || this.#headroom !== undefined || this.#attempt !== undefined ||
        this.#retired !== undefined || this.#current === undefined || this.#workload !== undefined) return;
    this.#reserving = true;
    try { this.#headroom = this.#reserveCandidate(undefined, this.#headroomStreams); this.#headroomFailures = 0; }
    catch {
      // Failed partial reservations also release resources. Bound their own
      // availability wakes so they cannot create an endless microtask retry.
      if (!this.#closed) {
        this.#headroomFailures = Math.min(8, this.#headroomFailures + 1);
        this.#headroomRetryTimer = setTimeout(() => { this.#headroomRetryTimer = undefined; this.#collect(); },
          Math.min(30000, 250 * 2 ** (this.#headroomFailures - 1)));
      }
    }
    finally { this.#reserving = false; }
  }

  #checkAttempt(attempt: Attempt): void {
    this.#check(); attempt.window.check(); attempt.deadline.check(); attempt.retention?.check();
    if (this.#attempt !== attempt || attempt.abort.signal.aborted) throw attempt.abort.signal.reason ?? new Error("canceled");
    attempt.candidate?.runtime.controllerGate(this.#dependency!.reference);
    this.#check(); if (attempt.abort.signal.aborted) throw attempt.abort.signal.reason;
  }
  #tickAttempt(attempt: Attempt): void {
    attempt.timer = undefined;
    try {
      this.#checkAttempt(attempt); const a = attempt.window.remainingMS(), b = attempt.deadline.remainingMS(), remaining = a < b ? a : b;
      this.#check(); if (attempt.abort.signal.aborted) return;
      attempt.timer = setTimeout(() => this.#tickAttempt(attempt), timerChunk(remaining));
    } catch (error) { attempt.abort.abort(error); }
  }
  async #run(attempt: Attempt): Promise<void> {
    let published = false;
    try {
      this.#checkAttempt(attempt);
      const runtime = await attempt.connection!.start(attempt.ordinal, true);
      if (!(runtime instanceof V4AuthenticatedSessionRuntime)) { await runtime.close(); throw new Error("owner_unavailable"); }
      let cleaned!: () => void;
      const completion = new Promise<void>(resolve => { cleaned = resolve; });
      const link: Link = { runtime, session: new V4Session(runtime), cleaned: completion, dependencies: attempt.dependencies, generation: attempt.generation };
      attempt.candidate = link; this.#links.add(link); this.#observe(link, cleaned);
      for (const subscription of this.#notificationSubscriptions) subscription.attachSource(link.runtime);
      this.#checkAttempt(attempt);
      await link.dependencies.prepare(runtime, attempt.deadline, attempt.abort.signal, () => this.#checkAttempt(attempt));
      this.#checkAttempt(attempt);
      // Transfer the pre-Acquire owners while the authenticated candidate is
      // private. Its normal registration/OPEN/cleanup path owns all later work.
      if (attempt.streams !== undefined) runtime.installPreparedRawStreams(attempt.streams);
      const initialize = this.#config!.initializeSession;
      if (initialize !== undefined) {
        const group = this.#group!;
        const permit = attempt.callback!.checkout();
        let invocation: ReturnType<ApplicationGroup["context"]> | undefined;
        let view: ReturnType<CandidateServiceDependencies["view"]> | undefined;
        try {
          this.#checkAttempt(attempt);
          view = link.dependencies.view(attempt.deadline, () => this.#checkAttempt(attempt), attempt.workload);
          invocation = group.context(permit, runtime.controllerAuthentication(this.#dependency!.reference), attempt.abort.signal, undefined, undefined, view.services);
          view.enter(invocation.context);
          attempt.entered = true; this.#initializing = true; this.#wake();
          this.#checkAttempt(attempt); await initialize(invocation.context as V4ControllerInitializationContext<Dependencies>, link.session);
        } finally { view?.revoke(); if (invocation === undefined) permit.release(); else invocation.release(); }
      }
      link.dependencies.checkRequired(); this.#checkAttempt(attempt);
      if (this.#current !== attempt.previous) throw new Error("not_ready");
      // No application/host call between the final gate and pointer publication.
      this.#current = link; this.#generation = link.generation; this.#retired = attempt.previous; this.#blocked = false; this.#initializing = false; published = true; attempt.committed = true;
      for (const subscription of this.#notificationSubscriptions) subscription.stageSourcePublication(link.runtime, attempt.retirement);
      for (const subscription of this.#notificationSubscriptions) subscription.flushSourcePublication();
      this.#lastConnectionFacts = Object.freeze({ ...attempt.connection!.facts(), applicationPublish: "published" });
      // Backoff is scoped to one uninterrupted outage. Once a candidate has
      // crossed the publication gate, a later independent disconnect starts
      // at the minimum retry delay instead of inheriting stale failures from
      // an earlier outage.
      this.#retryFailures = 0;
      let previousRetained = false, retirementError: unknown;
      if (attempt.previous !== undefined) {
        try {
          if (attempt.retirement === "retain") {
            attempt.previous.runtime.controllerGate(this.#dependency!.reference);
            this.#retention = attempt.retention; this.#tickRetention(); previousRetained = this.#retention !== undefined;
          } else attempt.previous.session.drain({ timeoutMS: this.#config!.drainTimeoutMS! });
        } catch (error) { retirementError = compactError(error); void attempt.previous.session.close().catch(() => undefined); }
      }
      attempt.result = Object.freeze({ current: link.session, previous: attempt.previous?.session, retirement: attempt.retirement, previousRetained, retirementError });
      this.#wake();
    } catch (error) {
      if (!published) attempt.connection?.failed(error);
      attempt.transportFailure = !attempt.abort.signal.aborted && originalNativeConnectionFailure(error);
      this.#lastFailurePhase = attempt.candidate === undefined ? "connect" : "session";
      this.#lastConnectionFacts = Object.freeze({ ...attempt.connection!.facts(), ...(attempt.candidate === undefined ? {} : { applicationPublish: "failed" as const }) });
      const failureCode = controllerFailureCode(error);
      this.#lastError = new ConnectionError(attempt.entered && failureCode === "controller_failed" ? "initialization_failed" : failureCode, this.#lastConnectionFacts, this.cleanupStatus()); if (attempt.entered && !published) this.#blocked = true;
      const candidate = error as { readonly retryAfterMS?: unknown; readonly retryAfterUnixMS?: unknown };
      const rawRetryAfter = candidate !== null && typeof candidate === "object" ? candidate.retryAfterMS ?? candidate.retryAfterUnixMS : undefined;
      const retryAfter = typeof rawRetryAfter === "bigint" ? rawRetryAfter :
        typeof rawRetryAfter === "number" && Number.isSafeInteger(rawRetryAfter) ? BigInt(rawRetryAfter) : undefined;
      if (rawRetryAfter !== undefined) {
        if (retryAfter !== undefined && retryAfter >= 0n && retryAfter <= maxRetryAfterMS) attempt.retryAfterMS = retryAfter;
        else attempt.retryAfterInvalid = true;
      }
      if (!attempt.settled) { attempt.settled = true; attempt.reject(this.#lastError); }
      this.#wake();
      if (!published && attempt.candidate !== undefined) {
        void attempt.candidate.session.close().catch(() => undefined);
        // Keep the failed candidate in the one pending slot until actual cleanup.
        await attempt.candidate.cleaned;
      }
    }
  }
  #observe(link: Link, cleaned: () => void): void {
    link.runtime.cleanupOwner.onControllerCleanup(() => {
      const wasCurrent = this.#current === link;
      link.dependencies.close(); this.#links.delete(link);
      if (wasCurrent) this.#current = undefined;
      if (this.#retired === link) {
        this.#retired = undefined; this.#retention = undefined;
        if (this.#retentionTimer !== undefined) clearTimeout(this.#retentionTimer); this.#retentionTimer = undefined;
      }
      for (const subscription of this.#notificationSubscriptions) subscription.retireSource(link.runtime);
      // Candidate failures are decided by their original attempt after cleanup.
      // Only the published current can start a separate reconnect cycle here.
      if (wasCurrent && link.runtime.controllerReconnectAllowed() && this.#started &&
          this.#current === undefined && this.#attempt === undefined && !this.#closed && !this.#blocked) this.#scheduleRetry();
      cleaned(); this.#collect(); this.#wake();
    });
  }
  #tickRetention(): void {
    this.#retentionTimer = undefined;
    try {
      this.#check(); this.#retention!.check(); const remaining = this.#retention!.remainingMS(); this.#check();
      this.#retentionTimer = setTimeout(() => this.#tickRetention(), timerChunk(remaining));
    } catch {
      this.#retention = undefined; if (this.#retired !== undefined) void this.#retired.session.close().catch(() => undefined);
    }
  }
  #tickClose(): void {
    this.#closeTimer = undefined;
    try { this.#closeWindow!.check(); this.#closeTimer = setTimeout(() => this.#tickClose(), timerChunk(this.#closeWindow!.remainingMS())); }
    catch { this.#incomplete = true; this.#closeResolve?.(this.cleanupStatus()); this.#closeResolve = undefined; }
  }
  #collect(): void {
    if (this.#collecting) return; this.#collecting = true;
    try { this.#collectOwned(); } finally { this.#collecting = false; }
  }
  #collectOwned(): void {
    if (this.#workload?.cleanupComplete()) this.#workload = undefined;
    this.#replenishHeadroom();
    if (this.#closed) for (const subscription of this.#notificationSubscriptions) subscription.close();
    if (!this.#closed || this.#closing || this.#attempt !== undefined || this.#workload !== undefined || this.#links.size !== 0 || this.#group?.cleanupComplete() === false || this.#notificationSubscriptions.size !== 0) {
      if (this.#closed && this.#incomplete && !this.#closing) { this.#closeResolve?.(this.cleanupStatus()); this.#closeResolve = undefined; }
      return;
    }
    if (this.#closeTimer !== undefined) clearTimeout(this.#closeTimer); this.#closeTimer = undefined;
    this.#closeWindow = undefined; this.#environment = undefined; this.#config = undefined; this.#group = undefined; this.#declarations = []; this.#streamDeclarations = []; this.#headroomStreams = [];
    this.#notificationOwners?.close(); this.#notificationOwners = undefined;
    this.#resourceObserver?.(); this.#resourceObserver = undefined;
    this.#dependency?.release(); this.#dependency = undefined; this.#current = undefined; this.#retired = undefined;
    this.#closeResolve?.(complete); this.#closeResolve = undefined;
  }
  #wake(): void {
    for (const wake of this.#waiters) wake();
    for (const changed of [...this.#serviceObservers]) changed();
  }
  #wait<T>(value: () => T | undefined, signal?: AbortSignal, deadline?: TrustedDeadline): Promise<T> {
    if (signal?.aborted) return Promise.reject(new Error("canceled"));
    try { const ready = value(); if (ready !== undefined) return Promise.resolve(ready); }
    catch (error) { return Promise.reject(error); }
    if (this.#waiters.size >= 32) return Promise.reject(new Error("resource_exhausted"));
    return new Promise((resolve, reject) => {
      let settled = false, timer: ReturnType<typeof setTimeout> | undefined;
      const finish = (): void => { settled = true; if (timer !== undefined) clearTimeout(timer); this.#waiters.delete(wake); signal?.removeEventListener("abort", wake); };
      const wake = (): void => {
        if (settled) return;
        try {
          if (signal?.aborted) throw new Error("canceled");
          deadline?.check();
          const ready = value(); if (ready === undefined) {
            if (deadline !== undefined && timer === undefined) timer = setTimeout(() => { timer = undefined; wake(); }, timerChunk(deadline.remainingMS()));
            return;
          }
          finish(); resolve(ready);
        } catch (error) { finish(); reject(error); }
      };
      this.#waiters.add(wake); signal?.addEventListener("abort", wake, { once: true }); wake();
    });
  }
}
export function createV4ConnectionController<Dependencies extends V4ServiceDependencies = {}>(environment: V4TransportEnvironment, config: V4ControllerConfig<Dependencies>): V4ConnectionController<Dependencies> {
  return new V4ConnectionController(token, originalEnvironment(environment), config);
}
