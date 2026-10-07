import { createNodeTunnelDialerListener, type NodeTunnelDialerOptions } from "./endpointDialer.js";
import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4Session, V4TransportEnvironment } from "../v4/public.js";
import type { HandlerPlan } from "../v4/handlerPlan.js";
import type { AuthenticatedRequestContext, ServeCallbacks, ServeHandle } from "../v4/serve.js";
import { ServeError, observeServeCleanup } from "../v4/serve.js";
import type { V4MaintenanceOwner } from "../v4/responsePublication.js";
import type { V4DrainOptions } from "../v4/drain.js";
import { originalEnvironment, type EnvironmentDependency } from "../v4/runtime/environment.js";
import { TrustedWindow, timerChunk } from "../v4/runtime/deadline.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { createNodeWebTransportListener, type NodeWebTransportListenerOptions } from "./webTransportCurrent.js";
import { createNodeRawQUICListener, type NodeRawQUICListenerOptions } from "./serveRawQUIC.js";
import { createNodeWSSListener, type NodeWSSListener, type NodeWSSListenerOptions } from "./serveWSS.js";

const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
export interface AcceptorOptions extends Omit<ServeCallbacks<HandlerPlan>, "onSession"> {
  readonly environment: V4TransportEnvironment;
  readonly listeners: readonly ((NodeWSSListenerOptions & Readonly<{ carrierKind?: "wss" }>) |
    (NodeRawQUICListenerOptions & Readonly<{ carrierKind: "raw_quic" }>) | (NodeWebTransportListenerOptions & Readonly<{ carrierKind: "webtransport" }>) | NodeTunnelDialerOptions)[];
  readonly maxPendingSessions: number;
  readonly maxPendingAccepts?: number;
  readonly maintenanceOwner?: V4MaintenanceOwner;
  readonly cleanupMS?: bigint;
}
export class AcceptedSession {
  constructor(readonly session: V4Session, readonly context: AuthenticatedRequestContext) { Object.freeze(this); }
  close() { return this.session.close(); }
  cleanupStatus(): V4CleanupStatus { return this.session.cleanupStatus(); }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> { return this.session.waitCleanup(options); }
  /** HandlerPlan handlers already run on the original accepted Session. */
  serve(options?: OperationOptions): Promise<void> { return this.session.waitTermination(options); }
}
interface PendingSession { readonly accepted: AcceptedSession; readonly observation: AbortController }
interface Waiter {
  readonly resolve: (session: AcceptedSession) => void;
  readonly reject: (error: ServeError) => void;
  readonly signal: AbortSignal | undefined;
  readonly cancel: () => void;
}
/** An accept queue over the actual current Serve owners. Only authenticated
 * READY Sessions enter it; each waiter and queue position was charged before
 * ingress started, and cancellation changes only that original waiter. */
export class Acceptor {
  readonly #listeners: Readonly<{ carrier: "wss" | "raw_quic" | "webtransport"; capability: NodeWSSListener }>[] = [];
  readonly #handles: ServeHandle[] = [];
  readonly #pending: PendingSession[] = [];
  readonly #queueObservations = new Set<PendingSession>();
  readonly #waiters: Waiter[] = [];
  readonly #abort = new AbortController();
  #dependency: EnvironmentDependency | undefined;
  #closed = false;
  #draining = false;
  #initializing = false;
  #finished = false;
  readonly #cleanupObservers = new Set<() => void>();
  #addresses: readonly Readonly<{ host: string; port: number }>[] = Object.freeze([]);
  readonly #cleanupMS: bigint;
  #started = false;
  #maximumSessions: number;
  #maximumWaiters: number;
  #close: Promise<V4CleanupStatus> | undefined;
  #parent: AbortSignal | undefined;
  readonly #parentClosed = () => { void this.close().catch(() => undefined); };
  constructor(readonly environment: V4TransportEnvironment, maximumSessions: number, maximumWaiters: number, cleanupMS = 10000n) {
    if (![maximumSessions, maximumWaiters].every(value => Number.isSafeInteger(value) && value >= 1 && value <= 1024)) throw new ServeError("configuration_capacity", complete);
    if (typeof cleanupMS !== "bigint" || cleanupMS < 1n || cleanupMS > 600000n) throw new ServeError("configuration_capacity", complete);
    this.#cleanupMS = cleanupMS;
    this.#maximumSessions = maximumSessions; this.#maximumWaiters = maximumWaiters;
    const runtime = originalEnvironment(environment), n = BigInt(maximumSessions + maximumWaiters + 32 + 16);
    this.#dependency = runtime.admitDependency("acceptor_queue", new ResourceVector([8192n + n * (1024n + runtime.resources.runtimeBytes), 0n, 0n, 1n + n, 0n, 17n + BigInt(maximumWaiters) + 32n, 32n, 0n, 0n, 0n, 0n]));
    this.#dependency.onClose(() => { void this.close().catch(() => undefined); });
  }
  async initialize(options: AcceptorOptions, operation?: OperationOptions): Promise<void> {
    if (this.#started || this.#closed) throw new ServeError("owner_unavailable", this.cleanupStatus());
    this.#started = this.#initializing = true;
    try {
      const configurations = options.listeners, maintenanceOwner = options.maintenanceOwner;
      if (options.environment !== this.environment || !Array.isArray(configurations) || configurations.length < 1 || configurations.length > 16) throw new ServeError("configuration_capacity", complete);
      const callbacks = Object.freeze({ authorizeRequest: options.authorizeRequest, resolveHandlers: options.resolveHandlers,
        authorizeApplication: options.authorizeApplication, release: options.release });
      if (Object.values(callbacks).some(callback => typeof callback !== "function")) throw new ServeError("configuration_capacity", complete);
      // Validate and capture every native listener before opening the first one.
      for (const config of Array.from(configurations)) {
        if ("physicalDirection" in config) this.#listeners.push(Object.freeze({ carrier: config.carrierKind === "wss" ? "wss" : "raw_quic", capability: createNodeTunnelDialerListener(this.environment, config) }));
        else if (config.carrierKind === "webtransport") this.#listeners.push(Object.freeze({ carrier: "webtransport", capability: createNodeWebTransportListener(this.environment, config) }));
        else if (config.carrierKind === "raw_quic") this.#listeners.push(Object.freeze({ carrier: "raw_quic", capability: createNodeRawQUICListener(this.environment, config) }));
        else this.#listeners.push(Object.freeze({ carrier: "wss", capability: createNodeWSSListener(this.environment, config) }));
      }
      this.#parent = operation?.signal;
      this.#parent?.addEventListener("abort", this.#parentClosed, { once: true });
      if (this.#parent?.aborted) throw new ServeError("canceled", this.cleanupStatus());
      for (const listener of this.#listeners) {
        if (this.#closed || this.#draining) throw new ServeError("closed", this.cleanupStatus());
        const handle = await this.environment.serve({ listener: listener.capability.listener, carrier: listener.carrier === "webtransport" ? "raw_quic" : listener.carrier, ...callbacks,
          ...(maintenanceOwner === undefined ? {} : { maintenanceOwner }),
          onSession: (session, context) => this.#handoff(session, context),
        }, { signal: this.#abort.signal });
        this.#handles.push(handle);
        observeServeCleanup(handle, () => this.#changed());
        if (this.#closed) { handle.close(); throw new ServeError("closed", this.cleanupStatus()); }
        if (this.#draining) { handle.drain(); throw new ServeError("closed", this.cleanupStatus()); }
      }
      this.#addresses = Object.freeze(this.#listeners.map(listener => Object.freeze({ ...listener.capability.address() })));
    } catch (error) {
      // Closing cannot await this same startup invocation. Its budget remains
      // held until finally and all physically started listener owners retire.
      void this.close().catch(() => undefined); throw error;
    } finally { this.#initializing = false; this.#changed(); }
  }
  #handoff(session: V4Session, context: AuthenticatedRequestContext): Readonly<{ accepted: boolean }> {
    // Serve invokes this only as the continuation of an authenticated READY
    // claim. Sealing the queue cannot revoke a claim that already succeeded.
    // A sealed acceptor acknowledges the handoff while the original Serve
    // owner drains/closes the Session and retains its cleanup obligations.
    if (this.#closed || this.#draining || context.signal.aborted) return Object.freeze({ accepted: true });
    const accepted = new AcceptedSession(session, context), waiter = this.#waiters.shift();
    if (waiter !== undefined) {
      waiter.signal?.removeEventListener("abort", waiter.cancel);
      waiter.resolve(accepted);
      return Object.freeze({ accepted: true });
    }
    if (this.#queueObservations.size >= this.#maximumSessions) return Object.freeze({ accepted: false });
    const queued: PendingSession = { accepted, observation: new AbortController() };
    this.#pending.push(queued); this.#queueObservations.add(queued);
    void session.waitTermination({ signal: queued.observation.signal }).finally(() => {
      const index = this.#pending.indexOf(queued);
      if (index >= 0) this.#pending.splice(index, 1);
      this.#queueObservations.delete(queued); this.#changed();
    }).catch(() => undefined);
    return Object.freeze({ accepted: true });
  }
  addresses(): readonly Readonly<{ host: string; port: number }>[] { return this.#addresses; }
  accept(options?: OperationOptions): Promise<AcceptedSession> {
    if (this.#closed || this.#draining || options?.signal?.aborted) return Promise.reject(new ServeError(options?.signal?.aborted ? "canceled" : "closed", this.cleanupStatus()));
    const queued = this.#pending.shift();
    if (queued !== undefined) { queued.observation.abort(); return Promise.resolve(queued.accepted); }
    if (this.#waiters.length >= this.#maximumWaiters) return Promise.reject(new ServeError("resource_exhausted", this.cleanupStatus()));
    return new Promise((resolve, reject) => {
      const signal = options?.signal;
      const waiter: Waiter = { resolve, reject, signal, cancel: () => {
        const index = this.#waiters.indexOf(waiter);
        if (index < 0) return;
        this.#waiters.splice(index, 1); signal?.removeEventListener("abort", waiter.cancel);
        reject(new ServeError("canceled", this.cleanupStatus()));
      } };
      this.#waiters.push(waiter); signal?.addEventListener("abort", waiter.cancel, { once: true });
      if (signal?.aborted) waiter.cancel();
    });
  }
  #sealAccepts(): void {
    this.#draining = true;
    for (const waiter of this.#waiters.splice(0)) {
      waiter.signal?.removeEventListener("abort", waiter.cancel);
      waiter.reject(new ServeError("closed", this.cleanupStatus()));
    }
    for (const queued of this.#pending.splice(0)) queued.observation.abort();
  }
  drain(options?: V4DrainOptions) {
    this.#sealAccepts();
    return Object.freeze(Array.from(this.#handles).map(handle => handle.drain(options)));
  }
  async waitDrain(options?: OperationOptions) { return Object.freeze(await Promise.all(this.#handles.map(handle => handle.waitDrain(options)))); }
  close(): Promise<V4CleanupStatus> {
    if (this.#close !== undefined) return this.#close;
    this.#closed = true; this.#sealAccepts(); this.#abort.abort();
    this.#parent?.removeEventListener("abort", this.#parentClosed); this.#parent = undefined;
    for (const handle of Array.from(this.#handles)) handle.close();
    this.#changed();
    return this.#close = this.waitCleanup();
  }
  #changed(): void {
    if (!this.#finished && (this.#closed || this.#draining) && !this.#initializing && this.#queueObservations.size === 0 && this.#handles.every(handle => handle.cleanupStatus().status === "complete")) {
      this.#finished = true;
      this.#dependency?.release(); this.#dependency = undefined;
      this.#listeners.length = this.#handles.length = 0;
      this.#parent?.removeEventListener("abort", this.#parentClosed); this.#parent = undefined;
    }
    for (const wake of this.#cleanupObservers) wake();
  }
  cleanupStatus(): V4CleanupStatus {
    if (this.#finished) return complete;
    const snapshots = this.#handles.map(handle => handle.cleanupStatus());
    return Object.freeze({ status: snapshots.some(value => value.status === "cleanup_incomplete") ? "cleanup_incomplete" : "pending",
      core_cleanup: !this.#initializing && (this.#closed || this.#draining) && snapshots.every(value => value.core_cleanup === "complete") ? "complete" : "pending",
      pending_callbacks: snapshots.reduce((n, value) => n + value.pending_callbacks, 0n) });
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    if (options?.signal?.aborted) return Promise.reject(new ServeError("canceled", this.cleanupStatus()));
    this.#changed();
    const current = this.cleanupStatus();
    if (current.status !== "pending") return Promise.resolve(current);
    if (this.#cleanupObservers.size >= 32) return Promise.reject(new ServeError("resource_exhausted", current));
    return new Promise((resolve, reject) => {
      let done = false, timer: ReturnType<typeof setTimeout> | undefined;
      const signal = options?.signal;
      const finish = (canceled = false, expired = false): void => {
        if (done) return; done = true;
        if (timer !== undefined) clearTimeout(timer);
        this.#cleanupObservers.delete(wake); signal?.removeEventListener("abort", abort);
        const status = this.cleanupStatus();
        if (canceled) reject(new ServeError("canceled", status));
        else resolve(expired && status.status === "pending" ? Object.freeze({ ...status, status: "cleanup_incomplete" as const }) : status);
      };
      const abort = () => finish(true), wake = () => { if (this.cleanupStatus().status !== "pending") finish(); };
      this.#cleanupObservers.add(wake); signal?.addEventListener("abort", abort, { once: true });
      try {
        const window = new TrustedWindow(originalEnvironment(this.environment).clock, this.#cleanupMS);
        const tick = (): void => {
          try { window.check(); timer = setTimeout(tick, timerChunk(window.remainingMS())); }
          catch { finish(false, true); }
        };
        if (signal?.aborted) abort(); else { wake(); if (!done) tick(); }
      } catch { finish(false, true); }
    });
  }

}
export async function createAcceptor(options: AcceptorOptions, operation?: OperationOptions): Promise<Acceptor> {
  const acceptor = new Acceptor(options.environment, options.maxPendingSessions, options.maxPendingAccepts ?? options.maxPendingSessions, options.cleanupMS);
  try { await acceptor.initialize(options, operation); return acceptor; }
  catch (error) { await acceptor.close(); throw error; }
}
