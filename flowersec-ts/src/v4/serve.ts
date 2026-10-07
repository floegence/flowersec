import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4TransportEnvironment, V4Session } from "./public.js";
import type { V4AuthenticatedContext } from "./streamHandlers.js";
import type { V4MaintenanceOwner } from "./responsePublication.js";
import type { V4DrainOptions, V4DrainOperation } from "./drain.js";

/** Carrier policy input. These fields do not identify an authenticated peer. */
export interface ServeRequestContext {
  readonly invocation: object;
  readonly signal: AbortSignal;
  readonly origin: string;
}
export interface AuthenticatedRequestContext {
  readonly invocation: object;
  readonly signal: AbortSignal;
  readonly authentication: V4AuthenticatedContext;
}
/** Application-owned reservation. Close burns this invocation's authorization;
 * waitCleanup observes real work and may be called again after an incomplete
 * bounded observation. Close is invoked once; observations never overlap. */
export interface ApplicationAuthorizationLease {
  close(): void;
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus>;
}
export type AuthorizeApplicationResult<Plan extends object = object> =
  | Readonly<{ decision: "authorized"; handlers: Plan; lease: ApplicationAuthorizationLease }>
  | Readonly<{ decision: "rejected" | "unknown"; lease?: ApplicationAuthorizationLease }>;
export interface ServeReleaseContext {
  readonly invocation: object;
  readonly authentication?: V4AuthenticatedContext;
  readonly authorization: "not_started" | "authorized" | "rejected" | "unknown";
  readonly published: boolean;
  readonly cleanup: V4CleanupStatus;
}
export interface ServeCallbacks<Plan extends object = object> {
  readonly authorizeRequest: (context: ServeRequestContext) => Readonly<{ allowed: boolean }> | Promise<Readonly<{ allowed: boolean }>>;
  readonly resolveHandlers: (context: AuthenticatedRequestContext) => Plan | Promise<Plan>;
  readonly authorizeApplication: (context: AuthenticatedRequestContext, handlers: Plan) => AuthorizeApplicationResult<Plan> | Promise<AuthorizeApplicationResult<Plan>>;
  readonly onSession: (session: V4Session, context: AuthenticatedRequestContext) => Readonly<{ accepted: boolean }> | Promise<Readonly<{ accepted: boolean }>>;
  /** Invoked once, including when authorization throws. The original context
   * lets the application settle a reservation whose outcome was unknown.
   * Keep the returned promise pending until actual cleanup ends; Serve bounds
   * the caller's wait independently. An incomplete return or rejection cannot
   * be confirmed later and keeps this invocation charged. */
  readonly release: (context: ServeReleaseContext) => V4CleanupStatus | Promise<V4CleanupStatus>;
}
export interface ServeOptions<Plan extends object = object> extends ServeCallbacks<Plan> {
  readonly listener: ServeListener<Plan>;
  readonly carrier: "wss" | "raw_quic";
  readonly maintenanceOwner?: V4MaintenanceOwner;
}
export type ServeFailure = "configuration_capacity" | "owner_unavailable" | "resource_exhausted" | "closed" | "canceled" | "rejected" | "authorization_unknown" | "serve_failed";
export class ServeError extends Error {
  constructor(readonly code: ServeFailure, readonly cleanup: V4CleanupStatus) { super(code); this.name = "ServeError"; }
  toJSON(): object { return { code: this.code, cleanup: this.cleanup }; }
}
export interface ServeHandleOwner {
  drain(options?: V4DrainOptions): V4DrainOperation;
  waitDrain(options?: OperationOptions): ReturnType<V4DrainOperation["wait"]>;
  close(): void;
  onCleanup(callback: () => void): void;
  cleanupStatus(): V4CleanupStatus;
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus>;
}
const token = Symbol("original Serve"), handles = new WeakMap<ServeHandle, ServeHandleOwner>();
export class ServeHandle {
  constructor(capability: symbol, owner: ServeHandleOwner) {
    if (capability !== token) throw new Error("owner_unavailable"); handles.set(this, owner);
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  drain(options?: V4DrainOptions): V4DrainOperation { return handles.get(this)!.drain(options); }
  waitDrain(options?: OperationOptions) { return handles.get(this)!.waitDrain(options); }
  close(): void { handles.get(this)!.close(); }
  cleanupStatus(): V4CleanupStatus { return handles.get(this)!.cleanupStatus(); }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> { return handles.get(this)!.waitCleanup(options); }
  toJSON(): object { return {}; }
}
interface ListenerOwner<Plan extends object> {
  environment: V4TransportEnvironment;
  carrier?: "wss" | "raw_quic";
  start(callbacks: ServeCallbacks<Plan>, maintenanceOwner: V4MaintenanceOwner | undefined, signal?: AbortSignal): Promise<ServeHandle>;
  used: boolean;
}
const listeners = new WeakMap<object, ListenerOwner<any>>();
/** An immutable, single-use configured listener capability. */
export class ServeListener<Plan extends object = object> {
  constructor(capability: symbol, owner: ListenerOwner<Plan>) {
    if (capability !== token) throw new Error("owner_unavailable"); listeners.set(this, owner); Object.freeze(this);
  }
  toJSON(): object { return {}; }
}
/** Internal composite owners observe actual cleanup independently of bounded
 * public waits. Each Serve owner supports one original parent observer. */
export function observeServeCleanup(handle: ServeHandle, callback: () => void): void {
  const owner = handles.get(handle);
  if (owner === undefined) throw new ServeError("owner_unavailable", complete);
  owner.onCleanup(callback);
}
export function createServeHandle(owner: ServeHandleOwner): ServeHandle { return new ServeHandle(token, owner); }
export function createServeListener<Plan extends object>(owner: Omit<ListenerOwner<Plan>, "used">): ServeListener<Plan> {
  return new ServeListener(token, { ...owner, used: false });
}
const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
/** Internal dispatch accepts only a registered production listener. */
export async function startServe<Plan extends object>(environment: V4TransportEnvironment, options: ServeOptions<Plan>, operation?: OperationOptions): Promise<ServeHandle> {
  let handle: ServeHandle | undefined;
  try {
    const owner = listeners.get(options.listener), carrier = options.carrier, maintenance = options.maintenanceOwner;
    const callbacks = Object.freeze({ authorizeRequest: options.authorizeRequest, resolveHandlers: options.resolveHandlers,
      authorizeApplication: options.authorizeApplication, onSession: options.onSession, release: options.release });
    if (owner === undefined || owner.environment !== environment || owner.used) throw new ServeError("owner_unavailable", complete);
    if (carrier !== (owner.carrier ?? "wss") || Object.values(callbacks).some(value => typeof value !== "function")) throw new ServeError("configuration_capacity", complete);
    if (operation?.signal?.aborted) throw new ServeError("canceled", complete);
    owner.used = true; listeners.delete(options.listener);
    handle = await owner.start(callbacks, maintenance, operation?.signal);
    if (operation?.signal?.aborted) { handle.close(); throw new ServeError("canceled", handle.cleanupStatus()); }
    return handle;
  } catch (error) {
    if (error instanceof ServeError) throw error;
    handle?.close(); throw new ServeError("serve_failed", handle?.cleanupStatus() ?? complete);
  }
}
