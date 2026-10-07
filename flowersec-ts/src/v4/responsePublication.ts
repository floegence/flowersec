import type { OperationOptions } from "../public/contract.js";
import type { V4ResponsePublicationStatus, V4ResponsePublicationCause } from "../generated/transportV4APIResults.js";
import type { V4TransportEnvironment } from "./public.js";
import { originalEnvironment, type EnvironmentDependency, type V4EnvironmentRuntime } from "./runtime/environment.js";
import { ResourceVector, type ProtectedResourceReservation, type ResourceReference } from "./runtime/resources.js";
import { RPCProtocolError } from "./runtime/rpcFragment.js";
import { timerChunk, type TrustedDeadline } from "./runtime/deadline.js";
import type { TrustedClock } from "./runtime/clock.js";

export type V4PublicationTransfer = "success" | "already_transferred" | "owner_unavailable" | "expired" | "invalid";
export interface V4ResponsePublication {
  state(): V4ResponsePublicationStatus;
  wait(options?: OperationOptions): Promise<V4ResponsePublicationStatus>;
  transferTo(owner: V4MaintenanceOwner): V4PublicationTransfer;
}
function status(value: V4ResponsePublicationStatus): V4ResponsePublicationStatus {
  Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
}
const pending = status({ state: "pending" }), flushed = status({ state: "flushed" });
const notApplicable = status({ state: "not_applicable" });
export const noResponsePublication: V4ResponsePublication = Object.freeze({ state: () => notApplicable,
  wait: async () => notApplicable, transferTo: () => "invalid" as const });
const capability = Symbol("runtime maintenance observation");
interface OwnerState {
  dependency: EnvironmentDependency | undefined;
  readonly positions: readonly ProtectedResourceReservation[];
  readonly observations: Set<ResponsePublication>;
  closed: boolean;
}
const owners = new WeakMap<V4MaintenanceOwner, OwnerState>();
/** Borrowed by either Session role from the application's existing lifecycle.
 * Closing observation authority never changes the publisher's outcome. */
export class V4MaintenanceOwner {
  constructor(token: symbol, state: OwnerState) {
    if (token !== capability) throw new RPCProtocolError("owner_unavailable");
    owners.set(this, state); state.dependency!.onClose(() => this.close()); Object.freeze(this);
  }
  close(): void {
    const state = owners.get(this)!;
    if (!state.closed) {
      state.closed = true;
      for (const observation of state.observations) observation.closeObserver();
      for (const position of state.positions) position.closeAfterUse();
    }
    collectOwner(state);
  }
  cleanupComplete(): boolean { const state = owners.get(this)!; collectOwner(state); return state.closed && state.dependency === undefined; }
  toJSON(): object { return {}; }
}
function collectOwner(state: OwnerState): void {
  if (!state.closed || state.observations.size !== 0 || state.positions.some(position => !position.cleanupComplete())) return;
  state.dependency?.release(); state.dependency = undefined;
}
export function checkMaintenanceOwner(owner: V4MaintenanceOwner | undefined, reference?: ResourceReference): void {
  const state = owner === undefined ? undefined : owners.get(owner);
  if (state === undefined || state.closed || state.dependency === undefined || reference !== undefined && !state.dependency.reference.sameEnvironment(reference)) throw new RPCProtocolError("configuration_capacity");
  state.dependency.check();
}
export function createV4MaintenanceOwner(environment: V4TransportEnvironment, maxObservations = 8): V4MaintenanceOwner {
  return createMaintenanceOwner(originalEnvironment(environment), maxObservations);
}
export function createMaintenanceOwner(environment: V4EnvironmentRuntime, maxObservations = 8): V4MaintenanceOwner {
  if (!Number.isSafeInteger(maxObservations) || maxObservations < 1 || maxObservations > 64) throw new RPCProtocolError("configuration_capacity");
  const runtime = environment.resources.runtimeBytes;
  const { dependency, positions } = environment.admitDependencyPositions("maintenance_observation", new ResourceVector([2048n + runtime + BigInt(maxObservations) * 128n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), responsePublicationCharge(runtime), maxObservations);
  try { return new V4MaintenanceOwner(capability, { dependency, positions, observations: new Set(), closed: false }); }
  catch (error) { for (const position of positions) position.close(); dependency.release(); throw error; }
}
export function responsePublicationCharge(runtime: bigint): ResourceVector {
  return new ResourceVector([4096n + 4n * runtime, 0n, 0n, 8n, 0n, 4n, 1n, 0n, 0n, 0n, 0n]);
}
interface Waiter {
  readonly resolve: (value: V4ResponsePublicationStatus) => void;
  readonly reject: (error: unknown) => void;
  readonly signal: AbortSignal | undefined;
  readonly cancel: () => void;
}
/** Original response cell, prepaid before the handler. Only the original
 * publisher can settle it; a transfer lends observation, never send authority. */
export class ResponsePublication {
  readonly view: V4ResponsePublication;
  #reference: ResourceReference | undefined;
  #transferred: ResourceReference | undefined;
  #owner: OwnerState | undefined;
  #status: V4ResponsePublicationStatus = pending;
  readonly #waiters = new Set<Waiter>();
  #handler = true;
  #didTransfer = false;
  #observerClosed = false;
  #physical = false;
  #selected = false;
  #deadline: TrustedDeadline | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  constructor(readonly maintenance: V4MaintenanceOwner, runtime: bigint, reference: ResourceReference) {
    checkMaintenanceOwner(maintenance, reference);
    this.#reference = reference.take(responsePublicationCharge(runtime));
    this.view = Object.freeze({ state: () => this.#status, wait: (options?: OperationOptions) => this.#wait(options?.signal), transferTo: (owner: V4MaintenanceOwner) => this.#transfer(owner) });
  }
  #transfer(owner: V4MaintenanceOwner): V4PublicationTransfer {
    if (owner !== this.maintenance) return "invalid";
    if (this.#didTransfer) return "already_transferred";
    const state = owners.get(owner);
    if (this.#observerClosed || state === undefined || state.closed || this.#physical) return "owner_unavailable";
    if (!this.#handler) return "expired";
    try {
      checkMaintenanceOwner(owner, this.#reference);
      const position = state.positions.find(candidate => candidate.available());
      if (position === undefined) return "owner_unavailable";
      this.#transferred = position.checkout(); this.#owner = state; this.#didTransfer = true; state.observations.add(this); return "success";
    } catch { return "owner_unavailable"; }
  }
  endHandler(): void { this.#handler = false; if (this.#owner === undefined) this.closeObserver(); this.#collect(); }
  select(deadline: TrustedDeadline, clock: TrustedClock, duration: bigint): void {
    if (this.#selected) throw new RPCProtocolError("rpc_publication_owner");
    this.#selected = true; this.#deadline = deadline.forkAgeAt(clock.sample(), duration); this.#tick();
  }
  check(): void { if (this.#status.cause === "deadline") throw new RPCProtocolError("deadline_exceeded"); this.#deadline?.check(); }
  readonly #tick = (): void => {
    this.#timer = undefined; if (this.#status.state !== "pending") return;
    try { this.#deadline!.check(); this.#timer = setTimeout(this.#tick, timerChunk(this.#deadline!.remainingMS())); }
    catch { this.unknown("deadline"); }
  };
  handoff(): void {
    if (!this.#selected || this.#status.state !== "pending") return;
    try { this.#deadline!.check(); this.#settle(flushed); } catch { this.unknown("deadline"); }
  }
  unknown(cause: V4ResponsePublicationCause): void { this.#settle(status({ state: "unknown", cause })); }
  #settle(value: V4ResponsePublicationStatus): void {
    if (this.#status.state !== "pending") return;
    this.#status = value; if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#deadline = undefined;
    for (const waiter of this.#waiters) { this.#remove(waiter); waiter.resolve(value); }
    // A settled publication no longer needs a maintenance observation slot.
    // Keep the original publication reference until the physical response and
    // handler have both retired, but return the transferred slot immediately
    // so a bounded owner can observe later responses in the same Session.
    this.#transferred?.release(); this.#transferred = undefined;
    this.#collect();
  }
  #releaseTransfer(): void {
    this.#transferred?.release(); this.#transferred = undefined;
    if (this.#owner !== undefined) { const owner = this.#owner; this.#owner = undefined; owner.observations.delete(this); collectOwner(owner); }
  }
  physicalDone(): void { this.#physical = true; this.unknown("owner_unavailable"); this.#collect(); }
  closeObserver(): void {
    this.#observerClosed = true;
    for (const waiter of this.#waiters) { this.#remove(waiter); waiter.reject(new RPCProtocolError("owner_unavailable")); }
    this.#collect();
  }
  #collect(): void {
    if (!this.#physical || this.#handler || this.#waiters.size !== 0) return;
    this.#reference?.release(); this.#reference = undefined;
    this.#releaseTransfer();
  }
  #remove(waiter: Waiter): void { this.#waiters.delete(waiter); waiter.signal?.removeEventListener("abort", waiter.cancel); }
  #wait(signal: AbortSignal | undefined): Promise<V4ResponsePublicationStatus> {
    if (this.#status.state !== "pending") return Promise.resolve(this.#status);
    if (this.#observerClosed || this.#owner?.closed) return Promise.reject(new RPCProtocolError("owner_unavailable"));
    if (signal?.aborted) return Promise.reject(new RPCProtocolError("wait_canceled"));
    if (this.#waiters.size >= 4) return Promise.reject(new RPCProtocolError("resource_exhausted"));
    return new Promise((resolve, reject) => {
      const waiter: Waiter = { resolve, reject, signal, cancel: () => {
        if (this.#waiters.has(waiter)) { this.#remove(waiter); reject(new RPCProtocolError("wait_canceled")); this.#collect(); }
      } };
      this.#waiters.add(waiter); signal?.addEventListener("abort", waiter.cancel, { once: true }); if (signal?.aborted) waiter.cancel();
    });
  }
}
Object.freeze(V4MaintenanceOwner.prototype); Object.freeze(V4MaintenanceOwner);
