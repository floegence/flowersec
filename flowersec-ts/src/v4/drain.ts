import type { OperationOptions } from "../public/contract.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";

export interface V4DrainOptions { readonly timeoutMS?: bigint }
export type V4DrainOutcome = "pending" | "drained" | "deadline_aborted" | "failed";
export interface V4DrainResult {
  readonly outcome: V4DrainOutcome;
  readonly cleanup_status: V4CleanupStatus;
}
export class V4DrainError extends Error {
  constructor(readonly code: "canceled" | "resource_exhausted" | "owner_unavailable", readonly result: V4DrainResult) {
    super(code); this.name = "V4DrainError";
  }
}
const token = Symbol("original Session Drain");
interface DrainState {
  outcome: V4DrainOutcome;
  cleanup: V4CleanupStatus;
  observeCleanup: (() => V4CleanupStatus) | undefined;
  reserve: (() => () => void) | undefined;
  readonly waiters: Set<() => void>;
}
const states = new WeakMap<V4DrainOperation, DrainState>();
function result(state: DrainState): V4DrainResult {
  const cleanup = state.observeCleanup?.() ?? state.cleanup;
  return Object.freeze({ outcome: state.outcome, cleanup_status: cleanup });
}
/** One original Drain observation. Canceling a wait never reopens admission or
 * changes the original deadline. Terminal handles retain finite facts only. */
export class V4DrainOperation {
  constructor(capability: symbol, state: DrainState) {
    if (capability !== token) throw new Error("owner_unavailable");
    states.set(this, state); Object.freeze(this);
  }
  status(): V4DrainResult { return result(states.get(this)!); }
  wait(options?: OperationOptions): Promise<V4DrainResult> {
    const state = states.get(this)!;
    if (state.outcome !== "pending") return Promise.resolve(result(state));
    if (options?.signal?.aborted) return Promise.reject(new V4DrainError("canceled", result(state)));
    if (state.waiters.size >= 32) return Promise.reject(new V4DrainError("resource_exhausted", result(state)));
    let release: () => void;
    try { release = state.reserve!(); }
    catch { return Promise.reject(new V4DrainError("resource_exhausted", result(state))); }
    return new Promise((resolve, reject) => {
      let finished = false;
      const finish = (): void => {
        if (finished) return; finished = true;
        state.waiters.delete(finish); options?.signal?.removeEventListener("abort", finish); release();
        if (state.outcome === "pending") reject(new V4DrainError("canceled", result(state))); else resolve(result(state));
      };
      state.waiters.add(finish); options?.signal?.addEventListener("abort", finish, { once: true });
      if (options?.signal?.aborted || state.outcome !== "pending") finish();
    });
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.DrainOperation"; }
}
/** Internal original-owner hooks, absent from package exports. */
export interface SessionDrain {
  readonly operation: V4DrainOperation;
  finish(outcome: Exclude<V4DrainOutcome, "pending">): void;
  cleanup(value: V4CleanupStatus): void;
}
export function createSessionDrain(reserve: () => () => void, cleanup: V4CleanupStatus, observeCleanup?: () => V4CleanupStatus): SessionDrain {
  const state: DrainState = { outcome: "pending", cleanup, observeCleanup, reserve, waiters: new Set() };
  return {
    operation: new V4DrainOperation(token, state),
    finish: outcome => {
      if (state.outcome !== "pending") return;
      state.outcome = outcome; state.reserve = undefined;
      for (const wake of state.waiters) wake();
    },
    cleanup: value => { if (value.status === "complete" && value.core_cleanup === "complete" && value.pending_callbacks === 0n) state.observeCleanup = undefined; state.cleanup = Object.freeze({ status: value.status, core_cleanup: value.core_cleanup, pending_callbacks: value.pending_callbacks }); },
  };
}
