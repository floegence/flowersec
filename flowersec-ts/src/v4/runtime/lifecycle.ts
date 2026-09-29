import type { V4CleanupStatus, V4LifecycleObjectKind, V4LifecycleReason, V4LifecycleResult, V4LifecycleState } from "../../generated/transportV4APIResults.js";
import { validLifecycleResult } from "../../generated/transportV4APIResults.js";

const define = Object.defineProperty, freeze = Object.freeze;
export function cleanupResult(cleanup: V4CleanupStatus): V4CleanupStatus {
  const value = { status: cleanup.status, core_cleanup: cleanup.core_cleanup, pending_callbacks: cleanup.pending_callbacks };
  define(value, "then", { value: undefined }); return freeze(value);
}
/** Compact native projection; lifecycle is supplied by its original owner,
 * never inferred from another object's cleanup/error state. */
export function lifecycleResult(object_kind: V4LifecycleObjectKind, lifecycle_state: V4LifecycleState, cleanup: V4CleanupStatus,
  reason: V4LifecycleReason = "none"): V4LifecycleResult {
  const cleanup_status = cleanupResult(cleanup);
  const value = { object_kind, lifecycle_state, cleanup_status, reason };
  if (!validLifecycleResult(value)) throw new Error("invalid_lifecycle_result");
  define(value, "then", { value: undefined }); return freeze(value);
}
