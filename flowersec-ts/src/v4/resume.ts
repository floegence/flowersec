import type { V4Checkpoint } from "./checkpoint.js";
import type { V4ApplicationContext } from "./streamHandlers.js";

export interface V4ResumeProgress { readonly checkpoint: V4Checkpoint; readonly generation: bigint; }
export type V4ResumeResult = Readonly<{ status: "accepted" } & V4ResumeProgress> |
  Readonly<{ status: "rejected" | "unknown"; checkpoint?: V4Checkpoint; generation?: bigint }>;
const progress = new WeakMap<V4ApplicationContext, V4ResumeProgress>();
/** Confirmed progress is available only during the original recovered handler. */
export function v4RecoveryProgress(context: V4ApplicationContext): V4ResumeProgress {
  const value = progress.get(context); if (value === undefined) throw new Error("recovery_progress_unavailable"); return value;
}
/** SDK-only association; applications cannot manufacture a recovery invocation. */
export function bindRecoveryProgress(context: V4ApplicationContext, value: V4ResumeProgress): () => void {
  if (progress.has(context)) throw new Error("recovery_progress_unavailable");
  progress.set(context, value); return () => { progress.delete(context); };
}
