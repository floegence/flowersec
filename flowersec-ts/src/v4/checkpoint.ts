import type { V4UnaryContext } from "./serviceHandlers.js";
import type { ExecutionTarget } from "./runtime/executionManagementCodec.js";
import { RPCProtocolError } from "./runtime/rpcFragment.js";

export type V4CheckpointTarget = ExecutionTarget;
export interface V4Checkpoint { readonly format: string; readonly position: Uint8Array; }
export interface V4CheckpointIssuanceOptions {
  readonly durationMS: bigint;
  readonly applicationDurationLimitMS: bigint;
  /** The application's actual checkpoint availability promise. */
  readonly historyNotAfterMS: bigint;
}
/** A handler result selected only by its original durable invocation. */
export interface V4CheckpointResult { readonly kind: "checkpoint_result"; }
type Issuer = (original: ExecutionTarget, checkpoint: V4Checkpoint, options: V4CheckpointIssuanceOptions) => V4CheckpointResult;
const issuers = new WeakMap<V4UnaryContext, Issuer>();
/** Finish this explicit unary execution with the original persisted token.
 * A duplicate joins the stored result and never calls the issuer again. */
export function issueV4Checkpoint(context: V4UnaryContext, original: ExecutionTarget, checkpoint: V4Checkpoint,
  options: V4CheckpointIssuanceOptions): V4CheckpointResult {
  const issue = issuers.get(context);
  if (issue === undefined) throw new RPCProtocolError("service_unavailable");
  return issue(original, checkpoint, options);
}
export function bindCheckpointIssuer(context: V4UnaryContext, issuer: Issuer): () => void {
  if (issuers.has(context)) throw new RPCProtocolError("rpc_owner");
  issuers.set(context, issuer); return () => { issuers.delete(context); };
}
