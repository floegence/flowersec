import type { V4ApplicationContext } from "./streamHandlers.js";
import type { V4UnaryContext } from "./serviceHandlers.js";
import type { V4CheckpointTarget } from "./checkpoint.js";
import { RPCProtocolError } from "./runtime/rpcFragment.js";

/** The application supplies and understands this complete canonical definition,
 * including selection, position/reference encoding, read request/response and
 * missing/expiry semantics. Both peers bind exactly these bytes and revision. */
export interface V4StreamContentDefinition {
  readonly schemaRevision: string;
  readonly canonical: Uint8Array;
  readonly readTypeID: number;
}
export interface V4ContentObservation {
  readonly found: boolean;
  readonly available: boolean;
  readonly expired: boolean;
  readonly committedAtMS: bigint;
  readonly expiresAtMS: bigint;
  readonly bytes: number;
  readonly digest: string;
}
type Save = (position: Uint8Array, payload: Uint8Array) => V4ContentObservation | Promise<V4ContentObservation>;
type Read = (target: V4CheckpointTarget, position: Uint8Array, destination: Uint8Array) => V4ContentObservation | Promise<V4ContentObservation>;
const savers = new WeakMap<V4ApplicationContext, Save>(), readers = new WeakMap<V4UnaryContext, Read>();
/** Explicit selection only; writing a stream item does not retain it. */
export async function saveV4StreamContent(context: V4ApplicationContext, position: Uint8Array, payload: Uint8Array): Promise<V4ContentObservation> {
  const save = savers.get(context); if (save === undefined) throw new RPCProtocolError("service_unavailable"); return await save(position, payload);
}
/** Call only from the definition's original authorized unary read method.
 * Missing history is an error; a missing position is a separate observation. */
export async function readV4RetainedContent(context: V4UnaryContext, target: V4CheckpointTarget, position: Uint8Array, destination: Uint8Array): Promise<V4ContentObservation> {
  const read = readers.get(context); if (read === undefined) throw new RPCProtocolError("service_unavailable"); return await read(target, position, destination);
}
export function bindContentSave(context: V4ApplicationContext, save: Save): () => void {
  if (savers.has(context)) throw new RPCProtocolError("rpc_owner"); savers.set(context, save); return () => { savers.delete(context); };
}
export function bindContentRead(context: V4UnaryContext, read: Read): () => void {
  if (readers.has(context)) throw new RPCProtocolError("rpc_owner"); readers.set(context, read); return () => { readers.delete(context); };
}
