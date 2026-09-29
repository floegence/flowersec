import type { V4StreamOwner } from "../public.js";
import type { RPCStreamOwner } from "./rpcStream.js";
import type { StreamAdapterProfile } from "./streamAdapter.js";
import type { CheckpointSessionPolicy } from "./checkpointToken.js";
import { RPCProtocolError } from "./rpcFragment.js";

/** Captured only by the original accepted application Stream. These facts are
 * not supplied by an application, imported reference or alternative Session. */
export interface ResumeStreamOwner extends RPCStreamOwner {
  readonly transportContextDigest: string;
  readonly streamID: bigint;
  readonly policy: CheckpointSessionPolicy;
  sameSession(session: object): boolean;
  /** Complete frame boundary and actual I/O exit must precede this handoff. */
  returnAtBoundary(): void;
}
type Acquire = (session: object, kind: string, profile: StreamAdapterProfile) => ResumeStreamOwner;
const streams = new WeakMap<V4StreamOwner, Readonly<{ acquire: Acquire; session: () => object | undefined }>>();
export function registerResumeStream(stream: V4StreamOwner, acquire: Acquire, session: () => object | undefined): void {
  if (streams.has(stream)) throw new RPCProtocolError("rpc_owner"); streams.set(stream, { acquire, session });
}
/** The caller is the SDK's trusted service binding. Acquire this exclusive
 * target before generating the recovery operation ID, digest or saved ref. */
export function acquireResumeStream(stream: V4StreamOwner, session: object, kind: string, profile: StreamAdapterProfile): ResumeStreamOwner {
  const acquire = streams.get(stream)?.acquire;
  if (acquire === undefined || profile.kind !== "message" || profile.preaccepted === true) throw new RPCProtocolError("rpc_owner");
  return acquire(session, kind, profile);
}

/** SDK-only original target identity. This neither claims a reader nor mints
 * a route from wire metadata, an application object or an imported reference. */
export function resumeStreamSession(stream: V4StreamOwner): object {
  const session = streams.get(stream)?.session();
  if (session === undefined) throw new RPCProtocolError("rpc_owner"); return session;
}
