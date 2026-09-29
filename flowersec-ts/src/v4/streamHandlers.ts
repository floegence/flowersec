import type * as ServiceDefinitionTypes from "./serviceDefinition.js";
import type { RawStreamMetadataContract, StreamMetadata } from "../public/streamMetadata.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { OperationOptions } from "../public/contract.js";
import type { V4StreamOwner } from "./public.js";
import type { V4TypedMessageStream, V4MessageStreamOptions } from "./messageStream.js";

/** Immutable facts derived from the original admitted credentials and READY. */
export interface V4AuthenticatedContext {
  readonly tenant: string;
  readonly audience: string;
  readonly localRole: "client" | "server";
  readonly localSubject: string;
  readonly peerSubject: string;
  readonly peerIdentityDigest: string;
}
export interface V4ApplicationContext {
  readonly authentication: V4AuthenticatedContext;
  readonly signal: AbortSignal;
}
export interface V4ApplicationWaitOptions extends OperationOptions { readonly context?: V4ApplicationContext; }
export interface V4StreamRegistrationOptions extends V4MessageStreamOptions {
  /** Trusted local service method used for the recovery prelude on this raw kind. */
  readonly resume?: Readonly<{ namespace: string; method: ServiceDefinitionTypes.V4MethodDefinition<Uint8Array, Uint8Array, "unary", "execution"> }>;
  /** Stream handlers are resident unless trusted local policy says otherwise. */
  readonly workClass?: "short" | "resident";
  readonly maxConcurrentStreams?: number;
  readonly maxAuthorizing?: number;
  readonly applicationTimeoutMS?: bigint;
  /** Explicit host allowance for retained callback graphs and application work. */
  readonly applicationBytes: bigint;
  /** Empty metadata is always allowed. Nonempty namespaces need local policy. */
  readonly metadataNamespaces?: readonly Readonly<{ namespace: string; version: number }>[];
  /** Optional fixed data-only projection for raw Stream metadata. */
  readonly metadataContract?: RawStreamMetadataContract;
}
export type V4StreamOpenAuthorizer = (context: V4ApplicationContext, metadata: StreamMetadata) => boolean | Promise<boolean>;
export type V4MessageStreamHandler<A = unknown, B = unknown> = (stream: V4TypedMessageStream<A, B>, context: V4ApplicationContext, metadata: StreamMetadata) => void | Promise<void>;
export type V4RawStreamHandler = (stream: V4StreamOwner, context: V4ApplicationContext, metadata: StreamMetadata) => void | Promise<void>;
export interface V4StreamRegistrationOwner {
  close(): void;
  cleanupStatus(): V4CleanupStatus;
  waitCleanup(options?: V4ApplicationWaitOptions): Promise<V4CleanupStatus>;
}
const capability = Symbol("stream registration"), registrations = new WeakMap<V4StreamRegistration, V4StreamRegistrationOwner>();
/** Close seals this registration's future admission. Accepted handlers retain
 * their captured generation until their actual application work has exited. */
export class V4StreamRegistration {
  constructor(token: symbol, owner: V4StreamRegistrationOwner) {
    if (token !== capability) throw new Error("owner_unavailable"); registrations.set(this, owner); Object.freeze(this);
  }
  close(): void { registrations.get(this)!.close(); }
  cleanupStatus(): V4CleanupStatus { return registrations.get(this)!.cleanupStatus(); }
  waitCleanup(options?: V4ApplicationWaitOptions): Promise<V4CleanupStatus> { return registrations.get(this)!.waitCleanup(options); }
}
export function streamRegistration(owner: V4StreamRegistrationOwner): V4StreamRegistration { return new V4StreamRegistration(capability, owner); }
export { applicationHasPermit } from "./runtime/applicationExecutor.js";
