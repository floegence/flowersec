import type * as ResourcesTypes from "./resources.js";
import type * as ApplicationExecutorTypes from "./applicationExecutor.js";
import type * as SessionCleanupTypes from "./sessionCleanup.js";
import type * as StreamHandlersTypes from "../streamHandlers.js";
import type * as TransportV4APIResultsTypes from "../../generated/transportV4APIResults.js";
import type * as DeadlineTypes from "./deadline.js";
import type * as ReceiveDirectionTypes from "./receiveDirection.js";
import type * as PublicTypes from "../public.js";
import type { OperationOptions } from "../../public/contract.js";
import type { V4CleanupStatus, V4CloseResult, V4ReadResult, V4WriteProgress } from "../../generated/transportV4APIResults.js";
import type { V4StreamOwner } from "../public.js";
import type { DiagnosticObserver } from "./diagnosticObservation.js";

/** Private capability installed by the original accepted Stream, never a duck-typed ByteStream. */
export interface StreamAdapterProfile {
  readonly kind?: "node" | "web" | "message" | "proxy" | "bridge";
  readonly readBytes: number;
  readonly inputBackingBytes: number;
  readonly inputEntries: number;
  readonly gracefulFinishMS: number;
  readonly cleanupMS: number;
  readonly prepaid?: ResourcesTypes.ResourceReference;
  /** Original SDK group admitted before a fixed channel can activate. */
  readonly application?: ApplicationExecutorTypes.ApplicationGroup;
  /** A Session-owned future channel group survives individual generations. */
  readonly reusableApplication?: boolean;
  /** Private candidate construction in the original peer acceptance path. */
  readonly preaccepted?: boolean;
  /** Charges a Node-native Duplex endpoint against the paired Stream owner. */
  readonly nativeEndpoint?: boolean;
}

/** Original Stream capabilities available only to the SDK message owner. */
export interface MessageStreamAdapterOwner extends StreamAdapterOwner {
  readonly diagnostics?: DiagnosticObserver | undefined;
  readonly application: ApplicationExecutorTypes.ApplicationGroup;
  readonly sessionCleanup: SessionCleanupTypes.SessionCleanup;
  readonly authentication: StreamHandlersTypes.V4AuthenticatedContext | undefined;
  releaseDelivery(): void;
  ioEndedWith(callback: () => void): void;
  inputChangedWith?(callback: () => void): void;
  /** Release the finished protocol graph while retaining result safety. */
  detachIO(): void;
  readonly direction: TransportV4APIResultsTypes.V4Direction;
  readonly localOpener: boolean;
  readonly kind: string;
  readonly metadata: Uint8Array;
  readonly maxWriteBytes: number;
  readonly maxWriteMilliseconds: bigint;
  readonly runtimeBytes: bigint;
  reserve(name: string, charge: ResourcesTypes.ResourceVector): ResourcesTypes.ResourceReference;
  reserveSend(name: string, charge: ResourcesTypes.ResourceVector): ResourcesTypes.ResourceReference;
  observeResources(changed: () => void): () => void;
  deadline(milliseconds: bigint): DeadlineTypes.TrustedDeadline;
  admitBody(length: number, structure: ResourcesTypes.ResourceVector): ReceiveDirectionTypes.MessageReceiveBody;
  ensureReadQueue(): void;
  readInto(maximum: number, transfer: (bytes: Uint8Array) => number, signal: AbortSignal): Promise<void>;
  readState(): PublicTypes.V4ReadState;
  releaseReader(): void;
  pauseCredit(paused: boolean): void;
  prepareWrite(bytes: Uint8Array, milliseconds: bigint): PublicTypes.V4WriteRequestOwner & { waitCleanup(): Promise<void> };
}
const messageOwners = new WeakMap<V4StreamOwner, (profile: StreamAdapterProfile) => MessageStreamAdapterOwner>();
export function registerMessageStreamAdapter(stream: V4StreamOwner, acquire: (profile: StreamAdapterProfile) => MessageStreamAdapterOwner): void {
  if (messageOwners.has(stream)) throw new Error("stream_owner");
  messageOwners.set(stream, acquire);
}
export function acquireMessageStreamAdapter(stream: V4StreamOwner, profile: StreamAdapterProfile): MessageStreamAdapterOwner {
  const acquire = messageOwners.get(stream);
  if (acquire === undefined || profile.kind !== "message") throw new Error("owner_unavailable");
  return acquire(profile);
}
export interface StreamAdapterOwner {
  readonly readBytes: number;
  check(): void;
  read(options?: OperationOptions): Promise<V4ReadResult>;
  write(bytes: Uint8Array, options?: OperationOptions): Promise<V4WriteProgress>;
  closeWrite(options?: OperationOptions): Promise<V4CloseResult>;
  finish(options?: OperationOptions): Promise<V4CloseResult>;
  reset(options?: OperationOptions): Promise<V4CloseResult>;
  abortRead(options?: OperationOptions): Promise<V4CloseResult>;
  abortWrite(options?: OperationOptions): Promise<V4CloseResult>;
  /** Underlying protocol cleanup, excluding this adapter's own reservation. */
  cleanupStatus(): V4CleanupStatus;
  invalidateWith(callback: () => void): void;
  /** A validated peer STOP sealed this adapter's send direction. */
  sendStoppedWith(callback: () => void): void;
  cleanupWith(callback: () => void): void;
  /** Construction failed before any endpoint or I/O was published. */
  rollback(): void;
  /** The adapter has stopped retaining native queues, callbacks and input aliases. */
  release(): void;
}
const owners = new WeakMap<V4StreamOwner, (profile: StreamAdapterProfile) => StreamAdapterOwner>();
export function registerStreamAdapter(stream: V4StreamOwner, acquire: (profile: StreamAdapterProfile) => StreamAdapterOwner): void {
  if (owners.has(stream)) throw new Error("stream_owner");
  owners.set(stream, acquire);
}
export function acquireStreamAdapter(stream: V4StreamOwner, profile: StreamAdapterProfile): StreamAdapterOwner {
  const acquire = owners.get(stream);
  if (acquire === undefined) throw new Error("owner_unavailable");
  for (const n of [profile.readBytes, profile.inputBackingBytes, profile.inputEntries, profile.gracefulFinishMS, profile.cleanupMS]) {
    if (!Number.isSafeInteger(n) || n < 1 || n > 0x7fffffff) throw new Error("configuration_capacity");
  }
  return acquire(Object.freeze({ ...profile }));
}

/** A bridge reserves its detached partial-result backing before either pump
 * starts. The reservation survives I/O retirement only while its result owns
 * an unaccepted tail; it carries no Session or protocol capability. */
export interface BridgeStreamAdapterOwner extends StreamAdapterOwner {
  readonly endpointKind: "flowersec_stream";
  readonly resultBacking: ResourcesTypes.ResourceReference;
  /** Extra detached-result backing for the other, Node-native endpoint. */
  readonly nativeResultBacking?: ResourcesTypes.ResourceReference;
  /** Original adapter I/O custody for native queues and callbacks, independent of result tails. */
  readonly nativeIOBacking?: ResourcesTypes.ResourceReference;
  readState(): PublicTypes.V4ReadState;
}
export interface NativeBridgeDuplexAdapterOwner extends StreamAdapterOwner {
  readonly endpointKind: "native_duplex";
  readonly resultBacking: ResourcesTypes.ResourceReference;
  readState(): PublicTypes.V4ReadState;
  /** Waits for the last accepted native input's callback and required drain.
   * Cancellation ends this producer wait; original callback custody remains. */
  waitProducerExit(options?: OperationOptions): Promise<void>;
}
const bridgeOwners = new WeakMap<V4StreamOwner, (profile: StreamAdapterProfile) => BridgeStreamAdapterOwner>();
export function registerBridgeStreamAdapter(stream: V4StreamOwner, acquire: (profile: StreamAdapterProfile) => BridgeStreamAdapterOwner): void {
  if (bridgeOwners.has(stream)) throw new Error("stream_owner");
  bridgeOwners.set(stream, acquire);
}
export function hasBridgeStreamAdapter(stream: object): stream is V4StreamOwner { return bridgeOwners.has(stream as V4StreamOwner); }
export function acquireBridgeStreamAdapter(stream: V4StreamOwner, profile: StreamAdapterProfile): BridgeStreamAdapterOwner {
  const acquire = bridgeOwners.get(stream);
  if (acquire === undefined || profile.kind !== "bridge" || profile.preaccepted === true) throw new Error("owner_unavailable");
  for (const n of [profile.readBytes, profile.inputBackingBytes, profile.inputEntries, profile.gracefulFinishMS, profile.cleanupMS]) {
    if (!Number.isSafeInteger(n) || n < 1 || n > 0x7fffffff) throw new Error("configuration_capacity");
  }
  return acquire(Object.freeze({ ...profile }));
}

const nativeBridgeOwners = new WeakMap<object, (profile: StreamAdapterProfile, resultBacking: ResourcesTypes.ResourceReference, ioBacking: ResourcesTypes.ResourceReference) => NativeBridgeDuplexAdapterOwner>();
export function registerNativeBridgeDuplexAdapter(endpoint: object,
  acquire: (profile: StreamAdapterProfile, resultBacking: ResourcesTypes.ResourceReference, ioBacking: ResourcesTypes.ResourceReference) => NativeBridgeDuplexAdapterOwner): void {
  if (nativeBridgeOwners.has(endpoint)) throw new Error("stream_owner");
  nativeBridgeOwners.set(endpoint, acquire);
}
export function hasNativeBridgeDuplexAdapter(endpoint: object): boolean { return nativeBridgeOwners.has(endpoint); }
export function acquireNativeBridgeDuplexAdapter(endpoint: object, profile: StreamAdapterProfile,
  resultBacking: ResourcesTypes.ResourceReference, ioBacking: ResourcesTypes.ResourceReference): NativeBridgeDuplexAdapterOwner {
  const acquire = nativeBridgeOwners.get(endpoint);
  if (acquire === undefined || profile.kind !== "bridge" || profile.nativeEndpoint !== true || profile.preaccepted === true) throw new Error("owner_unavailable");
  for (const n of [profile.readBytes, profile.inputBackingBytes, profile.inputEntries, profile.gracefulFinishMS, profile.cleanupMS]) {
    if (!Number.isSafeInteger(n) || n < 1 || n > 0x7fffffff) throw new Error("configuration_capacity");
  }
  return acquire(Object.freeze({ ...profile }), resultBacking, ioBacking);
}
