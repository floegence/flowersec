import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { NotificationScheduler, NotificationRegistration } from "./notifyDispatch.js";
import type { DiagnosticFields, DiagnosticMetric } from "../diagnostics.js";
import { DiagnosticActivity, type DiagnosticObserver } from "./diagnosticObservation.js";
import { diagnosticDuration, diagnosticFailure } from "./diagnosticCounters.js";
import type { VerifiedRelayCredentials } from "./relayCredentials.js";
import type { CredentialResources } from "./credentialSupport.js";
import type { HopAuthenticationPreparation } from "./hopAuthentication.js";
import { UnreliableRuntime, type UnreliablePreparation, type NativeDatagrams } from "./unreliable.js";
import { V4UnreliableMessageError, type V4UnreliableMessages } from "../unreliable.js";
import type * as StreamHandlersTypes from "../streamHandlers.js";
import type * as ResumeCodecTypes from "./resumeCodec.js";
import type * as ServiceDefinitionTypes from "../serviceDefinition.js";
import type * as ServiceHandlersTypes from "../serviceHandlers.js";
import type * as NotificationSubscriptionTypes from "../notificationSubscription.js";
import type * as ServiceBindingConfigTypes from "./serviceBindingConfig.js";
import type * as ServiceBindingPoolTypes from "./serviceBindingPool.js";
import type * as QueryRenewalPositionTypes from "./queryRenewalPosition.js";
import type * as ServiceBindingTypes from "./serviceBinding.js";
import { streamOpenCharges, streamTerminationCharge, StreamOpenPreparation } from "./streamOpenPreparation.js";
import { bindRecoveryProgress } from "../resume.js";
import { registerResumeStream, type ResumeStreamOwner } from "./resumeStream.js";
import { notifySpec } from "./notifyChannel.js";
import { managementSpec } from "./executionManagementCodec.js";
import { operationResultRead, type V4OperationResultRead, type V4OperationResultReadOptions } from "../operationResultRead.js";
import type { V4OperationReference, V4ExecutionManagementResult } from "../operationReference.js";
import { nativeAssociationCharge, nativeOutputCharge, type NativeProtocolPosition, type NativeProtocolPositions } from "./nativePositions.js";
import { DirectionKeyPositions, directionKeyCharge, MaintenancePositions, maintenancePositionCharges } from "./maintenancePositions.js";
import { captureSendQueueBytes, captureStreamSendQueueBytes, checkSendQueueCapacity, createSendAccount, createStreamSendAccounts, sendAccountPoolCapacity } from "./sendBudget.js";
import { SessionCleanup, sessionCleanupCharge } from "./sessionCleanup.js";
import { cleanupResult } from "./lifecycle.js";
import { NativeIngressScheduler } from "./nativeIngress.js";
import { NativeDirectionFailure, nativeConnectionEnded, observeNativeConnectionFailure, originalNativeConnectionFailure } from "./nativeFailure.js";
import { observeTask } from "./taskObservation.js";
import { encodeStreamData, StreamDataBounds } from "./streamData.js";
import { NativeFrameReader, type NativeFramePromise, type NativeFramePrefetch } from "./nativeFrame.js";
import { nativeCandidateCount } from "./nativeCandidates.js";
import { NativeSendWorkspace, nativeOutputFrame } from "./nativeSend.js";
import { serviceClient, type V4ServiceClient, type V4ServiceBindOptions } from "../serviceClient.js";
import { serviceDefinition, type V4ServiceDefinition, type V4ServiceMethods } from "../serviceDefinition.js";
import type { RandomFill } from "./random.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { table, wireDomains } from "./schemaRegistry.js";
import type { OperationOptions } from "../../public/contract.js";
import { applyRawStreamMetadataContract, type StreamMetadata, streamMetadataBytes, streamMetadataFromDocument } from "../../public/streamMetadata.js";
import type { V4LifecycleResult, V4CleanupStatus, V4CloseResult, V4SessionInfo, V4ReadResult, V4WriteProgress } from "../../generated/transportV4APIResults.js";
import type { V4SessionOwner, V4StreamOwner, V4CursorReadOwner, V4WriteRequestOwner } from "../public.js";
import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import { isVerifiedCredentialClosure, type VerifiedCredentialClosure, type CredentialSessionBinding } from "./credentialVerifier.js";
import { RecordCryptoError, type CryptoKeyPositions, type CryptoUsageLedger } from "./cryptoUsage.js";
import type { ClockMark } from "./clock.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import { EnvelopeDecoder, envelopeDecoderCharge, type EnvelopeFrame, type EnvelopePrefixCheck } from "./envelope.js";
import { NoiseHandshake, type NoiseHandshakeConfig, type NoiseRole, type ReadyConfig, type ReadyIdentitySigner } from "./noiseHandshake.js";
import type { RecordDirection } from "./record.js";
import { type RecordAuthorization, type RecordCipher, type RecordCipherConfig, type RecordEpoch, type RecordPacket, recordEpochCharge } from "./recordCrypto.js";
import { ReliableReceiveDirection, type ReceiveDeliveryGate, type ReceiveDirectionConfig, receiveDirectionCharge, receiveDecoderCharge, receiveCursorCharge } from "./receiveDirection.js";
import { ResourceError, ResourceVector, type ResourceReference, type ResourceRoot, type ResourceAccount, type ResourceOwner, type ProtectedResourceReservation, type ProtectedResourceAccounts, protectedAccountPoolCharge } from "./resources.js";
import { bootstrapSpec, FixedCBORWriter, OpenAdmission, OpenAdmissionError, type OpenAdmissionConfig, type OpenHandle } from "./openAdmission.js";
import { RekeyRound, type RekeyEntry, type RekeyConfig } from "./rekey.js";
import { registerRPCStream, type RPCStreamOwner } from "./rpcStream.js";
import type { RPCApplicationAdmission } from "./rpcApplication.js";
import { ReliableWriteRequest, writeRequestCharge } from "./writeRequest.js";
import { binaryWidth, envelopePrefixBytes, recordHeaderBytes, maxStreamScope, ownProfile, wire } from "./wireRegistry.js";
import { registerStreamAdapter, registerMessageStreamAdapter, registerBridgeStreamAdapter, type BridgeStreamAdapterOwner, type MessageStreamAdapterOwner, type StreamAdapterProfile, type StreamAdapterOwner } from "./streamAdapter.js";
import { TimeError } from "./timeArithmetic.js";
import { SessionLiveness } from "./liveness.js";
import { SessionIdleWatchdog, captureAutomaticLiveness, selectedIdleDuration, qualifySessionActivity } from "./sessionActivity.js";
import { V4LivenessError, type V4AutomaticLivenessPolicy, type V4LivenessResult } from "../liveness.js";
import { createSessionDrain, type SessionDrain, type V4DrainOptions, type V4DrainOperation } from "../drain.js";
import type { V4MessageStreamDefinition} from "../messageDefinition.js";
import { messageDefinition, messageMetadata } from "../messageDefinition.js";
import { type V4TypedMessageStream, type V4MessageStreamOptions, prepareTypedMessages, prepareMessageBinding, bindTypedMessages, captureMessageOptions, messageAdapterCharge } from "../messageStream.js";
import { streamRegistration, type V4StreamRegistration, type V4StreamRegistrationOptions, type V4StreamOpenAuthorizer, type V4MessageStreamHandler, type V4RawStreamHandler, type V4ApplicationContext } from "../streamHandlers.js";
import { applicationHasPermit, applicationGroup, type ApplicationGroup, type ApplicationPermit } from "./applicationExecutor.js";
import { SessionKeyPreparation } from "./sessionKeyPreparation.js";
import type { PeerOpenPreparation } from "./peerOpenPreparation.js";
import type { RawStreamPreparation, PreparedRawRegistration, PreparedRawInvocation } from "./rawStreamPreparation.js";
import { StreamRegistrationState, RegistrationHost, RegisteredStreamJob, captureRegistration, checkRawStreamKind, streamRegistrationCharge, streamHandlerCharge, type RegisteredHandler } from "./streamRegistration.js";

/** Internal adapter contract. Each returned read borrows at most maxBytes.
 * Message mode returns exactly one complete native message. Submission is the
 * actual irreversible output admission. It calls admitted exactly once at that
 * boundary; a return of undefined must never call admitted. Completion retains the original bytes
 * until the native task has stopped borrowing them, including failed output. */
export interface V4AuthenticatedTransport {
  readonly role: NoiseRole;
  readonly mode: "message" | "stream";
  readonly nativeStreams?: V4NativeStreamProvider;
  readonly nativeDatagrams?: NativeDatagrams;
  /** Current Tunnel hop authentication over this carrier's original
   * maintenance stream, before end-to-end negotiation. */
  authenticateHop?(credentials: VerifiedRelayCredentials, signer: ReadyIdentitySigner, random: RandomFill, resources: CredentialResources, reference: ResourceReference, options?: OperationOptions, acceptedHello?: Uint8Array, prepared?: HopAuthenticationPreparation, originalDeadline?: TrustedDeadline): Promise<void>;
  /** Native production preparation rechecks original TLS/provider evidence. */
  checkPreparation?(): void;
  /** Original authenticated handoff ends admission-only TLS window checks. */
  completePreparation?(): void;
  /** Original admission opens a prepared carrier's send gate after spend. */
  activate?(): void;
  /** Private native-provider operation over this original completed TLS owner. */
  exportBinding?(artifactDigest: Uint8Array): Uint8Array;
  read(maxBytes: number, options?: OperationOptions): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptions): Promise<number>;
  submit(data: Uint8Array, admitted: () => void, beforeSubmit?: () => void): Readonly<{ completion: Promise<void> }> | undefined;
  close(): Promise<void>;
  waitTermination(): Promise<void>;
}

/** Private native object identity. A provider never assigns a logical scope,
 * authenticates OPEN or exposes QUIC stream numbers as Flowersec identities. */
export interface V4NativeApplicationStream extends V4AuthenticatedTransport {
  readonly mode: "stream";
  readonly origin: "local" | "peer" | "maintenance";
  closeWrite(): Promise<void>;
  stopSending(reason?: "normal_drained"): Promise<void>;
  resetWrite(): Promise<void>;
  observeWriteFailure(changed: (failure: NativeDirectionFailure) => void): () => void;
  cleanupComplete(): boolean;
}
export interface V4NativeStreamProvider {
  readonly capacity: number;
  enable(): void;
  open(options?: OperationOptions): Promise<V4NativeApplicationStream>;
  accept(options?: OperationOptions): Promise<V4NativeApplicationStream>;
}

/** All references are distinct primary reservations from the original admission
 * transaction. An alias of one reservation cannot pay for independent backing. */
export interface V4SessionAssemblyReservations {
  readonly session: ResourceReference;
  readonly epoch: ResourceReference;
  readonly ingress: ResourceReference;
  readonly envelope: ResourceReference;
  readonly output: ResourceReference;
  readonly nativeIngress?: ResourceReference;
  readonly nativeRecord?: ResourceReference;
  readonly nativeEnvelope?: ResourceReference;
  readonly nativeReceive?: ResourceReference;
  readonly nativeReceiveDecoder?: ResourceReference;
  readonly nativeCandidates?: ResourceReference;
  readonly nativeSendCrypto?: ResourceReference;
  readonly nativeSendEncode?: ResourceReference;
}

/** Internal assembly inputs, after actual admission. This type is deliberately
 * absent from package entry points; applications cannot provide private keys,
 * assert READY/OPEN acceptance, or replace original authorization owners. */
export interface V4AuthenticatedSessionConfig {
  readonly diagnostics?: DiagnosticObserver | undefined;
  readonly diagnosticActivity?: DiagnosticActivity | undefined;
  readonly unreliablePreparation?: UnreliablePreparation | undefined;
  readonly preparedRawStreams?: RawStreamPreparation | undefined;
  /** Original Serve publication claim, after dual READY and before readers or
   * application dispatch start. This internal callback performs no I/O. */
  readonly claimReadySession?: (session: V4AuthenticatedSessionRuntime) => void;
  /** Install only original local inbound observers before committing own READY. */
  readonly prepareInbound?: (session: V4AuthenticatedSessionRuntime) => void;
  /** Evidence projection only; invoked after both authenticated READY directions. */
  readonly observeNetworkReady?: () => void;
  readonly transport: V4AuthenticatedTransport;
  readonly noise: NoiseHandshakeConfig;
  readonly signer: ReadyIdentitySigner;
  readonly ready: ReadyConfig;
  readonly peerReadyPublicKey: Uint8Array;
  readonly ledger: CryptoUsageLedger;
  readonly reservations: V4SessionAssemblyReservations;
  readonly maxFrame: number;
  readonly maxReceiveDirections: number;
  readonly idleDurationMS?: bigint;
  /** Bounded actual cleanup observation inherited from the owning Environment. */
  readonly cleanupMS?: number;
  readonly localIdleDurationMS?: bigint;
  readonly automaticLiveness?: V4AutomaticLivenessPolicy;
  readonly runtimeBytes: bigint;
  readonly info: V4SessionInfo;
  readonly streams: V4SessionStreamAssembly;
}

/** Original admission-owned stream resources. Each subsequent allocation is an
 * atomic charge to these same root/accounts before OPEN/accepted publication. */
export interface V4SessionStreamAssembly {
  readonly sendQueueBytes?: number;
  readonly streamSendQueueBytes?: number;
  readonly sendAccount?: ResourceAccount;
  readonly sendAccounts?: ProtectedResourceAccounts;
  readonly nativePositions?: NativeProtocolPositions;
  readonly peerOpenPreparation?: PeerOpenPreparation;
  readonly internalKeys?: SessionKeyPreparation;
  readonly maintenancePositions?: MaintenancePositions;
  /** Signed peer barrier envelope; independent of this host's active limit. */
  readonly rekeyMaxScopes?: number;
  /** Exact signed Session-wide general RPC matching bound; zero for transport. */
  readonly rpcMaxGeneralOutstanding?: number;
  /** Original Environment admission, assembled before authorization spend. */
  readonly rpcAdmission?: RPCApplicationAdmission;
  readonly rpcReservations?: readonly (readonly ResourceReference[])[];
  readonly rpcSendAccounts?: readonly ResourceAccount[];
  readonly rpcNativePositions?: readonly (NativeProtocolPosition | undefined)[];
  readonly notifyReservations?: readonly (readonly ResourceReference[])[];
  readonly notifySendAccounts?: readonly ResourceAccount[];
  readonly notifyNativePosition?: NativeProtocolPosition;
  readonly managementReservations?: readonly ResourceReference[];
  readonly managementSendAccount?: ResourceAccount;
  readonly managementNativePosition?: NativeProtocolPosition;
  /** Original admission batch; never acquired after authorization consumption. */
  readonly bootstrapReservations?: readonly ResourceReference[];
  readonly bootstrapSendAccount?: ResourceAccount;
  readonly bootstrapNativePosition?: NativeProtocolPosition;
  readonly nativeDataAssemblyDepth?: 1 | 2;
  readonly random?: RandomFill;
  readonly limits: OpenAdmissionConfig;
  readonly open: ResourceReference;
  readonly openDecoder: ResourceReference;
  readonly control: ResourceReference;
  readonly controlDecoder: ResourceReference;
  readonly controlSendCipher: ResourceReference;
  readonly controlReceiveCipher: ResourceReference;
  readonly root: ResourceRoot;
  readonly accounts: readonly ResourceAccount[];
  readonly owner: ResourceOwner;
  readonly receive: ReceiveDirectionConfig;
  readonly delivery: ReceiveDeliveryGate;
  readonly authorization: RecordAuthorization;
  readonly maxWriteBytes: number;
  readonly writeDeadlineMS: bigint;
  readonly operationDeadlineMS: bigint;
  readonly rekeyBurst: bigint;
  readonly rekeyRefillMS: bigint;
  readonly rekeyPrepareMS: bigint;
  readonly rekeyProtocolMS: bigint;
  readonly rekeyConfirmationMS: bigint;
}

export class V4SessionAssemblyError extends Error {
  constructor(readonly code: "configuration_capacity" | "resource_exhausted" | "authentication_failed" | "protocol_violation" | "carrier_failed" | "closed" | "busy" | "runtime_unavailable" | "idle_timeout" | "time_unavailable" | "liveness_path_unresponsive" | "session_draining" | "drain_deadline",
    readonly operation?: "open_stream" | "accept_stream" | "rekey" | "probe_liveness" | "record_dispatch") {
    super(operation === undefined ? code : `${code}: ${operation}`);
    this.name = "V4SessionAssemblyError";
  }
}
function fail(code: V4SessionAssemblyError["code"]): never { throw new V4SessionAssemblyError(code); }
const empty = new Uint8Array();
const copy = Uint8Array.prototype.set;
const readyActivation = Symbol("original dual READY completion");
const complete = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const pending: V4CleanupStatus = Object.freeze({ status: "pending", core_cleanup: "pending", pending_callbacks: 0n });
function frameType(name: string): number { const value = wire.frame_types[name]; if (value === undefined) fail("configuration_capacity"); return value; }
function capacity(maxFrame: number, runtimeBytes: bigint): number {
  if (!Number.isSafeInteger(maxFrame) || maxFrame < 103 || maxFrame > wire.resource_caps.max_payload_length ||
      typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) fail("configuration_capacity");
  return maxFrame + envelopePrefixBytes;
}
export function sessionIngressCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([BigInt(capacity(maxFrame, runtimeBytes)) + runtimeBytes, 0n, 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
export function sessionOutputCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([BigInt(capacity(maxFrame, runtimeBytes)) + runtimeBytes, 0n, 0n, 1n, 1n, 2n, 0n, 0n, 0n, 0n, 0n]);
}
export function authenticatedSessionCharge(maxReceiveDirections: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(maxReceiveDirections) || maxReceiveDirections < 0 || maxReceiveDirections > 2 ** 21 ||
      typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) fail("configuration_capacity");
  // The declared host allowance covers the original Noise/provider callbacks;
  // finite binding entries and the original deadline task are separately paid.
  // Eight probe slots prepay bounded waiters, timers and actual provider tails.
  // The idle and optional automatic scheduler share this admission lifecycle.
  // One fixed Drain owner includes its scheduler, deadline and result cell.
  // After actual core exit this reservation shrinks to the compact close cell;
  // remaining callbacks retain their separate original work reservations.
  return new ResourceVector([runtimeBytes * 11n + 5632n + BigInt(maxReceiveDirections) * 256n, 0n, 0n, 11n, 11n, 11n, 13n, 0n, 0n, 9n, 0n]).add(sessionCleanupCharge(runtimeBytes));
}

/** Registry envelope only; HANDSHAKE and READY carry their original payloads. */
function encodePlainEnvelope(type: number, payload: Uint8Array, output: Uint8Array, maxFrame: number): number {
  const size = byteLength(payload);
  if (size > maxFrame || size + envelopePrefixBytes > output.length) fail("configuration_capacity");
  let at = 0;
  for (const field of wire.envelope.layout) {
    const value = field.const ?? (field.name === "payload_length" ? size : field.name === "frame_type" ? type : -1);
    const width = binaryWidth(field.type);
    if (!Number.isSafeInteger(value) || value < 0 || BigInt(value) >= 1n << BigInt(width * 8) ||
        field.max !== undefined && value > field.max) fail("configuration_capacity");
    let remaining = value;
    for (let i = width - 1; i >= 0; i--) { output[at + i] = remaining % 256; remaining = Math.floor(remaining / 256); }
    at += width;
  }
  if (at !== envelopePrefixBytes) fail("configuration_capacity");
  copy.call(output, payload, at);
  return at + size;
}

/** One prepaid input backing, one decoder body and one reader task. Remainders
 * stay in this backing instead of repeated concatenation or an unbounded queue. */
class TransportReader {
  readonly #decoder: EnvelopeDecoder;
  readonly #transport: V4AuthenticatedTransport;
  #reservation: ResourceReference | undefined;
  #input: Uint8Array = empty;
  #at = 0;
  #used = 0;
  #busy = false;
  #closed = false;
  #assembling = false;
  constructor(transport: V4AuthenticatedTransport, maxFrame: number, runtimeBytes: bigint,
    reservation: ResourceReference, decoderReservation: ResourceReference, checkPrefix?: EnvelopePrefixCheck) {
    this.#transport = transport;
    this.#reservation = reservation.take(sessionIngressCharge(maxFrame, runtimeBytes));
    try {
      this.#input = new Uint8Array(capacity(maxFrame, runtimeBytes));
      this.#decoder = new EnvelopeDecoder({ maxFrame, mode: transport.mode, runtimeBytes }, decoderReservation, checkPrefix);
    } catch (error) { this.#input.fill(0); this.#reservation.release(); this.#reservation = undefined; throw error; }
  }
  async #read(limit: number, options?: OperationOptions): Promise<Uint8Array | null> {
    try { return await this.#transport.read(limit, options); }
    catch (error) {
      if (!this.#closed && !options?.signal?.aborted) observeNativeConnectionFailure(error); throw error;
    }
  }
  async next(options?: OperationOptions): Promise<EnvelopeFrame | null> {
    if (this.#closed) fail("closed");
    if (this.#busy) fail("busy");
    this.#busy = true;
    try {
      while (true) {
        this.#reservation!.check();
        if (this.#closed || options?.signal?.aborted) fail("closed");
        if (this.#at === this.#used) {
          const allowance = this.#transport.mode === "stream" ? this.#decoder.readAllowance(Math.min(16384, this.#input.length)) : this.#input.length;
          const input = await this.#read(allowance, options);
          if (this.#closed || options?.signal?.aborted) fail("closed");
          if (input === null) { this.#decoder.end(); return null; }
          const size = byteLength(input);
          if (size < 1 || size > allowance) fail("carrier_failed");
          this.#reservation!.check();
          if (this.#transport.mode === "message") return this.#decoder.message(input);
          copy.call(this.#input, input); this.#at = 0; this.#used = size;
        }
        const result = this.#decoder.push(byteSlice(this.#input, this.#at, this.#used));
        this.#input.fill(0, this.#at, this.#at + result.consumed); this.#at += result.consumed;
        this.#assembling = result.frame === undefined;
        if (result.frame !== undefined) return result.frame;
      }
    } finally { this.#busy = false; this.#cleanup(); }
  }
  async plain(expected: number, size: number, options?: OperationOptions): Promise<Uint8Array> {
    const frame = await this.next(options);
    if (frame === null) throw nativeConnectionEnded(new V4SessionAssemblyError("authentication_failed"));
    try {
      if (frame.frameType() !== expected || frame.payloadBytes() !== size) fail("authentication_failed");
      const payload = new Uint8Array(size); frame.copyPayload(payload); return payload;
    } finally { frame.release(); }
  }
  close(): void { this.#closed = true; this.#decoder.close(); this.#cleanup(); }
  atFrameBoundary(): boolean { return !this.#assembling; }
  #cleanup(): void { if (!this.#closed || this.#busy) return; this.#input.fill(0); this.#input = empty; this.#reservation?.release(); this.#reservation = undefined; }
  cleanupComplete(): boolean { return this.#reservation === undefined && this.#decoder.cleanupComplete(); }
}

/** One actual output position. No record is wrapped in another length prefix. */
class TransportOutput {
  #reservation: ResourceReference | undefined;
  #bytes: Uint8Array = empty;
  #busy = false;
  #closed = false;
  #tail: Promise<void> = Promise.resolve();
  #activity: (() => void) | undefined;
  #starting: (() => void) | undefined;
  #body: ResourceReference | undefined;
  #allocate: ((bytes: number) => ResourceReference) | undefined;
  readonly #dynamic: boolean;
  #failed: ((error: unknown) => void) | undefined;
  observeFailure(failed: (error: unknown) => void): void { this.#failed = failed; }
  observeRecords(activity: () => void, starting: () => void): void { this.#activity = activity; this.#starting = starting; }
  constructor(private readonly transport: V4AuthenticatedTransport, private readonly maxFrame: number, runtimeBytes: bigint, reservation: ResourceReference,
    allocate?: (bytes: number) => ResourceReference) {
    this.#allocate = allocate; this.#dynamic = allocate !== undefined;
    this.#reservation = reservation.take(this.#dynamic ? nativeOutputCharge(runtimeBytes) : sessionOutputCharge(maxFrame, runtimeBytes));
    try { if (!this.#dynamic) this.#bytes = new Uint8Array(capacity(maxFrame, runtimeBytes)); }
    catch (error) { this.#reservation.release(); this.#reservation = undefined; throw error; }
  }
  #submit(bytes: Uint8Array, admitted: () => void, beforeSubmit?: () => void): ReturnType<V4AuthenticatedTransport["submit"]> {
    let callbackFailed = false;
    try { return this.transport.submit(bytes, () => {
      try { admitted(); } catch (error) { callbackFailed = true; throw error; }
    }, () => {
      try { beforeSubmit?.(); } catch (error) { callbackFailed = true; throw error; }
    }); } catch (error) {
      if (!callbackFailed && !this.#closed) observeNativeConnectionFailure(error); throw error;
    }
  }
  async #write(bytes: Uint8Array, options?: OperationOptions): Promise<number> {
    try { return await this.transport.write(bytes, options); }
    catch (error) {
      if (!this.#closed && !options?.signal?.aborted) observeNativeConnectionFailure(error); throw error;
    }
  }
  #begin(bytes: number): void {
    if (this.#closed) fail("closed"); if (this.#busy) fail("busy"); this.#reservation!.check();
    this.#busy = true;
    try {
      if (this.#dynamic) {
        if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > this.maxFrame + envelopePrefixBytes) fail("configuration_capacity");
        const reference = this.#allocate!(bytes);
        try {
          if (this.#closed) fail("closed");
          this.#bytes = new Uint8Array(bytes); this.#body = reference;
        } catch (error) { reference.release(); throw error; }
      }
    } catch (error) { this.#busy = false; this.#cleanup(); throw error; }
  }
  plain(type: number, payload: Uint8Array, options?: OperationOptions): Promise<void> {
    this.#begin(byteLength(payload) + envelopePrefixBytes);
    this.#tail = this.#plain(type, payload, options);
    return observeTask(this.#tail, options?.signal);
  }
  async #plain(type: number, payload: Uint8Array, options?: OperationOptions): Promise<void> {
    try {
      const count = encodePlainEnvelope(type, payload, this.#bytes, this.maxFrame);
      let at = 0;
      do {
        if (this.#closed || options?.signal?.aborted) fail("closed");
        const accepted = await this.#write(byteSlice(this.#bytes, at, count), options);
        if (!Number.isSafeInteger(accepted) || accepted < 1 || accepted > count - at ||
            this.transport.mode === "message" && accepted !== count) fail("carrier_failed");
        at += accepted;
      } while (at < count);
    } finally { this.#finish(); }
  }
  submitReady(payload: Uint8Array): boolean {
    this.#begin(byteLength(payload) + envelopePrefixBytes);
    let submitted = false;
    try {
      const count = encodePlainEnvelope(frameType("READY"), payload, this.#bytes, this.maxFrame);
      const result = this.#submit(byteSlice(this.#bytes, 0, count), () => undefined);
      if (result === undefined) return false;
      submitted = true;
      this.#tail = result.completion.then(() => { this.#finish(); }, error => {
        if (!this.#closed) { observeNativeConnectionFailure(error); this.#failed?.(error); } this.#finish(); throw error;
      });
      // The original establishment owner awaits this same tail. Marking a
      // rejection observed here does not replace its later failed outcome.
      void this.#tail.catch(() => undefined);
      return true;
    } catch (error) {
      if (!this.#closed) this.#failed?.(error); throw error;
    } finally { if (!submitted) this.#finish(); }
  }
  available(): boolean { return !this.#closed && !this.#busy; }
  pending(): boolean { return this.#busy; }
  /** Sealing consumes a reliable sequence. Any failure after this call starts
   * the crypto ticket is fatal to that original Session, never a retry. */
  record(cipher: RecordCipher, type: number, plaintext: Uint8Array, submitted: () => void, ticket?: () => void, beforeSubmit?: () => void): Promise<void> {
    this.#begin(byteLength(plaintext) + envelopePrefixBytes + recordHeaderBytes + 16);
    let packet: RecordPacket | undefined, admitted = false;
    try {
      this.#starting?.();
      packet = cipher.seal(type, plaintext, ticket);
      const size = packet.copyBytes(this.#bytes);
      // This output owns an independent ciphertext copy before native entry.
      // The synchronous cipher position/key borrow has actually ended here.
      packet.release(); packet = undefined;
      let accepted = false;
      beforeSubmit?.();
      const result = this.#submit(byteSlice(this.#bytes, 0, size), () => {
        if (accepted) fail("carrier_failed");
        submitted(); accepted = true;
      }, beforeSubmit);
      if (result === undefined || !accepted) fail("carrier_failed");
      admitted = true;
      this.#tail = result.completion.then(
        () => { try { this.#activity?.(); } finally { this.#finish(); } },
        error => { if (!this.#closed) { observeNativeConnectionFailure(error); this.#failed?.(error); } this.#finish(); throw error; },
      );
      void this.#tail.catch(() => undefined);
      return this.#tail;
    } catch (error) {
      if (!this.#closed) this.#failed?.(error); throw error;
    } finally { if (!admitted) { packet?.release(); this.#finish(); } }
  }
  waitSubmitted(): Promise<void> { return this.#tail; }
  #finish(): void {
    this.#bytes.fill(0);
    if (this.#dynamic) { this.#bytes = empty; this.#body?.release(); this.#body = undefined; }
    this.#busy = false; this.#cleanup();
  }
  close(): void { this.#closed = true; this.#allocate = undefined; this.#activity = this.#starting = undefined; this.#cleanup(); }
  #cleanup(): void { if (!this.#closed || this.#busy) return; this.#bytes.fill(0); this.#bytes = empty; this.#reservation?.release(); this.#reservation = undefined; }
  cleanupComplete(): boolean { return this.#reservation === undefined; }
}


/** One actual native association and its independent parser/output position.
 * The original association survives outcome waits and logical cancellation. */
class NativeAssociation {
  readonly abort = new AbortController();
  readonly reader: NativeFrameReader;
  readonly output: TransportOutput;
  scope: bigint | undefined;
  readTask: Promise<void> | undefined;
  inputEnded = false;
  readFailed = false;
  writeFailure: NativeDirectionFailure | undefined;
  bounds: StreamDataBounds | undefined;
  #reference: ResourceReference | undefined;
  #closed = false;
  #closing = false;
  #rejected = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #stopWriteObservation: (() => void) | undefined;
  #waiting: (() => void) | undefined;
  constructor(readonly transport: V4NativeApplicationStream, config: { maxFrame: number; outputFrame: number; profile: string; runtimeBytes: bigint }, refs: readonly ResourceReference[],
    private readonly changed: () => void, checkPrefix: (type: number, payload: number) => NativeFramePromise | undefined,
    allocateOutput: (bytes: number) => ResourceReference, prefetch?: NativeFramePrefetch) {
    this.#reference = refs[2]!.take(nativeAssociationCharge(config.runtimeBytes));
    let reader: NativeFrameReader | undefined, output: TransportOutput | undefined;
    try {
      this.reader = reader = new NativeFrameReader(transport, config.maxFrame, config.profile, config.runtimeBytes, refs[0]!, checkPrefix, prefetch, () => this.changed(), refs[3]);
      this.output = output = new TransportOutput(transport, config.outputFrame, config.runtimeBytes, refs[1]!, allocateOutput);
      this.#stopWriteObservation = transport.observeWriteFailure(failure => { this.writeFailure ??= failure; this.changed(); });
    } catch (error) { reader?.close(); output?.close(); this.#reference.release(); this.#reference = undefined; throw error; }
  }
  watchOpen(deadline: TrustedDeadline, expired: () => void): void {
    if (this.#timer !== undefined) fail("configuration_capacity");
    const tick = (): void => {
      this.#timer = undefined;
      if (this.#closed) return;
      try { deadline.check(); this.#timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
      catch { expired(); }
    };
    tick();
  }
  outcome(): void { if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; }
  wait(deadline: TrustedDeadline, signal: AbortSignal): Promise<void> {
    if (this.#closed || signal.aborted) return Promise.reject(new Error("closed"));
    if (this.#waiting !== undefined) return Promise.reject(new Error("busy"));
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined, finished = false;
      const finish = (): void => {
        if (finished) return; finished = true;
        if (timer !== undefined) clearTimeout(timer); signal.removeEventListener("abort", finish); this.#waiting = undefined;
        try { if (this.#closed || signal.aborted) throw new Error("closed"); deadline.check(); resolve(); }
        catch (error) { reject(error); }
        this.cleanup();
      };
      this.#waiting = finish;
      try { deadline.check(); timer = setTimeout(finish, timerChunk(deadline.remainingMS())); signal.addEventListener("abort", finish, { once: true }); }
      catch { finish(); }
      if (signal.aborted) finish();
    });
  }
  wake(): void { this.#waiting?.(); }
  /** Only the authenticated rejection owner may use this zero-DATA proof. */
  reject(): void {
    if (this.#rejected || this.#closed) return;
    this.#rejected = true;
    this.outcome();
    void this.transport.stopSending("normal_drained").catch(() => undefined);
    // A rejected OPEN may still have its original native write in progress.
    // Queue FIN after that actual tail, retaining the association until exit.
    void this.output.waitSubmitted().then(() => this.transport.closeWrite(), () => undefined)
      .catch(() => undefined).finally(() => this.close());
  }
  close(): void {
    if (!this.#closed) {
      this.#closed = true; this.abort.abort(); this.outcome(); this.reader.close(); this.output.close(); this.#closing = true;
      let tail: Promise<void>;
      try { tail = this.transport.close(); } catch { tail = Promise.reject(new Error("carrier_failed")); }
      // A native stream can finish before the submitted output's JavaScript
      // continuation releases its original encoder position. Join both tails
      // before notifying the Session, so its association set observes release.
      void Promise.allSettled([tail, this.output.waitSubmitted()]).then(() => {
        this.#closing = false; this.cleanup(); this.changed();
      });
    }
    this.cleanup();
  }
  cleanup(): void {
    if (!this.#closed || this.#closing || this.#waiting !== undefined || this.readTask !== undefined || !this.reader.cleanupComplete() || !this.output.cleanupComplete() || !this.transport.cleanupComplete()) return;
    this.#stopWriteObservation?.(); this.#stopWriteObservation = undefined;
    this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { this.cleanup(); return this.#reference === undefined; }

}

/** Internal handshake/receive composition only. The original admission and
 * accepted scope owners must still be assembled before a usable public Session
 * can be published. No wire-version or raw-key factory is exported to users. */
export async function establishV4CredentialSession(config: V4AuthenticatedSessionConfig, credentials: VerifiedCredentialClosure,
  transportContext: Uint8Array, options?: OperationOptions): Promise<V4AuthenticatedSessionRuntime> {
  if (!isVerifiedCredentialClosure(credentials)) fail("authentication_failed");
  const binding = credentials.claimSession(config, transportContext), abort = new AbortController();
  let runtime: V4AuthenticatedSessionRuntime | undefined;
  const signal = options?.signal === undefined ? abort.signal : AbortSignal.any([abort.signal, options.signal]);
  try {
    const delivery = config.streams.delivery;
    binding.onRevoked(() => { abort.abort(); if (runtime !== undefined) void runtime.close().catch(() => undefined); else void config.transport.close().catch(() => undefined); },
      () => delivery.close("authorization_denied"));
    const authorization = binding.retainDelivery();
    try { config.streams.delivery.constrainAuthorization(authorization.check, config.reservations.session, authorization.release, authorization.remainingMS, authorization.observe); }
    catch (error) { authorization.release(); throw error; }
    runtime = await establishSession(config, { ...options, signal }, binding); binding.check(); return runtime;
  } catch (error) { if (runtime !== undefined) await runtime.close().catch(() => undefined); config.streams.delivery.close(); binding.close(); throw error; }
}

/** Private assembly test boundary. Production composition uses the verified
 * credential factory plus original once/provider admission owners. */
export function establishV4AuthenticatedSession(config: V4AuthenticatedSessionConfig, options?: OperationOptions): Promise<V4AuthenticatedSessionRuntime> {
  return establishSession(config, options);
}
async function establishSession(config: V4AuthenticatedSessionConfig, options?: OperationOptions, credentials?: CredentialSessionBinding): Promise<V4AuthenticatedSessionRuntime> {
  const { transport, noise, ledger, reservations, maxFrame, runtimeBytes } = config;
  const ready: ReadyConfig = Object.freeze({
    localCertificateDigest: new Uint8Array(config.ready.localCertificateDigest), peerCertificateDigest: new Uint8Array(config.ready.peerCertificateDigest),
    fsbDigest: new Uint8Array(config.ready.fsbDigest), fsaDigest: new Uint8Array(config.ready.fsaDigest),
    transportContextDigest: new Uint8Array(config.ready.transportContextDigest), admissionBinding: new Uint8Array(config.ready.admissionBinding),
    selectedFeatures: config.ready.selectedFeatures,
  });
  const signer = config.signer, peerReadyPublicKey = new Uint8Array(config.peerReadyPublicKey);
  const source = config.streams;
  const streams: V4SessionStreamAssembly = Object.freeze({
    ...(source.nativeDataAssemblyDepth === undefined ? {} : { nativeDataAssemblyDepth: source.nativeDataAssemblyDepth }),
    ...(source.random === undefined ? {} : { random: source.random }),
    limits: Object.freeze({ ...source.limits,
      perClass: Object.freeze([...source.limits.perClass]) as OpenAdmissionConfig["perClass"],
      perOpener: Object.freeze(source.limits.perOpener.map(row => Object.freeze([...row]))) as unknown as OpenAdmissionConfig["perOpener"],
      protected: Object.freeze(source.limits.protected.map(row => Object.freeze([...row]))) as unknown as OpenAdmissionConfig["protected"],
    }), open: source.open, openDecoder: source.openDecoder,
    control: source.control, controlDecoder: source.controlDecoder, controlSendCipher: source.controlSendCipher, controlReceiveCipher: source.controlReceiveCipher,
    root: source.root, accounts: Object.freeze(Array.from(source.accounts)), owner: Object.freeze({ ...source.owner }),
    rekeyBurst: source.rekeyBurst, rekeyRefillMS: source.rekeyRefillMS, rekeyPrepareMS: source.rekeyPrepareMS,
    rekeyProtocolMS: source.rekeyProtocolMS, rekeyConfirmationMS: source.rekeyConfirmationMS,
    sendQueueBytes: captureSendQueueBytes(source.sendQueueBytes),
    streamSendQueueBytes: captureStreamSendQueueBytes(source.streamSendQueueBytes, noise.role),
    ...(source.sendAccount === undefined ? {} : { sendAccount: source.sendAccount }),
    ...(source.sendAccounts === undefined ? {} : { sendAccounts: source.sendAccounts }),
    ...(source.internalKeys === undefined ? {} : { internalKeys: source.internalKeys }),
    ...(source.peerOpenPreparation === undefined ? {} : { peerOpenPreparation: source.peerOpenPreparation }),
    ...(source.nativePositions === undefined ? {} : { nativePositions: source.nativePositions }),
    ...(source.maintenancePositions === undefined ? {} : { maintenancePositions: source.maintenancePositions }),
    rekeyMaxScopes: source.rekeyMaxScopes ?? 1035,
    rpcMaxGeneralOutstanding: source.rpcMaxGeneralOutstanding ?? 0,
    ...(source.rpcAdmission === undefined ? {} : { rpcAdmission: source.rpcAdmission }),
    ...(source.rpcReservations === undefined ? {} : { rpcReservations: source.rpcReservations, rpcSendAccounts: source.rpcSendAccounts!, rpcNativePositions: source.rpcNativePositions! }),
    ...(source.notifyReservations === undefined ? {} : { notifyReservations: source.notifyReservations, notifySendAccounts: source.notifySendAccounts!,
      ...(source.notifyNativePosition === undefined ? {} : { notifyNativePosition: source.notifyNativePosition }) }),
    ...(source.managementReservations === undefined ? {} : { managementReservations: source.managementReservations, managementSendAccount: source.managementSendAccount!,
      ...(source.managementNativePosition === undefined ? {} : { managementNativePosition: source.managementNativePosition }) }),
    ...(source.bootstrapReservations === undefined ? {} : { bootstrapReservations: Object.freeze([...source.bootstrapReservations]) }),
    ...(source.bootstrapSendAccount === undefined ? {} : { bootstrapSendAccount: source.bootstrapSendAccount }),
    ...(source.bootstrapNativePosition === undefined ? {} : { bootstrapNativePosition: source.bootstrapNativePosition }),
    maxWriteBytes: source.maxWriteBytes, writeDeadlineMS: source.writeDeadlineMS, operationDeadlineMS: source.operationDeadlineMS,
    receive: Object.freeze({ ...source.receive }), delivery: source.delivery, authorization: Object.freeze({ check: source.authorization.check.bind(source.authorization) }),
  });
  const idleDurationMS = selectedIdleDuration(config.idleDurationMS ?? 0n, config.localIdleDurationMS);
  const automaticLiveness = captureAutomaticLiveness(config.automaticLiveness);
  qualifySessionActivity(noise.clock, idleDurationMS, streams.operationDeadlineMS, automaticLiveness);
  const captured = Object.freeze({ diagnostics: config.diagnostics, diagnosticActivity: config.diagnosticActivity, cleanupMS: config.cleanupMS, unreliablePreparation: config.unreliablePreparation, transportContextDigest: Array.from(ready.transportContextDigest, n => n.toString(16).padStart(2, "0")).join(""), idleDurationMS, automaticLiveness, transport, ledger, maxFrame, runtimeBytes, streams, credentials, maxReceiveDirections: config.maxReceiveDirections,
    deadline: noise.authorizationDeadline, clock: noise.clock,
    nativeIngress: config.reservations.nativeIngress,
    nativeRecord: config.reservations.nativeRecord,
    nativeEnvelope: config.reservations.nativeEnvelope,
    nativeReceive: config.reservations.nativeReceive,
    nativeReceiveDecoder: config.reservations.nativeReceiveDecoder,
    nativeCandidates: config.reservations.nativeCandidates,
    nativeSendCrypto: config.reservations.nativeSendCrypto,
    nativeSendEncode: config.reservations.nativeSendEncode,
    info: Object.freeze({ application_profile: config.info.application_profile, selected_features: config.info.selected_features,
      guarantees: Object.freeze({ ...config.info.guarantees }) }) });
  const profile = ownProfile(noise.profile);
  if (transport.role !== noise.role || ledger.profile !== noise.profile || profile === undefined ||
      ledger.sendDirection !== (noise.role === "client" ? 0 : 1) || captured.info.selected_features !== BigInt(ready.selectedFeatures) ||
      transport.mode !== "message" && transport.mode !== "stream") fail("configuration_capacity");
  const sessionCharge = authenticatedSessionCharge(captured.maxReceiveDirections, runtimeBytes);
  const ingressCharge = sessionIngressCharge(maxFrame, runtimeBytes), outputCharge = sessionOutputCharge(maxFrame, runtimeBytes);
  const decoderCharge = envelopeDecoderCharge({ maxFrame, mode: transport.mode, runtimeBytes });
  for (const reservation of Object.values(reservations)) if (!ledger.belongsTo(reservation)) fail("configuration_capacity");
  // Claim each original primary before any cryptographic/network work. A failed
  // claim returns already claimed pieces and never consumes a shared alias.
  const owned: ResourceReference[] = [];
  let sessionReservation: ResourceReference | undefined;
  let epochReservation: ResourceReference | undefined;
  let ingressReservation: ResourceReference | undefined;
  let decoderReservation: ResourceReference | undefined;
  let outputReservation: ResourceReference | undefined;
  let reader: TransportReader | undefined;
  let output: TransportOutput | undefined;
  let handshake: NoiseHandshake | undefined;
  let epoch: RecordEpoch | undefined;
  let runtime: V4AuthenticatedSessionRuntime | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const abort = new AbortController();
  const signal = options?.signal === undefined ? abort.signal : AbortSignal.any([options.signal, abort.signal]);
  const tick = (): void => {
    try {
      noise.preparationDeadline.check(); noise.authorizationDeadline.check(); credentials?.check(); transport.checkPreparation?.();
      const remaining = noise.preparationDeadline.remainingMS() < noise.authorizationDeadline.remainingMS()
        ? noise.preparationDeadline.remainingMS() : noise.authorizationDeadline.remainingMS();
      timer = setTimeout(tick, timerChunk(credentials === undefined || remaining < credentials.remainingMS() ? remaining : credentials.remainingMS()));
    } catch { abort.abort(); void transport.close().catch(() => undefined); }
  };
  try {
    sessionReservation = reservations.session.take(sessionCharge); owned.push(sessionReservation);
    epochReservation = reservations.epoch.take(recordEpochCharge(runtimeBytes)); owned.push(epochReservation);
    ingressReservation = reservations.ingress.take(ingressCharge); owned.push(ingressReservation);
    decoderReservation = reservations.envelope.take(decoderCharge); owned.push(decoderReservation);
    outputReservation = reservations.output.take(outputCharge); owned.push(outputReservation);
    if (signal.aborted) fail("closed");
    reader = new TransportReader(transport, maxFrame, runtimeBytes, ingressReservation, decoderReservation);
    output = new TransportOutput(transport, maxFrame, runtimeBytes, outputReservation);
    handshake = new NoiseHandshake(noise);
    tick();
    if (signal.aborted) fail("closed");
    if (noise.role === "client") {
      credentials?.check(); await output.plain(frameType("HANDSHAKE"), handshake.writeMessage(), { signal });
      const received = await reader.plain(frameType("HANDSHAKE"), profile.handshake_message_bytes, { signal });
      try { handshake.readMessage(received); } finally { received.fill(0); }
    } else {
      const received = await reader.plain(frameType("HANDSHAKE"), profile.handshake_message_bytes, { signal });
      try { handshake.readMessage(received); } finally { received.fill(0); }
      credentials?.check(); await output.plain(frameType("HANDSHAKE"), handshake.writeMessage(), { signal });
    }
    credentials?.check(); handshake.createReady(signer, ready);
    if (captured.info.application_profile !== "transport") {
      epoch = handshake.prepareEpoch({ runtimeBytes }, ledger, epochReservation);
      runtime = new V4AuthenticatedSessionRuntime(captured, epoch, reader, output, sessionReservation);
      config.prepareInbound?.(runtime);
    }
    handshake.submitReady(output);
    const peerReady = await reader.plain(frameType("READY"), 103, { signal });
    try { handshake.verifyReady(peerReady, peerReadyPublicKey, ready); } finally { peerReady.fill(0); }
    await observeTask(output.waitSubmitted(), signal);
    if (signal.aborted) fail("closed");
    credentials?.check(); epoch = handshake.finish({ runtimeBytes }, ledger, epochReservation);
    runtime ??= new V4AuthenticatedSessionRuntime(captured, epoch, reader, output, sessionReservation);
    config.observeNetworkReady?.();
    transport.checkPreparation?.();
    config.claimReadySession?.(runtime);
    if (signal.aborted) fail("closed");
    transport.completePreparation?.();
    runtime.start(readyActivation, epoch, config.preparedRawStreams);
    return runtime;
  } catch (error) {
    config.diagnosticActivity?.failure(error, true);
    abort.abort(); handshake?.close(); if (runtime !== undefined) void runtime.close().catch(() => undefined);
    epoch?.close(); reader?.close(); output?.close();
    // Cancellation never releases a native output tail early. These actual
    // dependencies retain their charge even when the close operation fails.
    void Promise.allSettled([transport.close(), transport.waitTermination(), output?.waitSubmitted()]);
    streams.internalKeys?.close(); streams.peerOpenPreparation?.close(); streams.rpcAdmission?.close(); ledger.close();
    for (const refs of streams.rpcReservations ?? []) for (const ref of refs) ref.release();
    for (const account of streams.rpcSendAccounts ?? []) account.close();
    for (const position of streams.rpcNativePositions ?? []) for (const ref of position?.references ?? []) ref.release();
    for (const ref of streams.managementReservations ?? []) ref.release(); streams.managementSendAccount?.close();
    for (const ref of streams.managementNativePosition?.references ?? []) ref.release();
    for (const ref of [streams.open, streams.openDecoder, streams.control, streams.controlDecoder, streams.controlSendCipher, streams.controlReceiveCipher]) ref.release();
    for (const ref of streams.bootstrapReservations ?? []) ref.release();
    streams.bootstrapSendAccount?.close();
    for (const ref of streams.bootstrapNativePosition?.references ?? []) ref.release();
    for (const reference of owned) reference.release();
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    peerReadyPublicKey.fill(0);
    for (const bytes of [ready.localCertificateDigest, ready.peerCertificateDigest, ready.fsbDigest, ready.fsaDigest, ready.transportContextDigest, ready.admissionBinding]) bytes.fill(0);
  }
}


interface RuntimeConfig {
  readonly diagnostics?: DiagnosticObserver | undefined;
  readonly diagnosticActivity?: DiagnosticActivity | undefined;
  readonly cleanupMS?: number | undefined;
  readonly unreliablePreparation: UnreliablePreparation | undefined;
  readonly nativeIngress: ResourceReference | undefined;
  readonly nativeRecord: ResourceReference | undefined;
  readonly nativeEnvelope: ResourceReference | undefined;
  readonly nativeReceive: ResourceReference | undefined;
  readonly nativeReceiveDecoder: ResourceReference | undefined;
  readonly nativeCandidates: ResourceReference | undefined;
  readonly nativeSendCrypto: ResourceReference | undefined;
  readonly nativeSendEncode: ResourceReference | undefined;
  readonly idleDurationMS: bigint; readonly automaticLiveness: V4AutomaticLivenessPolicy | undefined;
  readonly transport: V4AuthenticatedTransport; readonly ledger: CryptoUsageLedger;
  readonly maxFrame: number; readonly runtimeBytes: bigint; readonly maxReceiveDirections: number;
  readonly streams: V4SessionStreamAssembly; readonly info: V4SessionInfo;
  readonly deadline: NoiseHandshakeConfig["authorizationDeadline"];
  readonly clock: NoiseHandshakeConfig["clock"];
  readonly credentials: CredentialSessionBinding | undefined;
  readonly transportContextDigest: string;
}
interface TerminalTuple { readonly epoch: number; readonly next: bigint; readonly offset: bigint }
interface DirectionTermination { readonly normal: TrustedDeadline; readonly hard: TrustedDeadline; quarantined: boolean }
interface ReceiveBinding {
  rpcPosition?: number;
  retired?: boolean;
  retirementReferences?: number;
  sendAccount?: ResourceAccount;
  readonly receiveKeys: DirectionKeyPositions;
  sendKeys?: DirectionKeyPositions;
  readonly handle: OpenHandle; cipher: RecordCipher;
  direction?: ReliableReceiveDirection; send?: RecordCipher;
  stream?: RuntimeStream; write?: ReliableWriteRequest;
  terminalSend?: TerminalTuple; terminalReceive?: TerminalTuple; sendDrained: boolean; receiveDrained: boolean; stopPending: boolean; receiveAbandon: boolean; retiring: boolean; quarantined: boolean;
  draining?: Promise<void>; acknowledging?: Promise<void>; ackDirty?: boolean; nextReceive: bigint; nextSend: bigint; sentOffset: bigint; acknowledged: bigint; sendLimit: bigint; sendFIN: boolean;
  terminationReservation?: ResourceReference; termination?: Promise<void>;
  sendSealed?: boolean; resetRequested?: boolean; stoppedSent?: boolean; stopSent?: boolean; sendAborted?: boolean;
  authenticationWaiters?: number;
  ackTimer?: ReturnType<typeof setTimeout>; ackEligible?: boolean; ackUrgent?: boolean;
  ackCommittedOffset?: bigint; ackCommittedLimit?: bigint;
  gracefulFinishMS?: bigint;
  sendTermination?: DirectionTermination; receiveTermination?: DirectionTermination;
  adapterActive?: boolean;
  native?: NativeAssociation;
  rejectionPending?: number;
}
interface RetirementBatch {
  readonly sequence: bigint;
  readonly digest: Uint8Array;
  readonly ids: readonly bigint[];
  readonly deadline: TrustedDeadline;
  submitted: boolean;
  writing: boolean;
  done: boolean;
}
/** Bootstrap is part of the original pre-consumption Session batch. Reserving
 * the standalone codec upper bound also covers a shared native workspace;
 * adoption never needs a fresh root reservation after READY. */
export function sessionBootstrapCharges(profile: V4SessionInfo["application_profile"], maxFrame: number, runtimeBytes: bigint,
  receive: ReceiveDirectionConfig): readonly ResourceVector[] {
  if (profile === "transport") return [];
  if (profile !== "services" && profile !== "execution") fail("configuration_capacity");
  const cipher = { maxFrame, runtimeBytes }, initial = { ...receive, receiveLimit: BigInt(bootstrapSpec.initial_receive_limit) };
  return [directionKeyCharge(cipher), directionKeyCharge(cipher), directionKeyCharge(cipher), directionKeyCharge(cipher),
    streamTerminationCharge(runtimeBytes), receiveDirectionCharge(initial), receiveDecoderCharge(initial), receiveCursorCharge(initial),
    new ResourceVector([runtimeBytes + 1024n, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 1n, 0n]),
    bootstrapOutputCharge()];
}
function bootstrapOutputCharge(): ResourceVector {
  return new ResourceVector([BigInt(4480 + envelopePrefixBytes + recordHeaderBytes + 16 + 128), 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
function controlDecoderConfig(maxFrame: number, runtimeBytes: bigint): Readonly<{ bytes: number; nodes: number; textBytes: number; arrayItems: number; runtimeBytes: bigint }> {
  return { bytes: maxFrame, nodes: 5210, textBytes: Math.min(4096, maxFrame), arrayItems: 1035, runtimeBytes };
}
export function sessionControlDecoderCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector { return cborDecoderCharge(controlDecoderConfig(maxFrame, runtimeBytes)); }
export function sessionControlCharge(maxFrame: number, runtimeBytes: bigint): ResourceVector {
  capacity(maxFrame, runtimeBytes);
  // Independent inbound plaintext and outbound canonical body, plus the fixed
  // PING nonce. Cipher/output owners retain their own separate backing.
  return new ResourceVector([BigInt(maxFrame * 3 + 32 * 7 + 64 * 3 * 1024 + 1024) + runtimeBytes, 0n, 0n, 2n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}

/** Original shared reliable-carrier owner. OPEN, control and DATA all use the
 * same epoch/authorization, actual scope keys, prepaid buffers and admission.
 * Higher public request/terminal owners are still required to publish streams. */
export class V4AuthenticatedSessionRuntime implements V4SessionOwner {
  readonly #info: V4SessionInfo;
  readonly #bindings = new Map<bigint, ReceiveBinding>();
  #quarantineDirections = 0;
  readonly #abort = new AbortController();
  readonly #receiveDirection: RecordDirection;
  readonly #sendDirection: RecordDirection;
  #open: OpenAdmission | undefined;
  #controlDecoder: CBORDecoder | undefined;
  #controlSend: RecordCipher | undefined;
  #controlReceive: RecordCipher | undefined;
  #controlReservation: ResourceReference | undefined;
  #plain: Uint8Array = empty;
  #encode: Uint8Array = empty;
  #nonce: Uint8Array = empty;
  #handshakeHash: Uint8Array = empty;
  #retireScratch: Uint8Array = empty;
  #retireDigest: Uint8Array = empty;
  #retireOut: RetirementBatch | undefined;
  #retireIn: RetirementBatch | undefined;
  #retireTail: RetirementBatch | undefined;
  #retireWorking = false;
  #lastRetireSent = 0n;
  #lastRetireReceived = 0n;
  #lastRetireSentDigest: Uint8Array = empty;
  #lastRetireReceivedDigest: Uint8Array = empty;
  #reservation: ResourceReference | undefined;
  #receiving: Promise<void> | undefined;
  readonly cleanupOwner: SessionCleanup;
  #closeInitializing = false;
  #cleaning = false;
  #closed = false;
  #draining = false;
  #goaway: { ceiling: bigint; reason: bigint } | undefined;
  #drain: SessionDrain | undefined;
  #drainDeadline: TrustedDeadline | undefined;
  #drainTimer: ReturnType<typeof setTimeout> | undefined;
  #drainWork: Promise<void> | undefined;
  #businessDrained = false;
  #localGoaway: { ceiling: bigint; sent: boolean } | undefined;
  #cleanupFault = false;
  readonly #terminationWaiters = new Set<() => void>();
  #epochNumber = 0;
  #rekeyRound: RekeyRound | undefined;
  #rekeyStage: "idle" | "init" | "reply" | "commit" | "ack" = "idle";
  #rekeyDeadline: TrustedDeadline | undefined;
  #rekeySafetyDeadline: TrustedDeadline | undefined;
  #rekeyPhaseDeadline: TrustedDeadline | undefined;
  #rekeyTimer: ReturnType<typeof setTimeout> | undefined;
  #rekeyWorking = false;
  #peerBarrier: readonly RekeyEntry[] = [];
  #localFrozen: readonly RekeyEntry[] = [];
  #candidate: RecordEpoch | undefined;
  #candidateSend: RecordCipher | undefined;
  #candidateReceive: RecordCipher | undefined;
  #sendSwitched = false;
  #receiveSwitched = false;
  #rekeyBase = 0n;
  #rekeyAnchor: ClockMark | undefined;
  #rekeyPost = 0n;
  #rekeyCharged = false;
  #rekeyRequest: Promise<void> | undefined;
  #autoRekeyQueued = false;
  #rekeySafetyTimer: ReturnType<typeof setTimeout> | undefined;
  #rekeyRetired: RecordEpoch[] = [];
  #transportClosed = false;
  #supervisor: Promise<void> | undefined;
  #authorizationTimer: ReturnType<typeof setTimeout> | undefined;
  #accepting = false;
  #nextWait = 0n;
  #idle: SessionIdleWatchdog | undefined;
  #liveness: SessionLiveness | undefined;
  #failure: V4SessionAssemblyError | undefined;
  #controllerTerminalObserved = false;
  #controllerTransportFailure = false;
  #rekeyIntent = false;
  #diagnosticRekeyStarted: number | undefined;
  #diagnosticRekeyTimedOut = false;
  #diagnosticPhaseStarted = 0;
  #diagnosticRekeyPhase: DiagnosticFields["phase"] = "rekey_local_prepare";
  #readBlocked = false;
  readonly #waiters = new Set<() => void>();
  #authenticationWaiters = 0;
  #messageCandidates = 0n;
  readonly #streamRegistrations = new Map<string, StreamRegistrationState>();
  readonly #registrationOwners = new Set<StreamRegistrationState>();
  readonly #dispatching = new Set<OpenHandle>();
  #dispatchQueued = false;
  #rejecting = false;
  #application: ApplicationGroup | undefined;
  #rpc: RPCApplicationAdmission | undefined;
  readonly #rpcPositions: ProtectedResourceReservation[][] = Array.from({ length: 8 }, () => []);
  readonly #rpcRefs: ResourceReference[][] = Array.from({ length: 8 }, () => []);
  readonly #rpcOutputs: (ResourceReference | undefined)[] = Array.from({ length: 8 });
  readonly #rpcHandles: (OpenHandle | undefined)[] = Array.from({ length: 8 });
  readonly #rpcTasks: (Promise<void> | undefined)[] = Array.from({ length: 8 });
  readonly #rpcNative: (NativeProtocolPosition | undefined)[] = Array.from({ length: 8 });
  readonly #rpcNativeRenewal: NativeProtocolPosition["renewal"][] = Array.from({ length: 8 });
  readonly #rpcStopped = Array.from({ length: 8 }, () => false);
  #rpcDriving = false;
  readonly #dedicatedRPCStreams = new WeakSet<OpenHandle>();
  readonly #notifyRefs: ResourceReference[][] = [[], []];
  readonly #notifyPositions: ProtectedResourceReservation[][] = [[], []];
  readonly #notifyHandles: (OpenHandle | undefined)[] = [undefined, undefined];
  readonly #notifyTasks: (Promise<void> | undefined)[] = [undefined, undefined];
  readonly #notifyOutputs: (ResourceReference | undefined)[] = [undefined, undefined];
  readonly #notifyStopped = [false, false];
  #notifyNative: NativeProtocolPosition | undefined;
  #notifyDemand = false;
  readonly #managementRefs: ResourceReference[] = [];
  #managementTask: Promise<void> | undefined;
  #managementHandle: OpenHandle | undefined;
  readonly #managementPositions: ProtectedResourceReservation[] = [];
  #managementNativeRenewal: NativeProtocolPosition["renewal"];
  #managementDeadline: TrustedDeadline | undefined;
  #managementStopped = false;
  #managementDriving = false;
  #managementNative: NativeProtocolPosition | undefined;
  readonly #managementReceivePositions: ProtectedResourceReservation[] = [];
  #managementWaitPosition: ProtectedResourceReservation | undefined;
  #managementOutput: ResourceReference | undefined;
  readonly #nativeAssociations = new Set<NativeAssociation>();
  #nativeScheduler: NativeIngressScheduler | undefined;
  #nativeSend: NativeSendWorkspace | undefined;
  #sendAccount: ResourceAccount | undefined;
  #sendAccounts: ProtectedResourceAccounts | undefined;
  #nativeAcceptor: Promise<void> | undefined;
  #nativePositions: NativeProtocolPositions | undefined;
  #maintenancePositions: MaintenancePositions | undefined;
  #internalKeys: SessionKeyPreparation | undefined;
  #unreliable: UnreliableRuntime | undefined;
  #ready = false;
  #bootstrap: OpenHandle | undefined;
  #bootstrapTask: Promise<void> | undefined;
  #bootstrapReservation: ResourceReference | undefined;
  #bootstrapOutput: ResourceReference | undefined;
  #bootstrapPosition: NativeProtocolPosition | undefined;
  #bootstrapDeadline: TrustedDeadline | undefined;
  #bootstrapTimer: ReturnType<typeof setTimeout> | undefined;
  #bootstrapBinding = false;
  readonly #bootstrapAbort = new AbortController();
  #core: { config: RuntimeConfig; epoch: RecordEpoch; reader: TransportReader; output: TransportOutput } | undefined;
  private get config(): RuntimeConfig { return this.#core?.config ?? fail("closed"); }
  private get epoch(): RecordEpoch { return this.#core?.epoch ?? fail("closed"); }
  private set epoch(value: RecordEpoch) { if (this.#core === undefined) fail("closed"); this.#core.epoch = value; }
  private get reader(): TransportReader { return this.#core?.reader ?? fail("closed"); }
  private get output(): TransportOutput { return this.#core?.output ?? fail("closed"); }
  constructor(config: RuntimeConfig, epoch: RecordEpoch, reader: TransportReader, output: TransportOutput, reservation: ResourceReference) {
    this.#core = { config, epoch, reader, output };
    this.#reservation = reservation.take(authenticatedSessionCharge(config.maxReceiveDirections, config.runtimeBytes));
    this.cleanupOwner = new SessionCleanup(config.streams.root, config.streams.accounts, config.streams.owner, config.clock, config.runtimeBytes, config.cleanupMS, config.diagnostics?.counters);
    this.#sendDirection = config.ledger.sendDirection;
    this.#receiveDirection = this.#sendDirection === 0 ? 1 : 0;
    this.#info = config.info;
    this.#rekeyBase = config.streams.rekeyBurst * config.streams.rekeyRefillMS;
    const streams = config.streams;
    try {
      this.#internalKeys = streams.internalKeys ?? new SessionKeyPreparation(config.ledger, config.info.application_profile, this.#reservation);
      if (config.info.application_profile === "transport") {
        if (streams.rpcAdmission !== undefined) fail("configuration_capacity");
      } else {
        if (streams.rpcAdmission === undefined) fail("configuration_capacity");
        streams.rpcAdmission.claim(this.#reservation, config.info.application_profile, streams.rpcMaxGeneralOutstanding ?? 0, config.deadline, this.cleanupOwner,
          config.credentials?.applicationContext(this.#sendDirection === 0 ? "client" : "server"), config.credentials?.checkpointPolicy(config.info.selected_features), this,
          () => !this.#closed && !this.#sealBusinessDrain());
        this.#rpc = streams.rpcAdmission;
        this.#rpc.setStreamOpener((kind, metadata, deadline, signal, prepare, prepaid) => this.#openRPCStream(kind, metadata, deadline, signal, prepare, prepaid));
        const notifyCosts = sessionBootstrapCharges(config.info.application_profile, config.maxFrame, config.runtimeBytes, streams.receive);
        if (streams.rpcReservations?.length !== 7 || streams.rpcSendAccounts?.length !== 8 || streams.rpcNativePositions?.length !== 8) fail("configuration_capacity");
        for (let position = 0; position < 8; position++) {
          const refs = position === 0 ? streams.bootstrapReservations : streams.rpcReservations[position - 1];
          if (refs?.length !== notifyCosts.length) fail("configuration_capacity");
          for (const [index, ref] of refs.entries()) this.#rpcPositions[position]!.push(streams.root.protect(ref, notifyCosts[index]!));
          this.#rpcNative[position] = streams.rpcNativePositions[position]; this.#rpcNativeRenewal[position] = this.#rpcNative[position]?.renewal;
        }
        this.#rpc.onChannelsChange(() => this.#wake());
        if (streams.notifyReservations?.length !== 2 || streams.notifySendAccounts?.length !== 2) fail("configuration_capacity");
        for (let position = 0; position < 2; position++) {
          const refs = streams.notifyReservations[position]!; if (refs.length !== notifyCosts.length) fail("configuration_capacity");
          for (const [index, ref] of refs.entries()) this.#notifyPositions[position]!.push(streams.root.protect(ref, notifyCosts[index]!));
        }
        this.#notifyNative = streams.notifyNativePosition;
        if (config.info.application_profile === "execution") {
          const costs = sessionBootstrapCharges("execution", config.maxFrame, config.runtimeBytes, streams.receive), refs = streams.managementReservations;
          if (refs?.length !== costs.length || streams.managementSendAccount === undefined) fail("configuration_capacity");
          for (const [index, ref] of refs.entries()) this.#managementPositions.push(streams.root.protect(ref, costs[index]!));
          this.#managementWaitPosition = this.#managementPositions[8];
          if (this.#sendDirection === 1) this.#managementReceivePositions.push(...this.#managementPositions.slice(0, 2));
          this.#managementNative = streams.managementNativePosition;
          this.#managementNativeRenewal = this.#managementNative?.renewal;
          this.#rpc.onManagementChange(() => this.#wake());
        }
        this.#rpc.onCleanup(() => this.#cleanup());
      }
      this.#maintenancePositions = streams.maintenancePositions;
      if (this.#maintenancePositions === undefined) {
        // Private authenticated test assembly has already installed epoch zero.
        // Production owns both alternating epoch sets before consuming a lease.
        const storage = { maxFrame: config.maxFrame, runtimeBytes: config.runtimeBytes, maxScopes: streams.rekeyMaxScopes ?? 1035 };
        const costs = maintenancePositionCharges(storage);
        const refs = streams.root.reserveBatch([...costs, ...costs.slice(3)].map((charge, index) => ({ accounts: streams.accounts,
          owner: { ...streams.owner, kind: `maintenance_position_${index}` }, charge })));
        try { this.#maintenancePositions = new MaintenancePositions(streams.root, storage, refs[0]!, refs.slice(1, 3), refs.slice(3)); }
        finally { for (const reference of refs) reference.release(); }
      }
      this.#sendAccount = streams.sendAccount ?? createSendAccount(streams.root, streams.owner, captureSendQueueBytes(streams.sendQueueBytes));
      checkSendQueueCapacity(captureSendQueueBytes(streams.sendQueueBytes), streams.maxWriteBytes, config.runtimeBytes,
        config.transport.nativeStreams === undefined ? 0 : this.#nativeOutputFrame() + envelopePrefixBytes);
      checkSendQueueCapacity(captureStreamSendQueueBytes(streams.streamSendQueueBytes, config.transport.role), streams.maxWriteBytes, config.runtimeBytes,
        config.transport.nativeStreams === undefined ? 0 : this.#nativeOutputFrame() + envelopePrefixBytes);
      this.#sendAccounts = streams.sendAccounts;
      if (this.#sendAccounts === undefined) {
        // Private test assembly has no Environment admission transaction.
        const count = sendAccountPoolCapacity(config.maxReceiveDirections, streams.limits.ingressItems);
        const reference = streams.root.reserve({ accounts: streams.accounts, owner: { ...streams.owner, kind: "send_account_slots" },
          charge: protectedAccountPoolCharge(count, config.runtimeBytes) });
        try { this.#sendAccounts = createStreamSendAccounts(streams.root, count,
          captureStreamSendQueueBytes(streams.streamSendQueueBytes, config.transport.role), config.runtimeBytes, reference); }
        finally { reference.release(); }
      }
      if (config.transport.nativeStreams !== undefined) {
        this.#nativePositions = streams.nativePositions;
        if (this.#nativePositions === undefined) fail("configuration_capacity");
        const capacity = config.maxReceiveDirections + streams.limits.ingressItems + 1;
        if (config.transport.mode !== "stream" || config.nativeIngress === undefined || config.nativeRecord === undefined || config.nativeEnvelope === undefined ||
            config.nativeReceive === undefined || config.nativeReceiveDecoder === undefined || config.nativeCandidates === undefined || config.nativeSendCrypto === undefined || config.nativeSendEncode === undefined || config.transport.nativeStreams.capacity < capacity) fail("configuration_capacity");
        this.#nativeScheduler = new NativeIngressScheduler(capacity, config.runtimeBytes, config.nativeIngress, streams.root, config.maxFrame,
          config.nativeRecord, config.nativeEnvelope, config.nativeReceive, config.nativeReceiveDecoder,
          nativeCandidateCount(streams.nativeDataAssemblyDepth, this.#sendDirection, config.maxReceiveDirections), config.nativeCandidates);
        this.#nativeSend = new NativeSendWorkspace(this.#nativeOutputFrame(), config.runtimeBytes, config.nativeSendCrypto, config.nativeSendEncode);
      }
      if (streams.limits.direction !== this.#sendDirection || streams.limits.maxActive > config.maxReceiveDirections ||
          (streams.rekeyMaxScopes ?? 1035) < config.maxReceiveDirections ||
          streams.receive.maxDataBytes + 100 > config.maxFrame || config.maxFrame < 4480 || !Number.isSafeInteger(streams.maxWriteBytes) ||
          streams.maxWriteBytes < 1 || streams.maxWriteBytes > 1048576 || streams.writeDeadlineMS < 1n ||
          streams.writeDeadlineMS > 60000n || streams.operationDeadlineMS < 1n || streams.operationDeadlineMS > 60000n || streams.rekeyBurst < 1n || streams.rekeyBurst > 65535n ||
          streams.rekeyRefillMS < 1n || streams.rekeyRefillMS > 0xffffffffn || streams.rekeyPrepareMS < 1n ||
          streams.rekeyProtocolMS < 1n || streams.rekeyConfirmationMS < 1n || streams.limits.maxActive > 1035) fail("configuration_capacity");
      for (const r of [streams.open, streams.openDecoder, streams.control, streams.controlDecoder, streams.controlSendCipher, streams.controlReceiveCipher]) {
        if (!this.#reservation!.sameEnvironment(r)) fail("configuration_capacity");
      }
      this.#open = new OpenAdmission(streams.limits, streams.open, streams.openDecoder);
      this.#controlReservation = streams.control.take(sessionControlCharge(config.maxFrame, config.runtimeBytes));
      this.#plain = new Uint8Array(config.maxFrame); this.#encode = new Uint8Array(config.maxFrame); this.#nonce = new Uint8Array(16);
      this.#handshakeHash = new Uint8Array(32); epoch.copyHandshakeHash(this.#handshakeHash);
      this.#retireScratch = new Uint8Array(config.maxFrame); this.#retireDigest = new Uint8Array(32);
      this.#lastRetireSentDigest = new Uint8Array(32); this.#lastRetireReceivedDigest = new Uint8Array(32);
      this.#controlDecoder = new CBORDecoder(controlDecoderConfig(config.maxFrame, config.runtimeBytes), streams.controlDecoder);
      const authorization: RecordAuthorization = { check: (type, header, direction) => {
        this.#check();
        if (header.scope !== 0n) fail("protocol_violation");
        streams.authorization.check(type, header, direction);
      } };
      this.#controlSend = epoch.derive(0n, this.#sendDirection, config, authorization, streams.controlSendCipher);
      this.#controlReceive = epoch.derive(0n, this.#receiveDirection, config, authorization, streams.controlReceiveCipher);
      if (config.info.application_profile !== "transport") this.#prepareBootstrap();
    } catch (error) { void this.close().catch(() => undefined); throw error; }
    this.#idle = new SessionIdleWatchdog(config.clock, config.idleDurationMS, code => this.#failSession(code));
    this.#liveness = new SessionLiveness(config.clock, config.deadline, config.streams.operationDeadlineMS, config.automaticLiveness, {
      check: () => this.#check(), available: () => this.output.available(), epoch: () => this.#epochNumber,
      stalled: () => this.#readBlocked || !this.output.available(), fail: code => this.#failSession(code), changed: () => this.#wake(),
      submit: (nonce, ticket) => {
        this.#check();
        try {
          const body = new FixedCBORWriter(this.#encode).map(1).uint(0).data(nonce).result();
          return this.output.record(this.#controlSend!, frameType("PING"), body, () => undefined, ticket);
        } finally { this.#encode.fill(0); }
      },
    });
    this.output.observeFailure(error => this.#observeControllerFailure(error));
    this.output.observeRecords(() => this.#idle!.activity(), () => this.#liveness!.localStall());
    Object.defineProperty(this, "then", { value: undefined });
  }
  #observeControllerFailure(error: unknown): void {
    if (this.#closed || this.#controllerTerminalObserved) return;
    this.#controllerTerminalObserved = true;
    this.#controllerTransportFailure = originalNativeConnectionFailure(error);
  }
  #diagnostic(fields: Partial<DiagnosticFields>, metric?: DiagnosticMetric): void {
    if (this.config.diagnosticActivity !== undefined) this.config.diagnosticActivity.event(fields, metric);
    else if (metric !== undefined) this.config.diagnostics?.counters.observe(metric, fields);
  }
  #beginDiagnosticRekey(): void {
    if (this.#diagnosticRekeyStarted !== undefined) return;
    this.#diagnosticRekeyTimedOut = false;
    this.#diagnosticRekeyStarted = this.#diagnosticPhaseStarted = performance.now(); this.#diagnosticRekeyPhase = "rekey_local_prepare";
    this.#diagnostic({ state: "ready", phase: this.#diagnosticRekeyPhase }, "rekey_started");
  }
  #diagnosticRekeyFailure(error: unknown): void {
    if (this.#diagnosticRekeyStarted === undefined || this.#diagnosticRekeyTimedOut || diagnosticFailure(error).code !== "timeout") return;
    this.#diagnosticRekeyTimedOut = true;
    this.#diagnostic({ phase: this.#diagnosticRekeyPhase, code: "timeout", duration_bucket: diagnosticDuration(this.#diagnosticPhaseStarted) }, "rekey_timeout");
  }
  #checkRekeyDeadlines(): void {
    try { this.#rekeyDeadline!.check(); this.#rekeyPhaseDeadline!.check(); }
    catch (error) { this.#diagnosticRekeyFailure(error); throw error; }
  }
  #failSession(code: V4SessionAssemblyError["code"]): void {
    if (this.#closed) return;
    this.#observeControllerFailure(undefined);
    this.#failure ??= new V4SessionAssemblyError(code);
    const failure = diagnosticFailure(new Error(code));
    this.#diagnostic({ state: "failed", code: failure.code }, failure.metric === "identity_rejection" ? failure.metric : undefined);
    void this.close().catch(() => undefined);
  }
  #resourceFailure(alreadyObserved = false): void {
    if (this.#closed) return;
    this.#diagnostic({ code: "resource_exhausted" }, alreadyObserved ? undefined : "resource_rejection");
    this.#draining = true;
    // Best-effort publication uses only the already-admitted maintenance
    // position. There is no new waiter, codec or reserve in the failure path.
    // Close keeps any submitted output and native cleanup tail charged.
    try {
      if (this.output.available()) {
        const body = new FixedCBORWriter(this.#encode).map(2).uint(0)
          .uint(table<Record<string, number>>("error_codes")!.resource_exhausted!).uint(1).uint(0).result();
        void this.output.record(this.#sendSwitched ? this.#candidateSend! : this.#controlSend!, frameType("CLOSE"), body, () => undefined).catch(() => undefined);
      }
    } catch { /* Unavailable maintenance falls back to original carrier close. */ }
    finally { this.#encode.fill(0); this.#failSession("resource_exhausted"); }
  }
  #check(): void {
    if (this.#closed) throw this.#failure ?? new V4SessionAssemblyError("closed");
    if (!this.#ready) fail("authentication_failed");
    if (this.#drainDeadline !== undefined) this.#drainRemainingMS();
    this.#idle?.check();
    this.#reservation!.check(); this.config.deadline.check(); this.config.credentials?.check();
    if (this.#closed) fail("closed");
  }
  #drainRemainingMS(): bigint {
    // Every observation of the original Drain deadline, including timer
    // rearming, records its outcome before Session Close can settle it.
    try { return this.#drainDeadline!.remainingMS(); }
    catch (error) {
      const expired = error instanceof TimeError && error.code === "time_expired";
      this.#drain!.finish(expired ? "deadline_aborted" : "failed");
      this.#failSession(expired ? "drain_deadline" : "time_unavailable");
      throw this.#failure!;
    }
  }
  /** A local Close or original connection failure can obtain fresh material. */
  controllerReconnectAllowed(): boolean { return !this.#controllerTerminalObserved || this.#controllerTransportFailure; }
  controllerNotificationDraining(): boolean { return this.#draining; }
  /** Original Controller publication gate; this does not allocate or OPEN. */
  controllerGate(reference: ResourceReference): bigint {
    this.#check();
    if (!this.#reservation!.sameEnvironment(reference)) throw new Error("owner_unavailable");
    if (this.#draining || this.#goaway !== undefined) fail("session_draining");
    return this.config.deadline.cap;
  }
  controllerAuthentication(reference: ResourceReference): StreamHandlersTypes.V4AuthenticatedContext {
    this.controllerGate(reference);
    if (this.config.credentials === undefined) fail("authentication_failed");
    return this.config.credentials!.applicationContext(this.#sendDirection === 0 ? "client" : "server");
  }
  controllerNotificationAuthentication(reference: ResourceReference): StreamHandlersTypes.V4AuthenticatedContext {
    if (this.#closed || this.#draining || this.#rpc === undefined || !this.#reservation!.sameEnvironment(reference)) throw new Error("owner_unavailable");
    this.#reservation!.check(); this.config.deadline.check(); this.config.credentials?.check();
    if (this.config.credentials === undefined) fail("authentication_failed");
    return this.config.credentials.applicationContext(this.#sendDirection === 0 ? "client" : "server");
  }
  subscribeControllerNotification<Input, Value>(reference: ResourceReference, method: ServiceDefinitionTypes.V4MethodDefinition<Input, any, "notify">,
    handler: ServiceHandlersTypes.V4NotificationHandler<Value>, options: NotificationSubscriptionTypes.V4NotificationSubscriptionOptions<Input, Value>,
    scheduler: NotificationScheduler): NotificationRegistration {
    this.controllerNotificationAuthentication(reference);
    return this.#rpc!.subscribeNotificationOwner(method, handler, options, scheduler);
  }
  info(): V4SessionInfo { return this.#info; }
  drain(options?: V4DrainOptions): V4DrainOperation {
    if (this.#drain !== undefined) return this.#drain.operation;
    this.#check();
    const requested = options?.timeoutMS ?? 30000n;
    if (typeof requested !== "bigint" || requested <= 0n || requested > 0xffffffffffffffffn) fail("configuration_capacity");
    const deadline = this.#deadline(requested < 30000n ? requested : 30000n);
    const operation = createSessionDrain(() => {
      this.#check();
      const ref = this.#reserve(++this.#nextWait, ["v4_drain_wait"], [new ResourceVector([this.config.runtimeBytes + 256n, 0n, 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n])])[0]!;
      return () => ref.release();
    }, pending);
    // Admission and the accepted frontier are captured in the same local turn.
    this.#drain = operation; this.#drainDeadline = deadline; this.#draining = true;
    this.#rpc?.drain(deadline);
    this.#localGoaway = { ceiling: this.#open!.highestAccepted(false), sent: false };
    const tick = (): void => {
      this.#drainTimer = undefined;
      if (this.#closed) return;
      try { this.#check(); this.#driveDrain(); this.#drainTimer = setTimeout(tick, Math.min(10, timerChunk(this.#drainRemainingMS()))); }
      catch { operation.finish("failed"); void this.close().catch(() => undefined); }
    };
    tick(); this.#wake(); return operation.operation;
  }
  #communicationDrained(businessOnly = false): boolean {
    if (this.cleanupOwner.businessPending() || this.#application?.businessPending() === true ||
        this.#rpc?.businessPending() === true || this.#dispatching.size !== 0) return false;
    const counts = this.#open!.counts();
    if (counts.opening !== 0 || counts.ingress !== 0 || this.#readBlocked || this.#rekeyRound !== undefined || this.#rekeyIntent) return false;
    for (const binding of this.#bindings.values()) {
      if (businessOnly && binding.handle === this.#managementHandle) continue;
      if (binding.rejectionPending !== undefined) return false;
      const phase = this.#open!.phase(binding.handle);
      if (phase === "local_prepared" || phase === "local_opening" || phase === "peer_verifying" || phase === "peer_pending") return false;
      // The RPC owner accounts for real requests, partial input and publisher
      // tails. Idle internal FIN/EOF handshakes cannot prolong management
      // admission after those business obligations have ended.
      if (businessOnly && (this.#rpcHandles.includes(binding.handle) || this.#notifyHandles.includes(binding.handle))) continue;
      if (phase === "live" && (!binding.sendDrained || !binding.receiveDrained ||
          !binding.receiveAbandon && binding.direction?.state().stream_status !== "eof")) return false;
    }
    return true;
  }
  #driveDrain(): void {
    if (this.#closed || this.#drainWork !== undefined || this.#drain?.operation.status().outcome !== "pending") return;
    const work = Promise.resolve().then(async () => {
      this.#check(); const goaway = this.#localGoaway!;
      if (!goaway.sent) await this.#control(frameType("GOAWAY"), writer => writer.map(2).uint(0).uint(goaway.ceiling).uint(1).uint(0).result(), () => { goaway.sent = true; });
      const bootstrap = this.#bindings.get(BigInt(bootstrapSpec.scope));
      if (bootstrap !== undefined && bootstrap.handle === this.#bootstrap && !this.#open!.bootstrapBound(bootstrap.handle) &&
          this.#open!.phase(bootstrap.handle) === "live" && !bootstrap.resetRequested) this.#beginTermination(bootstrap, true);
      // Process a finite quantum of authenticated OPEN refusals. The existing
      // ingress and maintenance bounds continue to apply during Drain.
      for (let quantum = 0; quantum < 8; quantum++) {
        const handle = this.#open!.pendingPeer(); if (handle === undefined) break;
        while (!this.output.available()) await this.#wait(this.#drainDeadline!);
        this.#check();
        if (!this.#open!.canReject(handle)) break;
        if (this.#open!.phase(handle) === "peer_pending") await this.rejectOpen(handle, table<Record<string, number>>("open_rejection_codes")!.draining!);
      }
      this.#rpc?.drainChannels();
      this.#sealBusinessDrain();
      if (this.#communicationDrained() && this.output.available()) {
        // Existing communication proof is distinct from CLOSE I/O/cleanup.
        this.#drain!.finish("drained");
        await this.#control(frameType("CLOSE"), writer => writer.map(2).uint(0).uint(0).uint(1).uint(0).result());
        void this.close().catch(() => undefined);
      }
    });
    this.#drainWork = work;
    void work.then(() => { this.#drainWork = undefined; this.#cleanup(); }, () => {
      this.#drainWork = undefined; this.#drain?.finish("failed"); void this.close().catch(() => undefined); this.#cleanup();
    });
  }
  #sealBusinessDrain(): boolean {
    if (!this.#draining) return false;
    if (!this.#businessDrained && this.#communicationDrained(true)) {
      // Management entry and its store/publication guards repeat this same
      // synchronous gate, so polling cannot leave a new control admission
      // window after the original business frontier has ended.
      this.#businessDrained = true; this.#managementStopped = true;
      this.#rpc?.finishBusinessDrain();
      const management = this.#managementHandle === undefined ? undefined :
        this.#bindings.get(this.#open!.snapshot(this.#managementHandle).scope);
      if (management !== undefined && this.#open!.phase(management.handle) === "live" && !management.resetRequested)
        this.#beginTermination(management, true);
    }
    return this.#businessDrained;
  }
  start(capability: symbol, epoch: RecordEpoch, raw?: RawStreamPreparation): void {
    if (capability !== readyActivation || epoch !== this.epoch) fail("authentication_failed");
    if (this.#supervisor !== undefined || this.#closed) return;
    if (this.#bootstrap !== undefined) this.#open!.completeBootstrap(this.#bootstrap);
    this.#ready = true;
    if ((this.#info.selected_features & 1n) !== 0n) {
      if (this.config.transport.nativeDatagrams === undefined || this.config.unreliablePreparation === undefined) fail("configuration_capacity");
      this.#unreliable = new UnreliableRuntime(this.config.unreliablePreparation, this.config.transport.nativeDatagrams, {
        clock: this.config.clock, runtimeBytes: this.config.runtimeBytes, ledger: this.config.ledger, profile: this.config.ledger.profile,
        check: () => this.#check(), available: () => this.#ready && !this.#closed && !this.#draining && !this.#rekeyIntent && this.#rekeyRound === undefined,
        recordCheck: (frame, header, direction) => this.config.streams.authorization.check(frame, header, direction),
        dropped: epoch => this.#diagnostic({ code: epoch === "old" ? "old_datagram_dropped" : epoch === "future" ? "future_datagram_dropped" : "current_datagram_dropped" }, epoch === "old" ? "old_datagram_drop" : epoch === "future" ? "future_datagram_drop" : "current_datagram_drop"),
        changed: () => this.#wake(), failed: () => { void this.close().catch(() => undefined); },
      }, epoch, this.#epochNumber, this.#reservation!);
    } else this.config.unreliablePreparation?.close();
    if (raw !== undefined) this.installPreparedRawStreams(raw);
    this.#idle!.start();
    this.#check();
    this.#liveness!.start();
    const expiry = (): void => {
      try {
        this.#check(); const remaining = this.config.credentials?.remainingMS() ?? this.config.deadline.remainingMS();
        this.#authorizationTimer = setTimeout(expiry, timerChunk(remaining));
      } catch { this.config.streams.delivery.close("authorization_denied"); void this.close().catch(() => undefined); }
    };
    expiry();
    if (this.config.transport.nativeStreams !== undefined) {
      this.config.transport.nativeStreams.enable();
      this.#nativeAcceptor = this.#acceptNative();
      void this.#nativeAcceptor.then(() => { this.#nativeAcceptor = undefined; this.#cleanup(); }, error => {
        this.#nativeAcceptor = undefined; this.#observeControllerFailure(error); void this.close().catch(() => undefined); this.#cleanup();
      });
    }
    this.#unreliable?.start();
    this.#supervisor = (async () => {
      try { while (!this.#closed) {
        await this.receiveNext(); this.#wake();
        // Maintenance publication tails must not stop the original reader.
        // Peer INIT/COMMIT and the next authorized retirement batch can arrive
        // before a provider releases its previous output borrow.
        void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
      } }
      catch { void this.close().catch(() => undefined); }
    })();
    void this.#supervisor.then(() => { this.#supervisor = undefined; this.#cleanup(); });
    if (this.#bootstrap !== undefined) {
      this.#bootstrapDeadline = this.#deadline();
      const tick = (): void => {
        this.#bootstrapTimer = undefined;
        if (this.#closed || this.#bootstrapAbort.signal.aborted) return;
        try {
          this.#bootstrapDeadline!.check();
          this.#bootstrapTimer = setTimeout(tick, timerChunk(this.#bootstrapDeadline!.remainingMS()));
        } catch { this.#failSession("carrier_failed"); }
      };
      tick(); this.#driveBootstrap();
    }
    this.#driveRPCChannels(); this.#driveManagement(); this.#driveNotify(); this.#wake();
  }
  #rpcKey(position: number): "bootstrap" | `rpc_${number}` { return position === 0 ? "bootstrap" : `rpc_${position}`; }
  #receiveFloor(channel: Parameters<SessionKeyPreparation["exchangeReceive"]>[0]): ProtectedResourceReservation[] {
    if (channel === "management") return this.#managementPositions;
    if (channel === "notify_0" || channel === "notify_1") return this.#notifyPositions[channel === "notify_0" ? 0 : 1]!;
    return this.#rpcPositions[channel === "bootstrap" ? 0 : Number(channel.slice(4))]!;
  }
  #assignInternalReceive(binding: ReceiveBinding, from: Parameters<SessionKeyPreparation["exchangeReceive"]>[0]): boolean {
    const kind = this.#open!.kind(binding.handle);
    let to: Parameters<SessionKeyPreparation["exchangeReceive"]>[0], rpc = -1;
    if (kind === managementSpec.kind && this.#info.application_profile === "execution" && this.#sendDirection === 1) to = "management";
    else if (kind === notifySpec.kind && this.#rpc !== undefined) to = `notify_${this.#receiveDirection}`;
    else if (kind === bootstrapSpec.kind && this.#rpc !== undefined) {
      const start = this.#receiveDirection * 4;
      for (let position = start; position < start + 4; position++) if (this.#rpcHandles[position] === undefined && this.#rpcTasks[position] === undefined &&
          (this.#rpcKey(position) === from || this.#rpcPositions[position]!.slice(0, 2).every(slot => slot.available()) &&
            this.#internalKeys!.available(this.#rpcKey(position), "receive"))) { rpc = position; break; }
      if (rpc < 0) return false; to = this.#rpcKey(rpc);
    } else return false;
    if (from !== to) {
      const original = this.#receiveFloor(from), replacement = this.#receiveFloor(to);
      if (original?.length !== 10 || replacement?.length !== 10 || !replacement.slice(0, 2).every(slot => slot.available()) || !this.#internalKeys!.available(to, "receive")) return false;
      this.#internalKeys!.exchangeReceive(from, to);
      for (let index = 0; index < 2; index++) { const previous = original[index]!; original[index] = replacement[index]!; replacement[index] = previous; }
      if (from === "management" || to === "management") this.#managementReceivePositions.splice(0, 2, ...this.#managementPositions.slice(0, 2));
    }
    if (rpc >= 0) binding.rpcPosition = rpc;
    return true;
  }
  #rpcResourcesAvailable(position: number, incoming = false): boolean {
    const slots = this.#rpcPositions[position]!, key = this.#rpcKey(position);
    return slots.length === 10 && this.#internalKeys!.available(key, "send") &&
      (incoming || this.#internalKeys!.available(key, "receive")) &&
      slots.every((slot, index) => incoming && index < 2 || slot.available()) &&
      (incoming || this.#rpcNative[position] !== undefined || this.#rpcNativeRenewal[position] === undefined || this.#rpcNativeRenewal[position]!.available());
  }
  #releaseRPCInitialization(position: number): void {
    for (const ref of this.#rpcRefs[position]!) ref?.release(); this.#rpcRefs[position]!.length = 0;
    this.#rpcOutputs[position]?.release(); this.#rpcOutputs[position] = undefined;
    if (this.#closed) {
      for (const slot of this.#rpcPositions[position]!) slot.closeAfterUse();
      for (const ref of this.#rpcNative[position]?.references ?? []) ref.release(); this.#rpcNative[position] = undefined;
    }
  }
  #startRPCChannel(position: number, deadline: TrustedDeadline, incoming?: OpenHandle, signal?: AbortSignal): Promise<void> {
    this.#check();
    if (this.#rpc === undefined || this.#rpcTasks[position] !== undefined || !this.#rpc.channelReusable(position) ||
        !this.#rpcResourcesAvailable(position, incoming !== undefined)) throw new ResourceError("resource_exhausted");
    if (incoming !== undefined) this.#rpcHandles[position] = incoming;
    const cancellation = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal]);
    const slots = this.#rpcPositions[position]!;
    const task = Promise.resolve().then(async () => {
      deadline.check(); this.#check();
      if (cancellation.aborted || this.#draining || this.#goaway !== undefined) throw new Error("session_draining");
      for (let index = 0; index < slots.length; index++) if (index !== 8 && !(incoming !== undefined && index < 2))
        this.#rpcRefs[position]![index] = slots[index]!.checkout();
      if (incoming === undefined && this.#rpcNative[position] === undefined && this.#rpcNativeRenewal[position] !== undefined)
        this.#rpcNative[position] = this.#rpcNativeRenewal[position]!.checkout();
      while (this.#rekeyRound !== undefined || !this.#applicationOutputAvailable() || !this.output.available()) await this.#wait(deadline, cancellation, slots[8]);
      if (incoming === undefined) {
        this.#rpcHandles[position] = await this.submitOpen(bootstrapSpec.kind, empty, { signal: cancellation }, undefined, false, undefined, undefined, position);
        while (this.#open!.phase(this.#rpcHandles[position]!) === "local_opening") await this.#wait(deadline, cancellation, slots[8]);
        if (this.#open!.phase(this.#rpcHandles[position]!) !== "live") throw new Error("rpc_channel_unavailable");
      } else {
        const kind = new Uint8Array(128), metadata = new Uint8Array(4096), offer = this.#open!.copyOffer(incoming, kind, metadata);
        if (offer.metadataBytes !== 0 || this.#open!.peerLimit(incoming) < 16384n) throw new Error("rpc_channel_binding");
        await this.acceptOpen(incoming, { signal: cancellation }, undefined, undefined, undefined, false, undefined, undefined, position);
      }
      deadline.check(); this.#check(); if (cancellation.aborted) throw new Error("canceled");
      this.#rpc!.bindChannel(this.#stream(this.#rpcHandles[position]!), position);
    }).catch(error => {
      this.#rpcStopped[position] = true;
      if (!this.#closed) {
        const handle = this.#rpcHandles[position], binding = handle === undefined ? undefined : this.#bindings.get(this.#open!.snapshot(handle).scope);
        if (binding !== undefined) {
          if (this.#open!.phase(handle!) === "peer_pending") binding.rejectionPending = 2;
          else if (this.#open!.phase(handle!) === "live") this.#beginTermination(binding, true);
        }
      }
      throw error;
    }).finally(() => { this.#releaseRPCInitialization(position); this.#rpcTasks[position] = undefined; this.#wake(); });
    this.#rpcTasks[position] = task; return task;
  }
  /** Trusted SDK demand creates one shared channel; no application request or
   * retry is sent. The caller bounds establishment, while the Session owns the
   * accepted reader/publisher and their eventual physical cleanup. */
  openRPCChannel(channelClass: "interactive" | "bulk", options?: OperationOptions): Promise<void> {
    this.#check();
    if (!this.#ready || this.#rpc === undefined || !this.#rpc.bound || this.#draining || this.#goaway !== undefined ||
        channelClass !== "interactive" && channelClass !== "bulk") throw new Error("rpc_channel_unavailable");
    const start = this.#sendDirection * 4 + (channelClass === "bulk" ? 2 : 0);
    for (let position = start; position < start + 2; position++) if (this.#rpcHandles[position] === undefined &&
        this.#rpcTasks[position] === undefined && this.#rpc.channelReusable(position) && this.#rpcResourcesAvailable(position)) {
      this.#rpcStopped[position] = false; return this.#startRPCChannel(position, this.#deadline(), undefined, options?.signal);
    }
    throw new ResourceError("resource_exhausted");
  }
  #driveRPCChannels(): void {
    if (!this.#ready || this.#closed || this.#rpc === undefined || this.#rpcDriving) return;
    this.#rpcDriving = true;
    try {
      for (let position = 0; position < 8; position++) {
        if (this.#rpcTasks[position] !== undefined || this.#rpc.channelReady(position)) continue;
        const handle = this.#rpcHandles[position]; if (handle === undefined) continue;
        // Scope one remains the original initializer until its real prefix is
        // bound. A transient lack of writability cannot create a second path.
        if (position === 0 && handle === this.#bootstrap && (this.#bootstrapBinding || !this.#rpc.bound && !this.#bootstrapAbort.signal.aborted)) continue;
        const state = this.#open!.snapshot(handle), binding = this.#bindings.get(state.scope);
        if (state.phase === "live" && binding !== undefined && !binding.resetRequested && !this.#rpc.channelGracefullyEnded(position)) this.#beginTermination(binding, true);
        if (state.phase !== "stable" || binding !== undefined || !this.#rpc.channelReusable(position)) continue;
        this.#rpcHandles[position] = undefined;
      }
      if (this.#draining || this.#goaway !== undefined) return;
      for (const handle of this.#open!.pendingPeers()) {
        if (this.#open!.kind(handle) !== bootstrapSpec.kind || this.#rpcHandles.includes(handle)) continue;
        const binding = this.#bindings.get(this.#open!.snapshot(handle).scope); if (binding?.rejectionPending !== undefined) continue;
        const start = this.#receiveDirection * 4;
        let selected = -1;
        for (let position = start; position < start + 4; position++) if ((binding?.rpcPosition === undefined || binding.rpcPosition === position) && this.#rpcHandles[position] === undefined && this.#rpcTasks[position] === undefined &&
            this.#rpc.channelReusable(position) && this.#rpcResourcesAvailable(position, true)) { selected = position; break; }
        if (selected < 0) { if (binding !== undefined) binding.rejectionPending = 2; continue; }
        void this.#startRPCChannel(selected, this.#deadline(), handle).catch(() => undefined);
      }
      // Repair belongs to the original Session initializer. Existing messages
      // remain terminated on their original channel and are never replayed.
      if (this.#rpc.bound && !this.#rpc.channelsReady() && !this.#rpcTasks.some(Boolean)) {
        const start = this.#sendDirection * 4;
        for (let position = start; position < start + 2; position++) if (this.#rpcHandles[position] === undefined && !this.#rpcStopped[position] &&
            this.#rpc.channelReusable(position) && this.#rpcResourcesAvailable(position)) {
          void this.#startRPCChannel(position, this.#deadline()).catch(() => undefined); break;
        }
      }
    } finally { this.#rpcDriving = false; }
  }
  #releaseNotifyInitialization(position: 0 | 1): void {
    for (const ref of this.#notifyRefs[position]!) ref?.release(); this.#notifyRefs[position]!.length = 0;
    this.#notifyOutputs[position]?.release(); this.#notifyOutputs[position] = undefined;
    if (this.#closed) for (const entry of this.#notifyPositions[position]!) entry.closeAfterUse();
  }
  #driveNotify(): void {
    if (!this.#ready || this.#closed || this.#draining || this.#goaway !== undefined || this.#rpc === undefined || !this.#rpc.bound) return;
    for (const position of [0, 1] as const) {
      if (this.#notifyTasks[position] !== undefined) continue;
      const incoming = position === this.#sendDirection ? undefined : this.#open!.pendingPeers().find(handle => this.#open!.kind(handle) === notifySpec.kind && this.#bindings.get(this.#open!.snapshot(handle).scope)?.rejectionPending === undefined);
      if (this.#notifyHandles[position] !== undefined || this.#notifyStopped[position]) {
        if (incoming !== undefined && incoming !== this.#notifyHandles[position]) { this.#bindings.get(this.#open!.snapshot(incoming).scope)!.rejectionPending = 2; this.#driveRejections(); }
        continue;
      }
      if (position === this.#sendDirection ? !this.#notifyDemand : incoming === undefined) continue;
      const deadline = this.#deadline(30000n), positions = this.#notifyPositions[position]!;
      const task = Promise.resolve().then(async () => {
        if (incoming !== undefined) this.#notifyHandles[position] = incoming;
        deadline.check(); this.#check();
        // Keep one complete fixed vector for both opener directions. The
        // accept path still uses only its direction-specific key slice, while
        // the channel adapter and publication owner need the same indices on
        // either side of the authenticated OPEN.
        for (let index = 0; index < positions.length; index++) if (index !== 8 && !(incoming !== undefined && index < 2)) this.#notifyRefs[position]![index] = positions[index]!.checkout();
        while (this.#rekeyRound !== undefined || !this.#applicationOutputAvailable() || !this.output.available()) await this.#wait(deadline, this.#abort.signal, positions[8]);
        if (incoming === undefined) {
          this.#notifyHandles[position] = await this.submitOpen(notifySpec.kind, empty, undefined, undefined, false, position);
          while (this.#open!.phase(this.#notifyHandles[position]!) === "local_opening") await this.#wait(deadline, this.#abort.signal, positions[8]);
          if (this.#open!.phase(this.#notifyHandles[position]!) !== "live") throw new Error("notify_unavailable");
        } else {
          const kind = new Uint8Array(128), metadata = new Uint8Array(4096), offer = this.#open!.copyOffer(incoming, kind, metadata);
          if (offer.metadataBytes !== 0 || this.#open!.peerLimit(incoming) < 16384n) throw new Error("notify_binding");
          await this.acceptOpen(incoming, undefined, undefined, undefined, undefined, false, position);
        }
        deadline.check(); this.#check(); this.#rpc!.bindNotify(this.#stream(this.#notifyHandles[position]!), position);
      }).catch(() => {
        this.#notifyStopped[position] = true;
        if (!this.#closed) {
          const handle = this.#notifyHandles[position], binding = handle === undefined ? undefined : this.#bindings.get(this.#open!.snapshot(handle).scope);
          if (binding !== undefined) { if (this.#open!.phase(handle!) === "peer_pending") binding.rejectionPending = 2; else if (this.#open!.phase(handle!) === "live") this.#beginTermination(binding, true); }
        }
      }).finally(() => { this.#releaseNotifyInitialization(position); this.#notifyTasks[position] = undefined; this.#wake(); });
      this.#notifyTasks[position] = task;
    }
  }
  #releaseManagementInitialization(): void {
    for (const reference of this.#managementRefs) reference?.release(); this.#managementRefs.length = 0;
    for (const reference of this.#managementNative?.references ?? []) reference.release(); this.#managementNative = undefined;
    this.#managementOutput?.release(); this.#managementOutput = undefined;
    if (this.#closed) for (const position of this.#managementPositions) position.closeAfterUse();
  }
  #managementResourcesAvailable(): boolean {
    return this.#internalKeys!.available("management", "send") && (this.#sendDirection === 1 || this.#internalKeys!.available("management", "receive")) && this.#managementPositions.every((position, index) => index === 8 || this.#sendDirection === 1 && index < 2 || position.available()) &&
      (this.#managementNative !== undefined || this.#managementNativeRenewal === undefined || this.#managementNativeRenewal.available());
  }
  #checkoutManagementInitialization(): void {
    if (!this.#managementResourcesAvailable()) throw new ResourceError("resource_exhausted");
    // Server receive keys already belong to the authenticated peer OPEN. The
    // reusable fallback positions remain borrowed by that exact direction.
    for (let index = 0; index < this.#managementPositions.length; index++) {
      if (index === 8 || this.#sendDirection === 1 && index < 2) continue;
      this.#managementRefs[index] = this.#managementPositions[index]!.checkout();
    }
    if (this.#managementNative === undefined && this.#managementNativeRenewal !== undefined) this.#managementNative = this.#managementNativeRenewal.checkout();
  }
  #driveManagement(): void {
    if (!this.#ready || this.#closed || this.#info.application_profile !== "execution" || this.#managementTask !== undefined || this.#managementDriving) return;
    this.#managementDriving = true;
    try {
      if (this.#rpc!.managementReady()) return;
      const previous = this.#managementHandle;
      if (previous !== undefined) {
        if (!this.#managementStopped && !this.#draining) this.#managementDeadline ??= this.#deadline(30000n);
        const snapshot = this.#open!.snapshot(previous), binding = this.#bindings.get(snapshot.scope);
        if (snapshot.phase === "live" && binding !== undefined && !binding.resetRequested) this.#beginTermination(binding, true);
        if (snapshot.phase === "peer_pending" && binding !== undefined) { binding.rejectionPending = 1; this.#driveRejections(); }
        // Never detach an opening owner after timeout or reuse a recent proof.
        // An eventual accept is terminated above before any new generation.
        if (snapshot.phase !== "stable" || binding !== undefined) return;
        this.#managementHandle = undefined;
      }
      if (this.#managementStopped || this.#draining || this.#goaway !== undefined) return;
      if (this.#open!.managementAllocations() >= 16n) { this.#managementStopped = true; this.#rpc!.managementFailed(); return; }
      if (!this.#rpc!.managementReusable() || !this.#managementResourcesAvailable()) return;
      let incoming: OpenHandle | undefined;
      if (this.#sendDirection === 1) {
        incoming = this.#open!.pendingPeers().find(handle => this.#open!.kind(handle) === managementSpec.kind && this.#bindings.get(this.#open!.snapshot(handle).scope)?.rejectionPending === undefined);
        if (incoming === undefined) return;
      }
      const original = incoming;
      this.#managementDeadline ??= this.#deadline(30000n);
      const deadline = this.#managementDeadline;
      const task = Promise.resolve().then(async () => {
        if (original !== undefined) this.#managementHandle = original;
        deadline.check(); this.#check(); this.#checkoutManagementInitialization(); this.#rpc!.prepareManagement();
        // Rekey preparation alone is not a second OPEN gate. The actual
        // ticket freeze and publication position decide this bounded wait.
        while (this.#rekeyRound !== undefined || !this.#applicationOutputAvailable() || !this.output.available()) await this.#wait(deadline, this.#abort.signal, this.#managementWaitPosition);
        this.#check(); if (this.#draining || this.#goaway !== undefined) throw new Error("session_draining");
        if (original === undefined) {
          this.#managementHandle = await this.submitOpen(managementSpec.kind, empty, undefined, undefined, true);
          while (this.#open!.phase(this.#managementHandle) === "local_opening") await this.#wait(deadline, this.#abort.signal, this.#managementWaitPosition);
          if (this.#open!.phase(this.#managementHandle) !== "live") throw new Error("management_unavailable");
        } else {
          this.#managementHandle = original;
          const kind = new Uint8Array(128), metadata = new Uint8Array(4096), offer = this.#open!.copyOffer(original, kind, metadata);
          if (offer.metadataBytes !== 0 || this.#open!.peerLimit(original) !== 16384n) { await this.rejectOpen(original, 2); throw new Error("management_binding"); }
          await this.acceptOpen(original, undefined, undefined, undefined, undefined, true);
        }
        deadline.check(); this.#check(); this.#rpc!.bindManagement(this.#stream(this.#managementHandle!));
        this.#managementDeadline = undefined;
      }).catch(() => {
        if (!this.#closed) {
          try { deadline.check(); } catch { this.#managementStopped = true; }
          // A failure before any allocation is not an unbounded retry source.
          if (this.#managementHandle === undefined) this.#managementStopped = true;
        }
        this.#rpc?.managementFailed();
      }).finally(() => {
        this.#releaseManagementInitialization(); this.#managementTask = undefined;
        if (!this.#closed) this.#driveManagement(); this.#cleanup();
      });
      this.#managementTask = task;
    } catch { this.#managementStopped = true; this.#rpc?.managementFailed(); }
    finally { this.#managementDriving = false; }
  }
  #nativeReservations(): NativeProtocolPosition {
    this.#check(); return this.#nativePositions!.checkout();
  }
  #prepareBootstrap(): void {
    const streams = this.config.streams, profile = this.#info.application_profile;
    if (profile === "transport") fail("configuration_capacity");
    const costs = sessionBootstrapCharges(profile, this.config.maxFrame, this.config.runtimeBytes, streams.receive);
    if (streams.bootstrapReservations?.length !== costs.length || streams.bootstrapSendAccount === undefined ||
        this.#nativeScheduler !== undefined && this.#sendDirection === 0 && streams.bootstrapNativePosition === undefined) fail("configuration_capacity");
    const refs: ResourceReference[] = [];
    try { for (const position of this.#rpcPositions[0]!) refs.push(position.checkout()); }
    catch (error) { for (const ref of refs) ref.release(); throw error; }
    for (const ref of refs) if (!ref.sameEnvironment(this.#reservation!)) fail("configuration_capacity");
    this.#bootstrapPosition = this.#rpcNative[0]; this.#rpcNative[0] = undefined;
    const handle = this.#open!.prepareBootstrap(profile), scope = this.#open!.snapshot(handle).scope;
    this.#bootstrap = this.#rpcHandles[0] = handle;
    let receiveKeys: DirectionKeyPositions | undefined, sendKeys: DirectionKeyPositions | undefined, cipher: RecordCipher | undefined;
    let installed = false;
    try {
      this.#bootstrapReservation = refs[8]!.take(costs[8]!);
      this.#bootstrapOutput = refs[9]!.take(costs[9]!);
      receiveKeys = new DirectionKeyPositions(streams.root, this.#cipherConfig(this.#receiveDirection), refs.slice(0, 2), this.config.ledger, scope, this.#receiveDirection, this.#rpcPositions[0]!.slice(0, 2), this.#internalKeys!.checkout("bootstrap", "receive"));
      sendKeys = new DirectionKeyPositions(streams.root, this.#cipherConfig(this.#sendDirection), refs.slice(2, 4), this.config.ledger, scope, this.#sendDirection, this.#rpcPositions[0]!.slice(2, 4), this.#internalKeys!.checkout("bootstrap", "send"));
      cipher = this.#cipher(handle, this.#receiveDirection, receiveKeys);
      const binding: ReceiveBinding = { handle, receiveKeys, sendKeys, cipher, sendAccount: streams.bootstrapSendAccount,
        nextReceive: 0n, nextSend: 0n, sentOffset: 0n, acknowledged: 0n, sendLimit: BigInt(bootstrapSpec.initial_receive_limit),
        sendDrained: false, receiveDrained: false, stopPending: false, receiveAbandon: false, retiring: false, quarantined: false, sendFIN: false };
      this.#bindings.set(scope, binding); installed = true;
      binding.terminationReservation = refs[4]!.take(costs[4]!);
      binding.send = this.#cipher(handle, this.#sendDirection, sendKeys);
      binding.direction = this.#prepareDirection(binding, refs.slice(5, 8));
      binding.ackCommittedOffset = 0n; binding.ackCommittedLimit = BigInt(bootstrapSpec.initial_receive_limit);
    } catch (error) {
      if (!installed) { cipher?.close(); receiveKeys?.close(); sendKeys?.close(); }
      throw error;
    } finally { for (const ref of refs) ref.release(); }
  }
  #finishBootstrapInitialization(): void {
    if (this.#bootstrapTimer !== undefined) clearTimeout(this.#bootstrapTimer);
    this.#bootstrapTimer = undefined; this.#bootstrapDeadline = undefined;
    this.#bootstrapOutput?.release(); this.#bootstrapOutput = undefined;
    this.#bootstrapReservation?.release(); this.#bootstrapReservation = undefined;
    for (const reference of this.#bootstrapPosition?.references ?? []) reference.release();
    this.#bootstrapPosition = undefined;
  }
  #cancelBootstrapInitialization(): void {
    this.#bootstrapAbort.abort(); this.#finishBootstrapInitialization();
  }
  #driveBootstrap(): void {
    if (!this.#ready || this.#closed || this.#bootstrap === undefined || this.#bootstrapTask !== undefined ||
        this.#bootstrapAbort.signal.aborted) return;
    const binding = this.#bindings.get(BigInt(bootstrapSpec.scope));
    if (binding === undefined || this.#open!.phase(binding.handle) !== "live") return;
    if (this.#open!.bootstrapBound(binding.handle)) {
      this.#finishBootstrapInitialization();
      if (this.#rpc !== undefined && !this.#rpc.bound && !this.#draining) {
        this.#bootstrapBinding = true;
        try { this.#rpc.bindBootstrap(this.#stream(binding.handle)); }
        finally { this.#bootstrapBinding = false; }
      }
      return;
    }
    if (this.#bootstrapDeadline === undefined) return;
    if (this.#sendDirection !== 0) return;
    if (binding.sendSealed || binding.stopPending || binding.terminalSend !== undefined || this.#draining) {
      this.#cancelBootstrapInitialization(); return;
    }
    if (this.#rekeyIntent || this.#rekeyRound !== undefined || !this.#applicationOutputAvailable(binding.native)) return;
    // One initializer task owns the original native creation. Wakeups during
    // rekey resume this owner; neither a new scope nor a second handle is made.
    const task = Promise.resolve().then(async () => {
      this.#check();
      if (this.#bootstrapAbort.signal.aborted || this.#rekeyIntent || this.#rekeyRound !== undefined) return;
      if (this.#nativeScheduler !== undefined && binding.native === undefined) {
        const position = this.#bootstrapPosition; this.#bootstrapPosition = undefined;
        if (position === undefined) fail("configuration_capacity");
        const native = await this.#openNative({ signal: this.#bootstrapAbort.signal }, position);
        if (this.#closed || this.#bootstrapAbort.signal.aborted || binding.sendSealed || binding.stopPending ||
            binding.terminalSend !== undefined || this.#open!.phase(binding.handle) !== "live") { native.close(); return; }
        binding.native = native; native.scope = BigInt(bootstrapSpec.scope);
        native.bounds = new StreamDataBounds(native.scope, this.#receiveDirection, this.config.ledger.profile, this.config.maxFrame);
        native.reader.bindData(native.bounds);
      }
      if (this.#rekeyIntent || this.#rekeyRound !== undefined || !this.#applicationOutputAvailable(binding.native)) return;
      this.#bootstrapDeadline!.check();
      let ticket = false;
      try {
        const completion = this.#encodeApplication(binding.native, storage => {
          const body = this.#open!.encodeBootstrap(binding.handle, storage);
          return (binding.native?.output ?? this.output).record(binding.send!, frameType("OPEN_STREAM"), body, () => {
            this.#open!.submittedBootstrap(binding.handle); binding.native?.outcome();
          }, () => { ticket = true; binding.nextSend = 1n; });
        });
        if (binding.native !== undefined) this.#startNativeRead(binding.native);
        await completion;
        this.#finishBootstrapInitialization();
      } catch (error) {
        // A prefix crypto ticket is irrevocable even if the provider fails.
        if (ticket || !(error instanceof ResourceError) || error.code !== "resource_exhausted") throw error;
        this.#resourceFailure(true); throw error;
      }
    });
    this.#bootstrapTask = task;
    void task.then(() => {
      this.#bootstrapTask = undefined;
      if (!this.#closed) this.#terminal(binding);
      this.#wake();
    }, () => {
      this.#bootstrapTask = undefined;
      if (!this.#closed && !this.#bootstrapAbort.signal.aborted) this.#failSession("carrier_failed");
      if (!this.#closed) this.#terminal(binding);
      this.#wake();
    });
  }
  /** SDK-only default channel. The same RuntimeStream owns its sole reader;
   * callers cannot treat logical READY creation as physical writability. */
  bootstrapStream(): V4StreamOwner | undefined {
    this.#check(); const handle = this.#bootstrap;
    if (handle === undefined || this.#draining || this.#bootstrapAbort.signal.aborted) return undefined;
    const binding = this.#bindings.get(BigInt(bootstrapSpec.scope));
    if (binding === undefined || this.#open!.phase(handle) !== "live" || !this.#open!.bootstrapBound(handle) ||
        binding.sendSealed || binding.stopPending || binding.terminalSend !== undefined) return undefined;
    return this.#stream(handle);
  }
  #allocateNativeOutput(association: NativeAssociation, position: NativeProtocolPosition, bytes: number): ResourceReference {
    this.#check();
    const binding = association.scope === undefined ? undefined : this.#bindings.get(association.scope);
    if (binding === undefined || binding.native !== association) fail("protocol_violation");
    const rpc = this.#rpcHandles.indexOf(binding.handle);
    if (rpc >= 0 && this.#rpcOutputs[rpc] !== undefined) {
      if (bytes > 4480 + envelopePrefixBytes + recordHeaderBytes + 16) fail("configuration_capacity");
      const reference = this.#rpcOutputs[rpc]!; this.#rpcOutputs[rpc] = undefined; return reference;
    }
    const notify = this.#notifyHandles.indexOf(binding.handle);
    if (notify >= 0 && this.#notifyOutputs[notify] !== undefined) {
      if (bytes > 4480 + envelopePrefixBytes + recordHeaderBytes + 16) fail("configuration_capacity");
      const reference = this.#notifyOutputs[notify]!; this.#notifyOutputs[notify] = undefined; return reference;
    }
    if (binding.handle === this.#managementHandle && this.#managementOutput !== undefined) {
      if (bytes > 4480 + envelopePrefixBytes + recordHeaderBytes + 16) fail("configuration_capacity");
      const reference = this.#managementOutput; this.#managementOutput = undefined; return reference;
    }
    if (binding.handle === this.#bootstrap && !this.#open!.bootstrapBound(binding.handle) && this.#bootstrapOutput !== undefined) {
      if (bytes > 4480 + envelopePrefixBytes + recordHeaderBytes + 16) fail("configuration_capacity");
      const reference = this.#bootstrapOutput; this.#bootstrapOutput = undefined; return reference;
    }
    try {
      return position.output.checkoutBytes(BigInt(bytes), [...this.config.streams.accounts, this.#sendAccount!, this.#directionSendAccount(binding)]);
    } catch (error) { this.#diagnostic({ code: "resource_exhausted" }, "resource_rejection"); this.#liveness?.localStall(); throw error; }
  }
  #attachNative(transport: V4NativeApplicationStream, position: NativeProtocolPosition): NativeAssociation {
    this.#check();
    if (transport.mode !== "stream" || transport.role !== this.config.transport.role || transport.origin === "maintenance" ||
      [...this.#nativeAssociations].some(value => value.transport === transport) ||
      this.#nativeAssociations.size >= this.config.maxReceiveDirections + this.config.streams.limits.ingressItems + 1) fail("protocol_violation");
    const association = new NativeAssociation(transport, { maxFrame: this.config.maxFrame, outputFrame: this.#nativeOutputFrame(),
      profile: this.config.ledger.profile, runtimeBytes: this.config.runtimeBytes }, position.references, () => {
      association.cleanup();
      if (association.cleanupComplete()) this.#nativeAssociations.delete(association);
      try {
        if (association.scope !== undefined) {
          const binding = this.#bindings.get(association.scope);
          if (binding !== undefined) { this.#nativeOutputFailed(binding); this.#terminal(binding); }
        }
      } catch { void this.close().catch(() => undefined); }
      if (!this.#closed) void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
      this.#wake(); this.#cleanup();
    }, (type, payload) => this.#nativePrefix(association, type, payload), bytes => this.#allocateNativeOutput(association, position, bytes), this.#nativeScheduler!.candidates.enabled
      ? { pool: this.#nativeScheduler!.candidates, preview: () => this.#nativePrefetch(association) } : undefined);
    association.output.observeFailure(error => {
      if (originalNativeConnectionFailure(error)) this.#observeControllerFailure(error);
    });
    association.output.observeRecords(() => this.#idle!.activity(), () => undefined);
    this.#nativeAssociations.add(association); return association;
  }
  #nativePrefix(association: NativeAssociation, type: number, payload: number): NativeFramePromise | undefined {
    if (association.scope === undefined) {
      // OPEN has its own bounded metadata schema, never a DATA promise.
      if (type !== frameType("OPEN_STREAM") || payload > 4480) fail("protocol_violation");
      return;
    }
    const binding = this.#bindings.get(association.scope);
    if (binding === undefined || type !== frameType("STREAM_DATA")) fail("protocol_violation");
    const phase = this.#open!.phase(binding.handle);
    if (phase !== "live" && phase !== "local_opening") fail("protocol_violation");
    const progress = binding.direction!.progress(), final = binding.terminalReceive?.offset ?? progress.receive_limit;
    if (final < progress.ack_offset || final > progress.receive_limit) fail("protocol_violation");
    association.bounds ??= new StreamDataBounds(association.scope, this.#receiveDirection, this.config.ledger.profile, this.config.maxFrame);
    if (payload + envelopePrefixBytes > association.bounds.maximumEnvelope(final - progress.ack_offset)) fail("protocol_violation");
    return { direction: binding.direction!, bounds: association.bounds, remaining: final - progress.ack_offset };
  }
  #nativePrefetch(association: NativeAssociation): NativeFramePromise | undefined {
    if (this.#closed || this.#rekeyIntent || this.#rekeyRound !== undefined || association.readFailed || association.abort.signal.aborted || association.scope === undefined) return;
    const binding = this.#bindings.get(association.scope);
    if (binding?.direction === undefined || association.bounds === undefined || binding.receiveAbandon || binding.receiveDrained ||
        binding.terminalReceive !== undefined || binding.receiveTermination !== undefined || this.#open!.phase(binding.handle) !== "live") return;
    const progress = binding.direction.progress();
    if (progress.fin_offset !== undefined || progress.ack_offset > progress.receive_limit) return;
    return { direction: binding.direction, bounds: association.bounds, remaining: progress.receive_limit - progress.ack_offset };
  }
  async #openNative(options?: OperationOptions, prepaid?: NativeProtocolPosition): Promise<NativeAssociation> {
    const position = prepaid ?? this.#nativeReservations(), deadline = this.#deadline(), abort = new AbortController();
    const signal = AbortSignal.any(options?.signal === undefined ? [abort.signal, this.#abort.signal] : [abort.signal, this.#abort.signal, options.signal]);
    let timer: ReturnType<typeof setTimeout> | undefined, transport: V4NativeApplicationStream | undefined;
    try {
      const tick = (): void => {
        try { deadline.check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
        catch { abort.abort(); }
      };
      tick(); if (signal.aborted) fail("closed");
      transport = await this.config.transport.nativeStreams!.open({ signal });
      deadline.check(); this.#check(); if (signal.aborted || transport.origin !== "local") fail("closed");
      const association = this.#attachNative(transport, position); transport = undefined;
      association.watchOpen(deadline, () => { void this.close().catch(() => undefined); }); return association;
    } finally { if (timer !== undefined) clearTimeout(timer); if (transport !== undefined) void transport.close().catch(() => undefined); for (const ref of position.references) ref.release(); }
  }
  async #acceptNative(): Promise<void> {
    while (!this.#closed) {
      // Assembly positions are reserved before entering native accept. Native
      // input cannot allocate a second decoder behind a blocked application.
      this.#nativeScheduler!.capacityAttempt();
      while (this.#nativeAssociations.size >= this.config.maxReceiveDirections + this.config.streams.limits.ingressItems + 1 ||
          [...this.#nativeAssociations].filter(value => value.transport.origin === "peer" && value.scope === undefined).length >= this.config.streams.limits.ingressItems) {
        await this.#nativeScheduler!.waitCapacity(this.config.deadline, this.#abort.signal);
        this.#nativeScheduler!.capacityAttempt();
      }
      let position: NativeProtocolPosition;
      try { position = this.#nativeReservations(); }
      catch (error) {
        if (!(error instanceof ResourceError) || error.code !== "resource_exhausted") throw error;
        await this.#nativeScheduler!.waitCapacity(this.config.deadline, this.#abort.signal); continue;
      }
      let transport: V4NativeApplicationStream | undefined;
      try {
        this.#nativeScheduler!.capacityAttempt();
        try { transport = await this.config.transport.nativeStreams!.accept({ signal: this.#abort.signal }); }
        catch (error) {
          if (!this.#closed && !this.#abort.signal.aborted) observeNativeConnectionFailure(error); throw error;
        }
        this.#check(); if (transport.origin !== "peer") fail("protocol_violation");
        const association = this.#attachNative(transport, position);
        association.watchOpen(this.#deadline(), () => { void this.close().catch(() => undefined); });
        this.#startNativeRead(association); transport = undefined;
      } catch (error) {
        if (!(error instanceof ResourceError) || error.code !== "resource_exhausted") throw error;
        // Keep the preadmitted parser positions while a provider position is
        // unavailable; releasing our own reservation would wake this waiter.
        await this.#nativeScheduler!.waitCapacity(this.config.deadline, this.#abort.signal);
      } finally { if (transport !== undefined) void transport.close().catch(() => undefined); for (const ref of position.references) ref.release(); }
    }
  }
  #startNativeRead(association: NativeAssociation): void {
    if (association.readTask !== undefined) fail("configuration_capacity");
    association.readTask = this.#readNative(association);
    const finished = (): void => {
      association.readTask = undefined; association.reader.close(); association.cleanup();
      if (association.cleanupComplete()) this.#nativeAssociations.delete(association);
      if (association.scope !== undefined) {
        const binding = this.#bindings.get(association.scope);
        if (binding !== undefined) this.#terminal(binding);
      }
      if (!this.#closed) void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
      this.#wake(); this.#cleanup();
    };
    void association.readTask.then(finished, error => { this.#observeControllerFailure(error); finished(); if (!this.#closed) void this.close().catch(() => undefined); });
  }
  async #readNative(association: NativeAssociation): Promise<void> {
    const signal = AbortSignal.any([this.#abort.signal, association.abort.signal]);
    try {
      while (!this.#closed) {
        const binding = association.scope === undefined ? undefined : this.#bindings.get(association.scope);
        // An authenticated OPEN has already advanced its barrier frontier.
        // Waiting for outcome here holds only bounded association metadata.
        while (binding !== undefined && ["local_opening", "peer_pending"].includes(this.#open!.phase(binding.handle))) await association.wait(this.config.deadline, signal);
        if (binding !== undefined && this.#open!.phase(binding.handle) === "rejected") return;
        const candidate = await association.reader.next({ signal });
        if (candidate === null) { association.inputEnded = true; this.#nativeInputEnded(association); return; }
        let granted = false;
        let frame: EnvelopeFrame | undefined;
        try {
          const header = candidate.header;
          // A peer which has completed rekey can publish on this stream before
          // its maintenance marker arrives. Hold one candidate under the
          // original round, without key derivation or an authentication slot.
          while (header.epoch === this.#epochNumber + 1 && this.#rekeyRound !== undefined && this.#candidate !== undefined &&
              this.#sendSwitched && (this.#sendDirection === 0 || this.#receiveSwitched)) {
            await association.wait(this.#rekeyDeadline!, signal);
          }
          await this.#nativeScheduler!.acquire(association); granted = true;
          if (signal.aborted) return;
          frame = this.#nativeScheduler!.frame(association, candidate.segments);
          // DATA retains its original claim through complete schema/credit
          // validation. OPEN has no receive promise and returns staging before
          // the authenticated binding replaces its fixed header storage.
          if (candidate.header.frameType === frameType("OPEN_STREAM")) candidate.release();
          await this.#receiveFrame(frame, association);
        } finally { frame?.release(); candidate.release(); if (granted) this.#nativeScheduler!.release(association); }
        if (association.readFailed) return;
      }
    } catch (error) {
      if (this.#closed || association.abort.signal.aborted) return;
      const binding = association.scope === undefined ? undefined : this.#bindings.get(association.scope);
      if (error instanceof NativeDirectionFailure && error.code === "normal_drained" && association.reader.atFrameBoundary() && binding !== undefined &&
          this.#open!.phase(binding.handle) === "local_opening") { association.inputEnded = true; return; }
      if (!this.#isolateNativeInput(association)) throw error;
    }
  }
  #nativeOutputFailed(binding: ReceiveBinding): boolean {
    const failure = binding.native?.writeFailure;
    if (this.#closed || failure === undefined) return false;
    const phase = this.#open!.phase(binding.handle);
    if (phase === "local_opening") {
      if (failure.code !== "normal_drained") { void this.close().catch(() => undefined); return false; }
      return true;
    }
    if (phase === "rejected" || phase === "recent" || binding.sendDrained) return true;
    if (phase !== "live" || binding.terminationReservation === undefined) return false;
    binding.stopPending = true;
    this.#beginTermination(binding, false);
    if (failure.code !== "normal_drained" && binding.sendTermination !== undefined) this.#enterQuarantine(binding, binding.sendTermination, true);
    return true;
  }
  #isolateNativeInput(association: NativeAssociation): boolean {
    if (this.#closed) return false;
    const binding = association.scope === undefined ? undefined : this.#bindings.get(association.scope);
    if (binding !== undefined && this.#open!.phase(binding.handle) === "rejected") return true;
    if (binding === undefined || this.#open!.phase(binding.handle) !== "live" || binding.terminationReservation === undefined ||
        binding.native !== association || this.#open!.isBootstrap(binding.handle) && !this.#open!.bootstrapBound(binding.handle)) return false;
    if (binding.receiveDrained) { association.readFailed = true; return true; }
    association.readFailed = true; binding.quarantined = true; binding.receiveAbandon = true;
    // A provider may retire both physical halves before the authenticated
    // termination record can be published. Preserve the logical send
    // termination: STOPPED and the eventual DRAINED proof still travel on
    // the maintenance channel, while no FIN is attempted on the retired
    // native stream.
    if (association.transport.cleanupComplete()) {
      binding.stopPending = true; binding.sendSealed = true; binding.write?.terminate();
      binding.sendTermination ??= this.#newTermination(binding);
    }
    binding.direction?.abandonDelivery(); binding.cipher.close();
    association.reader.close(); void association.transport.stopSending().catch(() => undefined);
    this.#beginTermination(binding, false, true, true); return true;
  }
  #nativeInputEnded(association: NativeAssociation): void {
    const binding = association.scope === undefined ? undefined : this.#bindings.get(association.scope);
    if (binding === undefined) fail("protocol_violation");
    const phase = this.#open!.phase(binding.handle);
    // Physical hints do not accept/reject an opening operation or refund its
    // original credit. Its admission deadline remains active until the ACK.
    if (phase === "local_opening" || phase === "peer_pending" || phase === "rejected") return;
    if (binding.terminalReceive === undefined) this.#isolateNativeInput(association);
  }
  #deadline(duration = this.config.streams.operationDeadlineMS): TrustedDeadline {
    return this.config.deadline.forkAgeAt(this.config.deadline.sample(), duration);
  }
  #armSafetyRekey(): void {
    if (this.#rekeySafetyTimer !== undefined) { clearTimeout(this.#rekeySafetyTimer); this.#rekeySafetyTimer = undefined; }
    if (this.#closed || !this.#ready) return;
    try {
      const original = this.epoch, age = original.rekeySafetySnapshot(), window = age.rootMaxAgeMS / 5n;
      if (this.#rekeySafetyDeadline === undefined && !age.rootAgeLimited) return;
      const remaining = this.#rekeySafetyDeadline?.remainingMS() ?? age.remainingMS - (window === 0n ? 1n : window);
      if (remaining <= 0n) { this.#scheduleSafetyRekey(); return; }
      this.#rekeySafetyTimer = setTimeout(() => {
        if (this.epoch !== original || this.#closed) return;
        this.#rekeySafetyTimer = undefined; this.#wake();
      }, timerChunk(remaining));
    } catch { this.#failSession("time_unavailable"); }
  }
  #scheduleSafetyRekey(): void {
    if (this.#closed || !this.#ready) return;
    const original = this.epoch;
    try {
      const age = original.rekeySafetySnapshot(), rootWindow = age.rootMaxAgeMS / 5n;
      if (this.#rekeySafetyDeadline === undefined && !age.triggered &&
          (!age.rootAgeLimited || age.remainingMS > (rootWindow === 0n ? 1n : rootWindow))) return;
      // A safety cause belongs to this exact root and survives a canceled
      // manual waiter. Joining can only tighten the shared round's deadline.
      this.#rekeySafetyDeadline ??= original.safetyDeadline();
      this.#rekeySafetyDeadline.check();
      this.#rekeyDeadline?.tightenFrom(this.#rekeySafetyDeadline);
      this.#rekeyPhaseDeadline?.tightenFrom(this.#rekeySafetyDeadline);
      if (this.#rekeyDeadline !== undefined) this.#armRekey();
    } catch (error) { this.#diagnosticRekeyFailure(error); this.#failSession("time_unavailable"); return; }
    if (this.#rekeyIntent || this.#rekeyRound !== undefined || this.#autoRekeyQueued) return;
    this.#autoRekeyQueued = true;
    queueMicrotask(() => {
      this.#autoRekeyQueued = false;
      if (this.#closed || this.epoch !== original || this.#rekeyIntent || this.#rekeyRound !== undefined) return;
      void this.rekey().catch(() => { if (!this.#closed && this.epoch === original) void this.close().catch(() => undefined); });
    });
  }
  #wake(): void {
    for (const wake of this.#waiters) wake();
    for (const association of this.#nativeAssociations) association.wake();
    if (this.#closed) { this.#cleanup(); return; }
    if (!this.#ready) return;
    try {
      this.#driveBootstrap();
      this.#driveRPCChannels();
      this.#driveManagement();
      this.#driveNotify();
      this.#driveDrain();
      this.#driveRejections();
    } catch {
      // Authorization revocation can race a queued dispatch wake. The binding
      // callback already closed delivery; retire the Session without allowing
      // a stale credential error to escape the scheduler task.
      this.config.streams.delivery.close("authorization_denied");
      void this.close().catch(() => undefined);
      return;
    }
    this.#scheduleDispatch();
    this.#scheduleSafetyRekey();
    this.#armSafetyRekey();
    this.#liveness?.wake();
    if (!this.#closed && this.#rekeyRound !== undefined && !this.#rekeyWorking && this.output.available()) {
      void this.#progressRekey().catch(() => undefined);
    }
  }
  registerMessageStream<A, B>(definition: V4MessageStreamDefinition<A, B>, authorize: V4StreamOpenAuthorizer | undefined,
    handler: V4MessageStreamHandler<A, B>, options: V4StreamRegistrationOptions): V4StreamRegistration {
    messageDefinition(definition);
    return this.#registerStream(definition.kind, definition, authorize, handler as V4MessageStreamHandler<unknown, unknown>, options);
  }
  registerStream(kind: string, authorize: V4StreamOpenAuthorizer | undefined, handler: V4RawStreamHandler, options: V4StreamRegistrationOptions): V4StreamRegistration {
    checkRawStreamKind(kind);
    return this.#registerStream(kind, undefined, authorize, handler, options);
  }
  installPreparedRawStreams(preparation: RawStreamPreparation): void {
    this.#check(); if (this.#application !== undefined) throw new Error("already_registered");
    this.#application = preparation.takeGroup(this.#reservation!);
    for (let entry = preparation.takeRegistration(); entry !== undefined; entry = preparation.takeRegistration()) {
      const { kind, authorize, handler } = entry.takeDeclaration();
      try { this.#registerStream(kind, undefined, authorize, handler, undefined, entry); }
      catch (error) { entry.close(); throw error; }
    }
  }
  #registerStream(kind: string, definition: object | undefined, authorize: V4StreamOpenAuthorizer | undefined, handler: RegisteredHandler, options: V4StreamRegistrationOptions | undefined, preparation?: PreparedRawRegistration): V4StreamRegistration {
    this.#check(); if (preparation === undefined && options === undefined) throw new Error("configuration_capacity");
    const captured = preparation?.options ?? captureRegistration(options!);
    if (definition !== undefined && captured.metadataContract !== undefined) throw new Error("metadata_contract");
    if (captured.resume !== undefined && (definition !== undefined || this.#rpc === undefined)) throw new Error("resume_binding");
    if (this.#draining || this.#accepting || this.#streamRegistrations.has(kind) || this.#rpc?.hasStreamingKind(kind)) throw new Error("already_registered");
    if (this.#registrationOwners.size >= 128 || typeof handler !== "function" || authorize !== undefined && typeof authorize !== "function") throw new Error("invalid_handler");
    this.#applicationService(definition !== undefined);
    if (this.config.credentials === undefined) throw new Error("authentication_failed");
    if (this.#messageCandidates === (1n << 64n) - 1n) fail("configuration_capacity"); const id = ++this.#messageCandidates;
    const ref = preparation?.takeReference(this.#reservation!, this.config.runtimeBytes) ?? this.#reserve(id, ["v4_stream_registration"], [streamRegistrationCharge(captured, this.config.runtimeBytes)])[0]!;
    const { root, accounts, owner } = this.config.streams;
    const host = new RegistrationHost(this.config.clock, this.config.runtimeBytes, root, accounts, owner, id);
    const registration = new StreamRegistrationState(kind, captured, ref, host, definition, authorize, handler, preparation);
    host.attach(
      () => { if (this.#streamRegistrations.get(kind) === registration) this.#streamRegistrations.delete(kind); this.#scheduleDispatch(); },
      () => { if (registration.cleanupStatus().status === "complete") this.#registrationOwners.delete(registration); this.#scheduleDispatch(); this.#cleanup(); },
    );
    this.#streamRegistrations.set(kind, registration); this.#registrationOwners.add(registration); this.#scheduleDispatch();
    return streamRegistration(registration);
  }
  #applicationService(completion: boolean): ApplicationGroup {
    this.#check();
    if (this.#application === undefined) {
      const { root, accounts, owner } = this.config.streams;
      this.#application = applicationGroup(root, accounts, { ...owner, kind: "v4_application" }, this.config.runtimeBytes, completion);
    } else if (completion) this.#application.executor.enableCompletion();
    return this.#application;
  }
  #scheduleDispatch(): void {
    if (this.#dispatchQueued || this.#closed || this.#draining || this.#streamRegistrations.size === 0 && !this.#rpc?.hasStreamingHandlers()) return;
    this.#dispatchQueued = true;
    queueMicrotask(() => {
      this.#dispatchQueued = false;
      if (this.#closed) { this.#cleanup(); return; }
      if (this.#draining) return;
      try {
        for (const handle of this.#open!.pendingPeers()) {
          const binding = this.#bindings.get(this.#open!.snapshot(handle).scope);
          if ([managementSpec.kind as string, bootstrapSpec.kind, notifySpec.kind].includes(this.#open!.kind(handle)) || this.#dispatching.has(handle) || binding?.rejectionPending !== undefined) continue;
          if (this.#rpc?.hasStreamingKind(this.#open!.kind(handle))) {
            this.#dispatching.add(handle); void this.#dispatchRPCStream(handle); continue;
          }
          const registration = this.#streamRegistrations.get(this.#open!.kind(handle));
          if (registration === undefined || registration.closed || registration.authorizing >= registration.options.maxAuthorizing ||
              registration.active + registration.authorizing >= registration.options.maxActive) {
            if (binding !== undefined) binding.rejectionPending = 2;
            this.#driveRejections(); continue;
          }
          if (!this.#open!.reserveAuthorization(handle, 0)) {
            if (binding !== undefined) binding.rejectionPending = 1;
            this.#driveRejections(); continue;
          }
          this.#dispatching.add(handle); registration.authorizing++;
          void this.#dispatchStream(handle, registration);
        }
      } catch { if (!this.#closed) this.#failSession("closed"); }
    });
  }
  /** One prepaid maintenance publisher. Exhausted proof capacity leaves an
   * authenticated pending owner intact while the reader services retirement. */
  #driveRejections(): void {
    if (this.#closed || this.#rejecting || !this.output.available()) return;
    for (const binding of this.#bindings.values()) {
      const reason = binding.rejectionPending;
      if (reason === undefined || !this.#open!.canReject(binding.handle)) continue;
      this.#rejecting = true;
      void this.rejectOpen(binding.handle, reason).finally(() => {
        this.#rejecting = false; this.#wake();
      }).catch(() => undefined);
      return;
    }
  }
  async #rejectRegisteredOpen(handle: OpenHandle): Promise<void> {
    try {
      if (this.#closed || this.#open!.phase(handle) !== "peer_pending") return;
      const binding = this.#bindings.get(this.#open!.snapshot(handle).scope);
      if (binding !== undefined) binding.rejectionPending = 2;
      this.#driveRejections();
    } catch { /* The original Session retains any unfinished proof obligation. */ }
    finally { this.#dispatching.delete(handle); this.#cleanup(); }
  }
  async #dispatchStream(handle: OpenHandle, registration: StreamRegistrationState): Promise<void> {
    if (this.#messageCandidates === (1n << 64n) - 1n) { registration.authorizing--; await this.#rejectRegisteredOpen(handle); return; }
    const id = ++this.#messageCandidates, job = new RegisteredStreamJob(registration, this.cleanupOwner);
    const { definition, authorize, handler } = registration;
    let adapter: ResourceReference | undefined, stream: V4StreamOwner | V4TypedMessageStream<unknown, unknown> | undefined;
    let incomingOpen: StreamOpenPreparation | undefined, initial: PreparedRawInvocation | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined, permit: ApplicationPermit | undefined;
    let recovery: ReturnType<RPCApplicationAdmission["prepareIncomingResume"]> | undefined;
    let unbindRecovery: (() => void) | undefined;
    let rejection: Promise<void> | undefined;
    const rejectPending = (): Promise<void> => rejection ??= (async () => {
      if (job.accepted || this.#closed) return;
      try {
        const deadline = this.#deadline();
        while (!this.output.available()) await this.#wait(deadline);
        if (!job.accepted && this.#open!.phase(handle) === "peer_pending") await this.rejectOpen(handle, 2);
      } catch { /* The original pending/proof owner survives failed publication. */ }
    })();
    const aborted = (): void => { if (job.accepted) { if (stream !== undefined) void stream.close().catch(() => undefined); }
      else void rejectPending(); };
    job.abort.signal.addEventListener("abort", aborted, { once: true });
    const stop = (): void => { job.abort.abort(); };
    this.#abort.signal.addEventListener("abort", stop, { once: true });
    try {
      const charge = streamHandlerCharge(registration.options, this.config.runtimeBytes);
      initial = registration.preparation?.takeInvocation();
      job.own(initial?.work.take(charge) ?? this.#reserve(id, ["v4_stream_handler"], [charge])[0]!);
      const deadline = this.#deadline(registration.options.applicationTimeoutMS);
      const check = (): void => {
        this.#check(); deadline.check(); job.check();
        if (job.abort.signal.aborted || !job.accepted && (this.#draining || registration.closed || this.#streamRegistrations.get(registration.kind) !== registration)) throw new Error("closed");
      };
      const tick = (): void => {
        try { check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
        catch { timer = undefined; job.abort.abort(); }
      }; tick(); check();
      const auth = this.config.credentials!.applicationContext(this.#sendDirection === 0 ? "client" : "server");
      let metadata: StreamMetadata, candidate: V4TypedMessageStream<unknown, unknown> | undefined;
      if (definition !== undefined) {
        adapter = this.#reserve(id, ["v4_message_handler_candidate"], [messageAdapterCharge(this.config.runtimeBytes)])[0]!;
        candidate = prepareTypedMessages(definition, registration.options);
        const kind = new Uint8Array(128), bytes = new Uint8Array(4096), lengths = this.copyOpenOffer(handle, kind, bytes);
        prepareMessageBinding(candidate, { kind: registration.kind, localOpener: false, metadata: byteSlice(bytes, 0, lengths.metadataBytes), runtimeBytes: this.config.runtimeBytes,
          reserve: (name, charge) => this.#reserve(id, [name], [charge])[0]! });
        metadata = candidate.metadata;
      } else {
        const doc = this.#open!.metadataDocument(handle);
        try { if (doc !== undefined && doc.text(doc.field(0, 0)) === "flowersec/typed-message") throw new Error("definition_mismatch"); metadata = streamMetadataFromDocument(doc); }
        finally { doc?.release(); }
        if (registration.options.metadataContract !== undefined) metadata = applyRawStreamMetadataContract(metadata, registration.options.metadataContract);
      }
      if (metadata.namespace !== "" && !registration.options.namespaces.some(value => value.namespace === metadata.namespace && value.version === metadata.version)) throw new Error("metadata_denied");
      const application = this.#application!;
      if (authorize !== undefined) {
        permit = initial?.authorize?.checkout() ?? await application.acquire("short", job.abort.signal, check);
        check(); const invocation = application.context(permit, auth, job.abort.signal); permit = undefined;
        if (await observeTask(job.invoke(invocation, authorize, [invocation.context, metadata]), job.abort.signal) !== true) throw new Error("open_denied");
      }
      if (registration.options.resume !== undefined) {
        const target = registration.options.resume;
        recovery = this.#rpc!.prepareIncomingResume(registration.kind, target.namespace, target.method);
      }
      // Acquire the accepted Stream's complete direction/termination vector
      // before taking the application permit. The reservation is consumed by
      // the same OPEN_ACCEPT gate below and is released only after the real
      // stream owner has taken over or the pending OPEN is rejected.
      incomingOpen = initial?.open ?? this.#prepareIncomingOpen(this.#open!.snapshot(handle).scope);
      // Handler admission is real before accepted. No application code runs
      // while waiting for ACK publication; a late callback cannot release it.
      permit = initial?.handler.checkout() ?? await application.acquire(registration.options.workClass, job.abort.signal, check);
      check(); while (!this.output.available()) { await this.#wait(deadline, job.abort.signal, incomingOpen.wait); check(); }
      await this.acceptOpen(handle, { signal: job.abort.signal }, check, () => {
        job.accept();
      }, prepared => {
        if (candidate !== undefined) { bindTypedMessages(candidate, prepared, registration.options, adapter!, true); stream = candidate; }
        else stream = prepared;
      }, false, undefined, incomingOpen);
      check();
      let recovered: ResumeCodecTypes.ResumeOutcome | undefined;
      if (recovery !== undefined) {
        recovery.attach(stream as V4StreamOwner, this);
        permit.release(); permit = undefined;
        const result = await recovery.run(deadline, job.abort.signal);
        if (!result.dispatch) return; recovered = result.outcome;
        permit = await application.acquire(registration.options.workClass, job.abort.signal, check); check();
      }
      const invocation = application.context(permit, auth, job.abort.signal); permit = undefined;
      if (recovered?.status === "accepted") unbindRecovery = bindRecoveryProgress(invocation.context, Object.freeze({ checkpoint: recovered.checkpoint!, generation: recovered.generation! }));
      const actual = candidate !== undefined
        ? job.invoke(invocation, handler as V4MessageStreamHandler<unknown, unknown>, [candidate, invocation.context, metadata])
        : job.invoke(invocation, handler as V4RawStreamHandler, [stream as V4StreamOwner, invocation.context, metadata]);
      const unbind = unbindRecovery; unbindRecovery = undefined;
      await observeTask(actual.finally(() => unbind?.()), job.abort.signal);
      await stream!.finish({ signal: job.abort.signal });
    } catch {
      if (!job.accepted) await rejectPending();
    } finally {
      unbindRecovery?.(); recovery?.close(); incomingOpen?.close(); initial?.close();
      if (timer !== undefined) clearTimeout(timer); this.#abort.signal.removeEventListener("abort", stop);
      job.abort.signal.removeEventListener("abort", aborted); permit?.release();
      if (rejection !== undefined) await rejection;
      if (job.accepted && stream === undefined && !this.#closed) { try { await this.closeStream(handle); } catch { /* Retain the original termination owner. */ } }
      if (stream !== undefined) { try { await stream.close({ signal: job.abort.signal }); } catch { /* Protocol cleanup remains with its original Stream. */ } }
      this.#dispatching.delete(handle); adapter?.release(); job.finishWorkflow();
      this.#scheduleDispatch(); this.#cleanup();
    }
  }
  #wait(deadline: TrustedDeadline, signal?: AbortSignal, prepaid?: ProtectedResourceReservation): Promise<void> {
    this.#check(); deadline.check(); if (signal?.aborted) return Promise.reject(new Error("canceled"));
    if (this.#waiters.size >= 3 * this.config.maxReceiveDirections + this.config.streams.limits.ingressItems + 1) fail("configuration_capacity");
    const id = ++this.#nextWait, charge = new ResourceVector([this.config.runtimeBytes, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 1n, 0n]), ref = prepaid?.checkout() ?? this.#reserve(id, ["v4_wait"], [charge])[0]!;
    return new Promise<void>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined, settled = false;
      const finish = (): void => {
        if (settled) return; settled = true; this.#waiters.delete(finish);
        if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", finish); ref.release();
        try { this.#check(); deadline.check(); if (signal?.aborted) throw new Error("canceled"); resolve(); } catch (error) { reject(error); }
      };
      this.#waiters.add(finish); signal?.addEventListener("abort", finish, { once: true });
      timer = setTimeout(finish, timerChunk(deadline.remainingMS()));
      if (signal?.aborted || this.#closed) finish();
    });
  }
  async #dispatchRPCStream(handle: OpenHandle): Promise<void> {
    let candidate: ReturnType<RPCApplicationAdmission["prepareIncomingStream"]> | undefined;
    const kind = new Uint8Array(128), metadata = new Uint8Array(4096);
    try {
      const sizes = this.copyOpenOffer(handle, kind, metadata);
      candidate = this.#rpc!.prepareIncomingStream(new TextDecoder().decode(kind.subarray(0, sizes.kindBytes)), metadata.subarray(0, sizes.metadataBytes));
      while (!this.output.available()) await this.#wait(this.config.deadline);
      await this.acceptOpen(handle, undefined, undefined, undefined, stream => { this.#dedicatedRPCStreams.add(handle); candidate!.attach(stream); });
      candidate.start(); candidate = undefined;
    } catch {
      candidate?.close();
      if (!this.#closed && this.#open?.phase(handle) === "peer_pending") {
        try { await this.rejectOpen(handle, 2); } catch { /* Original rejection/Session owner retains its tail. */ }
      }
    } finally { kind.fill(0); metadata.fill(0); this.#dispatching.delete(handle); this.#scheduleDispatch(); this.#cleanup(); }
  }
  async #openRPCStream(kind: string, metadata: Uint8Array, deadline: TrustedDeadline, signal: AbortSignal,
    prepare: (stream: V4StreamOwner) => void, prepaid?: StreamOpenPreparation): Promise<void> {
    this.#check(); let handle: OpenHandle | undefined;
    try {
      while (this.#rekeyRound !== undefined || (this.#nativeSend === undefined ? !this.output.available() : !this.#nativeSend.available())) await this.#wait(deadline, signal, prepaid?.wait);
      deadline.check(); if (signal.aborted) throw new Error("canceled");
      handle = await this.submitOpen(kind, metadata, { signal }, (stream, preparedHandle) => {
        this.#dedicatedRPCStreams.add(preparedHandle); prepare(stream);
      }, false, undefined, prepaid);
      while (this.#open!.snapshot(handle).phase === "local_opening") await this.#wait(deadline, signal, prepaid?.wait);
      if (this.#open!.snapshot(handle).phase !== "live") throw new Error("open_rejected");
      deadline.check(); if (signal.aborted) throw new Error("canceled");
    } catch (error) {
      if (handle !== undefined && !this.#closed) void this.closeStream(handle).catch(() => undefined);
      throw error;
    } finally { prepaid?.close(); }
  }
  async openStream(kind: string, options?: OperationOptions & Readonly<{ metadata?: StreamMetadata }>): Promise<V4StreamOwner> {
    this.#check(); const deadline = this.#deadline();
    if (this.#draining || this.#goaway !== undefined) fail("session_draining");
    const metadata = options?.metadata === undefined ? empty : streamMetadataBytes(options.metadata);
    if (byteLength(metadata) > 4096) fail("configuration_capacity");
    let handle: OpenHandle | undefined;
    try {
      while (this.#nativeSend === undefined ? !this.output.available() : !this.#nativeSend.available()) await this.#wait(deadline, options?.signal);
      handle = await this.submitOpen(kind, metadata, options);
      while (this.#open!.snapshot(handle).phase === "local_opening") await this.#wait(deadline, options?.signal);
      if (this.#open!.snapshot(handle).phase !== "live") throw new Error("open_rejected");
      return this.#stream(handle);
    } catch (error) { if (handle !== undefined && !this.#closed && this.#open?.snapshot(handle).phase === "local_opening") void this.close().catch(() => undefined); throw error; }
    finally { if (metadata !== empty) metadata.fill(0); }
  }
  async openMessageStream<A, B>(definition: V4MessageStreamDefinition<A, B>, options: OperationOptions & V4MessageStreamOptions & Readonly<{ metadata?: StreamMetadata }> = {}): Promise<V4TypedMessageStream<B, A>> {
    this.#check(); const fixed = captureMessageOptions(options); messageDefinition(definition);
    this.#applicationService(true);
    if (this.#draining || this.#goaway !== undefined) fail("session_draining");
    if (this.#messageCandidates === (1n << 64n) - 1n) fail("configuration_capacity");
    const candidateID = ++this.#messageCandidates;
    const reference = this.#reserve(candidateID, ["v4_message_candidate"], [messageAdapterCharge(this.config.runtimeBytes)])[0]!;
    let handle: OpenHandle | undefined, metadata: Uint8Array = empty;
    try {
      const candidate = prepareTypedMessages(definition, fixed);
      metadata = messageMetadata(definition, options.metadata);
      prepareMessageBinding(candidate, { kind: definition.kind, localOpener: true, metadata, runtimeBytes: this.config.runtimeBytes,
        reserve: (name, charge) => this.#reserve(candidateID, [name], [charge])[0]! });
      const deadline = this.#deadline();
      while (this.#nativeSend === undefined ? !this.output.available() : !this.#nativeSend.available()) await this.#wait(deadline, options.signal);
      handle = await this.submitOpen(definition.kind, metadata, options, prepared => bindTypedMessages(candidate, prepared, fixed, reference, true));
      while (this.#open!.snapshot(handle).phase === "local_opening") await this.#wait(deadline, options.signal);
      if (this.#open!.snapshot(handle).phase !== "live") throw new Error("open_rejected");
      return candidate as V4TypedMessageStream<B, A>;
    } catch (error) {
      if (handle !== undefined && !this.#closed) {
        if (this.#open!.phase(handle) === "live") void this.closeStream(handle).catch(() => undefined);
        else if (this.#open!.phase(handle) === "local_opening") void this.close().catch(() => undefined);
      }
      throw error;
    } finally { metadata.fill(0); reference.release(); }
  }
  async acceptMessageStream<A, B>(definition: V4MessageStreamDefinition<A, B>, options: OperationOptions & V4MessageStreamOptions = {}): Promise<V4TypedMessageStream<A, B>> {
    this.#check(); messageDefinition(definition); const fixed = captureMessageOptions(options);
    this.#applicationService(true);
    if (this.#draining) fail("session_draining"); if (this.#accepting || this.#streamRegistrations.size !== 0 || this.#dispatching.size !== 0) fail("busy"); this.#accepting = true;
    let reference: ResourceReference | undefined, handle: OpenHandle | undefined;
    try {
      const deadline = this.#deadline();
      while (true) {
        handle = this.pendingOpen();
        while (handle === undefined || !this.output.available()) { await this.#wait(deadline, options.signal); if (this.#draining) fail("session_draining"); handle = this.pendingOpen(); }
        let candidate: V4TypedMessageStream<unknown, unknown>;
        try {
          if (this.#messageCandidates === (1n << 64n) - 1n) fail("configuration_capacity");
          const candidateID = ++this.#messageCandidates;
          reference = this.#reserve(candidateID, ["v4_message_candidate"], [messageAdapterCharge(this.config.runtimeBytes)])[0]!;
          candidate = prepareTypedMessages(definition, fixed);
          const kind = new Uint8Array(128), metadata = new Uint8Array(4096), sizes = this.copyOpenOffer(handle, kind, metadata);
          if (new TextDecoder("utf-8", { fatal: true }).decode(byteSlice(kind, 0, sizes.kindBytes)) !== definition.kind) throw new Error("definition_mismatch");
          prepareMessageBinding(candidate, { kind: definition.kind, localOpener: false, metadata: byteSlice(metadata, 0, sizes.metadataBytes), runtimeBytes: this.config.runtimeBytes,
            reserve: (name, charge) => this.#reserve(candidateID, [name], [charge])[0]! });
        } catch {
          reference?.release(); reference = undefined; await this.rejectOpen(handle, 2); continue;
        }
        await this.acceptOpen(handle, options, undefined, undefined, prepared => bindTypedMessages(candidate, prepared, fixed, reference!, true));
        return candidate as V4TypedMessageStream<A, B>;
      }
    } catch (error) {
      if (handle !== undefined && !this.#closed && this.#open!.phase(handle) === "live") void this.closeStream(handle).catch(() => undefined);
      throw error;
    } finally { reference?.release(); this.#accepting = false; }
  }
  async acceptStream(options?: OperationOptions): ReturnType<V4SessionOwner["acceptStream"]> {
    this.#check(); if (this.#draining) fail("session_draining"); if (this.#accepting || this.#streamRegistrations.size !== 0 || this.#dispatching.size !== 0) fail("busy"); this.#accepting = true;
    const refs: ResourceReference[] = []; let kindBytes = empty, metadataBytes = empty;
    try {
      const deadline = this.#deadline();
      refs.push(...this.#reserve(0n, ["v4_accept_offer"], [new ResourceVector([8448n + this.config.runtimeBytes, 0n, 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n])]));
      kindBytes = new Uint8Array(128); metadataBytes = new Uint8Array(4096);
      while (true) {
        if (this.#draining) fail("session_draining");
        let handle = this.pendingOpen();
        while (handle === undefined || !this.output.available()) { await this.#wait(deadline, options?.signal); if (this.#draining) fail("session_draining"); handle = this.pendingOpen(); }
        const sizes = this.copyOpenOffer(handle, kindBytes, metadataBytes);
        const kind = new TextDecoder("utf-8", { fatal: true }).decode(byteSlice(kindBytes, 0, sizes.kindBytes));
        let metadata: StreamMetadata;
        try {
          const document = this.#open!.metadataDocument(handle);
          try {
            if (document !== undefined && document.text(document.field(0, 0)) === "flowersec/typed-message") throw new Error("typed_definition_required");
            metadata = streamMetadataFromDocument(document);
          }
          finally { document?.release(); }
        } catch { await this.rejectOpen(handle, 2); continue; }
        try { await this.acceptOpen(handle, options); }
        catch (error) {
          if (error instanceof OpenAdmissionError && error.code === "open_capacity") { await this.rejectOpen(handle, 1); continue; }
          throw error;
        }
        const result = { kind, metadata, stream: this.#stream(handle) }; Object.defineProperty(result, "then", { value: undefined });
        return Object.freeze(result);
      }
    } finally { kindBytes.fill(0); metadataBytes.fill(0); for (const ref of refs) ref.release(); this.#accepting = false; }
  }
  #stream(handle: OpenHandle): RuntimeStream {
    const scope = this.#open!.snapshot(handle).scope, binding = this.#bindings.get(scope)!;
    return binding.stream ??= new RuntimeStream(this, handle, this.acceptedReceive(handle));
  }
  claimAdapter(handle: OpenHandle, profile: StreamAdapterProfile, invalidate: () => void): Readonly<{ reservation: ResourceReference; readBytes: number; delivery: { check(): void; release(): void } }> {
    this.#check();
    const binding = this.#streamBinding(handle);
    const phase = this.#open!.phase(handle);
    if (phase !== "live" && !(profile.preaccepted === true && (phase === "peer_pending" || phase === "local_prepared") && binding.direction !== undefined) ||
        binding.write !== undefined || binding.sendSealed || binding.sendTermination !== undefined || binding.receiveTermination !== undefined) fail("busy");
    binding.direction!.checkAdapterClaim();
    const message = profile.kind === "message", sdkBacking = profile.kind === "web" || profile.kind === "bridge";
    if (message && (binding.sentOffset !== 0n || binding.direction!.progress().released_offset !== 0n)) fail("busy");
    const charge = new ResourceVector([
      BigInt(2 * profile.readBytes) + this.config.runtimeBytes + (message ? 17408n : 2048n) + BigInt(profile.inputEntries) * 128n + (sdkBacking ? BigInt(profile.inputBackingBytes) : 0n),
      message || sdkBacking ? 0n : BigInt(profile.inputBackingBytes), 0n, BigInt(profile.inputEntries + 4), 6n, 6n, message ? 4n : 2n, 0n, 0n, 1n, message ? 0n : profile.kind === "web" ? 2n : 1n,
    ]);
    if (profile.prepaid !== undefined && !profile.prepaid.sameEnvironment(this.#reservation!)) fail("configuration_capacity");
    const reservation = profile.prepaid?.take(charge) ?? this.#reserve(this.#open!.snapshot(handle).scope, ["v4_stream_adapter"], [charge], message ? undefined : this.#directionSendAccount(binding))[0]!;
    try {
      const delivery = this.config.streams.delivery.retain(reservation, invalidate);
      binding.adapterActive = true;
      binding.gracefulFinishMS = BigInt(profile.gracefulFinishMS);
      return { reservation, delivery, readBytes: Math.min(profile.readBytes, this.config.streams.receive.maxCursorBytes) };
    } catch (error) { reservation.release(); throw error; }
  }
  bridgeResultBacking(handle: OpenHandle, bytes: number, endpoint: "flowersec_stream" | "native_duplex"): ResourceReference {
    const scope = this.#open!.snapshot(handle).scope;
    // Each endpoint needs distinct original backing and a distinct resource
    // owner. ResourceReference.take() transfers an entire owner rather than
    // splitting its byte allowance; the two bridge directions coexist.
    return this.#reserve(scope, [endpoint === "native_duplex" ? "v4_native_bridge_result" : "v4_bridge_result"], [new ResourceVector([
      BigInt(bytes) + this.config.runtimeBytes + 512n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n,
    ])])[0]!;
  }
  messageAdapterContext(handle: OpenHandle, reservation: ResourceReference, prepaidApplication?: ApplicationGroup) {
    const snapshot = this.#open!.snapshot(handle), kind = new Uint8Array(128), metadata = new Uint8Array(4096);
    const sizes = this.#open!.copyOffer(handle, kind, metadata);
    let direction = this.#streamBinding(handle).direction;
    let sequence = 0n;
    const { root, accounts, owner, maxWriteBytes, writeDeadlineMS } = this.config.streams;
    const runtimeBytes = this.config.runtimeBytes, deadline = this.config.deadline;
    const sendAccounts = Object.freeze([...accounts, this.#sendAccount!, this.#directionSendAccount(this.#streamBinding(handle))]);
    const authentication = this.config.credentials?.applicationContext(this.#sendDirection === 0 ? "client" : "server");
    if (prepaidApplication !== undefined && !prepaidApplication.sameEnvironment(reservation)) fail("configuration_capacity");
    const application = prepaidApplication ?? applicationGroup(root, accounts, { ...owner, kind: `v4_message_app_${snapshot.scope.toString(16)}` }, runtimeBytes, true);
    return {
      application, authentication, sessionCleanup: this.cleanupOwner, diagnostics: this.config.diagnostics,
      direction: this.#sendDirection === 0 ? "c2s" as const : "s2c" as const,
      localOpener: snapshot.local, kind: new TextDecoder("utf-8", { fatal: true }).decode(byteSlice(kind, 0, sizes.kindBytes)),
      metadata: byteSlice(metadata, 0, sizes.metadataBytes), maxWriteBytes,
      maxWriteMilliseconds: writeDeadlineMS, runtimeBytes,
      reserve: (name: string, charge: ResourceVector) => {
        reservation.checkRetained();
        if (sequence === (1n << 64n) - 1n) fail("configuration_capacity");
        return root.reserve({ accounts, owner: { ...owner, kind: `${name}_${snapshot.scope.toString(16)}_${(++sequence).toString(16)}` }, charge });
      },
      reserveSend: (name: string, charge: ResourceVector) => {
        reservation.checkRetained();
        if (sequence === (1n << 64n) - 1n) fail("configuration_capacity");
        return root.reserve({ accounts: sendAccounts, owner: { ...owner, kind: `${name}_${snapshot.scope.toString(16)}_${(++sequence).toString(16)}` }, charge });
      },
      observeResources: (changed: () => void) => root.observeAvailability(reservation, changed),
      deadline: (milliseconds: bigint) => deadline.forkAgeAt(deadline.sample(), milliseconds),
      pauseCredit: (paused: boolean) => direction?.setAdapterCreditPaused(paused),
      releaseIO: () => { direction = undefined; },
    };
  }
  rollbackAdapter(handle: OpenHandle): void {
    if (!this.#closed) delete this.#streamBinding(handle).gracefulFinishMS;
  }
  releaseAdapter(handle: OpenHandle): void {
    const binding = this.#streamBinding(handle);
    delete binding.adapterActive;
    this.#terminal(binding);
  }
  detachMessageIO(handle: OpenHandle): void {
    const binding = this.#streamBinding(handle);
    if (!this.#physicalComplete(binding, false)) fail("busy");
    const result = Object.freeze({ ...this.#closeResult(binding), cleanup_status: complete });
    binding.stream?.detach(result, binding.sendFIN, binding.sentOffset, binding.acknowledged, binding.direction?.progress().released_offset ?? 0n);
    delete binding.stream; delete binding.adapterActive;
    this.#terminal(binding);
  }
  unreliableMessages(): V4UnreliableMessages { this.#check(); if (!this.#ready || this.#unreliable === undefined) throw new V4UnreliableMessageError("unavailable"); return this.#unreliable; }
  async rekey(options?: OperationOptions): Promise<void> {
    this.#check(); const original = this.#epochNumber, deadline = this.#deadline();
    if (options?.signal?.aborted) throw new Error("canceled");
    if (this.#rekeyIntent || this.#rekeyRound !== undefined) {
      while (this.#epochNumber === original) await this.#wait(deadline, options?.signal);
      return;
    }
    // Acquire the local intent before waiting for output, so no queued probe
    // can publish between client preparation/server REQUEST and peer INIT.
    this.#unreliable?.freeze(); this.#rekeyIntent = true; this.#beginDiagnosticRekey();
    if (this.#rekeySafetyTimer !== undefined) clearTimeout(this.#rekeySafetyTimer); this.#rekeySafetyTimer = undefined;
    this.#liveness!.beginRekey();
    if (this.#sendDirection === 1) {
      if (this.#rekeySafetyDeadline !== undefined) deadline.tightenFrom(this.#rekeySafetyDeadline);
      this.#rekeyDeadline = this.#rekeyPhaseDeadline = deadline; this.#armRekey();
      this.#rekeyRequest = this.#control(frameType("REKEY"), writer => writer.map(1).uint(0).uint(0).result());
      void this.#rekeyRequest.catch(() => { this.#failSession("carrier_failed"); });
      // The request's provider tail and response obligation outlive this wait.
      while (this.#epochNumber === original) await this.#wait(deadline, options?.signal);
      return;
    }
    try {
      while (!this.output.available()) await this.#wait(deadline, options?.signal);
      if (options?.signal?.aborted) throw new Error("canceled");
      this.#beginRekey();
    } catch (error) {
      if (this.#rekeyRound === undefined) {
        this.#diagnosticRekeyFailure(error);
        this.#rekeyIntent = false; this.#diagnosticRekeyStarted = undefined; this.#liveness!.endRekey(false);
        if (this.#rekeySafetyDeadline !== undefined) this.#scheduleSafetyRekey();
      }
      throw error;
    }
    try {
      const body = this.#rekeyRound!.buildInit(this.#localFrozen);
      const completion = this.output.record(this.#controlSend!, frameType("REKEY"), body, () => {
        this.#chargeRekey(); this.#rekeyStage = "init"; this.#phaseDeadline(this.config.streams.rekeyProtocolMS);
      });
      // Keep the actual tail with the round even if the manual wait cancels.
      void completion.then(() => {
        this.#wake(); void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
      }, () => this.#failSession("carrier_failed"));
    } catch (error) {
      void this.close().catch(() => undefined); throw error;
    }
    while (this.#epochNumber === original) await this.#wait(this.#rekeyDeadline!, options?.signal);
  }
  probeLiveness(options?: OperationOptions): Promise<V4LivenessResult> {
    if (this.#closed) return Promise.reject(new V4LivenessError("closed", { submitted: false, complete: false, elapsedMS: null }));
    return this.#liveness!.probe(options);
  }
  #reserve(scope: bigint, kinds: readonly string[], charges: readonly ResourceVector[], send?: ResourceAccount): ResourceReference[] {
    this.#check(); const { root, accounts: originalAccounts, owner } = this.config.streams;
    const accounts = send === undefined ? originalAccounts : [...originalAccounts, this.#sendAccount!, send];
    let references: ResourceReference[];
    try {
      references = root.reserveBatch(charges.map((charge, index) => ({ accounts, charge,
        owner: { tenant: owner.tenant, environment: owner.environment, backing: owner.backing, kind: `${kinds[index]}_${scope}` } })));
    } catch (error) { this.#liveness?.localStall(); throw error; }
    try { for (const ref of references) if (!this.#reservation!.sameEnvironment(ref)) fail("configuration_capacity"); return references; }
    catch (error) { for (const ref of references) ref.release(); throw error; }
  }
  #cipherConfig(direction: RecordDirection): RecordCipherConfig {
    if (this.#nativeScheduler === undefined) return this.config;
    return { maxFrame: direction === this.#receiveDirection ? this.config.maxFrame : this.#nativeOutputFrame(), runtimeBytes: this.config.runtimeBytes,
      workspace: direction === this.#receiveDirection ? this.#nativeScheduler.workspace : this.#nativeSend!.crypto };
  }
  #nativeOutputFrame(): number { return nativeOutputFrame(this.config.maxFrame, this.config.streams.receive.maxDataBytes); }
  #applicationOutputAvailable(native?: NativeAssociation): boolean {
    return (native?.output ?? this.output).available() && (native === undefined || this.#nativeSend!.available());
  }
  #encodeApplication<T>(native: NativeAssociation | undefined, action: (storage: Uint8Array) => T): T {
    if (native !== undefined) {
      try { return this.#nativeSend!.encode(action); }
      finally { this.#wake(); }
    }
    try { return action(this.#encode); }
    finally { this.#encode.fill(0); }
  }
  #cipher(handle: OpenHandle, direction: RecordDirection, positions: DirectionKeyPositions): RecordCipher {
    const scope = this.#open!.snapshot(handle).scope;
    const authorization: RecordAuthorization = { check: (frame, header, actualDirection) => {
      this.#check();
      if (header.scope !== scope || actualDirection !== direction) fail("protocol_violation");
      this.#open!.authorize(handle, frame, actualDirection);
      this.config.streams.authorization.check(frame, header, actualDirection);
      this.#checkBootstrapTicket(handle, frame, actualDirection);
    } };
    const reservation = positions.checkout();
    try { return this.epoch.derive(scope, direction, this.#cipherConfig(direction), authorization, reservation, positions.usage); }
    finally { reservation.release(); }
  }
  #checkBootstrapTicket(handle: OpenHandle, frame: number, direction: RecordDirection): void {
    if (handle !== this.#bootstrap || frame !== frameType("OPEN_STREAM")) return;
    // This pure owner check follows all clock/authorization callbacks, including
    // the checks immediately before and after actual crypto precharge.
    const binding = this.#bindings.get(BigInt(bootstrapSpec.scope));
    if (this.#closed || !this.#ready || binding?.handle !== handle || this.#open!.phase(handle) !== "live" ||
        this.#open!.bootstrapBound(handle)) fail("protocol_violation");
    if (direction === this.#sendDirection) {
      if (this.#bootstrapAbort.signal.aborted || binding.sendSealed || binding.stopPending || binding.terminalSend !== undefined ||
          this.#draining || this.#rekeyIntent || this.#rekeyRound !== undefined) fail("closed");
    } else if (binding.receiveDrained || binding.terminalReceive?.next === 0n) fail("protocol_violation");
  }
  #directionSendAccount(binding: ReceiveBinding): ResourceAccount {
    if (binding.sendAccount === undefined) fail("configuration_capacity");
    return binding.sendAccount;
  }
  #prepareDirection(binding: ReceiveBinding, prepaid?: readonly ResourceReference[]): ReliableReceiveDirection {
    const { root, delivery } = this.config.streams, scope = this.#open!.snapshot(binding.handle).scope;
    binding.sendAccount ??= this.#sendAccounts!.checkout();
    const rpc = this.#rpcHandles.indexOf(binding.handle);
    const original = this.#open!.isBootstrap(binding.handle) || rpc >= 0 || binding.handle === this.#managementHandle || this.#notifyHandles.includes(binding.handle) ? { ...this.config.streams.receive, receiveLimit: BigInt(bootstrapSpec.initial_receive_limit) } : this.config.streams.receive;
    const receive = this.#nativeScheduler === undefined ? original : { ...original, workspace: this.#nativeScheduler.receiveWorkspace };
    const references = prepaid ?? this.#reserve(scope, ["v4_receive", "v4_receive_decoder", "v4_cursor"],
      [receiveDirectionCharge(receive), receiveDecoderCharge(receive), receiveCursorCharge(receive)]);
    try {
      return new ReliableReceiveDirection(receive, binding.cipher, delivery, {
        root, direction: references[0]!, decoder: references[1]!, cursor: references[2]!,
        ...(binding.handle === this.#managementHandle ? { cursorPosition: this.#managementPositions[7]! } : {}),
        ...(this.#notifyHandles.includes(binding.handle) ? { cursorPosition: this.#notifyPositions[this.#notifyHandles.indexOf(binding.handle)]![7]! } : {}),
        ...(rpc < 0 ? {} : { cursorPosition: this.#rpcPositions[rpc]![7]! }),
      }, () => {
        if (!this.#closed) {
          this.#terminal(binding);
          if (!binding.receiveDrained) void this.acknowledgeReceive(binding.handle).catch(() => undefined);
        }
      }, () => { if (!this.#closed) this.#terminal(binding); });
    } finally { for (const ref of references) ref.release(); }
  }
  /** The local OPEN ticket owns the active/pending position and receive promise
   * before publication. The returned handle conveys submission, not acceptance. */
  async submitOpen(kind: string, metadata: Uint8Array, options?: OperationOptions, prepare?: (stream: V4StreamOwner, handle: OpenHandle) => void, management = false, notify?: 0 | 1, prepaid?: StreamOpenPreparation, rpc?: number): Promise<OpenHandle> {
    this.#check(); if (this.#draining || this.#goaway !== undefined) fail("session_draining"); if (this.#rekeyRound !== undefined || options?.signal?.aborted) fail("closed");
    if (this.#nativeSend === undefined ? !this.output.available() : !this.#nativeSend.available()) fail("busy");
    if (management && (kind !== managementSpec.kind || metadata.length !== 0 || this.#info.application_profile !== "execution" || this.#sendDirection !== 0 || this.#managementRefs.length === 0)) fail("configuration_capacity");
    const notifying = notify !== undefined, notificationRefs = notifying ? this.#notifyRefs[notify]! : undefined;
    const ordinary = rpc !== undefined, rpcRefs = ordinary ? this.#rpcRefs[rpc] : undefined;
    if (ordinary && (management || notifying || !Number.isSafeInteger(rpc) || Math.floor(rpc / 4) !== this.#sendDirection ||
        kind !== bootstrapSpec.kind || metadata.length !== 0 || this.#rpc === undefined || rpcRefs?.length !== 10)) fail("configuration_capacity");
    if (notifying && (management || notify !== this.#sendDirection || kind !== notifySpec.kind || metadata.length !== 0 || this.#info.application_profile === "transport" || notificationRefs?.length !== 10)) fail("configuration_capacity");
    if (!management && !notifying && !ordinary && (kind === managementSpec.kind || kind === bootstrapSpec.kind || kind === notifySpec.kind)) fail("configuration_capacity");
    const owner = this.#open!, initialLimit = management || notifying || ordinary ? 16384n : this.config.streams.receive.receiveLimit;
    const streamClass = management ? 2 : notifying || ordinary ? 1 : 0;
    const internalKind = management ? managementSpec.kind : notifying ? notifySpec.kind : ordinary ? bootstrapSpec.kind : kind;
    const handle = owner.prepareLocal(this.#epochNumber, streamClass, internalKind, metadata, initialLimit);
    if (notifying) this.#notifyHandles[notify] = handle;
    if (management) this.#managementHandle = handle;
    if (ordinary) this.#rpcHandles[rpc] = handle;
    const scope = owner.snapshot(handle).scope;
    let binding: ReceiveBinding | undefined, submitted = false, ticket = false;
    let receiveKeys: DirectionKeyPositions | undefined, sendKeys: DirectionKeyPositions | undefined;
    let native: NativeAssociation | undefined;
    const references: ResourceReference[] = [];
    let prepared: ReturnType<StreamOpenPreparation["take"]> | undefined;
    let preparedAccount: ResourceAccount | undefined, nativePrepared = false;
    try {
      prepared = prepaid?.take(this.#reservation!); preparedAccount = prepared?.account;
      if (prepared !== undefined && (management || notifying || ordinary || (prepared.native !== undefined) !== (this.#nativeScheduler !== undefined))) fail("configuration_capacity");
      if (this.#nativeScheduler !== undefined) {
        const position = management ? this.#managementNative : notifying ? this.#notifyNative : ordinary ? this.#rpcNative[rpc] : prepared?.native; if (management) this.#managementNative = undefined; if (notifying) this.#notifyNative = undefined; if (ordinary) this.#rpcNative[rpc] = undefined;
        nativePrepared = prepared?.native !== undefined; native = await this.#openNative(options, position);
        this.#check(); if (this.#rekeyRound !== undefined || owner.snapshot(handle).epoch !== this.#epochNumber) fail("busy");
      }
      const rxConfig = this.#cipherConfig(this.#receiveDirection), txConfig = this.#cipherConfig(this.#sendDirection);
      references.push(...(management ? this.#managementRefs.slice(0, 5) : notifying ? notificationRefs!.slice(0, 5) : ordinary ? rpcRefs!.slice(0, 5) : prepared?.references.slice(0, 5) ?? this.#reserve(scope, ["v4_receive_key_0", "v4_receive_key_1", "v4_send_key_0", "v4_send_key_1", "v4_stream_termination"],
        [directionKeyCharge(rxConfig), directionKeyCharge(rxConfig), directionKeyCharge(txConfig), directionKeyCharge(txConfig), streamTerminationCharge(this.config.runtimeBytes)])));
      receiveKeys = new DirectionKeyPositions(this.config.streams.root, rxConfig, references.slice(0, 2), this.config.ledger, scope, this.#receiveDirection,
        management ? this.#managementPositions.slice(0, 2) : notifying ? this.#notifyPositions[notify]!.slice(0, 2) : ordinary ? this.#rpcPositions[rpc]!.slice(0, 2) : undefined,
        management ? this.#internalKeys!.checkout("management", "receive") : notifying ? this.#internalKeys!.checkout(`notify_${notify}`, "receive") : ordinary ? this.#internalKeys!.checkout(this.#rpcKey(rpc), "receive") : prepared?.receiveKeys);
      sendKeys = new DirectionKeyPositions(this.config.streams.root, txConfig, references.slice(2, 4), this.config.ledger, scope, this.#sendDirection,
        management ? this.#managementPositions.slice(2, 4) : notifying ? this.#notifyPositions[notify]!.slice(2, 4) : ordinary ? this.#rpcPositions[rpc]!.slice(2, 4) : undefined,
        management ? this.#internalKeys!.checkout("management", "send") : notifying ? this.#internalKeys!.checkout(`notify_${notify}`, "send") : ordinary ? this.#internalKeys!.checkout(this.#rpcKey(rpc), "send") : prepared?.sendKeys);
      binding = { handle, receiveKeys, sendKeys, cipher: this.#cipher(handle, this.#receiveDirection, receiveKeys), nextReceive: 0n, sendDrained: false, receiveDrained: false, stopPending: false, receiveAbandon: false, retiring: false, quarantined: false, nextSend: 0n, sentOffset: 0n, acknowledged: 0n, sendLimit: 0n, sendFIN: false };
      if (native !== undefined) {
        binding.native = native; native.scope = scope;
        native.bounds = new StreamDataBounds(scope, this.#receiveDirection, this.config.ledger.profile, this.config.maxFrame);
        native.reader.bindData(native.bounds);
      }
      binding.terminationReservation = references[4]!.take(streamTerminationCharge(this.config.runtimeBytes));
      binding.send = this.#cipher(handle, this.#sendDirection, sendKeys);
      if (management) { binding.sendAccount = this.config.streams.managementSendAccount!; this.#managementOutput = this.#managementRefs[9]!.take(bootstrapOutputCharge()); }
      if (notifying) { binding.sendAccount = this.config.streams.notifySendAccounts![notify]!; this.#notifyOutputs[notify] = notificationRefs![9]!.take(bootstrapOutputCharge()); }
      if (ordinary) { binding.sendAccount = this.config.streams.rpcSendAccounts![rpc]!; this.#rpcOutputs[rpc] = rpcRefs![9]!.take(bootstrapOutputCharge()); }
      if (preparedAccount !== undefined) { binding.sendAccount = preparedAccount; preparedAccount = undefined; }
      binding.direction = this.#prepareDirection(binding, management ? this.#managementRefs.slice(5, 8) : notifying ? notificationRefs!.slice(5, 8) : ordinary ? rpcRefs!.slice(5, 8) : prepared?.references.slice(5, 8));
      binding.ackCommittedOffset = 0n; binding.ackCommittedLimit = initialLimit;
      this.#bindings.set(scope, binding);
      if (prepare !== undefined) { binding.stream = new RuntimeStream(this, handle, binding.direction); prepare(binding.stream, handle); }
      const completion = this.#encodeApplication(native, encode => {
        const body = owner.encodeLocal(handle, encode);
        this.#check(); if (options?.signal?.aborted) fail("closed");
        return (native?.output ?? this.output).record(binding!.send!, frameType("OPEN_STREAM"), body, () => {
          submitted = true; binding!.nextSend = 1n; owner.submittedLocal(handle);
        }, () => { ticket = true; });
      });
      if (native !== undefined) this.#startNativeRead(native);
      await completion; this.#wake();
      this.#check(); if (options?.signal?.aborted) { void this.close().catch(() => undefined); fail("closed"); }
      return handle;
    } catch (error) {
      if (submitted && binding !== undefined && native !== undefined && error instanceof NativeDirectionFailure && error.code === "normal_drained") {
        native.writeFailure ??= error;
        if (this.#nativeOutputFailed(binding)) { this.#wake(); return handle; }
      }
      if (ticket || submitted) void this.close().catch(() => undefined);
      else {
        native?.close();
        binding?.stream?.rollbackUnpublishedAdapter();
        binding?.direction?.close(); binding?.cipher.close(); binding?.send?.close(); binding?.terminationReservation?.release(); if (!management && !notifying && !ordinary) binding?.sendAccount?.close(); this.#bindings.delete(scope);
        receiveKeys?.close(); sendKeys?.close();
        owner.cancelUnsubmitted(handle);
        if (ordinary) this.#rpcHandles[rpc] = undefined;
      }
      throw error;
    } finally {
      if (prepared === undefined) for (const reference of references) reference.release();
      else {
        for (const reference of prepared.references) reference.release();
        if (!nativePrepared) for (const reference of prepared.native?.references ?? []) reference.release();
      }
      preparedAccount?.close(); if (receiveKeys === undefined) prepared?.receiveKeys?.close(); if (sendKeys === undefined) prepared?.sendKeys?.close();
    }
  }
  pendingOpen(): OpenHandle | undefined { this.#check(); return this.#open!.pendingPeers().find(handle => ![managementSpec.kind as string, bootstrapSpec.kind, notifySpec.kind].includes(this.#open!.kind(handle)) && !this.#rpc?.hasStreamingKind(this.#open!.kind(handle))); }
  copyOpenOffer(handle: OpenHandle, kind: Uint8Array, metadata: Uint8Array): Readonly<{ kindBytes: number; metadataBytes: number }> {
    this.#check(); return this.#open!.copyOffer(handle, kind, metadata);
  }
  /** Reserve the complete accepted Stream direction vector before an
   * application handler permit is acquired. The peer's receive keys are
   * already installed when OPEN enters pending; those two protected slots are
   * deliberately retained in this bounded reservation until the accept gate,
   * then released without being re-derived. This keeps the pending owner
   * covered by one finite vector and prevents handler admission from racing a
   * late resource allocation. */
  #prepareIncomingOpen(scope: bigint): StreamOpenPreparation {
    this.#check();
    const receive = this.config.streams.receive;
    const charges = streamOpenCharges(this.config.maxFrame, this.config.runtimeBytes, receive, this.#nativeScheduler === undefined ? this.config.maxFrame : this.#nativeOutputFrame());
    const references = this.#reserve(scope, ["v4_incoming_open_0", "v4_incoming_open_1", "v4_incoming_open_2", "v4_incoming_open_3",
      "v4_incoming_open_termination", "v4_incoming_open_direction", "v4_incoming_open_decoder", "v4_incoming_open_cursor", "v4_incoming_open_wait"], charges);
    let account: ResourceAccount | undefined;
    try {
      account = this.#sendAccounts!.checkout();
      return new StreamOpenPreparation(this.config.streams.root, charges, references, account);
    } catch (error) {
      account?.close(); for (const reference of references) reference.release(); throw error;
    } finally { for (const reference of references) reference.release(); }
  }
  /** Actual accepted publication transfers ingress -> active synchronously,
   * after both key directions and the original receive promise are installed. */
  async acceptOpen(handle: OpenHandle, options?: OperationOptions, committing?: () => void,
    committed?: () => void, prepare?: (stream: V4StreamOwner, handle: OpenHandle) => void, management = false, notify?: 0 | 1,
    prepaid?: StreamOpenPreparation, rpc?: number): Promise<ReliableReceiveDirection> {
    this.#check(); if (this.#draining) fail("session_draining"); if (options?.signal?.aborted) fail("closed");
    if (!this.output.available()) fail("busy");
    const notifying = notify !== undefined, notificationRefs = notifying ? this.#notifyRefs[notify]! : undefined;
    const ordinary = rpc !== undefined, rpcRefs = ordinary ? this.#rpcRefs[rpc] : undefined;
    if (ordinary && (management || notifying || !Number.isSafeInteger(rpc) || Math.floor(rpc / 4) !== this.#receiveDirection ||
        handle !== this.#rpcHandles[rpc] || this.#rpc === undefined || rpcRefs?.length !== 10)) fail("configuration_capacity");
    if (notifying && (management || notify === this.#sendDirection || handle !== this.#notifyHandles[notify] || this.#info.application_profile === "transport")) fail("configuration_capacity");
    const classification = management ? 2 : notifying || ordinary ? 1 : 0, initialLimit = management || notifying || ordinary ? 16384n : this.config.streams.receive.receiveLimit;
    if (management && (handle !== this.#managementHandle || this.#info.application_profile !== "execution" || this.#sendDirection !== 1)) fail("configuration_capacity");
    const owner = this.#open!; owner.checkAccept(handle, classification);
    const scope = owner.snapshot(handle).scope, binding = this.#bindings.get(scope);
    if (binding?.handle !== handle || binding.direction !== undefined || binding.send !== undefined) fail("protocol_violation");
    const keyConfig = this.#cipherConfig(this.#sendDirection);
    let prepared: ReturnType<StreamOpenPreparation["take"]> | undefined;
    let preparedAccount: ResourceAccount | undefined;
    try {
      prepared = prepaid?.take(this.#reservation!);
      preparedAccount = prepared?.account;
    } catch (error) { prepaid?.close(); throw error; }
    const refs = management ? this.#managementRefs.slice(2, 5) : notifying ? notificationRefs!.slice(2, 5) : ordinary ? rpcRefs!.slice(2, 5) : prepared?.references.slice(2, 5) ??
      this.#reserve(scope, ["v4_send_key_0", "v4_send_key_1", "v4_stream_termination"],
        [directionKeyCharge(keyConfig), directionKeyCharge(keyConfig), streamTerminationCharge(this.config.runtimeBytes)]);
    let ticket = false;
    try {
      binding.sendKeys = new DirectionKeyPositions(this.config.streams.root, keyConfig, refs.slice(0, 2), this.config.ledger, scope, this.#sendDirection,
        management ? this.#managementPositions.slice(2, 4) : notifying ? this.#notifyPositions[notify]!.slice(2, 4) : ordinary ? this.#rpcPositions[rpc]!.slice(2, 4) : undefined,
        management ? this.#internalKeys!.checkout("management", "send") : notifying ? this.#internalKeys!.checkout(`notify_${notify}`, "send") : ordinary ? this.#internalKeys!.checkout(this.#rpcKey(rpc), "send") : prepared?.sendKeys);
      binding.send = this.#cipher(handle, this.#sendDirection, binding.sendKeys);
      binding.terminationReservation = refs[2]!.take(streamTerminationCharge(this.config.runtimeBytes));
      if (management) binding.sendAccount = this.config.streams.managementSendAccount!;
      if (notifying) binding.sendAccount = this.config.streams.notifySendAccounts![notify]!;
      if (ordinary) binding.sendAccount = this.config.streams.rpcSendAccounts![rpc]!;
      if (preparedAccount !== undefined) { binding.sendAccount = preparedAccount; preparedAccount = undefined; }
      binding.direction = this.#prepareDirection(binding, management ? this.#managementRefs.slice(5, 8) : notifying ? notificationRefs!.slice(5, 8) : ordinary ? rpcRefs!.slice(5, 8) : prepared?.references.slice(5, 8));
      if (prepare !== undefined) { binding.stream = new RuntimeStream(this, handle, binding.direction); prepare(binding.stream, handle); }
      const body = owner.encodeResult(handle, initialLimit, this.#encode, classification);
      this.#check(); owner.checkAccept(handle, classification); if (options?.signal?.aborted) fail("closed");
      ticket = true;
      const completion = this.output.record(this.#sendSwitched ? this.#candidateSend! : this.#controlSend!, frameType("STREAM_ACK"), body, () => {
        committing?.();
        owner.acceptedPeer(handle, initialLimit, classification); binding.sendLimit = owner.peerLimit(handle);
        binding.native?.outcome();
        binding.ackCommittedOffset = 0n; binding.ackCommittedLimit = initialLimit;
        committed?.();
      });
      this.#encode.fill(0); await completion; this.#wake();
      this.#nativeOutputFailed(binding);
      if (binding.native?.inputEnded) this.#nativeInputEnded(binding.native);
      this.#check(); return binding.direction;
    } catch (error) {
      if (ticket) void this.close().catch(() => undefined);
      else {
        // This scope may only be rejected after failed preparation; it is never
        // retried with freshly derived direction keys.
        binding.stream?.rollbackUnpublishedAdapter(); delete binding.stream;
        binding.direction?.close(); binding.send?.close(); binding.sendKeys?.close();
        if (!this.#closed && owner.phase(handle) === "peer_pending") {
          try { await this.rejectOpen(handle, 2); } catch { /* Publication owns its original failure. */ }
        }
      }
      throw error;
    } finally {
      this.#encode.fill(0); for (const ref of refs) ref.release();
      if (prepared !== undefined) { for (const ref of prepared.references) ref.release(); for (const ref of prepared.native?.references ?? []) ref.release(); }
      preparedAccount?.close(); if (binding.sendKeys === undefined) prepared?.sendKeys?.close();
    }
  }
  async rejectOpen(handle: OpenHandle, reason: number): Promise<void> {
    this.#check(); if (!this.output.available()) fail("busy");
    if (!this.#open!.canReject(handle)) throw new OpenAdmissionError("open_capacity");
    try {
      const scope = this.#open!.snapshot(handle).scope, binding = this.#bindings.get(scope);
      const body = this.#open!.encodeResult(handle, 0n, this.#encode, 0, reason);
      const completion = this.output.record(this.#sendSwitched ? this.#candidateSend! : this.#controlSend!, frameType("STREAM_ACK"), body, () => {
        this.#open!.rejectedPeer(handle); binding?.native?.reject();
      });
      this.#encode.fill(0); await completion; this.#wake();
      if (binding !== undefined) delete binding.rejectionPending;
      binding?.cipher.close(); binding?.direction?.close(); binding?.send?.close();
      binding?.native?.reject();
      void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
    } catch (error) { void this.close().catch(() => undefined); throw error; }
    finally { this.#encode.fill(0); }
  }
  acceptedReceive(handle: OpenHandle): ReliableReceiveDirection {
    this.#check(); const snapshot = this.#open!.snapshot(handle), binding = this.#bindings.get(snapshot.scope);
    if (snapshot.phase !== "live" || binding?.handle !== handle || binding.direction === undefined ||
        this.#open!.isBootstrap(handle) && !this.#open!.bootstrapBound(handle)) fail("protocol_violation");
    return binding.direction;
  }
  /** Internal one-record send, used by the original bounded WriteRequest owner.
   * Native admission is the accepted-prefix boundary; completion retains all
   * packet/output backing. This is not a public write-request replacement. */
  async sendData(handle: OpenHandle, data: Uint8Array, fin: boolean, options?: OperationOptions, admitted?: (bytes: number) => void, checkDeadline?: () => void): Promise<bigint> {
    this.#check(); if (this.#rekeyRound !== undefined) fail("busy");
    if (options?.signal?.aborted) fail("closed");
    const snapshot = this.#open!.snapshot(handle), binding = this.#bindings.get(snapshot.scope), size = byteLength(data);
    if (this.#open!.isBootstrap(handle) && !this.#open!.bootstrapBound(handle)) fail("busy");
    const output = binding?.native?.output ?? this.output;
    if (!this.#applicationOutputAvailable(binding?.native)) fail("busy");
    if (snapshot.phase !== "live" || binding?.handle !== handle || binding.send === undefined || binding.sendFIN || binding.terminalSend !== undefined || binding.stopPending ||
        size > this.config.streams.receive.maxDataBytes || BigInt(size) > binding.sendLimit - binding.sentOffset ||
        binding.sendSealed && !fin || binding.nextSend > (1n << 64n) - 1n) fail("protocol_violation");
    let ticket = false;
    try {
      const completion = this.#encodeApplication(binding.native, encode => {
        const body = encodeStreamData(new FixedCBORWriter(encode), snapshot.scope, this.#sendDirection, snapshot.epoch, binding.nextSend, binding.sentOffset, fin, data);
        const beforeSubmit = (): void => { checkDeadline?.(); if (options?.signal?.aborted) throw new Error("canceled"); };
        beforeSubmit();
        return output.record(binding.send!, frameType("STREAM_DATA"), body, () => {
          binding.sendFIN = fin;
          admitted?.(size);
          if (fin) this.#wake();
        }, () => {
          // STOPPED/barrier include every allocated sequence even when native
          // publication fails. The public accepted prefix is recorded separately.
          ticket = true; binding.nextSend++; binding.sentOffset += BigInt(size);
          if (fin) binding.terminalSend = { epoch: snapshot.epoch, next: binding.nextSend, offset: binding.sentOffset };
        }, beforeSubmit);
      });
      await completion;
      if (fin && binding.native !== undefined) {
        // Native FIN is physical cleanup. The original termination deadline
        // continues even if that provider operation does not cooperate.
        const native = binding.native;
        void native.transport.closeWrite().catch(error => {
          if (this.#closed) return;
          try {
            if (error instanceof NativeDirectionFailure) { native.writeFailure ??= error; this.#nativeOutputFailed(binding); }
            else void this.close().catch(() => undefined);
          } catch { void this.close().catch(() => undefined); }
        });
      }
      this.#wake(); return BigInt(size);
    } catch (error) {
      if (ticket && binding.native !== undefined && error instanceof NativeDirectionFailure) {
        binding.native.writeFailure ??= error;
        if (this.#nativeOutputFailed(binding)) { this.#wake(); throw error; }
      }
      if (ticket) void this.close().catch(() => undefined); throw error;
    }
  }
  resumeStreamTarget(handle: OpenHandle, session: object, kind: string) {
    this.#check();
    const snapshot = this.#open!.snapshot(handle), binding = this.#streamBinding(handle);
    const policy = this.config.credentials?.checkpointPolicy(this.#info.selected_features);
    if (session !== this || this.#info.application_profile !== "execution" || policy === undefined ||
        this.#draining || this.#goaway !== undefined || snapshot.phase !== "live" || this.#open!.classification(handle) !== 0 ||
        this.#open!.kind(handle) !== kind || this.#dedicatedRPCStreams.has(handle) || binding.sentOffset !== 0n ||
        binding.direction?.progress().released_offset !== 0n) fail("configuration_capacity");
    return Object.freeze({ transportContextDigest: this.config.transportContextDigest, streamID: snapshot.scope, policy });
  }
  checkMessageBoundary(handle: OpenHandle): void {
    this.#check(); const binding = this.#streamBinding(handle);
    if (this.#open!.phase(handle) !== "live" || binding.write !== undefined || binding.sendSealed || binding.sendTermination !== undefined ||
        binding.receiveTermination !== undefined || binding.stopPending || binding.receiveAbandon || binding.receiveDrained ||
        binding.terminalReceive !== undefined || binding.native?.writeFailure !== undefined || binding.native?.output.pending()) fail("busy");
    binding.direction!.checkAdapterClaim();
  }
  checkRPCStream(handle: OpenHandle): void {
    this.#check();
    const kind = this.#open!.kind(handle), classification = this.#open!.classification(handle);
    if (!(this.#info.application_profile !== "transport" && classification === 0 && this.#dedicatedRPCStreams.has(handle)) &&
        !(this.#info.application_profile !== "transport" && classification === 1 && (kind === "flowersec.rpc.v4" || kind === notifySpec.kind && this.#notifyHandles.includes(handle))) &&
        !(this.#info.application_profile === "execution" && classification === 2 && kind === managementSpec.kind && handle === this.#managementHandle)) fail("configuration_capacity");
  }
  isDedicatedRPCStream(handle: OpenHandle): boolean { return this.#dedicatedRPCStreams.has(handle); }
  unusedRPCStream(handle: OpenHandle): boolean {
    if (this.#closed || this.#draining || this.#goaway !== undefined || !this.#dedicatedRPCStreams.has(handle)) return false;
    const snapshot = this.#open!.snapshot(handle), binding = this.#bindings.get(snapshot.scope);
    if (snapshot.phase !== "live" || binding === undefined || binding.sentOffset !== 0n || binding.write !== undefined ||
        binding.sendSealed || binding.stopPending || binding.receiveAbandon || binding.receiveDrained || binding.terminalReceive !== undefined ||
        binding.direction === undefined || binding.native?.writeFailure !== undefined || binding.native?.inputEnded) return false;
    const received = binding.direction.progress();
    return received.ack_offset === 0n && received.released_offset === 0n && received.queued_bytes === 0n && received.fin_offset === undefined &&
      binding.sendLimit >= 16384n && received.receive_limit >= 16384n;
  }
  subscribeNotification<Input, Value>(method: ServiceDefinitionTypes.V4MethodDefinition<Input, any, "notify">,
    handler: ServiceHandlersTypes.V4NotificationHandler<Value>, options: NotificationSubscriptionTypes.V4NotificationSubscriptionOptions<Input, Value>): NotificationSubscriptionTypes.V4NotificationSubscription<Value> {
    this.#check(); return this.rpcApplication().subscribeNotification(method, handler, options);
  }
  queryOperation(reference: V4OperationReference, options: OperationOptions = {}): Promise<V4ExecutionManagementResult> {
    return this.rpcApplication().manageExecution(reference, false, this.#deadline(30000n), options.signal);
  }
  readOperationResult(reference: V4OperationReference, options: V4OperationResultReadOptions = {}): V4OperationResultRead {
    const { timeoutMS = 30000n, context, signal } = options;
    return operationResultRead(this.rpcApplication().readExecutionResult(reference, this.#deadline(timeoutMS), context, signal));
  }
  requestCancel(reference: V4OperationReference, options: OperationOptions = {}): Promise<V4ExecutionManagementResult> {
    return this.rpcApplication().manageExecution(reference, true, this.#deadline(30000n), options.signal);
  }
  /** Candidate dependency preparation shares Bind and the existing channels,
   * using the attempt's original deadline before an application permit. */
  async bindServiceDependency(definition: object, options: ServiceBindingConfigTypes.ServiceBindingOptions,
    captured: ServiceBindingConfigTypes.CapturedServiceBinding, deadline: TrustedDeadline, signal: AbortSignal,
    reservation?: ServiceBindingPoolTypes.ServiceBindingReservation, queries?: QueryRenewalPositionTypes.ContractQueryPreparation): Promise<ServiceBindingTypes.ServiceBinding> {
    this.#check(); const application = this.rpcApplication(), required = captured.methods.filter(method => method.required);
    if (required.length !== 0) while (!application.bound) await this.#wait(deadline, signal);
    if (required.some(method => method.facts.shape === "notify")) {
      this.#notifyDemand = true; this.#driveNotify();
      while (!application.notifyReady()) {
        if (this.#notifyStopped[this.#sendDirection]) throw new Error("notify_unavailable");
        await this.#wait(deadline, signal);
      }
    }
    this.#check(); deadline.check(); if (signal.aborted) throw new Error("canceled");
    return application.bindService(definition, options, deadline, undefined, signal, captured, reservation, queries);
  }
  async bindService<Methods extends V4ServiceMethods>(definition: V4ServiceDefinition<Methods>, options: V4ServiceBindOptions): Promise<V4ServiceClient<Methods>> {
    this.#check(); const { timeoutMS = 90000n, signal, context } = options;
    const deadline = this.#deadline(timeoutMS), application = this.rpcApplication();
    await this.prepareServiceChannels(serviceDefinition(definition).entries.some(entry => entry.facts.shape === "notify"), deadline, context, signal);
    return application.bindService(definition, options, deadline, context, signal).then(binding => {
      try {
        const client = serviceClient(definition, binding); binding.checkDelivery(); deadline.check();
        if (signal?.aborted) throw new Error("canceled"); return client;
      } catch (error) { binding.close(); throw error; }
    });
  }
  async prepareServiceChannels(notify: boolean, deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void> {
    this.#check(); const application = this.rpcApplication();
    // READY and local bootstrap publication have independent physical tails.
    // Keep the original BindService deadline while its preadmitted channel
    // becomes usable; a provider completion must not race the first query.
    if (applicationHasPermit(context) && !application.bound) throw new Error("not_ready");
    while (!application.bound) await this.#wait(deadline, signal);
    if (notify) {
      if (applicationHasPermit(context) && !application.notifyReady()) throw new Error("not_ready");
      this.#notifyDemand = true; this.#driveNotify();
      while (!application.notifyReady()) {
        if (this.#notifyStopped[this.#sendDirection]) throw new Error("notify_unavailable");
        await this.#wait(deadline, signal);
      }
    }
    this.#check(); deadline.check(); if (signal?.aborted) throw new Error("canceled");
  }
  /** SDK assembly access; the owner remains attached to this Session. */
  rpcApplication(): RPCApplicationAdmission {
    this.#check(); if (this.#rpc === undefined) fail("configuration_capacity"); return this.#rpc;
  }
  beginApplicationDiagnostic(): DiagnosticActivity { return new DiagnosticActivity(this.#core?.config.diagnostics, "application"); }
  prepareWrite(handle: OpenHandle, payload: Uint8Array, duration?: bigint, prepaid?: ResourceReference, diagnostic?: DiagnosticActivity, originalDeadline?: TrustedDeadline, publication?: RPCPublicationGuard): ReliableWriteRequest {
    this.#check(); const snapshot = this.#open!.snapshot(handle), binding = this.#bindings.get(snapshot.scope);
    const size = byteLength(payload), timeout = duration ?? this.config.streams.writeDeadlineMS;
    if (snapshot.phase !== "live" || binding?.handle !== handle || binding.write !== undefined || binding.terminalSend !== undefined || binding.sendSealed || binding.stopPending) fail("busy");
    if (this.#open!.isBootstrap(handle) && !this.#open!.bootstrapBound(handle)) fail("busy");
    if (size > this.config.streams.maxWriteBytes || timeout < 1n || timeout > this.config.streams.writeDeadlineMS) fail("configuration_capacity");
    if (prepaid !== undefined && !prepaid.sameEnvironment(this.#reservation!)) fail("configuration_capacity");
    const deadline = this.#deadline(timeout);
    if (originalDeadline !== undefined) deadline.tightenFrom(originalDeadline);
    const refs = prepaid === undefined
      ? this.#reserve(snapshot.scope, ["v4_write_request"], [writeRequestCharge(size, this.config.runtimeBytes)], this.#directionSendAccount(binding))
      : [prepaid.take(writeRequestCharge(size, this.config.runtimeBytes))];
    try {
      const request = new ReliableWriteRequest({
        maxChunk: this.config.streams.receive.maxDataBytes,
        readyBytes: () => {
          this.#check(); publication?.check();
          if (binding.terminalSend !== undefined || binding.stopPending) throw new Error("stream_terminated");
          return this.#applicationOutputAvailable(binding.native) && this.#rekeyRound === undefined ? Number(binding.sendLimit - binding.sentOffset > BigInt(this.config.streams.receive.maxDataBytes)
            ? BigInt(this.config.streams.receive.maxDataBytes) : binding.sendLimit - binding.sentOffset) : 0;
        },
        waitReady: signal => this.#wait(deadline, signal),
        send: async (bytes, admitted, signal) => {
          await this.sendData(handle, bytes, false, { signal }, admitted, () => { deadline.check(); originalDeadline?.check(); publication?.check(); });
        },
        release: request => { if (binding.write === request) delete binding.write; this.#wake(); },
      }, payload, deadline, this.config.runtimeBytes, refs[0]!, diagnostic);
      binding.write = request; return request;
    } finally { for (const ref of refs) ref.release(); }
  }
  prepareOrdinaryWrite(handle: OpenHandle, payload: Uint8Array, diagnostic?: DiagnosticActivity): V4WriteRequestOwner {
    // The optional stable operation's staging cap does not limit ordinary
    // Write input. Return a stable accepted prefix through the same owner.
    return this.prepareWrite(handle, byteSlice(payload, 0, Math.min(byteLength(payload), this.config.streams.maxWriteBytes)), undefined, undefined, diagnostic);
  }
  async #control(type: number, build: (writer: FixedCBORWriter) => Uint8Array | undefined, submitted: () => void = () => undefined, deadline = this.#deadline()): Promise<void> {
    deadline.check();
    while (!this.output.available()) await this.#wait(deadline);
    this.#check(); deadline.check();
    try {
      const body = build(new FixedCBORWriter(this.#encode));
      if (body === undefined) return;
      const completion = this.output.record(this.#sendSwitched ? this.#candidateSend! : this.#controlSend!, type, body, submitted);
      this.#encode.fill(0); await completion; this.#wake();
    } catch (error) { void this.close().catch(() => undefined); throw error; }
    finally { this.#encode.fill(0); }
  }
  acknowledgeReceive(handle: OpenHandle): Promise<void> {
    this.#check(); const binding = this.#bindings.get(this.#open!.snapshot(handle).scope);
    if (binding?.direction === undefined || binding.receiveAbandon || binding.receiveDrained || this.#open!.phase(handle) !== "live") return Promise.resolve();
    const ack = binding.direction.progress().ack_offset, limit = binding.direction.nextCredit();
    const committed = binding.ackCommittedLimit!, offset = binding.ackCommittedOffset!;
    if (ack <= offset && limit <= committed) return binding.acknowledging ?? Promise.resolve();
    binding.ackDirty = true;
    // Only reaching a real published credit boundary followed by an actual
    // reserved grant bypasses the ordinary bounded coalescing delay.
    binding.ackUrgent ||= ack >= committed && limit > committed;
    const window = committed - offset, threshold = window < 65536n ? (window > 0n ? window : 1n) : 65536n;
    binding.ackEligible ||= binding.ackUrgent || ack - offset >= threshold;
    if (binding.acknowledging !== undefined) return binding.acknowledging;
    if (!binding.ackEligible) {
      if (binding.ackTimer === undefined) binding.ackTimer = setTimeout(() => {
        delete binding.ackTimer; binding.ackEligible = true;
        if (!this.#closed) void this.acknowledgeReceive(handle).catch(() => { void this.close().catch(() => undefined); });
      }, 25);
      return Promise.resolve();
    }
    this.#clearAckTimer(binding);
    const operation = this.#acknowledgeReceive(handle); binding.acknowledging = operation;
    void operation.then(() => {
      delete binding.acknowledging; this.#terminal(binding); this.#wake();
      if (!this.#closed && binding.ackDirty) void this.acknowledgeReceive(handle).catch(() => { void this.close().catch(() => undefined); });
    }, () => { delete binding.acknowledging; void this.close().catch(() => undefined); this.#wake(); });
    return operation;
  }
  #clearAckTimer(binding: ReceiveBinding): void {
    if (binding.ackTimer !== undefined) clearTimeout(binding.ackTimer);
    delete binding.ackTimer;
  }
  async #acknowledgeReceive(handle: OpenHandle): Promise<void> {
    this.#check(); const snapshot = this.#open!.snapshot(handle), binding = this.#bindings.get(snapshot.scope);
    if (binding?.direction === undefined || snapshot.phase !== "live" || binding.receiveAbandon || binding.receiveDrained) return;
    let limit = 0n, ack = 0n;
    await this.#control(frameType("STREAM_ACK"), writer => {
      if (binding.receiveAbandon || binding.receiveDrained || this.#open!.phase(handle) !== "live") return;
      ack = binding.direction!.progress().ack_offset; limit = binding.direction!.nextCredit();
      if (ack <= binding.ackCommittedOffset! && limit <= binding.ackCommittedLimit!) { binding.ackDirty = false; return; }
      return writer.map(5).uint(0).uint(0).uint(1).uint(snapshot.scope).uint(2).uint(this.#receiveDirection)
        .uint(3).uint(ack).uint(4).uint(limit).result();
    }, () => {
      binding.direction!.commitCredit(limit);
      binding.ackCommittedOffset = ack; binding.ackCommittedLimit = limit;
      binding.ackEligible = false; binding.ackUrgent = false;
      binding.ackDirty = binding.direction!.progress().ack_offset > ack || binding.direction!.nextCredit() > limit;
    });
  }
  #drained(binding: ReceiveBinding, aborted: boolean): Promise<void> {
    if (binding.draining !== undefined) return binding.draining;
    const operation = this.#publishDrained(binding, aborted); binding.draining = operation;
    void operation.finally(() => { delete binding.draining; this.#terminal(binding); this.#wake(); void this.#retirement().catch(() => undefined); }).catch(() => undefined);
    return operation;
  }
  async #publishDrained(binding: ReceiveBinding, aborted: boolean): Promise<void> {
    const scope = this.#open!.snapshot(binding.handle).scope, terminal = binding.terminalReceive;
    if (terminal === undefined || binding.receiveDrained) return;
    await this.#control(frameType("STREAM_ACK"), writer => {
      if (binding.receiveDrained) return;
      aborted ||= binding.receiveAbandon;
      const observed: TerminalTuple = { epoch: terminal.epoch, next: binding.nextReceive, offset: binding.direction?.progress().ack_offset ?? 0n };
      if (!aborted && !sameTuple(terminal, observed) || observed.next > terminal.next || observed.offset > terminal.offset) fail("protocol_violation");
      writer.map(6).uint(0).uint(4).uint(1).uint(scope).uint(2).uint(this.#receiveDirection).uint(3);
      tuple(writer, terminal); writer.uint(4).uint(aborted ? 1 : 0).uint(5); tuple(writer, observed); return writer.result();
    }, () => {
      binding.receiveDrained = true; binding.ackDirty = false; this.#clearAckTimer(binding);
      // Irrevocable publication changes the protocol deadline even while the
      // original native completion still owns its physical cleanup tail.
      this.#wake();
      if (binding.native !== undefined) void binding.native.transport.stopSending(aborted ? undefined : "normal_drained").catch(() => undefined);
    });
    if (aborted) binding.direction?.close();
    this.#terminal(binding);
  }
  #terminal(binding: ReceiveBinding): void {
    if (binding.sendDrained) this.#leaveQuarantine(binding.sendTermination);
    if (binding.receiveDrained) this.#leaveQuarantine(binding.receiveTermination);
    if (this.#closed) { this.#cleanup(); return; }
    // A late completion can revisit its original terminal owner after the
    // authenticated retirement fence. It must not re-enter terminal admission
    // or operate on a slot that has since been released and reused.
    if (binding.retired) { this.#collectRetiredProofs(); this.#wake(); return; }
    if (!binding.receiveDrained || !binding.sendDrained) return;
    // Authentication of FIN does not consume its queued application bytes.
    // Keep the receive owner until its actual reader/cursor has relinquished it.
    if (binding.receiveAbandon || binding.direction?.state().stream_status === "eof") binding.direction?.close();
    binding.send?.close(); binding.cipher.close();
    // Authenticated DRAINED can arrive before the original FIN publisher's
    // continuation calls native closeWrite. Keep that publisher's stream open
    // until it exits; its completion revisits this same terminal owner.
    if (binding.write === undefined && binding.termination === undefined) binding.native?.close();
    if (this.#physicalComplete(binding, false)) binding.stream?.notifyAdapterCleanup();
    // Adapter cleanup can synchronously detach its I/O, re-enter this owner,
    // and publish retirement. Recheck the original binding after that callback
    // before touching the admission slot or releasing stream resources again.
    if (this.#closed) { this.#cleanup(); return; }
    if (binding.retired) { this.#collectRetiredProofs(); this.#wake(); return; }
    if (this.#physicalComplete(binding)) {
      this.#open!.terminal(binding.handle);
      this.#releaseStream(binding);
    }
    this.#wake();
    void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
  }
  #newTermination(binding: ReceiveBinding): DirectionTermination {
    const normal = this.#deadline(binding.gracefulFinishMS), total = normal.cap + 10000n;
    return { normal, hard: this.config.deadline.fork(total < this.config.deadline.cap ? total : this.config.deadline.cap), quarantined: false };
  }
  #beginTermination(binding: ReceiveBinding, reset: boolean, failed = false, receiveOnly = false): void {
    this.#check();
    if (binding.terminationReservation === undefined) fail("closed");
    // An unbound bootstrap has no DATA path on which to send FIN. Its exact
    // zero (or already ticketed prefix) frontier closes with STOPPED instead.
    if (binding.handle === this.#bootstrap && !this.#open!.bootstrapBound(binding.handle) && !receiveOnly) binding.stopPending = true;
    if (binding.handle === this.#bootstrap && !this.#open!.bootstrapBound(binding.handle) &&
        (this.#sendDirection === 0 && !receiveOnly || reset)) this.#cancelBootstrapInitialization();
    if (!receiveOnly) {
      binding.sendSealed = true; binding.write?.terminate();
      if (!binding.sendDrained) binding.sendTermination ??= this.#newTermination(binding);
    }
    if (reset || receiveOnly) {
      if (reset) binding.resetRequested = true;
      // A consumed authenticated FIN remains graceful even when Close races
      // the queued DRAINED publication. Only unread/open input is abandoned.
      if (binding.direction?.state().stream_status !== "eof") {
        binding.receiveAbandon = true;
        binding.direction?.abandonDelivery();
      }
      this.#clearAckTimer(binding); binding.ackDirty = false;
      if (!binding.receiveDrained) binding.receiveTermination ??= this.#newTermination(binding);
      else binding.direction?.close();
    }
    if (failed && binding.receiveTermination !== undefined && !binding.receiveDrained) {
      const immediate = this.#deadline(10000n);
      if (immediate.cap < binding.receiveTermination.hard.cap) binding.receiveTermination.hard.tightenFrom(immediate);
      this.#enterQuarantine(binding, binding.receiveTermination, false);
    }
    this.#startTermination(binding); this.#wake();
  }
  #startTermination(binding: ReceiveBinding): void {
    if (binding.termination === undefined) {
      const operation = this.#runTermination(binding); binding.termination = operation;
      void operation.then(() => {
        delete binding.termination; this.#terminal(binding); this.#wake();
        // A second direction can join while the previous driver's fulfilled
        // promise is awaiting this callback. It still gets the same owner.
        try { if (!this.#closed && this.#terminationDeadline(binding) !== undefined) this.#startTermination(binding); }
        catch { void this.close().catch(() => undefined); }
      }, () => {
        delete binding.termination; void this.close().catch(() => undefined); this.#wake();
      });
    }
  }
  #enterQuarantine(binding: ReceiveBinding, direction: DirectionTermination, send: boolean): void {
    this.#check(); direction.hard.check();
    if (direction.quarantined) return;
    if (this.#quarantineDirections >= 32) fail("configuration_capacity");
    this.#quarantineDirections++; direction.quarantined = true;
    if (send) { binding.stopPending = true; binding.write?.terminate(); }
    else binding.direction?.abandonDelivery();
    this.#wake();
  }
  #leaveQuarantine(direction: DirectionTermination | undefined): void {
    if (direction?.quarantined) { direction.quarantined = false; this.#quarantineDirections--; }
  }
  #terminationDeadline(binding: ReceiveBinding): TrustedDeadline | undefined {
    this.#check();
    let next: TrustedDeadline | undefined;
    for (const send of [true, false]) {
      const direction = send ? binding.sendTermination : binding.receiveTermination;
      if (direction === undefined || (send ? binding.sendDrained : binding.receiveDrained)) continue;
      if (!direction.quarantined) {
        try { direction.normal.check(); }
        catch (error) {
          if (!(error instanceof TimeError) || error.code !== "time_expired") throw error;
          this.#enterQuarantine(binding, direction, send);
        }
      }
      const deadline = direction.quarantined ? direction.hard : direction.normal;
      deadline.check(); if (next === undefined || deadline.cap < next.cap) next = deadline;
    }
    return next;
  }
  async #publishStopped(binding: ReceiveBinding): Promise<void> {
    const scope = this.#open!.snapshot(binding.handle).scope;
    await this.#control(frameType("STREAM_ACK"), writer => {
      if (binding.stoppedSent || binding.sendDrained) return;
      // Capture at the actual output gate after all earlier tickets, including
      // a FIN which won the race. Never replace that FIN's application epoch.
      const terminal = binding.terminalSend ??= {
        epoch: this.#open!.snapshot(binding.handle).epoch, next: binding.nextSend, offset: binding.sentOffset,
      };
      return writer.map(6).uint(0).uint(3).uint(1).uint(scope).uint(2).uint(this.#sendDirection)
        .uint(3).uint(terminal.epoch).uint(4).uint(terminal.next).uint(5).uint(terminal.offset).result();
    }, () => { binding.stoppedSent = true; });
  }
  async #runTermination(binding: ReceiveBinding): Promise<void> {
    while (true) {
      const deadline = this.#terminationDeadline(binding);
      if (deadline === undefined) return;
      try {
        if (await this.#terminationStep(binding, deadline)) return;
      } catch (error) {
        // Only expiry of normal local drainage can widen into the already
        // reserved quarantine cap. Safety/maintenance/provider errors keep
        // their existing Session scope; quarantine expiry is final.
        this.#check();
        if (!(error instanceof TimeError) || error.code !== "time_expired") throw error;
        const next = this.#terminationDeadline(binding);
        if (next === deadline) throw error;
      }
    }
  }
  async #terminationStep(binding: ReceiveBinding, deadline: TrustedDeadline): Promise<boolean> {
      const send = binding.sendTermination !== undefined && !binding.sendDrained;
      // Native input retirement can finish between #isolateNativeInput and this
      // wake. Once the physical stream is gone, preserve the original logical
      // termination owner and publish STOPPED on the maintenance channel instead
      // of attempting a FIN through the retired native output.
      if (send && binding.terminalSend === undefined && !binding.stopPending && !binding.resetRequested && binding.native?.transport.cleanupComplete()) {
        binding.stopPending = true; binding.sendSealed = true; binding.write?.terminate();
      }
      if (!this.output.available() || send && (binding.write !== undefined || binding.native?.output.pending() ||
          !binding.stopPending && !binding.resetRequested && (this.#rekeyRound !== undefined || !this.#applicationOutputAvailable(binding.native)))) {
        await this.#wait(deadline); return false;
      }
      deadline.check();
      if (send) {
        if (binding.resetRequested || binding.stopPending) await this.#publishStopped(binding);
        else if (binding.terminalSend === undefined) await this.sendData(binding.handle, empty, true);
      }
      if (binding.receiveTermination !== undefined && !binding.receiveDrained) {
        if (binding.terminalReceive === undefined && !binding.stopSent) {
          const scope = this.#open!.snapshot(binding.handle).scope;
          await this.#control(frameType("STREAM_ACK"), writer => writer.map(3).uint(0).uint(2)
            .uint(1).uint(scope).uint(2).uint(this.#receiveDirection).result(), () => { binding.stopSent = true; });
        }
        if (binding.terminalReceive !== undefined) await this.#drained(binding, binding.receiveAbandon);
      }
      const next = this.#terminationDeadline(binding);
      if (next === undefined) return true;
      await this.#wait(next);
      return false;
  }
  #streamBinding(handle: OpenHandle): ReceiveBinding {
    const binding = this.#bindings.get(this.#open!.snapshot(handle).scope);
    if (binding?.handle !== handle) fail("closed");
    return binding;
  }
  #closeResult(binding: ReceiveBinding): V4CloseResult {
    const state = binding.direction?.state();
    const result: V4CloseResult = {
      direction: this.#sendDirection === 0 ? "c2s" : "s2c",
      send_drained: binding.sendDrained && binding.sendAborted === false && binding.sendFIN,
      read_terminal: state?.stream_status === "eof" ? "eof" : binding.receiveAbandon ? "abandoned" : this.#closed ? "unknown" : "open",
      cleanup_status: this.#physicalComplete(binding) ? complete : pending,
      ...(state?.error === undefined ? {} : { first_error: state.error }),
    };
    Object.defineProperty(result, "then", { value: undefined }); return Object.freeze(result);
  }
  async closeWriteStream(handle: OpenHandle, finish: boolean, options?: OperationOptions): Promise<V4CloseResult> {
    const binding = this.#streamBinding(handle);
    if (!binding.sendFIN && (binding.stopPending || binding.resetRequested)) throw new Error("stream_aborted");
    if (!binding.sendFIN) this.#beginTermination(binding, false);
    const deadline = binding.sendTermination?.normal ?? this.#deadline();
    while (!binding.sendFIN) {
      if (binding.stopPending || binding.resetRequested) throw new Error("stream_aborted");
      await this.#wait(deadline, options?.signal);
    }
    if (finish) {
      while (!binding.sendDrained) await this.#wait(deadline, options?.signal);
      if (binding.sendAborted) throw new Error("stream_aborted");
    }
    return this.#closeResult(binding);
  }
  async closeStream(handle: OpenHandle, options?: OperationOptions): Promise<V4CloseResult> {
    const binding = this.#streamBinding(handle);
    if (!this.#physicalComplete(binding)) {
      this.#beginTermination(binding, true);
      // Once the protocol proofs settle, observing the original publication
      // tail keeps this call's deadline instead of renewing it on every wake.
      const observationDeadline = this.#deadline();
      while (!binding.sendDrained || !binding.receiveDrained || binding.termination !== undefined ||
          binding.draining !== undefined || binding.acknowledging !== undefined) {
        const deadline = this.#terminationDeadline(binding) ?? observationDeadline;
        try { await this.#wait(deadline, options?.signal); }
        catch (error) {
          if (!(error instanceof TimeError) || error.code !== "time_expired" ||
              (this.#terminationDeadline(binding) ?? observationDeadline) === deadline) throw error;
        }
      }
      this.#terminal(binding);
    }
    return this.#closeResult(binding);
  }
  async abortStreamDirection(handle: OpenHandle, send: boolean, options?: OperationOptions): Promise<V4CloseResult> {
    const binding = this.#streamBinding(handle);
    if (send) binding.stopPending = true;
    this.#beginTermination(binding, false, false, !send);
    while (!(send ? binding.sendDrained : binding.receiveDrained)) {
      const deadline = this.#terminationDeadline(binding)!;
      try { await this.#wait(deadline, options?.signal); }
      catch (error) {
        if (!(error instanceof TimeError) || error.code !== "time_expired" || this.#terminationDeadline(binding) === deadline) throw error;
      }
    }
    this.#terminal(binding); return this.#closeResult(binding);
  }
  async waitPeerAuthenticated(handle: OpenHandle, offset: bigint, options?: OperationOptions): Promise<void> {
    const binding = this.#streamBinding(handle);
    if (typeof offset !== "bigint" || offset < 0n || offset > binding.sentOffset) throw new Error("invalid_argument");
    if (offset <= binding.acknowledged) return;
    if ((binding.authenticationWaiters ?? 0) >= 4 || this.#authenticationWaiters >= 64) fail("configuration_capacity");
    binding.authenticationWaiters = (binding.authenticationWaiters ?? 0) + 1; this.#authenticationWaiters++;
    try {
      const deadline = this.#deadline();
      while (binding.acknowledged < offset) {
        if (binding.sendDrained) throw new Error("stream_aborted");
        await this.#wait(deadline, options?.signal);
      }
    } finally { binding.authenticationWaiters--; this.#authenticationWaiters--; }
  }
  streamCleanup(handle: OpenHandle, includeAdapter = true): V4CleanupStatus {
    const binding = this.#bindings.get(this.#open!.snapshot(handle).scope);
    return binding === undefined || this.#physicalComplete(binding, includeAdapter) ? complete : pending;
  }
  #releaseStream(binding: ReceiveBinding): void {
    binding.receiveKeys.close(); binding.sendKeys?.close();
    this.#leaveQuarantine(binding.sendTermination); this.#leaveQuarantine(binding.receiveTermination);
    if (binding.sendAccount !== this.config.streams.managementSendAccount &&
        !this.config.streams.rpcSendAccounts?.includes(binding.sendAccount!) && !this.config.streams.notifySendAccounts?.includes(binding.sendAccount!)) binding.sendAccount?.close(); delete binding.sendAccount;
    binding.stream?.detach(this.#closeResult(binding), binding.sendFIN, binding.sentOffset, binding.acknowledged,
      binding.direction?.progress().released_offset ?? 0n);
    delete binding.stream;
    binding.terminationReservation?.release(); delete binding.terminationReservation;
    if (binding.native?.cleanupComplete()) delete binding.native;
  }
  #localBarrier(): readonly RekeyEntry[] {
    const entries: RekeyEntry[] = [];
    for (const [scope, binding] of this.#bindings) {
      const phase = this.#open!.phase(binding.handle);
      // A ticketed local OPEN is already part of the authenticated send
      // frontier. It remains in the frozen snapshot with next=1 even while
      // its OPEN_ACCEPT outcome is pending. A peer outcome_pending owner has
      // no local send ticket and therefore contributes no fabricated entry.
      if (phase === "local_opening" || phase === "live") entries.push({ scope,
        next: binding.terminalSend !== undefined && binding.terminalSend.epoch < this.#epochNumber ? 0n : binding.nextSend });
    }
    entries.sort((a, b) => a.scope < b.scope ? -1 : a.scope > b.scope ? 1 : 0);
    if (entries.length > 1035) fail("configuration_capacity"); return entries;
  }
  #barrierSatisfied(): boolean {
    for (const entry of this.#peerBarrier) {
      const binding = this.#bindings.get(entry.scope);
      if (binding === undefined) {
        if (this.#nativeScheduler !== undefined) return false;
        fail("protocol_violation");
      }
      if (binding.terminalReceive !== undefined && binding.terminalReceive.epoch < this.#epochNumber) {
        if (entry.next !== 0n) fail("protocol_violation");
        continue;
      }
      if (binding.nextReceive > entry.next) fail("protocol_violation");
      if (binding.nextReceive < entry.next && !binding.receiveDrained) return false;
      if (binding.terminalReceive !== undefined && binding.terminalReceive.next !== entry.next) fail("protocol_violation");
    }
    return true;
  }
  #registerBarrier(entries: readonly RekeyEntry[]): void {
    if (entries.length > 1035) fail("protocol_violation");
    let previous = 0n;
    for (const entry of entries) {
      if (entry.scope <= previous || entry.scope === 0n || entry.scope > maxStreamScope || entry.next > (1n << 64n) - 1n) fail("protocol_violation");
      previous = entry.scope;
      const binding = this.#bindings.get(entry.scope);
      if (binding === undefined) {
        // Independent native streams may deliver this authenticated barrier
        // first. Keep only its original bounded entry: no key, scope map,
        // accepted slot or synthetic OPEN is created by the barrier.
        if (this.#nativeScheduler === undefined || entry.next !== 1n || (entry.scope + 1n) % 2n !== BigInt(this.#receiveDirection) ||
          this.#open!.isStable(entry.scope)) fail("protocol_violation");
      } else if (!["local_opening", "peer_pending", "live", "recent", "rejected"].includes(this.#open!.phase(binding.handle))) fail("protocol_violation");
    }
    this.#peerBarrier = entries.slice();
    this.#barrierSatisfied();
  }
  #phaseDeadline(duration: bigint, phase: DiagnosticFields["phase"] = "rekey_protocol_prepare"): void {
    if (phase !== this.#diagnosticRekeyPhase) {
      this.#diagnostic({ phase: this.#diagnosticRekeyPhase, code: "ok", duration_bucket: diagnosticDuration(this.#diagnosticPhaseStarted) }, "rekey_phase_completed");
      this.#diagnosticRekeyPhase = phase; this.#diagnosticPhaseStarted = performance.now();
    }
    this.#rekeyPhaseDeadline = this.config.deadline.forkAgeAt(this.config.deadline.sample(), duration);
    this.#armRekey();
  }
  #armRekey(): void {
    if (this.#rekeyTimer !== undefined) clearTimeout(this.#rekeyTimer);
    try {
      this.#checkRekeyDeadlines();
      const a = this.#rekeyDeadline!.remainingMS(), b = this.#rekeyPhaseDeadline!.remainingMS();
      const original = this.epoch, roundDeadline = this.#rekeyDeadline;
      this.#rekeyTimer = setTimeout(() => {
        if (this.#closed || this.epoch !== original || this.#rekeyDeadline !== roundDeadline) return;
        this.#rekeyTimer = undefined; this.#armRekey();
      }, timerChunk(a < b ? a : b));
    } catch (error) {
      this.#diagnosticRekeyFailure(error);
      void this.close().catch(() => undefined);
    }
  }
  #beginRekey(): void {
    this.#check();
    if (this.#rekeyRound !== undefined || this.#epochNumber === 0xffffffff) fail("busy");
    this.#localFrozen = this.#localBarrier();
    this.#unreliable?.freeze(); this.#rekeyIntent = true; this.#beginDiagnosticRekey(); this.#liveness!.beginRekey();
    const streams = this.config.streams, deadline = this.#deadline(streams.rekeyPrepareMS + streams.rekeyProtocolMS + streams.rekeyConfirmationMS);
    if (this.#rekeySafetyDeadline !== undefined) deadline.tightenFrom(this.#rekeySafetyDeadline);
    const config: RekeyConfig = { ...(this.config.streams.random === undefined ? {} : { random: this.config.streams.random }), profile: this.config.ledger.profile, epoch: this.#epochNumber, clock: this.config.clock,
      deadline, authorizationDeadline: this.config.deadline, maxFrame: this.config.maxFrame, maxScopes: this.config.streams.rekeyMaxScopes ?? 1035, runtimeBytes: this.config.runtimeBytes, direction: this.#sendDirection };
    const refs = this.#maintenancePositions!.round();
    try { this.#rekeyRound = new RekeyRound(config, this.epoch, refs[0]!, refs[1]!); }
    finally { for (const ref of refs) ref.release(); }
    this.#rekeyDeadline = deadline; this.#phaseDeadline(streams.rekeyPrepareMS, "rekey_local_prepare");
  }
  #chargeRekey(): void {
    if (this.#rekeyCharged) fail("protocol_violation");
    const { rekeyBurst: burst, rekeyRefillMS: period } = this.config.streams, capacity = burst * period;
    const now = this.config.clock.monotonic(); let available = this.#rekeyBase;
    if (this.#rekeyAnchor !== undefined) {
      if (!now.sameEra(this.#rekeyAnchor) || now.milliseconds < this.#rekeyAnchor.milliseconds) fail("authentication_failed");
      const elapsed = this.config.clock.profile.rate.elapsed(now.milliseconds - this.#rekeyAnchor.milliseconds);
      const bound = this.#sendDirection === 0 ? elapsed.lowerMS : elapsed.upperMS;
      available = this.#rekeyBase + burst * bound; if (available > capacity) available = capacity;
    }
    if (available < period) fail("configuration_capacity");
    this.#rekeyPost = available - period; this.#rekeyCharged = true;
  }
  #installCandidate(): void {
    const refs = this.#maintenancePositions!.epoch();
    try {
      this.#candidate = this.#rekeyRound!.install(refs[0]!);
      const authorization: RecordAuthorization = { check: (frame, header, direction) => {
        this.#check(); if (header.scope !== 0n || header.epoch !== this.#epochNumber + 1 && header.epoch !== this.#epochNumber) fail("protocol_violation");
        if (header.epoch === this.#epochNumber + 1 && header.sequence === 0n && frame !== frameType("REKEY")) fail("protocol_violation");
        this.config.streams.authorization.check(frame, header, direction);
      } };
      this.#candidateSend = this.#candidate.derive(0n, this.#sendDirection, this.config, authorization, refs[1]!);
      this.#candidateReceive = this.#candidate.derive(0n, this.#receiveDirection, this.config, authorization, refs[2]!);
    } finally { for (const ref of refs) ref.release(); }
  }
  #receiveRekey(schema: string, body: Uint8Array, packet: RecordPacket, epoch: number): void {
    if (schema === "REKEY_REQUEST") {
      if (this.#sendDirection !== 0 || epoch !== this.#epochNumber) fail("protocol_violation");
      packet.commitValidated();
      if (this.#rekeyRound === undefined) queueMicrotask(() => { void this.rekey().catch(() => undefined); });
      return;
    }
    if (schema === "REKEY_INIT") {
      if (this.#sendDirection !== 1 || epoch !== this.#epochNumber || this.#rekeyRound !== undefined) fail("protocol_violation");
      this.#beginRekey();
      const entries = this.#rekeyRound!.acceptInit(body); this.#registerBarrier(entries);
      this.#chargeRekey(); packet.commitValidated(); this.#phaseDeadline(this.config.streams.rekeyProtocolMS); this.#rekeyStage = "init"; return;
    }
    if (this.#rekeyRound === undefined) fail("protocol_violation");
    this.#checkRekeyDeadlines();
    if (schema === "REKEY_REPLY") {
      if (this.#sendDirection !== 0 || epoch !== this.#epochNumber || this.#rekeyStage !== "init") fail("protocol_violation");
      const entries = this.#rekeyRound.acceptReply(body); this.#registerBarrier(entries); this.#installCandidate();
      packet.commitValidated(); this.#rekeyStage = "reply"; return;
    }
    if (epoch !== this.#epochNumber + 1 || schema === "REKEY_COMMIT" && this.#sendDirection !== 1 || schema === "REKEY_ACK" && this.#sendDirection !== 0) fail("protocol_violation");
    this.#rekeyRound.acceptMarker(body, this.#controlReceive!.frontier().next);
    packet.commitValidated(); this.#receiveSwitched = true;
    if (schema === "REKEY_COMMIT") { this.#rekeyStage = "commit"; this.#phaseDeadline(this.config.streams.rekeyConfirmationMS, "rekey_confirmation"); }
    else { this.#rekeyStage = "ack"; this.#rekeyAnchor = this.config.clock.monotonic(); }
  }
  async #progressRekey(): Promise<void> {
    if (this.#closed || this.#rekeyRound === undefined || this.#rekeyWorking || !this.output.available() ||
        this.#sendDirection === 0 && this.#rekeyStage !== "reply" && this.#rekeyStage !== "ack" ||
        this.#sendDirection === 1 && this.#rekeyStage !== "init" && this.#rekeyStage !== "commit") return;
    this.#rekeyWorking = true;
    try {
      // Peer records may advance the round before a native send releases its
      // output tail. Recheck the original round after each completion while
      // retaining this single progress owner; the receive wake cannot start a
      // second owner while it is working.
      while (this.#rekeyRound !== undefined && this.output.available()) {
        this.#checkRekeyDeadlines();
        if (!this.#barrierSatisfied() || this.#unreliable?.pendingOutput() === true) return;
        if ([...this.#nativeAssociations].some(association => association.output.pending())) return;
        if (this.#sendDirection === 1 && this.#rekeyStage === "init") {
          const body = this.#rekeyRound.buildReply(this.#localFrozen); this.#installCandidate();
          await this.output.record(this.#controlSend!, frameType("REKEY"), body, () => { this.#rekeyStage = "reply"; });
        } else if (this.#sendDirection === 0 && this.#rekeyStage === "reply" || this.#sendDirection === 1 && this.#rekeyStage === "commit") {
          const server = this.#sendDirection === 1, body = this.#rekeyRound.buildMarker(this.#controlSend!.frontier().next);
          await this.output.record(this.#candidateSend!, frameType("REKEY"), body, () => {
            this.#sendSwitched = true; this.#rekeyStage = server ? "ack" : "commit";
            if (server) this.#rekeyAnchor = this.config.clock.monotonic(); else this.#phaseDeadline(this.config.streams.rekeyConfirmationMS, "rekey_confirmation");
          });
          if (server) this.#completeRekey();
        } else if (this.#sendDirection === 0 && this.#rekeyStage === "ack") this.#completeRekey();
        else return;
      }
    } catch (error) { void this.close().catch(() => undefined); throw error; }
    finally {
      this.#rekeyWorking = false; for (const wake of this.#waiters) wake();
      void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
    }
  }
  #completeRekey(): void {
    this.#check(); if (!this.#sendSwitched || !this.#receiveSwitched || this.#candidate === undefined) fail("protocol_violation");
    const next = this.#candidate, old = this.epoch;
    // Candidate keys are reserved before replacing any direction. The old
    // receive ring and delivery owner retain offsets and private cursor bytes.
    for (const [scope, binding] of this.#bindings) {
      if (!["live", "local_opening", "peer_pending"].includes(this.#open!.phase(binding.handle))) continue;
      const refs: ResourceReference[] = [];
      try {
        const authorization: RecordAuthorization = { check: (frame, header, direction) => {
          this.#check(); this.#open!.authorize(binding.handle, frame, direction);
          this.config.streams.authorization.check(frame, header, direction);
          this.#checkBootstrapTicket(binding.handle, frame, direction);
        } };
        if (binding.terminalReceive !== undefined || binding.quarantined) binding.cipher.close();
        if (binding.terminalSend !== undefined) binding.send?.close();
        if (binding.terminalReceive === undefined && !binding.quarantined) {
          const reference = binding.receiveKeys.checkout(); refs.push(reference);
          const cipher = next.derive(scope, this.#receiveDirection, this.#cipherConfig(this.#receiveDirection), authorization, reference, binding.receiveKeys.usage);
          binding.direction?.replaceCipher(cipher); binding.cipher.close(); binding.cipher = cipher; binding.nextReceive = 0n;
        }
        if (binding.terminalSend === undefined && binding.send !== undefined) {
          const reference = binding.sendKeys!.checkout(); refs.push(reference);
          const cipher = next.derive(scope, this.#sendDirection, this.#cipherConfig(this.#sendDirection), authorization, reference, binding.sendKeys!.usage);
          binding.send.close(); binding.send = cipher; binding.nextSend = 0n;
        }
      } finally { for (const ref of refs) ref.release(); }
    }
    this.#controlSend!.close(); this.#controlReceive!.close();
    this.epoch = next; this.#epochNumber++; this.#open!.completeRekey(this.#epochNumber);
    this.#controlSend = this.#candidateSend; this.#controlReceive = this.#candidateReceive;
    this.#candidate = undefined; this.#candidateSend = undefined; this.#candidateReceive = undefined;
    this.#unreliable?.replaceEpoch(next, this.#epochNumber);
    old.close(); this.#rekeyRetired = this.#rekeyRetired.filter(epoch => !epoch.cleanupComplete()); this.#rekeyRetired.push(old);
    this.#rekeyBase = this.#rekeyPost; this.#rekeyRound!.close(); this.#rekeyRound = undefined; this.#rekeyStage = "idle";
    this.#rekeyCharged = false; this.#sendSwitched = this.#receiveSwitched = false; this.#peerBarrier = []; this.#localFrozen = []; this.#rekeyRequest = undefined;
    this.#diagnostic({ state: "ready", phase: this.#diagnosticRekeyPhase, code: "ok", duration_bucket: diagnosticDuration(this.#diagnosticPhaseStarted) }, "rekey_phase_completed");
    this.#diagnostic({ state: "ready", phase: "rekey_switch", code: "ok", duration_bucket: diagnosticDuration(this.#diagnosticRekeyStarted ?? performance.now()) }, "rekey_succeeded");
    this.#diagnosticRekeyStarted = undefined;
    this.#collectRetiredProofs();
    if (this.#rekeyTimer !== undefined) clearTimeout(this.#rekeyTimer); this.#rekeyTimer = undefined;
    this.#rekeyDeadline = this.#rekeyPhaseDeadline = this.#rekeySafetyDeadline = undefined; this.#rekeyIntent = false; this.#liveness!.endRekey(true); this.#wake();
  }
  #batchDigest(body: Uint8Array, proposer: RecordDirection, destination: Uint8Array): void {
    const spec = wireDomains.find(item => item.name === "retirement_batch_digest");
    if (spec === undefined || spec.operation !== "sha256") fail("configuration_capacity");
    const label = Uint8Array.from(spec.label_bytes.match(/../gu)!.map(x => Number.parseInt(x, 16)));
    const profile = new TextEncoder().encode(this.config.ledger.profile), prefix = new Uint8Array(4), role = Uint8Array.of(proposer);
    const hash = sha256.create();
    const length = (bytes: Uint8Array): void => {
      let n = byteLength(bytes); for (let i = 3; i >= 0; i--) { prefix[i] = n % 256; n = Math.floor(n / 256); }
      hash.update(prefix).update(bytes);
    };
    try { hash.update(label); length(this.#handshakeHash); length(profile); hash.update(role); length(body); hash.digestInto(destination); }
    finally { hash.destroy(); prefix.fill(0); }
  }
  #proofComplete(binding: ReceiveBinding): boolean {
    if (binding.rejectionPending !== undefined) return false;
    const phase = this.#open!.phase(binding.handle);
    return phase === "rejected" || phase === "recent" && binding.receiveDrained && binding.sendDrained;
  }
  #physicalComplete(binding: ReceiveBinding, includeAdapter = true): boolean {
    return (binding.handle !== this.#bootstrap || this.#bootstrapTask === undefined) && binding.native?.cleanupComplete() !== false && (!includeAdapter || !binding.adapterActive) && binding.write === undefined && binding.termination === undefined && binding.acknowledging === undefined && binding.draining === undefined && binding.cipher.cleanupComplete() &&
      binding.send?.cleanupComplete() !== false && binding.direction?.cleanupStatus().status !== "pending";
  }
  #retirementFence(ids: readonly bigint[]): boolean {
    if (this.#rekeyRound === undefined) return true;
    const published = this.#sendDirection === 0 ? this.#rekeyStage !== "idle" : this.#rekeyStage !== "idle" && this.#rekeyStage !== "init";
    return published || !ids.some(scope => this.#localFrozen.some(entry => entry.scope === scope));
  }
  #retirementBatch(sequence: bigint, ids: readonly bigint[], digest = new Uint8Array(32)): RetirementBatch {
    const batch = { sequence, ids, digest, deadline: this.#deadline(), submitted: false, writing: false, done: false };
    for (const scope of ids) {
      const binding = this.#bindings.get(scope)!;
      binding.retirementReferences = (binding.retirementReferences ?? 0) + 1;
    }
    return batch;
  }
  #commitRetirement(batch: RetirementBatch): void {
    for (const scope of batch.ids) {
      const binding = this.#bindings.get(scope)!;
      this.#open!.retire(binding.handle, true); binding.retired = true;
    }
    batch.done = true;
  }
  #releaseRetirement(batch: RetirementBatch): void {
    for (const scope of batch.ids) {
      const binding = this.#bindings.get(scope)!;
      if (!binding.retirementReferences) fail("protocol_violation");
      binding.retirementReferences--;
    }
    batch.digest.fill(0); this.#collectRetiredProofs();
  }
  #collectRetiredProofs(): void {
    if (this.#closed) return;
    for (const [scope, binding] of this.#bindings) {
      if (!binding.retired || binding.retirementReferences || !this.#physicalComplete(binding) ||
          this.#localFrozen.some(entry => entry.scope === scope) || this.#peerBarrier.some(entry => entry.scope === scope)) continue;
      // Stable is a logical fence. The original slot and complete proof remain
      // charged while an already registered barrier or batch still owns them.
      this.#releaseStream(binding); this.#open!.releaseRetired(binding.handle); this.#bindings.delete(scope);
    }
  }
  async #retirement(): Promise<void> {
    if (this.#closed || this.#retireWorking) return;
    this.#retireWorking = true;
    let progressed = false;
    try {
      const incoming = this.#retireIn;
      if (incoming !== undefined && this.#retirementFence(incoming.ids) && incoming.ids.every(scope => {
        const binding = this.#bindings.get(scope); return binding !== undefined && this.#proofComplete(binding) && this.#physicalComplete(binding);
      })) {
        incoming.writing = true;
        try {
          await this.#control(frameType("STREAM_ACK"), writer => {
            // Waiting for output can overlap a newly frozen local barrier.
            // Do not acquire a ticket until that exact snapshot is published.
            if (!this.#retirementFence(incoming.ids)) return undefined;
            return writer.map(3).uint(0).uint(6).uint(1).uint(incoming.sequence).uint(2).data(incoming.digest).result();
          }, () => {
            incoming.submitted = true; this.#lastRetireReceived = incoming.sequence;
            copy.call(this.#lastRetireReceivedDigest, incoming.digest);
            this.#commitRetirement(incoming);
            // The next batch can arrive as soon as the peer sees this ACK.
            // One original publication tail retains these proof references;
            // the single driver cannot ACK another batch until it exits.
            this.#retireIn = undefined; this.#retireTail = incoming;
          }, incoming.deadline);
        } finally { incoming.writing = false; }
        if (this.#closed) return;
        if (incoming.submitted) {
          this.#retireTail = undefined; this.#releaseRetirement(incoming); progressed = true;
        }
      }
      if (this.#closed) return;
      if (this.#retireOut === undefined) {
        const ids: bigint[] = [];
        for (const [scope, binding] of this.#bindings) {
          if ((scope + 1n) % 2n === BigInt(this.#sendDirection) && this.#proofComplete(binding) && this.#physicalComplete(binding) && !binding.retiring) ids.push(scope);
          if (ids.length === 1024) break;
        }
        if (ids.length === 0) return;
        if (this.#lastRetireSent === (1n << 64n) - 1n) fail("protocol_violation");
        ids.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
        this.#retireOut = this.#retirementBatch(this.#lastRetireSent + 1n, ids);
        for (const scope of ids) this.#bindings.get(scope)!.retiring = true;
      }
      const batch = this.#retireOut;
      if (batch.submitted || !this.#retirementFence(batch.ids)) return;
      batch.writing = true;
      try {
        await this.#control(frameType("STREAM_ACK"), writer => {
          if (!this.#retirementFence(batch.ids)) return undefined;
          writer.map(3).uint(0).uint(5).uint(1).uint(batch.sequence).uint(2).array(batch.ids.length);
          for (const scope of batch.ids) writer.uint(scope);
          const body = writer.result(); this.#batchDigest(body, this.#sendDirection, batch.digest); return body;
        }, () => { batch.submitted = true; }, batch.deadline);
      } finally { batch.writing = false; }
      if (this.#closed) return;
      if (batch.done) { this.#retireOut = undefined; this.#releaseRetirement(batch); progressed = true; }
    } finally {
      this.#retireWorking = false; this.#cleanup();
      // A successful publication may have unlocked one original pending
      // batch while its provider tail was still running. A fence miss does
      // not queue polling work; rekey publication supplies its actual wake.
      if (progressed && !this.#closed) void this.#retirement().catch(() => { void this.close().catch(() => undefined); });
    }
  }
  #receiveRetirement(schema: string, document: CBORDocument, packet: RecordPacket): void {
    const sequence = document.uint(document.field(0, 1));
    if (schema === "STREAM_ACK_RETIRE_ACK") {
      document.copyPayload(document.field(0, 2), this.#retireDigest);
      if (sequence <= this.#lastRetireSent) {
        if (sequence === this.#lastRetireSent && !equalBytes(this.#retireDigest, this.#lastRetireSentDigest)) fail("protocol_violation");
        packet.commitValidated(); return;
      }
      const batch = this.#retireOut;
      if (batch === undefined || !batch.submitted || sequence !== batch.sequence || !equalBytes(this.#retireDigest, batch.digest)) fail("protocol_violation");
      batch.deadline.check();
      for (const scope of batch.ids) { const binding = this.#bindings.get(scope); if (binding === undefined || !this.#proofComplete(binding) || !this.#physicalComplete(binding)) fail("protocol_violation"); }
      packet.commitValidated(); this.#lastRetireSent = sequence; copy.call(this.#lastRetireSentDigest, batch.digest);
      this.#commitRetirement(batch);
      if (!batch.writing) { this.#retireOut = undefined; this.#releaseRetirement(batch); }
      this.#wake(); return;
    }
    const bytes = document.copyEncoded(0, this.#retireScratch); this.#batchDigest(byteSlice(this.#retireScratch, 0, bytes), this.#receiveDirection, this.#retireDigest);
    if (sequence < this.#lastRetireReceived) { packet.commitValidated(); return; }
    if (sequence === this.#lastRetireReceived) {
      if (!equalBytes(this.#retireDigest, this.#lastRetireReceivedDigest)) fail("protocol_violation");
      packet.commitValidated();
      if (this.#retireIn === undefined) this.#retireIn = this.#retirementBatch(sequence, [], new Uint8Array(this.#retireDigest));
      return;
    }
    if (sequence !== this.#lastRetireReceived + 1n) fail("protocol_violation");
    if (this.#retireIn !== undefined) {
      if (this.#retireIn.sequence !== sequence || !equalBytes(this.#retireIn.digest, this.#retireDigest)) fail("protocol_violation");
      packet.commitValidated(); return;
    }
    const ids: bigint[] = [], list = document.field(0, 2);
    for (let node = document.firstChild(list); node >= 0; node = document.nextSibling(node)) {
      const scope = document.uint(node), binding = this.#bindings.get(scope);
      if ((scope + 1n) % 2n !== BigInt(this.#receiveDirection) || binding === undefined || this.#open!.isStable(scope)) fail("protocol_violation");
      ids.push(scope);
    }
    const batch = this.#retirementBatch(sequence, ids, new Uint8Array(this.#retireDigest));
    packet.commitValidated(); this.#retireIn = batch;
  }
  receiveNext(options?: OperationOptions): Promise<void> {
    if (this.#closed) return Promise.reject(new V4SessionAssemblyError("closed"));
    if (this.#receiving !== undefined) return Promise.reject(new V4SessionAssemblyError("busy"));
    const signal = options?.signal === undefined ? this.#abort.signal : AbortSignal.any([options.signal, this.#abort.signal]);
    const operation = this.#receive(signal);
    this.#receiving = operation;
    void operation.then(() => { this.#receiving = undefined; this.#cleanup(); }, () => { this.#receiving = undefined; this.#cleanup(); });
    return operation;
  }
  async #receive(signal: AbortSignal): Promise<void> {
    let frame: EnvelopeFrame | undefined;
    try {
      frame = await this.reader.next({ signal }) ?? undefined;
      if (frame === undefined) throw nativeConnectionEnded(new V4SessionAssemblyError("carrier_failed"));
      await this.#receiveFrame(frame);
    } catch (error) {
      this.#observeControllerFailure(error);
      void this.close().catch(() => undefined); throw error;
    }
    finally { frame?.release(); this.#wake(); }
  }
  async #receiveFrame(frame: EnvelopeFrame, native?: NativeAssociation): Promise<void> {
    let packet: RecordPacket | undefined;
    let fixedPrefix = false;
    try {
      const header = frame.recordHeader(this.config.ledger.profile);
      fixedPrefix = this.#info.application_profile !== "transport" && header.scope === BigInt(bootstrapSpec.scope) && header.frameType === frameType("OPEN_STREAM");
      this.#check();
      if (this.#nativeScheduler !== undefined && (native === undefined ? header.scope !== 0n : header.scope === 0n ||
          native.scope !== undefined && native.scope !== header.scope || native.scope === undefined && header.frameType !== frameType("OPEN_STREAM"))) fail("protocol_violation");
      if (header.scope === 0n) {
        const candidate = header.epoch === this.#epochNumber + 1;
        if (candidate) {
          if (this.#candidateReceive === undefined || !this.#sendSwitched && this.#sendDirection === 0 ||
              !this.#receiveSwitched && (header.frameType !== frameType("REKEY") || header.sequence !== 0n)) fail("protocol_violation");
        } else if (header.epoch !== this.#epochNumber || this.#receiveSwitched) fail("protocol_violation");
        packet = (candidate ? this.#candidateReceive! : this.#controlReceive!).open(frame);
        packet.observeValidation(() => this.#idle!.activity());
        await this.#maintenance(header.frameType, packet, candidate ? this.#candidateReceive! : this.#controlReceive!);
        return;
      }
      if (header.epoch === this.#epochNumber + 1 && this.#sendSwitched && this.#receiveSwitched) {
        // Both markers authorize the peer's new epoch before our COMMIT/ACK
        // provider releases its output borrow. Keep this bounded input with
        // its original reader until the rekey owner installs the new keys.
        const awaitSwitch = async (): Promise<void> => {
          while (header.epoch === this.#epochNumber + 1) {
            this.#checkRekeyDeadlines();
            await this.#wait(this.#rekeyDeadline!, this.#abort.signal);
          }
        };
        if (native === undefined) await this.#readerWait(awaitSwitch);
        else await awaitSwitch();
      }
      let binding = this.#bindings.get(header.scope);
      if (header.frameType === frameType("OPEN_STREAM")) {
        if (fixedPrefix) {
          if (binding === undefined || binding.handle !== this.#bootstrap || this.#sendDirection !== 1 ||
              binding.native !== undefined || native?.scope !== undefined || header.sequence !== 0n ||
              header.epoch !== this.#epochNumber || this.#receiveSwitched || binding.nextReceive !== 0n ||
              binding.receiveDrained || binding.terminalReceive?.next === 0n) fail("protocol_violation");
          packet = binding.cipher.open(frame); packet.observeValidation(() => this.#idle!.activity());
          this.#open!.receiveBootstrap(binding.handle, binding.cipher, packet); binding.nextReceive = 1n;
          if (native !== undefined) {
            binding.native = native; native.scope = header.scope;
            native.bounds = new StreamDataBounds(header.scope, this.#receiveDirection, this.config.ledger.profile, this.config.maxFrame);
            native.reader.bindData(native.bounds); native.outcome(); this.#nativeScheduler!.capacityAvailable();
          }
          this.#finishBootstrapInitialization();
          return;
        }
        if (binding !== undefined || native?.scope !== undefined || header.sequence !== 0n || header.epoch !== this.#epochNumber || this.#receiveSwitched ||
            this.#bindings.size >= this.config.streams.limits.terminalCapacity + this.config.streams.limits.ingressItems + 1) fail("protocol_violation");
        const handle = this.#open!.reservePeer(header.scope, header.epoch);
        const keyConfig = this.#cipherConfig(this.#receiveDirection);
        const initial = this.config.streams.peerOpenPreparation?.take(this.#reservation!);
        let fallbackKind: string | undefined, fallbackChannel: Parameters<SessionKeyPreparation["exchangeReceive"]>[0] | undefined;
        let protectedSlots: readonly ProtectedResourceReservation[] | undefined;
        let refs: readonly ResourceReference[] = [], usage: CryptoKeyPositions | undefined = initial?.usage;
        try {
          refs = initial?.references ?? this.#reserve(header.scope, ["v4_receive_key_0", "v4_receive_key_1"], [directionKeyCharge(keyConfig), directionKeyCharge(keyConfig)]);
          usage ??= this.config.ledger.prepareKeyPositions(this.#receiveDirection, refs[0]!);
        } catch (error) {
          for (const reference of refs) reference.release(); usage?.close(); usage = undefined;
          if (!(error instanceof ResourceError) && !(error instanceof RecordCryptoError && error.code === "crypto_busy")) throw error;
          // Authenticate one bounded contender with an internal receive floor.
          // Only its own channel can retain that floor after classification.
          const notify = this.#receiveDirection;
          if (this.#managementReceivePositions.length === 2 && this.#managementReceivePositions.every(position => position.available()) &&
              this.#internalKeys!.available("management", "receive")) {
            protectedSlots = this.#managementReceivePositions; fallbackKind = managementSpec.kind;
            fallbackChannel = "management";
            usage = this.#internalKeys!.checkout("management", "receive");
          } else if (this.#notifyPositions[notify]!.length !== 0 && this.#notifyPositions[notify]!.slice(0, 2).every(position => position.available()) &&
              this.#internalKeys!.available(`notify_${notify}`, "receive")) {
            protectedSlots = this.#notifyPositions[notify]!.slice(0, 2); fallbackKind = notifySpec.kind;
            fallbackChannel = `notify_${notify}`;
            usage = this.#internalKeys!.checkout(`notify_${notify}`, "receive");
          } else {
            const start = this.#receiveDirection * 4;
            const position = this.#rpcPositions.findIndex((slots, index) => index >= start && index < start + 4 &&
              this.#rpcHandles[index] === undefined && this.#rpcTasks[index] === undefined && slots.length === 10 &&
              slots.slice(0, 2).every(slot => slot.available()) && this.#internalKeys!.available(this.#rpcKey(index), "receive"));
            if (position < 0) throw error;
            protectedSlots = this.#rpcPositions[position]!.slice(0, 2); fallbackKind = bootstrapSpec.kind; fallbackChannel = this.#rpcKey(position);
            usage = this.#internalKeys!.checkout(fallbackChannel, "receive");
          }
          const checked: ResourceReference[] = [];
          try { for (const position of protectedSlots) checked.push(position.checkout()); refs = checked; }
          catch (error) { for (const reference of checked) reference.release(); usage.close(); throw error; }
        }
        let receiveKeys: DirectionKeyPositions | undefined;
        try {
          receiveKeys = new DirectionKeyPositions(this.config.streams.root, keyConfig, refs, this.config.ledger, header.scope, this.#receiveDirection, protectedSlots, usage);
          binding = { handle, receiveKeys, cipher: this.#cipher(handle, this.#receiveDirection, receiveKeys), nextReceive: 0n, sendDrained: false, receiveDrained: false, stopPending: false, receiveAbandon: false, retiring: false, quarantined: false, nextSend: 0n, sentOffset: 0n, acknowledged: 0n, sendLimit: 0n, sendFIN: false };
          this.#bindings.set(header.scope, binding);
        } catch (error) { receiveKeys?.close(); usage?.close(); throw error; }
        finally { for (const ref of refs) ref.release(); }
        packet = binding.cipher.open(frame);
        packet.observeValidation(() => this.#idle!.activity());
        const outcome = this.#open!.receivePeer(handle, binding.cipher, packet); binding.nextReceive = 1n;
        if (outcome === "rejected" || fallbackKind !== undefined && !this.#assignInternalReceive(binding, fallbackChannel!)) binding.rejectionPending = 1;
        if (outcome === "pending" && this.#open!.kind(handle) === bootstrapSpec.kind && this.#rpc === undefined) binding.rejectionPending = 2;
        if (outcome === "pending" && this.#open!.kind(handle) === managementSpec.kind &&
            (this.#info.application_profile !== "execution" || this.#sendDirection !== 1 || this.#managementHandle !== undefined || this.#managementStopped)) binding.rejectionPending = 2;
        if (native !== undefined) {
          native.scope = header.scope; binding.native = native;
          native.bounds = new StreamDataBounds(header.scope, this.#receiveDirection, this.config.ledger.profile, this.config.maxFrame);
          native.reader.bindData(native.bounds); this.#nativeScheduler!.capacityAvailable();
        }
        if (binding.rejectionPending !== undefined) { binding.cipher.close(); if (fallbackKind !== undefined) binding.receiveKeys.close(); this.#driveRejections(); }
        return;
      }
      if (header.frameType === frameType("STREAM_DATA") && this.#open!.isStable(header.scope)) {
        if (header.epoch > this.#epochNumber) fail("protocol_violation"); return;
      }
      if (header.frameType === frameType("STREAM_DATA") && binding !== undefined &&
          (binding.receiveDrained || binding.quarantined || this.#open!.phase(binding.handle) === "rejected")) {
        if (header.epoch > this.#epochNumber) fail("protocol_violation"); return;
      }
      if (header.frameType !== frameType("STREAM_DATA") || binding?.direction === undefined || this.#open!.phase(binding.handle) !== "live") fail("protocol_violation");
      packet = binding.cipher.open(frame);
      native?.reader.beginAuthentication();
      packet.observeValidation(() => this.#idle!.activity());
      try { binding.direction.accept(packet, binding.terminalReceive?.offset); binding.nextReceive++; }
      catch {
        if (native !== undefined) { this.#isolateNativeInput(native); return; }
        // The shared envelope is authenticated to this existing scope. Seal its
        // receive direction permanently and retain the original promise until
        // STOPPED/DRAINED closes the authenticated abandoned frontier.
        binding.quarantined = true; binding.receiveAbandon = true;
        binding.direction.abandonDelivery(); binding.cipher.close();
        binding.stream?.invalidateAdapter();
        this.#beginTermination(binding, true, true);
        return;
      }
      const progress = binding.direction.progress();
      if (progress.fin_offset === undefined) void this.acknowledgeReceive(binding.handle).catch(() => { void this.close().catch(() => undefined); });
      if (progress.fin_offset !== undefined) {
        binding.terminalReceive = { epoch: header.epoch, next: binding.nextReceive, offset: progress.fin_offset };
        binding.stream?.notifyAdapterInput();
        if (native === undefined) await this.#readerWait(() => this.#drained(binding, binding!.receiveAbandon));
        else void this.#drained(binding, binding.receiveAbandon).catch(() => { void this.close().catch(() => undefined); });
      }
    } catch (error) {
      if (error instanceof OpenAdmissionError && error.code === "open_capacity" || error instanceof ResourceError && error.code === "resource_exhausted") {
        this.#resourceFailure(error instanceof ResourceError); throw error;
      }
      if (!fixedPrefix && native !== undefined && this.#isolateNativeInput(native)) return;
      this.#observeControllerFailure(error);
      void this.close().catch(() => undefined); throw error;
    }
    finally { packet?.release(); frame?.release(); this.#wake(); }
  }
  async #readerWait(work: () => Promise<void>): Promise<void> {
    this.#readBlocked = true; this.#liveness!.localStall();
    try { await work(); } finally { this.#readBlocked = false; this.#wake(); }
  }
  async #maintenance(type: number, packet: RecordPacket, cipher: RecordCipher): Promise<void> {
    let document: CBORDocument | undefined, pong = false, stopped: ReceiveBinding | undefined, drain: ReceiveBinding | undefined;
    try {
      const info = cipher.inspectIncoming(packet);
      if (info.scope !== 0n || info.direction !== this.#receiveDirection || info.frameType !== type) fail("protocol_violation");
      const size = packet.copyBytes(this.#plain), body = byteSlice(this.#plain, 0, size);
      let schema: string;
      if (type === frameType("STREAM_ACK")) {
        document = this.#controlDecoder!.decode(body);
        if (document.kind() !== "map") fail("protocol_violation");
        const accept = document.field(0, 10), variant = accept >= 0 ? 1 : Number(document.uint(document.field(0, 0)));
        schema = ["STREAM_ACK_CREDIT", "OPEN_ACCEPT", "STREAM_ACK_STOP", "STREAM_ACK_STOPPED", "STREAM_ACK_DRAINED", "STREAM_ACK_RETIRE_BATCH", "STREAM_ACK_RETIRE_ACK"][variant] ?? "";
        document.release(); document = undefined;
        if (schema === "") fail("protocol_violation");
      } else {
        schema = ["PING", "PONG", "GOAWAY", "CLOSE", "ERROR"].find(name => type === frameType(name)) ?? "";
        if (type === frameType("REKEY")) {
          document = this.#controlDecoder!.decode(body);
          const phase = Number(document.uint(document.field(0, 0))); document.release(); document = undefined;
          schema = ["REKEY_REQUEST", "REKEY_INIT", "REKEY_REPLY", "REKEY_COMMIT", "REKEY_ACK"][phase] ?? "";
        }
        if (schema === "") fail("protocol_violation");
      }
      document = this.#controlDecoder!.decodeMap(body, schema, { selectors: { crypto_profile_id: this.config.ledger.profile } });
      if (schema.startsWith("REKEY_")) { this.#receiveRekey(schema, body, packet, info.epoch); return; }
      if (schema === "OPEN_ACCEPT") {
        if (this.#goaway !== undefined && document.uint(document.field(0, 2)) === 0n && document.uint(document.field(0, 0)) > this.#goaway.ceiling) fail("protocol_violation");
        const handle = this.#open!.receiveResult(document, packet), scope = this.#open!.snapshot(handle).scope;
        const binding = this.#bindings.get(scope); if (binding?.handle !== handle) fail("protocol_violation");
        binding.native?.outcome();
        if (this.#open!.phase(handle) === "rejected") { binding.direction?.close(); binding.cipher.close(); binding.send?.close(); binding.native?.reject(); }
        else {
          binding.sendLimit = this.#open!.peerLimit(handle);
          this.#nativeOutputFailed(binding);
          if (binding.native?.inputEnded) this.#nativeInputEnded(binding.native);
        }
        return;
      }
      if (schema === "STREAM_ACK_CREDIT") {
        const scope = document.uint(document.field(0, 1)), direction = document.uint(document.field(0, 2));
        const binding = this.#bindings.get(scope), ack = document.uint(document.field(0, 3)), limit = document.uint(document.field(0, 4));
        if (direction !== BigInt(this.#sendDirection) || binding === undefined || this.#open!.phase(binding.handle) !== "live" ||
            ack > binding.sentOffset || limit < ack) fail("protocol_violation");
        if (ack <= binding.acknowledged && limit <= binding.sendLimit) { packet.commitValidated(); return; }
        if (ack < binding.acknowledged || limit < binding.sendLimit) fail("protocol_violation");
        packet.commitValidated(); binding.acknowledged = ack; binding.sendLimit = limit; return;
      }
      if (schema === "STREAM_ACK_RETIRE_BATCH" || schema === "STREAM_ACK_RETIRE_ACK") {
        this.#receiveRetirement(schema, document, packet); return;
      }
      if (schema === "STREAM_ACK_STOP" || schema === "STREAM_ACK_STOPPED" || schema === "STREAM_ACK_DRAINED") {
        const scope = document.uint(document.field(0, 1)), direction = Number(document.uint(document.field(0, 2))), binding = this.#bindings.get(scope);
        if (binding === undefined || !["live", "recent"].includes(this.#open!.phase(binding.handle))) fail("protocol_violation");
        if (schema === "STREAM_ACK_STOP") {
          if (direction !== this.#sendDirection) fail("protocol_violation");
          binding.write?.terminate(); binding.stopPending = true; stopped = binding;
        } else if (schema === "STREAM_ACK_STOPPED") {
          if (direction !== this.#receiveDirection) fail("protocol_violation");
          const terminal = { epoch: Number(document.uint(document.field(0, 3))), next: document.uint(document.field(0, 4)), offset: document.uint(document.field(0, 5)) };
          if (terminal.offset > binding.direction!.progress().receive_limit || (binding.terminalReceive !== undefined ? !sameTuple(binding.terminalReceive, terminal) :
              terminal.epoch !== this.#epochNumber || terminal.next < binding.nextReceive || terminal.offset < binding.direction!.progress().ack_offset)) fail("protocol_violation");
          // Normal proof already submitted is irreversible. A crossing
          // STOPPED cannot replace it or discard the application's unread FIN.
          if (binding.receiveDrained) { packet.commitValidated(); return; }
          binding.receiveAbandon = true; this.#clearAckTimer(binding); binding.ackDirty = false; binding.direction!.abandonDelivery();
          binding.terminalReceive = terminal; drain = binding;
        } else {
          if (direction !== this.#sendDirection || binding.terminalSend === undefined) fail("protocol_violation");
          const terminal = readTuple(document, document.field(0, 3)), observed = readTuple(document, document.field(0, 5));
          if (!sameTuple(terminal, binding.terminalSend) || observed.epoch !== terminal.epoch || observed.next > terminal.next || observed.offset > terminal.offset ||
              document.uint(document.field(0, 4)) === 0n && !sameTuple(terminal, observed)) fail("protocol_violation");
          const aborted = document.uint(document.field(0, 4)) !== 0n;
          if (binding.sendDrained && binding.sendAborted !== aborted) fail("protocol_violation");
          binding.sendAborted = aborted; binding.sendDrained = true;
          // Only an actual observed frontier proves peer authentication.
          if (!aborted) binding.acknowledged = terminal.offset;
        }
        packet.commitValidated();
        if (stopped === undefined && drain === undefined) { this.#terminal(binding); return; }
      } else if (schema === "PING") { document.copyPayload(document.field(0, 0), this.#nonce); pong = true; }
      else if (schema === "PONG") {
        document.copyPayload(document.field(0, 0), this.#nonce);
        packet.commitValidated();
        this.#liveness!.pong(this.#nonce, info.epoch);
        this.#nonce.fill(0); return;
      }
      else if (schema === "GOAWAY") {
        const ceiling = document.uint(document.field(0, 0)), reason = document.uint(document.field(0, 1));
        if (ceiling !== 0n && ((ceiling + 1n) % 2n !== BigInt(this.#sendDirection) ||
            ceiling > BigInt(this.#sendDirection === 0 ? wire.streams.client_ordinals : wire.streams.server_ordinals) * 2n) ||
            this.#goaway !== undefined && (this.#goaway.ceiling !== ceiling || this.#goaway.reason !== reason)) fail("protocol_violation");
        if (ceiling < this.#open!.highestAccepted(true)) fail("protocol_violation");
        this.#goaway = { ceiling, reason };
        // A peer GOAWAY is an application drain boundary too. Reuse the
        // original RPC/Notify owners so accepted tails can finish while the
        // Management lane retains its existing owner and deadline.
        this.#rpc?.peerGoaway();
      } else if (schema === "ERROR") {
        const code = Number(document.uint(document.field(0, 0))), scope = document.uint(document.field(0, 1));
        const codes = table<Record<string, number>>("error_codes")!, metadata = table<Record<string, { action: string; scope: string }>>("error_code_metadata")!;
        const name = Object.keys(codes).find(name => codes[name] === code), action = name === undefined ? undefined : metadata[name];
        if (action === undefined) fail("protocol_violation");
        const binding = scope === 0n ? undefined : this.#bindings.get(scope);
        if (action.scope === "stream" && (binding === undefined || !["live", "recent"].includes(this.#open!.phase(binding.handle)))) fail("protocol_violation");
        packet.commitValidated();
        if (action.action === "close_session") void this.close().catch(() => undefined);
        else if (action.action === "reset_stream") {
          binding!.write?.terminate(); binding!.receiveAbandon = true;
          void this.closeStream(binding!.handle).catch(() => { void this.close().catch(() => undefined); });
        } else if (action.action !== "none") fail("protocol_violation");
        return;
      } else if (schema === "CLOSE") {
        const scope = document.uint(document.field(0, 1));
        if (scope !== 0n && this.#bindings.get(scope) === undefined) fail("protocol_violation");
        packet.commitValidated();
        if (scope === 0n) {
          if (this.#drain !== undefined && document.uint(document.field(0, 0)) === 0n && this.#communicationDrained()) this.#drain.finish("drained");
          void this.close().catch(() => undefined);
        }
        else {
          const binding = this.#bindings.get(scope)!;
          void this.closeStream(binding.handle).catch(() => { void this.close().catch(() => undefined); });
        }
        return;
      } else throw new V4SessionAssemblyError("runtime_unavailable", "record_dispatch");
      if (stopped === undefined && drain === undefined) packet.commitValidated();
    } finally { document?.release(); packet.release(); this.#plain.fill(0); }
    if (stopped !== undefined) {
      if (!stopped.sendDrained) {
        stopped.stream?.notifyAdapterSendStopped();
        this.#beginTermination(stopped, false);
      }
    }
    if (drain !== undefined) {
      if (drain.handle === this.#bootstrap && this.#receiveDirection === 0 && drain.terminalReceive?.next === 0n &&
          !this.#open!.bootstrapBound(drain.handle)) {
        // The client has authenticated that no prefix can ever materialize.
        // Close the unbound reverse zero frontier through the same proofs.
        this.#cancelBootstrapInitialization(); this.#beginTermination(drain, false);
      }
      if (this.#nativeScheduler === undefined) await this.#readerWait(() => this.#drained(drain!, true));
      else void this.#drained(drain, true).catch(() => { void this.close().catch(() => undefined); });
    }
    if (pong) {
      // The single ingress owner keeps the nonce while the original control
      // gate waits for current output capacity. A previous tail completing
      // does not reserve that position against concurrent Stream termination.
      this.#readBlocked = true; this.#liveness!.localStall();
      try { await this.#control(frameType("PONG"), writer => writer.map(1).uint(0).data(this.#nonce).result()); }
      finally { this.#readBlocked = false; this.#nonce.fill(0); }
    }
  }

  waitTermination(options?: OperationOptions): Promise<void> {
    if (this.#closed) return this.#failure === undefined ? Promise.resolve() : Promise.reject(this.#failure);
    if (options?.signal?.aborted) return Promise.reject(new Error("canceled"));
    if (this.#terminationWaiters.size >= 32) return Promise.reject(new Error("resource_exhausted"));
    const reference = this.#reserve(++this.#nextWait, ["v4_termination_wait"], [new ResourceVector([
      this.config.runtimeBytes + 256n, 0n, 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n,
    ])])[0]!;
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (): void => {
        if (done) return; done = true;
        this.#terminationWaiters.delete(finish); options?.signal?.removeEventListener("abort", finish); reference.release();
        if (!this.#closed) reject(new Error("canceled")); else if (this.#failure !== undefined) reject(this.#failure); else resolve();
      };
      this.#terminationWaiters.add(finish); options?.signal?.addEventListener("abort", finish, { once: true });
      if (options?.signal?.aborted || this.#closed) finish();
    });
  }
  /** One bounded close observation; native work keeps its original owner. */
  close(): Promise<V4LifecycleResult> {
    if (this.#closed) return this.cleanupOwner.closed;
    this.#closeInitializing = true; this.#closed = true;
    this.config.diagnosticActivity?.close();
    this.#cancelBootstrapInitialization();
    this.#drain?.finish("failed");
    if (this.#drainTimer !== undefined) clearTimeout(this.#drainTimer); this.#drainTimer = undefined;
    this.cleanupOwner.startClose(this.#drain);
    this.#unreliable?.close(); if (this.#unreliable === undefined) this.config.unreliablePreparation?.close();
    this.#idle?.close(); this.#liveness?.close(); this.#abort.abort(); this.#wake();
    this.#internalKeys?.close(); this.config.streams.peerOpenPreparation?.close();
    this.#nativeScheduler?.close(); this.#nativeSend?.close(); this.#nativePositions?.close(); this.#maintenancePositions?.close(); this.#sendAccounts?.close(); this.#sendAccount?.close();
    for (const association of this.#nativeAssociations) association.close();
    for (const registration of this.#registrationOwners) { registration.host?.detach(); registration.close(); }
    this.#registrationOwners.clear(); this.#streamRegistrations.clear();
    this.#rpc?.close();
    for (let position = 0; position < 8; position++) if (this.#rpcTasks[position] === undefined) this.#releaseRPCInitialization(position);
    for (const account of this.config.streams.rpcSendAccounts ?? []) account.close();
    for (const position of [0, 1] as const) { if (this.#notifyTasks[position] === undefined) this.#releaseNotifyInitialization(position); this.config.streams.notifySendAccounts?.[position]?.close(); }
    for (const ref of this.#notifyNative?.references ?? []) ref.release(); this.#notifyNative = undefined;
    if (this.#managementTask === undefined) this.#releaseManagementInitialization(); this.config.streams.managementSendAccount?.close(); this.#application?.close();
    for (const finish of this.#terminationWaiters) finish();
    if (this.#authorizationTimer !== undefined) clearTimeout(this.#authorizationTimer); this.#authorizationTimer = undefined;
    if (this.#rekeyTimer !== undefined) clearTimeout(this.#rekeyTimer); this.#rekeyTimer = undefined;
    this.#rekeyRound?.close(); this.#candidateSend?.close(); this.#candidateReceive?.close(); this.#candidate?.close();
    for (const epoch of this.#rekeyRetired) epoch.close();
    for (const binding of this.#bindings.values()) { binding.receiveKeys.close(); binding.sendKeys?.close(); binding.sendAccount?.close(); binding.stream?.endAdapterIO(); this.#clearAckTimer(binding); binding.write?.terminate(); binding.direction?.close(); binding.cipher.close(); binding.send?.close(); }
    this.#controlSend?.close(); this.#controlReceive?.close(); this.#controlDecoder?.close();
    this.epoch.close(); this.config.ledger.close(); this.reader.close(); this.output.close();
    // Actual crypto jobs already own their fixed key references. Retained
    // application callbacks need no parsed credentials or handshake secrets;
    // independent message candidates retain only their original safety lease.
    this.config.credentials?.close();
    const tails = [...this.#bindings.values()].flatMap(binding => [binding.write?.waitCleanup(), binding.termination, binding.acknowledging, binding.draining]);
    // A synchronous provider exception must not prevent the other close paths.
    const invoke = (action: () => Promise<void>): Promise<void> => { try { return action(); } catch { return Promise.reject(new Error("carrier_failed")); } };
    const closing = invoke(() => this.config.transport.close()), terminated = invoke(() => this.config.transport.waitTermination());
    void Promise.allSettled([closing, terminated, this.#receiving, this.output.waitSubmitted(), this.#drainWork, this.#bootstrapTask, ...tails]).then(results => {
      this.#transportClosed = results[0]?.status === "fulfilled" && results[1]?.status === "fulfilled";
      if (!this.#transportClosed) this.#cleanupFault = true;
      this.#cleanup();
    });
    this.#closeInitializing = false; this.#cleanup();
    return this.cleanupOwner.closed;
  }
  /** Observations live in a compact owner after actual core exit. */
  onCleanup(callback: () => void): void { this.cleanupOwner.onCleanup(callback); }
  #cleanup(): void {
    if (this.#cleaning || this.#closeInitializing) return;
    this.#cleaning = true;
    try { this.#collect(); } finally { this.#cleaning = false; }
    this.cleanupOwner.updateCore(this.#reservation === undefined ? 0 :
      Number(this.#receiving !== undefined) + Number(this.#drainWork !== undefined) + Number(!this.output.cleanupComplete()) + Number(!this.#transportClosed) +
      Number(this.#unreliable?.cleanupComplete() === false) + Number(this.#nativeAcceptor !== undefined) + Number(this.#managementTask !== undefined) + Number(this.#bootstrapTask !== undefined) + Number(this.#supervisor !== undefined) + Number(this.#dispatchQueued) +
      Number(this.#rpc !== undefined) + Number(this.#retireWorking) + Number(this.#rekeyWorking) + this.#rpcTasks.filter(Boolean).length + this.#notifyTasks.filter(Boolean).length + this.#nativeAssociations.size + this.#dispatching.size, this.#cleanupFault);
  }
  #collect(): void {
    if (this.#reservation === undefined || !this.#closed || !this.#transportClosed || this.#rpcTasks.some(Boolean) || this.#notifyTasks.some(Boolean) || this.#managementTask !== undefined || this.#bootstrapTask !== undefined || this.#supervisor !== undefined || this.#dispatchQueued || this.#nativeAcceptor !== undefined || this.#nativeAssociations.size !== 0 ||
        this.#unreliable?.cleanupComplete() === false || this.config.unreliablePreparation?.cleanupComplete() === false && this.#unreliable === undefined || this.#nativeScheduler?.cleanupComplete() === false || this.#nativeSend?.cleanupComplete() === false || this.#nativePositions?.cleanupComplete() === false || this.#maintenancePositions?.cleanupComplete() === false || this.#drainWork !== undefined || this.#liveness?.cleanupComplete() === false || this.#receiving !== undefined || !this.reader.cleanupComplete() ||
        !this.output.cleanupComplete() || !this.epoch.cleanupComplete() || !this.config.ledger.cleanupComplete() ||
        this.#controlSend?.cleanupComplete() === false || this.#controlReceive?.cleanupComplete() === false || this.#controlDecoder?.cleanupComplete() === false || this.#waiters.size !== 0 || this.#rejecting || this.#retireWorking || this.#rekeyWorking || this.#candidate?.cleanupComplete() === false || this.#rekeyRetired.some(epoch => !epoch.cleanupComplete())) return;
    for (const binding of this.#bindings.values()) {
      if (this.#physicalComplete(binding, false)) binding.stream?.notifyAdapterCleanup();
      if (!this.#physicalComplete(binding)) return;
    }
    // Canceled SDK workflows must exit. Actual application invocations have
    // independent owners and keep their permits and parameter charges.
    if (this.#dispatching.size !== 0 || this.#rpc?.cleanupComplete() === false) return;
    for (const binding of this.#bindings.values()) this.#releaseStream(binding);
    this.#bindings.clear(); this.#open?.close();
    this.#plain.fill(0); this.#encode.fill(0); this.#nonce.fill(0); this.#plain = this.#encode = this.#nonce = empty;
    this.#handshakeHash.fill(0); this.#retireScratch.fill(0); this.#retireDigest.fill(0); this.#lastRetireSentDigest.fill(0); this.#lastRetireReceivedDigest.fill(0);
    this.#retireIn?.digest.fill(0); this.#retireOut?.digest.fill(0); this.#retireTail?.digest.fill(0); this.#retireIn = this.#retireOut = this.#retireTail = undefined;
    this.#handshakeHash = this.#retireScratch = this.#retireDigest = this.#lastRetireSentDigest = this.#lastRetireReceivedDigest = empty;
    this.#controlReservation?.release(); this.#controlReservation = undefined;
    this.#bootstrapReservation?.release(); this.#bootstrapReservation = undefined; this.#bootstrap = undefined;
    if (this.#rpcPositions.some(entries => entries.some(position => !position.cleanupComplete()))) return;
    for (const positions of this.#rpcPositions) positions.length = 0;
    this.#rpcHandles.length = this.#rpcNative.length = this.#rpcNativeRenewal.length = this.#rpcOutputs.length = 0;
    if (this.#notifyPositions.some(entries => entries.some(position => !position.cleanupComplete()))) return;
    for (const entries of this.#notifyPositions) entries.length = 0; this.#notifyHandles.length = 0;
    if (this.#managementPositions.some(position => !position.cleanupComplete())) return;
    this.#managementPositions.length = this.#managementReceivePositions.length = 0; this.#managementWaitPosition = undefined;
    this.#managementNativeRenewal = undefined; this.#managementDeadline = undefined; this.#managementHandle = undefined;
    this.config.credentials?.close();
    const reference = this.#reservation; this.#reservation = undefined;
    this.#application = undefined; this.#rpc = undefined; this.#open = undefined; this.#drainDeadline = undefined;
    this.#core = undefined; this.#nativeScheduler = undefined; this.#nativeSend = undefined; this.#nativePositions = undefined; this.#maintenancePositions = undefined; this.#internalKeys = undefined; this.#sendAccount = undefined; this.#sendAccounts = undefined; this.#idle = undefined; this.#liveness = undefined;
    this.#controlSend = this.#controlReceive = this.#candidateSend = this.#candidateReceive = undefined;
    this.#controlDecoder = undefined; this.#rekeyRound = undefined; this.#candidate = undefined; this.#rekeyRetired.length = 0;
    this.#rekeyDeadline = this.#rekeyPhaseDeadline = this.#rekeySafetyDeadline = undefined; this.#rekeyAnchor = undefined; this.#rekeyRequest = undefined; this.#autoRekeyQueued = false;
    if (this.#rekeySafetyTimer !== undefined) clearTimeout(this.#rekeySafetyTimer); this.#rekeySafetyTimer = undefined;
    this.#peerBarrier = this.#localFrozen = []; this.#drain = undefined;
    this.cleanupOwner.finishCore(reference);
  }
  lifecycleResult(): V4LifecycleResult { this.#cleanup(); return this.cleanupOwner.lifecycleResult(); }
  cleanupStatus(): V4CleanupStatus { this.#cleanup(); return this.cleanupOwner.cleanupStatus(); }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> { this.#cleanup(); return this.cleanupOwner.waitCleanup(options); }

}

function tuple(writer: FixedCBORWriter, value: TerminalTuple): void { writer.map(3).uint(0).uint(value.epoch).uint(1).uint(value.next).uint(2).uint(value.offset); }
function readTuple(doc: CBORDocument, node: number): TerminalTuple {
  return { epoch: Number(doc.uint(doc.field(node, 0))), next: doc.uint(doc.field(node, 1)), offset: doc.uint(doc.field(node, 2)) };
}
function sameTuple(a: TerminalTuple, b: TerminalTuple): boolean { return a.epoch === b.epoch && a.next === b.next && a.offset === b.offset; }
class RuntimeStream implements V4StreamOwner {
  #session: V4AuthenticatedSessionRuntime | undefined;
  #handle: OpenHandle | undefined;
  #receive: ReliableReceiveDirection | undefined;
  #final: V4CloseResult | undefined;
  #sendFIN = false;
  #accepted = 0n;
  #authenticated = 0n;
  #released = 0n;
  #adapterClaimed = false;
  #adapterReservation: ResourceReference | undefined;
  #adapterInvalidated = false;
  #adapterInvalidation: (() => void) | undefined;
  #adapterSendStopped: (() => void) | undefined;
  #sendStopped = false;
  #adapterCleanup: (() => void) | undefined;
  #adapterRollback: (() => void) | undefined;
  #adapterIOEnded: (() => void) | undefined;
  #adapterInputChanged: (() => void) | undefined;
  #rawUsed = false;
  constructor(session: V4AuthenticatedSessionRuntime, handle: OpenHandle, receive: ReliableReceiveDirection) {
    this.#session = session; this.#handle = handle; this.#receive = receive;
    Object.defineProperty(this, "then", { value: undefined });
    registerStreamAdapter(this, profile => this.#claimAdapter(profile));
    registerBridgeStreamAdapter(this, profile => this.#claimBridgeAdapter(profile));
    registerMessageStreamAdapter(this, profile => this.#claimMessageAdapter(profile));
    registerRPCStream(this, profile => this.#claimRPCAdapter(profile));
    registerResumeStream(this, (session, kind, profile) => this.#claimResumeAdapter(session, kind, profile), () => this.#session);
  }
  #claimResumeAdapter(session: object, kind: string, profile: StreamAdapterProfile): ResumeStreamOwner {
    if (this.#session === undefined || this.#rawUsed || this.#adapterClaimed) throw new Error("stream_owned");
    const target = this.#session.resumeStreamTarget(this.#handle!, session, kind), owner = this.#claimMessageAdapter(profile);
    return Object.freeze({ ...owner, ...target,
      sameSession: (candidate: object) => this.#session !== undefined && candidate === this.#session,
      unused: () => !this.#rawUsed && this.#session !== undefined,
      prepareFragment: (bytes: Uint8Array, reference: ResourceReference) => {
        owner.check();
        if (this.#session === undefined || byteLength(bytes) < 1 || byteLength(bytes) > 16384) throw new Error("rpc_fragment_capacity");
        return this.#session.prepareWrite(this.#handle!, bytes, undefined, reference);
      },
      returnAtBoundary: () => {
        owner.check(); owner.releaseReader();
        if (this.#session === undefined) throw new Error("closed");
        this.#session.checkMessageBoundary(this.#handle!);
        owner.returnAtBoundary(); this.#rawUsed = true;
      },
    });
  }
  #claimRPCAdapter(profile: StreamAdapterProfile): RPCStreamOwner {
    if (this.#session === undefined) throw new Error("closed");
    this.#session.checkRPCStream(this.#handle!);
    const owner = this.#claimMessageAdapter(profile);
    const dedicated = this.#session!.isDedicatedRPCStream(this.#handle!);
    if (!dedicated && ((owner.kind !== "flowersec.rpc.v4" && owner.kind !== managementSpec.kind && owner.kind !== notifySpec.kind) || owner.metadata.length !== 0 || this.#session?.info().application_profile === "transport")) {
      owner.rollback(); throw new Error("rpc_stream_kind");
    }
    return Object.freeze({ ...owner, unused: () => this.#session !== undefined && this.#session.unusedRPCStream(this.#handle!), prepareFragment: (bytes: Uint8Array, reference: ResourceReference, originalDeadline?: TrustedDeadline, publication?: RPCPublicationGuard) => {
      owner.check();
      if (this.#session === undefined || byteLength(bytes) < (dedicated || owner.kind === notifySpec.kind ? 1 : owner.kind === managementSpec.kind ? 3 : 13) || byteLength(bytes) > 16384) throw new Error("rpc_fragment_capacity");
      return this.#session.prepareWrite(this.#handle!, bytes, undefined, reference, undefined, originalDeadline, publication);
    } });
  }
  #claimMessageAdapter(profile: StreamAdapterProfile): MessageStreamAdapterOwner & { returnAtBoundary(): void } {
    if (this.#rawUsed || this.#session === undefined) throw new Error("stream_owned");
    const owner = this.#claimAdapter(profile);
    let cursor: V4CursorReadOwner | undefined, released = false;
    try {
      const context = this.#session.messageAdapterContext(this.#handle!, this.#adapterReservation!, profile.application);
      const releaseReader = (): void => { cursor?.release(); cursor = undefined; };
      const releaseApplication = (): void => { if (profile.reusableApplication !== true) context.application.close(); };
      const rollback = (): void => {
        if (released) return; released = true;
        releaseReader(); context.releaseIO(); context.metadata.fill(0); releaseApplication(); owner.rollback();
      };
      this.#adapterRollback = rollback;
      return Object.freeze({ ...owner, ...context,
        admitBody: (length: number, structure: ResourceVector) => {
          owner.check(); return this.#receive!.admitMessageBody(length, structure, context.reserve);
        },
        ensureReadQueue: () => { owner.check(); this.#receive!.ensureMessageQueue(context.reserve); },
        readInto: (maximum: number, transfer: (bytes: Uint8Array) => number, signal: AbortSignal) => {
          owner.check(); cursor ??= this.#receive!.acquireCursor(BigInt(owner.readBytes));
          return cursor.read(Math.min(maximum, owner.readBytes), transfer, signal);
        },
        readState: () => cursor?.state() ?? this.#receive?.state() ?? { stream_status: this.#final?.read_terminal === "eof" ? "eof" as const : "aborted" as const },
        releaseReader,
        prepareWrite: (bytes: Uint8Array, milliseconds: bigint) => {
          owner.check(); if (this.#session === undefined) throw new Error("closed");
          return this.#session.prepareWrite(this.#handle!, bytes, milliseconds);
        },
        ioEndedWith: (callback: () => void) => { this.#adapterIOEnded = callback; },
        inputChangedWith: (callback: () => void) => { this.#adapterInputChanged = callback; },
        detachIO: () => {
          releaseReader();
          if (this.#session !== undefined && this.#coreCleanup().status === "complete") {
            const session = this.#session, handle = this.#handle!;
            context.releaseIO(); this.#adapterIOEnded = this.#adapterInputChanged = undefined; session.detachMessageIO(handle);
          }
        },
        returnAtBoundary: () => {
          owner.check(); releaseReader();
          if (this.#session === undefined) throw new Error("closed");
          this.#session.checkMessageBoundary(this.#handle!);
          released = true; context.releaseIO(); context.metadata.fill(0); releaseApplication();
          this.#adapterClaimed = false; this.#session.rollbackAdapter(this.#handle!); owner.release();
        },
        rollback,
        release: () => { if (!released) { released = true; releaseReader(); context.releaseIO(); context.metadata.fill(0); releaseApplication(); owner.release(); } },
      });
    } catch (error) { cursor?.release(); owner.rollback(); throw error; }
  }
  #claimBridgeAdapter(profile: StreamAdapterProfile): BridgeStreamAdapterOwner {
    if (this.#rawUsed || this.#session === undefined) throw new Error("stream_owned");
    const session = this.#session, owner = this.#claimAdapter(profile);
    try {
      // Prepay this detached tail before publication or either pump. Its
      // reservation is independent of original adapter I/O cleanup.
      let resultBacking: ResourceReference | undefined, nativeResultBacking: ResourceReference | undefined, nativeIOBacking: ResourceReference | undefined;
      try {
        resultBacking = session.bridgeResultBacking(this.#handle!, profile.readBytes, "flowersec_stream");
        nativeResultBacking = profile.nativeEndpoint === true ? session.bridgeResultBacking(this.#handle!, profile.readBytes, "native_duplex") : undefined;
        nativeIOBacking = profile.nativeEndpoint === true ? this.#adapterReservation!.borrow() : undefined;
        return Object.freeze({ ...owner, endpointKind: "flowersec_stream" as const, resultBacking,
          ...(nativeResultBacking === undefined ? {} : { nativeResultBacking }),
          ...(nativeIOBacking === undefined ? {} : { nativeIOBacking }),
          release: () => owner.release(), rollback: () => { nativeIOBacking?.release(); nativeResultBacking?.release(); owner.rollback(); },
          readState: () => this.#receive?.state() ?? {
            stream_status: this.#final?.first_error !== undefined ? "error" as const : this.#final?.read_terminal === "eof" ? "eof" as const : "aborted" as const,
            ...(this.#final?.first_error === undefined ? {} : { error: this.#final.first_error }),
          },
        });
      } catch (error) { nativeIOBacking?.release(); nativeResultBacking?.release(); resultBacking?.release(); throw error; }
    } catch (error) { owner.rollback(); throw error; }
  }
  #claimAdapter(profile: StreamAdapterProfile): StreamAdapterOwner & { releaseDelivery(): void } {
    if (this.#adapterClaimed || this.#session === undefined) throw new Error("stream_owned");
    const claim = this.#session.claimAdapter(this.#handle!, profile, () => this.invalidateAdapter());
    this.#adapterClaimed = true; this.#adapterReservation = claim.reservation;
    let released = false, deliveryReleased = false;
    const releaseDelivery = (): void => { if (!deliveryReleased) { deliveryReleased = true; claim.delivery.release(); } };
    const release = (): void => {
      if (released) return;
      released = true; this.#adapterInvalidation = undefined; this.#adapterSendStopped = undefined; this.#adapterCleanup = undefined; this.#adapterRollback = undefined; this.#adapterIOEnded = undefined;
      this.#adapterInputChanged = undefined;
      releaseDelivery();
      this.#adapterReservation?.release(); this.#adapterReservation = undefined;
      this.#session?.releaseAdapter(this.#handle!);
    };
    const check = (): void => {
      if (released || deliveryReleased || this.#adapterInvalidated) throw new Error("closed");
      this.#adapterReservation!.check(); claim.delivery.check();
    };
    const rollback = (): void => {
      if (released) return;
      if (!this.#adapterInvalidated && this.#session !== undefined) {
        this.#session.rollbackAdapter(this.#handle!); this.#adapterClaimed = false;
      }
      release();
    };
    this.#adapterRollback = rollback;
    return Object.freeze({
      readBytes: claim.readBytes, check, releaseDelivery,
      read: (options?: OperationOptions) => { check(); return this.#read(BigInt(claim.readBytes), options); },
      write: (bytes: Uint8Array, options?: OperationOptions) => { check(); return this.#write(bytes, options); },
      closeWrite: (options?: OperationOptions) => { check(); return this.#closeWrite(options); },
      finish: (options?: OperationOptions) => { check(); return this.#finish(options); },
      reset: (options?: OperationOptions) => this.reset(options),
      abortRead: (options?: OperationOptions) => this.#abortDirection(false, options),
      abortWrite: (options?: OperationOptions) => this.#abortDirection(true, options),
      cleanupStatus: () => this.#coreCleanup(),
      invalidateWith: (callback: () => void) => { this.#adapterInvalidation = callback; if (this.#adapterInvalidated) callback(); },
      sendStoppedWith: (callback: () => void) => { this.#adapterSendStopped = callback; if (this.#sendStopped) callback(); },
      cleanupWith: (callback: () => void) => { this.#adapterCleanup = callback; if (this.#final !== undefined) callback(); },
      rollback,
      release,
    });
  }
  rollbackUnpublishedAdapter(): void { this.#adapterRollback?.(); }
  endAdapterIO(): void { if (this.#adapterIOEnded !== undefined) this.#adapterIOEnded(); else this.invalidateAdapter(); }
  notifyAdapterInput(): void { this.#adapterInputChanged?.(); }
  invalidateAdapter(): void {
    if (this.#adapterInvalidated) return;
    this.#adapterInvalidated = true; this.#adapterInvalidation?.();
  }
  notifyAdapterCleanup(): void { this.#adapterCleanup?.(); }
  notifyAdapterSendStopped(): void {
    if (this.#sendStopped) return;
    this.#sendStopped = true; this.#adapterSendStopped?.();
  }
  #checkRaw(): void { if (this.#adapterClaimed) throw new Error("stream_owned"); this.#rawUsed = true; }
  #abortDirection(send: boolean, options?: OperationOptions): Promise<V4CloseResult> {
    if (this.#final !== undefined) return Promise.resolve(this.#final);
    return this.#session!.abortStreamDirection(this.#handle!, send, options);
  }
  /** Retirement leaves only compact observations, never the Session/key graph. */
  detach(result: V4CloseResult, sendFIN: boolean, accepted: bigint, authenticated: bigint, released: bigint): void {
    this.#final = result; this.#sendFIN = sendFIN; this.#accepted = accepted; this.#authenticated = authenticated; this.#released = released;
    this.#session = undefined; this.#handle = undefined; this.#receive = undefined; this.#adapterRollback = undefined;
    this.#adapterCleanup?.();
  }
  acquireCursor(target: bigint): V4CursorReadOwner {
    this.#checkRaw();
    if (this.#receive === undefined) throw new Error("closed");
    return this.#receive.acquireCursor(target);
  }
  read(maxBytes: bigint, options?: OperationOptions): Promise<V4ReadResult> {
    this.#checkRaw(); return this.#read(maxBytes, options);
  }
  #read(maxBytes: bigint, options?: OperationOptions): Promise<V4ReadResult> {
    if (this.#receive !== undefined) return this.#receive.read(maxBytes, options);
    if (typeof maxBytes !== "bigint" || maxBytes <= 0n) return Promise.reject(new Error("invalid_argument"));
    const result: V4ReadResult = {
      data: new Uint8Array(), progress: Object.freeze({ offset: this.#released, filled: 0n }), wait_status: "ready",
      stream_status: this.#final?.first_error !== undefined ? "error" : this.#final?.read_terminal === "eof" ? "eof" : "aborted",
      ...(this.#final?.first_error === undefined ? {} : { error: this.#final.first_error }),
    };
    Object.defineProperty(result, "then", { value: undefined }); return Promise.resolve(Object.freeze(result));
  }
  prepareWrite(payload: Uint8Array, options?: Readonly<{ deadlineMilliseconds?: bigint }>): V4WriteRequestOwner {
    const diagnostic = this.#session?.beginApplicationDiagnostic() ?? new DiagnosticActivity(undefined, "application");
    try {
      this.#checkRaw();
      if (this.#session === undefined) throw new Error("closed");
      return this.#session.prepareWrite(this.#handle!, payload, options?.deadlineMilliseconds, undefined, diagnostic);
    } catch (error) { diagnostic.failure(error); throw error; }
  }
  async write(payload: Uint8Array, options?: OperationOptions): Promise<V4WriteProgress> {
    const diagnostic = this.#session?.beginApplicationDiagnostic() ?? new DiagnosticActivity(undefined, "application");
    try { this.#checkRaw(); return await this.#write(payload, options, diagnostic); }
    catch (error) { diagnostic.failure(error); throw error; }
  }
  async #write(payload: Uint8Array, options?: OperationOptions, diagnostic?: DiagnosticActivity): Promise<V4WriteProgress> {
    if (this.#session === undefined) throw new Error("closed");
    const requested = BigInt(byteLength(payload));
    const request = this.#session.prepareOrdinaryWrite(this.#handle!, payload, diagnostic), cancel = (): void => request.cancel();
    options?.signal?.addEventListener("abort", cancel, { once: true });
    try {
      if (options?.signal?.aborted) request.cancel(); request.start();
      const progress = await request.wait();
      if (progress.requested_bytes === requested) return progress;
      const result = { ...progress, requested_bytes: requested };
      Object.defineProperty(result, "then", { value: undefined }); return Object.freeze(result);
    }
    finally { options?.signal?.removeEventListener("abort", cancel); }
  }
  closeWrite(options?: OperationOptions): Promise<V4CloseResult> {
    this.#checkRaw(); return this.#closeWrite(options);
  }
  #closeWrite(options?: OperationOptions): Promise<V4CloseResult> {
    if (this.#final !== undefined) return this.#sendFIN ? Promise.resolve(this.#final) : Promise.reject(new Error("stream_aborted"));
    return this.#session!.closeWriteStream(this.#handle!, false, options);
  }
  finish(options?: OperationOptions): Promise<V4CloseResult> {
    this.#checkRaw(); return this.#finish(options);
  }
  #finish(options?: OperationOptions): Promise<V4CloseResult> {
    if (this.#final !== undefined) return this.#final.send_drained ? Promise.resolve(this.#final) : Promise.reject(new Error("stream_aborted"));
    return this.#session!.closeWriteStream(this.#handle!, true, options);
  }
  reset(options?: OperationOptions): Promise<V4CloseResult> {
    this.invalidateAdapter();
    if (this.#final !== undefined) return Promise.resolve(this.#final);
    return this.#session!.closeStream(this.#handle!, options);
  }
  close(options?: OperationOptions): Promise<V4CloseResult> { return this.reset(options); }
  waitPeerAuthenticated(offset: bigint, options?: OperationOptions): Promise<void> {
    if (this.#final === undefined) return this.#session!.waitPeerAuthenticated(this.#handle!, offset, options);
    if (typeof offset !== "bigint" || offset < 0n || offset > this.#accepted) return Promise.reject(new Error("invalid_argument"));
    return offset <= this.#authenticated ? Promise.resolve() : Promise.reject(new Error("stream_aborted"));
  }
  #coreCleanup(): V4CleanupStatus { return this.#final?.cleanup_status ?? this.#session!.streamCleanup(this.#handle!, false); }
  cleanupStatus(): V4CleanupStatus { return this.#adapterReservation === undefined ? this.#coreCleanup() : pending; }
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (byteLength(a) !== byteLength(b)) return false;
  let delta = 0; for (let i = 0; i < byteLength(a); i++) delta |= a[i]! ^ b[i]!; return delta === 0;
}
