import type * as RpcInputTypes from "./rpcInput.js";
import type * as ServiceBindingConfigTypes from "./serviceBindingConfig.js";
import type * as ServiceBindingPoolTypes from "./serviceBindingPool.js";
import type * as RpcPreacceptedStreamsTypes from "./rpcPreacceptedStreams.js";
import type * as RpcUnaryPreparationTypes from "./rpcUnaryPreparation.js";
import type * as ContractQueryAcquisitionTypes from "./contractQueryAcquisition.js";
import type { StreamOpenPreparation } from "./streamOpenPreparation.js";
import { initializerCallBacking } from "./initializerWorkload.js";
import { checkMaintenanceOwner, type V4MaintenanceOwner } from "../responsePublication.js";
import { rpcOutputInterestCharge } from "./rpcOutputInterest.js";
import { RPCResumeDispatch, rpcResumeDispatchCharge } from "./rpcResumeDispatch.js";
import { ResumeCodec, resumeCodecCharges } from "./resumeCodec.js";
import type { CheckpointSessionPolicy } from "./checkpointToken.js";
import { executionStorage, executionMode } from "./executionStorage.js";
import { byteEventSource } from "../eventSource.js";
import { eventSourceCharge } from "./rpcEventSource.js";
import { RPCStreamingExchange, rpcStreamingErrorCharge } from "./rpcStreamingExchange.js";
import { RPCStreamingDispatch, rpcStreamingDispatchCharges } from "./rpcStreamingDispatch.js";
import { RPCStreamMessages, rpcStreamMessagesCharges } from "./rpcStreamMessages.js";
import { RPCPreacceptedStreams, rpcPreacceptedStreamsCharge, type RPCStreamPoolMessages, type RPCStreamPoolDemand } from "./rpcPreacceptedStreams.js";
import type { RPCPreparedExchange, RPCPreparedStart } from "./rpcUnaryPreparation.js";
import { checkStreamingTarget, type CapturedBindingMethod } from "./serviceBindingConfig.js";
import type { V4StreamingImplementation, V4StreamingHandlerOptions } from "../serviceHandlers.js";
import { rpcCompletionCharge } from "./rpcCompletion.js";
import { NotificationExecution } from "./notifyExecution.js";
import { notificationSubscription, type V4NotificationSubscription, type V4NotificationSubscriptionOptions } from "../notificationSubscription.js";
import { NotifyChannel, notifyChannelCharges } from "./notifyChannel.js";
import { NotifyPreparation, captureNotifyOptions, notifyPreparationCharges, type NotifyPreparationOptions } from "./notifyPreparation.js";
import { NotificationInput, NotificationMessage, NotificationRegistration, NotificationSubscribers, NotificationAccess, captureNotificationHandler, notificationMessageCharges, notificationRegistrationCharge, notificationWorkCharge, notificationSubscribersCharge } from "./notifyDispatch.js";
import type { V4NotificationHandler, V4NotificationHandlerOptions } from "../serviceHandlers.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { rpcPayloadCharge } from "./rpcPayload.js";
import { timeAdd } from "./timeArithmetic.js";
import { operationTarget, operationResultLimit, type V4OperationReference } from "../operationReference.js";
import { captureServiceBindingTarget, type ServiceBindingTarget } from "./serviceBindingConfig.js";
import { ExecutionManagementChannel, executionManagementCharges } from "./executionManagementChannel.js";
import { ExecutionManagementCodec, executionManagementDecoderCharge, type ExecutionTarget, type ExecutionManagementResult } from "./executionManagementCodec.js";
import { captureExecutionIdentity, captureVolatileExecution, executionResultReadCharge, type VolatileExecutionConfig, type RPCExecutionIdentity, type VolatileExecutions } from "./volatileExecutions.js";
import type { V4StreamOwner } from "../public.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import { methodDefinition, serviceDefinition } from "../serviceDefinition.js";
import { applicationGroup, applicationGroupCharge, applicationWorkClass, completionPositionCharge, type ApplicationGroup, type ApplicationWorkClass, type ApplicationPermit, type CompletionClaim,
  type CompletionPosition, type CompletionReservation } from "./applicationExecutor.js";
import { byteLength } from "./cbor.js";
import type { RPCApplicationServices } from "./rpcApplicationServices.js";
import type { RPCStreamPreparation } from "./rpcStreamPreparation.js";
import type { TrustedClock } from "./clock.js";
import { type ContractQueryPermission, ContractQueryAccess } from "./contractQueryAccess.js";
import { contractQueryAccessCharge } from "./contractQueryAccess.js";
import type { ContractQueryAcquisition, ContractQueryAcquisitions } from "./contractQueryAcquisition.js";
import type { ContractQueryTarget } from "./contractQuery.js";
import { ContractQuerySession, contractQuerySessionCharges } from "./contractQuerySession.js";
import { ContractRoutes, contractRoutesCharge } from "./contractRoutes.js";
import type { TrustedDeadline } from "./deadline.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { RPCChannelRuntime, rpcChannelCharge } from "./rpcChannel.js";
import { RPCCallCapacity, rpcCallCapacityCharge, type RPCCallReservation } from "./rpcCallCapacity.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { RPCNetwork, rpcNetworkCharge, type RPCNetworkConfig } from "./rpcNetwork.js";
import { rpcPublisherCharge } from "./rpcPublisher.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import { rpcReceiverCharges, type RPCReadyRequest } from "./rpcReceiver.js";
import { RPCUnaryDispatch, rpcUnaryDispatchCharges } from "./rpcUnaryDispatch.js";
import { RPCUnaryRegistration, captureUnaryHandler, rpcUnaryRegistrationCharge } from "./rpcUnaryRegistration.js";
import type { V4UnaryHandler, V4UnaryHandlerOptions } from "../serviceHandlers.js";
import type { CapturedContractRoute } from "./contractRoutes.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import { TimeError } from "./timeArithmetic.js";
import { ServiceBinding, type ServiceBindingSource } from "./serviceBinding.js";
import { captureServiceBinding, type ServiceBindingOptions } from "./serviceBindingConfig.js";
import type { ServiceBindingPool } from "./serviceBindingPool.js";
import type { ContractRenewalProtection, ContractQueryPreparation } from "./queryRenewalPosition.js";
import { RPCUnaryExchange, rpcUnaryExchangeCharges } from "./rpcUnaryExchange.js";
import { RPCPayload } from "./rpcPayload.js";
import type { RPCPayloadBorrow } from "./rpcPayload.js";
import { RPCUnaryPreparation, captureUnaryOptions, rpcUnaryPreparationCharges, unaryResponseLimit, type RPCUnaryPreparationOptions, type RPCUnaryTransfer } from "./rpcUnaryPreparation.js";
import { messageInputBytes } from "./messageCodec.js";
import type { RandomFill } from "./random.js";
import { ServiceContractSnapshot, serviceContractCharge, serviceContractDecoderCharge, type AdmissionOffer } from "./serviceContract.js";
import type { SessionCleanup } from "./sessionCleanup.js";
import { ServiceInputs, serviceInputsCharges } from "./serviceInputs.js";
import { ResourceError, ResourceVector, type ResourceRoot, type ResourceAccount, type ResourceOwner, type ResourceReference, type ProtectedResourceReservation } from "./resources.js";
import { writeRequestCharge } from "./writeRequest.js";

const managementAddListener = EventTarget.prototype.addEventListener, managementRemoveListener = EventTarget.prototype.removeEventListener;
const managementAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;

/** Trusted local service configuration. The fixed method tuple must come from
 * the host's exact built-in contract, never a remote header or discovery call. */
export interface RPCApplicationUnaryHandler {
  readonly namespace: string;
  readonly method: object;
  readonly contract: ServiceContractSnapshot;
  readonly execution?: VolatileExecutionConfig;
  readonly offer?: AdmissionOffer;
  readonly maximumOfferWindowMS?: bigint;
  readonly handler: V4UnaryHandler<any, any>;
  readonly options: V4UnaryHandlerOptions;
}
export interface RPCApplicationStreamingHandler {
  readonly namespace: string;
  readonly method: object;
  readonly kind: string;
  readonly metadata?: Uint8Array;
  readonly contract: ServiceContractSnapshot;
  readonly execution?: VolatileExecutionConfig;
  readonly offer?: AdmissionOffer;
  readonly maximumOfferWindowMS?: bigint;
  readonly handler: V4StreamingImplementation<any, any>;
  readonly options: V4StreamingHandlerOptions;
}
export type RPCStreamOpener = (kind: string, metadata: Uint8Array, deadline: TrustedDeadline,
  signal: AbortSignal, prepare: (stream: V4StreamOwner) => void, prepaid?: StreamOpenPreparation) => Promise<void>;
export interface RPCApplicationNotificationMethod {
  readonly namespace: string;
  readonly method: object;
  readonly contract: ServiceContractSnapshot | Uint8Array;
  readonly permission: "allowed" | "denied" | "unavailable";
}
export interface RPCApplicationNotificationHandler {
  readonly execution?: VolatileExecutionConfig;
  readonly offer?: AdmissionOffer;
  readonly maximumOfferWindowMS?: bigint;
  readonly namespace: string;
  readonly method: object;
  readonly contract: ServiceContractSnapshot;
  readonly handler: V4NotificationHandler<any>;
  readonly options: V4NotificationHandlerOptions;
}
export interface RPCApplicationQueryPermission {
  readonly namespace: string;
  readonly method: object;
  readonly permission: ContractQueryPermission;
}
/** Explicit local grant for one authenticated actor to manage another
 * caller's original execution key. Saved references cannot carry this grant. */
export interface RPCExecutionDelegation {
  readonly direction: "outgoing" | "incoming";
  readonly namespace: string;
  readonly principalAuthority: string;
  readonly principalSubject: string;
  readonly targetAuthority: string;
  readonly targetSubject: string;
  readonly query: boolean;
  readonly cancel: boolean;
  readonly notAfterMS: bigint;
}
function captureExecutionDelegations(input: readonly RPCExecutionDelegation[]): readonly RPCExecutionDelegation[] {
  if (!Array.isArray(input) || input.length > 64) throw new RPCProtocolError("configuration_capacity");
  const keys = new Set<string>();
  return Object.freeze(input.map(entry => {
    const { direction, namespace, principalAuthority, principalSubject, targetAuthority, targetSubject, query, cancel, notAfterMS } = entry;
    if (direction !== "outgoing" && direction !== "incoming" || ![namespace, principalSubject, targetSubject].every(value => typeof value === "string" && /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(value)) ||
        ![principalAuthority, targetAuthority].every(value => typeof value === "string" && /^[0-9a-f]{64}$/u.test(value) && !/^0+$/u.test(value)) ||
        typeof query !== "boolean" || typeof cancel !== "boolean" || !query && !cancel || typeof notAfterMS !== "bigint" || notAfterMS < 1n || notAfterMS >= 1n << 64n) throw new RPCProtocolError("configuration_capacity");
    const key = [direction, namespace, principalAuthority, principalSubject, targetAuthority, targetSubject].join("\0");
    if (keys.has(key)) throw new RPCProtocolError("configuration_capacity"); keys.add(key);
    return Object.freeze({ direction, namespace, principalAuthority, principalSubject, targetAuthority, targetSubject, query, cancel, notAfterMS });
  }));
}
export interface RPCApplicationConfig {
  readonly maintenanceOwner?: V4MaintenanceOwner;
  readonly query: RPCNetworkConfig["query"];
  readonly resultRead?: RPCNetworkConfig["query"];
  readonly definitions: readonly object[];
  readonly maxMethods: number;
  readonly maxCaptureBytes: number;
  readonly queryAcquisitions?: 2 | 4;
  readonly unaryHandlers?: readonly RPCApplicationUnaryHandler[];
  readonly streamingHandlers?: readonly RPCApplicationStreamingHandler[];
  readonly notificationHandlers?: readonly RPCApplicationNotificationHandler[];
  readonly notificationMethods?: readonly RPCApplicationNotificationMethod[];
  readonly queryPermissions?: readonly RPCApplicationQueryPermission[];
  readonly executionIdentity?: RPCExecutionIdentity;
  readonly localExecutionAuthority?: string;
  readonly referenceTargets?: readonly ServiceBindingTarget[];
  readonly executionDelegations?: readonly RPCExecutionDelegation[];
  readonly executionServices?: readonly VolatileExecutionConfig[];
  readonly executionPermissions?: readonly Readonly<{ namespace: string; query: boolean; cancel: boolean }>[];
}
export function captureRPCApplication(input: RPCApplicationConfig): RPCApplicationConfig {
  const query = input.query, typeID = query.typeID, digest = query.contractDigest;
  const definitions = input.definitions, maxMethods = input.maxMethods, maxCaptureBytes = input.maxCaptureBytes, queryAcquisitions = input.queryAcquisitions ?? 4;
  if (queryAcquisitions !== 2 && queryAcquisitions !== 4 || !Number.isSafeInteger(typeID) || typeID < 1 || typeID > 0xffffffff || byteLength(digest) !== 32 ||
      !Array.isArray(definitions) || !Number.isSafeInteger(maxMethods) || maxMethods < 1 || maxMethods > 4096 || definitions.length > maxMethods ||
      !Number.isSafeInteger(maxCaptureBytes) || maxCaptureBytes < 0 || maxCaptureBytes > 1048576) throw new RPCProtocolError("configuration_capacity");
  const executionIdentity = captureExecutionIdentity(input.executionIdentity);
  const executionDelegations = captureExecutionDelegations(input.executionDelegations ?? []);
  const readInput = input.resultRead;
  const readType = readInput?.typeID, readDigest = readInput?.contractDigest;
  if (readInput !== undefined && (!Number.isSafeInteger(readType) || readType! < 1 || readType! > 0xffffffff || readDigest === undefined || byteLength(readDigest) !== 32)) throw new RPCProtocolError("configuration_capacity");
  const resultRead = readInput === undefined ? undefined : Object.freeze({ typeID: readType!, contractDigest: new Uint8Array(readDigest!) });
  const localExecutionAuthority = input.localExecutionAuthority;
  if (localExecutionAuthority !== undefined && (!/^[0-9a-f]{64}$/u.test(localExecutionAuthority) || /^0+$/u.test(localExecutionAuthority))) throw new RPCProtocolError("configuration_capacity");
  const targetInput = input.referenceTargets ?? [];
  if (!Array.isArray(targetInput) || targetInput.length > 64) throw new RPCProtocolError("configuration_capacity");
  const referenceTargets = Object.freeze(targetInput.map(captureServiceBindingTarget));
  if (new Set(referenceTargets.map(target => target.authority)).size !== referenceTargets.length) throw new RPCProtocolError("configuration_capacity");
  const serviceInput = input.executionServices ?? [], permissionInputExecution = input.executionPermissions ?? [];
  if (!Array.isArray(serviceInput) || serviceInput.length > 64 || !Array.isArray(permissionInputExecution) || permissionInputExecution.length > 64) throw new RPCProtocolError("configuration_capacity");
  const executionServices = Object.freeze(serviceInput.map(captureVolatileExecution));
  const executionPermissions = Object.freeze(permissionInputExecution.map(({ namespace, query, cancel }) => {
    if (!/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(namespace) || typeof query !== "boolean" || typeof cancel !== "boolean") throw new RPCProtocolError("configuration_capacity");
    return Object.freeze({ namespace, query, cancel });
  }));
  if (executionServices.length > 64 || executionPermissions.length > 64 || new Set(executionPermissions.map(entry => entry.namespace)).size !== executionPermissions.length) throw new RPCProtocolError("configuration_capacity");
  const handlerInput = input.unaryHandlers ?? [];
  if (!Array.isArray(handlerInput) || handlerInput.length > maxMethods) throw new RPCProtocolError("configuration_capacity");
  const declared = definitions.flatMap(definition => { const service = serviceDefinition(definition); return service.entries.map(entry => ({ namespace: service.namespace, method: entry.method })); });
  const keys = new Set<string>();
  const unaryHandlers = Object.freeze(handlerInput.map(entry => {
    const { namespace, method, contract, handler, options, offer, maximumOfferWindowMS } = entry, facts = methodDefinition(method);
    const key = `${namespace}\0${facts.typeID}`;
    if (keys.has(key) || typeof handler !== "function" || !declared.some(value => value.namespace === namespace && value.method === method) ||
        facts.shape !== "unary") throw new RPCProtocolError("configuration_capacity");
    keys.add(key); contract.checkMethod(namespace, facts);
    if (facts.restartFlush) checkMaintenanceOwner(input.maintenanceOwner);
    const execution = entry.execution === undefined ? undefined : captureVolatileExecution(entry.execution);
    if (facts.semantics === "execution") {
      if (execution === undefined || executionIdentity === undefined || offer === undefined || maximumOfferWindowMS === undefined ||
          execution.namespace !== namespace || !execution.callerAuthorities.includes(executionIdentity.authority) || contract.optionalUint(13) !== executionMode(execution) ||
          (contract.optionalUint(19) !== 0n && contract.optionalUint(19) !== 1n) || facts.checkpointFormat !== undefined && executionMode(execution) !== 1n) throw new RPCProtocolError("configuration_capacity");
      offer.copyEncoded(contract, maximumOfferWindowMS, new Uint8Array(256));
      executionStorage(execution)?.checkContract(contract, offer, maximumOfferWindowMS);
    } else if (execution !== undefined || offer !== undefined || maximumOfferWindowMS !== undefined) throw new RPCProtocolError("configuration_capacity");
    return Object.freeze({ namespace, method, contract, handler, options: captureUnaryHandler(options),
      ...(execution === undefined ? {} : { execution, offer: offer!, maximumOfferWindowMS: maximumOfferWindowMS! }) });
  }));
  const streamInput = input.streamingHandlers ?? [], streamKinds = new Set<string>();
  if (!Array.isArray(streamInput) || streamInput.length > maxMethods) throw new RPCProtocolError("configuration_capacity");
  const streamingHandlers = Object.freeze(streamInput.map(({ namespace, method, kind, metadata = new Uint8Array(), contract, handler, options, execution: executionInput, offer, maximumOfferWindowMS }) => {
    const facts = methodDefinition(method), key = `${namespace}\0${facts.typeID}`;
    checkStreamingTarget(kind, metadata);
    if (keys.has(key) || streamKinds.has(kind) || facts.shape !== "server_streaming" || facts.restartFlush ||
        typeof handler !== "function" && byteEventSource(handler) === undefined || !declared.some(entry => entry.namespace === namespace && entry.method === method)) throw new RPCProtocolError("configuration_capacity");
    contract.checkMethod(namespace, facts); keys.add(key); streamKinds.add(kind);
    const execution = executionInput === undefined ? undefined : captureVolatileExecution(executionInput);
    if (facts.semantics === "execution") {
      if (execution === undefined || executionIdentity === undefined || offer === undefined || maximumOfferWindowMS === undefined ||
          execution.namespace !== namespace || !execution.callerAuthorities.includes(executionIdentity.authority) || contract.optionalUint(13) !== executionMode(execution) ||
          (contract.optionalUint(19) !== 0n && contract.optionalUint(19) !== 1n) || facts.checkpointFormat !== undefined && executionMode(execution) !== 1n ||
          contract.streamContentMode() !== "none" && (facts.streamContent === undefined || executionMode(execution) !== 1n)) throw new RPCProtocolError("configuration_capacity");
      offer.copyEncoded(contract, maximumOfferWindowMS, new Uint8Array(256));
      executionStorage(execution)?.checkContract(contract, offer, maximumOfferWindowMS);
    } else if (execution !== undefined || offer !== undefined || maximumOfferWindowMS !== undefined) throw new RPCProtocolError("configuration_capacity");
    return Object.freeze({ namespace, method, kind, metadata: new Uint8Array(metadata), contract, handler, options: captureUnaryHandler(options),
      ...(execution === undefined ? {} : { execution, offer: offer!, maximumOfferWindowMS: maximumOfferWindowMS! }) });
  }));
  for (const source of streamingHandlers) {
    const definition = methodDefinition(source.method).streamContent;
    if (definition !== undefined && !unaryHandlers.some(reader => reader.namespace === source.namespace &&
        methodDefinition(reader.method).typeID === definition.readTypeID && reader.execution === source.execution)) throw new RPCProtocolError("configuration_capacity");
  }
  const notifyInput = input.notificationHandlers ?? [];
  // A local subscription selects an exact MethodDefinition. Reusing that
  // selector in another incoming namespace would make its dispatch ambiguous.
  const notificationSelectors = new Set<object>();
  if (!Array.isArray(notifyInput) || notifyInput.length > Math.min(maxMethods, 128)) throw new RPCProtocolError("configuration_capacity");
  const notificationHandlers = Object.freeze(notifyInput.map(({ namespace, method, contract, handler, options, execution: executionInput, offer, maximumOfferWindowMS }) => {
    const facts = methodDefinition(method), key = `${namespace}\0${facts.typeID}`;
    if (keys.has(key) || notificationSelectors.has(method) || typeof handler !== "function" || facts.shape !== "notify" ||
        !declared.some(value => value.namespace === namespace && value.method === method)) throw new RPCProtocolError("configuration_capacity");
    keys.add(key); notificationSelectors.add(method); contract.checkMethod(namespace, facts);
    const execution = executionInput === undefined ? undefined : captureVolatileExecution(executionInput);
    if (facts.semantics === "execution") {
      if (execution === undefined || executionIdentity === undefined || offer === undefined || maximumOfferWindowMS === undefined ||
          execution.namespace !== namespace || !execution.callerAuthorities.includes(executionIdentity.authority) || contract.optionalUint(13) !== executionMode(execution) ||
          (contract.optionalUint(19) !== 0n && contract.optionalUint(19) !== 1n)) throw new RPCProtocolError("configuration_capacity");
      offer.copyEncoded(contract, maximumOfferWindowMS, new Uint8Array(256));
      executionStorage(execution)?.checkContract(contract, offer, maximumOfferWindowMS);
    } else if (execution !== undefined || offer !== undefined || maximumOfferWindowMS !== undefined) throw new RPCProtocolError("configuration_capacity");
    return Object.freeze({ namespace, method, contract, handler, options: captureNotificationHandler(options),
      ...(execution === undefined ? {} : { execution, offer: offer!, maximumOfferWindowMS: maximumOfferWindowMS! }) });
  }));
  const notificationMethodInput = input.notificationMethods ?? [];
  if (!Array.isArray(notificationMethodInput) || notificationMethodInput.length > maxMethods) throw new RPCProtocolError("configuration_capacity");
  const notificationMethods = Object.freeze(notificationMethodInput.map(({ namespace, method, contract, permission }) => {
    const facts = methodDefinition(method), key = `${namespace}\0${facts.typeID}`;
    if (keys.has(key) || notificationSelectors.has(method) || facts.shape !== "notify" || facts.semantics !== "observation" || !["allowed", "denied", "unavailable"].includes(permission) ||
        !declared.some(value => value.namespace === namespace && value.method === method)) throw new RPCProtocolError("configuration_capacity");
    keys.add(key); notificationSelectors.add(method);
    if (contract instanceof Uint8Array) {
      if (byteLength(contract) < 1 || byteLength(contract) > 8192) throw new RPCProtocolError("configuration_capacity");
      return Object.freeze({ namespace, method, contract: new Uint8Array(contract), permission });
    }
    contract.checkMethod(namespace, facts); return Object.freeze({ namespace, method, contract, permission });
  }));
  const permissionInput = input.queryPermissions ?? [];
  if (!Array.isArray(permissionInput) || permissionInput.length > maxMethods) throw new RPCProtocolError("configuration_capacity");
  const permissionKeys = new Set<string>();
  const queryPermissions = Object.freeze(permissionInput.map(entry => {
    const { namespace, method, permission } = entry, facts = methodDefinition(method), key = `${namespace}\0${facts.typeID}`;
    if (permissionKeys.has(key) || !declared.some(value => value.namespace === namespace && value.method === method) ||
        !["unavailable", "denied", "allowed"].includes(permission)) throw new RPCProtocolError("configuration_capacity");
    permissionKeys.add(key); return Object.freeze({ namespace, method, permission });
  }));
  const histories = new Map<string, string>();
  for (const entry of [...executionServices, ...notificationHandlers.flatMap(entry => entry.execution === undefined ? [] : [entry.execution]), ...unaryHandlers.flatMap(entry => entry.execution === undefined ? [] : [entry.execution]), ...streamingHandlers.flatMap(entry => entry.execution === undefined ? [] : [entry.execution])]) {
    const encoded = JSON.stringify(entry, (_key, value) => typeof value === "bigint" ? value.toString() : value);
    const previous = histories.get(entry.namespace);
    if (previous !== undefined && previous !== encoded) throw new RPCProtocolError("configuration_capacity"); histories.set(entry.namespace, encoded);
  }
  const captured = Object.freeze({ ...(input.maintenanceOwner === undefined ? {} : { maintenanceOwner: input.maintenanceOwner }), query: Object.freeze({ typeID, contractDigest: new Uint8Array(digest) }),
    ...(resultRead === undefined ? {} : { resultRead: Object.freeze(resultRead) }),
    executionDelegations, referenceTargets, definitions: Object.freeze([...definitions]), maxMethods, maxCaptureBytes, queryAcquisitions, unaryHandlers, streamingHandlers, notificationHandlers, notificationMethods, queryPermissions, executionServices, executionPermissions, ...(localExecutionAuthority === undefined ? {} : { localExecutionAuthority }), ...(executionIdentity === undefined ? {} : { executionIdentity }) });
  // This also verifies unique trusted namespace/type identities without
  // executing any application encoder or authorization callback.
  contractRoutesCharge(captured.definitions, captured.maxMethods, 1n); return captured;
}
export interface RPCApplicationPlan {
  readonly charges: readonly ResourceVector[];
  readonly handlers: number;
  readonly streamingHandlers: number;
  readonly notificationHandlers: number;
  readonly notificationMethods: number;
  readonly notificationSubscribers: number;
  readonly notify: number;
  readonly inputs: number;
  readonly queries: number;
  readonly channel: number;
  readonly publication: number;
  readonly management: number;
  readonly resultRead: number;
}
export function rpcApplicationPlan(config: RPCApplicationConfig, profile: "services" | "execution", maxGeneral: number, runtimeBytes: bigint): RPCApplicationPlan {
  const referenceBytes = (config.referenceTargets ?? []).reduce((sum, target) => sum + 2048n + BigInt(target.peers.length) * 1024n, 0n);
  const charges = [new ResourceVector([8192n + referenceBytes + BigInt(config.executionDelegations?.length ?? 0) * 1536n + 65n * runtimeBytes, 0n, 0n, 84n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    applicationGroupCharge(runtimeBytes), rpcNetworkCharge({ profile, maxGeneral, query: config.query, runtimeBytes, ...(config.resultRead === undefined ? {} : { resultRead: config.resultRead }) }),
    contractRoutesCharge(config.definitions, config.maxMethods, runtimeBytes), contractQueryAccessCharge(config.definitions, config.maxMethods, runtimeBytes),
    rpcCallCapacityCharge(maxGeneral, runtimeBytes), completionPositionCharge(runtimeBytes)];
  const handlers = charges.length;
  for (const entry of config.unaryHandlers ?? []) {
    if (entry.options.maxConcurrentCalls > maxGeneral) throw new RPCProtocolError("configuration_capacity");
    charges.push(rpcUnaryRegistrationCharge(entry.options, runtimeBytes));
  }
  const streamingHandlers = charges.length;
  for (const entry of config.streamingHandlers ?? []) {
    const source = byteEventSource(entry.handler); if (source !== undefined) eventSourceCharge(source, runtimeBytes);
    if (entry.options.maxConcurrentCalls > maxGeneral) throw new RPCProtocolError("configuration_capacity");
    charges.push(rpcUnaryRegistrationCharge(entry.options, runtimeBytes).add(new ResourceVector([8192n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])));
  }
  const notificationHandlers = charges.length;
  for (const entry of config.notificationHandlers ?? []) charges.push(notificationRegistrationCharge(entry.options, runtimeBytes));
  const notificationMethods = charges.length;
  for (const entry of config.notificationMethods ?? []) if (entry.contract instanceof Uint8Array) charges.push(serviceContractCharge(runtimeBytes), serviceContractDecoderCharge(runtimeBytes));
  const notificationSubscribers = charges.length; charges.push(notificationSubscribersCharge(runtimeBytes));
  const inputs = charges.length; charges.push(...serviceInputsCharges(maxGeneral, runtimeBytes));
  const queries = charges.length; charges.push(...contractQuerySessionCharges(runtimeBytes));
  const channel = charges.length;
  charges.push(rpcChannelCharge(runtimeBytes),
    new ResourceVector([50304n + runtimeBytes, 0n, 0n, 5n, 6n, 6n, 4n, 0n, 0n, 1n, 0n]), applicationGroupCharge(runtimeBytes),
    ...rpcReceiverCharges(runtimeBytes), rpcPublisherCharge(runtimeBytes), writeRequestCharge(16384, runtimeBytes));
  const publication = charges.length - 1, management = charges.length;
  if (profile === "execution") charges.push(...executionManagementCharges(runtimeBytes));
  const resultRead = charges.length;
  if (config.resultRead !== undefined) charges.push(executionManagementDecoderCharge(runtimeBytes), new ResourceVector([4096n + runtimeBytes, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  const notify = charges.length; charges.push(...notifyChannelCharges(runtimeBytes), ...notifyChannelCharges(runtimeBytes));
  return Object.freeze({ charges: Object.freeze(charges), handlers, streamingHandlers, notificationHandlers, notificationMethods, notificationSubscribers, notify, inputs, queries, channel, publication, management, resultRead });
}

/** Original pre-spend Session RPC admission. All fixed query/network/input and
 * first-channel objects and execution-service attachments are acquired before
 * irreversible authorization consumption. Authentication and physical Stream
 * binding remain gates in the original Session; this owner cannot assert READY. */
export class RPCApplicationAdmission {
  readonly #profile: "services" | "execution";
  readonly #general: number;
  #deadline: TrustedDeadline | undefined;
  readonly #runtimeBytes: bigint;
  #reference: ResourceReference | undefined;
  #group: ApplicationGroup | undefined;
  #channelGroup: ApplicationGroup | undefined;
  #network: RPCNetwork | undefined;
  #calls: RPCCallCapacity | undefined;
  #completion: CompletionPosition | undefined;
  #routes: ContractRoutes | undefined;
  #access: ContractQueryAccess | undefined;
  #inputs: ServiceInputs | undefined;
  #queries: ContractQuerySession | undefined;
  #acquisitions: ContractQueryAcquisitions | undefined;
  #host: Readonly<{ root: ResourceRoot; accounts: readonly ResourceAccount[]; sendAccounts: readonly ResourceAccount[];
    owner: ResourceOwner; clock: TrustedClock; delivery: ReceiveDeliveryGate; notificationAccounts: readonly (readonly ResourceAccount[])[] }> | undefined;
  #cleanup: SessionCleanup | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #executionIdentity: RPCExecutionIdentity | undefined;
  #managementLease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #localExecutionAuthority: string | undefined;
  #referenceTargets: readonly ServiceBindingTarget[] = [];
  #executionDelegations: readonly RPCExecutionDelegation[] = [];
  readonly #executionPermissions: readonly Readonly<{ namespace: string; query: boolean; cancel: boolean }>[];
  readonly #histories = new Map<string, VolatileExecutions>();
  #management: ExecutionManagementChannel | undefined;
  #managementGroup: ApplicationGroup | undefined;
  #managementPosition: ProtectedResourceReservation | undefined;
  readonly #managementRefs: ResourceReference[] = [];
  readonly #managementPositions: ProtectedResourceReservation[] = [];
  #managementChanged: (() => void) | undefined;
  readonly #managementWaiters = new Set<() => void>();
  #managementUnavailable = false;
  #resultReadCodec: ExecutionManagementCodec | undefined;
  #resultReadReference: ResourceReference | undefined;
  #resultReadBuffer = new Uint8Array();
  #resultReadBusy = false;
  #subscribers: NotificationSubscribers | undefined;
  readonly #notificationAccess = new Map<object, NotificationAccess>();
  readonly #notificationBusinesses = new Map<object, NotificationRegistration>();
  readonly #notifyPreparations = new Set<NotifyPreparation>();
  readonly #notifyChannels: (NotifyChannel | undefined)[] = [undefined, undefined];
  readonly #notifyRefs: ResourceReference[][] = [[], []];
  readonly #notifyPositions: ProtectedResourceReservation[] = [];
  readonly #notifyGroups: ApplicationGroup[] = [];
  readonly #maxCaptureBytes: number;
  readonly #unary = new Set<RPCUnaryExchange>();
  readonly #inbound = new Set<RPCUnaryDispatch>();
  readonly #serviceClients = new Set<ServiceBinding>();
  readonly #serviceGroup: object = Object.freeze(Object.create(null) as object);
  readonly #inboundAbort = new AbortController();
  #nextInbound = 0n;
  #nextRegistration = 0n;
  readonly #preparations = new Set<RPCUnaryPreparation<RPCPreparedExchange>>();
  #streamOpener: RPCStreamOpener | undefined;
  #session: object | undefined;
  readonly #resumeDispatches = new Set<RPCResumeDispatch>();
  #preaccepted: RPCPreacceptedStreams | undefined;
  #initialStreams: RPCStreamPreparation | undefined;
  readonly #streamHandlers = new Map<string, RPCApplicationStreamingHandler>();
  readonly #streaming = new Set<RPCStreamingExchange>();
  readonly #streamDispatches = new Set<RPCStreamingDispatch>();
  #nextPreparation = 0n;
  #random: RandomFill | undefined;
  #bindings: ServiceBindingPool | undefined;
  #channel: RPCChannelRuntime | undefined;
  #publication: ProtectedResourceReservation | undefined;
  readonly #channelRefs: ResourceReference[] = [];
  #checkpointPolicy: CheckpointSessionPolicy | undefined;
  #claimed = false;
  #bound = false;
  #closed = false;
  #closing = false;
  #draining = false;
  #dispatching = false;
  #collecting = false;
  #observer: (() => void) | undefined;
  #cleaned: (() => void) | undefined;
  #turnTimer: ReturnType<typeof setTimeout> | undefined;
  #turnResolve: (() => void) | undefined;
  readonly #maintenanceOwner: V4MaintenanceOwner | undefined;
  constructor(config: RPCApplicationConfig, profile: "services" | "execution", maxGeneral: number, root: ResourceRoot,
    accounts: readonly ResourceAccount[], sendAccounts: readonly ResourceAccount[], owner: ResourceOwner, clock: TrustedClock, deadline: TrustedDeadline, delivery: ReceiveDeliveryGate,
    runtimeBytes: bigint, references: readonly ResourceReference[], acquisitions: ContractQueryAcquisitions, random: RandomFill, bindings: ServiceBindingPool, executionOwner: (config: VolatileExecutionConfig) => VolatileExecutions, notificationAccounts: readonly (readonly ResourceAccount[])[], prepaidCalls?: RPCCallCapacity, prepaidServices?: RPCApplicationServices, initialStreams?: RPCStreamPreparation) {
    const plan = rpcApplicationPlan(config, profile, maxGeneral, runtimeBytes);
    this.#maxCaptureBytes = config.maxCaptureBytes; this.#maintenanceOwner = config.maintenanceOwner;
    if (config.maintenanceOwner !== undefined) checkMaintenanceOwner(config.maintenanceOwner, references[0]!);
    this.#executionIdentity = config.executionIdentity; this.#localExecutionAuthority = config.localExecutionAuthority; this.#referenceTargets = config.referenceTargets ?? []; this.#executionDelegations = config.executionDelegations ?? [];
    this.#executionPermissions = config.executionPermissions ?? [];
    if (profile !== "execution" && ((config.executionServices?.length ?? 0) !== 0 || this.#executionPermissions.length !== 0 || this.#executionDelegations.length !== 0 || config.localExecutionAuthority !== undefined || config.executionIdentity !== undefined)) throw new RPCProtocolError("configuration_capacity");
    if (references.length !== plan.charges.length || !deadline.belongsTo(clock) || !references.every(reference => references[0]!.sameEnvironment(reference)) ||
        !acquisitions.sameEnvironment(references[0]!, clock)) throw new RPCProtocolError("rpc_owner");
    this.#profile = profile; this.#general = maxGeneral; this.#deadline = deadline; this.#runtimeBytes = runtimeBytes; this.#acquisitions = acquisitions; this.#random = random; this.#bindings = bindings;
    this.#host = { root, accounts: Object.freeze([...accounts]), sendAccounts: Object.freeze([...sendAccounts]), owner: Object.freeze({ ...owner }), clock, delivery, notificationAccounts };
    this.#reference = references[0]!.take(plan.charges[0]!);
    this.#initialStreams = initialStreams;
    try {
      if (prepaidServices !== undefined && (!prepaidServices.group.sameEnvironment(this.#reference) ||
          prepaidServices.completion.group !== prepaidServices.group || prepaidServices.queries.group !== prepaidServices.group ||
          prepaidServices.queries.direction !== 0 || prepaidServices.notificationGroups.length !== 2 ||
          !prepaidServices.channelGroup.sameEnvironment(this.#reference) ||
          !prepaidServices.notificationGroups.every(group => group.sameEnvironment(this.#reference!)))) throw new RPCProtocolError("rpc_owner");
      this.#group = prepaidServices?.group ?? applicationGroup(root, accounts, { ...owner, kind: "rpc_application" }, runtimeBytes, true, references[1]!);
      this.#completion = prepaidServices?.completion ?? this.#group.protectCompletion(runtimeBytes, references[6]!);
      if (prepaidCalls !== undefined && (prepaidCalls.limit !== maxGeneral || !prepaidCalls.sameEnvironment(this.#reference))) throw new RPCProtocolError("rpc_call_owner");
      this.#calls = prepaidCalls ?? new RPCCallCapacity(maxGeneral, runtimeBytes, references[5]!);
      this.#network = new RPCNetwork({ profile, maxGeneral, query: config.query, runtimeBytes, ...(config.resultRead === undefined ? {} : { resultRead: config.resultRead }) }, references[2]!, this.#calls);
      this.#routes = new ContractRoutes(config.definitions, config.maxMethods, runtimeBytes, references[3]!, clock);
      for (const configEntry of config.executionServices ?? []) this.#histories.set(configEntry.namespace, executionOwner(configEntry));
      for (const [index, entry] of (config.unaryHandlers ?? []).entries()) {
        if (entry.execution !== undefined && profile !== "execution") throw new RPCProtocolError("configuration_capacity");
        const history = entry.execution === undefined ? undefined : executionOwner(entry.execution);
        if (history !== undefined) this.#histories.set(entry.namespace, history);
        const registration = new RPCUnaryRegistration(entry.method, entry.handler, entry.options, runtimeBytes, references[plan.handlers + index]!, history);
        try {
          this.#routes.install(entry.namespace, entry.method, [entry.contract]);
          this.#routes.installHandler(entry.namespace, entry.method, registration);
          const digest = new Uint8Array(32); entry.contract.copyDigest(digest);
          try { this.#routes.advertise(entry.namespace, entry.method, digest, entry.offer, entry.maximumOfferWindowMS); } finally { digest.fill(0); }
        } catch (error) { registration.close(); throw error; }
      }
      for (const [index, entry] of (config.streamingHandlers ?? []).entries()) {
        if (entry.execution !== undefined && profile !== "execution") throw new RPCProtocolError("configuration_capacity");
        const history = entry.execution === undefined ? undefined : executionOwner(entry.execution);
        if (history !== undefined) this.#histories.set(entry.namespace, history);
        const registration = new RPCUnaryRegistration(entry.method, entry.handler, entry.options, runtimeBytes, references[plan.streamingHandlers + index]!, history, "server_streaming");
        try {
          this.#routes.install(entry.namespace, entry.method, [entry.contract]);
          this.#routes.installStreamingHandler(entry.namespace, entry.method, registration);
          const digest = new Uint8Array(32); entry.contract.copyDigest(digest);
          try { this.#routes.advertise(entry.namespace, entry.method, digest, entry.offer, entry.maximumOfferWindowMS); } finally { digest.fill(0); }
          this.#streamHandlers.set(entry.kind, entry);
        } catch (error) { registration.close(); throw error; }
      }
      this.#subscribers = new NotificationSubscribers(root, accounts, owner, clock, runtimeBytes, references[plan.notificationSubscribers]!);
      let notificationContractIndex = plan.notificationMethods;
      for (const entry of config.notificationMethods ?? []) {
        const snapshot = entry.contract instanceof Uint8Array
          ? new ServiceContractSnapshot(entry.contract, runtimeBytes, references[notificationContractIndex++]!, references[notificationContractIndex++]!) : entry.contract;
        try {
          this.#routes.install(entry.namespace, entry.method, [snapshot]);
          const digest = new Uint8Array(32); snapshot.copyDigest(digest);
          try { this.#routes.advertise(entry.namespace, entry.method, digest); } finally { digest.fill(0); }
          this.#notificationAccess.set(entry.method, new NotificationAccess(entry.permission));
        } finally { if (entry.contract instanceof Uint8Array) snapshot.release(); }
      }
      for (const [index, entry] of (config.notificationHandlers ?? []).entries()) {
        const access = new NotificationAccess("allowed"); this.#notificationAccess.set(entry.method, access);
        const history = entry.execution === undefined ? undefined : executionOwner(entry.execution);
        if (history !== undefined) {
          if (profile !== "execution") throw new RPCProtocolError("configuration_capacity");
          this.#histories.set(entry.namespace, history);
        }
        const registration = new NotificationRegistration(entry.handler, { ...captureNotificationHandler(entry.options), pendingPolicy: "drop_newest" }, access, runtimeBytes, references[plan.notificationHandlers + index]!, {
            clock, reserve: charge => root.reserve({ accounts, owner: { ...owner, kind: "notification_business_wait" }, charge }), released: () => undefined,
          });
        try {
          this.#notificationBusinesses.set(entry.method, registration);
          this.#routes.install(entry.namespace, entry.method, [entry.contract]);
          if (history !== undefined) this.#routes.installNotificationHandler(entry.namespace, entry.method, registration);
          const digest = new Uint8Array(32); entry.contract.copyDigest(digest);
          try { this.#routes.advertise(entry.namespace, entry.method, digest, entry.offer, entry.maximumOfferWindowMS); } finally { digest.fill(0); }
        } catch (error) { registration.close(); throw error; }
      }
      const notifyCosts = notifyChannelCharges(runtimeBytes);
      for (let position = 0; position < 2; position++) {
        const refs = references.slice(plan.notify + position * notifyCosts.length, plan.notify + (position + 1) * notifyCosts.length);
        this.#notifyGroups.push(prepaidServices?.notificationGroups[position] ?? applicationGroup(root, accounts, { ...owner, kind: `notify_channel_${position}` }, runtimeBytes, false, refs[2]!));
        this.#notifyPositions.push(root.protect(refs[5]!, notifyCosts[5]!));
        for (const index of [0, 1, 3, 4]) this.#notifyRefs[position]![index] = refs[index]!.take(notifyCosts[index]!);
      }
      this.#access = new ContractQueryAccess(config.definitions, config.maxMethods, delivery, runtimeBytes, references[4]!);
      for (const entry of config.queryPermissions ?? []) this.#access.set(entry.namespace, methodDefinition(entry.method).typeID, entry.permission);
      this.#inputs = new ServiceInputs(this.#network, this.#routes, { root, accounts, owner, deadline, maxCaptureBytes: config.maxCaptureBytes, runtimeBytes }, references.slice(plan.inputs, plan.queries));
      this.#queries = new ContractQuerySession(this.#network, this.#inputs, this.#routes, this.#access, this.#group,
        root, delivery, deadline, runtimeBytes, references.slice(plan.queries, plan.channel), prepaidServices?.queries, prepaidServices?.outgoing);
      this.#channelGroup = prepaidServices?.channelGroup ?? applicationGroup(root, accounts, { ...owner, kind: "rpc_first_channel" }, runtimeBytes, true, references[plan.channel + 2]!);
      this.#publication = root.protect(references[plan.publication]!, plan.charges[plan.publication]!);
      for (let i = plan.channel; i < plan.management; i++) if (i !== plan.channel + 2 && i !== plan.publication) this.#channelRefs.push(references[i]!.take(plan.charges[i]!));
      if (profile === "execution") {
        const costs = executionManagementCharges(runtimeBytes), refs = references.slice(plan.management, plan.resultRead);
        this.#managementPosition = root.protect(refs[6]!, costs[6]!);
        for (let i = 0; i < 6; i++) this.#managementPositions.push(root.protect(refs[i]!, costs[i]!));
      }
      if (config.resultRead !== undefined) {
        this.#resultReadReference = references[plan.resultRead + 1]!.take(plan.charges[plan.resultRead + 1]!);
        this.#resultReadCodec = new ExecutionManagementCodec(runtimeBytes, references[plan.resultRead]!);
        this.#resultReadBuffer = new Uint8Array(1024);
      }
      this.#observer = root.observeAvailability(this.#reference, () => { this.#collect(); if (!this.#closed) this.#managementChanged?.(); }); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void { if (this.#closed) throw new RPCProtocolError("rpc_closed"); this.#reference!.check(); }
  /** Once-only transfer to the actual authenticated Session assembly. */
  claim(reference: ResourceReference, profile: string, maxGeneral: number, deadline: TrustedDeadline, cleanup: SessionCleanup,
    authentication?: V4AuthenticatedContext, checkpointPolicy?: CheckpointSessionPolicy, session?: object): void {
    this.#check();
    if (this.#claimed || profile !== this.#profile || maxGeneral !== this.#general || deadline !== this.#deadline ||
        !this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("rpc_owner");
    if (this.#executionIdentity !== undefined && (authentication?.peerSubject !== this.#executionIdentity.subject ||
        authentication.peerIdentityDigest !== this.#executionIdentity.identityDigest)) throw new RPCProtocolError("permission_denied");
    this.#claimed = true; this.#cleanup = cleanup; this.#checkpointPolicy = checkpointPolicy; this.#session = session;
    this.#authentication = authentication === undefined ? undefined : Object.freeze({ ...authentication });
    if (profile === "execution") this.#managementLease = this.#host!.delivery.retain(this.#reference!, () => this.close());
  }
  /** Called only after the real fixed-scope prefix is bound. This never sends
   * another OPEN and never creates a channel for each service or method. */
  bindBootstrap(stream: V4StreamOwner): void {
    this.#check(); if (!this.#claimed || this.#bound) throw new RPCProtocolError("rpc_owner"); this.#bound = true;
    const refs = this.#channelRefs;
    try {
      this.#channel = new RPCChannelRuntime(stream, this.#network!, this.#inputs!, this.#runtimeBytes,
        { channel: refs[0]!, adapter: refs[1]!, application: this.#channelGroup!, receiver: refs.slice(2, 7), publisher: refs[7]!, publication: this.#publication! });
      this.#dispatching = true;
      void this.#dispatch(this.#channel); this.#channel.start();
    } catch (error) { this.close(); throw error; }
    finally { for (const reference of refs) reference.release(); refs.length = 0; }
  }
  bindNotify(stream: V4StreamOwner, position: 0 | 1): void {
    this.#check(); if (this.#notifyChannels[position] !== undefined || this.#draining) throw new RPCProtocolError("notify_unavailable");
    const refs = this.#notifyRefs[position]!;
    try {
      const channel = new NotifyChannel(stream, this.#runtimeBytes, refs, this.#notifyGroups[position]!, this.#notifyPositions[position]!, header => this.#acceptNotification(header), () => this.#collect());
      this.#notifyChannels[position] = channel; channel.start();
    } finally { for (const ref of refs) ref?.release(); refs.length = 0; }
  }
  notifyReady(): boolean { return !this.#closed && this.#notifyChannels.some(channel => channel?.ready()); }
  subscribeNotification<Input, Value>(method: object, handler: V4NotificationHandler<Value>, options: V4NotificationSubscriptionOptions<Input, Value>): V4NotificationSubscription<Value> {
    this.#check(); if (this.#draining || this.#authentication === undefined) throw new RPCProtocolError("source_unavailable");
    const access = this.#notificationAccess.get(method), definition = methodDefinition(method);
    if (access === undefined || definition.shape !== "notify") throw new RPCProtocolError("method_unavailable");
    const registration = this.#subscribers!.subscribe(method, definition, handler as V4NotificationHandler<unknown>, options as V4NotificationSubscriptionOptions<unknown, unknown>, access);
    try { this.#check(); if (this.#draining) throw new RPCProtocolError("source_unavailable"); return notificationSubscription<Value>(registration); }
    catch (error) { registration.close(); throw error; }
  }
  #acceptNotification(header: ApplicationHeader): NotificationMessage | undefined {
    let route: CapturedContractRoute | undefined, references: readonly ResourceReference[] = [];
    try {
      this.#check(); if (this.#draining || (header.kind !== "observation_notify" && header.kind !== "execution_notify") || header.payloadBytes > this.#maxCaptureBytes || this.#authentication === undefined || this.#cleanup === undefined) return;
      route = this.#routes!.capture(header); if (route === undefined || !route.registered) return;
      const access = this.#notificationAccess.get(route.method); if (access === undefined) return; access.check();
      route.contract.checkRequest(header);
      const host = this.#host!, sample = host.clock.sample(), now = sample.requireInterval(), cutoff = header.uint(5);
      this.#deadline!.checkAt(sample); this.#check(); access.check();
      if (cutoff <= now.upperMS || cutoff > timeAdd(now.lowerMS, route.contract.uint(header.kind === "execution_notify" ? 17 : 11))) return;
      const deadline = this.#deadline!.fork(cutoff < this.#deadline!.cap ? cutoff : this.#deadline!.cap);
      if (this.#nextInbound === (1n << 64n) - 1n) return; const id = ++this.#nextInbound;
      references = host.root.reserveBatch(notificationMessageCharges(header.payloadBytes, this.#runtimeBytes).map((charge, index) => ({ accounts: host.accounts, owner: { ...host.owner, kind: `notify_message_${id}_${index}` }, charge })));
      const input = new NotificationMessage(header, route, deadline, this.#runtimeBytes, references, (original, request, payload, limit) => {
        if (header.kind === "execution_notify") return this.#dispatchNotification(original, request, payload, limit);
        this.#fanoutNotification(original, payload, limit); return false;
      });
      route = undefined; return input;
    } catch { return undefined; }
    finally { route?.close(); for (const reference of references) reference.release(); }
  }
  #dispatchNotification(route: CapturedContractRoute, request: RpcInputTypes.RPCRequestInput, bytes: Uint8Array, deadline: TrustedDeadline): boolean {
    this.#check(); deadline.check();
    const registration = this.#notificationBusinesses.get(route.method), history = this.#histories.get(route.namespace), access = this.#notificationAccess.get(route.method);
    if (registration === undefined || history === undefined || access === undefined || this.#executionIdentity === undefined || !registration.available() || request.header.uint(7) === 1n && !registration.idle) return false;
    registration.check(); access.check();
    const boundary = this.#subscribers!.boundary, host = this.#host!;
    if (this.#nextInbound === (1n << 64n) - 1n) return false; const id = ++this.#nextInbound;
    const refs = host.root.reserveBatch([rpcPayloadCharge(bytes.length, this.#runtimeBytes), notificationWorkCharge(route.definition, registration.options, this.#runtimeBytes)]
      .map((charge, index) => ({ accounts: host.accounts, owner: { ...host.owner, kind: `notify_execution_${id}_${index}` }, charge })));
    let execution: NotificationExecution | undefined, input: NotificationInput | undefined;
    try {
      execution = new NotificationExecution(request, route, deadline, history, this.#routes!, this.#authentication!, this.#executionIdentity,
        { check: () => registration.check(), current: () => registration.current() }, () => {
          const original = request.borrow();
          try { this.#fanoutNotification(route, original.bytes, deadline, this.#subscribers!.snapshot(route.method, boundary)); } finally { original.release(); }
        });
      input = new NotificationInput(bytes, route.definition, registration, deadline.fork(deadline.cap), this.#group!, this.#authentication!, host.delivery, this.#cleanup!, this.#runtimeBytes, refs, execution);
      input.ready(); return true;
    } catch { input?.close(); execution?.close(); return false; }
    finally { for (const ref of refs) ref.release(); }
  }
  #fanoutNotification(route: CapturedContractRoute, bytes: Uint8Array, deadline: TrustedDeadline, captured?: readonly NotificationRegistration[]): void {
    this.#check(); deadline.check();
    if (this.#draining || this.#cleanup === undefined || this.#authentication === undefined) return;
    const access = this.#notificationAccess.get(route.method); access?.check(); if (access === undefined) return;
    // Capture once at complete-message admission; no late registration replay.
    const registrations = captured ?? [...(this.#notificationBusinesses.has(route.method) ? [this.#notificationBusinesses.get(route.method)!] : []), ...this.#subscribers!.snapshot(route.method)], host = this.#host!;
    for (const registration of registrations) {
      if (registration.closed) continue;
      if (!registration.available()) { registration.gap("dropped_budget"); continue; }
      let refs: readonly ResourceReference[] = [], input: NotificationInput | undefined;
      try {
        this.#check(); deadline.check(); access.check(); registration.check();
        if (this.#nextInbound === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted"); const id = ++this.#nextInbound;
        refs = host.root.reserveBatch([rpcPayloadCharge(bytes.length, this.#runtimeBytes), notificationWorkCharge(route.definition, registration.options, this.#runtimeBytes)]
          .map((charge, index) => ({ accounts: host.accounts, owner: { ...host.owner, kind: `notify_observer_${id}_${index}` }, charge })));
        input = new NotificationInput(bytes, route.definition, registration, deadline.fork(deadline.cap), this.#group!, this.#authentication!, host.delivery, this.#cleanup!, this.#runtimeBytes, refs);
        input.ready();
      } catch { if (input === undefined) registration.gap("dropped_budget"); else input.close("dropped_budget"); }
      finally { for (const ref of refs) ref.release(); }
    }
  }
  prepareNotify(method: object, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined, value: unknown, options: NotifyPreparationOptions,
    source: RPCPublicationGuard, workClass: ApplicationWorkClass, context?: V4ApplicationContext, signal?: AbortSignal, destination?: ServiceBindingTarget): Promise<NotifyPreparation> {
    this.#check(); const definition = methodDefinition(method), captured = captureNotifyOptions(options, context), host = this.#host!;
    if (this.#draining || this.#cleanup === undefined || this.#authentication === undefined || definition.shape !== "notify" || definition.semantics === "execution" && this.#profile !== "execution") throw new RPCProtocolError("notify_unavailable");
    contract.checkMethod(namespace, definition); source.check(); this.#check();
    if (!source.current() || signal?.aborted || context?.signal.aborted) throw new RPCProtocolError("canceled");
    const localClass = applicationWorkClass(workClass, context), inputBytes = messageInputBytes(value, definition.request.implementation, definition.request.maximum);
    if (this.#nextPreparation === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted"); const id = ++this.#nextPreparation;
    // Fix the original channel's send budget before retaining immutable bytes.
    // Start cannot silently move a preparation to a different channel/account.
    let position = this.#notifyChannels.findIndex(channel => channel?.ready());
    if (position < 0) position = this.#notifyChannels.findIndex(channel => channel !== undefined);
    if (position < 0) position = this.#authentication.localRole === "client" ? 0 : 1;
    const costs = notifyPreparationCharges(definition, contract, inputBytes, this.#runtimeBytes);
    const prepaid = initializerCallBacking(context, this, method, namespace, destination, costs, host.accounts, host.notificationAccounts[position]!);
    const refs = prepaid?.references ?? host.root.reserveBatch(costs.map((charge, index) => ({
      accounts: index === 1 ? host.notificationAccounts[position]! : host.accounts, owner: { ...host.owner, kind: `notify_preparation_${id}_${index}` }, charge })));
    let operation: NotifyPreparation | undefined;
    try {
      operation = new NotifyPreparation(definition, namespace, contract, captured, source, { start: original => {
        this.#check(); if (this.#draining) throw new RPCProtocolError("source_unavailable");
        const channel = this.#notifyChannels[position];
        return channel?.submit(original) ?? Object.freeze({ status: "not_admitted", submission: "not_submitted", reason: "not_ready" });
      } }, host.clock, this.#deadline!, this.#group!, this.#authentication, host.delivery, this.#cleanup, localClass, inputBytes, this.#runtimeBytes, refs, offer, this.#random, this.#localExecutionAuthority, destination);
      const original = operation; this.#notifyPreparations.add(original); original.onDetach(() => { this.#notifyPreparations.delete(original); this.#collect(); });
      return original.encode(value, context, signal).then(() => { original.checkPublication(); return original; });
    } catch (error) { operation?.close(); throw error; }
    finally { for (const ref of refs) ref.release(); }
  }
  bindManagement(stream: V4StreamOwner): void {
    this.#check(); if (this.#profile !== "execution" || this.#management !== undefined || this.#managementUnavailable || this.#draining) throw new RPCProtocolError("management_unavailable");
    const refs = this.#managementRefs;
    try {
      this.#management = new ExecutionManagementChannel(stream, this.#host!.clock, this.#deadline!, this.#managementPosition!, this.#runtimeBytes,
        refs, this.#managementGroup!, (target, cancel) => {
          const history = this.#histories.get(target.namespace);
          if (history === undefined) return { status: "unavailable" };
          return history.manage(target, cancel, { check: () => this.#authorizeManagement(target, cancel, false), current: () => !this.#closed });
        }, (target, cancel, outgoing) => this.#authorizeManagement(target, cancel, outgoing), () => { this.#collect(); this.#managementChanged?.(); });
      this.#management.start(); for (const wake of this.#managementWaiters) wake();
    } catch (error) { this.managementFailed(); throw error; }
    finally { for (const reference of refs) reference.release(); refs.length = 0; }
  }
  managementFailed(): void {
    this.#managementUnavailable = true; this.#management?.close(); this.#managementGroup?.close();
    for (const reference of this.#managementRefs) reference.release(); this.#managementRefs.length = 0;
    for (const wake of this.#managementWaiters) wake(); this.#managementChanged?.();
  }
  onManagementChange(callback: () => void): void {
    this.#check(); if (this.#managementChanged !== undefined) throw new RPCProtocolError("management_owner"); this.#managementChanged = callback;
  }
  managementReady(): boolean { return this.#management !== undefined && !this.#management.closed; }
  managementReusable(): boolean {
    return !this.#closed && !this.managementReady() && this.#management?.cleanupComplete() !== false && this.#managementGroup?.cleanupComplete() !== false &&
      this.#managementRefs.length === 0 && this.#managementPositions.every(position => position.available()) && this.#managementPosition?.available() === true;
  }
  prepareManagement(): void {
    this.#check(); if (this.#draining || !this.managementReusable()) throw new RPCProtocolError("management_unavailable");
    this.#management = undefined; this.#managementGroup = undefined;
    const host = this.#host!, refs: ResourceReference[] = [];
    try {
      for (const position of this.#managementPositions) refs.push(position.checkout());
      this.#managementGroup = applicationGroup(host.root, host.accounts, { ...host.owner, kind: "execution_management" }, this.#runtimeBytes, true, refs[2]!);
      const costs = executionManagementCharges(this.#runtimeBytes);
      for (const i of [0, 1, 3, 4, 5]) this.#managementRefs.push(refs[i]!.take(costs[i]!));
      this.#managementUnavailable = false;
    } catch (error) { this.managementFailed(); throw error; }
    finally { for (const reference of refs) reference.release(); }
  }
  #authorizeManagement(target: ExecutionTarget, cancel: boolean, outgoing: boolean): void {
    this.#check(); this.#deadline!.check(); this.#managementLease?.check(); const identity = this.#executionIdentity, authentication = this.#authentication;
    if (this.#profile !== "execution" || authentication === undefined || target.tenant !== authentication.tenant || target.audience !== authentication.audience) throw new RPCProtocolError("permission_denied");
    let authority: string | undefined, subject: string;
    if (outgoing) { authority = this.#localExecutionAuthority; subject = authentication.localSubject; }
    else {
      const permission = this.#executionPermissions.find(entry => entry.namespace === target.namespace);
      if (identity === undefined || identity.subject !== authentication.peerSubject || identity.identityDigest !== authentication.peerIdentityDigest ||
          !(cancel ? permission?.cancel : permission?.query)) throw new RPCProtocolError("permission_denied");
      authority = identity.authority; subject = identity.subject;
    }
    if (authority === undefined) throw new RPCProtocolError("permission_denied");
    if (authority !== target.authority || subject !== target.subject) {
      const grant = this.#executionDelegations.find(entry => entry.direction === (outgoing ? "outgoing" : "incoming") && entry.namespace === target.namespace &&
        entry.principalAuthority === authority && entry.principalSubject === subject && entry.targetAuthority === target.authority && entry.targetSubject === target.subject);
      if (grant === undefined || !(cancel ? grant.cancel : grant.query)) throw new RPCProtocolError("permission_denied");
      // Current trusted time and the original grant cutoff are checked again
      // at every management publication and retained-result fragment.
      const now = this.#host!.clock.sample().requireInterval(); this.#check();
      if (now.upperMS >= grant.notAfterMS) throw new RPCProtocolError("permission_denied");
    }
    this.#check();
  }
  async manageExecution(reference: V4OperationReference, cancel: boolean, deadline: TrustedDeadline, signal?: AbortSignal): Promise<ExecutionManagementResult> {
    this.#check(); if (this.#authentication === undefined) throw new RPCProtocolError("permission_denied");
    const target = operationTarget(reference, this.#authentication, this.#referenceTargets);
    this.#authorizeManagement(target, cancel, true);
    if (!this.managementReady()) {
      if (this.#managementWaiters.size >= 2 || this.#managementUnavailable || this.#draining) throw new RPCProtocolError("management_unavailable");
      await new Promise<void>((resolve, reject) => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const finish = (): void => {
          if (timer !== undefined) clearTimeout(timer); timer = undefined;
          this.#managementWaiters.delete(wake); if (signal !== undefined) managementRemoveListener.call(signal, "abort", wake);
        };
        const wake = (): void => {
          try {
            this.#check(); deadline.check(); if (signal !== undefined && managementAborted.call(signal)) throw new RPCProtocolError("canceled");
            if (this.#managementUnavailable || this.#draining) throw new RPCProtocolError("management_unavailable");
            if (this.managementReady()) { finish(); resolve(); }
          } catch (error) { finish(); reject(error); }
        };
        try {
          const remaining = deadline.remainingMS();
          this.#managementWaiters.add(wake); if (signal !== undefined) managementAddListener.call(signal, "abort", wake, { once: true });
          timer = setTimeout(wake, Number(remaining > 2147483647n ? 2147483647n : remaining)); wake();
        } catch (error) { finish(); reject(error); }
      });
    }
    return this.#management!.request(target, cancel, deadline, signal);
  }
  get bound(): boolean { return this.#bound; }
  /** Fixed ordinary read, admitted as general K + complete result ownership.
   * No management request, Offer refresh or execution registration is hidden. */
  readExecutionResult(reference: V4OperationReference, deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): RPCUnaryExchange {
    this.#check();
    if (this.#draining || this.#authentication === undefined || this.#resultReadCodec === undefined || this.#channel === undefined || this.#resultReadBusy) throw new RPCProtocolError("service_unavailable");
    if (signal !== undefined && managementAborted.call(signal)) throw new RPCProtocolError("canceled");
    const target = operationTarget(reference, this.#authentication, this.#referenceTargets), limit = operationResultLimit(reference), host = this.#host!, cleanup = this.#cleanup!;
    if (!deadline.belongsTo(host.clock) || deadline.cap > this.#deadline!.cap) throw new RPCProtocolError("rpc_request_binding");
    this.#authorizeManagement(target, false, true); deadline.check();
    const workClass = applicationWorkClass("resident", context);
    this.#resultReadBusy = true;
    let references: readonly ResourceReference[] = [], reserved: ReturnType<RPCApplicationAdmission["reserveCall"]> | undefined;
    let request: RPCPayload | undefined, exchange: RPCUnaryExchange | undefined, job = false;
    try {
      if (this.#nextPreparation === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
      const id = ++this.#nextPreparation, encoded = this.#resultReadCodec.encodeTarget(target, this.#resultReadBuffer);
      const costs = rpcUnaryExchangeCharges(encoded.length, limit, this.#runtimeBytes);
      references = host.root.reserveBatch(costs.map((charge, index) => ({ accounts: index === 1 ? host.sendAccounts : host.accounts,
        owner: { ...host.owner, kind: `rpc_result_read_${id}_${index}` }, charge })));
      reserved = this.reserveCall(workClass);
      request = new RPCPayload(encoded.length, this.#runtimeBytes, references[1]!); request.write(0, encoded);
      const header = this.#channel.resultReadHeader(encoded.length, deadline.cap);
      const guard: RPCPublicationGuard = Object.freeze({ check: () => this.#authorizeManagement(target, false, true), current: () => !this.#closed });
      cleanup.startJob(); job = true;
      exchange = new RPCUnaryExchange(header, undefined, request, deadline, guard, host.delivery, host.root, this.#runtimeBytes,
        [references[0]!, references[2]!], reserved.call, reserved.completion, undefined, this.#authentication, undefined, limit);
      const original = exchange; this.#unary.add(original);
      original.onNetworkCleanup(() => { this.#unary.delete(original); cleanup.finishJob(); this.#collect(); }); job = false;
      this.#check(); if (this.#draining) throw new RPCProtocolError("service_unavailable");
      original.cancelWith(signal); original.submit(this.#channel); return original;
    } catch (error) {
      exchange?.close(); request?.close(); reserved?.call.close(); reserved?.completion.close(); if (job) cleanup.finishJob(); throw error;
    } finally {
      this.#resultReadBuffer.fill(0); for (const ref of references) ref.release(); this.#resultReadBusy = false; this.#collect();
    }
  }
  get routes(): ContractRoutes { this.#check(); return this.#routes!; }
  get permissions(): ContractQueryAccess { this.#check(); return this.#access!; }
  /** Bind borrows this exact authenticated Session and its existing query
   * owner. It never acquires material, connects or opens a per-service Stream. */
  bindService(definition: object, options: ServiceBindingOptions, deadline: TrustedDeadline,
    context?: V4ApplicationContext, signal?: AbortSignal, dependency?: ServiceBindingConfigTypes.CapturedServiceBinding, prepaid?: ServiceBindingPoolTypes.ServiceBindingReservation, preparation?: ContractQueryPreparation): Promise<ServiceBinding> {
    this.#check(); const contracts = options.contractSource, captured = dependency ?? captureServiceBinding(definition, options);
    if (captured.definition !== definition) throw new RPCProtocolError("service_binding_owner"); this.#check();
    if (this.#draining || this.#authentication === undefined || !deadline.belongsTo(this.#host!.clock)) throw new RPCProtocolError("source_unavailable");
    const source = this.bindingSource(captured, () => preparation);
    const reservation = prepaid ?? this.#bindings!.reserve(captured);
    reservation.claim(captured, this.#bindings!);
    let binding: ServiceBinding | undefined;
    try {
      binding = new ServiceBinding(captured, reservation, source); const original = binding;
      this.#serviceClients.add(original); original.onClose(() => { this.#serviceClients.delete(original); this.#collect(); });
      this.#check(); return original.initialize(deadline, context, signal, contracts).finally(() => { preparation = undefined; });
    } catch (error) { binding?.close(); reservation.close(); throw error; }
  }
  /** Expose the original fixed Session capabilities without creating another
   * binding or taking ownership of a Controller's method snapshots. */
  bindingSource(captured: ServiceBindingConfigTypes.CapturedServiceBinding, preparation?: () => ContractQueryPreparation | undefined): ServiceBindingSource {
    this.#check();
    const check = (): void => {
      this.#check(); this.#deadline!.check();
      if (this.#draining || this.#authentication === undefined) throw new RPCProtocolError("source_unavailable");
    };
    const current = (): boolean => !this.#closed && !this.#draining && this.#authentication !== undefined;
    return Object.freeze<ServiceBindingSource>({ clock: this.#host!.clock, group: this.#serviceGroup, check, current,
      authentication: () => { check(); return this.#authentication!; },
      checkDependency: (method, contract) => {
        check();
        if (method.facts.shape === "notify") { if (!this.notifyReady()) throw new RPCProtocolError("not_ready"); }
        else if (method.facts.shape === "unary") { if (this.#channel === undefined) throw new RPCProtocolError("not_ready"); this.#channel.checkDependency(); }
        else {
          if (this.#preaccepted === undefined || method.streamKind === undefined) throw new RPCProtocolError("not_ready");
          this.#preaccepted.checkReady({ namespace: captured.namespace, authority: captured.target.authority, kind: method.streamKind, metadata: method.streamMetadata!, contract });
        }
      },
      deadline: duration => { check(); return this.#deadline!.forkAgeAt(this.#host!.clock.sample(), duration); },
      protectRenewal: reference => {
        check(); if (this.#channel === undefined) throw new RPCProtocolError("not_ready");
        return this.#queries!.protectRenewal(this.#acquisitions!, this.#channel, reference);
      },
      observeAvailability: (reference, wake) => this.#host!.root.observeAvailability(reference, wake),
      retain: (reference: ResourceReference, closed: () => void) => this.#host!.delivery.retain(reference, closed),
      query: (targets, limit, windows, invocation, delivery, renewal) => this.query(targets, limit, windows, invocation, delivery, renewal, renewal === undefined ? preparation?.() : undefined),
      prepareStream: (method, namespace, contract, offer, value, settings, invocation, cancellation) =>
        this.prepareStream(method, namespace, contract, offer, value, settings, { check, current }, invocation, cancellation, captured.target),
      preacceptStreams: (namespace, targets) => this.#preacceptStreams(namespace, targets, captured.target.authority),
      prepareNotify: (method, namespace, contract, offer, value, settings, invocation, cancellation) =>
        this.prepareNotify(method.method, namespace, contract, offer, value, settings, { check, current }, method.workClass, invocation, cancellation, captured.target),
      prepareResume: (method, namespace, contract, offer, stream, token, settings, invocation, cancellation) =>
        this.prepareResume(method, namespace, contract, offer, stream, token, settings, { check, current }, invocation, cancellation, captured.target),
      prepare: (method, namespace, contract, offer, value, settings, invocation, cancellation) =>
        this.prepareUnary(method.method, namespace, contract, offer, value, settings, { check, current }, method.workClass, invocation, cancellation, captured.target),
    });
  }
  /** Only a method declared by the original plan can receive a new handler
   * generation. This does not install or silently update its wire contract. */
  registerUnary(namespace: string, method: object, handler: V4UnaryHandler<any, any>, options: V4UnaryHandlerOptions): RPCUnaryRegistration {
    this.#check(); const captured = captureUnaryHandler(options), definition = methodDefinition(method), host = this.#host!;
    if (definition.restartFlush) checkMaintenanceOwner(this.#maintenanceOwner, this.#reference);
    if (definition.shape !== "unary" || definition.semantics !== "transient" ||
        captured.maxConcurrentCalls > this.#general || this.#nextRegistration === (1n << 64n) - 1n) throw new RPCProtocolError("configuration_capacity");
    const reference = host.root.reserve({ accounts: host.accounts,
      owner: { ...host.owner, kind: `rpc_unary_registration_${++this.#nextRegistration}` }, charge: rpcUnaryRegistrationCharge(captured, this.#runtimeBytes) });
    let registration: RPCUnaryRegistration | undefined;
    try {
      registration = new RPCUnaryRegistration(method, handler, captured, this.#runtimeBytes, reference);
      this.#routes!.installHandler(namespace, method, registration); return registration;
    } catch (error) { registration?.close(); throw error; }
    finally { reference.release(); }
  }
  /** The method binding supplies its captured local class before encoding. */
  reserveCall(workClass: ApplicationWorkClass, prepaid?: CompletionReservation, prepaidCall?: RPCCallReservation): Readonly<{ call: RPCCallReservation; completion: CompletionReservation }> {
    let call: RPCCallReservation;
    try {
      this.#check(); if (this.#draining) throw new RPCProtocolError("service_unavailable");
      if (prepaidCall !== undefined) { this.#calls!.checkUnsubmitted(prepaidCall); prepaidCall.inheritClass(workClass); }
      call = prepaidCall ?? this.#network!.reserveCall(workClass);
    } catch (error) { prepaidCall?.close(); prepaid?.close(); throw error; }
    try {
      const completion = prepaid ?? (workClass === "short" && this.#completion!.available() ? this.#completion!.checkout() : this.#group!.reserveCompletion());
      return Object.freeze({ call, completion });
    } catch (error) { call.close(); throw error; }
  }
  /** The exact trusted binding enters before any application encoder. All
   * request/result/codec bytes, K and Completion ownership are captured here. */
  setStreamOpener(opener: RPCStreamOpener): void {
    this.#check(); if (this.#streamOpener !== undefined) throw new RPCProtocolError("rpc_stream_owner"); this.#streamOpener = opener;
  }
  #preacceptStreams(namespace: string, targets: readonly Readonly<{ method: CapturedBindingMethod; contract: ServiceContractSnapshot }>[], authority: string): readonly RPCStreamPoolDemand[] {
    this.#check(); const host = this.#host!;
    if (this.#draining || this.#streamOpener === undefined || targets.some(({ method }) => method.streamKind === undefined || method.facts.shape !== "server_streaming")) throw new RPCProtocolError("not_ready");
    if (this.#preaccepted === undefined) {
      const reference = this.#initialStreams?.takePool() ?? host.root.reserve({ owner: { ...host.owner, kind: "rpc_preaccepted_streams" }, accounts: host.accounts, charge: rpcPreacceptedStreamsCharge(this.#runtimeBytes) });
      try {
        this.#preaccepted = new RPCPreacceptedStreams(this.#runtimeBytes, reference, host.clock, this.#deadline!.fork(this.#deadline!.cap), target => this.#newMessages(target),
          async (target, fixed, signal) => {
            this.#check(); if (this.#draining) throw new RPCProtocolError("source_unavailable");
            await this.#streamOpener!(target.kind, target.metadata, this.#deadline!.forkAgeAt(host.clock.sample(), 30000n), signal, stream => fixed.messages.attach(stream, fixed.adapter), fixed.open);
          }, () => this.#collect());
      } finally { reference.release(); }
    }
    return this.#preaccepted.demand(targets.map(({ method, contract }) => ({ namespace, authority, kind: method.streamKind!, metadata: method.streamMetadata!, contract })));
  }
  hasStreamingKind(kind: string): boolean { return !this.#closed && this.#streamHandlers.has(kind); }
  hasStreamingHandlers(): boolean { return !this.#closed && this.#streamHandlers.size !== 0; }
  #newMessages(target?: Omit<RpcPreacceptedStreamsTypes.RPCStreamPoolTarget, "contract">): RPCStreamPoolMessages {
    this.#check(); const host = this.#host!, costs = [...rpcStreamMessagesCharges(this.#runtimeBytes), rpcStreamingErrorCharge(this.#runtimeBytes)];
    if (this.#nextPreparation === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted"); const serial = ++this.#nextPreparation;
    const prepaid = target === undefined ? undefined : this.#initialStreams?.take(target.namespace, target.authority, target.kind, target.metadata);
    const references = prepaid === undefined ? host.root.reserveBatch(costs.map((charge, part) => ({ owner: { ...host.owner, kind: `rpc_stream_io_${serial}_${part}` },
      accounts: part === 4 ? host.sendAccounts : host.accounts, charge }))) : [...prepaid.references];
    let messages: RPCStreamMessages | undefined, group: ApplicationGroup | undefined = prepaid?.group, position: ProtectedResourceReservation | undefined;
    try {
      if (prepaid !== undefined) {
        const output = references[4]!;
        references[4] = output.transfer({ ...host.owner, kind: `rpc_stream_io_${serial}_4` }, host.owner.backing, host.sendAccounts); output.release();
      }
      group ??= applicationGroup(host.root, host.accounts, { ...host.owner, kind: `rpc_stream_group_${serial}` }, this.#runtimeBytes, false, references[5]!);
      position = host.root.protect(references[4]!, costs[4]!);
      messages = new RPCStreamMessages(this.#runtimeBytes, references, position, group);
      return { messages, adapter: references[1]!.take(costs[1]!), error: references[6]!.take(costs[6]!), ...(prepaid === undefined ? {} : { open: prepaid.open }) };
    } catch (error) { prepaid?.open.close(); messages?.close(); group?.close(); position?.closeAfterUse(); throw error; }
    finally { for (const reference of references) reference.release(); }
  }
  prepareIncomingResume(kind: string, namespace: string, method: object): RPCResumeDispatch {
    this.#check(); const host = this.#host!, definition = methodDefinition(method);
    if (this.#draining || this.#checkpointPolicy === undefined || this.#executionIdentity === undefined || this.#authentication === undefined ||
        this.#cleanup === undefined || definition.shape !== "unary" || definition.semantics !== "execution") throw new RPCProtocolError("resume_binding");
    const fixed = this.#newMessages(); let codec: ResumeCodec | undefined, output: ResourceReference | undefined, interest: ResourceReference | undefined, work: ResourceReference | undefined, dispatch: RPCResumeDispatch | undefined;
    try {
      codec = this.#newResumeCodec();
      output = host.root.reserve({ owner: { ...host.owner, kind: `rpc_resume_output_${this.#nextPreparation}` }, accounts: host.sendAccounts, charge: rpcPayloadCharge(4248, this.#runtimeBytes) });
      interest = host.root.reserve({ owner: { ...host.owner, kind: `rpc_resume_interest_${this.#nextPreparation}` }, accounts: host.accounts, charge: rpcOutputInterestCharge(this.#runtimeBytes) });
      const serial = this.#nextPreparation;
      work = host.root.reserve({ owner: { ...host.owner, kind: `rpc_resume_dispatch_${serial}` }, accounts: host.accounts, charge: rpcResumeDispatchCharge(this.#runtimeBytes) });
      const ticket = this.#network!.reserveIncomingStream(fixed.messages); fixed.messages.bind(this.#network!, ticket);
      dispatch = new RPCResumeDispatch(fixed.messages, fixed.adapter, codec, this.#network!, ticket, this.#inputs!, this.#routes!, namespace, method, kind,
        this.#group!, this.#authentication, this.#executionIdentity, this.#checkpointPolicy, host.clock, this.#cleanup, this.#runtimeBytes, output, interest, work, bytes => host.root.reserve({
          owner: { ...host.owner, kind: `rpc_resume_authorization_${serial}` }, accounts: host.accounts,
          charge: new ResourceVector([bytes, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) }));
      const original = dispatch; this.#resumeDispatches.add(original);
      original.onCleanup(() => { this.#resumeDispatches.delete(original); this.#collect(); }); return original;
    } catch (error) { dispatch?.close(); fixed.messages.close(); fixed.adapter.release(); codec?.close(); throw error; }
    finally { output?.release(); interest?.release(); work?.release(); fixed.error.release(); }
  }
  prepareIncomingStream(kind: string, metadata: Uint8Array): Readonly<{ attach(stream: V4StreamOwner): void; start(): void; close(): void }> {
    this.#check(); const entry = this.#streamHandlers.get(kind), host = this.#host!;
    if (entry === undefined || this.#draining || this.#authentication === undefined || this.#cleanup === undefined ||
        metadata.length !== (entry.metadata?.length ?? 0) || metadata.some((byte, index) => byte !== entry.metadata![index])) throw new RPCProtocolError("service_unavailable");
    const fixed = this.#newMessages(); let dispatch: RPCStreamingDispatch | undefined;
    const source = byteEventSource(entry.handler);
    const costs = rpcStreamingDispatchCharges(methodDefinition(entry.method), entry.options.applicationBytes, this.#runtimeBytes, source);
    let references: readonly ResourceReference[] = [];
    try {
      const ticket = this.#network!.reserveIncomingStream(fixed.messages); fixed.messages.bind(this.#network!, ticket);
      references = host.root.reserveBatch(costs.map((charge, part) => ({ owner: { ...host.owner, kind: `rpc_stream_dispatch_${this.#nextPreparation}_${part}` },
        accounts: part === 1 ? host.sendAccounts : host.accounts, charge })));
      dispatch = new RPCStreamingDispatch(fixed.messages, this.#network!, ticket, this.#inputs!, entry.contract, methodDefinition(entry.method), entry.options.applicationBytes,
        this.#group!, this.#authentication, host.clock, this.#deadline!.fork(this.#deadline!.cap), host.delivery, this.#cleanup, this.#runtimeBytes, references, this.#routes!, this.#executionIdentity, source, charge => {
          if (this.#nextPreparation === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
          return host.root.reserve({ owner: { ...host.owner, kind: `rpc_source_input_${++this.#nextPreparation}` }, accounts: host.accounts, charge });
        });
      const original = dispatch; this.#streamDispatches.add(original);
      original.onCleanup(() => { this.#streamDispatches.delete(original); if (this.#closed && this.#streamDispatches.size === 0) this.#group?.retireResults(); this.#collect(); });
      return Object.freeze({ attach: (stream: V4StreamOwner) => { try { fixed.messages.attach(stream, fixed.adapter); } finally { fixed.adapter.release(); } },
        start: () => original.start(), close: () => { fixed.adapter.release(); original.close(); } });
    } catch (error) { fixed.adapter.release(); dispatch?.close(); fixed.messages.close(); throw error; }
    finally { fixed.error.release(); for (const reference of references) reference.release(); }
  }
  prepareStream(method: CapturedBindingMethod, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    value: unknown, options: RPCUnaryPreparationOptions, source: RPCPublicationGuard, context?: V4ApplicationContext, signal?: AbortSignal,
    destination?: ServiceBindingTarget): Promise<RPCUnaryPreparation<RPCStreamingExchange>> {
    this.#check(); const host = this.#host!, captured = captureUnaryOptions(options, context), definition = method.facts;
    if (definition.shape !== "server_streaming" || definition.semantics === "execution" && this.#profile !== "execution" || method.streamKind === undefined || this.#streamOpener === undefined ||
        this.#draining || this.#authentication === undefined || this.#cleanup === undefined || destination === undefined) throw new RPCProtocolError("rpc_request_binding");
    const kind = method.streamKind, metadata = new Uint8Array(method.streamMetadata!); contract.checkMethod(namespace, definition);
    const localClass = applicationWorkClass(method.workClass, context), inputBytes = messageInputBytes(value, definition.request.implementation, definition.request.maximum);
    const costs = rpcUnaryPreparationCharges(contract, definition, unaryResponseLimit(contract, captured), inputBytes, this.#runtimeBytes);
    if (this.#nextPreparation === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted"); const serial = ++this.#nextPreparation;
    const prepaid = initializerCallBacking(context, this, method.method, namespace, destination, costs, host.accounts, host.sendAccounts);
    const references = prepaid?.references ?? host.root.reserveBatch(costs.map((charge, part) => ({ owner: { ...host.owner, kind: `rpc_stream_prepare_${serial}_${part}` }, accounts: part === 1 ? host.sendAccounts : host.accounts, charge })));
    let reserved: ReturnType<RPCApplicationAdmission["reserveCall"]> | undefined, preparation: RPCUnaryPreparation<RPCStreamingExchange> | undefined;
    try {
      reserved = this.reserveCall(localClass, prepaid?.completion, prepaid?.call);
      preparation = new RPCUnaryPreparation<RPCStreamingExchange>(definition, namespace, contract, offer, captured, source, {
        check: (header, call) => { this.#check(); if (this.#draining || this.#streamOpener === undefined) throw new RPCProtocolError("not_ready"); this.#network!.checkOutgoingStream(header, call); },
        current: () => !this.#closed && !this.#draining && this.#streamOpener !== undefined,
        reserve: (header, call) => header.uint(7) === 1n ? this.#reserveStreamStart(header, call, { namespace, authority: destination.authority, kind, metadata, contract }) : undefined,
        start: (transfer, claim) => this.#startStream(transfer, claim, kind, metadata),
      }, host.clock, this.#deadline!, this.#random!, host.delivery, this.#group!, this.#authentication, this.#cleanup,
      reserved.call, reserved.completion, localClass, inputBytes, this.#runtimeBytes, references, this.#localExecutionAuthority, destination);
      const original = preparation; this.#preparations.add(original);
      original.onDetach(() => { this.#preparations.delete(original); this.#collect(); });
      return original.encode(value, context, signal).then(() => { original.checkReady(); return original; });
    } catch (error) { preparation?.close(); reserved?.completion.close(); reserved?.call.close(); throw error; }
    finally { for (const reference of references) reference.release(); }
  }
  #reserveStreamStart(header: ApplicationHeader, call: RPCCallReservation, target: RpcPreacceptedStreamsTypes.RPCStreamPoolTarget): RPCPreparedStart<RPCStreamingExchange> {
    this.#check(); if (this.#preaccepted === undefined) throw new RPCProtocolError("not_ready");
    const checkout = this.#preaccepted.claim(target), host = this.#host!, network = this.#network!;
    let admission: ReturnType<RPCNetwork["prepareOutgoingStream"]> | undefined;
    let lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
    let exchange: RPCStreamingExchange | undefined, transferred = false, authorized = true;
    try {
      admission = network.prepareOutgoingStream(checkout.fixed.messages, header, call);
      lease = host.delivery.retain(checkout.fixed.error, () => { authorized = false; exchange?.authorizationClosed(); });
      return {
        current: () => authorized && !this.#closed && !this.#draining && checkout.current() && admission!.current(),
        start: (transfer, claim) => {
          const fixed = checkout.take(); transferred = true;
          try { exchange = this.#startStream(transfer, claim, target.kind, target.metadata, { fixed, admission: admission!, lease: lease! }); lease = undefined; return exchange; }
          catch (error) { fixed.messages.close(); fixed.error.release(); fixed.adapter.release(); throw error; }
        },
        release: () => { checkout.release(); admission!.release(); if (!transferred || lease !== undefined) lease?.release(); },
      };
    } catch (error) { lease?.release(); admission?.release(); checkout.release(); throw error; }
  }
  #startStream(transfer: RPCUnaryTransfer, claim: CompletionClaim | undefined, kind: string, metadata: Uint8Array,
    prepared?: Readonly<{ fixed: RPCStreamPoolMessages; admission: ReturnType<RPCNetwork["prepareOutgoingStream"]>; lease: ReturnType<ReceiveDeliveryGate["retain"]> }>): RPCStreamingExchange {
    this.#check(); const host = this.#host!, cleanup = this.#cleanup!, opener = this.#streamOpener!;
    const fixed = prepared?.fixed ?? this.#newMessages(); let exchange: RPCStreamingExchange | undefined, job = false;
    try {
      const ticket = prepared?.admission.commit() ?? this.#network!.reserveOutgoingStream(fixed.messages, transfer.header, transfer.call); fixed.messages.bind(this.#network!, ticket);
      cleanup.startJob(); job = true;
      exchange = new RPCStreamingExchange(transfer, fixed.messages, this.#runtimeBytes, fixed.error, host.delivery, this.#authentication!, () =>
        host.root.reserve({ owner: { ...host.owner, kind: "rpc_stream_item" }, accounts: host.accounts,
          charge: rpcCompletionCharge(Number(transfer.header.uint(8)), this.#runtimeBytes) }), claim, host.clock, prepared?.lease);
      const original = exchange; this.#streaming.add(original);
      original.onNetworkCleanup(() => { this.#streaming.delete(original); cleanup.finishJob(); this.#collect(); }); job = false;
      original.start(this.#network!, ticket, async signal => {
        if (prepared !== undefined) { if (signal.aborted) throw new RPCProtocolError("canceled"); return; }
        try { await opener(kind, metadata, transfer.deadline, signal, stream => fixed.messages.attach(stream, fixed.adapter), fixed.open); }
        finally { fixed.adapter.release(); }
      });
      return original;
    } catch (error) { fixed.adapter.release(); exchange?.close(); fixed.messages.close(); if (job) cleanup.finishJob(); throw error; }
    finally { fixed.error.release(); }
  }
  #newResumeCodec(): ResumeCodec {
    const host = this.#host!;
    if (this.#nextPreparation === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
    const id = ++this.#nextPreparation;
    const refs = host.root.reserveBatch(resumeCodecCharges(this.#runtimeBytes).map((charge, index) => ({
      owner: { ...host.owner, kind: `rpc_resume_codec_${id}_${index}` }, accounts: host.accounts, charge })));
    try { return new ResumeCodec(this.#runtimeBytes, refs); } finally { refs.forEach(ref => ref.release()); }
  }
  async prepareResume(method: CapturedBindingMethod, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    stream: V4StreamOwner, token: Uint8Array, options: RPCUnaryPreparationOptions, source: RPCPublicationGuard,
    context?: V4ApplicationContext, signal?: AbortSignal, destination?: ServiceBindingTarget): Promise<RPCUnaryPreparation> {
    this.#check();
    if (this.#session === undefined || this.#checkpointPolicy === undefined || method.resumeKind === undefined ||
        contract.optionalUint(13) !== 1n || contract.requestMaxBytes < 9345 || contract.maxResponseBytes < 4248 ||
        byteLength(token) > this.#checkpointPolicy.maxTokenBytes) throw new RPCProtocolError("resume_binding");
    const fixed = this.#newMessages(); let codec: ResumeCodec | undefined, preparation: RPCUnaryPreparation | undefined, moved = false;
    const release = (): void => {
      if (moved) return; moved = true;
      try { fixed.messages.releaseUnusedResume(); } catch { fixed.messages.close(); }
      codec?.close(); fixed.adapter.release(); fixed.error.release();
    };
    try {
      // Exclusive target qualification precedes every operation ID or saved ref.
      const target = fixed.messages.attachResume(stream, this.#session, method.resumeKind, fixed.adapter); fixed.adapter.release();
      codec = this.#newResumeCodec(); const bytes = new Uint8Array(9345);
      try {
        const size = codec.encodeRequest(token, target, bytes);
        const guard = { check: () => { source.check(); fixed.messages.check(); }, current: () => source.current() && !fixed.messages.closed };
        preparation = await this.prepareUnary(method.method, namespace, contract, offer, bytes.subarray(0, size), options, guard,
          method.workClass, context, signal, destination, {
            check: (header, call) => { guard.check(); this.#network!.checkOutgoingStream(header, call); },
            current: () => guard.current() && !this.#draining && !this.#closed,
            releaseUnused: release,
            reserve: (header, call) => {
              if (header.uint(7) !== 1n) return;
              const admission = this.#network!.prepareOutgoingStream(fixed.messages, header, call);
              return {
                current: () => guard.current() && !this.#draining && !this.#closed && admission.current(),
                start: (transfer, claim) => {
                  moved = true; fixed.error.release();
                  return this.#startResume(transfer, claim, fixed.messages, codec!, admission);
                },
                release: () => admission.release(),
              };
            },
            start: (transfer, claim) => {
              moved = true; fixed.error.release();
              return this.#startResume(transfer, claim, fixed.messages, codec!);
            },
          });
      } finally { bytes.fill(0); }
      return preparation;
    } catch (error) { preparation?.close(); release(); throw error; }
  }
  #startResume(transfer: RPCUnaryTransfer, claim: CompletionClaim | undefined, messages: RPCStreamMessages, codec: ResumeCodec,
    prepared?: ReturnType<RPCNetwork["prepareOutgoingStream"]>): RPCUnaryExchange {
    const host = this.#host!, cleanup = this.#cleanup!, network = this.#network!;
    let exchange: RPCUnaryExchange | undefined, job = false;
    try {
      this.#check();
      const ticket = prepared?.commit() ?? network.reserveOutgoingStream(messages, transfer.header, transfer.call); messages.bind(network, ticket);
      cleanup.startJob(); job = true;
      exchange = new RPCUnaryExchange(transfer.header, transfer.contract, transfer.request, transfer.deadline, transfer.guard,
        host.delivery, host.root, this.#runtimeBytes, transfer.references, transfer.call, transfer.completion, transfer.method, this.#authentication!, claim);
      const original = exchange; this.#unary.add(original);
      original.onNetworkCleanup(() => { this.#unary.delete(original); cleanup.finishJob(); this.#collect(); }); job = false;
      original.submitResume(messages, network, ticket, codec); return original;
    } catch (error) { exchange?.close(); messages.close(); codec.close(); if (job) cleanup.finishJob(); throw error; }
  }
  prepareUnary(method: object, namespace: string, contract: ServiceContractSnapshot, offer: AdmissionOffer | undefined,
    value: unknown, options: RPCUnaryPreparationOptions, source: RPCPublicationGuard, workClass: ApplicationWorkClass,
    context?: V4ApplicationContext, signal?: AbortSignal, destination?: ServiceBindingTarget, resume?: RpcUnaryPreparationTypes.RPCUnaryStartTarget): Promise<RPCUnaryPreparation> {
    this.#check();
    const captured = captureUnaryOptions(options, context), definition = methodDefinition(method);
    const host = this.#host!, cleanup = this.#cleanup, authentication = this.#authentication;
    if (this.#draining || cleanup === undefined || authentication === undefined) throw new RPCProtocolError("service_unavailable");
    if (signal?.aborted) throw new RPCProtocolError("canceled");
    if (definition.shape !== "unary" || definition.semantics === "execution" && this.#profile !== "execution" ||
        !contract.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_request_binding");
    contract.checkMethod(namespace, definition);
    source.check(); this.#check();
    if (!source.current() || this.#draining) throw new RPCProtocolError("source_unavailable");
    const localClass = applicationWorkClass(workClass, context);
    const inputBytes = messageInputBytes(value, definition.request.implementation, definition.request.maximum);
    const costs = rpcUnaryPreparationCharges(contract, definition, unaryResponseLimit(contract, captured), inputBytes, this.#runtimeBytes);
    if (this.#nextPreparation === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
    const index = ++this.#nextPreparation;
    const prepaid = initializerCallBacking(context, this, method, namespace, destination, costs, host.accounts, host.sendAccounts);
    const references = prepaid?.references ?? host.root.reserveBatch(costs.map((charge, part) => ({ accounts: part === 1 ? host.sendAccounts : host.accounts,
      owner: { ...host.owner, kind: `rpc_unary_${index}_${part}` }, charge })));
    let reserved: ReturnType<RPCApplicationAdmission["reserveCall"]> | undefined, preparation: RPCUnaryPreparation | undefined;
    try {
      reserved = this.reserveCall(localClass, prepaid?.completion, prepaid?.call);
      preparation = new RPCUnaryPreparation(definition, namespace, contract, offer, captured, source, resume ?? {
        check: (header, call) => {
          this.#check();
          if (this.#draining) throw new RPCProtocolError("service_unavailable");
          if (this.#channel === undefined) throw new RPCProtocolError("not_ready");
          this.#channel.checkRequestAdmission(header, call);
        },
        current: (header, call) => !this.#closed && !this.#draining && this.#channel?.requestAdmissionCurrent(header, call) === true,
        start: (transfer, claim) => this.#startUnary(transfer, claim),
      }, host.clock, this.#deadline!, this.#random!, host.delivery, this.#group!, authentication, cleanup,
      reserved.call, reserved.completion, localClass, inputBytes, this.#runtimeBytes, references, this.#localExecutionAuthority, destination, resume !== undefined);
      const original = preparation; this.#preparations.add(original);
      original.onDetach(() => { this.#preparations.delete(original); this.#collect(); });
      this.#check();
      return original.encode(value, context, signal).then(() => { original.checkReady(); return original; });
    } catch (error) {
      preparation?.close(); reserved?.completion.close(); reserved?.call.close(); throw error;
    } finally { for (const reference of references) reference.release(); }
  }
  #startUnary(transfer: RPCUnaryTransfer, claim: CompletionClaim | undefined): RPCUnaryExchange {
    this.#check();
    const host = this.#host!, channel = this.#channel, cleanup = this.#cleanup!;
    if (this.#draining || channel === undefined) throw new RPCProtocolError("service_unavailable");
    let exchange: RPCUnaryExchange | undefined, job = false;
    try {
      cleanup.startJob(); job = true;
      exchange = new RPCUnaryExchange(transfer.header, transfer.contract, transfer.request, transfer.deadline, transfer.guard,
        host.delivery, host.root, this.#runtimeBytes, transfer.references, transfer.call, transfer.completion, transfer.method, this.#authentication!, claim);
      const original = exchange; this.#unary.add(original);
      // Install original cleanup before any later safety check can fail.
      original.onNetworkCleanup(() => { this.#unary.delete(original); cleanup.finishJob(); this.#collect(); }); job = false;
      this.#check(); original.submit(channel); return original;
    } catch (error) {
      exchange?.close(); if (job) cleanup.finishJob(); throw error;
    }
  }
  query(targets: readonly ContractQueryTarget[], deadline: TrustedDeadline,
    windows: readonly bigint[], context?: V4ApplicationContext, delivery?: ContractQueryAcquisitionTypes.ContractQueryDelivery,
    renewal?: ContractRenewalProtection, preparation?: ContractQueryPreparation): ContractQueryAcquisition {
    this.#check(); if (this.#channel === undefined) throw new RPCProtocolError("query_source_unavailable");
    return this.#queries!.acquire(this.#acquisitions!, this.#channel, targets, deadline, windows, context, delivery, renewal, preparation);
  }
  #acceptUnary(channel: RPCChannelRuntime, request: RPCReadyRequest): void {
    if (request.refusal !== undefined || request.input === undefined) {
      request.input?.close(); channel.replySDK(request.ticket, request.refusal ?? "service_unavailable"); return;
    }
    const input = request.input, host = this.#host!;
    let route: CapturedContractRoute | undefined, permit: ApplicationPermit | undefined, job: RPCUnaryDispatch | undefined;
    let references: readonly ResourceReference[] = [];
    try {
      this.#check(); channel.checkIncoming(request.ticket);
      if (this.#draining || this.#cleanup === undefined || this.#authentication === undefined) throw new RPCProtocolError("service_unavailable");
      route = input.takeRoute(); const handler = route.handler;
      if (handler === undefined) throw new RPCProtocolError("method_unavailable");
      if (route.contract.semantics === "execution" && (handler.execution === undefined || this.#executionIdentity === undefined || this.#profile !== "execution")) throw new RPCProtocolError("service_unavailable");
      handler.check(); input.checkDeadline();
      const costs = rpcUnaryDispatchCharges(input.header.payloadBytes, Number(input.header.uint(8)), route.definition, handler, this.#runtimeBytes);
      if (this.#nextInbound === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
      const id = ++this.#nextInbound;
      references = host.root.reserveBatch(costs.map((charge, index) => ({ accounts: index === 1 ? host.sendAccounts : host.accounts,
        owner: { ...host.owner, kind: `rpc_dispatch_${id}_${index}` }, charge })));
      if (input.header.uint(7) === 1n) permit = this.#group!.tryOrdinary(handler.options.workClass);
      handler.admit();
      job = new RPCUnaryDispatch(input, route, channel, request.ticket, this.#group!, this.#authentication, host.clock, host.delivery,
        this.#cleanup, this.#inboundAbort.signal, this.#runtimeBytes, references, permit, this.#routes!, this.#executionIdentity, this.#checkpointPolicy, this.#maintenanceOwner);
      route = undefined; permit = undefined;
      const original = job; this.#inbound.add(original);
      original.onDetach(() => { this.#inbound.delete(original); this.#collect(); }); original.start();
    } catch (error) {
      job?.close(); route?.close(); permit?.release(); input.close();
      const code: RPCSDKError = error instanceof ResourceError || error instanceof Error && error.message === "would_block" ? "resource_exhausted"
        : error instanceof TimeError ? "deadline_exceeded"
          : error instanceof RPCProtocolError && ["permission_denied", "resource_exhausted", "method_unavailable", "service_unavailable"].includes(error.code) ? error.code as RPCSDKError : "service_failed";
      channel.replySDK(request.ticket, code);
    } finally { for (const reference of references) reference.release(); }
  }
  #acceptResultRead(channel: RPCChannelRuntime, request: RPCReadyRequest): void {
    const input = request.input!;
    let reference: ResourceReference | undefined, payload: RPCPayloadBorrow | undefined, entered = false;
    try {
      this.#check(); channel.checkIncoming(request.ticket);
      if (this.#draining || this.#resultReadCodec === undefined || this.#resultReadBusy) throw new RPCProtocolError("service_unavailable");
      this.#resultReadBusy = entered = true;
      const borrow = input.borrow(); let target: ExecutionTarget;
      try { target = this.#resultReadCodec.target(borrow.bytes); } finally { borrow.release(); }
      const deadline = input.forkDeadline();
      const access: RPCPublicationGuard = Object.freeze({ check: () => { deadline.check(); this.#authorizeManagement(target, false, false); }, current: () => !this.#closed });
      access.check();
      const history = this.#histories.get(target.namespace); if (history === undefined) throw new RPCProtocolError("service_unavailable");
      if (this.#nextInbound === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
      const host = this.#host!;
      reference = host.root.reserve({ accounts: host.accounts, owner: { ...host.owner, kind: `rpc_result_pin_${++this.#nextInbound}` }, charge: executionResultReadCharge(this.#runtimeBytes) });
      const read = history.captureResult(target, access, reference, this.#runtimeBytes); payload = read.payload;
      read.guard.check(); channel.queueResultRead(request.ticket, payload, read.guard); payload = undefined;
    } catch (error) {
      const code: RPCSDKError = error instanceof ResourceError ? "resource_exhausted" : error instanceof TimeError ? "deadline_exceeded" :
        error instanceof RPCProtocolError && ["permission_denied", "resource_exhausted", "operation_conflict", "result_expired", "deadline_exceeded"].includes(error.code) ? error.code as RPCSDKError : "service_unavailable";
      channel.replySDK(request.ticket, code);
    } finally { payload?.release(); reference?.release(); input.close(); if (entered) this.#resultReadBusy = false; this.#collect(); }
  }
  async #dispatch(channel: RPCChannelRuntime): Promise<void> {
    try {
      while (!this.#closed) {
        let count = 0;
        for (; count < 8; count++) {
          const request = channel.nextRequest(); if (request === undefined) break;
          if (this.#queries!.accept(channel, request)) continue;
          if (request.refusal === undefined && request.input?.header.kind === "read_result_request") { this.#acceptResultRead(channel, request); continue; }
          this.#acceptUnary(channel, request);
        }
        if (count < 8) await channel.waitRequests();
        else await new Promise<void>(resolve => {
          this.#turnResolve = resolve;
          this.#turnTimer = setTimeout(() => { this.#turnTimer = undefined; this.#turnResolve = undefined; resolve(); }, 0);
        });
      }
    } catch { channel.close(); }
    finally { this.#dispatching = false; this.#collect(); }
  }
  drain(): void { this.#check(); this.#draining = true; this.#preaccepted?.close(); this.#queries!.drain(); for (const wake of this.#managementWaiters) wake(); }
  onCleanup(callback: () => void): void {
    if (this.#cleaned !== undefined) throw new RPCProtocolError("rpc_owner");
    if (this.#reference === undefined) callback(); else this.#cleaned = callback;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#closing = true;
    try {
    if (this.#turnTimer !== undefined) clearTimeout(this.#turnTimer); this.#turnTimer = undefined;
    const resolve = this.#turnResolve; this.#turnResolve = undefined; resolve?.();
    this.#inboundAbort.abort(); this.#managementLease?.release(); this.#managementLease = undefined; this.managementFailed(); this.#management?.close(); this.#managementGroup?.close(); this.#managementPosition?.closeAfterUse();
    this.#managementChanged = undefined; for (const position of this.#managementPositions) position.closeAfterUse();
    for (const reference of this.#managementRefs) reference.release(); this.#managementRefs.length = 0;
    for (const binding of this.#serviceClients) binding.close(); this.#serviceClients.clear();
    for (const job of this.#inbound) job.close(); this.#inbound.clear();
    for (const preparation of this.#preparations) preparation.close();
    for (const stream of this.#streaming) stream.networkClosed();
    for (const dispatch of this.#streamDispatches) dispatch.close();
    for (const dispatch of this.#resumeDispatches) dispatch.close();
    this.#preaccepted?.close(); this.#initialStreams?.close(); this.#initialStreams = undefined; this.#streamOpener = undefined; this.#session = undefined; this.#streamHandlers.clear();
    for (const preparation of this.#notifyPreparations) preparation.close();
    for (const access of this.#notificationAccess.values()) access.close(); this.#notificationAccess.clear();
    for (const registration of this.#notificationBusinesses.values()) registration.close("source_closed"); this.#notificationBusinesses.clear();
    this.#subscribers?.close(); this.#subscribers = undefined;
    for (const channel of this.#notifyChannels) channel?.close();
    for (const refs of this.#notifyRefs) { for (const ref of refs) ref?.release(); refs.length = 0; }
    for (const position of this.#notifyPositions) position.closeAfterUse();
    for (const group of this.#notifyGroups) group.close();
    for (const exchange of this.#unary) exchange.endSession();
    this.#queries?.close(); this.#channel?.close(); this.#inputs?.close(); this.#access?.close(); this.#routes?.close();
    this.#publication?.closeAfterUse();
    this.#network?.close(); this.#network?.flushOutputEvents(); this.#calls?.close(); this.#completion?.close();
    // Accepted event subscriptions still own ordinary cleanup duties. Keep the
    // original executor service alive until their real disposer exits.
    if (this.#streamDispatches.size === 0) this.#group?.retireResults(); this.#channelGroup?.close();
      for (const reference of this.#channelRefs) reference.release(); this.#channelRefs.length = 0;
    } finally { this.#closing = false; this.#collect(); }
  }
  #collect(): void {
    if (!this.#closed || this.#closing || this.#collecting || this.#dispatching || this.#resultReadBusy) return; this.#collecting = true;
    try {
      if (this.#management?.cleanupComplete() === false || this.#managementPosition?.cleanupComplete() === false || this.#managementGroup?.cleanupComplete() === false ||
          this.#managementPositions.some(position => !position.cleanupComplete())) return;
      if (this.#notifyPreparations.size !== 0 || this.#notifyChannels.some(channel => channel?.cleanupComplete() === false) ||
          this.#notifyPositions.some(position => !position.cleanupComplete())) return;
      if (this.#preaccepted?.cleanupComplete() === false || this.#preparations.size !== 0 || this.#streaming.size !== 0 || this.#streamDispatches.size !== 0 || this.#resumeDispatches.size !== 0 || this.#unary.size !== 0 || this.#channel?.cleanupComplete() === false || this.#queries?.cleanupComplete() === false || this.#inputs?.cleanupComplete() === false ||
          this.#network?.cleanupComplete() === false || this.#channelGroup?.cleanupComplete() === false || this.#publication?.cleanupComplete() === false) return;
      this.#notifyChannels.length = this.#notifyPositions.length = this.#notifyGroups.length = 0;
      this.#management = undefined; this.#managementPosition = undefined; this.#managementGroup = undefined; this.#histories.clear(); this.#localExecutionAuthority = undefined; this.#referenceTargets = []; this.#executionDelegations = [];
      this.#managementPositions.length = 0;
      this.#resultReadCodec?.close(); this.#resultReadCodec = undefined; this.#resultReadReference?.release(); this.#resultReadReference = undefined;
      this.#resultReadBuffer.fill(0); this.#resultReadBuffer = new Uint8Array();
      this.#channel = undefined; this.#preaccepted = undefined; this.#queries = undefined; this.#inputs = undefined; this.#access = undefined; this.#routes = undefined;
      this.#network = undefined; this.#calls = undefined; this.#completion = undefined; this.#group = undefined; this.#channelGroup = undefined; this.#acquisitions = undefined;
      // Complete unary results retain only their original compact K and
      // Completion owners. Their eventual release does not hold Session core.
      this.#publication = undefined; this.#deadline = undefined; this.#host = undefined; this.#cleanup = undefined; this.#authentication = undefined; this.#executionIdentity = undefined; this.#random = undefined; this.#bindings = undefined;
      this.#observer?.(); this.#observer = undefined; this.#reference?.release(); this.#reference = undefined;
      const cleaned = this.#cleaned; this.#cleaned = undefined; cleaned?.();
    } finally { this.#collecting = false; }
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
Object.freeze(RPCApplicationAdmission.prototype); Object.freeze(RPCApplicationAdmission);
