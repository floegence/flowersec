import { RawStreamPreparation, type CapturedRawStreamDeclaration } from "./rawStreamPreparation.js";
import { RPCCallCapacity, type RPCCallPosition } from "./rpcCallCapacity.js";
import { closeRPCApplicationServices, reserveRPCApplicationServices, type RPCApplicationServices } from "./rpcApplicationServices.js";
import type { ContractQueryAcquisitions } from "./contractQueryAcquisition.js";
import { ContractQueryPreparation, type QueryPreparationReservation } from "./queryRenewalPosition.js";
import { streamOpenCharges } from "./streamOpenPreparation.js";
import { NativeProtocolPositions } from "./nativePositions.js";
import { RPCStreamPreparation } from "./rpcStreamPreparation.js";
import type { InitializerMethodTarget } from "./initializerWorkload.js";
import type { ApplicationWorkClass } from "./applicationExecutor.js";
import type { V4EnvironmentSessionSpec } from "./environment.js";
import type { ResourceVector} from "./resources.js";
import { type ResourceReference, type ResourceRoot, type ResourceOwner, type ResourceAccount, type ProtectedResourceAccounts } from "./resources.js";
import { captureRPCApplication, rpcApplicationPlan } from "./rpcApplication.js";
import { captureSendQueueBytes, captureStreamSendQueueBytes, checkSendQueueCapacity, sendAccountPoolCapacity, createSendAccount, createStreamSendAccounts } from "./sendBudget.js";
import { authenticatedSessionCharge, sessionBootstrapCharges, sessionIngressCharge, sessionOutputCharge, sessionControlCharge, sessionControlDecoderCharge } from "./session.js";
import { recordEpochCharge, recordCipherCharge } from "./recordCrypto.js";
import { envelopeDecoderCharge } from "./envelope.js";
import { checkBootstrapCapacity, openAdmissionCharge, openDecoderCharge } from "./openAdmission.js";
import { receiveDeliveryCharge } from "./receiveDirection.js";
import { SessionKeyPreparation } from "./sessionKeyPreparation.js";
import { PeerOpenPreparation } from "./peerOpenPreparation.js";
import type { TrustedClock } from "./clock.js";
import { CryptoUsageLedger, type CryptoUsageConfig, cryptoUsageCharge } from "./cryptoUsage.js";
import { nativeIngressCharge } from "./nativeIngress.js";
import { nativeCandidateCharge, nativeCandidateCount } from "./nativeCandidates.js";
import { recordWorkspaceCharge } from "./recordWorkspace.js";
import { nativeOutputFrame, nativeSendEncodeCharge } from "./nativeSend.js";
import { receiveWorkspaceCharge, receiveWorkspaceDecoderCharge } from "./receiveWorkspace.js";
import { nativePositionCharges, nativePositionPoolCharge } from "./nativePositions.js";
import { nativeOpeningCharge } from "./nativeFrame.js";
import { maintenancePositionCharges } from "./maintenancePositions.js";
import { protectedAccountPoolCharge } from "./resources.js";
import { envelopePrefixBytes } from "./wireRegistry.js";

/** Cost-bearing projection only: no credential, provider handle or deadline. */
export interface SessionResourceSpec extends Pick<V4EnvironmentSessionSpec, "maxFrame" | "maxReceiveDirections" | "streams" | "crypto" | "application"> {
  readonly noise: Pick<V4EnvironmentSessionSpec["noise"], "role" | "profile">;
  readonly info: Pick<V4EnvironmentSessionSpec["info"], "application_profile">;
  readonly transport: { readonly mode: "message" | "stream"; readonly nativeStreams?: { readonly capacity: number } };
}
function fail(code: string): never { throw new Error(code); }
/** Shared by pre-Acquire planning and actual Session assembly. */
export function sessionAdmissionPlan(spec: SessionResourceSpec, runtimeBytes: bigint, reservedAccounts = false) {
  const stream = spec.streams, noise = spec.noise;
  const crypto = { ...spec.crypto, profile: noise.profile, sendDirection: noise.role === "client" ? 0 as const : 1 as const, runtimeBytes };
  const cipher = { maxFrame: spec.maxFrame, runtimeBytes };
  const sendQueueBytes = captureSendQueueBytes(stream.sendQueueBytes);
  checkSendQueueCapacity(sendQueueBytes, stream.maxWriteBytes, runtimeBytes,
    spec.transport.nativeStreams === undefined ? 0 : nativeOutputFrame(spec.maxFrame, stream.receive.maxDataBytes) + envelopePrefixBytes);
  const streamSendQueueBytes = captureStreamSendQueueBytes(stream.streamSendQueueBytes, noise.role);
  checkSendQueueCapacity(streamSendQueueBytes, stream.maxWriteBytes, runtimeBytes,
    spec.transport.nativeStreams === undefined ? 0 : nativeOutputFrame(spec.maxFrame, stream.receive.maxDataBytes) + envelopePrefixBytes);
  const costs: [string, ResourceVector][] = [
    ["session", authenticatedSessionCharge(spec.maxReceiveDirections, runtimeBytes)], ["epoch", recordEpochCharge(runtimeBytes)],
    ["ingress", sessionIngressCharge(spec.maxFrame, runtimeBytes)], ["envelope", envelopeDecoderCharge({ ...cipher, mode: spec.transport.mode })], ["output", sessionOutputCharge(spec.maxFrame, runtimeBytes)],
    ["open", openAdmissionCharge(stream.limits)], ["open_decoder", openDecoderCharge(runtimeBytes)], ["control", sessionControlCharge(spec.maxFrame, runtimeBytes)],
    ["control_decoder", sessionControlDecoderCharge(spec.maxFrame, runtimeBytes)], ["control_send", recordCipherCharge(cipher)], ["control_receive", recordCipherCharge(cipher)],
    ["delivery", receiveDeliveryCharge(runtimeBytes)], ["ledger", cryptoUsageCharge(crypto)],
  ];
  let nativePositionIndex = -1, nativeOpeningIndex = -1, nativePositionCount = 0, nativeOpeningCount = 0;
  if (spec.transport.nativeStreams !== undefined) {
    const capacity = spec.transport.nativeStreams.capacity, required = spec.maxReceiveDirections + stream.limits.ingressItems + 1;
    if (spec.transport.mode !== "stream" || !Number.isSafeInteger(capacity) || capacity < required || capacity > 4096) fail("configuration_capacity");
    costs.push(["native_ingress", nativeIngressCharge(required, runtimeBytes)]);
    costs.push(["native_record_workspace", recordWorkspaceCharge(spec.maxFrame, runtimeBytes)]);
    costs.push(["native_envelope_workspace", envelopeDecoderCharge({ ...cipher, mode: "stream" })]);
    costs.push(["native_receive_workspace", receiveWorkspaceCharge(spec.maxFrame, runtimeBytes)]);
    costs.push(["native_receive_decoder", receiveWorkspaceDecoderCharge(spec.maxFrame, runtimeBytes)]);
    costs.push(["native_candidates", nativeCandidateCharge(nativeCandidateCount(stream.nativeDataAssemblyDepth, crypto.sendDirection, spec.maxReceiveDirections), required, runtimeBytes)]);
    const outputFrame = nativeOutputFrame(spec.maxFrame, stream.receive.maxDataBytes);
    costs.push(["native_send_crypto", recordWorkspaceCharge(outputFrame, runtimeBytes)]);
    costs.push(["native_send_encode", nativeSendEncodeCharge(outputFrame, runtimeBytes)]);
    nativePositionCount = required; nativeOpeningCount = stream.limits.maxPending + stream.limits.ingressItems + 1;
    nativePositionIndex = costs.length;
    costs.push(["native_protocol_positions", nativePositionPoolCharge(required, nativeOpeningCount, runtimeBytes)]);
    const positionCosts = nativePositionCharges(runtimeBytes);
    for (let index = 0; index < required; index++) {
      for (let part = 0; part < positionCosts.length; part++) costs.push([`native_position_${part}`, positionCosts[part]!]);
    }
    nativeOpeningIndex = costs.length;
    for (let index = 0; index < nativeOpeningCount; index++) costs.push(["native_opening_position", nativeOpeningCharge()]);
  }
  const maintenanceConfig = { ...cipher, maxScopes: stream.rekeyMaxScopes ?? 1035 }, maintenanceIndex = costs.length;
  if (maintenanceConfig.maxScopes < spec.maxReceiveDirections) fail("configuration_capacity");
  for (const [index, charge] of maintenancePositionCharges(maintenanceConfig).entries()) costs.push([`maintenance_position_${index}`, charge]);
  const sendAccountCount = sendAccountPoolCapacity(spec.maxReceiveDirections, stream.limits.ingressItems), sendAccountIndex = reservedAccounts ? -1 : costs.length;
  if (!reservedAccounts) costs.push(["send_account_slots", protectedAccountPoolCharge(sendAccountCount, runtimeBytes)]);
  const bootstrapIndex = costs.length, bootstrapCosts = sessionBootstrapCharges(spec.info.application_profile, spec.maxFrame, runtimeBytes, stream.receive);
  if (bootstrapCosts.length !== 0) {
    checkBootstrapCapacity(stream.limits);
    if (crypto.keys < 8) fail("configuration_capacity");
  }
  for (const [index, charge] of bootstrapCosts.entries()) costs.push([`bootstrap_${index}`, charge]);
  const managementIndex = costs.length, managementCosts = spec.info.application_profile === "execution" ? bootstrapCosts : [];
  if (managementCosts.length !== 0) {
    if (stream.limits.perClass[2] !== 1 || stream.limits.perOpener[0][2] !== 1 || stream.limits.perOpener[1][2] !== 0 || stream.limits.protected[0][2] !== 1 ||
        stream.receive.receiveLimit < 16384n || stream.receive.queueBytes < 16384 || crypto.keys < 12) fail("configuration_capacity");
    for (const [index, charge] of managementCosts.entries()) costs.push([`management_stream_${index}`, charge]);
  }
  const notifyIndex = costs.length;
  for (let position = 0; position < (bootstrapCosts.length === 0 ? 0 : 2); position++) for (const [index, charge] of bootstrapCosts.entries()) costs.push([`notify_stream_${position}_${index}`, charge]);
  const applicationProfile = spec.info.application_profile, applicationInput = spec.application;
  if ((applicationProfile === "transport") !== (applicationInput === undefined)) fail("configuration_capacity");
  const rpcConfig = applicationInput === undefined ? undefined : captureRPCApplication(applicationInput);
  const rpcPlan = rpcConfig === undefined || applicationProfile === "transport" ? undefined
    : rpcApplicationPlan(rpcConfig, applicationProfile, stream.rpcMaxGeneralOutstanding ?? 0, runtimeBytes);
  if (rpcPlan !== undefined && stream.maxWriteBytes < 16384) fail("configuration_capacity");
  const rpcIndex = costs.length;
  for (const [index, charge] of (rpcPlan?.charges ?? []).entries()) costs.push([`rpc_application_${index}`, charge]);
  return { costs, streamOpenCosts: streamOpenCharges(spec.maxFrame, runtimeBytes, stream.receive, spec.transport.nativeStreams === undefined ? spec.maxFrame : nativeOutputFrame(spec.maxFrame, stream.receive.maxDataBytes)), sendQueueBytes, streamSendQueueBytes, nativePositionIndex, nativeOpeningIndex, nativePositionCount, nativeOpeningCount,
    maintenanceConfig, maintenanceIndex, sendAccountCount, sendAccountIndex, bootstrapIndex, bootstrapCosts, managementIndex, managementCosts,
    notifyIndex, applicationProfile, rpcConfig, rpcPlan, rpcIndex };
}

/** A one-use reservation of the original maximum plan. Actual assembly moves
 * matching references; unused positions alone are released. */
export class ClientSessionAdmission {
  #parts: Map<string, { charge: ResourceVector; reference: ResourceReference; borrowed?: boolean }[]>;
  #closed = false;
  #calls: RPCCallCapacity | undefined;
  #ledger: CryptoUsageLedger | undefined;
  #internalKeys: SessionKeyPreparation | undefined;
  #peerOpens: PeerOpenPreparation | undefined;
  #services: RPCApplicationServices | undefined;
  #queryReference: ResourceReference | undefined;
  #streams: RPCStreamPreparation | undefined;
  #streamOpenCosts: readonly ResourceVector[] | undefined;
  #nativePositions: NativeProtocolPositions | undefined;
  #nativeLimits: readonly [number, number] | undefined;
  #sendAccount: ResourceAccount | undefined;
  #sendAccounts: ProtectedResourceAccounts | undefined;
  #accountLimits: Readonly<{ count: number; sessionBytes: number; streamBytes: number }> | undefined;
  constructor(costs: readonly (readonly [string, ResourceVector])[], references: readonly ResourceReference[], private readonly onClose: () => void = () => undefined) {
    this.#parts = new Map();
    for (let index = 0; index < costs.length; index++) {
      const [kind, charge] = costs[index]!;
      const entries = this.#parts.get(kind) ?? []; entries.push({ charge, reference: references[index]! }); this.#parts.set(kind, entries);
    }
  }
  reserveLedger(spec: SessionResourceSpec, clock: TrustedClock, runtimeBytes: bigint): void {
    if (this.#closed || this.#ledger !== undefined) throw new Error("owner_unavailable");
    const part = this.#parts.get("ledger")?.[0];
    if (part === undefined) throw new Error("configuration_capacity");
    const ledger = new CryptoUsageLedger({ ...spec.crypto, clock, runtimeBytes, profile: spec.noise.profile,
      sendDirection: spec.noise.role === "client" ? 0 : 1 }, part.reference);
    try { part.reference = ledger.borrowReference(); part.borrowed = true; this.#ledger = ledger;
      this.#internalKeys = new SessionKeyPreparation(ledger, spec.info.application_profile, part.reference); }
    catch (error) { ledger.close(); throw error; }
  }
  takeLedger(config: CryptoUsageConfig): CryptoUsageLedger {
    if (this.#closed || this.#ledger === undefined) throw new Error("owner_unavailable");
    this.#ledger.checkConfiguration(config); const ledger = this.#ledger; this.#ledger = undefined; return ledger;
  }
  takeInternalKeys(): SessionKeyPreparation {
    if (this.#closed || this.#internalKeys === undefined) throw new Error("owner_unavailable");
    const keys = this.#internalKeys; this.#internalKeys = undefined; return keys;
  }
  takePeerOpens(): PeerOpenPreparation | undefined {
    if (this.#closed) throw new Error("owner_unavailable"); const peer = this.#peerOpens; this.#peerOpens = undefined; return peer;
  }
  reserveCalls(limit: number, runtimeBytes: bigint): void {
    if (this.#closed || this.#calls !== undefined) throw new Error("owner_unavailable");
    const part = this.#parts.get("rpc_application_5")?.[0];
    if (part === undefined) throw new Error("configuration_capacity");
    const calls = new RPCCallCapacity(limit, runtimeBytes, part.reference, true);
    try { part.reference = calls.borrowReference(); part.borrowed = true; this.#calls = calls; }
    catch (error) { calls.close(); throw error; }
  }
  protectCall(workClass: ApplicationWorkClass): RPCCallPosition {
    if (this.#closed || this.#calls === undefined) throw new Error("configuration_capacity");
    return this.#calls.protect(workClass);
  }
  takeCalls(limit: number): RPCCallCapacity {
    if (this.#closed || this.#calls === undefined) throw new Error("owner_unavailable");
    this.#calls.bindLimit(limit); const calls = this.#calls; this.#calls = undefined; return calls;
  }
  reserveServices(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, runtimeBytes: bigint,
    plan: NonNullable<ReturnType<typeof sessionAdmissionPlan>["rpcPlan"]>): void {
    if (this.#closed || this.#services !== undefined) throw new Error("owner_unavailable");
    const query = this.#parts.get(`rpc_application_${plan.queries}`)?.[0];
    if (query === undefined) throw new Error("configuration_capacity");
    this.#services = reserveRPCApplicationServices(root, accounts, owner, runtimeBytes, plan, (indices, build) => {
      const parts = indices.map(index => {
        const part = this.#parts.get(`rpc_application_${index}`)?.[0];
        if (part === undefined || part.borrowed) throw new Error("configuration_capacity"); return part;
      });
      // Prepay every actual assembly identity lease before moving primaries.
      const aliases: ResourceReference[] = [];
      try {
        for (const part of parts) aliases.push(part.reference.borrow());
        build(parts.map(part => part.reference));
        for (const [index, part] of parts.entries()) { part.reference = aliases[index]!; part.borrowed = true; }
      } catch (error) { for (const alias of aliases) alias.release(); throw error; }
    }, query.reference);
    this.#queryReference = query.reference;
  }
  reserveDependencyQueries(acquisitions: ContractQueryAcquisitions): ContractQueryPreparation {
    const services = this.#services, reference = this.#queryReference;
    if (this.#closed || services === undefined || reference === undefined) throw new Error("owner_unavailable");
    let environment: QueryPreparationReservation | undefined, session: QueryPreparationReservation | undefined;
    try {
      environment = acquisitions.protectPreparation(reference); session = services.outgoing.protectPreparation(reference);
      const fixed = services.group.protectQueryAcquisition(reference);
      return new ContractQueryPreparation(environment, session, fixed);
    } catch (error) { session?.close(); environment?.close(); throw error; }
  }
  takeServices(): RPCApplicationServices {
    if (this.#closed || this.#services === undefined) throw new Error("owner_unavailable");
    const services = this.#services; this.#services = undefined; this.#queryReference = undefined; return services;
  }
  reserveDependencyStreams(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, runtimeBytes: bigint, targets: readonly InitializerMethodTarget[]): void {
    if (this.#closed || this.#streams !== undefined) throw new Error("owner_unavailable");
    if (targets.some(target => target.method.required && target.method.facts.shape === "server_streaming")) {
      if (this.#streamOpenCosts === undefined || this.#sendAccounts === undefined) throw new Error("configuration_capacity");
      this.#streams = new RPCStreamPreparation(root, accounts, owner, runtimeBytes, targets, this.#streamOpenCosts, this.#sendAccounts, this.#nativePositions, this.#ledger);
    }
  }
  prepareRawStreams(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, runtimeBytes: bigint,
    declarations: readonly CapturedRawStreamDeclaration[]): RawStreamPreparation {
    if (this.#closed || this.#peerOpens !== undefined || this.#ledger === undefined || this.#streamOpenCosts === undefined || this.#sendAccounts === undefined) throw new Error("configuration_capacity");
    if (declarations.some(declaration => declaration.options.resume !== undefined) && this.#services === undefined) throw new Error("resume_binding");
    const prepared = new RawStreamPreparation(root, accounts, owner, runtimeBytes, declarations, this.#streamOpenCosts, this.#sendAccounts, this.#ledger);
    try {
      this.#peerOpens = new PeerOpenPreparation(root, accounts, owner, this.#ledger,
        declarations.reduce((count, declaration) => count + declaration.options.maxActive, 0), this.#streamOpenCosts.slice(0, 2));
      return prepared;
    } catch (error) { prepared.close(); throw error; }
  }
  takeStreams(): RPCStreamPreparation | undefined {
    if (this.#closed) throw new Error("owner_unavailable"); const streams = this.#streams; this.#streams = undefined; return streams;
  }
  reserveNativePositions(root: ResourceRoot, plan: ReturnType<typeof sessionAdmissionPlan>, runtimeBytes: bigint): void {
    if (this.#closed || this.#nativeLimits !== undefined) throw new Error("owner_unavailable");
    if (plan.nativePositionIndex < 0) return;
    const costs = plan.costs.slice(plan.nativePositionIndex, plan.nativeOpeningIndex + plan.nativeOpeningCount);
    const references = this.take(costs);
    try {
      const opening = plan.nativeOpeningIndex - plan.nativePositionIndex;
      this.#nativePositions = new NativeProtocolPositions(root, plan.nativePositionCount, plan.nativeOpeningCount, runtimeBytes,
        references[0]!, references.slice(1, opening), references.slice(opening));
      this.#nativeLimits = [plan.nativePositionCount, plan.nativeOpeningCount];
    } finally { for (const reference of references) reference.release(); }
  }

  takeNativePositions(positions: number, openings: number): NativeProtocolPositions {
    if (this.#closed || this.#nativePositions === undefined || this.#nativeLimits?.[0] !== positions || this.#nativeLimits[1] !== openings) throw new Error("configuration_capacity");
    const pool = this.#nativePositions; this.#nativePositions = undefined; return pool;
  }
  reserveAccounts(root: ResourceRoot, owner: ResourceOwner, plan: ReturnType<typeof sessionAdmissionPlan>, runtimeBytes: bigint): void {
    if (this.#closed || this.#accountLimits !== undefined) throw new Error("owner_unavailable");
    this.#streamOpenCosts = plan.streamOpenCosts;
    const reference = this.take([["send_account_slots", protectedAccountPoolCharge(plan.sendAccountCount, runtimeBytes)]])[0]!;
    try {
      this.#sendAccount = createSendAccount(root, owner, plan.sendQueueBytes);
      this.#sendAccounts = createStreamSendAccounts(root, plan.sendAccountCount, plan.streamSendQueueBytes, runtimeBytes, reference);
      this.#accountLimits = Object.freeze({ count: plan.sendAccountCount, sessionBytes: plan.sendQueueBytes, streamBytes: plan.streamSendQueueBytes });
    } catch (error) { this.close(); throw error; }
    finally { reference.release(); }
  }
  takeAccounts(count: number, sessionBytes: number, streamBytes: number): Readonly<{ session: ResourceAccount; directions: ProtectedResourceAccounts }> {
    const limits = this.#accountLimits;
    if (this.#closed || limits === undefined || this.#sendAccount === undefined || this.#sendAccounts === undefined) throw new Error("owner_unavailable");
    if (count > limits.count || sessionBytes !== limits.sessionBytes || streamBytes !== limits.streamBytes) throw new Error("configuration_capacity");
    const result = Object.freeze({ session: this.#sendAccount, directions: this.#sendAccounts });
    this.#sendAccount = undefined; this.#sendAccounts = undefined; return result;
  }
  take(costs: readonly (readonly [string, ResourceVector])[]): ResourceReference[] {
    if (this.#closed) throw new Error("owner_unavailable");
    const next = new Map<string, number>();
    const selected = costs.map(([kind, charge]) => {
      const index = next.get(kind) ?? 0, part = this.#parts.get(kind)?.[index]; next.set(kind, index + 1);
      if (part === undefined || !part.charge.contains(charge)) throw new Error("configuration_capacity");
      part.reference.check(); return part;
    });
    // All limits and ownership checks precede the move. No allocation replaces
    // the prepaid root backing during this transfer.
    const result: ResourceReference[] = [];
    try {
      for (let index = 0; index < selected.length; index++) result.push(selected[index]!.borrowed ? selected[index]!.reference.takeBorrow() : selected[index]!.reference.take(costs[index]![1]));
      for (const [kind, count] of next) this.#parts.get(kind)!.splice(0, count);
      return result;
    } catch (error) { for (const reference of result) reference.release(); this.close(); throw error; }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#internalKeys?.close(); this.#internalKeys = undefined;
    this.#peerOpens?.close(); this.#peerOpens = undefined; this.#ledger?.close(); this.#ledger = undefined;
    this.#calls?.close(); this.#calls = undefined;
    if (this.#services !== undefined) closeRPCApplicationServices(this.#services); this.#services = undefined;
    this.#queryReference = undefined;
    this.#streams?.close(); this.#streams = undefined;
    this.#nativePositions?.close(); this.#nativePositions = undefined; this.#streamOpenCosts = undefined;
    this.#sendAccounts?.close(); this.#sendAccounts = undefined; this.#sendAccount?.close(); this.#sendAccount = undefined;
    for (const parts of this.#parts.values()) for (const part of parts) part.reference.release(); this.#parts.clear(); this.onClose();
  }
}
