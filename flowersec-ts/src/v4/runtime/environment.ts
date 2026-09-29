import { RawStreamPreparation } from "./rawStreamPreparation.js";
import { PeerOpenPreparation } from "./peerOpenPreparation.js";
import { streamOpenCharges } from "./streamOpenPreparation.js";
import type { ServerAdmissionExchange } from "./serverAdmission.js";
import { isServerAdmissionAuthority, type ServerAdmissionAuthority, type ServerAdmissionOwner } from "./serverAdmissionAuthority.js";
import type * as ServiceBindingConfigTypes from "./serviceBindingConfig.js";
import type * as ServiceBindingPoolTypes from "./serviceBindingPool.js";
import type * as QueryRenewalPositionTypes from "./queryRenewalPosition.js";
import type * as InitializerWorkloadTypes from "./initializerWorkload.js";
import type * as RawStreamPreparationTypes from "./rawStreamPreparation.js";
import type * as PeerOpenPreparationTypes from "./peerOpenPreparation.js";
import type * as RpcCallCapacityTypes from "./rpcCallCapacity.js";
import type * as RpcStreamPreparationTypes from "./rpcStreamPreparation.js";
import { ClientSessionAdmission, sessionAdmissionPlan, type SessionResourceSpec } from "./sessionAdmission.js";
import { closeRPCApplicationServices, type RPCApplicationServices } from "./rpcApplicationServices.js";
import { executionStorage } from "./executionStorage.js";
import { notifyChannelCharges } from "./notifyChannel.js";
import { VolatileExecutions, captureVolatileExecution, executionServiceKey, type VolatileExecutionConfig } from "./volatileExecutions.js";
import { NativeProtocolPositions, type NativeProtocolPosition } from "./nativePositions.js";
import { ContractQueryAcquisitions, contractQueryAcquisitionsCharges } from "./contractQueryAcquisition.js";
import { ServiceBindingPool, serviceBindingPoolCharge, serviceBindingAccount } from "./serviceBindingPool.js";
import { RPCApplicationAdmission, type RPCApplicationConfig } from "./rpcApplication.js";
import { MaintenancePositions } from "./maintenancePositions.js";

import { createSendAccount, createStreamSendAccounts } from "./sendBudget.js";
import { captureConnectionRequirements } from "../connectionRequirements.js";
import { cleanupResult, lifecycleResult } from "./lifecycle.js";
import type { SessionCleanup } from "./sessionCleanup.js";

import { selectedIdleDuration, captureAutomaticLiveness, qualifySessionActivity } from "./sessionActivity.js";
import type { OperationOptions } from "../../public/contract.js";
import type { V4LifecycleResult, V4CleanupStatus, V4ConnectionRequirements, V4ApplicationProfile } from "../../generated/transportV4APIResults.js";
import { V4TransportEnvironment, V4ConnectionMaterial, type V4ConnectionMaterialSource, type V4EnvironmentOwner, type V4MaterialOwner, type V4SessionOwner } from "../public.js";
import { TrustedClock, trustedClockCharge, type ClockProfile, type ClockTick } from "./clock.js";
import type { TimeInterval } from "./timeArithmetic.js";
import { TrustedWindow, timerChunk } from "./deadline.js";
import { TrustedRandom, randomCharge, randomDH, type RandomFill } from "./random.js";
import { SessionKeyPreparation } from "./sessionKeyPreparation.js";
import { ResourceVector, ResourceRoot, type ResourceAccount, type ResourceOwner, type ResourceReference, type ProtectedResourceReservation, type ProtectedResourceAccounts } from "./resources.js";
import { CredentialNamespace, type CredentialNamespaceConfig } from "./credentialNamespace.js";
import { credentialWorkCharge, equalCredential, type CredentialResources } from "./credentialSupport.js";
import { verifyDirectCredentials, credentialVerifierCharge, type CredentialVerifierConfig, type CredentialInput, type VerifiedCredentialClosure, type ActivationSource, type ClientPreparationFields } from "./credentialVerifier.js";
import { ClientAdmissionExchange, clientAdmissionCharge, clearClientPreparation } from "./clientAdmission.js";
import { CryptoUsageLedger, type CryptoUsageConfig } from "./cryptoUsage.js";
import { ReceiveDeliveryGate } from "./receiveDirection.js";

import { establishV4CredentialSession, type V4AuthenticatedSessionConfig, type V4AuthenticatedSessionRuntime, type V4SessionStreamAssembly } from "./session.js";
import { isPoolSpendStore, type PoolSpendStore } from "./poolSpend.js";
import type { LiveAuthorizationClient } from "./liveAuthorization.js";
import { ownProfile } from "./wireRegistry.js";

export interface V4EnvironmentClockConfig {
  readonly profile: ClockProfile;
  /** Qualified monotonic clock, including suspend/migration continuity. */
  readonly tick: () => ClockTick;
  /** Independently trusted initial UTC envelope, sampled during construction. */
  readonly initial: () => TimeInterval;
}
export interface V4EnvironmentConfig {
  /** Borrowed shared authority. Closing one Environment never closes this root. */
  readonly root: ResourceRoot;
  readonly tenantID: string;
  readonly environmentID: string;
  readonly tenantLimit: ResourceVector;
  readonly limit: ResourceVector;
  readonly runtimeBytes: bigint;
  readonly namespaces: number;
  readonly sources: number;
  readonly acquisitions: number;
  readonly materials: number;
  readonly sessions: number;
  readonly acquireMS: bigint;
  readonly cleanupMS?: number;
  readonly dependencies?: number;
  readonly clock: V4EnvironmentClockConfig;
  readonly random: RandomFill;
}
export type V4NamespaceOptions = Omit<CredentialNamespaceConfig, "clock" | "random" | "resources">;
export type V4CredentialPolicy = Omit<CredentialVerifierConfig, "clock" | "resources" | "namespaces"> & { readonly authorities: readonly string[] };
export interface V4CredentialBuffers {
  readonly artifact: Uint8Array;
  readonly clientCertificate: Uint8Array;
  readonly serverCertificate: Uint8Array;
  readonly activation: Uint8Array;
}
export interface V4CredentialLengths {
  readonly artifact: number;
  readonly clientCertificate: number;
  readonly serverCertificate: number;
  readonly activation: number;
  readonly candidateIndex: number;
}
/** Trusted bounded source adapter. Resolution proves the original buffer borrow
 * has ended, also after cancellation. The source profile is fixed on registration. */
export type V4CredentialProvider = (request: Readonly<{ signal: AbortSignal; requirements: V4ConnectionRequirements }>, buffers: V4CredentialBuffers) => Promise<V4CredentialLengths>;
export interface V4EnvironmentSessionSpec extends Omit<V4AuthenticatedSessionConfig, "noise" | "ledger" | "reservations" | "streams" | "runtimeBytes"> {
  readonly initialRawStreams?: readonly RawStreamPreparationTypes.CapturedRawStreamDeclaration[];
  readonly bindingMode?: "direct_exporter" | "authenticated_context";
  readonly application?: RPCApplicationConfig;
  readonly noise: Omit<V4AuthenticatedSessionConfig["noise"], "clock" | "ephemeralPrivate">;
  readonly crypto: Omit<CryptoUsageConfig, "clock" | "profile" | "sendDirection" | "runtimeBytes">;
  readonly streams: Omit<V4SessionStreamAssembly, "root" | "accounts" | "owner" | "random" | "sendAccount" | "sendAccounts" | "bootstrapReservations" | "bootstrapSendAccount" | "bootstrapNativePosition" | "rpcAdmission" | "notifyReservations" | "notifySendAccounts" | "notifyNativePosition" | "managementReservations" | "managementSendAccount" | "managementNativePosition" | "internalKeys" | "peerOpenPreparation" | "nativePositions" | "maintenancePositions" | "delivery" | "authorization" | "open" | "openDecoder" | "control" | "controlDecoder" | "controlSendCipher" | "controlReceiveCipher">;
}
const token = Symbol("environment owner");
const NativePromise = Promise;
const complete = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
const sizes = Object.freeze({ artifact: 65536, clientCertificate: 16384, serverCertificate: 16384, activation: 65536 });
const keys = Object.freeze(["artifact", "clientCertificate", "serverCertificate", "activation"] as const);
const max = 0xffffffffffffffffn;
function fail(code: string): never { throw new Error(code); }
function bounded(value: number, cap = 65536): number { if (!Number.isSafeInteger(value) || value < 1 || value > cap) fail("configuration_capacity"); return value; }
function duration(value: bigint): bigint { if (typeof value !== "bigint" || value <= 0n || value > max) fail("configuration_capacity"); return value; }
function sameNamespace(a: V4NamespaceOptions, b: V4NamespaceOptions): boolean {
  const fields = ["tenant", "authority", "maxTrustLifetimeMS", "bootstrapMS", "stateBytes", "stateNodes", "continuity", "trustConfigurations", "trustNodes", "subscriptions", "maxStateFetchMS", "maxFetchAttempts"] as const;
  return fields.every(key => a[key] === b[key]) && equalCredential(a.rootKeyID, b.rootKeyID) && equalCredential(a.rootPublicKey, b.rootPublicKey);
}
function captureNamespace(c: V4NamespaceOptions): V4NamespaceOptions {
  return Object.freeze({ tenant: c.tenant, authority: c.authority, rootKeyID: new Uint8Array(c.rootKeyID), rootPublicKey: new Uint8Array(c.rootPublicKey),
    maxTrustLifetimeMS: c.maxTrustLifetimeMS, bootstrapMS: c.bootstrapMS, stateBytes: c.stateBytes, stateNodes: c.stateNodes,
    continuity: c.continuity ?? "online_bootstrap", trustConfigurations: c.trustConfigurations ?? 8, trustNodes: c.trustNodes ?? 270336,
    subscriptions: c.subscriptions ?? 1024, maxStateFetchMS: c.maxStateFetchMS ?? 90000n, maxFetchAttempts: c.maxFetchAttempts ?? 3 });
}
export interface PreparedEnvironmentConnection {
  start(): Promise<V4SessionOwner>;
  close(): void;
}
interface MaterialState { admission?: ClientSessionAdmission; connectionClaim?: AbortController; environment: V4EnvironmentRuntime; closure: VerifiedCredentialClosure | undefined; claimed: boolean; timer: ReturnType<typeof setTimeout> | undefined }
const materials = new WeakMap<V4EnvironmentMaterial, MaterialState>();
/** An original verified snapshot. Only Environment admission can claim it. */
export class V4EnvironmentMaterial implements V4MaterialOwner {
  constructor(capability: symbol, state: MaterialState) { if (capability !== token) fail("material_unavailable"); materials.set(this, state); Object.freeze(this); }
  closeMaterial(): Promise<void> {
    const state = materials.get(this)!;
    if (!state.claimed) state.environment.releaseMaterial(token, this);
    return Promise.resolve();
  }
  toJSON(): object { return {}; }
}
interface SourceState { environment: V4EnvironmentRuntime; policy: V4CredentialPolicy; source: ActivationSource; provider: V4CredentialProvider; reference: ResourceReference; closed: boolean; active: number }
const sources = new WeakMap<V4EnvironmentCredentialSource, SourceState>();
const publicSources = new WeakMap<V4ConnectionMaterialSource, V4EnvironmentCredentialSource>();
export function wrapCredentialSource(source: V4EnvironmentCredentialSource): V4ConnectionMaterialSource {
  if (!sources.has(source)) fail("source_unavailable");
  const result = Object.freeze({ acquire: async (request: V4ConnectionRequirements, options?: OperationOptions) => new V4ConnectionMaterial(await source.acquire(request, options)) });
  publicSources.set(result, source); return result;
}
export interface EnvironmentClientConnector {
  readonly applicationProfile: V4ApplicationProfile;
  reserveAdmission?(): ClientSessionAdmission;
  connect(material: V4EnvironmentMaterial, options?: OperationOptions): Promise<V4SessionOwner>;
  checkRequirements(request: V4ConnectionRequirements): void;
}
export class V4EnvironmentCredentialSource {
  constructor(capability: symbol, state: SourceState) { if (capability !== token) fail("source_unavailable"); sources.set(this, state); Object.freeze(this); }
  acquire(request: V4ConnectionRequirements, options?: OperationOptions): Promise<V4EnvironmentMaterial> { return sources.get(this)!.environment.acquire(this, request, options); }
  close(): void { const state = sources.get(this)!; state.closed = true; state.environment.releaseSource(token, this); }
  toJSON(): object { return {}; }
}
/** Original native/store task reference. The actual provider releases it only
 * after close returns; Environment cancellation does not refund native work. */
export class EnvironmentDependency {
  #close: (() => void) | undefined;
  #closed = false;
  #released = false;
  constructor(capability: symbol, readonly reference: ResourceReference, private readonly released: () => void) { if (capability !== token) fail("invalid_resource_owner"); }
  check(): void { if (this.#closed || this.#released) fail("closed"); this.reference.check(); }
  onClose(close: () => void): void { if (this.#close !== undefined) fail("invalid_resource_owner"); this.#close = close; if (this.#closed) close(); }
  close(): void { if (this.#closed) return; this.#closed = true; this.#close?.(); }
  release(): void { if (this.#released) return; this.#released = true; this.#close = undefined; this.reference.release(); this.released(); }
}
const publicEnvironments = new WeakMap<V4TransportEnvironment, V4EnvironmentRuntime>();
const environmentFacades = new WeakMap<V4EnvironmentRuntime, V4TransportEnvironment>();
export function originalEnvironment(environment: V4TransportEnvironment): V4EnvironmentRuntime {
  const owner = publicEnvironments.get(environment); if (owner === undefined) fail("owner_unavailable"); return owner;
}

interface Acquisition { abort: AbortController; reference: ResourceReference; source: V4EnvironmentCredentialSource; timer: ReturnType<typeof setTimeout> | undefined }
interface SessionEntry { runtime: V4AuthenticatedSessionRuntime | undefined; cleanup: SessionCleanup; delivery: ReceiveDeliveryGate; material: V4EnvironmentMaterial; monitor: Promise<void> }

/** One actual root owner for namespaces, sources, materials and Session assembly.
 * Connect requires an installed production once/provider adapter. */
export class V4EnvironmentRuntime implements V4EnvironmentOwner {
  readonly clock: TrustedClock;
  readonly resources: CredentialResources;
  readonly #config: V4EnvironmentConfig;
  readonly #random: TrustedRandom;
  readonly #accounts: readonly ResourceAccount[];
  readonly #environment: ResourceAccount;
  readonly #namespaces = new Map<string, { options: V4NamespaceOptions; namespace: CredentialNamespace }>();
  readonly #sources = new Set<V4EnvironmentCredentialSource>();
  readonly #materials = new Set<V4EnvironmentMaterial>();
  readonly #acquisitions = new Set<Acquisition>();
  readonly #admissions = new Set<AbortController>();
  readonly #preparations = new Set<AbortController>();
  readonly #connectionClaims = new Set<AbortController>();
  readonly #sessions = new Set<SessionEntry>();
  readonly #results = new Set<Pick<SessionEntry, "delivery" | "material">>();
  readonly #dependencyClaims = new Set<ClientSessionAdmission>();
  readonly #dependencies = new Set<EnvironmentDependency>();
  #reference: ResourceReference | undefined;
  #contractQueries: ContractQueryAcquisitions | undefined;
  #serviceBindings: ServiceBindingPool | undefined;
  readonly #executionServices = new Map<string, VolatileExecutions>();
  #serviceAccount: ResourceAccount | undefined;
  #sequence = 0n;
  #working = 0;
  #verifying = 0;
  #closed = false;
  #closeResolve: ((status: V4LifecycleResult) => void) | undefined;
  readonly #close = new NativePromise<V4LifecycleResult>(resolve => { this.#closeResolve = resolve; });
  #closeInitializing = false;
  #cleaning = false;
  #cleaned: (() => void) | undefined;
  #cleanupWindow: TrustedWindow | undefined;
  #cleanupIncomplete = false;
  #cleanupFault = false;
  #resourceObserver: (() => void) | undefined;
  readonly #cleanupObservers = new Set<() => void>();
  #cleanupTimer: ReturnType<typeof setTimeout> | undefined;
  #waiters = 0;
  #connector: EnvironmentClientConnector | undefined;
  constructor(config: V4EnvironmentConfig) {
    if (new.target !== V4EnvironmentRuntime || Object.getPrototypeOf(config.root) !== ResourceRoot.prototype) fail("configuration_capacity");
    const c = this.#config = Object.freeze({ root: config.root, tenantID: config.tenantID, environmentID: config.environmentID, tenantLimit: config.tenantLimit,
      limit: config.limit, runtimeBytes: duration(config.runtimeBytes), namespaces: bounded(config.namespaces, 8), sources: bounded(config.sources), acquisitions: bounded(config.acquisitions),
      materials: bounded(config.materials), sessions: bounded(config.sessions), acquireMS: duration(config.acquireMS), cleanupMS: bounded(config.cleanupMS ?? 5000, 60000), dependencies: bounded(config.dependencies ?? 4, 64),
      clock: Object.freeze({ profile: config.clock.profile, tick: config.clock.tick, initial: config.clock.initial }), random: config.random });
    const tenant = c.root.account("tenant", c.tenantID, c.tenantLimit);
    this.#environment = c.root.account("environment", c.environmentID, c.limit);
    this.#accounts = Object.freeze([tenant, this.#environment]);
    const metadata = BigInt(c.namespaces + c.sources + c.acquisitions + c.materials + c.sessions + c.dependencies! + 32) * c.runtimeBytes;
    const refs = c.root.reserveBatch([
      { owner: { tenant: c.tenantID, environment: c.environmentID, kind: "environment", backing: c.environmentID }, accounts: this.#accounts,
        charge: new ResourceVector([metadata, 0n, 0n, BigInt(c.namespaces + c.sources + c.materials + 32), 33n, 33n, 66n, 0n, 0n, 0n, 0n]) },
      this.#request("clock", trustedClockCharge(c.runtimeBytes)), this.#request("random", randomCharge(c.runtimeBytes)),
    ]);
    let clock: TrustedClock | undefined, random: TrustedRandom | undefined;
    try {
      this.#reference = refs[0]!;
      this.#random = random = new TrustedRandom(c.random, c.runtimeBytes, refs[2]!, () => { if (this.clock !== undefined) void this.close(); });
      this.clock = clock = new TrustedClock(c.clock.profile, c.clock.tick, c.runtimeBytes, refs[1]!, bytes => this.#random.fill(bytes));
      const mark = clock.monotonic(); clock.installTrusted(mark, c.clock.initial());
      this.resources = Object.freeze({ root: c.root, accounts: this.#accounts, owner: this.#owner("credentials"), runtimeBytes: c.runtimeBytes });
      this.#resourceObserver = c.root.observeAvailability(this.#reference, () => this.#cleanup());
    } catch (error) { this.#resourceObserver?.(); this.#resourceObserver = undefined; clock?.close(); random?.close(); for (const ref of refs) ref.release(); this.#environment.close(); throw error; }
    finally { refs[1]!.release(); refs[2]!.release(); }
    Object.freeze(this);
  }
  #owner(kind: string): ResourceOwner {
    if (this.#sequence === max) fail("configuration_capacity");
    return Object.freeze({ tenant: this.#config.tenantID, environment: this.#config.environmentID, kind, backing: (++this.#sequence).toString(16).padStart(32, "0") });
  }
  #request(kind: string, charge: ResourceVector) { return { owner: this.#owner(kind), accounts: this.#accounts, charge }; }
  #reserve(kind: string, charge: ResourceVector): ResourceReference { this.#check(); return this.#config.root.reserve(this.#request(kind, charge)); }
  #check(): void { if (this.#closed) fail("closed"); this.#reference!.check(); }
  /** One immutable ordinary/constrained query table for this Environment.
   * The full delivery vector is prepaid in its original tenant/root accounts;
   * no native dependency or general result-owner pool is used for queries. */
  contractQueries(limit: 2 | 4 = 4): ContractQueryAcquisitions {
    this.#check();
    if (this.#contractQueries !== undefined) {
      if (this.#contractQueries.limit !== limit) fail("configuration_capacity"); return this.#contractQueries;
    }
    const costs = contractQueryAcquisitionsCharges(limit, this.#config.runtimeBytes);
    const references = this.#config.root.reserveBatch(costs.map(charge => this.#request("contract_query_acquisition", charge)));
    this.#working++;
    try {
      this.#contractQueries = new ContractQueryAcquisitions(this.#config.root, this.clock, limit, this.#config.runtimeBytes, references);
      this.#check(); return this.#contractQueries;
    } catch (error) { this.#contractQueries?.close(); throw error; }
    finally { for (const reference of references) reference.release(); this.#working--; this.#cleanup(); }
  }
  serviceBindings(limit: 16 | 256): ServiceBindingPool {
    this.#check();
    if (this.#serviceBindings !== undefined) {
      if (this.#serviceBindings.methodLimit !== limit) fail("configuration_capacity"); return this.#serviceBindings;
    }
    const owner = this.#owner("service_bindings");
    const account = serviceBindingAccount(this.#config.root, owner, limit, this.#config.limit);
    let reference: ResourceReference | undefined;
    try {
      const accounts = Object.freeze([...this.#accounts, account]);
      reference = this.#config.root.reserve({ accounts, owner, charge: serviceBindingPoolCharge(this.#config.runtimeBytes) });
      this.#serviceBindings = new ServiceBindingPool(this.#config.root, accounts, owner, limit, this.#config.runtimeBytes, reference, this.clock);
      this.#serviceAccount = account; return this.#serviceBindings;
    } catch (error) { account.close(); throw error; }
    finally { reference?.release(); }
  }
  reserveServiceBinding(config: ServiceBindingConfigTypes.CapturedServiceBinding): ServiceBindingPoolTypes.ServiceBindingReservation {
    this.#check(); if (this.#serviceBindings === undefined) fail("configuration_capacity");
    return this.#serviceBindings.reserve(config);
  }
  reserveDependencyQueries(admission: ClientSessionAdmission): QueryRenewalPositionTypes.ContractQueryPreparation {
    this.#check(); if (this.#contractQueries === undefined) fail("configuration_capacity");
    return admission.reserveDependencyQueries(this.#contractQueries);
  }
  reserveDependencyStreams(admission: ClientSessionAdmission, targets: readonly InitializerWorkloadTypes.InitializerMethodTarget[]): void {
    this.#check(); admission.reserveDependencyStreams(this.#config.root, this.#accounts, this.#owner("initial_streams"), this.#config.runtimeBytes, targets);
  }
  reserveRawStreams(admission: ClientSessionAdmission | undefined, declarations: readonly RawStreamPreparationTypes.CapturedRawStreamDeclaration[]): RawStreamPreparationTypes.RawStreamPreparation {
    this.#check(); if (admission === undefined) fail("configuration_capacity");
    return admission.prepareRawStreams(this.#config.root, this.#accounts, this.#owner("initial_raw_streams"), this.#config.runtimeBytes, declarations);
  }
  /** A logical authority keeps one continuous execution owner across Sessions.
   * Repeated configuration cannot install an empty replacement history. */
  executionService(input: VolatileExecutionConfig): VolatileExecutions {
    this.#check(); const config = captureVolatileExecution(input), key = executionServiceKey(config);
    const existing = this.#executionServices.get(key);
    if (existing !== undefined) {
      if (executionStorage(existing.config) !== executionStorage(config) || existing.configuration !== JSON.stringify(config, (_key, value) => typeof value === "bigint" ? value.toString() : value)) fail("configuration_capacity");
      return existing;
    }
    if (this.#executionServices.size >= 64) fail("resource_exhausted");
    const history = new VolatileExecutions(this.resources, this.clock, config);
    this.#executionServices.set(key, history); return history;
  }
  reserveClientAdmission(spec: SessionResourceSpec, carrierCosts: readonly (readonly [string, ResourceVector])[] = []): ClientSessionAdmission {
    this.#check();
    if (carrierCosts.length !== 0 && this.#dependencies.size + this.#dependencyClaims.size >= this.#config.dependencies!) fail("resource_exhausted");
    const plan = sessionAdmissionPlan(spec, this.#config.runtimeBytes);
    const costs = [...plan.costs, ["client_admission", clientAdmissionCharge(this.#config.runtimeBytes)] as const, ...carrierCosts];
    const references = this.#config.root.reserveBatch(costs.map(([kind, charge]) => this.#request(kind, charge)));
    try {
      const admission = new ClientSessionAdmission(costs, references, () => { this.#dependencyClaims.delete(admission); this.#cleanup(); });
      try {
        admission.reserveLedger(spec, this.clock, this.#config.runtimeBytes);
        admission.reserveAccounts(this.#config.root, this.#owner("send_headroom"), plan, this.#config.runtimeBytes);
        admission.reserveNativePositions(this.#config.root, plan, this.#config.runtimeBytes);
        // Environment services retain one original owner across candidates.
        // Establishment reuses these exact pools and execution histories.
        const application = plan.rpcConfig;
        if (application !== undefined) {
          admission.reserveCalls(spec.streams.rpcMaxGeneralOutstanding ?? 0, this.#config.runtimeBytes);
          admission.reserveServices(this.#config.root, this.#accounts, this.#owner("application_headroom"), this.#config.runtimeBytes, plan.rpcPlan!);
          this.contractQueries(application.queryAcquisitions);
          this.serviceBindings(application.queryAcquisitions === 2 ? 16 : 256);
          for (const config of application.executionServices ?? []) this.executionService(config);
          for (const entry of [...application.unaryHandlers ?? [], ...application.streamingHandlers ?? [], ...application.notificationHandlers ?? []]) {
            if (entry.execution !== undefined) this.executionService(entry.execution);
          }
        }
      } catch (error) { admission.close(); throw error; }
      if (carrierCosts.length !== 0) this.#dependencyClaims.add(admission);
      return admission;
    }
    catch (error) { for (const reference of references) reference.release(); throw error; }
  }
  /** Trusted assembly reserves the original fixed work vectors before Acquire. */
  reserveInitializerWorkload(charges: readonly ResourceVector[]): ResourceReference[] {
    this.#check(); if (charges.length < 1 || charges.length > 16) fail("configuration_capacity");
    return this.#config.root.reserveBatch(charges.map(charge => this.#request("initializer_workload", charge)));
  }
  fillRandom(bytes: Parameters<TrustedRandom["fill"]>[0]): void { this.#check(); this.#random.fill(bytes); }
  reserveConnectionWork(kind: string, charge: ResourceVector, admission?: ClientSessionAdmission): ResourceReference {
    this.#check(); return admission?.take([[kind, charge]])[0]! ?? this.#reserve(kind, charge);
  }
  admitDependency(kind: string, charge: ResourceVector, prepaid?: ResourceReference, admission?: ClientSessionAdmission): EnvironmentDependency {
    this.#check(); if (this.#dependencies.size + this.#dependencyClaims.size - (admission !== undefined && this.#dependencyClaims.has(admission) ? 1 : 0) >= this.#config.dependencies!) fail("resource_exhausted");
    if (prepaid !== undefined && !prepaid.sameEnvironment(this.#reference!)) fail("owner_unavailable");
    const ref = prepaid?.take(charge) ?? this.#reserve(kind, charge);
    const dependency = new EnvironmentDependency(token, ref, () => { this.#dependencies.delete(dependency); this.#cleanup(); });
    if (admission !== undefined) this.#dependencyClaims.delete(admission);
    this.#dependencies.add(dependency); return dependency;
  }
  /** One provider lifecycle with prepaid reusable native positions. The full
   * vector and every physical reference slot precede native construction. */
  admitDependencyPositions(kind: string, charge: ResourceVector, positionCharge: ResourceVector, count: number, prepaid?: readonly ResourceReference[], admission?: ClientSessionAdmission):
    Readonly<{ dependency: EnvironmentDependency; positions: readonly ProtectedResourceReservation[] }> {
    this.#check();
    if (!Number.isSafeInteger(count) || count < 1 || count > 4097) fail("configuration_capacity");
    if (this.#dependencies.size + this.#dependencyClaims.size - (admission !== undefined && this.#dependencyClaims.has(admission) ? 1 : 0) >= this.#config.dependencies!) fail("resource_exhausted");
    const requests = [this.#request(kind, charge)];
    for (let i = 0; i < count; i++) requests.push(this.#request("native_stream_position", positionCharge));
    if (prepaid !== undefined && (prepaid.length !== requests.length || prepaid.some(ref => !ref.sameEnvironment(this.#reference!)))) fail("owner_unavailable");
    const refs = prepaid === undefined ? this.#config.root.reserveBatch(requests) : [...prepaid], positions: ProtectedResourceReservation[] = [];
    try {
      for (const reference of refs.slice(1)) positions.push(this.#config.root.protect(reference, positionCharge));
      const dependency = new EnvironmentDependency(token, refs[0]!.take(charge), () => { this.#dependencies.delete(dependency); this.#cleanup(); });
      if (admission !== undefined) this.#dependencyClaims.delete(admission);
      this.#dependencies.add(dependency); return Object.freeze({ dependency, positions: Object.freeze(positions) });
    } catch (error) { for (const position of positions) position.close(); for (const reference of refs) reference.release(); throw error; }
  }
  namespace(options: V4NamespaceOptions): CredentialNamespace {
    this.#check(); const captured = captureNamespace(options), key = `${captured.tenant}\0${captured.authority}`;
    this.#check(); const existing = this.#namespaces.get(key);
    if (existing !== undefined) { if (!sameNamespace(existing.options, captured)) fail("credential_binding"); return existing.namespace; }
    if (this.#namespaces.size >= this.#config.namespaces) fail("resource_exhausted");
    const ref = this.#reserve("namespace", credentialWorkCharge(Math.max(270336, captured.stateBytes), this.#config.runtimeBytes));
    this.#working++;
    try {
      const namespace = new CredentialNamespace({ ...captured, clock: this.clock, random: bytes => this.#random.fill(bytes), resources: this.resources }, ref);
      if (this.#closed) { namespace.close(); fail("closed"); }
      this.#namespaces.set(key, { options: captured, namespace }); return namespace;
    } finally { ref.release(); this.#working--; this.#cleanup(); }
  }
  #policy(policy: V4CredentialPolicy): CredentialVerifierConfig {
    const tenant = policy.tenant, authorityNames = [...policy.authorities];
    if (authorityNames.length < 1 || authorityNames.length > 8 || new Set(authorityNames).size !== authorityNames.length) fail("configuration_capacity");
    const namespaces = authorityNames.map(authority => { const entry = this.#namespaces.get(`${tenant}\0${authority}`); if (entry === undefined) fail("credential_untrusted"); return entry.namespace; });
    return Object.freeze({ tenant, audience: policy.audience, clientSubject: policy.clientSubject, serverSubject: policy.serverSubject, cryptoProfiles: Object.freeze([...policy.cryptoProfiles]),
      resources: this.resources, clock: this.clock, namespaces: Object.freeze(namespaces) });
  }
  registerSource(policy: V4CredentialPolicy, source: ActivationSource, provider: V4CredentialProvider): V4EnvironmentCredentialSource {
    this.#check(); if (source !== "live_authority" && source !== "preauthorized_pool" || typeof provider !== "function") fail("configuration_capacity");
    const verified = this.#policy(policy), captured = Object.freeze({ tenant: verified.tenant, audience: verified.audience, clientSubject: verified.clientSubject, serverSubject: verified.serverSubject,
      cryptoProfiles: verified.cryptoProfiles, authorities: Object.freeze(verified.namespaces.map(ns => ns.authority)) });
    this.#check(); if (this.#sources.size >= this.#config.sources) fail("resource_exhausted");
    const reference = this.#reserve("source", new ResourceVector([this.#config.runtimeBytes, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
    const owner = new V4EnvironmentCredentialSource(token, { environment: this, policy: captured, source, provider, reference, closed: false, active: 0 });
    this.#sources.add(owner); return owner;
  }
  releaseSource(capability: symbol, owner: V4EnvironmentCredentialSource): void {
    if (capability !== token) fail("source_unavailable"); const state = sources.get(owner)!;
    if (state.closed) for (const job of this.#acquisitions) if (job.source === owner) job.abort.abort();
    if (state.closed && state.active === 0) { state.reference.release(); this.#sources.delete(owner); this.#cleanup(); }
  }
  verify(policy: V4CredentialPolicy, input: CredentialInput): V4EnvironmentMaterial {
    this.#check(); const config = this.#policy(policy);
    if (this.#materials.size + this.#acquisitions.size + this.#verifying >= this.#config.materials) fail("resource_exhausted");
    return this.#verify(config, input);
  }
  #verify(config: CredentialVerifierConfig, input: CredentialInput): V4EnvironmentMaterial {
    const ref = this.#reserve("material", credentialVerifierCharge(this.#config.runtimeBytes).add(new ResourceVector([this.#config.runtimeBytes, 0n, 0n, 0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n])));
    let closure: VerifiedCredentialClosure | undefined; this.#working++; this.#verifying++;
    try {
      closure = verifyDirectCredentials(config, input, ref); this.#check();
      const material = new V4EnvironmentMaterial(token, { environment: this, closure, claimed: false, timer: undefined });
      this.#materials.add(material); this.#expireMaterial(material); if (materials.get(material)!.closure === undefined) fail("material_unavailable"); return material;
    } catch (error) { closure?.close(); throw error; } finally { ref.release(); this.#working--; this.#verifying--; this.#cleanup(); }
  }
  #expireMaterial(material: V4EnvironmentMaterial): void {
    const state = materials.get(material)!;
    try {
      state.closure!.checkPreparation(this.#reference!);
      // The original credential deadlines remain authoritative; this bounded
      // wakeup only collects unused snapshots and never extends a deadline.
      state.timer = setTimeout(() => { state.timer = undefined; if (!state.claimed && state.closure !== undefined) this.#expireMaterial(material); }, 1000);
    } catch { this.releaseMaterial(token, material); }
  }
  releaseMaterial(capability: symbol, material: V4EnvironmentMaterial): void {
    if (capability !== token) fail("material_unavailable"); const state = materials.get(material)!;
    if (state.environment !== this) fail("material_unavailable");
    if (state.timer !== undefined) clearTimeout(state.timer); state.timer = undefined;
    state.closure?.close(); state.closure = undefined; this.#materials.delete(material); this.#cleanup();
  }
  acquire(owner: V4EnvironmentCredentialSource, request: V4ConnectionRequirements, options?: OperationOptions): Promise<V4EnvironmentMaterial> {
    try {
      this.#check(); const source = sources.get(owner);
      if (source?.environment !== this || source.closed || !this.#sources.has(owner)) fail("source_unavailable");
      if (options?.signal?.aborted) fail("canceled");
      const requirements = captureConnectionRequirements(request), config = this.#policy(source.policy);
      // Freshness is checked before asking a source to issue or remove a lease.
      for (const namespace of config.namespaces) namespace.check();
      if (this.#acquisitions.size >= this.#config.acquisitions || this.#materials.size + this.#acquisitions.size + this.#verifying >= this.#config.materials) fail("resource_exhausted");
      const original = new TrustedWindow(this.clock, this.#config.acquireMS), abort = new AbortController();
      const reference = this.#reserve("acquire", new ResourceVector([163840n + this.#config.runtimeBytes, 0n, 0n, 5n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]));
      const job: Acquisition = { reference, abort, source: owner, timer: undefined }; this.#acquisitions.add(job); source.active++;
      let buffers: V4CredentialBuffers;
      try { buffers = Object.freeze({ artifact: new Uint8Array(sizes.artifact), clientCertificate: new Uint8Array(sizes.clientCertificate), serverCertificate: new Uint8Array(sizes.serverCertificate), activation: new Uint8Array(sizes.activation) }); }
      catch (error) { this.#acquisitions.delete(job); source.active--; reference.release(); throw error; }
      let rejectCanceled!: (error: Error) => void;
      const canceled = new Promise<never>((_resolve, reject) => { rejectCanceled = reject; });
      const canceledResult = (): void => rejectCanceled(new Error(this.#closed ? "closed" : "canceled"));
      abort.signal.addEventListener("abort", canceledResult, { once: true });
      const onAbort = (): void => { abort.abort(); };
      options?.signal?.addEventListener("abort", onAbort, { once: true });
      const timeout = (): void => {
        try { original.check(); job.timer = setTimeout(timeout, timerChunk(original.remainingMS())); }
        catch { abort.abort(); rejectCanceled(new Error("deadline_exceeded")); }
      };
      timeout();
      // The original job is entered synchronously and remains paid until the
      // source callback has really returned. Abort only fences installation.
      const tail = (async () => {
        try {
          if (abort.signal.aborted) fail("canceled");
          const lengths = await source.provider(Object.freeze({ signal: abort.signal, requirements }), buffers);
          this.#check(); original.check(); if (abort.signal.aborted || source.closed) fail("canceled");
          for (const key of keys) if (!Number.isSafeInteger(lengths[key]) || lengths[key] < (key === "activation" && source.source === "live_authority" ? 0 : 1) || lengths[key] > sizes[key]) fail("source_contract_invalid");
          const candidateIndex = lengths.candidateIndex;
          const input = { artifact: buffers.artifact.subarray(0, lengths.artifact), clientCertificate: buffers.clientCertificate.subarray(0, lengths.clientCertificate),
            serverCertificate: buffers.serverCertificate.subarray(0, lengths.serverCertificate), activation: buffers.activation.subarray(0, lengths.activation), source: source.source, candidateIndex };
          const result = this.#verify(config, input);
          try {
            if (requirements.application_profile !== undefined) materials.get(result)!.closure!.checkApplicationProfile(requirements.application_profile, this.#reference!);
            if (abort.signal.aborted || this.#closed || source.closed) fail("canceled");
            return result;
          } catch (error) { this.releaseMaterial(token, result); throw error; }
        } finally {
          if (job.timer !== undefined) clearTimeout(job.timer); options?.signal?.removeEventListener("abort", onAbort); abort.signal.removeEventListener("abort", canceledResult);
          for (const key of keys) buffers[key].fill(0);
          reference.release(); this.#acquisitions.delete(job); source.active--; this.releaseSource(token, owner); this.#cleanup();
        }
      })();
      return Promise.race([tail, canceled]).then(material => {
        if (this.#closed || options?.signal?.aborted || source.closed) { this.releaseMaterial(token, material); fail(this.#closed ? "closed" : "canceled"); }
        return material;
      });
    } catch (error) { return Promise.reject(error); }
  }
  /** Private assembly, after an actual transport/once owner supplies its inputs.
   * No public API accepts this raw-key assembly or an authenticated flag. */
  establishVerified(material: V4EnvironmentMaterial, spec: V4EnvironmentSessionSpec, context: Uint8Array, options?: OperationOptions): Promise<V4AuthenticatedSessionRuntime> {
    return this.#establish(material, spec, context, options);
  }
  /** Internal pool assembly. The Node WSS entrance must still perform the real
   * HELLO/FSB/FSA sequence; this is not exposed as production Connect. */
  establishPoolVerified(material: V4EnvironmentMaterial, spec: V4EnvironmentSessionSpec, context: Uint8Array, store: PoolSpendStore, options?: OperationOptions): Promise<V4AuthenticatedSessionRuntime> {
    if (!isPoolSpendStore(store)) return Promise.reject(new Error("owner_unavailable"));
    return this.#establish(material, spec, context, options, store);
  }
  /** Internal production client assembly. A native carrier is prepared before
   * atomic Session admission; TxA-P precedes the first HELLO byte. */
  establishPoolClient(material: V4EnvironmentMaterial, store: PoolSpendStore,
    prepare: (fields: ClientPreparationFields, signal: AbortSignal, admission?: ClientSessionAdmission) => Promise<V4EnvironmentSessionSpec>, options?: OperationOptions): Promise<V4AuthenticatedSessionRuntime> {
    if (!isPoolSpendStore(store)) return Promise.reject(new Error("owner_unavailable"));
    return this.#establishClient(material, "preauthorized_pool", prepare, options, store);
  }
  establishLiveClient(material: V4EnvironmentMaterial, live: LiveAuthorizationClient,
    prepare: (fields: ClientPreparationFields, signal: AbortSignal, admission?: ClientSessionAdmission) => Promise<V4EnvironmentSessionSpec>, options?: OperationOptions): Promise<V4AuthenticatedSessionRuntime> {
    return this.#establishClient(material, "live_authority", prepare, options, undefined, live);
  }
  async #establishClient(material: V4EnvironmentMaterial, source: ActivationSource,
    prepare: (fields: ClientPreparationFields, signal: AbortSignal, admission?: ClientSessionAdmission) => Promise<V4EnvironmentSessionSpec>, options?: OperationOptions,
    store?: PoolSpendStore, live?: LiveAuthorizationClient): Promise<V4AuthenticatedSessionRuntime> {
    this.#check(); const state = materials.get(material);
    if (state?.environment !== this || state.claimed || state.closure === undefined || !this.#materials.has(material)) fail("material_unavailable");
    if (options?.signal?.aborted) fail("canceled");
    if (this.#sessions.size + this.#admissions.size + this.#preparations.size + this.#connectionClaims.size - (state.connectionClaim !== undefined && this.#connectionClaims.has(state.connectionClaim) ? 1 : 0) >= this.#config.sessions) fail("resource_exhausted");
    const abort = new AbortController(), signal = options?.signal === undefined ? abort.signal : AbortSignal.any([abort.signal, options.signal]);
    this.#preparations.add(abort); if (state.connectionClaim !== undefined) this.#connectionClaims.delete(state.connectionClaim); state.claimed = true; if (state.timer !== undefined) clearTimeout(state.timer); state.timer = undefined;
    let fields: ClientPreparationFields | undefined, spec: V4EnvironmentSessionSpec | undefined, exchange: ClientAdmissionExchange | undefined;
    try {
      if (source === "live_authority") {
        const attempt = new Uint8Array(16);
        try { this.#random.fill(attempt); state.closure.beginLivePreparation(attempt, this.#reference!); }
        finally { attempt.fill(0); }
      }
      fields = state.closure.clientPreparation(this.#reference!); if (fields.source !== source) fail("credential_binding");
      spec = await prepare(fields, signal, state.admission); this.#check(); if (signal.aborted) fail("canceled");
      if (typeof spec.transport.checkPreparation !== "function") fail("owner_unavailable"); spec.transport.checkPreparation();
      state.closure.checkClientIdentity(spec.noise.localStaticPrivate, spec.signer.publicKey, this.#reference!);
      const ref = state.admission?.take([["client_admission", clientAdmissionCharge(this.#config.runtimeBytes)]])[0] ?? this.#reserve("client_admission", clientAdmissionCharge(this.#config.runtimeBytes));
      try { exchange = new ClientAdmissionExchange(this.resources, state.closure, fields, spec.signer, bytes => this.#random.fill(bytes), ref, spec.transport, spec.bindingMode); } finally { ref.release(); }
      return await this.#establish(material, spec, new Uint8Array(), { ...options, signal }, store, exchange, live);
    } catch (error) {
      if (spec !== undefined) void Promise.allSettled([spec.transport.close(), spec.transport.waitTermination()]); this.releaseMaterial(token, material); throw error;
    } finally { exchange?.close(); if (fields !== undefined) clearClientPreparation(fields); this.#preparations.delete(abort); this.#cleanup(); }
  }
  /** Server assembly reaches its durable CAS only after the complete Session
   * graph, FSA workspace and confirmation work have been reserved. */
  async establishServer(material: V4EnvironmentMaterial, prepare: (fields: ClientPreparationFields) => V4EnvironmentSessionSpec | Promise<V4EnvironmentSessionSpec>,
    exchange: ServerAdmissionExchange, authority: ServerAdmissionAuthority, owner: ServerAdmissionOwner, options?: OperationOptions): Promise<V4AuthenticatedSessionRuntime> {
    this.#check(); const state = materials.get(material);
    if (state?.environment !== this || state.claimed || state.closure === undefined || !isServerAdmissionAuthority(authority)) fail("material_unavailable");
    if (options?.signal?.aborted) fail("canceled");
    if (this.#sessions.size + this.#admissions.size + this.#preparations.size + this.#connectionClaims.size >= this.#config.sessions) fail("resource_exhausted");
    const abort = new AbortController(), signal = options?.signal === undefined ? abort.signal : AbortSignal.any([abort.signal, options.signal]);
    this.#preparations.add(abort); state.claimed = true;
    if (state.timer !== undefined) clearTimeout(state.timer); state.timer = undefined;
    let fields: ClientPreparationFields | undefined;
    try {
      fields = state.closure.clientPreparation(this.#reference!);
      await exchange.authenticate(state.closure, fields, { ...options, signal }); this.#check(); if (signal.aborted) fail("canceled");
      const spec = await prepare(fields); this.#check(); if (signal.aborted) fail("canceled");
      if (spec.noise.role !== "server" || spec.transport.role !== "server" || typeof spec.transport.checkPreparation !== "function") fail("owner_unavailable");
      spec.transport.checkPreparation(); state.closure.checkServerIdentity(spec.noise.localStaticPrivate, spec.signer.publicKey, this.#reference!);
      return await this.#establish(material, spec, new Uint8Array(), { ...options, signal }, undefined, undefined, undefined, { exchange, authority, owner, fields });
    } catch (error) { this.releaseMaterial(token, material); throw error; }
    finally { exchange.close(); if (fields !== undefined) clearClientPreparation(fields); this.#preparations.delete(abort); this.#cleanup(); }
  }
  async #establish(material: V4EnvironmentMaterial, spec: V4EnvironmentSessionSpec, context: Uint8Array, options?: OperationOptions, store?: PoolSpendStore,
    exchange?: ClientAdmissionExchange, live?: LiveAuthorizationClient,
    server?: { exchange: ServerAdmissionExchange; authority: ServerAdmissionAuthority; owner: ServerAdmissionOwner; fields: ClientPreparationFields }): Promise<V4AuthenticatedSessionRuntime> {
    this.#check(); const state = materials.get(material);
    if (state?.environment !== this || state.claimed && exchange === undefined && server === undefined || state.closure === undefined || !this.#materials.has(material)) fail("material_unavailable");
    if (options?.signal?.aborted) fail("canceled");
    if (this.#sessions.size + this.#admissions.size + this.#preparations.size - (exchange === undefined && server === undefined ? 0 : 1) + this.#connectionClaims.size - (state.connectionClaim !== undefined && this.#connectionClaims.has(state.connectionClaim) ? 1 : 0) >= this.#config.sessions) fail("resource_exhausted");
    const c = this.#config, stream = spec.streams, noise = spec.noise, profile = ownProfile(noise.profile);
    if (profile === undefined || !noise.authorizationDeadline.belongsTo(this.clock) || !noise.preparationDeadline.belongsTo(this.clock)) fail("credential_binding");
    state.closure.checkPreparation(this.#reference!);
    qualifySessionActivity(this.clock, selectedIdleDuration(spec.idleDurationMS ?? 0n, spec.localIdleDurationMS), stream.operationDeadlineMS, captureAutomaticLiveness(spec.automaticLiveness));
    const crypto = { ...spec.crypto, clock: this.clock, profile: noise.profile, sendDirection: noise.role === "client" ? 0 as const : 1 as const, runtimeBytes: c.runtimeBytes };
    const streamOwner = this.#owner("stream");
    const { costs, sendQueueBytes, streamSendQueueBytes, nativePositionIndex, nativeOpeningIndex, nativePositionCount, nativeOpeningCount,
      maintenanceConfig, maintenanceIndex, sendAccountCount, sendAccountIndex, bootstrapIndex, bootstrapCosts, managementIndex, managementCosts,
      notifyIndex, applicationProfile, rpcConfig, rpcPlan, rpcIndex } = sessionAdmissionPlan(spec, c.runtimeBytes, state.admission !== undefined);
    this.#check(); if (this.#sessions.size + this.#admissions.size + this.#preparations.size - (exchange === undefined && server === undefined ? 0 : 1) + this.#connectionClaims.size - (state.connectionClaim !== undefined && this.#connectionClaims.has(state.connectionClaim) ? 1 : 0) >= c.sessions) fail("resource_exhausted");
    const serverWorkIndex = costs.length; if (server !== undefined) costs.push(["server_admission_store", server.authority.charge()]);
    const refs = state.admission?.take(costs) ?? c.root.reserveBatch(costs.map(([kind, charge]) => this.#request(kind, charge)));
    const abort = new AbortController(), signal = options?.signal === undefined ? abort.signal : AbortSignal.any([abort.signal, options.signal]);
    this.#admissions.add(abort); if (state.connectionClaim !== undefined) this.#connectionClaims.delete(state.connectionClaim); state.claimed = true; if (state.timer !== undefined) clearTimeout(state.timer); state.timer = undefined;
    let ledger: CryptoUsageLedger | undefined, delivery: ReceiveDeliveryGate | undefined, runtime: V4AuthenticatedSessionRuntime | undefined;
    let ephemeral = new Uint8Array(), sendAccount: ResourceAccount | undefined, sendAccounts: ProtectedResourceAccounts | undefined, nativePositions: NativeProtocolPositions | undefined;
    let maintenancePositions: MaintenancePositions | undefined;
    let internalKeys: SessionKeyPreparation | undefined;
    let peerOpenPreparation: PeerOpenPreparationTypes.PeerOpenPreparation | undefined;
    let rpcAdmission: RPCApplicationAdmission | undefined;
    let calls: RpcCallCapacityTypes.RPCCallCapacity | undefined;
    let applicationServices: RPCApplicationServices | undefined;
    let initialStreams: RpcStreamPreparationTypes.RPCStreamPreparation | undefined;
    let initialRawStreams: RawStreamPreparation | undefined;
    const notifySendAccounts: ResourceAccount[] = []; let notifyNativePosition: NativeProtocolPosition | undefined;
    let managementSendAccount: ResourceAccount | undefined, managementNativePosition: NativeProtocolPosition | undefined;
    let bootstrapSendAccount: ResourceAccount | undefined, bootstrapNativePosition: NativeProtocolPosition | undefined;
    try {
      maintenancePositions = new MaintenancePositions(c.root, maintenanceConfig, refs[maintenanceIndex]!, refs.slice(maintenanceIndex + 1, maintenanceIndex + 3),
        [refs[1]!, refs[9]!, refs[10]!, ...refs.slice(maintenanceIndex + 3, maintenanceIndex + 6)]);
      const initialEpoch = maintenancePositions.epoch();
      refs[1] = initialEpoch[0]!; refs[9] = initialEpoch[1]!; refs[10] = initialEpoch[2]!;
      if (state.admission !== undefined) {
        const prepaid = state.admission.takeAccounts(sendAccountCount, sendQueueBytes, streamSendQueueBytes);
        sendAccount = prepaid.session; sendAccounts = prepaid.directions;
      } else {
        sendAccount = createSendAccount(c.root, streamOwner, sendQueueBytes);
        sendAccounts = createStreamSendAccounts(c.root, sendAccountCount, streamSendQueueBytes, c.runtimeBytes, refs[sendAccountIndex]!);
      }
      if (nativePositionCount > 0) nativePositions = state.admission?.takeNativePositions(nativePositionCount, nativeOpeningCount) ?? new NativeProtocolPositions(c.root, nativePositionCount, nativeOpeningCount, c.runtimeBytes,
        refs[nativePositionIndex]!, refs.slice(nativePositionIndex + 1, nativeOpeningIndex), refs.slice(nativeOpeningIndex, nativeOpeningIndex + nativeOpeningCount));
      if (bootstrapCosts.length !== 0) {
        bootstrapSendAccount = sendAccounts.checkout();
        const output = refs[bootstrapIndex + 9]!;
        refs[bootstrapIndex + 9] = output.transfer({ ...streamOwner, kind: "bootstrap_output" }, streamOwner.backing,
          [...this.#accounts, sendAccount, bootstrapSendAccount]);
        output.release();
        if (nativePositions !== undefined && noise.role === "client") bootstrapNativePosition = nativePositions.checkout();
      }
      if (managementCosts.length !== 0) {
        managementSendAccount = sendAccounts.checkout();
        const output = refs[managementIndex + 9]!;
        refs[managementIndex + 9] = output.transfer({ ...streamOwner, kind: "management_open_output" }, streamOwner.backing, [...this.#accounts, sendAccount, managementSendAccount]); output.release();
        if (nativePositions !== undefined && noise.role === "client") managementNativePosition = nativePositions.checkout(true);
      }
      if (bootstrapCosts.length !== 0) {
        for (let position = 0; position < 2; position++) {
          const account = sendAccounts.checkout(); notifySendAccounts.push(account);
          const index = notifyIndex + position * bootstrapCosts.length + 9, output = refs[index]!;
          refs[index] = output.transfer({ ...streamOwner, kind: `notify_open_output_${position}` }, streamOwner.backing, [...this.#accounts, sendAccount, account]); output.release();
        }
        if (nativePositions !== undefined) notifyNativePosition = nativePositions.checkout();
      }
      ledger = state.admission?.takeLedger(crypto) ?? new CryptoUsageLedger(crypto, refs[12]!);
      internalKeys = state.admission?.takeInternalKeys() ?? new SessionKeyPreparation(ledger, spec.info.application_profile, refs[0]!);
      peerOpenPreparation = state.admission?.takePeerOpens();
      delivery = new ReceiveDeliveryGate(noise.authorizationDeadline, c.runtimeBytes, refs[11]!);
      if (rpcConfig !== undefined && rpcPlan !== undefined && applicationProfile !== "transport") {
        const index = rpcIndex + rpcPlan.publication, publication = refs[index]!;
        refs[index] = publication.transfer({ ...streamOwner, kind: "rpc_publication" }, streamOwner.backing,
          [...this.#accounts, sendAccount, bootstrapSendAccount!]);
        publication.release();
        if (applicationProfile === "execution") {
          const index = rpcIndex + rpcPlan.management + 6, output = refs[index]!;
          refs[index] = output.transfer({ ...streamOwner, kind: "management_publication" }, streamOwner.backing, [...this.#accounts, sendAccount, managementSendAccount!]); output.release();
        }
        for (let position = 0; position < 2; position++) {
          const index = rpcIndex + rpcPlan.notify + position * notifyChannelCharges(c.runtimeBytes).length + 5, output = refs[index]!;
          refs[index] = output.transfer({ ...streamOwner, kind: `notify_publication_${position}` }, streamOwner.backing, [...this.#accounts, sendAccount, notifySendAccounts[position]!]); output.release();
        }
        calls = state.admission?.takeCalls(stream.rpcMaxGeneralOutstanding ?? 0);
        applicationServices = state.admission?.takeServices();
        initialStreams = state.admission?.takeStreams();
        rpcAdmission = new RPCApplicationAdmission(rpcConfig, applicationProfile, stream.rpcMaxGeneralOutstanding ?? 0,
          c.root, this.#accounts, [...this.#accounts, sendAccount, bootstrapSendAccount!], streamOwner, this.clock, noise.authorizationDeadline, delivery, c.runtimeBytes,
          refs.slice(rpcIndex, rpcIndex + rpcPlan.charges.length), this.contractQueries(rpcConfig.queryAcquisitions), bytes => this.#random.fill(bytes),
          this.serviceBindings(rpcConfig.queryAcquisitions === 2 ? 16 : 256), config => this.executionService(config),
          notifySendAccounts.map(account => Object.freeze([...this.#accounts, sendAccount!, account])), calls, applicationServices, initialStreams);
        // The application now owns retirement, including independent results.
        // Later connection failure must use that lifecycle rather than close
        // its transferred groups as unused preparation resources.
        applicationServices = undefined; calls = undefined; initialStreams = undefined;
      }
      if (spec.initialRawStreams !== undefined && spec.initialRawStreams.length > 0) {
        const charges = streamOpenCharges(spec.maxFrame, c.runtimeBytes, stream.receive, spec.maxFrame);
        initialRawStreams = new RawStreamPreparation(c.root, this.#accounts, streamOwner, c.runtimeBytes, spec.initialRawStreams, charges, sendAccounts!, ledger);
        if (peerOpenPreparation !== undefined) fail("configuration_capacity");
        peerOpenPreparation = new PeerOpenPreparation(c.root, this.#accounts, streamOwner, ledger,
          spec.initialRawStreams.reduce((count, declaration) => count + declaration.options.maxActive, 0), charges.slice(0, 2));
      }
      ephemeral = randomDH(profile.dh_algorithm === 0, bytes => this.#random.fill(bytes));
      let config: V4AuthenticatedSessionConfig = { ...spec, preparedRawStreams: initialRawStreams, runtimeBytes: c.runtimeBytes, ledger,
        noise: { ...noise, clock: this.clock, ephemeralPrivate: ephemeral },
        reservations: { session: refs[0]!, epoch: refs[1]!, ingress: refs[2]!, envelope: refs[3]!, output: refs[4]!,
          ...(spec.transport.nativeStreams === undefined ? {} : { nativeIngress: refs[13]!, nativeRecord: refs[14]!, nativeEnvelope: refs[15]!, nativeReceive: refs[16]!, nativeReceiveDecoder: refs[17]!, nativeCandidates: refs[18]!, nativeSendCrypto: refs[19]!, nativeSendEncode: refs[20]! }) },
        streams: { ...stream, maintenancePositions, internalKeys, ...(peerOpenPreparation === undefined ? {} : { peerOpenPreparation }), ...(nativePositions === undefined ? {} : { nativePositions }),
          ...(rpcAdmission === undefined ? {} : { rpcAdmission, notifyReservations: [refs.slice(notifyIndex, notifyIndex + bootstrapCosts.length), refs.slice(notifyIndex + bootstrapCosts.length, notifyIndex + 2 * bootstrapCosts.length)],
            notifySendAccounts, ...(notifyNativePosition === undefined ? {} : { notifyNativePosition }) }),
          ...(managementCosts.length === 0 ? {} : { managementReservations: refs.slice(managementIndex, managementIndex + managementCosts.length), managementSendAccount: managementSendAccount!,
            ...(managementNativePosition === undefined ? {} : { managementNativePosition }) }),
          ...(bootstrapCosts.length === 0 ? {} : { bootstrapReservations: refs.slice(bootstrapIndex, bootstrapIndex + bootstrapCosts.length), bootstrapSendAccount: bootstrapSendAccount!,
            ...(bootstrapNativePosition === undefined ? {} : { bootstrapNativePosition }) }),
          sendQueueBytes, streamSendQueueBytes, sendAccount, sendAccounts, root: c.root, accounts: this.#accounts, owner: streamOwner, random: bytes => this.#random.fill(bytes),
          delivery, authorization: { check: () => noise.authorizationDeadline.check() },
          open: refs[5]!, openDecoder: refs[6]!, control: refs[7]!, controlDecoder: refs[8]!, controlSendCipher: refs[9]!, controlReceiveCipher: refs[10]! } };
      if (store !== undefined) {
        if (noise.role !== "client") fail("credential_binding");
        if (exchange === undefined) state.closure.checkSessionInputs(config, context);
        const facts = state.closure.poolSpendFacts(refs[0]!), connect = new Uint8Array(16), carrier = new Uint8Array(16), originalTransport = spec.transport;
        try {
          this.#random.fill(connect); this.#random.fill(carrier);
          const guard = (): void => { this.#check(); if (signal.aborted || spec.transport !== originalTransport) fail("closed"); state.closure!.checkPreparation(refs[0]!); if (exchange !== undefined) originalTransport.checkPreparation!(); };
          await store.consume(facts, { connect, carrier, generation: 1n, signal }, noise.preparationDeadline, refs[0]!, guard); guard();
        } finally { facts.close(); connect.fill(0); carrier.fill(0); }
      }
      if (live !== undefined) {
        if (store !== undefined || exchange === undefined || noise.role !== "client") fail("credential_binding");
        const originalTransport = spec.transport;
        const guard = (): void => {
          this.#check(); if (signal.aborted || spec.transport !== originalTransport) fail("closed");
          state.closure!.checkPreparation(refs[0]!); originalTransport.checkPreparation!();
        };
        await live.authorize(state.closure, exchange, refs[0]!, guard, signal); guard();
      }
      if (exchange !== undefined) {
        if (store === undefined && live === undefined) fail("owner_unavailable");
        const admission = await exchange.run(spec.transport, { ...options, signal }); context = admission.context;
        config = { ...config, noise: { ...config.noise, contextDigest: admission.contextDigest, fsb: admission.fsb, fsa: admission.fsa },
          ready: admission.ready, info: { ...config.info, selected_features: admission.selected } };
      }
      if (server !== undefined) {
        if (store !== undefined || live !== undefined || exchange !== undefined || noise.role !== "server") fail("owner_unavailable");
        const admitted = await server.exchange.run(state.closure, server.fields, server.authority, { ...server.owner, signal }, refs[serverWorkIndex]!, { ...options, signal });
        context = admitted.context;
        config = { ...config, noise: { ...config.noise, contextDigest: admitted.contextDigest, fsb: admitted.fsb, fsa: admitted.fsa },
          ready: admitted.ready, info: { ...config.info, selected_features: admitted.selected } };
      }
      runtime = await establishV4CredentialSession(config, state.closure, context, { ...options, signal });
      if (this.#closed || signal.aborted) { delivery.close(); await runtime.close(); fail("closed"); }
      const entry: SessionEntry = { runtime, cleanup: runtime.cleanupOwner, delivery, material, monitor: Promise.resolve() };
      this.#sessions.add(entry);
      this.#observeSession(entry);
      return runtime;
    } catch (error) {
      for (const account of notifySendAccounts) account.close(); for (const ref of notifyNativePosition?.references ?? []) ref.release();
      rpcAdmission?.close(); calls?.close(); managementSendAccount?.close(); for (const ref of managementNativePosition?.references ?? []) ref.release(); delivery?.close();
      if (applicationServices !== undefined) closeRPCApplicationServices(applicationServices);
      initialStreams?.close(); initialRawStreams?.close(); peerOpenPreparation?.close(); internalKeys?.close();
      if (runtime === undefined) void Promise.allSettled([spec.transport.close(), spec.transport.waitTermination()]);
      else await runtime.close().catch(() => undefined);
      for (const reference of bootstrapNativePosition?.references ?? []) reference.release(); bootstrapSendAccount?.close();
      maintenancePositions?.close(); nativePositions?.close(); sendAccounts?.close(); sendAccount?.close(); ledger?.close(); this.releaseMaterial(token, material); throw error;
    } finally {
      initialRawStreams?.close(); ephemeral.fill(0); for (const ref of refs) ref.release();
      // A failure before Session ownership returns the initial epoch references
      // here, after closing the pool. Collect its now-empty metadata as well.
      maintenancePositions?.cleanupComplete(); this.#admissions.delete(abort); this.#cleanup();
    }
  }
  installClientConnector(connector: EnvironmentClientConnector): void {
    this.#check();
    const profile = connector.applicationProfile;
    if (this.#connector !== undefined || !["transport", "services", "execution"].includes(profile)) fail("configuration_capacity");
    this.#connector = Object.freeze({ applicationProfile: profile, connect: connector.connect.bind(connector),
      checkRequirements: connector.checkRequirements.bind(connector),
      ...(connector.reserveAdmission === undefined ? {} : { reserveAdmission: connector.reserveAdmission.bind(connector) }) });
  }
  assertConnectAvailable(): void { this.#check(); if (this.#connector === undefined) fail("runtime_unavailable"); }
  async connect(source: V4ConnectionMaterialSource, request: V4ConnectionRequirements, options?: OperationOptions, prepareDependencies?: (admission: ClientSessionAdmission | undefined) => void): Promise<V4SessionOwner> {
    return this.prepareConnect(source, request, options, prepareDependencies).start();
  }
  /** Reserve the actual connection before starting source or network work.
   * Multiple factory groups may prepare first, then transfer each reservation. */
  prepareConnect(source: V4ConnectionMaterialSource, request: V4ConnectionRequirements, options?: OperationOptions,
    prepareDependencies?: (admission: ClientSessionAdmission | undefined) => void): PreparedEnvironmentConnection {
    this.assertConnectAvailable(); const original = publicSources.get(source); if (original === undefined || sources.get(original)?.environment !== this) fail("source_unavailable");
    const requirements = captureConnectionRequirements(request), applicationProfile = this.#connector!.applicationProfile;
    if (requirements.application_profile !== undefined && requirements.application_profile !== applicationProfile) fail("connection_requirement_unavailable");
    // The local assembly plan supplies the source's precise profile before
    // acquisition; omission never silently chooses a lower application tier.
    const captured = Object.freeze({ ...requirements, application_profile: applicationProfile }); this.#connector!.checkRequirements(captured);
    this.#check();
    if (this.#sessions.size + this.#admissions.size + this.#preparations.size + this.#connectionClaims.size >= this.#config.sessions) fail("resource_exhausted");
    const claim = new AbortController(); this.#connectionClaims.add(claim);
    const signal = options?.signal === undefined ? claim.signal : AbortSignal.any([claim.signal, options.signal]);
    let admission: ClientSessionAdmission | undefined, started = false, closed = false;
    const cleanup = (): void => {
      signal.removeEventListener("abort", cancelled);
      admission?.close(); admission = undefined; this.#connectionClaims.delete(claim); this.#cleanup();
    };
    const close = (): void => { if (closed) return; closed = true; claim.abort(); if (!started) cleanup(); };
    const cancelled = (): void => { if (!started) close(); };
    try {
      admission = this.#connector!.reserveAdmission?.();
      prepareDependencies?.(admission); this.#check(); if (signal.aborted) fail("canceled");
      signal.addEventListener("abort", cancelled, { once: true });
      return Object.freeze({ close, start: async (): Promise<V4SessionOwner> => {
        if (started || closed) fail("closed"); started = true;
        let material: V4EnvironmentMaterial | undefined;
        try {
          this.#check(); if (signal.aborted) fail("canceled");
          material = await this.acquire(original, captured, { signal }); this.#check();
          if (signal.aborted) fail("canceled");
          materials.get(material)!.connectionClaim = claim;
          if (admission !== undefined) materials.get(material)!.admission = admission;
          return await this.connectMaterial(material, { signal });
        } catch (error) { await material?.closeMaterial(); throw error; }
        finally { if (material !== undefined) delete materials.get(material)!.admission; closed = true; cleanup(); }
      } });
    } catch (error) { close(); throw error; }
  }
  async connectMaterial(material: V4MaterialOwner, options?: OperationOptions): Promise<V4SessionOwner> {
    this.assertConnectAvailable(); if (!(material instanceof V4EnvironmentMaterial)) fail("material_unavailable");
    const state = materials.get(material)!;
    if (state.environment !== this || state.claimed || !this.#materials.has(material)) fail("material_unavailable");
    let admission: ClientSessionAdmission | undefined;
    try {
      admission = state.admission === undefined ? this.#connector!.reserveAdmission?.() : undefined;
      if (admission !== undefined) state.admission = admission;
      return await this.#connector!.connect(material, options);
    } catch (error) {
      // The public handle transferred this material before entering admission.
      // A local capacity failure must retire its verified closure immediately;
      // the caller can no longer close or consume that original handle.
      await material.closeMaterial();
      throw error;
    }
    finally { if (admission !== undefined) { admission.close(); delete state.admission; } }
  }

  close(): Promise<V4LifecycleResult> {
    if (this.#closed) return this.#close;
    this.#closeInitializing = true; this.#closed = true;
    try { this.#cleanupWindow = new TrustedWindow(this.clock, BigInt(this.#config.cleanupMS!)); }
    catch { this.#cleanupIncomplete = true; }
    const tick = (): void => {
      this.#cleanupTimer = undefined;
      if (this.#reference === undefined) return;
      try { this.#cleanupWindow!.check(); this.#cleanupTimer = setTimeout(tick, timerChunk(this.#cleanupWindow!.remainingMS())); }
      catch { this.#cleanupIncomplete = true; this.#notifyCleanup(); }
    };
    if (this.#cleanupWindow !== undefined) tick();
    this.#contractQueries?.close();
    this.#serviceBindings?.close();
    for (const history of this.#executionServices.values()) history.close();
    for (const job of this.#acquisitions) job.abort.abort();
    for (const abort of this.#admissions) abort.abort();
    for (const abort of this.#preparations) abort.abort();
    for (const claim of this.#connectionClaims) claim.abort();
    for (const source of [...this.#sources]) source.close();
    for (const admission of [...this.#dependencyClaims]) admission.close();
    for (const dependency of [...this.#dependencies]) try { dependency.close(); } catch { this.#cleanupFault = this.#cleanupIncomplete = true; }
    for (const material of [...this.#materials]) if (!materials.get(material)!.claimed) this.releaseMaterial(token, material);
    for (const entry of this.#sessions) { entry.delivery.close(); void entry.runtime?.close().catch(() => undefined); }
    for (const entry of this.#results) entry.delivery.close();
    for (const entry of this.#namespaces.values()) entry.namespace.close();
    // Keep clock/random/accounts alive until every original callback and
    // Session reference has returned; shared root/tenant are borrowed.
    this.#closeInitializing = false; this.#cleanup(); return this.#close;
  }
  #cleanup(): void {
    if (this.#cleaning || this.#closeInitializing) return;
    this.#cleaning = true;
    try { this.#collect(); } finally { this.#cleaning = false; }
    this.#notifyCleanup();
  }
  #observeSession(entry: SessionEntry): void {
    entry.delivery.onCleanup(() => this.#cleanup());
    entry.cleanup.onCleanup(() => this.#cleanup());
    entry.monitor = entry.runtime!.waitTermination().catch(() => undefined).then(async () => {
      await (entry.runtime?.close() ?? entry.cleanup.closed).catch(() => undefined);
      entry.delivery.retire(); this.#cleanup();
    });
    entry.cleanup.onCoreCleanup(() => {
      // Preserve callback accounting and result authorization without making
      // the Environment's root observer retain the old Session/key graph.
      entry.runtime = undefined; entry.delivery.retire(); this.#cleanup();
    });
  }
  #notifyCleanup(): void {
    if (this.#closeInitializing) return;
    const status = this.#cleanupProjection();
    if (this.#closed && status.status !== "pending") { const resolve = this.#closeResolve; this.#closeResolve = undefined; resolve?.(this.#lifecycleProjection(status)); }
    for (const wake of this.#cleanupObservers) wake();
    if (status.status === "complete") { const cleaned = this.#cleaned; this.#cleaned = undefined; cleaned?.(); }
  }
  onCleanup(callback: () => void): void {
    if (this.#cleaned !== undefined) fail("configuration_capacity");
    if (this.#reference === undefined) callback(); else this.#cleaned = callback;
  }
  #collect(): void {
    for (const entry of this.#sessions) if ((entry.runtime?.cleanupStatus() ?? entry.cleanup.cleanupStatus()).status === "complete") {
      this.#sessions.delete(entry);
      if (entry.delivery.cleanupStatus().status === "complete") this.releaseMaterial(token, entry.material);
      else this.#results.add({ delivery: entry.delivery, material: entry.material });
    }
    for (const entry of this.#results) if (entry.delivery.cleanupStatus().status === "complete") {
      this.#results.delete(entry); this.releaseMaterial(token, entry.material);
    }
    if (!this.#closed || this.#reference === undefined) return;
    if (this.#contractQueries?.cleanupComplete()) this.#contractQueries = undefined;
    if (this.#serviceBindings?.cleanupComplete()) { this.#serviceBindings = undefined; this.#serviceAccount?.close(); this.#serviceAccount = undefined; }
    for (const [key, history] of this.#executionServices) if (history.cleanupComplete()) this.#executionServices.delete(key);
    const pending = this.#dependencyClaims.size + this.#connectionClaims.size + this.#executionServices.size + (this.#contractQueries === undefined ? 0 : 1) + (this.#serviceBindings === undefined ? 0 : 1) + this.#dependencies.size + this.#working + this.#acquisitions.size + this.#admissions.size + this.#preparations.size + this.#sessions.size + this.#results.size + this.#materials.size + this.#sources.size;
    if (pending === 0 && [...this.#namespaces.values()].every(entry => entry.namespace.cleanupComplete())) {
      this.clock.close(); this.#random.close();
      if (this.clock.cleanupComplete() && this.#random.cleanupComplete()) {
        for (const entry of this.#namespaces.values()) { entry.options.rootKeyID.fill(0); entry.options.rootPublicKey.fill(0); }
        this.#namespaces.clear(); this.#connector = undefined;
        this.#resourceObserver?.(); this.#resourceObserver = undefined;
        this.#reference.release(); this.#reference = undefined; this.#environment.close();
        if (this.#cleanupTimer !== undefined) clearTimeout(this.#cleanupTimer); this.#cleanupTimer = undefined; this.#cleanupWindow = undefined; return;
      }
    }
  }
  #lifecycleProjection(status: V4CleanupStatus): V4LifecycleResult {
    return lifecycleResult("environment", this.#closed ? "closed" : "active", status,
      this.#cleanupFault ? "core_cleanup_failed" : status.status === "cleanup_incomplete" ? "deadline_exceeded" : "none");
  }
  lifecycleResult(): V4LifecycleResult { return this.#lifecycleProjection(this.cleanupStatus()); }
  #cleanupProjection(): V4CleanupStatus {
    if (this.#reference === undefined) return complete;
    return cleanupResult({ status: this.#cleanupIncomplete ? "cleanup_incomplete" : "pending", core_cleanup: "pending",
      pending_callbacks: BigInt(this.#connectionClaims.size + (this.#contractQueries?.pending ?? 0) + this.#acquisitions.size + this.#admissions.size + this.#preparations.size + this.#sessions.size + this.#dependencies.size + this.#working) });
  }
  cleanupStatus(): V4CleanupStatus {
    this.#cleanup();
    if (this.#cleanupWindow !== undefined) try { this.#cleanupWindow.check(); } catch {
      if (!this.#cleanupIncomplete) { this.#cleanupIncomplete = true; this.#notifyCleanup(); }
    }
    return this.#cleanupProjection();
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    if (options?.signal?.aborted) return Promise.reject(new Error("canceled"));
    const initial = this.cleanupStatus(); if (initial.status !== "pending") return Promise.resolve(initial);
    if (this.#waiters >= 32) return Promise.reject(new Error("resource_exhausted"));
    const retained = this.#reference!.borrow(); this.#waiters++;
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined, window: TrustedWindow | undefined, finished = false;
      const finish = (canceled = false, expired = false): void => {
        if (finished) return; finished = true;
        this.#cleanupObservers.delete(wake); if (timer !== undefined) clearTimeout(timer);
        options?.signal?.removeEventListener("abort", abort); this.#waiters--; retained.release();
        if (canceled) reject(new Error("canceled"));
        else {
          const status = this.#cleanupProjection();
          resolve(expired && status.status === "pending" ? cleanupResult({ ...status, status: "cleanup_incomplete" }) : status);
        }
      };
      const abort = (): void => finish(true), wake = (): void => { if (this.#cleanupProjection().status !== "pending") finish(); };
      const tick = (): void => {
        try { window!.check(); timer = setTimeout(tick, timerChunk(window!.remainingMS())); }
        catch { finish(false, true); }
      };
      this.#cleanupObservers.add(wake); options?.signal?.addEventListener("abort", abort, { once: true });
      try { window = new TrustedWindow(this.clock, BigInt(this.#config.cleanupMS!)); if (options?.signal?.aborted) abort(); else { wake(); if (!finished) tick(); } }
      catch { finish(false, true); }
    });
  }
  toJSON(): object { return {}; }
}
/** Creates shared-resource lifecycle ownership. Connect requires installation
 * of a production provider/once adapter before calling a credential source. */
export function createV4TransportEnvironment(config: V4EnvironmentConfig): V4TransportEnvironment {
  return wrapTransportEnvironment(new V4EnvironmentRuntime(config));
}
/** One public facade per original Environment lifecycle. */
export function wrapTransportEnvironment(owner: V4EnvironmentRuntime): V4TransportEnvironment {
  const existing = environmentFacades.get(owner); if (existing !== undefined) return existing;
  const environment = new V4TransportEnvironment(owner);
  publicEnvironments.set(environment, owner); environmentFacades.set(owner, environment); return environment;
}
for (const constructor of [EnvironmentDependency, V4EnvironmentRuntime, V4EnvironmentCredentialSource, V4EnvironmentMaterial]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
