import { createOriginalPoolSource, type V4PoolSourceConfiguration, type V4PreauthorizedPoolSource } from "../v4/poolSource.js";
import { isIP } from "node:net";
import { announceOriginalLiveCarrierPreparation } from "../v4/runtime/liveCarrierPreparation.js";
import { endpointListenerCost, endpointListenerCandidateIndex, nativeListenerSelectionCost, prepareEndpointWSSListener, prepareEndpointNativeListeners, type NodeWSSTunnelClientListenerOptions, type NodeNativeTunnelClientListenerOptions } from "./endpointListener.js";
import { applicationResumeFeature } from "../v4/runtime/checkpointToken.js";
import type { SessionResourceSpec, ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import { captureClientServices, type V4ClientServicesConfig } from "../v4/clientServices.js";
import { captureHandlerPlan, type HandlerPlan } from "../v4/handlerPlan.js";
import type { V4MaintenanceOwner } from "../v4/responsePublication.js";
import { KeyObject, createPublicKey, sign } from "node:crypto";
import { V4ConnectionMaterial, type V4ConnectionMaterialSource, type V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, wrapCredentialSource, type V4CredentialPolicy, type V4CredentialProvider, type V4NamespaceOptions, type EnvironmentClientConnector } from "../v4/runtime/environment.js";
import { reliableClientSpec, reliableClientAdmissionSpec, captureReliableClientLimits, type ReliableClientLimits } from "../v4/runtime/clientSessionSpec.js";
import type { CredentialNamespace } from "../v4/runtime/credentialNamespace.js";
import type { CredentialInput } from "../v4/runtime/credentialVerifier.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { requireCredential } from "../v4/runtime/credentialSupport.js";
import { captureNodeRawQUICCandidates, prepareNodeRawQUICCandidates, nodeRawQUICCandidateAdmissionCosts, nodeNativePreparationBudgetCost, prepayNodeNativePreparationBudget, releaseNodeNativePreparationBudget, nativeRawQUICQueueBytes, captureNodeRawQUIC, nodeRawQUICAdmissionCosts, type NodeRawQUICOptions, NodeRawQUICCarrier } from "./rawQUICCurrent.js";
import { loadCurrentNativeTransport, loadCurrentNativeWebTransport, type NativeTransportBinding } from "./nativeTransportCurrent.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import { prepareNodeWSS, nodeWSSAdmissionCosts, NodeWSSCarrier, type V4NodeWSSOptions } from "./wssV4.js";
import { V4SQLitePoolStore } from "./sqlitePoolV4.js";
import type { V4ConnectionRequirements } from "../generated/transportV4APIResults.js";
import { LiveAuthorizationClient, type V4LiveAuthorizationConfig } from "../v4/runtime/liveAuthorization.js";
import { capturePoolServerAllowConfiguration, clearPoolServerAllowConfiguration, poolServerAllowConfigurationCharge, type PoolServerAllowConfiguration } from "../v4/runtime/poolServerAllow.js";

export interface V4NodeWSSClientConfig {
  readonly identityKey: KeyObject;
  readonly noiseKey: KeyObject;
  readonly poolStore?: V4SQLitePoolStore;
  readonly poolServerAllow?: PoolServerAllowConfiguration;
  readonly liveAuthority?: V4LiveAuthorizationConfig;
  readonly carrier: V4NodeWSSOptions;
  /** Trusted physical listener for the signed A leg, prepared before spend. */
  readonly tunnelListener?: NodeWSSTunnelClientListenerOptions;
  readonly limits: V4NodeWSSClientLimits;
  readonly services?: V4ClientServicesConfig;
  /** Original immutable inbound/outbound application plan for this Environment.
   * Configure either services or a HandlerPlan, never two conflicting plans. */
  readonly handlerPlan?: HandlerPlan;
  readonly maintenanceOwner?: V4MaintenanceOwner;
  /** Fixed before preparation; exporter failures never select another mode. */
  readonly bindingMode?: "direct_exporter" | "authenticated_context";
}
export type V4NodeWSSClientLimits = ReliableClientLimits;
export interface V4NodeWSSClient {
  namespace(options: V4NamespaceOptions): CredentialNamespace;
  registerPoolSource(policy: V4CredentialPolicy, provider: V4CredentialProvider): V4ConnectionMaterialSource;
  registerDurablePoolSource(policy: V4CredentialPolicy, configuration: V4PoolSourceConfiguration): Promise<V4PreauthorizedPoolSource>;
  verifyPoolMaterial(policy: V4CredentialPolicy, input: Omit<CredentialInput, "source">): V4ConnectionMaterial;
  registerLiveSource(policy: V4CredentialPolicy, provider: V4CredentialProvider): V4ConnectionMaterialSource;
  verifyLiveMaterial(policy: V4CredentialPolicy, input: Omit<CredentialInput, "source" | "activation">): V4ConnectionMaterial;
}
function requirements(value: V4ConnectionRequirements): void {
  if (value.datagram || value.independent_reliable_read_progress || value.bound_stream_input_isolation) throw new Error("required_guarantee_unavailable");
}
/** Installs one direct WSS provider in the original Environment. */
export function configureV4NodeWSS(environment: V4TransportEnvironment, config: V4NodeWSSClientConfig): V4NodeWSSClient {
  originalEnvironment(environment);
  const captured = captureNodeClientConfiguration(config);
  const listener = config.tunnelListener === undefined ? undefined : Object.freeze({ host: config.tunnelListener.host, port: config.tunnelListener.port, serverName: config.tunnelListener.serverName, ...(config.tunnelListener.onPrepared === undefined ? {} : { onPrepared: config.tunnelListener.onPrepared }), tls: Object.freeze({ certificate: config.tunnelListener.tls.certificate, privateKey: config.tunnelListener.tls.privateKey }) });
  const c = config.carrier, ca = c.ca === undefined ? undefined : c.ca.map(value => typeof value === "string" ? value : new Uint8Array(value));
  requireCredential(ca === undefined || ca.length <= 64 && ca.reduce((n, value) => n + (typeof value === "string" ? Buffer.byteLength(value) : value.length), 0) <= 1048576, "configuration_capacity");
  const carrier = Object.freeze({ remoteAddress: c.remoteAddress, ...(c.origin === undefined ? {} : { origin: c.origin }), ...(ca === undefined ? {} : { ca: Object.freeze(ca) }),
    queueMessages: c.queueMessages, runtimeBytes: c.runtimeBytes, nativeBytes: c.nativeBytes, prepareBytes: c.prepareBytes });
  return configureNodeClient(environment, captured, { mode: "message" }, runtimeBytes => [...nodeWSSAdmissionCosts(captured.limits.maxFrame, carrier, runtimeBytes), ...(listener === undefined ? [] : [endpointListenerCost(runtimeBytes, carrier.nativeBytes)])],
    (owner, fields, signal, admission) => listener === undefined ? prepareNodeWSS(owner, fields, carrier, signal, admission) : prepareEndpointWSSListener(owner, fields, listener, carrier, signal, admission, () => announceOriginalLiveCarrierPreparation(owner, captured.liveAuthority, fields, signal)), undefined,
    () => { for (const value of ca ?? []) if (value instanceof Uint8Array) value.fill(0); });
}
export interface NodeRawQUICClientConfig extends Omit<V4NodeWSSClientConfig, "carrier" | "tunnelListener"> {
  readonly carrier: NodeRawQUICOptions;
  readonly carrierAlternatives?: readonly NodeRawQUICOptions[];
  readonly candidateAttemptLimit?: number;
  readonly tunnelListener?: NodeNativeTunnelClientListenerOptions;
  /** One additional physical listener, with its own native carrier policy. */
  readonly tunnelListenerAlternatives?: readonly Readonly<{ listener: NodeNativeTunnelClientListenerOptions; carrier: NodeRawQUICOptions }>[];
}
export type NodeRawQUICClient = V4NodeWSSClient;
function captureNativeClientListener(input: NodeNativeTunnelClientListenerOptions): NodeNativeTunnelClientListenerOptions {
  const host = input.host, port = input.port, serverName = input.serverName, onPrepared = input.onPrepared, tls = input.tls;
  const chain = tls.certificateChainDER, key = tls.privateKeyDER;
  requireCredential(isIP(host) !== 0 && Number.isSafeInteger(port) && port > 0 && port <= 65535 && typeof serverName === "string" && serverName.length > 0 && serverName.length <= 253 && !serverName.includes("\0") &&
    (onPrepared === undefined || typeof onPrepared === "function") && Array.isArray(chain) && chain.length > 0 && chain.length <= 16 && chain.every(bytes => bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 65536) &&
    key instanceof Uint8Array && key.length > 0 && key.length <= 65536, "configuration_capacity");
  return Object.freeze({ host, port, serverName, ...(onPrepared === undefined ? {} : { onPrepared }), tls: Object.freeze({ certificateChainDER: Object.freeze(chain.map(bytes => new Uint8Array(bytes))), privateKeyDER: new Uint8Array(key) }) });
}
/** Selects the actual current native ABI before any material can be consumed. */
export function configureNodeRawQUIC(environment: V4TransportEnvironment, config: NodeRawQUICClientConfig): NodeRawQUICClient {
  originalEnvironment(environment);
  const captured = captureNodeClientConfiguration(config), listenerInput = config.tunnelListener, listenerAlternatives = config.tunnelListenerAlternatives, carrierAlternatives = config.carrierAlternatives;
  requireCredential(listenerAlternatives === undefined || Array.isArray(listenerAlternatives) && listenerAlternatives.length <= 1 && listenerInput !== undefined, "configuration_capacity");
  requireCredential(listenerInput === undefined || carrierAlternatives === undefined || carrierAlternatives.length === 0, "configuration_capacity");
  const listeners = listenerInput === undefined ? undefined : Object.freeze([captureNativeClientListener(listenerInput), ...(listenerAlternatives ?? []).map(value => captureNativeClientListener(value.listener))]);
  const candidates = listeners === undefined ? captureNodeRawQUICCandidates([config.carrier, ...(carrierAlternatives ?? [])]) : Object.freeze([captureNodeRawQUIC(config.carrier), ...(listenerAlternatives ?? []).map(value => captureNodeRawQUIC(value.carrier))]);
  const carrier = candidates[0]!, bindings = listeners?.map((listener, index) => Object.freeze({ listener, carrier: candidates[index]! }));
  const attemptLimit = config.candidateAttemptLimit ?? (listeners === undefined ? 16 : listeners.length), maximum = Math.min(captured.limits.maxStreams, 1024), maxFrame = captured.limits.maxFrame;
  requireCredential(Number.isSafeInteger(attemptLimit) && attemptLimit >= 1 && attemptLimit <= 16 && Number.isSafeInteger(maximum) && maximum > 0 &&
    candidates.every(value => value.applicationStreams === carrier.applicationStreams && value.applicationStreams >= maximum + Math.min(128, Math.max(4, maximum)) + 1), "configuration_capacity");
  requireCredential(listeners === undefined || listeners.length === 1 || listeners[0]!.host !== listeners[1]!.host || listeners[0]!.port !== listeners[1]!.port, "configuration_capacity");
  let drivers: Partial<Record<"raw-quic" | "webtransport", NativeTransportBinding>> | undefined;
  const carrierCosts = (runtimeBytes: bigint) => bindings === undefined ? nodeRawQUICCandidateAdmissionCosts(maxFrame, candidates, runtimeBytes, attemptLimit) :
    [nativeListenerSelectionCost(runtimeBytes), ...bindings.flatMap(({ carrier: options }) => [...nodeRawQUICAdmissionCosts(maxFrame, options, runtimeBytes), endpointListenerCost(runtimeBytes, options.providerRuntimeBytes + nativeRawQUICQueueBytes(options))])];
  return configureNodeClient(environment, captured, { mode: "stream", nativeStreams: { capacity: carrier.applicationStreams }, nativeDatagrams: {} },
    runtimeBytes => [nodeNativePreparationBudgetCost(runtimeBytes), ...carrierCosts(runtimeBytes)],
    (owner, fields, signal, admission) => bindings === undefined ? prepareNodeRawQUICCandidates(owner, fields, candidates, drivers!, signal, admission, 0, 0, attemptLimit) :
      prepareEndpointNativeListeners(owner, fields, bindings, drivers!, signal, admission, (selected, attemptSignal) => {
        const candidate = fields.candidates.find(value => value.candidateIndex === selected.candidateIndex);
        requireCredential(candidate !== undefined, "credential_binding");
        return announceOriginalLiveCarrierPreparation(owner, captured.liveAuthority, Object.freeze({ ...fields, ...candidate }), attemptSignal);
      }, attemptLimit),
    () => {
      drivers = Object.fromEntries(candidates.map(value => [value.nativeCarrier ?? "raw-quic", (value.nativeCarrier ?? "raw-quic") === "webtransport" ? loadCurrentNativeWebTransport() : loadCurrentNativeTransport()]));
      requireCredential(candidates.every(value => typeof drivers![value.nativeCarrier ?? "raw-quic"]?.createPreparationBudget === "function"), "configuration_capacity");
    },
    () => { drivers = undefined; for (const value of candidates) for (const root of value.trustRootsDER ?? []) root.fill(0); for (const listener of listeners ?? []) { for (const bytes of listener.tls.certificateChainDER) bytes.fill(0); listener.tls.privateKeyDER.fill(0); } },
    () => undefined, (owner, admission) => prepayNodeNativePreparationBudget(owner, admission, drivers![carrier.nativeCarrier ?? "raw-quic"]!), releaseNodeNativePreparationBudget);
}

/** Caller configuration is captured once, before any admission transaction.
 * Carrier cost callbacks close over this plain immutable snapshot. */
function captureNodeClientConfiguration(config: Omit<V4NodeWSSClientConfig, "carrier" | "tunnelListener">): Omit<V4NodeWSSClientConfig, "carrier" | "tunnelListener"> {
  const identityKey = config.identityKey, noiseKey = config.noiseKey, poolStore = config.poolStore;
  const liveAuthority = config.liveAuthority, poolServerAllow = config.poolServerAllow, services = config.services, bindingMode = config.bindingMode, handlerPlan = config.handlerPlan, maintenanceOwner = config.maintenanceOwner;
  const limits = captureReliableClientLimits(config.limits);
  return Object.freeze({ identityKey, noiseKey, limits,
    ...(poolStore === undefined ? {} : { poolStore }), ...(liveAuthority === undefined ? {} : { liveAuthority }),
    ...(poolServerAllow === undefined ? {} : { poolServerAllow }),
    ...(services === undefined ? {} : { services }), ...(handlerPlan === undefined ? {} : { handlerPlan }),
    ...(maintenanceOwner === undefined ? {} : { maintenanceOwner }), ...(bindingMode === undefined ? {} : { bindingMode }) });
}

/** Current Node carriers share the original identity, source and activation
 * owners. Provider setup runs under its admitted dependency, before consume. */
function configureNodeClient(environment: V4TransportEnvironment, config: Omit<V4NodeWSSClientConfig, "carrier" | "tunnelListener">,
  shape: SessionResourceSpec["transport"], costs: (runtimeBytes: bigint) => readonly (readonly [string, ResourceVector])[],
  prepareTransport: (owner: ReturnType<typeof originalEnvironment>, fields: Parameters<typeof reliableClientSpec>[0], signal: AbortSignal, admission?: ClientSessionAdmission) => Promise<V4AuthenticatedTransport>,
  initialize?: () => void, dispose?: () => void, checkRequirements: (requirements: V4ConnectionRequirements) => void = requirements,
  prepareAdmission?: (owner: ReturnType<typeof originalEnvironment>, admission: ClientSessionAdmission) => void, releaseAdmission?: (admission: ClientSessionAdmission) => void): V4NodeWSSClient {
  const owner = originalEnvironment(environment), limits = captureReliableClientLimits(config.limits), runtimeBytes = owner.resources.runtimeBytes;
  requireCredential(config.handlerPlan === undefined || config.services === undefined, "configuration_capacity");
  const services = captureClientServices(config.services);
  let application = services?.application, applicationProfile: "transport" | "services" | "execution" = services?.profile ?? "transport";
  let handlerCapture: ReturnType<typeof captureHandlerPlan> | undefined;
  const bindingMode = config.bindingMode ?? "authenticated_context";
  requireCredential(bindingMode === "direct_exporter" || bindingMode === "authenticated_context", "configuration_capacity");
  requireCredential(config.identityKey instanceof KeyObject && config.identityKey.type === "private" && config.identityKey.asymmetricKeyType === "ed25519" &&
    config.noiseKey instanceof KeyObject && config.noiseKey.type === "private" && ["x25519", "ec"].includes(config.noiseKey.asymmetricKeyType ?? "") &&
    (config.poolStore instanceof V4SQLitePoolStore && config.liveAuthority === undefined || config.poolStore === undefined && config.liveAuthority !== undefined), "configuration_capacity");
  for (const value of [limits.maxFrame, limits.maxStreams, limits.receiveQueueBytes, limits.maxDataBytes, limits.maxCursorBytes, limits.maxWriteBytes, limits.cryptoKeys])
    requireCredential(Number.isSafeInteger(value) && value > 0 && value <= 16777216, "configuration_capacity");
  for (const value of [limits.writeDeadlineMS, limits.operationDeadlineMS, limits.rekeyPrepareMS, limits.rekeyProtocolMS, limits.rekeyConfirmationMS])
    requireCredential(typeof value === "bigint" && value > 0n && value <= 0xffffffffffffffffn, "configuration_capacity");
  requireCredential(limits.receiveQueueBytes >= limits.maxDataBytes && limits.cryptoKeys <= 65536, "configuration_capacity");
  let identity: KeyObject | undefined = config.identityKey, noise: KeyObject | undefined = config.noiseKey;
  const identityJWK = createPublicKey(identity).export({ format: "jwk" }), noiseJWK = noise.export({ format: "jwk" });
  requireCredential(identityJWK.crv === "Ed25519" && typeof identityJWK.x === "string" && typeof noiseJWK.d === "string" && ["X25519", "P-256"].includes(noiseJWK.crv ?? ""), "configuration_capacity");
  const publicKey = new Uint8Array(Buffer.from(identityJWK.x, "base64url")), privateKey = new Uint8Array(Buffer.from(noiseJWK.d, "base64url")), curve = noiseJWK.crv;
  noiseJWK.d = "";
  let dependency;
  try { dependency = owner.admitDependency("node_client_identity", new ResourceVector([1048576n + runtimeBytes, 65536n, 0n, 4n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]).add(poolServerAllowConfigurationCharge(config.poolServerAllow))); }
  catch (error) { privateKey.fill(0); publicKey.fill(0); throw error; }
  let poolServerAllow: PoolServerAllowConfiguration | undefined;
  dependency.onClose(() => { identity = undefined; noise = undefined; publicKey.fill(0); privateKey.fill(0); clearPoolServerAllowConfiguration(poolServerAllow); dispose?.(); handlerCapture?.release(); handlerCapture = undefined; dependency.release(); });
  const signer = Object.freeze({ publicKey, sign: (bytes: Uint8Array): Uint8Array => { dependency.check(); requireCredential(identity !== undefined, "credential_closed"); return new Uint8Array(sign(null, bytes, identity)); } });
  const poolStore = config.poolStore;
  let live: LiveAuthorizationClient | undefined;
  try {
    if (config.poolServerAllow !== undefined) poolServerAllow = capturePoolServerAllowConfiguration(config.poolServerAllow);
    if (config.handlerPlan !== undefined) {
      handlerCapture = captureHandlerPlan(config.handlerPlan, owner, config.maintenanceOwner);
      application = handlerCapture.application; applicationProfile = handlerCapture.profile;
    }
    initialize?.();
    if (config.liveAuthority !== undefined) live = new LiveAuthorizationClient(owner, config.liveAuthority);
    const prepare = async (fields: Parameters<typeof reliableClientSpec>[0], signal: AbortSignal, admission?: ClientSessionAdmission) => {
      dependency.check(); requireCredential(fields.applicationProfile === (applicationProfile === "transport" ? 0n : applicationProfile === "services" ? 1n : 2n) && (fields.required & ~((shape.nativeDatagrams === undefined ? 0n : 1n) | (applicationProfile === "execution" ? applicationResumeFeature() : 0n))) === 0n && fields.maxFrame <= limits.maxFrame && fields.rpcMaxGeneralOutstanding <= (limits.maxGeneralOutstanding ?? 1024) &&
        limits.maxDataBytes + 41 <= fields.maxFrame && BigInt(limits.receiveQueueBytes) <= fields.maxCredit &&
        (fields.profile.includes("x25519") ? curve === "X25519" : curve === "P-256"), "configuration_capacity");
      const transport = await prepareTransport(owner, fields, signal, admission);
      try {
        const selectedCandidateIndex = transport instanceof NodeWSSCarrier && transport.selectedCandidateIndex >= 0 ? transport.selectedCandidateIndex : transport instanceof NodeRawQUICCarrier && transport.selectedCandidateIndex >= 0 ? transport.selectedCandidateIndex : endpointListenerCandidateIndex(transport) ?? fields.candidateIndex;
        const candidate = fields.candidates.find(value => value.candidateIndex === selectedCandidateIndex);
        requireCredential(candidate !== undefined, "credential_binding");
        const selectedFields = Object.freeze({ ...fields, ...candidate });
        await announceOriginalLiveCarrierPreparation(owner, config.liveAuthority, selectedFields, signal); return { ...reliableClientSpec(selectedFields, transport, signer, privateKey, limits, runtimeBytes, "consumer_enforced", application, applicationProfile === "execution" ? "execution" : "services"),
        selectedCandidateIndex, bindingMode, ...(poolServerAllow === undefined ? {} : { poolServerAllow }), ...(handlerCapture === undefined ? {} : { initialRawStreams: handlerCapture.raw }) }; }
      catch (error) {
        await Promise.allSettled([transport.close(), transport.waitTermination()]);
        throw error;
      }
    };
    owner.installClientConnector(Object.freeze<EnvironmentClientConnector>({
      applicationProfile,
      reserveAdmission: () => {
        dependency.check();
        let admission: ClientSessionAdmission | undefined;
        const admissionSpec = reliableClientAdmissionSpec(curve === "X25519" ? "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" : "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1",
          shape, limits, runtimeBytes, application, applicationProfile === "execution" ? "execution" : "services", handlerCapture?.raw);
        admission = owner.reserveClientAdmission(admissionSpec, costs(runtimeBytes), () => { if (admission !== undefined) releaseAdmission?.(admission); });
        try { prepareAdmission?.(owner, admission); return admission; }
        catch (error) { admission.close(); throw error; }
      },
      checkRequirements, ...(live === undefined ? {} : { acquireMaterial: live.acquireOriginalMaterial.bind(live), withdrawUnboundAcquisition: live.withdrawUnboundAcquisition.bind(live) }), connect: (material, options) => live === undefined
      ? owner.establishPoolClient(material, poolStore!, prepare, options) : owner.establishLiveClient(material, live, prepare, options) }));
  } catch (error) { live?.close(); dependency.close(); throw error; }
  return Object.freeze({ namespace: (options: V4NamespaceOptions) => { dependency.check(); return owner.namespace(options); },
    registerDurablePoolSource: (policy: V4CredentialPolicy, configuration: V4PoolSourceConfiguration) => {
      dependency.check(); requireCredential(poolStore !== undefined && noise !== undefined, "configuration_capacity");
      const key = createPublicKey(noise).export({ format: "jwk" });
      const x = new Uint8Array(Buffer.from(key.x!, "base64url")), actual = key.crv === "X25519" ? x :
        new Uint8Array([4, ...x, ...Buffer.from(key.y!, "base64url")]);
      return createOriginalPoolSource(owner, policy, poolStore, configuration, { signingPublicKey: publicKey,
        noisePublicKey: actual, check: () => dependency.check() }).finally(() => actual.fill(0));
    },
    registerPoolSource: (policy: V4CredentialPolicy, provider: V4CredentialProvider) => { dependency.check(); requireCredential(poolStore !== undefined, "configuration_capacity"); return wrapCredentialSource(owner.registerSource(policy, "preauthorized_pool", provider)); },
    verifyPoolMaterial: (policy: V4CredentialPolicy, input: Omit<CredentialInput, "source">) => { dependency.check(); requireCredential(poolStore !== undefined, "configuration_capacity"); return new V4ConnectionMaterial(owner.verify(policy, { ...input, source: "preauthorized_pool" })); },
    registerLiveSource: (policy: V4CredentialPolicy, provider: V4CredentialProvider) => { dependency.check(); requireCredential(live !== undefined, "configuration_capacity"); return wrapCredentialSource(owner.registerSource(policy, "live_authority", provider)); },
    verifyLiveMaterial: (policy: V4CredentialPolicy, input: Omit<CredentialInput, "source" | "activation">) => { dependency.check(); requireCredential(live !== undefined, "configuration_capacity"); return new V4ConnectionMaterial(owner.verify(policy, { ...input, activation: new Uint8Array(), source: "live_authority" })); } });
}
