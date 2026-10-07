import { createOriginalPoolSource, type V4PoolSourceConfiguration, type V4PreauthorizedPoolSource } from "../v4/poolSource.js";
import type { PoolJournalStore } from "../v4/runtime/poolJournal.js";
import { applicationResumeFeature } from "../v4/runtime/checkpointToken.js";
import type { SessionResourceSpec, ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import { captureClientServices, type V4ClientServicesConfig } from "../v4/clientServices.js";
import { captureHandlerPlan, type HandlerPlan } from "../v4/handlerPlan.js";
import type { V4MaintenanceOwner } from "../v4/responsePublication.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import type { V4ConsumerTLS13Verification, V4ConnectionRequirements } from "../generated/transportV4APIResults.js";
import { V4ConnectionMaterial, type V4ConnectionMaterialSource, type V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, wrapCredentialSource, type EnvironmentClientConnector, type V4NamespaceOptions, type V4CredentialPolicy, type V4CredentialProvider } from "../v4/runtime/environment.js";
import { reliableClientSpec, reliableClientAdmissionSpec, captureReliableClientLimits, type ReliableClientLimits } from "../v4/runtime/clientSessionSpec.js";
import { requireCredential, equalCredential } from "../v4/runtime/credentialSupport.js";
import type { CredentialInput } from "../v4/runtime/credentialVerifier.js";
import type { CredentialNamespace } from "../v4/runtime/credentialNamespace.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { isPoolSpendStore, type PoolSpendStore } from "../v4/runtime/poolSpend.js";
import { captureLocalBrowserBridge, prepareLocalBrowserBridge, type LocalBrowserBridgeOptions } from "./localBrowserBridge.js";
import { captureBrowserWSS, prepareBrowserWSS, browserWSSAdmissionCosts, type V4BrowserWSSOptions } from "./wssV4.js";
import { captureBrowserWebTransport, prepareBrowserWebTransport, browserWebTransportAdmissionCosts, type V4BrowserWebTransportOptions } from "./webTransportV4.js";
import { LiveAuthorizationClient, type V4LiveAuthorizationConfig } from "../v4/runtime/liveAuthorization.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import { capturePoolServerAllowConfiguration, clearPoolServerAllowConfiguration, poolServerAllowConfigurationCharge, type PoolServerAllowConfiguration } from "../v4/runtime/poolServerAllow.js";

export type V4BrowserWSSClientLimits = ReliableClientLimits;
export interface V4BrowserWSSClientConfig {
  /** This software Noise/signing adapter requires extractable private keys;
   * non-extractable/hardware-required deployments are refused before consume. */
  readonly identityKey: CryptoKey;
  readonly noiseKey: CryptoKey;
  /** A built-in durable store configured by this original Environment. A host
   * embedding the browser adapter may supply its native built-in store; plain
   * objects and application-asserted consume callbacks are never accepted. */
  readonly poolStore?: PoolSpendStore;
  readonly poolServerAllow?: PoolServerAllowConfiguration;
  readonly liveAuthority?: V4LiveAuthorizationConfig;
  readonly carrier: V4BrowserWSSOptions;
  readonly limits: V4BrowserWSSClientLimits;
  readonly services?: V4ClientServicesConfig;
  /** Original same-Environment inbound/outbound plan, captured before key
   * export or admission callbacks. Mutually exclusive with services. */
  readonly handlerPlan?: HandlerPlan;
  readonly maintenanceOwner?: V4MaintenanceOwner;
}
export interface V4BrowserWSSClient {
  namespace(options: V4NamespaceOptions): CredentialNamespace;
  registerPoolSource(policy: V4CredentialPolicy, provider: V4CredentialProvider): V4ConnectionMaterialSource;
  registerDurablePoolSource(policy: V4CredentialPolicy, configuration: V4PoolSourceConfiguration): Promise<V4PreauthorizedPoolSource>;
  verifyPoolMaterial(policy: V4CredentialPolicy, input: Omit<CredentialInput, "source">): V4ConnectionMaterial;
  registerLiveSource(policy: V4CredentialPolicy, provider: V4CredentialProvider): V4ConnectionMaterialSource;
  verifyLiveMaterial(policy: V4CredentialPolicy, input: Omit<CredentialInput, "source" | "activation">): V4ConnectionMaterial;
}
export type V4BrowserWebTransportClientLimits = ReliableClientLimits;
export interface V4BrowserWebTransportClientConfig extends Omit<V4BrowserWSSClientConfig, "carrier"> {
  readonly carrier: V4BrowserWebTransportOptions;
}
export type V4BrowserWebTransportClient = V4BrowserWSSClient;
function requirements(value: V4ConnectionRequirements): void {
  if (value.datagram || value.local_consumer_tls13_verification || value.independent_reliable_read_progress || value.bound_stream_input_isolation) throw new Error("required_guarantee_unavailable");
}
function decoded(value: string | undefined): Uint8Array<ArrayBuffer> {
  requireCredential(typeof value === "string" && /^[A-Za-z0-9_-]+$/u.test(value) && value.length <= 128, "configuration_capacity");
  return Uint8Array.from(atob(value.replace(/-/gu, "+").replace(/_/gu, "/")), c => c.charCodeAt(0));
}

/** Capture the ordinary host declarations before native/key callbacks. */
function captureBrowserClientConfiguration(input: Omit<V4BrowserWSSClientConfig, "carrier">): Omit<V4BrowserWSSClientConfig, "carrier"> {
  const identityKey = input.identityKey, noiseKey = input.noiseKey, poolStore = input.poolStore, liveAuthority = input.liveAuthority;
  const services = input.services, poolServerAllow = input.poolServerAllow, handlerPlan = input.handlerPlan, maintenanceOwner = input.maintenanceOwner;
  const limits = captureReliableClientLimits(input.limits);
  return Object.freeze({ identityKey, noiseKey, limits, ...(poolStore === undefined ? {} : { poolStore }),
    ...(liveAuthority === undefined ? {} : { liveAuthority }), ...(services === undefined ? {} : { services }),
    ...(poolServerAllow === undefined ? {} : { poolServerAllow }),
    ...(handlerPlan === undefined ? {} : { handlerPlan }), ...(maintenanceOwner === undefined ? {} : { maintenanceOwner }) });
}
/** Installs the browser WSS software client in the original Environment.
 * Key export and native callbacks retain paid ownership through real exit.
 * Public Connect never receives a raw-key or asserted READY/session factory. */
export async function configureV4BrowserWSS(environment: V4TransportEnvironment, config: V4BrowserWSSClientConfig): Promise<V4BrowserWSSClient> {
  originalEnvironment(environment);
  const captured = captureBrowserClientConfiguration(config), carrier = captureBrowserWSS(config.carrier), maxFrame = captured.limits.maxFrame;
  return configureBrowserClient(environment, captured, (owner, fields, signal, admission) => prepareBrowserWSS(owner, fields, carrier, signal, admission), { mode: "message" }, runtimeBytes => browserWSSAdmissionCosts(maxFrame, carrier, runtimeBytes));
}

/** One dedicated browser native connection, with a separate maintenance bidi
 * and one original native association for each application Stream. */
export async function configureV4BrowserWebTransport(environment: V4TransportEnvironment,
  config: V4BrowserWebTransportClientConfig): Promise<V4BrowserWebTransportClient> {
  originalEnvironment(environment);
  const captured = captureBrowserClientConfiguration(config), carrier = captureBrowserWebTransport(config.carrier), maxFrame = captured.limits.maxFrame;
  const maximum = Math.min(captured.limits.maxStreams, 1024);
  requireCredential(Number.isSafeInteger(maximum) && maximum > 0 && carrier.applicationStreams >= maximum + Math.min(128, Math.max(4, maximum)) + 1, "configuration_capacity");
  return configureBrowserClient(environment, captured, (owner, fields, signal, admission) => prepareBrowserWebTransport(owner, fields, carrier, signal, admission), { mode: "stream", nativeStreams: { capacity: carrier.applicationStreams }, nativeDatagrams: {} }, runtimeBytes => browserWebTransportAdmissionCosts(maxFrame, carrier, runtimeBytes), "controlled_terminator",
    value => { if (value.local_consumer_tls13_verification) throw new Error("required_guarantee_unavailable"); });
}

export interface LocalBrowserBridgeConfig extends Omit<V4BrowserWSSClientConfig, "carrier"> {
  readonly carrier: LocalBrowserBridgeOptions;
}
export type LocalBrowserBridge = V4BrowserWSSClient;
/** The dedicated same-wire entrance rejects every network/tunnel descriptor. */
export async function configureLocalBrowserBridge(environment: V4TransportEnvironment, config: LocalBrowserBridgeConfig): Promise<LocalBrowserBridge> {
  originalEnvironment(environment);
  const captured = captureBrowserClientConfiguration(config), carrier = captureLocalBrowserBridge(config.carrier), maxFrame = captured.limits.maxFrame;
  return configureBrowserClient(environment, captured, (owner, fields, signal, admission) => prepareLocalBrowserBridge(owner, fields, carrier, signal, admission),
    { mode: "message" }, runtimeBytes => browserWSSAdmissionCosts(maxFrame, carrier, runtimeBytes), "not_applicable");
}

/** Carrier entrances share the original identity and source owners. */
async function configureBrowserClient(environment: V4TransportEnvironment, config: Omit<V4BrowserWSSClientConfig, "carrier">,
  prepareTransport: (owner: ReturnType<typeof originalEnvironment>, fields: Parameters<typeof reliableClientSpec>[0], signal: AbortSignal, admission?: ClientSessionAdmission) => Promise<V4AuthenticatedTransport>, transportShape: SessionResourceSpec["transport"],
  carrierCosts: (runtimeBytes: bigint) => readonly (readonly [string, ResourceVector])[], verification: V4ConsumerTLS13Verification = "controlled_terminator",
  checkRequirements: (requirements: V4ConnectionRequirements) => void = requirements): Promise<V4BrowserWSSClient> {
  const owner = originalEnvironment(environment), runtimeBytes = owner.resources.runtimeBytes, limits = captureReliableClientLimits(config.limits);
  const identityKey = config.identityKey, noiseKey = config.noiseKey, poolStore = config.poolStore, liveAuthority = config.liveAuthority;
  const handlerPlan = config.handlerPlan, maintenanceOwner = config.maintenanceOwner;
  requireCredential(handlerPlan === undefined || config.services === undefined, "configuration_capacity");
  const services = captureClientServices(config.services);
  let application = services?.application, applicationProfile: "transport" | "services" | "execution" = services?.profile ?? "transport";
  let handlerCapture: ReturnType<typeof captureHandlerPlan> | undefined;
  requireCredential(identityKey instanceof CryptoKey && noiseKey instanceof CryptoKey && identityKey.type === "private" && noiseKey.type === "private" &&
    identityKey.extractable && noiseKey.extractable && identityKey.algorithm.name === "Ed25519" && identityKey.usages.includes("sign") &&
    ["X25519", "ECDH"].includes(noiseKey.algorithm.name) && noiseKey.usages.includes("deriveBits") &&
    (poolStore !== undefined && isPoolSpendStore(poolStore) && liveAuthority === undefined || poolStore === undefined && liveAuthority !== undefined), "configuration_capacity");
  for (const value of [limits.maxFrame, limits.maxStreams, limits.receiveQueueBytes, limits.maxDataBytes, limits.maxCursorBytes, limits.maxWriteBytes, limits.cryptoKeys])
    requireCredential(Number.isSafeInteger(value) && value > 0 && value <= 16777216, "configuration_capacity");
  for (const value of [limits.writeDeadlineMS, limits.operationDeadlineMS, limits.rekeyPrepareMS, limits.rekeyProtocolMS, limits.rekeyConfirmationMS])
    requireCredential(typeof value === "bigint" && value > 0n && value <= 0xffffffffffffffffn, "configuration_capacity");
  requireCredential(limits.receiveQueueBytes >= limits.maxDataBytes && limits.cryptoKeys <= 65536, "configuration_capacity");
  const dependency = owner.admitDependency("browser_client_identity", new ResourceVector([32768n + runtimeBytes, 65536n, 0n, 8n, 2n, 2n, 0n, 0n, 0n, 0n, 0n]).add(poolServerAllowConfigurationCharge(config.poolServerAllow)));
  let closed = false, active = true, seed: Uint8Array = new Uint8Array(), privateKey: Uint8Array = new Uint8Array(), publicKey: Uint8Array = new Uint8Array();
  let live: LiveAuthorizationClient | undefined;
  let poolServerAllow: PoolServerAllowConfiguration | undefined;
  const cleanup = (): void => { if (closed && !active) { seed.fill(0); privateKey.fill(0); publicKey.fill(0); clearPoolServerAllowConfiguration(poolServerAllow); handlerCapture?.release(); handlerCapture = undefined; dependency.release(); } };
  dependency.onClose(() => { closed = true; cleanup(); });
  try {
    if (config.poolServerAllow !== undefined) poolServerAllow = capturePoolServerAllowConfiguration(config.poolServerAllow);
    if (handlerPlan !== undefined) {
      handlerCapture = captureHandlerPlan(handlerPlan, owner, maintenanceOwner);
      application = handlerCapture.application; applicationProfile = handlerCapture.profile;
    }
    if (liveAuthority !== undefined) live = new LiveAuthorizationClient(owner, liveAuthority);
    const exports = await Promise.allSettled([crypto.subtle.exportKey("jwk", identityKey), crypto.subtle.exportKey("jwk", noiseKey)]);
    if (exports[0].status !== "fulfilled" || exports[1].status !== "fulfilled") { for (const result of exports) if (result.status === "fulfilled") result.value.d = ""; throw new Error("key_unavailable"); }
    const signing = exports[0].value, noise = exports[1].value;
    try {
      dependency.check(); requireCredential(!closed && signing.crv === "Ed25519" && ["X25519", "P-256"].includes(noise.crv ?? ""), "configuration_capacity");
      seed = decoded(signing.d); privateKey = decoded(noise.d); publicKey = decoded(signing.x);
      requireCredential(seed.length === 32 && privateKey.length === 32 && publicKey.length === 32 && equalCredential(ed25519.getPublicKey(seed), publicKey));
      const curve = noise.crv, actual = curve === "X25519" ? x25519.getPublicKey(privateKey) : p256.getPublicKey(privateKey, false), x = decoded(noise.x);
      requireCredential(equalCredential(curve === "X25519" ? actual : actual.subarray(1, 33), x));
      if (curve === "P-256") requireCredential(equalCredential(actual.subarray(33), decoded(noise.y))); actual.fill(0); x.fill(0);
      const signer = Object.freeze({ publicKey, sign: (input: Uint8Array): Uint8Array => { dependency.check(); requireCredential(!closed, "credential_closed"); return ed25519.sign(input, seed); } });
      const prepare = async (fields: Parameters<typeof reliableClientSpec>[0], signal: AbortSignal, admission?: ClientSessionAdmission) => {
        dependency.check(); requireCredential(fields.applicationProfile === (applicationProfile === "transport" ? 0n : applicationProfile === "services" ? 1n : 2n) && (fields.required & ~((transportShape.nativeDatagrams === undefined ? 0n : 1n) | (applicationProfile === "execution" ? applicationResumeFeature() : 0n))) === 0n && fields.maxFrame <= limits.maxFrame && fields.rpcMaxGeneralOutstanding <= (limits.maxGeneralOutstanding ?? 1024) &&
          limits.maxDataBytes + 41 <= fields.maxFrame && BigInt(limits.receiveQueueBytes) <= fields.maxCredit && (fields.profile.includes("x25519") ? curve === "X25519" : curve === "P-256"), "configuration_capacity");
        const transport = await prepareTransport(owner, fields, signal, admission);
        try { return { ...reliableClientSpec(fields, transport, signer, privateKey, limits, runtimeBytes, verification, application,
          applicationProfile === "execution" ? "execution" : "services"), ...(poolServerAllow === undefined ? {} : { poolServerAllow }), ...(handlerCapture === undefined ? {} : { initialRawStreams: handlerCapture.raw }) }; }
        catch (error) {
          await Promise.allSettled([transport.close(), transport.waitTermination()]);
          throw error;
        }
      };
      owner.installClientConnector(Object.freeze<EnvironmentClientConnector>({
        applicationProfile,
        reserveAdmission: () => { dependency.check(); return owner.reserveClientAdmission(reliableClientAdmissionSpec(curve === "X25519" ? "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" : "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1",
          transportShape, limits, runtimeBytes, application, applicationProfile === "execution" ? "execution" : "services", handlerCapture?.raw), carrierCosts(runtimeBytes)); },
        checkRequirements, connect: (material, options) => live === undefined
        ? owner.establishPoolClient(material, poolStore!, prepare, options) : owner.establishLiveClient(material, live, prepare, options) }));
    } finally { signing.d = ""; noise.d = ""; }
    return Object.freeze({ namespace: (options: V4NamespaceOptions) => { dependency.check(); return owner.namespace(options); },
      registerDurablePoolSource: async (policy: V4CredentialPolicy, configuration: V4PoolSourceConfiguration) => {
        dependency.check(); requireCredential(poolStore !== undefined, "configuration_capacity");
        const exported = await crypto.subtle.exportKey("jwk", noiseKey);
        const x = decoded(exported.x), actual = exported.crv === "X25519" ? x : new Uint8Array([4, ...x, ...decoded(exported.y)]); exported.d = "";
        try { return await createOriginalPoolSource(owner, policy, poolStore as PoolSpendStore & PoolJournalStore, configuration,
          { signingPublicKey: publicKey, noisePublicKey: actual, check: () => dependency.check() }); }
        finally { actual.fill(0); }
      },
      registerPoolSource: (policy: V4CredentialPolicy, provider: V4CredentialProvider) => { dependency.check(); requireCredential(poolStore !== undefined, "configuration_capacity"); return wrapCredentialSource(owner.registerSource(policy, "preauthorized_pool", provider)); },
      verifyPoolMaterial: (policy: V4CredentialPolicy, input: Omit<CredentialInput, "source">) => { dependency.check(); requireCredential(poolStore !== undefined, "configuration_capacity"); return new V4ConnectionMaterial(owner.verify(policy, { ...input, source: "preauthorized_pool" })); },
      registerLiveSource: (policy: V4CredentialPolicy, provider: V4CredentialProvider) => { dependency.check(); requireCredential(live !== undefined, "configuration_capacity"); return wrapCredentialSource(owner.registerSource(policy, "live_authority", provider)); },
      verifyLiveMaterial: (policy: V4CredentialPolicy, input: Omit<CredentialInput, "source" | "activation">) => { dependency.check(); requireCredential(live !== undefined, "configuration_capacity"); return new V4ConnectionMaterial(owner.verify(policy, { ...input, activation: new Uint8Array(), source: "live_authority" })); } });
  } catch (error) { live?.close(); dependency.close(); throw error; }
  finally { active = false; cleanup(); }
}
