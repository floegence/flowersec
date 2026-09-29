import type { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import { captureClientServices, type V4ClientServicesConfig } from "../v4/clientServices.js";
import { KeyObject, createPublicKey, sign } from "node:crypto";
import { V4ConnectionMaterial, type V4ConnectionMaterialSource, type V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, wrapCredentialSource, type V4CredentialPolicy, type V4CredentialProvider, type V4NamespaceOptions, type EnvironmentClientConnector } from "../v4/runtime/environment.js";
import { reliableClientSpec, reliableClientAdmissionSpec, captureReliableClientLimits, type ReliableClientLimits } from "../v4/runtime/clientSessionSpec.js";
import type { CredentialNamespace } from "../v4/runtime/credentialNamespace.js";
import type { CredentialInput } from "../v4/runtime/credentialVerifier.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { requireCredential } from "../v4/runtime/credentialSupport.js";
import { prepareNodeWSS, nodeWSSAdmissionCosts, type V4NodeWSSOptions } from "./wssV4.js";
import { V4SQLitePoolStore } from "./sqlitePoolV4.js";
import type { V4ConnectionRequirements } from "../generated/transportV4APIResults.js";
import { LiveAuthorizationClient, type V4LiveAuthorizationConfig } from "../v4/runtime/liveAuthorization.js";

export interface V4NodeWSSClientConfig {
  readonly identityKey: KeyObject;
  readonly noiseKey: KeyObject;
  readonly poolStore?: V4SQLitePoolStore;
  readonly liveAuthority?: V4LiveAuthorizationConfig;
  readonly carrier: V4NodeWSSOptions;
  readonly limits: V4NodeWSSClientLimits;
  readonly services?: V4ClientServicesConfig;
  /** Fixed before preparation; exporter failures never select another mode. */
  readonly bindingMode?: "direct_exporter" | "authenticated_context";
}
export type V4NodeWSSClientLimits = ReliableClientLimits;
export interface V4NodeWSSClient {
  namespace(options: V4NamespaceOptions): CredentialNamespace;
  registerPoolSource(policy: V4CredentialPolicy, provider: V4CredentialProvider): V4ConnectionMaterialSource;
  verifyPoolMaterial(policy: V4CredentialPolicy, input: Omit<CredentialInput, "source">): V4ConnectionMaterial;
  registerLiveSource(policy: V4CredentialPolicy, provider: V4CredentialProvider): V4ConnectionMaterialSource;
  verifyLiveMaterial(policy: V4CredentialPolicy, input: Omit<CredentialInput, "source" | "activation">): V4ConnectionMaterial;
}
function requirements(value: V4ConnectionRequirements): void {
  if (value.datagram || value.independent_reliable_read_progress || value.bound_stream_input_isolation) throw new Error("required_guarantee_unavailable");
}
/** Installs one direct WSS client and its fixed activation source. Session
 * publication requires actual once authorization, admission, Noise and dual
 * READY. Host keys are captured as immutable native KeyObjects. */
export function configureV4NodeWSS(environment: V4TransportEnvironment, config: V4NodeWSSClientConfig): V4NodeWSSClient {
  const owner = originalEnvironment(environment), limits = captureReliableClientLimits(config.limits), runtimeBytes = owner.resources.runtimeBytes;
  const services = captureClientServices(config.services), application = services?.application;
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
  const c = config.carrier, ca = c.ca?.map(value => typeof value === "string" ? value : new Uint8Array(value));
  requireCredential(ca === undefined || ca.reduce((n, value) => n + (typeof value === "string" ? Buffer.byteLength(value) : value.length), 0) <= 1048576, "configuration_capacity");
  const carrier = Object.freeze({ remoteAddress: c.remoteAddress, ...(c.origin === undefined ? {} : { origin: c.origin }), ...(ca === undefined ? {} : { ca: Object.freeze(ca) }),
    queueMessages: c.queueMessages, runtimeBytes: c.runtimeBytes, nativeBytes: c.nativeBytes, prepareBytes: c.prepareBytes });
  let identity: KeyObject | undefined = config.identityKey, noise: KeyObject | undefined = config.noiseKey;
  const identityJWK = createPublicKey(identity).export({ format: "jwk" }), noiseJWK = noise.export({ format: "jwk" });
  requireCredential(identityJWK.crv === "Ed25519" && typeof identityJWK.x === "string" && typeof noiseJWK.d === "string" && ["X25519", "P-256"].includes(noiseJWK.crv ?? ""), "configuration_capacity");
  const publicKey = new Uint8Array(Buffer.from(identityJWK.x, "base64url")), privateKey = new Uint8Array(Buffer.from(noiseJWK.d, "base64url")), curve = noiseJWK.crv;
  noiseJWK.d = "";
  let dependency;
  try { dependency = owner.admitDependency("node_wss_identity", new ResourceVector([1048576n + runtimeBytes, 65536n, 0n, 4n, 1n, 0n, 0n, 0n, 0n, 0n, 0n])); }
  catch (error) { privateKey.fill(0); publicKey.fill(0); throw error; }
  dependency.onClose(() => { identity = undefined; noise = undefined; publicKey.fill(0); privateKey.fill(0); for (const value of ca ?? []) if (value instanceof Uint8Array) value.fill(0); dependency.release(); });
  const signer = Object.freeze({ publicKey, sign: (bytes: Uint8Array): Uint8Array => { dependency.check(); requireCredential(identity !== undefined, "credential_closed"); return new Uint8Array(sign(null, bytes, identity)); } });
  const poolStore = config.poolStore;
  let live: LiveAuthorizationClient | undefined;
  try {
    if (config.liveAuthority !== undefined) live = new LiveAuthorizationClient(owner, config.liveAuthority);
    const prepare = async (fields: Parameters<typeof reliableClientSpec>[0], signal: AbortSignal, admission?: ClientSessionAdmission) => {
      dependency.check(); requireCredential(fields.applicationProfile === (services === undefined ? 0n : services.profile === "services" ? 1n : 2n) && fields.required === 0n && fields.maxFrame <= limits.maxFrame && fields.rpcMaxGeneralOutstanding <= (limits.maxGeneralOutstanding ?? 1024) &&
        limits.maxDataBytes + 41 <= fields.maxFrame && BigInt(limits.receiveQueueBytes) <= fields.maxCredit &&
        (fields.profile.includes("x25519") ? curve === "X25519" : curve === "P-256"), "configuration_capacity");
      const transport = await prepareNodeWSS(owner, fields, carrier, signal, admission);
      try { return { ...reliableClientSpec(fields, transport, signer, privateKey, limits, runtimeBytes, "consumer_enforced", application, services?.profile), bindingMode }; }
      catch (error) { void transport.close().catch(() => undefined); throw error; }
    };
    owner.installClientConnector(Object.freeze<EnvironmentClientConnector>({
      applicationProfile: services?.profile ?? "transport",
      reserveAdmission: () => { dependency.check(); return owner.reserveClientAdmission(reliableClientAdmissionSpec(curve === "X25519" ? "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" : "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1",
        { mode: "message" }, limits, runtimeBytes, application, services?.profile), nodeWSSAdmissionCosts(limits.maxFrame, carrier, runtimeBytes)); },
      checkRequirements: requirements, connect: (material, options) => live === undefined
      ? owner.establishPoolClient(material, poolStore!, prepare, options) : owner.establishLiveClient(material, live, prepare, options) }));
  } catch (error) { live?.close(); dependency.close(); throw error; }
  return Object.freeze({ namespace: (options: V4NamespaceOptions) => { dependency.check(); return owner.namespace(options); },
    registerPoolSource: (policy: V4CredentialPolicy, provider: V4CredentialProvider) => { dependency.check(); requireCredential(poolStore !== undefined, "configuration_capacity"); return wrapCredentialSource(owner.registerSource(policy, "preauthorized_pool", provider)); },
    verifyPoolMaterial: (policy: V4CredentialPolicy, input: Omit<CredentialInput, "source">) => { dependency.check(); requireCredential(poolStore !== undefined, "configuration_capacity"); return new V4ConnectionMaterial(owner.verify(policy, { ...input, source: "preauthorized_pool" })); },
    registerLiveSource: (policy: V4CredentialPolicy, provider: V4CredentialProvider) => { dependency.check(); requireCredential(live !== undefined, "configuration_capacity"); return wrapCredentialSource(owner.registerSource(policy, "live_authority", provider)); },
    verifyLiveMaterial: (policy: V4CredentialPolicy, input: Omit<CredentialInput, "source" | "activation">) => { dependency.check(); requireCredential(live !== undefined, "configuration_capacity"); return new V4ConnectionMaterial(owner.verify(policy, { ...input, activation: new Uint8Array(), source: "live_authority" })); } });
}
