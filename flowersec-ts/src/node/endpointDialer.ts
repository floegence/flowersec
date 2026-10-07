import type { NodeWSSListenerOptions } from "./serveWSS.js";
import { KeyObject, createPublicKey, sign } from "node:crypto";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency, type V4CredentialPolicy, type V4EnvironmentMaterial } from "../v4/runtime/environment.js";
import type { CarrierPreparationFields, CredentialInput } from "../v4/runtime/credentialVerifier.js";
import type { RegisteredCarrierPreparation } from "../v4/runtime/registeredCarrierPreparation.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { createServeListener, createServeHandle, ServeError } from "../v4/serve.js";
import { captureHandlerPlan, type HandlerPlan } from "../v4/handlerPlan.js";
import { ServeGroup, type ServeGroupLimits } from "../v4/runtime/serveGroup.js";
import { ServerAdmissionExchange, serverAdmissionCharge } from "../v4/runtime/serverAdmission.js";
import { captureReliableClientLimits, type ReliableClientLimits } from "../v4/runtime/clientSessionSpec.js";
import { reliableServerSpec } from "../v4/runtime/serverSessionSpec.js";
import { captureNodeWSS, prepareNodeWSS, type V4NodeWSSOptions } from "./wssV4.js";
import { captureNodeRawQUICCandidates, prepareNodeRawQUICCandidates, type NodeRawQUICOptions } from "./rawQUICCurrent.js";
import { loadCurrentNativeTransport, loadCurrentNativeWebTransport, type NativeTransportBinding } from "./nativeTransportCurrent.js";
import { endpointTransport } from "./endpointTransport.js";
import { SQLiteAdmissionStore } from "./sqliteAdmission.js";

type Carrier = Readonly<{ carrierKind: "wss"; carrier: V4NodeWSSOptions }> | Readonly<{ carrierKind: "raw_quic" | "webtransport"; carrier: NodeRawQUICOptions; carrierAlternatives?: readonly NodeRawQUICOptions[]; candidateAttemptLimit?: number }>;
const capability = Symbol("original physical B dialer preparation"), preparations = new WeakSet<TunnelEndpointDialerPreparation>();
export type TunnelEndpointDialerPreparationOptions = Carrier & Readonly<{ environment: V4TransportEnvironment; policy: V4CredentialPolicy; material: CredentialInput; workMS: bigint }>;
/** Owns one real native connection prepared from signed registry facts before
 * original TxA/TxB. Adoption cannot create another carrier or reconstruct allow. */
export class TunnelEndpointDialerPreparation {
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #dependency: EnvironmentDependency; readonly #registry: RegisteredCarrierPreparation;
  readonly #physical: V4AuthenticatedTransport; readonly #carrierKind: Carrier["carrierKind"]; readonly #configuration: Carrier;
  get carrierKind(): Carrier["carrierKind"] { return this.#carrierKind; }
  #taken = false; #closed = false; #closing: Promise<void> | undefined;
  constructor(token: symbol, options: TunnelEndpointDialerPreparationOptions, registry: RegisteredCarrierPreparation, physical: V4AuthenticatedTransport, configuration: Carrier) {
    requireCredential(token === capability); this.#runtime = originalEnvironment(options.environment); this.#registry = registry; this.#physical = physical; this.#carrierKind = configuration.carrierKind; this.#configuration = configuration;
    this.#dependency = this.#runtime.admitDependency("endpoint_dialer_preparation", new ResourceVector([1048576n + this.#runtime.resources.runtimeBytes, 0n, 0n, 4n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
    this.#dependency.onClose(() => { void this.close().catch(() => undefined); }); preparations.add(this);
    void physical.waitTermination().then(() => this.close(), () => this.close()).catch(() => undefined); Object.freeze(this);
  }
  take(environment: V4TransportEnvironment, kind: Carrier["carrierKind"]): V4AuthenticatedTransport {
    requireCredential(preparations.has(this) && !this.#closed && !this.#taken && originalEnvironment(environment) === this.#runtime && kind === this.#carrierKind, "credential_binding");
    this.#dependency.check(); this.#registry.check(); this.#physical.checkPreparation?.(); this.#taken = true; return this.#physical;
  }
  checkMaterial(material: V4EnvironmentMaterial): void { this.#dependency.check(); this.#runtime.checkPreparedTunnelCarrierMaterial(material, this.#registry); }
  /** B's logical admission uses the exact signed Route of its original
   * physical dialer. Listener evidence belongs to the opposite hop role. */
  checkAdmissionRoute(fields: CarrierPreparationFields): void {
    requireCredential(!this.#closed && this.#taken, "credential_closed");
    this.#dependency.check(); this.#physical.checkPreparation!();
    const prepared = this.#registry.fields();
    requireCredential(fields.pathKind === 1 && fields.source === prepared.source && fields.accessClass === prepared.accessClass &&
      fields.candidateIndex === prepared.candidateIndex && equalCredential(fields.route, prepared.route), "credential_binding");
  }
  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing; this.#closed = true;
    return this.#closing = (async () => {
      const results = await Promise.allSettled([this.#physical.close(), this.#physical.waitTermination()]); this.#registry.close();
      if (this.#configuration.carrierKind === "wss") for (const root of this.#configuration.carrier.ca ?? []) { if (root instanceof Uint8Array) root.fill(0); }
      else for (const root of this.#configuration.carrier.trustRootsDER ?? []) root.fill(0);
      this.#dependency.release(); const failure = results.find(result => result.status === "rejected"); if (failure?.status === "rejected") throw failure.reason;
    })();
  }
}
export async function prepareTunnelEndpointDialer(options: TunnelEndpointDialerPreparationOptions, signal?: AbortSignal): Promise<TunnelEndpointDialerPreparation> {
  const runtime = originalEnvironment(options.environment); requireCredential(options.policy.tunnel?.role === 1, "configuration_capacity");
  const registry = runtime.prepareRegisteredTunnelCarrier(options.policy, options.material, options.workMS); let physical: V4AuthenticatedTransport | undefined, configuration: Carrier | undefined;
  try {
    if (options.carrierKind === "wss") { const carrier = captureNodeWSS(options.carrier); configuration = Object.freeze({ carrierKind: "wss", carrier }); const prepared = await prepareNodeWSS(runtime, registry.fields(), carrier, signal, undefined, 1); physical = prepared; registry.selectCandidate(prepared.selectedCandidateIndex); }
    else {
      const candidates = captureNodeRawQUICCandidates([options.carrier, ...(options.carrierAlternatives ?? [])]);
      try {
        const firstCandidate = candidates[0];
        requireCredential(firstCandidate !== undefined && (firstCandidate.nativeCarrier === "webtransport") === (options.carrierKind === "webtransport"), "configuration_capacity");
        const drivers: Partial<Record<"raw-quic" | "webtransport", NativeTransportBinding>> = Object.fromEntries(candidates.map(value => [value.nativeCarrier ?? "raw-quic", value.nativeCarrier === "webtransport" ? loadCurrentNativeWebTransport() : loadCurrentNativeTransport()]));
        const prepared = await prepareNodeRawQUICCandidates(runtime, registry.fields(), candidates, drivers, signal, undefined, 1, 1, options.candidateAttemptLimit ?? 16); physical = prepared;
        registry.selectCandidate(prepared.selectedCandidateIndex);
        const kind = prepared.nativeCarrier, selected = candidates.find(value => value.nativeCarrier === kind); requireCredential(selected !== undefined, "credential_binding");
        configuration = Object.freeze({ carrierKind: kind === "webtransport" ? "webtransport" : "raw_quic", carrier: selected });
      } finally { for (const value of candidates) if (value !== configuration?.carrier) for (const root of value.trustRootsDER ?? []) root.fill(0); }
    }
    requireCredential(physical !== undefined && configuration !== undefined, "configuration_capacity");
    return new TunnelEndpointDialerPreparation(capability, options, registry, physical, configuration);
  } catch (error) { if (physical !== undefined) await Promise.allSettled([physical.close(), physical.waitTermination()]); registry.close(); if (configuration?.carrierKind === "wss") { for (const root of configuration.carrier.ca ?? []) if (root instanceof Uint8Array) root.fill(0); } else if (configuration !== undefined) for (const root of configuration.carrier.trustRootsDER ?? []) root.fill(0); throw error; }
}
export type NodeTunnelDialerOptions = Carrier & Readonly<{
  physicalDirection: "dialer"; path: "tunnel"; serverName: string; port: number;
  identityKey: KeyObject; noiseKey: KeyObject; admissionStore: SQLiteAdmissionStore;
  limits: ReliableClientLimits; ingress: ServeGroupLimits;
  preparation: TunnelEndpointDialerPreparation;
  credentials: NodeWSSListenerOptions["credentials"] & Readonly<{ takePreparedHop(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>): Promise<V4EnvironmentMaterial> }>;
}>;
/** The current Serve lifecycle runs over the original prepared physical B
 * dialer. Only its logical view changes for Admission, Noise and READY. */
export function createNodeTunnelDialerListener(environment: V4TransportEnvironment, input: NodeTunnelDialerOptions) {
  const runtime = originalEnvironment(environment), limits = captureReliableClientLimits(input.limits), ingress = Object.freeze({ ...input.ingress });
  const preparation = input.preparation, identityKey = input.identityKey, noiseKey = input.noiseKey, store = input.admissionStore, take = input.credentials.takePreparedHop, kind = preparation.carrierKind;
  requireCredential(preparations.has(preparation) && input.path === "tunnel" && identityKey instanceof KeyObject && identityKey.type === "private" && identityKey.asymmetricKeyType === "ed25519" && noiseKey instanceof KeyObject && noiseKey.type === "private" && ["x25519", "ec"].includes(noiseKey.asymmetricKeyType ?? "") && store instanceof SQLiteAdmissionStore && typeof take === "function", "configuration_capacity");
  const address = Object.freeze({ host: input.serverName, port: input.port });
  const listener = createServeListener<HandlerPlan>({ environment, carrier: kind === "wss" ? "wss" : "raw_quic", async start(callbacks, maintenanceOwner, signal) {
    const group = new ServeGroup(runtime, ingress, callbacks, signal); let dependency: EnvironmentDependency | undefined, physical: V4AuthenticatedTransport | undefined;
    let publicKey = new Uint8Array(), privateKey = new Uint8Array(); const acceptor = new Uint8Array(16);
    try {
      dependency = runtime.admitDependency("endpoint_dialer_serve", new ResourceVector([1048576n + runtime.resources.runtimeBytes, 0n, 0n, 8n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
      dependency.onClose(() => group.close()); physical = preparation.take(environment, kind);
      const transport = endpointTransport(physical, 1);
      const serverTransport = Object.freeze({ ...transport, checkAcceptedRoute: (fields: CarrierPreparationFields) => preparation.checkAdmissionRoute(fields) });
      const identity = createPublicKey(identityKey).export({ format: "jwk" }), noise = noiseKey.export({ format: "jwk" });
      requireCredential(identity.crv === "Ed25519" && typeof identity.x === "string" && typeof noise.d === "string" && ["X25519", "P-256"].includes(noise.crv ?? ""), "configuration_capacity");
      publicKey = new Uint8Array(Buffer.from(identity.x, "base64url")); privateKey = new Uint8Array(Buffer.from(noise.d, "base64url")); noise.d = ""; runtime.fillRandom(acceptor);
      const signer = Object.freeze({ publicKey, sign: (bytes: Uint8Array): Uint8Array => { dependency!.check(); return new Uint8Array(sign(null, bytes, identityKey)); } });
      const entry = group.begin(() => { void physical!.close(); });
      group.bindListener(() => {}, () => entry.abort()); group.checkIngress();
      const run = async (): Promise<void> => {
        let material: V4EnvironmentMaterial | undefined, exchange: ServerAdmissionExchange | undefined, plan: ReturnType<typeof captureHandlerPlan> | undefined;
        const invocation = new Uint8Array(16), carrier = new Uint8Array(16);
        try {
          await entry.authorizeRequest(""); entry.check();
          material = await entry.resolveMaterial(async () => { const original = await take(Object.freeze({ signal: entry.signal, hello: new Uint8Array() })); material = original; return original; });
          runtime.checkOriginalServerPublication(material, dependency!.reference); preparation.checkMaterial(material);
          await runtime.authenticatePreparedEndpointHop(material, physical!, signer, { signal: entry.signal }); entry.check();
          const reference = runtime.reserveConnectionWork("server_admission", serverAdmissionCharge(runtime.resources.runtimeBytes));
          try { exchange = new ServerAdmissionExchange(runtime.resources, serverTransport, signer, bytes => runtime.fillRandom(bytes), reference, () => entry.check(), "authenticated_context"); } finally { reference.release(); }
          await exchange.readHello({ signal: entry.signal }); runtime.fillRandom(invocation); runtime.fillRandom(carrier);
          const session = await runtime.establishServer(material, async fields => {
            plan = captureHandlerPlan(await entry.authorize(exchange!.requestContext()), runtime, maintenanceOwner); entry.check();
            requireCredential(fields.maxFrame <= limits.maxFrame && fields.rpcMaxGeneralOutstanding <= (limits.maxGeneralOutstanding ?? 1024) && limits.maxDataBytes + 41 <= fields.maxFrame && BigInt(limits.receiveQueueBytes) <= fields.maxCredit && (fields.profile.includes("x25519") ? noise.crv === "X25519" : noise.crv === "P-256"), "configuration_capacity");
            return { ...reliableServerSpec(fields, transport, signer, privateKey, limits, runtime.resources.runtimeBytes, plan.application, plan.profile === "transport" ? "services" : plan.profile), initialRawStreams: plan.raw, claimReadySession: session => entry.claim(session) };
          }, exchange, store, { acceptor, invocation, carrier, generation: 1n, signal: entry.signal }, { signal: entry.signal }).finally(() => entry.publishClaimed());
          await session.waitTermination();
        } catch (error) {
          throw error;
        } finally { plan?.release(); exchange?.close(); await material?.closeMaterial(); invocation.fill(0); carrier.fill(0); }
      };
      void run().catch(() => entry.abort()).finally(async () => {
        await preparation.close(); entry.nativeEnded(); group.listenerCoreEnded(); await entry.finish(); privateKey.fill(0); publicKey.fill(0); acceptor.fill(0); dependency!.release(); group.listenerEnded();
      }).catch(() => group.close());
      return createServeHandle(group);
    } catch { group.close(); await preparation.close(); privateKey.fill(0); publicKey.fill(0); acceptor.fill(0); dependency?.release(); group.listenerCoreEnded(); group.listenerEnded(); throw new ServeError(signal?.aborted ? "canceled" : "serve_failed", group.cleanupStatus()); }
  } });
  return Object.freeze({ listener, address: () => address });
}
Object.freeze(TunnelEndpointDialerPreparation.prototype); Object.freeze(TunnelEndpointDialerPreparation);
