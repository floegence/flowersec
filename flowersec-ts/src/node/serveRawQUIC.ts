import { KeyObject, X509Certificate, createPublicKey, sign } from "node:crypto";
import { isIP } from "node:net";
import type { V4TransportEnvironment } from "../v4/public.js";
import { ServeError, createServeHandle, createServeListener, type ServeListener } from "../v4/serve.js";
import { captureHandlerPlan, type HandlerPlan } from "../v4/handlerPlan.js";
import { ServeGroup, type ServeGroupLimits, type ServeIngress } from "../v4/runtime/serveGroup.js";
import { originalEnvironment, type EnvironmentDependency, type V4CredentialBuffers, type V4CredentialLengths, type V4CredentialPolicy, type V4EnvironmentMaterial } from "../v4/runtime/environment.js";
import { captureReliableClientLimits, type ReliableClientLimits } from "../v4/runtime/clientSessionSpec.js";
import { ServerAdmissionExchange, serverAdmissionCharge } from "../v4/runtime/serverAdmission.js";
import { reliableServerSpec } from "../v4/runtime/serverSessionSpec.js";
import { requireCredential } from "../v4/runtime/credentialSupport.js";
import { maxTime } from "../v4/runtime/timeArithmetic.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { observeTask } from "../v4/runtime/taskObservation.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { NativeProviderPositions } from "../v4/runtime/nativeProviderPositions.js";
import { SQLiteAdmissionStore } from "./sqliteAdmission.js";
import { NodeRawQUICCarrier, captureNodeRawQUIC, nodeRawQUICAdmissionCosts, type NodeRawQUICOptions, nativeRawQUICQueueBytes } from "./rawQUICCurrent.js";
import { loadCurrentNativeTransport, loadCurrentNativeWebTransport, bindCurrentNativeListener, type NativeRawListener, type NativeRawSession, type NativeOperation, type NativePreparationLimits } from "./nativeTransportCurrent.js";

import { readRelayEnvelope } from "./relayNativePair.js";
import { wire } from "../v4/runtime/wireRegistry.js";

export interface NodeRawQUICListenerOptions {
  readonly path?: "direct" | "tunnel";
  readonly host: string;
  readonly port: number;
  readonly serverName: string;
  readonly tls: Readonly<{ certificateChainDER: readonly Uint8Array[]; privateKeyDER: Uint8Array }>;
  readonly identityKey: KeyObject;
  readonly noiseKey: KeyObject;
  readonly admissionStore: SQLiteAdmissionStore;
  readonly credentials: Readonly<{ source: "preauthorized_pool" | "live_authority"; policy: V4CredentialPolicy;
    resolve(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, buffers: V4CredentialBuffers): Promise<V4CredentialLengths>;
    /** Transfers the exact server-local original prepared material once. */
    takePreparedHop?(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>): Promise<V4EnvironmentMaterial>;
    resolveHop?(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, buffers: V4CredentialBuffers): Promise<V4CredentialLengths> }>;
  readonly limits: ReliableClientLimits;
  readonly ingress: ServeGroupLimits;
  /** Trusted local network Prepare capacity for each independent incoming
   * connection. Defaults to 1 MiB of input, one address and 4096 work units.
   * This ends before HELLO/HOP and never inherits remote Route/Grant quotas. */
  readonly incomingPreparationCapacity?: NativePreparationLimits;
  readonly carrier: NodeRawQUICOptions;
  readonly bindingMode?: "direct_exporter" | "authenticated_context";
}
export interface NodeRawQUICListener {
  readonly listener: ServeListener<HandlerPlan>;
  address(): Readonly<{ host: string; port: number }>;
}
interface Entry {
  readonly raw: NativeRawSession;
  readonly ingress: ServeIngress<HandlerPlan>;
  readonly transport: NodeRawQUICCarrier;
  readonly custody: ResourceReference;
}
/** One actual current native listener, with finite preauth/READY positions and
 * original TLS, stream, application lease and release custody through exit. */
export function createNodeRawQUICListener(environment: V4TransportEnvironment, input: NodeRawQUICListenerOptions): NodeRawQUICListener {
  const runtime = originalEnvironment(environment), runtimeBytes = runtime.resources.runtimeBytes;
  const requestedPreparation = input.incomingPreparationCapacity;
  requireCredential(requestedPreparation === undefined || requestedPreparation !== null && typeof requestedPreparation === "object", "configuration_capacity");
  const incomingPreparationCapacity = Object.freeze({ preauthInputBytes: requestedPreparation === undefined ? 1048576 : requestedPreparation.preauthInputBytes,
    addressAttempts: requestedPreparation === undefined ? 1 : requestedPreparation.addressAttempts,
    workUnits: requestedPreparation === undefined ? 4096 : requestedPreparation.workUnits });
  requireCredential([incomingPreparationCapacity.preauthInputBytes, incomingPreparationCapacity.addressAttempts, incomingPreparationCapacity.workUnits]
    .every(value => Number.isSafeInteger(value) && value > 0 && value <= 0xffffffff), "configuration_capacity");
  const host = input.host, port = input.port, serverName = input.serverName, identityKey = input.identityKey, noiseKey = input.noiseKey;
  const certificateChain = input.tls.certificateChainDER.map(bytes => new Uint8Array(bytes)), privateKeyDER = new Uint8Array(input.tls.privateKeyDER);
  const store = input.admissionStore, limits = captureReliableClientLimits(input.limits), ingress = Object.freeze({ ...input.ingress }), carrier = captureNodeRawQUIC(input.carrier);
  const source = input.credentials.source, provider = input.credentials.resolve, hopProvider = input.credentials.resolveHop, preparedProvider = input.credentials.takePreparedHop, p = input.credentials.policy, path = input.path ?? (p.tunnel === undefined ? "direct" : "tunnel");
  const policy = Object.freeze({ tenant: p.tenant, audience: p.audience, clientSubject: p.clientSubject, serverSubject: p.serverSubject,
    authorities: Object.freeze([...p.authorities]), cryptoProfiles: Object.freeze([...p.cryptoProfiles]), ...(p.tunnel === undefined ? {} : { tunnel: Object.freeze({ ...p.tunnel }) }) });
  const bindingMode = input.bindingMode ?? "authenticated_context";
  requireCredential(isIP(host) !== 0 && Number.isSafeInteger(port) && port >= 0 && port <= 65535 && typeof serverName === "string" && serverName.length > 0 && serverName.length <= 253 &&
    certificateChain.length >= 1 && certificateChain.length <= 16 && certificateChain.every(bytes => bytes.length > 0 && bytes.length <= 65536) &&
    certificateChain.reduce((n, bytes) => n + bytes.length, 0) <= 262144 && privateKeyDER.length > 0 && privateKeyDER.length <= 16384 &&
    identityKey instanceof KeyObject && identityKey.type === "private" && identityKey.asymmetricKeyType === "ed25519" && noiseKey instanceof KeyObject && noiseKey.type === "private" &&
    ["x25519", "ec"].includes(noiseKey.asymmetricKeyType ?? "") && store instanceof SQLiteAdmissionStore && typeof provider === "function" &&
    (source === "preauthorized_pool" || source === "live_authority") && (bindingMode === "direct_exporter" || bindingMode === "authenticated_context"), "configuration_capacity");
  for (const value of [limits.maxFrame, limits.maxStreams, limits.receiveQueueBytes, limits.maxDataBytes, limits.maxCursorBytes, limits.maxWriteBytes, limits.cryptoKeys])
    requireCredential(Number.isSafeInteger(value) && value > 0 && value <= 16777216, "configuration_capacity");
  for (const value of [limits.writeDeadlineMS, limits.operationDeadlineMS, limits.rekeyPrepareMS, limits.rekeyProtocolMS, limits.rekeyConfirmationMS])
    requireCredential(typeof value === "bigint" && value > 0n && value <= 0xffffffffffffffffn, "configuration_capacity");
  requireCredential(path === "direct" ? policy.tunnel === undefined : path === "tunnel" && policy.tunnel?.role === 1 && (typeof hopProvider === "function" || typeof preparedProvider === "function") && bindingMode === "authenticated_context", "configuration_capacity");
  const maximum = Math.min(limits.maxStreams, 1024);
  requireCredential(limits.receiveQueueBytes >= limits.maxDataBytes && limits.cryptoKeys <= 65536 &&
    carrier.applicationStreams >= maximum + Math.min(128, Math.max(4, maximum)) + 1, "configuration_capacity");
  const leaf = new X509Certificate(certificateChain[0]!), costs = nodeRawQUICAdmissionCosts(limits.maxFrame, carrier, runtimeBytes);
  let address: Readonly<{ host: string; port: number }> | undefined;
  const listener = createServeListener<HandlerPlan>({ environment, carrier: "raw_quic", async start(callbacks, maintenanceOwner, signal) {
    const group = new ServeGroup(runtime, ingress, callbacks, signal);
    const entries = new Set<Entry>(), retiring = new Set<NativeRawSession>();
    let dependency: EnvironmentDependency | undefined, native: NativeRawListener | undefined, accept: NativeOperation<NativeRawSession> | undefined;
    let sealed = false, binding = true, nativeEnded = false, accepting = false, retired = false;
    let bindingTask: Promise<NativeRawListener> | undefined;
    let signingPublic = new Uint8Array(), noisePrivate = new Uint8Array();
    const acceptor = new Uint8Array(16); runtime.fillRandom(acceptor);
    const collect = (): void => {
      if (retired || !sealed || binding || accepting || !nativeEnded) return;
      group.listenerCoreEnded();
      if (entries.size !== 0 || retiring.size !== 0) return;
      retired = true; signingPublic.fill(0); noisePrivate.fill(0); acceptor.fill(0);
      for (const bytes of certificateChain) bytes.fill(0); privateKeyDER.fill(0);
      for (const bytes of carrier.trustRootsDER ?? []) bytes.fill(0);
      dependency?.release(); dependency = undefined; native = undefined; group.listenerEnded();
    };
    const seal = (): void => {
      if (sealed) return; sealed = true; accept?.cancel(); native?.stopAcceptingCurrent(); collect();
    };
    group.bindListener(seal, () => { native?.abort(); for (const entry of Array.from(entries)) entry.ingress.abort(); });
    try {
      // Pending original owners and admitted original owner histories remain
      // prepaid until their actual native tails and listener custody end.
      const incomingBudgetBytes = 65536n * BigInt(2 * ingress.positions);
      dependency = runtime.admitDependency("raw_quic_listener", new ResourceVector([524288n + runtimeBytes + BigInt(ingress.positions) * 128n,
        carrier.providerRuntimeBytes * BigInt(ingress.positions + 1) + nativeRawQUICQueueBytes(carrier) * BigInt(ingress.positions) + incomingBudgetBytes, 0n, BigInt(ingress.positions + 8), 4n, 4n, 1n, 0n, 0n, 0n, 1n]));
      dependency.onClose(() => group.close()); group.checkIngress();
      const driver = carrier.nativeCarrier === "webtransport" ? loadCurrentNativeWebTransport() : loadCurrentNativeTransport(), identityJWK = createPublicKey(identityKey).export({ format: "jwk" }), noiseJWK = noiseKey.export({ format: "jwk" });
      requireCredential(typeof driver.createPreparationBudget === "function", "configuration_capacity");
      requireCredential(identityJWK.crv === "Ed25519" && typeof identityJWK.x === "string" && typeof noiseJWK.d === "string" && ["X25519", "P-256"].includes(noiseJWK.crv ?? ""), "configuration_capacity");
      signingPublic = new Uint8Array(Buffer.from(identityJWK.x, "base64url")); noisePrivate = new Uint8Array(Buffer.from(noiseJWK.d, "base64url")); noiseJWK.d = "";
      const signer = Object.freeze({ publicKey: signingPublic, sign: (bytes: Uint8Array): Uint8Array => { dependency!.check(); return new Uint8Array(sign(null, bytes, identityKey)); } });
      group.checkIngress(); dependency.check();
      bindingTask = bindCurrentNativeListener(driver, { host, port, path, certificateChainDer: certificateChain, privateKeyDer: privateKeyDER,
        inboundBidirectionalStreamCapacity: carrier.applicationStreams + 1, readBufferBytes: Math.min(16384, carrier.streamBufferBytes), datagramQueueBytes: 65536,
        handshakeTimeoutMs: Number(ingress.handshakeMS), pendingConnections: ingress.positions, incomingPreparationCapacity }, serverName, carrier.webTransport).then(value => {
          native = value;
          void value.waitTermination().then(() => { nativeEnded = true; if (!sealed) group.close(); collect(); }, () => { group.close(); });
          if (group.closing) value.abort();
          else if (sealed) value.stopAcceptingCurrent();
          return value;
        }, error => { nativeEnded = true; group.close(); throw error; }).finally(() => { binding = false; collect(); });
      // Public cancellation observes this task; the original bind continuation
      // retains infrastructure until a late native listener actually exits.
      await observeTask(bindingTask, signal);
      requireCredential(native !== undefined, "credential_binding");
      const endpoint = native.address(); requireCredential(endpoint.host === host && Number.isSafeInteger(endpoint.port) && endpoint.port > 0 && endpoint.port <= 65535 && (port === 0 || endpoint.port === port), "credential_binding");
      address = Object.freeze({ host: endpoint.host, port: endpoint.port });
      group.checkIngress();
      const run = async (entry: Entry): Promise<void> => {
        let exchange: ServerAdmissionExchange | undefined, material: V4EnvironmentMaterial | undefined, plan: ReturnType<typeof captureHandlerPlan> | undefined;
        let work: ReturnType<typeof runtime.reserveConnectionWork> | undefined, prepared: ReturnType<typeof runtime.prepareTunnelCredentials> | undefined;
        let buffers: V4CredentialBuffers | undefined;
        try {
          entry.ingress.check(); await entry.ingress.authorizeRequest(""); entry.ingress.check();
          await entry.transport.accept(entry.raw, { host: serverName, port: address!.port, leaf }, entry.ingress.signal);
          entry.ingress.check();
          work = runtime.reserveConnectionWork("server_material_input", new ResourceVector([(path === "direct" ? 278528n : 344080n) + runtimeBytes, 0n, 0n, 8n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
          buffers = { artifact: new Uint8Array(65536), clientCertificate: new Uint8Array(16384), serverCertificate: new Uint8Array(16384), activation: new Uint8Array(65536), tunnelGrant: new Uint8Array(65536), relayCertificate: new Uint8Array(16384) };
          if (path === "tunnel" && preparedProvider === undefined) prepared = runtime.prepareTunnelCredentials(policy);
          const verifyMaterial = (lengths: V4CredentialLengths): V4EnvironmentMaterial => {
            for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation", "tunnelGrant", "relayCertificate"] as const) {
              const length = lengths[name] ?? 0; requireCredential(Number.isSafeInteger(length) && length >= 0 && length <= buffers![name].length, "credential_binding");
            }
            return runtime.verify(policy, { source, artifact: buffers!.artifact.subarray(0, lengths.artifact), clientCertificate: buffers!.clientCertificate.subarray(0, lengths.clientCertificate),
              serverCertificate: buffers!.serverCertificate.subarray(0, lengths.serverCertificate), activation: buffers!.activation.subarray(0, lengths.activation), candidateIndex: lengths.candidateIndex,
              ...(path === "direct" ? {} : { tunnel: { grant: buffers!.tunnelGrant.subarray(0, lengths.tunnelGrant ?? 0), relayCertificate: buffers!.relayCertificate.subarray(0, lengths.relayCertificate ?? 0) } }) }, prepared);
          };
          if (path === "tunnel") {
            const routing = new Uint8Array(65544);
            try {
              const count = await readRelayEnvelope(entry.transport, routing, () => entry.ingress.check(), entry.ingress.signal); requireCredential(count !== null && routing[4] === wire.frame_types.HOP_AUTH);
              const hello = routing.subarray(8, count), request = Object.freeze({ signal: entry.ingress.signal, hello });
              if (preparedProvider === undefined) { const lengths = await entry.ingress.resolveMaterial(() => hopProvider!(request, buffers!)); material = verifyMaterial(lengths); }
              else {
                // Capture custody before the ingress checks cancellation again.
                material = await entry.ingress.resolveMaterial(async () => {
                  const original = await preparedProvider(request); material = original; return original;
                });
                runtime.checkOriginalServerPublication(material, work);
              }
              await runtime.authenticateAcceptedHop(material, entry.transport, signer, hello, { signal: entry.ingress.signal });
            } finally { routing.fill(0); }
          }
          const ref = runtime.reserveConnectionWork("server_admission", serverAdmissionCharge(runtimeBytes));
          try { exchange = new ServerAdmissionExchange(runtime.resources, entry.transport, signer, bytes => runtime.fillRandom(bytes), ref, () => entry.ingress.check(), bindingMode); }
          finally { ref.release(); }
          const hello = await exchange.readHello({ signal: entry.ingress.signal }), destination = buffers;
          if (material === undefined) {
            const lengths = await entry.ingress.resolveMaterial(() => provider(Object.freeze({ signal: entry.ingress.signal, hello }), destination));
            material = verifyMaterial(lengths);
          }
          const invocation = new Uint8Array(16), carrierID = new Uint8Array(16); runtime.fillRandom(invocation); runtime.fillRandom(carrierID);
          try {
            const session = await runtime.establishServer(material, async fields => {
              const authentication = exchange!.requestContext(), selected = await entry.ingress.authorize(authentication);
              plan = captureHandlerPlan(selected, runtime, maintenanceOwner); entry.ingress.check();
              requireCredential(fields.maxFrame <= limits.maxFrame && fields.rpcMaxGeneralOutstanding <= (limits.maxGeneralOutstanding ?? 1024) &&
                limits.maxDataBytes + 41 <= fields.maxFrame && BigInt(limits.receiveQueueBytes) <= fields.maxCredit &&
                (fields.profile.includes("x25519") ? noiseJWK.crv === "X25519" : noiseJWK.crv === "P-256"), "configuration_capacity");
              return { ...reliableServerSpec(fields, entry.transport, signer, noisePrivate, limits, runtimeBytes, plan.application, plan.profile === "transport" ? "services" : plan.profile),
                initialRawStreams: plan.raw, claimReadySession: session => entry.ingress.claim(session) };
            }, exchange, store, { acceptor, invocation, carrier: carrierID, generation: 1n, signal: entry.ingress.signal }, { signal: entry.ingress.signal })
              .finally(() => entry.ingress.publishClaimed());
            await session.waitTermination();
          } finally { invocation.fill(0); carrierID.fill(0); }
        } finally {
          prepared?.close(); plan?.release(); exchange?.close(); await material?.closeMaterial();
          if (buffers !== undefined) for (const bytes of Object.values(buffers)) bytes.fill(0); work?.release();
        }
      };
      const admit = (raw: NativeRawSession): void => {
        // Rejected native sessions still borrow the listener's pending native
        // capacity until actual termination, including pre-admission refusal.
        retiring.add(raw);
        let custody: ResourceReference | undefined;
        let accepted: ReturnType<typeof runtime.admitDependencyPositions> | undefined, ingressOwner: ServeIngress<HandlerPlan> | undefined, transport: NodeRawQUICCarrier | undefined;
        try {
          group.checkIngress(); requireCredential(typeof raw.completePreparation === "function", "configuration_capacity");
          accepted = runtime.admitDependencyPositions("accepted_raw_quic", costs[0]![1], costs[1]![1], carrier.applicationStreams + 1);
          custody = accepted.dependency.reference.borrow();
          ingressOwner = group.begin(() => { raw.abort(); void transport?.close(); });
          transport = new NodeRawQUICCarrier(runtime, accepted.dependency, new NativeProviderPositions(accepted.positions), carrier,
            TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), ingress.handshakeMS, maxTime), "server", path);
          const entry: Entry = { raw, ingress: ingressOwner, transport, custody }; entries.add(entry); retiring.delete(raw);
          const job = run(entry);
          void job.catch(() => entry.ingress.abort()).finally(async () => {
            raw.abort(); await raw.waitTermination(); await entry.transport.close(); entry.custody.release(); entry.ingress.nativeEnded(); await entry.ingress.finish(); entries.delete(entry); collect();
          }).catch(() => { entry.ingress.abort(); group.close(); });
        } catch {
          raw.abort(); ingressOwner?.abort();
          void raw.waitTermination().then(async () => {
            if (transport !== undefined) await transport.close();
            else if (accepted !== undefined) { for (const position of accepted.positions) position.closeAfterUse(); accepted.dependency.release(); }
            custody?.release(); ingressOwner?.nativeEnded(); await ingressOwner?.finish(); retiring.delete(raw); collect();
          }).catch(() => group.close());
        }
      };
      const pump = async (): Promise<void> => {
        accepting = true;
        try {
          while (!sealed) {
            group.checkIngress(); dependency!.check();
            const operation = accept = native!.accept();
            let raw: NativeRawSession;
            try { raw = await operation.result(); }
            catch (error) {
              // Only the original accept's expected seal cancellation ends
              // ingress normally. Native failures still close the group.
              if (sealed && error instanceof Error && (error.message === "canceled" || error.message === "listener_closed")) break;
              throw error;
            } finally { accept = undefined; }
            if (sealed) { retiring.add(raw); raw.abort(); await raw.waitTermination(); retiring.delete(raw); break; }
            admit(raw);
          }
        } catch { group.close(); }
        finally { accept = undefined; accepting = false; collect(); }
      };
      binding = false; void pump(); group.checkIngress(); return createServeHandle(group);
    } catch {
      group.close();
      if (bindingTask === undefined) { binding = false; nativeEnded = true; }
      collect(); throw new ServeError(signal?.aborted ? "canceled" : "serve_failed", group.cleanupStatus());
    } finally { collect(); }
  } });
  return Object.freeze({ listener, address: () => { if (address === undefined) throw new Error("not_listening"); return address; } });
}
