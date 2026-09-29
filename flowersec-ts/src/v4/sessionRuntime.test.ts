import type * as ServiceClientTypes from "./serviceClient.js";
import type * as StreamingOperationTypes from "./streamingOperation.js";
import type * as ServiceBindingPoolTypes from "./runtime/serviceBindingPool.js";
import type * as QueryRenewalPositionTypes from "./runtime/queryRenewalPosition.js";
import type * as UnaryOperationTypes from "./unaryOperation.js";
import type * as ServiceHandlersTypes from "./serviceHandlers.js";
import type * as StreamHandlersTypes from "./streamHandlers.js";
import type * as ResumeTypes from "./resume.js";
import type * as PublicTypes from "./public.js";
import { createV4ServiceClient } from "./serviceFactory.js";
import { captureServiceBinding } from "./runtime/serviceBindingConfig.js";
import type { ServiceBindingReservation } from "./runtime/serviceBindingPool.js";
import { v4ServiceDependency } from "./serviceDependencies.js";
import { createV4ConnectionController } from "./controller.js";
import { wrapCredentialSource, wrapTransportEnvironment, type V4EnvironmentMaterial } from "./runtime/environment.js";
import { createMaintenanceOwner, type V4MaintenanceOwner, type V4ResponsePublication } from "./responsePublication.js";
import { saveV4StreamContent, readV4RetainedContent, type V4ContentObservation } from "./streamContent.js";
import { v4RecoveryProgress } from "./resume.js";
import { RPCStreamMessages, rpcStreamMessagesCharges } from "./runtime/rpcStreamMessages.js";
import { applicationGroup } from "./runtime/applicationExecutor.js";
import { createHash, createHmac, createPublicKey, verify as verifySignature } from "node:crypto";
import { issueV4Checkpoint } from "./checkpoint.js";
import { applicationResumeFeature } from "./runtime/checkpointToken.js";
import { operationReferenceState } from "./operationReference.js";
import { v4BytesMessageCodec } from "./messageDefinition.js";
import { v4ByteEventSource, type V4ByteEventPublisher } from "./eventSource.js";
import { applicationHasPermit, applicationWorkload } from "./runtime/applicationExecutor.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import type { V4NotificationSubscription } from "./notificationSubscription.js";
import { createStaticServiceContracts, type V4StaticServiceContracts } from "./staticServiceContracts.js";
import { DatabaseSync } from "node:sqlite";
import { openV4SQLiteExecutionStore, type V4SQLiteExecutionStore } from "../node/sqliteExecutionV4.js";
import { createOperationReferenceStore, type V4OperationReferenceStore } from "./operationReferenceStore.js";
import { createOperationReferenceCodec } from "./operationReferenceCodec.js";
import { V4ExecutionStreamingOperation } from "./streamingOperation.js";
import { V4ExecutionNotifyOperation } from "./notificationOperation.js";
import { V4ExecutionUnaryOperation } from "./unaryOperation.js";
import { CBORDecoder, cborDecoderCharge } from "./runtime/cbor.js";
import { V4Session } from "./public.js";
import { V4MethodDefinition, V4ServiceDefinition } from "./serviceDefinition.js";
import { V4ServiceError } from "./serviceHandlers.js";
import { v4ApplicationMessageCodec, v4UTF8MessageCodec } from "./messageDefinition.js";
import type { RPCApplicationConfig } from "./runtime/rpcApplication.js";
import { AdmissionOffer, ServiceContractSnapshot, serviceContractCharge, serviceContractDecoderCharge } from "./runtime/serviceContract.js";
import { createStreamMetadataEnvelope } from "../public/streamMetadata.js";
import { asNodeDuplex } from "../node/streamDuplexV4.js";
import { asWebStreams } from "./webStreams.js";
import { credentialFixture, encode, map, text, u, bytes, fill, digest, sign, array, replace } from "./testSupport/credentials.js";
import { createSQLitePoolBacking, openV4SQLitePoolStore } from "../node/sqlitePoolV4.js";
import type { PoolSpendStore } from "./runtime/poolSpend.js";
import type { ActivationSource } from "./runtime/credentialVerifier.js";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it, vi } from "vitest";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import type { OperationOptions } from "../public/contract.js";
import { TrustedDeadline } from "./runtime/deadline.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { type OpenAdmissionConfig } from "./runtime/openAdmission.js";
import { inspectEnvelopePrefix, inspectRecordPrefix } from "./runtime/envelope.js";
import { wire } from "./runtime/wireRegistry.js";
import type { V4AuthenticatedSessionRuntime, V4AuthenticatedTransport } from "./runtime/session.js";
import { V4EnvironmentRuntime, type V4EnvironmentSessionSpec } from "./runtime/environment.js";

async function transportEvent(event: Promise<void>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([event, new Promise<void>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("transport_event_timeout")), 2000); })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

class MemoryTransport implements V4AuthenticatedTransport {
  readonly createdAtMS = performance.now();
  peer!: MemoryTransport;
  readonly queue: Uint8Array[] = [];
  waiter: ((bytes: Uint8Array | null) => void) | undefined;
  ended = false;
  completionDelayMS = 0;
  submissionTail: ((bytes: Uint8Array) => Promise<void> | undefined) | undefined;
  deferDelivery: ((bytes: Uint8Array) => boolean) | undefined;
  #readMax = 0;
  #spaceWaiter: (() => void) | undefined;
  #hold: Promise<void> | undefined;
  done!: () => void;
  readonly termination = new Promise<void>(resolve => { this.done = resolve; });
  constructor(readonly role: "client" | "server", readonly mode: "message" | "stream") {}
  #take(max: number): Uint8Array {
    const first = this.queue[0]!, size = this.mode === "message" ? first.length : Math.min(max, 17, first.length);
    if (size === first.length) {
      this.queue.shift(); const space = this.#spaceWaiter; this.#spaceWaiter = undefined; space?.(); return first;
    }
    this.queue[0] = first.subarray(size); return first.subarray(0, size);
  }
  read(max: number, options?: OperationOptions): Promise<Uint8Array | null> {
    if (this.queue.length !== 0) return Promise.resolve(this.#take(max));
    if (this.ended || options?.signal?.aborted) return Promise.resolve(null);
    return new Promise(resolve => { this.#readMax = max; this.waiter = resolve; });
  }
  push(bytes: Uint8Array): void {
    if (this.peer.ended) throw new Error("closed");
    const copy = new Uint8Array(bytes), waiter = this.peer.waiter;
    if (this.deferDelivery?.(copy)) return;
    if (this.peer.queue.length === 4) throw new Error("test carrier queue full"); this.peer.queue.push(copy);
    if (waiter !== undefined) { this.peer.waiter = undefined; waiter(this.peer.#take(this.peer.#readMax)); }
  }
  #waitCapacity(): Promise<void> {
    // Completion retains backpressure until this bounded carrier can accept
    // the next frame. Control bursts do not imply a transport failure.
    return this.peer.queue.length < 4 ? Promise.resolve() : new Promise(resolve => { this.peer.#spaceWaiter = resolve; });
  }
  write(bytes: Uint8Array): Promise<number> {
    const count = this.mode === "message" ? bytes.length : Math.min(23, bytes.length);
    this.push(bytes.subarray(0, count)); return this.#waitCapacity().then(() => count);
  }
  holdNext(): () => void {
    let release!: () => void;
    this.#hold = new Promise<void>(resolve => { release = resolve; }); return release;
  }
  submit(bytes: Uint8Array, admitted: () => void): { completion: Promise<void> } | undefined {
    if (this.ended || this.peer.ended) return undefined; admitted(); this.push(bytes);
    const observed = this.submissionTail?.(bytes);
    const completion = this.#hold ?? observed ?? (this.completionDelayMS === 0 ? Promise.resolve() : new Promise<void>(resolve => setTimeout(resolve, this.completionDelayMS)));
    this.#hold = undefined; return { completion: Promise.all([completion, this.#waitCapacity()]).then(() => undefined) };
  }
  close(): Promise<void> {
    this.ended = true; this.waiter?.(null); this.waiter = undefined; this.#spaceWaiter?.(); this.#spaceWaiter = undefined; this.done(); return Promise.resolve();
  }
  waitTermination(): Promise<void> { return this.termination; }
}
function endpoint(role: "client" | "server", transport: MemoryTransport, profile: "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" | "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1", source: ActivationSource = "live_authority", operationDeadlineMS = 1000n, services?: (environment: V4EnvironmentRuntime, material: ReturnType<typeof credentialFixture>) => RPCApplicationConfig,
  serviceOptions: { resourceAccounts?: number; sessions?: number; sessionNotAfterMS?: number; resume?: boolean; writeDeadlineMS?: bigint; profile?: "services" | "execution"; operationEntropy?: Uint8Array; environment?: V4EnvironmentRuntime; clockOriginMS?: number; clockMS?: () => bigint; clientSubject?: string; authorizedClientSubjects?: readonly string[]; connectionSeed?: number } = {}) {
  const limit = new ResourceVector([512n * 1024n * 1024n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  // Include Session/Environment accounts and all 13 protected direction positions.
  const root = serviceOptions.environment?.resources.root ?? new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: serviceOptions.resourceAccounts ?? (services === undefined ? 16 : 32), reservations: services === undefined ? 200 : 2000, references: services === undefined ? 400 : 4000,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const start = performance.now();
  const serviceOrigin = services === undefined ? undefined : (serviceOptions.clockOriginMS ?? Math.min(transport.createdAtMS, transport.peer.createdAtMS));
  const environment = serviceOptions.environment ?? new V4EnvironmentRuntime({ root, tenantID: "1".repeat(32), environmentID: "2".repeat(32), tenantLimit: limit, limit,
    runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: serviceOptions.sessions ?? 1, sessions: serviceOptions.sessions ?? 1, acquireMS: 10000n, cleanupMS: 25,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: serviceOptions.clockMS?.() ?? BigInt(Math.floor(performance.now() - start)), incarnation: "3".repeat(32) }), initial: () => {
        // Service peers model the same UTC instant despite separate setup work.
        const elapsed = serviceOptions.clockMS?.() ?? (serviceOrigin === undefined ? 0n : BigInt(Math.floor(performance.now() - serviceOrigin)));
        return { lowerMS: 1000n + elapsed, upperMS: 1000n + elapsed + (serviceOrigin === undefined ? 0n : 1n) };
      } },
    random: bytes => {
      // Deliberate test-only operation ID collision exercises the real join gate.
      if (bytes.length === 24 && serviceOptions.operationEntropy !== undefined) bytes.set(serviceOptions.operationEntropy);
      else crypto.getRandomValues(bytes);
    } });
  const clock = environment.clock, direction = role === "client" ? 0 : 1;
  const namespace = environment.namespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
    maxTrustLifetimeMS: 120000n, bootstrapMS: 10000n, stateBytes: 8192, stateNodes: 16384 });
  const material = credentialFixture(environment.resources, clock, () => { throw new Error("all reservations belong to Environment"); }, source, profile, namespace, { ...serviceOptions, ...(services === undefined ? {} : { applicationProfile: serviceOptions.profile ?? "services" }) });
  const application = services?.(environment, material);
  if (serviceOptions.environment === undefined) material.bootstrap();
  const credentials = environment.verify({ ...material.config, authorities: ["authority"] }, material.input());
  const execution = application !== undefined && serviceOptions.profile === "execution";
  const limits: OpenAdmissionConfig = { direction, maxActive: 8, maxPending: 8, ingressItems: 4, ingressBytes: 16384, terminalCapacity: 32, rejectionReserve: 4,
    runtimeBytes: 1024n, perClass: [8, application === undefined ? 0 : 8, execution ? 1 : 0], perOpener: [[8, application === undefined ? 0 : 8, execution ? 1 : 0], [8, application === undefined ? 0 : 8, 0]], protected: [[0, application === undefined ? 0 : 1, execution ? 1 : 0], [0, 0, 0]] };
  const features = serviceOptions.resume ? applicationResumeFeature() : 0n;
  const context = map({ 0: text("4"), 1: text(profile), 2: u(0), 3: u(0), 4: bytes(digest("artifact_digest", material.artifact)), 5: bytes(material.route), 6: bytes(material.attemptID),
    7: bytes(material.sessionNonce), 8: bytes(fill(28)), 9: u(features), 10: u(1), 11: u(0), 12: bytes(new Uint8Array()) });
  const contextDigest = digest("transport_context_digest", context);
  const fsb = sign("FSB4", map({ 0: bytes(digest("artifact_digest", material.artifact)), 1: text("tenant"), 2: bytes(fill(5, 16)), 3: bytes(material.leaseID), 4: bytes(material.sessionNonce),
    5: bytes(fill(20, 16)), 6: bytes(material.route), 7: bytes(material.attemptID), 8: bytes(fill(26)), 9: bytes(fill(28)), 10: u(features), 11: u(1), 12: bytes(contextDigest),
    13: bytes(encode(material.activation)), 14: bytes(encode(material.client)) }), 14);
  const admission = digest("admission_binding", fsb), clientDigest = digest("certificate_digest", material.client), serverDigest = digest("certificate_digest", material.server);
  const fsa = sign("FSA4", map({ 0: u(0), 1: u(0), 2: u(1), 3: bytes(fill(27)), 4: bytes(admission), 5: bytes(material.route), 6: bytes(fill(28)), 7: u(features), 8: u(1), 9: bytes(contextDigest),
    10: bytes(clientDigest), 11: bytes(serverDigest), 12: bytes(encode(material.server)) }), 15);
  const seed = fill(role === "client" ? 14 : 15), peerSeed = fill(role === "client" ? 15 : 14);
  const cs = fill(16), ss = fill(17);
  const publicKey = (secret: Uint8Array) => profile.includes("x25519") ? x25519.getPublicKey(secret) : p256.getPublicKey(secret, false);
  const ready = { localCertificateDigest: role === "client" ? clientDigest : serverDigest, peerCertificateDigest: role === "client" ? serverDigest : clientDigest,
    fsbDigest: digest("fsb_digest", fsb), fsaDigest: digest("fsa_digest", fsa), admissionBinding: admission, transportContextDigest: contextDigest, selectedFeatures: features };
  const config: V4EnvironmentSessionSpec = {
    ...(application === undefined ? {} : { application }),
    transport, maxFrame: 65536, maxReceiveDirections: 8,
    crypto: { keys: 100, maintenance: { calls: 10n, blocks: 100n, bytes: 10000n } },
    noise: { authorizationDeadline: new TrustedDeadline(clock, BigInt(serviceOptions.sessionNotAfterMS ?? 30000)), preparationDeadline: new TrustedDeadline(clock, 10000n), profile, role,
      localStaticPrivate: role === "client" ? cs : ss, localStaticPublic: publicKey(role === "client" ? cs : ss), peerStaticPublic: publicKey(role === "client" ? ss : cs),
      psk: fill(24),
      contextDigest, fsb: encode(fsb), fsa: encode(fsa) },
    signer: { publicKey: ed25519.getPublicKey(seed), sign: bytes => ed25519.sign(bytes, seed) }, ready, peerReadyPublicKey: ed25519.getPublicKey(peerSeed),
    streams: { limits,
      ...(application === undefined ? {} : { rpcMaxGeneralOutstanding: 4 }),
      receive: { maxDataBytes: 128, queueBytes: application === undefined ? 256 : 16384, maxCursorBytes: application === undefined ? 1024 : 16384, receiveLimit: application === undefined ? 256n : 16384n, runtimeBytes: 1024n, cursorRuntimeBytes: 1024n, decoderRuntimeBytes: 1024n },
      maxWriteBytes: application === undefined ? 1024 : 16384, writeDeadlineMS: serviceOptions.writeDeadlineMS ?? 1000n, operationDeadlineMS, rekeyBurst: 10n, rekeyRefillMS: 1000n, rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n },
    info: { application_profile: application === undefined ? "transport" : serviceOptions.profile ?? "services", selected_features: features, guarantees: { reliable_progress: "shared_ordered", bound_stream_input_isolation: "shared_failure_scope",
      datagram: false, local_consumer_tls13_verification: "not_applicable", scope: "complete_direct_path", assumptions: "authenticated_peer_within_transport_profile" } },
  };
  return { config, material, environment, discardPrepared: () => credentials.closeMaterial(), establishMaterial: (acquired: V4EnvironmentMaterial, signal?: AbortSignal) => environment.establishVerified(acquired, config, encode(context), signal === undefined ? undefined : { signal }), establish: (store?: PoolSpendStore) => store === undefined ? environment.establishVerified(credentials, config, encode(context)) : environment.establishPoolVerified(credentials, config, encode(context), store), close: async () => {
    await environment.close(); expect((await environment.waitCleanup()).status).toBe("complete"); expect(root.snapshot().reservations).toBe(0);
  } };
}
describe("original v4 reliable Session assembly", () => {
  // The existing ten-second attempt and real setup/cleanup need a longer runner bound.
  it("initializes a Controller through required accepted streaming and notification paths", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const events = new V4MethodDefinition({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, maxItemCount: 2, maxStreamPayloadBytes: 256n, maxStreamDurationMS: 10000n, restartFlush: false });
    const changed = new V4MethodDefinition({ typeID: 44, shape: "notify", notifySemantics: "observation", request: codec,
      requestMaxBytes: 128, responseRevision: "none-v1", restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.initializer", methods: { events, changed } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const notifyContract = encode(map({ 0: text(definition.namespace), 1: u(44), 2: u(2), 5: u(0), 6: text("text-v1"), 7: text("none-v1"),
      8: u(0), 9: u(0), 10: u(0), 11: u(30000), 21: { kind: "bool", value: false }, 23: u(128), 27: array() }));
    const calls: string[] = [], notifications: string[] = [];
    let contract!: ServiceContractSnapshot;
    const client = endpoint("client", a, profile, "live_authority", 3000n, () => common); await client.discardPrepared();
    const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
      const r = environment.resources, refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
        accounts: r.accounts, owner: { ...r.owner, kind: `initializer_stream_contract_${index}` }, charge })));
      try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(1), 4: u(0),
        6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
        21: { kind: "bool", value: false }, 23: u(128), 24: u(2), 25: u(256), 26: u(10000), 27: array() })), 1024n, refs[0]!, refs[1]!); }
      finally { for (const ref of refs) ref.release(); }
      return { ...common, queryPermissions: [{ namespace: definition.namespace, method: events, permission: "allowed" }, { namespace: definition.namespace, method: changed, permission: "allowed" }],
        notificationMethods: [{ namespace: definition.namespace, method: changed, contract: notifyContract, permission: "allowed" }],
        streamingHandlers: [{ namespace: definition.namespace, method: events, kind: "example.initializer.events", contract,
          handler: async (_context, value: string, writer) => { calls.push(value); await writer.write(value + ":typed"); await writer.write(value + ":encoded"); },
          options: { workClass: "resident", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
    });
    let acquisitions = 0, peer: V4Session | undefined, subscription: V4NotificationSubscription<string> | undefined;
    const environment = client.environment;
    const source = wrapCredentialSource(environment.registerSource({ ...client.material.config, authorities: ["authority"] }, "live_authority", async (request, destination) => {
      expect(request.requirements).toEqual({ independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false, application_profile: "services" });
      acquisitions++; const input = client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(client.config), checkRequirements: requirements => {
      expect(requirements.application_profile).toBe("services");
    }, connect: async (material, options) => {
      const [runtime, remote] = await Promise.all([client.establishMaterial(material, options?.signal), server.establish()]);
      peer = new V4Session(remote); subscription = peer.notifications.subscribe(changed, (_context, value) => { notifications.push(value); },
        { workClass: "short", applicationBytes: 1024n, authorization: "authenticated" }); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
    const initial = v4ServiceDependency(definition, { binding: { target, maximumOfferWindowMS: 10000n,
      methods: [{ method: events, streamKind: "example.initializer.events" }] }, methods: { events, changed } });
    const controller = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
      initializeServices: { initial }, attemptTimeoutMS: 10000n, initializeApplicationBytes: 1024n,
      initializeSession: async (context, candidate) => {
        expect(await context.services.initial.changed("initializing")).toMatchObject({ submission: "submitted" });
        const stream = await context.services.initial.events("ready");
        try {
          const typed = await stream.readNext({ context }); expect(typed).toMatchObject({ kind: "value", value: "ready:typed" }); if ("release" in typed) typed.release();
          const encoded = await stream.readNextEncoded({ context }); expect(encoded).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("ready:encoded") }); if ("release" in encoded) encoded.release();
          expect(await stream.readNext({ context })).toMatchObject({ kind: "end", status: { state: "complete" } });
        } finally { stream.close(); }
        expect((await stream.waitCleanup({ context })).status).toBe("complete");
        await candidate.probeLiveness();
      } });
    try {
      const result = await controller.replaceSession(); expect(controller.captureSession()).toBe(result.current);
      expect(result.current.info().application_profile).toBe("services");
      expect(acquisitions).toBe(1); expect(calls).toEqual(["ready"]);
      await expect.poll(() => notifications).toEqual(["initializing"]);
    } finally {
      subscription?.close(); await controller.close(); expect((await controller.waitCleanup()).status).toBe("complete");
      await peer?.close(); contract.release(); await Promise.all([client.close(), server.close()]);
    }
  }, 15000);
  it("transfers Controller raw initializer reservations through authorization, bytes and Close", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile, "live_authority", 3000n), server = endpoint("server", b, profile, "live_authority", 3000n);
    await client.discardPrepared();
    const environment = client.environment;
    let limitedKeys = false;
    let acquisitions = 0, peer: V4Session | undefined, authorized = 0, handled = 0;
    const source = wrapCredentialSource(environment.registerSource({ ...client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      acquisitions++;
      expect(applicationWorkload(environment.resources.root)?.ordinaryRunning).toBe(0);
      const input = client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(limitedKeys ? { ...client.config, crypto: { ...client.config.crypto, keys: 6 } } : client.config), checkRequirements: () => undefined, connect: async (material, options) => {
      const [runtime, remote] = await Promise.all([client.establishMaterial(material, options?.signal), server.establish()]);
      peer = new V4Session(remote); return runtime;
    } });
    const requirements = { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false,
      local_consumer_tls13_verification: false, application_profile: "transport" as const };
    const oversized = createV4ConnectionController(wrapTransportEnvironment(environment), { source, requirements,
      initializeStreams: [{ kind: "example/raw", handler: () => undefined, options: { applicationBytes: 4096n, maxConcurrentStreams: 19 } }] });
    await expect(oversized.replaceSession()).rejects.toThrow(/resource_exhausted|would_block/);
    expect(acquisitions).toBe(0); await oversized.close(); await oversized.waitCleanup();
    const metadata = createStreamMetadataEnvelope("code/http_v1", 1, { method: new TextEncoder().encode(JSON.stringify("GET")) });
    const exchange = async () => {
      const out = await peer!.openStream("example/raw", { metadata });
      try {
        await peer!.rekey();
        await out.write(Uint8Array.of(7));
        expect((await out.read(1n)).data).toEqual(Uint8Array.of(8));
      } finally { await out.close(); }
    };
    const controller = createV4ConnectionController(wrapTransportEnvironment(environment), { source, requirements,
      attemptTimeoutMS: 10000n, initializeApplicationBytes: 1024n,
      initializeStreams: [{ kind: "example/raw", authorize: (context, value) => {
        expect(applicationHasPermit(context)).toBe(true); expect(value.descriptorValues()).toEqual({ method: "GET" }); authorized++; return true;
      }, handler: async (stream, context, value) => {
        expect(applicationHasPermit(context)).toBe(true); expect(value.descriptorValues()).toEqual({ method: "GET" });
        expect((await stream.read(1n)).data).toEqual(Uint8Array.of(7));
        await stream.write(Uint8Array.of(8)); handled++;
      }, options: { applicationBytes: 4096n, maxConcurrentStreams: 1, metadataContract: { contractID: "http-v1", namespace: "code/http_v1", version: 1,
        codec: "application/json", fields: [{ name: "method", type: "string", required: true }] } } }],
      initializeSession: async () => {
        expect(() => controller.captureSession()).toThrow("initialization_blocked");
        await exchange();
      } });
    try {
      // Memory capacity alone cannot promise future key counters. Both
      // directions reserve actual slots before source invocation.
      limitedKeys = true;
      await expect(controller.replaceSession()).rejects.toThrow("crypto_busy");
      expect(acquisitions).toBe(0);
      await expect.poll(() => controller.status().pending).toBe(false);
      limitedKeys = false;
      const result = await controller.replaceSession(); expect(controller.captureSession()).toBe(result.current);
      expect(acquisitions).toBe(1); expect(authorized).toBe(1); expect(handled).toBe(1);
      // Once the declared first work is consumed, normal Session admission
      // continues to own later calls and their actual cleanup.
      await exchange(); expect(authorized).toBe(2); expect(handled).toBe(2);
    } finally {
      await controller.close(); expect((await controller.waitCleanup()).status).toBe("complete");
      await peer?.close(); await Promise.all([client.close(), server.close()]);
    }
  });
  it("renews Controller accepted stream demand and notification routing on replacement", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const events = new V4MethodDefinition({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, maxItemCount: 2, maxStreamPayloadBytes: 256n, maxStreamDurationMS: 10000n, restartFlush: false });
    const changed = new V4MethodDefinition({ typeID: 44, shape: "notify", notifySemantics: "observation", request: codec,
      requestMaxBytes: 128, responseRevision: "none-v1", restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.controller.streams", methods: { events, changed } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const notificationContract = encode(map({ 0: text(definition.namespace), 1: u(44), 2: u(2), 5: u(0), 6: text("text-v1"), 7: text("none-v1"),
      8: u(0), 9: u(0), 10: u(0), 11: u(30000), 21: { kind: "bool", value: false }, 23: u(128), 27: array() }));
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const peers: V4Session[] = [], subscriptions: V4NotificationSubscription<string>[] = [], notifications: string[] = [], calls: string[] = [];
    const origin = performance.now(); let releaseOld!: () => void;
    const held = new Promise<void>(resolve => { releaseOld = resolve; });
    for (let i = 0; i < 2; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { sessions: 3, connectionSeed: 100 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, () => common,
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) }); await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
        const r = environment.resources, refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `controller_stream_contract_${index}` }, charge })));
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(1), 4: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 24: u(2), 25: u(256), 26: u(10000), 27: array() })), 1024n, refs[0]!, refs[1]!); }
        finally { for (const ref of refs) ref.release(); }
        return { ...common, queryPermissions: [{ namespace: definition.namespace, method: events, permission: "allowed" }, { namespace: definition.namespace, method: changed, permission: "allowed" }],
          notificationMethods: [{ namespace: definition.namespace, method: changed, contract: notificationContract, permission: "allowed" }],
          streamingHandlers: [{ namespace: definition.namespace, method: events, kind: "example.controller.events", contract,
            handler: async (_context, value: string, writer) => {
              calls.push(`${i}:${value}`); await writer.write(`${i}:${value}:typed`);
              if (value === "old") await held;
              await writer.write(`${i}:${value}:encoded`);
            }, options: { workClass: "resident", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment; let acquisitions = 0, selected = 0;
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(pairs[acquisitions]!.client.config), checkRequirements: () => undefined, connect: async (material, options) => {
      const index = selected, pair = pairs[index]!;
      const [runtime, remote] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]);
      const peer = new V4Session(remote); peers.push(peer);
      subscriptions.push(peer.notifications.subscribe(changed, (_context, value) => { notifications.push(`${index}:${value}`); },
        { workClass: "short", applicationBytes: 1024n, authorization: "authenticated" })); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const controller = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
      requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false, application_profile: "services" }, attemptTimeoutMS: 10000n });
    let service: ServiceClientTypes.V4ServiceClient<{ events: typeof events; changed: typeof changed }> | undefined;
    const streams: StreamingOperationTypes.V4StreamingOperation<string>[] = [];
    try {
      await controller.replaceSession();
      service = await controller.bindService(definition, { target, maximumOfferWindowMS: 10000n,
        methods: [{ method: events, streamKind: "example.controller.events", preacceptStream: true }] });
      const old = await service.stream(events, "old", { admission: "try_now" }); streams.push(old);
      const first = await old.readNext(); expect(first).toMatchObject({ kind: "value", value: "0:old:typed" }); if ("release" in first) first.release();
      const preparedNotify = await service.prepareOperation(changed, "prepared");
      await controller.replaceSession({ retirement: "retain", retainUntilMS: 20000n });
      const next = await service.prepareStreamOperation(events, "new", { admission: "try_now" }); streams.push(next);
      // Start only observes already-declared demand. It cannot create a pool.
      await expect.poll(() => next.start().status).toBe("admitted");
      const current = await next.readNext(); expect(current).toMatchObject({ kind: "value", value: "1:new:typed" }); if ("release" in current) current.release();
      expect(preparedNotify.start()).toMatchObject({ status: "admitted" });
      await preparedNotify.waitSubmission(); preparedNotify.close();
      expect(await service.notify(changed, "current")).toMatchObject({ submission: "submitted" });
      await expect.poll(() => notifications).toEqual(["0:prepared", "1:current"]);
      service.close(); releaseOld();
      for (const [stream, expected] of [[old, "0:old:encoded"], [next, "1:new:encoded"]] as const) {
        const encoded = await stream.readNextEncoded(); expect(encoded).toMatchObject({ kind: "value", bytes: new TextEncoder().encode(expected) }); if ("release" in encoded) encoded.release();
        expect(await stream.readNext()).toMatchObject({ kind: "end", status: { state: "complete" } }); stream.close();
        expect((await stream.waitCleanup()).status).toBe("complete");
      }
      expect(calls).toEqual(["0:old", "1:new"]); expect(acquisitions).toBe(2);
      await controller.captureSession().probeLiveness();
    } finally {
      releaseOld(); service?.close(); for (const stream of streams) stream.close(); for (const subscription of subscriptions) subscription.close();
      await controller.close(); expect((await controller.waitCleanup()).status).toBe("complete");
      for (const peer of peers) await peer.close();
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close();
    }
  }, 20000);
  it("renews managed Controller execution offers after a blocked source is replaced", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "execution", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const optionalCodec = v4ApplicationMessageCodec<string>({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 }, {
      execution: "sync", applicationBytes: 1024n, encode: (_ctx, value) => new TextEncoder().encode(value),
      decode: (_ctx, value) => new TextDecoder().decode(value),
    });
    const optional = new V4MethodDefinition({ typeID: 44, shape: "unary", unarySemantics: "transient", request: optionalCodec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.controller.managed", methods: { echo: method, optional } });
    const common = { resultRead: { typeID: 45, contractDigest: fill(33) }, query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const services: ServiceClientTypes.V4ServiceClient<{ echo: typeof method; optional: typeof optional }>[] = [];
    const execution = { tenant: "tenant", audience: "service", namespace: definition.namespace, callerAuthorities: ["3".repeat(64)], maxRecords: 16, maxActive: 4, resultBytes: 1048576n };
    const calls: string[] = [], origin = performance.now();
    for (let i = 0; i < 3; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { profile: "execution" as const, sessions: 3, connectionSeed: 90 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, (_environment, material) => ({ ...common, localExecutionAuthority: "3".repeat(64),
        referenceTargets: [{ authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
          peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", material.server)).toString("hex") }] }] }),
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) });
      await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const server = endpoint("server", b, profile, "live_authority", 3000n, (environment, material) => {
        const r = environment.resources, offerConfig = { bytes: 256, nodes: 16, textBytes: 128, arrayItems: 8, runtimeBytes: 1024n };
        const refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n), cborDecoderCharge(offerConfig)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `controller_contract_${index}` }, charge })));
        let decoder: CBORDecoder | undefined, offer!: AdmissionOffer;
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(0), 3: u(1),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 13: u(0), 14: u(30000), 15: u(30000),
          16: u(10000), 17: u(60000), 18: u(10000), 19: u(1),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!);
          const digest = new Uint8Array(32); contract.copyDigest(digest); decoder = new CBORDecoder(offerConfig, refs[2]!);
          const document = decoder.decodeMap(encode(map({ 0: bytes(digest), 1: u(900), 2: u(500000 + i * 50000) })), "AdmissionOffer");
          try { offer = new AdmissionOffer(document, contract, 700000n, new Uint8Array(32)); } finally { document.release(); }
        } finally { decoder?.close(); for (const ref of refs) ref.release(); }
        return { ...common, executionIdentity: { authority: "3".repeat(64), subject: "client", identityDigest: Buffer.from(digest("certificate_digest", material.client)).toString("hex") },
          executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }],
          queryPermissions: [{ namespace: definition.namespace, method, permission: i === 1 ? "denied" as const : "allowed" as const }],
          unaryHandlers: [{ namespace: definition.namespace, method, contract, offer, maximumOfferWindowMS: 700000n, execution, handler: (_context, value: string) => {
            calls.push(`${i}:${value}`); return `${i}:${value}`;
          }, options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment; let acquisitions = 0, selected = 0;
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(pairs[acquisitions]!.client.config), checkRequirements: () => undefined, connect: async (material, options) => {
      const pair = pairs[selected]!;
      const [runtime] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const controller = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
      requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false,
        local_consumer_tls13_verification: false, application_profile: "execution" }, attemptTimeoutMS: 10000n });
    try {
      await controller.replaceSession(); const first = controller.captureSession();
      const service = await controller.bindService(definition, { target, maximumOfferWindowMS: 700000n, initialMethods: [method], offerRefresh: "managed" }); services.push(service);
      const plan = environment.serviceBindings(256).offers;
      expect(plan.envelope()).toMatchObject({ methods: 1, groups: 1, batches: 1 });
      const digest = service.contract(method).digest;
      const prepared = await service.prepareOperation(method, "old");
      await controller.replaceSession({ retirement: "retain", retainUntilMS: 20000n });
      await expect.poll(() => service.contract(method), { timeout: 3000 }).toMatchObject({ refresh: "blocked", reason: "permission_denied" });
      expect(prepared.start().status).toBe("admitted");
      const old = await prepared.takeResult(); expect(old).toMatchObject({ kind: "value", value: "0:old" }); if ("release" in old) old.release(); prepared.close();
      await first.close(); await expect.poll(() => controller.status().retired).toBe(false);
      await controller.replaceSession({ retirement: "retain", retainUntilMS: 20000n });
      await expect.poll(() => service.contract(method), { timeout: 4000 }).toMatchObject({ refresh: "installed", availability: "available", digest });
      expect(plan.envelope()).toMatchObject({ methods: 1, groups: 1, batches: 1 });
      const fresh = await service.call(method, "current"); expect(fresh).toMatchObject({ kind: "value", value: "2:current" }); if ("release" in fresh) fresh.release();
      expect(calls).toEqual(["0:old", "2:current"]); expect(acquisitions).toBe(3);
      service.close(); expect(plan.envelope().methods).toBe(0);
      await controller.captureSession().probeLiveness();
    } finally {
      for (const service of services) service.close(); await controller.close(); expect((await controller.waitCleanup()).status).toBe("complete");
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close();
    }
  }, 20000);
  it("constructs owned and borrowed Controller services with one acquisition and exact cleanup ownership", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const optionalCodec = v4ApplicationMessageCodec<string>({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 }, {
      execution: "sync", applicationBytes: 1024n, encode: (_ctx, value) => new TextEncoder().encode(value),
      decode: (_ctx, value) => new TextDecoder().decode(value),
    });
    const optional = new V4MethodDefinition({ typeID: 44, shape: "unary", unarySemantics: "transient", request: optionalCodec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.controller", methods: { echo: method, optional } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const services: ServiceClientTypes.V4ServiceClient<{ echo: typeof method; optional: typeof optional }>[] = [];
    const calls: string[] = [], origin = performance.now();
    for (let i = 0; i < 3; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { sessions: 3, connectionSeed: 90 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, () => common,
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) });
      await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
        const r = environment.resources;
        const refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `controller_contract_${index}` }, charge })));
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(i === 2 ? 64 : 128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!); }
        finally { for (const ref of refs) ref.release(); }
        return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" as const }],
          unaryHandlers: [{ namespace: definition.namespace, method, contract, handler: (_context, value: string) => {
            calls.push(`${i}:${value}`); return `${i}:${value}`;
          }, options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment; let acquisitions = 0, selected = 0;
    const runtimes: V4AuthenticatedSessionRuntime[] = [];
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(pairs[acquisitions]!.client.config), checkRequirements: () => undefined, connect: async (material, options) => {
      const pair = pairs[selected]!;
      const [runtime] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]); runtimes.push(runtime); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const binding = { target, maximumOfferWindowMS: 10000n, initialMethods: [method] };
    const config = { source, requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false,
      local_consumer_tls13_verification: false, application_profile: "services" as const }, attemptTimeoutMS: 10000n };
    const owned = { ownership: "owned" as const, environment: wrapTransportEnvironment(environment), controller: config };
    const controller = createV4ConnectionController(owned.environment, config);
    try {
      const pool = environment.serviceBindings(256), captured = captureServiceBinding(definition, binding);
      const held: ServiceBindingPoolTypes.ServiceBindingReservation[] = [];
      try {
        for (let index = 0; index < 64; index++) held.push(pool.reserve(captured));
        await expect(createV4ServiceClient(definition, owned, binding)).rejects.toThrow(/configuration_capacity|resource_exhausted/);
        expect(acquisitions).toBe(0);
      } finally { for (const reservation of held) reservation.close(); }
      const service = await createV4ServiceClient(definition, owned, binding); services.push(service); expect(acquisitions).toBe(1);
      const result = await service.call(method, "owned"); expect(result).toMatchObject({ kind: "value", value: "0:owned" }); if ("release" in result) result.release();
      service.close(); await expect.poll(() => runtimes[0]!.cleanupStatus().status).toBe("complete");
      // Binding failure after READY closes only the factory's new Controller.
      await expect(createV4ServiceClient(definition, owned, { ...binding, initialMethods: [optional] })).rejects.toThrow(/method_unavailable|permission_denied/);
      expect(acquisitions).toBe(2); await expect.poll(() => runtimes[1]!.cleanupStatus().status).toBe("complete");
      const cancel = new AbortController();
      const waiting = createV4ServiceClient(definition, { ownership: "borrowed", controller }, { ...binding, signal: cancel.signal });
      await Promise.resolve(); expect(controller.status().started).toBe(false); expect(acquisitions).toBe(2);
      cancel.abort(); await expect(waiting).rejects.toThrow("canceled"); expect(controller.status().closed).toBe(false);
      await controller.replaceSession();
      const borrowed = await createV4ServiceClient(definition, { ownership: "borrowed", controller }, binding); services.push(borrowed);
      const operation = await borrowed.prepareOperation(method, "borrowed"); borrowed.close();
      expect(controller.status().closed).toBe(false); expect(operation.start().status).toBe("admitted");
      const encoded = await operation.takeEncodedResult(); expect(encoded).toMatchObject({ kind: "value", bytes: new TextEncoder().encode("2:borrowed") });
      if ("release" in encoded) encoded.release(); operation.close();
      await controller.captureSession().probeLiveness(); expect(acquisitions).toBe(3);
    } finally {
      for (const service of services) service.close(); await controller.close();
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close();
    }
  }, 20000);
  it("routes a two-group service through joint admission, disjoint methods and owned or borrowed cleanup", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = (typeID: number) => new V4MethodDefinition({ typeID, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const interactive = method(42), bulk = method(44);
    const definition = new V4ServiceDefinition({ namespace: "example.groups", methods: { interactive, bulk } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const calls: string[] = [], origin = performance.now();
    for (let i = 0; i < 4; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { sessions: 2, connectionSeed: 100 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, () => common,
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) });
      await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const selectedMethod = i % 2 === 0 ? interactive : bulk;
      const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
        const r = environment.resources;
        const refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `group_contract_${index}` }, charge })));
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(selectedMethod.typeID), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!); }
        finally { for (const ref of refs) ref.release(); }
        return { ...common, queryPermissions: [{ namespace: definition.namespace, method: selectedMethod, permission: "allowed" as const }],
          unaryHandlers: [{ namespace: definition.namespace, method: selectedMethod, contract, handler: (_context, value: string) => {
            calls.push(`${i}:${value}`); return `${i}:${value}`;
          }, options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment; let acquisitions = 0, selected = 0;
    const runtimes: V4AuthenticatedSessionRuntime[] = [];
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(pairs[acquisitions]!.client.config), checkRequirements: () => undefined, connect: async (material, options) => {
      const pair = pairs[selected]!;
      const [runtime] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]); runtimes.push(runtime); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const binding = { target, maximumOfferWindowMS: 10000n, initialMethods: [interactive] };
    const config = { source, requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false,
      local_consumer_tls13_verification: false, application_profile: "services" as const }, attemptTimeoutMS: 10000n };
    const owned = { ownership: "owned" as const, environment: wrapTransportEnvironment(environment), controller: config };
    const routes = [{ method: interactive, group: "interactive" as const }, { method: bulk, group: "bulk" as const }];
    const grouped = { groups: { interactive: owned, bulk: owned }, routes };
    const controllers = [createV4ConnectionController(owned.environment, config), createV4ConnectionController(owned.environment, config)];
    const clients: ServiceClientTypes.V4ServiceClient<typeof definition.methods>[] = [];
    const held: ServiceBindingPoolTypes.ServiceBindingReservation[] = [];
    try {
      await expect(createV4ServiceClient(definition, { ...grouped, routes: [routes[0]!, routes[0]!] }, binding)).rejects.toThrow("configuration_capacity");
      await expect(createV4ServiceClient(definition, { ...grouped, groups: { ...grouped.groups, bulk: { ...owned, target: { ...target, authority: "other" } } } }, binding)).rejects.toThrow("service_target_mismatch");
      const headroom = { ...owned, controller: { ...config, handoffHeadroom: true } };
      await expect(createV4ServiceClient(definition, { ...grouped, groups: { interactive: headroom, bulk: headroom } }, binding)).rejects.toThrow(/configuration_capacity|resource_exhausted/);
      expect(acquisitions).toBe(0);
      const occupied = environment.prepareConnect(source, config.requirements);
      try {
        await expect(createV4ServiceClient(definition, grouped, binding)).rejects.toThrow(/configuration_capacity|resource_exhausted/);
        expect(acquisitions).toBe(0);
      } finally { occupied.close(); }
      const queryBacking = environment.serviceBindings(256).reserve(captureServiceBinding(definition, binding));
      const queryPositions: QueryRenewalPositionTypes.QueryPreparationReservation[] = [];
      try {
        for (let i = 0; i < 3; i++) queryPositions.push(environment.contractQueries(4).protectPreparation(queryBacking.reference));
        await expect(createV4ServiceClient(definition, grouped, { ...binding, initialMethods: [interactive, bulk] })).rejects.toThrow(/resource_exhausted|configuration_capacity/);
        expect(acquisitions).toBe(0);
      } finally { for (const position of queryPositions) position.close(); queryBacking.close(); }
      // Two method owners share one public service root, including its closing tails.
      const pool = environment.serviceBindings(256), captured = captureServiceBinding(definition, binding);
      for (let index = 0; index < 63; index++) held.push(pool.reserve(captured));
      const service = await createV4ServiceClient(definition, grouped, binding); clients.push(service);
      expect(acquisitions).toBe(2); expect(service.info().methodCount).toBe(2);
      expect(service.contract(bulk).availability).toBe("not_ready");
      await service.refresh([bulk]);
      for (const [selectedMethod, textValue, expected] of [[interactive, "small", "0:small"], [bulk, "large", "1:large"]] as const) {
        const result = await service.call(selectedMethod, textValue); expect(result).toMatchObject({ kind: "value", value: expected }); if ("release" in result) result.release();
      }
      service.close(); expect(service.contract(interactive).availability).toBe("closed");
      await expect.poll(() => runtimes.slice(0, 2).every(runtime => runtime.cleanupStatus().status === "complete")).toBe(true);
      for (const reservation of held.splice(0)) reservation.close();
      const borrowed = { groups: { interactive: { ownership: "borrowed" as const, controller: controllers[0]! }, bulk: { ownership: "borrowed" as const, controller: controllers[1]! } }, routes };
      const cancel = new AbortController();
      const pending = createV4ServiceClient(definition, borrowed, { ...binding, signal: cancel.signal });
      await Promise.resolve(); expect(acquisitions).toBe(2); expect(controllers.every(controller => !controller.status().started)).toBe(true);
      cancel.abort(); await expect(pending).rejects.toThrow("canceled");
      for (const controller of controllers) await controller.replaceSession();
      const borrowedService = await createV4ServiceClient(definition, borrowed, { ...binding, initialMethods: [interactive, bulk] }); clients.push(borrowedService);
      const prepared = await borrowedService.prepareOperation(bulk, "independent"); borrowedService.close();
      expect(controllers.every(controller => !controller.status().closed)).toBe(true);
      expect(prepared.start().status).toBe("admitted");
      const result = await prepared.takeEncodedResult(); expect(result).toMatchObject({ kind: "value", bytes: new TextEncoder().encode("3:independent") });
      if ("release" in result) result.release(); prepared.close();
      for (const controller of controllers) await controller.captureSession().probeLiveness();
      expect(calls).toEqual(["0:small", "1:large", "3:independent"]); expect(acquisitions).toBe(4);
    } finally {
      for (const client of clients) client.close(); for (const reservation of held) reservation.close();
      for (const controller of controllers) await controller.close();
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close();
    }
  }, 20000);
  it("replaces grouped Controllers using real reserved headroom while old operations retain their Sessions", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = (typeID: number) => new V4MethodDefinition({ typeID, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const interactive = method(42), bulk = method(44);
    const definition = new V4ServiceDefinition({ namespace: "example.groups", methods: { interactive, bulk } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const calls: string[] = [], origin = performance.now();
    for (let i = 0; i < 4; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { resourceAccounts: 64, sessions: 4, connectionSeed: 100 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, () => common,
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) });
      await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const selectedMethod = i % 2 === 0 ? interactive : bulk;
      const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
        const r = environment.resources;
        const refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `group_contract_${index}` }, charge })));
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(selectedMethod.typeID), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!); }
        finally { for (const ref of refs) ref.release(); }
        return { ...common, queryPermissions: [{ namespace: definition.namespace, method: selectedMethod, permission: "allowed" as const }],
          unaryHandlers: [{ namespace: definition.namespace, method: selectedMethod, contract, handler: (_context, value: string) => {
            calls.push(`${i}:${value}`); return `${i}:${value}`;
          }, options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment; let acquisitions = 0, selected = 0, admissions = 0;
    const runtimes: V4AuthenticatedSessionRuntime[] = [];
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => { admissions++; return environment.reserveClientAdmission(pairs[0]!.client.config); }, checkRequirements: () => undefined, connect: async (material, options) => {
      const pair = pairs[selected]!;
      const [runtime] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]); runtimes.push(runtime); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const binding = { target, maximumOfferWindowMS: 10000n, initialMethods: [interactive] };
    const config = { source, handoffHeadroom: true, requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false,
      local_consumer_tls13_verification: false, application_profile: "services" as const }, attemptTimeoutMS: 10000n };
    const owned = { ownership: "owned" as const, environment: wrapTransportEnvironment(environment), controller: config };
    const controllers = [createV4ConnectionController(owned.environment, config), createV4ConnectionController(owned.environment, config)];
    const routes = [{ method: interactive, group: "interactive" as const }, { method: bulk, group: "bulk" as const }];
    const grouped = { groups: {
      interactive: { ownership: "borrowed" as const, controller: controllers[0]! },
      bulk: { ownership: "borrowed" as const, controller: controllers[1]! },
    }, routes };
    let service: ServiceClientTypes.V4ServiceClient<typeof definition.methods> | undefined;
    const operations: UnaryOperationTypes.V4UnaryOperation<string>[] = [];
    try {
      for (const controller of controllers) await controller.replaceSession();
      expect(acquisitions).toBe(2); expect(admissions).toBe(4);
      expect(controllers.map(controller => controller.status().headroom)).toEqual(["reserved", "reserved"]);
      service = await createV4ServiceClient(definition, grouped, { ...binding, initialMethods: [interactive, bulk] });
      operations.push(await service.prepareOperation(interactive, "old-small"), await service.prepareOperation(bulk, "old-large"));
      // No capacity remains beyond the two current and two actual standbys.
      expect(() => environment.prepareConnect(source, config.requirements)).toThrow("resource_exhausted");
      const replacementA = await controllers[0]!.replaceSession({ retirement: "retain", retainUntilMS: 25000n });
      expect(admissions).toBe(4); expect(acquisitions).toBe(3);
      expect(controllers[0]!.status().headroom).toBe("in_use");
      expect(controllers[1]!.status().headroom).toBe("reserved");
      const replacementB = await controllers[1]!.replaceSession({ retirement: "retain", retainUntilMS: 25000n });
      expect(admissions).toBe(4); expect(acquisitions).toBe(4);
      await expect(controllers[0]!.replaceSession()).rejects.toThrow("retirement_capacity");
      for (const [index, operation] of operations.entries()) {
        expect(operation.start().status).toBe("admitted");
        const result = await operation.takeEncodedResult();
        expect(result).toMatchObject({ kind: "value", bytes: new TextEncoder().encode(index === 0 ? "0:old-small" : "1:old-large") });
        if ("release" in result) result.release(); operation.close();
      }
      for (const [selectedMethod, value, expected] of [[interactive, "new-small", "2:new-small"], [bulk, "new-large", "3:new-large"]] as const) {
        const result = await service.call(selectedMethod, value); expect(result).toMatchObject({ kind: "value", value: expected });
        if ("release" in result) result.release();
      }
      // Only actual old Session cleanup lets the original admission refill.
      await replacementA.previous!.close(); await replacementA.previous!.waitCleanup();
      await expect.poll(() => controllers[0]!.status().headroom).toBe("reserved");
      expect(controllers[1]!.status().headroom).toBe("in_use");
      await replacementB.previous!.close(); await replacementB.previous!.waitCleanup();
      await expect.poll(() => controllers[1]!.status().headroom).toBe("reserved");
      expect(admissions).toBe(6); expect(acquisitions).toBe(4);
      service.close(); expect(controllers.every(controller => !controller.status().closed)).toBe(true);
      expect(calls).toEqual(["0:old-small", "1:old-large", "2:new-small", "3:new-large"]);
    } finally {
      for (const operation of operations) operation.close(); service?.close();
      for (const controller of controllers) await controller.close();
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close();
    }
  }, 20000);
  it("constructs owned groups with prepaid headroom and reconnects one source without migrating its peer group", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = (typeID: number) => new V4MethodDefinition({ typeID, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const interactive = method(42), bulk = method(44);
    const definition = new V4ServiceDefinition({ namespace: "example.groups", methods: { interactive, bulk } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const calls: string[] = [], origin = performance.now();
    for (let i = 0; i < 4; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { resourceAccounts: 64, sessions: 4, connectionSeed: 100 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, () => common,
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) });
      await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const selectedMethod = i % 2 === 0 ? interactive : bulk;
      const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
        const r = environment.resources;
        const refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `group_contract_${index}` }, charge })));
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(selectedMethod.typeID), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!); }
        finally { for (const ref of refs) ref.release(); }
        return { ...common, queryPermissions: [{ namespace: definition.namespace, method: selectedMethod, permission: "allowed" as const }],
          unaryHandlers: [{ namespace: definition.namespace, method: selectedMethod, contract, handler: (_context, value: string) => {
            calls.push(`${i}:${value}`); return `${i}:${value}`;
          }, options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment; let acquisitions = 0, selected = 0, admissions = 0;
    const runtimes: V4AuthenticatedSessionRuntime[] = [];
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => { admissions++; return environment.reserveClientAdmission(pairs[0]!.client.config); }, checkRequirements: () => undefined, connect: async (material, options) => {
      const pair = pairs[selected]!;
      const [runtime] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]); runtimes.push(runtime); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const binding = { target, maximumOfferWindowMS: 10000n, initialMethods: [interactive] };
    const config = { source, handoffHeadroom: true, requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false,
      local_consumer_tls13_verification: false, application_profile: "services" as const }, attemptTimeoutMS: 10000n };
    const owned = { ownership: "owned" as const, environment: wrapTransportEnvironment(environment), controller: config };
    const candidates: V4Session[] = [];
    const configured = { ...owned, controller: { ...config, initializeApplicationBytes: 1024n,
      initializeSession: (_context: V4ApplicationContext, candidate: V4Session) => { candidates.push(candidate); } } };
    const routes = [{ method: interactive, group: "interactive" as const }, { method: bulk, group: "bulk" as const }];
    let service: ServiceClientTypes.V4ServiceClient<typeof definition.methods> | undefined;
    try {
      service = await createV4ServiceClient(definition, { groups: { interactive: configured, bulk: configured }, routes },
        { ...binding, initialMethods: [interactive, bulk] });
      expect(acquisitions).toBe(2); expect(admissions).toBe(4); expect(candidates).toHaveLength(2);
      for (const [selectedMethod, value, expected] of [[interactive, "small", "0:small"], [bulk, "large", "1:large"]] as const) {
        const result = await service.call(selectedMethod, value); expect(result).toMatchObject({ kind: "value", value: expected });
        if ("release" in result) result.release();
      }
      await candidates[0]!.close(); await candidates[0]!.waitCleanup();
      await expect.poll(() => candidates.length).toBe(3);
      const result = await service.call(interactive, "reconnected"); expect(result).toMatchObject({ kind: "value", value: "2:reconnected" });
      if ("release" in result) result.release();
      const bulkResult = await service.call(bulk, "unchanged"); expect(bulkResult).toMatchObject({ kind: "value", value: "1:unchanged" });
      if ("release" in bulkResult) bulkResult.release();
      expect(acquisitions).toBe(3); expect(admissions).toBe(5);
      service.close();
      await expect.poll(() => runtimes.every(runtime => runtime.cleanupStatus().status === "complete")).toBe(true);
      expect(calls).toEqual(["0:small", "1:large", "2:reconnected", "1:unchanged"]);
    } finally {
      service?.close();
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close();
    }
  }, 20000);
  it("keeps a Controller service across replacement without rebinding or moving prepared calls", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const optionalCodec = v4ApplicationMessageCodec<string>({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 }, {
      execution: "sync", applicationBytes: 1024n, encode: (_ctx, value) => new TextEncoder().encode(value),
      decode: (_ctx, value) => new TextDecoder().decode(value),
    });
    const optional = new V4MethodDefinition({ typeID: 44, shape: "unary", unarySemantics: "transient", request: optionalCodec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.controller", methods: { echo: method, optional } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const services: ServiceClientTypes.V4ServiceClient<{ echo: typeof method; optional: typeof optional }>[] = [];
    const calls: string[] = [], origin = performance.now();
    for (let i = 0; i < 3; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { sessions: 3, connectionSeed: 90 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, () => common,
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) });
      await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
        const r = environment.resources;
        const refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `controller_contract_${index}` }, charge })));
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(i === 2 ? 64 : 128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!); }
        finally { for (const ref of refs) ref.release(); }
        return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" as const }],
          unaryHandlers: [{ namespace: definition.namespace, method, contract, handler: (_context, value: string) => {
            calls.push(`${i}:${value}`); return `${i}:${value}`;
          }, options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment;
    let acquisitions = 0, selected = 0, initializations = 0;
    let enterReplacement!: () => void, releaseReplacement!: () => void;
    const entered = new Promise<void>(resolve => { enterReplacement = resolve; });
    const release = new Promise<void>(resolve => { releaseReplacement = resolve; });
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(pairs[acquisitions]!.client.config), checkRequirements: () => undefined, connect: async (material, options) => {
      const pair = pairs[selected]!;
      const [runtime] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]); return runtime;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const binding = { target, maximumOfferWindowMS: 10000n, initialMethods: [method] };
    const controller = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
      requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false, application_profile: "services" },
      attemptTimeoutMS: 10000n, initializeApplicationBytes: 1024n,
      initializeSession: async () => { if (++initializations === 2) { enterReplacement(); await release; } } });
    const call = async (service: typeof services[number], value: string, expected: string) => {
      const result = await service.call(method, value); expect(result).toMatchObject({ kind: "value", value: expected });
      if ("release" in result) result.release();
    };
    try {
      const cancel = new AbortController(), idle = controller.bindService(definition, { ...binding, signal: cancel.signal });
      await Promise.resolve(); expect(acquisitions).toBe(0); expect(controller.status().started).toBe(false);
      cancel.abort(); await expect(idle).rejects.toThrow("canceled");
      const waiting = controller.bindService(definition, binding);
      await controller.replaceSession(); const service = await waiting; services.push(service);
      const first = controller.captureSession(), originalDigest = service.contract(method).digest;
      await call(service, "first", "0:first");
      const prepared = await service.prepareOperation(method, "prepared");
      const replacing = controller.replaceSession({ retirement: "retain", retainUntilMS: 20000n }); await entered;
      const queued = call(service, "queued", "1:queued");
      await Promise.resolve(); expect(calls).toEqual(["0:first"]);
      releaseReplacement(); await replacing; await queued;
      expect(service.contract(method).digest).toBe(originalDigest); expect(acquisitions).toBe(2);
      expect(prepared.start().status).toBe("admitted");
      const result = await prepared.takeEncodedResult();
      expect(result).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("0:prepared") });
      if ("release" in result) result.release(); prepared.close();
      await first.close(); await expect.poll(() => controller.status().retired).toBe(false);
      await call(service, "new", "1:new");
      const independent = await service.prepareOperation(method, "independent");
      await controller.replaceSession({ retirement: "retain", retainUntilMS: 20000n });
      expect(service.contract(method).digest).toBe(originalDigest);
      const mismatch = await service.call(method, "unapproved");
      expect(mismatch.kind).not.toBe("value"); if ("release" in mismatch) mismatch.release();
      expect(calls).not.toContain("2:unapproved"); expect(service.contract(method).digest).toBe(originalDigest);
      const approved = new Uint8Array(32); pairs[2]!.contract.copyDigest(approved);
      const updated = await service.updateContract(method, approved);
      expect(updated[0]?.contract.refresh, updated[0]?.contract.reason).toBe("installed");
      expect(service.contract(method).digest).toBe(Buffer.from(approved).toString("hex"));
      await call(service, "approved", "2:approved");
      service.close();
      expect(independent.start().status).toBe("admitted");
      const final = await independent.takeResult(); expect(final).toMatchObject({ kind: "value", value: "1:independent" });
      if ("release" in final) final.release(); independent.close();
      await controller.captureSession().probeLiveness();
      await expect(service.call(method, "closed")).rejects.toThrow("service_binding_closed");
      expect(acquisitions).toBe(3);
    } finally {
      releaseReplacement(); for (const service of services) service.close();
      await controller.close(); expect((await controller.waitCleanup()).status).toBe("complete");
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close(); expect(environment.resources.root.snapshot().reservations).toBe(0);
    }
  }, 20000);
  it("publishes Controller candidates, retains fixed business calls and blocks unknown initialization", async () => {
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    let optionalEncodes = 0;
    const optionalCodec = v4ApplicationMessageCodec<string>({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 }, {
      execution: "sync", applicationBytes: 1024n, encode: (_ctx, value) => { optionalEncodes++; return new TextEncoder().encode(value); },
      decode: (_ctx, value) => new TextDecoder().decode(value),
    });
    const optional = new V4MethodDefinition({ typeID: 44, shape: "unary", unarySemantics: "transient", request: optionalCodec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.controller", methods: { echo: method, optional } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 2, maxCaptureBytes: 128 };
    const pairs: { client: ReturnType<typeof endpoint>; server: ReturnType<typeof endpoint>; contract: ServiceContractSnapshot }[] = [];
    const services: ServiceClientTypes.V4ServiceClient<{ echo: typeof method; optional: typeof optional }>[] = [];
    const calls: string[] = [], origin = performance.now();
    for (let i = 0; i < 4; i++) {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const options = { sessions: 3, connectionSeed: 90 + i, clockOriginMS: origin };
      const client = endpoint("client", a, profile, "live_authority", 3000n, () => common,
        { ...options, ...(pairs.length === 0 ? {} : { environment: pairs[0]!.client.environment }) });
      await client.discardPrepared();
      let contract!: ServiceContractSnapshot;
      const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
        const r = environment.resources;
        const refs = r.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
          accounts: r.accounts, owner: { ...r.owner, kind: `controller_contract_${index}` }, charge })));
        try { contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!); }
        finally { for (const ref of refs) ref.release(); }
        return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" as const }],
          unaryHandlers: [{ namespace: definition.namespace, method, contract, handler: (_context, value: string) => {
            calls.push(`${i}:${value}`); return `${i}:${value}`;
          }, options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      }, options);
      pairs.push({ client, server, contract });
    }
    const environment = pairs[0]!.client.environment;
    let acquisitions = 0, selected = 0, initializations = 0, probeOrdinal = 0;
    const executorProbe = () => {
      const r = environment.resources;
      return applicationGroup(r.root, r.accounts, { ...r.owner, kind: `controller_executor_probe_${++probeOrdinal}` }, r.runtimeBytes, false);
    };
    const queryProbe = (direction: 0 | 1 = 0) => {
      const r = environment.resources, group = executorProbe();
      const reference = r.root.reserve({ accounts: r.accounts, owner: { ...r.owner, kind: `controller_query_probe_${probeOrdinal}` },
        charge: new ResourceVector([4096n, 0n, 0n, 2n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) });
      try {
        const protection = direction === 0 ? group.protectQueries(reference) : group.protectQueryAcquisition(reference);
        return () => { protection.close(); group.close(); };
      } catch (error) { group.close(); throw error; }
      finally { reference.release(); }
    };
    const acquisitionProbe = () => {
      const r = environment.resources;
      const reference = r.root.reserve({ accounts: r.accounts, owner: { ...r.owner, kind: `controller_acquisition_probe_${++probeOrdinal}` },
        charge: new ResourceVector([4096n, 0n, 0n, 2n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) });
      try { return environment.contractQueries(4).protectPreparation(reference); }
      finally { reference.release(); }
    };
    const source = wrapCredentialSource(environment.registerSource({ ...pairs[0]!.client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
      const probe = executorProbe(), permits = [];
      try {
        // This attempt already owns one position, but its initializer has not
        // entered. Other work can fill only the remaining original 25 slots.
        expect(applicationWorkload(environment.resources.root)?.ordinaryRunning).toBe(0);
        for (let index = 0; index < 25; index++) permits.push(probe.tryOrdinary("short"));
        expect(() => probe.tryOrdinary("short")).toThrow("would_block");
      } finally { for (const permit of permits) permit.release(); probe.close(); }
      if (acquisitions === 0) {
        const queries = [];
        try {
          // The candidate already holds its two incoming fixed-query slots.
          for (let index = 0; index < 3; index++) queries.push(queryProbe());
          expect(() => queryProbe()).toThrow("resource_exhausted");
        } finally { for (const close of queries) close(); }
        const acquisitions = [], outgoing = [];
        try {
          for (let index = 0; index < 3; index++) { acquisitions.push(acquisitionProbe()); outgoing.push(queryProbe(1)); }
          expect(acquisitionProbe).toThrow("resource_exhausted");
          expect(() => queryProbe(1)).toThrow("resource_exhausted");
        } finally { for (const position of acquisitions) position.close(); for (const close of outgoing) close(); }
      }
      selected = acquisitions++; const input = pairs[selected]!.client.material.input();
      for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
        activation: input.activation.length, candidateIndex: input.candidateIndex };
    }));
    // The test connector reuses original verified material and encrypted READY.
    // Production native carrier/TxA/TxB qualification remains a separate path.
    environment.installClientConnector({ applicationProfile: pairs[0]!.client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(pairs[acquisitions]!.client.config), checkRequirements: () => undefined, connect: async (material, options) => {
      const pair = pairs[selected]!;
      const [client] = await Promise.all([pair.client.establishMaterial(material, options?.signal), pair.server.establish()]); return client;
    } });
    const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
    const registration = v4ServiceDependency(definition, {
      binding: { target, maximumOfferWindowMS: 10000n }, methods: { register: method, optional },
      dispatchRequirements: { optional: "on_use" },
    });
    const optionalOnly = v4ServiceDependency(definition, {
      binding: { target, maximumOfferWindowMS: 10000n, methods: [{ method: optional, workClass: "resident" }] },
      methods: { optional }, dispatchRequirements: { optional: "on_use" },
    });
    const secondRegistration = v4ServiceDependency(definition, {
      binding: { target, maximumOfferWindowMS: 10000n, contractCheckIntervalMS: 90000n }, methods: { register: method },
    });
    const oversized = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
      requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false, application_profile: "services" },
      initializeServices: { registration }, initializeApplicationBytes: 1024n,
      initializeWorkload: { inputBytes: 1073741824 },
      initializeSession: () => { throw new Error("unexpected_initializer"); },
    });
    const excessiveCalls = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
      requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false, application_profile: "services" },
      initializeServices: { registration }, initializeApplicationBytes: 1024n,
      initializeWorkload: { callsPerMethod: 3 },
      initializeSession: () => { throw new Error("unexpected_initializer"); },
    });
    let escaped: ((value: string) => Promise<unknown>) | undefined;
    const controller = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
      requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false, local_consumer_tls13_verification: false, application_profile: "services" },
      initializeServices: { registration, registrationCopy: registration, optionalOnly, secondRegistration }, attemptTimeoutMS: 10000n, initializeApplicationBytes: 1024n,
      initializeSession: async (context, candidate) => {
        expect(applicationHasPermit(context)).toBe(true); initializations++;
        expect(() => controller.captureSession()).toThrow("initialization_blocked");
        expect(Object.keys(context.services.registration)).toEqual(["register", "optional"]);
        expect("refresh" in context.services.registration).toBe(false);
        await expect(context.services.registration.optional("unavailable")).rejects.toThrow("not_ready");
        await expect(context.services.optionalOnly.optional("unavailable")).rejects.toThrow("not_ready");
        expect(optionalEncodes).toBe(0);
        const registration = await context.services.registration.register("register");
        expect(registration).toMatchObject({ kind: "value", value: `${initializations - 1}:register` });
        if ("release" in registration) registration.release();
        if (initializations === 1) {
          // Complete another real round trip so the first call's physical
          // publication and deferred cleanup can exit before reusing its slot.
          await candidate.probeLiveness();
          const repeated = await context.services.registration.register("register-again");
          expect(repeated).toMatchObject({ kind: "value", value: "0:register-again" });
          if ("release" in repeated) repeated.release();
          const second = await context.services.secondRegistration.register("second-binding");
          expect(second).toMatchObject({ kind: "value", value: "0:second-binding" });
          if ("release" in second) second.release();
        }
        escaped ??= context.services.registration.register;
        await candidate.probeLiveness(); if (initializations === 3) throw new Error("registration_unknown");
      } });
    const bind = async (session: V4Session) => {
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", pairs[0]!.server.material.server)).toString("hex") }] };
      const service = await session.bindService(definition, { target, maximumOfferWindowMS: 10000n, initialMethods: [method] }); services.push(service); return service;
    };
    const call = async (service: typeof services[number], value: string, expected: string) => {
      const result = await service.call(method, value); expect(result).toMatchObject({ kind: "value", value: expected });
      if ("release" in result) result.release();
    };
    try {
      // Both Controllers share the same original Environment. A rejected local
      // workload must neither acquire material nor disturb the other owner.
      try {
        await expect(oversized.replaceSession()).rejects.toThrow("resource_exhausted");
        expect(acquisitions).toBe(0); expect(initializations).toBe(0);
      } finally { await oversized.close(); expect((await oversized.waitCleanup()).status).toBe("complete"); }
      try {
        await expect(excessiveCalls.replaceSession()).rejects.toThrow("resource_exhausted");
        expect(acquisitions).toBe(0); expect(initializations).toBe(0);
      } finally { await excessiveCalls.close(); expect((await excessiveCalls.waitCleanup()).status).toBe("complete"); }
      expect(() => controller.captureSession()).toThrow("not_ready"); expect(acquisitions).toBe(0);
      const canceled = new AbortController(), wait = controller.waitForSession({ signal: canceled.signal }); canceled.abort();
      await expect(wait).rejects.toThrow("canceled"); expect(acquisitions).toBe(0);
      const busy = executorProbe(), occupied = [];
      try {
        for (let index = 0; index < 26; index++) occupied.push(busy.tryOrdinary("short"));
        expect(() => controller.start()).toThrow("resource_exhausted");
        expect(acquisitions).toBe(0); expect(initializations).toBe(0);
      } finally { for (const permit of occupied) permit.release(); busy.close(); }
      const occupiedQueries = [];
      try {
        for (let index = 0; index < 4; index++) occupiedQueries.push(queryProbe());
        await expect(controller.replaceSession()).rejects.toThrow("resource_exhausted");
        expect(acquisitions).toBe(0); expect(initializations).toBe(0);
        await expect.poll(() => controller.status().pending).toBe(false);
      } finally { for (const close of occupiedQueries) close(); }
      const occupiedAcquisitions = [];
      try {
        for (let index = 0; index < 4; index++) occupiedAcquisitions.push(acquisitionProbe());
        await expect(controller.replaceSession()).rejects.toThrow("resource_exhausted");
        expect(acquisitions).toBe(0); expect(initializations).toBe(0);
        await expect.poll(() => controller.status().pending).toBe(false);
      } finally { for (const position of occupiedAcquisitions) position.close(); }
      const bindingPool = environment.serviceBindings(256), heldBindings: ServiceBindingReservation[] = [];
      const bindingConfig = captureServiceBinding(definition, { target, maximumOfferWindowMS: 10000n });
      try {
        for (let index = 0; index < 64; index++) {
          try { heldBindings.push(bindingPool.reserve(bindingConfig)); }
          catch (error) { expect(String(error)).toMatch(/configuration_capacity|resource_exhausted/); break; }
        }
        expect(heldBindings.length).toBeGreaterThan(0);
        await expect(controller.replaceSession()).rejects.toThrow(/configuration_capacity|resource_exhausted/);
        expect(acquisitions).toBe(0); expect(initializations).toBe(0);
        await expect.poll(() => controller.status().pending).toBe(false);
      } finally { for (const binding of heldBindings) binding.close(); }
      await controller.replaceSession(); const first = await controller.waitForSession(), old = await bind(first);
      await expect(escaped!("late")).rejects.toThrow("invocation_closed");
      const prepared = await old.prepareOperation(method, "old");
      const replacement = await controller.replaceSession({ retirement: "retain", retainUntilMS: 20000n });
      expect(replacement.previous).toBe(first); expect(replacement.previousRetained).toBe(true);
      expect(controller.captureSession()).toBe(replacement.current); expect(acquisitions).toBe(2);
      await expect(controller.replaceSession()).rejects.toThrow("retirement_capacity"); expect(acquisitions).toBe(2);
      expect(prepared.start().status).toBe("admitted"); const result = await prepared.takeResult();
      expect(result).toMatchObject({ kind: "value", value: "0:old" }); if ("release" in result) result.release(); prepared.close();
      await call(old, "fixed", "0:fixed");
      const current = await bind(replacement.current); await call(current, "new", "1:new");
      old.close(); first.drain({ timeoutMS: 1000n }); await first.waitCleanup();
      await expect.poll(() => controller.status().retired).toBe(false);
      await expect(controller.replaceSession()).rejects.toThrow("registration_unknown");
      expect(() => controller.captureSession()).toThrow("initialization_blocked");
      await expect(controller.waitForSession()).rejects.toThrow("initialization_blocked");
      controller.start(); expect(acquisitions).toBe(3); expect(initializations).toBe(3);
      await call(current, "owned", "1:owned");
      await expect.poll(() => controller.status().pending).toBe(false);
      const recovered = await controller.replaceSession(); expect(controller.captureSession()).toBe(recovered.current);
      const last = await bind(recovered.current); await call(last, "recovered", "3:recovered");
      expect(calls).toEqual(["0:register", "0:register-again", "0:second-binding", "1:register", "0:old", "0:fixed", "1:new", "2:register", "1:owned", "3:register", "3:recovered"]);
    } finally {
      for (const service of services) service.close();
      await controller.close(); expect((await controller.waitCleanup()).status).toBe("complete");
      for (const pair of pairs) { pair.contract.release(); await pair.server.close(); }
      await pairs[0]!.client.close();
    }
  }, 20000);
  it.each([false, true])("connects static services BindService, Prepare/Call, handler, typed/encoded results and Close (restart flush: %s)", async restartFlush => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const direction = { schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 };
    const request = v4UTF8MessageCodec(direction);
    let decodes = 0, calls = 0;
    let maintenance: V4MaintenanceOwner | undefined;
    const publications: V4ResponsePublication[] = [];
    const response = v4ApplicationMessageCodec<string>(direction, { execution: "sync", applicationBytes: 1024n,
      encode: (_context, value) => new TextEncoder().encode(value),
      decode: (_context, value) => { decodes++; return new TextDecoder().decode(value); } });
    const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "transient", request, response,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, ...(restartFlush ? { restartFlush: true as const, restartFlushDeadlineMS: 5000n } : { restartFlush: false as const }),
      errors: [{ code: 7, codec: request, maxPayloadBytes: 128 }] });
    const definition = new V4ServiceDefinition({ namespace: "example.echo", methods: { echo: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    let contract: ServiceContractSnapshot | undefined, staticContracts: V4StaticServiceContracts | undefined;
    const client = endpoint("client", a, profile, "live_authority", 1000n, () => common);
    const server = endpoint("server", b, profile, "live_authority", 1000n, environment => {
      if (restartFlush) maintenance = createMaintenanceOwner(environment, 4);
      const resources = environment.resources, charges = [serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)];
      const references = resources.root.reserveBatch(charges.map((charge, index) => ({ accounts: resources.accounts,
        owner: { ...resources.owner, kind: `test_contract_${index}` }, charge })));
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text("example.echo"), 1: u(42), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: restartFlush }, ...(restartFlush ? { 22: u(5000) } : {}), 23: u(128), 27: array(map({ 0: u(7), 1: text("text-v1"), 2: u(128), 3: bytes(fill(31)) })) })),
        1024n, references[0]!, references[1]!);
      } finally { for (const reference of references) reference.release(); }
      return { ...common, ...(maintenance === undefined ? {} : { maintenanceOwner: maintenance }), queryPermissions: [{ namespace: definition.namespace, method, permission: "denied" }],
        unaryHandlers: [{ namespace: definition.namespace, method, contract,
          handler: (context, value: string) => {
            if (restartFlush) {
              expect(context.maintenanceOwner).toBe(maintenance);
              expect(context.responsePublication).toBe(context.responsePublication);
              expect(context.responsePublication.state()).toEqual({ state: "pending" });
              expect(context.responsePublication.transferTo(maintenance!)).toBe("success");
              expect(context.responsePublication.transferTo(maintenance!)).toBe("already_transferred");
              publications.push(context.responsePublication);
            } else expect(context.responsePublication.state()).toEqual({ state: "not_applicable" });
            calls++; if (value === "fail") throw new V4ServiceError(7, "declined"); return value.toUpperCase(); },
          options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
    });
    let c: V4Session | undefined, s: V4Session | undefined;
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      const contractBytes = new Uint8Array(contract!.encodedBytes()); contract!.copyEncoded(contractBytes);
      staticContracts = createStaticServiceContracts(client.environment, definition, [{ method, contract: contractBytes }], { target, maximumOfferWindowMS: 10000n });
      contractBytes.fill(0);
      // The peer denies remote contract queries. Local trusted snapshots must
      // close the same service path without querying or borrowing input bytes.
      const service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, contractSource: staticContracts });
      const currentDigest = new Uint8Array(32); contract!.copyDigest(currentDigest);
      const refreshed = await service.updateContract(method, currentDigest);
      expect(refreshed[0]!.contract).toMatchObject({ availability: "available", refresh: "installed" });
      staticContracts.close();
      const operation = await service.prepareOperation(method, "prepared");
      expect(operation.status()).toMatchObject({ state: "prepared", submission: "not_submitted" }); expect(calls).toBe(0);
      expect(operation.start().status).toBe("admitted");
      const typed = await operation.takeResult();
      expect(typed).toMatchObject({ kind: "value", encoding: "typed", value: "PREPARED" });
      operation.close(); if ("release" in typed) typed.release();
      const called = await service.call(method, "called");
      expect(called).toMatchObject({ kind: "value", encoding: "typed", value: "CALLED" }); if ("release" in called) called.release();
      const failure = await service.call(method, "fail");
      expect(failure).toMatchObject({ kind: "application_error", encoding: "typed", error: "declined" }); if ("release" in failure) failure.release();
      const encodedOperation = await service.prepareOperation(method, "encoded");
      service.close(); service.close();
      expect(encodedOperation.start().status).toBe("admitted");
      const encoded = await encodedOperation.takeEncodedResult();
      expect(encoded).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("ENCODED") });
      encodedOperation.close();
      if ("bytes" in encoded) { expect(new TextDecoder().decode(encoded.bytes)).toBe("ENCODED"); encoded.release(); }
      expect(calls).toBe(4); expect(decodes).toBe(2);
      if (restartFlush) {
        expect(publications.length).toBe(4);
        for (const publication of publications) expect(await publication.wait()).toEqual({ state: "flushed" });
        maintenance!.close();
        for (const publication of publications) expect(publication.state()).toEqual({ state: "flushed" });
        await expect.poll(() => maintenance!.cleanupComplete()).toBe(true);
      }
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally {
      maintenance?.close(); staticContracts?.close(); await Promise.all([c?.close(), s?.close()]); contract?.release();
      await Promise.all([client.close(), server.close()]);
    }
  });
  it("checks bounded advertisements and preserves the old prepared call through Close", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false, errors: [] });
    const definition = new V4ServiceDefinition({ namespace: "example.advertisement", methods: { echo: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    const snapshots: ServiceContractSnapshot[] = [];
    let calls = 0;
    const client = endpoint("client", a, profile, "live_authority", 1000n, () => common, { sessionNotAfterMS: 38000 });
    const server = endpoint("server", b, profile, "live_authority", 1000n, environment => {
      const resources = environment.resources;
      for (const maximum of [64, 128]) {
        const costs = [serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)];
        const refs = resources.root.reserveBatch(costs.map((charge, index) => ({ accounts: resources.accounts,
          owner: { ...resources.owner, kind: `advertisement_${maximum}_${index}` }, charge })));
        try { snapshots.push(new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(0), 3: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(maximum), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!)); }
        finally { for (const ref of refs) ref.release(); }
      }
      return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
        unaryHandlers: [{ namespace: definition.namespace, method, contract: snapshots[0]!,
          handler: (_context, value: string) => { calls++; return value.toUpperCase(); },
          options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
    }, { sessionNotAfterMS: 38000 });
    let c: V4Session | undefined, s: V4Session | undefined;
    let service: ServiceClientTypes.V4ServiceClient<{ echo: typeof method }> | undefined;
    let old: UnaryOperationTypes.V4UnaryOperation<string> | undefined;
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, contractCheckIntervalMS: 30000n,
        methods: [{ method, acceptance: { mode: "bounded", ranges: [{ field: "max_response_bytes", lower: 64n, upper: 128n }] } }] });
      const previous = service.contract(method).digest;
      // Keep the real 30s minimum; all credentials explicitly cover this test.
      await new Promise(resolve => setTimeout(resolve, 29000));
      old = await service.prepareOperation(method, "old");
      const routes = established[1].rpcApplication().routes;
      routes.install(definition.namespace, method, snapshots);
      const next = new Uint8Array(32); snapshots[1]!.copyDigest(next);
      routes.advertise(definition.namespace, method, next);
      await expect.poll(() => service!.contract(method).digest, { timeout: 4000, interval: 10 }).toBe(Buffer.from(next).toString("hex"));
      expect(service.contract(method).digest).not.toBe(previous);
      expect(old.start().status).toBe("admitted");
      const oldResult = await old.takeResult(); expect(oldResult).toMatchObject({ kind: "value", value: "OLD" });
      if ("release" in oldResult) oldResult.release(); old.close();
      const result = await service.call(method, "new"); expect(result).toMatchObject({ kind: "value", value: "NEW" });
      if ("release" in result) result.release(); expect(calls).toBe(2);
      service.close(); expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally {
      old?.close(); service?.close(); await Promise.all([c?.close(), s?.close()]); for (const snapshot of snapshots) snapshot.release();
      await Promise.all([client.close(), server.close()]);
    }
  }, 45000);
  it("connects dedicated streaming Prepare/Start, writer, typed/encoded items and Close", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const request = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    let decodes = 0, calls = 0;
    let decoderEntered!: () => void, releaseDecoder!: () => void;
    const entered = new Promise<void>(resolve => { decoderEntered = resolve; });
    const held = new Promise<void>(resolve => { releaseDecoder = resolve; });
    const response = v4ApplicationMessageCodec<string>({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 }, {
      execution: "async", applicationBytes: 1024n, encode: async (_context, value) => new TextEncoder().encode(value),
      decode: async (_context, bytes) => {
        decodes++; const value = new TextDecoder().decode(bytes);
        if (value === "retained:two") { decoderEntered(); await held; }
        return value;
      } });
    const method = new V4MethodDefinition({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "transient", request, response,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, maxItemCount: 3, maxStreamPayloadBytes: 384n, maxStreamDurationMS: 10000n, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.events", methods: { events: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    let contract: ServiceContractSnapshot | undefined;
    const client = endpoint("client", a, profile, "live_authority", 1000n, () => common);
    const server = endpoint("server", b, profile, "live_authority", 1000n, environment => {
      const resources = environment.resources, charges = [serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)];
      const references = resources.root.reserveBatch(charges.map((charge, index) => ({ accounts: resources.accounts,
        owner: { ...resources.owner, kind: `test_stream_contract_${index}` }, charge })));
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(1), 4: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 24: u(3), 25: u(384), 26: u(10000), 27: array() })), 1024n, references[0]!, references[1]!);
      } finally { for (const reference of references) reference.release(); }
      return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
        streamingHandlers: [{ namespace: definition.namespace, method, kind: "example.events.stream", contract,
          handler: async (_context, value: string, writer) => {
            calls++; if (value === "failed") throw new Error("business failure");
            await writer.write(value + ":one"); await writer.write(value + ":two");
          },
          options: { workClass: "resident", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
    });
    let c: V4Session | undefined, s: V4Session | undefined;
    const operations: Array<{ close(): void }> = [];
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const service = await c.bindService(definition, { target: { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] },
        maximumOfferWindowMS: 10000n, methods: [{ method, streamKind: "example.events.stream" }] });
      const prepared = await service.prepareStreamOperation(method, "prepared", { maxItemBytes: 64 }); operations.push(prepared);
      expect(prepared.status()).toMatchObject({ state: "prepared", submission: "not_submitted" }); expect(calls).toBe(0);
      expect(prepared.abandonResult()).toMatchObject({ outcome: "not_started", status: { state: "prepared" } });
      const preparedCleanup = prepared.waitCleanup();
      expect(prepared.start().status).toBe("admitted"); expect(prepared.start().status).toBe("admitted");
      const first = await prepared.readNext(); expect(first).toMatchObject({ kind: "value", encoding: "typed", value: "prepared:one" });
      if ("release" in first) first.release();
      const second = await prepared.readNextEncoded(); expect(second).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("prepared:two") });
      if ("release" in second) second.release();
      expect(await prepared.readNext()).toMatchObject({ kind: "end", status: { state: "complete", deliveredItems: 2n, deliveredBytes: 24n } });
      expect(await prepared.waitStatus()).toMatchObject({ state: "complete" }); prepared.close();
      expect(prepared.abandonResult().outcome).toBe("already_delivered");
      expect((await preparedCleanup).status).toBe("complete");
      const iterated = await service.stream(method, "convenient"); operations.push(iterated);
      const iterator = iterated.items();
      expect(() => iterated.readNextEncoded()).toThrow("read_in_progress");
      expect(() => iterated.items()).toThrow("read_in_progress");
      for await (const item of iterator) { expect(item.kind).toBe("value"); if ("release" in item) item.release(); break; }
      expect(iterated.status().state).not.toBe("streaming");
      expect((await iterated.waitCleanup()).status).toBe("complete");
      expect(calls).toBe(2); expect(decodes).toBe(2);
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);

      const failed = await service.stream(method, "failed"); operations.push(failed);
      expect(await failed.readNextEncoded()).toMatchObject({ kind: "sdk_error", code: "service_failed" });
      expect(await failed.waitStatus()).toMatchObject({ state: "complete" }); failed.close();
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);

      const retained = await service.stream(method, "retained"); operations.push(retained);
      const before = await retained.readNextEncoded(); if ("release" in before) before.release();
      const cancellation = new AbortController(), waiting = retained.readNext({ signal: cancellation.signal });
      await entered; cancellation.abort(); await expect(waiting).rejects.toThrow("wait_canceled");
      const cleanupCancel = new AbortController(), cleanupWait = retained.waitCleanup({ signal: cleanupCancel.signal });
      cleanupCancel.abort(); await expect(cleanupWait).rejects.toThrow("wait_canceled");
      expect(retained.status()).toMatchObject({ applicationInputDelivered: true, payloadStatus: "available" });
      await expect(retained.readNextEncoded()).rejects.toThrow("result_mode_conflict");
      expect(await retained.waitStatus()).toMatchObject({ state: "complete", deliveredItems: 1n });
      await Promise.all([c.close(), s.close()]); releaseDecoder();
      const last = await retained.readNext(); expect(last).toMatchObject({ kind: "value", encoding: "typed", value: "retained:two" });
      if ("release" in last) last.release();
      expect(await retained.readNext()).toMatchObject({ kind: "end", status: { state: "complete", deliveredItems: 2n } });
      expect((await retained.waitCleanup()).status).toBe("complete");
      expect(calls).toBe(4); expect(decodes).toBe(3); service.close();
    } finally {
      releaseDecoder();
      for (const operation of operations) operation.close();
      await Promise.all([c?.close(), s?.close()]); contract?.release(); await Promise.all([client.close(), server.close()]);
    }
  });
  it("preserves streaming decoder output across revocation and accepts deadline terminals within fixed grace", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const request = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    let calls = 0, decodes = 0;
    let releaseHandler!: () => void, releaseDecoders!: () => void;
    const handlerHeld = new Promise<void>(resolve => { releaseHandler = resolve; });
    const decodersHeld = new Promise<void>(resolve => { releaseDecoders = resolve; });
    const response = v4ApplicationMessageCodec<string>({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 }, {
      execution: "async", applicationBytes: 1024n, encode: async (_context, value) => new TextEncoder().encode(value),
      decode: async (_context, bytes) => { decodes++; await decodersHeld; return new TextDecoder().decode(bytes); } });
    const method = new V4MethodDefinition({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "transient", request, response,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, maxItemCount: 3, maxStreamPayloadBytes: 384n, maxStreamDurationMS: 10000n, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.events", methods: { events: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    let contract: ServiceContractSnapshot | undefined;
    const client = endpoint("client", a, profile, "live_authority", 1000n, () => common);
    const server = endpoint("server", b, profile, "live_authority", 1000n, environment => {
      const resources = environment.resources, charges = [serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)];
      const references = resources.root.reserveBatch(charges.map((charge, index) => ({ accounts: resources.accounts,
        owner: { ...resources.owner, kind: `test_stream_contract_${index}` }, charge })));
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(1), 4: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 24: u(3), 25: u(384), 26: u(10000), 27: array() })), 1024n, references[0]!, references[1]!);
      } finally { for (const reference of references) reference.release(); }
      return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
        streamingHandlers: [{ namespace: definition.namespace, method, kind: "example.events.stream", contract,
          handler: async (_context, value: string, writer) => {
            calls++; if (value === "deadline") { await handlerHeld; return; }
            await writer.write(value);
          },
          options: { workClass: "resident", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
    });
    let c: V4Session | undefined, s: V4Session | undefined;
    const owners: Array<{ close(): void }> = [];
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      const service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, methods: [{ method, streamKind: "example.events.stream" }] }); owners.push(service);
      const deadline = await service.stream(method, "deadline", { timeoutMS: 250n }); owners.push(deadline);
      expect(await deadline.readNextEncoded()).toMatchObject({ kind: "sdk_error", code: "deadline_exceeded" });
      releaseHandler(); deadline.close(); expect((await deadline.waitCleanup()).status).toBe("complete");
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);

      const first = await service.stream(method, "first"); owners.push(first);
      const firstValue = first.readNext(); await expect.poll(() => decodes).toBe(1);
      const second = await service.stream(method, "second"); owners.push(second);
      const secondValue = second.readNext(); await expect.poll(() => decodes).toBe(2);
      const third = await service.stream(method, "private"); owners.push(third);
      const thirdValue = third.readNext();
      await expect.poll(() => third.status().payloadStatus).toBe("available"); expect(decodes).toBe(2);
      expect(third.status().applicationInputDelivered).toBe(false);
      const material = client.material;
      const revoked = replace(material.state, { 9: array(map({ 0: bytes(digest("certificate_digest", material.server)), 1: u(8), 2: u(50000) })) });
      material.namespace.refresh(encode(material.headFor(revoked, 2)), encode(revoked));
      releaseDecoders();
      for (const [pending, value] of [[firstValue, "first"], [secondValue, "second"]] as const) {
        const item = await pending; expect(item).toMatchObject({ kind: "value", encoding: "typed", value }); if ("release" in item) item.release();
      }
      expect(await thirdValue).toMatchObject({ kind: "end", status: { payloadStatus: "payload_unavailable", applicationInputDelivered: false } });
      expect(decodes).toBe(2); expect(calls).toBe(4);
      for (const operation of [first, second]) {
        expect(await operation.readNext()).toMatchObject({ kind: "end", status: { deliveredItems: 1n, applicationInputDelivered: true } });
        operation.close(); expect((await operation.waitCleanup()).status).toBe("complete");
      }
    } finally {
      releaseHandler(); releaseDecoders(); for (const owner of owners) owner.close();
      await Promise.all([c?.close(), s?.close()]); contract?.release(); await Promise.all([client.close(), server.close()]);
    }
  });
  it("connects controlled Watch setup, bounded events, overflow and real unsubscribe cleanup", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "transient", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, maxItemCount: 10, maxStreamPayloadBytes: 1280n, maxStreamDurationMS: 10000n, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.watch", methods: { watch: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    let contract: ServiceContractSnapshot | undefined, setups = 0, maps = 0, disposals = 0;
    let releaseSetup!: () => void, releaseOverflow!: () => void, releaseDisposer!: () => void;
    const setupHeld = new Promise<void>(resolve => { releaseSetup = resolve; });
    const overflowHeld = new Promise<void>(resolve => { releaseOverflow = resolve; });
    const disposerHeld = new Promise<void>(resolve => { releaseDisposer = resolve; });
    const publishers = new Map<string, V4ByteEventPublisher>(), contexts = new Map<string, V4ApplicationContext>();
    const source = v4ByteEventSource<string, string>({ maxEventInputBytes: 128, maxPendingItems: 2, maxPendingBytes: 16384n,
      setup: async (context, value, publisher) => {
        setups++; contexts.set(value, context); publishers.set(value, publisher);
        expect(applicationHasPermit(context)).toBe(true); expect("outputInterest" in context).toBe(false);
        if (value === "setup") {
          const input = new TextEncoder().encode("snapshot"); expect(publisher.tryPublish(input)).toBe("accepted"); input.fill(0);
          publisher.complete(); await setupHeld;
        } else if (value === "overflow") {
          expect(publisher.tryPublish(new Uint8Array([1]))).toBe("accepted");
          expect(publisher.tryPublish(new Uint8Array([2]))).toBe("accepted");
          expect(publisher.tryPublish(new Uint8Array([3]))).toBe("overflow");
          expect(publisher.tryPublish(new Uint8Array([4]))).toBe("closed"); await overflowHeld;
        }
        return async () => { disposals++; if (value === "idle") await disposerHeld; };
      },
      map: async (context, input) => {
        maps++; expect(applicationHasPermit(context)).toBe(true);
        expect([...contexts.values()].includes(context)).toBe(false);
        return new TextDecoder().decode(input);
      } });
    const client = endpoint("client", a, profile, "live_authority", 1000n, () => common);
    const server = endpoint("server", b, profile, "live_authority", 1000n, environment => {
      const resources = environment.resources;
      const references = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
        accounts: resources.accounts, owner: { ...resources.owner, kind: `test_watch_contract_${index}` }, charge })));
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(1), 4: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 24: u(10), 25: u(1280), 26: u(10000), 27: array() })), 1024n, references[0]!, references[1]!);
      } finally { for (const reference of references) reference.release(); }
      return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
        streamingHandlers: [{ namespace: definition.namespace, method, kind: "example.watch.stream", contract, handler: source,
          options: { workClass: "resident", maxConcurrentCalls: 4, applicationBytes: 2048n, authorization: "authenticated" } }] };
    });
    let c: V4Session | undefined, s: V4Session | undefined;
    const owners: Array<{ close(): void }> = [];
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      const service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, methods: [{ method, streamKind: "example.watch.stream" }] }); owners.push(service);
      const setup = await service.stream(method, "setup"); owners.push(setup);
      let delivered = false; const pending = setup.readNext().then(item => { delivered = true; return item; });
      await expect.poll(() => setups).toBe(1);
      expect(maps).toBe(0); expect(delivered).toBe(false); expect(applicationWorkload(server.environment.resources.root)?.ordinaryRunning).toBe(1);
      releaseSetup(); const first = await pending;
      expect(first).toMatchObject({ kind: "value", encoding: "typed", value: "snapshot" }); if ("release" in first) first.release();
      expect(await setup.readNext()).toMatchObject({ kind: "end", status: { state: "complete", deliveredItems: 1n } }); setup.close();
      await expect.poll(() => disposals).toBe(1);
      expect(() => applicationHasPermit(contexts.get("setup"))).toThrow("dependency_unavailable");

      const overflow = await service.stream(method, "overflow"); owners.push(overflow);
      await expect.poll(() => setups).toBe(2); expect(maps).toBe(1); releaseOverflow();
      expect(await overflow.readNextEncoded()).toMatchObject({ kind: "sdk_error", code: "source_overflow" }); overflow.close();
      await expect.poll(() => disposals).toBe(2); expect(maps).toBe(1);
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);

      const idle = await service.stream(method, "idle"); owners.push(idle);
      await expect.poll(() => setups).toBe(3);
      await expect.poll(() => applicationWorkload(server.environment.resources.root)?.ordinaryRunning).toBe(0);
      expect(() => applicationHasPermit(contexts.get("idle"))).toThrow("dependency_unavailable");
      const idlePublisher = publishers.get("idle")!;
      expect(idlePublisher.tryPublish(new TextEncoder().encode("next"))).toBe("accepted");
      const next = await idle.readNextEncoded(); expect(next).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("next") }); if ("release" in next) next.release();
      await expect.poll(() => applicationWorkload(server.environment.resources.root)?.ordinaryRunning).toBe(0);
      idle.close(); await expect.poll(() => disposals).toBe(3);
      expect(idlePublisher.tryPublish(new Uint8Array([5]))).toBe("closed");
      expect(applicationWorkload(server.environment.resources.root)?.ordinaryRunning).toBe(1);
      service.close(); const closing = s.close();
      expect(s.cleanupStatus().status).not.toBe("complete");
      releaseDisposer(); await closing; expect((await s.waitCleanup()).status).toBe("complete");
      expect(setups).toBe(3); expect(maps).toBe(2); expect(disposals).toBe(3);
    } finally {
      releaseSetup(); releaseOverflow(); releaseDisposer(); for (const owner of owners) owner.close();
      await Promise.all([c?.close(), s?.close()]); contract?.release(); await Promise.all([client.close(), server.close()]);
    }
  });
  it("saves and starts one execution stream and queries its original history from a new Session", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "execution", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, maxItemCount: 3, maxStreamPayloadBytes: 384n, maxStreamDurationMS: 10000n, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.execution.stream", methods: { events: method } });
    const execution = { tenant: "tenant", audience: "service", namespace: definition.namespace, callerAuthorities: ["3".repeat(64)], maxRecords: 16, maxActive: 4, resultBytes: 1048576n };
    const common = { query: { typeID: 43, contractDigest: fill(32) }, resultRead: { typeID: 44, contractDigest: fill(33) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    const targetFor = (material: ReturnType<typeof credentialFixture>) => ({ authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", material.server)).toString("hex") }] });
    const clientConfig = (_environment: V4EnvironmentRuntime, material: ReturnType<typeof credentialFixture>) => ({ ...common,
      localExecutionAuthority: "3".repeat(64), referenceTargets: [targetFor(material)] });
    let calls = 0, cancellationObserved = false, releaseHandler!: () => void, enteredHandler!: () => void;
    const held = new Promise<void>(resolve => { releaseHandler = resolve; }), entered = new Promise<void>(resolve => { enteredHandler = resolve; });
    let contract: ServiceContractSnapshot | undefined;
    const client = endpoint("client", a, profile, "live_authority", 1000n, clientConfig, { profile: "execution", operationEntropy: fill(48, 24) });
    const server = endpoint("server", b, profile, "live_authority", 1000n, (environment, material) => {
      const resources = environment.resources, offerConfig = { bytes: 256, nodes: 16, textBytes: 128, arrayItems: 8, runtimeBytes: 1024n };
      const references = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n), cborDecoderCharge(offerConfig)].map((charge, index) => ({
        accounts: resources.accounts, owner: { ...resources.owner, kind: `test_execution_stream_contract_${index}` }, charge })));
      let decoder: CBORDecoder | undefined;
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(1), 4: u(1),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 13: u(0), 14: u(30000),
          16: u(10000), 17: u(60000), 18: u(10000), 19: u(1), 21: { kind: "bool", value: false }, 23: u(128),
          24: u(3), 25: u(384), 26: u(10000), 27: array(), 28: map({ 0: u(0) }) })), 1024n, references[0]!, references[1]!);
        const contractDigest = new Uint8Array(32); contract.copyDigest(contractDigest);
        decoder = new CBORDecoder(offerConfig, references[2]!);
        const document = decoder.decodeMap(encode(map({ 0: bytes(contractDigest), 1: u(900), 2: u(10000) })), "AdmissionOffer");
        let offer: AdmissionOffer;
        try { offer = new AdmissionOffer(document, contract, 10000n, new Uint8Array(32)); } finally { document.release(); }
        return { ...common, executionIdentity: { authority: "3".repeat(64), subject: "client", identityDigest: Buffer.from(digest("certificate_digest", material.client)).toString("hex") },
          executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }],
          queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
          streamingHandlers: [{ namespace: definition.namespace, method, kind: "example.execution.stream", contract, offer, maximumOfferWindowMS: 10000n, execution,
            handler: async (context, value: string, writer) => {
              calls++; enteredHandler(); await held; cancellationObserved = context.signal.aborted;
              await writer.write(`${value}:one`); await writer.write(`${value}:two`);
            }, options: { workClass: "resident", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      } finally { decoder?.close(); for (const reference of references) reference.release(); }
    }, { profile: "execution" });
    let c: V4Session | undefined, s: V4Session | undefined, nextClient: ReturnType<typeof endpoint> | undefined;
    let nextC: V4Session | undefined, nextS: V4Session | undefined, store: V4OperationReferenceStore | undefined;
    let directory: string | undefined, db: DatabaseSync | undefined;
    const owners: Array<{ close(): void }> = [];
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const service = await c.bindService(definition, { target: targetFor(client.material), maximumOfferWindowMS: 10000n,
        methods: [{ method, streamKind: "example.execution.stream" }] }); owners.push(service);
      directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-stream-reference-"));
      db = new DatabaseSync(join(directory, "references.sqlite"));
      db.exec("PRAGMA synchronous=FULL; CREATE TABLE saved (identity TEXT PRIMARY KEY, canonical BLOB NOT NULL)");
      store = createOperationReferenceStore(client.environment, { targetDomain: "authority", durability: "durable_create_or_compare", storage: "application_owned",
        maxRecords: 1, maxStoredBytes: 2048n, retentionMS: 60000n, maxConcurrentSaves: 1, applicationBytes: 65536n }, async (_context, record) => {
        const previous = db!.prepare("SELECT canonical FROM saved WHERE identity=?").get(record.identity);
        if (previous !== undefined) return Buffer.from(previous.canonical as Uint8Array).equals(record.canonical) ? "confirmed" : "conflict";
        db!.prepare("INSERT INTO saved VALUES (?,?)").run(record.identity, record.canonical); return "confirmed";
      });
      const options = { deadlineAtMS: 40000n, admissionNotAfterMS: 5000n, maxItemBytes: 128 };
      const saved = await service.prepareAndSave(method, "original", store, options);
      expect(saved).toMatchObject({ status: "prepared", save: { attempted: true, outcome: "confirmed" } });
      if (saved.status !== "prepared") throw new Error("missing execution stream capability");
      const operation = saved.operation; owners.push(operation);
      expect(operation).toBeInstanceOf(V4ExecutionStreamingOperation); expect(calls).toBe(0);
      expect(operation.status()).toMatchObject({ state: "prepared", submission: "not_submitted" });
      expect(await c.queryOperation(operation.reference())).toMatchObject({ status: "history_unknown" });
      store.close(); expect(operation.start().status).toBe("admitted");
      const firstPending = operation.readNext();
      await Promise.race([entered, firstPending.then(value => { throw new Error(`execution stream ended before dispatch: ${value.kind}${"code" in value ? `/${value.code}` : ""}`); })]);
      const duplicate = await service.prepareStreamOperation(method, "original", options); owners.push(duplicate);
      expect(duplicate.reference()).toBeDefined(); expect(duplicate.start().status).toBe("admitted");
      const joined = duplicate.readNextEncoded();
      expect(await c.queryOperation(saved.reference)).toMatchObject({ status: "ok", observation: { state: "executing", dispatched: true, workActive: true, resultAvailable: false } });
      expect(await c.requestCancel(saved.reference)).toMatchObject({ status: "ok", cancelResult: "requested" });
      releaseHandler();
      const first = await firstPending; expect(first).toMatchObject({ kind: "value", encoding: "typed", value: "original:one" }); if ("release" in first) first.release();
      const second = await operation.readNextEncoded(); expect(second).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("original:two") }); if ("release" in second) second.release();
      expect(await operation.readNext()).toMatchObject({ kind: "end", status: { state: "complete", deliveredItems: 2n } });
      expect(await joined).toMatchObject({ kind: "sdk_error", code: "service_unavailable" });
      expect(calls).toBe(1); expect(cancellationObserved).toBe(true);
      operation.close(); duplicate.close();
      expect((await operation.waitCleanup()).status).toBe("complete"); expect((await duplicate.waitCleanup()).status).toBe("complete");
      const conflict = await service.stream(method, "different", options); owners.push(conflict);
      expect(await conflict.readNextEncoded()).toMatchObject({ kind: "sdk_error", code: "operation_conflict" }); conflict.close();
      expect((await conflict.waitCleanup()).status).toBe("complete");
      expect(await c.queryOperation(saved.reference)).toMatchObject({ status: "ok", observation: { state: "completed", workActive: false,
        resultAvailable: false, resultDeleted: false, resultBytes: 0, cancelRequested: true } });
      service.close(); await Promise.all([c.close(), s.close()]);
      expect((await c.waitCleanup()).status).toBe("complete"); expect((await s.waitCleanup()).status).toBe("complete");
      await client.close();
      const nextA = new MemoryTransport("client", "message"), nextB = new MemoryTransport("server", "message"); nextA.peer = nextB; nextB.peer = nextA;
      const nextOptions = { profile: "execution" as const, connectionSeed: 70, clockOriginMS: Math.min(a.createdAtMS, b.createdAtMS) };
      nextClient = endpoint("client", nextA, profile, "live_authority", 1000n, clientConfig, nextOptions);
      const nextServer = endpoint("server", nextB, profile, "live_authority", 1000n, (_environment, material) => ({ ...common,
        executionIdentity: { authority: "3".repeat(64), subject: "client", identityDigest: Buffer.from(digest("certificate_digest", material.client)).toString("hex") },
        executionServices: [execution], executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }] }), { ...nextOptions, environment: server.environment });
      const pair = await Promise.all([nextClient.establish(), nextServer.establish()]); nextC = new V4Session(pair[0]); nextS = new V4Session(pair[1]);
      const referenceCodec = createOperationReferenceCodec(nextClient.environment); owners.push(referenceCodec);
      const imported = referenceCodec.import(db.prepare("SELECT canonical FROM saved").get()!.canonical as Uint8Array, "authority"); referenceCodec.close();
      expect(await nextC.queryOperation(imported)).toMatchObject({ status: "ok", observation: { state: "completed", resultAvailable: false, resultDeleted: false } });
      expect(await nextC.requestCancel(imported)).toMatchObject({ status: "ok", cancelResult: "terminal" });
      expect(() => nextC!.readOperationResult(imported)).toThrow("operation_reference_shape");
      expect(calls).toBe(1);
    } finally {
      releaseHandler(); for (const owner of owners) owner.close(); store?.close();
      await Promise.all([c?.close(), s?.close(), nextC?.close(), nextS?.close()]); contract?.release();
      try { await Promise.all([client.close(), server.close(), nextClient?.close()]); }
      finally { db?.close(); if (directory !== undefined) rmSync(directory, { recursive: true, force: true }); }
    }
  });
  it("connects preaccepted streaming Bind demand, try_now checkout, results and Close", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const request = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    let calls = 0;
    const response = request;
    const method = new V4MethodDefinition({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "transient", request, response,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, maxItemCount: 3, maxStreamPayloadBytes: 384n, maxStreamDurationMS: 10000n, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.events", methods: { events: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    let contract: ServiceContractSnapshot | undefined;
    const client = endpoint("client", a, profile, "live_authority", 1000n, () => common);
    const server = endpoint("server", b, profile, "live_authority", 1000n, environment => {
      const resources = environment.resources, charges = [serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)];
      const references = resources.root.reserveBatch(charges.map((charge, index) => ({ accounts: resources.accounts,
        owner: { ...resources.owner, kind: `test_stream_contract_${index}` }, charge })));
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(1), 4: u(0),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 11: u(30000), 12: u(10000),
          21: { kind: "bool", value: false }, 23: u(128), 24: u(3), 25: u(384), 26: u(10000), 27: array() })), 1024n, references[0]!, references[1]!);
      } finally { for (const reference of references) reference.release(); }
      return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
        streamingHandlers: [{ namespace: definition.namespace, method, kind: "example.events.stream", contract,
          handler: async (_context, value: string, writer) => {
            calls++; if (value === "failed") throw new Error("business failure");
            await writer.write(value + ":one"); await writer.write(value + ":two");
          },
          options: { workClass: "resident", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
    });
    let c: V4Session | undefined, s: V4Session | undefined;
    const owners: Array<{ close(): void }> = [];
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      const plain = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, methods: [{ method, streamKind: "example.events.stream" }] }); owners.push(plain);
      const prepared = await plain.prepareStreamOperation(method, "first", { admission: "try_now" }); owners.push(prepared);
      expect(prepared.start()).toMatchObject({ status: "not_admitted", submission: "not_submitted", reason: "not_ready" });
      expect(prepared.status().state).toBe("prepared"); expect(calls).toBe(0);
      const required = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n,
        methods: [{ method, streamKind: "example.events.stream", requiredForDispatch: true }] }); owners.push(required);
      const shared = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n,
        methods: [{ method, streamKind: "example.events.stream", preacceptStream: true }] }); owners.push(shared);
      required.close(); expect(calls).toBe(0);
      const competitor = await shared.prepareStreamOperation(method, "second", { admission: "try_now" }); owners.push(competitor);
      expect(prepared.start().status).toBe("admitted");
      expect(competitor.start()).toMatchObject({ status: "not_admitted", submission: "not_submitted", reason: "not_ready" });
      for (const value of ["first:one", "first:two"]) {
        const item = await prepared.readNext(); expect(item).toMatchObject({ kind: "value", encoding: "typed", value }); if ("release" in item) item.release();
      }
      expect(await prepared.readNext()).toMatchObject({ kind: "end", status: { deliveredItems: 2n } }); prepared.close();
      // Only the existing explicit demand replenishes. Each retry is a new
      // caller action on the same prepared bytes and original finite deadline.
      await expect.poll(() => competitor.start().status, { timeout: 1000 }).toBe("admitted");
      shared.close(); plain.close();
      const item = await competitor.readNextEncoded(); expect(item).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("second:one") });
      if ("release" in item) item.release();
      expect(competitor.abandonResult()).toMatchObject({ outcome: "result_abandoned", status: { deliveredItems: 1n, payloadStatus: "result_abandoned" } });
      expect(competitor.abandonResult().outcome).toBe("result_abandoned");
      expect(await competitor.readNext()).toMatchObject({ kind: "end", status: { deliveredItems: 1n, payloadStatus: "result_abandoned" } }); competitor.close();
      expect((await competitor.waitCleanup()).status).toBe("complete");
      expect(calls).toBe(2); expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally {
      for (const owner of owners) owner.close();
      await Promise.all([c?.close(), s?.close()]); contract?.release(); await Promise.all([client.close(), server.close()]);
    }
  });
  it("connects observation NOTIFY preparation, complete submission, serial handlers and Close", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const request = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 40000 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "notify", notifySemantics: "observation", request,
      requestMaxBytes: 40000, responseRevision: "none-v1", restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.events", methods: { changed: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 40000 };
    let contract: ServiceContractSnapshot | undefined, source: V4StaticServiceContracts | undefined;
    let permission = false, running = 0, maximumRunning = 0, release!: () => void, entered!: () => void, delivered!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; }), first = new Promise<void>(resolve => { entered = resolve; });
    const last = new Promise<void>(resolve => { delivered = resolve; }), values: string[] = [];
    // This connectivity path sends over 250 authenticated DATA frames through
    // the deliberately tiny 128-byte fixture; use its explicit write budget.
    const client = endpoint("client", a, profile, "live_authority", 3000n, () => common, { writeDeadlineMS: 3000n });
    const server = endpoint("server", b, profile, "live_authority", 3000n, environment => {
      const resources = environment.resources;
      const refs = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
        accounts: resources.accounts, owner: { ...resources.owner, kind: `notify_contract_${index}` }, charge })));
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(2), 5: u(0), 6: text("text-v1"), 7: text("none-v1"),
          8: u(0), 9: u(0), 10: u(0), 11: u(30000), 21: { kind: "bool", value: false }, 23: u(40000), 27: array() })), 1024n, refs[0]!, refs[1]!);
      } finally { for (const ref of refs) ref.release(); }
      return { ...common, queryPermissions: [{ namespace: definition.namespace, method, permission: "denied" }], notificationHandlers: [{ namespace: definition.namespace, method, contract,
        options: { workClass: "short", applicationBytes: 4096n, authorization: () => permission },
        handler: async (_context, value: string) => {
          running++; maximumRunning = Math.max(maximumRunning, running);
          try { values.push(value); if (value.startsWith("first")) { entered(); await held; } if (value === "last") delivered(); }
          finally { running--; }
        } }] };
    });
    let c: V4Session | undefined, s: V4Session | undefined;
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      const bytes = new Uint8Array(contract!.encodedBytes()); contract!.copyEncoded(bytes);
      source = createStaticServiceContracts(client.environment, definition, [{ method, contract: bytes }], { target, maximumOfferWindowMS: 10000n }); bytes.fill(0);
      const service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, contractSource: source });
      // A denial is local to the receiver. Submitted is not a remote outcome.
      expect(await service.notify(method, "denied")).toMatchObject({ submission: "submitted" });
      await c.probeLiveness(); expect(values).toEqual([]); permission = true;
      const operation = await service.prepareOperation(method, "first" + "x".repeat(33000));
      expect(operation.status()).toMatchObject({ state: "prepared", submission: "not_submitted" });
      expect("takeResult" in operation).toBe(false); expect("reference" in operation).toBe(false);
      expect(operation.start().status).toBe("admitted"); expect(operation.start().status).toBe("admitted");
      operation.close(); // The prefix has admitted the whole immutable tail.
      expect(await operation.waitSubmission()).toMatchObject({ submission: "submitted" });
      await expect.poll(() => values.length, { timeout: 1500 }).toBe(1); await first;
      expect(await service.notify(method, "second")).toMatchObject({ submission: "submitted" });
      expect(values.length).toBe(1); expect(maximumRunning).toBe(1);
      release();
      const finalOperation = await service.prepareOperation(method, "last"); service.close(); source.close();
      expect(finalOperation.start().status).toBe("admitted"); expect(await finalOperation.waitSubmission()).toMatchObject({ submission: "submitted" }); finalOperation.close();
      await expect.poll(() => values.length, { timeout: 1500 }).toBe(3); await last; expect(values).toEqual(["first" + "x".repeat(33000), "second", "last"]); expect(maximumRunning).toBe(1);
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally { release(); source?.close(); await Promise.all([c?.close(), s?.close()]); contract?.release(); await Promise.all([client.close(), server.close()]); }
  });
  it("fans out local observation subscriptions with isolated decoding, latest pending and real closure", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    let decodes = 0;
    const codec = v4ApplicationMessageCodec<string>({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 }, {
      execution: "sync", applicationBytes: 1024n,
      encode: (_context, value) => new TextEncoder().encode(value),
      decode: (_context, bytes) => { const value = new TextDecoder().decode(bytes); bytes.fill(0); decodes++; return value; },
    });
    const method = new V4MethodDefinition({ typeID: 42, shape: "notify", notifySemantics: "observation", request: codec,
      requestMaxBytes: 128, responseRevision: "none-v1", restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.snapshots", methods: { changed: method } });
    const contract = encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(2), 5: u(0), 6: text("text-v1"), 7: text("none-v1"),
      8: u(0), 9: u(0), 10: u(0), 11: u(30000), 21: { kind: "bool", value: false }, 23: u(128), 27: array() }));
    const common = { query: { typeID: 43, contractDigest: fill(32) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    const client = endpoint("client", a, profile, "live_authority", 3000n, () => common);
    const server = endpoint("server", b, profile, "live_authority", 3000n, () => ({ ...common,
      notificationMethods: [{ namespace: definition.namespace, method, contract, permission: "allowed" }] }));
    let c: V4Session | undefined, s: V4Session | undefined, source: V4StaticServiceContracts | undefined;
    let release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
    const tokens: V4NotificationSubscription<any>[] = [];
    const options = { workClass: "short" as const, applicationBytes: 2048n, authorization: "authenticated" as const };
    const events = new Map<string, () => void>();
    const watch = (value: string): Promise<void> => new Promise(resolve => { events.set(value, resolve); });
    const fifoValues: string[] = [], latestValues: string[] = [], fastValues: string[] = [], lateValues: string[] = [];
    let selfWait!: { closed: boolean; wait: string }, selfDone!: () => void;
    const selfFinished = new Promise<void>(resolve => { selfDone = resolve; });
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      source = createStaticServiceContracts(client.environment, definition, [{ method, contract }], { target, maximumOfferWindowMS: 10000n });
      const service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, contractSource: source });
      const fifo = s.notifications.subscribe(method, async (_context, value) => { fifoValues.push(value); if (value === "one") await held; }, options);
      const latest = s.notifications.subscribe(method, async (_context, value) => { latestValues.push(value); if (value === "one") await held; }, { ...options, pendingPolicy: "latest_pending" });
      const errors = s.notifications.subscribe(method, (_context, value) => { if (value === "three") throw new Error("handler failure"); }, {
        ...options, project: (_context, value) => { if (value === "two") throw new Error("projection failure"); return value; },
      });
      const fast = s.notifications.subscribe(method, (_context, value) => { fastValues.push(value); events.get(value)?.(); events.delete(value); }, options);
      tokens.push(fifo, latest, errors, fast);
      const send = async (value: string): Promise<void> => { const observed = watch(value); expect(await service.notify(method, value)).toMatchObject({ submission: "submitted" }); await observed; };
      await send("one"); expect(fifoValues).toEqual(["one"]); expect(latestValues).toEqual(["one"]);
      const late = s.notifications.subscribe(method, (_context, value) => { lateValues.push(value); }, options); tokens.push(late);
      const passive = await late.waitClosed({ timeoutMS: 1n }); expect(passive).toMatchObject({ closed: false, wait: "deadline_exceeded", cleanupStatus: { status: "pending" } });
      expect(late.observationStatus().closed).toBe(false); expect(lateValues).toEqual([]);
      await send("two"); await send("three");
      expect(latest.observationStatus()).toMatchObject({ pending: 1, running: 1, knownDropped: 1n, lastGap: "coalesced_pending" });
      expect(fifo.observationStatus()).toMatchObject({ pending: 2, running: 1, knownDropped: 0n });
      expect(errors.observationStatus()).toMatchObject({ knownDropped: 2n, lastGap: "handler_error" });
      expect(fastValues).toEqual(["one", "two", "three"]); expect(lateValues).toEqual(["two", "three"]);
      // Every token gets independent mutable decoder bytes. Coalesced data was
      // never decoded and a late subscriber did not receive the first event.
      expect(decodes).toBe(10);
      const fillers = Array.from({ length: 27 }, () => s!.notifications.subscribe(method, () => undefined, options)); tokens.push(...fillers);
      expect(() => s!.notifications.subscribe(method, () => undefined, options)).toThrow("resource_exhausted");
      latest.close(); latest.close(); expect(latest.observationStatus()).toMatchObject({ closed: true, running: 1, pending: 0 });
      expect(() => s!.notifications.subscribe(method, () => undefined, options)).toThrow("resource_exhausted");
      release(); expect(await latest.waitClosed()).toMatchObject({ closed: true, wait: "complete", cleanupStatus: { status: "complete" } });
      expect(latestValues).toEqual(["one"]);
      const replacement = s.notifications.subscribe(method, () => undefined, options); tokens.push(replacement);
      for (const token of fillers) token.close(); replacement.close();
      const self = s.notifications.subscribe(method, async (context, value) => {
        if (value !== "self") return; self.close(); selfWait = await self.waitClosed({ context }); selfDone();
      }, options); tokens.push(self);
      await send("self"); await selfFinished;
      expect(selfWait).toMatchObject({ closed: true, wait: "dependency_unavailable", cleanupStatus: { status: "cleanup_incomplete" } });
      expect(await self.waitClosed()).toMatchObject({ wait: "complete", cleanupStatus: { status: "complete" } });
      expect(fifoValues).toEqual(["one", "two", "three", "self"]);
      service.close(); source.close();
      for (const token of tokens) { token.close(); expect(await token.waitClosed()).toMatchObject({ closed: true, wait: "complete" }); }
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally { release(); for (const token of tokens) token.close(); source?.close(); await Promise.all([c?.close(), s?.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("connects execution NOTIFY with one business dispatch, observer fanout, saved reference and management", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const request = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "notify", notifySemantics: "execution", request,
      requestMaxBytes: 128, responseRevision: "none-v1", restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.jobs", methods: { enqueue: method } });
    const common = { query: { typeID: 43, contractDigest: fill(32) }, resultRead: { typeID: 44, contractDigest: fill(33) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    const execution = { tenant: "tenant", audience: "service", namespace: definition.namespace, callerAuthorities: ["3".repeat(64)], maxRecords: 16, maxActive: 4, resultBytes: 1048576n };
    const observerOptions = { workClass: "short" as const, applicationBytes: 1024n, authorization: "authenticated" as const };
    let contract: ServiceContractSnapshot | undefined, release!: () => void, entered!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; }), began = new Promise<void>(resolve => { entered = resolve; });
    const business: string[] = [], observed: string[] = [], late: string[] = [];
    const client = endpoint("client", a, profile, "live_authority", 3000n, (_environment, material) => ({ ...common, localExecutionAuthority: "3".repeat(64),
      referenceTargets: [{ authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", material.server)).toString("hex") }] }] }),
      { profile: "execution", operationEntropy: fill(48, 24) });
    const server = endpoint("server", b, profile, "live_authority", 3000n, (environment, material) => {
      const resources = environment.resources, offerConfig = { bytes: 256, nodes: 16, textBytes: 128, arrayItems: 8, runtimeBytes: 1024n };
      const refs = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n), cborDecoderCharge(offerConfig)]
        .map((charge, index) => ({ accounts: resources.accounts, owner: { ...resources.owner, kind: `notify_execution_contract_${index}` }, charge })));
      let decoder: CBORDecoder | undefined;
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(2), 5: u(1),
          6: text("text-v1"), 7: text("none-v1"), 8: u(0), 9: u(0), 10: u(0), 13: u(0), 14: u(30000),
          16: u(10000), 17: u(60000), 18: u(10000), 19: u(1), 21: { kind: "bool", value: false }, 23: u(128), 27: array() })), 1024n, refs[0]!, refs[1]!);
        const contractDigest = new Uint8Array(32); contract.copyDigest(contractDigest); decoder = new CBORDecoder(offerConfig, refs[2]!);
        const document = decoder.decodeMap(encode(map({ 0: bytes(contractDigest), 1: u(900), 2: u(10000) })), "AdmissionOffer");
        let offer: AdmissionOffer;
        try { offer = new AdmissionOffer(document, contract, 10000n, new Uint8Array(32)); } finally { document.release(); }
        return { ...common, executionIdentity: { authority: "3".repeat(64), subject: "client", identityDigest: Buffer.from(digest("certificate_digest", material.client)).toString("hex") },
          executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }],
          queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
          notificationHandlers: [{ namespace: definition.namespace, method, contract, execution, offer, maximumOfferWindowMS: 10000n, options: observerOptions,
            handler: async (_context, value: string) => { business.push(value); if (value === "first") { entered(); await held; } } }] };
      } finally { decoder?.close(); for (const ref of refs) ref.release(); }
    }, { profile: "execution" });
    let c: V4Session | undefined, s: V4Session | undefined, store: V4OperationReferenceStore | undefined, database: DatabaseSync | undefined, directory: string | undefined;
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const subscription = s.notifications.subscribe(method, (_context, value) => { observed.push(value); }, observerOptions);
      expect(() => s!.notifications.subscribe(method, () => undefined, { ...observerOptions, pendingPolicy: "latest_pending" })).toThrow("configuration_capacity");
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      const service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n });
      const options = { deadlineAtMS: 40000n, admissionNotAfterMS: 5000n };
      const first = await service.prepareOperation(method, "first", options), reference = first.reference();
      expect("takeTypedResult" in first).toBe(false);
      expect(await c.queryOperation(reference)).toMatchObject({ status: "history_unknown" });
      expect(first.start()).toEqual({ status: "admitted" }); expect((await first.waitSubmission()).submission).toBe("submitted"); first.close();
      await expect.poll(() => business, { timeout: 1000 }).toEqual(["first"]); await began;
      expect(await c.queryOperation(reference)).toMatchObject({ status: "ok", observation: { state: "executing", resultAvailable: false, workActive: true } });
      await expect.poll(() => observed).toEqual(["first"]);
      const lateSubscription = s.notifications.subscribe(method, (_context, value) => { late.push(value); }, observerOptions);
      const duplicate = await service.prepareOperation(method, "first", options);
      expect(duplicate.start()).toEqual({ status: "admitted" }); expect((await duplicate.waitSubmission()).submission).toBe("submitted"); duplicate.close();
      const conflict = await service.prepareOperation(method, "different", options);
      expect(conflict.start()).toEqual({ status: "admitted" }); expect((await conflict.waitSubmission()).submission).toBe("submitted"); conflict.close();
      release();
      await expect.poll(async () => (await c!.queryOperation(reference)).observation?.state).toBe("completed");
      expect(await c.requestCancel(reference)).toMatchObject({ status: "ok", cancelResult: "terminal", observation: { resultAvailable: false, resultBytes: 0, resultNotAfterMS: 0n } });
      expect(() => c!.readOperationResult(reference)).toThrow("operation_reference_shape");
      directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-notify-reference-"));
      database = new DatabaseSync(join(directory, "references.sqlite"));
      database.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE saved (canonical BLOB NOT NULL)");
      const backing = database;
      store = createOperationReferenceStore(client.environment, { targetDomain: "authority", durability: "durable_create_or_compare", storage: "application_owned",
        maxRecords: 1, maxStoredBytes: 2048n, retentionMS: 60000n, maxConcurrentSaves: 1, applicationBytes: 65536n }, async (_context, record) => {
        backing.exec("BEGIN IMMEDIATE"); backing.prepare("INSERT INTO saved VALUES (?)").run(record.canonical); backing.exec("COMMIT");
        return "confirmed";
      });
      const saved = await service.prepareAndSave(method, "next", store, { ...options, admissionNotAfterMS: 6000n });
      expect(saved.status).toBe("prepared"); if (saved.status !== "prepared") throw new Error("notify_save_failed");
      const referenceCodec = createOperationReferenceCodec(client.environment);
      const imported = referenceCodec.import(backing.prepare("SELECT canonical FROM saved").get()!.canonical as Uint8Array, "authority"); referenceCodec.close();
      expect(await c.queryOperation(saved.reference)).toMatchObject({ status: "history_unknown" });
      saved.operation.start(); expect((await saved.operation.waitSubmission()).submission).toBe("submitted"); saved.operation.close();
      await expect.poll(async () => (await c!.queryOperation(imported)).observation?.state).toBe("completed");
      await expect.poll(() => observed).toEqual(["first", "next"]); await expect.poll(() => late).toEqual(["next"]);
      expect(business).toEqual(["first", "next"]);
      subscription.close(); lateSubscription.close(); expect((await subscription.waitClosed()).wait).toBe("complete");
      service.close(); store.close(); await Promise.all([c.close(), s.close()]);
      expect((await c.waitCleanup()).status).toBe("complete"); expect((await s.waitCleanup()).status).toBe("complete");
    } finally {
      try { release(); store?.close(); await Promise.all([c?.close(), s?.close()]); contract?.release(); await Promise.all([client.close(), server.close()]); }
      finally { database?.close(); if (directory !== undefined) rmSync(directory, { recursive: true, force: true }); }
    }
    expect(client.environment.resources.root.snapshot().reservations).toBe(0); expect(server.environment.resources.root.snapshot().reservations).toBe(0);
  });
  it.each([
    { shape: "unary", lostReceipt: false, applicationFailure: false }, { shape: "unary", lostReceipt: true, applicationFailure: false },
    { shape: "notify", lostReceipt: false, applicationFailure: false }, { shape: "server_streaming", lostReceipt: false, applicationFailure: false },
    { shape: "server_streaming", lostReceipt: false, applicationFailure: true }, { shape: "server_streaming", lostReceipt: true, applicationFailure: true },
  ] as const)("reopens durable execution $shape in a new Environment over an encrypted Session (lost receipt: $lostReceipt, application failure: $applicationFailure)", async ({ shape, lostReceipt, applicationFailure }) => {
    const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-execution-reopen-"));
    const path = join(directory, "execution.sqlite");
    // One explicit timeline spans both Environments. Expensive crypto/SQLite
    // fixture construction must not consume the fixed original admission window.
    let elapsedMS = 0n;
    const clockMS = () => elapsedMS;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = shape === "notify" ? new V4MethodDefinition<string, string, "notify", "execution">({
      typeID: 42, shape, request: codec, requestMaxBytes: 128, restartFlush: false, notifySemantics: "execution", responseRevision: "none-v1",
    }) : shape === "server_streaming" ? new V4MethodDefinition<string, string, "server_streaming", "execution">({
      typeID: 42, shape, request: codec, response: codec, requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128,
      restartFlush: false, serverStreamingSemantics: "execution", maxItemCount: 3, maxStreamPayloadBytes: 384n, maxStreamDurationMS: 10000n,
      errors: applicationFailure ? [{ code: 7, codec, maxPayloadBytes: 128 }] : [],
    }) : new V4MethodDefinition<string, string, "unary", "execution">({
      typeID: 42, shape, request: codec, response: codec, requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128,
      restartFlush: false, unarySemantics: "execution",
    });
    const definition = new V4ServiceDefinition({ namespace: "example.durable", methods: { echo: method } });
    const execution = { tenant: "tenant", audience: "service", namespace: definition.namespace, callerAuthorities: ["3".repeat(64)], maxRecords: 8, maxActive: 4, resultBytes: 1048576n };
    const common = { query: { typeID: 43, contractDigest: fill(32) }, resultRead: { typeID: 44, contractDigest: fill(33) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    const backings: ReturnType<typeof createSQLitePoolBacking>[] = [], environments: V4EnvironmentRuntime[] = [];
    const persisted = new Uint8Array(2048); let persistedBytes = 0, calls = 0, previousSettled = true;
    try {
      for (const generation of [0, 1]) {
        const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
        let contract: ServiceContractSnapshot | undefined, store: V4SQLiteExecutionStore | undefined;
        elapsedMS = BigInt(generation) * 1000n;
        const serviceOptions = { profile: "execution" as const, clockMS, operationEntropy: fill(48, 24), connectionSeed: 70 + generation };
        const client = endpoint("client", a, profile, "live_authority", 1000n, (_environment, material) => ({ ...common, localExecutionAuthority: "3".repeat(64),
          referenceTargets: [{ authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
            peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", material.server)).toString("hex") }] }] }), serviceOptions);
        environments.push(client.environment);
        const server = endpoint("server", b, profile, "live_authority", 1000n, (environment, material) => {
          environments.push(environment);
          const backing = createSQLitePoolBacking(environment, path, { maxPages: 512, maxRecords: 8, maxRecordBytes: 16384,
            runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n }); backings.push(backing);
          store = openV4SQLiteExecutionStore(backing, { create: generation === 0, service: execution, maxContracts: 4,
            identity: { authority: "execution", storeID: fill(5), generation: 1n },
            continuity: { check: (_identity, _service, epoch, provisioning) => {
              // This fixture proves settlement independently by waiting for the
              // previous Environment and all real handler work to terminate.
              if (!previousSettled || provisioning && generation !== 0 || epoch > BigInt(generation + 1)) throw new Error("unproven continuity");
            } } });
          const resources = environment.resources, offerConfig = { bytes: 256, nodes: 16, textBytes: 128, arrayItems: 8, runtimeBytes: 1024n };
          const references = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n), cborDecoderCharge(offerConfig)].map((charge, index) => ({
            accounts: resources.accounts, owner: { ...resources.owner, kind: `test_durable_contract_${index}` }, charge })));
          let decoder: CBORDecoder | undefined;
          try {
            contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42),
              ...(shape === "notify" ? { 2: u(2), 5: u(1) } : shape === "unary" ? { 2: u(0), 3: u(1), 15: u(30000) } : {
                2: u(1), 4: u(1), 24: u(3), 25: u(384), 26: u(10000), 28: map({ 0: u(0) }) }),
              6: text("text-v1"), 7: text(shape === "notify" ? "none-v1" : "text-v1"), 8: u(shape === "notify" ? 0 : 1), 9: u(0), 10: u(shape === "notify" ? 0 : 128), 13: u(1), 14: u(30000),
              16: u(10000), 17: u(60000), 18: u(10000), 19: u(1), 21: { kind: "bool", value: false }, 23: u(128), 27: applicationFailure ? array(map({ 0: u(7), 1: text("text-v1"), 2: u(128), 3: bytes(fill(31)) })) : array() })),
            1024n, references[0]!, references[1]!);
            if (generation === 0) expect(store.installContract(contract, [{ notBeforeMS: 900n, notAfterMS: 10000n }], 0n)).toBe(1n);
            const contractDigest = new Uint8Array(32); contract.copyDigest(contractDigest);
            const original = new Uint8Array(8192), registration = store.readRegistration(contractDigest, original);
            expect(registration).toMatchObject({ revision: 1n, enabled: true, typeID: 42, offers: [{ notBeforeMS: 900n, notAfterMS: 10000n }] });
            if (generation === 1) {
              contract.release();
              const restored = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n)].map((charge, index) => ({
                accounts: resources.accounts, owner: { ...resources.owner, kind: `test_restored_contract_${index}` }, charge })));
              try { contract = new ServiceContractSnapshot(original.subarray(0, registration.encodedBytes), 1024n, restored[0]!, restored[1]!); }
              finally { for (const reference of restored) reference.release(); }
            }
            original.fill(0);
            decoder = new CBORDecoder(offerConfig, references[2]!);
            const document = decoder.decodeMap(encode(map({ 0: bytes(contractDigest), 1: u(900), 2: u(10000) })), "AdmissionOffer");
            let offer: AdmissionOffer;
            try { offer = new AdmissionOffer(document, contract, 10000n, new Uint8Array(32)); } finally { document.release(); }
            const registrationConfig = { namespace: definition.namespace, method, contract, offer, maximumOfferWindowMS: 10000n, execution: store.service,
              options: { workClass: "short" as const, maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" as const } };
            const handlers: Partial<RPCApplicationConfig> = shape === "notify" ? {
              notificationHandlers: [{ ...registrationConfig, handler: () => { calls++; } }],
            } : shape === "server_streaming" ? {
              streamingHandlers: [{ ...registrationConfig, kind: "example.durable.stream", handler: async (_context, value: string, writer) => {
                calls++; await writer.write(`${value}:one`); await writer.write(`${value}:two`);
                if (applicationFailure) throw new V4ServiceError(7, "declined");
              } }],
            } : { unaryHandlers: [{ ...registrationConfig, handler: (_context, value: string) => { calls++; return value.toUpperCase(); } }] };
            return { ...common, ...handlers, executionIdentity: { authority: "3".repeat(64), subject: "client", identityDigest: Buffer.from(digest("certificate_digest", material.client)).toString("hex") },
              executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }],
              queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }] };
          } finally { decoder?.close(); for (const reference of references) reference.release(); }
        }, serviceOptions);
        let c: V4Session | undefined, s: V4Session | undefined;
        try {
          const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
          const referenceCodec = createOperationReferenceCodec(client.environment);
          try {
            if (generation === 1) {
              const imported = referenceCodec.import(persisted.subarray(0, persistedBytes), "authority");
              expect(await c.queryOperation(imported)).toMatchObject({ status: "ok", observation: { state: applicationFailure ? "failed" : "completed", workActive: false, resultAvailable: shape === "unary", resultDeleted: false, applicationErrorCode: applicationFailure ? 7 : 0 } });
              expect(await c.requestCancel(imported)).toMatchObject({ status: "ok", cancelResult: "terminal" });
              if (shape === "unary") {
                const read = c.readOperationResult(imported), result = await read.takeEncodedResult();
                expect(result).toMatchObject({ kind: "retained_result", bytes: new TextEncoder().encode("ORIGINAL") });
                if ("release" in result) result.release(); read.close();
              } else expect(() => c!.readOperationResult(imported)).toThrow("operation_reference_shape");
              expect(calls).toBe(1);
            }
            const service = await c.bindService(definition, { target: { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
              peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] }, maximumOfferWindowMS: 10000n,
                ...(shape === "server_streaming" ? { methods: [{ method, streamKind: "example.durable.stream" }] } : {}) });
            try {
              const options = { deadlineAtMS: 40000n, admissionNotAfterMS: 5000n };
              const operation = method.shape === "server_streaming" ? await service.prepareStreamOperation(method, "original", options)
                : method.shape === "notify" ? await service.prepareOperation(method, "original", options) : await service.prepareOperation(method, "original", options);
              if (!(operation instanceof V4ExecutionUnaryOperation || operation instanceof V4ExecutionStreamingOperation || operation instanceof V4ExecutionNotifyOperation)) throw new Error("missing execution capability");
              try {
                if (generation === 0) {
                  persistedBytes = referenceCodec.export(operation.reference(), persisted);
                  expect(await c.queryOperation(operation.reference())).toMatchObject({ status: "not_found", observation: { found: false, reason: "not_registered" } });
                  expect(await c.requestCancel(operation.reference())).toMatchObject({ status: "ok", cancelResult: "not_registered" });
                } else {
                  const reopened = new Uint8Array(2048), size = referenceCodec.export(operation.reference(), reopened);
                  expect(reopened.subarray(0, size)).toEqual(persisted.subarray(0, persistedBytes));
                }
                const originalExec = DatabaseSync.prototype.exec;
                let receiptLost = false;
                const fault = generation === 0 && lostReceipt ? vi.spyOn(DatabaseSync.prototype, "exec").mockImplementation(function(this: DatabaseSync, sql: string) {
                  originalExec.call(this, sql);
                  if (sql === "COMMIT" && calls === 1 && !receiptLost) {
                    receiptLost = true; throw new Error("lost receipt after real durable result COMMIT");
                  }
                }) : undefined;
                try {
                  expect(operation.start().status).toBe("admitted");
                  if (operation instanceof V4ExecutionUnaryOperation) {
                    const result = await operation.takeResult();
                    if (generation === 0 && lostReceipt) {
                      expect(receiptLost).toBe(true); expect(result).toMatchObject({ kind: "sdk_error" });
                    } else expect(result).toMatchObject({ kind: "value", value: "ORIGINAL" });
                    if ("release" in result) result.release();
                  } else if (operation instanceof V4ExecutionStreamingOperation) {
                    if (generation === 0) {
                      const first = await operation.readNext(), second = await operation.readNextEncoded();
                      expect(first).toMatchObject({ kind: "value", value: "original:one" });
                      expect(second).toMatchObject({ kind: "value", bytes: new TextEncoder().encode("original:two") });
                      if ("release" in first) first.release(); if ("release" in second) second.release();
                      const terminal = await operation.readNext();
                      expect(terminal).toMatchObject(applicationFailure ? lostReceipt ? { kind: "sdk_error", code: "service_failed" } : { kind: "application_error", error: "declined" } : { kind: "end" });
                      if ("release" in terminal) terminal.release();
                      if (lostReceipt) expect(receiptLost).toBe(true);
                    } else expect(await operation.readNextEncoded()).toMatchObject({ kind: "sdk_error", code: "service_unavailable" });
                  } else {
                    expect(await operation.waitSubmission()).toMatchObject({ submission: "submitted" });
                    if (generation === 1 && method.shape === "notify") {
                      // A later fresh notification on the same FIFO channel
                      // establishes that the duplicate was actually consumed.
                      const barrier = await service.prepareOperation(method, "barrier", { deadlineAtMS: 40000n, admissionNotAfterMS: 6000n });
                      if (!(barrier instanceof V4ExecutionNotifyOperation)) throw new Error("missing notify capability");
                      try {
                        barrier.start(); await barrier.waitSubmission();
                        await expect.poll(async () => (await c!.queryOperation(barrier.reference())).observation?.state).toBe("completed");
                      } finally { barrier.close(); }
                    }
                  }
                  if (!lostReceipt) await expect.poll(async () => (await c!.queryOperation(operation.reference())).observation?.state).toBe(applicationFailure ? "failed" : "completed");
                  expect(calls).toBe(shape === "notify" && generation === 1 ? 2 : 1);
                } finally { fault?.mockRestore(); }
              } finally { operation.close(); }
              if (generation === 1) {
                // Reopening preserved the original cutoff; it did not renew it.
                elapsedMS = 5000n;
                const expired = method.shape === "server_streaming" ? service.prepareStreamOperation(method, "original", options)
                  : service.prepareOperation(method, "original", options);
                await expect(expired).rejects.toThrow("admission_window_closed");
              }
            } finally { service.close(); }
          } finally { referenceCodec.close(); }
        } finally {
          previousSettled = false;
          await Promise.all([c?.close(), s?.close()]);
          contract?.release(); store?.close();
          await Promise.all([client.environment.close(), server.environment.close()]);
          expect((await server.environment.waitCleanup()).status).toBe("complete");
          expect(store?.cleanupComplete()).toBe(true); previousSettled = true;
          expect(backings[generation]!.retainedDiskBytes()).toBeGreaterThan(0n);
          expect(() => backings[generation]!.releaseRemoved()).toThrow("history_unknown");
        }
      }
    } finally {
      await Promise.all(environments.map(environment => environment.close()));
      rmSync(directory, { recursive: true, force: true }); for (const backing of backings) backing.releaseRemoved(); persisted.fill(0);
      for (const environment of environments) expect(environment.resources.root.snapshot().reservations).toBe(0);
    }
  });
  it.each([{ lostReceipt: false, signed: false, streaming: false, retained: false }, { lostReceipt: true, signed: false, streaming: false, retained: false },
    { lostReceipt: false, signed: true, streaming: false, retained: false }, { lostReceipt: false, signed: true, streaming: true, retained: false }, { lostReceipt: false, signed: true, streaming: true, retained: true }])("issues a checkpoint over encrypted RPC and reopens its original token ($lostReceipt, signed: $signed, streaming: $streaming, retained: $retained)", async ({ lostReceipt, signed, streaming, retained }) => {
    const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-checkpoint-chain-")), path = join(directory, "execution.sqlite");
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    // Recovery advances one shared logical clock instead of racing credential
    // construction against the unchanged operation and token deadlines.
    let elapsedMS = 0n;
    const clockMS = () => elapsedMS;
    const codec = v4BytesMessageCodec({ schemaDigest: fill(31), revision: "bytes-v1", maxMessageBytes: 512 });
    const contentDefinition = { schemaRevision: "content/1", readTypeID: 45, canonical: encode(map({
      0: text("explicit-selected-bytes"), 1: text("bytes:1..256"), 2: u(45), 3: text("target96+position"),
      4: text("flags2+commit8+expiry8+payload"), 5: text("missing-or-expired-without-payload") })) };
    let originalContent: V4ContentObservation | undefined;
    const method = streaming ? new V4MethodDefinition<Uint8Array, Uint8Array, "server_streaming", "execution">({ typeID: 42, shape: "server_streaming", serverStreamingSemantics: "execution", request: codec, response: codec,
      requestMaxBytes: 96, minResponseLimitBytes: 0, maxResponseBytes: 512, restartFlush: false, checkpointFormat: "position-v1",
      ...(retained ? { streamContent: contentDefinition } : {}), maxItemCount: 2, maxStreamPayloadBytes: 1024n, maxStreamDurationMS: 10000n }) : new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "execution", request: codec, response: codec,
      requestMaxBytes: 96, minResponseLimitBytes: 0, maxResponseBytes: 512, restartFlush: false, checkpointFormat: "position-v1" });
    const issuer = new V4MethodDefinition({ typeID: 45, shape: "unary", unarySemantics: "execution", request: codec, response: codec,
      requestMaxBytes: retained ? 128 : 96, minResponseLimitBytes: 0, maxResponseBytes: 512, restartFlush: false });
    const recoveryCodec = v4BytesMessageCodec({ schemaDigest: fill(34), revision: "bytes-v1", maxMessageBytes: 9345 });
    const recover = new V4MethodDefinition({ typeID: 46, shape: "unary", unarySemantics: "execution", request: recoveryCodec, response: recoveryCodec,
      requestMaxBytes: 9345, minResponseLimitBytes: 4248, maxResponseBytes: 4248, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.checkpoint", methods: { work: method, checkpoint: issuer, recover } });
    const execution = { tenant: "tenant", audience: "service", namespace: definition.namespace, callerAuthorities: ["3".repeat(64)], maxRecords: 8, maxActive: 4, resultBytes: 1048576n };
    const common = { query: { typeID: 43, contractDigest: fill(32) }, resultRead: { typeID: 44, contractDigest: fill(33) }, definitions: [definition], maxMethods: 3, maxCaptureBytes: 9345 };
    const environments: V4EnvironmentRuntime[] = [], backings: ReturnType<typeof createSQLitePoolBacking>[] = [];
    const saved = new Uint8Array(2048), issueRequest = new Uint8Array(96); let savedBytes = 0, token: Uint8Array | undefined;
    let calls = 0, issues = 0, previousSettled = true;
    const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
    try {
      for (const generation of [0, 1]) {
        const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
        let enteredResolve!: () => void, permitResolve!: () => void;
        const enteredPromise = new Promise<void>(resolve => { enteredResolve = resolve; });
        const permitPromise = new Promise<void>(resolve => { permitResolve = resolve; });
        const resumeEntered = { promise: enteredPromise, resolve: enteredResolve }, resumePermit = { promise: permitPromise, resolve: permitResolve };
        const contracts: ServiceContractSnapshot[] = []; let store: V4SQLiteExecutionStore | undefined;
        const controllerRouting = generation === 1 && !lostReceipt && !signed && !streaming && !retained;
        elapsedMS = BigInt(generation) * 1000n;
        const options = { profile: "execution" as const, resume: true, clockMS, operationEntropy: fill(48, 24), connectionSeed: 80 + generation,
          ...(controllerRouting ? { sessions: 3 } : {}) };
        const client = endpoint("client", a, profile, "live_authority", 1000n, (_environment, material) => ({ ...common,
          localExecutionAuthority: "3".repeat(64), referenceTargets: [{ authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
            peers: [{ subject: "server", identityDigest: hex(digest("certificate_digest", material.server)) }] }] }), options);
        environments.push(client.environment);
        const server = endpoint("server", b, profile, "live_authority", 1000n, (environment, material) => {
          environments.push(environment);
          const backing = createSQLitePoolBacking(environment, path, { maxPages: 512, maxRecords: 8, maxRecordBytes: 16384,
            runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n }); backings.push(backing);
          store = openV4SQLiteExecutionStore(backing, { ...(retained ? { content: { methods: [method], maxItemsPerOperation: 2, maxBytesPerOperation: 64, maxItemBytes: 32 } } : {}), create: generation === 0, service: execution, maxContracts: 4,
            identity: { authority: "execution", storeID: fill(5), generation: 1n }, checkpoint: {
              signingKey: signed ? { protection: "ed25519", keyID: fill(generation === 0 ? 60 : 62, 16), seed: fill(generation === 0 ? 61 : 63) } :
                { protection: "hmac_sha256", keyID: fill(generation === 0 ? 60 : 62, 16), macKey: fill(generation === 0 ? 61 : 63) },
              verificationKeys: generation === 0 ? [] : [signed ? { protection: "ed25519", keyID: fill(60, 16), publicKey: ed25519.getPublicKey(fill(61)) } :
                { protection: "hmac_sha256", keyID: fill(60, 16), macKey: fill(61) }],
              maxTokens: 8, maxTokensPerOperation: 1, maxTokenBytes: signed ? 4980 : 4948, maxIssuesPerWindow: 2, windowMS: 10000n },
            continuity: { check: (_id, _service, epoch, provisioning) => {
              if (!previousSettled || provisioning && generation !== 0 || epoch > BigInt(generation + 1)) throw new Error("unproven continuity");
            } } });
          const resources = environment.resources, offerConfig = { bytes: 256, nodes: 16, textBytes: 128, arrayItems: 8, runtimeBytes: 1024n };
          const registrations = [method, issuer, recover].map((entry, index) => {
            const refs = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n), cborDecoderCharge(offerConfig)].map((charge, at) => ({
              accounts: resources.accounts, owner: { ...resources.owner, kind: `checkpoint_contract_${index}_${at}` }, charge })));
            let decoder: CBORDecoder | undefined;
            try {
              const contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(entry.typeID),
                ...(entry.shape === "server_streaming" ? { 2: u(1), 4: u(1), 24: u(2), 25: u(1024), 26: u(10000), 28: retained ? map({ 0: u(1), 1: u(1), 2: u(60000), 3: u(2), 4: u(64), 5: text(contentDefinition.schemaRevision), 6: bytes(contentDefinition.canonical) }) : map({ 0: u(0) }) } : { 2: u(0), 3: u(1), 15: u(30000) }),
                6: text("bytes-v1"), 7: text("bytes-v1"), 8: u(1), 9: u(index === 2 ? 4248 : 0), 10: u(index === 2 ? 4248 : 512), 13: u(1), 14: u(30000),
                16: u(10000), 17: u(60000), 18: u(10000), 19: u(1), ...(index === 0 ? { 20: text("position-v1") } : {}),
                21: { kind: "bool", value: false }, 23: u(index === 2 ? 9345 : index === 1 && retained ? 128 : 96), 27: array() })), 1024n, refs[0]!, refs[1]!); contracts.push(contract);
              if (generation === 0) store!.installContract(contract, [{ notBeforeMS: 900n, notAfterMS: 10000n }], BigInt(index));
              const contractDigest = new Uint8Array(32); contract.copyDigest(contractDigest);
              decoder = new CBORDecoder(offerConfig, refs[2]!);
              const doc = decoder.decodeMap(encode(map({ 0: bytes(contractDigest), 1: u(900), 2: u(10000) })), "AdmissionOffer");
              let offer: AdmissionOffer; try { offer = new AdmissionOffer(doc, contract, 10000n, new Uint8Array(32)); } finally { doc.release(); }
              const registration = { namespace: definition.namespace, method: entry, contract, offer, maximumOfferWindowMS: 10000n, execution: store!.service,
                options: { workClass: "short" as const, maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: index === 2 && lostReceipt ? async () => { resumeEntered.resolve(); await resumePermit.promise; return true; } : "authenticated" as const },
                handler: (context: ServiceHandlersTypes.V4UnaryContext, request: Uint8Array) => {
                  if (index === 0) { calls++; return new Uint8Array([7, 8]); }
                  if (index === 2) throw new Error("Resume must not invoke the unary handler");
                  if (retained && request.length === 97) {
                    const payload = new Uint8Array(32), target = { tenant: context.authentication.tenant, audience: context.authentication.audience, namespace: definition.namespace,
                      subject: context.authentication.peerSubject, authority: "3".repeat(64), operation: hex(request.subarray(0, 32)), requestDigest: hex(request.subarray(32, 64)), contractDigest: hex(request.subarray(64, 96)) };
                    const content = readV4RetainedContent(context, target, request.subarray(96), payload);
                    const response = new Uint8Array(18 + (content.available ? content.bytes : 0)), view = new DataView(response.buffer);
                    response[0] = content.found ? 1 : 0; response[1] = content.available ? 1 : 0;
                    view.setBigUint64(2, content.committedAtMS); view.setBigUint64(10, content.expiresAtMS);
                    if (content.available) response.set(payload.subarray(0, content.bytes), 18);
                    return response;
                  }
                  issues++;
                  if (request.length !== 96) throw new Error("invalid checkpoint source");
                  return issueV4Checkpoint(context, { tenant: context.authentication.tenant, audience: context.authentication.audience, namespace: definition.namespace,
                    subject: context.authentication.peerSubject, authority: "3".repeat(64), operation: hex(request.subarray(0, 32)),
                    requestDigest: hex(request.subarray(32, 64)), contractDigest: hex(request.subarray(64, 96)) },
                  { format: "position-v1", position: streaming ? new Uint8Array(readFileSync(join(directory, "progress"))) : new Uint8Array([3, 4]) }, { durationMS: 20000n, applicationDurationLimitMS: 10000n, historyNotAfterMS: 25000n });
                } };
              if (entry.shape === "server_streaming") return { streaming: { ...registration, kind: "example.checkpoint.stream",
                handler: async (_context: StreamHandlersTypes.V4ApplicationContext, _request: Uint8Array, writer: ServiceHandlersTypes.V4StreamWriter<Uint8Array>) => {
                  calls++;
                  if (retained) {
                    originalContent = saveV4StreamContent(_context, new Uint8Array([1]), new Uint8Array([3]));
                    expect(saveV4StreamContent(_context, new Uint8Array([1]), new Uint8Array([3]))).toEqual(originalContent);
                  }
                  await writer.write(new Uint8Array([3]));
                  writeFileSync(join(directory, "progress"), new Uint8Array([3, 4]), { flush: true });
                  await writer.write(new Uint8Array([4]));
                } } };
              return { unary: registration };
            } finally { decoder?.close(); for (const ref of refs) ref.release(); }
          });
          return { ...common, unaryHandlers: registrations.flatMap(entry => entry.unary === undefined ? [] : [entry.unary]),
            streamingHandlers: registrations.flatMap(entry => entry.streaming === undefined ? [] : [entry.streaming]), executionIdentity: { authority: "3".repeat(64), subject: "client", identityDigest: hex(digest("certificate_digest", material.client)) },
            executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }],
            queryPermissions: [method, issuer, recover].map(entry => ({ namespace: definition.namespace, method: entry, permission: "allowed" as const })) };
        }, options);
        let c: V4Session | undefined, s: V4Session | undefined, replacementPeer: V4Session | undefined;
        let controller: ReturnType<typeof createV4ConnectionController> | undefined;
        let controllerAcquisitions = 0;
        try {
          if (controllerRouting) {
            await client.discardPrepared();
            const nextA = new MemoryTransport("client", "message"), nextB = new MemoryTransport("server", "message"); nextA.peer = nextB; nextB.peer = nextA;
            const nextOptions = { ...options, connectionSeed: 91 };
            const nextClient = endpoint("client", nextA, profile, "live_authority", 1000n, () => client.config.application!, { ...nextOptions, environment: client.environment });
            await nextClient.discardPrepared();
            const nextServer = endpoint("server", nextB, profile, "live_authority", 1000n, () => common, nextOptions);
            environments.push(nextServer.environment);
            const candidates = [{ client, server }, { client: nextClient, server: nextServer }]; let selected = 0;
            const environment = client.environment;
            const source = wrapCredentialSource(environment.registerSource({ ...client.material.config, authorities: ["authority"] }, "live_authority", async (_request, destination) => {
              selected = controllerAcquisitions++; const input = candidates[selected]!.client.material.input();
              for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) destination[name].set(input[name]);
              return { artifact: input.artifact.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length,
                activation: input.activation.length, candidateIndex: input.candidateIndex };
            }));
            environment.installClientConnector({ applicationProfile: candidates[0]!.client.config.info.application_profile, reserveAdmission: () => environment.reserveClientAdmission(candidates[controllerAcquisitions]!.client.config), checkRequirements: () => undefined, connect: async (material, connectOptions) => {
              const index = selected, pair = candidates[index]!;
              const [runtime, remote] = await Promise.all([pair.client.establishMaterial(material, connectOptions?.signal), pair.server.establish()]);
              if (index === 0) s = new V4Session(remote); else replacementPeer = new V4Session(remote);
              return runtime;
            } });
            controller = createV4ConnectionController(wrapTransportEnvironment(environment), { source,
              requirements: { independent_reliable_read_progress: false, bound_stream_input_isolation: false, datagram: false,
                local_consumer_tls13_verification: false, application_profile: "execution" }, attemptTimeoutMS: 10000n });
            await controller.replaceSession(); c = controller.captureSession();
          } else {
            const ready = await Promise.all([client.establish(), server.establish()]); c = new V4Session(ready[0]); s = new V4Session(ready[1]);
          }
          if (c === undefined || s === undefined) throw new Error("missing established Session");
          const refs = createOperationReferenceCodec(client.environment);
          const service = await (controller ?? c).bindService(definition, { target: { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
            peers: [{ subject: "server", identityDigest: hex(digest("certificate_digest", server.material.server)) }] }, maximumOfferWindowMS: 10000n, methods: [{ method: recover, resumeKind: "example/recover" }, ...(streaming ? [{ method, streamKind: "example.checkpoint.stream" }] : [])] });
          try {
            if (generation === 0) {
              const work = method.shape === "server_streaming" ? await service.prepareStreamOperation(method, new Uint8Array(), { deadlineAtMS: 40000n, admissionNotAfterMS: 5000n }) :
                await service.prepareOperation(method, new Uint8Array(), { deadlineAtMS: 40000n, admissionNotAfterMS: 5000n });
              if (!(work instanceof V4ExecutionUnaryOperation || work instanceof V4ExecutionStreamingOperation)) throw new Error("missing execution capability");
              try {
                const target = operationReferenceState(work.reference()).target;
                issueRequest.set(Buffer.from(target.operation + target.requestDigest + target.contractDigest, "hex"));
                expect(work.start().status).toBe("admitted");
                if (work instanceof V4ExecutionStreamingOperation) {
                  const first = await work.readNext(); expect(first).toMatchObject({ kind: "value", value: new Uint8Array([3]) });
                  if ("release" in first) first.release();
                  const item = await work.readNextEncoded(); expect(item).toMatchObject({ kind: "value", bytes: new Uint8Array([4]) });
                  if ("release" in item) item.release();
                  expect(await work.readNext()).toMatchObject({ kind: "end" });
                  expect(await c.queryOperation(work.reference())).toMatchObject({ status: "ok", observation: { state: "completed", resultAvailable: false } });
                } else {
                  const result = await work.takeEncodedResult();
                  expect(result).toMatchObject({ kind: "value", bytes: new Uint8Array([7, 8]) }); if ("release" in result) result.release();
                }
              } finally { work.close(); }
            } else {
              const imported = refs.import(saved.subarray(0, savedBytes), "authority");
              expect(await c.queryOperation(imported)).toMatchObject({ status: "ok", observation: { state: "completed", workActive: false, resultAvailable: true } });
              const read = c.readOperationResult(imported);
              try {
                const result = await read.takeEncodedResult(); expect(result.kind).toBe("retained_result");
                if (result.kind === "retained_result" && "bytes" in result) { if (token === undefined) token = new Uint8Array(result.bytes); else expect(result.bytes).toEqual(token); }
                if ("release" in result) result.release();
              } finally { read.close(); }
            }
            const issue = await service.prepareOperation(issuer, issueRequest, { deadlineAtMS: 40000n, admissionNotAfterMS: 6000n });
            if (!(issue instanceof V4ExecutionUnaryOperation)) throw new Error("missing execution capability");
            try {
              if (generation === 0) savedBytes = refs.export(issue.reference(), saved);
              else {
                const reopened = new Uint8Array(2048), size = refs.export(issue.reference(), reopened);
                expect(reopened.subarray(0, size)).toEqual(saved.subarray(0, savedBytes));
              }
              const exec = DatabaseSync.prototype.exec; let receiptLost = false;
              const fault = generation === 0 && lostReceipt ? vi.spyOn(DatabaseSync.prototype, "exec").mockImplementation(function(this: DatabaseSync, sql: string) {
                exec.call(this, sql); if (sql === "COMMIT" && issues === 1 && !receiptLost) { receiptLost = true; throw new Error("lost checkpoint commit receipt"); }
              }) : undefined;
              try {
                expect(issue.start().status).toBe("admitted"); const result = await issue.takeEncodedResult();
                if (generation === 0 && lostReceipt) { expect(receiptLost).toBe(true); expect(result.kind).toBe("sdk_error"); }
                else {
                  expect(result.kind).toBe("value");
                  if (result.kind === "value" && "bytes" in result) { if (token === undefined) token = new Uint8Array(result.bytes); else expect(result.bytes).toEqual(token); }
                }
                if ("release" in result) result.release();
              } finally { fault?.mockRestore(); }
              if (!lostReceipt || generation === 1) {
                const read = c.readOperationResult(issue.reference());
                try { const result = await read.takeEncodedResult(); expect(result).toMatchObject({ kind: "retained_result", bytes: token }); if ("release" in result) result.release(); }
                finally { read.close(); }
              }
              expect(calls).toBe(1); expect(issues).toBe(1);
              if (generation === 1) {
                if (retained) {
                  for (const position of [1, 2]) {
                    const request = new Uint8Array(97); request.set(issueRequest); request[96] = position;
                    const reader = await service.prepareOperation(issuer, request, { deadlineAtMS: 40000n, admissionNotAfterMS: 6500n + BigInt(position) });
                    try {
                      expect(reader.start().status).toBe("admitted");
                      const result = await reader.takeEncodedResult();
                      try {
                        expect(result).toMatchObject({ kind: "value" });
                        if (result.kind === "value" && "bytes" in result) {
                          expect(result.bytes[0]).toBe(position === 1 ? 1 : 0); expect(result.bytes[1]).toBe(position === 1 ? 1 : 0);
                          expect(result.bytes.length).toBe(position === 1 ? 19 : 18);
                          if (position === 1) {
                            const view = new DataView(result.bytes.buffer, result.bytes.byteOffset, result.bytes.byteLength);
                            expect(view.getBigUint64(2)).toBe(originalContent!.committedAtMS); expect(view.getBigUint64(10)).toBe(originalContent!.expiresAtMS);
                            expect(result.bytes[18]).toBe(3);
                          }
                        }
                      } finally { if ("release" in result) result.release(); }
                    } finally { reader.close(); }
                  }
                  expect(calls).toBe(1);
                }
                const fresh = await service.prepareOperation(issuer, issueRequest, { deadlineAtMS: 40000n, admissionNotAfterMS: 7000n });
                try {
                  expect(fresh.start().status).toBe("admitted");
                  expect(await fresh.takeEncodedResult()).toMatchObject({ kind: "sdk_error", code: "resource_exhausted" });
                } finally { fresh.close(); }
                expect(issues).toBe(2);
                const settings = { bytes: 4948, nodes: 64, textBytes: 640, arrayItems: 8, runtimeBytes: 1024n }, resources = client.environment.resources;
                const reference = resources.root.reserve({ accounts: resources.accounts, owner: { ...resources.owner, kind: "checkpoint_wire_assertions" }, charge: cborDecoderCharge(settings) });
                let decoder: CBORDecoder | undefined;
                try {
                  decoder = new CBORDecoder(settings, reference);
                  const doc = decoder.decodeMap(token!, signed ? "ResumeSignedToken" : "ResumeMACToken");
                  try {
                    const claims = doc.field(0, 0), checkpoint = doc.field(claims, 6), position = new Uint8Array(2), tag = new Uint8Array(signed ? 64 : 32);
                    expect(doc.uint(doc.field(claims, 7))).toBe(0n);
                    expect(doc.uint(doc.field(claims, 9)) - doc.uint(doc.field(claims, 8))).toBe(8000n);
                    expect(doc.uint(doc.field(claims, 9))).toBeLessThanOrEqual(25000n);
                    expect(doc.text(doc.field(checkpoint, 0))).toBe("position-v1");
                    doc.copyPayload(doc.field(checkpoint, 1), position); expect(position).toEqual(new Uint8Array([3, 4]));
                    doc.copyPayload(doc.field(0, 2), tag);
                    const unsigned = new Uint8Array(4948), size = doc.copyWithoutField(2, unsigned), length = Buffer.alloc(4); length.writeUInt32BE(size);
                    if (signed) {
                      const publicKey = createPublicKey({ format: "der", type: "spki", key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), ed25519.getPublicKey(fill(61))]) });
                      const input = Buffer.concat([Buffer.from("flowersec/v4/resume-token/signature\0", "ascii"), length, unsigned.subarray(0, size)]);
                      expect(verifySignature(null, input, publicKey, tag)).toBe(true);
                    } else {
                      const expected = createHmac("sha256", fill(61)).update(Buffer.from("flowersec/v4/resume-token/mac\0", "ascii")).update(length).update(unsigned.subarray(0, size)).digest();
                      expect(tag).toEqual(new Uint8Array(expected));
                    }
                    unsigned.fill(0); tag.fill(0);
                  } finally { doc.release(); }
                } finally { decoder?.close(); reference.release(); }
                const read = c.readOperationResult(issue.reference());
                try { const result = await read.takeEncodedResult(); expect(result).toMatchObject({ kind: "retained_result", bytes: token }); if ("release" in result) result.release(); }
                finally { read.close(); }
                let recoveredCalls = 0, observed: ResumeTypes.V4ResumeProgress | undefined;
                const registration = s.registerStream("example/recover", undefined, async (stream, context) => {
                  recoveredCalls++; observed = v4RecoveryProgress(context);
                  await stream.write(new Uint8Array([7, 6]));
                  const input = await stream.read(16n); await stream.write(input.data); await stream.closeWrite();
                }, { applicationBytes: 8192n, resume: { namespace: definition.namespace, method: recover } });
                const referenceDB = new DatabaseSync(join(directory, "references.sqlite"));
                referenceDB.exec("CREATE TABLE saved (identity TEXT PRIMARY KEY, canonical BLOB NOT NULL)");
                let saveEntered!: () => void, saveRelease!: () => void, deferSave = true;
                const saving = new Promise<void>(resolve => { saveEntered = resolve; }), saveTail = new Promise<void>(resolve => { saveRelease = resolve; });
                const referenceStore = createOperationReferenceStore(client.environment, { targetDomain: "authority", durability: "durable_create_or_compare", storage: "application_owned",
                  maxRecords: 1, maxStoredBytes: 2048n, retentionMS: 60000n, maxConcurrentSaves: 1, applicationBytes: 65536n }, async (_context, record) => {
                  if (deferSave) { saveEntered(); await saveTail; return "unknown"; }
                  referenceDB.prepare("INSERT INTO saved VALUES (?,?)").run(record.identity, record.canonical); return "confirmed";
                });
                try {
                  const target = await c.openStream("example/recover");
                  if (controller !== undefined) {
                    await controller.replaceSession({ retirement: "retain", retainUntilMS: 20000n });
                    expect(controller.captureSession()).not.toBe(c); expect(controllerAcquisitions).toBe(2);
                  }
                  const abandoned = await service.prepareResume(recover, target, token!, { deadlineAtMS: 40000n, admissionNotAfterMS: 8000n });
                  expect(() => target.acquireCursor(1n)).toThrow("stream_owned"); abandoned.close();
                  // A canceled save observation cannot return the target while
                  // the original provider task still owns the local operation.
                  const canceledSave = new AbortController();
                  const savingResume = service.prepareResumeAndSave(recover, target, token!, referenceStore,
                    { deadlineAtMS: 40000n, admissionNotAfterMS: 8000n, signal: canceledSave.signal });
                  await saving; canceledSave.abort();
                  expect(await savingResume).toMatchObject({ status: "not_prepared", save: { attempted: true, outcome: "unknown" } });
                  expect(() => target.acquireCursor(1n)).toThrow("stream_owned");
                  deferSave = false; saveRelease();
                  await vi.waitFor(() => expect(referenceStore.cleanupStatus().pending_callbacks).toBe(0n), { timeout: 1000, interval: 5 });
                  // Closing an unused preparation returns this exact target.
                  const savedResume = await service.prepareResumeAndSave(recover, target, token!, referenceStore, { deadlineAtMS: 40000n, admissionNotAfterMS: 8000n });
                  expect(savedResume.status).toBe("prepared");
                  if (savedResume.status !== "prepared") throw new Error(savedResume.reason);
                  const operation = savedResume.operation;
                  try {
                    expect(recoveredCalls).toBe(0); expect(operation.status().submission).toBe("not_submitted");
                    expect(operation.start().status).toBe("admitted");
                    if (lostReceipt) {
                      await resumeEntered.promise; operation.close();
                      expect(operation.status()).toMatchObject({ submission: "submitted", payloadStatus: "explicitly_abandoned" });
                      expect(() => target.acquireCursor(1n)).toThrow("stream_owned");
                      expect(operation.cleanupStatus().status).toBe("pending");
                      resumePermit.resolve();
                      await vi.waitFor(() => expect(operation.cleanupStatus().status).toBe("complete"), { timeout: 1000, interval: 5 });
                      expect(await operation.takeResult()).toMatchObject({ kind: "metadata" });
                    } else {
                      const result = await operation.takeResult();
                      expect(result).toMatchObject({ kind: "value", value: { status: "accepted", generation: 1n, checkpoint: { format: "position-v1", position: new Uint8Array([3, 4]) } } });
                      if ("release" in result) result.release(); operation.close();
                    }
                    expect((await target.read(16n)).data).toEqual(new Uint8Array([7, 6]));
                    expect(observed).toMatchObject({ generation: 1n, checkpoint: { format: "position-v1", position: new Uint8Array([3, 4]) } });
                    await target.write(new Uint8Array([9])); expect((await target.read(16n)).data).toEqual(new Uint8Array([9]));
                    await target.closeWrite(); await target.finish();
                    const row = referenceDB.prepare("SELECT canonical FROM saved").get()!;
                    const importedResume = refs.import(row.canonical as Uint8Array, "authority");
                    expect(await c.queryOperation(importedResume)).toMatchObject({ status: "ok", observation: { state: "completed", workActive: false, resultAvailable: true } });
                    const replay = c.readOperationResult(importedResume);
                    try { const result = await replay.takeEncodedResult(); expect(result.kind).toBe("retained_result"); if ("release" in result) result.release(); }
                    finally { replay.close(); }
                  } finally { operation.close(); await target.close(); }
                  const other = await c.openStream("example/recover");
                  const rejected = await service.resume(recover, other, token!, { deadlineAtMS: 40000n, admissionNotAfterMS: 8500n, admission: "try_now" });
                  try {
                    const result = await rejected.takeEncodedResult(); expect(result).toMatchObject({ kind: "value", bytes: new Uint8Array([0xa1, 0x00, 0x01]) });
                    if ("release" in result) result.release(); expect(recoveredCalls).toBe(1);
                  } finally { rejected.close(); await other.close(); }
                } finally { saveRelease(); registration.close(); referenceStore.close(); referenceDB.close(); }

              }
            } finally { issue.close(); }
            if (generation === 1 && !controllerRouting) {
              elapsedMS = 6000n;
              await expect(service.prepareOperation(issuer, issueRequest, { deadlineAtMS: 40000n, admissionNotAfterMS: 6000n }))
                .rejects.toThrow("admission_window_closed");
            }
          } finally { service.close(); refs.close(); }
        } finally {
          resumePermit.resolve(); previousSettled = false; await controller?.close(); await replacementPeer?.close(); await Promise.all([c?.close(), s?.close()]); contracts.forEach(contract => contract.release()); store?.close();
          await Promise.all([client.environment.close(), server.environment.close()]);
          expect((await server.environment.waitCleanup()).status).toBe("complete"); expect(store?.cleanupComplete()).toBe(true); previousSettled = true;
        }
        if (generation === 0 && !signed && !lostReceipt) {
          // The single-MAC producer records a key fingerprint in its manifest.
          // It must not pin that key as authority after an explicit rotation.
          const persisted = new DatabaseSync(path);
          try {
            const row = persisted.prepare("SELECT configuration FROM manifest WHERE id=1").get()!;
            const configuration = JSON.parse(row.configuration as string);
            configuration.checkpoint.keyID = hex(fill(60, 16));
            configuration.checkpoint.macKey = createHash("sha256").update(fill(61)).digest("hex");
            persisted.prepare("UPDATE manifest SET configuration=? WHERE id=1").run(JSON.stringify(configuration));
          } finally { persisted.close(); }
        }
      }
      expect(token).toBeDefined();
    } finally {
      await Promise.all(environments.map(environment => environment.close()));
      rmSync(directory, { recursive: true, force: true }); for (const backing of backings) backing.releaseRemoved(); saved.fill(0); token?.fill(0);
      for (const environment of environments) expect(environment.resources.root.snapshot().reservations).toBe(0);
    }
  }, 15000);
  it.each(["message", "stream"] as const)("returns temporary recovery framing to the same live Stream over %s transport", async mode => {
    const a = new MemoryTransport("client", mode), b = new MemoryTransport("server", mode); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", origin = performance.now();
    const configuration = () => ({ query: { typeID: 43, contractDigest: fill(32) }, definitions: [], maxMethods: 1, maxCaptureBytes: 128 });
    const options = { profile: "execution" as const, resume: true, clockOriginMS: origin };
    const client = endpoint("client", a, profile, "live_authority", 1000n, configuration, options);
    const server = endpoint("server", b, profile, "live_authority", 1000n, configuration, options);
    const framing: RPCStreamMessages[] = []; let sequence = 0;
    const messages = (environment: V4EnvironmentRuntime, stream: PublicTypes.V4StreamOwner, session: object, kind = "example/recover") => {
      const resources = environment.resources, costs = rpcStreamMessagesCharges(1024n), id = ++sequence;
      const refs = resources.root.reserveBatch(costs.map((charge, index) => ({ accounts: resources.accounts,
        owner: { ...resources.owner, kind: `resume_framing_${id}_${index}` }, charge })));
      let owner: RPCStreamMessages | undefined;
      const group = applicationGroup(resources.root, resources.accounts, { ...resources.owner, kind: `resume_framing_group_${id}` }, 1024n, false, refs[5]!);
      const position = resources.root.protect(refs[4]!, costs[4]!);
      try {
        owner = new RPCStreamMessages(1024n, refs, position, group); framing.push(owner);
        const target = owner.attachResume(stream, session, kind, refs[1]!); return { owner, target };
      } catch (error) { owner?.close(); group.close(); position.closeAfterUse(); throw error; }
      finally { refs.forEach(reference => reference.release()); }
    };
    let c: V4Session | undefined, s: V4Session | undefined;
    try {
      const ready = await Promise.all([client.establish(), server.establish()]); c = new V4Session(ready[0]); s = new V4Session(ready[1]);
      const [out, incoming] = await Promise.all([c.openStream("example/recover"), s.acceptStream()]);
      const input = incoming.stream;
      expect(() => messages(client.environment, out, ready[1])).toThrow("configuration_capacity");
      expect(() => messages(client.environment, out, ready[0], "example/wrong")).toThrow("configuration_capacity");
      const unused = messages(client.environment, out, ready[0]);
      expect(() => out.acquireCursor(1n)).toThrow("stream_owned");
      unused.owner.releaseUnusedResume(); expect(unused.owner.cleanupComplete()).toBe(true);
      // Preparation cancellation returned this exact unused target; another
      // explicit preparation may capture it without creating another Stream.
      const left = messages(client.environment, out, ready[0]), right = messages(server.environment, input, ready[1]);
      expect(left.target.sameSession(ready[0])).toBe(true); expect(left.target.sameSession(ready[1])).toBe(false);
      expect(left.target.streamID).toBe(right.target.streamID);
      expect(left.target.transportContextDigest).toBe(right.target.transportContextDigest);
      expect(left.target.transportContextDigest).toBe(Buffer.from(client.config.ready.transportContextDigest).toString("hex"));
      expect(() => messages(client.environment, out, ready[0])).toThrow("stream_owned");
      expect(() => left.owner.returnResumeBoundary()).toThrow("rpc_stream_incomplete");
      const payload = new Uint8Array([1, 2, 3]), reply = new Uint8Array([4, 5]);
      const request = left.owner.codec().create({ kind: "resume_request", operationID: fill(10), typeID: 42, payloadBytes: payload.length,
        requestDigest: fill(11), deadlineAtMS: 40000n, contractDigest: fill(12), admissionMode: 0, responseLimitBytes: 512 });
      const receive = new Uint8Array(payload.length), result = new Uint8Array(reply.length);
      const read = right.owner.read(header => {
        expect(header.kind).toBe("resume_request"); return { write: (offset, bytes) => receive.set(bytes, offset), finish: () => undefined };
      });
      await left.owner.send(request, payload, () => left.target.check());
      const received = await read; expect(receive).toEqual(payload);
      expect(() => right.owner.returnResumeBoundary()).toThrow("rpc_stream_incomplete"); right.owner.consume();
      expect(() => left.owner.releaseUnusedResume()).toThrow("rpc_stream_incomplete");
      const response = right.owner.codec().response(received!, "resume_response", reply.length);
      await right.owner.send(response, reply, () => right.target.check());
      right.owner.returnResumeBoundary(); right.owner.close(); expect(right.owner.cleanupComplete()).toBe(true);
      // Following application bytes can already be queued behind the framed
      // reply. Returning message ownership must leave those bytes untouched.
      const following = new TextEncoder().encode("after-resume"); await input.write(following);
      const returned = await left.owner.read(header => {
        header.checkResponse(request); return { write: (offset, bytes) => result.set(bytes, offset), finish: () => undefined };
      });
      expect(returned?.kind).toBe("resume_response"); expect(result).toEqual(reply);
      expect(() => out.acquireCursor(1n)).toThrow("stream_owned");
      left.owner.consume(); left.owner.returnResumeBoundary(); left.owner.close(); expect(left.owner.cleanupComplete()).toBe(true);
      expect((await out.read(128n)).data).toEqual(following);
      const nextRead = input.read(128n); await out.write(new Uint8Array([9])); expect((await nextRead).data).toEqual(new Uint8Array([9]));
      expect(() => messages(client.environment, out, ready[0])).toThrow("stream_owned");
      await Promise.all([out.closeWrite(), input.closeWrite()]);
      await Promise.all([out.finish(), input.finish()]);
    } finally {
      framing.forEach(owner => owner.close()); await Promise.all([c?.close(), s?.close()]);
      await Promise.all([client.close(), server.close()]);
      for (const owner of framing) expect(owner.cleanupComplete()).toBe(true);
    }
  });
  it.each(["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"] as const)("joins one volatile execution and retains its result independently of the response (%s)", async profile => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const codec = v4UTF8MessageCodec({ schemaDigest: fill(31), revision: "text-v1", maxMessageBytes: 128 });
    const method = new V4MethodDefinition({ typeID: 42, shape: "unary", unarySemantics: "execution", request: codec, response: codec,
      requestMaxBytes: 128, minResponseLimitBytes: 0, maxResponseBytes: 128, restartFlush: false });
    const definition = new V4ServiceDefinition({ namespace: "example.execution", methods: { echo: method } });
    const execution = { tenant: "tenant", audience: "service", namespace: definition.namespace, callerAuthorities: ["3".repeat(64)], maxRecords: 16, maxActive: 4, resultBytes: 1048576n };
    const authorizedClientSubjects = ["client", "administrator"];
    const common = { query: { typeID: 43, contractDigest: fill(32) }, resultRead: { typeID: 44, contractDigest: fill(33) }, definitions: [definition], maxMethods: 1, maxCaptureBytes: 128 };
    let staticExecution: V4StaticServiceContracts | undefined, suppliedOffer: AdmissionOffer | undefined;
    let contract: ServiceContractSnapshot | undefined, calls = 0, releaseHandler!: () => void, enteredHandler!: () => void;
    const entered = new Promise<void>(resolve => { enteredHandler = resolve; }), release = new Promise<void>(resolve => { releaseHandler = resolve; });
    const client = endpoint("client", a, profile, "live_authority", 1000n, (_environment, material) => ({ ...common, localExecutionAuthority: "3".repeat(64),
      referenceTargets: [{ authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", material.server)).toString("hex") }] }] }),
    { profile: "execution", operationEntropy: fill(48, 24), authorizedClientSubjects });
    const server = endpoint("server", b, profile, "live_authority", 1000n, (environment, material) => {
      const resources = environment.resources, offerConfig = { bytes: 256, nodes: 16, textBytes: 128, arrayItems: 8, runtimeBytes: 1024n };
      const references = resources.root.reserveBatch([serviceContractCharge(1024n), serviceContractDecoderCharge(1024n), cborDecoderCharge(offerConfig)].map((charge, index) => ({
        accounts: resources.accounts, owner: { ...resources.owner, kind: `test_execution_contract_${index}` }, charge })));
      let decoder: CBORDecoder | undefined;
      try {
        contract = new ServiceContractSnapshot(encode(map({ 0: text(definition.namespace), 1: u(42), 2: u(0), 3: u(1),
          6: text("text-v1"), 7: text("text-v1"), 8: u(1), 9: u(0), 10: u(128), 13: u(0), 14: u(30000), 15: u(30000),
          16: u(10000), 17: u(60000), 18: u(10000), 19: u(1), 21: { kind: "bool", value: false }, 23: u(128), 27: array() })),
        1024n, references[0]!, references[1]!);
        const contractDigest = new Uint8Array(32); contract.copyDigest(contractDigest);
        decoder = new CBORDecoder(offerConfig, references[2]!);
        const document = decoder.decodeMap(encode(map({ 0: bytes(contractDigest), 1: u(900), 2: u(10000) })), "AdmissionOffer");
        let offer: AdmissionOffer;
        try { suppliedOffer = offer = new AdmissionOffer(document, contract, 10000n, new Uint8Array(32)); } finally { document.release(); }
        return { ...common, executionIdentity: { authority: "3".repeat(64), subject: "client", identityDigest: Buffer.from(digest("certificate_digest", material.client)).toString("hex") },
          executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }],
          queryPermissions: [{ namespace: definition.namespace, method, permission: "allowed" }],
          unaryHandlers: [{ namespace: definition.namespace, method, contract, offer, maximumOfferWindowMS: 10000n,
            execution,
            handler: async (_context, value: string) => { calls++; enteredHandler(); await release; return value.toUpperCase(); },
            options: { workClass: "short", maxConcurrentCalls: 4, applicationBytes: 1024n, authorization: "authenticated" } }] };
      } finally { decoder?.close(); for (const reference of references) reference.release(); }
    }, { profile: "execution", authorizedClientSubjects });
    let c: V4Session | undefined, s: V4Session | undefined, referenceStore: V4OperationReferenceStore | undefined;
    let adminClient: ReturnType<typeof endpoint> | undefined, adminSession: V4Session | undefined, adminServerSession: V4Session | undefined;
    let referenceDirectory: string | undefined, referenceDB: DatabaseSync | undefined, releaseStore: (() => void) | undefined;
    let saveMode: "normal" | "unknown" | "delayed" = "normal", storeCalls = 0, storeEntered: (() => void) | undefined;
    try {
      const established = await Promise.all([client.establish(), server.establish()]); c = new V4Session(established[0]); s = new V4Session(established[1]);
      const target = { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] };
      const contractBytes = new Uint8Array(contract!.encodedBytes()), offerBytes = new Uint8Array(256); contract!.copyEncoded(contractBytes);
      const offerLength = suppliedOffer!.copyEncoded(contract!, 10000n, offerBytes);
      staticExecution = createStaticServiceContracts(client.environment, definition, [{ method, contract: contractBytes, offer: offerBytes.subarray(0, offerLength) }], { target, maximumOfferWindowMS: 10000n });
      contractBytes.fill(0); offerBytes.fill(0);
      const service = await c.bindService(definition, { target, maximumOfferWindowMS: 10000n, contractSource: staticExecution });
      staticExecution.close();
      const options = { deadlineAtMS: 40000n, admissionNotAfterMS: 5000n };
      referenceDirectory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-reference-save-"));
      const referencePath = join(referenceDirectory, "references.sqlite");
      referenceDB = new DatabaseSync(referencePath);
      referenceDB.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE saved (identity TEXT PRIMARY KEY, canonical BLOB NOT NULL, retain_until TEXT NOT NULL)");
      referenceStore = createOperationReferenceStore(client.environment, { targetDomain: "authority", durability: "durable_create_or_compare", storage: "application_owned",
        maxRecords: 2, maxStoredBytes: 4096n, retentionMS: 60000n, maxConcurrentSaves: 1, applicationBytes: 65536n }, async (_context, record, policy) => {
        storeCalls++;
        if (saveMode === "delayed") { storeEntered?.(); await new Promise<void>(resolve => { releaseStore = resolve; }); }
        // This application adapter intentionally continues a submitted transaction
        // after cancellation. Only its actual durable COMMIT confirms a save.
        referenceDB!.exec("BEGIN IMMEDIATE");
        try {
          const previous = referenceDB!.prepare("SELECT canonical FROM saved WHERE identity=?").get(record.identity);
          if (previous !== undefined && !Buffer.from(previous.canonical as Uint8Array).equals(record.canonical)) {
            referenceDB!.exec("ROLLBACK"); return "conflict";
          }
          if (previous === undefined) {
            const usage = referenceDB!.prepare("SELECT count(*) AS items, coalesce(sum(length(canonical)),0) AS bytes FROM saved").get()!;
            if (Number(usage.items) >= policy.maxRecords || BigInt(usage.bytes as number) + BigInt(record.canonical.length) > policy.maxStoredBytes) {
              referenceDB!.exec("ROLLBACK"); return "rejected";
            }
            referenceDB!.prepare("INSERT INTO saved VALUES (?,?,?)").run(record.identity, record.canonical, record.retainUntilMS.toString());
          }
          referenceDB!.exec("COMMIT"); return saveMode === "unknown" ? "unknown" : "confirmed";
        } catch (error) { referenceDB!.exec("ROLLBACK"); throw error; }
      });
      saveMode = "unknown";
      const unknownSave = await service.prepareAndSave(method, "original", referenceStore, options);
      expect(unknownSave).toMatchObject({ status: "not_prepared", save: { attempted: true, outcome: "unknown" }, reason: "save_unknown" });
      expect("operation" in unknownSave).toBe(false); expect(unknownSave.reference).toBeDefined(); expect(calls).toBe(0);
      saveMode = "normal";
      const conflictSave = await service.prepareAndSave(method, "different", referenceStore, options);
      expect(conflictSave).toMatchObject({ status: "not_prepared", save: { attempted: true, outcome: "conflict" }, reason: "save_conflict" });
      saveMode = "delayed";
      const enteredStore = new Promise<void>(resolve => { storeEntered = resolve; }), saveAbort = new AbortController();
      const delayedSave = service.prepareAndSave(method, "original", referenceStore, { ...options, signal: saveAbort.signal });
      await enteredStore; saveAbort.abort();
      const canceledSave = await delayedSave;
      expect(canceledSave).toMatchObject({ status: "not_prepared", save: { attempted: true, outcome: "unknown" }, reason: "canceled", cleanup: { status: "pending" } });
      expect("operation" in canceledSave).toBe(false); expect(referenceStore.cleanupStatus().pending_callbacks).toBe(1n);
      const saturatedSave = await service.prepareAndSave(method, "original", referenceStore, options);
      expect(saturatedSave).toMatchObject({ status: "not_prepared", save: { attempted: false }, reason: "resource_exhausted" });
      expect(storeCalls).toBe(3); expect(calls).toBe(0);
      saveMode = "normal"; releaseStore!(); releaseStore = undefined;
      await expect.poll(() => referenceStore!.cleanupStatus().pending_callbacks).toBe(0n);
      expect(calls).toBe(0);
      const saved = await service.prepareAndSave(method, "original", referenceStore, options);
      expect(saved).toMatchObject({ status: "prepared", save: { attempted: true, outcome: "confirmed" } });
      if (saved.status !== "prepared") throw new Error("missing saved execution capability");
      const prepared = saved.operation;
      const readback = new DatabaseSync(referencePath, { readOnly: true });
      try { expect(Number(readback.prepare("SELECT count(*) AS items FROM saved").get()!.items)).toBe(1); } finally { readback.close(); }
      referenceStore.close(); expect(referenceStore.cleanupStatus().status).toBe("complete");
      expect(calls).toBe(0);
      if (!(prepared instanceof V4ExecutionUnaryOperation)) throw new Error("missing execution capability");
      const reference = prepared.reference(), referenceCodec = createOperationReferenceCodec(client.environment), persisted = new Uint8Array(2048);
      const persistedBytes = referenceCodec.export(reference, persisted);
      expect(() => referenceCodec.import(persisted.subarray(0, persistedBytes), "other-authority")).toThrow("operation_reference_domain");
      const unknownVersion = persisted.slice(0, persistedBytes); unknownVersion[2] = 2;
      expect(() => referenceCodec.import(unknownVersion, "authority")).toThrow();
      const missingRead = c.readOperationResult(reference);
      expect(await missingRead.takeEncodedResult()).toMatchObject({ kind: "sdk_error", code: "service_unavailable" }); missingRead.close();
      expect(calls).toBe(0);
      expect(await c.queryOperation(reference)).toMatchObject({ status: "history_unknown", observation: { found: false, reason: "history_unknown" } });
      expect(await c.requestCancel(reference)).toMatchObject({ status: "ok", cancelResult: "history_unknown" });
      expect(prepared.start().status).toBe("admitted");
      const first = prepared.takeResult(), joined = service.call(method, "original", options);
      await entered;
      expect(await c.queryOperation(reference)).toMatchObject({ status: "ok", observation: { state: "executing", dispatched: true, workActive: true, cancelRequested: false } });
      expect(await c.requestCancel(reference)).toMatchObject({ status: "ok", cancelResult: "requested", observation: { cancelRequested: true, workActive: true } });
      releaseHandler();
      const results = await Promise.all([first, joined]);
      for (const result of results) { expect(result).toMatchObject({ kind: "value", encoding: "typed", value: "ORIGINAL" }); if ("release" in result) result.release(); }
      prepared.close();
      const operation = await service.prepareOperation(method, "original", options); service.close();
      expect(operation.start().status).toBe("admitted");
      const retained = await operation.takeEncodedResult();
      expect(retained).toMatchObject({ kind: "value", encoding: "encoded", bytes: new TextEncoder().encode("ORIGINAL") });
      operation.close(); if ("release" in retained) retained.release();
      const secondBinding = await c.bindService(definition, { target: { authority: "authority", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", server.material.server)).toString("hex") }] }, maximumOfferWindowMS: 10000n });
      const conflict = await secondBinding.call(method, "different", options);
      expect(conflict).toMatchObject({ kind: "sdk_error", code: "operation_conflict" });
      const changedDeadline = await secondBinding.call(method, "original", { ...options, deadlineAtMS: 45000n });
      expect(changedDeadline).toMatchObject({ kind: "sdk_error", code: "operation_conflict" });
      expect(calls).toBe(1); secondBinding.close();
      const imported = referenceCodec.import(persisted.subarray(0, persistedBytes), "authority"), roundtrip = new Uint8Array(2048);
      const roundtripBytes = referenceCodec.export(imported, roundtrip);
      expect(roundtrip.subarray(0, roundtripBytes)).toEqual(persisted.subarray(0, persistedBytes));
      expect("start" in imported || "close" in imported || "takeResult" in imported).toBe(false);
      expect(JSON.stringify(imported)).toBe("{}");
      persisted.fill(0); roundtrip.fill(0); referenceCodec.close();
      expect(await c.queryOperation(imported)).toMatchObject({ status: "ok", observation: { state: "completed", resultAvailable: true } });
      expect(await c.requestCancel(imported)).toMatchObject({ status: "ok", cancelResult: "terminal" });
      // Explicit reads use the fixed ordinary RPC tuple after both service
      // bindings and operation handles are closed. They cannot redispatch.
      const typedRead = c.readOperationResult(imported), encodedRead = c.readOperationResult(reference);
      const [readValue, readBytes] = await Promise.all([typedRead.takeResult(), encodedRead.takeEncodedResult()]);
      expect(readValue).toMatchObject({ kind: "retained_result", encoding: "typed", value: new TextEncoder().encode("ORIGINAL") });
      expect(readBytes).toMatchObject({ kind: "retained_result", encoding: "encoded", bytes: new TextEncoder().encode("ORIGINAL") });
      expect(readBytes.kind === "retained_result" && readBytes.header.kind).toBe("read_result_response");
      expect(await encodedRead.takeResult()).toMatchObject({ kind: "metadata", progress: { payloadStatus: "already_delivered" } });
      typedRead.close(); encodedRead.close();
      if ("release" in readValue) readValue.release(); if ("release" in readBytes) readBytes.release();
      const canceledRead = new AbortController(); canceledRead.abort();
      expect(() => c!.readOperationResult(reference, { signal: canceledRead.signal })).toThrow("canceled");
      expect(calls).toBe(1);
      expect(await c.queryOperation(reference)).toMatchObject({ status: "ok", observation: { state: "completed", resultAvailable: true, resultBytes: 8, cancelRequested: true, workActive: false } });
      expect(await c.requestCancel(reference)).toMatchObject({ status: "ok", cancelResult: "terminal", observation: { state: "completed", resultAvailable: true } });
      // Retire successive real M generations while ordinary result reads
      // continue. Adapter cleanup can synchronously publish retirement during
      // the original termination callback; neither result nor Session is lost.
      for (let generation = 0; generation < 2; generation++) {
        const duringManagementRecovery = c.readOperationResult(reference);
        established[0].rpcApplication().managementFailed();
        const duringRecovery = await duringManagementRecovery.takeEncodedResult();
        expect(duringRecovery).toMatchObject({ kind: "retained_result", bytes: new TextEncoder().encode("ORIGINAL") });
        if ("release" in duringRecovery) duringRecovery.release(); duringManagementRecovery.close();
        await expect.poll(() => established[0].rpcApplication().managementReady(), { timeout: 3000 }).toBe(true);
        expect(await c.queryOperation(imported)).toMatchObject({ status: "ok", observation: { state: "completed", resultAvailable: true } });
      }
      expect(calls).toBe(1);
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      // Close both original Sessions, then authenticate a distinct principal
      // against the same server Environment and its original execution owner.
      await Promise.all([c.close(), s.close()]);
      expect((await c.waitCleanup()).status).toBe("complete"); expect((await s.waitCleanup()).status).toBe("complete");
      referenceStore.close(); await client.close();
      const delegation = { namespace: definition.namespace, principalAuthority: "4".repeat(64), principalSubject: "administrator",
        targetAuthority: "3".repeat(64), targetSubject: "client", query: true, cancel: true, notAfterMS: 30000n };
      for (const cancelAllowed of [false, true]) {
        const nextA = new MemoryTransport("client", "message"), nextB = new MemoryTransport("server", "message"); nextA.peer = nextB; nextB.peer = nextA;
        const nextOptions = { profile: "execution" as const, authorizedClientSubjects, clientSubject: "administrator", connectionSeed: cancelAllowed ? 70 : 60,
          clockOriginMS: Math.min(a.createdAtMS, b.createdAtMS) };
        adminClient = endpoint("client", nextA, profile, "live_authority", 1000n, (_environment, material) => ({ ...common,
          localExecutionAuthority: "4".repeat(64), executionDelegations: [{ ...delegation, direction: "outgoing" }],
          referenceTargets: [{ authority: "authority", tenant: "tenant", audience: "service", localSubject: "administrator",
            peers: [{ subject: "server", identityDigest: Buffer.from(digest("certificate_digest", material.server)).toString("hex") }] }] }), nextOptions);
        const nextServer = endpoint("server", nextB, profile, "live_authority", 1000n, (_environment, material) => ({ ...common,
          executionIdentity: { authority: "4".repeat(64), subject: "administrator", identityDigest: Buffer.from(digest("certificate_digest", material.client)).toString("hex") },
          executionServices: [execution], executionPermissions: [{ namespace: definition.namespace, query: true, cancel: true }],
          // Independent server cancellation permission is checked before lookup,
          // even for this terminal record. No new handler is registered here.
          executionDelegations: [{ ...delegation, direction: "incoming", cancel: cancelAllowed }] }), { ...nextOptions, environment: server.environment });
        const nextEstablished = await Promise.all([adminClient.establish(), nextServer.establish()]);
        adminSession = new V4Session(nextEstablished[0]); adminServerSession = new V4Session(nextEstablished[1]);
        const nextCodec = createOperationReferenceCodec(adminClient.environment);
        const savedBytes = referenceDB.prepare("SELECT canonical FROM saved").get()!.canonical as Uint8Array;
        const savedReference = nextCodec.import(savedBytes, "authority"); nextCodec.close();
        expect(await adminSession.queryOperation(savedReference)).toMatchObject({ status: "ok", observation: { state: "completed", resultAvailable: true } });
        expect(await adminSession.requestCancel(savedReference)).toMatchObject(cancelAllowed ? { status: "ok", cancelResult: "terminal" } : { status: "unauthorized" });
        const delegatedRead = adminSession.readOperationResult(savedReference), delegatedResult = await delegatedRead.takeEncodedResult();
        expect(delegatedResult).toMatchObject({ kind: "retained_result", bytes: new TextEncoder().encode("ORIGINAL") });
        delegatedRead.close(); if ("release" in delegatedResult) delegatedResult.release();
        await Promise.all([adminSession.close(), adminServerSession.close()]);
        expect((await adminSession.waitCleanup()).status).toBe("complete"); expect((await adminServerSession.waitCleanup()).status).toBe("complete");
        await adminClient.close();
      }
      expect(calls).toBe(1);
    } finally {
      try {
        releaseStore?.(); referenceStore?.close(); staticExecution?.close();
        releaseHandler(); await Promise.all([c?.close(), s?.close(), adminSession?.close(), adminServerSession?.close()]); contract?.release();
        await Promise.all([client.close(), server.close(), adminClient?.close()]);
      } finally { referenceDB?.close(); if (referenceDirectory !== undefined) rmSync(referenceDirectory, { recursive: true, force: true }); }
    }
  });
  it("keeps Web readable cancellation independent from a healthy request send", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const [out, incoming] = await Promise.all([c.openStream("example/web"), s.acceptStream()]);
      const pair = asWebStreams(out), reader = pair.readable.getReader(), writer = pair.writable.getWriter();
      const waiting = reader.read(); await reader.cancel({ arbitrary: "reason" });
      expect((await waiting).done).toBe(true);
      const request = new Uint8Array([10, 11, 12]); await writer.write(request); await writer.close();
      const read = await incoming.stream.read(64n); expect(read.data).toEqual(request); expect(read.stream_status).toBe("eof");
      await expect(incoming.stream.finish()).rejects.toThrow("stream_aborted");
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      await new Promise(resolve => setTimeout(resolve, 0));
      expect(out.cleanupStatus().status).toBe("complete");
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("keeps Web writable abort independent from a healthy response receive", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const [out, incoming] = await Promise.all([c.openStream("example/web"), s.acceptStream()]);
      const pair = asWebStreams(out), writer = pair.writable.getWriter();
      await writer.write(new Uint8Array([1, 2])); await writer.abort();
      const response: number[] = [], reading = pair.readable.pipeTo(new WritableStream({ write(chunk) { response.push(...chunk); } }));
      await incoming.stream.write(new Uint8Array([20, 21, 22])); await incoming.stream.finish();
      await reading;
      expect(response).toEqual([20, 21, 22]); expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      await new Promise(resolve => setTimeout(resolve, 0)); expect(out.cleanupStatus().status).toBe("complete");
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("owns a native Node Duplex through partial writes, authenticated finish and reverse EOF", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const [out, incoming] = await Promise.all([c.openStream("example/node"), s.acceptStream()]);
      const duplex = asNodeDuplex(out, { producer: { maxChunkBytes: 16384, maxBackingBytes: 16384, maxPendingWrites: 4, maxQueuedBackingBytes: 65536 } });
      const failures: Error[] = []; duplex.on("error", error => failures.push(error));
      expect(() => out.acquireCursor(1n)).toThrow("stream_owned");
      await expect(out.write(new Uint8Array([99]))).rejects.toThrow("stream_owned");
      expect(() => asNodeDuplex(out, { producer: { maxChunkBytes: 1, maxBackingBytes: 1, maxPendingWrites: 1, maxQueuedBackingBytes: 1 } })).toThrow("stream_owned");
      const request = Uint8Array.from({ length: 8193 }, (_, n) => n % 251), received: number[] = [];
      const consume = (async () => {
        while (true) {
          const read = await incoming.stream.read(128n); received.push(...read.data);
          if (read.stream_status === "eof") return;
        }
      })();
      const finished = new Promise<void>((resolve, reject) => duplex.end(request, (error?: Error | null) => error ? reject(error) : resolve()));
      await Promise.all([consume, finished]);
      expect(received).toEqual([...request]); expect(duplex.writableFinished).toBe(true);
      expect(duplex.destroyed).toBe(false); expect(duplex.closeResult()?.send_drained).toBe(true);
      const response: number[] = [];
      const reading = (async () => { for await (const chunk of duplex) response.push(...chunk as Uint8Array); })();
      await incoming.stream.write(new Uint8Array([7, 8, 9])); await incoming.stream.finish();
      await reading;
      expect((await duplex.waitCleanup()).status).toBe("complete");
      expect(response).toEqual([7, 8, 9]); expect(failures).toEqual([]);
      expect(duplex.closeResult()).toMatchObject({ send_drained: true, read_terminal: "eof", cleanup_status: { status: "complete" } });
      expect(out.cleanupStatus().status).toBe("complete");
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("keeps a healthy Session and reverse direction alive after normal send drainage expires", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile, "live_authority", 150n), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const [out, incoming] = await Promise.all([c.openStream("example/quarantine"), s.acceptStream()]);
      const release = a.holdNext(), writing = out.write(new Uint8Array([1, 2, 3]));
      try { await expect(out.finish()).rejects.toThrow("time_expired"); }
      finally { release(); }
      expect((await writing).accepted_bytes).toBe(3n);
      // A settled aborted proof is visible to the reverse application reader;
      // it does not terminate that Stream's independent response direction.
      const read = await incoming.stream.read(64n);
      if (read.stream_status === "open") expect((await incoming.stream.read(64n)).stream_status).toBe("aborted");
      else expect(read.stream_status).toBe("aborted");
      await incoming.stream.write(new Uint8Array([4, 5]));
      expect((await out.read(64n)).data).toEqual(new Uint8Array([4, 5]));
      await incoming.stream.finish();
      expect((await out.read(64n)).stream_status).toBe("eof");
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      await expect(out.finish()).rejects.toThrow("stream_aborted");
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("finishes authenticated half-closes without consuming unread responses and retains terminal observations", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const [out, incoming] = await Promise.all([c.openStream("example/half"), s.acceptStream()]);
      const request = new Uint8Array([1, 2, 3]), response = new Uint8Array([4, 5]);
      await out.write(request);
      expect((await out.finish()).send_drained).toBe(true);
      expect((await incoming.stream.read(64n)).data).toEqual(request);
      await incoming.stream.write(response);
      expect((await incoming.stream.finish()).send_drained).toBe(true);
      // Both wire directions have finished, but the real response still belongs
      // to the original bounded receive queue until the application reads it.
      expect(out.cleanupStatus().status).toBe("pending");
      const read = await out.read(64n);
      expect(read.data).toEqual(response); expect(read.stream_status).toBe("eof");
      await c.probeLiveness();
      expect((await out.finish()).send_drained).toBe(true);
      expect((await out.closeWrite()).send_drained).toBe(true);
      await out.waitPeerAuthenticated(3n);
      expect((await out.read(64n)).stream_status).toBe("eof");
      expect(out.cleanupStatus().status).toBe("complete");
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("canceling CloseWrite only cancels its waiter and preserves the original admitted output", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const [out, incoming] = await Promise.all([c.openStream("example/half"), s.acceptStream()]);
      const release = a.holdNext(), writing = out.write(new Uint8Array([1, 2, 3]));
      const abort = new AbortController(), closing = out.closeWrite({ signal: abort.signal }); abort.abort();
      try {
        await expect(closing).rejects.toThrow("canceled");
        expect(() => out.prepareWrite(new Uint8Array([4]))).toThrow();
      } finally { release(); }
      expect((await writing).accepted_bytes).toBe(3n);
      expect((await out.finish()).send_drained).toBe(true);
      expect((await incoming.stream.read(64n)).data).toEqual(new Uint8Array([1, 2, 3]));
      await incoming.stream.finish();
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("Close uses reset proofs and cannot later report a graceful Finish", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const [out, incoming] = await Promise.all([c.openStream("example/reset"), s.acceptStream()]);
      await out.write(new Uint8Array([1, 2, 3]));
      const result = await incoming.stream.close();
      expect(result.send_drained).toBe(false); expect(result.read_terminal).toBe("abandoned");
      await expect(out.finish()).rejects.toThrow("stream_aborted");
      await expect(incoming.stream.finish()).rejects.toThrow("stream_aborted");
      expect((await incoming.stream.reset()).cleanup_status.status).toBe("complete");
      expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("advances rekey when peer markers arrive before native send completion", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      a.completionDelayMS = 10;
      await c.rekey(); expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      a.completionDelayMS = 0; b.completionDelayMS = 10;
      await c.rekey(); expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  for (const profile of ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"] as const) {
    it(`retains a logically stable proof for the already published rekey barrier: ${profile}`, async () => {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
      const [c, s] = await Promise.all([client.establish(), server.establish()]);
      let changing: Promise<void> | undefined, holding = false, sawACK!: () => void, sawCommit!: () => void, release!: () => void;
      const queuedACK = new Promise<void>(resolve => { sawACK = resolve; });
      const committed = new Promise<void>(resolve => { sawCommit = resolve; });
      const commitTail = new Promise<void>(resolve => { release = resolve; });
      const queued: Uint8Array[] = [];
      const ackBytes = encode(map({ 0: u(6), 1: u(1), 2: bytes(fill(0)) })).length + 16;
      try {
        const opening = c.openStream("example/barrier-proof"), incoming = await s.acceptStream(), stream = await opening;
        await stream.closeWrite(); expect((await incoming.stream.read(1n)).stream_status).toBe("eof");
        // Freeze while the server's real FIN is submitted but before the
        // client authenticates it. Both original barriers still own scope 1.
        b.submissionTail = frame => {
          if (inspectEnvelopePrefix(frame, 65536).frameType === wire.frame_types.STREAM_DATA && changing === undefined) {
            changing = c.rekey(); void changing.catch(() => undefined);
          }
          return undefined;
        };
        // Preserve reliable ordering while delaying REPLY and the retirement
        // ACK that follows it. The peer may keep processing c2s maintenance.
        b.deferDelivery = frame => {
          const prefix = inspectEnvelopePrefix(frame, 65536);
          holding ||= prefix.frameType === wire.frame_types.REKEY;
          if (!holding) return false;
          expect(queued.length).toBeLessThan(4); queued.push(frame);
          if (prefix.frameType === wire.frame_types.STREAM_ACK && inspectRecordPrefix(frame, prefix.payloadBytes, profile).ciphertextBytes === ackBytes) sawACK();
          return true;
        };
        a.submissionTail = frame => {
          const prefix = inspectEnvelopePrefix(frame, 65536);
          if (prefix.frameType === wire.frame_types.REKEY && inspectRecordPrefix(frame, prefix.payloadBytes, profile).epoch === 1) {
            sawCommit(); return commitTail;
          }
          return undefined;
        };
        await incoming.stream.closeWrite(); expect((await stream.read(1n)).stream_status).toBe("eof");
        await transportEvent(queuedACK);
        b.deferDelivery = undefined; for (const frame of queued.splice(0)) b.push(frame);
        await transportEvent(committed);
        // RETIRE_ACK now authenticates behind the registered peer barrier,
        // while the original COMMIT output still prevents round completion.
        await new Promise<void>(resolve => setImmediate(resolve));
        release(); await changing;
        expect((await c.probeLiveness()).submitted).toBe(true);
        await Promise.all([stream.finish(), incoming.stream.finish()]);
        const next = c.openStream("example/after-held-proof"), accepted = await s.acceptStream(), outgoing = await next;
        await outgoing.write(fill(68, 7)); expect((await accepted.stream.read(7n)).data).toEqual(fill(68, 7));
        await Promise.all([outgoing.close(), accepted.stream.close()]);
      } finally {
        release(); a.submissionTail = b.submissionTail = undefined; b.deferDelivery = undefined;
        await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]);
      }
    }, 10000);
    for (const outcome of ["rekey", "close"] as const) it(`keeps a retired proof owned through its real ACK tail during ${outcome}: ${profile}`, async () => {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
      const [c, s] = await Promise.all([client.establish(), server.establish()]);
      let release!: () => void, sawACK!: () => void, sawINIT!: () => void;
      const held = new Promise<void>(resolve => { release = resolve; });
      const acknowledged = new Promise<void>(resolve => { sawACK = resolve; });
      const initiated = new Promise<void>(resolve => { sawINIT = resolve; });
      let intercepted = false, terminated = false;
      void s.waitTermination().then(() => { terminated = true; });
      // In this fixed one-stream fixture the only 40-byte STREAM_ACK body is
      // RETIRE_ACK (batch sequence 1 and one 32-byte digest). No payload is
      // decrypted or changed; hold only the real provider completion after
      // delivering the original authenticated message to the peer.
      const ackBytes = encode(map({ 0: u(6), 1: u(1), 2: bytes(fill(0)) })).length + 16;
      b.submissionTail = frame => {
        const prefix = inspectEnvelopePrefix(frame, 65536);
        if (prefix.frameType !== wire.frame_types.STREAM_ACK || intercepted) return undefined;
        const header = inspectRecordPrefix(frame, prefix.payloadBytes, profile);
        if (header.ciphertextBytes !== ackBytes) return undefined;
        intercepted = true; sawACK(); return held;
      };
      a.submissionTail = frame => {
        if (inspectEnvelopePrefix(frame, 65536).frameType === wire.frame_types.REKEY) sawINIT();
        return undefined;
      };
      try {
        const opening = c.openStream("example/retirement-tail"), incoming = await s.acceptStream(), stream = await opening;
        await stream.write(fill(66, 8)); await stream.closeWrite();
        expect((await incoming.stream.read(8n)).data).toEqual(fill(66, 8));
        expect((await incoming.stream.read(1n)).stream_status).toBe("eof");
        await incoming.stream.closeWrite(); expect((await stream.read(1n)).stream_status).toBe("eof");
        await Promise.all([stream.finish(), incoming.stream.finish()]);
        await transportEvent(acknowledged);
        expect(intercepted).toBe(true);
        if (outcome === "rekey") {
          const changing = c.rekey(); void changing.catch(() => undefined);
          await transportEvent(initiated);
          // Let the actual reader process INIT while the ACK output borrow
          // remains outstanding. A publication tail cannot stop that reader.
          await new Promise<void>(resolve => setImmediate(resolve));
          expect(terminated).toBe(false);
          release(); await changing;
          expect((await c.probeLiveness()).submitted).toBe(true);
          const next = c.openStream("example/after-retirement"), accepted = await s.acceptStream(), outgoing = await next;
          await outgoing.write(fill(67, 8)); expect((await accepted.stream.read(8n)).data).toEqual(fill(67, 8));
          await Promise.all([outgoing.close(), accepted.stream.close()]);
        } else {
          const closing = await s.close();
          expect(closing.cleanup_status.status).not.toBe("complete");
          expect(server.environment.resources.root.snapshot().reservations).toBeGreaterThan(0);
          release();
        }
      } finally {
        release(); a.submissionTail = b.submissionTail = undefined;
        await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]);
      }
    }, 10000);
    for (const role of ["client", "server"] as const) it(`rekeys immediately after finished streams from ${role}: ${profile}`, async () => {
      const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
      const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
      const [c, s] = await Promise.all([client.establish(), server.establish()]);
      a.completionDelayMS = b.completionDelayMS = 2;
      try {
        const local = role === "client" ? c : s, remote = role === "client" ? s : c;
        for (let index = 0; index < 4; index++) {
          const opening = local.openStream("example/finished-rekey"), incoming = await remote.acceptStream(), stream = await opening;
          await stream.write(fill(index, 9)); await stream.closeWrite();
          expect((await incoming.stream.read(9n)).data).toEqual(fill(index, 9));
          expect((await incoming.stream.read(1n)).stream_status).toBe("eof");
          await incoming.stream.closeWrite(); expect((await stream.read(1n)).stream_status).toBe("eof");
          await Promise.all([stream.finish(), incoming.stream.finish()]);
          await local.rekey();
        }
        expect((await c.probeLiveness()).submitted).toBe(true);
      } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
    }, 15000);
  }
  for (const profile of ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"] as const) {
    for (const mode of ["message", "stream"] as const) it(`opens, writes, rekeys, probes and retires actual streams over ${mode} with ${profile}`, async () => {
      const a = new MemoryTransport("client", mode), b = new MemoryTransport("server", mode); a.peer = b; b.peer = a;
      const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
      const [c, s] = await Promise.all([client.establish(), server.establish()]);
      try {
        const metadata = createStreamMetadataEnvelope("example/binary", 7, { token: new Uint8Array([255, 0, 254]) });
        const opening = c.openStream("example/raw", { metadata });
        // The original OPEN keeps its epoch/digest association while both
        // sides install the next application epoch before choosing outcome.
        await c.rekey();
        const [out, incoming] = await Promise.all([opening, s.acceptStream()]);
        expect(incoming.kind).toBe("example/raw");
        expect(incoming.metadata.namespace).toBe("example/binary");
        expect(incoming.metadata.version).toBe(7);
        expect(incoming.metadata.encoded()).toEqual(metadata.encoded());
        expect(incoming.metadata.byteValues().token).toEqual(new Uint8Array([255, 0, 254]));
        const bytes = new TextEncoder().encode("original transport data");
        expect((await out.write(bytes)).accepted_bytes).toBe(BigInt(bytes.length));
        expect((await incoming.stream.read(64n)).data).toEqual(bytes);
        expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
        await c.rekey();
        expect((await incoming.stream.write(bytes)).accepted_bytes).toBe(BigInt(bytes.length));
        expect((await out.read(64n)).data).toEqual(bytes);
        const bulk = Uint8Array.from({ length: 2304 }, (_, i) => i % 251), received = new Uint8Array(bulk.length);
        expect(() => out.prepareWrite(bulk)).toThrow();
        const writing = (async () => {
          let offset = 0;
          while (offset < bulk.length) {
            const progress = await out.write(bulk.subarray(offset));
            expect(progress.requested_bytes).toBe(BigInt(bulk.length - offset));
            expect(progress.accepted_bytes).toBeGreaterThan(0n);
            offset += Number(progress.accepted_bytes);
          }
          return offset;
        })();
        for (let at = 0; at < bulk.length;) {
          const part = await incoming.stream.read(64n); received.set(part.data, at); at += part.data.length;
        }
        expect(await writing).toBe(bulk.length); expect(received).toEqual(bulk);
        const canceled = out.prepareWrite(bytes); canceled.cancel();
        expect((await canceled.wait()).accepted_bytes).toBe(0n);
        expect(canceled.cleanupStatus().status).toBe("complete");
        await c.probeLiveness();
        const release = a.holdNext(), partial = out.prepareWrite(new Uint8Array(256).fill(0x33));
        partial.start(); partial.cancel();
        try { expect(partial.progress().accepted_bytes).toBe(128n); expect(partial.cleanupStatus().status).toBe("pending"); }
        finally { release(); }
        expect((await partial.wait()).terminal_reason).toBe("canceled");
        expect((await incoming.stream.read(128n)).data).toEqual(new Uint8Array(128).fill(0x33));
        // Responder requests are coalesced; callers observe the same round.
        await Promise.all([s.rekey(), s.rekey()]);
        await c.rekey();
        expect((await c.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
        await Promise.all([out.close(), incoming.stream.close()]);
        // A FIN tuple and unread authenticated bytes survive multiple epoch
        // switches; only the still-live direction receives new record keys.
        const halfOpening = c.openStream("example/half");
        const accepted = await s.acceptStream(), half = await halfOpening;
        await c.probeLiveness();
        await half.write(bytes); await half.closeWrite();
        await c.rekey(); await c.rekey();
        const finalRead = await accepted.stream.read(64n);
        expect(finalRead.data).toEqual(bytes); expect(finalRead.stream_status).toBe("eof");
        await Promise.all([half.close(), accepted.stream.close()]);
      } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
    }, 10000);
  }
  it("uses a real durable pool consume under original admission before Noise and READY", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile, "preauthorized_pool"), server = endpoint("server", b, profile, "preauthorized_pool");
    const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-session-pool-"));
    const backing = createSQLitePoolBacking(client.environment, join(directory, "once.sqlite"), { maxPages: 64, maxRecords: 4, maxRecordBytes: 16384, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
    const store = openV4SQLitePoolStore(backing, { create: true, identity: { authority: "spend", storeID: fill(5), generation: 1n }, continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: fill(5, 16) }] });
    try {
      const [c, s] = await Promise.all([client.establish(store), server.establish()]);
      try {
        const opening = c.openStream("example/pool"), incoming = await s.acceptStream(), stream = await opening;
        await stream.write(fill(77, 12)); expect((await incoming.stream.read(12n)).data).toEqual(fill(77, 12));
      } finally { await Promise.all([c.close(), s.close()]); }
    } finally {
      store.close(); rmSync(directory, { recursive: true }); backing.releaseRemoved(); await Promise.all([client.close(), server.close()]);
    }
  });
  it("keeps a real native output tail charged after Environment Close times out", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    let release: (() => void) | undefined;
    try {
      const opening = c.openStream("example/tail"); await s.acceptStream(); const stream = await opening;
      release = a.holdNext(); const writing = stream.write(fill(99, 12));
      await client.environment.close(); expect(client.environment.cleanupStatus().status).toBe("cleanup_incomplete");
      expect((await client.environment.waitCleanup()).status).toBe("cleanup_incomplete");
      const cleaned = new Promise<void>(resolve => client.environment.onCleanup(resolve));
      release(); release = undefined; await writing;
      await cleaned;
      expect((await client.environment.waitCleanup()).status).toBe("complete");
    } finally { release?.(); await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("denies buffered plaintext after an authenticated namespace revocation", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const opening = c.openStream("example/raw"), incoming = await s.acceptStream(), stream = await opening;
      await stream.write(fill(99, 12)); await c.probeLiveness();
      const material = server.material, revoked = replace(material.state, { 9: array(map({ 0: bytes(digest("certificate_digest", material.client)), 1: u(8), 2: u(50000) })) });
      material.namespace.refresh(encode(material.headFor(revoked, 2)), encode(revoked));
      await expect(incoming.stream.read(12n)).rejects.toThrow();
      await s.close(); expect((await s.waitCleanup()).status).toBe("complete");
      await expect(s.probeLiveness()).rejects.toMatchObject({ name: "V4LivenessError", code: "closed", result: { submitted: false, complete: false, elapsedMS: null } });
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("immediately fences a pending read when independent trust retires its issuer", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    try {
      const opening = c.openStream("example/raw"), incoming = await s.acceptStream(); await opening;
      const read = incoming.stream.read(12n), rejected = expect(read).rejects.toThrow();
      const trust = sign("TrustConfig", replace(server.material.trust, { 4: u(2), 14: array(bytes(fill(4, 16))) }), 7);
      server.material.namespace.updateTrust(encode(trust));
      await rejected; await s.waitTermination(); expect(b.ended).toBe(true);
    } finally { await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
  it("projects raw metadata before authorization and accepted handler delivery", async () => {
    const a = new MemoryTransport("client", "message"), b = new MemoryTransport("server", "message"); a.peer = b; b.peer = a;
    const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
    const client = endpoint("client", a, profile), server = endpoint("server", b, profile);
    const [c, s] = await Promise.all([client.establish(), server.establish()]);
    let authorized: unknown, handled: unknown;
    const registration = s.registerStream("example/contract", (_context, metadata) => {
      authorized = metadata.descriptorValues(); return true;
    }, async (stream, _context, metadata) => {
      handled = metadata.descriptorValues(); await stream.close();
    }, { applicationBytes: 4096n, metadataContract: { contractID: "http-v1", namespace: "code/http_v1", version: 1, codec: "application/json",
      fields: [{ name: "method", type: "string", required: true }] } });
    try {
      const metadata = createStreamMetadataEnvelope("code/http_v1", 1, { method: new TextEncoder().encode(JSON.stringify("GET")) });
      const stream = await c.openStream("example/contract", { metadata }); await stream.close();
      await expect.poll(() => handled).toEqual({ method: "GET" }); expect(authorized).toEqual({ method: "GET" });
    } finally { registration.close(); await Promise.all([c.close(), s.close()]); await Promise.all([client.close(), server.close()]); }
  });
});
