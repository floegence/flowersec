import { createServer as createNetServer, isIP, type Socket } from "node:net";
import { createServer as createHTTPSServer } from "node:https";
import { constants, createHash, X509Certificate } from "node:crypto";
import { type TLSSocket } from "node:tls";
import { WebSocketServer } from "ws";
import type { EnvironmentDependency, V4EnvironmentRuntime } from "../v4/runtime/environment.js";
import type { CarrierPreparationFields } from "../v4/runtime/credentialVerifier.js";
import type { ClientSessionAdmission } from "../v4/runtime/sessionAdmission.js";
import type { V4AuthenticatedTransport } from "../v4/runtime/session.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { CredentialWork, credentialWorkCharge, equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { timerChunk } from "../v4/runtime/deadline.js";
import { NativeProviderPositions } from "../v4/runtime/nativeProviderPositions.js";
import { NodeWSSCarrier, nodeWSSAdmissionCosts, pinProfile, type V4NodeWSSOptions } from "./wssV4.js";
import { NodeRawQUICCarrier, nodeRawQUICAdmissionCosts, nativeRawQUICQueueBytes, originalNodeNativePreparationOwner, type NodeRawQUICOptions } from "./rawQUICCurrent.js";
import { bindCurrentNativeListener, type NativeCandidatePreparationBudget, type NativeOperation, type NativeRawListener, type NativeRawSession, type NativeTransportBinding } from "./nativeTransportCurrent.js";
import { endpointTransport } from "./endpointTransport.js";

export interface NodeWSSTunnelClientListenerOptions {
  readonly host: string; readonly port: number; readonly serverName: string;
  readonly onPrepared?: (address: Readonly<{ host: string; port: number }>) => void;
  readonly tls: Readonly<{ certificate: string; privateKey: string }>;
}
export interface NodeNativeTunnelClientListenerOptions {
  readonly host: string; readonly port: number; readonly serverName: string;
  readonly onPrepared?: (address: Readonly<{ host: string; port: number }>) => void;
  readonly tls: Readonly<{ certificateChainDER: readonly Uint8Array[]; privateKeyDER: Uint8Array }>;
}
export interface NodeNativeTunnelListenerBinding {
  readonly listener: NodeNativeTunnelClientListenerOptions;
  readonly carrier: NodeRawQUICOptions;
}
export function nativeListenerSelectionCost(runtimeBytes: bigint): readonly [string, ResourceVector] {
  return ["node_native_listener_selection", credentialWorkCharge(16384, runtimeBytes)];
}
const selectedListenerCandidates = new WeakMap<V4AuthenticatedTransport, number>();
export function endpointListenerCandidateIndex(transport: V4AuthenticatedTransport): number | undefined { return selectedListenerCandidates.get(transport); }
export function endpointListenerCost(runtimeBytes: bigint, nativeBytes: bigint): readonly [string, ResourceVector] {
  return ["endpoint_listener", new ResourceVector([1048576n + runtimeBytes, nativeBytes, 0n, 8n, 1n, 1n, 0n, 0n, 0n, 0n, 0n])];
}
function listenerDependency(runtime: V4EnvironmentRuntime, nativeBytes: bigint, admission?: ClientSessionAdmission): EnvironmentDependency {
  const cost = endpointListenerCost(runtime.resources.runtimeBytes, nativeBytes), reference = admission?.take([cost])[0];
  try { return runtime.admitDependency(cost[0], cost[1], reference, admission); } finally { reference?.release(); }
}
function checkEndpoint(runtime: V4EnvironmentRuntime, fields: CarrierPreparationFields, options: NodeWSSTunnelClientListenerOptions | NodeNativeTunnelClientListenerOptions, carrier: bigint, admission?: ClientSessionAdmission): void {
  requireCredential(fields.pathKind === 1 && fields.accessClass === 0n && isIP(options.host) !== 0 && Number.isSafeInteger(options.port) && options.port > 0 && options.port <= 65535 && typeof options.serverName === "string" && options.serverName.length > 0 && options.serverName.length <= 253, "configuration_capacity");
  const reference = runtime.reserveConnectionWork(carrier === 1n ? "node_wss_policy" : "node_raw_quic_policy", credentialWorkCharge(16384, runtime.resources.runtimeBytes), admission);
  let work: CredentialWork | undefined;
  try { work = new CredentialWork(runtime.resources, 16384, reference); const route = work.parse(fields.route, "Route", 16384);
    try { const leg = route.field("client_leg"); requireCredential(route.uint("path_kind") === 1n && route.uint("endpoint_role", leg, "Leg") === 0n && route.uint("listener_role", leg, "Leg") === 0n && route.uint("dialer_role", leg, "Leg") === 2n && route.uint("carrier", leg, "Leg") === carrier && route.text("host", leg, "Leg") === options.serverName && route.uint("port", leg, "Leg") === BigInt(options.port), "credential_binding"); }
    finally { route.close(); }
  } finally { work?.close(); reference.release(); }
}
function retainListener(physical: V4AuthenticatedTransport, retire: () => Promise<void>): V4AuthenticatedTransport {
  const logical = endpointTransport(physical, 0);
  let retirement: Promise<void> | undefined;
  const close = (): Promise<void> => retirement ??= (async () => { try { await physical.close(); } finally { await retire(); } })();
  void physical.waitTermination().then(close, close).catch(() => undefined);
  const transport = Object.freeze({ ...logical,
    ...(physical.completePreparation === undefined ? {} : { completePreparation: physical.completePreparation.bind(physical) }),
    close, waitTermination: async () => { await physical.waitTermination(); await close(); } });
  if (physical instanceof NodeRawQUICCarrier && physical.selectedCandidateIndex >= 0) selectedListenerCandidates.set(transport, physical.selectedCandidateIndex);
  return transport;
}
/** Accept one original relay carrier before the client's durable spend. The
 * native listener remains charged until that same carrier really terminates. */
export async function prepareEndpointWSSListener(runtime: V4EnvironmentRuntime, fields: CarrierPreparationFields, options: NodeWSSTunnelClientListenerOptions, carrierOptions: V4NodeWSSOptions, signal: AbortSignal, admission?: ClientSessionAdmission, announcePrepared?: () => Promise<void>): Promise<V4AuthenticatedTransport> {
  checkEndpoint(runtime, fields, options, 1n, admission);
  requireCredential(typeof options.tls.certificate === "string" && options.tls.certificate.length > 0 && options.tls.certificate.length <= 262144 && typeof options.tls.privateKey === "string" && options.tls.privateKey.length > 0 && options.tls.privateKey.length <= 65536, "configuration_capacity");
  if (fields.source === "preauthorized_pool") requireCredential(fields.preparationBytes >= carrierOptions.prepareBytes && fields.preparationWork >= 1, "configuration_capacity");
  const infrastructure = listenerDependency(runtime, carrierOptions.nativeBytes, admission), costs = nodeWSSAdmissionCosts(fields.maxFrame, carrierOptions, runtime.resources.runtimeBytes);
  let dependency: EnvironmentDependency | undefined, physical: NodeWSSCarrier | undefined;
  let network: ReturnType<typeof createNetServer> | undefined, https: ReturnType<typeof createHTTPSServer> | undefined, wss: WebSocketServer | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined, failure: unknown, retired: Promise<void> | undefined;
  let rejectPreparation: ((error: unknown) => void) | undefined, announcement = Promise.resolve();
  const sockets = new Set<Socket>();
  const retire = (): Promise<void> => retired ??= (async () => {
    for (const socket of sockets) socket.destroy();
    await physical?.close();
    const networkDone = network === undefined ? Promise.resolve() : new Promise<void>(resolve => { network!.close(() => resolve()); });
    const websocketDone = wss === undefined ? Promise.resolve() : new Promise<void>(resolve => { wss!.close(() => resolve()); });
    await Promise.all([networkDone, websocketDone]); https?.closeAllConnections();
    if (physical === undefined) dependency?.release(); infrastructure.release();
  })();
  const fail = (error: unknown): void => { failure ??= error; rejectPreparation?.(failure); for (const socket of sockets) socket.destroy(); void physical?.close(); };
  const check = (): void => { infrastructure.check(); fields.preparationDeadline.check(); if (signal.aborted || failure !== undefined) throw failure ?? new Error("canceled"); };
  const abort = (): void => fail(new Error("canceled"));
  try {
    const reference = admission?.take([costs[0]!])[0];
    try { dependency = runtime.admitDependency("node_wss", costs[0]![1], reference, admission); } finally { reference?.release(); }
    physical = new NodeWSSCarrier(runtime, dependency, Math.max(fields.maxFrame, 65536) + 8, carrierOptions.queueMessages, "server", "tunnel", fields.preparationDeadline);
    infrastructure.onClose(() => { fail(new Error("credential_closed")); void retire(); });
    network = createNetServer({ pauseOnConnect: true }); network.maxConnections = 1;
    https = createHTTPSServer({ cert: options.tls.certificate, key: options.tls.privateKey, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], secureOptions: constants.SSL_OP_NO_TICKET,
      maxHeaderSize: 16384, highWaterMark: 16384, handshakeTimeout: Number(fields.preparationDeadline.remainingMS()), requestTimeout: Number(fields.preparationDeadline.remainingMS()), headersTimeout: Number(fields.preparationDeadline.remainingMS()) });
    https.maxHeadersCount = 32; https.maxRequestsPerSocket = 1;
    wss = new WebSocketServer({ noServer: true, clientTracking: false, perMessageDeflate: false, maxPayload: Math.max(fields.maxFrame, 65536) + 8,
      handleProtocols: protocols => protocols.size === 1 && protocols.has("flowersec.tunnel.v4") ? "flowersec.tunnel.v4" : false });
    let entered = false;
    network.on("connection", socket => { try { check(); requireCredential(!entered); entered = true; sockets.add(socket); socket.once("close", () => sockets.delete(socket)); physical!.ownPendingSocket(socket); https!.emit("connection", socket); socket.resume(); } catch (error) { socket.destroy(); fail(error); } });
    network.on("error", fail); https.on("error", fail); wss.on("error", fail);
    network.once("listening", () => { try { check(); const actual = network!.address(); requireCredential(actual !== null && typeof actual !== "string" && actual.address === options.host && actual.port === options.port, "credential_binding"); options.onPrepared?.(Object.freeze({ host: actual.address, port: actual.port })); announcement = announcePrepared?.() ?? Promise.resolve(); void announcement.catch(fail); } catch (error) { fail(error); } });
    https.on("request", (request, response) => { response.destroy(); request.socket.destroy(); fail(new Error("credential_binding")); });
    https.on("clientError", (_error, socket) => { socket.destroy(); fail(new Error("credential_binding")); });
    https.on("tlsClientError", (_error, socket) => { socket.destroy(); fail(new Error("credential_binding")); });
    signal.addEventListener("abort", abort, { once: true });
    const tick = (): void => { try { check(); timer = setTimeout(tick, timerChunk(fields.preparationDeadline.remainingMS())); } catch (error) { fail(error); } }; tick();
    const accepted = new Promise<void>((resolve, reject) => {
      rejectPreparation = reject;
      https!.on("upgrade", (request, socket, head) => {
        try { check(); const tls = request.socket as TLSSocket;
          requireCredential(head.length === 0 && entered && !tls.destroyed && tls.getProtocol() === "TLSv1.3" && tls.alpnProtocol === "http/1.1" && !tls.isSessionReused() && request.method === "GET" && request.httpVersion === "1.1" && request.url === "/flowersec/v4/tunnel" && request.headers["sec-websocket-protocol"] === "flowersec.tunnel.v4" && request.headers["sec-websocket-extensions"] === undefined, "credential_binding");
          wss!.handleUpgrade(request, socket, head, websocket => { try { physical!.accept(websocket, request, { host: options.serverName, port: options.port }); physical!.checkAcceptedRoute(fields, 0); check(); resolve(); } catch (error) { websocket.terminate(); fail(error); } });
        } catch (error) { socket.destroy(); fail(error); }
      });
      network!.listen({ host: options.host, port: options.port, backlog: 1 });
      if (failure !== undefined) reject(failure);
    });
    await accepted; await announcement; check(); return retainListener(physical, retire);
  } catch (error) { fail(error); await retire(); throw error; }
  finally { signal.removeEventListener("abort", abort); if (timer !== undefined) clearTimeout(timer); rejectPreparation = undefined; }
}
export async function prepareEndpointNativeListener(runtime: V4EnvironmentRuntime, fields: CarrierPreparationFields, options: NodeNativeTunnelClientListenerOptions, carrierOptions: NodeRawQUICOptions, driver: NativeTransportBinding, signal: AbortSignal, admission?: ClientSessionAdmission, announcePrepared?: () => Promise<void>, preparationBudget?: NativeCandidatePreparationBudget, retainPreparationOwner?: (physical: NodeRawQUICCarrier) => void): Promise<V4AuthenticatedTransport> {
  requireCredential(preparationBudget !== undefined, "configuration_capacity");
  checkEndpoint(runtime, fields, options, carrierOptions.nativeCarrier === "webtransport" ? 2n : 0n, admission);
  requireCredential(options.tls.certificateChainDER.length > 0 && options.tls.certificateChainDER.length <= 16 && options.tls.certificateChainDER.every(bytes => bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 65536) && options.tls.privateKeyDER instanceof Uint8Array && options.tls.privateKeyDER.length > 0 && options.tls.privateKeyDER.length <= 65536, "configuration_capacity");
  const infrastructure = listenerDependency(runtime, carrierOptions.providerRuntimeBytes + nativeRawQUICQueueBytes(carrierOptions), admission), costs = nodeRawQUICAdmissionCosts(fields.maxFrame, carrierOptions, runtime.resources.runtimeBytes);
  let reserved: ReturnType<V4EnvironmentRuntime["admitDependencyPositions"]> | undefined, physical: NodeRawQUICCarrier | undefined, native: NativeRawListener | undefined, raw: NativeRawSession | undefined;
  let accept: NativeOperation<NativeRawSession> | undefined, timer: ReturnType<typeof setTimeout> | undefined, failure: unknown, retired: Promise<void> | undefined;
  const retire = (): Promise<void> => retired ??= (async () => {
    accept?.cancel(); raw?.abort(); native?.abort();
    try { await Promise.allSettled([raw?.waitTermination(), physical?.close(), native?.waitTermination()]); }
    finally { if (physical === undefined && reserved !== undefined) { for (const position of reserved.positions) position.closeAfterUse(); reserved.dependency.release(); } infrastructure.release(); }
  })();
  const fail = (error: unknown): void => { failure ??= error; accept?.cancel(); raw?.abort(); void physical?.close(); native?.abort(); };
  const check = (): void => { infrastructure.check(); fields.preparationDeadline.check(); if (signal.aborted || failure !== undefined) throw failure ?? new Error("canceled"); };
  const abort = (): void => fail(new Error("canceled"));
  try {
    const refs = admission?.take(costs.slice(0, -1));
    try { reserved = runtime.admitDependencyPositions("node_raw_quic", costs[0]![1], costs[1]![1], carrierOptions.applicationStreams + 1, refs, admission); } finally { for (const ref of refs ?? []) ref.release(); }
    physical = new NodeRawQUICCarrier(runtime, reserved.dependency, new NativeProviderPositions(reserved.positions), carrierOptions, fields.preparationDeadline, "server", "tunnel", fields.candidateIndex ?? -1, preparationBudget);
    retainPreparationOwner?.(physical);
    infrastructure.onClose(() => { fail(new Error("credential_closed")); }); signal.addEventListener("abort", abort, { once: true });
    const tick = (): void => { try { check(); timer = setTimeout(tick, timerChunk(fields.preparationDeadline.remainingMS())); } catch (error) { fail(error); } }; tick(); check();
    native = await bindCurrentNativeListener(driver, { host: options.host, port: options.port, path: "tunnel", preparationBudget, certificateChainDer: options.tls.certificateChainDER, privateKeyDer: options.tls.privateKeyDER,
      inboundBidirectionalStreamCapacity: carrierOptions.applicationStreams + 1, readBufferBytes: Math.min(16384, carrierOptions.streamBufferBytes), datagramQueueBytes: 65536, handshakeTimeoutMs: Number(fields.preparationDeadline.remainingMS()), pendingConnections: 1 }, options.serverName, carrierOptions.webTransport);
    check(); const address = native.address(); requireCredential(address.host === options.host && address.port === options.port, "credential_binding"); options.onPrepared?.(Object.freeze({ ...address })); check(); const announcement = announcePrepared?.() ?? Promise.resolve(); void announcement.catch(fail);
    accept = native.accept(); if (signal.aborted) accept.cancel(); raw = await accept.result(); accept = undefined; check();
    // Select a physical candidate before any maintenance HELLO/HOP input.
    // The selected carrier accepts that one original stream on its first read.
    await physical.accept(raw, { host: options.serverName, port: options.port, leaf: new X509Certificate(options.tls.certificateChainDER[0]!) }, signal, true);
    physical.checkAcceptedRoute(fields, 0); await announcement; check(); return retainListener(physical, retire);
  } catch (error) { fail(error); await retire(); throw error; }
  finally { signal.removeEventListener("abort", abort); if (timer !== undefined) clearTimeout(timer); }
}

/** Match the complete signed physical policy before constructing a listener.
 * A socket tuple never selects a different full Route after peer claims arrive. */
function matchesNativeListener(runtime: V4EnvironmentRuntime, route: ReturnType<CredentialWork["parse"]>, binding: NodeNativeTunnelListenerBinding): boolean {
  const options = binding.listener, carrier = binding.carrier, wt = carrier.webTransport;
  const leg = route.field("client_leg"), nativeH3 = carrier.nativeCarrier === "webtransport";
  if (route.uint("path_kind") !== 1n || route.uint("endpoint_role", leg, "Leg") !== 0n || route.uint("access_class", leg, "Leg") !== 0n ||
      route.uint("listener_role", leg, "Leg") !== 0n || route.uint("dialer_role", leg, "Leg") !== 2n ||
      route.uint("carrier", leg, "Leg") !== (nativeH3 ? 2n : 0n) || route.text("host", leg, "Leg") !== options.serverName ||
      route.uint("port", leg, "Leg") !== BigInt(options.port) || route.text("alpn", leg, "Leg") !== (nativeH3 ? "h3" : "flowersec-tunnel/4") ||
      route.text("path", leg, "Leg") !== (nativeH3 ? "/flowersec/webtransport/v4/tunnel" : "") || route.text("subprotocol", leg, "Leg") !== "") return false;
  const origin = route.optional("origin_policy", leg, "Leg");
  if (nativeH3) {
    if (origin < 0 || wt === undefined || wt.allowAbsentOrigin && !route.doc.boolean(route.field("allow_absent", origin, "OriginPolicy"))) return false;
    const signedOrigins = new Set([...route.items("origins", origin, "OriginPolicy")].map(entry => route.doc.text(entry)));
    if (wt.allowedOrigins.some(value => !signedOrigins.has(value))) return false;
  } else if (origin >= 0 && !route.doc.boolean(route.field("allow_absent", origin, "OriginPolicy"))) return false;
  const tls = route.field("tls_policy", leg, "Leg"), leaf = new X509Certificate(options.tls.certificateChainDER[0]!);
  const mode = route.uint("mode", tls, "TLSPolicy");
  if (mode === 0n) return isIP(options.serverName) !== 0 ? leaf.checkIP(options.serverName) === options.serverName : leaf.checkHost(options.serverName, { subject: "never" }) !== undefined;
  if (mode !== 1n || route.uint("pin_kind", tls, "TLSPolicy") !== 0n) return false;
  const now = runtime.clock.sample().requireInterval(), window = pinProfile(leaf, now), digest = new Uint8Array(createHash("sha256").update(leaf.raw).digest());
  try { return [...route.items("pins", tls, "TLSPolicy")].some(pin => {
    const from = route.uint("not_before_ms", pin, "TLSPin"), until = route.uint("not_after_ms", pin, "TLSPin");
    return now.lowerMS >= from && now.upperMS < until && from >= window.from && until <= window.until && equalCredential(digest, route.bytes("leaf_der_sha256", pin, "TLSPin"));
  }); } finally { digest.fill(0); }
}
/** At most two distinct physical sockets race under one cumulative signed
 * budget. All losing native tails finish before the actual winner is returned. */
export async function prepareEndpointNativeListeners(runtime: V4EnvironmentRuntime, fields: CarrierPreparationFields,
  bindings: readonly NodeNativeTunnelListenerBinding[], drivers: Readonly<Partial<Record<"raw-quic" | "webtransport", NativeTransportBinding>>>,
  signal: AbortSignal, admission?: ClientSessionAdmission, announcePrepared?: (fields: CarrierPreparationFields, signal: AbortSignal) => Promise<void>, attemptLimit = 2): Promise<V4AuthenticatedTransport> {
  requireCredential(fields.pathKind === 1 && fields.accessClass === 0n && bindings.length >= 1 && bindings.length <= 2 &&
    Number.isSafeInteger(attemptLimit) && attemptLimit >= 1 && attemptLimit <= 16, "configuration_capacity");
  const candidates = fields.candidates ?? [], preferred = fields.candidateIndex;
  requireCredential(candidates.length > 0 && candidates.length <= 16 && candidates.some(candidate => candidate.candidateIndex === preferred), "credential_binding");
  const ordered = [candidates.find(candidate => candidate.candidateIndex === preferred)!, ...candidates.filter(candidate => candidate.candidateIndex !== preferred)];
  const selected: { binding: NodeNativeTunnelListenerBinding; fields: CarrierPreparationFields }[] = [];
  const cost = nativeListenerSelectionCost(runtime.resources.runtimeBytes), reference = runtime.reserveConnectionWork(cost[0], cost[1], admission);
  let work: CredentialWork | undefined;
  try {
    work = new CredentialWork(runtime.resources, 16384, reference);
    const matches = bindings.map(() => [] as Array<(typeof candidates)[number]>);
    for (const candidate of ordered) {
      const route = work.parse(candidate.route, "Route", 16384);
      try { bindings.forEach((binding, index) => { if (matchesNativeListener(runtime, route, binding)) matches[index]!.push(candidate); }); }
      finally { route.close(); }
    }
    bindings.forEach((binding, index) => {
      const candidatesForBinding = matches[index]!, candidate = candidatesForBinding.find(candidate => candidate.candidateIndex === preferred) ?? (candidatesForBinding.length === 1 ? candidatesForBinding[0] : undefined);
      if (candidate !== undefined) selected.push({ binding, fields: Object.freeze({ ...fields, ...candidate }) });
    });
  } finally { work?.close(); reference.release(); }
  selected.sort((left, right) => Number(right.fields.candidateIndex === preferred) - Number(left.fields.candidateIndex === preferred));
  selected.splice(Math.min(attemptLimit, fields.totalCandidateAttempts ?? 1));
  requireCredential(selected.length > 0, "credential_binding");
  const owner = originalNodeNativePreparationOwner(runtime, fields, drivers[bindings[0]!.carrier.nativeCarrier ?? "raw-quic"]!, admission);
  const attempts: { controller: AbortController; task: Promise<{ transport: V4AuthenticatedTransport; physical: NodeRawQUICCarrier; index: number }> }[] = [];
  let winner: Awaited<(typeof attempts)[number]["task"]> | undefined;
  const abort = (): void => { for (const attempt of attempts) attempt.controller.abort(); };
  signal.addEventListener("abort", abort, { once: true });
  try {
    if (signal.aborted) throw new Error("canceled");
    selected.forEach(({ binding, fields: selectedFields }, index) => {
      const controller = new AbortController(), driver = drivers[binding.carrier.nativeCarrier ?? "raw-quic"];
      requireCredential(driver !== undefined, "configuration_capacity");
      const budget = owner.candidate(selectedFields); let physical: NodeRawQUICCarrier | undefined;
      const task = prepareEndpointNativeListener(runtime, selectedFields, binding.listener, binding.carrier, driver, controller.signal, admission,
        announcePrepared === undefined ? undefined : () => announcePrepared(selectedFields, controller.signal), budget, value => { physical = value; })
        .then(transport => { requireCredential(physical !== undefined, "credential_binding"); return { transport, physical, index }; });
      attempts.push({ controller, task });
    });
    winner = await Promise.any(attempts.map(attempt => attempt.task));
    for (let index = 0; index < attempts.length; index++) if (index !== winner.index) attempts[index]!.controller.abort();
    const finished = await Promise.allSettled(attempts.map(attempt => attempt.task));
    await Promise.all(finished.map(async result => { if (result.status === "fulfilled" && result.value !== winner) await Promise.allSettled([result.value.transport.close(), result.value.transport.waitTermination()]); }));
    if (signal.aborted) throw new Error("canceled");
    winner.physical.checkPreparation(); winner.physical.completePreparation(); owner.transfer(winner.physical); return winner.transport;
  } catch (error) {
    abort(); const finished = await Promise.allSettled(attempts.map(attempt => attempt.task));
    await Promise.all(finished.map(async result => { if (result.status === "fulfilled") await Promise.allSettled([result.value.transport.close(), result.value.transport.waitTermination()]); }));
    if (error instanceof AggregateError && error.errors.length > 0) throw error.errors[error.errors.length - 1];
    throw error;
  } finally { signal.removeEventListener("abort", abort); owner.releaseUnused(); }
}
