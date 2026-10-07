import {
  ServiceDefinition, createHandlerPlan, createStaticServiceContracts, createStreamMetadata, connect,
  type HandlerPlan, type Session, type Stream, type TransportEnvironment, type NodeLiveHTTPSOptions,
  type PoolServerAllowBinding,
} from "../node/index.js";
import type { ServiceBindingTarget } from "../v4/runtime/serviceBindingConfig.js";
import {
  createCurrentPeerClient, createCurrentLivePeerClient, readCurrentPeerMaterial, configureCurrentPeerWSS, configureCurrentPeerRawQUIC, peerServices, peerRequirements,
  type CurrentRegisteredLiveClientInstallation, type CurrentPoolClientInstallation, installCurrentPoolServerAllow, peerPingMethod, peerNotifyMethod, peerCompletionMethod, peerDatagramBarrierMethod, peerJSONBytes, peerJSONValue,
} from "./currentPeer.js";
import { currentPeerContract } from "./currentContracts.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { createCurrentPeerServer } from "./currentServer.js";

export type CurrentParityCarrier = "websocket" | "raw-quic";
export interface CurrentParityReady {
  readonly type: "ready";
  readonly runtime: string;
  readonly carrier: CurrentParityCarrier;
  readonly path: "direct" | "tunnel";
  readonly wire_revision: 4;
  readonly artifact_json: string;
  readonly trust_pem: string;
  readonly origin: string;
  readonly profile: string;
  readonly source: string;
  readonly client_tls_certificate_pem?: string; readonly client_tls_private_key_pem?: string;
  readonly server_allow?: PoolServerAllowBinding;
  /** Requires the actual route-wide datagram guarantee, including both legs. */
  readonly datagram?: boolean;
}
export const parityService = new ServiceDefinition({ namespace: "flowersec.parity", methods: {
  ping: peerPingMethod, notification: peerNotifyMethod, completion: peerCompletionMethod, datagramBarrier: peerDatagramBarrierMethod,
} });
const methods = [peerPingMethod, peerNotifyMethod, peerCompletionMethod, peerDatagramBarrierMethod] as const;
const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
const output = (value: unknown): void => { process.stdout.write(`${JSON.stringify(value)}\n`); };

/** Explicit bounded application observations. Only actual admitted handlers
 * publish here; request arrival and fixture material are never execution proof. */
class Signal {
  #pending = 0;
  #waiter: (() => void) | undefined;
  push(): void {
    if (this.#waiter !== undefined) { const waiter = this.#waiter; this.#waiter = undefined; waiter(); }
    else { if (this.#pending >= 8) throw new Error("parity observation capacity exceeded"); this.#pending++; }
  }
  wait(signal: AbortSignal): Promise<void> {
    if (signal.aborted) return Promise.reject(new Error("canceled"));
    if (this.#pending > 0) { this.#pending--; return Promise.resolve(); }
    if (this.#waiter !== undefined) return Promise.reject(new Error("busy"));
    return new Promise((resolve, reject) => {
      const canceled = () => { this.#waiter = undefined; reject(new Error("canceled")); };
      this.#waiter = () => { signal.removeEventListener("abort", canceled); resolve(); };
      signal.addEventListener("abort", canceled, { once: true });
      if (signal.aborted) { signal.removeEventListener("abort", canceled); canceled(); }
    });
  }
}
function value(bytes: Uint8Array, expected: string): void {
  const parsed = peerJSONValue(bytes);
  if (parsed === null || typeof parsed !== "object" || !("value" in parsed) || parsed.value !== expected) throw new Error("invalid parity application payload");
}
export class CurrentParityState {
  constructor(readonly path: "direct" | "tunnel" = "direct") {}
  readonly executed = new Set<string>();
  readonly notified = new Signal();
  readonly datagramReady = new Signal();
  readonly completed = new Signal();
  readonly notificationsObserved = new Signal();
  #notificationCount = 0;
  active = 0;
  session: Session | undefined;
  environment: TransportEnvironment | undefined;
  record(...cases: string[]): void { for (const item of cases) this.executed.add(item); }
  plan(environment: TransportEnvironment): HandlerPlan {
    this.environment = environment;
    const namespace = parityService.namespace;
    return createHandlerPlan(environment, { applicationBytes: 16384n, services: {
      ...peerServices, profile: "services", definitions: [parityService], notificationMethods: [],
      queryPermissions: methods.map(method => ({ namespace, method, permission: "allowed" as const })),
      unaryHandlers: [
        { namespace, method: peerPingMethod, contract: currentPeerContract(7001),
          handler: async (context, request: Uint8Array) => {
            const payload = peerJSONValue(request);
            if (payload !== null && typeof payload === "object" && "value" in payload && payload.value === "notifications-observed") {
              // A submitted notification must reach its original handler before
              // the client's Drain closes remote application admission.
              if (this.#notificationCount < 2) await this.notificationsObserved.wait(context.signal);
            } else { value(request, "ping"); }
            this.record("rpc"); return request;
          },
          options: { workClass: "short", maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" } },
        { namespace, method: peerCompletionMethod, contract: currentPeerContract(7003),
          handler: async (context, request: Uint8Array) => {
            value(request, "complete"); if (this.session === undefined) throw new Error("parity Session unavailable");
            await this.session.rekey({ signal: context.signal }); this.record("rekey");
            await this.session.probeLiveness({ signal: context.signal }); this.record("liveness");
            this.completed.push(); return request;
          }, options: { workClass: "short", maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" } },
        { namespace, method: peerDatagramBarrierMethod, contract: currentPeerContract(7005),
          handler: async (_context, request: Uint8Array) => { value(request, "datagram-ready"); this.datagramReady.push(); return request; },
          options: { workClass: "short", maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" } },
      ],
      notificationHandlers: [{ namespace, method: peerNotifyMethod, contract: currentPeerContract(7002),
        handler: (_context, request: Uint8Array) => {
          value(request, "notify"); this.record("notification"); this.notified.push();
          if (++this.#notificationCount === 2) this.notificationsObserved.push();
        },
        options: { workClass: "short", applicationBytes: 16384n, authorization: "authenticated", applicationTimeoutMS: 10000n } }],
    }, streams: [
      { kind: "parity.echo", authorize: () => true, options: { workClass: "resident", applicationBytes: 16384n,
        maxConcurrentStreams: 2, maxAuthorizing: 2, applicationTimeoutMS: 10000n, metadataNamespaces: [{ namespace: "application/json", version: 1 }] },
        handler: async (stream, context, metadata) => {
          this.active++;
          try {
            if (metadata.values.cell !== this.path || decoder.decode(await readAll(stream, context.signal)) !== "hello") throw new Error("invalid echo stream payload or metadata");
            this.record("stream-metadata"); await write(stream, encoder.encode("world"), context.signal);
            const finished = await stream.finish({ signal: context.signal });
            if (!finished.send_drained) throw new Error("echo stream output did not drain");
            this.record("stream-fin");
          } finally { this.active--; }
        } },
      { kind: "parity.reset", authorize: () => true, options: { workClass: "resident", applicationBytes: 16384n,
        maxConcurrentStreams: 2, maxAuthorizing: 2, applicationTimeoutMS: 10000n },
        handler: async (stream, context) => {
          this.active++;
          try {
            if (decoder.decode(await readAll(stream, context.signal)) !== "reset") throw new Error("invalid reset stream payload");
            await stream.reset({ signal: context.signal }); this.record("stream-reset");
          } finally { this.active--; }
        } },
    ] });
  }
}
async function write(stream: Stream, bytes: Uint8Array, signal: AbortSignal): Promise<void> {
  const progress = await stream.write(bytes, { signal });
  if (progress.phase !== "terminal" || progress.terminal_reason !== "complete" || progress.accepted_bytes !== BigInt(bytes.length)) throw new Error("parity Stream write failed");
}
export async function readAll(stream: Stream, signal: AbortSignal): Promise<Uint8Array> {
  const output = new Uint8Array(16); let length = 0;
  for (;;) {
    const result = await stream.read(16n, { signal });
    if (result.wait_status !== "ready" || result.stream_status === "aborted" || result.stream_status === "error") throw new Error("parity Stream read failed");
    if (result.data.length > output.length - length) throw new Error("parity Stream exceeds input bound");
    output.set(result.data, length); length += result.data.length;
    if (result.stream_status === "eof") return output.slice(0, length);
    if (result.data.length === 0) throw new Error("empty open parity Stream read");
  }
}
export async function canceledWait(session: Session): Promise<void> {
  const cancellation = new AbortController(); cancellation.abort();
  try { await session.waitTermination({ signal: cancellation.signal }); }
  catch (error) { if (error instanceof Error && error.message === "canceled") return; throw error; }
  throw new Error("passive termination wait ignored cancellation");
}
export async function bindParity(environment: TransportEnvironment, session: Session, target: ServiceBindingTarget, signal: AbortSignal) {
  const contracts = createStaticServiceContracts(environment, parityService,
    methods.map(method => ({ method, contract: currentPeerContract(method.typeID as 7001 | 7002 | 7003 | 7005) })),
    { target, maximumOfferWindowMS: 10000n });
  try {
    const service = await session.bindService(parityService, { target, contractSource: contracts, maximumOfferWindowMS: 10000n, signal,
      methods: [peerPingMethod, peerCompletionMethod, peerDatagramBarrierMethod].map(method => ({ method, workClass: "short", defaultResponseLimitBytes: 4096 })) });
    return { service, contracts };
  } catch (error) { contracts.close(); throw error; }
}
type Binding = Awaited<ReturnType<typeof bindParity>>;
export async function callParity(binding: Binding, method: typeof peerPingMethod, expected: string, signal: AbortSignal): Promise<void> {
  const result = await binding.service.call(method, peerJSONBytes({ value: expected }), { signal, responseLimitBytes: 4096, timeoutMS: 10000n });
  if (result.kind !== "value" || result.encoding !== "typed") throw new Error("parity RPC did not return a typed value");
  try { value(result.value, expected); } finally { result.release(); }
}
export async function notifyParity(binding: Binding, signal: AbortSignal): Promise<void> {
  const result = await binding.service.notify(peerNotifyMethod, peerJSONBytes({ value: "notify" }), { signal, timeoutMS: 10000n });
  if (result.submission !== "submitted") throw new Error("parity notification was not submitted");
}
async function datagram(session: Session, carrier: CurrentParityCarrier, initiator: boolean, environment: TransportEnvironment, signal: AbortSignal): Promise<void> {
  if (carrier === "websocket") return;
  if (!session.info().guarantees.datagram || (session.info().selected_features & 1n) === 0n) throw new Error("signed native datagram feature was not selected");
  const channel = session.unreliableMessages(), request = Uint8Array.of(1, 2, 3), response = Uint8Array.of(3, 2, 1);
  const send = async (bytes: Uint8Array): Promise<void> => {
    const now = originalEnvironment(environment).clock.sample().requireInterval();
    if (await channel.send(bytes, { signal, expiresAtMS: now.upperMS + 2000n }) !== "accepted") throw new Error("original native provider did not admit the parity datagram");
  };
  if (initiator) await send(request);
  const result = await channel.receive({ signal }), expected = initiator ? response : request;
  try { if (result.length !== expected.length || !expected.every((byte, index) => result[index] === byte)) throw new Error("native parity datagram payload mismatch"); }
  finally { result.fill(0); }
  if (!initiator) await send(response);
}
export async function exerciseCurrentParityClient(session: Session, state: CurrentParityState, binding: Binding, carrier: CurrentParityCarrier, signal: AbortSignal) {
  state.session = session;
  await callParity(binding, peerPingMethod, "ping", signal); state.record("rpc");
  await notifyParity(binding, signal); await state.notified.wait(signal);
  const echo = await session.openStream("parity.echo", { metadata: createStreamMetadata({ cell: state.path }), signal });
  try {
    await write(echo, encoder.encode("hello"), signal); await echo.closeWrite({ signal });
    if (decoder.decode(await readAll(echo, signal)) !== "world") throw new Error("parity echo did not preserve data and FIN");
    const finished = await echo.finish({ signal }); if (!finished.send_drained) throw new Error("client echo output did not drain");
    state.record("stream-metadata", "stream-fin");
  } finally { await echo.close({ signal }); }
  await callParity(binding, peerPingMethod, "ping", signal);
  const reset = await session.openStream("parity.reset", { signal });
  try {
    await write(reset, encoder.encode("reset"), signal); await reset.closeWrite({ signal });
    const result = await reset.read(16n, { signal });
    if (result.wait_status !== "ready" || result.stream_status !== "aborted") throw new Error("parity reset did not report its authenticated failure");
    state.record("stream-reset");
  } finally { await reset.close({ signal }); }
  await canceledWait(session); state.record("cancel");
  await callParity(binding, peerPingMethod, "ping", signal);
  await callParity(binding, peerDatagramBarrierMethod, "datagram-ready", signal); await datagram(session, carrier, true, state.environment!, signal);
  if (carrier !== "websocket") state.record("datagram");
  await session.rekey({ signal }); state.record("rekey");
  await session.probeLiveness({ signal }); state.record("liveness");
  await callParity(binding, peerCompletionMethod, "complete", signal); await notifyParity(binding, signal);
  await callParity(binding, peerPingMethod, "notifications-observed", signal);
  const drained = await session.drain({ timeoutMS: 5000n }).wait({ signal });
  if (drained.outcome !== "drained") throw new Error(`current parity communication did not drain: ${drained.outcome}`);
  await session.waitTermination({ signal });
}
function result(kind: "client-result" | "server-result" | "endpoint-a-result" | "endpoint-b-result", carrier: CurrentParityCarrier, state: CurrentParityState, profile: string, source: string) {
  return { type: kind, runtime: "node-typescript", carrier, path: state.path, cases: [...state.executed], wire_revision: 4, profile, source };
}
export type { CurrentPoolClientInstallation } from "./currentPeer.js";
export async function runCurrentParityClient(ready: CurrentParityReady, carrier: CurrentParityCarrier, liveHTTPS?: NodeLiveHTTPSOptions | CurrentRegisteredLiveClientInstallation, resultKind: "client-result" | "endpoint-a-result" = "client-result", poolInstallation?: CurrentPoolClientInstallation): Promise<void> {
  if (ready === null || typeof ready !== "object" || ready.type !== "ready" || (ready.path !== "direct" && ready.path !== "tunnel") || ready.carrier !== carrier || ready.wire_revision !== 4) throw new Error("invalid current ready envelope");
  const signal = AbortSignal.timeout(30000), material = readCurrentPeerMaterial(ready.artifact_json);
  if (material.source === "live_authority" && liveHTTPS === undefined) throw new Error("live parity requires independently configured mutual TLS control deployment");
  const fixture = material.source === "preauthorized_pool" ? await createCurrentPeerClient(ready.artifact_json, { trustPEM: ready.trust_pem })
    : await createCurrentLivePeerClient(ready.artifact_json, "control" in liveHTTPS! ? { trustPEM: ready.trust_pem, registeredLive: liveHTTPS as CurrentRegisteredLiveClientInstallation } : { trustPEM: ready.trust_pem, liveHTTPS: liveHTTPS as NodeLiveHTTPSOptions });
  const state = new CurrentParityState(ready.path);
  let plan: HandlerPlan | undefined;
  let session: Session | undefined, binding: Binding | undefined;
  let poolServerAllow: ReturnType<typeof installCurrentPoolServerAllow> | undefined;
  try {
    if (fixture.path !== ready.path || fixture.carrierKind !== carrier || fixture.material.profile !== ready.profile || fixture.material.source !== ready.source) throw new Error("signed material disagrees with ready envelope");
    plan = state.plan(fixture.environment);
    if (material.source === "preauthorized_pool" && ready.path === "tunnel") {
      poolServerAllow = installCurrentPoolServerAllow(fixture, poolInstallation, ready.server_allow);
    }
    const listenerTLS = ready.client_tls_certificate_pem === undefined || ready.client_tls_private_key_pem === undefined ? undefined : { certificatePEM: ready.client_tls_certificate_pem, privateKeyPEM: ready.client_tls_private_key_pem, ...(resultKind === "endpoint-a-result" ? { onPrepared: (address: Readonly<{ host: string; port: number }>) => output({ type: "endpoint-a-prepared", runtime: "node-typescript", wire_revision: 4, profile: material.profile, source: material.source, path: "tunnel", carrier, address }) } : {}) };
    const connector = carrier === "websocket" ? configureCurrentPeerWSS(fixture, ready.origin, ready.trust_pem, plan, listenerTLS, poolServerAllow) : configureCurrentPeerRawQUIC(fixture, ready.trust_pem, plan, listenerTLS, poolServerAllow);
    session = await connect(fixture.environment, fixture.registerSource(connector), peerRequirements, { signal }); state.session = session; state.record("admission");
    if ("poolStore" in fixture && fixture.spentCount() !== 1) throw new Error("original parity material was not durably consumed once");
    binding = await bindParity(fixture.environment, session, { authority: fixture.policy.authorities[0]!, tenant: fixture.policy.tenant, audience: fixture.policy.audience,
      localSubject: fixture.policy.clientSubject, peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity }] }, signal);
    const datagramCarrier = ready.datagram === false ? "websocket" : carrier;
    await exerciseCurrentParityClient(session, state, binding, datagramCarrier, signal);
    await session.close(); state.record("close"); binding.service.close(); binding.contracts.close(); plan.close();
    await fixture.close(); if (state.active !== 0 || session.cleanupStatus().status !== "complete") throw new Error("original parity owner did not clean up");
    state.record("cleanup"); output(result(resultKind, carrier, state, ready.profile, ready.source));
  } finally { binding?.service.close(); binding?.contracts.close(); plan?.close(); await session?.close(); await poolServerAllow?.close(); await fixture.close(); }
}
export async function exerciseCurrentParityServer(session: Session, state: CurrentParityState, binding: Binding, carrier: CurrentParityCarrier, signal: AbortSignal): Promise<void> {
    await canceledWait(session); state.record("cancel");
    await callParity(binding, peerPingMethod, "ping", signal); await notifyParity(binding, signal);
    await state.notified.wait(signal); await state.datagramReady.wait(signal); await datagram(session, carrier, false, state.environment!, signal);
    if (carrier !== "websocket") state.record("datagram");
    await state.completed.wait(signal); await state.notified.wait(signal);
    await session.waitTermination({ signal }); state.record("close");
}
export async function runCurrentParityServer(carrier: CurrentParityCarrier, origin: string): Promise<void> {
  const signal = AbortSignal.timeout(30000), state = new CurrentParityState();
  const owner = await createCurrentPeerServer(environment => state.plan(environment), origin, { applicationProfile: "services", carrier });
  let binding: Binding | undefined, session: Session | undefined;
  const material = JSON.parse(owner.artifactJSON) as { profile: string; source: string };
  try {
    const accepting = owner.acceptor.accept({ signal }); void accepting.catch(() => undefined);
    output({ type: "ready", runtime: "node-typescript", carrier, path: "direct", artifact_json: owner.artifactJSON, trust_pem: owner.trustPEM,
      origin, wire_revision: 4, profile: material.profile, source: material.source });
    session = (await accepting).session; state.session = session; state.record("admission");
    binding = await bindParity(owner.environment, session, { authority: "authority", tenant: "tenant", audience: "service", localSubject: "server",
      peers: [{ subject: "client", identityDigest: owner.clientIdentity }] }, signal);
    await exerciseCurrentParityServer(session, state, binding, carrier, signal);
    binding.service.close(); binding.contracts.close(); await owner.close();
    const cleanup = session.cleanupStatus();
    if (state.active !== 0 || cleanup.status !== "complete") throw new Error(
      `original accepted parity owner did not clean up: handlers=${state.active} status=${cleanup.status} core=${cleanup.core_cleanup} callbacks=${cleanup.pending_callbacks}`);
    state.record("cleanup"); output(result("server-result", carrier, state, material.profile, material.source));
  } finally { binding?.service.close(); binding?.contracts.close(); await session?.close(); await owner.close(); }
}
