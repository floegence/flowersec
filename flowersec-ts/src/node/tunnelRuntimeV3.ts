import {
  createAdmissionReasonRegistryV3,
  receiveSessionAdmissionV3,
  rejectSessionAdmissionV3,
  type ReceivedSessionAdmissionV3,
} from "../v3/serverAdmission.js";
import { configureServerWebSocketCarrierRoleV3 } from "../v3/webSocketCarrier.js";
import {
  AdmissionStatusV3,
  encodeFSA3ResponseV3,
  type TunnelFSB3RequestV3,
} from "../v3/artifact.js";
import {
  CarrierError,
  type CarrierSessionV3,
  type CarrierStreamV3,
  type CarrierUnreliableDatagramsV3,
} from "../v3/carrier.js";
import type { OperationOptions } from "../public/contract.js";
import { X509Certificate } from "node:crypto";
import { boundIngressURL, matchesIngress, type BoundIngress } from "./listenerIngress.js";
import { startNodeWebSocketListenerV3, type NodeWebSocketListenerV3 } from "./webSocketServerV3.js";
import { createNativeRawQuicDriver } from "./nativeTransportAddon.js";
import { startNodeRawQuicListenerV3, startNodeWebTransportListener, validateWebTransportListeners, type NodeWebTransportListenerConfig, type NodeRawQuicListenerV3 } from "./rawQuicServerV3.js";
import {
  consumeTunnelAuthorizationGrantV3,
  inspectTunnelAuthorizationGrantV3,
  retireTunnelAuthorizationGrantV3,
  runtimeAuthorizationRequestV3FromDecoded,
  validateTunnelAuthorizationGrantV3,
  type RuntimeAuthorizationRequestV3,
  type TunnelAuthorizationGrantClaimsV3,
  type TunnelAuthorizationGrantV3,
} from "./runtimeAuthorizationV3.js";

const DEFAULT_PAIR_TIMEOUT_MS = 10_000;
const DEFAULT_ADMISSION_TIMEOUT_MS = 10_000;
const DEFAULT_CLEANUP_TIMEOUT_MS = 2_000;
const DEFAULT_MAX_CONCURRENT_ADMISSIONS = 1_024;
const DEFAULT_MAX_PENDING_LEGS = 1_024;
const DEFAULT_MAX_ACTIVE_PAIRS = 1_024;
const DEFAULT_MAX_CONCURRENT_STREAMS = 128;
const ID = /^[A-Za-z0-9._~-]{1,128}$/u;
const BUILT_IN_ADMISSION_REASONS = [
  "authorization_expired",
  "capacity",
  "credential_replay",
  "expired_artifact",
  "invalid_credential",
  "pair_mismatch",
  "pair_timeout",
  "replaced",
  "replacement_denied",
] as const;

export type TunnelAuthorizationDecisionV3 =
  | Readonly<{
      decision: "allow";
      grant: TunnelAuthorizationGrantV3;
    }>
  | Readonly<{ decision: "reject" | "retry"; reason: string }>;

export type TunnelRuntimeListenerV3 =
  | NodeWebTransportListenerConfig
  | Readonly<{
      carrier: "websocket";
      publicURL?: string;
      host: string;
      port: number;
      tls: Readonly<{ certificate: string; privateKey: string }>;
      allowedOrigins: readonly string[];
    }>
  | Readonly<{
      carrier: "raw_quic";
      publicURL?: string;
      host: string;
      port: number;
      tls: Readonly<{ certificate: string | Uint8Array; privateKey: string | Uint8Array }>;
    }>;

export type TunnelRuntimeOptionsV3 = Readonly<{
  listeners: readonly TunnelRuntimeListenerV3[];
  maxInboundStreams: number;
  maxPendingLegs?: number;
  maxActivePairs?: number;
  maxConcurrentStreams?: number;
  maxConcurrentAdmissions?: number;
  pairTimeoutMs?: number;
  admissionTimeoutMs?: number;
  cleanupTimeoutMs?: number;
  admissionReasons?: readonly string[];
  authorize(
    request: RuntimeAuthorizationRequestV3,
    options: OperationOptions,
  ): Promise<TunnelAuthorizationDecisionV3>;
  release?(leaseId: string, options: Readonly<{ signal: AbortSignal }>): Promise<void> | void;
}>;

export class TunnelRuntimeV3 {
  private constructor() {}

  async start(): Promise<void> {
    await startTunnelRuntimeV3(tunnelRuntimeStateV3(this));
  }

  addresses(): readonly Readonly<{ host: string; port: number }>[] {
    return tunnelRuntimeStateV3(this).listeners.map((listener) => listener.address());
  }

  async close(): Promise<void> {
    const state = tunnelRuntimeStateV3(this);
    const existing = closes.get(state);
    if (existing !== undefined) return await existing;
    const closing = (async () => {
      await Promise.resolve();
      state.abort.abort(new Error("Flowersec tunnel runtime closed"));
      for (const generation of [...state.generations.values()]) finishGeneration(state, generation);
      const starting = starts.get(state);
      if (starting !== undefined) await Promise.allSettled([starting]);
      await Promise.allSettled(state.listeners.map(async (listener) => await listener.close()));
      await drainTasks(state.tasks);
      state.usedCredentials.clear();
      state.expirations.length = 0;
    })();
    closes.set(state, closing);
    return await closing;
  }
}

type Listener = NodeWebSocketListenerV3 | NodeRawQuicListenerV3;
type AllowedDecision = Extract<TunnelAuthorizationDecisionV3, Readonly<{ decision: "allow" }>>;
type TunnelLeg = Readonly<{
  received: ReceivedSessionAdmissionV3;
  ingress: BoundIngress;
  request: TunnelFSB3RequestV3;
  authorization: TunnelAuthorizationGrantClaimsV3;
  release(): void;
}>;
type Generation = {
  readonly key: string;
  readonly abort: AbortController;
  readonly roles: Map<1 | 2, TunnelLeg>;
  timer?: ReturnType<typeof setTimeout>;
  active: boolean;
  finished: boolean;
};
type TunnelRuntimeStateV3 = Readonly<{
  listeners: Listener[];
  ingress: Map<Listener, BoundIngress>;
  options: TunnelRuntimeOptionsV3;
  admissionReasons: ReadonlySet<string>;
  limits: Readonly<{
    maxPendingLegs: number;
    maxActivePairs: number;
    maxConcurrentStreams: number;
    maxConcurrentAdmissions: number;
    pairTimeoutMs: number;
    admissionTimeoutMs: number;
    cleanupTimeoutMs: number;
  }>;
  abort: AbortController;
  generations: Map<string, Generation>;
  usedCredentials: Set<string>;
  expirations: { credential: string; expiry: number }[];
  legGenerations: WeakMap<TunnelLeg, Generation>;
  admissionSlots: AdmissionSlots;
  authorizerSlots: Slots;
  tasks: Set<Promise<void>>;
  counts: { pendingLegs: number; activePairs: number };
}>;
const tunnelRuntimeStatesV3 = new WeakMap<TunnelRuntimeV3, TunnelRuntimeStateV3>();

function tunnelRuntimeStateV3(runtime: TunnelRuntimeV3): TunnelRuntimeStateV3 {
  const state = tunnelRuntimeStatesV3.get(runtime);
  if (state === undefined) throw new Error("invalid Flowersec TunnelRuntimeV3");
  return state;
}

export function createTunnelRuntimeV3(options: TunnelRuntimeOptionsV3): TunnelRuntimeV3 {
  const limits = validateOptions(options);
  const admissionReasons = createAdmissionReasonRegistryV3(
    BUILT_IN_ADMISSION_REASONS,
    options.admissionReasons,
  );
  const runtime = new (TunnelRuntimeV3 as unknown as { new(): TunnelRuntimeV3 })();
  const state: TunnelRuntimeStateV3 = {
    listeners: [],
    ingress: new Map(),
    options,
    admissionReasons,
    limits,
    abort: new AbortController(),
    generations: new Map(),
    usedCredentials: new Set(),
    expirations: [],
    legGenerations: new WeakMap(),
    admissionSlots: new AdmissionSlots(limits.maxConcurrentAdmissions),
    authorizerSlots: new Slots(limits.maxConcurrentAdmissions),
    tasks: new Set(),
    counts: { pendingLegs: 0, activePairs: 0 },
  };
  tunnelRuntimeStatesV3.set(runtime, state);
  return Object.freeze(runtime);
}

const starts = new WeakMap<TunnelRuntimeStateV3, Promise<void>>();
const closes = new WeakMap<TunnelRuntimeStateV3, Promise<void>>();

async function startTunnelRuntimeV3(state: TunnelRuntimeStateV3): Promise<void> {
  if (state.abort.signal.aborted) throw new Error("Flowersec tunnel runtime is closed");
  let started = starts.get(state);
  if (started === undefined) {
    started = (async () => {
      let rawQuicDriver: ReturnType<typeof createNativeRawQuicDriver> | undefined;
      try {
        for (const listener of state.options.listeners) {
          const leaf = new X509Certificate(listener.tls.certificate);
          if (state.abort.signal.aborted) throw new Error("Flowersec tunnel runtime is closed");
          const running = listener.carrier === "websocket"
            ? await startNodeWebSocketListenerV3({
                ...listener,
                path: "tunnel",
                inboundBidirectionalStreamCapacity: state.options.maxInboundStreams + 2,
                maxPendingSessions: state.limits.maxConcurrentAdmissions,
                pendingSessionTimeoutMs: state.limits.admissionTimeoutMs,
                cleanupTimeoutMs: state.limits.cleanupTimeoutMs,
              })
            : listener.carrier === "webtransport" ? await startNodeWebTransportListener({ ...listener, path: "tunnel", inboundBidirectionalStreamCapacity: state.options.maxInboundStreams + 2 })
            : await startNodeRawQuicListenerV3(
                rawQuicDriver ??= createNativeRawQuicDriver(),
                {
                  ...listener,
                  path: "tunnel",
                  inboundBidirectionalStreamCapacity: state.options.maxInboundStreams + 2,
                },
              );
          if (state.abort.signal.aborted) {
            await running.close().catch(() => undefined);
            throw new Error("Flowersec tunnel runtime is closed");
          }
          state.listeners.push(running);
          state.ingress.set(running, {
            leaf,
            url: boundIngressURL("tunnel", listener.carrier, running.address(), listener.publicURL),
          });
        }
      } catch (error) {
        await Promise.allSettled(state.listeners.splice(0).map(async (listener) => await listener.close()));
        throw error;
      }
      for (const listener of state.listeners) track(state, runListener(state, listener));
    })();
    starts.set(state, started);
  }
  await started;
}

async function runListener(state: TunnelRuntimeStateV3, listener: Listener): Promise<void> {
  while (!state.abort.signal.aborted) {
    let carrier: CarrierSessionV3;
    try {
      carrier = await listener.accept({ signal: state.abort.signal });
    } catch {
      return;
    }
    const releaseAdmission = state.admissionSlots.tryAcquire();
    if (releaseAdmission === undefined) {
      carrier.abort({ code: 6, reason: "tunnel admission capacity" });
      continue;
    }
    track(state, processCarrier(state, carrier, state.ingress.get(listener)!).finally(releaseAdmission));
  }
}

async function processCarrier(state: TunnelRuntimeStateV3, carrier: CarrierSessionV3, ingress: BoundIngress): Promise<void> {
  const admission = new AbortController();
  const unlinkRuntime = linkAbort(state.abort.signal, admission);
  const deadline = setTimeout(() => {
    admission.abort(new Error("Flowersec tunnel admission timed out"));
  }, state.limits.admissionTimeoutMs);
  try {
    const received = await receiveSessionAdmissionV3(carrier, admission.signal);
    const decoded = received.decoded;
    const authorizationRequest = runtimeAuthorizationRequestV3FromDecoded(decoded);
    const selected = decoded.request.candidates.find(candidate => candidate.id === decoded.request.chosen_candidate_id);
    if (carrier.path !== "tunnel" || decoded.request.pathKind !== "tunnel" ||
      selected?.carrier !== carrier.kind || !matchesIngress(selected, ingress)) {
      await reject(received, "invalid_credential", false, state.admissionReasons, admission.signal);
      return;
    }
    const releaseAuthorizer = await state.authorizerSlots.acquire(admission.signal);
    let authorizerStarted = false;
    let decision: TunnelAuthorizationDecisionV3;
    try {
      decision = await abortableCallback(
        () => {
          authorizerStarted = true;
          try {
            // Admission cancellation must not free this slot while an
            // application-owned authorization Promise is still running.
            const provider = state.options.authorize(authorizationRequest, { signal: admission.signal }).finally(releaseAuthorizer);
            track(state, provider.then(() => undefined));
            return provider;
          } catch (error) {
            releaseAuthorizer();
            throw error;
          }
        },
        admission.signal,
        (lateDecision) => {
          if (lateDecision !== undefined && lateDecision.decision === "allow") {
            releaseDecision(state, lateDecision);
          }
        },
      );
    } finally {
      if (!authorizerStarted) releaseAuthorizer();
    }
    if (decision.decision !== "allow") {
      await reject(
        received,
        decision.reason,
        decision.decision === "retry",
        state.admissionReasons,
        admission.signal,
      );
      return;
    }
    const leg = validatedLeg(state, received, ingress, decoded.request, authorizationRequest, decision);
    if (leg === undefined) {
      const grant = inspectTunnelAuthorizationGrantV3(decision.grant);
      releaseDecision(state, decision);
      const expired = grant !== undefined &&
        grant.expiresAtUnixSeconds <= Math.floor(Date.now() / 1_000);
      await reject(
        received,
        expired ? "expired_artifact" : "invalid_credential",
        expired,
        state.admissionReasons,
        admission.signal,
      );
      return;
    }
    try {
      configureRole(leg);
      registerLeg(state, leg);
    } catch (error) {
      leg.release();
      throw error;
    }
  } catch {
    carrier.abort({ code: 6, reason: "tunnel admission failed" });
  } finally {
    clearTimeout(deadline);
    unlinkRuntime();
  }
}

function validatedLeg(
  state: TunnelRuntimeStateV3,
  received: ReceivedSessionAdmissionV3,
  ingress: BoundIngress,
  request: TunnelFSB3RequestV3,
  authorizationRequest: RuntimeAuthorizationRequestV3,
  authorization: AllowedDecision,
): TunnelLeg | undefined {
  const now = Math.floor(Date.now() / 1_000);
  const candidate = validateTunnelAuthorizationGrantV3(authorization.grant, authorizationRequest);
  if (candidate === undefined ||
    !ID.test(candidate.credentialId) || candidate.credentialId !== authorizationRequest.lookupKey() ||
    !ID.test(candidate.leaseId) || !Number.isSafeInteger(candidate.expiresAtUnixSeconds) ||
    candidate.expiresAtUnixSeconds <= now || !ID.test(candidate.expectedPeerEndpointInstanceId) ||
    candidate.expectedPeerEndpointInstanceId === request.endpoint_instance_id) return undefined;
  const grant = consumeTunnelAuthorizationGrantV3(authorization.grant, authorizationRequest);
  if (grant === undefined ||
    grant !== candidate) return undefined;
  let released = false;
  return {
    received,
    ingress,
    request,
    authorization: grant,
    release() {
      if (released) return;
      released = true;
      trackRelease(state, grant.leaseId);
    },
  };
}

function registerLeg(state: TunnelRuntimeStateV3, leg: TunnelLeg): void {
  pruneCredentials(state);
  if (state.usedCredentials.has(leg.authorization.credentialId)) {
    leg.release();
    track(state, reject(
      leg.received,
      "credential_replay",
      false,
      state.admissionReasons,
      state.abort.signal,
    ));
    return;
  }
  rememberCredential(state, leg.authorization.credentialId, leg.authorization.expiresAtUnixSeconds);
  const key = pairKey(leg.request, leg.authorization.authorityScope);
  let generation = state.generations.get(key);
  if (generation !== undefined && !generation.finished &&
    (generation.active || generation.roles.has(leg.request.role))) {
    if (!leg.authorization.allowReplacement) {
      leg.release();
      track(state, reject(
        leg.received,
        "replacement_denied",
        false,
        state.admissionReasons,
        state.abort.signal,
      ));
      return;
    }
    replaceGeneration(state, generation);
    generation = undefined;
  }
  if (generation === undefined || generation.finished) {
    if (state.counts.pendingLegs >= state.limits.maxPendingLegs) {
      leg.release();
      track(state, reject(
        leg.received,
        "capacity",
        true,
        state.admissionReasons,
        state.abort.signal,
      ));
      return;
    }
    generation = {
      key,
      abort: new AbortController(),
      roles: new Map(),
      active: false,
      finished: false,
    };
    state.generations.set(key, generation);
  }
  const peer = generation.roles.get(leg.request.role === 1 ? 2 : 1);
  if (peer !== undefined && !mirrored(peer, leg)) {
    leg.release();
    track(state, reject(
      leg.received,
      "pair_mismatch",
      false,
      state.admissionReasons,
      state.abort.signal,
    ));
    return;
  }
  generation.roles.set(leg.request.role, leg);
  state.legGenerations.set(leg, generation);
  track(state, watchTermination(state, leg));
  if (generation.roles.size === 1) {
    state.counts.pendingLegs += 1;
    const expiresFirst = leg.authorization.expiresAtUnixSeconds * 1_000 <= Date.now() + state.limits.pairTimeoutMs;
    const timeout = Math.min(
      state.limits.pairTimeoutMs,
      Math.max(1, leg.authorization.expiresAtUnixSeconds * 1_000 - Date.now()),
    );
    generation.timer = setTimeout(() => rejectGeneration(
      state,
      generation!,
      expiresFirst ? "expired_artifact" : "pair_timeout",
      true,
    ), timeout);
    return;
  }
  const now = Math.floor(Date.now() / 1_000);
  if (firstAuthorizationExpired(generation, now)) {
    rejectGeneration(state, generation, "expired_artifact", true);
    return;
  }
  if (state.counts.activePairs >= state.limits.maxActivePairs) {
    rejectGeneration(state, generation, "capacity", true);
    return;
  }
  if (generation.timer !== undefined) clearTimeout(generation.timer);
  state.counts.pendingLegs -= 1;
  state.counts.activePairs += 1;
  generation.active = true;
  track(state, activatePair(state, generation));
}

async function activatePair(state: TunnelRuntimeStateV3, generation: Generation): Promise<void> {
  const first = generation.roles.get(1);
  const second = generation.roles.get(2);
  try {
    if (first === undefined || second === undefined) return;
    await respondTunnelPairAdmissionsV3(
      first.received,
      second.received,
      generation.abort.signal,
      state.limits.admissionTimeoutMs,
    );
    await bridgeTunnelPairV3(first.received.carrier, second.received.carrier, generation.abort.signal, state.limits);
    detachGeneration(state, generation);
  } catch {
    // Pair teardown below is the observable failure boundary for both endpoints.
  } finally {
    finishGeneration(state, generation);
    state.counts.activePairs--;
    for (const leg of generation.roles.values()) leg.release();
  }
}

async function watchTermination(state: TunnelRuntimeStateV3, leg: TunnelLeg): Promise<void> {
  try {
    await leg.received.carrier.waitTermination();
  } catch {
    // Carrier termination has the same generation cleanup below.
  }
  const generation = state.legGenerations.get(leg);
  if (generation !== undefined && !generation.active && !generation.finished) finishGeneration(state, generation);
}

function configureRole(leg: TunnelLeg): void {
  if (leg.received.carrier.kind === "websocket") {
    configureServerWebSocketCarrierRoleV3(leg.received.carrier, leg.request.role === 2);
  }
}

/** @internal */
export async function bridgeTunnelPairV3(
  first: CarrierSessionV3,
  second: CarrierSessionV3,
  signal: AbortSignal,
  limits: Pick<TunnelRuntimeStateV3["limits"], "maxConcurrentStreams" | "admissionTimeoutMs" | "cleanupTimeoutMs">,
): Promise<void> {
  const controller = new AbortController();
  const unlink = linkAbort(signal, controller);
  const tasks = new Set<Promise<void>>();
  const slots = new Slots(limits.maxConcurrentStreams);
  let serverFIN = false;
  let finished = false;
  const start = (task: Promise<void>, fatal = true) => {
    tasks.add(task);
    void task.catch((error) => {
      if (fatal && !(serverFIN && error instanceof CarrierError && error.code === "closed")) {
        controller.abort(asError(error));
      }
    }).finally(() => tasks.delete(task));
  };
  try {
    const [controlIn, controlOut] = await activateTunnelControlStreamsV3(
      first,
      second,
      controller.signal,
      limits.admissionTimeoutMs,
    );
    const control = spliceTunnelStreamsV3(
      controlIn,
      controlOut,
      controller.signal,
      limits.cleanupTimeoutMs,
      (source) => {
        if (source !== controlOut) throw new Error("Flowersec tunnel client FIN preceded server FIN");
        serverFIN = true;
      },
    );
    start(bridgeStreams(first, second, slots, controller.signal, start));
    start(bridgeStreams(second, first, slots, controller.signal, start));
    if (first.unreliableDatagrams !== undefined && second.unreliableDatagrams !== undefined) {
      start(bridgeDatagrams(first.unreliableDatagrams, second.unreliableDatagrams, controller.signal));
      start(bridgeDatagrams(second.unreliableDatagrams, first.unreliableDatagrams, controller.signal));
    }
    await control;
    await runBoundedPhase(controller.signal, limits.cleanupTimeoutMs, "Flowersec tunnel carrier close timed out", async (closeSignal) => {
      await first.close({ code: 1, reason: "session closed" });
      closeSignal.throwIfAborted();
      if (await second.waitRemoteSessionClose?.() !== true) throw new Error("missing normal tunnel server close");
    });
    finished = true;
  } finally {
    unlink();
    controller.abort(new Error("Flowersec tunnel bridge closed"));
    if (!finished) {
      first.abort({ code: 6, reason: "tunnel bridge failed" });
      second.abort({ code: 6, reason: "tunnel bridge failed" });
    }
    await drainTasks(tasks);
  }
}

/** @internal */
export async function activateTunnelControlStreamsV3(
  first: CarrierSessionV3,
  second: CarrierSessionV3,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<readonly [CarrierStreamV3, CarrierStreamV3]> {
  let partialIncoming: CarrierStreamV3 | undefined;
  try {
    return await runBoundedPhase(
      signal,
      timeoutMs,
      "Flowersec tunnel activation timed out",
      async (activationSignal) => {
        const incoming = await first.acceptStream({ signal: activationSignal });
        partialIncoming = incoming;
        if (activationSignal.aborted) {
          incoming.abort(asError(activationSignal.reason));
          throw asError(activationSignal.reason);
        }
        try {
          const outgoing = await second.openStream({ signal: activationSignal });
          if (activationSignal.aborted) {
            incoming.abort(asError(activationSignal.reason));
            outgoing.abort(asError(activationSignal.reason));
            throw asError(activationSignal.reason);
          }
          partialIncoming = undefined;
          return [incoming, outgoing] as const;
        } catch (error) {
          incoming.abort(asError(error));
          partialIncoming = undefined;
          throw error;
        }
      },
      ([incoming, outgoing]) => {
        incoming.abort(new Error("Flowersec tunnel activation completed after timeout"));
        outgoing.abort(new Error("Flowersec tunnel activation completed after timeout"));
      },
    );
  } catch (error) {
    partialIncoming?.abort(asError(error));
    throw error;
  }
}

async function bridgeStreams(
  source: CarrierSessionV3,
  target: CarrierSessionV3,
  slots: Slots,
  signal: AbortSignal,
  start: (task: Promise<void>, fatal?: boolean) => void,
): Promise<void> {
  while (!signal.aborted) {
    const incoming = await source.acceptStream({ signal });
    const release = await slots.acquire(signal);
    let outgoing: CarrierStreamV3;
    try {
      outgoing = await target.openStream({ signal });
    } catch (error) {
      release();
      if (signal.aborted) {
        incoming.abort(asError(error));
        throw error;
      }
      await incoming.reset().catch(() => undefined);
      continue;
    }
    start(spliceTunnelStreamsV3(incoming, outgoing, signal).finally(release), false);
  }
}

export async function spliceTunnelStreamsV3(
  left: CarrierStreamV3,
  right: CarrierStreamV3,
  signal: AbortSignal,
  halfCloseGraceMs = 0,
  onControlEOF?: (source: CarrierStreamV3) => void,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let finished = false;
  try {
    await abortableCallback(() => new Promise<void>((resolve, reject) => {
      const onEOF = halfCloseGraceMs <= 0 ? undefined : (source: CarrierStreamV3) => {
        if (finished || signal.aborted || timer !== undefined) return;
        onControlEOF?.(source);
        timer = setTimeout(() => reject(new Error("Flowersec tunnel control half-close timed out")), halfCloseGraceMs);
      };
      void Promise.all([
        copyStream(left, right, signal, onEOF),
        copyStream(right, left, signal, onEOF),
      ]).then(() => resolve(), reject);
    }), signal);
  } catch (error) {
    if (halfCloseGraceMs > 0 || signal.aborted) {
      left.abort(asError(error));
      right.abort(asError(error));
    } else {
      await Promise.allSettled([left.reset(), right.reset()]);
    }
    throw error;
  } finally {
    finished = true;
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function copyStream(
  source: CarrierStreamV3,
  target: CarrierStreamV3,
  signal: AbortSignal,
  onEOF?: (source: CarrierStreamV3) => void,
): Promise<void> {
  while (true) {
    const chunk = await source.read({ signal });
    if (chunk === null) {
      onEOF?.(source);
      await target.closeWrite();
      return;
    }
    let offset = 0;
    while (offset < chunk.length) {
      const written = await target.write(chunk.subarray(offset), { signal });
      if (written < 1 || written > chunk.length - offset) throw new Error("invalid tunnel stream write");
      offset += written;
    }
  }
}

async function bridgeDatagrams(
  source: CarrierUnreliableDatagramsV3,
  target: CarrierUnreliableDatagramsV3,
  signal: AbortSignal,
): Promise<void> {
  while (!signal.aborted) {
    const message = await source.receive({ signal });
    if (message.length <= target.maxDatagramSize) await target.send(message, { signal });
  }
}

function mirrored(first: TunnelLeg, second: TunnelLeg): boolean {
  const a = first.request;
  const b = second.request;
  return a.role !== b.role &&
    a.channel_id === b.channel_id &&
    a.profile === b.profile &&
    a.rendezvous_group_id === b.rendezvous_group_id &&
    a.session_contract_hash_b64u === b.session_contract_hash_b64u &&
    first.authorization.authorityScope === second.authorization.authorityScope &&
    a.listener_audience === b.listener_audience &&
    first.authorization.expectedPeerEndpointInstanceId === b.endpoint_instance_id &&
    second.authorization.expectedPeerEndpointInstanceId === a.endpoint_instance_id;
}

function pairKey(request: TunnelFSB3RequestV3, authorityScope: string): string {
  return JSON.stringify([
    authorityScope,
    request.profile,
    request.channel_id,
    request.rendezvous_group_id,
    request.listener_audience,
    request.session_contract_hash_b64u,
  ]);
}

function firstAuthorizationExpired(generation: Generation, nowUnixSeconds: number): boolean {
  for (const leg of generation.roles.values()) {
    if (leg.authorization.expiresAtUnixSeconds <= nowUnixSeconds) return true;
  }
  return false;
}

function rejectGeneration(
  state: TunnelRuntimeStateV3,
  generation: Generation,
  reason: string,
  retryable: boolean,
): void {
  if (generation.finished) return;
  detachGeneration(state, generation);
  track(state, (async () => {
    try {
      await rejectTunnelPairAdmissionsV3(
        [...generation.roles.values()].map(({ received }) => received),
        reason,
        retryable,
        state.admissionReasons,
        state.abort.signal,
        state.limits.admissionTimeoutMs,
      );
    } catch {
      // Pair teardown below owns the observable rejection boundary.
    } finally {
      generation.abort.abort(new Error("Flowersec tunnel pair rejected"));
      for (const leg of generation.roles.values()) {
        leg.received.carrier.abort({ code: 6, reason: "tunnel pair rejected" });
        leg.release();
      }
    }
  })());
}

function replaceGeneration(state: TunnelRuntimeStateV3, generation: Generation): void {
  if (generation.finished) return;
  const error = new Error("Flowersec tunnel pair replaced");
  generation.abort.abort(error);
  for (const leg of generation.roles.values()) {
    leg.received.stream.abort(error);
    leg.received.carrier.abort({ code: 6, reason: "tunnel pair replaced" });
    if (!generation.active) leg.release();
  }
  detachGeneration(state, generation);
}

/** @internal */
export async function rejectTunnelPairAdmissionsV3(
  admissions: readonly ReceivedSessionAdmissionV3[],
  reason: string,
  retryable: boolean,
  admissionReasons: ReadonlySet<string>,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<void> {
  await runBoundedPhase(
    signal,
    timeoutMs,
    "Flowersec tunnel admission rejection timed out",
    async (responseSignal) => {
      await Promise.all(admissions.map(async (received) => {
        await reject(received, reason, retryable, admissionReasons, responseSignal);
      }));
    },
  );
}

function finishGeneration(state: TunnelRuntimeStateV3, generation: Generation): void {
  if (generation.finished) return;
  detachGeneration(state, generation);
  generation.abort.abort(new Error("Flowersec tunnel pair closed"));
  for (const leg of generation.roles.values()) {
    leg.received.carrier.abort({ code: 1, reason: "tunnel pair closed" });
    if (!generation.active) leg.release();
  }
}

function detachGeneration(state: TunnelRuntimeStateV3, generation: Generation): void {
  generation.finished = true;
  if (generation.timer !== undefined) clearTimeout(generation.timer);
  if (!generation.active && generation.roles.size > 0) state.counts.pendingLegs -= 1;
  if (state.generations.get(generation.key) === generation) state.generations.delete(generation.key);
}

export async function respondTunnelPairAdmissionsV3(
  first: ReceivedSessionAdmissionV3,
  second: ReceivedSessionAdmissionV3,
  signal: AbortSignal,
  timeoutMs: number,
): Promise<void> {
  await runBoundedPhase(
    signal,
    timeoutMs,
    "Flowersec tunnel admission response timed out",
    async (responseSignal) => {
      await Promise.all([
        acceptAdmission(first, responseSignal),
        acceptAdmission(second, responseSignal),
      ]);
    },
  );
}

async function acceptAdmission(received: ReceivedSessionAdmissionV3, signal: AbortSignal): Promise<void> {
  const response = encodeFSA3ResponseV3({ status: AdmissionStatusV3.Success, reason: "" });
  let offset = 0;
  while (offset < response.length) {
    const written = await received.stream.write(response.subarray(offset), { signal });
    if (written < 1 || written > response.length - offset) throw new Error("invalid admission write");
    offset += written;
  }
  await abortableCallback(async () => await received.stream.closeWrite(), signal);
}

async function reject(
  received: ReceivedSessionAdmissionV3,
  reason: string,
  retryable: boolean,
  admissionReasons: ReadonlySet<string>,
  signal: AbortSignal,
): Promise<void> {
  try {
    await rejectSessionAdmissionV3(received, {
      accepted: false,
      status: retryable ? AdmissionStatusV3.Retryable : AdmissionStatusV3.Reject,
      reason,
    }, admissionReasons, signal);
  } catch {
    // Rejection intentionally closes the carrier and reports through FSA3.
  }
}

function validateOptions(options: TunnelRuntimeOptionsV3): TunnelRuntimeStateV3["limits"] {
  validateWebTransportListeners(options.listeners);
  const limits = {
    maxPendingLegs: options.maxPendingLegs ?? DEFAULT_MAX_PENDING_LEGS,
    maxActivePairs: options.maxActivePairs ?? DEFAULT_MAX_ACTIVE_PAIRS,
    maxConcurrentStreams: options.maxConcurrentStreams ?? DEFAULT_MAX_CONCURRENT_STREAMS,
    maxConcurrentAdmissions: options.maxConcurrentAdmissions ?? DEFAULT_MAX_CONCURRENT_ADMISSIONS,
    pairTimeoutMs: options.pairTimeoutMs ?? DEFAULT_PAIR_TIMEOUT_MS,
    admissionTimeoutMs: options.admissionTimeoutMs ?? DEFAULT_ADMISSION_TIMEOUT_MS,
    cleanupTimeoutMs: options.cleanupTimeoutMs ?? DEFAULT_CLEANUP_TIMEOUT_MS,
  };
  if (options.listeners.length === 0 || options.listeners.some(({ carrier }) => !["websocket", "raw_quic", "webtransport"].includes(carrier)) ||
      !Number.isSafeInteger(options.maxInboundStreams) ||
    options.maxInboundStreams < 1 || options.maxInboundStreams > 128 || typeof options.authorize !== "function" ||
    (options.release !== undefined && typeof options.release !== "function") ||
    !boundedInteger(limits.maxPendingLegs, 1, 65_536) || !boundedInteger(limits.maxActivePairs, 1, 65_536) ||
    !boundedInteger(limits.maxConcurrentStreams, 1, 128) ||
    !boundedInteger(limits.maxConcurrentAdmissions, 1, 65_536) ||
    !boundedInteger(limits.pairTimeoutMs, 1, 60_000) ||
    !boundedInteger(limits.admissionTimeoutMs, 1, 60_000) ||
    !boundedInteger(limits.cleanupTimeoutMs, 1, 60_000)) {
    throw new TypeError("invalid Flowersec TunnelRuntimeV3 options");
  }
  return limits;
}

function boundedInteger(value: number, minimum: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function rememberCredential(state: TunnelRuntimeStateV3, credential: string, expiry: number): void {
  state.usedCredentials.add(credential);
  const heap = state.expirations;
  let index = heap.length;
  while (index > 0) {
    const parent = Math.floor((index - 1) / 2);
    if (heap[parent]!.expiry <= expiry) break;
    heap[index] = heap[parent]!;
    index = parent;
  }
  heap[index] = { credential, expiry };
}

function pruneCredentials(state: TunnelRuntimeStateV3): void {
  const now = Math.floor(Date.now() / 1_000);
  const heap = state.expirations;
  while (heap.length && heap[0]!.expiry <= now) {
    state.usedCredentials.delete(heap[0]!.credential);
    const last = heap.pop()!;
    if (!heap.length) break;
    let index = 0;
    while (2 * index + 1 < heap.length) {
      let child = 2 * index + 1;
      if (child + 1 < heap.length && heap[child + 1]!.expiry < heap[child]!.expiry) child++;
      if (last.expiry <= heap[child]!.expiry) break;
      heap[index] = heap[child]!;
      index = child;
    }
    heap[index] = last;
  }
}

function releaseDecision(state: TunnelRuntimeStateV3, decision: AllowedDecision): void {
  const grant = retireTunnelAuthorizationGrantV3(decision.grant);
  if (grant === undefined || !ID.test(grant.leaseId)) return;
  trackRelease(state, grant.leaseId);
}

function trackRelease(state: TunnelRuntimeStateV3, leaseId: string): void {
  if (state.options.release === undefined) return;
  const controller = new AbortController();
  const release = Promise.resolve()
    .then(async () => await state.options.release!(leaseId, { signal: controller.signal }))
    .then(() => undefined);
  const timer = setTimeout(() => {
    controller.abort(new Error("Flowersec tunnel lease cleanup timed out"));
  }, state.limits.cleanupTimeoutMs);
  track(state, release.finally(() => clearTimeout(timer)));
}

function track(state: TunnelRuntimeStateV3, task: Promise<void>): void {
  state.tasks.add(task);
  void task.catch(() => undefined).finally(() => state.tasks.delete(task));
}

async function drainTasks(tasks: ReadonlySet<Promise<void>>): Promise<void> {
  while (tasks.size > 0) await Promise.allSettled(tasks);
}

async function abortableCallback<T>(
  callback: () => Promise<T>,
  signal: AbortSignal,
  onLateValue?: (value: T) => void,
): Promise<T> {
  if (signal.aborted) throw asError(signal.reason);
  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", abort);
    const abort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(asError(signal.reason));
    };
    signal.addEventListener("abort", abort, { once: true });
    let promise: Promise<T>;
    try {
      promise = callback();
    } catch (error) {
      settled = true;
      cleanup();
      reject(error);
      return;
    }
    void promise.then(
      (value) => {
        if (settled) {
          onLateValue?.(value);
          return;
        }
        settled = true;
        cleanup();
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

async function runBoundedPhase<T>(
  parent: AbortSignal,
  timeoutMs: number,
  timeoutMessage: string,
  operation: (signal: AbortSignal) => Promise<T>,
  onLateValue?: (value: T) => void,
): Promise<T> {
  const controller = new AbortController();
  const unlink = linkAbort(parent, controller);
  const timer = setTimeout(() => controller.abort(new Error(timeoutMessage)), timeoutMs);
  try {
    return await abortableCallback(
      async () => await operation(controller.signal),
      controller.signal,
      onLateValue,
    );
  } finally {
    clearTimeout(timer);
    unlink();
  }
}

function linkAbort(source: AbortSignal, target: AbortController): () => void {
  const abort = () => target.abort(source.reason);
  source.addEventListener("abort", abort, { once: true });
  if (source.aborted) abort();
  return () => source.removeEventListener("abort", abort);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

class Slots {
  private active = 0;
  private readonly waiters: Array<{
    grant: () => void;
  }> = [];

  constructor(private readonly maximum: number) {}

  async acquire(signal: AbortSignal): Promise<() => void> {
    if (signal.aborted) throw asError(signal.reason);
    if (this.active >= this.maximum) {
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const ready = () => {
          if (settled) return;
          settled = true;
          cleanup();
          // Reserve the released slot before waking the waiter. A new caller
          // can otherwise claim it during the microtask turn.
          this.active += 1;
          resolve();
        };
        const abort = () => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(asError(signal.reason));
        };
        const cleanup = () => {
          const index = this.waiters.findIndex((waiter) => waiter.grant === ready);
          if (index >= 0) this.waiters.splice(index, 1);
          signal.removeEventListener("abort", abort);
        };
        this.waiters.push({ grant: ready });
        signal.addEventListener("abort", abort, { once: true });
      });
    } else {
      this.active += 1;
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
      while (this.waiters.length > 0) {
        const waiter = this.waiters.shift()!;
        waiter.grant();
        if (this.active <= this.maximum) break;
      }
    };
  }
}

class AdmissionSlots {
  private active = 0;

  constructor(private readonly maximum: number) {}

  tryAcquire(): (() => void) | undefined {
    if (this.active >= this.maximum) return undefined;
    this.active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
    };
  }
}
