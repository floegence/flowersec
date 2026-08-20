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
  type DecodedFSB3RequestV3,
  type TunnelFSB3RequestV3,
} from "../v3/artifact.js";
import type {
  CarrierSessionV3,
  CarrierStreamV3,
  CarrierUnreliableDatagramsV3,
} from "../v3/carrier.js";
import type { OperationOptions } from "../public/contract.js";
import { createHash } from "node:crypto";
import { startNodeWebSocketListenerV3, type NodeWebSocketListenerV3 } from "./webSocketServerV3.js";
import { createNativeRawQuicDriverV3 } from "./nativeTransportAddon.js";
import { startNodeRawQuicListenerV3, type NodeRawQuicListenerV3 } from "./rawQuicServerV3.js";

const DEFAULT_PAIR_TIMEOUT_MS = 10_000;
const DEFAULT_CLEANUP_TIMEOUT_MS = 2_000;
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
      credentialId: string;
      leaseId: string;
      expiresAtUnixSeconds: number;
      expectedPeerEndpointInstanceId: string;
      allowReplacement?: boolean;
    }>
  | Readonly<{ decision: "reject" | "retry"; reason: string }>;

export type TunnelRuntimeListenerV3 =
  | Readonly<{
      carrier: "websocket";
      host: string;
      port: number;
      tls: Readonly<{ certificate: string; privateKey: string }>;
      allowedOrigins: readonly string[];
    }>
  | Readonly<{
      carrier: "raw_quic";
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
  pairTimeoutMs?: number;
  cleanupTimeoutMs?: number;
  admissionReasons?: readonly string[];
  authorize(
    request: DecodedFSB3RequestV3,
    options: OperationOptions,
  ): Promise<TunnelAuthorizationDecisionV3>;
  release?(leaseId: string): Promise<void> | void;
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
      await boundedCleanup(state.tasks, state.limits.cleanupTimeoutMs);
    })();
    closes.set(state, closing);
    return await closing;
  }
}

type Listener = NodeWebSocketListenerV3 | NodeRawQuicListenerV3;
type AllowedDecision = Extract<TunnelAuthorizationDecisionV3, Readonly<{ decision: "allow" }>>;
type TunnelLeg = Readonly<{
  received: ReceivedSessionAdmissionV3;
  request: TunnelFSB3RequestV3;
  authorization: AllowedDecision;
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
  options: TunnelRuntimeOptionsV3;
  admissionReasons: ReadonlySet<string>;
  limits: Readonly<{
    maxPendingLegs: number;
    maxActivePairs: number;
    maxConcurrentStreams: number;
    pairTimeoutMs: number;
    cleanupTimeoutMs: number;
  }>;
  abort: AbortController;
  generations: Map<string, Generation>;
  usedCredentials: Map<string, number>;
  legGenerations: WeakMap<TunnelLeg, Generation>;
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
    options,
    admissionReasons,
    limits,
    abort: new AbortController(),
    generations: new Map(),
    usedCredentials: new Map(),
    legGenerations: new WeakMap(),
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
      let rawQuicDriver: ReturnType<typeof createNativeRawQuicDriverV3> | undefined;
      try {
        for (const listener of state.options.listeners) {
          if (state.abort.signal.aborted) throw new Error("Flowersec tunnel runtime is closed");
          const running = listener.carrier === "websocket"
            ? await startNodeWebSocketListenerV3({
                ...listener,
                path: "tunnel",
                inboundBidirectionalStreamCapacity: state.options.maxInboundStreams + 2,
              })
            : await startNodeRawQuicListenerV3(
                rawQuicDriver ??= createNativeRawQuicDriverV3(),
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
    track(state, processCarrier(state, carrier));
  }
}

async function processCarrier(state: TunnelRuntimeStateV3, carrier: CarrierSessionV3): Promise<void> {
  try {
    const received = await receiveSessionAdmissionV3(carrier, state.abort.signal);
    const decoded = received.decoded;
    if (carrier.path !== "tunnel" || decoded.request.pathKind !== "tunnel" ||
      decoded.request.candidates.find((candidate) => candidate.id === decoded.request.chosen_candidate_id)?.carrier !== carrier.kind) {
      await reject(received, "invalid_credential", false, state.admissionReasons, state.abort.signal);
      return;
    }
    const decision = await abortableCallback(
      state.options.authorize(decoded, { signal: state.abort.signal }),
      state.abort.signal,
      (lateDecision) => {
        if (lateDecision !== undefined && lateDecision.decision === "allow") {
          releaseDecision(state, lateDecision);
        }
      },
    );
    if (decision.decision !== "allow") {
      await reject(
        received,
        decision.reason,
        decision.decision === "retry",
        state.admissionReasons,
        state.abort.signal,
      );
      return;
    }
    const leg = validatedLeg(state, received, decoded.request, decision);
    if (leg === undefined) {
      releaseDecision(state, decision);
      const expired = decision.expiresAtUnixSeconds <= Math.floor(Date.now() / 1_000);
      await reject(
        received,
        expired ? "expired_artifact" : "invalid_credential",
        expired,
        state.admissionReasons,
        state.abort.signal,
      );
      return;
    }
    configureRole(leg);
    registerLeg(state, leg);
  } catch {
    await carrier.close().catch(() => undefined);
  }
}

function validatedLeg(
  state: TunnelRuntimeStateV3,
  received: ReceivedSessionAdmissionV3,
  request: TunnelFSB3RequestV3,
  authorization: AllowedDecision,
): TunnelLeg | undefined {
  const now = Math.floor(Date.now() / 1_000);
  if (!ID.test(authorization.credentialId) || authorization.credentialId !== credentialLookup(request.attach_token) ||
    !ID.test(authorization.leaseId) || !Number.isSafeInteger(authorization.expiresAtUnixSeconds) ||
    authorization.expiresAtUnixSeconds <= now || !ID.test(authorization.expectedPeerEndpointInstanceId) ||
    authorization.expectedPeerEndpointInstanceId === request.endpoint_instance_id) return undefined;
  let released = false;
  return {
    received,
    request,
    authorization,
    release() {
      if (released) return;
      released = true;
      trackRelease(state, authorization.leaseId);
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
  state.usedCredentials.set(leg.authorization.credentialId, leg.authorization.expiresAtUnixSeconds);
  const key = pairKey(leg.request);
  let generation = state.generations.get(key);
  if (generation !== undefined && !generation.finished &&
    (generation.active || generation.roles.has(leg.request.role))) {
    if (leg.authorization.allowReplacement !== true) {
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
    rejectGeneration(state, generation, "replaced", false);
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
  if (first === undefined || second === undefined) {
    finishGeneration(state, generation);
    return;
  }
  try {
    await Promise.all([
      acceptAdmission(first.received, generation.abort.signal),
      acceptAdmission(second.received, generation.abort.signal),
    ]);
    await bridgePair(state, first.received.carrier, second.received.carrier, generation.abort.signal);
  } catch {
    // Pair teardown below is the observable failure boundary for both endpoints.
  } finally {
    finishGeneration(state, generation);
  }
}

async function watchTermination(state: TunnelRuntimeStateV3, leg: TunnelLeg): Promise<void> {
  try {
    await leg.received.carrier.waitTermination();
  } catch {
    // Carrier termination has the same generation cleanup below.
  }
  const generation = state.legGenerations.get(leg);
  if (generation !== undefined && !generation.finished) finishGeneration(state, generation);
}

function configureRole(leg: TunnelLeg): void {
  if (leg.received.carrier.kind === "websocket") {
    configureServerWebSocketCarrierRoleV3(leg.received.carrier, leg.request.role === 2);
  }
}

async function bridgePair(
  state: TunnelRuntimeStateV3,
  first: CarrierSessionV3,
  second: CarrierSessionV3,
  signal: AbortSignal,
): Promise<void> {
  const controller = new AbortController();
  const cancel = () => controller.abort(signal.reason);
  signal.addEventListener("abort", cancel, { once: true });
  const tasks = new Set<Promise<void>>();
  const slots = new StreamSlots(state.limits.maxConcurrentStreams);
  const start = (task: Promise<void>, fatal = true) => {
    tasks.add(task);
    void task.catch(() => { if (fatal) controller.abort(); }).finally(() => tasks.delete(task));
  };
  try {
    const controlIn = await first.acceptStream({ signal: controller.signal });
    const controlOut = await second.openStream({ signal: controller.signal });
    start(spliceStreams(controlIn, controlOut, controller.signal, true));
    start(bridgeStreams(first, second, slots, controller.signal, start));
    start(bridgeStreams(second, first, slots, controller.signal, start));
    if (first.unreliableDatagrams !== undefined && second.unreliableDatagrams !== undefined) {
      start(bridgeDatagrams(first.unreliableDatagrams, second.unreliableDatagrams, controller.signal));
      start(bridgeDatagrams(second.unreliableDatagrams, first.unreliableDatagrams, controller.signal));
    }
    await aborted(controller.signal);
  } finally {
    signal.removeEventListener("abort", cancel);
    controller.abort();
    first.abort({ code: 1, reason: "tunnel bridge closed" });
    second.abort({ code: 1, reason: "tunnel bridge closed" });
    await boundedCleanup(tasks, state.limits.cleanupTimeoutMs);
  }
}

async function bridgeStreams(
  source: CarrierSessionV3,
  target: CarrierSessionV3,
  slots: StreamSlots,
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
    start(spliceStreams(incoming, outgoing, signal, false).finally(release), false);
  }
}

async function spliceStreams(
  left: CarrierStreamV3,
  right: CarrierStreamV3,
  signal: AbortSignal,
  closePair: boolean,
): Promise<void> {
  const abort = () => {
    left.abort(asError(signal.reason));
    right.abort(asError(signal.reason));
  };
  signal.addEventListener("abort", abort, { once: true });
  try {
    await Promise.all([copyStream(left, right, signal), copyStream(right, left, signal)]);
    if (closePair) throw new Error("Flowersec tunnel control stream closed");
  } catch (error) {
    if (closePair || signal.aborted) {
      left.abort(asError(error));
      right.abort(asError(error));
    } else {
      await Promise.allSettled([left.reset(), right.reset()]);
    }
    throw error;
  } finally {
    signal.removeEventListener("abort", abort);
  }
}

async function copyStream(source: CarrierStreamV3, target: CarrierStreamV3, signal: AbortSignal): Promise<void> {
  while (true) {
    const chunk = await source.read({ signal });
    if (chunk === null) {
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
    a.candidate_set_hash_b64u === b.candidate_set_hash_b64u &&
    a.listener_audience === b.listener_audience &&
    first.authorization.expectedPeerEndpointInstanceId === b.endpoint_instance_id &&
    second.authorization.expectedPeerEndpointInstanceId === a.endpoint_instance_id;
}

function pairKey(request: TunnelFSB3RequestV3): string {
  return JSON.stringify([
    request.profile,
    request.channel_id,
    request.rendezvous_group_id,
    request.listener_audience,
    request.session_contract_hash_b64u,
    request.candidate_set_hash_b64u,
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
    await Promise.allSettled([...generation.roles.values()].map(async (leg) =>
      await reject(
        leg.received,
        reason,
        retryable,
        state.admissionReasons,
        state.abort.signal,
      )));
    generation.abort.abort(new Error("Flowersec tunnel pair rejected"));
    for (const leg of generation.roles.values()) leg.release();
  })());
}

function finishGeneration(state: TunnelRuntimeStateV3, generation: Generation): void {
  if (generation.finished) return;
  detachGeneration(state, generation);
  generation.abort.abort(new Error("Flowersec tunnel pair closed"));
  for (const leg of generation.roles.values()) {
    leg.received.carrier.abort({ code: 1, reason: "tunnel pair closed" });
    leg.release();
  }
}

function detachGeneration(state: TunnelRuntimeStateV3, generation: Generation): void {
  generation.finished = true;
  if (generation.timer !== undefined) clearTimeout(generation.timer);
  if (generation.active) state.counts.activePairs -= 1;
  else if (generation.roles.size > 0) state.counts.pendingLegs -= 1;
  if (state.generations.get(generation.key) === generation) state.generations.delete(generation.key);
}

async function acceptAdmission(received: ReceivedSessionAdmissionV3, signal: AbortSignal): Promise<void> {
  const response = encodeFSA3ResponseV3({ status: AdmissionStatusV3.Success, reason: "" });
  let offset = 0;
  while (offset < response.length) {
    const written = await received.stream.write(response.subarray(offset), { signal });
    if (written < 1 || written > response.length - offset) throw new Error("invalid admission write");
    offset += written;
  }
  await received.stream.closeWrite();
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
  const limits = {
    maxPendingLegs: options.maxPendingLegs ?? DEFAULT_MAX_PENDING_LEGS,
    maxActivePairs: options.maxActivePairs ?? DEFAULT_MAX_ACTIVE_PAIRS,
    maxConcurrentStreams: options.maxConcurrentStreams ?? DEFAULT_MAX_CONCURRENT_STREAMS,
    pairTimeoutMs: options.pairTimeoutMs ?? DEFAULT_PAIR_TIMEOUT_MS,
    cleanupTimeoutMs: options.cleanupTimeoutMs ?? DEFAULT_CLEANUP_TIMEOUT_MS,
  };
  if (options.listeners.length === 0 || !Number.isSafeInteger(options.maxInboundStreams) ||
    options.maxInboundStreams < 1 || options.maxInboundStreams > 128 || typeof options.authorize !== "function" ||
    !boundedInteger(limits.maxPendingLegs, 1, 65_536) || !boundedInteger(limits.maxActivePairs, 1, 65_536) ||
    !boundedInteger(limits.maxConcurrentStreams, 1, 128) || !boundedInteger(limits.pairTimeoutMs, 1, 60_000) ||
    !boundedInteger(limits.cleanupTimeoutMs, 1, 60_000)) {
    throw new TypeError("invalid Flowersec TunnelRuntimeV3 options");
  }
  return limits;
}

function boundedInteger(value: number, minimum: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function pruneCredentials(state: TunnelRuntimeStateV3): void {
  const now = Math.floor(Date.now() / 1_000);
  for (const [credential, expiry] of state.usedCredentials) {
    if (expiry <= now) state.usedCredentials.delete(credential);
  }
}

function releaseDecision(state: TunnelRuntimeStateV3, decision: AllowedDecision): void {
  if (!ID.test(decision.leaseId)) return;
  trackRelease(state, decision.leaseId);
}

function trackRelease(state: TunnelRuntimeStateV3, leaseId: string): void {
  if (state.options.release === undefined) return;
  const release = Promise.resolve()
    .then(async () => await state.options.release!(leaseId))
    .then(() => undefined);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, state.limits.cleanupTimeoutMs);
  });
  track(state, Promise.race([release, timeout])
    .then(() => undefined)
    .finally(() => {
      if (timer !== undefined) clearTimeout(timer);
    }));
}

function track(state: TunnelRuntimeStateV3, task: Promise<void>): void {
  state.tasks.add(task);
  void task.catch(() => undefined).finally(() => state.tasks.delete(task));
}

async function boundedCleanup(tasks: ReadonlySet<Promise<void>>, timeoutMs: number): Promise<void> {
  await Promise.race([
    Promise.allSettled([...tasks]).then(() => undefined),
    new Promise<void>((resolve) => setTimeout(resolve, timeoutMs)),
  ]);
}

async function abortableCallback<T>(
  promise: Promise<T>,
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

function aborted(signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => signal.addEventListener("abort", () => resolve(), { once: true }));
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function credentialLookup(credential: string): string {
  return createHash("sha256").update(credential, "utf8").digest("base64url");
}

class StreamSlots {
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
