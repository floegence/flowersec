import { base64urlDecode } from "../utils/base64url.js";
import { SDK_DEFAULTS } from "../defaults.js";
import type { Session } from "../public/contract.js";
import type { RpcRouter } from "../rpc/server.js";
import {
  AdmissionStatusV3,
  admissionBindingV3,
  buildFSB3RequestV3,
  canonicalizeCandidatesV3,
  decodeFSA3ResponseV3,
  encodeFSB3RequestV3,
  validateArtifactV3,
  type ArtifactV3,
  type CanonicalArtifactCandidateV3,
} from "./artifact.js";
import {
  artifactLeaseStateV3,
  claimArtifactLeaseV3,
  claimedArtifactV3,
  commitArtifactLeaseSpendV3,
  retireArtifactLeaseV3,
  type ArtifactLeaseV3,
} from "./artifactLease.js";
import type {
  CarrierSessionV3,
  NativeCarrierStreamV3,
} from "./carrier.js";
import {
  aggregateCandidateFailuresV3,
  type CandidateFailureV3,
} from "./controller.js";
import type { LeaseAttemptContextV3, LeaseAttemptResultV3 } from "./connectionController.js";
import { projectSessionV3 } from "./publicSession.js";
import {
  ConnectErrorV3,
  TransportFailureV3,
  snapshotTransportSecurityPolicyV3,
} from "./security.js";
import {
  establishSessionV3,
  type SessionConfigV3,
  type SessionDeadlineFactoryV3,
  type SessionProtocolRuntimeV3,
} from "./session.js";
import {
  supportsCandidateSecurityV3,
  validateRuntimeCapabilityDescriptorV3,
  type RuntimeCapabilityDescriptorV3,
} from "./capability.js";

export type ClientAdmissionChannelV3 =
  | Readonly<{
    framing: "message";
    write(data: Uint8Array, signal?: AbortSignal): Promise<void>;
    read(signal?: AbortSignal): Promise<Uint8Array>;
    abort(error: Error): void;
  }>
  | Readonly<{
    framing: "stream";
    stream: NativeCarrierStreamV3;
    abort(error: Error): void;
  }>;

export type ReadyAdmissionTransportV3 = Readonly<{
  candidate: CanonicalArtifactCandidateV3;
  openAdmissionChannel(signal?: AbortSignal): Promise<ClientAdmissionChannelV3>;
  finalize(): CarrierSessionV3;
  close(): Promise<void>;
  abort(): void;
}>;

export type CandidateDialerV3 = (
  candidate: CanonicalArtifactCandidateV3,
  artifact: ArtifactV3,
  attemptNowUnixSeconds: number,
  capability: RuntimeCapabilityDescriptorV3,
  signal: AbortSignal,
) => Promise<ReadyAdmissionTransportV3>;

export type SessionConnectorRuntimeV3 = Readonly<{
  capabilitySnapshot(): RuntimeCapabilityDescriptorV3;
  dial: CandidateDialerV3;
  protocolRuntime: SessionProtocolRuntimeV3;
  connectTimeoutMilliseconds?: number;
  createRPCRouter?: () => RpcRouter;
  nowUnixSeconds?: () => number;
  deadlineFactory?: SessionDeadlineFactoryV3;
}>;

export async function connectArtifactLeaseV3(
  lease: ArtifactLeaseV3,
  runtime: SessionConnectorRuntimeV3,
  signal?: AbortSignal,
): Promise<Session> {
  let claim;
  try {
    claim = claimArtifactLeaseV3(lease);
  } catch {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  const artifact = claimedArtifactV3(claim);
  const now = runtime.nowUnixSeconds ?? (() => Math.floor(Date.now() / 1_000));
  let capability: RuntimeCapabilityDescriptorV3;
  let candidates: readonly CanonicalArtifactCandidateV3[];
  try {
    capability = runtime.capabilitySnapshot();
    validateRuntimeCapabilityDescriptorV3(capability);
    validateArtifactV3(artifact);
    assertArtifactFresh(artifact, now);
    candidates = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates).candidates;
  } catch (error) {
    await retireArtifactLeaseV3(claim);
    throw publicPreSpendError(error);
  }
  const controller = new AbortController();
  const unlink = linkAbort(signal, controller);
  try {
    const result = await attemptClaimedArtifactLeaseV3({
      kind: "primary",
      artifact,
      candidates,
      claim,
      signal: controller.signal,
      capability,
      assertArtifactFresh: () => assertArtifactFresh(artifact, now),
    }, runtime);
    if (result.kind === "established") return result.session;
    if (artifactLeaseStateV3(claim) === "claimed") await retireArtifactLeaseV3(claim);
    if (result.kind === "candidate_failures") {
      const failure = aggregateCandidateFailuresV3(result.failures, false);
      throw failure === "policy_refresh"
        ? new ConnectErrorV3("transport_security_failed", { kind: "terminal" })
        : failure;
    }
    throw result.error;
  } finally {
    unlink();
  }
}

export async function attemptClaimedArtifactLeaseV3(
  context: LeaseAttemptContextV3,
  runtime: SessionConnectorRuntimeV3,
): Promise<LeaseAttemptResultV3<Session>> {
  let timeoutMilliseconds: number;
  try {
    timeoutMilliseconds = normalizeConnectTimeoutMilliseconds(runtime.connectTimeoutMilliseconds);
  } catch (error) {
    return { kind: "pre_spend_failure", error: publicPreSpendError(error) };
  }
  const controller = new AbortController();
  const unlink = linkConnectAttemptAbort(context.signal, controller);
  const timer = setTimeout(() => controller.abort(
    new ConnectErrorV3("connection_failed", { kind: "retryable" }),
  ), timeoutMilliseconds);
  try {
    throwIfAborted(controller.signal);
    return await attemptClaimedArtifactLeaseWithinDeadlineV3(
      { ...context, signal: controller.signal },
      runtime,
    );
  } catch (error) {
    const projected = error instanceof ConnectErrorV3
      ? error
      : new ConnectErrorV3("connection_failed", { kind: "terminal" });
    return artifactLeaseStateV3(context.claim) === "claimed"
      ? { kind: "pre_spend_failure", error: projected }
      : { kind: "post_spend_failure", error: projected };
  } finally {
    clearTimeout(timer);
    unlink();
  }
}

async function attemptClaimedArtifactLeaseWithinDeadlineV3(
  context: LeaseAttemptContextV3,
  runtime: SessionConnectorRuntimeV3,
): Promise<LeaseAttemptResultV3<Session>> {
  const role = context.artifact.path.kind === "tunnel" && context.artifact.path.role === 2
    ? "server"
    : "client";
  const failures: CandidateFailureV3[] = [];
  const pending = new Map<number, Promise<Readonly<{
    index: number;
    ready?: ReadyAdmissionTransportV3;
    failure?: TransportFailureV3;
  }>>>();
  const controllers = new Map<number, AbortController>();
  let attemptNow: number;
  try {
    // A candidate race has one fixed wall-clock snapshot for every pin policy.
    attemptNow = readAttemptNow(runtime.nowUnixSeconds);
  } catch (error) {
    return {
      kind: "pre_spend_failure",
      error: publicPreSpendError(error),
    };
  }

  for (const [index, candidate] of context.candidates.entries()) {
    throwIfAborted(context.signal);
    if (!supportsCandidateSecurityV3(
      context.capability,
      candidate.carrier,
      context.artifact.path.kind,
      role,
      candidate.tls.mode,
    )) {
      failures.push({ candidate, failure: new TransportFailureV3("tls_unsupported") });
      continue;
    }
    try {
      const tuple = context.capability.tuples.find((entry) =>
        entry.carrier === candidate.carrier && entry.path === context.artifact.path.kind &&
        entry.networkMode === "dial" && entry.sessionRole === role);
      snapshotTransportSecurityPolicyV3(candidate.tls, attemptNow, tuple?.securityModes ?? []);
    } catch (error) {
      failures.push({ candidate, failure: asTransportFailure(error) });
      continue;
    }
    const controller = new AbortController();
    controllers.set(index, controller);
    const unlink = linkAbort(context.signal, controller);
    const task = Promise.resolve().then(async () => {
      throwIfAborted(controller.signal);
      return await runtime.dial(candidate, context.artifact, attemptNow, context.capability, controller.signal);
    })
      .then((ready) => ({ index, ready }))
      .catch((error: unknown) => ({ index, failure: asTransportFailure(error) }))
      .finally(unlink);
    pending.set(index, task);
  }

  let winner: ReadyAdmissionTransportV3 | undefined;
  while (pending.size > 0 && winner === undefined) {
    throwIfAborted(context.signal);
    const result = await raceAbort(Promise.race(pending.values()), context.signal);
    throwIfAborted(context.signal);
    pending.delete(result.index);
    if (result.ready !== undefined) winner = result.ready;
    else {
      const candidate = context.candidates[result.index]!;
      failures.push({ candidate, failure: result.failure ?? new TransportFailureV3("connection_failed") });
    }
  }
  for (const [index, controller] of controllers) {
    if (context.candidates[index] !== winner?.candidate) controller.abort(new Error("candidate lost race"));
  }
  try {
    await drainCandidateResultsV3([...pending.values()], winner, context.signal);
  } catch (error) {
    if (winner !== undefined) await closePreparedTransportV3(winner, context.signal);
    throw error;
  }
  if (winner === undefined) {
    try { context.assertArtifactFresh(); } catch (error) {
      return { kind: "pre_spend_failure", error: publicPreSpendError(error) };
    }
    return { kind: "candidate_failures", failures: Object.freeze(failures) };
  }

  try {
    context.assertArtifactFresh();
    const rawFSB3 = encodeFSB3RequestV3(buildFSB3RequestV3(context.artifact, winner.candidate.id));
    const config = sessionConfigFromArtifactV3(context.artifact, rawFSB3, runtime);
    const channel = await raceAbort(winner.openAdmissionChannel(context.signal), context.signal);
    try {
      context.assertArtifactFresh();
      await commitArtifactLeaseSpendV3(context.claim, context.signal);
      context.assertArtifactFresh();
      const response = channel.framing === "message"
        ? await exchangeMessage(channel, rawFSB3, context.signal)
        : await exchangeStream(channel.stream, rawFSB3, context.signal);
      const fsa3 = decodeFSA3ResponseV3(response);
      if (fsa3.status !== AdmissionStatusV3.Success) {
        throw new ConnectErrorV3("connection_failed", {
          kind: fsa3.status === AdmissionStatusV3.Retryable ? "retryable" : "terminal",
        });
      }
      const carrier = winner.finalize();
      try {
        const session = await raceAbort(establishSessionV3(carrier, config, { signal: context.signal }), context.signal);
        return { kind: "established", session: projectSessionV3(session) };
      } catch (error) {
        carrier.abort({ code: 6, reason: "session establishment failed" });
        throw error;
      }
    } catch (error) {
      channel.abort(asError(error));
      throw error;
    }
  } catch (error) {
    await closePreparedTransportV3(winner, context.signal);
    throwIfAborted(context.signal);
    if (artifactLeaseStateV3(context.claim) === "claimed") {
      return { kind: "pre_spend_failure", error: publicPreSpendError(error) };
    }
    return {
      kind: "post_spend_failure",
      error: error instanceof ConnectErrorV3
        ? error
        : new ConnectErrorV3("connection_failed", { kind: "terminal" }),
    };
  }
}

function sessionConfigFromArtifactV3(
  artifact: ArtifactV3,
  rawFSB3: Uint8Array,
  runtime: SessionConnectorRuntimeV3,
): SessionConfigV3 {
  const localBinding = admissionBindingV3(rawFSB3);
  const tunnel = artifact.path.kind === "tunnel" ? artifact.path : undefined;
  return {
    role: tunnel?.role === 2 ? "server" : "client",
    path: artifact.path.kind,
    channelID: artifact.session.channel_id,
    sessionContractHash: base64urlDecode(artifact.session.contract_hash_b64u),
    suite: artifact.session.default_suite,
    psk: base64urlDecode(artifact.session.e2ee_psk_b64u),
    maxInboundStreams: artifact.session.max_inbound_streams,
    sessionContract: artifact.session,
    ...(runtime.createRPCRouter === undefined ? {} : { rpcRouter: runtime.createRPCRouter() }),
    idleTimeoutMs: artifact.session.idle_timeout_seconds * 1_000,
    closeTimeoutMs: 5_000,
    runtime: runtime.protocolRuntime,
    localAdmissionBinding: localBinding,
    peerAdmissionBinding: tunnel === undefined ? localBinding : new Uint8Array(32),
    localEndpointInstanceID: tunnel?.local_endpoint_instance_id ?? "",
    expectedPeerEndpointInstanceID: tunnel?.expected_peer_endpoint_instance_id ?? "",
    deadlines: {
      establishTimeoutMs: artifact.session.establish_timeout_seconds * 1_000,
      rekeyPrepareTimeoutMs: artifact.session.rekey_prepare_timeout_seconds * 1_000,
      rekeyCompletionTimeoutMs: artifact.session.rekey_completion_timeout_seconds * 1_000,
      ...(runtime.deadlineFactory === undefined ? {} : { factory: runtime.deadlineFactory }),
    },
  };
}

async function exchangeMessage(
  channel: Extract<ClientAdmissionChannelV3, { framing: "message" }>,
  rawFSB3: Uint8Array,
  signal: AbortSignal,
): Promise<Uint8Array> {
  await raceAbort(channel.write(rawFSB3, signal), signal);
  return await raceAbort(channel.read(signal), signal);
}

async function exchangeStream(
  stream: NativeCarrierStreamV3,
  rawFSB3: Uint8Array,
  signal: AbortSignal,
): Promise<Uint8Array> {
  await writeAll(stream, rawFSB3, signal);
  await raceAbort(stream.closeWrite(), signal);
  const reader = new ExactReader(stream);
  const header = await reader.readExactly(8, signal);
  const reasonLength = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint16(6, false);
  if (reasonLength > 64) throw new ConnectErrorV3("connection_failed", { kind: "terminal" });
  const reason = await reader.readExactly(reasonLength, signal);
  await reader.expectEOF(signal);
  return concat(header, reason);
}

class ExactReader {
  readonly #chunks: Uint8Array[] = [];
  #offset = 0;
  #bytes = 0;

  constructor(private readonly stream: NativeCarrierStreamV3) {}

  async readExactly(length: number, signal: AbortSignal): Promise<Uint8Array> {
    while (this.#bytes < length) {
      const chunk = await raceAbort(this.stream.read(), signal);
      if (chunk === null) throw new ConnectErrorV3("connection_failed", { kind: "terminal" });
      if (chunk.length > 0) {
        this.#chunks.push(chunk);
        this.#bytes += chunk.length;
      }
    }
    const output = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      const chunk = this.#chunks[0]!;
      const take = Math.min(length - written, chunk.length - this.#offset);
      output.set(chunk.subarray(this.#offset, this.#offset + take), written);
      written += take;
      this.#offset += take;
      this.#bytes -= take;
      if (this.#offset === chunk.length) {
        this.#chunks.shift();
        this.#offset = 0;
      }
    }
    return output;
  }

  async expectEOF(signal: AbortSignal): Promise<void> {
    if (this.#bytes !== 0) throw new ConnectErrorV3("connection_failed", { kind: "terminal" });
    while (true) {
      const chunk = await raceAbort(this.stream.read(), signal);
      if (chunk === null) return;
      if (chunk.length !== 0) throw new ConnectErrorV3("connection_failed", { kind: "terminal" });
    }
  }
}

async function writeAll(stream: NativeCarrierStreamV3, data: Uint8Array, signal: AbortSignal): Promise<void> {
  let offset = 0;
  while (offset < data.length) {
    const written = await raceAbort(stream.write(data.subarray(offset)), signal);
    if (written < 1 || written > data.length - offset) {
      throw new ConnectErrorV3("connection_failed", { kind: "terminal" });
    }
    offset += written;
  }
}

function readAttemptNow(now: (() => number) | undefined): number {
  const value = (now ?? (() => Math.floor(Date.now() / 1_000)))();
  if (!Number.isSafeInteger(value) || value < 0) throw new TransportFailureV3("invalid_artifact");
  return value;
}

function assertArtifactFresh(artifact: ArtifactV3, now: () => number): void {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  if (value >= artifact.session.init_expire_at_unix_s) {
    throw new ConnectErrorV3("expired_artifact", { kind: "retryable" });
  }
}

function publicPreSpendError(error: unknown): ConnectErrorV3 {
  if (error instanceof ConnectErrorV3) return error;
  return new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
}

function normalizeConnectTimeoutMilliseconds(value: number | undefined): number {
  const timeout = value ?? SDK_DEFAULTS.transport.connectTimeoutMs;
  if (!Number.isSafeInteger(timeout) || timeout < 1) {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  return timeout;
}

function asTransportFailure(error: unknown): TransportFailureV3 {
  return error instanceof TransportFailureV3
    ? error
    : new TransportFailureV3("connection_failed", undefined, error);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function linkAbort(parent: AbortSignal | undefined, child: AbortController): () => void {
  if (parent === undefined) return () => undefined;
  const abort = () => child.abort(parent.reason);
  if (parent.aborted) abort();
  else parent.addEventListener("abort", abort, { once: true });
  return () => parent.removeEventListener("abort", abort);
}

function linkConnectAttemptAbort(parent: AbortSignal, child: AbortController): () => void {
  const abort = () => child.abort(new ConnectErrorV3("connection_failed", { kind: "terminal" }));
  if (parent.aborted) abort();
  else parent.addEventListener("abort", abort, { once: true });
  return () => parent.removeEventListener("abort", abort);
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw signal.reason;
}

async function drainCandidateResultsV3(
  pending: readonly Promise<Readonly<{
    index: number;
    ready?: ReadyAdmissionTransportV3;
    failure?: TransportFailureV3;
  }>>[],
  winner: ReadyAdmissionTransportV3 | undefined,
  signal: AbortSignal,
): Promise<void> {
  const drain = Promise.all(pending).then(async (results) => {
    await Promise.allSettled(results.map(async (result) => {
      if (result.ready !== undefined && result.ready !== winner) {
        await closePreparedTransportV3(result.ready, signal);
      }
    }));
  });
  await raceAbort(drain, signal);
}

async function closePreparedTransportV3(
  transport: ReadyAdmissionTransportV3,
  signal: AbortSignal,
): Promise<void> {
  const closing = Promise.resolve()
    .then(async () => await transport.close())
    .catch(() => undefined);
  if (signal.aborted) {
    abortPreparedTransportV3(transport);
    return;
  }
  try {
    await raceAbort(closing, signal);
  } catch {
    abortPreparedTransportV3(transport);
  }
}

function abortPreparedTransportV3(transport: ReadyAdmissionTransportV3): void {
  try { transport.abort(); } catch { /* best effort */ }
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", abort);
    const abort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(signal.reason);
    };
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}
