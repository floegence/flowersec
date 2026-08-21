import { base64urlDecode } from "../utils/base64url.js";
import {
  AdmissionStatusV3,
  buildFSB3RequestV3,
  decodeFSB3RequestV3,
  encodeFSA3ResponseV3,
  encodeFSB3RequestV3,
  validateArtifactV3,
  type ArtifactV3,
  type DecodedFSB3RequestV3,
} from "./artifact.js";
import { AdmissionSessionV3Error } from "./admissionError.js";
import type { CarrierSessionV3, CarrierStreamV3 } from "./carrier.js";
import { configureServerWebSocketCarrierRoleV3 } from "./webSocketCarrier.js";
import { establishSessionV3, type SessionProtocolRuntimeV3, type SessionV3 } from "./session.js";
import type { RpcRouter } from "../rpc/server.js";

export type AdmissionDecisionV3 =
  | Readonly<{ accepted: true; artifact: ArtifactV3 }>
  | Readonly<{
      accepted: false;
      status: AdmissionStatusV3.Reject | AdmissionStatusV3.Retryable;
      reason: string;
    }>;

export type AdmissionAuthorizerV3 = (
  request: DecodedFSB3RequestV3,
  signal?: AbortSignal,
) => Promise<AdmissionDecisionV3>;

export function createAdmissionReasonRegistryV3(
  builtInReasons: readonly string[],
  deploymentReasons: readonly string[] = [],
): ReadonlySet<string> {
  const registry = new Set<string>();
  for (const reason of [...builtInReasons, ...deploymentReasons]) {
    if (registry.has(reason)) throw new TypeError(`duplicate Flowersec v3 admission reason: ${reason}`);
    registry.add(reason);
    encodeFSA3ResponseV3({
      status: reason === "expired_artifact" ? AdmissionStatusV3.Retryable : AdmissionStatusV3.Reject,
      reason,
    }, registry);
  }
  return registry;
}

export type ReceivedSessionAdmissionV3 = Readonly<{
  carrier: CarrierSessionV3;
  stream: CarrierStreamV3;
  rawFSB3: Uint8Array;
  decoded: DecodedFSB3RequestV3;
}>;

export async function receiveSessionAdmissionV3(
  carrier: CarrierSessionV3,
  signal?: AbortSignal,
): Promise<ReceivedSessionAdmissionV3> {
  const stream = await carrier.acceptStream(signalOptions(signal));
  try {
    const rawFSB3 = await readFSB3(stream, signal);
    return Object.freeze({ carrier, stream, rawFSB3, decoded: decodeFSB3RequestV3(rawFSB3) });
  } catch (error) {
    stream.abort(asError(error));
    carrier.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
}

export async function rejectSessionAdmissionV3(
  received: ReceivedSessionAdmissionV3,
  decision: Extract<AdmissionDecisionV3, Readonly<{ accepted: false }>>,
  admissionReasons: ReadonlySet<string>,
  signal?: AbortSignal,
): Promise<never> {
  try {
    await respondAdmission(
      received.stream,
      { status: decision.status, reason: decision.reason },
      admissionReasons,
      signal,
    );
  } finally {
    received.carrier.abort({ code: 6, reason: "admission rejected" });
  }
  throw new AdmissionSessionV3Error(decision.reason, `Flowersec v3 admission rejected: ${decision.reason}`);
}

export async function acceptReceivedSessionV3(
  received: ReceivedSessionAdmissionV3,
  artifact: ArtifactV3,
  options: Readonly<{
    runtime: SessionProtocolRuntimeV3;
    admissionReasons: ReadonlySet<string>;
    resolveRPCRouter?(
      request: DecodedFSB3RequestV3,
      signal?: AbortSignal,
    ): Promise<RpcRouter> | RpcRouter;
    nowUnixSeconds?: () => number;
    signal?: AbortSignal;
  }>,
): Promise<SessionV3> {
  return await acceptCarrierBoundSessionV3(received, artifact, options);
}

async function acceptCarrierBoundSessionV3(
  received: ReceivedSessionAdmissionV3,
  artifact: ArtifactV3,
  options: Readonly<{
    runtime: SessionProtocolRuntimeV3;
    admissionReasons: ReadonlySet<string>;
    resolveRPCRouter?(
      request: DecodedFSB3RequestV3,
      signal?: AbortSignal,
    ): Promise<RpcRouter> | RpcRouter;
    nowUnixSeconds?: () => number;
    signal?: AbortSignal;
  }>,
): Promise<SessionV3> {
  try {
    assertAdmissionCarrierBindingV3(received);
    validateArtifactV3(artifact);
    const expected = encodeFSB3RequestV3(
      buildFSB3RequestV3(artifact, received.decoded.request.chosen_candidate_id),
    );
    if (!equalBytes(expected, received.rawFSB3)) throw new Error("authorized artifact does not match admission");
    if ((options.nowUnixSeconds?.() ?? Math.floor(Date.now() / 1_000)) >= artifact.session.init_expire_at_unix_s) {
      return await rejectSessionAdmissionV3(received, {
        accepted: false,
        status: AdmissionStatusV3.Retryable,
        reason: "expired_artifact",
      }, options.admissionReasons, options.signal);
    }
    const rpcRouter = options.resolveRPCRouter === undefined
      ? undefined
      : await raceAbort(
          Promise.resolve().then(async () =>
            await options.resolveRPCRouter!(received.decoded, options.signal)),
          options.signal,
        );
    if (received.carrier.kind === "websocket") {
      configureServerWebSocketCarrierRoleV3(received.carrier, false);
    }
    await respondAdmission(
      received.stream,
      { status: AdmissionStatusV3.Success, reason: "" },
      options.admissionReasons,
      options.signal,
    );
    const binding = received.decoded.localAdmissionBinding;
    return await establishSessionV3(received.carrier, {
      role: "server",
      path: artifact.path.kind,
      channelID: artifact.session.channel_id,
      sessionContractHash: base64urlDecode(artifact.session.contract_hash_b64u),
      suite: artifact.session.default_suite,
      psk: base64urlDecode(artifact.session.e2ee_psk_b64u),
      maxInboundStreams: artifact.session.max_inbound_streams,
      sessionContract: artifact.session,
      idleTimeoutMs: artifact.session.idle_timeout_seconds * 1_000,
      closeTimeoutMs: 5_000,
      runtime: options.runtime,
      ...(rpcRouter === undefined ? {} : { rpcRouter }),
      localAdmissionBinding: binding,
      peerAdmissionBinding: binding,
      localEndpointInstanceID: "",
      expectedPeerEndpointInstanceID: "",
      deadlines: {
        establishTimeoutMs: artifact.session.establish_timeout_seconds * 1_000,
        rekeyPrepareTimeoutMs: artifact.session.rekey_prepare_timeout_seconds * 1_000,
        rekeyCompletionTimeoutMs: artifact.session.rekey_completion_timeout_seconds * 1_000,
      },
    }, signalOptions(options.signal));
  } catch (error) {
    received.stream.abort(asError(error));
    received.carrier.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
}

export async function acceptCarrierSessionV3(
  carrier: CarrierSessionV3,
  authorize: AdmissionAuthorizerV3,
  options: Readonly<{
    runtime: SessionProtocolRuntimeV3;
    admissionReasons: ReadonlySet<string>;
    resolveRPCRouter?(
      request: DecodedFSB3RequestV3,
      signal?: AbortSignal,
    ): Promise<RpcRouter> | RpcRouter;
    nowUnixSeconds?: () => number;
    signal?: AbortSignal;
  }>,
): Promise<SessionV3> {
  const received = await receiveSessionAdmissionV3(carrier, options.signal);
  try {
    assertAdmissionCarrierBindingV3(received);
    const decision = await raceAbort(
      Promise.resolve().then(async () => await authorize(received.decoded, options.signal)),
      options.signal,
    );
    if (!decision.accepted) {
      return await rejectSessionAdmissionV3(
        received,
        decision,
        options.admissionReasons,
        options.signal,
      );
    }
    return await acceptCarrierBoundSessionV3(received, decision.artifact, options);
  } catch (error) {
    received.stream.abort(asError(error));
    carrier.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
}

function assertAdmissionCarrierBindingV3(received: ReceivedSessionAdmissionV3): void {
  const chosen = received.decoded.request.candidates.find(({ id }) =>
    id === received.decoded.request.chosen_candidate_id);
  if (chosen?.carrier !== received.carrier.kind || received.decoded.request.pathKind !== received.carrier.path) {
    throw new Error("admission carrier binding mismatch");
  }
}

async function respondAdmission(
  stream: CarrierStreamV3,
  response: Readonly<{ status: AdmissionStatusV3; reason: string }>,
  admissionReasons: ReadonlySet<string>,
  signal?: AbortSignal,
): Promise<void> {
  await writeAll(stream, encodeFSA3ResponseV3(response, admissionReasons), signal);
  await raceAbort(stream.closeWrite(), signal);
}

async function readFSB3(stream: CarrierStreamV3, signal?: AbortSignal): Promise<Uint8Array> {
  const reader = new ExactReader(stream);
  const header = await reader.readExactly(12, signal);
  const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(8, false);
  if (length < 1 || length > 32_768) throw new Error("invalid FSB3 payload length");
  const payload = await reader.readExactly(length, signal);
  await reader.expectEOF(signal);
  const raw = new Uint8Array(header.length + payload.length);
  raw.set(header);
  raw.set(payload, header.length);
  return raw;
}

class ExactReader {
  private readonly chunks: Uint8Array[] = [];
  private offset = 0;
  private available = 0;

  constructor(private readonly stream: CarrierStreamV3) {}

  async readExactly(length: number, signal?: AbortSignal): Promise<Uint8Array> {
    while (this.available < length) {
      const chunk = await raceAbort(this.stream.read(signalOptions(signal)), signal);
      if (chunk === null) throw new Error("truncated admission stream");
      if (chunk.length === 0) continue;
      this.chunks.push(chunk);
      this.available += chunk.length;
    }
    const result = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      const chunk = this.chunks[0]!;
      const take = Math.min(length - written, chunk.length - this.offset);
      result.set(chunk.subarray(this.offset, this.offset + take), written);
      this.offset += take;
      this.available -= take;
      written += take;
      if (this.offset === chunk.length) {
        this.chunks.shift();
        this.offset = 0;
      }
    }
    return result;
  }

  async expectEOF(signal?: AbortSignal): Promise<void> {
    if (this.available !== 0) throw new Error("trailing bytes after FSB3");
    while (true) {
      const chunk = await raceAbort(this.stream.read(signalOptions(signal)), signal);
      if (chunk === null) return;
      if (chunk.length !== 0) throw new Error("trailing bytes after FSB3");
    }
  }
}

async function writeAll(stream: CarrierStreamV3, value: Uint8Array, signal?: AbortSignal): Promise<void> {
  let offset = 0;
  while (offset < value.length) {
    const written = await raceAbort(stream.write(value.subarray(offset), signalOptions(signal)), signal);
    if (written < 1 || written > value.length - offset) throw new Error("short admission write");
    offset += written;
  }
}

function signalOptions(signal: AbortSignal | undefined): Readonly<{ signal?: AbortSignal }> {
  return signal === undefined ? {} : { signal };
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
