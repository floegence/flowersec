import {
  AdmissionStatusV2,
  buildFSB2RequestV2,
  decodeFSB2RequestV2,
  encodeFSB2RequestV2,
  encodeFSA2ResponseV2,
  type ArtifactV2,
  type DecodedFSB2RequestV2,
} from "../v2/artifact.js";
import type { CarrierSessionV2, CarrierStreamV2 } from "../v2/carrier.js";
import type { SessionProtocolRuntimeV2, SessionV2 as InternalSessionV2 } from "../v2/session.js";
import { establishSessionV2 } from "../v2/session.js";
import { AdmissionSessionV2Error } from "../v2/admissionError.js";
import { sessionConfigFromArtifactV2 } from "./sessionConfig.js";
import type { RpcRouter } from "../rpc/server.js";

export type AdmissionDecisionV2 =
  | Readonly<{ accepted: true; artifact: ArtifactV2 }>
  | Readonly<{
    accepted: false;
    status: AdmissionStatusV2.Reject | AdmissionStatusV2.Retryable;
    reason: string;
  }>;

export type AdmissionAuthorizerV2 = (
  request: DecodedFSB2RequestV2,
  signal?: AbortSignal,
) => Promise<AdmissionDecisionV2>;

export type ReceivedSessionAdmissionV2 = Readonly<{
  carrier: CarrierSessionV2;
  stream: CarrierStreamV2;
  rawFSB2: Uint8Array;
  decoded: DecodedFSB2RequestV2;
}>;

export async function receiveSessionAdmissionV2(
  carrier: CarrierSessionV2,
  signal?: AbortSignal,
): Promise<ReceivedSessionAdmissionV2> {
  const stream = carrier.kind === "webtransport"
    ? await carrier.openStream(signalOptions(signal))
    : await carrier.acceptStream(signalOptions(signal));
  try {
    const rawFSB2 = await readFSB2(stream, signal);
    return Object.freeze({ carrier, stream, rawFSB2, decoded: decodeFSB2RequestV2(rawFSB2) });
  } catch (error) {
    stream.abort(asError(error));
    carrier.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
}

export async function rejectSessionAdmissionV2(
  received: ReceivedSessionAdmissionV2,
  decision: Extract<AdmissionDecisionV2, Readonly<{ accepted: false }>>,
  signal?: AbortSignal,
): Promise<never> {
  await respondAdmission(received.stream, { status: decision.status, reason: decision.reason }, signal);
  received.carrier.abort({ code: 6, reason: "admission rejected" });
  throw new AdmissionSessionV2Error(
    decision.reason,
    `Flowersec v2 admission rejected: ${decision.reason}`,
  );
}

export async function acceptReceivedSessionV2(
  received: ReceivedSessionAdmissionV2,
  artifact: ArtifactV2,
  options: Readonly<{
    runtime: SessionProtocolRuntimeV2;
    rpcRouter?: RpcRouter;
    signal?: AbortSignal;
    role?: "client" | "server";
    localAdmissionBinding?: Uint8Array;
    peerAdmissionBinding?: Uint8Array;
    localEndpointInstanceID?: string;
    expectedPeerEndpointInstanceID?: string;
  }>,
): Promise<InternalSessionV2> {
  try {
    const expected = encodeFSB2RequestV2(
      buildFSB2RequestV2(artifact, received.decoded.request.chosen_candidate_id),
    );
    if (!equalBytes(expected, received.rawFSB2)) throw new Error("authorized artifact does not match admission");
    await respondAdmission(received.stream, { status: AdmissionStatusV2.Success, reason: "" }, options.signal);
    const base = sessionConfigFromArtifactV2(
      artifact,
      received.rawFSB2,
      options.runtime,
      undefined,
      options.role,
    );
    const config = {
      ...base,
      ...(options.rpcRouter === undefined ? {} : { rpcRouter: options.rpcRouter }),
      ...(options.localAdmissionBinding === undefined ? {} : { localAdmissionBinding: options.localAdmissionBinding }),
      ...(options.peerAdmissionBinding === undefined ? {} : { peerAdmissionBinding: options.peerAdmissionBinding }),
      ...(options.localEndpointInstanceID === undefined ? {} : { localEndpointInstanceID: options.localEndpointInstanceID }),
      ...(options.expectedPeerEndpointInstanceID === undefined ? {} : { expectedPeerEndpointInstanceID: options.expectedPeerEndpointInstanceID }),
    };
    return await establishSessionV2(received.carrier, config, signalOptions(options.signal));
  } catch (error) {
    received.stream.abort(asError(error));
    received.carrier.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
}

export async function acceptNativeSessionV2(
  carrier: CarrierSessionV2,
  authorize: AdmissionAuthorizerV2,
  options: Readonly<{ runtime: SessionProtocolRuntimeV2; rpcRouter?: RpcRouter; signal?: AbortSignal }>,
): Promise<InternalSessionV2> {
  const received = await receiveSessionAdmissionV2(carrier, options.signal);
  try {
    const decision = await authorize(received.decoded, options.signal);
    if (!decision.accepted) {
      return await rejectSessionAdmissionV2(received, decision, options.signal);
    }
    return await acceptReceivedSessionV2(received, decision.artifact, { ...options, role: "server" });
  } catch (error) {
    received.stream.abort(asError(error));
    carrier.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
}

async function respondAdmission(
  stream: CarrierStreamV2,
  response: Readonly<{ status: AdmissionStatusV2; reason: string }>,
  signal?: AbortSignal,
): Promise<void> {
  await writeAll(stream, encodeFSA2ResponseV2(response), signal);
  await raceAbort(stream.closeWrite(), signal);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

async function readFSB2(stream: CarrierStreamV2, signal?: AbortSignal): Promise<Uint8Array> {
  const reader = new NativeReader(stream);
  const header = await reader.readExactly(12, signal);
  const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(8, false);
  if (length < 1 || length > 32_768) throw new Error("invalid FSB2 payload length");
  const payload = await reader.readExactly(length, signal);
  await reader.expectEOF(signal);
  const raw = new Uint8Array(header.length + payload.length);
  raw.set(header);
  raw.set(payload, header.length);
  return raw;
}

class NativeReader {
  private readonly chunks: Uint8Array[] = [];
  private offset = 0;
  private available = 0;

  constructor(private readonly stream: CarrierStreamV2) {}

  async readExactly(length: number, signal?: AbortSignal): Promise<Uint8Array> {
    while (this.available < length) {
      const chunk = await raceAbort(this.stream.read(), signal);
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
    if (this.available !== 0) throw new Error("trailing bytes after FSB2");
    while (true) {
      const chunk = await raceAbort(this.stream.read(), signal);
      if (chunk === null) return;
      if (chunk.length !== 0) throw new Error("trailing bytes after FSB2");
    }
  }
}

async function writeAll(stream: CarrierStreamV2, value: Uint8Array, signal?: AbortSignal): Promise<void> {
  let offset = 0;
  while (offset < value.length) {
    const written = await raceAbort(stream.write(value.subarray(offset)), signal);
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

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
