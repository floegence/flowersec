import {
  AdmissionStatusV2,
  computeSessionContractHashV2,
  decodeFSB2RequestV2,
  decodeFSA2ResponseV2,
  type CanonicalArtifactCandidateV2,
} from "../v2/artifact.js";
import type {
  CarrierSessionV2,
  NativeCarrierStreamV2,
} from "../v2/carrier.js";
import type { CarrierKind, OperationOptionsV2, PathKind } from "../v2/contract.js";
import type { SessionConfigV2 } from "../v2/session.js";
import { AdmissionSessionV2Error } from "../v2/admissionError.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import {
  commitArtifactLeaseSpendV2,
  type ArtifactLeaseV2,
} from "../v2/artifactLease.js";

export class CredentialCommitError extends Error {
  constructor(cause: unknown) {
    super("durable credential spend failed", { cause });
    this.name = "CredentialCommitError";
  }
}

export type ClientAdmissionChannelV2 =
  | Readonly<{
    framing: "message";
    write(data: Uint8Array, options?: OperationOptionsV2): Promise<void>;
    read(options?: OperationOptionsV2): Promise<Uint8Array>;
    abort(error: Error): void;
  }>
  | Readonly<{
    framing: "stream";
    stream: NativeCarrierStreamV2;
    abort(error: Error): void;
  }>;

export type ReadyAdmissionTransportV2 = Readonly<{
  candidate: CanonicalArtifactCandidateV2;
  kind: CarrierKind;
  path: PathKind;
  inboundBidirectionalStreamCapacity: number;
  openAdmissionChannel(signal?: AbortSignal): Promise<ClientAdmissionChannelV2>;
  finalize(): CarrierSessionV2;
  close(): Promise<void>;
  abort(): void;
}>;

export async function commitClientAdmissionV2(
  ready: ReadyAdmissionTransportV2,
  lease: ArtifactLeaseV2,
  assertCredentialValid: () => void,
  rawFSB2: Uint8Array,
  config: SessionConfigV2,
  signal?: AbortSignal,
): Promise<CarrierSessionV2> {
  throwIfAborted(signal);
  requireReadyTransportBinding(ready, config);
  validateOutboundAdmissionV2(rawFSB2, config, ready.kind);
  const channel = await ready.openAdmissionChannel(signal);
  try {
    assertCredentialValid();
    try {
      await commitArtifactLeaseSpendV2(lease, signal);
    } catch (error) {
      throw new CredentialCommitError(error);
    }
    assertCredentialValid();
    throwIfAborted(signal);
    const rawFSA2 = channel.framing === "message"
      ? await exchangeMessage(channel, rawFSB2, signal)
      : await exchangeStream(channel.stream, rawFSB2, signal);
    requireAdmissionSuccessV2(rawFSA2);
    return ready.finalize();
  } catch (error) {
    const failure = asError(error);
    channel.abort(failure);
    ready.abort();
    throw error;
  }
}

function requireReadyTransportBinding(
  ready: ReadyAdmissionTransportV2,
  config: SessionConfigV2,
): void {
  if (ready.candidate.carrier !== ready.kind) {
    throw new AdmissionSessionV2Error("carrier_mismatch", "ready carrier does not match its artifact candidate");
  }
  if (ready.path !== config.path) {
    throw new AdmissionSessionV2Error("path_mismatch", "ready carrier path does not match SessionV2 path");
  }
  requireExactCarrierCapacityV2(ready.inboundBidirectionalStreamCapacity, config.maxInboundStreams);
}

async function exchangeMessage(
  channel: Extract<ClientAdmissionChannelV2, Readonly<{ framing: "message" }>>,
  rawFSB2: Uint8Array,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const options = signalOptions(signal);
  await channel.write(rawFSB2, options);
  return await channel.read(options);
}

async function exchangeStream(
  stream: NativeCarrierStreamV2,
  rawFSB2: Uint8Array,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  await writeAll(stream, rawFSB2, signal);
  await raceAbort(stream.closeWrite(), signal);
  const reader = new NativeExactReader(stream);
  const header = await reader.readExactly(8, signal);
  const reasonLength = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint16(6, false);
  if (reasonLength > 64) throw new AdmissionSessionV2Error("invalid_fsa2", "FSA2 reason exceeds limit");
  const rawFSA2 = concat(header, await reader.readExactly(reasonLength, signal));
  await reader.expectCleanEOF(signal);
  return rawFSA2;
}

export function requireExactCarrierCapacityV2(physical: number, logical: number): void {
  if (!validLogicalStreamCapacity(logical) || physical !== logical + 2) {
    throw new AdmissionSessionV2Error(
      "stream_capacity_mismatch",
      "carrier inbound bidirectional stream capacity does not match SessionV2 logical limit",
    );
  }
}

export function validateOutboundAdmissionV2(
  rawFSB2: Uint8Array,
  config: SessionConfigV2,
  carrier: CarrierKind,
): void {
  let decoded;
  try {
    decoded = decodeFSB2RequestV2(rawFSB2);
  } catch (error) {
    throw new AdmissionSessionV2Error(
      "invalid_fsb2",
      error instanceof Error ? error.message : "invalid FSB2 request",
    );
  }
  const request = decoded.request;
  if (request.pathKind !== config.path) {
    throw new AdmissionSessionV2Error("path_mismatch", "FSB2 path does not match SessionV2 path");
  }
  validateSessionContract(config);
  const expectedRole = request.pathKind === "tunnel" && request.role === 2 ? "server" : "client";
  if (config.role !== expectedRole) {
    throw new AdmissionSessionV2Error("role_mismatch", "FSB2 role does not match SessionV2 role");
  }
  if (
    request.channel_id !== config.channelID ||
    request.session_contract_hash_b64u !== base64urlEncode(config.sessionContractHash)
  ) {
    throw new AdmissionSessionV2Error("session_config_mismatch", "FSB2 session identity does not match SessionV2 config");
  }
  if (request.pathKind === "tunnel" && request.endpoint_instance_id !== config.localEndpointInstanceID) {
    throw new AdmissionSessionV2Error("endpoint_mismatch", "FSB2 endpoint identity does not match SessionV2 config");
  }
  if (!bytesEqual(decoded.localAdmissionBinding, config.localAdmissionBinding)) {
    throw new AdmissionSessionV2Error("admission_binding_mismatch", "FSB2 admission binding does not match SessionV2 config");
  }
  if (request.pathKind === "direct" && !bytesEqual(decoded.localAdmissionBinding, config.peerAdmissionBinding)) {
    throw new AdmissionSessionV2Error(
      "peer_admission_binding_mismatch",
      "direct FSB2 admission binding does not match SessionV2 peer binding",
    );
  }
  const candidate = request.candidates.find((entry) => entry.id === request.chosen_candidate_id);
  if (candidate?.carrier !== carrier) {
    throw new AdmissionSessionV2Error("carrier_mismatch", "FSB2 chosen candidate does not match the carrier");
  }
}

function validateSessionContract(config: SessionConfigV2): void {
  const contract = config.sessionContract;
  if (contract === undefined) {
    throw new AdmissionSessionV2Error("session_config_mismatch", "admitted SessionV2 requires a validated session contract");
  }
  let hash: Uint8Array;
  let hashBase64URL: string;
  let psk: Uint8Array;
  try {
    hashBase64URL = computeSessionContractHashV2(contract).hashBase64URL;
    hash = base64urlDecode(hashBase64URL);
    psk = base64urlDecode(contract.e2ee_psk_b64u);
  } catch (error) {
    throw new AdmissionSessionV2Error(
      "session_config_mismatch",
      error instanceof Error ? error.message : "invalid session contract",
    );
  }
  if (
    contract.contract_hash_b64u !== hashBase64URL ||
    !bytesEqual(hash, config.sessionContractHash) ||
    contract.channel_id !== config.channelID ||
    contract.max_inbound_streams !== config.maxInboundStreams ||
    contract.default_suite !== config.suite ||
    !contract.allowed_suites.includes(config.suite) ||
    !bytesEqual(psk, config.psk) ||
    contract.selected_features !== 0 ||
    (config.idleTimeoutMs ?? 60_000) !== contract.idle_timeout_seconds * 1_000 ||
    (config.deadlines?.establishTimeoutMs ?? 30_000) !== contract.establish_timeout_seconds * 1_000 ||
    (config.deadlines?.rekeyPrepareTimeoutMs ?? 10_000) !== contract.rekey_prepare_timeout_seconds * 1_000 ||
    (config.deadlines?.rekeyCompletionTimeoutMs ?? 30_000) !== contract.rekey_completion_timeout_seconds * 1_000
  ) {
    throw new AdmissionSessionV2Error("session_config_mismatch", "SessionV2 config does not match the signed session contract");
  }
}

function requireAdmissionSuccessV2(rawFSA2: Uint8Array): void {
  const response = decodeFSA2ResponseV2(rawFSA2);
  if (response.status !== AdmissionStatusV2.Success) {
    throw new AdmissionSessionV2Error(response.reason, `Flowersec v2 admission rejected: ${response.reason}`);
  }
}

class NativeExactReader {
  private readonly chunks: Uint8Array[] = [];
  private offset = 0;
  private bytes = 0;

  constructor(private readonly stream: NativeCarrierStreamV2) {}

  async readExactly(length: number, signal?: AbortSignal): Promise<Uint8Array> {
    while (this.bytes < length) {
      throwIfAborted(signal);
      const chunk = await raceAbort(this.stream.read(), signal);
      if (chunk === null) throw new AdmissionSessionV2Error("truncated_fsa2", "unexpected admission EOF");
      if (chunk.length === 0) continue;
      this.chunks.push(chunk);
      this.bytes += chunk.length;
    }
    const output = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      const chunk = this.chunks[0]!;
      const take = Math.min(length - written, chunk.length - this.offset);
      output.set(chunk.subarray(this.offset, this.offset + take), written);
      written += take;
      this.offset += take;
      this.bytes -= take;
      if (this.offset === chunk.length) {
        this.chunks.shift();
        this.offset = 0;
      }
    }
    return output;
  }

  async expectCleanEOF(signal?: AbortSignal): Promise<void> {
    if (this.bytes !== 0) throw new AdmissionSessionV2Error("invalid_fsa2", "trailing bytes after FSA2");
    while (true) {
      throwIfAborted(signal);
      const chunk = await raceAbort(this.stream.read(), signal);
      if (chunk === null) return;
      if (chunk.length !== 0) throw new AdmissionSessionV2Error("invalid_fsa2", "trailing bytes after FSA2");
    }
  }
}

async function writeAll(stream: NativeCarrierStreamV2, value: Uint8Array, signal?: AbortSignal): Promise<void> {
  let offset = 0;
  while (offset < value.length) {
    throwIfAborted(signal);
    const written = await raceAbort(stream.write(value.subarray(offset)), signal);
    if (written < 1 || written > value.length - offset) {
      throw new AdmissionSessionV2Error("short_write", "short admission write");
    }
    offset += written;
  }
}

function signalOptions(signal: AbortSignal | undefined): OperationOptionsV2 {
  return signal === undefined ? {} : { signal };
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new AdmissionSessionV2Error("aborted", "admission aborted");
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  throwIfAborted(signal);
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason instanceof Error
      ? signal.reason
      : new AdmissionSessionV2Error("aborted", "admission aborted"));
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function validLogicalStreamCapacity(logical: number): boolean {
  return Number.isInteger(logical) && logical >= 1 && logical <= 128;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index++) different |= left[index]! ^ right[index]!;
  return different === 0;
}
