import {
  AdmissionStatusV2,
  computeSessionContractHashV2,
  decodeFSB2RequestV2,
  decodeFSA2ResponseV2,
} from "./artifact.js";
import {
  adaptNativeCarrierSessionV2,
  createWebSocketCarrierSessionV2,
  type NativeCarrierSessionV2,
  type NativeCarrierStreamV2,
  type WebSocketBinaryTransportV2,
  type WebSocketResourcePolicyV2,
} from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "./session.js";

export type { WebSocketResourcePolicyV2 } from "./carrier.js";

export class AdmissionSessionV2Error extends Error {
  constructor(readonly reason: string, message: string) {
    super(message);
    this.name = "AdmissionSessionV2Error";
  }
}

export async function establishAdmittedWebSocketSessionV2(
  transport: WebSocketBinaryTransportV2,
  rawFSB2: Uint8Array,
  reasons: ReadonlySet<string>,
  config: SessionConfigV2,
  options: OperationOptionsV2 & Readonly<{ resourcePolicy?: WebSocketResourcePolicyV2 }> = {},
): Promise<SessionV2> {
  throwIfAborted(options.signal);
  try {
    requireLogicalStreamCapacity(config.maxInboundStreams);
    validateOutboundAdmission(rawFSB2, config, "websocket");
    await transport.writeBinary(rawFSB2, signalOptions(options.signal));
    const rawFSA2 = await transport.readBinary(signalOptions(options.signal));
    requireAdmissionSuccess(rawFSA2, reasons);
    const physicalIncomingStreams = config.maxInboundStreams + 2;
    const carrier = createWebSocketCarrierSessionV2(transport, {
      path: config.path,
      client: config.role === "client",
      inboundBidirectionalStreamCapacity: physicalIncomingStreams,
      ...(options.resourcePolicy === undefined ? {} : { resourcePolicy: options.resourcePolicy }),
    });
    return await establishSessionV2(carrier, config, signalOptions(options.signal));
  } catch (error) {
    transport.close();
    throw error;
  }
}

export async function establishAdmittedNativeSessionV2(
  native: NativeCarrierSessionV2,
  rawFSB2: Uint8Array,
  reasons: ReadonlySet<string>,
  config: SessionConfigV2,
  options: OperationOptionsV2 = {},
): Promise<SessionV2> {
  throwIfAborted(options.signal);
  if (native.path !== config.path) throw new AdmissionSessionV2Error("path_mismatch", "native carrier path mismatch");
  requireExactCarrierCapacity(native.inboundBidirectionalStreamCapacity, config.maxInboundStreams);
  validateOutboundAdmission(rawFSB2, config, native.kind);
  const admission = await native.openStream(signalOptions(options.signal));
  try {
    await writeAll(admission, rawFSB2, options.signal);
    await raceAbort(admission.closeWrite(), options.signal);
    const reader = new NativeExactReader(admission);
    const header = await reader.readExactly(8, options.signal);
    const reasonLength = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint16(6, false);
    if (reasonLength > 64) throw new AdmissionSessionV2Error("invalid_fsa2", "FSA2 reason exceeds limit");
    const rawFSA2 = concat(header, await reader.readExactly(reasonLength, options.signal));
    await reader.expectCleanEOF(options.signal);
    requireAdmissionSuccess(rawFSA2, reasons);
  } catch (error) {
    admission.abort(asError(error));
    native.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
  return await establishSessionV2(adaptNativeCarrierSessionV2(native), config, signalOptions(options.signal));
}

function requireExactCarrierCapacity(physical: number, logical: number): void {
  if (!validLogicalStreamCapacity(logical) || physical !== logical + 2) {
    throw new AdmissionSessionV2Error(
      "stream_capacity_mismatch",
      "carrier inbound bidirectional stream capacity does not match SessionV2 logical limit",
    );
  }
}

function requireLogicalStreamCapacity(logical: number): void {
  if (!validLogicalStreamCapacity(logical)) {
    throw new AdmissionSessionV2Error(
      "stream_capacity_mismatch",
      "SessionV2 logical inbound stream capacity must be an integer from 1 to 128",
    );
  }
}

function validateOutboundAdmission(
  rawFSB2: Uint8Array,
  config: SessionConfigV2,
  carrier: "websocket" | NativeCarrierSessionV2["kind"],
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

function validLogicalStreamCapacity(logical: number): boolean {
  return Number.isInteger(logical) && logical >= 1 && logical <= 128;
}

function requireAdmissionSuccess(rawFSA2: Uint8Array, reasons: ReadonlySet<string>): void {
  const response = decodeFSA2ResponseV2(rawFSA2, reasons);
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
    const out = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      const chunk = this.chunks[0]!;
      const take = Math.min(length - written, chunk.length - this.offset);
      out.set(chunk.subarray(this.offset, this.offset + take), written);
      written += take;
      this.offset += take;
      this.bytes -= take;
      if (this.offset === chunk.length) {
        this.chunks.shift();
        this.offset = 0;
      }
    }
    return out;
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
    if (written < 1 || written > value.length - offset) throw new AdmissionSessionV2Error("short_write", "short admission write");
    offset += written;
  }
}

function signalOptions(signal: AbortSignal | undefined): Readonly<{ signal?: AbortSignal }> {
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
  const out = new Uint8Array(left.length + right.length);
  out.set(left);
  out.set(right, left.length);
  return out;
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index++) different |= left[index]! ^ right[index]!;
  return different === 0;
}
