import {
  AdmissionStatusV2,
  decodeFSB2RequestV2,
  encodeFSA2ResponseV2,
  type ArtifactV2,
  type DecodedFSB2RequestV2,
} from "../v2/artifact.js";
import { adaptNativeCarrierSessionV2, type NativeCarrierSessionV2, type NativeCarrierStreamV2 } from "../v2/carrier.js";
import type { SessionProtocolRuntimeV2, SessionV2 as InternalSessionV2 } from "../v2/session.js";
import { establishSessionV2 } from "../v2/session.js";
import { AdmissionSessionV2Error } from "../v2/admissionError.js";
import { sessionConfigFromArtifactV2 } from "./sessionConfig.js";

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

export async function acceptNativeSessionV2(
  carrier: NativeCarrierSessionV2,
  authorize: AdmissionAuthorizerV2,
  options: Readonly<{ runtime: SessionProtocolRuntimeV2; signal?: AbortSignal }>,
): Promise<InternalSessionV2> {
  const admission = carrier.kind === "webtransport"
    ? await carrier.openStream(signalOptions(options.signal))
    : await carrier.acceptStream(signalOptions(options.signal));
  try {
    const rawFSB2 = await readFSB2(admission, options.signal);
    const decoded = decodeFSB2RequestV2(rawFSB2);
    const decision = await authorize(decoded, options.signal);
    const response = decision.accepted
      ? { status: AdmissionStatusV2.Success, reason: "" }
      : { status: decision.status, reason: decision.reason };
    await writeAll(
      admission,
      encodeFSA2ResponseV2(response),
      options.signal,
    );
    await raceAbort(admission.closeWrite(), options.signal);
    if (!decision.accepted) {
      throw new AdmissionSessionV2Error(decision.reason, `Flowersec v2 admission rejected: ${decision.reason}`);
    }
    return await establishSessionV2(
      adaptNativeCarrierSessionV2(carrier),
      sessionConfigFromArtifactV2(decision.artifact, rawFSB2, options.runtime, undefined, "server"),
      signalOptions(options.signal),
    );
  } catch (error) {
    admission.abort(asError(error));
    carrier.abort({ code: 6, reason: "admission failed" });
    throw error;
  }
}

async function readFSB2(stream: NativeCarrierStreamV2, signal?: AbortSignal): Promise<Uint8Array> {
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

  constructor(private readonly stream: NativeCarrierStreamV2) {}

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

async function writeAll(stream: NativeCarrierStreamV2, value: Uint8Array, signal?: AbortSignal): Promise<void> {
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
