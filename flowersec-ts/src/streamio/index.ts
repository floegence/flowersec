import type { Client } from "../client.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { AbortError, throwIfAborted } from "../utils/errors.js";
import { ByteReader } from "../yamux/byteReader.js";
import type { YamuxStream } from "../yamux/stream.js";

function abortReasonToError(signal: AbortSignal): Error {
  const r = signal.reason;
  if (r instanceof Error) return r;
  if (typeof r === "string" && r !== "") return new AbortError(r);
  return new AbortError("aborted");
}

function bindAbortToStream(stream: YamuxStream, signal: AbortSignal): void {
  const onAbort = () => {
    try {
      stream.reset(abortReasonToError(signal));
    } catch {
      // Best-effort cancel.
    }
  };
  if (signal.aborted) {
    onAbort();
    return;
  }
  signal.addEventListener("abort", onAbort, { once: true });
}

// readMaybe reads the next chunk or null on EOF.
export async function readMaybe(stream: YamuxStream): Promise<Uint8Array | null> {
  return await stream.read();
}

// createByteReader adapts a YamuxStream to a ByteReader (EOF is handled by YamuxStream.read()).
export function createByteReader(stream: YamuxStream, opts: Readonly<{ signal?: AbortSignal }> = {}): ByteReader {
  if (opts.signal != null) bindAbortToStream(stream, opts.signal);
  return new ByteReader(() => stream.read());
}

// readExactly reads n bytes (or throws on EOF/error). If signal aborts, the caller is expected to reset/close the stream.
export async function readExactly(reader: ByteReader, n: number, opts: Readonly<{ signal?: AbortSignal }> = {}): Promise<Uint8Array> {
  throwIfAborted(opts.signal, "read aborted");
  return await reader.readExactly(n);
}

export type ReadNBytesOptions = Readonly<{
  chunkSize?: number;
  signal?: AbortSignal;
  onProgress?: (read: number) => void;
}>;

// readNBytes reads exactly n bytes and returns them as a single contiguous buffer.
export async function readNBytes(reader: ByteReader, n: number, opts: ReadNBytesOptions = {}): Promise<Uint8Array> {
  const total = Math.max(0, Math.floor(n));
  const out = new Uint8Array(total);
  if (total === 0) return out;

  const chunkSize = Math.max(1, Math.floor(opts.chunkSize ?? 64 * 1024));
  let off = 0;
  while (off < total) {
    throwIfAborted(opts.signal, "read aborted");
    const take = Math.min(chunkSize, total - off);
    const chunk = await reader.readExactly(take);
    out.set(chunk, off);
    off += chunk.length;
    opts.onProgress?.(off);
  }
  return out;
}

export type JsonFrameChannel = Readonly<{
  stream: YamuxStream;
  reader: ByteReader;
  writeFrame: (value: unknown) => Promise<void>;
  readFrame: <T = unknown>(
    opts?: Readonly<{ maxBytes?: number; assert?: (value: unknown) => T }>
  ) => Promise<T>;
  close: () => Promise<void>;
}>;

export type JsonFrameChannelOptions = Readonly<{
  signal?: AbortSignal;
  maxJsonFrameBytes?: number;
}>;

function normalizeMaxJsonFrameBytes(maxBytes: number | undefined): number {
  const value = maxBytes ?? DEFAULT_MAX_JSON_FRAME_BYTES;
  if (!Number.isFinite(value) || value < 0) {
    throw new Error("maxJsonFrameBytes must be a non-negative finite number");
  }
  return Math.floor(value);
}

export function createJsonFrameChannel(
  stream: YamuxStream,
  opts: JsonFrameChannelOptions = {}
): JsonFrameChannel {
  const reader = createByteReader(stream, opts.signal == null ? {} : { signal: opts.signal });
  const defaultMaxBytes = normalizeMaxJsonFrameBytes(opts.maxJsonFrameBytes);

  return {
    stream,
    reader,
    writeFrame: async (value) => {
      await writeJsonFrame(stream, value);
    },
    readFrame: async <T = unknown>(
      readOpts: Readonly<{ maxBytes?: number; assert?: (value: unknown) => T }> = {}
    ): Promise<T> => {
      const raw = await readJsonFrame(reader, normalizeMaxJsonFrameBytes(readOpts.maxBytes ?? defaultMaxBytes));
      if (readOpts.assert != null) return readOpts.assert(raw);
      return raw as T;
    },
    close: async () => {
      await stream.close();
    },
  };
}

export async function openJsonFrameChannel(
  client: Pick<Client, "openStream">,
  kind: string,
  opts: JsonFrameChannelOptions = {}
): Promise<JsonFrameChannel> {
  const stream = await client.openStream(kind, opts.signal == null ? {} : { signal: opts.signal });
  return createJsonFrameChannel(stream, opts);
}
