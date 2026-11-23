import type { ByteStream, OperationOptions } from "../public/contract.js";

export class ProxyByteReader {
  private buffered: Uint8Array<ArrayBufferLike> | undefined;

  constructor(
    private readonly stream: ByteStream,
    private readonly options: OperationOptions = {},
  ) {}

  async readExactly(length: number): Promise<Uint8Array<ArrayBuffer>> {
    if (!Number.isSafeInteger(length) || length < 0) throw new TypeError("invalid proxy read length");
    const output = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      if (this.buffered === undefined) {
        const next = await this.stream.read(this.options);
        if (next === null) throw new Error("proxy stream ended unexpectedly");
        if (next.length === 0) continue;
        this.buffered = next;
      }
      const take = Math.min(length - offset, this.buffered.length);
      output.set(this.buffered.subarray(0, take), offset);
      offset += take;
      this.buffered = take === this.buffered.length ? undefined : this.buffered.subarray(take);
    }
    return output;
  }

  remainingStream(): ByteStream {
    if (this.buffered === undefined) return this.stream;
    let remaining: Uint8Array | undefined = this.buffered;
    this.buffered = undefined;
    const stream = this.stream;
    return {
      kind: stream.kind,
      get terminalError() { return stream.terminalError; },
      async read(options) {
        options?.signal?.throwIfAborted();
        if (stream.terminalError !== undefined) throw stream.terminalError;
        const chunk = remaining;
        remaining = undefined;
        return chunk ?? await stream.read(options);
      },
      write: (data, options) => stream.write(data, options),
      closeWrite: () => stream.closeWrite(),
      reset: () => { remaining = undefined; return stream.reset(); },
      close: () => { remaining = undefined; return stream.close(); },
    };
  }
}

export async function writeProxyWebSocketFrame(stream: ByteStream, opcode: number, payload: Uint8Array, maximum: number, options: OperationOptions = {}): Promise<void> {
  if (payload.length > maximum || payload.length > 0xffff_ffff) throw new Error("WebSocket frame exceeds the proxy limit");
  const chunkSize = 64 * 1024;
  const first = Math.min(payload.length, chunkSize - 5);
  const frame = new Uint8Array(5 + first);
  frame[0] = opcode;
  new DataView(frame.buffer).setUint32(1, payload.length, false);
  frame.set(payload.subarray(0, first), 5);
  await writeAll(stream, frame, options);
  for (let offset = first; offset < payload.length; offset += chunkSize) {
    await writeAll(stream, payload.subarray(offset, offset + chunkSize), options);
  }
}

export async function writeAll(
  stream: ByteStream,
  input: Uint8Array,
  options: OperationOptions = {},
): Promise<void> {
  let offset = 0;
  while (offset < input.length) {
    const written = await stream.write(input.subarray(offset), options);
    if (!Number.isSafeInteger(written) || written <= 0 || written > input.length - offset) {
      throw new Error("proxy stream write made no progress");
    }
    offset += written;
  }
}
