import type { OperationOptions } from "../public/contract.js";

/** Private application I/O shared by the proxy framing and its local bridge. */
export interface ProxyStream {
  readonly signal?: AbortSignal;
  read(options?: OperationOptions): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptions): Promise<number>;
  closeWrite(options?: OperationOptions): Promise<void>;
  finish?(options?: OperationOptions): Promise<void>;
  reset(): Promise<void>;
  close(): Promise<void>;
  dispose?(onCleanup?: () => void): void;
}

export class ProxyByteReader {
  private buffered: Uint8Array<ArrayBufferLike> = new Uint8Array();

  constructor(
    private readonly stream: ProxyStream,
    private readonly options: OperationOptions = {},
  ) {}

  get bufferedBytes(): number { return this.buffered.length; }

  takeBuffered(): Uint8Array {
    const bytes = this.buffered;
    this.buffered = new Uint8Array();
    return bytes;
  }

  async readExactly(length: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(length) || length < 0) throw new TypeError("invalid proxy read length");
    const output = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      if (this.buffered.length === 0) {
        const next = await this.stream.read(this.options);
        if (next === null) throw new Error("proxy stream ended unexpectedly");
        if (next.length === 0) continue;
        this.buffered = next;
      }
      const take = Math.min(length - offset, this.buffered.length);
      output.set(this.buffered.subarray(0, take), offset);
      offset += take;
      this.buffered = this.buffered.subarray(take);
    }
    return output;
  }
}

export async function writeAll(
  stream: ProxyStream,
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
