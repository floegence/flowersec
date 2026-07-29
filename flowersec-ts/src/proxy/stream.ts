import type { ByteStreamV2, OperationOptionsV2 } from "../v2/contract.js";

export class ProxyByteReader {
  private buffered: Uint8Array<ArrayBufferLike> = new Uint8Array();

  constructor(
    private readonly stream: ByteStreamV2,
    private readonly options: OperationOptionsV2 = {},
  ) {}

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
  stream: ByteStreamV2,
  input: Uint8Array,
  options: OperationOptionsV2 = {},
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
