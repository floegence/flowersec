import { StreamEOFError } from "./errors.js";

// ByteReader buffers incoming chunks and supports exact reads.
export class ByteReader {
  private readonly chunks: Uint8Array[] = [];
  private chunkHead = 0;
  private headOff = 0;
  private buffered = 0;

  constructor(private readonly readChunk: () => Promise<Uint8Array | null>) {}

  // readExactly reads n bytes or throws on EOF.
  async readExactly(n: number): Promise<Uint8Array> {
    if (n < 0) throw new Error("invalid length");
    while (this.buffered < n) {
      const chunk = await this.readChunk();
      if (chunk == null) throw new StreamEOFError();
      if (chunk.length === 0) continue;
      this.chunks.push(chunk);
      this.buffered += chunk.length;
    }
    const out = new Uint8Array(n);
    this.consumeAvailable(n, out);
    return out;
  }

  // discardExactly consumes bytes without allocating a contiguous output buffer.
  async discardExactly(n: number): Promise<void> {
    if (n < 0) throw new Error("invalid length");
    let remaining = n;
    while (remaining > 0) {
      if (this.buffered === 0) {
        const chunk = await this.readChunk();
        if (chunk == null) throw new StreamEOFError();
        if (chunk.length === 0) continue;
        this.chunks.push(chunk);
        this.buffered += chunk.length;
      }
      remaining -= this.consumeAvailable(remaining);
    }
  }

  // bufferedBytes returns the number of bytes currently buffered.
  bufferedBytes(): number {
    return this.buffered;
  }

  private consumeAvailable(maxBytes: number, output?: Uint8Array): number {
    let consumed = 0;
    while (consumed < maxBytes && this.buffered > 0) {
      const head = this.chunks[this.chunkHead]!;
      const take = Math.min(maxBytes - consumed, head.length - this.headOff);
      if (output != null) output.set(head.subarray(this.headOff, this.headOff + take), consumed);
      this.headOff += take;
      this.buffered -= take;
      consumed += take;
      if (this.headOff === head.length) {
        this.chunkHead++;
        this.headOff = 0;
      }
    }
    this.compactConsumedChunks();
    return consumed;
  }

  private compactConsumedChunks(): void {
    if (this.buffered === 0) {
      this.chunks.length = 0;
      this.chunkHead = 0;
      this.headOff = 0;
      return;
    }
    if (this.chunkHead > 1024 && this.chunkHead * 2 > this.chunks.length) {
      this.chunks.splice(0, this.chunkHead);
      this.chunkHead = 0;
    }
  }
}
