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
    let outOff = 0;
    while (outOff < n) {
      const head = this.chunks[this.chunkHead]!;
      const avail = head.length - this.headOff;
      const need = n - outOff;
      const take = Math.min(avail, need);
      out.set(head.subarray(this.headOff, this.headOff + take), outOff);
      outOff += take;
      this.headOff += take;
      this.buffered -= take;
      if (this.headOff === head.length) {
        this.chunkHead++;
        this.headOff = 0;
        if (this.chunkHead > 1024 && this.chunkHead * 2 > this.chunks.length) {
          this.chunks.splice(0, this.chunkHead);
          this.chunkHead = 0;
        }
      }
    }
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
      const head = this.chunks[this.chunkHead]!;
      const take = Math.min(remaining, head.length - this.headOff);
      this.headOff += take;
      this.buffered -= take;
      remaining -= take;
      if (this.headOff === head.length) {
        this.chunkHead++;
        this.headOff = 0;
      }
    }
  }

  // bufferedBytes returns the number of bytes currently buffered.
  bufferedBytes(): number {
    return this.buffered;
  }
}
