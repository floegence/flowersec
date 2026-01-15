export class ByteReader {
  private readonly chunks: Uint8Array[] = [];
  private headOff = 0;
  private buffered = 0;

  constructor(private readonly readChunk: () => Promise<Uint8Array | null>) {}

  async readExactly(n: number): Promise<Uint8Array> {
    if (n < 0) throw new Error("invalid length");
    while (this.buffered < n) {
      const chunk = await this.readChunk();
      if (chunk == null) throw new Error("eof");
      if (chunk.length === 0) continue;
      this.chunks.push(chunk);
      this.buffered += chunk.length;
    }
    const out = new Uint8Array(n);
    let outOff = 0;
    while (outOff < n) {
      const head = this.chunks[0]!;
      const avail = head.length - this.headOff;
      const need = n - outOff;
      const take = Math.min(avail, need);
      out.set(head.subarray(this.headOff, this.headOff + take), outOff);
      outOff += take;
      this.headOff += take;
      this.buffered -= take;
      if (this.headOff === head.length) {
        this.chunks.shift();
        this.headOff = 0;
      }
    }
    return out;
  }

  bufferedBytes(): number {
    return this.buffered;
  }
}

