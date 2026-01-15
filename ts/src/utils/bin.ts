export function u16be(n: number): Uint8Array {
  const b = new Uint8Array(2);
  const v = n >>> 0;
  b[0] = (v >>> 8) & 0xff;
  b[1] = v & 0xff;
  return b;
}

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  const v = n >>> 0;
  b[0] = (v >>> 24) & 0xff;
  b[1] = (v >>> 16) & 0xff;
  b[2] = (v >>> 8) & 0xff;
  b[3] = v & 0xff;
  return b;
}

export function u64be(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  let v = n;
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

export function readU32be(buf: Uint8Array, off: number): number {
  return (
    (buf[off]! << 24) |
    (buf[off + 1]! << 16) |
    (buf[off + 2]! << 8) |
    buf[off + 3]!
  ) >>> 0;
}

export function readU64be(buf: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(buf[off + i]!);
  return v;
}

export function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

