import { byteLength, byteSlice, CBORWireError } from "./cbor.js";

const copy = Uint8Array.prototype.set;
function capacity(): never { throw new CBORWireError("configuration_capacity"); }
export function canonicalHeadBytes(value: bigint): number {
  if (value < 0n || value > (1n << 64n) - 1n) capacity();
  return value < 24n ? 1 : value <= 255n ? 2 : value <= 65535n ? 3 : value <= 0xffffffffn ? 5 : 9;
}

/** Fixed caller-owned canonical encoder. It creates no per-field byte arrays. */
export class FixedCBORWriter {
  #at = 0;
  constructor(readonly bytes: Uint8Array) {}
  reset(): this { this.#at = 0; return this; }
  #head(major: number, value: bigint): this {
    const count = canonicalHeadBytes(value) - 1;
    if (this.#at + 1 + count > byteLength(this.bytes)) capacity();
    this.bytes[this.#at++] = major * 32 + (count === 0 ? Number(value) : count === 1 ? 24 : count === 2 ? 25 : count === 4 ? 26 : 27);
    for (let i = count - 1; i >= 0; i--) { this.bytes[this.#at + i] = Number(value & 255n); value >>= 8n; }
    this.#at += count; return this;
  }
  map(fields: number): this { return this.#head(5, BigInt(fields)); }
  array(items: number): this { return this.#head(4, BigInt(items)); }
  /** Private incremental encoders append exactly this many owned bytes before
   * writing another field; the header alone is not a complete CBOR value. */
  bytesHeader(length: number): this { return this.#head(2, BigInt(length)); }
  uint(value: number | bigint): this { return this.#head(0, BigInt(value)); }
  bool(value: boolean): this {
    if (this.#at === byteLength(this.bytes)) capacity();
    this.bytes[this.#at++] = value ? 245 : 244; return this;
  }
  data(value: Uint8Array, text = false): this {
    const n = byteLength(value); this.#head(text ? 3 : 2, BigInt(n));
    if (n > byteLength(this.bytes) - this.#at) capacity();
    copy.call(this.bytes, value, this.#at); this.#at += n; return this;
  }
  encoded(value: Uint8Array): this {
    const n = byteLength(value); if (n > byteLength(this.bytes) - this.#at) capacity();
    copy.call(this.bytes, value, this.#at); this.#at += n; return this;
  }
  result(): Uint8Array { return byteSlice(this.bytes, 0, this.#at); }
}
