import { canonicalHeadBytes, FixedCBORWriter } from "./cborWriter.js";
import { envelopePrefixBytes, maxStreamScope, ownProfile, recordHeaderBytes, wire } from "./wireRegistry.js";

export function encodeStreamData(writer: FixedCBORWriter, scope: bigint, direction: 0 | 1, epoch: number, sequence: bigint,
  offset: bigint, fin: boolean, data: Uint8Array): Uint8Array {
  return writer.map(7).uint(0).uint(scope).uint(1).uint(direction).uint(2).uint(epoch).uint(3).uint(sequence)
    .uint(4).uint(offset).uint(5).bool(fin).uint(6).data(data).result();
}

/** Bounds use the actual DATA encoder and canonical byte-string head widths.
 * They inspect no unauthenticated inner offsets, data lengths or stream IDs. */
export class StreamDataBounds {
  readonly #minimum: number;
  readonly #maximum: number;
  readonly #limit: number;
  constructor(scope: bigint, direction: 0 | 1, profile: string, maxFrame: number) {
    const p = ownProfile(profile);
    if (p === undefined || scope < 1n || scope > maxStreamScope || !Number.isSafeInteger(maxFrame) || maxFrame < 1 || maxFrame > wire.resource_caps.max_payload_length) throw new Error("configuration_capacity");
    const scratch = new Uint8Array(64), writer = new FixedCBORWriter(scratch), empty = new Uint8Array();
    const fixed = envelopePrefixBytes + recordHeaderBytes + p.tag_bytes;
    try {
      this.#minimum = fixed + encodeStreamData(writer, scope, direction, 0, 0n, 0n, false, empty).length - 1;
      this.#maximum = fixed + encodeStreamData(writer.reset(), scope, direction, 0xffffffff, (1n << 64n) - 2n, (1n << 64n) - 1n, true, empty).length - 1;
    } finally { scratch.fill(0); }
    this.#limit = envelopePrefixBytes + maxFrame;
    if (this.#minimum + 1 > this.#limit) throw new Error("configuration_capacity");
  }
  maximumEnvelope(promise: bigint): number {
    if (promise < 0n || promise > (1n << 64n) - 1n) throw new Error("protocol_violation");
    const bytes = promise > BigInt(this.#limit) ? this.#limit : Number(promise);
    return Math.min(this.#limit, this.#maximum + canonicalHeadBytes(BigInt(bytes)) + bytes);
  }
  overhead(): number { return this.#maximum + canonicalHeadBytes(BigInt(this.#limit)); }
  payloadUpper(length: number): bigint {
    if (!Number.isSafeInteger(length) || length < this.#minimum + 1 || length > this.#limit) throw new Error("protocol_violation");
    let low = 0, high = length - this.#minimum;
    while (low < high) {
      const mid = low + Math.ceil((high - low) / 2);
      if (this.#minimum + canonicalHeadBytes(BigInt(mid)) + mid <= length) low = mid; else high = mid - 1;
    }
    return BigInt(low);
  }
}
