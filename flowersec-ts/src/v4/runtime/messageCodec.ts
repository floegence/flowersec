import { byteLength, byteSlice } from "./cbor.js";
import type { ResourceReference, ResourceVector } from "./resources.js";
import { ResourceVector as Vector } from "./resources.js";

const typed = Object.getPrototypeOf(Uint8Array.prototype) as object;
const buffer = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength")!.get!;
const resizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get;
const detached = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "detached")?.get;
const copy = Uint8Array.prototype.set;
const codeUnit = String.prototype.charCodeAt;
export function messageInputBytes(value: unknown, implementation: "bytes" | "utf8" | "application", maximum: number): number {
  if (implementation === "application") {
    if (typeof value === "string") return value.length * 2;
    // Intrinsic access never probes arbitrary input properties or getters.
    try { return bufferLength.call(buffer.call(value)) as number; } catch { return 0; }
  }
  if (implementation === "utf8") {
    if (typeof value !== "string" || value.length > maximum) throw new Error("encode_failed");
    return value.length * 2;
  }
  const bytes = value as Uint8Array, n = byteLength(bytes), backing = buffer.call(bytes) as ArrayBuffer;
  if (n > maximum || resizable?.call(backing) || detached?.call(backing)) throw new Error("encode_failed");
  byteSlice(bytes, 0, n); return bufferLength.call(backing) as number;
}
interface Segment { bytes: Uint8Array; used: number; reference: ResourceReference }
/** Private fallible writer: all capacity and descriptor ownership precedes
 * allocation; a failed append is sticky through finalization. */
export class MessageSegments {
  readonly #segments: Segment[] = [];
  #capacity = 0;
  #length = 0;
  #writeIndex = 0;
  #failed = false;
  #sealed = false;
  constructor(private readonly maximum: number, private readonly runtimeBytes: bigint,
    private readonly reserve: (charge: ResourceVector, capacity: number) => ResourceReference, private readonly guard: () => void) {}
  get length(): number { return this.#length; }
  get capacity(): number { return this.#capacity; }
  #space(count: number): void {
    if (this.#failed || this.#sealed) throw new Error("encode_failed");
    try {
      if (!Number.isSafeInteger(count) || count < 0 || count > this.maximum - this.#length) throw new Error("encode_failed");
      if (this.#capacity - this.#length >= count) return;
      this.guard();
      // Every append is all-or-nothing. Charge all new blocks in one vector.
      const capacities: number[] = []; let capacity = this.#capacity;
      while (capacity - this.#length < count) {
        const next = Math.min(capacity === 0 ? 256 : 16384, this.maximum - capacity);
        if (next === 0) throw new Error("encode_failed"); capacities.push(next); capacity += next;
      }
      const reference = this.reserve(new Vector([BigInt(capacity - this.#capacity) + BigInt(capacities.length) * (this.runtimeBytes + 64n), 0n, 0n, BigInt(capacities.length), 0n, 0n, 0n, 0n, 0n, 0n, 0n]), capacity - this.#capacity);
      const added: Segment[] = [];
      try {
        for (const n of capacities) added.push({ bytes: new Uint8Array(n), used: 0, reference: reference.borrow() });
        this.#segments.push(...added); this.#capacity = capacity;
      } catch (error) { for (const block of added) { block.bytes.fill(0); block.reference.release(); } throw error; }
      finally { reference.release(); }
    } catch (error) { this.#failed = true; throw error; }
  }
  append(bytes: Uint8Array): void {
    const count = byteLength(bytes); this.#space(count); let at = 0;
    for (; this.#writeIndex < this.#segments.length; this.#writeIndex++) {
      const block = this.#segments[this.#writeIndex]!;
      const n = Math.min(count - at, block.bytes.length - block.used);
      if (n > 0) { copy.call(block.bytes, byteSlice(bytes, at, at + n), block.used); block.used += n; at += n; }
      if (at === count) break;
    }
    this.#length += count;
  }
  utf8(value: string): void {
    // No toString, getters, JSON hooks or intermediate encoded string/array.
    // The four-byte scratch belongs to the send entry's initial reservation.
    const scratch = new Uint8Array(4);
    try {
      for (let i = 0; i < value.length; i++) {
        let cp = codeUnit.call(value, i);
        if (cp >= 0xd800 && cp <= 0xdbff) {
          const low = codeUnit.call(value, ++i); if (low < 0xdc00 || low > 0xdfff || !Number.isFinite(low)) throw new Error("encode_failed");
          cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) throw new Error("encode_failed");
        let n: number;
        if (cp < 0x80) { n = 1; scratch[0] = cp; }
        else if (cp < 0x800) { n = 2; scratch[0] = 0xc0 | cp >> 6; scratch[1] = 0x80 | cp & 63; }
        else if (cp < 0x10000) { n = 3; scratch[0] = 0xe0 | cp >> 12; scratch[1] = 0x80 | cp >> 6 & 63; scratch[2] = 0x80 | cp & 63; }
        else { n = 4; scratch[0] = 0xf0 | cp >> 18; scratch[1] = 0x80 | cp >> 12 & 63; scratch[2] = 0x80 | cp >> 6 & 63; scratch[3] = 0x80 | cp & 63; }
        this.append(byteSlice(scratch, 0, n));
      }
    } catch (error) { this.#failed = true; throw error; }
    finally { scratch.fill(0); }
  }
  finalize(): readonly Uint8Array[] {
    if (this.#failed || this.#sealed) throw new Error("encode_failed");
    try { this.guard(); this.#sealed = true; return this.#segments.map(block => byteSlice(block.bytes, 0, block.used)); }
    catch (error) { this.#failed = true; throw error; }
  }
  close(): void {
    this.#sealed = true;
    for (const block of this.#segments) { block.bytes.fill(0); block.reference.release(); }
    this.#segments.length = 0; this.#capacity = 0;
  }
}

/** Validate the actual encoder view and its entire backing before copying. */
export function checkApplicationMessageOutput(value: unknown, maximum: number): Uint8Array {
  const bytes = value as Uint8Array, length = byteLength(bytes), backing = buffer.call(bytes) as ArrayBuffer;
  if (length > maximum || (bufferLength.call(backing) as number) > maximum || resizable?.call(backing) || detached?.call(backing)) throw new Error("encode_failed");
  return byteSlice(bytes, 0, length);
}
