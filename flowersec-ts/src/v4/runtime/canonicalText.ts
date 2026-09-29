import { assignedScalar, canonicalParts, combiningClass, composePair, maxCanonicalDecomposition } from "../../generated/normalization151.js";

export type CanonicalTextFailure = "invalid_utf8" | "unassigned_code_point" | "non_canonical_text" | "text_capacity";

// The low two bits hold width - 1. No host text conversion, Unicode version or
// replacement decoding influences the signed input. Negative means malformed.
function scalar(input: Uint8Array, at: number, end: number): number {
  if (at >= end) return -1;
  const first = input[at]!;
  if (first < 0x80) return first * 4;
  let n: number, cp: number;
  if (first >= 0xc2 && first <= 0xdf) { n = 2; cp = first & 31; }
  else if (first >= 0xe0 && first <= 0xef) { n = 3; cp = first & 15; }
  else if (first >= 0xf0 && first <= 0xf4) { n = 4; cp = first & 7; }
  else return -1;
  if (end - at < n) return -1;
  for (let i = 1; i < n; i++) { const b = input[at + i]!; if (b < 0x80 || b > 0xbf) return -1; cp = cp * 64 + (b & 63); }
  if (n === 3 && cp < 0x800 || n === 4 && cp < 0x10000 || cp > 0x10ffff || cp >= 0xd800 && cp <= 0xdfff) return -1;
  return cp * 4 + n - 1;
}

export function canonicalTextBackingBytes(cap: number): number {
  if (!Number.isSafeInteger(cap) || cap < 0 || cap > Math.floor(0xffffffff / maxCanonicalDecomposition)) throw new RangeError("text_capacity");
  return cap * maxCanonicalDecomposition * 8 + 256 * 4;
}

// The containing decoder prepays these exact arrays and their runtime overhead.
// They never grow. Counting sort is stable and linear even for a long adversarial
// combining run. Signed text is checked against NFC, never silently repaired.
export class CanonicalTextWorkspace {
  readonly #cap: number;
  readonly #work: Uint32Array;
  readonly #scratch: Uint32Array;
  readonly #positions = new Uint32Array(256);
  constructor(cap: number) {
    canonicalTextBackingBytes(cap);
    this.#cap = cap;
    this.#work = new Uint32Array(cap * maxCanonicalDecomposition);
    this.#scratch = new Uint32Array(cap * maxCanonicalDecomposition);
    Object.freeze(this);
  }
  check(input: Uint8Array, start = 0, end = input.length): CanonicalTextFailure | undefined {
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > input.length || end - start > this.#cap) return "text_capacity";
    const work = this.#work, scratch = this.#scratch, positions = this.#positions;
    let n = 0, scratchUsed = 0;
    try {
      for (let at = start; at < end;) {
        const packed = scalar(input, at, end);
        if (packed < 0) return "invalid_utf8";
        const cp = Math.floor(packed / 4); at += packed % 4 + 1;
        if (!assignedScalar(cp)) return "unassigned_code_point";
        if (cp >= 0xac00 && cp < 0xac00 + 11172) {
          const index = cp - 0xac00;
          work[n++] = 0x1100 + Math.floor(index / 588);
          work[n++] = 0x1161 + Math.floor(index % 588 / 28);
          if (index % 28 !== 0) work[n++] = 0x11a7 + index % 28;
        } else n += canonicalParts(cp, work, n);
      }
      for (let from = 0; from < n;) {
        if (combiningClass(work[from]!) === 0) { from++; continue; }
        let to = from + 1;
        while (to < n && combiningClass(work[to]!) !== 0) to++;
        positions.fill(0);
        scratchUsed = Math.max(scratchUsed, to - from);
        for (let i = from; i < to; i++) { const c = combiningClass(work[i]!); positions[c] = positions[c]! + 1; }
        let total = 0;
        for (let c = 0; c < 256; c++) { const count = positions[c]!; positions[c] = total; total += count; }
        for (let i = from; i < to; i++) { const cp = work[i]!, c = combiningClass(cp); scratch[positions[c]!] = cp; positions[c] = positions[c]! + 1; }
        work.set(scratch.subarray(0, to - from), from);
        from = to;
      }
      let output = 0, starter = -1, lastClass = 0;
      for (let i = 0; i < n; i++) {
        const cp = work[i]!, c = combiningClass(cp);
        if (starter >= 0 && (lastClass === 0 || lastClass < c)) {
          const composed = composePair(work[starter]!, cp);
          if (composed >= 0) { work[starter] = composed; continue; }
        }
        if (c === 0) starter = output;
        work[output++] = cp; lastClass = c;
      }
      let at = start;
      for (let i = 0; i < output; i++) {
        const packed = scalar(input, at, end);
        if (packed < 0 || Math.floor(packed / 4) !== work[i]) return "non_canonical_text";
        at += packed % 4 + 1;
      }
      return at === end ? undefined : "non_canonical_text";
    } finally { work.fill(0, 0, n); scratch.fill(0, 0, scratchUsed); positions.fill(0); }
  }
  clear(): void { this.#work.fill(0); this.#scratch.fill(0); this.#positions.fill(0); }
}
Object.freeze(CanonicalTextWorkspace.prototype); Object.freeze(CanonicalTextWorkspace);
