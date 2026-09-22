// Independent test-only UAX #15 implementation over hash-pinned Unicode data.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export class V4Failure extends Error {
  constructor(readonly code: string) { super(code); }
}

export const root = new URL("../../../../", import.meta.url);
export const hash = (input: Uint8Array): string => createHash("sha256").update(input).digest("hex");

type Table = {
  unicode_version: string;
  ccc: [number, number][];
  decompositions: [number, number[]][];
  compositions: [number, number, number][];
  assigned: [number, number][];
  sources: Record<string, { sha256: string }>;
};

export class NFC {
  private readonly classes: Map<number, number>;
  private readonly decompositions: Map<number, number[]>;
  private readonly compositions: Map<number, number>;
  private readonly ranges: [number, number][];
  readonly conformanceSHA256: string;

  constructor(path: string, expectedHash: string) {
    if (path !== "testdata/unicode15_1/normalization_generated.json") throw new V4Failure("unicode_path");
    const raw = readFileSync(new URL(path, root));
    if (hash(raw) !== expectedHash) throw new V4Failure("unicode_hash");
    const table = JSON.parse(raw.toString("utf8")) as Table;
    if (table.unicode_version !== "15.1.0") throw new V4Failure("unicode_version");
    this.classes = new Map(table.ccc);
    this.decompositions = new Map(table.decompositions);
    // Scalar pairs fit exactly in 42 bits; no bitwise truncation is used.
    this.compositions = new Map(table.compositions.map(([a, b, cp]) => [a * 0x200000 + b, cp]));
    this.ranges = table.assigned;
    this.conformanceSHA256 = table.sources["NormalizationTest.txt"]!.sha256;
  }

  assigned(cp: number): boolean {
    let low = 0, high = this.ranges.length;
    while (low < high) {
      const mid = low + Math.floor((high - low) / 2);
      if (this.ranges[mid]![1] < cp) low = mid + 1;
      else high = mid;
    }
    return low < this.ranges.length && this.ranges[low]![0] <= cp;
  }

  private ccc(cp: number): number { return this.classes.get(cp) ?? 0; }

  private decompose(cp: number, output: number[]): void {
    if (cp >= 0xac00 && cp < 0xac00 + 11172) {
      const index = cp - 0xac00;
      output.push(0x1100 + Math.floor(index / 588), 0x1161 + Math.floor(index % 588 / 28));
      if (index % 28 !== 0) output.push(0x11a7 + index % 28);
    } else {
      const parts = this.decompositions.get(cp);
      if (parts) for (const part of parts) this.decompose(part, output);
      else output.push(cp);
    }
  }

  private compose(a: number, b: number): number | undefined {
    if (a >= 0x1100 && a < 0x1100 + 19 && b >= 0x1161 && b < 0x1161 + 21) return 0xac00 + ((a - 0x1100) * 21 + b - 0x1161) * 28;
    if (a >= 0xac00 && a < 0xac00 + 11172 && (a - 0xac00) % 28 === 0 && b > 0x11a7 && b < 0x11a7 + 28) return a + b - 0x11a7;
    return this.compositions.get(a * 0x200000 + b);
  }

  normalize(input: string): string {
    const scalars: number[] = [];
    for (const scalar of input) {
      const cp = scalar.codePointAt(0)!;
      if (cp >= 0xd800 && cp <= 0xdfff) throw new V4Failure("unicode_scalar");
      this.decompose(cp, scalars);
    }
    let start = 0;
    while (start < scalars.length) {
      if (this.ccc(scalars[start]!) === 0) { start += 1; continue; }
      let end = start + 1;
      while (end < scalars.length && this.ccc(scalars[end]!) !== 0) end += 1;
      const run = scalars.slice(start, end).map((cp, index) => ({ cp, index }));
      run.sort((a, b) => this.ccc(a.cp) - this.ccc(b.cp) || a.index - b.index);
      for (let at = 0; at < run.length; at++) scalars[start + at] = run[at]!.cp;
      start = end;
    }
    const output: number[] = [];
    let starter: number | undefined, previous = 0;
    for (const cp of scalars) {
      const current = this.ccc(cp);
      if (starter !== undefined && (previous === 0 || previous < current)) {
        const combined = this.compose(output[starter]!, cp);
        if (combined !== undefined) { output[starter] = combined; continue; }
      }
      if (current === 0) starter = output.length;
      output.push(cp); previous = current;
    }
    // Avoid an argument-count-dependent limit for long combining sequences.
    return output.map(cp => String.fromCodePoint(cp)).join("");
  }
}
