// Independent Unicode 15.1 UTS46/IDNA2008 reference, without host mapping data.
import { readFileSync } from "node:fs";
import type { Reference } from "./cbor.js";
import { V4Failure, hash, root } from "./unicode.js";
import type { NFC } from "./unicode.js";

type Row = [number, number, string | number, number[]?];
type TableName = "mapping" | "classes" | "categories" | "bidi" | "ccc" | "joining" | "scripts";
type Table = Record<TableName, Row[]> & { unicode_version: string; uts46_revision: number; nfc_data_sha256: string; sources: Record<string, { sha256: string }> };
export const scalar = (cp: number): boolean => Number.isInteger(cp) && cp >= 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff);
export function points(input: string): number[] {
  return Array.from(input, char => { const cp = char.codePointAt(0)!; if (!scalar(cp)) throw new V4Failure("unicode_scalar"); return cp; });
}
export const scalarText = (input: readonly number[]): string => input.map(cp => String.fromCodePoint(cp)).join("");

export class IDNA {
  readonly nfc: NFC;
  readonly conformanceSHA256: string;
  private readonly tables: Map<TableName, Row[]>;

  constructor(syntax: Reference) {
    const unicode = syntax.registry.unicode, source = unicode.idna_data;
    if (source.path !== "testdata/unicode15_1/idna_generated.json") throw new V4Failure("idna_path");
    const raw = readFileSync(new URL(source.path, root));
    if (hash(raw) !== source.sha256) throw new V4Failure("idna_hash");
    const data = JSON.parse(raw.toString("utf8")) as Table;
    if (data.unicode_version !== "15.1.0" || data.uts46_revision !== 31 || data.nfc_data_sha256 !== unicode.nfc_data.sha256) throw new V4Failure("idna_version");
    this.nfc = syntax.nfc; this.tables = new Map();
    for (const name of ["mapping", "classes", "categories", "bidi", "ccc", "joining", "scripts"] as const) {
      const rows = data[name];
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i]!;
        if (row.length < 3 || row.length > 4 || row[0] > row[1] || i > 0 && rows[i - 1]![1] >= row[0]) throw new V4Failure("idna_table");
      }
      this.tables.set(name, rows);
    }
    this.conformanceSHA256 = data.sources["IdnaTestV2.txt"]!.sha256;
  }

  private lookup(name: TableName, cp: number): Row | undefined {
    const rows = this.tables.get(name)!;
    let low = 0, high = rows.length;
    while (low < high) { const mid = low + Math.floor((high - low) / 2); if (rows[mid]![1] < cp) low = mid + 1; else high = mid; }
    return low < rows.length && rows[low]![0] <= cp ? rows[low] : undefined;
  }
  private prop(name: TableName, cp: number): string { return String(this.lookup(name, cp)?.[2] ?? ""); }

  private contextJ(label: number[], index: number): boolean {
    if (index > 0 && this.prop("ccc", label[index - 1]!) === "9") return true;
    if (label[index] === 0x200d) return false;
    let left = index - 1, right = index + 1;
    while (left >= 0 && this.prop("joining", label[left]!) === "T") left -= 1;
    while (right < label.length && this.prop("joining", label[right]!) === "T") right += 1;
    return left >= 0 && right < label.length && ["L", "D"].includes(this.prop("joining", label[left]!)) && ["R", "D"].includes(this.prop("joining", label[right]!));
  }

  private contextO(label: number[], index: number): boolean {
    const cp = label[index]!;
    if (cp === 0xb7) return index > 0 && index + 1 < label.length && label[index - 1] === 0x6c && label[index + 1] === 0x6c;
    if (cp === 0x375) return index + 1 < label.length && this.prop("scripts", label[index + 1]!) === "Greek";
    if (cp === 0x5f3 || cp === 0x5f4) return index > 0 && this.prop("scripts", label[index - 1]!) === "Hebrew";
    if (cp === 0x30fb) return label.some(cp => ["Hiragana", "Katakana", "Han"].includes(this.prop("scripts", cp)));
    if (cp >= 0x660 && cp <= 0x669) return !label.some(cp => cp >= 0x6f0 && cp <= 0x6f9);
    if (cp >= 0x6f0 && cp <= 0x6f9) return !label.some(cp => cp >= 0x660 && cp <= 0x669);
    return false;
  }

  private bidi(label: number[]): void {
    if (!label.length) throw new V4Failure("idna_empty_label");
    const first = this.prop("bidi", label[0]!), rtl = ["R", "AL"].includes(first);
    if (!rtl && first !== "L") throw new V4Failure("idna_bidi_start");
    let last = "", arabic = false, european = false;
    for (const cp of label) {
      const direction = this.prop("bidi", cp), common = ["EN", "ES", "CS", "ET", "ON", "BN", "NSM"].includes(direction);
      if (!common && !(rtl ? ["R", "AL", "AN"].includes(direction) : direction === "L")) throw new V4Failure("idna_bidi_character");
      if (direction !== "NSM") last = direction;
      arabic ||= direction === "AN"; european ||= direction === "EN";
    }
    if (!(rtl ? ["R", "AL", "EN", "AN"] : ["L", "EN"]).includes(last)) throw new V4Failure("idna_bidi_end");
    if (rtl && arabic && european) throw new V4Failure("idna_bidi_digits");
  }

  private validUTSLabel(label: number[]): void {
    if (!label.length) throw new V4Failure("idna_empty_label");
    const text = scalarText(label);
    if (this.nfc.normalize(text) !== text) throw new V4Failure("idna_nfc");
    if (label[0] === 45 || label.at(-1) === 45 || label.length >= 4 && label[2] === 45 && label[3] === 45) throw new V4Failure("idna_hyphen");
    if (this.prop("categories", label[0]!).startsWith("M")) throw new V4Failure("idna_initial_mark");
    for (let i = 0; i < label.length; i++) {
      const cp = label[i]!;
      if (!["valid", "deviation"].includes(this.prop("mapping", cp))) throw new V4Failure("idna_validity");
      if ([0x200c, 0x200d].includes(cp) && !this.contextJ(label, i)) throw new V4Failure("idna_contextj");
    }
  }

  process(input: string): { ascii: string; labels: number[][]; trailing: boolean } {
    const mapped: number[] = [];
    for (const cp of points(input)) {
      const row = this.lookup("mapping", cp);
      if (!row) { mapped.push(cp); continue; }
      switch (row[2]) {
        case "mapped": for (const child of row[3]!) mapped.push(child); break;
        case "ignored": break;
        case "valid": case "deviation": case "disallowed": case "disallowed_STD3_valid": case "disallowed_STD3_mapped": mapped.push(cp); break;
        default: throw new V4Failure("idna_mapping");
      }
    }
    // UTS46 revision 31 checks validity after NFC composition.
    const names = this.nfc.normalize(scalarText(mapped)).split("."), trailing = names.at(-1) === "";
    if (trailing) names.pop();
    if (!names.length) throw new V4Failure("idna_empty_domain");
    const labels: number[][] = []; let bidiDomain = false;
    for (const name of names) {
      let label: number[];
      if (name.startsWith("xn--")) {
        if (new TextEncoder().encode(name).length > 63) throw new V4Failure("idna_label_length");
        const payload = name.slice(4); label = punyDecode(payload);
        if (!label.some(cp => cp >= 128)) throw new V4Failure("idna_fake_alabel");
        if (punyEncode(label) !== payload) throw new V4Failure("idna_alabel_roundtrip");
      } else label = points(name);
      this.validUTSLabel(label);
      bidiDomain ||= label.some(cp => ["R", "AL", "AN"].includes(this.prop("bidi", cp)));
      labels.push(label);
    }
    const ascii = labels.map(label => {
      if (bidiDomain) this.bidi(label);
      const text = label.some(cp => cp >= 128) ? "xn--" + punyEncode(label) : scalarText(label);
      if (!text.length || text.length > 63) throw new V4Failure("idna_label_length"); return text;
    }).join(".");
    if (ascii.length > 253) throw new V4Failure("idna_domain_length");
    return { ascii: ascii + (trailing ? "." : ""), labels, trailing };
  }

  issuerDNS(input: string): string {
    if (!points(input).every(cp => this.nfc.assigned(cp))) throw new V4Failure("idna_unassigned");
    const result = this.process(input);
    if (result.trailing) throw new V4Failure("idna_trailing_dot");
    for (const label of result.labels) for (let i = 0; i < label.length; i++) {
      const cp = label[i]!, kind = this.prop("classes", cp);
      if (!this.nfc.assigned(cp)) throw new V4Failure("idna_unassigned");
      if (!(kind === "PVALID" || kind === "CONTEXTJ" && this.contextJ(label, i) || kind === "CONTEXTO" && this.contextO(label, i))) throw new V4Failure("idna2008_validity");
    }
    return result.ascii;
  }

  wireDNS(input: string): void {
    if (!input.length || /[^\x00-\x7f]/u.test(input)) throw new V4Failure("idna_wire_ascii");
    if (this.issuerDNS(input) !== input) throw new V4Failure("idna_wire_noncanonical");
  }
}

const maximum = 0x7fffffff;
const threshold = (k: number, bias: number): number => Math.min(26, Math.max(1, k - bias));
function adapt(original: number, count: number, first: boolean): number {
  let delta = Math.floor(original / (first ? 700 : 2)), k = 0;
  delta += Math.floor(delta / count);
  while (delta > 455) { delta = Math.floor(delta / 35); k += 36; }
  return k + Math.floor(36 * delta / (delta + 38));
}
const digit = (n: number): string => String.fromCharCode(n < 26 ? n + 97 : n - 26 + 48);

export function punyEncode(input: number[]): string {
  if (!input.every(scalar)) throw new V4Failure("punycode_scalar");
  const out = input.filter(cp => cp < 128).map(cp => String.fromCharCode(cp)), basic = out.length;
  let handled = basic, n = 128, delta = 0, bias = 72;
  if (basic) out.push("-");
  while (handled < input.length) {
    let next = Infinity;
    for (const cp of input) if (cp >= n && cp < next) next = cp;
    if (next - n > Math.floor((maximum - delta) / (handled + 1))) throw new V4Failure("punycode_overflow");
    delta += (next - n) * (handled + 1); n = next;
    for (const cp of input) {
      if (cp < n) { if (delta >= maximum) throw new V4Failure("punycode_overflow"); delta += 1; }
      if (cp !== n) continue;
      let q = delta;
      for (let k = 36; ; k += 36) {
        const t = threshold(k, bias); if (q < t) break;
        out.push(digit(t + (q - t) % (36 - t))); q = Math.floor((q - t) / (36 - t));
      }
      out.push(digit(q)); bias = adapt(delta, handled + 1, handled === basic); delta = 0; handled += 1;
    }
    if (delta >= maximum) throw new V4Failure("punycode_overflow"); delta += 1; n += 1;
  }
  return out.join("");
}

export function punyDecode(input: string): number[] {
  if (/[^\x00-\x7f]/u.test(input)) throw new V4Failure("punycode_ascii");
  const dash = input.lastIndexOf("-");
  const out = dash > 0 ? points(input.slice(0, dash)) : [];
  let index = dash > 0 ? dash + 1 : 0, n = 128, i = 0, bias = 72;
  while (index < input.length) {
    const old = i; let weight = 1;
    for (let k = 36; ; k += 36) {
      if (index >= input.length) throw new V4Failure("punycode_truncated");
      const cp = input.charCodeAt(index++);
      const d = cp >= 97 && cp <= 122 ? cp - 97 : cp >= 65 && cp <= 90 ? cp - 65 : cp >= 48 && cp <= 57 ? cp - 48 + 26 : -1;
      if (d < 0) throw new V4Failure("punycode_digit");
      if (d > Math.floor((maximum - i) / weight)) throw new V4Failure("punycode_overflow");
      i += d * weight;
      const t = threshold(k, bias); if (d < t) break;
      if (weight > Math.floor(maximum / (36 - t))) throw new V4Failure("punycode_overflow");
      weight *= 36 - t;
    }
    const count = out.length + 1;
    bias = adapt(i - old, count, old === 0);
    if (Math.floor(i / count) > maximum - n) throw new V4Failure("punycode_overflow");
    n += Math.floor(i / count); i %= count;
    if (!scalar(n)) throw new V4Failure("punycode_scalar");
    out.splice(i, 0, n); i += 1;
  }
  return out;
}
