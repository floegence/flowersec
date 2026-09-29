import { idnaProperty as prop } from "../../generated/idna151.js";
import { CanonicalTextWorkspace, canonicalTextBackingBytes } from "./canonicalText.js";

export type HostFailure = "host_text" | "host_syntax" | "host_wire_ascii" | "host_noncanonical" | "host_ipv4" | "host_ipv6" |
  "host_numeric_final_label" | "host_loopback" | "idna_domain_length" | "idna_label_length" | "idna_wire_noncanonical" |
  "idna_alabel_roundtrip" | "idna_fake_alabel" | "idna_nfc" | "idna_hyphen" | "idna_initial_mark" | "idna_validity" |
  "idna_contextj" | "idna_contexto" | "idna2008_validity" | "idna_bidi" | "punycode_overflow" | "punycode_truncated" |
  "punycode_scalar" | "punycode_digit" | "origin_ascii" | "origin_syntax" | "origin_scheme_unregistered" | "origin_port" | "origin_default_port";
export class HostValidationError extends Error {
  readonly code: HostFailure;
  constructor(code: HostFailure) { super(code); this.name = "HostValidationError"; this.code = code; }
}
function reject(code: HostFailure): never { throw new HostValidationError(code); }
function requireThat(condition: boolean, code: HostFailure): void { if (!condition) reject(code); }
function safe(n: number): number { if (!Number.isSafeInteger(n) || n < 0 || n > 0x7fffffff) reject("punycode_overflow"); return n; }
function threshold(k: number, bias: number): number { return Math.min(26, Math.max(1, k - bias)); }
function adapt(delta: number, count: number, first: boolean): number {
  delta = Math.floor(delta / (first ? 700 : 2)); delta += Math.floor(delta / count);
  let k = 0;
  while (delta > 455) { delta = Math.floor(delta / 35); k += 36; }
  return k + Math.floor(36 * delta / (delta + 38));
}
function digit(cp: number): number { return cp >= 97 && cp <= 122 ? cp - 97 : cp >= 48 && cp <= 57 ? cp - 22 : -1; }
function asciiDigit(n: number): number { return n < 26 ? n + 97 : n + 22; }

export const hostWorkspaceBackingBytes = 253 * 4 + 256 * 2 + 252 + 63 + canonicalTextBackingBytes(252);

// One synchronous schema decoder owns this fixed workspace. Punycode only
// performs arithmetic; all Unicode validity, NFC, joining and Bidi decisions
// use the pinned 15.1 tables. No URL parser, host IDNA, or UTS mapping rewrites
// signed input. Address families, including mapped IPv6, remain distinct.
export class WireHostWorkspace {
  readonly #points = new Uint32Array(253);
  readonly #bounds = new Uint16Array(256);
  readonly #utf8 = new Uint8Array(252);
  readonly #encoded = new Uint8Array(63);
  readonly #nfc = new CanonicalTextWorkspace(252);

  host(text: string): void {
    requireThat(typeof text === "string" && text.length > 0 && text.length <= 253, "host_text");
    for (let i = 0; i < text.length; i++) requireThat(text.charCodeAt(i) >= 0x21 && text.charCodeAt(i) <= 0x7e, "host_wire_ascii");
    requireThat(!/[\[\]%\\/?#@]/u.test(text), "host_syntax");
    if (text.includes(":")) { this.#ipv6(text); return; }
    if (/^[0-9.]+$/u.test(text)) { this.#ipv4(text); return; }
    try {
      this.#dns(text);
      const last = text.slice(text.lastIndexOf(".") + 1);
      requireThat(!/^(?:[0-9]+|0x[0-9a-f]*)$/u.test(last), "host_numeric_final_label");
    } finally { this.clear(); }
  }
  loopback(text: string): void {
    this.host(text);
    requireThat(text === "::1" || /^127(?:\.[0-9]{1,3}){3}$/u.test(text), "host_loopback");
  }
  origin(text: string, schemes: Readonly<Record<string, { readonly default_port: number }>>): void {
    requireThat(typeof text === "string" && text.length > 0 && text.length <= 512 && !/[^\x21-\x7e]/u.test(text), "origin_ascii");
    const m = /^([a-z][a-z0-9+.-]*):\/\/(\[[0-9a-f:]+\]|[^:/?#@\\\[\]]+)(?::([0-9]+))?$/u.exec(text);
    if (m === null || m[0] !== text) reject("origin_syntax");
    const scheme = m[1]!, authority = m[2]!, port = m[3];
    if (!Object.hasOwn(schemes, scheme)) reject("origin_scheme_unregistered");
    const host = authority.startsWith("[") ? authority.slice(1, -1) : authority;
    requireThat(!authority.startsWith("[") || host.includes(":"), "origin_syntax");
    this.host(host);
    if (port !== undefined) {
      requireThat(/^(?:0|[1-9][0-9]{0,4})$/u.test(port) && Number(port) <= 65535, "origin_port");
      requireThat(Number(port) !== schemes[scheme]!.default_port, "origin_default_port");
    }
  }
  #ipv4(text: string): void {
    requireThat(text.length <= 15, "host_ipv4");
    const parts = text.split(".");
    requireThat(parts.length === 4, "host_ipv4");
    for (const part of parts) requireThat(/^(?:0|[1-9][0-9]{0,2})$/u.test(part) && Number(part) <= 255, "host_ipv4");
  }
  #ipv6(text: string): void {
    requireThat(text.length <= 39 && /^[0-9a-f:]+$/u.test(text), "host_ipv6");
    const halves = text.split("::");
    requireThat(halves.length <= 2, "host_ipv6");
    const left = halves[0] === "" ? [] : halves[0]!.split(":"), right = halves.length === 2 && halves[1] !== "" ? halves[1]!.split(":") : [];
    const missing = 8 - left.length - right.length;
    requireThat(halves.length === 2 ? missing >= 1 : missing === 0, "host_ipv6");
    const words: number[] = [];
    for (const part of left) { requireThat(/^(?:0|[1-9a-f][0-9a-f]{0,3})$/u.test(part), "host_ipv6"); words.push(Number.parseInt(part, 16)); }
    for (let i = 0; i < missing; i++) words.push(0);
    for (const part of right) { requireThat(/^(?:0|[1-9a-f][0-9a-f]{0,3})$/u.test(part), "host_ipv6"); words.push(Number.parseInt(part, 16)); }
    let best = -1, length = 1;
    for (let from = 0; from < 8;) {
      if (words[from] !== 0) { from++; continue; }
      let to = from + 1; while (to < 8 && words[to] === 0) to++;
      if (to - from > length) { best = from; length = to - from; }
      from = to;
    }
    const hex = words.map(word => word.toString(16));
    const canonical = best < 0 ? hex.join(":") : hex.slice(0, best).join(":") + "::" + hex.slice(best + length).join(":");
    requireThat(canonical === text, "host_noncanonical");
  }
  #dns(text: string): void {
    requireThat(text.length <= 253, "idna_domain_length");
    let at = 0, used = 0, labels = 0, bidi = false;
    while (at <= text.length) {
      const dot = text.indexOf(".", at), end = dot < 0 ? text.length : dot;
      const label = text.slice(at, end);
      requireThat(label.length > 0 && label.length <= 63 && labels < 128, "idna_label_length");
      requireThat(/^[a-z0-9-]+$/u.test(label), "idna_wire_noncanonical");
      const from = used;
      if (label.startsWith("xn--")) {
        used = this.#decode(label.slice(4), from);
        let nonASCII = false; for (let i = from; i < used; i++) nonASCII ||= this.#points[i]! >= 128;
        requireThat(nonASCII, "idna_fake_alabel");
        this.#roundtrip(label, from, used);
      } else {
        requireThat(used + label.length <= 253, "idna_label_length");
        for (let i = 0; i < label.length; i++) this.#points[used++] = label.charCodeAt(i);
      }
      let bytes = 0;
      for (let i = from; i < used; i++) {
        const cp = this.#points[i]!;
        if (cp < 0x80) this.#utf8[bytes++] = cp;
        else if (cp < 0x800) { this.#utf8[bytes++] = 0xc0 + (cp >>> 6); this.#utf8[bytes++] = 0x80 + (cp & 63); }
        else if (cp < 0x10000) { this.#utf8[bytes++] = 0xe0 + (cp >>> 12); this.#utf8[bytes++] = 0x80 + (cp >>> 6 & 63); this.#utf8[bytes++] = 0x80 + (cp & 63); }
        else { this.#utf8[bytes++] = 0xf0 + (cp >>> 18); this.#utf8[bytes++] = 0x80 + (cp >>> 12 & 63); this.#utf8[bytes++] = 0x80 + (cp >>> 6 & 63); this.#utf8[bytes++] = 0x80 + (cp & 63); }
      }
      requireThat(this.#nfc.check(this.#utf8, 0, bytes) === undefined, "idna_nfc");
      const points = this.#points;
      requireThat(used > from && used - from <= 63 && points[from] !== 45 && points[used - 1] !== 45 && !(used - from >= 4 && points[from + 2] === 45 && points[from + 3] === 45), "idna_hyphen");
      requireThat(!prop("categories", points[from]!).startsWith("M"), "idna_initial_mark");
      for (let i = from; i < used; i++) {
        const cp = points[i]!, mapping = prop("mapping", cp), kind = prop("classes", cp), direction = prop("bidi", cp);
        requireThat(mapping === "valid" || mapping === "deviation", "idna_validity");
        if (kind === "CONTEXTJ") requireThat(this.#contextJ(from, used, i), "idna_contextj");
        else if (kind === "CONTEXTO") requireThat(this.#contextO(from, used, i), "idna_contexto");
        else requireThat(kind === "PVALID", "idna2008_validity");
        bidi ||= direction === "R" || direction === "AL" || direction === "AN";
      }
      this.#bounds[labels * 2] = from; this.#bounds[labels * 2 + 1] = used; labels++;
      if (dot < 0) break;
      at = dot + 1;
    }
    if (bidi) for (let i = 0; i < labels; i++) requireThat(this.#bidi(this.#bounds[i * 2]!, this.#bounds[i * 2 + 1]!), "idna_bidi");
  }
  #decode(input: string, from: number): number {
    let used = from, at = 0, n = 128, i = 0, bias = 72;
    const dash = input.lastIndexOf("-");
    if (dash > 0) { for (let j = 0; j < dash; j++) this.#points[used++] = input.charCodeAt(j); at = dash + 1; }
    while (at < input.length) {
      const old = i; let weight = 1;
      for (let k = 36;; k += 36) {
        if (at === input.length) reject("punycode_truncated");
        const d = digit(input.charCodeAt(at++)); if (d < 0) reject("punycode_digit");
        i = safe(i + d * weight); const t = threshold(k, bias);
        if (d < t) break; weight = safe(weight * (36 - t));
      }
      const count = used - from + 1;
      bias = adapt(i - old, count, old === 0); n = safe(n + Math.floor(i / count)); i %= count;
      requireThat(n <= 0x10ffff && (n < 0xd800 || n > 0xdfff), "punycode_scalar");
      requireThat(used < 253 && count <= 63, "idna_label_length");
      this.#points.copyWithin(from + i + 1, from + i, used); this.#points[from + i] = n; used++; i++;
    }
    return used;
  }
  #roundtrip(label: string, from: number, to: number): void {
    let output = 0, handled = 0, n = 128, delta = 0, bias = 72;
    const put = (cp: number) => { if (output === 63) reject("idna_label_length"); this.#encoded[output++] = cp; };
    for (let i = from; i < to; i++) if (this.#points[i]! < 128) { put(this.#points[i]!); handled++; }
    const basic = handled; if (basic > 0) put(45);
    while (handled < to - from) {
      let next = 0x110000;
      for (let i = from; i < to; i++) { const cp = this.#points[i]!; if (cp >= n && cp < next) next = cp; }
      delta = safe(delta + (next - n) * (handled + 1)); n = next;
      for (let i = from; i < to; i++) {
        const cp = this.#points[i]!; if (cp < n) delta = safe(delta + 1); if (cp !== n) continue;
        let q = delta;
        for (let k = 36;; k += 36) { const t = threshold(k, bias); if (q < t) break; put(asciiDigit(t + (q - t) % (36 - t))); q = Math.floor((q - t) / (36 - t)); }
        put(asciiDigit(q)); bias = adapt(delta, handled + 1, handled === basic); delta = 0; handled++;
      }
      delta = safe(delta + 1); n++;
    }
    requireThat(output + 4 === label.length, "idna_alabel_roundtrip");
    for (let i = 0; i < output; i++) requireThat(this.#encoded[i] === label.charCodeAt(i + 4), "idna_alabel_roundtrip");
  }
  #contextJ(from: number, to: number, i: number): boolean {
    if (i > from && prop("ccc", this.#points[i - 1]!) === "9") return true;
    if (this.#points[i] === 0x200d) return false;
    let left = i - 1, right = i + 1;
    while (left >= from && prop("joining", this.#points[left]!) === "T") left--;
    while (right < to && prop("joining", this.#points[right]!) === "T") right++;
    if (left < from || right === to) return false;
    const l = prop("joining", this.#points[left]!), r = prop("joining", this.#points[right]!);
    return (l === "L" || l === "D") && (r === "R" || r === "D");
  }
  #contextO(from: number, to: number, i: number): boolean {
    const p = this.#points, cp = p[i]!;
    if (cp === 0xb7) return i > from && i + 1 < to && p[i - 1] === 0x6c && p[i + 1] === 0x6c;
    if (cp === 0x375) return i + 1 < to && prop("scripts", p[i + 1]!) === "Greek";
    if (cp === 0x5f3 || cp === 0x5f4) return i > from && prop("scripts", p[i - 1]!) === "Hebrew";
    if (cp === 0x30fb) { for (let j = from; j < to; j++) { const s = prop("scripts", p[j]!); if (s === "Hiragana" || s === "Katakana" || s === "Han") return true; } return false; }
    if (cp >= 0x660 && cp <= 0x669 || cp >= 0x6f0 && cp <= 0x6f9) {
      for (let j = from; j < to; j++) if (cp <= 0x669 && p[j]! >= 0x6f0 && p[j]! <= 0x6f9 || cp >= 0x6f0 && p[j]! >= 0x660 && p[j]! <= 0x669) return false;
      return true;
    }
    return false;
  }
  #bidi(from: number, to: number): boolean {
    const first = prop("bidi", this.#points[from]!), rtl = first === "R" || first === "AL";
    if (!rtl && first !== "L") return false;
    let last = "", arabic = false, european = false;
    for (let i = from; i < to; i++) {
      const d = prop("bidi", this.#points[i]!);
      if (!(d === "ES" || d === "CS" || d === "ET" || d === "ON" || d === "BN" || d === "NSM" || d === "EN" || (rtl ? d === "R" || d === "AL" || d === "AN" : d === "L"))) return false;
      if (d !== "NSM") last = d;
      arabic ||= d === "AN"; european ||= d === "EN";
    }
    return rtl ? (last === "R" || last === "AL" || last === "EN" || last === "AN") && !(arabic && european) : last === "L" || last === "EN";
  }
  clear(): void { this.#points.fill(0); this.#bounds.fill(0); this.#utf8.fill(0); this.#encoded.fill(0); this.#nfc.clear(); }
}
Object.freeze(WireHostWorkspace.prototype); Object.freeze(WireHostWorkspace);
