import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { Reference, utf8 } from "./testSupport/cbor.js";
import { IDNA, points, punyDecode, punyEncode, scalar, scalarText } from "./testSupport/idna.js";
import { hex } from "./testSupport/rules.js";
import { V4Failure, hash, root } from "./testSupport/unicode.js";

const reference = new IDNA(new Reference());
function unescape(input: string): string {
  const text = input.replace(/\\u([a-f0-9]{4})|\\x\{([a-f0-9]+)\}/giu, (_, small: string | undefined, large: string | undefined) => {
    const cp = Number.parseInt(small ?? large!, 16);
    if (cp > 0x10ffff) throw new V4Failure("invalid_scalar"); return String.fromCodePoint(cp);
  });
  points(text); return text;
}
function rejects(operation: () => unknown): void { expect(operation).toThrow(V4Failure); }

describe("v4.ts_idna", () => {
  // v4.ts_idna.conformance
  it("passes the complete pinned nontransitional ToASCII corpus", () => {
    const raw = readFileSync(new URL("testdata/unicode15_1/IdnaTestV2.txt", root));
    expect(hash(raw)).toBe(reference.conformanceSHA256);
    let count = 0;
    for (const [lineNumber, rawLine] of raw.toString("utf8").split("\n").entries()) {
      const line = rawLine.split("#")[0]!.replace(/^[ \t\r]+|[ \t\r]+$/gu, ""); if (!line) continue;
      const columns = line.split(";").map(column => column.replace(/^[ \t\r]+|[ \t\r]+$/gu, ""));
      expect(columns.length).toBeGreaterThanOrEqual(5);
      const expected = columns[3] || columns[1] || columns[0]!, status = columns[4] || columns[2] || "[]";
      let actual: string | undefined;
      try { actual = reference.process(unescape(columns[0]!)).ascii; }
      catch (error) { expect(error).toBeInstanceOf(V4Failure); }
      expect(actual !== undefined, `line ${lineNumber + 1}`).toBe(status === "[]");
      if (actual !== undefined) expect(utf8.encode(actual), `line ${lineNumber + 1}`).toEqual(utf8.encode(unescape(expected)));
      count += 1;
    }
    expect(count).toBe(6265);
  });

  // v4.ts_idna.context
  it("enforces IDNA2008 contexts and exact wire identity", () => {
    // Multilingual fixtures are limited to script, joiner and Bidi behavior.
    for (const input of ["\u0375\u03b1.example", "\u05d0\u05f3.example", "\u05d0\u05f4.example", "\u30ab\u30fb\u30ca.example", "\u30fb\u4e00.example", "\u0627\u0660\u0661.example", "\u0627\u06f0\u06f1.example", "\u0915\u094d\u200d\u0937.example", "\u0915\u094d\u200c\u0937.example", "a1.\u0645\u062b\u0627\u0644"]) {
      const ascii = reference.issuerDNS(input); expect(() => reference.wireDNS(ascii), input).not.toThrow();
    }
    for (const input of ["\u0375a.example", "\u05f3\u05d0.example", "\u05f4\u05d0.example", "a\u30fbb.example", "\u0627\u0660\u06f0.example", "\u0915\u200d\u0937.example", "\u0628\u200c\u0301a.example", "a\u200c\u0628.example", "1.\u0645\u062b\u0627\u0644", "\u{1f600}.example", "xn--e28h.example", "xn--abc-.example", "xn--a!", "a_b.example", "\u{1cc00}.example", "\ud800.example"]) rejects(() => reference.issuerDNS(input));
    expect(reference.process("\u{1f600}.example").ascii).toBe("xn--e28h.example");
    for (const input of ["EXAMPLE.COM", "\u00fc.example", "example.com.", "xn--BCHER-kva.example"]) rejects(() => reference.wireDNS(input));
    expect(reference.issuerDNS("EXAMPLE.COM")).toBe("example.com");
    rejects(() => unescape("\\uD800")); rejects(() => unescape("\\x{110000}"));
    expect(unescape("\\uD83D\\uDE00")).toBe("\u{1f600}");
  });

  // v4.ts_idna.shared_dns
  it("consumes the shared issuer and wire DNS vectors", () => {
    type Vector = { id: string; operation: string; input: string; output?: string; utf8_hex?: string; expected_error?: string };
    const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/text.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    let positive = 0, negative = 0;
    for (const vector of corpus.vectors) {
      if (!["issuer_dns", "wire_dns"].includes(vector.operation)) continue;
      const operation = (): string => { if (vector.operation === "issuer_dns") return reference.issuerDNS(vector.input); reference.wireDNS(vector.input); return vector.input; };
      if (vector.expected_error) { rejects(operation); negative += 1; }
      else {
        const output = operation(); expect(output, vector.id).toBe(vector.output); expect(utf8.encode(output), vector.id).toEqual(hex(vector.utf8_hex)); positive += 1;
      }
    }
    expect(positive).toBeGreaterThan(0); expect(negative).toBeGreaterThan(0);
  });

  // v4.ts_idna.properties
  it("round-trips bootstring and issuer/wire identity over two 4096-case paths", () => {
    let state = 0x41d0a41d;
    function next(): number { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; }
    function point(): number { while (true) { const cp = next() % 0x110000; if (scalar(cp)) return cp; } }
    for (let iteration = 0; iteration < 4096; iteration++) {
      const values = Array.from({ length: next() % 64 }, point);
      expect(punyDecode(punyEncode(values))).toEqual(values);
      const input = scalarText(Array.from({ length: next() % 128 }, point));
      let ascii: string | undefined;
      try { ascii = reference.issuerDNS(input); } catch (error) { expect(error).toBeInstanceOf(V4Failure); }
      if (ascii !== undefined) { reference.wireDNS(ascii); expect(reference.issuerDNS(ascii)).toBe(ascii); }
    }
  }, 30000);
});
