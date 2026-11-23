import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { encode, utf8 } from "./testSupport/cbor.js";
import type { Value } from "./testSupport/cbor.js";
import { integer } from "./testSupport/shape.js";
import type { Context } from "./testSupport/shape.js";
import { hex } from "./testSupport/rules.js";
import { scalar, scalarText } from "./testSupport/idna.js";
import { TextReference, ipv6, ipv6Hex } from "./testSupport/text.js";
import { V4Failure, root } from "./testSupport/unicode.js";

type Vector = { id: string; hex: string; schema?: string; expected_error?: string; limits?: Record<string, number | string> };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/corpus.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
const reference = new TextReference();
const context = (vector: Vector): Context => ({
  limits: Object.fromEntries(Object.entries(vector.limits ?? {}).filter(([, value]) => typeof value === "number").map(([key, value]) => [key, integer(value)])),
  selectors: Object.fromEntries(Object.entries(vector.limits ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
});

describe("v4.ts_text", () => {
  // v4.ts_text.corpus
  it("consumes every shared issuer and wire text vector", () => {
    type TextVector = { id: string; operation: string; input: string; output?: string; utf8_hex?: string; expected_error?: string };
    const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/text.json", root), "utf8")) as { schema_sha256: string; vectors: TextVector[] };
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    for (const vector of corpus.vectors) {
      const operation = (): string => {
        switch (vector.operation) {
          case "issuer_dns": return reference.idna.issuerDNS(vector.input);
          case "wire_dns": reference.idna.wireDNS(vector.input); break;
          case "issuer_host": return reference.issuerHost(vector.input);
          case "wire_host": reference.wireHost(vector.input); break;
          case "wire_origin": reference.wireOrigin(vector.input); break;
          default: throw new Error("unknown text operation");
        }
        return vector.input;
      };
      if (vector.expected_error) expect(operation, vector.id).toThrow(V4Failure);
      else {
        const output = operation(); expect(output, vector.id).toBe(vector.output); expect(utf8.encode(output), vector.id).toEqual(hex(vector.utf8_hex));
      }
    }
    expect(corpus.vectors.length).toBe(100);
  });

  // v4.ts_text.wire_maps
  it("validates the complete map corpus except external composition", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    let positive = 0, negative = 0, separate = 0;
    for (const vector of corpus.vectors) {
      if (["pool_set_membership", "open_digest_mismatch"].includes(vector.expected_error ?? "")) { separate += 1; continue; }
      const raw = hex(vector.hex), ctx = context(vector), before = structuredClone(ctx);
      const decode = (): Value => reference.wireMap(raw, vector.schema, ctx, BigInt(raw.length) + 1n);
      if (vector.expected_error) { expect(decode, vector.id).toThrow(V4Failure); negative += 1; }
      else { expect(encode(decode()), vector.id).toEqual(raw); positive += 1; }
      expect(ctx).toEqual(before);
    }
    expect(positive).toBe(337); expect(negative).toBe(826); expect(separate).toBe(2);
  });

  // v4.ts_text.address_boundaries
  it("preserves address family/bits and requires canonical registered Origins", () => {
    for (const [input, canonical] of [["2001:0DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1"], ["0:0:0:0:0:0:0:0", "::"], ["::FFFF:192.0.2.1", "::ffff:c000:201"], ["0:0:0:0:0:0:0:1", "::1"]]) {
      expect(reference.issuerHost(input!)).toBe(canonical); expect(ipv6(input!)).toEqual(ipv6(canonical!));
      reference.wireHost(canonical!); expect(() => reference.wireHost(input!)).toThrow(V4Failure);
    }
    for (const host of ["127.1", "127.00.0.1", "2130706433", "0x7f000001", "example.0x", "example.123", "::ffff:127.0.0.1%lo", "example.com.", "example.com/path", "example.com\u00a0", "1::2::3", ":::1", "1:::2", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "192.0.2.1::", "+1::", "::ffff:192.00.2.1"]) expect(() => reference.issuerHost(host), host).toThrow(V4Failure);
    reference.wireHost("example.0xg");
    for (const origin of ["https://example.com", "https://example.com:0", "https://[::ffff:c000:201]", "http://127.0.0.1:3000"]) reference.wireOrigin(origin);
    for (const origin of ["https://example.com:443", "http://127.0.0.1:80", "https://example.com:0443", "https://example.com:65536", "https://user@example.com", "https://example.com/", "https://example.com?x", "https://example.com#x", "https://EXAMPLE.COM", "https://[::ffff:192.0.2.1]", "https://example.com\n", "unregistered://example.com", "https://example.com:", "https://[example.com]", "https://[::1]]", "https://[::1]:+1"]) expect(() => reference.wireOrigin(origin), origin).toThrow(V4Failure);
    expect(ipv6Hex([1, 0, 0, 2, 0, 0, 3, 4])).toBe("1::2:0:0:3:4");
    expect(ipv6Hex([1, 0, 2, 3, 4, 5, 6, 7])).toBe("1:0:2:3:4:5:6:7");
    expect(ipv6("::ffff:c000:201")).toEqual([0, 0, 0, 0, 0, 65535, 49152, 513]);
  });

  // v4.ts_text.properties
  it("preserves address/issuer identity and mutated maps over three 4096-case paths", () => {
    let state = 0x41e7141e;
    function next(): number { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; }
    for (let iteration = 0; iteration < 4096; iteration++) {
      const words = Array.from({ length: 8 }, () => { const n = next(); return n % 3 === 0 ? 0 : n & 0xffff; });
      const full = words.map(word => word.toString(16).toUpperCase().padStart(4, "0")).join(":"), canonical = reference.issuerHost(full);
      expect(ipv6(canonical)).toEqual(words); reference.wireHost(canonical); reference.wireOrigin(`https://[${canonical}]`);
      const input = scalarText(Array.from({ length: next() % 128 }, () => next() % 0x110000).filter(scalar));
      let host: string | undefined;
      try { host = reference.issuerHost(input); } catch (error) { expect(error).toBeInstanceOf(V4Failure); }
      if (host !== undefined) { reference.wireHost(host); reference.wireOrigin("https://" + (host.includes(":") ? `[${host}]` : host)); }
      const vector = corpus.vectors[next() % corpus.vectors.length]!, raw = hex(vector.hex), ctx = context(vector), before = structuredClone(ctx);
      if (raw.length) { const at = next() % raw.length; raw[at] = raw[at]! ^ (next() & 255); }
      let value: Value | undefined;
      try { value = reference.wireMap(raw, vector.schema, ctx, BigInt(raw.length) + 1n); } catch (error) { expect(error).toBeInstanceOf(V4Failure); }
      if (value) expect(encode(value)).toEqual(raw); expect(ctx).toEqual(before);
    }
  }, 30000);
});
