// Independent syntax/NFC consumer; field, authority and runtime checks are separate.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { Reference, encode, head, join, uint } from "./testSupport/cbor.js";
import type { Decoded, Limits, Value } from "./testSupport/cbor.js";
import { hash, root } from "./testSupport/unicode.js";

type Vector = { id: string; kind: string; hex: string; schema?: string; decimal?: string; expected_error?: string; limits?: Record<string, number | string> };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/corpus.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
const reference = new Reference();
const bytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));
const seed = (id: string): Vector => corpus.vectors.find(v => v.id === id)!;
const limits = (vector: Vector): Limits => Object.fromEntries(Object.entries(vector.limits ?? {}).filter(([, value]) => typeof value === "number").map(([key, value]) => [key, BigInt(value)]));
function error(result: Decoded): string | undefined { return result.ok ? undefined : result.error; }
function value(result: Decoded): Value { if (!result.ok) throw new Error(result.error); return result.value; }

describe("v4.ts_cbor", () => {
  // v4.ts_cbor.corpus
  it("consumes the complete positive and syntax-negative shared corpus", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    const syntaxErrors = new Set(["non_canonical_text", "unassigned_code_point", "invalid_utf8", "unsupported_type", "array_limit", "duplicate_key", "non_shortest_integer", "map_order", "truncated", "trailing_bytes", "field_id_type", "indefinite_length", "depth_limit", "invalid_header", "map_limit"]);
    let positive = 0, negative = 0;
    for (const vector of corpus.vectors) {
      if (vector.expected_error && !syntaxErrors.has(vector.expected_error)) continue;
      const input = bytes(vector.hex), original = input.slice();
      const result = reference.decode(input, vector.schema, limits(vector), BigInt(input.length) + 1n);
      expect(result.nodes, vector.id).toBeLessThanOrEqual(input.length);
      expect(input, vector.id).toEqual(original);
      if (vector.expected_error) {
        negative += 1; expect(result.ok, vector.id).toBe(false);
        if (vector.kind === "cbor_syntax") expect(error(result), vector.id).toBe(vector.expected_error);
      } else {
        positive += 1;
        const parsed = value(result);
        expect(encode(parsed), vector.id).toEqual(input);
        if (vector.decimal) expect(parsed, vector.id).toEqual(uint(BigInt(vector.decimal)));
      }
    }
    expect(positive).toBe(337); expect(negative).toBe(252);
  });

  // v4.ts_cbor.limits
  it("rejects forged lengths and caps before parsed allocation", () => {
    for (const hex of ["5bffffffffffffffff", "7bffffffffffffffff", "9bffffffffffffffff", "bbffffffffffffffff", "99040b", "b880"]) {
      const result = reference.decode(bytes(hex), "", {}, 64n);
      expect(result.ok, hex).toBe(false); expect(result.nodes, hex).toBe(0);
    }
    for (const [input, schema, cap, expected] of [
      [Uint8Array.of(255, 255), "", 1n, "map_size"], [new Uint8Array(), "", 0n, "limit_unresolved"],
      [Uint8Array.of(0), "RevocationState", 1n, "limit_unresolved"],
      [Uint8Array.of(0), "Unregistered", 1n, "unknown_schema"],
      [Uint8Array.of(0), "__proto__", 1n, "unknown_schema"],
    ] as const) {
      const result = reference.decode(input, schema, {}, cap);
      expect(error(result)).toBe(expected); expect(result.nodes).toBe(0);
    }
    for (const [major, bound] of [[5, reference.registry.encoding.max_map_entries], [4, reference.registry.encoding.ordinary_array_items]] as const) {
      const parts = [head(major, BigInt(bound))];
      for (let n = 0; n < bound; n++) { if (major === 5) parts.push(head(0, BigInt(n))); parts.push(Uint8Array.of(0)); }
      const input = join(parts);
      expect(encode(value(reference.decode(input, "", {}, BigInt(input.length))))).toEqual(input);
      expect(reference.decode(head(major, BigInt(bound) + 1n), "", {}, 64n).ok).toBe(false);
    }
    const sliced = Uint8Array.of(255, 1, 255).subarray(1, 2);
    expect(value(reference.decode(sliced, "", {}, 1n))).toEqual(uint(1n));
    // Uint8Array and Buffer inputs both return detached byte-string backing.
    for (const input of [Uint8Array.of(0x42, 1, 2), Buffer.from([0x42, 1, 2])]) {
      const parsed = value(reference.decode(input, "", {}, 3n));
      if (parsed.kind !== "bytes") throw new Error("byte fixture");
      input.fill(0); expect(parsed.value).toEqual(Uint8Array.of(1, 2));
      parsed.value.fill(255); expect(input).toEqual(input.map(() => 0));
    }
    const maximum = value(reference.decode(bytes("1bffffffffffffffff"), "", {}, 9n));
    expect(maximum).toEqual(uint(0xffffffffffffffffn));
  });

  // v4.ts_cbor.context
  it("scopes nullable/text-key slots and capacity-derived arrays", () => {
    expect(error(reference.decode(Uint8Array.of(0xf6), "", {}, 1n))).toBe("unsupported_type");
    const vector = seed("revoked_issuer_minimum"), schema = vector.schema!, input = bytes(vector.hex);
    const context: Record<string, bigint> = { max_state_encoded_bytes: 1n << 20n, max_revoked_issuer_authorizations: 1036n };
    const parsed = value(reference.decode(input, schema, context, 1n << 20n));
    if (parsed.kind !== "map") throw new Error("map fixture");
    const [id] = Object.entries(reference.registry.frame_maps[schema]!.fields).find(([, field]) => field.max_items_ref === "max_revoked_issuer_authorizations")!;
    const pair = parsed.value.find(([key]) => key.kind === "uint" && key.value === BigInt(id))!;
    if (pair[1].kind !== "array") throw new Error("array fixture");
    const member = pair[1].value[0]!;
    pair[1] = { kind: "array", value: Array.from({ length: 1036 }, () => member) };
    const large = encode(parsed);
    expect(encode(value(reference.decode(large, schema, context, BigInt(large.length))))).toEqual(large);
    context.max_revoked_issuer_authorizations = 1035n;
    expect(error(reference.decode(large, schema, context, BigInt(large.length)))).toBe("array_limit");
    context.max_revoked_issuer_authorizations = 1n << 32n;
    expect(error(reference.decode(large, schema, context, BigInt(large.length)))).toBe("limit_unresolved");
    context.max_revoked_issuer_authorizations = 1036n; context.max_state_encoded_bytes = BigInt(large.length) - 1n;
    const result = reference.decode(large, schema, context, BigInt(large.length));
    expect(error(result)).toBe("map_size"); expect(result.nodes).toBe(0);
    expect(error(reference.decode(encode({ kind: "map", value: [[{ kind: "text", value: "a" }, { kind: "text", value: "b" }]] }), "", {}, 64n))).toBe("field_id_type");
  });

  // v4.ts_cbor.embedded_cap
  it("checks declared embedded caps before payload extraction", () => {
    const schema = "TopUpRequest";
    const [id] = Object.entries(reference.registry.frame_maps[schema]!.fields).find(([, field]) => field.encoded_schema_ref === "OwnerFenceProof")!;
    const bound = BigInt(reference.registry.frame_maps.OwnerFenceProof!.max_encoded_bytes!);
    const prefix = join([head(5, 1n), head(0, BigInt(id))]);
    for (const n of [bound + 1n, 0xffffffffffffffffn]) {
      expect(error(reference.decode(join([prefix, head(2, n)]), schema, {}, 65536n))).toBe("map_size");
    }
    expect(error(reference.decode(join([prefix, head(2, bound)]), schema, {}, 65536n))).toBe("truncated");
    expect(error(reference.decode(join([prefix, head(2, bound + 1n), new Uint8Array(Number(bound + 1n))]), schema, {}, 65536n))).toBe("map_size");
  });

  // v4.ts_cbor.unicode
  it("passes pinned normalization conformance and the Part1 complement", () => {
    const nfc = reference.nfc, raw = readFileSync(new URL("testdata/unicode15_1/NormalizationTest.txt", root));
    expect(hash(raw)).toBe(nfc.conformanceSHA256);
    let partOne = false, count = 0;
    const covered = new Set<number>();
    for (const rawLine of raw.toString("utf8").split("\n")) {
      const line = rawLine.split("#")[0]!.trim();
      if (line.startsWith("@")) { partOne = line.startsWith("@Part1"); continue; }
      if (!line) continue;
      const columns = line.split(";").slice(0, 5).map(column => column.trim().split(/ +/u).map(cp => String.fromCodePoint(Number.parseInt(cp, 16))).join(""));
      expect(columns.length).toBe(5);
      if (partOne) for (const cp of columns[0]!) covered.add(cp.codePointAt(0)!);
      for (let index = 0; index < columns.length; index++) expect(nfc.normalize(columns[index]!), `case ${count} column ${index}`).toBe(columns[index < 3 ? 1 : 3]);
      count += 1;
    }
    expect(count).toBe(19074);
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff || covered.has(cp)) continue;
      const input = String.fromCodePoint(cp);
      if (nfc.normalize(input) !== input) throw new Error(`Part1 complement U+${cp.toString(16)}`);
    }
    expect(nfc.assigned(0x1cc00)).toBe(false); expect(nfc.assigned(0x378)).toBe(false);
    const normalized = nfc.normalize("A" + "\u0315\u0300".repeat(10000));
    expect(nfc.normalize(normalized)).toBe(normalized);
    expect(() => nfc.normalize("\ud800")).toThrow("unicode_scalar");
    expect(error(reference.decode(encode({ kind: "text", value: "e\u0301" }), "", {}, 64n))).toBe("non_canonical_text");
    const bom = encode({ kind: "text", value: "\ufeffvalue" });
    expect(encode(value(reference.decode(bom, "", {}, 64n)))).toEqual(bom);
  }, 30000);

  // v4.ts_cbor.properties
  it("round-trips or rejects 4096 arbitrary and 4096 mutated inputs", () => {
    let state = 0x41cb041c;
    function next(): number { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; }
    for (let iteration = 0; iteration < 4096; iteration++) {
      const input = Uint8Array.from({ length: next() % 8192 }, () => next() & 255);
      const result = reference.decode(input, "", {}, 4096n);
      expect(result.nodes).toBeLessThanOrEqual(input.length);
      if (input.length > 4096) { expect(error(result)).toBe("map_size"); expect(result.nodes).toBe(0); }
      if (result.ok) expect(encode(result.value)).toEqual(input);
      const vector = corpus.vectors[next() % corpus.vectors.length]!, mutated = bytes(vector.hex);
      if (mutated.length) { const at = next() % mutated.length; mutated[at] = mutated[at]! ^ (next() & 255); }
      const decoded = reference.decode(mutated, vector.schema, limits(vector), BigInt(mutated.length) + 1n);
      expect(decoded.nodes).toBeLessThanOrEqual(mutated.length);
      if (decoded.ok) expect(encode(decoded.value)).toEqual(mutated);
    }
  }, 30000);
});
