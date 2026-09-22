// Independent generated field-shape consumer; live authority is separate.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { encode, uint } from "./testSupport/cbor.js";
import type { Value } from "./testSupport/cbor.js";
import { Shape, emptyContext, integer, record } from "./testSupport/shape.js";
import type { Context } from "./testSupport/shape.js";
import { V4Failure, root } from "./testSupport/unicode.js";

type Vector = { id: string; hex: string; schema?: string; expected_error?: string; limits?: Record<string, number | string> };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/corpus.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
const reference = new Shape();
const bytes = (hex: string): Uint8Array => new Uint8Array(Buffer.from(hex, "hex"));
const seed = (id: string): Vector => corpus.vectors.find(vector => vector.id === id)!;
const context = (vector: Vector): Context => ({
  limits: Object.fromEntries(Object.entries(vector.limits ?? {}).filter(([, value]) => typeof value === "number").map(([key, value]) => [key, integer(value)])),
  selectors: Object.fromEntries(Object.entries(vector.limits ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
});
const fieldID = (schema: string, name: string): bigint => BigInt(Object.entries(reference.descriptor(schema).fields).find(([, field]) => field.name === name)![0]);
function replace(value: Value, id: bigint, replacement: Value): Value {
  if (value.kind !== "map") throw new Error("map fixture");
  expect(value.value.some(([key]) => key.kind === "uint" && key.value === id)).toBe(true);
  return { kind: "map", value: value.value.map(([key, item]) => [key, key.kind === "uint" && key.value === id ? replacement : item]) };
}
function failure(operation: () => unknown, expected?: string): void {
  let error: unknown;
  try { operation(); } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(V4Failure);
  if (expected) expect((error as V4Failure).code).toBe(expected);
}

describe("v4.ts_shape", () => {
  // v4.ts_shape.corpus
  it("consumes all shared positive and field-negative cases", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    const errors = new Set(["unknown_field", "missing_field", "integer_type", "integer_range", "constant_mismatch", "field_type", "field_length", "field_nonzero", "text_pattern", "reserved_namespace", "enum_value", "unknown_bits", "map_type", "map_length", "array_length", "map_size"]);
    let positive = 0, negative = 0;
    for (const vector of corpus.vectors) {
      // These names overlap field errors but require the separate variant layer.
      if (["admission_rejected_unknown_code", "context_auth_exporter_bytes"].includes(vector.id)) continue;
      if (vector.expected_error && !errors.has(vector.expected_error)) continue;
      const input = bytes(vector.hex), ctx = context(vector), before = structuredClone(ctx);
      const decode = (): Value => reference.decode(input, vector.schema, ctx, BigInt(input.length) + 1n);
      if (vector.expected_error) { negative += 1; failure(decode); }
      else { positive += 1; expect(encode(decode()), vector.id).toEqual(input); }
      expect(ctx, vector.id).toEqual(before);
    }
    expect(positive).toBe(337); expect(negative).toBe(324);
  });

  // v4.ts_shape.required_unknown
  it("rejects missing and unknown fields for every positive root schema", () => {
    const seen = new Set<string>();
    for (const vector of corpus.vectors) {
      if (!vector.schema || vector.expected_error || seen.has(vector.schema)) continue;
      const name = vector.schema; seen.add(name);
      const input = bytes(vector.hex), ctx = context(vector);
      const decoded = reference.decode(input, name, ctx, BigInt(input.length) + 1n);
      if (decoded.kind !== "map") throw new Error(name);
      const descriptor = reference.descriptor(name);
      for (const id of descriptor.required) {
        const changed: Value = { kind: "map", value: decoded.value.filter(([key]) => key.kind !== "uint" || key.value !== integer(id)) };
        failure(() => reference.checkMap(name, changed, ctx));
      }
      expect(descriptor.fields["65535"]).toBeUndefined();
      const changed: Value = { kind: "map", value: [...decoded.value, [uint(65535n), uint(0n)]] };
      failure(() => reference.checkMap(name, changed, ctx), "unknown_field");
    }
    expect(seen.size).toBe(93);
  });

  // v4.ts_shape.context_boundaries
  it("uses explicit isolated selectors and exact field boundaries", () => {
    const vector = seed("rekey_init_fields"), input = bytes(vector.hex), ctx = context(vector);
    failure(() => reference.decode(input, "REKEY_INIT", emptyContext(), 65536n), "context_unresolved");
    for (const selector of ["unknown", "__proto__", "constructor"]) {
      failure(() => reference.decode(input, "REKEY_INIT", { ...ctx, selectors: { crypto_profile_id: selector } }, 65536n), "context_unresolved");
    }
    const [profileName, profileValue] = Object.entries(record(reference.fieldRegistry("crypto_profiles"))).find(([, profile]) => integer(record(profile).dh_algorithm) === 1n)!;
    const profile = record(profileValue), p256: Context = { ...ctx, selectors: { crypto_profile_id: profileName } };
    failure(() => reference.decode(input, "REKEY_INIT", p256, 65536n), "field_length");
    const decoded = reference.decode(input, "REKEY_INIT", ctx, 65536n);
    const key = new Uint8Array(Number(integer(profile.dh_public_bytes))); key[0] = 3;
    const changed = replace(decoded, fieldID("REKEY_INIT", "client_ephemeral"), { kind: "bytes", value: key });
    failure(() => reference.checkMap("REKEY_INIT", changed, p256), "field_prefix");
    // Correct prefix/length establishes shape only, not curve validity.
    key[0] = 4; reference.checkMap("REKEY_INIT", changed, p256);
    const pool = seed("activation_pool_fields");
    failure(() => reference.decode(bytes(pool.hex), "ActivationAuthorization", emptyContext(), 65536n), "context_unresolved");
    failure(() => reference.decode(bytes(pool.hex), "ActivationAuthorization", { ...context(pool), selectors: { activation_source_profile: "live_authority" } }, 65536n));
    const owner = reference.decode(bytes(seed("topup_owner_proof_fields").hex), "OwnerFenceProof", emptyContext(), 65536n);
    for (const value of ["Tenant", "tenant\n", "tenant\0", "ténant"]) {
      failure(() => reference.checkMap("OwnerFenceProof", replace(owner, fieldID("OwnerFenceProof", "tenant_id"), { kind: "text", value }), emptyContext()), "text_pattern");
    }
    const maximum = encode(replace(owner, fieldID("OwnerFenceProof", "expires_at_ms"), uint(0xffffffffffffffffn)));
    expect(encode(reference.decode(maximum, "OwnerFenceProof", emptyContext(), 65536n))).toEqual(maximum);
    for (const item of corpus.vectors) {
      if (item.expected_error || !item.schema) continue;
      const selectors = reference.descriptor(item.schema).context_fields;
      if (!selectors || !Object.keys(selectors).length) continue;
      const caller: Context = { ...context(item), selectors: { ...context(item).selectors, ...Object.fromEntries(Object.keys(selectors).map(name => [name, "invalid_external_selector"])) } };
      const before = structuredClone(caller), raw = bytes(item.hex);
      expect(encode(reference.decode(raw, item.schema, caller, BigInt(raw.length) + 1n)), item.id).toEqual(raw);
      expect(caller, item.id).toEqual(before);
    }
  });

  // v4.ts_shape.properties
  it("rejects or preserves original bytes and caller context for 4096 mutations", () => {
    let state = 0x41f1e1d4;
    function next(): number { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; }
    for (let iteration = 0; iteration < 4096; iteration++) {
      const vector = corpus.vectors[next() % corpus.vectors.length]!, input = bytes(vector.hex);
      if (input.length) { const at = next() % input.length; input[at] = input[at]! ^ (next() & 255); }
      const ctx = context(vector), before = structuredClone(ctx);
      let decoded: Value | undefined;
      try { decoded = reference.decode(input, vector.schema, ctx, BigInt(input.length) + 1n); }
      catch (error) { expect(error).toBeInstanceOf(V4Failure); }
      if (decoded) expect(encode(decoded)).toEqual(input);
      expect(ctx).toEqual(before);
    }
  }, 30000);
});
