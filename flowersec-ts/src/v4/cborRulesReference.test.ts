// Independent closed variants and stateless relations, without live authority.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { encode, uint } from "./testSupport/cbor.js";
import type { Value } from "./testSupport/cbor.js";
import { emptyContext, integer } from "./testSupport/shape.js";
import type { Context } from "./testSupport/shape.js";
import { hex } from "./testSupport/rules.js";
import { Relations } from "./testSupport/relations.js";
import { V4Failure, root } from "./testSupport/unicode.js";

type Vector = { id: string; hex: string; schema?: string; expected_error?: string; limits?: Record<string, number | string> };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/corpus.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
const reference = new Relations();
const seed = (id: string): Vector => corpus.vectors.find(vector => vector.id === id)!;
const positive = (schema: string): Vector => corpus.vectors.find(vector => vector.schema === schema && !vector.expected_error)!;
const context = (vector: Vector): Context => ({
  limits: Object.fromEntries(Object.entries(vector.limits ?? {}).filter(([, value]) => typeof value === "number").map(([key, value]) => [key, integer(value)])),
  selectors: Object.fromEntries(Object.entries(vector.limits ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
});
function replace(schema: string, value: Value, field: string, replacement: Value): Value {
  const id = BigInt(Object.entries(reference.descriptor(schema).fields).find(([, item]) => item.name === field)![0]);
  if (value.kind !== "map") throw new Error("map fixture");
  expect(value.value.some(([key]) => key.kind === "uint" && key.value === id)).toBe(true);
  return { kind: "map", value: value.value.map(([key, item]) => [key, key.kind === "uint" && key.value === id ? replacement : item]) };
}
function bytes(value: Value | undefined): Uint8Array {
  if (value?.kind !== "bytes") throw new Error("bytes fixture"); return value.value;
}
function failure(operation: () => unknown, expected?: string): void {
  let error: unknown;
  try { operation(); } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(V4Failure);
  if (expected) expect((error as V4Failure).code).toBe(expected);
}

describe("v4.ts_rules", () => {
  // v4.ts_rules.variants / v4.ts_rules.relations
  for (const relations of [false, true]) it(`consumes the shared ${relations ? "relation" : "variant"} corpus`, () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    const excluded = new Set(["host_noncanonical", "host_loopback", "origin_endpoint", "origin_default_port", "origin_syntax", "pool_set_membership", "open_digest_mismatch"]);
    let positive = 0, negative = 0, separate = 0;
    for (const vector of corpus.vectors) {
      if (vector.expected_error) {
        if (relations) { if (excluded.has(vector.expected_error)) { separate += 1; continue; } }
        else if (!vector.expected_error.startsWith("variant_") && !["field_range", "field_prefix"].includes(vector.expected_error) && !["admission_rejected_unknown_code", "context_auth_exporter_bytes"].includes(vector.id)) continue;
      }
      const input = hex(vector.hex), ctx = context(vector), before = structuredClone(ctx);
      const decode = (): Value => relations ? reference.relations(input, vector.schema, ctx, BigInt(input.length) + 1n) : reference.variants(input, vector.schema, ctx, BigInt(input.length) + 1n);
      if (vector.expected_error) { negative += 1; failure(decode); }
      else { positive += 1; expect(encode(decode()), vector.id).toEqual(input); }
      expect(ctx, vector.id).toEqual(before);
    }
    expect(positive).toBe(337); expect(negative).toBe(relations ? 816 : 133); expect(separate).toBe(relations ? 12 : 0);
  });

  // v4.ts_rules.scoped_paths
  it("preserves containing and external context through embedded and array paths", () => {
    for (const id of ["route_direct_fields", "route_tunnel_mixed_fields", "activation_live_fields", "activation_pool_fields"]) {
      const vector = seed(id), raw = hex(vector.hex), name = vector.schema!;
      const ctx: Context = name === "Route" ? { ...context(vector), selectors: { path_kind: "invalid-caller-selector" } } : context(vector);
      const before = structuredClone(ctx);
      expect(encode(reference.relations(raw, name, ctx, BigInt(raw.length) + 1n))).toEqual(raw); expect(ctx).toEqual(before);
      if (name === "ActivationAuthorization") {
        failure(() => reference.variants(raw, name, emptyContext(), 65536n), "context_unresolved");
        failure(() => reference.variants(raw, name, { ...ctx, selectors: { activation_source_profile: "unknown" } }, 65536n), "context_unresolved");
      }
    }
    const fsb = seed("fsb_fields"), ctx = context(fsb), value = reference.relations(hex(fsb.hex), "FSB4", ctx, 65536n);
    expect(reference.path("FSB4", value, "client_certificate.role", ctx)).toEqual(uint(0n));
    failure(() => reference.path("FSB4", value, "not_registered", ctx), "unknown_rule_field");
    const grant = seed("grant_fields"), grantContext = context(grant), grantValue = reference.relations(hex(grant.hex), "Grant", grantContext, 65536n);
    expect(reference.path("Grant", grantValue, "legs.1.logical_role", grantContext)).toEqual(uint(1n));
    expect(reference.path("Grant", grantValue, "legs.18446744073709551615.logical_role", grantContext)).toBeUndefined();
    for (const index of ["invalid", "01", "1\n", "1\r", "1\u2028", "1\u2029", "18446744073709551616"]) failure(() => reference.path("Grant", grantValue, `legs.${index}.logical_role`, grantContext), "unknown_rule_field");
  });

  // v4.ts_rules.shape_preserving
  it("rejects shape-valid public-key, scope and nested role contradictions", () => {
    const vector = seed("grant_certificate_maximum_fields"), ctx = context(vector);
    const certificate = reference.variants(hex(vector.hex), "IdentityCertificate", ctx, 65536n);
    const key = reference.path("IdentityCertificate", certificate, "noise_static_public_key", ctx)!;
    const publicKey = bytes(reference.path("IdentityCertificate", certificate, "noise_static_public_key.public_key_bytes", ctx)).slice(); publicKey[0] = publicKey[0]! ^ 1;
    const modifiedKey = replace("NoiseStaticPublicKey", key, "public_key_bytes", { kind: "bytes", value: publicKey });
    const modified = encode(replace("IdentityCertificate", certificate, "noise_static_public_key", modifiedKey));
    reference.decode(modified, "IdentityCertificate", ctx, 65536n);
    failure(() => reference.variants(modified, "IdentityCertificate", ctx, 65536n), "field_prefix");
    const open = positive("OPEN_STREAM"), openContext = context(open), original = reference.variants(hex(open.hex), "OPEN_STREAM", openContext, 65536n);
    for (const scope of [0n, 1n << 63n, 0xffffffffffffffffn]) {
      const raw = encode(replace("OPEN_STREAM", original, "scope", uint(scope)));
      reference.decode(raw, "OPEN_STREAM", openContext, 65536n);
      failure(() => reference.variants(raw, "OPEN_STREAM", openContext, 65536n), "field_range");
    }
    reference.variants(encode(replace("OPEN_STREAM", original, "scope", uint((1n << 63n) - 1n))), "OPEN_STREAM", openContext, 65536n);
    const fsb = seed("fsb_fields"), fsbContext = context(fsb), fsbValue = reference.variants(hex(fsb.hex), "FSB4", fsbContext, 65536n);
    const cert = reference.decode(bytes(reference.path("FSB4", fsbValue, "client_certificate", fsbContext)), "IdentityCertificate", fsbContext, 65536n);
    const changed = encode(replace("IdentityCertificate", cert, "role", uint(1n)));
    const raw = encode(replace("FSB4", fsbValue, "client_certificate", { kind: "bytes", value: changed }));
    reference.decode(raw, "FSB4", fsbContext, 65536n);
    failure(() => reference.variants(raw, "FSB4", fsbContext, 65536n), "field_range");
    const grant = seed("grant_fields"), grantContext = context(grant), grantValue = reference.variants(hex(grant.hex), "Grant", grantContext, 65536n);
    const legs = reference.path("Grant", grantValue, "legs", grantContext);
    if (legs?.kind !== "array") throw new Error("legs fixture");
    const badLegs = encode(replace("Grant", grantValue, "legs", { kind: "array", value: [legs.value[0]!, replace("GrantLegRef", legs.value[1]!, "logical_role", uint(0n))] }));
    reference.decode(badLegs, "Grant", grantContext, 65536n);
    failure(() => reference.variants(badLegs, "Grant", grantContext, 65536n), "field_range");
  });

  // v4.ts_rules.full_width
  it("retains full-width terminal frontiers and duration arithmetic", () => {
    const drained = positive("STREAM_ACK_DRAINED"), ctx = context(drained);
    let value = reference.relations(hex(drained.hex), "STREAM_ACK_DRAINED", ctx, 65536n);
    const tuple = reference.path("STREAM_ACK_DRAINED", value, "terminal_tuple", ctx)!;
    value = replace("STREAM_ACK_DRAINED", value, "terminal_tuple", replace("terminal_tuple", tuple, "next_sequence", uint(0xfffffffffffffffen)));
    value = replace("STREAM_ACK_DRAINED", value, "observed_tuple", replace("terminal_tuple", tuple, "next_sequence", uint(0xffffffffffffffffn)));
    for (const [outcome, expected] of [[1n, "field_order"], [0n, "field_equality"]] as const) {
      const raw = encode(replace("STREAM_ACK_DRAINED", value, "outcome", uint(outcome)));
      reference.decode(raw, "STREAM_ACK_DRAINED", ctx, 65536n);
      failure(() => reference.variants(raw, "STREAM_ACK_DRAINED", ctx, 65536n), expected);
    }
    const tls = seed("tls_pin_full_window"), tlsContext = context(tls), pin = reference.relations(hex(tls.hex), "TLSPin", tlsContext, 65536n);
    const limit = integer(reference.registry.relation_rules.TLSPin!.find(rule => rule.op === "max_difference")!.max), max = 0xffffffffffffffffn;
    for (const [before, after, expected] of [[max - limit, max, undefined], [max - limit - 1n, max, "field_duration"], [max, 1n, "field_order"]] as const) {
      const raw = encode(replace("TLSPin", replace("TLSPin", pin, "not_before_ms", uint(before)), "not_after_ms", uint(after)));
      reference.variants(raw, "TLSPin", tlsContext, 65536n);
      if (expected) failure(() => reference.relations(raw, "TLSPin", tlsContext, 65536n), expected);
      else expect(encode(reference.relations(raw, "TLSPin", tlsContext, 65536n))).toEqual(raw);
    }
  });

  // v4.ts_rules.signed_bytes
  it("includes the original embedded certificate signature in its digest", () => {
    const vector = seed("hop_endpoint_hello_fields"), ctx = context(vector), hello = reference.relations(hex(vector.hex), "HOP_AUTH_HELLO", ctx, 65536n);
    const raw = bytes(reference.path("HOP_AUTH_HELLO", hello, "identity_certificate", ctx));
    const certificate = reference.decode(raw, "IdentityCertificate", ctx, 65536n);
    const signature = bytes(reference.path("IdentityCertificate", certificate, "signature", ctx)).slice(); signature[0] = signature[0]! ^ 1;
    const changed = encode(replace("IdentityCertificate", certificate, "signature", { kind: "bytes", value: signature }));
    const wire = encode(replace("HOP_AUTH_HELLO", hello, "identity_certificate", { kind: "bytes", value: changed }));
    reference.variants(wire, "HOP_AUTH_HELLO", ctx, 65536n);
    failure(() => reference.relations(wire, "HOP_AUTH_HELLO", ctx, 65536n), "map_digest_mismatch");
  });

  // v4.ts_rules.properties
  it("rejects or round-trips 4096 mutations through both rule layers", () => {
    let state = 0x41a1141a;
    function next(): number { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; }
    for (let iteration = 0; iteration < 4096; iteration++) {
      const vector = corpus.vectors[next() % corpus.vectors.length]!, input = hex(vector.hex);
      if (input.length) { const at = next() % input.length; input[at] = input[at]! ^ (next() & 255); }
      const ctx = context(vector), before = structuredClone(ctx);
      for (const relations of [false, true]) {
        let decoded: Value | undefined;
        try { decoded = relations ? reference.relations(input, vector.schema, ctx, BigInt(input.length) + 1n) : reference.variants(input, vector.schema, ctx, BigInt(input.length) + 1n); }
        catch (error) { expect(error).toBeInstanceOf(V4Failure); }
        if (decoded) expect(encode(decoded)).toEqual(input);
        expect(ctx).toEqual(before);
      }
    }
  }, 30000);
});
