import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { transportV4Domains, transportV4Registry } from "../generated/transportV4Registry.js";
import { encode, join } from "./testSupport/cbor.js";
import type { Value } from "./testSupport/cbor.js";
import { emptyContext, integer, record } from "./testSupport/shape.js";
import type { Context } from "./testSupport/shape.js";
import { array, hex, string } from "./testSupport/rules.js";
import { Domains, fixedUnsigned } from "./testSupport/domains.js";
import type { DomainResult } from "./testSupport/domains.js";
import { V4Failure, root } from "./testSupport/unicode.js";

type Vector = { id: string; domain: string; context?: Record<string, number | string>; inputs: Record<string, unknown>; expected_error?: string; result?: { label_hex: string; input_hex: string; output_hex?: string; salt_hex?: string; ikm_hex?: string; output_length?: number } };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/domains.json", root), "utf8")) as { schema_sha256: string; vectors: Vector[] };
const reference = new Domains(), cap = 1n << 20n;
function input(vector: Vector): Record<string, unknown> {
  return Object.fromEntries(Object.entries(vector.inputs).map(([name, value]) => {
    if (value && typeof value === "object") {
      const object = record(value);
      if (object.$bytes !== undefined) return [name, hex(object.$bytes)];
      if (object.$uint !== undefined) return [name, BigInt(string(object.$uint))];
      throw new Error("unknown fixture type");
    }
    return [name, value];
  }));
}
function context(vector: Vector): Context {
  return {
    limits: Object.fromEntries(Object.entries(vector.context ?? {}).filter(([, value]) => typeof value === "number").map(([key, value]) => [key, integer(value)])),
    selectors: Object.fromEntries(Object.entries(vector.context ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
  };
}
const seed = (domain: string): Vector => corpus.vectors.find(vector => vector.domain === domain && !vector.expected_error)!;
function failure(operation: () => unknown, expected?: string): void {
  let error: unknown; try { operation(); } catch (caught) { error = caught; }
  expect(error).toBeInstanceOf(V4Failure); if (expected) expect((error as V4Failure).code).toBe(expected);
}
function mutateField(schema: string, raw: Uint8Array, name: string, ctx: Context): Uint8Array {
  const value = reference.wireMap(raw, schema, ctx, cap), id = reference.namedField(schema, name)[0];
  if (value.kind !== "map") throw new Error("map fixture");
  const pair = value.value.find(([key]) => key.kind === "uint" && key.value === id)!;
  if (pair[1].kind !== "bytes") throw new Error("bytes fixture");
  const changed = pair[1].value.slice(); changed[0] = changed[0]! ^ 1; pair[1] = { kind: "bytes", value: changed }; return encode(value);
}

describe("v4.ts_domains", () => {
  // v4.ts_domains.corpus
  it("independently constructs all registered domain inputs and primitive outputs", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    let positive = 0, negative = 0; const covered = new Set<string>();
    for (const vector of corpus.vectors) {
      const args = input(vector), ctx = context(vector), savedArgs = structuredClone(args), savedContext = structuredClone(ctx);
      if (vector.expected_error) {
        negative += 1;
        // Layer-specific CBOR error precedence is separate from domain errors.
        failure(() => reference.evaluate(vector.domain, args, ctx, cap), vector.expected_error.startsWith("domain_") ? vector.expected_error : undefined);
      } else {
        positive += 1; covered.add(vector.domain);
        const result = reference.evaluate(vector.domain, args, ctx, cap), expected = vector.result!;
        expect(result, vector.id).toEqual({
          label: hex(expected.label_hex), input: hex(expected.input_hex),
          ...(expected.output_hex === undefined ? {} : { output: hex(expected.output_hex) }),
          ...(expected.salt_hex === undefined ? {} : { salt: hex(expected.salt_hex) }),
          ...(expected.ikm_hex === undefined ? {} : { ikm: hex(expected.ikm_hex) }),
          ...(expected.output_length === undefined ? {} : { outputLength: expected.output_length }),
        });
      }
      expect(args).toEqual(savedArgs); expect(ctx).toEqual(savedContext);
    }
    expect(positive).toBe(107); expect(negative).toBe(52); expect(covered.size).toBe(58);
    for (const domain of transportV4Domains) expect(covered.has(domain.name), domain.name).toBe(true);
  });

  // v4.ts_domains.signing_inputs
  it("reconstructs signing bytes before consuming real public-fixture signatures", () => {
    type Signature = { id: string; domain_vector: string | null; domain: string | null; message_hex: string; public_key_hex: string; signature_hex: string; accept: boolean };
    const signatures = JSON.parse(readFileSync(new URL("testdata/transport_v4/signatures.json", root), "utf8")) as { signing_seed_hex: string; vectors: Signature[] };
    let count = 0;
    for (const vector of signatures.vectors.filter(vector => vector.accept && vector.domain_vector !== null)) {
      const domain = corpus.vectors.find(domain => domain.id === vector.domain_vector)!;
      const result = reference.evaluate(vector.domain!, input(domain), context(domain), cap);
      expect(result.output).toBeUndefined(); expect(result.input).toEqual(hex(vector.message_hex));
      const signature = ed25519.sign(result.input, hex(signatures.signing_seed_hex));
      expect(signature).toEqual(hex(vector.signature_hex));
      expect(ed25519.verify(signature, result.input, hex(vector.public_key_hex), { zip215: false })).toBe(true); count += 1;
    }
    expect(count).toBeGreaterThanOrEqual(transportV4Domains.filter(domain => domain.operation === "ed25519").length);
  });

  // v4.ts_domains.arguments
  it("rejects unknown, missing, inherited and wrongly typed arguments without changing context", () => {
    failure(() => reference.evaluate("unregistered", {}, emptyContext(), cap), "domain_unknown");
    for (const domain of transportV4Domains) {
      const vector = seed(domain.name), args = input(vector), ctx = context(vector), before = structuredClone(ctx);
      for (const invalid of [undefined, null, [], { ...args, extra: new Uint8Array() }, Object.create(args) as unknown]) failure(() => reference.evaluate(domain.name, invalid, ctx, cap), "domain_arguments");
      for (const name of Object.keys(args)) {
        const missing = { ...args }; delete missing[name]; failure(() => reference.evaluate(domain.name, missing, ctx, cap), "domain_arguments");
        failure(() => reference.evaluate(domain.name, { ...args, [name]: null }, ctx, cap));
      }
      expect(ctx).toEqual(before);
    }
  });

  // v4.ts_domains.projections
  it("excludes only registered signature or MAC fields while full digests bind their original bytes", () => {
    for (const [signing, digest, schema, field, included] of [
      ["artifact_signature", "artifact_digest", "Artifact", "signature", true],
      ["certificate_signature", "certificate_digest", "IdentityCertificate", "signature", true],
      ["activation_signature", "activation_digest", "ActivationAuthorization", "signature", true],
      ["fsb_signature", "fsb_digest", "FSB4", "client_signature", true],
      ["fsa_signature", "fsa_digest", "FSA4", "server_signature", true],
      ["freshness_head_signature", "freshness_head_digest", "FreshnessHead", "signature", true],
      ["grant_signature", "grant_digest", "Grant", "signature", false],
    ] as const) {
      const vector = seed(signing), args = input(vector), key = Object.keys(args)[0]!, ctx = context(vector);
      const changed = mutateField(schema, args[key] as Uint8Array, field, ctx), mutation = { ...args, [key]: changed };
      const unsigned = reference.evaluate(signing, args, ctx, cap);
      expect(reference.evaluate(signing, mutation, ctx, cap)).toEqual(unsigned);
      const originalDigest = reference.evaluate(digest, args, ctx, cap), changedDigest = reference.evaluate(digest, mutation, ctx, cap);
      if (included) expect(changedDigest.output).not.toEqual(originalDigest.output);
      else expect(changedDigest.output).toEqual(originalDigest.output);
      expect(unsigned.input).not.toEqual(originalDigest.input);
      const descriptor = reference.descriptor(schema), projected = reference.syntax.decode(unsigned.input.subarray(unsigned.label.length + 4), "", {}, cap);
      if (!projected.ok || projected.value.kind !== "map") throw new Error("projected map fixture");
      const ids = projected.value.value.map(([id]) => { if (id.kind !== "uint") throw new Error("key fixture"); return id.value; });
      const full = reference.wireMap(args[key] as Uint8Array, schema, ctx, cap);
      if (full.kind !== "map") throw new Error("full map fixture");
      expect(ids).toEqual(full.value.filter(([id]) => id.kind !== "uint" || id.value !== BigInt(descriptor.signature_field!)).map(([id]) => (id as Extract<Value, { kind: "uint" }>).value));
    }
    for (const vector of corpus.vectors.filter(vector => vector.domain === "rekey_confirm_mac" && !vector.expected_error)) {
      const args = input(vector), ctx = context(vector), phase = Number(args.phase), name = ["", "REKEY_INIT", "REKEY_REPLY", "REKEY_COMMIT", "REKEY_ACK"][phase]!;
      const descriptor = reference.descriptor(name), macName = descriptor.fields[String(descriptor.mac_field)]!.name!;
      const changed = mutateField(name, args.message as Uint8Array, macName, ctx);
      expect(reference.evaluate(vector.domain, { ...args, message: changed }, ctx, cap)).toEqual(reference.evaluate(vector.domain, args, ctx, cap));
    }
  });

  // v4.ts_domains.widths_and_exporters
  it("preserves UInt64, exact external exporter bytes and raw TopUp projections", () => {
    expect(fixedUnsigned(0xffffffffffffffffn, 8)).toEqual(new Uint8Array(8).fill(255));
    expect(fixedUnsigned(0x12345678, 4)).toEqual(hex("12345678"));
    for (const width of [1, 4, 8] as const) for (const invalid of [-1n, 1n << BigInt(width * 8), 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, "1", true]) failure(() => fixedUnsigned(invalid, width));
    const wt = seed("tls_exporter_wt"), wtArgs = input(wt), output = reference.evaluate(wt.domain, wtArgs, context(wt), cap);
    expect(new TextDecoder().decode(output.label)).toBe("EXPORTER-WebTransport"); expect(output.input.length).toBe(63); expect(output.outputLength).toBe(32); expect(output.output).toBeUndefined();
    expect(output.input.subarray(8, 31)).toEqual(join([Uint8Array.of(21), new TextEncoder().encode("EXPORTER-flowersec-v4"), Uint8Array.of(32)]));
    expect(reference.evaluate(wt.domain, { ...wtArgs, connect_stream_id: (1n << 62n) - 4n }, context(wt), cap).input.subarray(0, 8)).toEqual(hex("3ffffffffffffffc"));
    for (const id of [1n, (1n << 62n) - 1n, 1n << 62n]) failure(() => reference.evaluate(wt.domain, { ...wtArgs, connect_stream_id: id }, context(wt), cap));
    const raw = seed("tls_exporter_raw"), result = reference.evaluate(raw.domain, input(raw), context(raw), cap);
    expect(new TextDecoder().decode(result.label)).toBe("EXPORTER-flowersec-v4"); expect(result.label.length).toBe(21); expect(result.input.length).toBe(32);
    for (const domain of ["topup_request_digest", "topup_response_digest"]) {
      const vector = seed(domain), args = input(vector), result = reference.evaluate(domain, args, context(vector), cap);
      expect(result.label.length).toBe(0);
      const decoded = reference.syntax.decode(result.input, "", {}, cap); expect(decoded.ok).toBe(true);
      const descriptor = record(reference.domains.get(domain)!.input_schema), part = record(array(descriptor.parts)[0]);
      const schema = string(part.schema_ref), original = reference.wireMap(Object.values(args)[0] as Uint8Array, schema, context(vector), cap);
      if (!decoded.ok || decoded.value.kind !== "map" || original.kind !== "map") throw new Error("projection fixture");
      const excluded = array(part.fields).map(field => reference.namedField(schema, string(field))[0]);
      expect(decoded.value.value.map(([key]) => key)).toEqual(original.value.filter(([key]) => key.kind !== "uint" || !excluded.includes(key.value)).map(([key]) => key));
    }
  });

  // v4.ts_domains.properties
  it("checks 4096 mutations with deterministic results and detached Buffer outputs", () => {
    const positives = corpus.vectors.filter(vector => !vector.expected_error);
    let state = 0x41d04a10;
    const next = (): number => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
    for (let iteration = 0; iteration < 4096; iteration++) {
      const vector = positives[next() % positives.length]!, args = input(vector), ctx = context(vector), key = Object.keys(args)[next() % Object.keys(args).length]!, value = args[key];
      if (value instanceof Uint8Array && value.length) { const at = next() % value.length; value[at] = value[at]! ^ (next() & 255); }
      else if (typeof value === "number" || typeof value === "bigint") args[key] = BigInt(value) ^ BigInt(next());
      else if (typeof value === "string") args[key] = value + "x";
      const saved = structuredClone(args), before = structuredClone(ctx); let result: DomainResult | undefined;
      try { result = reference.evaluate(vector.domain, args, ctx, cap); } catch (error) { assert.ok(error instanceof V4Failure); }
      // Native typed-array comparisons keep the complete corpus bounded under
      // the parallel language gate without reducing mutations or assertions.
      assert.deepStrictEqual(args, saved); assert.deepStrictEqual(ctx, before);
      if (result) {
        assert.deepStrictEqual(reference.evaluate(vector.domain, args, ctx, cap), result);
        const buffers = Object.fromEntries(Object.entries(args).map(([key, value]) => [key, value instanceof Uint8Array ? Buffer.from(value) : value]));
        const detached = reference.evaluate(vector.domain, buffers, ctx, cap), snapshot = structuredClone(detached);
        assert.deepStrictEqual(detached, result); for (const value of Object.values(buffers)) if (value instanceof Uint8Array) value.fill(0);
        assert.deepStrictEqual(detached, snapshot);
      }
    }
  }, 30000);
});
