import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4Registry } from "../generated/transportV4Registry.js";
import { Application } from "./testSupport/application.js";
import { encode, uint } from "./testSupport/cbor.js";
import type { Value } from "./testSupport/cbor.js";
import { emptyContext } from "./testSupport/shape.js";
import { hex } from "./testSupport/rules.js";
import { root, V4Failure } from "./testSupport/unicode.js";

type Vector = { id: string; hex: string; kind?: string; accept?: boolean; expected_error?: string };
type Corpus = { schema_sha256: string; schema_revision: string; vectors: Vector[] };
const load = (path: string): Corpus => JSON.parse(readFileSync(new URL(`testdata/transport_v4/${path}.json`, root), "utf8")) as Corpus;
const corpus = load("application_headers"), maps = load("corpus"), r = new Application();
const bstr = (value: Uint8Array): Value => ({ kind: "bytes", value });
const field = (name: string, value: Value, key: string): Value => r.requiredValue(name, value, key);
const read = (name: string, input: Uint8Array): Value => r.wireMap(input, name, emptyContext(), 8192n);
const seed = (id: string): Uint8Array => hex(maps.vectors.find(v => v.id === id)!.hex);
const maximum = (kind: string): Value => r.header(hex(corpus.vectors.find(v => v.kind === kind && v.accept)!.hex)).value;
function change(name: string, value: Value, key: string, replacement?: Value): Value {
  if (value.kind !== "map") throw new Error("map fixture");
  const id = r.namedField(name, key)[0], fields = value.value.filter(([key]) => key.kind !== "uint" || key.value !== id);
  if (replacement) fields.push([uint(id), replacement]);
  fields.sort(([a], [b]) => a.kind === "uint" && b.kind === "uint" ? a.value < b.value ? -1 : a.value > b.value ? 1 : 0 : 0);
  return { kind: "map", value: fields };
}
const hset = (value: Value, key: string, replacement?: Value): Value => change("ApplicationHeader", value, key, replacement);
function fail(operation: () => unknown, code?: string): void {
  let caught: unknown; try { operation(); } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(V4Failure); if (code) expect((caught as V4Failure).code).toBe(code);
}
function digest(name: string, args: Record<string, unknown>): Uint8Array {
  return r.evaluate(name, args, emptyContext(), 8192n).output!;
}
function pair(requestKind: string, responseKind: string, length = 0n, limit = 0n): { request: Value; response: Value } {
  let request = maximum(requestKind), response = maximum(responseKind);
  if (r.namedValue("ApplicationHeader", request, "response_limit_bytes")) request = hset(request, "response_limit_bytes", uint(limit));
  response = hset(response, "payload_length", uint(length));
  return { request, response };
}
function execution(kind: string, payload = Uint8Array.of(1, 2, 3)): { header: Value; contract: Uint8Array; payload: Uint8Array } {
  const suffix = kind === "execution_notify" ? "notify_execution" : kind === "execution_stream_request" ? "stream_execution" : "unary_execution";
  const contract = seed(`service_${suffix}`), definition = read("ServiceContract", contract);
  let header = maximum(kind);
  for (const [key, value] of [
    ["type_id", field("ServiceContract", definition, "type_id")], ["payload_length", uint(BigInt(payload.length))],
    ["service_contract_digest", bstr(digest("service_contract_digest", { contract }))],
    ["response_limit_bytes", field("ServiceContract", definition, "max_response_bytes")],
  ] as const) header = hset(header, key, value);
  header = hset(header, "request_digest", bstr(r.executionDigest(encode(header), contract, payload)));
  return { header, contract, payload };
}

describe("v4.ts_application", () => {
  // v4.ts_application.corpus
  it("independently consumes every exact header and malformed shared candidate", () => {
    expect(maps.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    expect(corpus.schema_revision).toBe(maps.schema_revision);
    expect(corpus.vectors).toHaveLength(589);
    const kinds = new Set<string>(); let rejected = 0;
    for (const v of corpus.vectors) {
      const bytes = hex(v.hex);
      if (v.accept) {
        const result = r.header(bytes); kinds.add(result.kind);
        expect(result.kind, v.id).toBe(v.kind); expect(encode(result.value), v.id).toEqual(bytes);
        expect(bytes.length, v.id).toBe(r.kinds[result.kind]!.max_encoded_bytes);
      } else { rejected++; fail(() => r.header(bytes), v.expected_error?.startsWith("application_") ? v.expected_error : undefined); }
    }
    expect([...kinds].sort()).toEqual(Object.keys(r.kinds).sort()); expect(rejected).toBe(558);
    fail(() => r.header(encode(hset(maximum("execution_notify"), "response_limit_bytes", uint(1n)))), "application_constant");
  });

  // v4.ts_application.response_binding
  it("uses original request kind, identifiers and limits for every response variant", () => {
    for (const [kind, variant] of Object.entries(r.kinds).filter(([, v]) => v.request)) {
      const p = pair(variant.request!, kind); r.response(encode(p.request), encode(p.response));
      for (const name of ["operation_id", "type_id", "request_digest", "service_contract_digest", "control_serial"]) {
        const value = r.namedValue("ApplicationHeader", p.response, name); if (!value) continue;
        const replacement = value.kind === "uint" ? uint(value.value - 1n) : bstr(new Uint8Array(32).fill(7));
        fail(() => r.response(encode(p.request), encode(hset(p.response, name, replacement))), "application_response_binding");
      }
      for (const name of ["deadline_at_ms", "admission_mode", "response_limit_bytes"]) for (const n of [0n, 1n]) fail(() => r.response(encode(p.request), encode(hset(p.response, name, uint(n)))), "application_fields");
      for (const [other, otherVariant] of Object.entries(r.kinds).filter(([other, v]) => !v.request && other !== variant.request)) {
        let request = maximum(other);
        if (otherVariant.fields.includes(Number(r.namedField("ApplicationHeader", "response_limit_bytes")[0]))) request = hset(request, "response_limit_bytes", uint(0n));
        fail(() => r.response(encode(request), encode(p.response)), "application_response_kind");
      }
    }
  });

  // v4.ts_application.execution_digest
  it("binds full execution bytes, exact contract variant, limits and immutable options", () => {
    for (const kind of r.application.policy.execution_requests) {
      const p = execution(kind), raw = encode(p.header); r.verifyExecution(raw, p.contract, p.payload);
      for (const [key, value] of [["deadline_at_ms", uint(17n)], ["admission_mode", uint(0n)], ["operation_id", bstr(new Uint8Array(32))]] as const) fail(() => r.verifyExecution(encode(hset(p.header, key, value)), p.contract, p.payload), "application_request_digest");
      fail(() => r.verifyExecution(raw, p.contract, Uint8Array.of(1, 2, 4)), "application_request_digest");
      fail(() => r.verifyExecution(raw, p.contract, new Uint8Array()), "application_payload_length");
      fail(() => r.executionDigest(encode(hset(p.header, "type_id", uint(900n))), p.contract, p.payload), "application_contract_binding");
      const contract = change("ServiceContract", read("ServiceContract", p.contract), "request_schema_revision", { kind: "text", value: "changed" }), changed = encode(contract);
      fail(() => r.verifyExecution(raw, changed, p.payload), "application_contract_binding");
      const rebound = hset(p.header, "service_contract_digest", bstr(digest("service_contract_digest", { contract: changed })));
      fail(() => r.verifyExecution(encode(rebound), changed, p.payload), "application_request_digest");
    }
    const p = execution("execution_unary_request");
    fail(() => r.executionDigest(encode(hset(p.header, "message_kind", uint(BigInt(r.kinds.execution_stream_request!.code)))), p.contract, p.payload), "application_contract_variant");
    for (const kind of Object.keys(r.kinds).filter(kind => !(r.application.policy.execution_requests as readonly string[]).includes(kind))) fail(() => r.executionDigest(encode(maximum(kind)), p.contract, p.payload), "application_execution_request");
    const small = encode(change("ServiceContract", read("ServiceContract", p.contract), "request_max_bytes", uint(2n)));
    fail(() => r.executionDigest(encode(hset(p.header, "service_contract_digest", bstr(digest("service_contract_digest", { contract: small })))), small, p.payload), "application_request_limit");
    const limited = encode(change("ServiceContract", change("ServiceContract", read("ServiceContract", p.contract), "max_response_bytes", uint(2n)), "min_response_limit_bytes", uint(1n)));
    const limitedHeader = hset(p.header, "service_contract_digest", bstr(digest("service_contract_digest", { contract: limited })));
    for (const n of [0n, 3n]) fail(() => r.executionDigest(encode(hset(limitedHeader, "response_limit_bytes", uint(n))), limited, p.payload), "application_response_limit");
    for (const length of [0, 1048576]) {
      const boundary = execution("execution_unary_request", new Uint8Array(length));
      r.verifyExecution(encode(boundary.header), boundary.contract, boundary.payload);
    }
  });

  // v4.ts_application.sdk_stop
  it("preserves the fixed small-error reservation and never synthesizes execution facts", () => {
    for (const [kind, variant] of Object.entries(r.kinds).filter(([, v]) => v.sdk_error)) for (const [label, code] of Object.entries(r.application.sdk_error_codes)) {
      const body = encode(r.namedMap(r.application.sdk_errors.payload_schema, [["code", uint(BigInt(code))]]));
      const p = pair(variant.request!, kind, BigInt(body.length)), request = encode(p.request), response = encode(p.response);
      const stream = ["execution_stream_sdk_error", "transient_stream_sdk_error"].includes(kind);
      if (stream && ["request_message_aborted", "response_output_stopped"].includes(label)) {
        fail(() => r.sdkError(request, response, body), "streaming_sdk_error_code"); continue;
      }
      if (!stream && label === "source_overflow") {
        fail(() => r.sdkError(request, response, body), "application_sdk_error_code"); continue;
      }
      const result = r.sdkError(request, response, body); expect(result).toEqual({ code: label }); expect(Object.isFrozen(result)).toBe(true);
      expect(Object.keys(result)).toEqual(["code"]);
      for (const length of [0n, 1n, 255n, 256n]) r.response(request, encode(hset(p.response, "payload_length", uint(length))));
      fail(() => r.response(request, encode(hset(p.response, "payload_length", uint(257n)))), "application_sdk_error_limit");
      fail(() => r.sdkError(request, response, new Uint8Array(257)), "application_input_size");
      fail(() => r.sdkError(request, response, body.subarray(0, -1)), "application_payload_length");
      for (const raw of ["a10000", "a10019ffff", "a0", "a200010100", "a200010001", "a1180001", "a1000100", "a100"]) {
        const invalid = hex(raw); fail(() => r.sdkError(request, encode(hset(p.response, "payload_length", uint(BigInt(invalid.length)))), invalid));
      }
      if (r.namedValue("ApplicationHeader", p.request, "response_limit_bytes")) {
        for (const [other, descriptor] of Object.entries(r.kinds).filter(([, v]) => v.request === variant.request && !v.sdk_error)) {
          const alternate = pair(variant.request!, other, 1n); expect(descriptor.sdk_error).toBeUndefined();
          fail(() => r.response(encode(alternate.request), encode(alternate.response)), "application_response_limit");
        }
      }
    }
    const p = pair("transient_unary_request", "transient_unary_response");
    fail(() => r.sdkError(encode(p.request), encode(p.response), new Uint8Array()), "application_sdk_error_kind");
  });

  // v4.ts_application.business_errors
  it("matches exact local catalog bytes and classifies only within the original business limit", () => {
    const schema = hex("a10001"), definition = r.namedMap("ErrorDefinition", [["code", uint(12345n)], ["schema_revision", { kind: "text", value: "error-1" }], ["max_payload_bytes", uint(2n)], ["schema_digest", bstr(digest("business_error_schema_digest", { error_schema: schema }))]]), definitionBytes = encode(definition);
    r.matchErrorSchema(definitionBytes, schema);
    fail(() => r.matchErrorSchema(definitionBytes, hex("a0")), "application_error_schema_mismatch");
    fail(() => r.matchErrorSchema(definitionBytes, new Uint8Array(8193)), "application_input_size");
    for (const semantics of ["execution", "transient"]) for (const shape of ["unary", "stream"]) {
      const contract = encode(change("ServiceContract", read("ServiceContract", seed(`service_${shape}_${semantics}`)), "application_error_catalog", { kind: "array", value: [definition] }));
      r.matchErrorCatalog(contract, [definitionBytes]);
      fail(() => r.matchErrorCatalog(contract, []), "application_error_catalog_mismatch");
      fail(() => r.matchErrorCatalog(contract, Array<Uint8Array>(65).fill(definitionBytes)), "application_error_catalog_size");
      for (const [key, value] of [["code", uint(12346n)], ["schema_revision", { kind: "text", value: "error-2" }], ["max_payload_bytes", uint(3n)], ["schema_digest", bstr(new Uint8Array(32))]] as const) fail(() => r.matchErrorCatalog(contract, [encode(change("ErrorDefinition", definition, key, value))]), "application_error_catalog_mismatch");
      const p = pair(`${semantics}_${shape}_request`, `${semantics}_${shape}_application_error`, 2n, 4n);
      for (const side of ["request", "response"] as const) {
        p[side] = hset(p[side], "service_contract_digest", bstr(digest("service_contract_digest", { contract })));
        p[side] = hset(p[side], "type_id", field("ServiceContract", read("ServiceContract", contract), "type_id"));
      }
      const classify = (length: number, code: bigint) => r.businessError(encode(p.request), encode(hset(hset(p.response, "payload_length", uint(BigInt(length))), "application_error_code", uint(code))), contract, new Uint8Array(length));
      expect(classify(2, 12345n)).toEqual({ classification: "known_application_error", code: 12345n });
      expect(classify(3, 12345n)).toEqual({ classification: "application_result_decode_failed", code: 12345n });
      expect(classify(3, 0xffffffffn)).toEqual({ classification: "unknown_application_error", code: 0xffffffffn });
      const valid = hset(p.response, "application_error_code", uint(12345n));
      fail(() => r.businessError(encode(p.request), encode(valid), contract, new Uint8Array(1)), "application_payload_length");
      fail(() => r.businessError(encode(p.request), encode(valid), contract, new Uint8Array(3)), "application_input_size");
      fail(() => classify(5, 12345n), "application_response_limit");
      p.request = hset(p.request, "response_limit_bytes", uint(0n));
      expect(Object.isFrozen(classify(0, 12345n))).toBe(true); fail(() => classify(1, 12345n), "application_response_limit");
    }
  });

  // v4.ts_application.ownership
  it("bounds copies and owns outputs without executing input metadata getters", () => {
    const p = execution("execution_unary_request"), header = encode(p.header), before = new Uint8Array(header);
    const parsed = r.header(Buffer.from(header)); parsed.bytes.fill(0); expect(header).toEqual(before);
    const source = Buffer.from(header), decoded = r.header(source); source.fill(0); expect(encode(decoded.value)).toEqual(before);
    fail(() => r.header(new Uint8Array(513)), "application_input_size");
    fail(() => r.executionDigest(header, new Uint8Array(8193), p.payload), "application_input_size");
    fail(() => r.executionDigest(header, p.contract, new Uint8Array(1048577)), "application_input_size");
    let traps = 0;
    const proxy = new Proxy(header, { get() { traps++; throw new Error("input trap"); }, getPrototypeOf() { traps++; throw new Error("input trap"); } });
    const revoked = Proxy.revocable(header, {}); revoked.revoke();
    for (const input of [proxy, revoked.proxy]) fail(() => r.header(input), "application_input_bytes");
    const detached = new Uint8Array(header); structuredClone(detached, { transfer: [detached.buffer] });
    fail(() => r.header(detached), "application_input_bytes");
    for (const key of ["length", "byteLength", "byteOffset", "buffer"]) {
      const input = new Uint8Array(header); Object.defineProperty(input, key, { get() { traps++; throw new Error("metadata trap"); } });
      fail(() => r.header(input), "application_input_bytes");
    }
    const backing = new ArrayBuffer(header.length + 4), input = new Uint8Array(backing, 2, header.length); input.set(header);
    Object.defineProperty(backing, "byteLength", { get() { traps++; throw new Error("backing trap"); } });
    expect(r.header(input).bytes).toEqual(header); expect(traps).toBe(0);
  });

  // v4.ts_application.properties
  // Allow the bounded corpus to finish alongside the other language gates.
  it("keeps mutated header validation deterministic and detached across 4096 cases", () => {
    const positives = corpus.vectors.filter(v => v.accept); let state = 0x235ba919;
    const next = (): number => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
    for (let i = 0; i < 4096; i++) {
      const raw = hex(positives[next() % positives.length]!.hex); raw[next() % raw.length]! ^= 1 << (next() % 8);
      const before = new Uint8Array(raw);
      const result = (): string => { try { const decoded = r.header(raw); expect(encode(decoded.value)).toEqual(before); decoded.bytes.fill(0); return decoded.kind; } catch (error) { expect(error).toBeInstanceOf(V4Failure); return `error:${(error as V4Failure).code}`; } };
      expect(result()).toBe(result()); expect(raw).toEqual(before);
    }
  }, 15_000);
});
