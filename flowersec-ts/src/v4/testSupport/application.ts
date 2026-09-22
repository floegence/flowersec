// Independent test-only application byte relations over generated definitions.
// Real authentication, channel/serial owners, admission and publication are external.
import { types } from "node:util";
import { transportV4ApplicationHeaders } from "../../generated/transportV4Registry.js";
import { encode, equal } from "./cbor.js";
import type { Value } from "./cbor.js";
import { Domains } from "./domains.js";
import { emptyContext, integer, lookup, record } from "./shape.js";
import { array, string } from "./rules.js";
import { V4Failure } from "./unicode.js";

type Variant = { code: number; fields: readonly number[]; constants?: Readonly<Record<string, number>>; request?: string; sdk_error?: boolean; application_error?: boolean; max_encoded_bytes: number };
export type ApplicationHeader = { kind: string; value: Value; bytes: Uint8Array };
const bytePrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const intrinsic = (name: string): ((this: Uint8Array) => unknown) => Object.getOwnPropertyDescriptor(bytePrototype, name)!.get!;
const byteLength = intrinsic("byteLength"), byteOffset = intrinsic("byteOffset"), byteBuffer = intrinsic("buffer");

// Check the intrinsic brand and length before copying. No caller getters or
// iterator, including shadowed backing byteLength, run during capture.
function capture(input: Uint8Array, cap: bigint): Uint8Array {
  if (types.isProxy(input) || !types.isUint8Array(input) || ![Uint8Array.prototype, Buffer.prototype].includes(Object.getPrototypeOf(input))) throw new V4Failure("application_input_bytes");
  for (const key of ["length", "byteLength", "byteOffset", "buffer"]) if (Object.hasOwn(input, key)) throw new V4Failure("application_input_bytes");
  const length = byteLength.call(input) as number;
  if (BigInt(length) > cap) throw new V4Failure("application_input_size");
  let view: Uint8Array;
  try { view = new Uint8Array(byteBuffer.call(input) as ArrayBuffer, byteOffset.call(input) as number, length); }
  catch { throw new V4Failure("application_input_bytes"); }
  return new Uint8Array(view);
}
function same(left: Value | undefined, right: Value | undefined): boolean {
  if (left === undefined || right === undefined) return left === right;
  return equal(encode(left), encode(right));
}
function unsigned(value: Value): bigint {
  if (value.kind !== "uint") throw new V4Failure("integer_type"); return value.value;
}

export class Application extends Domains {
  readonly application = transportV4ApplicationHeaders;
  readonly kinds: Readonly<Record<string, Variant>> = this.application.kinds;

  private bound(name: string): bigint { return integer(this.descriptor(name).max_encoded_bytes); }
  private rawMap(name: string, input: Uint8Array): Value {
    const bytes = capture(input, this.bound(name));
    return this.wireMap(bytes, name, emptyContext(), this.bound(name));
  }
  private hash(name: string, args: Record<string, unknown>): Uint8Array {
    const output = this.evaluate(name, args, emptyContext(), this.bound("ServiceContract")).output;
    if (!output) throw new V4Failure("registry_unresolved"); return output;
  }
  private headerValue(header: ApplicationHeader, name: string): Value { return this.requiredValue("ApplicationHeader", header.value, name); }
  private headerUint(header: ApplicationHeader, name: string): bigint { return unsigned(this.headerValue(header, name)); }

  header(input: Uint8Array): ApplicationHeader {
    const bytes = capture(input, this.bound("ApplicationHeader"));
    const value = this.wireMap(bytes, "ApplicationHeader", emptyContext(), this.bound("ApplicationHeader"));
    const code = unsigned(this.requiredValue("ApplicationHeader", value, "message_kind"));
    const entry = Object.entries(this.kinds).find(([, variant]) => BigInt(variant.code) === code);
    if (!entry) throw new V4Failure("application_kind");
    const [kind, variant] = entry;
    if (value.kind !== "map" || value.value.length !== variant.fields.length || variant.fields.some(id => lookup(value, BigInt(id)) === undefined)) throw new V4Failure("application_fields");
    for (const [id, expected] of Object.entries(variant.constants ?? {})) {
      const actual = lookup(value, BigInt(id));
      if (!actual || actual.kind !== "uint" || actual.value !== BigInt(expected)) throw new V4Failure("application_constant");
    }
    const result = { kind, value, bytes };
    if (variant.sdk_error && this.headerUint(result, "payload_length") > this.bound(this.application.sdk_errors.payload_schema)) throw new V4Failure("application_sdk_error_limit");
    return result;
  }

  response(original: Uint8Array, input: Uint8Array): ApplicationHeader {
    const request = this.header(original), result = this.header(input), variant = this.kinds[result.kind]!;
    if (variant.request !== request.kind) throw new V4Failure("application_response_kind");
    for (const name of ["operation_id", "type_id", "request_digest", "service_contract_digest", "control_serial"]) {
      if (!same(this.namedValue("ApplicationHeader", request.value, name), this.namedValue("ApplicationHeader", result.value, name))) throw new V4Failure("application_response_binding");
    }
    const limit = this.namedValue("ApplicationHeader", request.value, "response_limit_bytes");
    if (limit && !variant.sdk_error && this.headerUint(result, "payload_length") > unsigned(limit)) throw new V4Failure("application_response_limit");
    return result;
  }

  private contract(header: ApplicationHeader, requestKind: string, input: Uint8Array): { bytes: Uint8Array; value: Value } {
    const bytes = capture(input, this.bound("ServiceContract")), value = this.rawMap("ServiceContract", bytes);
    const digest = this.headerValue(header, "service_contract_digest");
    if (digest.kind !== "bytes" || !equal(digest.value, this.hash("service_contract_digest", { contract: bytes })) || !same(this.headerValue(header, "type_id"), this.requiredValue("ServiceContract", value, "type_id"))) throw new V4Failure("application_contract_binding");
    const shape = record(this.application.policy.contract_variants)[requestKind];
    if (!shape) throw new V4Failure("application_contract_variant");
    for (const [id, expected] of Object.entries(record(shape))) {
      const actual = lookup(value, BigInt(id));
      if (!actual || actual.kind !== "uint" || actual.value !== integer(expected)) throw new V4Failure("application_contract_variant");
    }
    return { bytes, value };
  }

  executionDigest(input: Uint8Array, contractInput: Uint8Array, payloadInput: Uint8Array): Uint8Array {
    const header = this.header(input);
    if (!(this.application.policy.execution_requests as readonly string[]).includes(header.kind)) throw new V4Failure("application_execution_request");
    const contract = this.contract(header, header.kind, contractInput);
    const payload = capture(payloadInput, integer(this.namedField("ApplicationHeader", "payload_length")[1].max));
    if (BigInt(payload.length) !== this.headerUint(header, "payload_length")) throw new V4Failure("application_payload_length");
    if (BigInt(payload.length) > unsigned(this.requiredValue("ServiceContract", contract.value, "request_max_bytes"))) throw new V4Failure("application_request_limit");
    const limit = this.headerUint(header, "response_limit_bytes");
    if (limit < unsigned(this.requiredValue("ServiceContract", contract.value, "min_response_limit_bytes")) || limit > unsigned(this.requiredValue("ServiceContract", contract.value, "max_response_bytes"))) throw new V4Failure("application_response_limit");
    const args: Record<string, unknown> = { contract: contract.bytes, payload };
    for (const name of ["message_kind", "operation_id", "type_id", "deadline_at_ms", "admission_mode", "response_limit_bytes"]) {
      const value = this.headerValue(header, name);
      if (value.kind !== "uint" && value.kind !== "bytes") throw new V4Failure("field_type"); args[name] = value.value;
    }
    return this.hash("execution_request_digest", args);
  }

  verifyExecution(input: Uint8Array, contract: Uint8Array, payload: Uint8Array): void {
    const header = this.header(input), expected = this.executionDigest(header.bytes, contract, payload);
    const digest = this.headerValue(header, "request_digest");
    if (digest.kind !== "bytes" || !equal(digest.value, expected)) throw new V4Failure("application_request_digest");
  }

  matchErrorSchema(definition: Uint8Array, registeredBytes: Uint8Array): void {
    const value = this.rawMap("ErrorDefinition", definition), domain = this.domains.get("business_error_schema_digest");
    if (!domain) throw new V4Failure("registry_unresolved");
    const part = record(array(record(domain.input_schema).parts)[0]);
    const bytes = capture(registeredBytes, integer(part.max_length)), expected = this.requiredValue("ErrorDefinition", value, "schema_digest");
    if (expected.kind !== "bytes" || !equal(expected.value, this.hash(string(domain.name), { error_schema: bytes }))) throw new V4Failure("application_error_schema_mismatch");
  }

  matchErrorCatalog(input: Uint8Array, definitions: readonly Uint8Array[]): void {
    const contract = this.rawMap("ServiceContract", input), [, field] = this.namedField("ServiceContract", "application_error_catalog");
    if (BigInt(definitions.length) > integer(field.max_items)) throw new V4Failure("application_error_catalog_size");
    const catalog = this.requiredValue("ServiceContract", contract, "application_error_catalog");
    if (catalog.kind !== "array") throw new V4Failure("field_type");
    if (catalog.value.length !== definitions.length) throw new V4Failure("application_error_catalog_mismatch");
    for (let i = 0; i < definitions.length; i++) if (!same(catalog.value[i], this.rawMap("ErrorDefinition", definitions[i]!))) throw new V4Failure("application_error_catalog_mismatch");
  }

  businessError(original: Uint8Array, input: Uint8Array, contractInput: Uint8Array, payloadInput: Uint8Array): Readonly<{ classification: string; code: bigint }> {
    const header = this.response(original, input), variant = this.kinds[header.kind]!;
    if (!variant.application_error || !variant.request) throw new V4Failure("application_error_kind");
    const contract = this.contract(header, variant.request, contractInput);
    const payload = capture(payloadInput, this.headerUint(header, "payload_length"));
    if (BigInt(payload.length) !== this.headerUint(header, "payload_length")) throw new V4Failure("application_payload_length");
    const code = this.headerUint(header, "application_error_code"), catalog = this.requiredValue("ServiceContract", contract.value, "application_error_catalog");
    if (catalog.kind !== "array") throw new V4Failure("field_type");
    const definition = catalog.value.find(entry => unsigned(this.requiredValue("ErrorDefinition", entry, "code")) === code);
    const classification = !definition ? "unknown_application_error" : BigInt(payload.length) > unsigned(this.requiredValue("ErrorDefinition", definition, "max_payload_bytes")) ? "application_result_decode_failed" : "known_application_error";
    // Classification does not run a codec, retain a payload or grant a retry.
    return Object.freeze({ classification, code });
  }

  sdkError(original: Uint8Array, input: Uint8Array, payloadInput: Uint8Array): Readonly<{ code: string }> {
    const header = this.response(original, input);
    if (!this.kinds[header.kind]!.sdk_error) throw new V4Failure("application_sdk_error_kind");
    const name = this.application.sdk_errors.payload_schema, payload = capture(payloadInput, this.bound(name));
    if (BigInt(payload.length) !== this.headerUint(header, "payload_length")) throw new V4Failure("application_payload_length");
    const value = this.rawMap(name, payload), code = unsigned(this.requiredValue(name, value, "code"));
    const entry = Object.entries(this.application.sdk_error_codes).find(([, candidate]) => BigInt(candidate) === code);
    if (!entry) throw new V4Failure("application_sdk_error_code");
    const stream = ["execution_stream_sdk_error", "transient_stream_sdk_error"].includes(header.kind);
    if (stream && ["request_message_aborted", "response_output_stopped"].includes(entry[0])) throw new V4Failure("streaming_sdk_error_code");
    if (!stream && entry[0] === "source_overflow") throw new V4Failure("application_sdk_error_code");
    // An incomplete request echoes its declared digest without proving it.
    return Object.freeze({ code: entry[0] });
  }
}
