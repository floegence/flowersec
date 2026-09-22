// Reference tooling for draft vectors. This is not a production SDK codec.
// Text uses pinned Unicode 15.1 NFC; parsing never normalizes received bytes.
import { TextDecoder, isDeepStrictEqual } from "node:util";
import { assigned151, normalizeNFC151 } from "./transport-v4-unicode.mjs";
import { HostValidationError, validateWireHost151, validateWireLoopbackHost151 } from "./transport-v4-host.mjs";
import { IDNAValidationError } from "./transport-v4-idna.mjs";
import { OriginValidationError, validateWireOrigin } from "./transport-v4-origin.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";

const UINT64_MAX = (1n << 64n) - 1n;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class VectorError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = (code) => { throw new VectorError(code); };
const requireThat = (condition, code) => { if (!condition) fail(code); };
export const textFormats = {host:validateWireHost151, loopback_host:validateWireLoopbackHost151, origin:validateWireOrigin};

function validateTextFormat(format, item, schema) {
  requireThat(Object.hasOwn(textFormats, format), "text_format_unresolved");
  try { textFormats[format](item, schema); }
  catch (error) {
    if (error instanceof HostValidationError || error instanceof IDNAValidationError || error instanceof OriginValidationError) fail(error.message);
    throw error;
  }
}

function validateText(value) {
  for (const character of value) requireThat(assigned151(character.codePointAt(0)),"unassigned_code_point");
  requireThat(normalizeNFC151(value) === value,"non_canonical_text");
}

export function strictHex(value) {
  requireThat(typeof value === "string" && /^(?:[0-9a-fA-F]{2})*$/u.test(value), "invalid_hex");
  return Buffer.from(value, "hex");
}

function unsigned(value) {
  if (typeof value === "number") requireThat(Number.isSafeInteger(value), "unsafe_integer");
  requireThat(typeof value === "number" || typeof value === "bigint", "integer_type");
  const n = BigInt(value);
  requireThat(n >= 0n && n <= UINT64_MAX, "integer_range");
  return n;
}

export function cborHead(major, value) {
  const n = unsigned(value);
  if (n < 24n) return Buffer.from([major * 32 + Number(n)]);
  const size = n <= 0xffn ? 1 : n <= 0xffffn ? 2 : n <= 0xffffffffn ? 4 : 8;
  const out = Buffer.alloc(size + 1);
  out[0] = major * 32 + ({1:24, 2:25, 4:26, 8:27})[size];
  if (size === 8) out.writeBigUInt64BE(n, 1);
  else out.writeUIntBE(Number(n), 1, size);
  return out;
}

const head = cborHead;
const compareKeys = (left, right) => left.length - right.length || Buffer.compare(left, right);

export function encodeCBOR(value, depth = 0) {
  return encodeValue(value, depth);
}

// Nullable positions are declared by the exact map schema. The schema-free
// encoder retains its strict grammar and cannot produce a null sentinel.
export function encodeMap(schema, name, value, limits = {}) {
  requireThat(schema?.frame_maps?.[name] !== undefined, "unknown_schema");
  return encodeValue(value, 0, schema, {type:"map", schema_ref:name}, limits);
}

function externalLimit(limits, name, maximum = Number.MAX_SAFE_INTEGER, minimum = 1) {
  const value = limits[name];
  requireThat(Number.isSafeInteger(value) && value >= minimum && value <= maximum, "limit_unresolved");
  return value;
}

function arrayLimit(field, limits) {
  return field?.max_items_ref === undefined ? field?.max_items ?? 1035 : externalLimit(limits, field.max_items_ref, 0xffffffff, 0);
}

function encodeValue(value, depth, schema, descriptor, limits = {}) {
  requireThat(depth <= 8, "depth_limit");
  if (value === null) {
    requireThat(descriptor?.type === "uint64" && descriptor.nullable === true, "unsupported_type");
    return Buffer.from([0xf6]);
  }
  if (typeof value === "number" || typeof value === "bigint") return head(0, value);
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "string") {
    validateText(value);
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) {
    requireThat(value.length <= (descriptor?.max_items_ref === undefined ? 1035 : arrayLimit(descriptor,limits)), "array_limit");
    return Buffer.concat([head(4, value.length), ...value.map((v) => encodeValue(v, depth + 1, schema, descriptor?.items, limits))]);
  }
  requireThat(value instanceof Map, "unsupported_type");
  requireThat(value.size <= 128, "map_limit");
  if (value.size > 0 && typeof value.keys().next().value === "string") {
    const pairs = [...value].map(([key, item]) => {
      requireThat(typeof key === "string", "field_id_type");
      return [encodeCBOR(key, depth + 1), item, key];
    }).sort(([left], [right]) => compareKeys(left, right));
    return Buffer.concat([head(5, pairs.length), ...pairs.flatMap(([key, item, fieldName]) => {
      return [key, encodeValue(item, depth + 1, schema, descriptor?.entries?.[fieldName] ?? descriptor?.values, limits)];
    })]);
  }
  const pairs = [...value].map(([k, v]) => [unsigned(k), v]).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  let previous = -1n;
  for (const [key] of pairs) {
    requireThat(key <= 65535n, "field_id_range");
    requireThat(key !== previous, "duplicate_key");
    previous = key;
  }
  const fields = schema?.frame_maps?.[descriptor?.schema_ref]?.fields;
  return Buffer.concat([head(5, pairs.length), ...pairs.flatMap(([k, v]) => [head(0, k), encodeValue(v, depth + 1, schema, fields?.[k.toString()], limits)])]);
}

export function decodeCBOR(input, {schema, name, limits = {}} = {}) {
  // Inspect intrinsic byte metadata and the root bound before copying input.
  const view = referenceByteView(input);
  const root = schema?.frame_maps?.[name];
  if (root?.max_encoded_bytes !== undefined) requireThat(view.length <= root.max_encoded_bytes,"map_size");
  if (root?.max_encoded_bytes_ref !== undefined) requireThat(view.length <= externalLimit(limits,root.max_encoded_bytes_ref),"map_size");
  const bytes = Buffer.from(view);
  let cursor = 0;
  function take(n) {
    requireThat(n <= bytes.length - cursor, "truncated");
    const result = bytes.subarray(cursor, cursor + n); cursor += n; return result;
  }
  function item(depth, descriptor) {
    requireThat(depth <= 8, "depth_limit");
    const initial = take(1)[0], major = initial >> 5, ai = initial & 31;
    requireThat(ai !== 31, "indefinite_length");
    if (major === 7 && (ai === 20 || ai === 21)) return ai === 21;
    if (major === 7 && ai === 22) {
      requireThat(descriptor?.type === "uint64" && descriptor.nullable === true, "unsupported_type");
      return null;
    }
    requireThat([0, 2, 3, 4, 5].includes(major), "unsupported_type");
    requireThat(ai <= 27, "invalid_header");
    let n = BigInt(ai);
    if (ai >= 24) {
      const size = 2 ** (ai - 24), raw = take(size);
      n = size === 8 ? raw.readBigUInt64BE() : BigInt(raw.readUIntBE(0, size));
      requireThat(n >= ({1:24n, 2:256n, 4:65536n, 8:4294967296n})[size], "non_shortest_integer");
    }
    if (major === 0) return n;
    if (major === 2 || major === 3) {
      requireThat(n <= BigInt(bytes.length - cursor), "truncated");
      const raw = take(Number(n));
      if (major === 2) return raw;
      let value;
      try { value = utf8.decode(raw); } catch { fail("invalid_utf8"); }
      validateText(value);
      return value;
    }
    const itemLimit = major === 5 ? 128 : descriptor?.max_items_ref === undefined ? 1035 : arrayLimit(descriptor,limits);
    requireThat(n <= BigInt(itemLimit), major === 5 ? "map_limit" : "array_limit");
    if (major === 4) {
      // Every item consumes at least one byte. Reject a forged count before
      // Array.from allocates slots, including within a capacity-bound array.
      requireThat(n <= BigInt(bytes.length - cursor), "truncated");
      return Array.from({length:Number(n)}, () => item(depth + 1, descriptor?.items));
    }
    const fields = schema?.frame_maps?.[descriptor?.schema_ref]?.fields;
    const textMap = descriptor?.type === "text_map";
    const result = new Map(); let previous;
    for (let i = 0; i < Number(n); i++) {
      const start = cursor;
      const key = item(depth + 1);
      requireThat(textMap ? typeof key === "string" : typeof key === "bigint" && key <= 65535n, "field_id_type");
      const encodedKey = bytes.subarray(start, cursor);
      requireThat(!result.has(key), "duplicate_key");
      requireThat(previous === undefined || compareKeys(previous, encodedKey) < 0, "map_order");
      previous = encodedKey;
      const child = textMap ? (descriptor.entries && Object.hasOwn(descriptor.entries,key) ? descriptor.entries[key] : descriptor.values) : fields?.[key.toString()];
      result.set(key, item(depth + 1, child));
    }
    return result;
  }
  // Text keys are admitted only at a schema-declared application map. Fixed
  // maps and schema-free decoding retain strict integer field IDs.
  const value = item(0, name === undefined ? undefined : {type:"map",schema_ref:name});
  requireThat(cursor === bytes.length, "trailing_bytes");
  return value;
}

function resolveField(field, limits) {
  if (field.type !== "context_variant") return field;
  requireThat(typeof limits[field.context] === "string" && Object.hasOwn(field.cases, limits[field.context]), "context_unresolved");
  return field.cases[limits[field.context]];
}

// A containing signed map supplies context for its nested descriptors. An
// external caller cannot override the discriminator carried by that map.
function mapContext(definition, value, limits, named = false) {
  const context = {...limits};
  for (const [key, fieldName] of Object.entries(definition.context_fields ?? {})) {
    const field = Object.entries(definition.fields).find(([, item]) => item.name === fieldName);
    requireThat(field !== undefined && field[1].enum !== undefined, "context_unresolved");
    const input = named ? value[fieldName] : value.get(BigInt(field[0]));
    requireThat(input !== undefined, "missing_field");
    const ordinal = unsigned(named && input && Object.hasOwn(input, "$uint") ? BigInt(input.$uint) : input);
    const label = Object.entries(field[1].enum).find(([, code]) => BigInt(code) === ordinal)?.[0];
    requireThat(label !== undefined, "enum_value");
    context[key] = label;
  }
  return context;
}

export function mapFromNames(schema, name, values, limits = {}) {
  const fields = schema.frame_maps[name]?.fields;
  requireThat(fields !== undefined, "unknown_schema");
  limits = mapContext(schema.frame_maps[name], values, limits, true);
  const out = new Map();
  for (const [fieldName, value] of Object.entries(values)) {
    const field = Object.entries(fields).find(([, f]) => f.name === fieldName);
    requireThat(field !== undefined, "unknown_field");
    const [id, f] = field;
    const convert = (definition, input) => {
      if (input && Object.hasOwn(input, "$uint")) return BigInt(input.$uint);
      if (input && Object.hasOwn(input, "$bytes")) return strictHex(input.$bytes);
      const resolved = resolveField(definition, limits);
      if (input && Object.hasOwn(input, "$cbor")) {
        requireThat(resolved.encoded_schema_ref !== undefined, "unknown_schema");
        return encodeCBOR(mapFromNames(schema, resolved.encoded_schema_ref, input.$cbor, limits));
      }
      if (resolved.type === "map") return mapFromNames(schema, resolved.schema_ref, input, limits);
      if (resolved.type === "text_map" && input && typeof input === "object" && !Array.isArray(input)) {
        return new Map(Object.entries(input).map(([key, item]) => [key, convert(resolved.entries?.[key] ?? resolved.values ?? {type:"bytes"}, item)]));
      }
      if (Array.isArray(input)) return input.map((x) => convert(resolved.items ?? {type:"uint64"}, x));
      return input;
    };
    const v = convert(f, value);
    out.set(BigInt(id), v);
  }
  return out;
}

// Projection field membership belongs to the registry. Nested signed values
// retain their original representation; only the destination field IDs change.
export function projectMap(schema, projectionName, value, limits = {}) {
  requireThat(Object.hasOwn(schema.map_projections,projectionName), "projection_unresolved");
  const projection=schema.map_projections[projectionName];
  validateMap(schema,projection.source,value,limits);
  const source=schema.frame_maps[projection.source], target=schema.frame_maps[projection.target], output=new Map();
  for (const name of projection.fields) {
    const from=BigInt(Object.entries(source.fields).find(([,field])=>field.name===name)[0]);
    const to=BigInt(Object.entries(target.fields).find(([,field])=>field.name===name)[0]);
    if (value.has(from)) output.set(to,value.get(from));
  }
  return validateMap(schema,projection.target,output,limits);
}

// The encoded entry point checks the complete object cap before parsing it.
// Neither this reference tool nor its vectors qualify SDK allocation behavior.
export function decodeMap(schema, name, bytes, limits = {}) {
  const definition = schema.frame_maps[name];
  requireThat(definition !== undefined, "unknown_schema");
  const view = referenceByteView(bytes);
  if (definition.max_encoded_bytes !== undefined) requireThat(view.length <= definition.max_encoded_bytes, "map_size");
  if (definition.max_encoded_bytes_ref !== undefined) requireThat(view.length <= externalLimit(limits,definition.max_encoded_bytes_ref), "map_size");
  if (definition.encoded_bytes !== undefined) requireThat(view.length === definition.encoded_bytes, "map_size");
  return validateMap(schema, name, decodeCBOR(view, {schema,name,limits}), limits);
}

export function validateMap(schema, name, value, limits = {}) {
  const definition = schema.frame_maps[name];
  requireThat(definition !== undefined, "unknown_schema");
  requireThat(value instanceof Map, "map_type");
  limits = mapContext(definition, value, limits);
  const embedded = new Map();
  function validateField(originalField, item) {
    const field = resolveField(originalField, limits);
    if (item === null && field.type === "uint64" && field.nullable === true) return;
    if (/^uint(?:8|16|32|64)$/u.test(field.type)) {
      requireThat(typeof item === "bigint", "integer_type");
      requireThat(item >= 0n && item < (1n << BigInt(field.type.slice(4))), "integer_range");
      if (field.min !== undefined) requireThat(item >= BigInt(field.min), "field_range");
      if (field.max !== undefined) requireThat(item <= BigInt(field.max), "field_range");
      if (field.bitmask !== undefined) requireThat((item & ~BigInt(field.bitmask)) === 0n, "unknown_bits");
      if (field.const !== undefined) requireThat(item === BigInt(field.const), "constant_mismatch");
      if (field.enum) requireThat(Object.values(field.enum).some((x) => BigInt(x) === item), "enum_value");
      if (field.enum_ref) {
        const entries = Object.values(schema[field.enum_ref] ?? {});
        requireThat(entries.length > 0, "registry_unresolved");
        requireThat(entries.some((x) => BigInt(typeof x === "object" ? x.code : x) === item), "enum_value");
      }
    } else if (field.type === "bytes" || field.type === "text") {
      requireThat(field.type === "bytes" ? Buffer.isBuffer(item) : typeof item === "string", "field_type");
      const n = Buffer.byteLength(item);
      if (field.length !== undefined) requireThat(n === field.length, "field_length");
      if (field.min_bytes !== undefined) requireThat(n >= field.min_bytes, "field_length");
      if (field.max_bytes !== undefined) requireThat(n <= field.max_bytes, "field_length");
      if (field.nonzero) requireThat(Buffer.isBuffer(item) && item.some((byte) => byte !== 0), "field_nonzero");
      if (field.profile_public_key) {
        requireThat(Object.hasOwn(schema.crypto_profiles, limits.crypto_profile_id), "context_unresolved");
        const profile = schema.crypto_profiles[limits.crypto_profile_id];
        requireThat(n === profile.dh_public_bytes, "field_length");
        if (profile.dh_algorithm === 1) requireThat(item[0] === 4, "field_prefix");
      }
      if (field.const !== undefined) requireThat(item === field.const, "constant_mismatch");
      if (field.const_ref) requireThat(item === schema[field.const_ref], "constant_mismatch");
      if (field.pattern_ref) {
        requireThat(typeof schema.text_patterns?.[field.pattern_ref] === "string", "pattern_unresolved");
        const match = new RegExp(schema.text_patterns[field.pattern_ref], "u").exec(item);
        requireThat(match !== null && match[0] === item, "text_pattern");
      }
      if (field.text_enum_ref) {
        const entries = schema[field.text_enum_ref];
        requireThat(entries && Object.keys(entries).length > 0, "registry_unresolved");
        requireThat(Object.hasOwn(entries, item), "enum_value");
      }
      if (field.text_format) validateTextFormat(field.text_format,item,schema);
      if (field.forbidden_prefix !== undefined) requireThat(!item.startsWith(field.forbidden_prefix), "reserved_namespace");
      if (field.encoded_schema_ref && !(field.allow_empty && item.length === 0)) embedded.set(item, decodeMap(schema, field.encoded_schema_ref, item, limits));
      if (field.max_ref) {
        requireThat(Number.isSafeInteger(limits[field.max_ref]), "limit_unresolved");
        requireThat(n <= limits[field.max_ref], "field_length");
      }
    } else if (field.type === "bool") {
      requireThat(typeof item === "boolean", "field_type");
      if (field.const !== undefined) requireThat(item === field.const, "field_equality");
    }
    else if (field.type === "map") validateMap(schema, field.schema_ref, item, limits);
    else if (field.type === "text_map") {
      requireThat(item instanceof Map, "map_type");
      requireThat(item.size >= field.min_items && item.size <= field.max_items, "map_length");
      for (const [key, entry] of item) {
        validateField(field.keys, key);
        const entryField = field.entries ? (Object.hasOwn(field.entries, key) ? field.entries[key] : undefined) : field.values;
        requireThat(entryField !== undefined, "unknown_field");
        validateField(entryField, entry);
      }
      for (const key of Object.keys(field.entries ?? {})) requireThat(item.has(key), "missing_field");
    }
    else if (field.type === "array<uint64>" || field.type === "array") {
      requireThat(Array.isArray(item), "field_type");
      requireThat(item.length >= field.min_items && item.length <= arrayLimit(field,limits), "array_length");
      for (const x of item) validateField(field.items ?? {type:"uint64"}, x);
    } else fail("schema_type_unresolved");
  }
  for (const [id, item] of value) {
    requireThat(typeof id === "bigint" && id >= 0n && id <= 65535n, "field_id_type");
    const field = definition.fields[id.toString()];
    requireThat(field !== undefined, "unknown_field");
    validateField(field, item);
  }
  for (const id of definition.required) requireThat(value.has(BigInt(id)), "missing_field");
  for (const rule of schema.map_rules?.[name] ?? []) {
    const get = (fieldPath) => {
      let current = value, currentField = {type:"map",schema_ref:name};
      const parts = fieldPath.split(".");
      for (const part of parts) {
        if (current === undefined) return undefined;
        const resolved = resolveField(currentField, limits);
        if (resolved.type === "array" || resolved.type === "array<uint64>") {
          requireThat(/^(?:0|[1-9][0-9]*)$/u.test(part) && Number.isSafeInteger(Number(part)) && Number(part) < arrayLimit(resolved,limits), "unknown_rule_field");
          current = current[Number(part)];
          currentField = resolved.items ?? {type:"uint64"};
        } else {
          const currentDefinition = schema.frame_maps[resolved.schema_ref ?? resolved.encoded_schema_ref];
          const field = Object.entries(currentDefinition?.fields ?? {}).find(([, f]) => f.name === part);
          requireThat(field !== undefined, "unknown_rule_field");
          if (resolved.encoded_schema_ref) current = embedded.get(current) ?? decodeMap(schema, resolved.encoded_schema_ref, current, limits);
          current = current.get(BigInt(field[0]));
          currentField = field[1];
        }
      }
      return current;
    };
    if (rule.when) {
      const actual = rule.when.context ? limits[rule.when.context] : get(rule.when.field);
      if (rule.when.context) requireThat(typeof actual === "string", "context_unresolved");
      const expected = typeof actual === "bigint" ? BigInt(rule.when.value) : rule.when.value;
      if (actual !== expected) continue;
    }
    const variant = (branch) => {
      for (const field of branch.absent ?? []) requireThat(get(field) === undefined, "variant_absent");
      for (const field of branch.required ?? []) requireThat(get(field) !== undefined, "variant_required");
      for (const [field, expected] of Object.entries(branch.constants ?? {})) requireThat(get(field) === (typeof expected === "boolean" ? expected : BigInt(expected)), "variant_constant");
      for (const [field, allowed] of Object.entries(branch.enum_values ?? {})) requireThat(allowed.some((x) => get(field) === BigInt(x)), "enum_value");
      for (const [a, b] of branch.equal ?? []) requireThat(isDeepStrictEqual(get(a), get(b)), "field_equality");
      for (const [a, b] of branch.less_or_equal ?? []) requireThat(get(a) <= get(b), "field_order");
      for (const field of branch.nonzero ?? []) {
        const item = get(field);
        requireThat(Buffer.isBuffer(item) ? item.some((byte) => byte !== 0) : item > 0n, "variant_nonzero");
      }
      for (const field of branch.zero_bytes ?? []) requireThat(Buffer.isBuffer(get(field)) && get(field).every((byte) => byte === 0), "variant_zero_bytes");
      for (const [field, n] of Object.entries(branch.byte_lengths ?? {})) requireThat(Buffer.isBuffer(get(field)) && get(field).length === n, "field_length");
      for (const [field, hex] of Object.entries(branch.byte_prefixes ?? {})) requireThat(Buffer.isBuffer(get(field)) && get(field).subarray(0, hex.length / 2).equals(strictHex(hex)), "field_prefix");
      for (const [field, registry] of Object.entries(branch.registered ?? {})) {
        const codes = Object.values(schema[registry] ?? {});
        requireThat(codes.length > 0, "registry_unresolved");
        requireThat(codes.some((entry) => BigInt(typeof entry === "object" ? entry.code : entry) === get(field)), "enum_value");
      }
    };
    if (rule.op === "is_null") requireThat(get(rule.field) === null, "field_null");
    else if (rule.op === "at_least_one") requireThat(rule.fields.some(field => get(field) !== undefined), "field_presence");
    else if (rule.op === "equal") requireThat(isDeepStrictEqual(get(rule.left), get(rule.right)), "field_equality");
    else if (rule.op === "equal_if_present") {
      const left = get(rule.left), right = get(rule.right);
      if (left !== undefined && right !== undefined) requireThat(isDeepStrictEqual(left,right), "field_equality");
    }
    else if (rule.op === "ordinal_indices") {
      for (const [index,entry] of get(rule.field).entries()) requireThat(entry.get(BigInt(rule.item_field_id)) === BigInt(index), "item_index");
    }
    else if (rule.op === "map_digest") {
      const domain = schema.domains.find(item => item.name === rule.domain);
      requireThat(domain?.operation === "sha256" && domain.input_schema.parts.length === 1, "domain_projection");
      const input = domain.input_schema.parts[0];
      requireThat(input.encoding === "lp-map" && input.projection === "full", "domain_projection");
      const source = get(rule.source);
      const result = evaluateDomain(schema,rule.domain,{[input.name]:Buffer.isBuffer(source) ? source : encodeCBOR(source)},limits);
      requireThat(Buffer.isBuffer(get(rule.field)) && get(rule.field).equals(strictHex(result.output_hex)), "map_digest_mismatch");
    }
    else if (rule.op === "not_equal") requireThat(!isDeepStrictEqual(get(rule.left), get(rule.right)), "field_distinctness");
    else if (rule.op === "less_or_equal") requireThat(get(rule.left) <= get(rule.right), "field_order");
    else if (rule.op === "less_than") requireThat(get(rule.left) < get(rule.right), "field_order");
    else if (rule.op === "bit_subset") {
      const left = get(rule.left), right = get(rule.right);
      requireThat(typeof left === "bigint" && typeof right === "bigint", "integer_type");
      requireThat((left & ~right) === 0n, "feature_subset");
    }
    else if (rule.op === "feature_bit") {
      const bit = schema.feature_registry[rule.feature]?.bit;
      requireThat(Number.isInteger(bit) && bit >= 0 && bit < 64, "registry_unresolved");
      const bits = get(rule.field);
      requireThat(typeof bits === "bigint", "integer_type");
      requireThat(((bits & (1n << BigInt(bit))) !== 0n) === rule.present, "feature_policy");
    }
    else if (rule.op === "max_difference") {
      const low = get(rule.left), high = get(rule.right);
      requireThat(typeof low === "bigint" && typeof high === "bigint", "integer_type");
      requireThat(low <= high && high - low <= BigInt(rule.max), "field_duration");
    }
    else if (rule.op === "error_scope") {
      const code = get(rule.code_field);
      const metadata = Object.entries(schema.error_codes).find(([, value]) => BigInt(value) === code)?.[0];
      requireThat(metadata !== undefined, "enum_value");
      const policy = schema.error_code_metadata[metadata];
      const target = get(rule.target_scope_field), stream = get(rule.stream_id_field), retryAfter = get(rule.retry_after_field);
      requireThat(policy?.scope === "session" || policy?.scope === "stream", "error_scope");
      if (policy.scope === "session") {
        requireThat(target === 0n && stream === undefined, "error_scope");
      } else if (policy.scope === "stream") {
        requireThat(target > 0n && stream !== undefined && stream === target, "error_scope");
      }
      if (policy.retryable !== true) requireThat(retryAfter === undefined, "retry_after_forbidden");
    }
    else if (rule.op === "allowed_pairs") requireThat(rule.pairs.some(([a,b]) => get(rule.left) === BigInt(a) && get(rule.right) === BigInt(b)), "field_pair");
    else if (rule.op === "text_format") validateTextFormat(rule.format,get(rule.field),schema);
    else if (rule.op === "origin_endpoint") {
      const host = get(rule.host), port = get(rule.port);
      const expected = rule.scheme + "://" + (host.includes(":") ? "[" + host + "]" : host) + (port === BigInt(schema.origin_schemes[rule.scheme].default_port) ? "" : ":" + port);
      requireThat(get(rule.origin) === expected, "origin_endpoint");
    }
    else if (rule.op === "allowed_tuples") requireThat(rule.rows.some(row => row.every((item,index) => get(rule.fields[index]) === BigInt(item))), "field_tuple");
    else if (rule.op === "registry_tuple") {
      let tuple = schema[rule.registry];
      requireThat(tuple !== undefined, "registry_unresolved");
      for (const selector of rule.selectors) {
        let key;
        if (selector.context) key = limits[selector.context];
        else {
          const field = Object.values(definition.fields).find(item => item.name === selector.field);
          key = Object.entries(field?.enum ?? {}).find(([,code]) => BigInt(code) === get(selector.field))?.[0];
        }
        requireThat(typeof key === "string" && Object.hasOwn(tuple,key), "context_unresolved");
        tuple = tuple[key];
      }
      for (const field of rule.fields) requireThat(Object.hasOwn(tuple,field) && isDeepStrictEqual(get(field),tuple[field]), "carrier_tuple");
    }
    else if (rule.op === "unique_by") {
      const field = Object.values(definition.fields).find(item => item.name === rule.field);
      const itemDefinition = schema.frame_maps[field.items.schema_ref];
      const ids = rule.item_fields.map(itemName => BigInt(Object.entries(itemDefinition.fields).find(([,item]) => item.name === itemName)[0]));
      const seen = new Set();
      for (const entry of get(rule.field)) {
        const key = encodeCBOR(ids.map(id => entry.get(id))).toString("hex");
        requireThat(!seen.has(key), "item_identity"); seen.add(key);
      }
    }
    else if (rule.op === "range") requireThat(get(rule.field) >= BigInt(rule.min) && get(rule.field) <= BigInt(rule.max), "field_range");
    else if (rule.op === "increasing_tuple") {
      let previous;
      for (let index = 0; index < get(rule.field).length; index++) {
        const tuple = rule.item_fields.map(field => get(`${rule.field}.${index}.${field}`));
        if (previous) {
          let order = 0;
          for (let i = 0; i < tuple.length && order === 0; i++) {
            const left = previous[i], right = tuple[i];
            if (Buffer.isBuffer(left) && Buffer.isBuffer(right)) order = Buffer.compare(left,right);
            else {
              requireThat(typeof left === "bigint" && typeof right === "bigint", "integer_type");
              order = left < right ? -1 : left > right ? 1 : 0;
            }
          }
          requireThat(order < 0, "item_order");
        }
        previous = tuple;
      }
    }
    else if (rule.op === "exclusive_item") {
      const entries = get(rule.field);
      for (let index = 0; index < entries.length; index++) {
        const actual = get(`${rule.field}.${index}.${rule.item_field}`);
        const expected = typeof rule.value === "boolean" ? rule.value : BigInt(rule.value);
        if (actual === expected) requireThat(entries.length === 1, "item_exclusive");
      }
    }
    else if (rule.op === "profile_algorithm") {
      const profile = schema.crypto_profiles[get(rule.profile)];
      requireThat(profile !== undefined, "enum_value");
      requireThat(get(rule.algorithm) === BigInt(profile.dh_algorithm), "profile_algorithm");
    }
    else if (rule.op === "increasing") {
      let previous = -1n;
      for (const entry of get(rule.field)) {
        const item = rule.item_field_id === undefined ? entry : entry.get(BigInt(rule.item_field_id));
        requireThat(typeof item === "bigint" && item > previous, "item_order");
        previous = item;
      }
    }
    else if (rule.op === "increasing_bytes") {
      const entries = get(rule.field);
      // Presence belongs to the map/variant rule; ordering applies to a
      // present array, including optional fields in closed union variants.
      if (entries === undefined) continue;
      let previous;
      for (const entry of entries) {
        const item = rule.item_field_id === undefined ? entry : entry.get(BigInt(rule.item_field_id));
        requireThat(Buffer.isBuffer(item), "field_type");
        requireThat(previous === undefined || Buffer.compare(previous, item) < 0, "item_order");
        previous = item;
      }
    }
    else if (rule.op === "increasing_scopes") {
      let previous = 0n;
      for (const scope of get(rule.field)) {
        requireThat(scope > previous && scope <= BigInt(schema.resource_caps.scope_id.max), "scope_order");
        previous = scope;
      }
    } else if (rule.op === "increasing_cbor") {
      const entries = get(rule.field);
      if (entries === undefined) continue;
      let previous;
      for (const entry of entries) {
        const bytes = encodeCBOR(entry);
        requireThat(previous === undefined || Buffer.compare(previous, bytes) < 0, "item_order");
        previous = bytes;
      }
    } else if (rule.op === "variant") {
      const expected = typeof rule.value === "boolean" ? rule.value : BigInt(rule.value);
      if (get(rule.discriminator) !== expected) continue;
      variant(rule);
    } else if (rule.op === "context_variant") {
      requireThat(typeof limits[rule.context] === "string" && Object.hasOwn(rule.cases, limits[rule.context]), "context_unresolved");
      variant(rule.cases[limits[rule.context]]);
    } else fail("rule_unresolved");
  }
  if (definition.max_encoded_bytes !== undefined) requireThat(encodeMap(schema,name,value,limits).length <= definition.max_encoded_bytes, "map_size");
  if (definition.max_encoded_bytes_ref !== undefined) requireThat(encodeMap(schema,name,value,limits).length <= externalLimit(limits,definition.max_encoded_bytes_ref), "map_size");
  if (definition.encoded_bytes !== undefined) requireThat(encodeMap(schema,name,value,limits).length === definition.encoded_bytes, "map_size");
  return value;
}
