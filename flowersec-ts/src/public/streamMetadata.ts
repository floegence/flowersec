import type { JsonObject } from "./contract.js";
import { byteLength, type CBORDocument } from "../v4/runtime/cbor.js";
import { FixedCBORWriter } from "../v4/runtime/cborWriter.js";
import { CanonicalTextWorkspace } from "../v4/runtime/canonicalText.js";
import { fieldPattern, wireMaps } from "../v4/runtime/schemaRegistry.js";

export class StreamMetadataError extends Error {
  constructor() { super("invalid Flowersec stream metadata"); this.name = "StreamMetadataError"; }
}
/** A fixed, local descriptor for raw Stream metadata. The descriptor is
 * intentionally data-only: it cannot install a second decoder or access I/O. */
export interface RawStreamMetadataField {
  readonly name: string;
  readonly type: "string" | "number" | "boolean";
  readonly required?: boolean;
}
export interface RawStreamMetadataContract {
  readonly contractID: string;
  readonly namespace: string;
  readonly version: number;
  readonly codec: "application/json";
  readonly fields: readonly RawStreamMetadataField[];
  readonly maxEncodedBytes?: number;
  readonly maxDecodedBytes?: number;
}
const utf8 = new TextEncoder(), decode = new TextDecoder("utf-8", { fatal: true });
const schema = wireMaps.StreamMetadata!;
const jsonNamespace = "application/json";
let createOwned: (namespace: string, version: number, entries: Readonly<Record<string, Uint8Array>>, wire: Uint8Array,
  projection?: Readonly<Record<string, unknown>>) => StreamMetadata;

/** Immutable ordinary v4 metadata; application values remain opaque bytes. */
export class StreamMetadata {
  readonly #entries: Readonly<Record<string, Uint8Array>>;
  readonly #wire: Uint8Array;
  readonly #projection: Readonly<Record<string, unknown>> | undefined;
  private constructor(readonly namespace: string, readonly version: number, entries: Readonly<Record<string, Uint8Array>>, wire: Uint8Array,
    projection?: Readonly<Record<string, unknown>>) {
    this.#entries = entries; this.#wire = wire; this.#projection = projection; Object.freeze(this);
  }
  static { createOwned = (namespace, version, entries, wire, projection) => new StreamMetadata(namespace, version, entries, wire, projection); }
  encoded(): Uint8Array { return new Uint8Array(this.#wire); }
  byteValues(): Readonly<Record<string, Uint8Array>> {
    const values: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
    for (const [key, value] of Object.entries(this.#entries)) values[key] = new Uint8Array(value);
    return Object.freeze(values);
  }
  /** Typed values produced by a registered RawStreamMetadataContract. */
  descriptorValues(): Readonly<Record<string, unknown>> {
    if (this.#projection === undefined) throw new StreamMetadataError();
    return this.#projection;
  }
  /** JSON convenience values are available only for the application/json codec. */
  get values(): JsonObject {
    if (this.#wire.length === 0) return Object.freeze({});
    if (this.namespace !== jsonNamespace || this.version !== 1) throw new StreamMetadataError();
    try {
      const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      for (const [key, value] of Object.entries(this.#entries)) values[key] = JSON.parse(decode.decode(value)) as unknown;
      return deepFreeze(values) as JsonObject;
    } catch { throw new StreamMetadataError(); }
  }
}

/** Capture the registered namespace/version/byte-map shell without a JSON conversion. */
export function createStreamMetadataEnvelope(namespace: string, version: number, values: Readonly<Record<string, Uint8Array>>): StreamMetadata {
  let text: CanonicalTextWorkspace | undefined;
  try {
    if (typeof namespace !== "string" || namespace.length > schema.fields[0]!.max_bytes! ||
        !fieldPattern(schema.fields[0]!.pattern_ref!)!.test(namespace) || namespace.startsWith(schema.fields[0]!.forbidden_prefix!) ||
        !Number.isSafeInteger(version) || version < 0 || version > 65535 || values === null || typeof values !== "object") throw new StreamMetadataError();
    const keys = Object.keys(values), rules = schema.fields[2]!;
    if (keys.length > rules.max_items!) throw new StreamMetadataError();
    const entries: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
    const names: { key: string; encoded: Uint8Array }[] = [];
    text = new CanonicalTextWorkspace(rules.keys!.max_bytes!);
    for (const key of keys) {
      if (key.length > rules.keys!.max_bytes!) throw new StreamMetadataError();
      const encoded = utf8.encode(key), value = values[key]!;
      if (decode.decode(encoded) !== key || encoded.length < rules.keys!.min_bytes! || encoded.length > rules.keys!.max_bytes! || text.check(encoded) !== undefined || byteLength(value) > rules.values!.max_bytes!) throw new StreamMetadataError();
      entries[key] = new Uint8Array(value); names.push({ key, encoded });
    }
    names.sort((a, b) => {
      if (a.encoded.length !== b.encoded.length) return a.encoded.length - b.encoded.length;
      for (let i = 0; i < a.encoded.length; i++) { const difference = a.encoded[i]! - b.encoded[i]!; if (difference !== 0) return difference; }
      return 0;
    });
    const writer = new FixedCBORWriter(new Uint8Array(schema.max_encoded_bytes!));
    writer.map(3).uint(0).data(utf8.encode(namespace), true).uint(1).uint(version).uint(2).map(names.length);
    for (const { key, encoded } of names) writer.data(encoded, true).data(entries[key]!);
    return createOwned(namespace, version, Object.freeze(entries), new Uint8Array(writer.result()));
  } catch { throw new StreamMetadataError(); }
  finally { text?.clear(); }
}

/** Optional JSON application codec; every value retains its JSON bytes. */
export function createStreamMetadata(values: JsonObject): StreamMetadata {
  try {
    if (values === null || typeof values !== "object" || Array.isArray(values)) throw new StreamMetadataError();
    const keys = Object.keys(values);
    if (keys.length === 0) return createOwned("", 0, Object.freeze({}), new Uint8Array());
    if (keys.length > schema.fields[2]!.max_items!) throw new StreamMetadataError();
    const entries: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
    for (const key of keys) {
      const json = JSON.stringify(values[key]);
      if (json === undefined || json.length > schema.fields[2]!.values!.max_bytes!) throw new StreamMetadataError();
      entries[key] = utf8.encode(json);
    }
    return createStreamMetadataEnvelope(jsonNamespace, 1, entries);
  } catch { throw new StreamMetadataError(); }
}

/** Validate and attach one fixed descriptor projection to an already decoded
 * metadata envelope. The original bytes remain the only handler metadata. */
export function applyRawStreamMetadataContract(metadata: StreamMetadata, contract: RawStreamMetadataContract): StreamMetadata {
  try {
    if (!(metadata instanceof StreamMetadata) || !captureRawStreamMetadataContract(contract) ||
        metadata.namespace !== contract.namespace || metadata.version !== contract.version || contract.codec !== "application/json") throw new StreamMetadataError();
    const encoded = metadata.encoded();
    const maxEncoded = contract.maxEncodedBytes ?? 4096, maxDecoded = contract.maxDecodedBytes ?? 4096;
    if (!Number.isSafeInteger(maxEncoded) || maxEncoded < 1 || maxEncoded > 4096 || encoded.length > maxEncoded ||
        !Number.isSafeInteger(maxDecoded) || maxDecoded < 1 || maxDecoded > 4096) throw new StreamMetadataError();
    const raw: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, value] of Object.entries(metadata.byteValues())) raw[key] = JSON.parse(decode.decode(value)) as unknown;
    const allowed = new Map(contract.fields.map(field => [field.name, field]));
    const keys = Object.keys(raw); if (keys.some(key => !allowed.has(key)) || contract.fields.some(field => field.required === true && !Object.hasOwn(raw, field.name))) throw new StreamMetadataError();
    const projection: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    let decodedBytes = 0;
    for (const key of keys) {
      const field = allowed.get(key)!; const value = raw[key];
      if (field.type === "string" && typeof value !== "string" || field.type === "number" && (typeof value !== "number" || !Number.isFinite(value)) ||
          field.type === "boolean" && typeof value !== "boolean") throw new StreamMetadataError();
      // The decoded cap covers the complete bounded projection input, including
      // field names.  Keys are retained by the projection and therefore cannot
      // be treated as free metadata.  Primitive values use their stable owned
      // representation: UTF-8 bytes for strings, IEEE-754 width for numbers,
      // and one byte for booleans.
      decodedBytes += utf8.encode(key).length;
      // JavaScript's `String.length` counts UTF-16 code units and would
      // undercount non-ASCII values (for example an emoji consumes four
      // UTF-8 bytes). Charge the bounded representation retained by the
      // projection rather than the host string's code-unit count.
      decodedBytes += typeof value === "string" ? utf8.encode(value).length : typeof value === "number" ? 8 : 1;
      if (decodedBytes > maxDecoded) throw new StreamMetadataError(); projection[key] = value;
    }
    return createOwned(metadata.namespace, metadata.version, Object.freeze(Object.fromEntries(Object.entries(metadata.byteValues()).map(([key, value]) => [key, value]))), encoded,
      deepFreeze(projection));
  } catch { throw new StreamMetadataError(); }
}

/** Capture and validate descriptor shape at registration time. */
export function captureRawStreamMetadataContract(contract: RawStreamMetadataContract | undefined): RawStreamMetadataContract | undefined {
  if (contract === undefined) return undefined;
  if (contract === null || typeof contract !== "object" || typeof contract.contractID !== "string" || contract.contractID.length < 1 || contract.contractID.length > 128 ||
      !/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(contract.contractID) || contract.contractID.normalize("NFC") !== contract.contractID || typeof contract.namespace !== "string" || contract.namespace.length < 1 ||
      !fieldPattern(schema.fields[0]!.pattern_ref!)!.test(contract.namespace) || contract.namespace.startsWith(schema.fields[0]!.forbidden_prefix!) ||
      !Number.isSafeInteger(contract.version) || contract.version < 0 || contract.version > 65535 || contract.codec !== "application/json" ||
      !Array.isArray(contract.fields) || contract.fields.length > 64) throw new StreamMetadataError();
  const fields = contract.fields.map(field => {
    if (field === null || typeof field !== "object" || typeof field.name !== "string" || field.name.length < 1 || field.name.length > 64 ||
        field.name.normalize("NFC") !== field.name || !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(field.name) ||
        field.type !== "string" && field.type !== "number" && field.type !== "boolean" || field.required !== undefined && typeof field.required !== "boolean") throw new StreamMetadataError();
    return Object.freeze({ name: field.name, type: field.type, ...(field.required === undefined ? {} : { required: field.required }) });
  });
  if (new Set(fields.map(field => field.name)).size !== fields.length ||
      contract.maxEncodedBytes !== undefined && (!Number.isSafeInteger(contract.maxEncodedBytes) || contract.maxEncodedBytes < 1 || contract.maxEncodedBytes > 4096) ||
      contract.maxDecodedBytes !== undefined && (!Number.isSafeInteger(contract.maxDecodedBytes) || contract.maxDecodedBytes < 1 || contract.maxDecodedBytes > 4096)) throw new StreamMetadataError();
  return Object.freeze({ contractID: contract.contractID, namespace: contract.namespace, version: contract.version, codec: contract.codec,
    fields: Object.freeze(fields), ...(contract.maxEncodedBytes === undefined ? {} : { maxEncodedBytes: contract.maxEncodedBytes }),
    ...(contract.maxDecodedBytes === undefined ? {} : { maxDecodedBytes: contract.maxDecodedBytes }) });
}

/** @internal Consume only a document checked by the original OPEN decoder. */
export function streamMetadataFromDocument(document: CBORDocument | undefined): StreamMetadata {
  if (document === undefined) return createOwned("", 0, Object.freeze({}), new Uint8Array());
  const values: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
  for (let key = document.firstChild(document.field(0, 2)); key >= 0;) {
    const value = document.nextSibling(key), data = new Uint8Array(document.size(value));
    document.copyPayload(value, data); values[document.text(key)] = data; key = document.nextSibling(value);
  }
  const encoded = new Uint8Array(document.encodedSize()); document.copyEncoded(0, encoded);
  return createOwned(document.text(document.field(0, 0)), Number(document.uint(document.field(0, 1))), Object.freeze(values), encoded);
}

/** @internal */
export function streamMetadataValues(metadata: StreamMetadata): JsonObject {
  if (!(metadata instanceof StreamMetadata)) throw new StreamMetadataError();
  return metadata.values;
}
/** @internal */
export function streamMetadataBytes(metadata: StreamMetadata): Uint8Array {
  if (!(metadata instanceof StreamMetadata)) throw new StreamMetadataError();
  return metadata.encoded();
}
function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
