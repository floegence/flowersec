import { transportV4ProxyApplicationRegistry as policy, transportV4Registry } from "../generated/transportV4Registry.js";
import { CBORDecoder, cborDecoderCharge, type CBORDocument } from "../v4/runtime/cbor.js";
import { FixedCBORWriter } from "../v4/runtime/openAdmission.js";
import { ResourceRoot, ResourceVector } from "../v4/runtime/resources.js";
import { wireMaps, type WireField } from "../v4/runtime/schemaRegistry.js";
import { readU32be, u32be } from "../utils/bin.js";

export const PROXY_WIRE_VERSION = policy.version;
export type ProxySchema = "ProxyHTTPRequest" | "ProxyHTTPResponse" | "ProxyWebSocketOpen" | "ProxyWebSocketResponse" | "ProxyBodyEnd" | "ProxyCredentialControlRequest" | "ProxyCredentialControlResponse";
const token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const ascii = /^[\x20-\x7e]*$/u;
const octets = /^[\x09\x20-\x7e\x80-\xff]*$/u;
const fail = (): never => { throw new Error("invalid proxy metadata"); };
const record = (value: unknown): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return fail();
  return value as Record<string, unknown>;
};
const property = (name: string): string => name === "version" ? "v" : name;

// Parsing is synchronous and uses the same canonical decoder as the protocol.
// This private finite workspace admits one actual parse at a time; no waiter or
// peer-selected cache is created. Original request/response storage is separate.
const limit = new ResourceVector([32n << 20n, 0n, 0n, 400000n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
const root = new ResourceRoot({ profileRevision: transportV4Registry.schemaSHA256, limit,
  accounts: 2, reservations: 1, references: 2, rootRuntimeBytes: 4096n,
  accountRuntimeBytes: 512n, reservationRuntimeBytes: 512n, referenceRuntimeBytes: 512n });
const tenant = root.account("tenant", "1".repeat(32), limit);
const environment = root.account("environment", "2".repeat(32), limit);

function validateSemantic(schema: string, value: Record<string, unknown>): void {
  if (schema === "ProxyField") {
    if (typeof value.name !== "string" || !token.test(value.name) || value.name !== value.name.toLowerCase() || typeof value.value !== "string" || !octets.test(value.value)) fail();
  } else {
    for (const [name, item] of Object.entries(value)) if (typeof item === "string" && (!ascii.test(item) || name === "method" && !token.test(item))) fail();
  }
  if (schema === "ProxyHTTPResponse") {
    if (value.ok === true ? value.error !== undefined || value.status === undefined || value.headers === undefined : value.error === undefined || value.status !== undefined || value.headers !== undefined) fail();
  }
  if (schema === "ProxyWebSocketResponse") {
    if (value.ok === true ? value.error !== undefined || value.protocol === undefined : value.error === undefined || value.protocol !== undefined) fail();
  }
}

function decodeMap(doc: CBORDocument, schema: string, node: number): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [id, spec] of Object.entries(wireMaps[schema]!.fields)) {
    const child = doc.field(node, Number(id));
    if (child >= 0) result[property(spec.name!)] = decodeField(doc, spec, child);
  }
  validateSemantic(schema, result);
  return result;
}
function decodeField(doc: CBORDocument, spec: WireField, node: number): unknown {
  if (spec.type.startsWith("uint")) return Number(doc.uint(node));
  if (spec.type === "bool") return doc.boolean(node);
  if (spec.type === "map") return decodeMap(doc, spec.schema_ref!, node);
  if (spec.type === "array") {
    const result: unknown[] = [];
    for (let child = doc.firstChild(node); child >= 0; child = doc.nextSibling(child)) result.push(decodeField(doc, spec.items!, child));
    return result;
  }
  if (spec.type === "bytes") {
    // ByteString is deliberately independent of UTF-8 and NFC. Chunking avoids
    // argument-count limits and quadratic character concatenation.
    const bytes = new Uint8Array(doc.size(node)); doc.copyPayload(node, bytes);
    const pieces: string[] = [];
    for (let at = 0; at < bytes.length; at += 8192) pieces.push(String.fromCharCode(...bytes.subarray(at, at + 8192)));
    return pieces.join("");
  }
  return fail();
}
export function decodeProxyMetadata(schema: ProxySchema, bytes: Uint8Array, maximum: number = policy.max_metadata_bytes): Record<string, unknown> {
  if (bytes.length === 0 || bytes.length > maximum || bytes.length > policy.max_metadata_bytes) return fail();
  const config = { bytes: bytes.length, nodes: Math.min(bytes.length, policy.max_field_count * 5 + 32), textBytes: 0, arrayItems: policy.max_field_count, runtimeBytes: 4096n };
  const ref = root.reserve({ owner: { tenant: "1".repeat(32), environment: "2".repeat(32), kind: "proxy_decoder", backing: "3".repeat(32) }, accounts: [tenant, environment], charge: cborDecoderCharge(config) });
  let decoder: CBORDecoder | undefined, doc: CBORDocument | undefined;
  try {
    decoder = new CBORDecoder(config, ref);
    doc = decoder.decodeMap(bytes, schema, { limits: { max_proxy_fields: policy.max_field_count } });
    return decodeMap(doc, schema, 0);
  } finally { doc?.release(); decoder?.close(); ref.release(); }
}

type Captured = number | boolean | string | { map: readonly [number, Captured][] } | { array: readonly Captured[] };
function captureMap(schema: string, input: unknown): Captured {
  const value = record(input), spec = wireMaps[schema]!;
  const entries: [number, Captured][] = [];
  const known = new Set<string>();
  for (const [id, field] of Object.entries(spec.fields)) {
    const name = property(field.name!); known.add(name);
    let item = value[name];
    if (item === undefined) { if (spec.required.includes(Number(id))) fail(); continue; }
    if (schema === "ProxyField" && name === "name" && typeof item === "string") item = item.toLowerCase();
    entries.push([Number(id), captureField(field, item)]);
  }
  if (Object.keys(value).some(name => !known.has(name))) fail();
  validateSemantic(schema, schema === "ProxyField" ? { ...value, name: String(value.name).toLowerCase() } : value);
  return { map: entries };
}
function captureField(spec: WireField, value: unknown): Captured {
  if (spec.type.startsWith("uint")) {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < Number(spec.min ?? 0) || value > Number(spec.max ?? 0xffffffff) || spec.const !== undefined && value !== spec.const) fail();
    return value as number;
  }
  if (spec.type === "bool") { if (typeof value !== "boolean") fail(); return value as boolean; }
  if (spec.type === "map") return captureMap(spec.schema_ref!, value);
  if (spec.type === "array") {
    if (!Array.isArray(value) || value.length > policy.max_field_count) return fail();
    return { array: value.map(item => captureField(spec.items!, item)) };
  }
  if (spec.type === "bytes") {
    if (typeof value !== "string" || value.length < (spec.min_bytes ?? 0) || value.length > (spec.max_bytes ?? policy.max_metadata_bytes) || !octets.test(value)) return fail();
    return value;
  }
  return fail();
}
function headSize(n: number): number { return n < 24 ? 1 : n <= 255 ? 2 : n <= 65535 ? 3 : 5; }
function size(value: Captured): number {
  if (typeof value === "number") return headSize(value);
  if (typeof value === "boolean") return 1;
  if (typeof value === "string") return headSize(value.length) + value.length;
  if ("array" in value) return headSize(value.array.length) + value.array.reduce<number>((n, v) => n + size(v), 0);
  return headSize(value.map.length) + value.map.reduce((n, [id, v]) => n + headSize(id) + size(v), 0);
}
function write(writer: FixedCBORWriter, value: Captured): void {
  if (typeof value === "number") { writer.uint(value); return; }
  if (typeof value === "boolean") { writer.bool(value); return; }
  if (typeof value === "string") {
    const bytes = new Uint8Array(value.length);
    for (let i = 0; i < value.length; i++) bytes[i] = value.charCodeAt(i);
    writer.data(bytes); return;
  }
  if ("array" in value) { writer.array(value.array.length); for (const v of value.array) write(writer, v); return; }
  writer.map(value.map.length); for (const [id, v] of value.map) { writer.uint(id); write(writer, v); }
}
export function encodeProxyMetadata(schema: ProxySchema, value: unknown, maximum: number = policy.max_metadata_bytes): Uint8Array {
  const captured = captureMap(schema, value), length = size(captured);
  if (length > maximum || length > policy.max_metadata_bytes) return fail();
  const writer = new FixedCBORWriter(new Uint8Array(length)); write(writer, captured); return writer.result();
}
export async function readProxyFrame(reader: { readExactly(n: number): Promise<Uint8Array> }, schema: ProxySchema, maximum: number = policy.max_metadata_bytes): Promise<Record<string, unknown>> {
  const length = readU32be(await reader.readExactly(4), 0);
  if (length === 0 || length > maximum || length > policy.max_metadata_bytes) return fail();
  return decodeProxyMetadata(schema, await reader.readExactly(length), maximum);
}
export async function writeProxyFrame(writer: { write(bytes: Uint8Array): Promise<void> }, schema: ProxySchema, value: unknown, maximum: number = policy.max_metadata_bytes): Promise<void> {
  const bytes = encodeProxyMetadata(schema, value, maximum);
  await writer.write(u32be(bytes.length)); await writer.write(bytes);
}

export function validateProxyTrailers(value: unknown, connection: ReadonlySet<string> = new Set()): void {
  if (!Array.isArray(value)) fail();
  const forbidden = new Set(["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "authorization", "www-authenticate", "cookie", "set-cookie", "host", "origin", "content-length", "content-encoding", "content-range", "content-type", "location"]);
  for (const item of value as unknown[]) { const h = record(item); validateSemantic("ProxyField", h); if (forbidden.has(h.name as string) || connection.has(h.name as string)) fail(); }
}
