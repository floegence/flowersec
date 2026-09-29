import { transportV4ApplicationHeaders as registry } from "../../generated/transportV4Registry.js";
import { byteLength, byteSlice, CBORDecoder, cborDecoderCharge } from "./cbor.js";
import { FixedCBORWriter } from "./cborWriter.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";

export type ApplicationMessageKind = keyof typeof registry.kinds;
interface HeaderVariant {
  readonly code: number;
  readonly fields: readonly number[];
  readonly constants?: Readonly<Record<string, number>>;
  readonly request?: string;
  readonly sdk_error?: boolean;
  readonly application_error?: boolean;
}
const variants: Readonly<Record<string, HeaderVariant>> = Object.freeze(Object.fromEntries(
  Object.entries(registry.kinds).map(([name, source]) => {
    const variant: HeaderVariant = source;
    return [name, Object.freeze({ ...variant, fields: Object.freeze([...variant.fields]),
      ...(variant.constants === undefined ? {} : { constants: Object.freeze({ ...variant.constants }) }) })];
  }),
));
const byCode = new Map<number, Readonly<{ name: ApplicationMessageKind; variant: HeaderVariant }>>();
for (const [name, variant] of Object.entries(variants)) {
  if (variant.code < 1 || variant.code > 255 || byCode.has(variant.code) || variant.fields.length > 11 ||
      variant.fields.some((id, index) => id < 0 || id > 10 || index !== 0 && id <= variant.fields[index - 1]!)) throw new Error("registry_unresolved");
  byCode.set(variant.code, Object.freeze({ name: name as ApplicationMessageKind, variant }));
}
const capability = Symbol("canonical application header");
const u64 = (1n << 64n) - 1n;
const fieldNames = ["kind", "operationID", "typeID", "payloadBytes", "requestDigest", "deadlineAtMS", "contractDigest", "admissionMode", "responseLimitBytes", "controlSerial", "applicationErrorCode"] as const;
type Scalar = bigint | Uint8Array;
interface HeaderState { readonly variant: HeaderVariant; readonly fields: readonly (Scalar | undefined)[] }
const states = new WeakMap<ApplicationHeader, HeaderState>();
function state(header: ApplicationHeader): HeaderState {
  const value = states.get(header); if (value === undefined) throw new RPCProtocolError("application_header_owner"); return value;
}
function equal(a: Scalar | undefined, b: Scalar | undefined): boolean {
  if (a === undefined || b === undefined || typeof a === "bigint" || typeof b === "bigint") return a === b;
  if (a.length !== b.length) return false;
  let difference = 0; for (let index = 0; index < a.length; index++) difference |= a[index]! ^ b[index]!;
  return difference === 0;
}
/** Detached syntax facts only. The actual channel/serial, trusted service
 * route, authorization and completion owner remain separate admission gates. */
export class ApplicationHeader {
  readonly kind: ApplicationMessageKind;
  readonly typeID: number;
  readonly payloadBytes: number;
  constructor(token: symbol, name: ApplicationMessageKind, value: HeaderState) {
    if (token !== capability) throw new RPCProtocolError("application_header_owner");
    this.kind = name; this.typeID = Number(value.fields[2]); this.payloadBytes = Number(value.fields[3]);
    states.set(this, value); Object.freeze(this);
  }
  isResponse(): boolean { return state(this).variant.request !== undefined; }
  isSDKError(): boolean { return state(this).variant.sdk_error === true; }
  isApplicationError(): boolean { return state(this).variant.application_error === true; }
  has(id: number): boolean { return state(this).variant.fields.includes(id); }
  uint(id: number): bigint {
    const value = state(this).fields[id]; if (typeof value !== "bigint") throw new RPCProtocolError("application_header_field"); return value;
  }
  copyBytes(id: number, destination: Uint8Array): number {
    const value = state(this).fields[id];
    if (!(value instanceof Uint8Array) || byteLength(destination) < value.length) throw new RPCProtocolError("application_header_field");
    Uint8Array.prototype.set.call(destination, value); return value.length;
  }
  sameField(other: ApplicationHeader, id: number): boolean { return equal(state(this).fields[id], state(other).fields[id]); }
  checkResponse(request: ApplicationHeader): void {
    const response = state(this), original = state(request);
    if (response.variant.request !== request.kind) throw new RPCProtocolError("application_response_kind");
    for (const id of [1, 2, 4, 6, 9]) if (!equal(response.fields[id], original.fields[id])) throw new RPCProtocolError("application_response_binding");
    const limit = original.fields[8];
    if (!this.isSDKError() && typeof limit === "bigint" && BigInt(this.payloadBytes) > limit) throw new RPCProtocolError("application_response_limit");
  }
  encode(destination: Uint8Array): number {
    const captured = state(this), writer = new FixedCBORWriter(destination).map(captured.variant.fields.length);
    for (const id of captured.variant.fields) {
      const value = captured.fields[id]!; writer.uint(id);
      if (typeof value === "bigint") writer.uint(value); else writer.data(value);
    }
    return byteLength(writer.result());
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ApplicationHeader"; }
}
export interface ApplicationHeaderInput {
  readonly kind: ApplicationMessageKind;
  readonly operationID?: Uint8Array;
  readonly typeID: number;
  readonly payloadBytes: number;
  readonly requestDigest?: Uint8Array;
  readonly deadlineAtMS?: bigint;
  readonly contractDigest: Uint8Array;
  readonly admissionMode?: 0 | 1;
  readonly responseLimitBytes?: number;
  readonly controlSerial?: bigint;
  readonly applicationErrorCode?: number;
}
function decoderConfig(runtimeBytes: bigint) { return { bytes: 512, nodes: 23, textBytes: 0, arrayItems: 1, runtimeBytes }; }
export function applicationHeaderDecoderCharge(runtimeBytes: bigint): ResourceVector { return cborDecoderCharge(decoderConfig(runtimeBytes)); }
export function applicationHeaderCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  return new ResourceVector([512n + runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
/** One fixed production header codec per admitted channel. Every returned
 * header's compact scalar projection is paid by its original message slot. */
export class ApplicationHeaderCodec {
  #reference: ResourceReference | undefined;
  #decoder: CBORDecoder | undefined;
  #output = new Uint8Array();
  #busy = false;
  constructor(runtimeBytes: bigint, reference: ResourceReference, decoder: ResourceReference) {
    if (!reference.sameEnvironment(decoder)) throw new RPCProtocolError("application_header_owner");
    this.#reference = reference.take(applicationHeaderCharge(runtimeBytes));
    try { this.#decoder = new CBORDecoder(decoderConfig(runtimeBytes), decoder); this.#output = new Uint8Array(512); }
    catch (error) { this.close(); throw error; }
  }
  decode(bytes: Uint8Array): ApplicationHeader {
    if (this.#reference === undefined) throw new RPCProtocolError("application_header_closed");
    this.#reference.check();
    const doc = this.#decoder!.decodeMap(bytes, "ApplicationHeader");
    try {
      const selected = byCode.get(Number(doc.uint(doc.field(0, 0))));
      if (selected === undefined || doc.size() !== selected.variant.fields.length) throw new RPCProtocolError("application_header_variant");
      const fields: (Scalar | undefined)[] = Array(11).fill(undefined);
      for (const id of selected.variant.fields) {
        const node = doc.field(0, id);
        if (node < 0) throw new RPCProtocolError("application_header_variant");
        if (doc.kind(node) === "bytes") { const value = new Uint8Array(doc.size(node)); doc.copyPayload(node, value); fields[id] = value; }
        else fields[id] = doc.uint(node);
      }
      for (const [id, expected] of Object.entries(selected.variant.constants ?? {})) {
        if (fields[Number(id)] !== BigInt(expected)) throw new RPCProtocolError("application_header_constant");
      }
      if (selected.variant.sdk_error && (fields[3] as bigint) > 256n) throw new RPCProtocolError("application_sdk_error_limit");
      return new ApplicationHeader(capability, selected.name, Object.freeze({ variant: selected.variant, fields: Object.freeze(fields) }));
    } finally { doc.release(); }
  }
  create(input: ApplicationHeaderInput): ApplicationHeader {
    // All caller properties are captured before claiming reusable output.
    const values = fieldNames.map(name => input[name]), name = values[0];
    if (typeof name !== "string" || !Object.hasOwn(variants, name)) throw new RPCProtocolError("application_header_variant");
    const selected = variants[name]!;
    for (let id = 1; id < values.length; id++) {
      const value = values[id];
      if (selected.fields.includes(id) !== (value !== undefined)) throw new RPCProtocolError("application_header_variant");
      if (value === undefined) continue;
      if ([1, 4, 6].includes(id)) {
        if (!(value instanceof Uint8Array) || byteLength(value) !== 32) throw new RPCProtocolError("application_header_field");
        values[id] = new Uint8Array(byteSlice(value, 0, 32));
      } else if (typeof value !== "bigint" && (typeof value !== "number" || !Number.isSafeInteger(value)) ||
          BigInt(value as bigint | number) < 0n || BigInt(value as bigint | number) > u64) throw new RPCProtocolError("application_header_field");
    }
    if (this.#busy || this.#reference === undefined) throw new RPCProtocolError("application_header_unavailable");
    this.#reference.check(); this.#busy = true;
    try {
      const writer = new FixedCBORWriter(this.#output).map(selected.fields.length);
      for (const id of selected.fields) {
        const value = id === 0 ? selected.code : values[id]!; writer.uint(id);
        if (value instanceof Uint8Array) writer.data(value); else writer.uint(BigInt(value as bigint | number));
      }
      return this.decode(writer.result());
    } finally { this.#output.fill(0); this.#busy = false; }
  }
  response(request: ApplicationHeader, kind: ApplicationMessageKind, payloadBytes: number, applicationErrorCode?: number): ApplicationHeader {
    const selected = variants[kind];
    if (selected?.request !== request.kind) throw new RPCProtocolError("application_response_kind");
    const original = state(request), input: Record<string, unknown> = { kind, payloadBytes };
    for (const id of selected.fields) {
      if (id === 0 || id === 3) continue;
      input[fieldNames[id]!] = id === 10 ? applicationErrorCode : original.fields[id];
    }
    const header = this.create(input as unknown as ApplicationHeaderInput); header.checkResponse(request); return header;
  }
  close(): void {
    this.#decoder?.close(); this.#decoder = undefined; this.#output.fill(0); this.#output = new Uint8Array();
    this.#reference?.release(); this.#reference = undefined;
  }
}
