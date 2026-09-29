import type { V4StreamContentDefinition } from "./streamContent.js";
import { byteLength } from "./runtime/cbor.js";
import { messageCodecDefinition, type V4MessageCodec } from "./messageDefinition.js";
import { checkServiceExportName } from "./serviceMembers.js";
import { fieldPattern } from "./runtime/schemaRegistry.js";

export type V4ServiceShape = "unary" | "server_streaming" | "notify";
export type V4ServiceSemantics = "transient" | "execution" | "observation";
export interface V4ApplicationErrorDefinition<T = unknown> {
  readonly code: number;
  readonly codec: V4MessageCodec<T>;
  readonly maxPayloadBytes: number;
}
interface Common<Request> {
  readonly typeID: number;
  readonly request: V4MessageCodec<Request>;
  readonly requestMaxBytes: number;
  readonly exportName?: string;
  readonly requireDurable?: boolean;
  readonly checkpointFormat?: string;
  readonly streamContent?: V4StreamContentDefinition;
  readonly errors?: readonly V4ApplicationErrorDefinition<any>[];
}
interface Response<Response> {
  readonly response: V4MessageCodec<Response>;
  readonly minResponseLimitBytes: number;
  readonly maxResponseBytes: number;
}
type Restart = { readonly restartFlush: false; readonly restartFlushDeadlineMS?: never } |
  { readonly restartFlush: true; readonly restartFlushDeadlineMS: bigint };
export type V4MethodDefinitionOptions<Request, ResponseValue> = Common<Request> & (
  (Response<ResponseValue> & Restart & { readonly shape: "unary"; readonly unarySemantics: "transient" | "execution";
    readonly serverStreamingSemantics?: never; readonly notifySemantics?: never; readonly maxItemCount?: never;
    readonly maxStreamPayloadBytes?: never; readonly maxStreamDurationMS?: never; readonly responseRevision?: never }) |
  (Response<ResponseValue> & { readonly shape: "server_streaming"; readonly serverStreamingSemantics: "transient" | "execution";
    readonly maxItemCount: number; readonly maxStreamPayloadBytes: bigint; readonly maxStreamDurationMS: bigint;
    readonly restartFlush: false; readonly restartFlushDeadlineMS?: never; readonly unarySemantics?: never;
    readonly notifySemantics?: never; readonly responseRevision?: never }) |
  { readonly shape: "notify"; readonly notifySemantics: "observation" | "execution"; readonly responseRevision: string;
    readonly restartFlush: false; readonly restartFlushDeadlineMS?: never; readonly unarySemantics?: never;
    readonly serverStreamingSemantics?: never; readonly response?: never; readonly minResponseLimitBytes?: never;
    readonly maxResponseBytes?: never; readonly maxItemCount?: never; readonly maxStreamPayloadBytes?: never; readonly maxStreamDurationMS?: never }
);
type Codec = ReturnType<typeof messageCodecDefinition>;
export interface CapturedErrorDefinition { readonly code: number; readonly codec: Codec; readonly maximum: number }
export interface CapturedMethodDefinition {
  readonly typeID: number; readonly shape: V4ServiceShape; readonly semantics: V4ServiceSemantics;
  readonly request: Codec; readonly response: Codec | undefined; readonly requestMaxBytes: number;
  readonly responseRevision: string; readonly minResponseLimitBytes: number; readonly maxResponseBytes: number;
  readonly requireDurable: boolean; readonly checkpointFormat: string | undefined;
  readonly streamContent?: V4StreamContentDefinition;
  readonly restartFlush: boolean; readonly restartFlushDeadlineMS: bigint | undefined;
  readonly maxItemCount: number | undefined; readonly maxStreamPayloadBytes: bigint | undefined; readonly maxStreamDurationMS: bigint | undefined;
  readonly errors: readonly CapturedErrorDefinition[]; readonly exportName: string | undefined;
}
const methods = new WeakMap<object, CapturedMethodDefinition>();
const definitions = new WeakMap<object, Readonly<{ namespace: string; entries: readonly ServiceDefinitionEntry[]; preset: "full" | "constrained" }>>();
export interface ServiceDefinitionEntry { readonly name: string; readonly exportName: string; readonly method: object; readonly facts: CapturedMethodDefinition }
function identifier(value: string): string {
  if (typeof value !== "string" || fieldPattern("security_id")!.exec(value)?.[0] !== value) throw new Error("service_definition_invalid"); return value;
}
function number(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error("service_definition_invalid"); return value;
}
function positive(value: bigint, maximum = (1n << 64n) - 1n): bigint {
  if (typeof value !== "bigint" || value < 1n || value > maximum) throw new Error("service_definition_invalid"); return value;
}

/** Immutable local type value with no independent Close or transport authority.
 * A concrete contract is installed separately against these exact facts. */
export class V4MethodDefinition<Request, ResponseValue = never, Shape extends V4ServiceShape = V4ServiceShape, Semantics extends V4ServiceSemantics = V4ServiceSemantics> {
  declare private readonly valueTypes: (request: Request) => ResponseValue;
  readonly typeID: number;
  readonly shape: Shape;
  readonly semantics: Semantics;
  constructor(options: V4MethodDefinitionOptions<Request, ResponseValue> & { readonly shape: Shape } &
    ({ readonly unarySemantics: Semantics } | { readonly serverStreamingSemantics: Semantics } | { readonly notifySemantics: Semantics })) {
    const { typeID, shape, request, response, requestMaxBytes, responseRevision, minResponseLimitBytes, maxResponseBytes,
      unarySemantics, serverStreamingSemantics, notifySemantics, restartFlush, restartFlushDeadlineMS,
      maxItemCount, maxStreamPayloadBytes, maxStreamDurationMS, requireDurable, checkpointFormat, streamContent, exportName, errors } = options;
    const req = messageCodecDefinition(request), res = response === undefined ? undefined : messageCodecDefinition(response);
    this.typeID = number(typeID, 1, 0xffffffff); this.shape = shape;
    const semantics = shape === "unary" ? unarySemantics : shape === "server_streaming" ? serverStreamingSemantics : shape === "notify" ? notifySemantics : undefined;
    if (semantics === undefined || (shape === "notify" ? semantics !== "observation" && semantics !== "execution" : semantics !== "transient" && semantics !== "execution")) throw new Error("service_definition_invalid");
    this.semantics = semantics as Semantics;
    if (shape !== "unary" && unarySemantics !== undefined || shape !== "server_streaming" && serverStreamingSemantics !== undefined ||
        shape !== "notify" && notifySemantics !== undefined || typeof restartFlush !== "boolean" ||
        requireDurable !== undefined && typeof requireDurable !== "boolean" || requireDurable === true && semantics !== "execution" ||
        checkpointFormat !== undefined && (semantics !== "execution" || shape === "notify")) throw new Error("service_definition_invalid");
    if (restartFlush) {
      if (shape !== "unary") throw new Error("service_definition_invalid"); positive(restartFlushDeadlineMS!, 120000n);
    } else if (restartFlushDeadlineMS !== undefined) throw new Error("service_definition_invalid");
    if (shape === "server_streaming") {
      number(maxItemCount!, 1, 0xffffffff); positive(maxStreamPayloadBytes!); positive(maxStreamDurationMS!);
    } else if (maxItemCount !== undefined || maxStreamPayloadBytes !== undefined || maxStreamDurationMS !== undefined) throw new Error("service_definition_invalid");
    number(requestMaxBytes, 0, req.maximum);
    if (shape === "notify") {
      if (res !== undefined || minResponseLimitBytes !== undefined || maxResponseBytes !== undefined || errors !== undefined && errors.length !== 0) throw new Error("service_definition_invalid");
      identifier(responseRevision!);
    } else {
      if (res === undefined || responseRevision !== undefined) throw new Error("service_definition_invalid");
      number(minResponseLimitBytes!, 0, 1048576); number(maxResponseBytes!, minResponseLimitBytes!, res.maximum);
    }
    if (exportName !== undefined) checkServiceExportName(exportName);
    if (checkpointFormat !== undefined) identifier(checkpointFormat);
    let content: V4StreamContentDefinition | undefined;
    if (streamContent !== undefined) {
      if (shape !== "server_streaming" || semantics !== "execution" || byteLength(streamContent.canonical) < 1 || byteLength(streamContent.canonical) > 2048 ||
          streamContent.canonical.buffer instanceof SharedArrayBuffer || streamContent.readTypeID === typeID) throw new Error("service_definition_invalid");
      content = Object.freeze({ schemaRevision: identifier(streamContent.schemaRevision), canonical: new Uint8Array(streamContent.canonical), readTypeID: number(streamContent.readTypeID, 1, 0xffffffff) });
    }
    if (errors !== undefined && (!Array.isArray(errors) || errors.length > 64)) throw new Error("service_definition_invalid");
    const catalog = (errors ?? []).map(error => {
      const code = number(error.code, 1, 0xffffffff), codec = messageCodecDefinition(error.codec), maximum = number(error.maxPayloadBytes, 0, codec.maximum);
      return Object.freeze({ code, codec, maximum });
    }).sort((a, b) => a.code - b.code);
    if (catalog.some((error, i) => i > 0 && error.code === catalog[i - 1]!.code)) throw new Error("service_definition_invalid");
    methods.set(this, Object.freeze({ typeID, shape, semantics, request: req, response: res, requestMaxBytes,
      responseRevision: res?.revision ?? responseRevision!, minResponseLimitBytes: minResponseLimitBytes ?? 0, maxResponseBytes: maxResponseBytes ?? 0,
      requireDurable: requireDurable ?? false, checkpointFormat, ...(content === undefined ? {} : { streamContent: content }), restartFlush, restartFlushDeadlineMS,
      maxItemCount, maxStreamPayloadBytes, maxStreamDurationMS, errors: Object.freeze(catalog), exportName }));
    Object.freeze(this);
  }
  toJSON(): object { return {}; }
}
export type V4ServiceMethods = Readonly<Record<string, V4MethodDefinition<any, any>>>;

/** One frozen namespace/method set, shared by client binding and server plans.
 * Projection is explicit local configuration, never dynamic remote discovery. */
export class V4ServiceDefinition<Methods extends V4ServiceMethods> {
  readonly namespace: string;
  readonly methods: Methods;
  constructor(options: Readonly<{ namespace: string; methods: Methods; preset?: "full" | "constrained" }>) {
    const { namespace, methods: input, preset = "full" } = options;
    this.namespace = identifier(namespace);
    if (preset !== "full" && preset !== "constrained" || input === null || typeof input !== "object") throw new Error("service_definition_invalid");
    const names = Object.keys(input);
    if (names.length < 1 || names.length > (preset === "full" ? 256 : 16)) throw new Error("service_definition_capacity");
    const seenTypes = new Set<number>(), seenNames = new Set<string>(), entries: ServiceDefinitionEntry[] = [];
    const captured: Record<string, object> = Object.create(null) as Record<string, object>;
    for (const name of names) {
      if (name.length < 1 || name.length > 128 || !/^[\x21-\x7e]+$/u.test(name)) throw new Error("service_definition_invalid");
      const method = input[name]!, facts = methodDefinition(method), exported = facts.exportName ?? name;
      checkServiceExportName(exported);
      if (seenTypes.has(facts.typeID) || seenNames.has(exported)) throw new Error("service_definition_duplicate");
      seenTypes.add(facts.typeID); seenNames.add(exported); captured[name] = method;
      entries.push(Object.freeze({ name, exportName: exported, method, facts }));
    }
    this.methods = Object.freeze(captured) as Methods;
    definitions.set(this, Object.freeze({ namespace: this.namespace, entries: Object.freeze(entries), preset })); Object.freeze(this);
  }
  project<Key extends keyof Methods & string>(names: readonly Key[]): V4ServiceDefinition<Pick<Methods, Key>> {
    const original = serviceDefinition(this), subset: Record<string, object> = Object.create(null) as Record<string, object>;
    if (!Array.isArray(names) || names.length < 1 || names.length > original.entries.length) throw new Error("service_definition_invalid");
    for (const name of names) {
      if (!Object.hasOwn(this.methods, name) || Object.hasOwn(subset, name)) throw new Error("service_definition_invalid"); subset[name] = this.methods[name]!;
    }
    return new V4ServiceDefinition({ namespace: original.namespace, methods: subset as Pick<Methods, Key>, preset: original.preset });
  }
  toJSON(): object { return {}; }
}
export function methodDefinition(method: object): CapturedMethodDefinition {
  const facts = methods.get(method); if (facts === undefined) throw new Error("service_definition_invalid"); return facts;
}
export function serviceDefinition(definition: object) {
  const facts = definitions.get(definition); if (facts === undefined) throw new Error("service_definition_invalid"); return facts;
}
