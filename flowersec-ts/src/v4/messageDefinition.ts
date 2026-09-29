import type { V4ApplicationContext } from "./streamHandlers.js";
import { byteLength } from "./runtime/cbor.js";
import { FixedCBORWriter } from "./runtime/cborWriter.js";
import { CanonicalTextWorkspace } from "./runtime/canonicalText.js";
import { fieldPattern, wireMaps } from "./runtime/schemaRegistry.js";
import { credentialDigest } from "./runtime/credentialSupport.js";
import { StreamMetadata, createStreamMetadata, streamMetadataBytes } from "../public/streamMetadata.js";

export interface V4MessageDirection {
  readonly schemaDigest: Uint8Array;
  readonly revision: string;
  readonly maxMessageBytes: number;
}
export type V4ApplicationMessageCodec<T = unknown> = Readonly<{
  /** Host allowance for retained callbacks, input references and application work.
   * This does not bound arbitrary application-owned object graphs. */
  applicationBytes: bigint;
}> & (Readonly<{
  execution: "sync";
  encode(context: V4ApplicationContext, value: T): Uint8Array;
  decode(context: V4ApplicationContext, bytes: Uint8Array): T;
}> | Readonly<{
  execution: "async";
  encode(context: V4ApplicationContext, value: T): Promise<Uint8Array>;
  decode(context: V4ApplicationContext, bytes: Uint8Array): Promise<T>;
}>);
interface Direction {
  readonly schema: Uint8Array; readonly revision: string; readonly maximum: number;
  readonly implementation: "bytes" | "utf8" | "application";
  readonly application?: V4ApplicationMessageCodec<unknown>;
}
const codecs = new WeakMap<object, Direction>();
/** Internal immutable codec facts shared by message and service definitions.
 * Package facades export the opaque codec, never these mutable byte aliases. */
export function messageCodecDefinition(codec: object): Direction {
  const direction = codecs.get(codec); if (direction === undefined) throw new Error("message_definition_invalid"); return direction;
}
const definitions = new WeakMap<object, { wire: Uint8Array; digest: Uint8Array; directions: readonly [Direction, Direction] }>();
const token = Symbol("local message codec"), utf8 = new TextEncoder();
const encode = TextEncoder.prototype.encode;
function text(value: string): Uint8Array { return encode.call(utf8, value); }
function revision(value: string): string {
  if (typeof value !== "string" || fieldPattern("security_id")!.exec(value)?.[0] !== value) throw new Error("message_definition_invalid");
  return value;
}
/** Only concrete SDK byte and primitive UTF-8 implementations have incremental
 * output authority. A callback or a peer-provided flag cannot create one. */
export class V4MessageCodec<T = unknown> {
  declare private readonly valueType: (value: T) => T;
  constructor(capability: symbol, direction: V4MessageDirection, implementation: Direction["implementation"], application?: V4ApplicationMessageCodec<unknown>) {
    if (capability !== token || byteLength(direction.schemaDigest) !== 32 || !Number.isSafeInteger(direction.maxMessageBytes) ||
        direction.maxMessageBytes < 1 || direction.maxMessageBytes > 1048576) throw new Error("message_definition_invalid");
    codecs.set(this, Object.freeze({ schema: new Uint8Array(direction.schemaDigest), revision: revision(direction.revision), maximum: direction.maxMessageBytes, implementation, ...(application === undefined ? {} : { application }) }));
    Object.freeze(this);
  }
}
export function v4BytesMessageCodec(direction: V4MessageDirection): V4MessageCodec<Uint8Array> { return new V4MessageCodec(token, direction, "bytes"); }
export function v4UTF8MessageCodec(direction: V4MessageDirection): V4MessageCodec<string> { return new V4MessageCodec(token, direction, "utf8"); }
/** Application callbacks never receive the SDK's incremental writer capability.
 * Their complete output and owned copy are reserved before invocation. */
export function v4ApplicationMessageCodec<T>(direction: V4MessageDirection, callbacks: V4ApplicationMessageCodec<T>): V4MessageCodec<T> {
  const { execution, applicationBytes, encode, decode } = callbacks;
  if ((execution !== "sync" && execution !== "async") || typeof applicationBytes !== "bigint" || applicationBytes < 1n || applicationBytes > 0x7fffffffffffffffn ||
      typeof encode !== "function" || typeof decode !== "function") throw new Error("message_definition_invalid");
  const captured = Object.freeze({ execution, applicationBytes, encode, decode }) as V4ApplicationMessageCodec<unknown>;
  return new V4MessageCodec(token, direction, "application", captured);
}

/** Immutable local definition. Directions describe the opener, regardless of
 * which logical endpoint opened the stream. */
export class V4MessageStreamDefinition<OpenerToAcceptor = unknown, AcceptorToOpener = unknown> {
  declare private readonly directionTypes: (value: OpenerToAcceptor) => AcceptorToOpener;
  readonly kind: string;
  readonly revision: string;
  constructor(config: Readonly<{ kind: string; revision: string; openerToAcceptor: V4MessageCodec<OpenerToAcceptor>; acceptorToOpener: V4MessageCodec<AcceptorToOpener> }>) {
    const a = codecs.get(config.openerToAcceptor), b = codecs.get(config.acceptorToOpener), kind = config.kind;
    if (a === undefined || b === undefined || typeof kind !== "string" || kind.length < 1 || kind.length > 128 || kind.startsWith("flowersec/")) throw new Error("message_definition_invalid");
    const encoded = text(kind), workspace = new CanonicalTextWorkspace(128);
    try { if (encoded.length < 1 || encoded.length > 128 || workspace.check(encoded) !== undefined || new TextDecoder("utf-8", { fatal: true }).decode(encoded) !== kind) throw new Error("message_definition_invalid"); }
    finally { workspace.clear(); }
    this.kind = kind; this.revision = revision(config.revision);
    const writer = new FixedCBORWriter(new Uint8Array(wireMaps.MessageStreamDefinition!.max_encoded_bytes!));
    writer.map(4).uint(0).data(encoded, true).uint(1).data(text(this.revision), true);
    for (const [index, direction] of [a, b].entries()) writer.uint(index + 2).map(3).uint(0).data(direction.schema).uint(1).data(text(direction.revision), true).uint(2).uint(direction.maximum);
    const wire = new Uint8Array(writer.result()), digest = credentialDigest("typed_message_definition_digest", wire);
    definitions.set(this, Object.freeze({ wire, digest, directions: Object.freeze([a, b]) as readonly [Direction, Direction] }));
    Object.freeze(this);
  }
  digest(): Uint8Array { return new Uint8Array(messageDefinition(this).digest); }
  encoded(): Uint8Array { return new Uint8Array(messageDefinition(this).wire); }
}
/** Internal captured schema; no mutable alias is exported by package entries. */
export function messageDefinition(definition: object) {
  const value = definitions.get(definition); if (value === undefined) throw new Error("message_definition_invalid"); return value;
}
export function messageMetadata(definition: object, application: StreamMetadata | undefined): Uint8Array {
  const value = messageDefinition(definition), bytes = application === undefined ? new Uint8Array() : streamMetadataBytes(application);
  if (application !== undefined && (!(application instanceof StreamMetadata) || application.namespace.startsWith("flowersec/"))) throw new Error("message_metadata_invalid");
  try {
    if (bytes.length > 4006) throw new Error("message_metadata_invalid");
    const writer = new FixedCBORWriter(new Uint8Array(4096));
    writer.map(3).uint(0).data(text("flowersec/typed-message"), true).uint(1).uint(1).uint(2).map(2)
      .data(text("definition"), true).data(value.digest).data(text("application"), true).data(bytes);
    return new Uint8Array(writer.result());
  } finally { bytes.fill(0); }
}
export function emptyMessageMetadata(): StreamMetadata { return createStreamMetadata({}); }
export function sameMessageDigest(a: Uint8Array, b: Uint8Array): boolean {
  if (byteLength(a) !== 32 || byteLength(b) !== 32) return false;
  let difference = 0; for (let i = 0; i < 32; i++) difference |= a[i]! ^ b[i]!; return difference === 0;
}
