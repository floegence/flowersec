import type { SQLOutputValue } from "node:sqlite";
import type { SQLiteWorkerDatabase } from "./sqliteWorkerV4.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { V4ContentObservation } from "../v4/streamContent.js";
import { methodDefinition, type V4MethodDefinition, type CapturedMethodDefinition } from "../v4/serviceDefinition.js";
import { CBORDecoder, cborDecoderCharge, byteLength } from "../v4/runtime/cbor.js";
import { credentialDigest, equalCredential } from "../v4/runtime/credentialSupport.js";
import { hex, type ExecutionTarget } from "../v4/runtime/executionManagementCodec.js";
import type { ExecutionRecordFacts } from "../v4/runtime/executionStorage.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { RPCProtocolError } from "../v4/runtime/rpcFragment.js";
import { timeAdd } from "../v4/runtime/timeArithmetic.js";
import { count, readU64, u64 } from "./sqliteV4.js";
export interface V4SQLiteContentConfig {
  readonly methods: readonly V4MethodDefinition<any, any>[];
  readonly maxItemsPerOperation: number;
  readonly maxBytesPerOperation: number;
  readonly maxItemBytes: number;
}
export interface CapturedContentConfig {
  readonly methods: readonly CapturedMethodDefinition[];
  readonly maxItemsPerOperation: number; readonly maxBytesPerOperation: number; readonly maxItemBytes: number;
}
export function captureContent(input: V4SQLiteContentConfig | undefined): CapturedContentConfig | undefined {
  if (input === undefined) return;
  if (!Array.isArray(input.methods) || input.methods.length < 1 || input.methods.length > 128) throw new RPCProtocolError("configuration_capacity");
  const methods = input.methods.map(methodDefinition);
  if (methods.some((method, i) => method.shape !== "server_streaming" || method.semantics !== "execution" || method.streamContent === undefined || methods.slice(0, i).some(previous => previous.typeID === method.typeID))) throw new RPCProtocolError("configuration_capacity");
  const maxBytesPerOperation = count(input.maxBytesPerOperation, 1, 1048576);
  return Object.freeze({ methods: Object.freeze(methods), maxItemsPerOperation: count(input.maxItemsPerOperation, 1, 1024), maxBytesPerOperation, maxItemBytes: count(input.maxItemBytes, 1, maxBytesPerOperation) });
}
export function contentConfiguration(c: CapturedContentConfig) {
  return {
    maxItemsPerOperation: c.maxItemsPerOperation, maxBytesPerOperation: c.maxBytesPerOperation, maxItemBytes: c.maxItemBytes,
    methods: c.methods.map(m => ({ type: m.typeID, revision: m.streamContent!.schemaRevision, definition: hex(m.streamContent!.canonical), reader: m.streamContent!.readTypeID }))
  };
}
export const contentSchemas = [
  ["content_heads", "CREATE TABLE content_heads (key TEXT PRIMARY KEY, admitted BLOB NOT NULL CHECK(length(admitted)=8)) STRICT, WITHOUT ROWID"],
  ["content_items", "CREATE TABLE content_items (key TEXT NOT NULL, position BLOB NOT NULL CHECK(length(position) BETWEEN 1 AND 256), committed BLOB NOT NULL CHECK(length(committed)=8), expires BLOB NOT NULL CHECK(length(expires)=8), bytes INTEGER NOT NULL CHECK(bytes BETWEEN 0 AND 1048576), digest TEXT NOT NULL CHECK(length(digest)=64), payload BLOB, PRIMARY KEY(key,position)) STRICT, WITHOUT ROWID"],
] as const;
const settings = { bytes: 8192, nodes: 512, textBytes: 2048, arrayItems: 128, runtimeBytes: 1024n };
export const contentCharges = (c: CapturedContentConfig) => [cborDecoderCharge(settings), new ResourceVector([BigInt(3 * c.maxItemBytes + 16384 + c.methods.length * 2560), 0n, 0n, BigInt(4 + c.methods.length), 0n, 0n, 0n, 0n, 0n, 0n, 0n])];
interface Policy { readonly origin: bigint; readonly retention: bigint; readonly maxItems: number; readonly maxBytes: number; readonly reader: number; }
const unavailable = (): never => { throw new RPCProtocolError("service_unavailable"); };
const missing = (): V4ContentObservation => Object.freeze({ found: false, available: false, expired: false, committedAtMS: 0n, expiresAtMS: 0n, bytes: 0, digest: "0".repeat(64) });
/** Bounded content workspace in the original execution store. Every method is
 * invoked inside its caller's original transaction/fence, never a second DB. */
export class SQLiteExecutionContent {
  readonly #decoder: CBORDecoder;
  readonly #reference: ResourceReference;
  readonly #scratch: Uint8Array;
  #delivering = false;
  constructor(readonly config: CapturedContentConfig, references: readonly ResourceReference[]) {
    this.#reference = references[1]!.take(contentCharges(config)[1]!);
    try { this.#decoder = new CBORDecoder(settings, references[0]!); }
    catch (error) { this.#reference.release(); throw error; }
    this.#scratch = new Uint8Array(config.maxItemBytes);
    try { for (const method of config.methods) { const doc = this.#decoder.decode(method.streamContent!.canonical); doc.release(); } }
    catch (error) { this.close(); throw error; }
  }
  policy(wire: Uint8Array): Policy | undefined {
    this.#reference.checkRetained();
    const doc = this.#decoder.decodeMap(wire, "ServiceContract");
    try {
      const content = doc.field(0, 28); if (content < 0 || doc.uint(doc.field(content, 0)) === 0n) return;
      const type = Number(doc.uint(doc.field(0, 1))), method = this.config.methods.find(m => m.typeID === type);
      if (method === undefined || doc.uint(doc.field(0, 13)) !== 1n) unavailable();
      const expected = method!.streamContent!, node = doc.field(content, 6), definition = new Uint8Array(doc.size(node));
      try { doc.copyPayload(node, definition); if (doc.text(doc.field(content, 5)) !== expected.schemaRevision || !equalCredential(definition, expected.canonical)) unavailable(); }
      finally { definition.fill(0); }
      const maxItems = doc.uint(doc.field(content, 3)), maxBytes = doc.uint(doc.field(content, 4));
      if (maxItems > BigInt(this.config.maxItemsPerOperation) || maxBytes > BigInt(this.config.maxBytesPerOperation)) throw new RPCProtocolError("configuration_capacity");
      return { origin: doc.uint(doc.field(content, 1)), retention: doc.uint(doc.field(content, 2)), maxItems: Number(maxItems), maxBytes: Number(maxBytes), reader: expected.readTypeID };
    } finally { doc.release(); }
  }
  async #original(db: SQLiteWorkerDatabase, contract: string): Promise<Policy> {
    const row = (await db.get("SELECT canonical FROM contracts WHERE digest=?", contract));
    if (!(row?.canonical instanceof Uint8Array) || hex(credentialDigest("service_contract_digest", row.canonical)) !== contract) unavailable();
    try { return this.policy(row!.canonical as Uint8Array) ?? unavailable(); } finally { (row!.canonical as Uint8Array).fill(0); }
  }
  #observation(row: Record<string, SQLOutputValue> | undefined, now: { lowerMS: bigint; upperMS: bigint }): V4ContentObservation {
    if (row === undefined) return missing();
    const expires = readU64(row.expires), committed = readU64(row.committed);
    if (typeof row.digest !== "string" || !/^[0-9a-f]{64}$/u.test(row.digest) || !Number.isSafeInteger(row.bytes) || Number(row.bytes) < 0 || Number(row.bytes) > this.config.maxItemBytes || expires <= committed) unavailable();
    return Object.freeze({
      found: true, available: row.payload !== null && now.upperMS < expires, expired: row.payload === null || now.lowerMS >= expires,
      committedAtMS: committed, expiresAtMS: expires, bytes: Number(row.bytes), digest: row.digest as string
    });
  }
  async save(db: SQLiteWorkerDatabase, facts: ExecutionRecordFacts, position: Uint8Array, payload: Uint8Array, now: { lowerMS: bigint; upperMS: bigint }): Promise<V4ContentObservation> {
    if (byteLength(position) < 1 || byteLength(position) > 256 || position.buffer instanceof SharedArrayBuffer || payload.buffer instanceof SharedArrayBuffer || byteLength(payload) > this.config.maxItemBytes) throw new RPCProtocolError("configuration_capacity");
    const location = new Uint8Array(position), content = new Uint8Array(payload);
    try {
      const policy = (await this.#original(db, facts.contract)), head = (await db.get("SELECT admitted FROM content_heads WHERE key=?", facts.key));
      const admitted = readU64(head?.admitted), digest = hex(sha256(content));
      const existing = (await db.get("SELECT committed,expires,bytes,digest,payload FROM content_items WHERE key=? AND position=?", facts.key, location));
      if (existing !== undefined) {
        try { if (existing.digest !== digest || existing.bytes !== content.length) throw new RPCProtocolError("operation_conflict"); return this.#observation(existing, now); }
        finally { if (existing.payload instanceof Uint8Array) existing.payload.fill(0); }
      }
      const count = (await db.get("SELECT count(*) AS items,coalesce(sum(bytes),0) AS bytes FROM content_items WHERE key=?", facts.key))!;
      if (Number(count.items) >= policy.maxItems || Number(count.bytes) + content.length > policy.maxBytes) throw new RPCProtocolError("resource_exhausted");
      const expires = timeAdd(policy.origin === 0n ? admitted : now.upperMS, policy.retention);
      if (expires <= now.upperMS) throw new RPCProtocolError("result_expired");
      (await db.run("INSERT INTO content_items VALUES(?,?,?,?,?,?,?)", facts.key, location, u64(now.upperMS), u64(expires), content.length, digest, content));
      return Object.freeze({ found: true, available: true, expired: false, committedAtMS: now.upperMS, expiresAtMS: expires, bytes: content.length, digest });
    }
    finally { location.fill(0); content.fill(0); }
  }
  // Keep bytes in the original prepaid workspace until the transaction and
  // current invocation guard both succeed. Reentrant callbacks cannot reuse it.
  async deliver(destination: Uint8Array, action: (scratch: Uint8Array) => V4ContentObservation | Promise<V4ContentObservation>, guard: () => void, sample: () => { lowerMS: bigint; upperMS: bigint }): Promise<V4ContentObservation> {
    const capacity = byteLength(destination);
    if (destination.buffer instanceof SharedArrayBuffer || capacity > 1048576) throw new RPCProtocolError("configuration_capacity");
    if (this.#delivering) throw new RPCProtocolError("resource_exhausted");
    this.#reference.checkRetained();
    this.#delivering = true;
    try {
      let observation = await action(this.#scratch);
      const now = sample();
      guard();
      this.#reference.checkRetained();
      if (observation.available && now.upperMS >= observation.expiresAtMS) observation = Object.freeze({ ...observation, available: false, expired: now.lowerMS >= observation.expiresAtMS });
      if (observation.available) {
        if (byteLength(destination) < observation.bytes) throw new RPCProtocolError("resource_exhausted");
        Uint8Array.prototype.set.call(destination, this.#scratch.subarray(0, observation.bytes));
      }
      return observation;
    }
    finally { this.#scratch.fill(0); this.#delivering = false; }
  }
  async read(db: SQLiteWorkerDatabase, target: ExecutionTarget, position: Uint8Array, destination: Uint8Array, reader: number, now: { lowerMS: bigint; upperMS: bigint }, decode: (value: SQLOutputValue | undefined) => ExecutionRecordFacts): Promise<V4ContentObservation> {
    if (byteLength(position) < 1 || byteLength(position) > 256 || position.buffer instanceof SharedArrayBuffer || destination.buffer instanceof SharedArrayBuffer || byteLength(destination) > 1048576) throw new RPCProtocolError("configuration_capacity");
    const key = `${target.authority}\0${target.subject}\0${target.operation}`, row = (await db.get("SELECT facts FROM executions WHERE key=?", key));
    if (row === undefined) throw new RPCProtocolError("service_unavailable");
    const facts = decode(row.facts);
    if (facts.request !== target.requestDigest || facts.contract !== target.contractDigest) throw new RPCProtocolError("operation_conflict");
    const policy = (await this.#original(db, facts.contract));
    if (policy.reader !== reader) throw new RPCProtocolError("permission_denied");
    (await db.run("UPDATE content_items SET payload=NULL WHERE key=? AND expires<=?", key, u64(now.lowerMS)));
    const item = (await db.get("SELECT committed,expires,bytes,digest,payload FROM content_items WHERE key=? AND position=?", key, position));
    try {
      const observation = this.#observation(item, now);
      if (observation.available) {
        if (!(item?.payload instanceof Uint8Array) || item.payload.length !== observation.bytes || hex(sha256(item.payload)) !== observation.digest) unavailable();
        if (destination.length < observation.bytes) throw new RPCProtocolError("resource_exhausted");
        destination.set(item!.payload as Uint8Array);
      }
      return observation;
    } finally { if (item?.payload instanceof Uint8Array) item.payload.fill(0); }
  }
  async validate(db: SQLiteWorkerDatabase, maxRecords: number, decode: (value: SQLOutputValue | undefined) => ExecutionRecordFacts): Promise<void> {
    if (Number((await db.get("SELECT count(*) AS n FROM content_heads"))!.n) > maxRecords ||
      Number((await db.get("SELECT count(*) AS n FROM content_items"))!.n) > maxRecords * this.config.maxItemsPerOperation ||
      (await db.get("SELECT 1 FROM content_items i LEFT JOIN content_heads h ON h.key=i.key WHERE h.key IS NULL LIMIT 1")) !== undefined)
      unavailable();
    for (const row of (await db.all("SELECT e.facts,c.canonical,h.admitted FROM executions e JOIN contracts c ON c.digest=json_extract(e.facts,'$.contract') LEFT JOIN content_heads h ON h.key=e.key"))) {
      try {
        const facts = decode(row.facts);
        if (!(row.canonical instanceof Uint8Array) || hex(credentialDigest("service_contract_digest", row.canonical)) !== facts.contract) unavailable();
        const retained = this.policy(row.canonical as Uint8Array) !== undefined;
        if (retained !== (row.admitted !== null) || retained && !facts.streaming) unavailable();
      } finally { if (row.canonical instanceof Uint8Array) row.canonical.fill(0); }
    }
    for (const row of (await db.all("SELECT h.key,h.admitted,e.facts FROM content_heads h LEFT JOIN executions e ON e.key=h.key"))) {
      const facts = decode(row.facts), admitted = readU64(row.admitted), policy = (await this.#original(db, facts.contract));
      if (!facts.streaming || row.key !== facts.key) unavailable();
      let items = 0, bytes = 0;
      for (const item of (await db.all("SELECT committed,expires,bytes,digest,payload FROM content_items WHERE key=?", facts.key))) {
        try {
          const observation = this.#observation(item, { lowerMS: 0n, upperMS: 0n });
          if (observation.committedAtMS < admitted || observation.expiresAtMS !== timeAdd(policy.origin === 0n ? admitted : observation.committedAtMS, policy.retention)) unavailable();
          if (item.payload !== null && (!(item.payload instanceof Uint8Array) || item.payload.length !== observation.bytes || hex(sha256(item.payload)) !== observation.digest)) unavailable();
          items++; bytes += observation.bytes;
        } finally { if (item.payload instanceof Uint8Array) item.payload.fill(0); }
      }
      if (items > policy.maxItems || bytes > policy.maxBytes) unavailable();
    }
  }
  close(): void { this.#scratch?.fill(0); this.#decoder.close(); this.#reference.release(); }
}
