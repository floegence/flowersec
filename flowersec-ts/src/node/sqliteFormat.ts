import type { SQLInputValue, SQLOutputValue } from "node:sqlite";

/** The same fixed row bound covers worker inspection and provider admission. */
export function sqliteInspectionRowBytes(maxRecordBytes: number): number {
  const profile = [128, 256, 512, 1024, 2048].find(kib => kib * 1024 >= maxRecordBytes + 65536);
  if (profile === undefined) throw new Error("storage_unavailable");
  return profile * 1024;
}

import { storageFormatProjection, type StorageTransactionGroup, type StorageFormatReason, type StorageRevision, type StorageFormatProjection } from "../v4/storageFormat.js";
export { storageFormatProjection };
export type { StorageTransactionGroup, StorageFormatReason, StorageRevision, StorageFormatProjection };
/** The worker may send only this fixed projection, never provider text. */
export function captureStorageFormat(input: unknown, group: StorageTransactionGroup, required: number): StorageFormatProjection | undefined {
  if (input === null || typeof input !== "object") return;
  const p = input as Partial<StorageFormatProjection>, observed = p.observedRevision;
  if (p.code !== "storage_format_incompatible" || p.transactionGroup !== group || p.wireProfile !== "flowersec-v4-transport-security" ||
      p.requiredRevision !== required || p.exactConversionAvailable !== false || observed === null || typeof observed !== "object" || typeof observed.known !== "boolean" ||
      !Number.isInteger(observed.value) || observed.value < (observed.known ? 1 : 0) || observed.value > 0xffffffff || !observed.known && observed.value !== 0 ||
      !["backend_configuration", "manifest_unknown_or_invalid", "identity_mismatch", "revision_conflict", "older_revision", "newer_revision", "schema_or_state_invalid"].includes(p.reason!)) return;
  return storageFormatProjection(group, required, observed, p.reason!);
}
type HeaderGet = (sql: string, ...args: SQLInputValue[]) => Record<string, SQLOutputValue> | undefined | Promise<Record<string, SQLOutputValue> | undefined>;
export interface StorageHeaderResult { readonly observedRevision: StorageRevision; readonly refusal?: StorageFormatProjection; }
/** Closure-free fixed-header reader shared with the original pool worker.
 * Reading a bounded header never admits or decodes an older record format. */
export async function inspectSQLiteStorageHeader(get: HeaderGet, manifest: string, group: StorageTransactionGroup, required: number,
  identity: { readonly authority: string; readonly storeID: Uint8Array; readonly generation: bigint }): Promise<StorageHeaderResult> {
  const unknown = { known: false, value: 0 };
  const refuse = (reason: StorageFormatReason, observed = unknown): StorageHeaderResult => ({ observedRevision: observed,
    refusal: { code: "storage_format_incompatible", transactionGroup: group, wireProfile: "flowersec-v4-transport-security",
      requiredRevision: required, observedRevision: observed, reason, exactConversionAvailable: false } });
  const row = await get("SELECT substr(CAST(sql AS BLOB),1,768) AS prefix FROM sqlite_schema WHERE type='table' AND name='manifest'");
  if (!(row?.prefix instanceof Uint8Array) || row.prefix.length > 768) return refuse("manifest_unknown_or_invalid");
  let prefix: string;
  try { prefix = new TextDecoder("utf-8", { fatal: true }).decode(row.prefix); }
  catch { return refuse("manifest_unknown_or_invalid"); }
  const marker = `CHECK(revision=${required})`, split = manifest.indexOf(marker);
  const before = manifest.slice(0, split) + "CHECK(revision=", after = manifest.slice(split + marker.length);
  const end = after.indexOf("epoch BLOB NOT NULL CHECK(length(epoch)=8),");
  const headerTail = after.slice(0, end + "epoch BLOB NOT NULL CHECK(length(epoch)=8),".length);
  if (split < 0 || end < 0 || !prefix.startsWith(before)) return refuse("manifest_unknown_or_invalid");
  const match = /^([1-9][0-9]{0,9})\)/u.exec(prefix.slice(before.length));
  if (match === null || !prefix.slice(before.length + match[0].length).startsWith(headerTail)) return refuse("manifest_unknown_or_invalid");
  const revision = Number(match[1]);
  if (!Number.isSafeInteger(revision) || revision > 0xffffffff) return refuse("manifest_unknown_or_invalid");
  const generation = new Uint8Array(8); new DataView(generation.buffer).setBigUint64(0, identity.generation);
  const facts = await get("SELECT (SELECT count(*) FROM (SELECT 1 FROM manifest LIMIT 2)) AS rows,id=1 AS singleton,typeof(format)='text' AND format=? AS format_ok,CASE WHEN typeof(revision)='integer' AND revision BETWEEN 1 AND 4294967295 THEN revision END AS revision,typeof(authority)='text' AND authority=? AS authority_ok,typeof(instance)='blob' AND instance=? AS instance_ok,typeof(generation)='blob' AND generation=? AS generation_ok,CASE WHEN typeof(epoch)='blob' AND length(epoch)=8 THEN epoch END AS epoch FROM manifest LIMIT 1", group, identity.authority, identity.storeID, generation);
  generation.fill(0);
  if (facts?.rows !== 1 || facts.singleton !== 1 || facts.format_ok !== 1 || !(facts.epoch instanceof Uint8Array) || facts.epoch.length !== 8) return refuse("manifest_unknown_or_invalid");
  const epoch = new DataView(facts.epoch.buffer, facts.epoch.byteOffset, 8).getBigUint64(0); facts.epoch.fill(0);
  if (epoch === 0n || epoch === 0xffffffffffffffffn) return refuse("manifest_unknown_or_invalid");
  if (facts.authority_ok !== 1 || facts.instance_ok !== 1 || facts.generation_ok !== 1) return refuse("identity_mismatch");
  const hint = await get("PRAGMA user_version");
  if (facts.revision !== revision || hint?.user_version !== revision) return refuse("revision_conflict");
  const observed = { known: true, value: revision };
  if (revision < required) return refuse("older_revision", observed);
  if (revision > required) return refuse("newer_revision", observed);
  return { observedRevision: observed };
}
