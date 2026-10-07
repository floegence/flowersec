export type StorageTransactionGroup = "flowersec-v4-node-pool" | "flowersec-node-admission" | "flowersec-v4-node-execution" | "flowersec-v4-indexeddb-pool";
export type StorageFormatReason = "backend_configuration" | "manifest_unknown_or_invalid" | "identity_mismatch" | "revision_conflict" | "older_revision" | "newer_revision" | "schema_or_state_invalid";
export interface StorageRevision { readonly known: boolean; readonly value: number; }
export interface StorageFormatProjection {
  readonly code: "storage_format_incompatible";
  readonly transactionGroup: StorageTransactionGroup;
  readonly wireProfile: "flowersec-v4-transport-security";
  readonly observedRevision: StorageRevision;
  readonly requiredRevision: number;
  readonly reason: StorageFormatReason;
  readonly exactConversionAvailable: false;
}
export function storageFormatProjection(group: StorageTransactionGroup, required: number, observed: StorageRevision, reason: StorageFormatReason): StorageFormatProjection {
  return Object.freeze({ code: "storage_format_incompatible", transactionGroup: group, wireProfile: "flowersec-v4-transport-security",
    observedRevision: Object.freeze({ known: observed.known, value: observed.known ? observed.value : 0 }), requiredRevision: required, reason,
    exactConversionAvailable: false });
}
