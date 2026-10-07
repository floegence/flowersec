import type { ResourceReference } from "./resources.js";
import type { V4EnvironmentRuntime } from "./environment.js";

export interface PoolJournalStore {
  /** Original durable read. Missing is distinct from unavailable history. */
  readPoolJournal(key: Uint8Array, check: () => void): Promise<Uint8Array | undefined>;
  /** Single transaction installs all pending/Applied/material/frontier facts.
   * Undefined expected creates once. Only an original COMMIT confirms success. */
  comparePoolJournal(key: Uint8Array, expected: Uint8Array | undefined, replacement: Uint8Array, check: () => void): Promise<void>;
}
interface OriginalJournal { environment: V4EnvironmentRuntime; reference: () => ResourceReference; generation: () => bigint; check(): void }
const journals = new WeakMap<PoolJournalStore, OriginalJournal>();
export function registerPoolJournalStore(store: PoolJournalStore, original: OriginalJournal): void {
  if (journals.has(store)) throw new Error("source_contract_invalid"); journals.set(store, original);
}
export function originalPoolJournal(store: PoolJournalStore, environment: V4EnvironmentRuntime): OriginalJournal {
  const original = journals.get(store);
  if (original === undefined || original.environment !== environment) throw new Error("source_contract_invalid");
  original.check(); original.reference().check(); return original;
}
