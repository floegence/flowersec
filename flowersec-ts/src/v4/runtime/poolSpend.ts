import type { VerifiedPoolSpendFacts } from "./credentialVerifier.js";
import type { ResourceReference } from "./resources.js";
import type { TrustedDeadline } from "./deadline.js";

/** Internal owner captured from the original Environment admission and carrier. */
export interface PoolSpendOwner {
  readonly connect: Uint8Array;
  readonly carrier: Uint8Array;
  readonly generation: bigint;
  readonly signal?: AbortSignal;
  /** Original receipt observation; these callbacks confer no storage authority. */
  readonly spendDispatched?: () => void;
  readonly spent?: () => void;
  readonly unspent?: () => void;
}
export interface PoolSpendStore {
  consume(facts: VerifiedPoolSpendFacts, owner: PoolSpendOwner, deadline: TrustedDeadline, admission: ResourceReference, check: () => void): void | Promise<void>;
}
const stores = new WeakSet<PoolSpendStore>();
/** Called only by built-in storage constructors; absent from package exports. */
export function registerPoolSpendStore(store: PoolSpendStore): void { stores.add(store); }
export function isPoolSpendStore(store: PoolSpendStore): boolean { return stores.has(store); }
